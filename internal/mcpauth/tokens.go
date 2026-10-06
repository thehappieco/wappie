package mcpauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/store"
)

// The console connection token (docs/mcp-enclave.md §19.18), for tools that
// cannot run an OAuth flow but can send a fixed Authorization header. The
// console asks the attested reader for a token request through this server,
// mints the bearer in the browser, seals the bundle with its SHA-256 to the
// key the reader attested, and records the connection here; this server
// relays the bundle and waits while the reader proves the grants, installs
// the connection and activates it. It never sees the bearer, its hash or its
// allowed networks: what it keeps is the ledger row, with the label as the
// row's name, the history window, and client_kind token, which is always
// the unknown tier.

// tokenRequestKind is a pending token request's entry kind.
const tokenRequestKind = "token"

// tokenBundleTimeout is how long the reader may take with a token's bundle:
// for text it proves every grant before it installs and activates.
const tokenBundleTimeout = 30 * time.Second

// tokenPrepared is the part of a token request's descriptor this server
// reads (§19.18 step 1).
type tokenPrepared struct {
	preparedDescriptor
	DescriptorVersion int    `json:"descriptor_version"`
	Kind              string `json:"kind"`
	ClientKind        string `json:"client_kind"`
	Trust             string `json:"trust"`
	LimitsTier        string `json:"limits_tier"`
}

// checkTokenRequest reads what the reader attested for a token request and
// checks its shape: a version-2 token descriptor, the unknown tier and the
// token's limits, a request id of the right shape, this reader's resource,
// the full per-request key, and an attestation over the request id.
func checkTokenRequest(raw json.RawMessage, rd reader) (string, requestEntry, error) {
	var p tokenPrepared
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", requestEntry{}, errors.New("the token request is not the expected object")
	}
	if p.DescriptorVersion != descriptorV2 || p.Kind != kindTokenReq || p.ClientKind != store.ClientToken ||
		p.Trust != store.TrustUnknown || p.LimitsTier != store.TierToken {
		return "", requestEntry{}, errors.New("the token request is not a version-2 token descriptor of the unknown tier")
	}
	if !validRequestID(p.RequestID) || p.Resource != rd.resource() {
		return "", requestEntry{}, errors.New("the token request is for another resource, or its id is malformed")
	}
	if p.Attestation != nil && p.Attestation.RequestID != p.RequestID {
		return "", requestEntry{}, errors.New("the token request's attestation is for another request")
	}
	e, err := p.entry(rd, true)
	if err != nil {
		return "", requestEntry{}, err
	}
	e.kind, e.version = tokenRequestKind, descriptorV2
	return p.RequestID, e, nil
}

// tokenRequest asks the content reader for a pending token request over the
// browser's nonce, for an owner or an admin of a workspace that may use the
// attested reader, and relays the descriptor once its shape is checked. The
// bundle that answers it must be the same person's. Rate-limited like a
// prepare.
func (h *Handler) tokenRequest(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	if !allow(w, r, h.DescriptorLimits, "token-request:"+user.ID.String()) {
		return
	}
	var req prepareBody
	if !decode(w, r, &req) {
		return
	}
	if !validPrepareNonce(req.Nonce) {
		fail(w, http.StatusBadRequest, "bad_request", "nonce must be 16 to 64 bytes in unpadded base64url")
		return
	}
	if user.Role != "owner" && user.Role != "admin" {
		fail(w, http.StatusForbidden, "not_authorized", "a connection token is made by a workspace owner or an administrator")
		return
	}
	rd, ok := h.tokenReader(w, user.TenantID)
	if !ok {
		return
	}
	if code := h.clientRefusal(store.TrustUnknown, ""); code != "" {
		fail(w, http.StatusForbidden, code, "connection tokens are switched off on this server right now")
		return
	}
	raw, err := rd.attested.Relay.TokenRequest(r.Context(), req.Nonce)
	switch {
	case errors.Is(err, ErrTooManyPrepares):
		fail(w, http.StatusTooManyRequests, "too_many_prepares", "too many token requests are waiting; try again in a few minutes")
		return
	case errors.Is(err, ErrReaderNotFound):
		// A reader before 0.6.0 has no such route.
		fail(w, http.StatusNotFound, "not_found", "this assistant connector makes no connection tokens")
		return
	case err != nil:
		h.readerError(w, err)
		return
	}
	id, entry, err := checkTokenRequest(raw, rd)
	if err != nil {
		h.log().Warn("an attested reader answered a token request with the wrong shape", "reader", rd.id, "error", err)
		fail(w, http.StatusBadGateway, "reader_unavailable", "the assistant connector answered with something unexpected; try again in a moment")
		return
	}
	entry.user = user.ID
	h.requests.put(id, entry, time.Now())
	h.log().Info("mcp token request prepared", "reader", rd.id, "pcr0", entry.pcr0[:12], "document", entry.documentSHA256[:12])
	sendRaw(w, raw)
}

// tokenReader is the reader a workspace's tokens are made with: the content
// reader, attested and admitting the workspace. It answers the refusal
// itself.
func (h *Handler) tokenReader(w http.ResponseWriter, tenant uuid.UUID) (reader, bool) {
	rd, ok := h.readerByID(h.ContentReader)
	if !ok || rd.attested == nil {
		fail(w, http.StatusConflict, "attestation_unsupported", "connection tokens need the attested reader, which this server does not front")
		return reader{}, false
	}
	if !rd.attested.allows(tenant) {
		fail(w, http.StatusForbidden, "tenant_not_allowed", "this workspace may not use this assistant connector yet")
		return reader{}, false
	}
	return rd, true
}

// tokenBundleRequest is the console's token consent (§19.18 step 5).
type tokenBundleRequest struct {
	// Kind is "metadata" or "content".
	Kind      string `json:"kind"`
	KeyPrefix string `json:"key_prefix"`
	ExpiresAt string `json:"expires_at"`
	KID       string `json:"kid"`
	Sealed    string `json:"sealed"`
	// Label is the person's name for the token, the ledger's client_name.
	Label       string `json:"label"`
	HistoryDays int    `json:"history_days"`
	Media       bool   `json:"media"`
	// For text only: the token's service account, its key mode and the
	// content consent's version, 4.
	ServiceUserID  string `json:"service_user_id"`
	KeyMode        string `json:"key_mode"`
	ConsentVersion int    `json:"consent_version"`
}

// TokenBundleRelay is what the reader receives with a token's bundle: the
// consent relay's members, and the kind, the history window and media
// always, which the reader compares with the sealed bundle.
type TokenBundleRelay struct {
	ConnectionID string    `json:"connection_id"`
	TenantID     string    `json:"tenant_id"`
	KID          string    `json:"kid"`
	Sealed       string    `json:"sealed"`
	ExpiresAt    time.Time `json:"expires_at"`
	Kind         string    `json:"kind"`
	HistoryDays  int       `json:"history_days"`
	Media        bool      `json:"media"`
}

// checkTokenBundle validates the shape of a token consent and turns it into
// the ledger's: a token, unknown, redirecting nowhere, named by its label.
func checkTokenBundle(w http.ResponseWriter, id string, req tokenBundleRequest) (store.CreateMCPConnection, bool) {
	bad := func(msg string) (store.CreateMCPConnection, bool) {
		fail(w, http.StatusBadRequest, "bad_request", msg)
		return store.CreateMCPConnection{}, false
	}
	switch {
	case len(req.KeyPrefix) != prefixLen || !isHex(req.KeyPrefix):
		return bad("key_prefix must be the 8 hex characters before the dot")
	case len(req.KID) != kidLen || !isHex(req.KID):
		return bad("kid must be 16 hex characters")
	case !slices.Contains(store.HistoryDayChoices, req.HistoryDays):
		return bad("history_days must be 7, 30 or 90")
	}
	label, ok := normalName(req.Label)
	if !ok {
		return bad("label must be 1 to 100 characters of one script, without controls or doubled spaces")
	}
	at, err := time.Parse(time.RFC3339, req.ExpiresAt)
	if err != nil {
		return bad("expires_at must be an RFC 3339 timestamp")
	}
	if sealed, err := base64.RawURLEncoding.DecodeString(req.Sealed); err != nil || len(sealed) < minSealedLen {
		return bad("sealed must be the unpadded base64url of the sealed bundle")
	}
	in := store.CreateMCPConnection{
		RequestID: id, KeyPrefix: req.KeyPrefix, ClientName: label, RedirectHost: store.TokenRedirectHost,
		ReaderKID: req.KID, ExpiresAt: at.UTC(), Kind: store.KindMetadata,
		ClientKind: store.ClientToken, Trust: store.TrustUnknown, HistoryDays: req.HistoryDays,
	}
	switch req.Kind {
	case store.KindMetadata:
		if req.ServiceUserID != "" || req.KeyMode != "" || req.ConsentVersion != 0 || req.Media {
			return bad("service_user_id, key_mode, consent_version and media are for a text token only")
		}
	case store.KindContent:
		service, err := uuid.Parse(req.ServiceUserID)
		if err != nil || len(req.ServiceUserID) != 36 || service == uuid.Nil {
			return bad("service_user_id must be the token's service account id")
		}
		if req.KeyMode != store.KeyModeEphemeral {
			return bad("key_mode must be ephemeral")
		}
		if req.ConsentVersion != store.ClientConsentVersion {
			return bad("a text token's consent_version is 4")
		}
		in.Kind, in.ServiceUserID, in.KeyMode, in.ConsentVersion, in.Media = store.KindContent, service, req.KeyMode, req.ConsentVersion, req.Media
	default:
		return bad("kind must be metadata or content")
	}
	if now := time.Now(); !at.After(now) || at.After(now.Add(store.MaxLifetime(in.Kind, store.TierToken))) {
		return bad("expires_at must be in the future and within 90 days for metadata or 30 days for text")
	}
	return in, true
}

// tokenBundle records a token consent and hands the reader its bundle
// (§19.18 step 5). The order is create's: the request must be one this
// process prepared for this person with this kid; the switches, the key, the
// caps and, for text, the notice precondition come before the ledger; the row
// is written pending and the bundle relayed with a 30-second wait, during
// which the reader installs the token and activates the row; a refusal or a
// failure undoes the row with its key.
func (h *Handler) tokenBundle(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	if !allow(w, r, h.Limits, user.ID.String()) {
		return
	}
	id := r.PathValue("id")
	if !validRequestID(id) {
		fail(w, http.StatusNotFound, "not_found", "no such request")
		return
	}
	var req tokenBundleRequest
	if !decode(w, r, &req) {
		return
	}
	in, ok := checkTokenBundle(w, id, req)
	if !ok {
		return
	}
	ctx := r.Context()
	entry, ok := h.requests.get(id, time.Now())
	rd, known := h.readerByID(entry.reader)
	if !ok || !entry.prepared || entry.kind != tokenRequestKind || entry.user != user.ID || entry.kid != in.ReaderKID ||
		len(entry.publicKey) != readerPublicKeyLen || !known || rd.attested == nil || rd.id != h.ContentReader {
		fail(w, http.StatusConflict, "attestation_required", "this token request must be verified by you first; start again")
		return
	}
	if !rd.attested.allows(user.TenantID) {
		fail(w, http.StatusForbidden, "tenant_not_allowed", "this workspace may not use this assistant connector yet")
		return
	}
	if code := h.clientRefusal(store.TrustUnknown, ""); code != "" {
		fail(w, http.StatusForbidden, code, "connection tokens are switched off on this server right now")
		return
	}
	content := in.Kind == store.KindContent
	if content && !h.contentAllowed(rd, user.TenantID) {
		fail(w, http.StatusForbidden, "content_not_allowed", "this workspace may not let an assistant read message text yet")
		return
	}
	if in.Media && !h.mediaAllowed(rd, user.TenantID) {
		fail(w, http.StatusBadRequest, "media_not_allowed", "media is not enabled for this workspace")
		return
	}
	if content && !h.mayGiveUntestedText(w, r, user) {
		return
	}
	keys, err := h.APIKeys.List(ctx, user.TenantID.String())
	if err != nil {
		h.log().Error("could not list api keys for a token", "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not record the token")
		return
	}
	i := slices.IndexFunc(keys, func(k store.APIKeyInfo) bool { return k.Prefix == in.KeyPrefix })
	if i < 0 {
		fail(w, http.StatusNotFound, "not_found", "no such key in this workspace")
		return
	}
	if !keys[i].DevicesRestricted || len(keys[i].DeviceIDs) == 0 {
		fail(w, http.StatusUnprocessableEntity, "key_unsuitable", "the key must be restricted to named numbers")
		return
	}
	in.DeviceCount = len(keys[i].DeviceIDs)
	in.Reader, in.ReaderMeasurement = rd.id, entry.measurement()
	if content {
		in.ReaderPublicKey = append([]byte(nil), entry.publicKey...)
	}
	conn, err := h.Connections.Create(ctx, user.TenantID, user.ID, in)
	if err != nil {
		h.connectionError(w, err)
		return
	}
	relay := TokenBundleRelay{
		ConnectionID: conn.ID, TenantID: conn.TenantID, KID: in.ReaderKID, Sealed: req.Sealed, ExpiresAt: conn.ExpiresAt,
		Kind: in.Kind, HistoryDays: in.HistoryDays, Media: in.Media,
	}
	if err := rd.attested.Relay.TokenBundle(ctx, id, relay); err != nil {
		if derr := h.Connections.DeleteFailed(context.WithoutCancel(ctx), conn.ID); derr != nil && !errors.Is(derr, store.ErrMCPConnectionNotFound) {
			h.log().Error("could not undo a token the reader did not take", "connection", conn.ID, "error", derr)
		}
		h.log().Warn("the reader did not take a token's bundle", "connection", conn.ID, "error", err)
		h.tokenReaderError(w, err)
		return
	}
	status, err := h.Connections.StatusOf(ctx, user.TenantID, conn.ID)
	if err != nil {
		h.log().Error("could not read a token back", "connection", conn.ID, "error", err)
		fail(w, http.StatusInternalServerError, "internal", "the token was recorded; reload the list")
		return
	}
	h.log().Info("mcp token consented", "connection", conn.ID, "devices", in.DeviceCount, "expires_at", conn.ExpiresAt, "reader", rd.id,
		"kind", in.Kind, "media", in.Media, "history_days", in.HistoryDays, "status", status)
	send(w, http.StatusCreated, renewReply{ID: conn.ID, Status: status, ExpiresAt: conn.ExpiresAt})
}

// tokenReaderError maps the reader's answer to a token's bundle: a 400
// passes with its code, the reader's own cap of untested connections with
// its, and anything else is 502.
func (h *Handler) tokenReaderError(w http.ResponseWriter, err error) {
	var refusal *RefusalError
	switch {
	case errors.As(err, &refusal) && refusal.Code == "too_many_unknown":
		fail(w, http.StatusConflict, "too_many_unknown", "this workspace already has as many untested assistants and tokens as it may; revoke one first")
	case errors.As(err, &refusal) && refusal.Status == http.StatusBadRequest && codePattern.MatchString(refusal.Code):
		fail(w, http.StatusBadRequest, refusal.Code, "the reader refused the token; see the code, then start again")
	default:
		h.log().Warn("the reader is unavailable for a token's bundle", "error", err)
		fail(w, http.StatusBadGateway, "reader_unavailable", "the assistant connector is not answering; try again in a moment")
	}
}

// ---------------------------------------------------------------------------
// The signed relay's calls
// ---------------------------------------------------------------------------

// TokenRequest asks the reader for a pending token request over the
// browser's nonce. The bytes come back as the reader sent them.
func (c *SignedRelay) TokenRequest(ctx context.Context, nonce string) (json.RawMessage, error) {
	status, body, err := c.do(ctx, http.MethodPost, "/internal/token-requests", prepareRequest{Nonce: nonce})
	if err != nil {
		return nil, err
	}
	switch status {
	case http.StatusTooManyRequests:
		return nil, ErrTooManyPrepares
	case http.StatusBadRequest:
		return nil, &RefusalError{Code: readerCode(body), Status: status}
	case http.StatusServiceUnavailable:
		return nil, fmt.Errorf("%w: token request answered 503 %s", ErrReaderUnavailable, readerCode(body))
	}
	return descriptorAnswer(status, body)
}

// TokenBundle hands the reader a token's sealed bundle and waits while it
// proves the grants, installs the token and activates the connection.
func (c *SignedRelay) TokenBundle(ctx context.Context, requestID string, in TokenBundleRelay) error {
	ctx, cancel := context.WithTimeout(ctx, tokenBundleTimeout)
	defer cancel()
	client := c.patient()
	client.Timeout = tokenBundleTimeout
	status, body, err := c.doWith(ctx, client, http.MethodPost, "/internal/token-requests/"+url.PathEscape(requestID)+"/bundle", in)
	if err != nil {
		return err
	}
	return bundleAnswer(status, body)
}
