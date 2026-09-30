package mcpauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/store"
)

// AI integrations (docs/mcp-enclave.md §18): the Go side of an AI
// authorization. The console asks the enclave for a pending AI request
// through this server, seals the AI bundle to the key it attested, and
// consents here with the configuration's mirror; this server checks the
// mirror, records the row and hands the enclave the bundle, which checks
// every tag, key and model before it answers. It never sees a key or a word
// of the content, and it can only narrow what the bundle says: the switches,
// a pause, functions off, a lower cap.

// aiAllowed reports whether a workspace may have AI authorizations with this
// reader right now: attachments are allowed, and so is AI, behind its own
// switch and list (docs/mcp-enclave.md §18.4).
func (h *Handler) aiAllowed(rd reader, tenant uuid.UUID) bool {
	return h.mediaAllowed(rd, tenant) && h.AIAllowed != nil && h.AIAllowed(tenant)
}

// AIAllowedFor is aiAllowed for the content reader: what the console is
// told, and what every AI route asks.
func (h *Handler) AIAllowedFor(tenant uuid.UUID) bool {
	rd, ok := h.readerByID(h.ContentReader)
	return ok && h.aiAllowed(rd, tenant)
}

// AIPolicy is what the switches say for a workspace, for PickAIAuthorization.
func (h *Handler) AIPolicy(tenant uuid.UUID) store.AIPolicy {
	return store.AIPolicy{Allowed: h.AIAllowedFor(tenant), OffFeatures: h.AIOffFeatures, OffProviders: h.AIOffProviders}
}

// ---------------------------------------------------------------------------
// The request
// ---------------------------------------------------------------------------

// aiPrepared is the part of a prepared AI descriptor this server reads.
type aiPrepared struct {
	preparedDescriptor
	Kind string `json:"kind"`
}

// checkPreparedAI reads what the reader attested for a pending AI request
// and checks its shape: an AI request, a request id of the right shape,
// this reader's resource, the full per-request key, and an attestation over
// the request id. The id comes back with the entry to remember under it.
func checkPreparedAI(raw json.RawMessage, rd reader) (string, requestEntry, error) {
	var p aiPrepared
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", requestEntry{}, errors.New("the AI request is not the expected object")
	}
	if p.Kind != store.KindAI || !validRequestID(p.RequestID) || p.Resource != rd.resource() {
		return "", requestEntry{}, errors.New("the AI request is of another kind or resource, or its id is malformed")
	}
	if p.Attestation != nil && p.Attestation.RequestID != p.RequestID {
		return "", requestEntry{}, errors.New("the AI request's attestation is for another request")
	}
	e, err := p.entry(rd, true)
	if err != nil {
		return "", requestEntry{}, err
	}
	e.kind = store.KindAI
	return p.RequestID, e, nil
}

// PrepareAI asks the content reader for a pending AI request over the
// browser's nonce, checks its shape, and remembers it for this person only:
// the consent that answers it must be theirs. The reader's bytes come back
// as it sent them. The caller has checked who may ask.
func (h *Handler) PrepareAI(ctx context.Context, tenant, user uuid.UUID, nonce string) (json.RawMessage, error) {
	rd, ok := h.readerByID(h.ContentReader)
	if !ok || rd.attested == nil {
		return nil, ErrReaderUnavailable
	}
	raw, err := rd.attested.Relay.AIRequest(ctx, nonce)
	if err != nil {
		return nil, err
	}
	id, entry, err := checkPreparedAI(raw, rd)
	if err != nil {
		h.log().Warn("an attested reader answered an AI request with the wrong shape", "reader", rd.id, "error", err)
		return nil, ErrReaderUnavailable
	}
	entry.user = user
	h.requests.put(id, entry, time.Now())
	h.log().Info("mcp ai request prepared", "reader", rd.id, "pcr0", entry.pcr0[:12], "document", entry.documentSHA256[:12])
	return raw, nil
}

// ---------------------------------------------------------------------------
// The consent
// ---------------------------------------------------------------------------

// checkAICreate validates the shape of an AI consent: a content consent's
// fields as the AI card has them, consent version 1, no media and no
// sending, and an ai_config that parses and names this consent.
func checkAICreate(w http.ResponseWriter, req createRequest) (store.CreateMCPConnection, bool) {
	bad := func(msg string) (store.CreateMCPConnection, bool) {
		fail(w, http.StatusBadRequest, "bad_request", msg)
		return store.CreateMCPConnection{}, false
	}
	switch {
	case !validRequestID(req.RequestID):
		return bad("request_id must be 22 base64url characters")
	case len(req.KeyPrefix) != prefixLen || !isHex(req.KeyPrefix):
		return bad("key_prefix must be the 8 hex characters before the dot")
	case len(req.KID) != kidLen || !isHex(req.KID):
		return bad("kid must be 16 hex characters")
	case req.ClientName != "" && req.ClientName != store.AIClientName:
		return bad("an AI authorization's client_name is " + store.AIClientName)
	case req.KeyMode != store.KeyModeEphemeral:
		return bad("key_mode must be ephemeral")
	case req.ConsentVersion != store.AIConsentVersion:
		return bad("an AI authorization's consent_version is 1")
	case req.Media || req.Send != "" || req.SendSelf || req.SendGroups || len(req.SendChats) > 0:
		return bad("an AI authorization carries no media and no sending")
	case len(req.AIConfig) == 0:
		return bad("ai_config is required")
	}
	service, err := uuid.Parse(req.ServiceUserID)
	if err != nil || len(req.ServiceUserID) != 36 || service == uuid.Nil {
		return bad("service_user_id must be the authorization's service account id")
	}
	at, err := time.Parse(time.RFC3339, req.ExpiresAt)
	if err != nil {
		return bad("expires_at must be an RFC 3339 timestamp")
	}
	if now := time.Now(); !at.After(now) || at.After(now.Add(maxContentLifetime)) {
		return bad("an AI authorization's expires_at must be in the future and within 90 days")
	}
	if sealed, err := base64.RawURLEncoding.DecodeString(req.Sealed); err != nil || len(sealed) < minSealedLen {
		return bad("sealed must be the unpadded base64url of the sealed bundle")
	}
	cfg, err := store.ParseAIConfig(req.AIConfig)
	if err != nil {
		return bad(aiConfigMessage(err))
	}
	cfg.Raw = append(json.RawMessage(nil), req.AIConfig...)
	return store.CreateMCPConnection{
		RequestID: req.RequestID, KeyPrefix: req.KeyPrefix, ClientName: store.AIClientName, RedirectHost: store.AIRedirectHost,
		ReaderKID: req.KID, ExpiresAt: at.UTC(), Kind: store.KindAI, ServiceUserID: service, KeyMode: req.KeyMode,
		ConsentVersion: req.ConsentVersion, AIConfig: &cfg,
	}, true
}

// aiRefusals are the enclave's refusals of an AI bundle that reach the
// console with their code; anything else is the reader being unavailable.
var aiRefusals = []string{"invalid_bundle", "grant_proof_failed", "ai_key_rejected", "ai_model_unavailable"}

// createAI records an AI authorization and hands the enclave its bundle
// (docs/mcp-enclave.md §18.7 step 5). The request must be one this process
// prepared for this person; AI must be allowed; none of the configuration's
// functions or providers may be off; the key, the service account and the
// configuration are held to the store's rules in one transaction;
// and only then is the bundle relayed, with a 30-second wait. A refusal
// undoes the consent.
func (h *Handler) createAI(w http.ResponseWriter, r *http.Request, user store.User, req createRequest) {
	in, ok := checkAICreate(w, req)
	if !ok {
		return
	}
	ctx := r.Context()
	entry, ok := h.requests.get(in.RequestID, time.Now())
	rd, known := h.readerByID(entry.reader)
	if !ok || !entry.prepared || entry.kind != store.KindAI || entry.user != user.ID || entry.kid != in.ReaderKID ||
		entry.connection != "" || len(entry.publicKey) != readerPublicKeyLen || !known || rd.attested == nil || rd.id != h.ContentReader {
		fail(w, http.StatusConflict, "attestation_required", "this AI request must be verified by you first; start the integration again")
		return
	}
	if !h.aiAllowed(rd, user.TenantID) {
		fail(w, http.StatusForbidden, "ai_not_allowed", "AI integrations are not enabled for this workspace")
		return
	}
	if in.AIConfig.FunctionsOff(h.AIOffFeatures, h.AIOffProviders) {
		// Part of the configuration's checks: 400, as its other refusals.
		fail(w, http.StatusBadRequest, "bad_request", "a function or provider this integration uses is switched off here")
		return
	}
	keys, err := h.APIKeys.List(ctx, user.TenantID.String())
	if err != nil {
		h.log().Error("could not list api keys for an AI consent", "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not record the consent")
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
	in.ReaderPublicKey = append([]byte(nil), entry.publicKey...)

	conn, err := h.Connections.Create(ctx, user.TenantID, user.ID, in)
	if err != nil {
		h.aiConnectionError(w, err)
		return
	}
	relay := BundleRelay{
		ConnectionID: conn.ID, TenantID: conn.TenantID, KID: in.ReaderKID, Sealed: req.Sealed, ExpiresAt: conn.ExpiresAt,
		Kind: store.KindAI,
	}
	if err := rd.attested.Relay.AIBundle(ctx, in.RequestID, relay); err != nil {
		if derr := h.Connections.DeleteFailed(context.WithoutCancel(ctx), conn.ID); derr != nil {
			h.log().Error("could not undo an AI consent the reader did not take", "connection", conn.ID, "error", derr)
		}
		h.log().Warn("the reader did not take an AI bundle", "connection", conn.ID, "error", err)
		h.aiReaderError(w, err)
		return
	}
	h.log().Info("mcp ai authorization consented", "connection", conn.ID, "devices", in.DeviceCount, "expires_at", conn.ExpiresAt,
		"reader", rd.id, "functions", len(in.AIConfig.Functions))
	a, err := h.Connections.AIAuthorization(ctx, user.TenantID, conn.ID)
	if err != nil {
		h.log().Error("could not read an AI authorization back", "connection", conn.ID, "error", err)
		fail(w, http.StatusInternalServerError, "internal", "the authorization was recorded; reload the list")
		return
	}
	send(w, http.StatusCreated, ListedAIAuthorization(a, user.ID, true, time.Now()))
}

// aiConnectionError is connectionError with the configuration's refusals.
func (h *Handler) aiConnectionError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrAIConfig) {
		fail(w, http.StatusBadRequest, "bad_request", aiConfigMessage(err))
		return
	}
	h.connectionError(w, err)
}

// aiConfigMessage is what is wrong with an ai_config, in the store's words
// without its prefix.
func aiConfigMessage(err error) string {
	return strings.TrimPrefix(err.Error(), store.ErrAIConfig.Error()+": ")
}

// aiReaderError maps the enclave's answer to an AI bundle: its own refusals
// pass as 400 with their code, anything else is 502.
func (h *Handler) aiReaderError(w http.ResponseWriter, err error) {
	var refusal *RefusalError
	if errors.As(err, &refusal) && slices.Contains(aiRefusals, refusal.Code) {
		fail(w, http.StatusBadRequest, refusal.Code, "the reader refused the AI integration; see the code, then start again")
		return
	}
	h.log().Warn("the reader is unavailable for an AI bundle", "error", err)
	fail(w, http.StatusBadGateway, "reader_unavailable", "the reader is not answering; try again in a moment")
}

// ---------------------------------------------------------------------------
// The listing
// ---------------------------------------------------------------------------

// AIAuthorizationInfo is one AI authorization as the console lists it
// (GET /v1/ai/authorizations): its configuration's mirror, what narrows it
// and where it stands. Nothing in it is a key.
type AIAuthorizationInfo struct {
	ID           string          `json:"id"`
	CreatedBy    string          `json:"created_by"`
	Status       string          `json:"status"`
	ExpiresAt    time.Time       `json:"expires_at"`
	DeviceCount  int             `json:"device_count"`
	AIConfig     json.RawMessage `json:"ai_config"`
	Paused       bool            `json:"paused"`
	Off          []string        `json:"off"`
	CapTokens    *int64          `json:"cap_tokens"`
	Alerts       []store.AIAlert `json:"alerts"`
	RevokeReason *string         `json:"revoke_reason"`
	Renewable    bool            `json:"renewable"`
	CreatedAt    time.Time       `json:"created_at"`
}

// ListedAIAuthorization shapes an authorization for viewer, with AI allowed
// or not for the workspace right now. An active or resealed one past its
// deadline is listed expired, as the reader is told; it is renewable by its
// creator while it is live and AI is allowed.
func ListedAIAuthorization(a store.AIAuthorization, viewer uuid.UUID, allowed bool, now time.Time) AIAuthorizationInfo {
	status := a.Status
	if (status == "active" || status == "reseal") && !a.ExpiresAt.After(now) {
		status = "expired"
	}
	info := AIAuthorizationInfo{
		ID: a.ID, CreatedBy: a.CreatedBy.String(), Status: status, ExpiresAt: a.ExpiresAt.UTC(), DeviceCount: a.DeviceCount,
		AIConfig: a.Config, Paused: a.PausedAt != nil, Off: a.Off, CapTokens: a.CapTokens, Alerts: a.Alerts,
		Renewable: (status == "active" || status == "reseal") && a.CreatedBy == viewer && allowed, CreatedAt: a.CreatedAt.UTC(),
	}
	if info.Off == nil {
		info.Off = []string{}
	}
	if info.Alerts == nil {
		info.Alerts = []store.AIAlert{}
	}
	if a.RevokeReason != "" {
		info.RevokeReason = &a.RevokeReason
	}
	return info
}

// ---------------------------------------------------------------------------
// The status
// ---------------------------------------------------------------------------

// aiOff is what an AI row's status says is narrowed: the functions off (the
// switches', the row's own, and those whose provider is off), the providers
// off, the pause and the cap in tokens.
type aiOff struct {
	Functions     []string `json:"functions"`
	Providers     []string `json:"providers"`
	Paused        bool     `json:"paused"`
	MonthlyTokens *int64   `json:"monthly_tokens"`
}

// aiStatusReply answers the enclave's standing check for an AI row: the
// content answer's first fields, never media, and ai_off.
type aiStatusReply struct {
	Status        string    `json:"status"`
	ExpiresAt     time.Time `json:"expires_at"`
	Kind          string    `json:"kind"`
	ServiceUserID *string   `json:"service_user_id"`
	Media         bool      `json:"media"`
	MediaOff      []string  `json:"media_off"`
	AIOff         aiOff     `json:"ai_off"`
}

// aiStanding shapes an AI row's standing: the switches' and the row's
// narrowing, whatever the status.
func aiStanding(a store.StatusAnswer, mediaOff, offFeatures, offProviders []string) aiStatusReply {
	reply := aiStatusReply{Status: a.Status, ExpiresAt: a.ExpiresAt.UTC(), Kind: store.KindAI, MediaOff: []string{},
		AIOff: aiOff{Functions: []string{}, Providers: []string{}, Paused: a.AIPaused, MonthlyTokens: a.AICapTokens}}
	if a.ServiceUserID != nil {
		service := a.ServiceUserID.String()
		reply.ServiceUserID = &service
	}
	reply.MediaOff = append(reply.MediaOff, mediaOff...)
	reply.AIOff.Providers = append(reply.AIOff.Providers, offProviders...)
	if a.AIConfig != nil {
		reply.AIOff.Functions = a.AIConfig.OffFunctions(offFeatures, offProviders, a.AIOff)
	} else {
		reply.AIOff.Functions = store.AIConfig{}.OffFunctions(offFeatures, offProviders, a.AIOff)
	}
	return reply
}

// ---------------------------------------------------------------------------
// For the /v1/ai routes
// ---------------------------------------------------------------------------

// TellRevoked tells a connection's reader it ended, and records the notice;
// one that does not arrive is repeated by WatchRevocations.
func (h *Handler) TellRevoked(ctx context.Context, readerID, id string) {
	h.tellRevoked(ctx, readerID, id)
}

// StartAIJob hands the content reader a console's job.
func (h *Handler) StartAIJob(ctx context.Context, in AIJobRequest) (AIJobStarted, error) {
	rd, ok := h.readerByID(h.ContentReader)
	if !ok || rd.attested == nil {
		return AIJobStarted{}, ErrReaderUnavailable
	}
	return rd.attested.Relay.AIJob(ctx, in)
}

// AIJobStatus asks the content reader for a job's state, for its requester.
func (h *Handler) AIJobStatus(ctx context.Context, job string, requester uuid.UUID) (AIJobState, error) {
	rd, ok := h.readerByID(h.ContentReader)
	if !ok || rd.attested == nil {
		return AIJobState{}, ErrReaderUnavailable
	}
	return rd.attested.Relay.AIJobStatus(ctx, job, requester.String())
}
