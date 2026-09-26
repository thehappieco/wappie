package mcpauth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/store"
)

// Content connections: message text, chat and contact names and filenames,
// opened only inside the attested reader.
//
// This server decides who may have one and keeps the ledger honest; it never
// sees a key or a word of text. Content is allowed for a consent only when
// the request's reader is the content reader and attested, this process
// served its prepare, the kill switch is on and the workspace is listed.
// The same test answers the reader's status checks, so switching content off
// reaches live connections within a minute: their status reads 'reseal', the
// reader drops the key, and the consent waits for the switch to come back.

// contentAllowed reports whether a workspace may have content connections
// with this reader right now.
func (h *Handler) contentAllowed(rd reader, tenant uuid.UUID) bool {
	return rd.attested != nil && h.ContentReader != "" && rd.id == h.ContentReader &&
		rd.attested.allows(tenant) && h.ContentAllowed != nil && h.ContentAllowed(tenant)
}

// contentEnabledFor reports whether a workspace may consent to content at
// all, which is what the console asks before it shows the toggle.
func (h *Handler) contentEnabledFor(tenant uuid.UUID) bool {
	rd, ok := h.readerByID(h.ContentReader)
	return ok && h.contentAllowed(rd, tenant)
}

type contentReply struct {
	Enabled bool `json:"enabled"`
}

// content answers the console: may this workspace let an assistant read
// message text? The console shows the toggle only when this says so, the
// discovery document advertises it and an attestation for the request
// verified; none of them alone is enough.
func (h *Handler) content(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	send(w, http.StatusOK, contentReply{Enabled: h.contentEnabledFor(user.TenantID)})
}

// ---------------------------------------------------------------------------
// Renewal
// ---------------------------------------------------------------------------

// renewal asks a content connection's reader for a new, attested key: the
// reader restarted and lost the old one, or the person wants to. Only the
// person who consented, still an owner or admin, may renew, and only while
// content is allowed. Rate-limited like a prepare, which it is for an
// existing connection. The reader's answer is relayed verbatim after a shape
// check, and what it attested is remembered under the renewal id.
func (h *Handler) renewal(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	id, ok := connectionID(w, r)
	if !ok {
		return
	}
	if !allow(w, r, h.DescriptorLimits, "renewal:"+id) {
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
	ctx := r.Context()
	conn, err := h.Connections.Renewable(ctx, user.TenantID, user.ID, id)
	if err != nil {
		h.connectionError(w, err)
		return
	}
	rd, known := h.readerByID(conn.Reader)
	if !known || rd.attested == nil {
		fail(w, http.StatusNotFound, "not_found", "no such key or connection in this workspace")
		return
	}
	if !h.contentAllowed(rd, user.TenantID) {
		fail(w, http.StatusForbidden, "content_not_allowed", "this workspace may not let an assistant read message text right now")
		return
	}
	raw, err := rd.attested.Relay.Renewal(ctx, id, req.Nonce)
	if errors.Is(err, ErrTooManyPrepares) {
		fail(w, http.StatusTooManyRequests, "too_many_prepares", "this connection has been renewed too many times in the last hour; try again later")
		return
	}
	if err != nil {
		h.readerError(w, err)
		return
	}
	renewalID, entry, err := checkRenewal(raw, id, rd)
	if err != nil {
		h.log().Warn("an attested reader answered a renewal with the wrong shape", "reader", rd.id, "connection", id, "error", err)
		fail(w, http.StatusBadGateway, "reader_unavailable", "the assistant connector answered with something unexpected; try again in a moment")
		return
	}
	h.requests.put(renewalID, entry, time.Now())
	h.log().Info("mcp renewal prepared", "connection", id, "reader", rd.id, "pcr0", entry.pcr0[:12], "document", entry.documentSHA256[:12])
	sendRaw(w, raw)
}

// renewRequest is the console's renewal: the new key and service account,
// and the bundle sealed to the key the renewal attested.
type renewRequest struct {
	RenewalID     string `json:"renewal_id"`
	KeyPrefix     string `json:"key_prefix"`
	ServiceUserID string `json:"service_user_id"`
	KID           string `json:"kid"`
	Sealed        string `json:"sealed"`
}

type renewReply struct {
	ID        string    `json:"id"`
	Status    string    `json:"status"`
	ExpiresAt time.Time `json:"expires_at"`
}

// renew records a renewal. The order mirrors create's: the renewal must be
// one this process prepared for this connection with this kid; the new key
// and account are checked before the reader is bothered; the reader takes
// the bundle, proves every grant opens and stages the key; and only then
// does the ledger swap the key and account, in one transaction. A reader
// that refuses leaves the old connection as it was, and the new account is
// removed so nothing it was given outlives the attempt.
func (h *Handler) renew(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	id, ok := connectionID(w, r)
	if !ok {
		return
	}
	if !allow(w, r, h.Limits, user.ID.String()) {
		return
	}
	var req renewRequest
	if !decode(w, r, &req) {
		return
	}
	service, err := uuid.Parse(req.ServiceUserID)
	switch {
	case !validRequestID(req.RenewalID):
		fail(w, http.StatusBadRequest, "bad_request", "renewal_id must be 22 base64url characters")
		return
	case len(req.KeyPrefix) != prefixLen || !isHex(req.KeyPrefix):
		fail(w, http.StatusBadRequest, "bad_request", "key_prefix must be the 8 hex characters before the dot")
		return
	case err != nil || len(req.ServiceUserID) != 36 || service == uuid.Nil:
		fail(w, http.StatusBadRequest, "bad_request", "service_user_id must be the new service account's id")
		return
	case len(req.KID) != kidLen || !isHex(req.KID):
		fail(w, http.StatusBadRequest, "bad_request", "kid must be 16 hex characters")
		return
	}
	if sealed, err := base64.RawURLEncoding.DecodeString(req.Sealed); err != nil || len(sealed) < minSealedLen {
		fail(w, http.StatusBadRequest, "bad_request", "sealed must be the unpadded base64url of the sealed bundle")
		return
	}
	ctx := r.Context()
	conn, err := h.Connections.Renewable(ctx, user.TenantID, user.ID, id)
	if err != nil {
		h.connectionError(w, err)
		return
	}
	rd, known := h.readerByID(conn.Reader)
	if !known || rd.attested == nil {
		fail(w, http.StatusNotFound, "not_found", "no such key or connection in this workspace")
		return
	}
	if !h.contentAllowed(rd, user.TenantID) {
		fail(w, http.StatusForbidden, "content_not_allowed", "this workspace may not let an assistant read message text right now")
		return
	}
	entry, ok := h.requests.get(req.RenewalID, time.Now())
	if !ok || !entry.prepared || entry.reader != rd.id || entry.connection != id || entry.kid != req.KID {
		fail(w, http.StatusConflict, "attestation_required", "this renewal must be verified first; reload the renewal page")
		return
	}
	in := store.RenewMCPConnection{
		KeyPrefix: req.KeyPrefix, ServiceUserID: service, ReaderKID: req.KID,
		ReaderMeasurement: entry.measurement(), ReaderPublicKey: append([]byte(nil), entry.publicKey...),
	}
	if err := h.Connections.CheckRenewal(ctx, user.TenantID, user.ID, id, in); err != nil {
		h.connectionError(w, err)
		return
	}
	// The expiry is the connection's, unchanged, in UTC as the consent's
	// relay carried it: the reader requires it to equal what it recorded.
	relay := BundleRelay{
		ConnectionID: id, TenantID: user.TenantID.String(), KID: req.KID, Sealed: req.Sealed,
		ExpiresAt: conn.ExpiresAt.UTC(), Kind: store.KindContent,
	}
	if err := rd.attested.Relay.RenewalBundle(ctx, id, req.RenewalID, relay); err != nil {
		h.discardService(ctx, user.TenantID, service, id)
		h.log().Warn("the reader did not take a renewal bundle", "connection", id, "reader", rd.id, "error", err)
		h.readerError(w, err)
		return
	}
	renewed, err := h.Connections.Renew(ctx, user.TenantID, user.ID, id, in)
	if err != nil {
		// Something changed between the check and now. The reader's stage
		// dies with its lifetime; the new account goes now.
		h.discardService(ctx, user.TenantID, service, id)
		h.connectionError(w, err)
		return
	}
	h.log().Info("mcp connection renewed", "connection", id, "reader", rd.id)
	send(w, http.StatusOK, renewReply{ID: id, Status: renewed.Status, ExpiresAt: renewed.ExpiresAt})
}

// discardService removes a renewal's new service account after the renewal
// failed. A failure here is left to the thirty-minute deadline the account
// was born with, which the janitor enforces.
func (h *Handler) discardService(ctx context.Context, tenant, service uuid.UUID, connection string) {
	if err := h.Connections.DiscardService(context.WithoutCancel(ctx), tenant, service); err != nil {
		h.log().Warn("could not remove a renewal's service account", "connection", connection, "error", err)
	}
}

// ---------------------------------------------------------------------------
// The attested reader's routes
// ---------------------------------------------------------------------------

// revokeBody is what an attested reader may say when it ends a connection:
// nothing, or that a token was replayed.
type revokeBody struct {
	Reason string `json:"reason"`
}

// attestedRevoke ends one of an attested reader's connections. The body is
// empty, or {"reason":"reuse_detected"} when a token family died of a
// replayed code or refresh token: someone may hold a copy, and the console
// says so. Anything else is 400.
func (h *Handler) attestedRevoke(w http.ResponseWriter, r *http.Request, caller *AttestedReader, body []byte) {
	reason := store.ReasonReader
	if len(body) > 0 {
		var in revokeBody
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&in); err != nil || in.Reason != store.ReasonReuseDetected || dec.Decode(&struct{}{}) != io.EOF {
			fail(w, http.StatusBadRequest, "bad_request", `the body must be empty or {"reason":"reuse_detected"}`)
			return
		}
		reason = store.ReasonReuseDetected
	}
	h.connectionRevoke(w, r, caller.ID, reason)
}

// reseal records that an attested reader holds no key for one of its
// content connections (it restarted). The connection and its token family
// survive; the person renews in the console.
func (h *Handler) reseal(w http.ResponseWriter, r *http.Request, caller *AttestedReader, _ []byte) {
	id, ok := connectionID(w, r)
	if !ok {
		return
	}
	if err := h.Connections.Reseal(r.Context(), caller.ID, id); err != nil {
		h.connectionError(w, err)
		return
	}
	h.log().Info("mcp connection resealed", "connection", id, "reader", caller.ID)
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Revocation notices
// ---------------------------------------------------------------------------

const (
	// noticeEvery is how often each attested reader is re-told about the
	// ends it has not confirmed. Its own sweep asks about every content
	// connection once a minute; this closes the gap for the rest.
	noticeEvery = 30 * time.Second
	// noticeBatch bounds one round.
	noticeBatch = 100
)

// tellRevoked tells a connection's reader it ended. For an attested reader a
// confirmed notice is recorded, and one that did not arrive is repeated by
// WatchRevocations until it does; the hosted reader's is best effort, as it
// always was, since it re-reads the ledger on every token.
func (h *Handler) tellRevoked(ctx context.Context, readerID, id string) {
	rd, ok := h.readerByID(readerID)
	if !ok {
		h.log().Warn("the reader of a revoked connection is not configured here", "connection", id, "reader", readerID)
		return
	}
	if err := rd.relay.Revoke(ctx, id); err != nil {
		h.log().Warn("the reader was not told about a revocation", "connection", id, "reader", readerID, "error", err)
		return
	}
	if rd.attested != nil {
		if err := h.Connections.MarkNotified(context.WithoutCancel(ctx), readerID, id); err != nil {
			h.log().Warn("could not record a revocation notice", "connection", id, "reader", readerID, "error", err)
		}
	}
}

// WatchRevocations re-tells every attested reader, every thirty seconds,
// about the connections that ended in the last day without its confirming:
// the janitor's expiries, a member's removal, a notice that did not arrive.
func (h *Handler) WatchRevocations(ctx context.Context) {
	for _, a := range h.Attested {
		go h.watchRevocations(ctx, a, noticeEvery)
	}
}

func (h *Handler) watchRevocations(ctx context.Context, a *AttestedReader, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		h.resendRevocations(ctx, a)
	}
}

// resendRevocations sends one round of notices and reports how many the
// reader confirmed.
func (h *Handler) resendRevocations(ctx context.Context, a *AttestedReader) int {
	ids, err := h.Connections.Unnotified(ctx, a.ID, noticeBatch)
	if err != nil {
		if ctx.Err() == nil {
			h.log().Warn("could not list unconfirmed revocations", "reader", a.ID, "error", err)
		}
		return 0
	}
	confirmed := 0
	for _, id := range ids {
		call, cancel := context.WithTimeout(ctx, signedRelayTimeout)
		err := a.Relay.Revoke(call, id)
		cancel()
		if err != nil {
			if ctx.Err() == nil {
				h.log().Info("a revocation notice is still unconfirmed", "reader", a.ID, "connection", id, "error", err)
			}
			// The reader is not answering; the next round tries again.
			break
		}
		if err := h.Connections.MarkNotified(ctx, a.ID, id); err != nil {
			h.log().Warn("could not record a revocation notice", "connection", id, "reader", a.ID, "error", err)
			continue
		}
		confirmed++
	}
	if confirmed > 0 {
		h.log().Info("revocation notices confirmed", "reader", a.ID, "connections", confirmed)
	}
	return confirmed
}
