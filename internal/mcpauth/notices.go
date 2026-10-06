package mcpauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"whatserver2/internal/mailer"
	"whatserver2/internal/store"
)

// The new-assistant notice (docs/mcp-enclave.md §19.22). It is raised by
// every activation of an assistant's connection or a console token and by
// every reading limit a reader says a connection reached. Raising it records
// the event and clears the managers' seen marks, so the console's banner
// shows the connection again; its e-mail goes once per connection and event,
// at most twenty a day per workspace, to the person who consented and the
// owners with a verified address, carrying a revoke-only link of its own,
// which works beside the connection's earlier ones until one is used or the
// connection ends. The e-mail goes after the answer: a reader's activation
// or budget_hit never waits on a mail server.

// noticeMailTimeout bounds one notice's e-mails, every recipient included.
const noticeMailTimeout = 2 * time.Minute

// announce raises a notice for one of a reader's connections and sends its
// e-mail in the background. A failure is logged and changes nothing for the
// caller: the connection is already what it is.
func (h *Handler) announce(ctx context.Context, readerID, id, event string) {
	n, err := h.Connections.RaiseNotice(ctx, readerID, id, event)
	if err != nil {
		if !errors.Is(err, store.ErrMCPConnectionNotFound) {
			h.log().Warn("could not raise an mcp notice", "connection", id, "event", event, "error", err)
		}
		return
	}
	h.raised(ctx, readerID, n)
}

// raised logs a notice and, the first time a connection raises its event,
// sends its e-mail after the caller has answered.
func (h *Handler) raised(ctx context.Context, readerID string, n store.MCPNotice) {
	h.log().Info("mcp notice raised", "connection", n.ConnectionID, "reader", readerID, "event", n.Event, "client_host", n.ClientHost,
		"trust", n.Trust, "client_kind", n.ClientKind, "first", n.First)
	if !n.First || !h.noticesReady() || len(n.Recipients) == 0 {
		return
	}
	h.notices.Go(func() {
		mailCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), noticeMailTimeout)
		defer cancel()
		h.mailNotice(mailCtx, n)
	})
}

// mailNotice claims a notice's e-mail and sends it to each recipient.
func (h *Handler) mailNotice(ctx context.Context, n store.MCPNotice) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		h.log().Error("could not draw a revoke link", "error", err)
		return
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	claimed, err := h.Connections.ClaimNoticeMail(ctx, n.TenantID, n.ConnectionID, n.Event, revokeLinkHash(token))
	if err != nil {
		h.log().Warn("could not claim a notice e-mail", "connection", n.ConnectionID, "event", n.Event, "error", err)
		return
	}
	if !claimed {
		// Already sent for this event, the day's twenty are gone, or the
		// connection ended meanwhile; the banner still shows it.
		h.log().Info("a notice e-mail was not sent", "connection", n.ConnectionID, "event", n.Event)
		return
	}
	notice := mailer.MCPNotice{
		Event: n.Event, ClientHost: n.ClientHost, Workspace: n.Workspace, Tier: noticeTier(n), Numbers: n.DeviceCount,
		Text: n.Kind == store.KindContent, Attachments: n.Kind == store.KindContent && n.Media,
		HistoryDays: n.HistoryDays, ExpiresAt: n.ExpiresAt, At: time.Now(),
		RevokeLink: strings.TrimRight(h.NoticeOrigin, "/") + revokeLinkPath + token,
		// The recipient's preferred locale would choose the language; accounts
		// carry none on this server (the console keeps its language in the
		// browser), so every notice goes in English (§19.22).
		Lang: "",
	}
	// A token is named by its label, the admin's own words; it has no host.
	if n.ClientKind == store.ClientToken {
		notice.ClientHost, notice.Label = "", n.ClientName
	}
	sent := 0
	for _, to := range n.Recipients {
		if err := h.MailNotice(ctx, to, notice); err != nil {
			// The address is the recipient's; the error is the mail
			// server's, and neither carries the link.
			h.log().Warn("a notice e-mail was not delivered", "connection", n.ConnectionID, "event", n.Event, "error", err)
			continue
		}
		sent++
	}
	h.log().Info("notice e-mails sent", "connection", n.ConnectionID, "event", n.Event, "recipients", sent)
}

// noticeTier is how an e-mail names a connection's tier.
func noticeTier(n store.MCPNotice) string {
	switch {
	case n.ClientKind == store.ClientToken:
		return "token"
	case n.Trust == store.TrustUnknown:
		return "unknown"
	case n.ClientLocal:
		return "local"
	}
	return "tested"
}

// revokeLinkHash is how a revoke-only link is stored: the SHA-256 of its
// token, in lower-case hex.
func revokeLinkHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// WaitNotices waits for the notice e-mails on their way.
func (h *Handler) WaitNotices() { h.notices.Wait() }

// ---------------------------------------------------------------------------
// The console's seen mark
// ---------------------------------------------------------------------------

// seen marks one of the workspace's connections seen by the viewer, for the
// new-assistant banner. Any member who may list may mark; idempotent.
func (h *Handler) seen(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	id, ok := connectionID(w, r)
	if !ok {
		return
	}
	if err := h.Connections.MarkSeen(r.Context(), user.TenantID, user.ID, id); err != nil {
		h.connectionError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// The reader's budget_hit
// ---------------------------------------------------------------------------

// budgetHitBody is a reader's word that a connection reached a reading
// limit: the code and nothing else.
type budgetHitBody struct {
	Code string `json:"code"`
}

// budgetHit records that one of the calling reader's connections reached a
// reading limit (§19.19), and raises the notice. Another reader's, an ended
// one and an unknown id are 404; anything but {"code": <a budget_hit code>}
// is 400.
func (h *Handler) budgetHit(w http.ResponseWriter, r *http.Request, caller *AttestedReader, body []byte) {
	id, ok := connectionID(w, r)
	if !ok {
		return
	}
	var in budgetHitBody
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil || dec.Decode(&struct{}{}) != io.EOF || !slices.Contains(store.BudgetHitCodes, in.Code) {
		fail(w, http.StatusBadRequest, "bad_request", `the body must be {"code": one of `+strings.Join(store.BudgetHitCodes, ", ")+`}`)
		return
	}
	n, err := h.Connections.RaiseNotice(r.Context(), caller.ID, id, in.Code)
	if err != nil {
		h.connectionError(w, err)
		return
	}
	h.raised(r.Context(), caller.ID, n)
	w.WriteHeader(http.StatusNoContent)
}
