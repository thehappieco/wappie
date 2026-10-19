package mcpauth

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/membership"
)

// The contract's freshness hook at the connector's gated acts (README 7.1;
// design 2.6, "creating an API key, a standing service account, or an MCP
// or AI connection", "renewing an MCP connection", "MCP sends, by the
// consenting person's freshness"; the plan's 4.12): each rare act asks
// before its store transaction and before any bundle reaches a reader, and
// a send is checked in the background on the stored freshness only.
// Release B only logs the verdicts (DB4); with the enforce flag a refusal
// is 503 memberships_unconfirmed and nothing changes.

// The acts' names in the hook's logs.
const (
	actConnect   = "mcp.connect"
	actToken     = "mcp.token"
	actAIConnect = "ai.connect"
	actRenew     = "mcp.renew"
	actSend      = "mcp.send"
)

// sendCheckBound bounds a send's background check.
const sendCheckBound = 5 * time.Second

// fresh asks the hook for an act in tenant; false when it is refused,
// which is answered.
func (h *Handler) fresh(ctx context.Context, w http.ResponseWriter, act string, tenant uuid.UUID, parties ...membership.Party) bool {
	if h.Membership == nil {
		return true
	}
	if _, err := h.Membership.RequireFresh(ctx, act, tenant, parties...); err != nil {
		w.Header().Set("Retry-After", "60")
		fail(w, http.StatusServiceUnavailable, "memberships_unconfirmed",
			"could not confirm the memberships with The Happie Co; nothing changed, try again in a minute")
		return false
	}
	return true
}

// freshAtSend checks a connection's send in the background, on its
// consenting person's stored freshness (membership.Stored): no call, and
// the send goes on whatever the verdict, which the hook logs. The enforce
// release gives it a synchronous GET instead (the plan's 4.9).
func (h *Handler) freshAtSend(ctx context.Context, tenant, consenting uuid.UUID) {
	m := h.Membership
	if m == nil {
		return
	}
	// Past the request's own end: the check finishes, bounded, after the
	// send is answered.
	check, cancel := context.WithTimeout(context.WithoutCancel(ctx), sendCheckBound)
	go func() {
		defer cancel()
		_, _ = m.RequireFresh(check, actSend, tenant, membership.Party{User: consenting, How: membership.Stored}) //nolint:errcheck // logged by the hook; a send never waits on it
	}()
}
