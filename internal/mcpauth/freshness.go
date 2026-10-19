package mcpauth

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/membership"
)

// The contract's freshness hook at the connector's gated acts (README 7.1;
// design 2.6, "creating an API key, a standing service account, or an MCP
// or AI connection", "renewing an MCP connection", "MCP sends, by the
// consenting person's freshness"; the plan's 4.12): each rare act widens
// access, so it asks in a personal workspace too, before its store
// transaction and before any bundle reaches a reader; a send, a team
// number's act, is checked in the background on the stored freshness only,
// as the socket's sends are (wsapi's freshAtAct): once a minute per
// connection and number, and never past sendChecksInFlight at once.
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

const (
	// sendCheckBound bounds a send's background check.
	sendCheckBound = 5 * time.Second
	// sendChecksInFlight bounds the background checks running at once,
	// across the process; one past it is skipped, never waited for.
	sendChecksInFlight = 16
	// sendCheckEvery is how often one connection's sends from one number
	// are checked: a stale verdict lasts at least that long, and a stream
	// of sends must not become a stream of queries.
	sendCheckEvery = time.Minute
)

// fresh asks the hook for an act in tenant; false when it is refused,
// which is answered.
func (h *Handler) fresh(ctx context.Context, w http.ResponseWriter, act string, tenant uuid.UUID, parties ...membership.Party) bool {
	if h.Membership == nil {
		return true
	}
	if _, err := h.Membership.RequireWidening(ctx, act, tenant, parties...); err != nil {
		w.Header().Set("Retry-After", "60")
		fail(w, http.StatusServiceUnavailable, "memberships_unconfirmed",
			"could not confirm the memberships with The Happie Co; nothing changed, try again in a minute")
		return false
	}
	return true
}

// sendChecks are the sends' background checks: the slots in flight and,
// by connection and number, when each was last checked. Set up by Mount.
type sendChecks struct {
	slots chan struct{}
	mu    sync.Mutex
	seen  map[string]time.Time
}

func newSendChecks() *sendChecks {
	return &sendChecks{slots: make(chan struct{}, sendChecksInFlight), seen: map[string]time.Time{}}
}

// start takes a slot for key's check, unless key was checked within
// sendCheckEvery or every slot is taken; the caller gives the slot back.
func (c *sendChecks) start(key string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if last, ok := c.seen[key]; ok && now.Sub(last) < sendCheckEvery {
		return false
	}
	select {
	case c.slots <- struct{}{}:
	default:
		return false
	}
	for k, at := range c.seen {
		if now.Sub(at) >= sendCheckEvery {
			delete(c.seen, k)
		}
	}
	c.seen[key] = now
	return true
}

// freshAtSend checks a connection's send from device in the background, on
// its consenting person's stored freshness (membership.Stored): no call,
// and the send goes on whatever the verdict, which the hook logs. One
// connection's sends from one number are checked once every
// sendCheckEvery, and a check past sendChecksInFlight is skipped. The
// enforce release gives it a synchronous GET instead (the plan's 4.9).
func (h *Handler) freshAtSend(ctx context.Context, conn string, tenant, device, consenting uuid.UUID) {
	m := h.Membership
	if m == nil || h.sendChecks == nil {
		return
	}
	if !h.sendChecks.start(conn+"/"+device.String(), time.Now()) {
		return
	}
	// Past the request's own end: the check finishes, bounded, after the
	// send is answered.
	check, cancel := context.WithTimeout(context.WithoutCancel(ctx), sendCheckBound)
	go func() {
		defer func() { <-h.sendChecks.slots }()
		defer cancel()
		_, _ = m.RequireFresh(check, actSend, tenant, membership.Party{User: consenting, How: membership.Stored}) //nolint:errcheck // logged by the hook; a send never waits on it
	}()
}
