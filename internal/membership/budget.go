package membership

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
)

// The freshness hook's budget of GETs. The platform answers every call of
// every process rate_limited, unsigned, past 50 requests a second for the
// app (README 3, and 4 step 3, before the signature): a stream of gated
// acts, each with its own GET, would fail the round, the feed, the
// snapshots, the events and every sign-up with them. So the hook's GETs,
// and only theirs, take a token from this process's bucket and from their
// workspace's. The process's leaves room under 50 a second for the
// leader's calls, 10 a second for the round, the sweep and both senders
// together (Members.paced), for the sign-ins and for the feed: the two
// make 20 a second, and 40 in a second that starts with this bucket full;
// the workspace's keeps one team's stream from taking all of it. A GET
// waits for its tokens within its act's bound; one that would not get them
// in time is no answer, throttled, which at observe is only logged.
const (
	hookPerSecond   = 10
	hookBurst       = 20
	tenantPerSecond = 5
	tenantBurst     = 20
)

// errThrottled is a hook's GET that got no place in the budget in time.
var errThrottled = errors.New("membership: the freshness hook's GETs are over their budget")

// callBudget is the process's bucket and each workspace's, with their
// rates (a second) and bursts.
type callBudget struct {
	perSecond, burst             float64
	tenantPerSecond, tenantBurst float64

	mu      sync.Mutex
	all     bucket
	tenants map[uuid.UUID]*bucket
	swept   time.Time
	now     func() time.Time
}

// bucket is a token bucket that may go below zero: a reservation waits
// until its token has come.
type bucket struct {
	tokens float64
	last   time.Time
}

func newCallBudget() *callBudget {
	return &callBudget{perSecond: hookPerSecond, burst: hookBurst, tenantPerSecond: tenantPerSecond, tenantBurst: tenantBurst,
		tenants: map[uuid.UUID]*bucket{}, now: time.Now}
}

// budget is m's, made on first use.
func (m *Members) budget() *callBudget {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.calls == nil {
		m.calls = newCallBudget()
	}
	return m.calls
}

// reserve takes one token, refilled at perSecond up to burst, and says how
// long until it has come (zero when it is there).
func (b *bucket) reserve(now time.Time, perSecond, burst float64) time.Duration {
	if b.last.IsZero() {
		b.tokens, b.last = burst, now
	}
	b.tokens = min(burst, b.tokens+now.Sub(b.last).Seconds()*perSecond)
	b.last = now
	b.tokens--
	if b.tokens >= 0 {
		return 0
	}
	return time.Duration(-b.tokens / perSecond * float64(time.Second))
}

// take spends one of the process's tokens and one of tenant's, waiting for
// them until deadline; errThrottled, with nothing spent, when they would
// not come by then.
func (c *callBudget) take(ctx context.Context, deadline time.Time, tenant uuid.UUID) error {
	c.mu.Lock()
	now := c.now()
	c.sweep(now)
	t := c.tenants[tenant]
	if t == nil {
		t = &bucket{}
		c.tenants[tenant] = t
	}
	wait := max(t.reserve(now, c.tenantPerSecond, c.tenantBurst), c.all.reserve(now, c.perSecond, c.burst))
	if wait > 0 && now.Add(wait).After(deadline) {
		t.tokens++
		c.all.tokens++
		c.mu.Unlock()
		return errThrottled
	}
	c.mu.Unlock()
	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// sweep forgets the workspaces whose buckets are full again, once a
// minute, so the map does not grow with every workspace that ever acted.
func (c *callBudget) sweep(now time.Time) {
	if now.Sub(c.swept) < time.Minute {
		return
	}
	c.swept = now
	full := time.Duration(c.tenantBurst / c.tenantPerSecond * float64(time.Second))
	for id, b := range c.tenants {
		if now.Sub(b.last) > full {
			delete(c.tenants, id)
		}
	}
}
