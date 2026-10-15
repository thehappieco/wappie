package membership

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// The round and the sweep (the plan's 4.6): the round subscribes everyone
// Wappie holds, the sweep unsubscribes the subscriptions of everyone it
// does not. The leader runs both (P3b); each is one pass here.

// roundPace is the pace of the round and of the sweep: 10 calls a second,
// a fifth of the platform's limit on all of an app's calls (README 4), so
// neither crowds out a sign-in's PUT or the feed.
const roundPace = 100 * time.Millisecond

// roundBatch is how many subs the round, or the sweep, reads at once.
const roundBatch = 50

// OrphanAfter is how old a subscription of a sub Wappie does not hold must
// be before the sweep unsubscribes it. A sign-up under way is never that
// old: its intent row is written after its ticket is read, which lives
// store.PlatformTicketTTL (5 minutes), and its PUT is bounded to 5 s. It is short
// because the platform watches every account an app follows: a workspace
// such a document names goes stale after 90 minutes without a snapshot
// (its contract_snapshots_stale alert), and Wappie never records an
// orphan's workspaces, so never sends them one. The leader's sweep must
// therefore run at least every OrphanAfter (P3b), which unfollows an
// orphan within about twice OrphanAfter of its last PUT.
const OrphanAfter = 15 * time.Minute

func (m *Members) pace() time.Duration {
	if m.Pace > 0 {
		return m.Pace
	}
	return roundPace
}

// pacer spaces a pass's calls at least every apart, the first at once.
type pacer struct {
	every time.Duration
	last  time.Time
}

// wait returns once every has passed since the call before, or with the
// context's error.
func (p *pacer) wait(ctx context.Context) error {
	if !p.last.IsZero() {
		t := time.NewTimer(time.Until(p.last.Add(p.every)))
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
	p.last = time.Now()
	return nil
}

// Round is one pass of the round (README 6.1, "once for every person the
// app holds when it connects"; 7.4): every sub Wappie holds whose row is
// missing or has no version of the stored generation is PUT, after its
// intent row, at the round's pace, and its document stored as an answer.
// It reports done once none is left, recording round_generation; a sub
// whose PUT failed (no answer, a refusal, a not_found, which never means
// closed) is tried again by the next pass, after the subs not yet tried.
func (m *Members) Round(ctx context.Context) (bool, error) {
	if !m.connected() {
		return false, ErrUnavailable
	}
	tried := map[uuid.UUID]bool{}
	pace := pacer{every: m.pace()}
	for {
		subs, err := m.Contract.Unsubscribed(ctx, roundBatch)
		if err != nil {
			return false, err
		}
		if len(subs) == 0 {
			state, err := m.Contract.State(ctx)
			if err != nil || state.Generation == nil {
				// No document was ever stored: nobody to subscribe yet.
				return err == nil, err
			}
			return m.Contract.RoundDone(ctx, *state.Generation)
		}
		progressed := false
		for _, sub := range subs {
			if tried[sub] {
				continue
			}
			if err := pace.wait(ctx); err != nil {
				return false, err
			}
			tried[sub], progressed = true, true
			// subscribe logs a failure; the next pass tries it again.
			_, _ = m.subscribe(ctx, sub, true) //nolint:errcheck // logged, and retried by the next pass
		}
		if !progressed {
			// Every sub left was tried in this pass and has no document.
			return false, nil
		}
	}
}

// Sweep is one pass of the sweep, the only path that unsubscribes an
// orphan (the plan's DB21): a subscription of a sub Wappie does not hold
// whose last PUT's intent is over OrphanAfter old (a sign-up refused after
// its PUT, an unsubscribe that failed, an abandoned sign-up). On the
// platform's signed unsubscribe its row is removed by compare-and-set on
// the intent the sweep read; when that removes nothing, a sign-in's PUT or
// a link came in between, and the sub is subscribed again at once. Its
// DELETEs go at the round's pace, each with the PUT that may follow it. It
// returns how many it unsubscribed.
func (m *Members) Sweep(ctx context.Context) (int, error) {
	if !m.connected() {
		return 0, ErrUnavailable
	}
	orphans, err := m.Contract.Orphans(ctx, OrphanAfter, roundBatch)
	if err != nil {
		return 0, err
	}
	n := 0
	pace := pacer{every: m.pace()}
	for _, o := range orphans {
		if err := pace.wait(ctx); err != nil {
			return n, err
		}
		call, cancel := context.WithTimeout(ctx, m.bound())
		err := m.Client.Unsubscribe(call, o.Sub.String())
		cancel()
		if err != nil {
			m.log().Warn("contract: the sweep's unsubscribe got no answer", append([]any{"sub", o.Sub}, callAttrs(err)...)...)
			continue
		}
		if m.forget(ctx, o.Sub, o.SubscribedAt) {
			n++
		}
	}
	return n, nil
}
