package membership

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// The round and the sweep (the plan's 4.6): the round subscribes everyone
// Wappie holds, the sweep unsubscribes the subscriptions of everyone it
// does not. The leader runs both (P3b); each is one pass here.

// roundPace is the round's pace: 10 PUTs a second, a fifth of the
// platform's limit for an app (README 4).
const roundPace = 100 * time.Millisecond

// roundBatch is how many subs the round reads at once.
const roundBatch = 50

// OrphanAfter is how old a subscription of a sub Wappie does not hold must
// be before the sweep unsubscribes it: an hour after its last PUT's intent,
// so a sign-up under way keeps its own.
const OrphanAfter = time.Hour

func (m *Members) pace() time.Duration {
	if m.Pace > 0 {
		return m.Pace
	}
	return roundPace
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
	tick := time.NewTicker(m.pace())
	defer tick.Stop()
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
			if len(tried) > 0 {
				select {
				case <-ctx.Done():
					return false, ctx.Err()
				case <-tick.C:
				}
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
// a link came in between, and the sub is subscribed again at once. It
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
	for _, o := range orphans {
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
