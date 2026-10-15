package membership

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/store"
)

// The follower (README 6.3 and 7.4; the plan's 4.7): the leader's one
// long-poll of the feed. Only a signed page moves the cursor (README 5);
// published_through is trusted only from a page with more false; a page of
// another generation, or a signed gone, restarts the stored state, then the
// round subscribes everyone again and the feed is read from 0. Every write
// to contract_state names the cursor and the generation it was read with.

// follower is one leader's feed loop.
type follower struct {
	l *Leader
	// round kicks the leader's round (a restart forgot every version).
	round chan struct{}

	mu sync.Mutex
	// cut ends the long-poll in flight, when a notice says another
	// generation was seen: the next call finds it or gone at once.
	cut context.CancelFunc
}

// interrupt ends the long-poll in flight, if any.
func (f *follower) interrupt() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cut != nil {
		f.cut()
	}
}

// run follows the feed until ctx ends.
func (f *follower) run(ctx context.Context) {
	l, m := f.l, f.l.Members
	minBack, maxBack := or(l.BackoffMin, feedBackoffMin), or(l.BackoffMax, feedBackoffMax)
	backoff := minBack
	lastPage := time.Now() // the leader's start counts as one, for the silence's ERROR
	var warned time.Time
	failing, silent := false, false
	fail := func(class string, attrs ...any) {
		if ctx.Err() != nil {
			// The leader is stopping: no failure of the feed's.
			return
		}
		failing = true
		if err := m.Contract.FeedFailed(ctx, class); err != nil && ctx.Err() == nil {
			l.log().Warn("contract: could not record the feed's failure", "error", err)
		}
		if time.Since(warned) >= warnEvery {
			warned = time.Now()
			l.log().Warn("contract: the feed got no page", append([]any{"class", class}, attrs...)...)
		}
		if !silent && time.Since(lastPage) >= or(l.SilentAfter, feedSilentAfter) {
			silent = true
			l.log().Error("contract: no feed page for a long time", "since", lastPage.UTC().Format(time.RFC3339), "class", class)
			if err := m.Contract.RecordError(ctx, store.ContractErrorFeedSilent); err != nil && ctx.Err() == nil {
				l.log().Warn("contract: could not record an ERROR", "error", err)
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, maxBack)
	}
	for ctx.Err() == nil {
		state, err := m.Contract.State(ctx)
		if err != nil {
			fail("database", "error", err)
			continue
		}
		poll, cut := context.WithCancel(ctx)
		f.mu.Lock()
		f.cut = cut
		f.mu.Unlock()
		page, err := m.Client.Feed(poll, state.FeedCursor, l.wait())
		interrupted := poll.Err() != nil && ctx.Err() == nil
		cut()
		if ctx.Err() != nil {
			return
		}
		if interrupted && err != nil {
			continue
		}
		switch {
		case err == nil:
		case RefusalCode(err) == kc.CodeGone:
			// Signed: the cursor is past the platform's head, its database
			// was restored (README 7.4). Never the same cursor again.
			if err := f.restart(ctx, state, nil, false, "gone"); err != nil {
				fail("store", "error", err)
			}
			continue
		default:
			fail(feedClass(err), callAttrs(err)...)
			continue
		}
		gen, err := uuid.Parse(page.Generation)
		restart := err == nil && state.Generation != nil && *state.Generation != gen
		if err != nil || (!restart && !pageMoves(page, state.FeedCursor)) {
			// The kit validated it, signature and shape; a page that is not
			// one README 6.3 describes is no page all the same, and taking
			// it would have the follower ask again at once, for nothing.
			fail("unverified")
			continue
		}
		if failing {
			failing, silent, backoff = false, false, minBack
			l.log().Info("contract: the feed answers again")
			if n, err := m.Contract.Recovered(ctx); err != nil && ctx.Err() == nil {
				l.log().Warn("contract: could not make the backed-off workspaces due", "error", err)
			} else if n > 0 {
				l.log().Info("contract: workspaces due again after the outage", "count", n)
			}
		}
		lastPage = time.Now()
		if restart {
			if err := f.restart(ctx, state, &gen, page.GenerationConfirmed, "generation"); err != nil {
				fail("store", "error", err)
			}
			continue
		}
		if err := f.commit(ctx, state, gen, page); err != nil {
			fail("store", "error", err)
		}
	}
}

// pageMoves reports whether a page asked from cursor is one README 6.3
// describes, which the kit does not check: its next_after is never behind
// the cursor, and a page with more ends at its last item's seq, past the
// cursor. A signed page that is not, committed, would have the follower
// call again at once with nothing moved: a busy loop of the app's calls,
// which share the platform's 50 a second with every sign-in's PUT.
func pageMoves(page kc.Feed, cursor int64) bool {
	switch {
	case page.NextAfter < cursor:
		return false
	case page.More:
		return len(page.Items) > 0 && page.NextAfter == page.Items[len(page.Items)-1].Seq && page.NextAfter > cursor
	}
	return true
}

// feedClass is a failed feed call's class, as contract status shows it.
func feedClass(err error) string {
	switch o := Classify(err); o {
	case Refused:
		return "refused:" + RefusalCode(err)
	case Unavailable:
		return unavailableClass(err)
	default:
		return o.String()
	}
}

// restart forgets the stored generation's versions and cursor (README 7.4)
// by compare-and-set on what was read, then kicks the round: every sub
// Wappie holds is PUT again while the feed is read from 0. The two run side
// by side rather than one after the other: a round of thousands at its pace
// would otherwise leave the feed unread past the platform's 10-minute
// alert, and both store by the same newer-only rules.
// A failure is returned, for the follower's backoff.
func (f *follower) restart(ctx context.Context, state store.ContractState, gen *uuid.UUID, confirmed bool, why string) error {
	l := f.l
	done, err := l.Members.Contract.Restart(ctx, state.Generation, state.FeedCursor, gen, confirmed)
	switch {
	case err != nil:
		return err
	case !done:
		// The state moved meanwhile: read it again.
		return nil
	}
	attrs := []any{"why", why, "cursor", state.FeedCursor}
	if state.Generation != nil {
		attrs = append(attrs, "old", *state.Generation)
	}
	if gen != nil {
		attrs = append(attrs, "generation", *gen, "confirmed", confirmed)
	}
	l.log().Warn("contract: the platform's generation changed: every sub is subscribed again and the feed read from 0", attrs...)
	kick(f.round)
	return nil
}

// commit stores a page of the stored generation (or the first one, which
// adopts it), then compares each document it stored. A failure to store is
// returned, for the follower's backoff.
func (f *follower) commit(ctx context.Context, state store.ContractState, gen uuid.UUID, page kc.Feed) error {
	l, m := f.l, f.l.Members
	docs := make([]store.ContractDoc, 0, len(page.Items))
	var unreadable []uuid.UUID
	for _, it := range page.Items {
		d, err := DocOf(it.Doc)
		if err != nil {
			// Its sub's version is forgotten when the sub can be told (the
			// kit checked it): the round asks for its document again.
			l.log().Error("contract: a feed document cannot be read; it is skipped", "seq", it.Seq)
			if sub, err := uuid.Parse(it.Doc.Sub); err == nil {
				unreadable = append(unreadable, sub)
			}
			continue
		}
		docs = append(docs, d)
	}
	res, err := m.Contract.CommitPage(ctx, store.ContractPage{
		After: state.FeedCursor, SeenGeneration: state.Generation, Generation: gen, Confirmed: page.GenerationConfirmed,
		NextAfter: page.NextAfter, More: page.More, PublishedThrough: page.PublishedThrough.Time, Docs: docs,
		Unreadable: unreadable,
	})
	switch {
	case err != nil:
		return err
	case !res.Committed:
		// Another writer moved the state: read it again.
		return nil
	}
	for i, o := range res.Outcomes {
		if o == store.ContractDocStored {
			m.observe(ctx, docs[i].Sub, docs[i].Version)
		}
	}
	return nil
}
