package membership

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/store"
)

// The token part in the leader (step 7's plan, 4.3 to 4.5; the design's
// 3.3, 3.5 and 3.8): the token follower, the leader's second long-poll, of
// GET /contract/v1/tokens, from a cursor of its own under the one
// generation both feeds share; the judge of the grants its records bring;
// the acknowledgement (POST /contract/v1/tokens/applied); and the usage
// report (POST /contract/v1/tokens/usage). They run only while the token
// mode is on: the leader's watcher starts them when it reads on (at its
// start, every mode check and each notice) and stops them when it reads
// off.
//
// A reset is the account side's too: a signed gone, a page or a record of
// another generation, or a feed rewound (its head or next_after behind the
// cursor in the same generation) restarts both feeds in one transaction
// (RestartFromTokens), which never widens what Wappie held, and the round
// subscribes everyone again. While the account side holds no generation
// the token follower asks the platform nothing.

// The token part's defaults.
const (
	// tokenBackoffMin and tokenBackoffMax bound the wait after a token feed
	// call that got no page: never the account feed's minute, since a
	// revocation waits behind it.
	tokenBackoffMin = time.Second
	tokenBackoffMax = 5 * time.Second
	// tokenStaleAfter: a leader's first token page after a stored read this
	// old holds token auth until a page with more false commits (a restore
	// of Wappie's own database, whose revocations since the backup the feed
	// has yet to bring).
	tokenStaleAfter = time.Hour
	// tokenCommitSlow: a page whose commit took longer from its receipt is
	// recorded for contract status --check (the design's bound: a narrowing
	// applies within a second of its record's receipt).
	tokenCommitSlow = time.Second
	// ackSpacing and ackEvery: an acknowledgement goes at most every
	// ackSpacing, but at once after a page that narrowed something and
	// after a reset's pass, and at least every ackEvery while the token
	// feed runs (the design's 3.5).
	ackSpacing = time.Second
	ackEvery   = time.Minute
	// ackBackoffMin and ackBackoffMax bound the wait after an
	// acknowledgement that was not accepted: the console's "Revogado no
	// Wappie" waits on it, so never the events' hour.
	ackBackoffMin = time.Second
	ackBackoffMax = 30 * time.Second
	// usageEvery: the usage report goes at most this often (the design's
	// 3.8); what does not fit one body follows at once.
	usageEvery = time.Minute
	// judgeEvery: the judge's pass when nothing woke it, for a document
	// whose notice was lost.
	judgeEvery = time.Minute
)

// tokenWork is one leader's token part: its four loops, while the token
// mode is on, and the kicks between them.
type tokenWork struct {
	l *Leader
	// round kicks the leader's round: a reset forgot every version.
	round chan struct{}
	// judge wakes the judge (a page brought grants, a document came);
	// ackNow sends the acknowledgement at once (a narrowing, a reset's
	// pass); ackSoon within ackSpacing of the last (the cursor moved).
	judge, ackNow, ackSoon chan struct{}

	mu sync.Mutex
	// cut ends the token long-poll in flight, or the pause after it.
	cut context.CancelFunc
	// stop ends the running loops; nil while they do not run.
	stop context.CancelFunc
	wg   sync.WaitGroup
}

func newTokenWork(l *Leader, round chan struct{}) *tokenWork {
	return &tokenWork{l: l, round: round, judge: make(chan struct{}, 1), ackNow: make(chan struct{}, 1), ackSoon: make(chan struct{}, 1)}
}

// set starts the loops under ctx when on and they do not run, or stops them
// and waits for them when off and they do. Only the leader's watcher calls
// it, and the leader's end (halt).
func (tw *tokenWork) set(ctx context.Context, on bool) {
	tw.mu.Lock()
	if on == (tw.stop != nil) {
		tw.mu.Unlock()
		return
	}
	if !on {
		stop := tw.stop
		tw.stop = nil
		tw.mu.Unlock()
		stop()
		tw.wg.Wait()
		tw.l.log().Info("contract: no longer following the token feed")
		return
	}
	run, stop := context.WithCancel(ctx)
	tw.stop = stop
	tw.mu.Unlock()
	tw.l.log().Info("contract: following the token feed")
	tw.wg.Go(func() { tw.follow(run) })
	tw.wg.Go(func() { tw.judging(run) })
	tw.wg.Go(func() { tw.acknowledging(run) })
	tw.wg.Go(func() { tw.reporting(run) })
}

// halt stops the loops, if they run, and waits for them.
func (tw *tokenWork) halt() { tw.set(context.Background(), false) }

// interrupt ends the token long-poll in flight, or its pause: another
// generation was seen, or the account side adopted one.
func (tw *tokenWork) interrupt() {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	if tw.cut != nil {
		tw.cut()
	}
}

// pause waits d, or less when ctx ends or interrupt cuts it.
func (tw *tokenWork) pause(ctx context.Context, d time.Duration) {
	wait, cut := context.WithTimeout(ctx, d)
	defer cut()
	tw.mu.Lock()
	tw.cut = cut
	tw.mu.Unlock()
	<-wait.Done()
}

// follow follows the token feed until ctx ends.
func (tw *tokenWork) follow(ctx context.Context) {
	l, m := tw.l, tw.l.Members
	minBack, maxBack := or(l.TokenBackoffMin, tokenBackoffMin), or(l.TokenBackoffMax, tokenBackoffMax)
	backoff := minBack
	lastPage := time.Now() // the loops' start counts as one, for the silence's ERROR
	var warned time.Time
	failing, silent := false, false
	// first: no page has committed since the loops started, so the stored
	// read is from before this leader (a stale start).
	first := true
	fail := func(class string, attrs ...any) {
		if ctx.Err() != nil {
			return
		}
		failing = true
		if err := m.Tokens.FeedFailed(ctx, class, time.Now()); err != nil && ctx.Err() == nil {
			l.log().Warn("contract: could not record the token feed's failure", "error", err)
		}
		if time.Since(warned) >= warnEvery {
			warned = time.Now()
			l.log().Warn("contract: the token feed got no page", append([]any{"class", class}, attrs...)...)
		}
		if !silent && time.Since(lastPage) >= or(l.SilentAfter, feedSilentAfter) {
			silent = true
			l.log().Error("contract: no token feed page for a long time", "since", lastPage.UTC().Format(time.RFC3339), "class", class)
			if err := m.Contract.RecordError(ctx, store.ContractErrorTokenFeedSilent); err != nil && ctx.Err() == nil {
				l.log().Warn("contract: could not record an ERROR", "error", err)
			}
		}
		tw.pause(ctx, backoff)
		backoff = min(backoff*2, maxBack)
	}
	reset := func(seen uuid.UUID, gen *uuid.UUID, confirmed bool, why string) {
		if err := tw.reset(ctx, seen, gen, confirmed, why); err != nil {
			fail("store", "error", err)
		}
	}
	for ctx.Err() == nil {
		st, err := m.Tokens.FeedState(ctx)
		if err != nil {
			fail("database", "error", err)
			continue
		}
		if st.Generation == nil {
			// The account side holds no generation (its first answer, or
			// after a gone): nothing is asked until it adopts one, so a reset
			// never loops. Its commit, or the generation notice, cuts this.
			tw.pause(ctx, maxBack)
			continue
		}
		seen := *st.Generation
		poll, cut := context.WithCancel(ctx)
		tw.mu.Lock()
		tw.cut = cut
		tw.mu.Unlock()
		asked := time.Now()
		page, err := m.Client.Tokens(poll, st.Cursor, l.wait())
		received := time.Now()
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
			// Signed: the cursor is past the token feed's head, the
			// platform's database was restored. Never the same cursor again.
			reset(seen, nil, false, "gone")
			continue
		default:
			fail(feedClass(err), callAttrs(err)...)
			continue
		}
		gen, err := uuid.Parse(page.Generation)
		switch {
		case err != nil:
			fail("unverified")
			continue
		case gen != seen:
			reset(seen, &gen, page.GenerationConfirmed, "generation")
			continue
		case page.Head < st.Cursor || page.NextAfter < st.Cursor:
			// Behind the cursor in the same generation: the feed was
			// rewound. A reset never widens, so it is taken as one.
			reset(seen, nil, false, "rewound")
			continue
		case !pageMoves(tokenShape(page), st.Cursor):
			// Signed and valid, but no page the design's 3.3 describes:
			// taking it would have the follower ask again at once.
			fail("unverified")
			continue
		}
		if failing {
			failing, silent, backoff = false, false, minBack
			l.log().Info("contract: the token feed answers again")
		}
		lastPage = time.Now()
		stale := first && st.ReadAt != nil && time.Since(*st.ReadAt) > tokenStaleAfter
		res, err := m.Tokens.CommitTokenPage(ctx, store.TokenPage{After: st.Cursor, SeenGeneration: seen, Feed: page, Now: time.Now(),
			StaleStart: stale})
		switch {
		case errors.Is(err, store.ErrPageGeneration):
			// A record of another generation than its page's.
			reset(seen, nil, false, "record_generation")
			continue
		case errors.Is(err, store.ErrFeedRewound):
			reset(seen, nil, false, "rewound")
			continue
		case errors.Is(err, store.ErrNoGeneration):
			// The account side reset meanwhile: read the state again.
			continue
		case err != nil:
			fail("store", "error", err)
			continue
		case !res.Committed:
			// Another writer moved the state: read it again.
			continue
		}
		if stale {
			l.log().Warn("contract: the token feed was last read over an hour before this leader; token auth holds until it has caught up",
				"read_at", st.ReadAt.UTC().Format(time.RFC3339))
		}
		first = false
		if took := time.Since(received); took > tokenCommitSlow {
			l.log().Warn("contract: a token page took over a second to commit", "took_ms", took.Milliseconds(), "items", len(page.Items))
			if err := m.Tokens.CommitTook(ctx, took, time.Now()); err != nil && ctx.Err() == nil {
				l.log().Warn("contract: could not record a slow token commit", "error", err)
			}
		}
		if res.Narrowed {
			kick(tw.ackNow)
		} else {
			kick(tw.ackSoon)
		}
		if res.Pending > 0 {
			kick(tw.judge)
		}
		if res.PassReady {
			tw.finishPass(ctx, gen)
		}
		if early(tokenShape(page), time.Since(asked), l.wait()) {
			tw.pause(ctx, minBack)
		}
	}
}

// reset restarts both feeds (RestartFromTokens), by compare-and-set on the
// generation the follower read, then kicks the round. A failure is
// returned, for the follower's backoff.
func (tw *tokenWork) reset(ctx context.Context, seen uuid.UUID, gen *uuid.UUID, confirmed bool, why string) error {
	l := tw.l
	done, err := l.Members.Contract.RestartFromTokens(ctx, seen, gen, confirmed)
	switch {
	case err != nil:
		return err
	case !done:
		// The state moved meanwhile: read it again.
		return nil
	}
	attrs := []any{"why", why, "old", seen}
	if gen != nil {
		attrs = append(attrs, "generation", *gen, "confirmed", confirmed)
	}
	l.log().Warn("contract: the token feed says the platform's generation changed: every sub is subscribed again and both feeds read from 0", attrs...)
	kick(tw.round)
	return nil
}

// finishPass ends a reset's pass of gen once a page with more false
// committed after the round ran in it (FinishTokenPass): the tokens it did
// not list are refused for good, and the acknowledgement goes at once with
// what Wappie holds narrower.
func (tw *tokenWork) finishPass(ctx context.Context, gen uuid.UUID) {
	l := tw.l
	res, err := l.Members.Tokens.FinishTokenPass(ctx, gen, time.Now())
	switch {
	case err != nil:
		// pass_ready_at stays: the next page with more false tries again.
		if ctx.Err() == nil {
			l.log().Warn("contract: could not finish the token feed's pass", "generation", gen, "error", err)
		}
		return
	case !res.Done:
		return
	}
	l.log().Info("contract: the token feed's pass is done", "generation", gen, "unlisted", len(res.Unlisted))
	kick(tw.ackNow)
}

// judging judges the grants the records brought (JudgeTokenGrants), at
// the loops' start, when kicked, and every JudgeEvery.
func (tw *tokenWork) judging(ctx context.Context) {
	l, m := tw.l, tw.l.Members
	every := or(l.JudgeEvery, judgeEvery)
	for ctx.Err() == nil {
		res, err := m.Tokens.JudgeTokenGrants(ctx, time.Now())
		wait := every
		switch {
		case err != nil:
			if ctx.Err() != nil {
				return
			}
			l.log().Warn("contract: the token judge's pass failed", "error", err)
			wait = min(every, or(l.TokenBackoffMax, tokenBackoffMax))
		case res.Applied+res.Refused+res.Waiting > 0:
			l.log().Debug("contract: token grants judged", "applied", res.Applied, "refused", res.Refused, "waiting", res.Waiting)
			kick(tw.ackSoon)
		}
		select {
		case <-ctx.Done():
			return
		case <-tw.judge:
		case <-time.After(wait):
		}
	}
}

// acknowledging sends the acknowledgement (AckBody) until ctx ends: at the
// loops' start, at once after a narrowing or a reset's pass, within
// AckSpacing of the last after the cursor moved, at least every AckEvery,
// and at once again while what is due did not fit. Each takes a turn of the
// leader's pace. One not accepted backs off from AckBackoffMin doubled to
// AckBackoffMax; a signed gone (another generation, or a through past the
// platform's head) resets both feeds.
func (tw *tokenWork) acknowledging(ctx context.Context) {
	l, m := tw.l, tw.l.Members
	spacing, every := or(l.AckSpacing, ackSpacing), or(l.AckEvery, ackEvery)
	minBack, maxBack := or(l.AckBackoffMin, ackBackoffMin), or(l.AckBackoffMax, ackBackoffMax)
	backoff := minBack
	// sent is when the last one went, accepted or not; next when the next
	// goes.
	var sent, warned time.Time
	next := time.Now()
	failing := false
	for {
		timer := time.NewTimer(time.Until(next))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-tw.ackNow:
			timer.Stop()
			// Never within a failing run's backoff: that would be a loop
			// of calls the platform does not answer.
			if !failing {
				next = time.Now()
			}
			continue
		case <-tw.ackSoon:
			timer.Stop()
			if !failing {
				next = minTime(next, maxTime(time.Now(), sent.Add(spacing)))
			}
			continue
		case <-timer.C:
		}
		if err := m.paced(ctx); err != nil {
			return
		}
		ack, ok, err := m.Tokens.AckBody(ctx)
		now := time.Now()
		switch {
		case err != nil:
			if ctx.Err() != nil {
				return
			}
			l.log().Warn("contract: could not read the token acknowledgement", "error", err)
			next = now.Add(minBack)
			continue
		case !ok:
			// No token page committed in this generation yet: nothing to
			// acknowledge, until the cursor moves.
			next = now.Add(every)
			continue
		case ack.Empty(ack.Acked) && now.Sub(sent) < every:
			// Nothing new since the last accepted: the minute's goes later.
			next = sent.Add(every)
			continue
		}
		if err := ack.Body.Validate(); err != nil {
			// Never: the store builds every entry from what it validated.
			// The platform would refuse such a body whole, again and again.
			l.log().Warn("contract: an acknowledgement Wappie would not send", "rule", err.Error())
			if err := m.Tokens.AckFailed(ctx, "local_invalid", now); err != nil && ctx.Err() == nil {
				l.log().Warn("contract: could not record the acknowledgement's failure", "error", err)
			}
			failing, next = true, now.Add(maxBack)
			continue
		}
		sent = now
		err = m.Client.TokensApplied(ctx, ack.Body)
		if ctx.Err() != nil {
			return
		}
		switch {
		case err == nil:
			if err := m.Tokens.AckSent(ctx, ack, time.Now()); err != nil && ctx.Err() == nil {
				l.log().Warn("contract: could not record an accepted acknowledgement", "error", err)
			}
			if failing {
				l.log().Info("contract: the token acknowledgement is accepted again")
			}
			failing, backoff = false, minBack
			next = time.Now().Add(every)
			if ack.More {
				next = time.Now()
			}
		case RefusalCode(err) == kc.CodeGone:
			// Signed: not the platform's generation, or past its head.
			if gen, perr := uuid.Parse(ack.Body.Generation); perr == nil {
				if err := tw.reset(ctx, gen, nil, false, "acknowledgement_gone"); err != nil && ctx.Err() == nil {
					l.log().Warn("contract: could not reset the feeds", "error", err)
				}
			}
			next = time.Now().Add(spacing)
		default:
			class := feedClass(err)
			if err := m.Tokens.AckFailed(ctx, class, now); err != nil && ctx.Err() == nil {
				l.log().Warn("contract: could not record the acknowledgement's failure", "error", err)
			}
			failing = true
			if time.Since(warned) >= warnEvery {
				warned = time.Now()
				l.log().Warn("contract: the token acknowledgement was not accepted", append([]any{"through", ack.Body.Through}, callAttrs(err)...)...)
			}
			next = time.Now().Add(backoff)
			backoff = min(backoff*2, maxBack)
		}
	}
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// reporting sends the usage report (UsageBody) at the loops' start and then
// at most every UsageEvery, each body's overflow at once after it, each call
// on a turn of the leader's pace. Both lists are absolute, so a report not
// accepted is simply sent again the next time.
func (tw *tokenWork) reporting(ctx context.Context) {
	every := or(tw.l.UsageEvery, usageEvery)
	run := &usageRun{}
	for ctx.Err() == nil {
		for tw.report(ctx, run) && ctx.Err() == nil {
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// usageRun is the usage reports' failing run: whether one is, and when its
// last WARN went.
type usageRun struct {
	failing bool
	warned  time.Time
}

// report sends one usage report, if anything is due, and says whether more
// is due than it carried. A report not accepted is recorded, and WARNed at
// most every warnEvery.
func (tw *tokenWork) report(ctx context.Context, run *usageRun) bool {
	l, m := tw.l, tw.l.Members
	if m.paced(ctx) != nil {
		return false
	}
	body, err := m.Tokens.UsageBody(ctx)
	switch {
	case err != nil:
		if ctx.Err() == nil {
			l.log().Warn("contract: could not read the token usage", "error", err)
		}
		return false
	case body.Empty():
		return false
	}
	if rule := body.Body.Validate(); rule != nil {
		// Never: every row was counted as the kit names it.
		l.log().Warn("contract: a usage report Wappie would not send", "rule", rule.Error())
		if err := m.Tokens.UsageFailed(ctx, "local_invalid", time.Now()); err != nil && ctx.Err() == nil {
			l.log().Warn("contract: could not record the usage report's failure", "error", err)
		}
		return false
	}
	sent := m.Client.TokenUsage(ctx, body.Body)
	switch {
	case ctx.Err() != nil:
		return false
	case sent != nil:
		if err := m.Tokens.UsageFailed(ctx, feedClass(sent), time.Now()); err != nil && ctx.Err() == nil {
			l.log().Warn("contract: could not record the usage report's failure", "error", err)
		}
		run.failing = true
		if time.Since(run.warned) >= warnEvery {
			run.warned = time.Now()
			l.log().Warn("contract: the token usage report was not accepted", callAttrs(sent)...)
		}
		return false
	}
	if run.failing {
		run.failing = false
		l.log().Info("contract: the token usage report is accepted again")
	}
	if err := m.Tokens.UsageSent(ctx, body, time.Now()); err != nil {
		if ctx.Err() == nil {
			l.log().Warn("contract: could not record an accepted usage report", "error", err)
		}
		return false
	}
	return body.More
}

// CallClass is a failed call's class, as contract status shows a feed's:
// an outcome, a refusal's code (refused:<code>) or a transport's class,
// never a message.
func CallClass(err error) string { return feedClass(err) }
