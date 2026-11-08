package membership

import (
	"context"
	"errors"
	"time"

	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/store"
)

// The lookups (decision 0056; the platform's review of step 7's p5, its F2
// and F3): the leader asks the platform, by a signed GET, the date of a
// token Wappie keeps something of but does not hold, so that it keeps it no
// longer than that token's created_at + 365 days. By id
// (GET /contract/v1/tokens/{id}) for a bad record's revocation, which
// Wappie's clock dates; by selector
// (GET /contract/v1/token-selectors/{selector}) for a stop of a selector
// Wappie does not hold that no valid record dates. The store says what is
// due and writes each answer (store.TokenLookup).
//
// They run in the leader while the contract is on, whatever the token mode:
// they only date what Wappie keeps, and what a bad record left while tokens
// were on waits on them after tokens are off. Each GET takes a turn of the
// leader's pace, and no transaction is open during it. The lookups by
// selector are an operator's stops, never a client's token, so they need
// no limit per client address (the design's 3.4); each is asked once.
//
// A not_found by id lets a revocation go, so the leader takes it only in
// the generation its bad record came in, and only once the platform says
// it is still in that generation after the not_found: a signed page of the
// account feed asked after it (generationNow). Wappie's own generation is
// not enough: a freshly restored platform answers not_found for a token it
// never named to Wappie, and Wappie's feeds may not have seen its new
// generation yet (the account feed backs off up to a minute, and the
// token feed may be off).

// The lookups' defaults.
const (
	// lookupEvery: how often the leader looks for lookups due.
	lookupEvery = time.Minute
	// lookupRetry: after a lookup that got no answer, it is due again this
	// much later, for as long as its row lasts.
	lookupRetry = 15 * time.Minute
	// lookupBadMax: after a signed answer whose record Wappie cannot use,
	// the platform answers with the same stored record until it changes, so
	// the wait doubles from lookupRetry for each one in a row, to this.
	lookupBadMax = 24 * time.Hour
	// lookupBatch: how many of each kind one pass takes; more follow at
	// once.
	lookupBatch = 50
)

// lookingUp runs the lookups until ctx ends: a pass at once, then every
// LookupEvery, and the next at once while a pass found more due than it
// takes.
func (l *Leader) lookingUp(ctx context.Context) {
	every := or(l.LookupEvery, lookupEvery)
	run := &lookupRun{}
	for ctx.Err() == nil {
		if l.lookUp(ctx, run) {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// lookupRun is the lookups' run of calls with no answer: whether one is,
// and when its last WARN went.
type lookupRun struct {
	failing bool
	warned  time.Time
}

// lookUp is one pass: the lookups due, each a GET on a turn of the pace,
// its answer written on its own. It reports whether more were due than it
// took.
func (l *Leader) lookUp(ctx context.Context, run *lookupRun) bool {
	m := l.Members
	due, err := m.Tokens.DueTokenLookups(ctx, time.Now(), lookupBatch)
	if err != nil {
		if ctx.Err() == nil {
			l.log().Warn("contract: could not read the token lookups due", "error", err)
		}
		return false
	}
	ids, dated, unknown, failed, stuck := 0, 0, 0, 0, false
	for _, lk := range due {
		if lk.ByID() {
			ids++
		}
		if m.paced(ctx) != nil {
			return false
		}
		switch l.lookUpOne(ctx, run, lk) {
		case lookupDated:
			dated++
		case lookupUnknown:
			unknown++
		case lookupFailed:
			failed++
		case lookupStuck:
			// Its answer could not be written, so it is still due: the next
			// pass waits LookupEvery, never a loop of calls.
			failed++
			stuck = true
		}
		if ctx.Err() != nil {
			return false
		}
	}
	if len(due) > 0 {
		l.log().Debug("contract: token lookups", "dated", dated, "unknown", unknown, "failed", failed)
	}
	return !stuck && (ids == lookupBatch || len(due)-ids == lookupBatch)
}

// The outcomes of one lookup.
const (
	lookupDated = iota + 1
	lookupUnknown
	lookupFailed
	lookupStuck
)

// lookUpOne asks the platform one lookup and writes what it answered, on
// Wappie's clock after the answer: a good record dates what was asked of; a
// signed not_found lets a bad record's revocation go once the platform
// places it in the record's generation (else settles it, or puts it off
// when the platform does not say), or settles a stop undated; an answer
// the kit or the store refuses for anything but its signature (a record
// that is not valid, another app's or another token's, a body that does
// not decode, or one too large to check) puts it off, longer each time,
// and its first logs an ERROR; anything else (no answer, one whose
// signature fails, any other refusal) puts it off LookupRetry.
func (l *Leader) lookUpOne(ctx context.Context, run *lookupRun, lk store.TokenLookup) int {
	m := l.Members
	retry, most := or(l.LookupRetry, lookupRetry), or(l.LookupBadMax, lookupBadMax)
	kind := "selector"
	var rec kc.TokenRecord
	var err error
	if lk.ByID() {
		kind = "id"
		rec, err = m.Client.Token(ctx, lk.Token.String())
	} else {
		rec, err = m.Client.TokenBySelector(ctx, lk.Selector)
	}
	if ctx.Err() != nil {
		return 0
	}
	now := time.Now()
	bad := false
	switch {
	case err == nil:
		err = m.Tokens.TokenLookupAnswered(ctx, lk, rec, now)
		switch {
		case err == nil:
			l.lookupsAnswer(run)
			return lookupDated
		case errors.Is(err, store.ErrTokenLookupRecord):
			bad = true
		default:
			l.lookupNotRecorded(ctx, err)
			return lookupStuck
		}
	case RefusalCode(err) == kc.CodeNotFound:
		gen := ""
		if lk.ByID() {
			gen, err = l.generationNow(ctx)
			if ctx.Err() != nil {
				return 0
			}
		}
		took, werr := m.Tokens.TokenLookupNotFound(ctx, lk, gen)
		if werr != nil {
			l.lookupNotRecorded(ctx, werr)
			return lookupStuck
		}
		if took != store.NotFoundUnconfirmed {
			l.lookupsAnswer(run)
			return lookupUnknown
		}
		// The platform did not say its generation: asked again later, as
		// a lookup with no answer.
		l.noAnswer(run, "contract: a token lookup's not_found waits for the platform's generation", kind, err)
	case errors.Is(err, kc.ErrUnverified) && !unsigned(err):
		// Refused for anything but its signature: a record that is not
		// valid, another app's or another token's, a body that does not
		// decode, or one too large to check.
		bad = true
	default:
		l.noAnswer(run, "contract: a token lookup got no answer", kind, err)
	}
	n, err := m.Tokens.TokenLookupFailed(ctx, lk, now, bad, retry, most)
	if err != nil {
		l.lookupNotRecorded(ctx, err)
		return lookupStuck
	}
	if bad {
		l.lookupsAnswer(run)
		if n == 1 {
			// Once per lookup: its later bad answers are put off longer
			// each time, to lookupBadMax.
			l.log().Error("contract: the platform answered a token lookup with a record Wappie cannot use; it is asked again later",
				"class", store.ContractErrorTokenLookupInvalid, "kind", kind)
			if err := m.Contract.RecordError(ctx, store.ContractErrorTokenLookupInvalid); err != nil && ctx.Err() == nil {
				l.log().Warn("contract: could not record an ERROR", "error", err)
			}
		}
	}
	return lookupFailed
}

// unsigned reports whether the kit refused an answer for its signature: a
// header missing or stale, another request's nonce, or a signature none of
// Wappie's secrets made. As far as Wappie can tell, the platform did not
// answer.
func unsigned(err error) bool {
	return errors.Is(err, kc.ErrMissing) || errors.Is(err, kc.ErrStale) ||
		errors.Is(err, kc.ErrBad) || errors.Is(err, kc.ErrAnswerNonce)
}

// generationNow asks the platform its generation after a not_found by id,
// on a turn of the pace: a signed page of the account feed
// (GET /contract/v1/feed, wait 0, from Wappie's cursor), which the
// platform answers in its generation of the moment, after the not_found.
// The page is not stored: the follower reads it again. "" with a nil error
// when Wappie holds no generation: nothing can be confirmed.
func (l *Leader) generationNow(ctx context.Context) (string, error) {
	m := l.Members
	state, err := m.Contract.State(ctx)
	if err != nil || state.Generation == nil {
		return "", err
	}
	if err := m.paced(ctx); err != nil {
		return "", err
	}
	f, err := m.Client.Feed(ctx, state.FeedCursor, 0)
	if err != nil {
		return "", err
	}
	return f.Generation, nil
}

// noAnswer marks a run of lookups with no answer and logs msg at most once
// a warnEvery.
func (l *Leader) noAnswer(run *lookupRun, msg, kind string, err error) {
	run.failing = true
	if time.Since(run.warned) >= warnEvery {
		run.warned = time.Now()
		attrs := []any{"kind", kind}
		if err != nil {
			attrs = append(attrs, callAttrs(err)...)
		}
		l.log().Warn(msg, attrs...)
	}
}

// lookupsAnswer ends a run of lookups with no answer, said once.
func (l *Leader) lookupsAnswer(run *lookupRun) {
	if run.failing {
		run.failing = false
		l.log().Info("contract: the token lookups answer again")
	}
}

// lookupNotRecorded says a lookup's answer could not be written: it is due
// again at the next pass.
func (l *Leader) lookupNotRecorded(ctx context.Context, err error) {
	if ctx.Err() == nil {
		l.log().Warn("contract: could not record a token lookup's answer", "error", err)
	}
}
