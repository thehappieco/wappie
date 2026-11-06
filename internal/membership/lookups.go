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
// signed not_found lets a bad record's revocation go, or settles a stop
// undated; a signed answer whose record Wappie cannot use puts it off,
// longer each time, and its first logs an ERROR; anything else (no answer,
// an unsigned one, any other refusal) puts it off LookupRetry.
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
		if _, err := m.Tokens.TokenLookupNotFound(ctx, lk); err != nil {
			l.lookupNotRecorded(ctx, err)
			return lookupStuck
		}
		l.lookupsAnswer(run)
		return lookupUnknown
	case errors.Is(err, kc.ErrUnverified) && errors.Is(err, kc.ErrInvalid):
		// Signed, but its record is not valid.
		bad = true
	default:
		run.failing = true
		if time.Since(run.warned) >= warnEvery {
			run.warned = time.Now()
			l.log().Warn("contract: a token lookup got no answer", append([]any{"kind", kind}, callAttrs(err)...)...)
		}
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
