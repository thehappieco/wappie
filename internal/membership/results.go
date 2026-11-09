package membership

import (
	"bytes"
	"context"
	"time"

	"github.com/google/uuid"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/store"
)

// The results poster (the spec's 14.9; the plan's 5.1): the leader's one
// sender of the ledger's results not delivered yet, oldest first, at most
// kc.MaxCommandResults and under kc.ResultsBodyLimit a call, at the round's
// pace. Before each batch the store drops the results of an old
// generation's commands (the platform no longer expects them). Each result
// is checked as the platform reads it first: one of a row with a kind with
// ValidateFor, one of a row refused before it was decoded (always
// invalid_command) with Validate alone, since ValidateFor refuses a kind it
// does not know. One that fails is Wappie's bug: parked local_invalid,
// never sent, with an ERROR. The answers settle each result: accepted and
// duplicate deliver it, a rejection parks it (invalid_request with an
// ERROR; not_found and conflict are the platform's, logged).

// resultsBatch is how many results the poster reads at once.
const resultsBatch = kc.MaxCommandResults

// post sends the ledger's results until ctx ends.
func (sw *settingsWork) post(ctx context.Context) {
	l, m := sw.l, sw.l.Members
	c := m.Contract
	minBack, maxBack := or(sw.cfg.ResultsBackoffMin, resultsBackoffMin), or(sw.cfg.ResultsBackoffMax, resultsBackoffMax)
	backoff, storeBack := minBack, minBack
	idle := or(sw.cfg.Idle, settingsIdle)
	warned := map[string]time.Time{}
	// warn logs msg at most once every warnEvery.
	warn := func(msg string, attrs ...any) {
		if time.Since(warned[msg]) >= warnEvery {
			warned[msg] = time.Now()
			l.log().Warn(msg, attrs...)
		}
	}
	// stored waits after a write of the ledger that failed, doubling to the
	// results' backoff, before the rows are read again: a park or answers
	// that cannot be stored never loop on the database, or on the platform
	// with the same batch.
	stored := func(err error, msg string) bool {
		if err == nil {
			storeBack = minBack
			return true
		}
		if ctx.Err() == nil {
			warn(msg, "error", err)
			if pause(ctx, storeBack, nil) {
				storeBack = min(storeBack*2, maxBack)
			}
		}
		return false
	}
	failing := false
	for ctx.Err() == nil {
		rows, err := c.UndeliveredResults(ctx, resultsBatch)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			warn("contract: could not read the results to post", "error", err)
			if !pause(ctx, minBack, sw.results) {
				return
			}
			continue
		}
		if len(rows) == 0 {
			if !pause(ctx, idle, sw.results) {
				return
			}
			continue
		}
		batch, ids, parked := sw.checkResults(ctx, rows)
		if len(parked) > 0 && !stored(sw.park(ctx, parked), "contract: could not park results") {
			continue
		}
		if len(batch) == 0 {
			continue
		}
		if err := m.paced(ctx); err != nil {
			return
		}
		answers, err := m.Client.PostResults(ctx, batch)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			failing = true
			class := feedClass(err)
			if rerr := c.ResultsFailed(ctx, class); rerr != nil && ctx.Err() == nil {
				warn("contract: could not record the results' failure", "error", rerr)
			}
			outcomes := make([]store.ContractResultOutcome, len(ids))
			for i, id := range ids {
				outcomes[i] = store.ContractResultOutcome{ID: id, Failed: class}
			}
			if rerr := c.ResultsPosted(ctx, outcomes); rerr != nil && ctx.Err() == nil {
				warn("contract: could not record the results' failure", "error", rerr)
			}
			warn("contract: the results got no answer", append([]any{"results", len(batch)}, callAttrs(err)...)...)
			if !pause(ctx, backoff, nil) {
				return
			}
			backoff = min(backoff*2, maxBack)
			continue
		}
		if failing {
			failing, backoff = false, minBack
			l.log().Info("contract: the results are answered again")
		}
		stored(sw.settle(ctx, ids, answers), "contract: could not record the results' answers")
	}
}

// checkResults turns rows into the results to post, those that fit one
// call, and the ids of each, in order; and those Wappie would not post,
// with why.
func (sw *settingsWork) checkResults(ctx context.Context, rows []store.ContractResult) ([]kc.CommandResult, []uuid.UUID,
	map[uuid.UUID]string) {
	batch := make([]kc.CommandResult, 0, len(rows))
	ids := make([]uuid.UUID, 0, len(rows))
	parked := map[uuid.UUID]string{}
	size := len(`{"results":[]}`)
	for _, row := range rows {
		r, why := resultOf(row)
		if why != "" {
			parked[row.ID] = why
			continue
		}
		raw, err := encodeData(r)
		if err != nil {
			parked[row.ID] = "encode"
			continue
		}
		if len(batch) > 0 && size+len(raw)+1 > kc.ResultsBodyLimit {
			// The rest go in the next call.
			break
		}
		size += len(raw) + 1
		batch = append(batch, r)
		ids = append(ids, row.ID)
	}
	if ctx.Err() != nil {
		return nil, nil, nil
	}
	return batch, ids, parked
}

// resultOf is a ledger row's result as the wire carries it, and why Wappie
// would not post it, or "": a result the kit's check refuses for its
// command's kind, or, for a row with none, whatever its kind.
func resultOf(row store.ContractResult) (kc.CommandResult, string) {
	r := kc.CommandResult{ID: row.ID.String(), Outcome: row.Outcome, StateSeq: row.StateSeq, At: kc.T(row.At)}
	if row.Code != "" {
		code := row.Code
		r.Code = &code
	}
	if row.RetryAfter != nil {
		retry := int64(*row.RetryAfter)
		r.RetryAfter = &retry
	}
	if len(bytes.TrimSpace(row.Detail)) > 0 {
		var d kc.ResultDetail
		if err := kc.DecodeStrict(row.Detail, &d); err != nil {
			return r, "detail"
		}
		r.Detail = &d
	}
	check := r.Validate
	if row.Kind != "" {
		check = func() error { return r.ValidateFor(App, row.Kind) }
	}
	if err := check(); err != nil {
		return r, "invalid"
	}
	return r, ""
}

// park parks the results Wappie would not post, with one ERROR per call
// and one recorded for --check; it returns the error of a park that could
// not be stored.
func (sw *settingsWork) park(ctx context.Context, parked map[uuid.UUID]string) error {
	l, c := sw.l, sw.l.Members.Contract
	byWhy := map[string][]uuid.UUID{}
	for id, why := range parked {
		byWhy[why] = append(byWhy[why], id)
	}
	for why, ids := range byWhy {
		if err := c.ResultsParked(ctx, ids, "local_invalid:"+why); err != nil {
			return err
		}
		l.log().Error("contract: results are parked: Wappie would not post them", "count", len(ids), "reason", why, "first", ids[0])
	}
	if err := c.RecordError(ctx, store.ContractErrorResultParked); err != nil && ctx.Err() == nil {
		l.log().Warn("contract: could not record an ERROR", "error", err)
	}
	return nil
}

// settle records the platform's answers to the results ids, by position;
// it returns the error of answers that could not be stored.
func (sw *settingsWork) settle(ctx context.Context, ids []uuid.UUID, answers []kc.CommandResultAnswer) error {
	l, c := sw.l, sw.l.Members.Contract
	outcomes := make([]store.ContractResultOutcome, len(ids))
	parked := 0
	for i, id := range ids {
		a := answers[i]
		o := store.ContractResultOutcome{ID: id, Answer: a.Outcome}
		if a.Code != nil {
			o.Code = *a.Code
		}
		switch {
		case a.Outcome != kc.OutcomeRejected:
		case o.Code == kc.CodeNotFound || o.Code == kc.CodeConflict:
			// The platform's to look at: no such command any more, or
			// another final result kept.
			l.log().Warn("contract: the platform rejected a result", "id", id, "code", o.Code)
		default:
			// invalid_request, or a code the contract does not name, which
			// the store parks as it.
			parked++
		}
		outcomes[i] = o
	}
	if err := c.ResultsPosted(ctx, outcomes); err != nil {
		return err
	}
	if parked > 0 {
		l.log().Error("contract: results are parked: the platform refused them", "count", parked)
		if err := c.RecordError(ctx, store.ContractErrorResultParked); err != nil && ctx.Err() == nil {
			l.log().Warn("contract: could not record an ERROR", "error", err)
		}
	}
	l.log().Debug("contract: results posted", "results", len(ids))
	return nil
}
