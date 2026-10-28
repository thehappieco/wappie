package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/store"
)

// The token mode, the follower's state and contract status's counts
// (step 7's plan, 4.3 and section 8).

// passOf is contract_token_state's pass: its generation, and whether it
// finished.
func (w *tokenWorld) passOf() (*uuid.UUID, bool) {
	w.t.Helper()
	var gen *uuid.UUID
	var done bool
	if err := w.pool.QueryRow(context.Background(), `SELECT pass_generation, pass_done_at IS NOT NULL FROM contract_token_state`).Scan(&gen, &done); err != nil {
		w.t.Fatal(err)
	}
	return gen, done
}

// A reset after a signed gone stores no generation, so it cannot name the
// one its pass lists: the first answer that adopts a generation starts that
// pass (the account feed's page, or a sign-in's document), so a token the
// restored platform no longer has is still refused once it is done.
func TestAGoneResetStillFinishesItsPass(t *testing.T) {
	for _, by := range []string{"the account feed's page", "a sign-in's document"} {
		t.Run(by, func(t *testing.T) {
			w := newTokenWorld(t)
			ctx := w.ctx()
			kept, gone := uuid.New(), uuid.New()
			w.page(false, w.record(kept, 1), w.record(gone, 2))
			if ok, err := w.contract.RestartFromTokens(ctx, w.gen, nil, false); err != nil || !ok {
				t.Fatalf("the gone's reset: %v %v", ok, err)
			}
			if gen, _ := w.passOf(); gen != nil {
				t.Fatalf("a gone's reset named the pass %v", gen)
			}
			next := uuid.New()
			switch by {
			case "the account feed's page":
				res, err := w.contract.CommitPage(ctx, store.ContractPage{After: 0, Generation: next, NextAfter: 0, PublishedThrough: w.now,
					Docs: []store.ContractDoc{}})
				if err != nil || !res.Committed {
					t.Fatalf("the adopting page: %+v %v", res, err)
				}
			default:
				doc := store.ContractDoc{Sub: w.ownerSub, Generation: next, Version: 1, Status: kc.AccountActive,
					Raw: []byte(`{"v":1,"workspaces":[]}`)}
				if _, err := w.contract.StoreDocuments(ctx, store.ContractAnswer, doc); err != nil {
					t.Fatalf("the adopting document: %v", err)
				}
			}
			if gen, done := w.passOf(); gen == nil || *gen != next || done {
				t.Fatalf("after the adoption the pass is %v (done %t), want %s", gen, done, next)
			}
			// The pass from 0 lists one of the two; the round runs in the
			// generation; the page with more false makes it ready.
			w.gen = next
			w.seq = 0
			w.exec(`UPDATE contract_state SET round_generation = $1`, next)
			if res := w.page(false, w.record(kept, 1)); !res.PassReady {
				t.Fatalf("the pass is not ready: %+v", res)
			}
			res, err := w.tokens.FinishTokenPass(ctx, next, w.now)
			if err != nil || !res.Done || len(res.Unlisted) != 1 || res.Unlisted[0] != gone {
				t.Fatalf("FinishTokenPass: %+v %v", res, err)
			}
		})
	}
}

// The token mode's switch: on needs the contract on and clears
// caught_up_at; the same mode again changes nothing; the follower's own
// state, failures and slow commits are kept for status.
func TestTheTokenModeAndTheFollowersState(t *testing.T) {
	w := newTokenWorld(t)
	ctx := context.Background()
	if _, err := w.tokens.SetMode(ctx, store.TokensOn, w.now); !errors.Is(err, store.ErrTokensNeedTheContract) {
		t.Fatalf("tokens on with the contract off: %v", err)
	}
	if _, err := w.tokens.SetMode(ctx, "sideways", w.now); !errors.Is(err, store.ErrTokensMode) {
		t.Fatalf("an unknown token mode: %v", err)
	}
	if _, err := w.contract.SetMode(ctx, store.ContractObserve); err != nil {
		t.Fatal(err)
	}
	w.exec(`UPDATE contract_token_state SET caught_up_at = clock_timestamp()`)
	change, err := w.tokens.SetMode(ctx, store.TokensOn, w.now)
	if err != nil || !change.Changed || change.From != store.TokensOff {
		t.Fatalf("tokens on: %+v %v", change, err)
	}
	st, err := w.tokens.TokenStatus(ctx, w.now.Add(-24*time.Hour))
	if err != nil || st.Mode != store.TokensOn || st.CaughtUpAt != nil || !st.ModeChangedAt.Equal(w.now) {
		t.Fatalf("after tokens on: %+v %v", st, err)
	}
	if change, err := w.tokens.SetMode(ctx, store.TokensOn, w.now); err != nil || change.Changed {
		t.Fatalf("tokens on again: %+v %v", change, err)
	}

	if err := w.tokens.FeedFailed(ctx, "unavailable", w.now); err != nil {
		t.Fatal(err)
	}
	if err := w.tokens.FeedFailed(ctx, "refused:rate_limited", w.now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := w.tokens.CommitTook(ctx, 1500*time.Millisecond, w.now); err != nil {
		t.Fatal(err)
	}
	st, err = w.tokens.TokenStatus(ctx, w.now.Add(-24*time.Hour))
	if err != nil || st.Error != "refused:rate_limited" || st.ErrorAt == nil || !st.ErrorAt.Equal(w.now) ||
		st.SlowCommit != 1500*time.Millisecond || st.SlowCommitAt == nil {
		t.Fatalf("the failing run and the slow commit: %+v %v", st, err)
	}
	f, err := w.tokens.FeedState(ctx)
	if err != nil || f.Mode != store.TokensOn || f.Generation == nil || *f.Generation != w.gen {
		t.Fatalf("the feed's state: %+v %v", f, err)
	}
	// A page's commit clears the failure.
	w.page(false)
	if st, err := w.tokens.TokenStatus(ctx, w.now); err != nil || st.Error != "" || st.ErrorAt != nil {
		t.Fatalf("after a page: %+v %v", st, err)
	}
}

// contract status's counts of the token part, workspace by workspace under
// each one's app.tenant_id: live tokens, those unlisted since, those whose
// key changed, and the open stops: every operator's, and the apply_failed
// stops of live tokens only, which only a later version that applies cleanly
// lifts, so the end of a token (unlisted, expired), or a selector Wappie
// never held, never leaves --check failing.
func TestTokenStatusCountsEveryWorkspace(t *testing.T) {
	w := newTokenWorld(t)
	ctx := context.Background()
	other := uuid.New()
	w.exec(`INSERT INTO tenants (id, name) VALUES ($1, 'other')`, other)
	a, b, c := uuid.New(), uuid.New(), uuid.New()
	inOther := func(r *kc.TokenRecord) { r.WorkspaceID = other.String() }
	w.page(false, w.record(a, 1), w.record(b, 2, inOther), w.record(c, 3))
	w.exec(`UPDATE contract_token_state SET pass_generation = $1, pass_ready_at = clock_timestamp()`, w.gen)
	w.exec(`UPDATE contract_state SET round_generation = $1`, w.gen)
	w.scoped(func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `UPDATE contract_tokens SET listed_gen = NULL WHERE id = $1`, c)
		return err
	})
	if _, err := w.tokens.FinishTokenPass(ctx, w.gen, w.now); err != nil {
		t.Fatal(err)
	}
	if err := w.tokens.StopToken(ctx, selectorOf(b), "test", "", w.now); err != nil {
		t.Fatal(err)
	}
	for _, sel := range []string{selectorOf(a), selectorOf(c), selectorOf(uuid.New())} {
		w.exec(`INSERT INTO contract_token_stops (selector, cause, stopped_at, stopped_by) VALUES ($1, 'apply_failed', clock_timestamp(), 'wappie')`, sel)
	}
	st, err := w.tokens.TokenStatus(ctx, w.now.Add(-time.Hour))
	if err != nil || st.Live != 2 || st.Unlisted != 1 || st.Stopped != 1 || st.ApplyFailed != 1 {
		t.Fatalf("the counts: live %d unlisted %d stopped %d apply_failed %d, %v", st.Live, st.Unlisted, st.Stopped, st.ApplyFailed, err)
	}
	if st, err := w.tokens.TokenStatus(ctx, w.now.Add(time.Hour)); err != nil || st.Unlisted != 0 {
		t.Fatalf("the unlisted ones since later: %d %v", st.Unlisted, err)
	}
	// a expires, its stop still open: no longer counted.
	if _, err := w.tokens.RetainTokens(ctx, w.now.Add(31*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if st, err := w.tokens.TokenStatus(ctx, w.now.Add(-time.Hour)); err != nil || st.ApplyFailed != 0 || st.Live != 0 {
		t.Fatalf("after the expiry: apply_failed %d, live %d, %v", st.ApplyFailed, st.Live, err)
	}
	if n := w.count(`SELECT count(*) FROM contract_token_stops WHERE cause = 'apply_failed' AND lifted_at IS NULL`); n != 3 {
		t.Fatalf("%d apply_failed stops open, want the three kept for tokens list", n)
	}
}

// A usage report that cannot carry all that is due says so (More), and the
// next carries the rest.
func TestUsageThatDoesNotFitSaysSo(t *testing.T) {
	w := newTokenWorld(t)
	ctx := context.Background()
	var used []store.TokenDay
	for i := range kc.MaxUsageEntries + 1 {
		used = append(used, store.TokenDay{Token: uuid.New(), Day: w.now.AddDate(0, 0, -i%3)})
	}
	if err := w.tokens.AddTokenUse(ctx, store.TokenUse{Used: used}); err != nil {
		t.Fatal(err)
	}
	body, err := w.tokens.UsageBody(ctx)
	if err != nil || !body.More || len(body.Body.Used) != kc.MaxUsageEntries {
		t.Fatalf("the first report: %d entries, more %t, %v", len(body.Body.Used), body.More, err)
	}
	if err := w.tokens.UsageSent(ctx, body, w.now); err != nil {
		t.Fatal(err)
	}
	body, err = w.tokens.UsageBody(ctx)
	if err != nil || body.More || len(body.Body.Used) != 1 {
		t.Fatalf("the rest: %d entries, more %t, %v", len(body.Body.Used), body.More, err)
	}
}
