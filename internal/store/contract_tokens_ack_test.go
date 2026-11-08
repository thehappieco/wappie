package store_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
)

func (w *tokenWorld) ackBody() store.TokenAck {
	w.t.Helper()
	a, ok, err := w.tokens.AckBody(context.Background())
	if err != nil || !ok {
		w.t.Fatalf("AckBody: %v %v", ok, err)
	}
	if err := a.Body.Validate(); err != nil {
		w.t.Fatalf("Wappie's acknowledgement is not valid: %v", err)
	}
	// What the platform decodes, strictly.
	b, err := json.Marshal(a.Body)
	if err != nil {
		w.t.Fatal(err)
	}
	var back kc.TokenApplied
	if err := json.Unmarshal(b, &back); err != nil || back.Validate() != nil {
		w.t.Fatalf("the acknowledgement does not round-trip: %v", err)
	}
	return a
}

// The acknowledgement: through is the cursor; refusals are sent once, on an
// accepted answer only (held tokens too:
// TestAHeldEntryIsSentOnceAndAMergeStaysDue); the waiting and suspended sets
// go whole, only when they change, suspended computed per workspace; and
// every body stays within the four lists' one budget of 1000
// (TestOverflowGoesInFurtherAcksAtTheSameThrough).
func TestTheAcknowledgementSendsEachEntryOnce(t *testing.T) {
	w := newTokenWorld(t)
	if _, ok, err := w.tokens.AckBody(context.Background()); err != nil || ok {
		t.Fatalf("an acknowledgement before any page: %v %v", ok, err)
	}
	device := w.number(uuid.Nil)
	waitingSub := uuid.New()
	w.linked("waiting", "admin", waitingSub, false)
	refused, waiting, stopped := uuid.New(), uuid.New(), uuid.New()
	w.page(false,
		w.record(refused, 1, func(r *kc.TokenRecord) {
			r.Items = []kc.TokenItem{{ID: "gone", Kind: kc.ItemNumber, Perms: []kc.TokenPerm{{Perm: kc.CanRead, GrantedBy: w.ownerSub.String(), GrantedAt: kc.T(w.now)}}}}
		}),
		w.record(waiting, 1, grants(device, waitingSub, w.now, kc.CanSend)),
		w.record(stopped, 1))
	w.judge()
	if _, err := w.tokens.StopToken(w.ctx(), selectorOf(stopped), "root", "", w.now); err != nil {
		t.Fatal(err)
	}
	a := w.ackBody()
	if a.Body.Generation != w.gen.String() || a.Body.Through != w.cursor() || !a.Body.AppliedAt.Equal(w.now) {
		t.Fatalf("the acknowledgement's head: %+v", a.Body)
	}
	if len(a.Body.Refused) != 1 || a.Body.Refused[0] != (kc.TokenRefusal{Token: refused.String(), Version: 1, Item: "gone", Perm: kc.CanRead, Code: kc.RefusedItemUnknown}) {
		t.Fatalf("refused: %+v", a.Body.Refused)
	}
	if len(a.Body.Waiting) != 1 || a.Body.Waiting[0].Token != waiting.String() || a.Body.Waiting[0].GrantedBy != waitingSub.String() {
		t.Fatalf("waiting: %+v", a.Body.Waiting)
	}
	if len(a.Body.Suspended) != 1 || a.Body.Suspended[0] != (kc.Suspension{Token: stopped.String(), Cause: kc.SuspendedOperator}) {
		t.Fatalf("suspended: %+v", a.Body.Suspended)
	}
	// Not accepted: everything again.
	if err := w.tokens.AckFailed(context.Background(), "unavailable", w.now); err != nil {
		t.Fatal(err)
	}
	if again := w.ackBody(); len(again.Body.Refused) != 1 || again.Body.Waiting == nil || again.Body.Suspended == nil {
		t.Fatalf("after a failure: %+v", again.Body)
	}
	if err := w.tokens.AckSent(context.Background(), a, w.now); err != nil {
		t.Fatal(err)
	}
	next := w.ackBody()
	st, err := w.tokens.AckState(context.Background())
	if err != nil || !next.Empty(st.Acked) || len(next.Body.Refused) != 0 || next.Body.Waiting != nil || next.Body.Suspended != nil {
		t.Fatalf("after it was accepted: %+v %+v %v", next.Body, st, err)
	}
	// A change sends the whole set again; a lifted stop empties it.
	if _, _, err := w.tokens.LiftToken(w.ctx(), selectorOf(stopped), w.now); err != nil {
		t.Fatal(err)
	}
	if lifted := w.ackBody(); lifted.Body.Suspended == nil || len(lifted.Body.Suspended) != 0 || lifted.Body.Waiting != nil {
		t.Fatalf("after the lift: %+v", lifted.Body)
	}
}

// TestAHeldEntryIsSentOnceAndAMergeStaysDue: a reset's pass queues a token
// held narrower than its record; the acknowledgement carries it, and once
// accepted it is not sent again. An entry that changed between the body and
// its acceptance (a later page of the pass merged more into it, a refusal
// recoded) was not what the platform accepted: it stays due, and goes
// whole in the next body.
func TestAHeldEntryIsSentOnceAndAMergeStaysDue(t *testing.T) {
	w := newTokenWorld(t)
	one, two := w.number(uuid.Nil), w.number(uuid.Nil)
	id := uuid.New()
	early := w.now.Add(-time.Hour)
	// Both grants unjudged at the reset: neither was held, so the pass's
	// record that lists them again is held narrower.
	w.page(false, w.record(id, 1, grants(one, w.ownerSub, early, kc.CanSend), grants(two, w.ownerSub, early, kc.CanSend)))
	w.reset()
	w.page(true, w.record(id, 1, grants(one, w.ownerSub, early, kc.CanSend)))
	first := w.ackBody()
	if len(first.Body.Held) != 1 || len(first.Body.Held[0].Removed) != 1 {
		t.Fatalf("the first body's held: %+v", first.Body.Held)
	}
	// A refusal in the same body, recoded before the platform accepts it.
	w.exec(`INSERT INTO contract_token_refusals_out (token_id, version, item, perm, code) VALUES ($1, 1, $2, 'read', 'local_role')`, id, one.String())
	first = w.ackBody()
	if len(first.Body.Refused) != 1 || len(first.Body.Held) != 1 {
		t.Fatalf("the first body: %+v", first.Body)
	}
	w.page(true, w.record(id, 2, grants(one, w.ownerSub, early, kc.CanSend), grants(two, w.ownerSub, early, kc.CanSend)))
	w.exec(`UPDATE contract_token_refusals_out SET code = 'giver_not_reader', queued_at = clock_timestamp() WHERE token_id = $1`, id)
	if err := w.tokens.AckSent(context.Background(), first, w.now); err != nil {
		t.Fatal(err)
	}
	next := w.ackBody()
	if len(next.Body.Held) != 1 || len(next.Body.Held[0].Removed) != 2 {
		t.Fatalf("a merged held entry was taken for sent: %+v", next.Body.Held)
	}
	if len(next.Body.Refused) != 1 || next.Body.Refused[0].Code != kc.RefusedGiverNotReader {
		t.Fatalf("a recoded refusal was taken for sent: %+v", next.Body.Refused)
	}
	if err := w.tokens.AckSent(context.Background(), next, w.now); err != nil {
		t.Fatal(err)
	}
	if last := w.ackBody(); len(last.Body.Held) != 0 || len(last.Body.Refused) != 0 {
		t.Fatalf("sent entries went again: %+v", last.Body)
	}
}

// A reset that commits while an acknowledgement is in flight (after the
// platform accepted it, before AckSent) starts the acknowledgement again:
// the old generation's through, sets and refusals are not written over the
// new one's, so the new generation is told both sets whole, though they did
// not change, and a refusal its records bring again.
func TestAResetBeforeAckSentStartsTheAcknowledgementAgain(t *testing.T) {
	w := newTokenWorld(t)
	ctx := w.ctx()
	device := w.number(uuid.Nil)
	waitingSub := uuid.New()
	w.linked("waiting", "admin", waitingSub, false)
	refused, waiting, stopped := uuid.New(), uuid.New(), uuid.New()
	unknown := func(r *kc.TokenRecord) {
		r.Items = []kc.TokenItem{{ID: "gone", Kind: kc.ItemNumber, Perms: []kc.TokenPerm{{Perm: kc.CanRead, GrantedBy: w.ownerSub.String(), GrantedAt: kc.T(w.now)}}}}
	}
	records := func() []any {
		return []any{w.record(refused, 1, unknown), w.record(waiting, 1, grants(device, waitingSub, w.now, kc.CanSend)), w.record(stopped, 1)}
	}
	w.page(false, records()...)
	w.judge()
	if _, err := w.tokens.StopToken(ctx, selectorOf(stopped), "root", "", w.now); err != nil {
		t.Fatal(err)
	}
	inFlight := w.ackBody()
	if len(inFlight.Body.Refused) != 1 || len(inFlight.Body.Waiting) != 1 || len(inFlight.Body.Suspended) != 1 {
		t.Fatalf("the acknowledgement in flight: %+v", inFlight.Body)
	}

	// The platform accepts it; a reset to another generation commits, and
	// the new generation's pass from 0 brings the same records again.
	next := uuid.New()
	if ok, err := w.contract.RestartFromTokens(ctx, w.gen, &next, true); err != nil || !ok {
		t.Fatalf("the reset: %v %v", ok, err)
	}
	w.gen, w.seq = next, 0
	w.page(false, records()...)
	if err := w.tokens.AckSent(ctx, inFlight, w.now); err != nil {
		t.Fatal(err)
	}
	st, err := w.tokens.AckState(ctx)
	if err != nil || st.Acked != 0 {
		t.Fatalf("the old generation's through %d was kept in the new one (%v)", st.Acked, err)
	}
	again := w.ackBody()
	if again.Body.Generation != next.String() || len(again.Body.Waiting) != 1 || len(again.Body.Suspended) != 1 {
		t.Fatalf("the new generation's first acknowledgement: generation %s, waiting %+v, suspended %+v", again.Body.Generation,
			again.Body.Waiting, again.Body.Suspended)
	}
	if len(again.Body.Refused) != 1 || again.Body.Refused[0] != inFlight.Body.Refused[0] {
		t.Fatalf("the refusal the new generation's record brings: %+v", again.Body.Refused)
	}
	// Accepted in its own generation, it is marked as before.
	if err := w.tokens.AckSent(ctx, again, w.now); err != nil {
		t.Fatal(err)
	}
	if st, err := w.tokens.AckState(ctx); err != nil || st.Acked != again.Body.Through {
		t.Fatalf("after the new generation's acknowledgement: %+v %v", st, err)
	}
	if last := w.ackBody(); len(last.Body.Refused) != 0 || last.Body.Waiting != nil || last.Body.Suspended != nil {
		t.Fatalf("after it was accepted: %+v", last.Body)
	}
}

// The four lists share one budget of 1000: a waiting set that does not fit
// beside the refusals goes in its own acknowledgement at the same through,
// and one over 1000 goes as its first 1000 with waiting_more.
func TestOverflowGoesInFurtherAcksAtTheSameThrough(t *testing.T) {
	w := newTokenWorld(t)
	device := w.number(uuid.Nil)
	w.page(false, w.record(uuid.New(), 1))
	// 990 refusals and 20 waiting perms, written as the commit and the
	// judge would.
	w.exec(`INSERT INTO contract_token_refusals_out (token_id, version, item, perm, code)
		SELECT gen_random_uuid(), 1, 'x' || g, 'read', 'local_role' FROM generate_series(1, 990) g`)
	ids := make([]uuid.UUID, 1001)
	for i := range ids {
		ids[i] = uuid.New()
	}
	waitingRows := func(n int) {
		w.exec(`INSERT INTO contract_token_selectors (selector, token_id, tenant_id, hash, until)
			SELECT substr(md5(t::text), 1, 16), t, $1, decode(repeat('ab', 32), 'hex'), clock_timestamp() + interval '1 day'
			FROM unnest($2::uuid[]) t`, w.tenant, ids[:n])
		w.scoped(func(tx pgx.Tx) error {
			ctx := context.Background()
			if _, err := tx.Exec(ctx, `INSERT INTO contract_tokens (id, tenant_id, name, created_by, created_at, expires_at)
				SELECT t, $1, 'n', $2, clock_timestamp(), clock_timestamp() + interval '1 day' FROM unnest($3::uuid[]) t`, w.tenant, w.ownerSub, ids[:n]); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO contract_token_perms (token_id, tenant_id, device_id, perm, granted_by, granted_at, generation, version, state)
				SELECT t, $1, $2, 'send', $3, clock_timestamp(), $4, 1, 'waiting' FROM unnest($5::uuid[]) t`, w.tenant, device, w.ownerSub, w.gen, ids[:n])
			return err
		})
	}
	waitingRows(20)
	first := w.ackBody()
	// More: the waiting set did not fit, and its own acknowledgement goes
	// at once.
	if len(first.Body.Refused) != 990 || first.Body.Waiting != nil || !first.More {
		t.Fatalf("the first: %d refused, waiting %v, more %t", len(first.Body.Refused), first.Body.Waiting != nil, first.More)
	}
	if err := w.tokens.AckSent(context.Background(), first, w.now); err != nil {
		t.Fatal(err)
	}
	second := w.ackBody()
	if len(second.Body.Refused) != 0 || len(second.Body.Waiting) != 20 || second.Body.Through != first.Body.Through || second.More {
		t.Fatalf("the second: %d refused, %d waiting, through %d, more %t", len(second.Body.Refused), len(second.Body.Waiting),
			second.Body.Through, second.More)
	}
	if err := w.tokens.AckSent(context.Background(), second, w.now); err != nil {
		t.Fatal(err)
	}
	// Over 1000: its first 1000, with waiting_more.
	w.scoped(func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `DELETE FROM contract_tokens`)
		return err
	})
	w.exec(`ALTER TABLE contract_token_selectors DISABLE TRIGGER contract_token_selectors_guard; DELETE FROM contract_token_selectors;
		ALTER TABLE contract_token_selectors ENABLE TRIGGER contract_token_selectors_guard`)
	waitingRows(1001)
	big := w.ackBody()
	if len(big.Body.Waiting) != 1000 || !bool(big.Body.WaitingMore) || big.More {
		t.Fatalf("over 1000: %d waiting, waiting_more %v, more %t", len(big.Body.Waiting), big.Body.WaitingMore, big.More)
	}
	if err := w.tokens.AckSent(context.Background(), big, w.now); err != nil {
		t.Fatal(err)
	}
	// A suspended set over 1000 behind a refusal: More, and the next
	// acknowledgement carries its first 1000, with suspended_more.
	w.exec(`INSERT INTO contract_token_refusals_out (token_id, version, item, perm, code) VALUES (gen_random_uuid(), 1, 'y', 'read', 'local_role')`)
	w.exec(`INSERT INTO contract_token_stops (selector, cause, stopped_at, stopped_by) SELECT selector, 'operator', clock_timestamp(), 'root'
		FROM contract_token_selectors`)
	behind := w.ackBody()
	if len(behind.Body.Refused) != 1 || behind.Body.Suspended != nil || !behind.More {
		t.Fatalf("behind a refusal: %d refused, suspended %v, more %t", len(behind.Body.Refused), behind.Body.Suspended != nil, behind.More)
	}
	if err := w.tokens.AckSent(context.Background(), behind, w.now); err != nil {
		t.Fatal(err)
	}
	stops := w.ackBody()
	if len(stops.Body.Refused) != 0 || len(stops.Body.Suspended) != 1000 || !bool(stops.Body.SuspendedMore) || stops.More ||
		stops.Body.Through != behind.Body.Through {
		t.Fatalf("the suspended set: %d refused, %d suspended, suspended_more %v, more %t", len(stops.Body.Refused), len(stops.Body.Suspended),
			stops.Body.SuspendedMore, stops.More)
	}
}

// TestUsageIsAbsoluteAndCountedPerRow: several processes add their deltas
// to one row per key, the report carries each row's absolute count, a row
// is reported only on acceptance, and only what rose since goes again.
func TestUsageIsAbsoluteAndCountedPerRow(t *testing.T) {
	w := newTokenWorld(t)
	token, device := uuid.New(), uuid.New()
	day := time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)
	read := kc.CanRead
	one := store.TokenUse{
		Used: []store.TokenDay{{Token: token, Day: day.Add(3 * time.Hour)}},
		Refusals: []store.TokenUseRefusal{
			{Token: token, Day: day, Device: &device, Perm: &read, Code: kc.UseNoGrant, Count: 2},
			{Token: token, Day: day, Code: kc.UseRevoked, Count: 1},
		},
	}
	for range 2 { // two processes' flushes
		if err := w.tokens.AddTokenUse(context.Background(), one); err != nil {
			t.Fatal(err)
		}
	}
	u, err := w.tokens.UsageBody(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := u.Body.Validate(); err != nil {
		t.Fatalf("Wappie's usage report is not valid: %v", err)
	}
	if len(u.Body.Used) != 1 || u.Body.Used[0] != (kc.TokenUsed{Token: token.String(), Day: "2026-10-27"}) || len(u.Body.Refusals) != 2 {
		t.Fatalf("the report: %+v", u.Body)
	}
	counts := map[string]int64{}
	for _, r := range u.Body.Refusals {
		counts[r.Code] = r.Count
	}
	if counts[kc.UseNoGrant] != 4 || counts[kc.UseRevoked] != 2 {
		t.Fatalf("the counts: %v", counts)
	}
	if err := w.tokens.UsageSent(context.Background(), u, w.now); err != nil {
		t.Fatal(err)
	}
	if again, err := w.tokens.UsageBody(context.Background()); err != nil || !again.Empty() {
		t.Fatalf("after it was accepted: %+v %v", again.Body, err)
	}
	if err := w.tokens.AddTokenUse(context.Background(), store.TokenUse{Refusals: one.Refusals[1:]}); err != nil {
		t.Fatal(err)
	}
	if again, err := w.tokens.UsageBody(context.Background()); err != nil || len(again.Body.Refusals) != 1 || again.Body.Refusals[0].Count != 3 {
		t.Fatalf("after one more: %+v %v", again.Body, err)
	}
}

// TestTokenUseDaysAreUTC (the design's 3.8): a use's day, and the days
// retention keeps, are UTC days whatever the database session's time zone:
// here São Paulo's, three hours behind, where 01:00 UTC is the day before.
// A day's rows, once reported, go at the start of the second UTC day after
// it: at most 2 days after they were reported.
func TestTokenUseDaysAreUTC(t *testing.T) {
	pool := pgtest.FreshWith(t, migrate.Run, func(cfg *pgxpool.Config) {
		cfg.ConnConfig.RuntimeParams["timezone"] = "America/Sao_Paulo"
	})
	tokens := store.NewTokens(pool)
	ctx := context.Background()
	token, workspace := uuid.New(), uuid.New()
	// Its selector, which Wappie keeps a year on: usage rows are written
	// only for a token whose secret matched it. Its workspace is there: a
	// token of a workspace whose row is gone loses its days of use at the
	// next pass.
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, 'Acme')`, workspace); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO contract_token_selectors (selector, token_id, tenant_id, hash, until)
		VALUES ('0123456789abcdef', $1, $2, decode(repeat('00', 32), 'hex'), clock_timestamp() + interval '365 days')`, token, workspace); err != nil {
		t.Fatal(err)
	}
	use := time.Date(2026, 10, 28, 1, 0, 0, 0, time.UTC)
	if err := tokens.AddTokenUse(ctx, store.TokenUse{Used: []store.TokenDay{{Token: token, Day: use}},
		Refusals: []store.TokenUseRefusal{{Token: token, Day: use, Code: kc.UseRevoked, Count: 1}}}); err != nil {
		t.Fatal(err)
	}
	u, err := tokens.UsageBody(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(u.Body.Used) != 1 || u.Body.Used[0].Day != "2026-10-28" || len(u.Body.Refusals) != 1 || u.Body.Refusals[0].Day != "2026-10-28" {
		t.Fatalf("the days of a use at 01:00 UTC: %+v", u.Body)
	}
	if err := tokens.UsageSent(ctx, u, use); err != nil {
		t.Fatal(err)
	}
	// The 29th at 23:00 UTC (20:00 in São Paulo): the 27th, reported, goes
	// at the start of the 29th; the 28th, reported at 01:00 on the 28th,
	// stays to the start of the 30th, and goes then.
	if _, err := pool.Exec(ctx, `INSERT INTO contract_token_used (token_id, day, reported_at) VALUES ($1, '2026-10-27', clock_timestamp())`, token); err != nil {
		t.Fatal(err)
	}
	usedDays := func() []string {
		t.Helper()
		rows, err := pool.Query(ctx, `SELECT to_char(day, 'YYYY-MM-DD') FROM contract_token_used ORDER BY day`)
		if err != nil {
			t.Fatal(err)
		}
		days, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		return days
	}
	if _, err := tokens.RetainTokens(ctx, time.Date(2026, 10, 29, 23, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	if days := usedDays(); len(days) != 1 || days[0] != "2026-10-28" {
		t.Fatalf("the used days retention kept on the 29th: %v, want 2026-10-28 alone", days)
	}
	if _, err := tokens.RetainTokens(ctx, time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	if days := usedDays(); len(days) != 0 {
		t.Fatalf("the used days retention kept at the start of the 30th: %v, want none", days)
	}
	var refusals int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM contract_token_refusals`).Scan(&refusals); err != nil || refusals != 0 {
		t.Fatalf("the refusal rows retention kept at the start of the 30th: %d %v, want none", refusals, err)
	}
}
