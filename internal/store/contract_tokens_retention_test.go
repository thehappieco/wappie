package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kc "github.com/thehappieco/kit/contract"
)

// What Wappie keeps of a token, by the site's privacy text: a token's record
// up to 30 days after it ends; a security record to its created_at + 365
// days; its own stops to that date, or 365 days after the stop while no
// record of its selector has come; nothing past those, a workspace's row
// deleted or not.

const tokenDay = 24 * time.Hour

// in counts in workspace ws, its policies in force.
func (w *tokenWorld) in(ws uuid.UUID, query string, args ...any) int {
	w.t.Helper()
	var n int
	inTenantTx(context.Background(), w.t, w.pool, ws, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), query, args...).Scan(&n)
	})
	return n
}

// stopOf is a selector's operator stop: whether it is there, when it was
// made, and its record_until.
func (w *tokenWorld) stopOf(selector string) (exists bool, stopped time.Time, recordUntil *time.Time) {
	w.t.Helper()
	err := w.pool.QueryRow(context.Background(), `SELECT stopped_at, record_until FROM contract_token_stops
		WHERE selector = $1 AND cause = 'operator'`, selector).Scan(&stopped, &recordUntil)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, time.Time{}, nil
	}
	if err != nil {
		w.t.Fatal(err)
	}
	return true, stopped, recordUntil
}

// retain runs retention on Wappie's clock at.
func (w *tokenWorld) retain(at time.Time) {
	w.t.Helper()
	if _, err := w.tokens.RetainTokens(w.ctx(), at); err != nil {
		w.t.Fatal(err)
	}
}

// createdAt makes a record created at at, living for life.
func createdAt(at time.Time, life time.Duration) func(*kc.TokenRecord) {
	return func(r *kc.TokenRecord) { r.CreatedAt, r.ExpiresAt = kc.T(at), kc.T(at.Add(life)) }
}

// unknownItem lists a send on an item that is no number: an item_unknown
// removed instance, never a perm.
func unknownItem(by uuid.UUID, at time.Time) func(*kc.TokenRecord) {
	return func(r *kc.TokenRecord) {
		r.Items = append(r.Items, kc.TokenItem{ID: "not-a-number", Kind: kc.ItemNumber,
			Perms: []kc.TokenPerm{{Perm: kc.CanSend, GrantedBy: by.String(), GrantedAt: kc.T(at)}}})
	}
}

// A token's removed instances go at its selector's until at the
// latest, also when it ended less than 30 days before (so its content was
// never forgotten): a 365-day token that expires at its until, and one
// that expired 10 days before it. No removed instance keeps its giver.
func TestTokenRetentionTakesRemovedInstancesAtUntil(t *testing.T) {
	w := newTokenWorld(t)
	device := w.number(uuid.Nil)
	created := w.now.Add(-366 * tokenDay) // until: a day ago
	full, early := uuid.New(), uuid.New()
	w.page(false,
		w.record(full, 1, createdAt(created, kc.MaxTokenLifetime), unknownItem(w.ownerSub, created)),
		w.record(early, 1, createdAt(created, kc.MaxTokenLifetime-10*tokenDay), unknownItem(w.ownerSub, created),
			grants(device, w.ownerSub, created, kc.CanRead)))
	// The early one's Read dropped: a removed instance of its own.
	w.page(false, w.record(early, 2, createdAt(created, kc.MaxTokenLifetime-10*tokenDay), unknownItem(w.ownerSub, created)))
	removed := func(id uuid.UUID) int {
		t.Helper()
		return w.count(`SELECT count(*) FROM contract_token_removed WHERE token_id = $1`, id)
	}
	if removed(full) != 1 || removed(early) != 2 {
		t.Fatalf("the removed instances: %d and %d, want 1 and 2", removed(full), removed(early))
	}
	var giver bool
	w.scoped(func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT coalesce(bool_or(to_jsonb(r) ? 'granted_by'), false) FROM contract_token_removed r`).Scan(&giver)
	})
	if giver {
		t.Fatal("a removed instance keeps its giver")
	}

	// 10 days ago by Wappie's clock: the early one expired the day before,
	// and ends; before its until on both clocks, nothing goes.
	w.retain(w.now.Add(-10 * tokenDay))
	if !w.token(early).Exists || removed(early) != 2 || removed(full) != 1 {
		t.Fatal("retention before until took a token or its removed instances")
	}
	// Now, past until on both clocks: the 365-day token expires and goes in
	// the same pass; the early one, ended 10 days ago, was never forgotten.
	w.retain(w.now)
	for name, id := range map[string]uuid.UUID{"expiring at its until": full, "ended 10 days before its until": early} {
		if w.token(id).Exists || removed(id) != 0 {
			t.Errorf("a token %s: its row %v, %d removed instances left", name, w.token(id).Exists, removed(id))
		}
	}
	var selectors int
	if err := w.pool.QueryRow(context.Background(), `SELECT count(*) FROM contract_token_selectors`).Scan(&selectors); err != nil || selectors != 0 {
		t.Fatalf("%d selectors left past until (%v)", selectors, err)
	}
}

// What goes at a token's until goes on both clocks: a retention 400 days
// on by Wappie's clock, but a day after the token's creation by the
// database's, ends the token (its expiry is Wappie's clock's) and keeps its
// row, its removed instances and its queue entries.
func TestTokenRetentionWaitsForTheDatabasesClock(t *testing.T) {
	w := newTokenWorld(t)
	id := uuid.New()
	w.page(false, w.record(id, 1, unknownItem(w.ownerSub, w.now)))
	w.exec(`INSERT INTO contract_token_refusals_out (token_id, version, item, perm, code) VALUES ($1, 1, 'not-a-number', 'send', 'item_unknown')
		ON CONFLICT DO NOTHING`, id)
	removed := func() int {
		t.Helper()
		return w.count(`SELECT count(*) FROM contract_token_removed WHERE token_id = $1`, id)
	}
	if removed() != 1 {
		t.Fatal("the token has no removed instance")
	}
	got, err := w.tokens.RetainTokens(w.ctx(), w.now.Add(400*tokenDay))
	if err != nil || got.Expired != 1 || got.Ended != 0 {
		t.Fatalf("a retention ahead of the database's clock: %+v %v", got, err)
	}
	if !w.token(id).Exists || removed() != 1 || len(w.refused(id)) != 1 {
		t.Fatalf("a retention ahead of the database's clock: the token's row %v, %d removed instances, its refusals %v",
			w.token(id).Exists, removed(), w.refused(id))
	}
}

// Retention visits a workspace whose tenants row is gone, from the
// selectors alone: its tokens' removed instances and hidden identities (and
// their logins) go at once (the token rows went with the workspace, so they
// ended then), their pins, stops and selectors at their until, in the same
// pass.
func TestTokenRetentionVisitsADeletedWorkspace(t *testing.T) {
	w := newTokenWorld(t)
	gone := uuid.New()
	w.exec(`INSERT INTO tenants (id, name) VALUES ($1, 'gone')`, gone)
	inGone := func(r *kc.TokenRecord) { r.WorkspaceID = gone.String(); r.ReadingKey = readingKey(t) }
	past, live := uuid.New(), uuid.New()
	w.page(false,
		w.record(past, 1, inGone, createdAt(w.now.Add(-366*tokenDay), 300*tokenDay), unknownItem(w.ownerSub, w.now.Add(-300*tokenDay))),
		w.record(live, 1, inGone, unknownItem(w.ownerSub, w.now)))
	for _, id := range []uuid.UUID{past, live} {
		if _, err := w.tokens.StopToken(w.ctx(), selectorOf(id), "root", "", w.now); err != nil {
			t.Fatal(err)
		}
	}
	if w.in(gone, `SELECT count(*) FROM contract_token_pins`) != 2 || w.in(gone, `SELECT count(*) FROM contract_token_removed`) != 2 {
		t.Fatal("the workspace's tokens have no pins or no removed instances")
	}
	identities := func() (users, logins int) {
		t.Helper()
		if err := w.pool.QueryRow(context.Background(), `SELECT count(*) FROM user_logins WHERE email LIKE '%@token.invalid'`).Scan(&logins); err != nil {
			t.Fatal(err)
		}
		return w.in(gone, `SELECT count(*) FROM users WHERE token_identity`), logins
	}
	if users, logins := identities(); users != 1 || logins != 1 {
		t.Fatalf("the live token's identity: %d users, %d logins", users, logins)
	}
	w.exec(`DELETE FROM tenants WHERE id = $1`, gone)
	if users, logins := identities(); users != 1 || logins != 1 {
		t.Fatalf("the workspace's delete took the identity already (%d users, %d logins): nothing to prove", users, logins)
	}
	w.retain(w.now)
	if n := w.in(gone, `SELECT count(*) FROM contract_token_removed`); n != 0 {
		t.Errorf("%d removed instances of a deleted workspace's tokens left", n)
	}
	if users, logins := identities(); users != 0 || logins != 0 {
		t.Errorf("a deleted workspace's token identities left: %d users, %d logins", users, logins)
	}
	pin := func(id uuid.UUID) bool {
		t.Helper()
		return w.in(gone, `SELECT count(*) FROM contract_token_pins WHERE token_id = $1`, id) == 1
	}
	held := func(id uuid.UUID) bool {
		t.Helper()
		var n int
		if err := w.pool.QueryRow(context.Background(), `SELECT count(*) FROM contract_token_selectors WHERE token_id = $1`, id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	}
	if pin(past) || held(past) {
		t.Errorf("past its until, a deleted workspace's token keeps its pin (%v) or its selector (%v)", pin(past), held(past))
	}
	if exists, _, _ := w.stopOf(selectorOf(past)); exists {
		t.Error("past its until, a deleted workspace's token keeps its stop")
	}
	if !pin(live) || !held(live) {
		t.Errorf("before its until, a deleted workspace's token lost its pin (%v) or its selector (%v)", pin(live), held(live))
	}
	if exists, _, _ := w.stopOf(selectorOf(live)); !exists {
		t.Error("before its until, a deleted workspace's token lost its stop")
	}
}

// untilBack moves every selector's until back to at, the selectors' guard
// set aside for that alone: on Wappie's clock, so a retention at a later
// now is past it on both clocks unless the database's lags by more.
func (w *tokenWorld) untilBack(at time.Time) {
	w.t.Helper()
	w.exec(`ALTER TABLE contract_token_selectors DISABLE TRIGGER contract_token_selectors_guard`)
	w.exec(`UPDATE contract_token_selectors SET until = $1`, at)
	w.exec(`ALTER TABLE contract_token_selectors ENABLE TRIGGER contract_token_selectors_guard`)
}

// A stop of a selector Wappie holds stays while the selector does,
// however old, and no record, bad or of another token, lowers what it
// keeps; it goes with the selector. A stop of a selector Wappie never held
// goes 365 days after it was made, or earlier at the created_at + 365 days
// of a valid record of its selector, which a later record never raises
// and a re-stop keeps; a write that would not lower it is none. A bad
// record never lowers it, its token's or another's, so the stop still
// stands when the token's good record comes.
func TestTokenRetentionTakesStops(t *testing.T) {
	w := newTokenWorld(t)
	// Held: stopped 400 days ago, before its record came.
	held := uuid.New()
	if _, err := w.tokens.StopToken(w.ctx(), selectorOf(held), "root", "", w.now.Add(-400*tokenDay)); err != nil {
		t.Fatal(err)
	}
	w.page(false, w.record(held, 1))
	heldUntil := w.now.Add(-tokenDay).Add(kc.MaxTokenLifetime) // record's created_at + 365 days
	// A bad record of it, with another creation time, and another token's
	// record that claims its selector.
	w.page(false,
		w.record(held, 2, createdAt(w.now.Add(-380*tokenDay), 30*tokenDay)),
		w.record(uuid.New(), 1, func(r *kc.TokenRecord) { r.Selector = selectorOf(held) }, createdAt(w.now.Add(-380*tokenDay), 30*tokenDay)))
	if _, _, ru := w.stopOf(selectorOf(held)); ru == nil || !ru.Equal(heldUntil) {
		t.Fatalf("a held selector's stop: record_until %v, want its until %v", ru, heldUntil)
	}

	// Never held: one stopped 366 days ago, one 364 days ago.
	lapsed, standing := selectorOf(uuid.New()), selectorOf(uuid.New())
	for sel, at := range map[string]time.Time{lapsed: w.now.Add(-366 * tokenDay), standing: w.now.Add(-364 * tokenDay)} {
		if _, err := w.tokens.StopToken(w.ctx(), sel, "root", "", at); err != nil {
			t.Fatal(err)
		}
	}
	// Never held, stopped 10 days ago, then a record of its selector comes:
	// a valid one of a workspace Wappie does not hold, created 366 days ago;
	// for the other, a bad one, created 366 days ago too, which tells
	// nothing, then a valid one created 200 days ago, then a later one.
	orphan, narrowed := uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{orphan, narrowed} {
		if _, err := w.tokens.StopToken(w.ctx(), selectorOf(id), "root", "", w.now.Add(-10*tokenDay)); err != nil {
			t.Fatal(err)
		}
	}
	elsewhere := func(r *kc.TokenRecord) { r.WorkspaceID = uuid.NewString() }
	invalid := func(r *kc.TokenRecord) { r.Hash = "not a hash" }
	w.page(false,
		w.record(orphan, 1, elsewhere, createdAt(w.now.Add(-366*tokenDay), 30*tokenDay)),
		w.record(narrowed, 1, invalid, createdAt(w.now.Add(-366*tokenDay), 30*tokenDay)))
	if _, _, ru := w.stopOf(selectorOf(narrowed)); ru != nil {
		t.Fatalf("a bad record set a never-held stop's record_until to %v", *ru)
	}
	w.page(false, w.record(narrowed, 2, elsewhere, createdAt(w.now.Add(-200*tokenDay), 30*tokenDay)))
	narrowedUntil := w.now.Add(-200 * tokenDay).Add(kc.MaxTokenLifetime)
	if _, _, ru := w.stopOf(selectorOf(narrowed)); ru == nil || !ru.Equal(narrowedUntil) {
		t.Fatalf("a never-held stop after a valid record: record_until %v, want %v", ru, narrowedUntil)
	}
	xmin := func() string {
		t.Helper()
		var x string
		if err := w.pool.QueryRow(context.Background(), `SELECT xmin::text FROM contract_token_stops WHERE selector = $1`, selectorOf(narrowed)).Scan(&x); err != nil {
			t.Fatal(err)
		}
		return x
	}
	before := xmin()
	w.page(false, w.record(narrowed, 3, elsewhere, createdAt(w.now.Add(-100*tokenDay), 30*tokenDay)))
	if _, _, ru := w.stopOf(selectorOf(narrowed)); ru == nil || !ru.Equal(narrowedUntil) {
		t.Fatalf("a later record raised record_until to %v, want %v", ru, narrowedUntil)
	}
	if xmin() != before {
		t.Fatal("a record that lowers nothing rewrote the stop")
	}
	// A re-stop is made now, and keeps record_until.
	if _, err := w.tokens.StopToken(w.ctx(), selectorOf(narrowed), "root", "again", w.now); err != nil {
		t.Fatal(err)
	}
	if _, stopped, ru := w.stopOf(selectorOf(narrowed)); !stopped.Equal(w.now) || ru == nil || !ru.Equal(narrowedUntil) {
		t.Fatalf("a re-stop: stopped_at %v, record_until %v; want %v and %v", stopped, ru, w.now, narrowedUntil)
	}

	// A leaked token stopped before its record came: a bad record of it,
	// whose created_at is too old (its lifetime over 365 days, so Validate
	// refuses it), and, for another, another token's bad record that claims
	// its selector, so dated; then retention; then each token's good record.
	leaked, claimed := uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{leaked, claimed} {
		if _, err := w.tokens.StopToken(w.ctx(), selectorOf(id), "root", "leak", w.now.Add(-time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	tooOld := func(r *kc.TokenRecord) {
		r.CreatedAt, r.ExpiresAt = kc.T(w.now.Add(-400*tokenDay)), kc.T(w.now.Add(30*tokenDay))
	}
	w.page(false, w.record(leaked, 1, tooOld),
		w.record(uuid.New(), 1, func(r *kc.TokenRecord) { r.Selector = selectorOf(claimed) }, tooOld))
	for _, id := range []uuid.UUID{leaked, claimed} {
		if _, _, ru := w.stopOf(selectorOf(id)); ru != nil {
			t.Fatalf("a bad record set a stop's record_until to %v", *ru)
		}
	}

	cases := map[string]struct {
		sel  string
		want bool
	}{
		"a held selector's, made 400 days ago":                        {selectorOf(held), true},
		"a never-held selector's, made 366 days ago":                  {lapsed, false},
		"a never-held selector's, made 364 days ago":                  {standing, true},
		"one whose selector's valid record was created 366 days ago":  {selectorOf(orphan), false},
		"one whose selector's valid record was created 200 days ago":  {selectorOf(narrowed), true},
		"a leaked token's, after its bad record created 400 days ago": {selectorOf(leaked), true},
		"a leaked token's, after another's bad record claiming it":    {selectorOf(claimed), true},
	}
	w.retain(w.now)
	for name, c := range cases {
		if exists, _, _ := w.stopOf(c.sel); exists != c.want {
			t.Errorf("retention now, the stop %s: there %v, want %v", name, exists, c.want)
		}
	}
	// A retention 400 days on by Wappie's clock, but not by the database's:
	// every stop left is due by the one and not the other, and stays.
	if got, err := w.tokens.RetainTokens(w.ctx(), w.now.Add(400*tokenDay)); err != nil || got.Stops != 0 {
		t.Fatalf("a retention ahead of the database's clock: %+v %v", got, err)
	}
	for name, c := range cases {
		if exists, _, _ := w.stopOf(c.sel); exists != c.want {
			t.Errorf("retention ahead of the database's clock, the stop %s: there %v, want %v", name, exists, c.want)
		}
	}
	// The leaked tokens' good records: each held, and still stopped.
	w.page(false, w.record(leaked, 2), w.record(claimed, 1))
	for _, id := range []uuid.UUID{leaked, claimed} {
		if exists, _, _ := w.stopOf(selectorOf(id)); !w.token(id).Exists || !exists {
			t.Errorf("a leaked token's good record: its row %v, its stop there %v", w.token(id).Exists, exists)
		}
	}

	// The held selectors past their until on Wappie's clock (moved back, a
	// minute's margin for the database's): each stop goes with its selector,
	// in the same pass.
	w.untilBack(w.now.Add(-time.Minute))
	got, err := w.tokens.RetainTokens(w.ctx(), w.now)
	if err != nil {
		t.Fatal(err)
	}
	if exists, _, _ := w.stopOf(selectorOf(held)); exists || got.Stops != 3 || got.Ended != 3 {
		t.Fatalf("past its selector's until: the stop there %v, %+v", exists, got)
	}
}

// Retention returns the operator's stops it deleted, each selector's with
// its last change, for the stop record's trim: a held selector's at its
// until, a never-held one's 365 days after it was made, and one at its
// record_until, lifted; never an apply_failed stop it deletes (no line has
// it), nor a stop it keeps.
func TestTokenRetentionReturnsTheOperatorsStops(t *testing.T) {
	w := newTokenWorld(t)
	held := uuid.New()
	w.page(false, w.record(held, 1))
	lapsed, narrowed, standing, applyFailed := selectorOf(uuid.New()), selectorOf(uuid.New()), selectorOf(uuid.New()), selectorOf(uuid.New())
	for sel, at := range map[string]time.Time{selectorOf(held): w.now.Add(-2 * tokenDay), lapsed: w.now.Add(-366 * tokenDay),
		narrowed: w.now.Add(-10 * tokenDay), standing: w.now.Add(-10 * tokenDay)} {
		if _, err := w.tokens.StopToken(w.ctx(), sel, "root", "", at); err != nil {
			t.Fatal(err)
		}
	}
	if _, lifted, err := w.tokens.LiftToken(w.ctx(), narrowed, w.now.Add(-9*tokenDay)); err != nil || !lifted {
		t.Fatalf("the lift: %v %v", lifted, err)
	}
	w.exec(`UPDATE contract_token_stops SET record_until = $2 WHERE selector = $1`, narrowed, w.now.Add(-time.Minute))
	w.exec(`INSERT INTO contract_token_stops (selector, cause, stopped_at, stopped_by) VALUES ($1, 'apply_failed', $2, 'wappie')`,
		applyFailed, w.now.Add(-366*tokenDay))
	w.untilBack(w.now.Add(-time.Minute))
	got, err := w.tokens.RetainTokens(w.ctx(), w.now)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]time.Time{selectorOf(held): w.now.Add(-2 * tokenDay), lapsed: w.now.Add(-366 * tokenDay), narrowed: w.now.Add(-9 * tokenDay)}
	if got.Stops != 4 || len(got.OperatorStops) != len(want) {
		t.Fatalf("retention deleted %d stops and returned %v, want 4 and %v", got.Stops, got.OperatorStops, want)
	}
	for sel, through := range want {
		if at, ok := got.OperatorStops[sel]; !ok || !at.Equal(through) {
			t.Errorf("the stop of %s: returned %v (%v), want its last change %v", sel, at, ok, through)
		}
	}
	if exists, _, _ := w.stopOf(standing); !exists {
		t.Fatal("a standing stop went")
	}

	// What the trim reads under the record's lock: when the operator's stop
	// the database holds again was made, never another cause's.
	if _, err := w.tokens.StopToken(w.ctx(), narrowed, "root", "", w.now); err != nil {
		t.Fatal(err)
	}
	failing := selectorOf(uuid.New())
	w.exec(`INSERT INTO contract_token_stops (selector, cause, stopped_at, stopped_by) VALUES ($1, 'apply_failed', $2, 'wappie')`, failing, w.now)
	made, err := w.tokens.OperatorStopsMade(w.ctx(), []string{narrowed, lapsed, failing})
	if err != nil || len(made) != 1 || !made[narrowed].Equal(w.now) {
		t.Fatalf("the stops made again: %v %v, want %s's at %v alone", made, err, narrowed, w.now)
	}
}

// A pass that fails after deleting stops rolls them back and returns none,
// so the stop record's trim never drops a line of a stop still there.
func TestAFailedRetentionReturnsNoStops(t *testing.T) {
	w := newTokenWorld(t)
	lapsed := selectorOf(uuid.New())
	if _, err := w.tokens.StopToken(w.ctx(), lapsed, "root", "", w.now.Add(-366*tokenDay)); err != nil {
		t.Fatal(err)
	}
	// A statement the pass runs after the stops' delete fails.
	w.exec(`CREATE FUNCTION retention_fails() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'the test fails it'; END $$`)
	w.exec(`CREATE TRIGGER retention_fails BEFORE DELETE ON contract_token_refusals_out FOR EACH STATEMENT EXECUTE FUNCTION retention_fails()`)
	got, err := w.tokens.RetainTokens(w.ctx(), w.now)
	if err == nil || !strings.Contains(err.Error(), "the test fails it") {
		t.Fatalf("retention: %v", err)
	}
	if got.Stops != 0 || got.OperatorStops != nil {
		t.Fatalf("a failed pass returned %+v", got)
	}
	if exists, _, _ := w.stopOf(lapsed); !exists {
		t.Fatal("a failed pass deleted a stop")
	}
}

// A stop's times never go back, so the stop record's line, which carries
// the time the database returns, is never later than its stop's last
// change: a re-stop timed before the stop (two commands at once, the later
// timed first, or a clock stepped back) is made at the stop's time, a lift
// timed before its stop at the stop's, and a re-stop timed before the lift
// at the lift's. A lift of a stop lifted already changes nothing and gives
// that lift's time; with no operator's stop of the selector (none, or only
// Wappie's own), none.
func TestAStopsTimesNeverGoBack(t *testing.T) {
	w := newTokenWorld(t)
	sel, failing := selectorOf(uuid.New()), selectorOf(uuid.New())
	base, ms := w.now, time.Millisecond
	stored := func() (time.Time, *time.Time) {
		t.Helper()
		var stopped time.Time
		var lifted *time.Time
		if err := w.pool.QueryRow(context.Background(), `SELECT stopped_at, lifted_at FROM contract_token_stops
			WHERE selector = $1 AND cause = 'operator'`, sel).Scan(&stopped, &lifted); err != nil {
			t.Fatal(err)
		}
		return stopped, lifted
	}
	stop := func(at, want time.Time) {
		t.Helper()
		got, err := w.tokens.StopToken(w.ctx(), sel, "root", "", at)
		if stopped, lifted := stored(); err != nil || !got.Equal(want) || !stopped.Equal(want) || lifted != nil {
			t.Fatalf("a stop at %v: returned %v, stored %v lifted %v, %v; want %v, open", at, got, stopped, lifted, err, want)
		}
	}
	lift := func(at, want time.Time, wantLifted bool) {
		t.Helper()
		got, lifted, err := w.tokens.LiftToken(w.ctx(), sel, at)
		if _, was := stored(); err != nil || lifted != wantLifted || !got.Equal(want) || was == nil || !was.Equal(want) {
			t.Fatalf("a lift at %v: returned %v %v, stored %v, %v; want %v %v", at, got, lifted, was, err, want, wantLifted)
		}
	}
	stop(base.Add(ms), base.Add(ms))
	stop(base, base.Add(ms))
	lift(base, base.Add(ms), true)
	lift(base.Add(time.Hour), base.Add(ms), false)
	stop(base.Add(-time.Hour), base.Add(ms))
	lift(base.Add(2*ms), base.Add(2*ms), true)
	stop(base.Add(3*ms), base.Add(3*ms))

	w.exec(`INSERT INTO contract_token_stops (selector, cause, stopped_at, stopped_by) VALUES ($1, 'apply_failed', $2, 'wappie')`, failing, base)
	for _, s := range []string{failing, selectorOf(uuid.New())} {
		if at, lifted, err := w.tokens.LiftToken(w.ctx(), s, base); err != nil || lifted || !at.IsZero() {
			t.Fatalf("a lift with no operator's stop: %v %v %v", at, lifted, err)
		}
	}
}

// stickyUntil is a token's sticky until, nil with no row.
func (w *tokenWorld) stickyUntil(id uuid.UUID) *time.Time {
	w.t.Helper()
	var at time.Time
	err := w.pool.QueryRow(context.Background(), `SELECT until FROM contract_token_sticky WHERE token_id = $1`, id).Scan(&at)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		w.t.Fatal(err)
	}
	return &at
}

// The revocation of a token Wappie never held sticks to a valid record's
// created_at + 365 days (never past Wappie's clock + 365 days), and not at
// all once that has passed, as a record of a workspace Wappie does not
// hold. A bad record's sticks to Wappie's clock + 365 days whatever its own
// times say, a record with none too (H2), so a later unrevoked record of
// the token, as after a platform restore, never makes a live row; a later
// valid record lowers it, past now or not.
func TestANeverHeldRevocationSticksToItsCreation(t *testing.T) {
	w := newTokenWorld(t)
	elsewhere := func(r *kc.TokenRecord) { r.WorkspaceID = uuid.NewString() }
	invalid := func(r *kc.TokenRecord) { r.Hash = "not a hash" }
	revoked := revokedBy(kc.RevokedInConsole, w.now.Add(-time.Hour))
	ids := map[string]uuid.UUID{}
	for _, name := range []string{"elsewhere", "bad", "ahead", "lapsed", "lapsed bad", "no creation", "narrowed", "narrowed past"} {
		ids[name] = uuid.New()
	}
	noCreation, err := json.Marshal(w.record(ids["no creation"], 1, invalid, revoked))
	if err != nil {
		t.Fatal(err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(noCreation, &members); err != nil {
		t.Fatal(err)
	}
	delete(members, "created_at")
	if noCreation, err = json.Marshal(members); err != nil {
		t.Fatal(err)
	}
	w.page(false,
		w.record(ids["elsewhere"], 1, elsewhere, createdAt(w.now.Add(-100*tokenDay), 200*tokenDay), revoked),
		w.record(ids["bad"], 1, invalid, createdAt(w.now.Add(-10*tokenDay), 30*tokenDay), revoked),
		w.record(ids["ahead"], 1, elsewhere, createdAt(w.now.Add(10*tokenDay), 30*tokenDay), revoked),
		w.record(ids["lapsed"], 1, elsewhere, createdAt(w.now.Add(-400*tokenDay), 30*tokenDay), revoked),
		w.record(ids["lapsed bad"], 1, invalid, createdAt(w.now.Add(-365*tokenDay), 30*tokenDay), revoked),
		json.RawMessage(noCreation),
		w.record(ids["narrowed"], 1, elsewhere, invalid, createdAt(w.now.Add(-100*tokenDay), 30*tokenDay), revoked),
		w.record(ids["narrowed past"], 1, elsewhere, invalid, createdAt(w.now.Add(-400*tokenDay), 30*tokenDay), revoked))
	check := func(when string, wants map[string]*time.Time) {
		t.Helper()
		for name, want := range wants {
			got := w.stickyUntil(ids[name])
			switch {
			case want == nil && got != nil:
				t.Errorf("%s, %s: a sticky row to %v, want none", when, name, *got)
			case want != nil && (got == nil || !got.Equal(*want)):
				t.Errorf("%s, %s: a sticky row to %v, want %v", when, name, got, *want)
			}
		}
	}
	yearOn := w.now.Add(kc.MaxTokenLifetime)
	check("the first records", map[string]*time.Time{
		"elsewhere":     new(w.now.Add(-100 * tokenDay).Add(kc.MaxTokenLifetime)),
		"bad":           &yearOn,
		"ahead":         &yearOn,
		"no creation":   &yearOn,
		"lapsed":        nil,
		"lapsed bad":    &yearOn,
		"narrowed":      &yearOn,
		"narrowed past": &yearOn,
	})
	// Their valid records: the bad ones' until lowered to theirs, one to a
	// time already past, which the next retention lets go.
	w.page(false,
		w.record(ids["narrowed"], 2, elsewhere, createdAt(w.now.Add(-100*tokenDay), 30*tokenDay), revoked),
		w.record(ids["narrowed past"], 2, elsewhere, createdAt(w.now.Add(-400*tokenDay), 30*tokenDay), revoked))
	check("their valid records", map[string]*time.Time{
		"narrowed":      new(w.now.Add(-100 * tokenDay).Add(kc.MaxTokenLifetime)),
		"narrowed past": new(w.now.Add(-400 * tokenDay).Add(kc.MaxTokenLifetime)),
	})
	w.retain(w.now)
	check("retention", map[string]*time.Time{"narrowed past": nil, "lapsed bad": &yearOn})

	// A platform restore: the bad records' tokens listed unrevoked, valid,
	// in the workspace: neither is ever a live row.
	w.reset()
	if res := w.page(false, w.record(ids["bad"], 1), w.record(ids["lapsed bad"], 1)); res.Bad != 2 {
		t.Fatalf("the restored records: %+v", res)
	}
	for _, name := range []string{"bad", "lapsed bad"} {
		if w.token(ids[name]).Exists {
			t.Errorf("%s: a revoked token came back live after a platform restore", name)
		}
	}
}

// A revocation of a token whose selector Wappie keeps with no row of it
// (its workspace's row gone) sticks to that selector's until, the stored
// created_at + 365 days, whatever the record says: none, or a later one.
func TestAKeptSelectorsRevocationSticksToItsUntil(t *testing.T) {
	w := newTokenWorld(t)
	gone := uuid.New()
	w.exec(`INSERT INTO tenants (id, name) VALUES ($1, 'gone')`, gone)
	inGone := func(r *kc.TokenRecord) { r.WorkspaceID = gone.String() }
	missing, later := uuid.New(), uuid.New()
	w.page(false, w.record(missing, 1, inGone), w.record(later, 1, inGone))
	w.exec(`DELETE FROM tenants WHERE id = $1`, gone)
	revoked := revokedBy(kc.RevokedInConsole, w.now)
	noCreation, err := json.Marshal(w.record(missing, 2, inGone, revoked))
	if err != nil {
		t.Fatal(err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(noCreation, &members); err != nil {
		t.Fatal(err)
	}
	delete(members, "created_at")
	if noCreation, err = json.Marshal(members); err != nil {
		t.Fatal(err)
	}
	w.page(false, json.RawMessage(noCreation), w.record(later, 2, inGone, revoked, createdAt(w.now.Add(-time.Hour), 30*tokenDay)))
	stored := w.now.Add(-tokenDay).Add(kc.MaxTokenLifetime)
	for name, id := range map[string]uuid.UUID{"with no created_at": missing, "with a later created_at": later} {
		if got := w.stickyUntil(id); got == nil || !got.Equal(stored) {
			t.Errorf("a kept selector's revocation %s: sticky until %v, want the stored %v", name, got, stored)
		}
	}
}

// A replayed line of the stop record over 365 days old is left, so a
// replay never brings back a stop retention let go; a younger one applies.
func TestReplayLeavesALapsedStop(t *testing.T) {
	w := newTokenWorld(t)
	old, young := selectorOf(uuid.New()), selectorOf(uuid.New())
	if applied, err := w.tokens.ReplayTokenStop(w.ctx(), old, "root", "", w.now.Add(-365*tokenDay), w.now); err != nil || applied {
		t.Fatalf("a line 365 days old: applied %v, %v", applied, err)
	}
	if exists, _, _ := w.stopOf(old); exists {
		t.Fatal("a line 365 days old brought its stop back")
	}
	if applied, err := w.tokens.ReplayTokenStop(w.ctx(), young, "root", "", w.now.Add(-364*tokenDay), w.now); err != nil || !applied {
		t.Fatalf("a line 364 days old: applied %v, %v", applied, err)
	}
	if exists, _, _ := w.stopOf(young); !exists {
		t.Fatal("a line 364 days old was left")
	}
}

// Retention past a token's until deletes its perms (the token row's
// cascade) before its removed instances, as a number's drop does
// (dropNumberTokensTx: the number's perms, then their instances, ON
// CONFLICT DO NOTHING, the key a refused perm shares with its instance):
// so with the drop holding the perm, retention waits on it having taken no
// instance, and the drop's insert never waits on retention. Taken the other
// way, each would wait on the other.
func TestTokenRetentionBesideANumbersDrop(t *testing.T) {
	w := newTokenWorld(t)
	ctx := context.Background()
	device, id := w.number(uuid.Nil), uuid.New()
	// A giver with no local identity: the perm is refused, with its
	// instance.
	w.page(false, w.record(id, 1, grants(device, uuid.New(), w.now.Add(-time.Hour), kc.CanRead)))
	w.judge()
	if p := w.perms(id); p[device.String()+"/read"] != "refused:local_role" ||
		w.count(`SELECT count(*) FROM contract_token_removed WHERE token_id = $1 AND cause = 'refused'`, id) != 1 {
		t.Fatalf("no refused perm with its instance: %v", p)
	}
	w.untilBack(w.now.Add(-time.Minute))
	drop, err := w.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer drop.Rollback(ctx) //nolint:errcheck // committed below; a no-op then
	if _, err := drop.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true), set_config('lock_timeout', '10s', true)`, w.tenant.String()); err != nil {
		t.Fatal(err)
	}
	// The drop's first step: the number's perms, locked.
	if _, err := drop.Exec(ctx, `SELECT 1 FROM contract_token_perms WHERE device_id = $1 ORDER BY token_id, device_id, perm FOR UPDATE`, device); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := w.tokens.RetainTokens(w.ctx(), w.now)
		done <- err
	}()
	untilTokenWaiters(t, w, 1)
	// The rest of the drop (transfer_access.go's statement).
	if _, err := drop.Exec(ctx, `WITH gone AS (
			DELETE FROM contract_token_perms p
			USING (SELECT token_id, device_id, perm FROM contract_token_perms WHERE device_id = $1
			       ORDER BY token_id, device_id, perm FOR UPDATE) l
			WHERE p.token_id = l.token_id AND p.device_id = l.device_id AND p.perm = l.perm
			RETURNING p.token_id, p.tenant_id, p.device_id, p.perm, p.granted_at)
		INSERT INTO contract_token_removed (token_id, tenant_id, item, perm, granted_at, cause)
		SELECT token_id, tenant_id, device_id::text, perm, granted_at, 'item_moved' FROM gone
		ON CONFLICT DO NOTHING`, device); err != nil {
		t.Fatalf("the number's drop beside retention: %v", err)
	}
	if err := drop.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("retention beside the drop: %v", err)
	}
	if strings.Contains(w.logs.String(), "deadlock") {
		t.Fatalf("a deadlock:\n%s", w.logs.String())
	}
	if w.token(id).Exists || w.count(`SELECT count(*) FROM contract_token_removed WHERE token_id = $1`, id) != 0 {
		t.Fatal("retention left the token past its until")
	}
}

// A held entry queued in a reset's pass and not sent before the next reset
// to another generation is never sent (the acknowledgement sends the
// current generation's): the reset deletes it, and the new pass queues
// again what is still held. Retention deletes one of another generation
// than Wappie's all the same; a sent one stays its 30 days.
func TestAResetLeavesNoHeldEntryBehind(t *testing.T) {
	w := newTokenWorld(t)
	id := uuid.New()
	w.page(false, w.record(id, 1))
	w.page(false, w.record(id, 2, revokedBy(kc.RevokedInConsole, w.now)))
	stale := func() int {
		t.Helper()
		var n int
		if err := w.pool.QueryRow(context.Background(), `SELECT count(*) FROM contract_token_held_out
			WHERE sent_at IS NULL AND generation <> $1`, w.gen).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	// A restore: the pass lists it unrevoked, so it is held revoked.
	w.reset()
	w.page(false, w.record(id, 1))
	if h, ok := w.held()[id]; !ok || !h.Revoked {
		t.Fatalf("the pass's held entry: %+v %v", h, ok)
	}
	// Another reset before the acknowledgement: the entry goes, and the new
	// pass queues it again.
	w.reset()
	if n := stale(); n != 0 {
		t.Fatalf("%d held entries of the old generation left unsent", n)
	}
	w.page(false, w.record(id, 1))
	if h, ok := w.held()[id]; !ok || !h.Revoked {
		t.Fatalf("the new pass's held entry: %+v %v", h, ok)
	}
	// Retention's belt: one of another generation, unsent, goes; a sent one
	// stays.
	other, sent := uuid.New(), uuid.New()
	w.exec(`INSERT INTO contract_token_held_out (token_id, generation) VALUES ($1, gen_random_uuid())`, other)
	w.exec(`INSERT INTO contract_token_held_out (token_id, generation, sent_at) VALUES ($1, gen_random_uuid(), clock_timestamp())`, sent)
	w.retain(w.now)
	if n := stale(); n != 0 {
		t.Fatalf("retention left %d held entries of another generation unsent", n)
	}
	if n := w.count(`SELECT count(*) FROM contract_token_held_out WHERE token_id = $1`, sent); n != 1 {
		t.Fatal("retention took a sent held entry before its 30 days")
	}
	if _, ok := w.held()[id]; !ok {
		t.Fatal("retention took the current generation's held entry")
	}
}

// What the acknowledgement and the usage report hold of a token goes with
// its selector or sticky row at its until, sent or not, reported or not
// (the acknowledgement or the usage report off, or refused, that long); a
// usage row of a token Wappie keeps no selector of goes at once (they are
// written only for one whose secret matched it); an unsent queue entry of
// a token Wappie keeps nothing of goes 30 days after it was queued.
func TestTokenRetentionTakesWhatWasNeverSent(t *testing.T) {
	w := newTokenWorld(t)
	past, kept, revoked := uuid.New(), uuid.New(), uuid.New()
	w.page(false, w.record(past, 1, createdAt(w.now.Add(-366*tokenDay), kc.MaxTokenLifetime)), w.record(kept, 1),
		w.record(revoked, 1, func(r *kc.TokenRecord) { r.WorkspaceID = uuid.NewString() }, createdAt(w.now.Add(-200*tokenDay), 30*tokenDay),
			revokedBy(kc.RevokedInConsole, w.now)))
	never, recent, unselected := uuid.New(), uuid.New(), uuid.New()
	today := w.now.UTC().Format(time.DateOnly)
	for _, id := range []uuid.UUID{past, kept, revoked, recent} {
		w.exec(`INSERT INTO contract_token_refusals_out (token_id, version, item, perm, code) VALUES ($1, 1, 'item', 'read', 'local_role')`, id)
	}
	w.exec(`INSERT INTO contract_token_refusals_out (token_id, version, item, perm, code, queued_at)
		VALUES ($1, 1, 'item', 'read', 'invalid_record', $2)`, never, w.now.Add(-31*tokenDay))
	w.exec(`INSERT INTO contract_token_held_out (token_id, generation, revoked, queued_at) VALUES ($1, $2, true, $3)`, never, w.gen, w.now.Add(-31*tokenDay))
	for _, id := range []uuid.UUID{past, kept, revoked} {
		w.exec(`INSERT INTO contract_token_held_out (token_id, generation, revoked) VALUES ($1, $2, true)`, id, w.gen)
	}
	for _, id := range []uuid.UUID{past, kept, unselected} {
		w.exec(`INSERT INTO contract_token_used (token_id, day) VALUES ($1, $2::date)`, id, today)
		w.exec(`INSERT INTO contract_token_refusals (token_id, day, code, count) VALUES ($1, $2::date, 'revoked', 1)`, id, today)
	}
	// The revoked one Wappie never held keeps its sticky row alone: past
	// its until.
	w.exec(`ALTER TABLE contract_token_sticky DISABLE TRIGGER contract_token_sticky_guard`)
	w.exec(`UPDATE contract_token_sticky SET until = $2 WHERE token_id = $1`, revoked, w.now.Add(-time.Minute))
	w.exec(`ALTER TABLE contract_token_sticky ENABLE TRIGGER contract_token_sticky_guard`)
	rows := func(id uuid.UUID) int {
		t.Helper()
		var n int
		if err := w.pool.QueryRow(context.Background(), `SELECT
			(SELECT count(*) FROM contract_token_refusals_out WHERE token_id = $1) + (SELECT count(*) FROM contract_token_held_out WHERE token_id = $1) +
			(SELECT count(*) FROM contract_token_used WHERE token_id = $1) + (SELECT count(*) FROM contract_token_refusals WHERE token_id = $1)`, id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	w.retain(w.now)
	for name, c := range map[string]struct {
		id   uuid.UUID
		want int
	}{
		"a token past its selector's until":                {past, 0},
		"a token Wappie never held, past its sticky until": {revoked, 0},
		"a live token": {kept, 4},
		"no token Wappie keeps, queued 31 days ago":    {never, 0},
		"no token Wappie keeps, queued now":            {recent, 1},
		"usage of a token Wappie keeps no selector of": {unselected, 0},
	} {
		if n := rows(c.id); n != c.want {
			t.Errorf("%s: %d rows of the queues and usage left, want %d", name, n, c.want)
		}
	}
	// 31 days on by Wappie's clock: the unsent entry of no token goes; a
	// live token's stay, its until 364 days on the database's clock.
	w.retain(w.now.Add(31 * tokenDay))
	if n, m := rows(recent), rows(kept); n != 0 || m != 4 {
		t.Errorf("31 days on: %d entries of no token left, want 0; %d of a live token's, want 4", n, m)
	}
}
