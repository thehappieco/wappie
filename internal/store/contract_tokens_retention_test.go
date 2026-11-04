package store_test

import (
	"context"
	"encoding/json"
	"errors"
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

// Retention visits a workspace whose tenants row is gone, from the
// selectors alone: its tokens' removed instances go at once (the token rows
// went with the workspace, so they ended then), their pins, stops and
// selectors at their until, in the same pass.
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
		if err := w.tokens.StopToken(w.ctx(), selectorOf(id), "root", "", w.now); err != nil {
			t.Fatal(err)
		}
	}
	if w.in(gone, `SELECT count(*) FROM contract_token_pins`) != 2 || w.in(gone, `SELECT count(*) FROM contract_token_removed`) != 2 {
		t.Fatal("the workspace's tokens have no pins or no removed instances")
	}
	w.exec(`DELETE FROM tenants WHERE id = $1`, gone)
	w.retain(w.now)
	if n := w.in(gone, `SELECT count(*) FROM contract_token_removed`); n != 0 {
		t.Errorf("%d removed instances of a deleted workspace's tokens left", n)
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

// A stop of a selector Wappie holds stays while the selector does,
// however old, and no record, bad or of another token, lowers what it
// keeps; it goes with the selector. A stop of a selector Wappie never held
// goes 365 days after it was made, or earlier at the created_at + 365 days
// of a record of its selector, which a later record never raises and a
// re-stop keeps; a write that would not lower it is none.
func TestTokenRetentionTakesStops(t *testing.T) {
	w := newTokenWorld(t)
	// Held: stopped 400 days ago, before its record came.
	held := uuid.New()
	if err := w.tokens.StopToken(w.ctx(), selectorOf(held), "root", "", w.now.Add(-400*tokenDay)); err != nil {
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
		if err := w.tokens.StopToken(w.ctx(), sel, "root", "", at); err != nil {
			t.Fatal(err)
		}
	}
	// Never held, stopped 10 days ago, then a record of its selector comes:
	// of a workspace Wappie does not hold, created 366 days ago; and a bad
	// one, created 200 days ago, then a later one.
	orphan, bad := uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{orphan, bad} {
		if err := w.tokens.StopToken(w.ctx(), selectorOf(id), "root", "", w.now.Add(-10*tokenDay)); err != nil {
			t.Fatal(err)
		}
	}
	invalid := func(r *kc.TokenRecord) { r.Hash = "not a hash" }
	w.page(false,
		w.record(orphan, 1, func(r *kc.TokenRecord) { r.WorkspaceID = uuid.NewString() }, createdAt(w.now.Add(-366*tokenDay), 30*tokenDay)),
		w.record(bad, 1, invalid, createdAt(w.now.Add(-200*tokenDay), 30*tokenDay)))
	badUntil := w.now.Add(-200 * tokenDay).Add(kc.MaxTokenLifetime)
	if _, _, ru := w.stopOf(selectorOf(bad)); ru == nil || !ru.Equal(badUntil) {
		t.Fatalf("a never-held stop after a bad record: record_until %v, want %v", ru, badUntil)
	}
	xmin := func() string {
		t.Helper()
		var x string
		if err := w.pool.QueryRow(context.Background(), `SELECT xmin::text FROM contract_token_stops WHERE selector = $1`, selectorOf(bad)).Scan(&x); err != nil {
			t.Fatal(err)
		}
		return x
	}
	before := xmin()
	w.page(false, w.record(bad, 2, invalid, createdAt(w.now.Add(-100*tokenDay), 30*tokenDay)))
	if _, _, ru := w.stopOf(selectorOf(bad)); ru == nil || !ru.Equal(badUntil) {
		t.Fatalf("a later record raised record_until to %v, want %v", ru, badUntil)
	}
	if xmin() != before {
		t.Fatal("a record that lowers nothing rewrote the stop")
	}
	// A re-stop is made now, and keeps record_until.
	if err := w.tokens.StopToken(w.ctx(), selectorOf(bad), "root", "again", w.now); err != nil {
		t.Fatal(err)
	}
	if _, stopped, ru := w.stopOf(selectorOf(bad)); !stopped.Equal(w.now) || ru == nil || !ru.Equal(badUntil) {
		t.Fatalf("a re-stop: stopped_at %v, record_until %v; want %v and %v", stopped, ru, w.now, badUntil)
	}

	w.retain(w.now)
	for name, c := range map[string]struct {
		sel  string
		want bool
	}{
		"a held selector's, made 400 days ago":                     {selectorOf(held), true},
		"a never-held selector's, made 366 days ago":               {lapsed, false},
		"a never-held selector's, made 364 days ago":               {standing, true},
		"one whose selector's record was created 366 days ago":     {selectorOf(orphan), false},
		"one whose selector's bad record was created 200 days ago": {selectorOf(bad), true},
	} {
		if exists, _, _ := w.stopOf(c.sel); exists != c.want {
			t.Errorf("retention now, the stop %s: there %v, want %v", name, exists, c.want)
		}
	}

	// The held selector past its until (moved back, its guard set aside for
	// that alone): its stop goes with it, in the same pass.
	w.exec(`ALTER TABLE contract_token_selectors DISABLE TRIGGER contract_token_selectors_guard;
		UPDATE contract_token_selectors SET until = clock_timestamp() - interval '1 second';
		ALTER TABLE contract_token_selectors ENABLE TRIGGER contract_token_selectors_guard`)
	got, err := w.tokens.RetainTokens(w.ctx(), w.now)
	if err != nil {
		t.Fatal(err)
	}
	if exists, _, _ := w.stopOf(selectorOf(held)); exists || got.Stops != 1 || got.Ended != 1 {
		t.Fatalf("past its selector's until: the stop there %v, %+v", exists, got)
	}
}

// The revocation of a token Wappie never held sticks to the record's
// created_at + 365 days (never past Wappie's clock + 365 days, which also
// stands for a record with no created_at), and not at all once that has
// passed: as a record of a workspace Wappie does not hold, and as a bad
// record.
func TestANeverHeldRevocationSticksToItsCreation(t *testing.T) {
	w := newTokenWorld(t)
	elsewhere := func(r *kc.TokenRecord) { r.WorkspaceID = uuid.NewString() }
	invalid := func(r *kc.TokenRecord) { r.Hash = "not a hash" }
	revoked := revokedBy(kc.RevokedInConsole, w.now.Add(-time.Hour))
	ids := map[string]uuid.UUID{"elsewhere": uuid.New(), "bad": uuid.New(), "ahead": uuid.New(), "lapsed": uuid.New(),
		"lapsed bad": uuid.New(), "no creation": uuid.New()}
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
		json.RawMessage(noCreation))
	until := func(id uuid.UUID) *time.Time {
		t.Helper()
		var at time.Time
		err := w.pool.QueryRow(context.Background(), `SELECT until FROM contract_token_sticky WHERE token_id = $1`, id).Scan(&at)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			t.Fatal(err)
		}
		return &at
	}
	for name, want := range map[string]*time.Time{
		"elsewhere":   new(w.now.Add(-100 * tokenDay).Add(kc.MaxTokenLifetime)),
		"bad":         new(w.now.Add(-10 * tokenDay).Add(kc.MaxTokenLifetime)),
		"ahead":       new(w.now.Add(kc.MaxTokenLifetime)),
		"no creation": new(w.now.Add(kc.MaxTokenLifetime)),
		"lapsed":      nil,
		"lapsed bad":  nil,
	} {
		got := until(ids[name])
		switch {
		case want == nil && got != nil:
			t.Errorf("%s: a sticky row to %v, want none", name, *got)
		case want != nil && (got == nil || !got.Equal(*want)):
			t.Errorf("%s: a sticky row to %v, want %v", name, got, *want)
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
