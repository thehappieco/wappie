package store_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/store"
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

// zeroExpiry is r's JSON with no expiry (a bad record), which Wappie
// keeps as -infinity (TestZeroTimesNarrow).
func zeroExpiry(t *testing.T, r kc.TokenRecord) json.RawMessage {
	t.Helper()
	old := []byte(`"expires_at":"` + r.ExpiresAt.UTC().Format(time.RFC3339Nano) + `"`)
	b := raw(t, r)
	if !bytes.Contains(b, old) {
		t.Fatalf("no expires_at in %s", b)
	}
	return bytes.Replace(b, old, []byte(`"expires_at":null`), 1)
}

// endsAt reports whether token id's ended_at is at, and what it is.
func (w *tokenWorld) endsAt(id uuid.UUID, at time.Time) (bool, string) {
	w.t.Helper()
	var ended string
	w.scoped(func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT coalesce(ended_at::text, 'none') FROM contract_tokens WHERE id = $1`, id).Scan(&ended)
	})
	return w.count(`SELECT count(*) FROM contract_tokens WHERE id = $1 AND ended_at = $2`, id, at) == 1, ended
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

// What goes at a token's until goes on both clocks: a retention 380 days
// on by Wappie's clock, past the until of a 365-day token but under 30 days
// past its expiry, and a day after its creation by the database's, ends
// the token (its expiry is Wappie's clock's) and keeps its row, its removed
// instances and its queue entries.
func TestTokenRetentionWaitsForTheDatabasesClock(t *testing.T) {
	w := newTokenWorld(t)
	id := uuid.New()
	w.page(false, w.record(id, 1, createdAt(w.now.Add(-tokenDay), kc.MaxTokenLifetime), unknownItem(w.ownerSub, w.now)))
	w.exec(`INSERT INTO contract_token_refusals_out (token_id, version, item, perm, code) VALUES ($1, 1, 'not-a-number', 'send', 'item_unknown')
		ON CONFLICT DO NOTHING`, id)
	removed := func() int {
		t.Helper()
		return w.count(`SELECT count(*) FROM contract_token_removed WHERE token_id = $1`, id)
	}
	if removed() != 1 {
		t.Fatal("the token has no removed instance")
	}
	got, err := w.tokens.RetainTokens(w.ctx(), w.now.Add(380*tokenDay))
	if err != nil || got.Expired != 1 || got.Ended != 0 {
		t.Fatalf("a retention ahead of the database's clock: %+v %v", got, err)
	}
	if !w.token(id).Exists || removed() != 1 || len(w.refused(id)) != 1 {
		t.Fatalf("a retention ahead of the database's clock: the token's row %v, %d removed instances, its refusals %v",
			w.token(id).Exists, removed(), w.refused(id))
	}
}

// A token's record goes 30 days after its end, the earlier of its
// revocation's and its expiry's own times, however late Wappie learns of
// it (a restore's re-read of the feed, a turn-on after a time off): a
// token first seen 40 days after it expired, with a giver's perm, one
// first seen revoked 40 days ago, one first seen revoked an hour ago 60
// days after it expired, and a held one expired 60 days ago whose
// revocation of an hour ago comes before the janitor ran, go at the first
// pass; a held one whose revocation of 40 days ago comes late, one the
// janitor ended at its expiry 10 days ago whose earlier revocation comes
// after, and one the janitor ended at its expiry 10 days ago whose expiry
// a later record shortens to 50 days ago, at the next. A revocation timed
// ahead of Wappie's clock ends its token at Wappie's clock. A zero expiry
// (-infinity, a bad record's) gives no time: a held token revoked an hour
// ago by a bad record with none ends at its revocation.
func TestATokensRecordCountsFromItsEnd(t *testing.T) {
	w := newTokenWorld(t)
	device := w.number(uuid.Nil)
	created := w.now.Add(-100 * tokenDay)
	expired, revoked, late, both, ahead := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	expiredRevoked, revokedExpired, shortened, zero := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	w.page(false,
		w.record(expired, 1, createdAt(created, 60*tokenDay), grants(device, w.ownerSub, created, kc.CanRead)),
		w.record(revoked, 1, createdAt(created, 300*tokenDay), revokedBy(kc.RevokedInConsole, w.now.Add(-40*tokenDay))),
		w.record(late, 1, createdAt(created, 300*tokenDay), grants(device, w.ownerSub, created, kc.CanRead)),
		w.record(both, 1, createdAt(created, 90*tokenDay)),
		w.record(ahead, 1, createdAt(created, 300*tokenDay)),
		w.record(expiredRevoked, 1, createdAt(created, 40*tokenDay), revokedBy(kc.RevokedInConsole, w.now.Add(-time.Hour))),
		w.record(revokedExpired, 1, createdAt(created, 40*tokenDay)),
		w.record(shortened, 1, createdAt(created, 90*tokenDay)),
		w.record(zero, 1, createdAt(created, 300*tokenDay)))
	w.page(false, w.record(revokedExpired, 2, createdAt(created, 40*tokenDay), revokedBy(kc.RevokedInConsole, w.now.Add(-time.Hour))),
		zeroExpiry(t, w.record(zero, 2, createdAt(created, 300*tokenDay), revokedBy(kc.RevokedInConsole, w.now.Add(-time.Hour)))))
	if s := w.token(zero); !s.Revoked || s.Expires != "-infinity" {
		t.Fatalf("a bad record with no expiry, revoked: %+v", s)
	}
	if at, ended := w.endsAt(zero, w.now.Add(-time.Hour)); !at {
		t.Fatalf("a token revoked with no expiry ended at %s, want its revocation %v", ended, w.now.Add(-time.Hour))
	}
	gone := func(when string, ids map[string]uuid.UUID, want bool) {
		t.Helper()
		for name, id := range ids {
			s := w.token(id)
			if !s.Exists || s.Forgotten != want || (want && (s.Name != "" || len(w.perms(id)) != 0)) {
				t.Errorf("%s, the token %s: forgotten %v (want %v), name %q, perms %v", when, name, s.Forgotten, want, s.Name, w.perms(id))
			}
		}
	}
	w.retain(w.now)
	gone("the first pass", map[string]uuid.UUID{"first seen 40 days after its expiry": expired, "first seen revoked 40 days ago": revoked,
		"first seen revoked an hour ago, 60 days after its expiry":        expiredRevoked,
		"expired 60 days ago, revoked an hour ago before the janitor ran": revokedExpired}, true)
	gone("the first pass", map[string]uuid.UUID{"held": late, "expired 10 days ago": both, "held, revoked later": ahead,
		"expired 10 days ago, to be shortened": shortened, "revoked with no expiry": zero}, false)
	if w.perms(late)[device.String()+"/read"] == "" {
		t.Fatal("the held token has no perm to forget")
	}
	w.page(false,
		w.record(late, 2, createdAt(created, 300*tokenDay), revokedBy(kc.RevokedInConsole, w.now.Add(-40*tokenDay))),
		w.record(both, 2, createdAt(created, 90*tokenDay), revokedBy(kc.RevokedInConsole, w.now.Add(-40*tokenDay))),
		w.record(ahead, 2, createdAt(created, 300*tokenDay), revokedBy(kc.RevokedInConsole, w.now.Add(time.Hour))),
		w.record(shortened, 2, createdAt(created, 50*tokenDay)))
	w.retain(w.now)
	gone("the next pass", map[string]uuid.UUID{"revoked 40 days ago, learned now": late, "expired, then revoked earlier": both,
		"ended at its expiry, then shortened to 50 days ago": shortened}, true)
	gone("the next pass", map[string]uuid.UUID{"revoked ahead of Wappie's clock": ahead, "revoked with no expiry": zero}, false)
	w.retain(w.now.Add(29 * tokenDay))
	gone("29 days on", map[string]uuid.UUID{"revoked ahead of Wappie's clock": ahead, "revoked with no expiry": zero}, false)
	w.retain(w.now.Add(30 * tokenDay))
	gone("30 days on", map[string]uuid.UUID{"revoked ahead of Wappie's clock": ahead, "revoked with no expiry": zero}, true)
}

// A reset's pass forgets what it unlists at once: its record, name, terms,
// perms (a Read applied and held at the reset among them) and removed
// instances, since an unlisting carries no time and a restore whose
// re-read of the feed runs the pass again would start a 30 days of its own
// again. It ends at the pass, or at its expiry if that came first and the
// janitor has not run yet; a zero expiry (-infinity) gives no time, so at
// the pass. A token the pass lists keeps its content.
func TestAResetsPassForgetsWhatItUnlists(t *testing.T) {
	w := newTokenWorld(t)
	device := w.number(uuid.Nil)
	live, expired, zero, listed := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	expiry := w.now.Add(-60 * tokenDay)
	terms := func(r *kc.TokenRecord) {
		r.Terms = &kc.TokenTerms{Version: "2026-10-api-keys-2", AgreedAt: kc.T(w.now.Add(-time.Hour))}
	}
	w.page(false,
		w.record(live, 1, terms, grants(device, w.ownerSub, w.now.Add(-time.Hour), kc.CanRead), unknownItem(w.ownerSub, w.now.Add(-time.Hour))),
		w.record(expired, 1, createdAt(expiry.Add(-40*tokenDay), 40*tokenDay)),
		w.record(zero, 1),
		w.record(listed, 1))
	w.page(false, zeroExpiry(t, w.record(zero, 2)))
	if s := w.token(zero); s.Expires != "-infinity" {
		t.Fatalf("a bad record with no expiry: %+v", s)
	}
	content := func(id uuid.UUID) int {
		t.Helper()
		return len(w.perms(id)) + w.count(`SELECT count(*) FROM contract_token_removed WHERE token_id = $1`, id)
	}
	kept := func(id uuid.UUID) bool {
		t.Helper()
		var kept bool
		w.scoped(func(tx pgx.Tx) error {
			return tx.QueryRow(context.Background(), `SELECT record IS NOT NULL OR terms IS NOT NULL FROM contract_tokens WHERE id = $1`, id).Scan(&kept)
		})
		return kept
	}
	w.judge()
	w.reset()
	w.exec(`UPDATE contract_state SET round_generation = $1`, w.gen)
	if p := w.perms(live); len(p) != 1 || content(live) != 2 || w.count(`SELECT count(*) FROM contract_tokens WHERE id = $1 AND terms IS NOT NULL`, live) != 1 {
		t.Fatalf("before the pass, the live token holds perms %v, %d perms and removed instances (want 2), and its terms %v", p, content(live), kept(live))
	}
	if res := w.page(false, w.record(listed, 1)); !res.PassReady {
		t.Fatal("the pass is not ready")
	}
	if res, err := w.tokens.FinishTokenPass(w.ctx(), w.gen, w.now); err != nil || !res.Done || len(res.Unlisted) != 3 {
		t.Fatalf("the pass: %+v %v", res, err)
	}
	for name, c := range map[string]struct {
		id  uuid.UUID
		end time.Time
	}{"live at the pass": {live, w.now}, "expired 60 days before the pass": {expired, expiry}, "with no expiry": {zero, w.now}} {
		at, ended := w.endsAt(c.id, c.end)
		if s := w.token(c.id); !s.Unlisted || !s.Forgotten || s.Name != "" || kept(c.id) || content(c.id) != 0 || !at {
			t.Errorf("a token %s, unlisted: forgotten %v, name %q, its record or terms kept %v, %d perms and removed instances, ended %s (want %v)",
				name, s.Forgotten, s.Name, kept(c.id), content(c.id), ended, c.end)
		}
	}
	if s := w.token(listed); s.Unlisted || s.Forgotten || s.Name != "Nightly" {
		t.Fatalf("the token the pass listed: %+v", s)
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

	// Never held: one stopped 366 days ago, one 364 days ago; and Wappie's
	// own apply_failed stops as old.
	lapsed, standing := selectorOf(uuid.New()), selectorOf(uuid.New())
	for sel, at := range map[string]time.Time{lapsed: w.now.Add(-366 * tokenDay), standing: w.now.Add(-364 * tokenDay)} {
		if _, err := w.tokens.StopToken(w.ctx(), sel, "root", "", at); err != nil {
			t.Fatal(err)
		}
	}
	failedLapsed, failedStanding := selectorOf(uuid.New()), selectorOf(uuid.New())
	for sel, at := range map[string]time.Time{failedLapsed: w.now.Add(-366 * tokenDay), failedStanding: w.now.Add(-364 * tokenDay)} {
		w.exec(`INSERT INTO contract_token_stops (selector, cause, stopped_at, stopped_by) VALUES ($1, 'apply_failed', $2, 'wappie')`, sel, at)
	}
	failed := func(sel string) bool {
		t.Helper()
		return w.count(`SELECT count(*) FROM contract_token_stops WHERE selector = $1 AND cause = 'apply_failed'`, sel) == 1
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
	if failed(failedLapsed) || !failed(failedStanding) {
		t.Errorf("retention now, an apply_failed stop made 366 days ago there %v, one made 364 days ago %v", failed(failedLapsed), failed(failedStanding))
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

	// The held selectors past their until on Wappie's clock (moved back, an
	// hour's margin for the database's): each stop goes with its selector,
	// in the same pass, Wappie's own apply_failed one too.
	w.exec(`INSERT INTO contract_token_stops (selector, cause, stopped_by) VALUES ($1, 'apply_failed', 'wappie')`, selectorOf(held))
	w.untilBack(w.now.Add(-time.Hour))
	got, err := w.tokens.RetainTokens(w.ctx(), w.now)
	if err != nil {
		t.Fatal(err)
	}
	if exists, _, _ := w.stopOf(selectorOf(held)); exists || failed(selectorOf(held)) || got.Stops != 4 || got.Ended != 3 {
		t.Fatalf("past its selector's until: the stop there %v, the apply_failed one %v, %+v", exists, failed(selectorOf(held)), got)
	}
}

// A stop's times only go forward, and each command returns the time the
// database holds, which the stop record's line carries: a re-stop timed
// at or before the stop (two commands at once, the later timed first, or
// a clock stepped back) is made a microsecond after the stop's time, a
// lift timed at or before its stop a microsecond after the stop's, and a
// re-stop timed at or before the lift a microsecond after the lift's, so
// no two changes of one stop share a time. A lift of a stop lifted already
// changes nothing and gives that lift's time; with no operator's stop of
// the selector (none, or only Wappie's own), none.
func TestAStopsTimesNeverGoBack(t *testing.T) {
	w := newTokenWorld(t)
	sel, failing := selectorOf(uuid.New()), selectorOf(uuid.New())
	base, ms, us := w.now, time.Millisecond, time.Microsecond
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
	stop(base, base.Add(ms+us))
	stop(base.Add(ms+us), base.Add(ms+2*us))
	lift(base, base.Add(ms+3*us), true)
	lift(base.Add(time.Hour), base.Add(ms+3*us), false)
	stop(base.Add(-time.Hour), base.Add(ms+4*us))
	lift(base.Add(ms+4*us), base.Add(ms+5*us), true)
	stop(base.Add(ms+5*us), base.Add(ms+6*us))
	lift(base.Add(2*ms), base.Add(2*ms), true)
	stop(base.Add(3*ms), base.Add(3*ms))

	w.exec(`INSERT INTO contract_token_stops (selector, cause, stopped_at, stopped_by) VALUES ($1, 'apply_failed', $2, 'wappie')`, failing, base)
	for _, s := range []string{failing, selectorOf(uuid.New())} {
		if at, lifted, err := w.tokens.LiftToken(w.ctx(), s, base); err != nil || lifted || !at.IsZero() {
			t.Fatalf("a lift with no operator's stop: %v %v %v", at, lifted, err)
		}
	}
}

// Two commands at once, or a clock stepped back: a lift timed before its
// stop and a re-stop timed before that lift are each made a microsecond
// after the change before, so their lines, replayed over a snapshot that
// holds them, change nothing: the re-stop keeps who made it and its note.
// Nor does a stop's line whose lift's line is missing (its lock not taken
// in time) re-stop what the snapshot holds lifted. Over a snapshot taken
// between the lift and the re-stop, the re-stop comes back. A line at the
// time of the stop's last change is that change: a stop's or a lift's at
// it is left.
func TestAReplayOfRacedChangesKeepsTheStop(t *testing.T) {
	w := newTokenWorld(t)
	restopped, lifted, tied := selectorOf(uuid.New()), selectorOf(uuid.New()), selectorOf(uuid.New())
	t0 := w.now.Add(-time.Hour)
	type line struct {
		sel  string
		at   time.Time
		lift bool
	}
	stop := func(sel, by, note string, at time.Time) line {
		t.Helper()
		got, err := w.tokens.StopToken(w.ctx(), sel, by, note, at)
		if err != nil {
			t.Fatal(err)
		}
		return line{sel, got, false}
	}
	lift := func(sel string, at time.Time) line {
		t.Helper()
		got, lifted, err := w.tokens.LiftToken(w.ctx(), sel, at)
		if err != nil || !lifted {
			t.Fatal(lifted, err)
		}
		return line{sel, got, true}
	}
	lines := []line{stop(restopped, "alice", "leaked", t0), lift(restopped, t0.Add(-time.Second)),
		stop(restopped, "bob", "leaked again", t0.Add(-2*time.Second)), stop(lifted, "alice", "leaked", t0)}
	lift(lifted, t0.Add(-time.Second)) // its line missing
	stops := func() string {
		t.Helper()
		list, err := w.tokens.TokenStops(w.ctx())
		if err != nil {
			t.Fatal(err)
		}
		var b strings.Builder
		for _, s := range list {
			b.WriteString(s.Selector + " " + s.StoppedBy + " " + s.Note + " " + s.StoppedAt.UTC().Format(time.RFC3339Nano))
			if s.LiftedAt != nil {
				b.WriteString(" lifted " + s.LiftedAt.UTC().Format(time.RFC3339Nano))
			}
			b.WriteString("\n")
		}
		return b.String()
	}
	before := stops()
	for _, l := range lines {
		var applied bool
		var err error
		if l.lift {
			applied, err = w.tokens.ReplayTokenLift(w.ctx(), l.sel, l.at)
		} else {
			applied, err = w.tokens.ReplayTokenStop(w.ctx(), l.sel, "replayer", "", l.at, w.now)
		}
		if err != nil || applied {
			t.Errorf("a replay of %+v over the stop the snapshot holds: applied %v, %v", l, applied, err)
		}
	}
	if after := stops(); after != before {
		t.Fatalf("the replay changed the stops the snapshot held:\nbefore %s\nafter  %s", before, after)
	}
	// A snapshot taken between the lift and the re-stop: the re-stop's line
	// applies, and the stop stands again at its time.
	w.exec(`UPDATE contract_token_stops SET stopped_at = $2, lifted_at = $3, stopped_by = 'alice', note = 'leaked'
		WHERE selector = $1 AND cause = 'operator'`, restopped, lines[0].at, lines[1].at)
	applied := 0
	for _, l := range lines[:3] {
		var ok bool
		var err error
		if l.lift {
			ok, err = w.tokens.ReplayTokenLift(w.ctx(), l.sel, l.at)
		} else {
			ok, err = w.tokens.ReplayTokenStop(w.ctx(), l.sel, "replayer", "", l.at, w.now)
		}
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			applied++
		}
	}
	if _, stopped, _ := w.stopOf(restopped); applied != 1 || !stopped.Equal(lines[2].at) ||
		w.count(`SELECT count(*) FROM contract_token_stops WHERE selector = $1 AND lifted_at IS NULL`, restopped) != 1 {
		t.Fatalf("a replay over the lift before the re-stop: %d applied, stopped %v, want the re-stop's %v, open", applied, stopped, lines[2].at)
	}
	// The replay's own rule: lines at the time of the last change.
	w.exec(`INSERT INTO contract_token_stops (selector, cause, stopped_at, stopped_by, note, lifted_at)
		VALUES ($1, 'operator', $2, 'alice', 'held', $3)`, tied, t0, t0.Add(time.Second))
	if applied, err := w.tokens.ReplayTokenStop(w.ctx(), tied, "replayer", "", t0.Add(time.Second), w.now); err != nil || applied {
		t.Fatalf("a stop's line at its lift's time: applied %v, %v", applied, err)
	}
	w.exec(`UPDATE contract_token_stops SET lifted_at = NULL WHERE selector = $1`, tied)
	if applied, err := w.tokens.ReplayTokenLift(w.ctx(), tied, t0); err != nil || applied {
		t.Fatalf("a lift's line at its stop's time: applied %v, %v", applied, err)
	}
	if exists, _, _ := w.stopOf(tied); !exists || w.count(`SELECT count(*) FROM contract_token_stops WHERE selector = $1
		AND stopped_by = 'alice' AND note = 'held' AND lifted_at IS NULL`, tied) != 1 {
		t.Fatal("a line at the time of the stop's last change changed it")
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

// letGo is the mark of what retention let go.
func (w *tokenWorld) letGo() *time.Time {
	w.t.Helper()
	through, err := w.tokens.TokenStopsLetGo(w.ctx())
	if err != nil {
		w.t.Fatal(err)
	}
	return through
}

// A replay after a restore never brings back a stop retention let go
// before the snapshot: a held token's stop, gone with its selector at its
// until, and a never-held one gone at its record_until, each with its
// lines at or before the mark retention moved to their latest time. The
// mark is never lowered: not by a pass that lets no stop go, nor by one
// that lets go a stop older than it. A stop made after the snapshot still
// comes back. A lift's line at or before the mark lifts nothing, even a
// stop made before it that retention kept. A stop or a lift timed at or
// before the mark is made just after it, so its line replays.
func TestAReplayLeavesWhatRetentionLetGo(t *testing.T) {
	w := newTokenWorld(t)
	if w.letGo() != nil {
		t.Fatal("a mark before any retention")
	}
	held := uuid.New()
	w.page(false, w.record(held, 1, createdAt(w.now.Add(-364*tokenDay), kc.MaxTokenLifetime)))
	heldStop, err := w.tokens.StopToken(w.ctx(), selectorOf(held), "root", "leaked", w.now.Add(-200*tokenDay))
	if err != nil {
		t.Fatal(err)
	}
	heldLift, lifted, err := w.tokens.LiftToken(w.ctx(), selectorOf(held), w.now.Add(-100*tokenDay))
	if err != nil || !lifted {
		t.Fatal(lifted, err)
	}
	orphan := uuid.New()
	orphanStop, err := w.tokens.StopToken(w.ctx(), selectorOf(orphan), "root", "", w.now.Add(-10*tokenDay))
	if err != nil {
		t.Fatal(err)
	}
	w.page(false, w.record(orphan, 1, func(r *kc.TokenRecord) { r.WorkspaceID = uuid.NewString() }, createdAt(w.now.Add(-366*tokenDay), 30*tokenDay)))
	// A never-held stop made before the orphan's, which retention keeps.
	kept := selectorOf(uuid.New())
	if _, err := w.tokens.StopToken(w.ctx(), kept, "root", "", w.now.Add(-20*tokenDay)); err != nil {
		t.Fatal(err)
	}
	// An apply_failed stop is never in the record: it moves no mark.
	w.exec(`INSERT INTO contract_token_stops (selector, cause, stopped_at, stopped_by) VALUES ($1, 'apply_failed', $2, 'wappie')`,
		selectorOf(held), w.now.Add(-time.Hour))
	// Its year over, an hour back on Wappie's clock, so the database's may
	// lag that much.
	w.untilBack(w.now.Add(-time.Hour))
	if got, err := w.tokens.RetainTokens(w.ctx(), w.now); err != nil || got.Stops != 3 {
		t.Fatalf("retention: %+v %v", got, err)
	}
	if through := w.letGo(); through == nil || !through.Equal(orphanStop) {
		t.Fatalf("the mark after retention: %v, want the latest time of a stop let go, %v", through, orphanStop)
	}
	// A pass that lets no stop go, then one that lets go an operator's stop
	// older than the mark (made before any mark, 366 days ago): the mark
	// stays.
	if got, err := w.tokens.RetainTokens(w.ctx(), w.now); err != nil || got.Stops != 0 {
		t.Fatalf("a retention with no stop due: %+v %v", got, err)
	}
	if through := w.letGo(); through == nil || !through.Equal(orphanStop) {
		t.Fatalf("the mark after a pass that let no stop go: %v, want %v", through, orphanStop)
	}
	w.exec(`INSERT INTO contract_token_stops (selector, cause, stopped_at, stopped_by) VALUES ($1, 'operator', $2, 'root')`,
		selectorOf(uuid.New()), w.now.Add(-366*tokenDay))
	if got, err := w.tokens.RetainTokens(w.ctx(), w.now); err != nil || got.Stops != 1 {
		t.Fatalf("a retention of a stop older than the mark: %+v %v", got, err)
	}
	if through := w.letGo(); through == nil || !through.Equal(orphanStop) {
		t.Fatalf("the mark after a pass that let go a stop older than it: %v, want %v", through, orphanStop)
	}

	// A snapshot taken since, then a stop made after it, then a restore of
	// the snapshot (the stop made after it deleted), then the replay.
	later := selectorOf(uuid.New())
	laterStop, err := w.tokens.StopToken(w.ctx(), later, "root", "", w.now)
	if err != nil {
		t.Fatal(err)
	}
	w.exec(`DELETE FROM contract_token_stops WHERE selector = $1`, later)
	for name, line := range map[string]struct {
		sel  string
		at   time.Time
		lift bool
	}{
		"the held token's stop":     {selectorOf(held), heldStop, false},
		"the held token's lift":     {selectorOf(held), heldLift, true},
		"the never-held one's stop": {selectorOf(orphan), orphanStop, false},
	} {
		var applied bool
		if line.lift {
			applied, err = w.tokens.ReplayTokenLift(w.ctx(), line.sel, line.at)
		} else {
			applied, err = w.tokens.ReplayTokenStop(w.ctx(), line.sel, "wappie", "", line.at, w.now)
		}
		if exists, _, _ := w.stopOf(line.sel); err != nil || applied || exists {
			t.Errorf("a replay of %s, let go before the snapshot: applied %v, the stop there %v, %v", name, applied, exists, err)
		}
	}
	if applied, err := w.tokens.ReplayTokenStop(w.ctx(), later, "wappie", "", laterStop, w.now); err != nil || !applied {
		t.Fatalf("a replay of a stop made after the snapshot: applied %v, %v", applied, err)
	}
	if exists, _, _ := w.stopOf(later); !exists {
		t.Fatal("a stop made after the snapshot did not come back")
	}

	// A lift's line at or before the mark, over the open stop retention
	// kept, made before it: left, the stop still open.
	open := func(sel string) bool {
		t.Helper()
		return w.count(`SELECT count(*) FROM contract_token_stops WHERE selector = $1 AND cause = 'operator' AND lifted_at IS NULL`, sel) == 1
	}
	if applied, err := w.tokens.ReplayTokenLift(w.ctx(), kept, orphanStop.Add(-2*tokenDay)); err != nil || applied || !open(kept) {
		t.Fatalf("a replay of a lift's line before the mark: applied %v, the stop open %v, %v", applied, open(kept), err)
	}
	// A lift timed before the mark, of that stop: made just after the mark,
	// so a replay of its line over the stop as the snapshot held it, open,
	// lifts it.
	keptLift, lifted, err := w.tokens.LiftToken(w.ctx(), kept, orphanStop.Add(-5*tokenDay))
	if err != nil || !lifted || !keptLift.Equal(orphanStop.Add(time.Microsecond)) {
		t.Fatalf("a lift timed before the mark: made at %v %v, %v; want %v", keptLift, lifted, err, orphanStop.Add(time.Microsecond))
	}
	w.exec(`UPDATE contract_token_stops SET lifted_at = NULL WHERE selector = $1`, kept)
	if applied, err := w.tokens.ReplayTokenLift(w.ctx(), kept, keptLift); err != nil || !applied || open(kept) {
		t.Fatalf("a replay of a lift made just after the mark: applied %v, the stop open %v, %v", applied, open(kept), err)
	}

	// Timed before the mark (a command begun before retention moved it): made
	// just after it, so a replay of its line applies.
	early := selectorOf(uuid.New())
	through := *w.letGo()
	justAfter := through.Add(time.Microsecond)
	if at, err := w.tokens.StopToken(w.ctx(), early, "root", "", through.Add(-time.Hour)); err != nil || !at.Equal(justAfter) {
		t.Fatalf("a stop timed before the mark: made at %v, %v; want %v", at, err, justAfter)
	}
	// Its lift, timed before the mark too: made just after the stop.
	if at, lifted, err := w.tokens.LiftToken(w.ctx(), early, through.Add(-time.Hour)); err != nil || !lifted || !at.Equal(justAfter.Add(time.Microsecond)) {
		t.Fatalf("a lift timed before the mark: made at %v %v, %v; want %v", at, lifted, err, justAfter.Add(time.Microsecond))
	}
	if !store.TokenStopMarked(through, &through) || store.TokenStopMarked(justAfter, &through) || store.TokenStopMarked(through, nil) {
		t.Fatal("TokenStopMarked: a line at the mark is marked, one after it or with no mark is not")
	}
}

// Retention lets an operator's stop go only once its times are at or
// before its cut, so the mark never passes Wappie's clock (a clock ahead
// when a stop or a lift was made). Two held selectors' stops, one timed 30
// days ahead and one lifted 30 days ahead, stay when their selectors go,
// with the selector's until as their record_until; so does the stop of a
// selector Wappie never held, 366 days old and lifted a day ahead. Past
// its date each keeps only its selector and times, as the stop record
// does: its note goes and it reads as made by wappie, once (a later pass
// writes nothing). A young stop, not due, keeps its own. A stop and a lift
// made since, of another selector, are made at their own times. Once a
// stop's times have passed (moved back here, as if the days went by) the
// next pass lets it go, at that record_until, not 365 days after it was
// made, and the mark moves to its latest time.
func TestAStopAheadOfTheClockWaitsForIt(t *testing.T) {
	w := newTokenWorld(t)
	stopAhead, liftAhead := uuid.New(), uuid.New()
	w.page(false, w.record(stopAhead, 1, createdAt(w.now.Add(-364*tokenDay), kc.MaxTokenLifetime)),
		w.record(liftAhead, 1, createdAt(w.now.Add(-364*tokenDay), kc.MaxTokenLifetime)))
	ahead := w.now.Add(30 * tokenDay)
	if _, err := w.tokens.StopToken(w.ctx(), selectorOf(stopAhead), "alice", "leaked by bob@example.com", ahead); err != nil {
		t.Fatal(err)
	}
	if _, err := w.tokens.StopToken(w.ctx(), selectorOf(liftAhead), "alice", "leaked in a log", w.now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if at, lifted, err := w.tokens.LiftToken(w.ctx(), selectorOf(liftAhead), ahead); err != nil || !lifted || !at.Equal(ahead) {
		t.Fatalf("a lift timed ahead: at %v %v, %v; want %v", at, lifted, err, ahead)
	}
	never, young := selectorOf(uuid.New()), selectorOf(uuid.New())
	if _, err := w.tokens.StopToken(w.ctx(), never, "carol", "from INC-9", w.now.Add(-366*tokenDay)); err != nil {
		t.Fatal(err)
	}
	if _, lifted, err := w.tokens.LiftToken(w.ctx(), never, w.now.Add(tokenDay)); err != nil || !lifted {
		t.Fatal(lifted, err)
	}
	if _, err := w.tokens.StopToken(w.ctx(), young, "dave", "keep me", w.now.Add(tokenDay)); err != nil {
		t.Fatal(err)
	}
	until := w.now.Add(-time.Hour)
	w.untilBack(until)
	if got, err := w.tokens.RetainTokens(w.ctx(), w.now); err != nil || got.Stops != 0 || got.Ended != 2 {
		t.Fatalf("retention past the selectors' until, a stop and a lift ahead of the clock: %+v %v", got, err)
	}
	type kept struct {
		by, note, row string
		recordUntil   *time.Time
	}
	keptOf := func(sel string) kept {
		t.Helper()
		var k kept
		if err := w.pool.QueryRow(context.Background(), `SELECT stopped_by, note, xmin::text, record_until FROM contract_token_stops
			WHERE selector = $1 AND cause = 'operator'`, sel).Scan(&k.by, &k.note, &k.row, &k.recordUntil); err != nil {
			t.Fatalf("the stop of %s: %v", sel, err)
		}
		return k
	}
	first := map[string]kept{}
	for _, c := range []struct {
		name, sel, by, note string
		recordUntil         *time.Time
	}{
		{"timed ahead, its selector gone", selectorOf(stopAhead), "wappie", "", &until},
		{"lifted ahead, its selector gone", selectorOf(liftAhead), "wappie", "", &until},
		{"never held, 366 days old, lifted ahead", never, "wappie", "", nil},
		{"never held, young", young, "dave", "keep me", nil},
	} {
		k := keptOf(c.sel)
		if k.by != c.by || k.note != c.note || (k.recordUntil == nil) != (c.recordUntil == nil) ||
			(c.recordUntil != nil && !k.recordUntil.Equal(*c.recordUntil)) {
			t.Errorf("a stop %s: by %q, note %q, record_until %v; want by %q, note %q, record_until %v",
				c.name, k.by, k.note, k.recordUntil, c.by, c.note, c.recordUntil)
		}
		first[c.sel] = k
	}
	if exists, stopped, _ := w.stopOf(selectorOf(stopAhead)); !exists || !stopped.Equal(ahead) {
		t.Fatalf("the stop timed ahead: there %v, stopped %v (want %v)", exists, stopped, ahead)
	}
	if n := w.count(`SELECT count(*) FROM contract_token_selectors`); n != 0 {
		t.Fatal("the selectors stayed past their until")
	}
	if through := w.letGo(); through != nil {
		t.Fatalf("the mark moved to %v, ahead of the clock", *through)
	}
	if got, err := w.tokens.RetainTokens(w.ctx(), w.now); err != nil || got.Stops != 0 {
		t.Fatalf("the next retention: %+v %v", got, err)
	}
	for sel, k := range first {
		if again := keptOf(sel); again.row != k.row {
			t.Errorf("the next retention wrote the stop of %s again", sel)
		}
	}
	other := selectorOf(uuid.New())
	if at, err := w.tokens.StopToken(w.ctx(), other, "root", "", w.now); err != nil || !at.Equal(w.now) {
		t.Fatalf("a stop made now: at %v, %v; want %v", at, err, w.now)
	}
	if at, lifted, err := w.tokens.LiftToken(w.ctx(), other, w.now.Add(time.Second)); err != nil || !lifted || !at.Equal(w.now.Add(time.Second)) {
		t.Fatalf("a lift made now: at %v %v, %v; want %v", at, lifted, err, w.now.Add(time.Second))
	}
	// As if 31 days went by for the stop timed ahead, then 30 days and a
	// minute for the lift: each goes at the next pass, and the mark moves
	// to its time.
	for _, c := range []struct {
		name, sel, move string
		mark            time.Time
	}{
		{"the stop timed ahead", selectorOf(stopAhead), `stopped_at = stopped_at - interval '31 days'`, ahead.Add(-31 * tokenDay)},
		{"the lift timed ahead", selectorOf(liftAhead), `lifted_at = lifted_at - interval '30 days 1 minute'`, ahead.Add(-30*tokenDay - time.Minute)},
	} {
		w.exec(`UPDATE contract_token_stops SET `+c.move+` WHERE selector = $1`, c.sel)
		if got, err := w.tokens.RetainTokens(w.ctx(), w.now); err != nil || got.Stops != 1 {
			t.Fatalf("retention once %s passed: %+v %v", c.name, got, err)
		}
		if exists, _, _ := w.stopOf(c.sel); exists {
			t.Fatalf("%s stayed once its time passed", c.name)
		}
		if through := w.letGo(); through == nil || !through.Equal(c.mark) {
			t.Fatalf("the mark after %s went: %v, want %v", c.name, through, c.mark)
		}
	}
}

// Retention moves the mark under its row lock, and a stop takes that lock
// shared before its write: a stop timed before a mark that retention
// commits while the stop waits is made after that mark.
func TestAStopWaitsForRetentionsMark(t *testing.T) {
	w := newTokenWorld(t)
	ctx := context.Background()
	mark := w.now.Add(time.Hour)
	tx, err := w.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // committed below; a no-op then
	if _, err := tx.Exec(ctx, `UPDATE contract_token_stops_let_go SET through = $1`, mark); err != nil {
		t.Fatal(err)
	}
	type made struct {
		at  time.Time
		err error
	}
	done := make(chan made, 1)
	go func() {
		at, err := w.tokens.StopToken(w.ctx(), selectorOf(uuid.New()), "root", "", w.now)
		done <- made{at, err}
	}()
	untilTokenWaiters(t, w, 1)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if got := <-done; got.err != nil || !got.at.After(mark) {
		t.Fatalf("a stop beside retention's mark: made at %v, %v; want after %v", got.at, got.err, mark)
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
// written only for one whose secret matched it), and any 30 days after its
// day; an unsent queue entry of a token Wappie keeps nothing of goes 30
// days after it was queued.
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
	// 31 days on by Wappie's clock: the unsent entry of no token goes, and
	// so do a live token's usage rows, 30 days after their day, reported or
	// not (the platform keeps a day's counts no longer); its queue entries
	// stay, its until 364 days on the database's clock.
	w.retain(w.now.Add(31 * tokenDay))
	if n, m := rows(recent), rows(kept); n != 0 || m != 2 {
		t.Errorf("31 days on: %d entries of no token left, want 0; %d of a live token's, want 2", n, m)
	}
}
