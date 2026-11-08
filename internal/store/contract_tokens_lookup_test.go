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

// What Wappie keeps of what the platform sends, by decision 0056 as the
// platform's review of step 7 (F1 to F3) reads it: a token's items in the
// acknowledgement's queues and the usage rows go with its record; a stop
// of a selector Wappie does not hold goes by the token's own date when
// Wappie can learn it; and so does a bad record's revocation.

// queues counts what the acknowledgement and the usage report hold of a
// token: its refusals, its held entries (and how many still keep items
// off), its days of use, and its usage refusals on a number and of the
// token itself.
type queues struct {
	refused, held, heldItems, used, itemRefusals, tokenRefusals int
}

func (w *tokenWorld) queues(id uuid.UUID) queues {
	w.t.Helper()
	var q queues
	if err := w.pool.QueryRow(context.Background(), `SELECT
		(SELECT count(*) FROM contract_token_refusals_out WHERE token_id = $1),
		(SELECT count(*) FROM contract_token_held_out WHERE token_id = $1),
		(SELECT count(*) FROM contract_token_held_out WHERE token_id = $1 AND removed <> '[]'::jsonb),
		(SELECT count(*) FROM contract_token_used WHERE token_id = $1),
		(SELECT count(*) FROM contract_token_refusals WHERE token_id = $1 AND device_id IS NOT NULL),
		(SELECT count(*) FROM contract_token_refusals WHERE token_id = $1 AND device_id IS NULL)`, id).
		Scan(&q.refused, &q.held, &q.heldItems, &q.used, &q.itemRefusals, &q.tokenRefusals); err != nil {
		w.t.Fatal(err)
	}
	return q
}

// fill queues, for token id, a refusal of each kind (unsent, and one sent
// a day ago), a held entry of the current generation (revoked, with an
// item kept off) and one of another, sent, with only an item, a day of
// use, and usage refusals on device (one reported) and of the token itself,
// all of today.
func (w *tokenWorld) fill(id, device uuid.UUID) {
	w.t.Helper()
	today := w.now.UTC().Format(time.DateOnly)
	removed := `[{"item": "` + device.String() + `", "perm": "read"}]`
	w.exec(`INSERT INTO contract_token_refusals_out (token_id, version, item, perm, code) VALUES ($1, 1, $2, 'read', 'local_role')`, id, device.String())
	w.exec(`INSERT INTO contract_token_refusals_out (token_id, version, item, perm, code, sent_at) VALUES ($1, 2, $2, 'send', 'local_role', $3)`,
		id, device.String(), w.now.Add(-tokenDay))
	w.exec(`INSERT INTO contract_token_held_out (token_id, generation, revoked, removed) VALUES ($1, $2, true, $3::jsonb)`, id, w.gen, removed)
	w.exec(`INSERT INTO contract_token_held_out (token_id, generation, removed, sent_at) VALUES ($1, $2, $3::jsonb, $4)`,
		id, uuid.New(), removed, w.now.Add(-tokenDay))
	w.exec(`INSERT INTO contract_token_used (token_id, day) VALUES ($1, $2::date)`, id, today)
	w.exec(`INSERT INTO contract_token_refusals (token_id, day, device_id, perm, code, count) VALUES ($1, $2::date, $3, 'send', 'local_role', 2)`,
		id, today, device)
	w.exec(`INSERT INTO contract_token_refusals (token_id, day, device_id, perm, code, count, reported_count)
		VALUES ($1, $2::date, $3, 'read', 'local_role', 1, 1)`, id, today, device)
	w.exec(`INSERT INTO contract_token_refusals (token_id, day, code, count) VALUES ($1, $2::date, 'revoked', 3)`, id, today)
}

// F1: at the pass that forgets a token's record, 30 days after its end,
// what the acknowledgement and the usage report hold of it goes, sent or
// reported or not: its refusals, the items its held entries keep off (an
// entry that then says nothing goes; one still told revoked stays, its
// queued_at as it was), its usage refusals on a number and its days of
// use. Its refusals as a token stay to their own rule. A live token's
// stay.
func TestAForgottenTokensQueuesGoWithIt(t *testing.T) {
	w := newTokenWorld(t)
	device := w.number(uuid.Nil)
	ended, live := uuid.New(), uuid.New()
	w.page(false,
		w.record(ended, 1, createdAt(w.now.Add(-40*tokenDay), 300*tokenDay), revokedBy(kc.RevokedInConsole, w.now.Add(-31*tokenDay))),
		w.record(live, 1))
	for _, id := range []uuid.UUID{ended, live} {
		w.fill(id, device)
	}
	full := queues{refused: 2, held: 2, heldItems: 2, used: 1, itemRefusals: 2, tokenRefusals: 1}
	if q := w.queues(ended); q != full {
		t.Fatalf("before the pass: %+v, want %+v", q, full)
	}
	queued := func() time.Time {
		t.Helper()
		var at time.Time
		if err := w.pool.QueryRow(context.Background(), `SELECT queued_at FROM contract_token_held_out
			WHERE token_id = $1 AND generation = $2`, ended, w.gen).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at
	}
	before := queued()
	got, err := w.tokens.RetainTokens(w.ctx(), w.now)
	if err != nil {
		t.Fatal(err)
	}
	if !w.token(ended).Forgotten || got.Forgotten != 1 {
		t.Fatalf("the ended token was not forgotten: %+v", got)
	}
	want := queues{held: 1, tokenRefusals: 1}
	if q := w.queues(ended); q != want {
		t.Errorf("a forgotten token's queues: %+v, want %+v", q, want)
	}
	var revoked bool
	if err := w.pool.QueryRow(context.Background(), `SELECT revoked FROM contract_token_held_out WHERE token_id = $1`, ended).Scan(&revoked); err != nil || !revoked {
		t.Errorf("the forgotten token's held entry: revoked %v, %v", revoked, err)
	}
	// Its items taken off are no news to send again sooner, nor to keep
	// longer: an unsent entry of a token Wappie keeps nothing of goes 30
	// days after its queued_at.
	if after := queued(); !after.Equal(before) {
		t.Errorf("the held entry's queued_at moved from %v to %v when its items went", before, after)
	}
	if got.Queues != 8 {
		t.Errorf("the pass counted %d queue entries and usage rows, want 8", got.Queues)
	}
	if q := w.queues(live); q != full {
		t.Errorf("a live token's queues: %+v, want %+v", q, full)
	}
	// Every pass after finds nothing more.
	if got, err := w.tokens.RetainTokens(w.ctx(), w.now); err != nil || got.Queues != 0 {
		t.Fatalf("the next pass: %+v %v", got, err)
	}
}

// F1: a token a reset's pass unlists is forgotten at that pass, and what
// the acknowledgement and the usage report hold of it goes at that pass
// too, as at retention's forget: a refusal sent the day before included,
// which the 30 days after its sending kept before. A listed token's stay.
func TestAFinishedPassForgetsTheQueuesToo(t *testing.T) {
	w := newTokenWorld(t)
	device := w.number(uuid.Nil)
	unlisted, listed := uuid.New(), uuid.New()
	w.page(false, w.record(unlisted, 1), w.record(listed, 1))
	w.reset()
	for _, id := range []uuid.UUID{unlisted, listed} {
		w.fill(id, device)
	}
	w.exec(`UPDATE contract_state SET round_generation = $1`, w.gen)
	if res := w.page(false, w.record(listed, 1)); !res.PassReady {
		t.Fatal("the pass is not ready")
	}
	if res, err := w.tokens.FinishTokenPass(w.ctx(), w.gen, w.now); err != nil || len(res.Unlisted) != 1 {
		t.Fatalf("the pass: %+v %v", res, err)
	}
	if q, want := w.queues(unlisted), (queues{held: 1, tokenRefusals: 1}); q != want {
		t.Errorf("an unlisted token's queues after the pass: %+v, want %+v", q, want)
	}
	if q := w.queues(listed); q.refused != 2 || q.used != 1 || q.itemRefusals != 2 || q.tokenRefusals != 1 {
		t.Errorf("a listed token's queues after the pass: %+v", q)
	}
}

// F1: a refusal of a token Wappie holds no selector of (a bad record's)
// goes 30 days after the earlier of its queuing and the end its sticky row
// keeps, sent or not: a token revoked 31 days ago loses one queued and
// sent now; one revoked 29 days ago keeps it; with no sticky row, 30 days
// after it was queued, sent or not.
func TestANeverHeldTokensRefusalsGoByItsEnd(t *testing.T) {
	w := newTokenWorld(t)
	invalid := func(r *kc.TokenRecord) { r.Hash = "not a hash" }
	old, young, sent, recent := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	w.page(false,
		w.record(old, 1, invalid, revokedBy(kc.RevokedInConsole, w.now.Add(-31*tokenDay))),
		w.record(young, 1, invalid, revokedBy(kc.RevokedInConsole, w.now.Add(-29*tokenDay))))
	for _, id := range []uuid.UUID{old, young} {
		if exists, _, _ := w.sticky(id); !exists {
			t.Fatal("a bad record's revocation kept no sticky row")
		}
		w.exec(`INSERT INTO contract_token_refusals_out (token_id, version, item, perm, code, sent_at)
			VALUES ($1, 1, 'item', 'read', 'invalid_record', $2)`, id, w.now)
	}
	for id, queued := range map[uuid.UUID]time.Time{sent: w.now.Add(-31 * tokenDay), recent: w.now.Add(-29 * tokenDay)} {
		w.exec(`INSERT INTO contract_token_refusals_out (token_id, version, item, perm, code, queued_at, sent_at)
			VALUES ($1, 1, 'item', 'read', 'invalid_record', $2, $3)`, id, queued, w.now.Add(-tokenDay))
	}
	w.retain(w.now)
	for name, c := range map[string]struct {
		id   uuid.UUID
		want int
	}{
		"revoked 31 days ago, queued now":   {old, 0},
		"revoked 29 days ago, queued now":   {young, 1},
		"no sticky row, queued 31 days ago": {sent, 0},
		"no sticky row, queued 29 days ago": {recent, 1},
	} {
		if q := w.queues(c.id); q.refused != c.want {
			t.Errorf("a never-held token's refusal %s: %d left, want %d", name, q.refused, c.want)
		}
	}
}

// F1: the tokens of a workspace whose row Wappie deleted ended with it:
// their items' queue entries, their usage refusals on a number and their
// days of use go at the next pass, as a forgotten token's.
func TestADeletedWorkspacesTokensLoseTheirQueues(t *testing.T) {
	w := newTokenWorld(t)
	device := w.number(uuid.Nil)
	gone := uuid.New()
	w.exec(`INSERT INTO tenants (id, name) VALUES ($1, 'gone')`, gone)
	there, live := uuid.New(), uuid.New()
	w.page(false, w.record(there, 1, func(r *kc.TokenRecord) { r.WorkspaceID = gone.String() }), w.record(live, 1))
	for _, id := range []uuid.UUID{there, live} {
		w.fill(id, device)
	}
	w.exec(`DELETE FROM tenants WHERE id = $1`, gone)
	w.retain(w.now)
	if q, want := w.queues(there), (queues{held: 1, tokenRefusals: 1}); q != want {
		t.Errorf("a deleted workspace's token: %+v, want %+v", q, want)
	}
	if q, want := w.queues(live), (queues{refused: 2, held: 2, heldItems: 2, used: 1, itemRefusals: 2, tokenRefusals: 1}); q != want {
		t.Errorf("a live token: %+v, want %+v", q, want)
	}
}

// dateOf is a selector's date, nil without one.
func (w *tokenWorld) dateOf(selector string) *time.Time {
	w.t.Helper()
	var at time.Time
	err := w.pool.QueryRow(context.Background(), `SELECT until FROM contract_token_dates WHERE selector = $1`, selector).Scan(&at)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		w.t.Fatal(err)
	}
	return &at
}

// datesBack moves the selectors' dates back to at, their guard set aside
// for that alone, as untilBack does the selectors'.
func (w *tokenWorld) datesBack(at time.Time, selectors ...string) {
	w.t.Helper()
	w.exec(`ALTER TABLE contract_token_dates DISABLE TRIGGER contract_token_dates_guard`)
	w.exec(`UPDATE contract_token_dates SET until = $1 WHERE selector = ANY ($2)`, at, selectors)
	w.exec(`ALTER TABLE contract_token_dates ENABLE TRIGGER contract_token_dates_guard`)
}

// stopNote is an operator stop's note and author.
func (w *tokenWorld) stopNote(selector string) (note, by string) {
	w.t.Helper()
	if err := w.pool.QueryRow(context.Background(), `SELECT note, stopped_by FROM contract_token_stops
		WHERE selector = $1 AND cause = 'operator'`, selector).Scan(&note, &by); err != nil {
		w.t.Fatal(err)
	}
	return note, by
}

// F2(i): a valid record of a selector Wappie does not keep (another
// workspace's token, revoked or not, or a token held only in the sticky
// set) dates the selector, to the record's created_at + 365 days (at most
// Wappie's clock + 365 days), so a stop made after it goes by that date,
// not 365 days after it was made. A bad record dates nothing, nor does a
// record of a selector another token holds: those stops stand. A stop
// timed past the pass keeps only its times, with the date as its
// record_until; the dates go once past.
func TestAStopTakesTheDateOfARecordWappieDidNotKeep(t *testing.T) {
	w := newTokenWorld(t)
	elsewhere := func(r *kc.TokenRecord) { r.WorkspaceID = uuid.NewString() }
	invalid := func(r *kc.TokenRecord) { r.Hash = "not a hash" }
	created := w.now.Add(-300 * tokenDay)
	made := createdAt(created, 300*tokenDay)
	other, revoked, sticky, bad, ahead, claimant, holder := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	w.page(false,
		w.record(other, 1, elsewhere, made),
		w.record(revoked, 1, elsewhere, made, revokedBy(kc.RevokedInConsole, w.now.Add(-time.Hour))),
		w.record(sticky, 1, invalid, made, revokedBy(kc.RevokedInConsole, w.now.Add(-time.Hour))),
		w.record(bad, 1, elsewhere, invalid, made),
		w.record(ahead, 1, elsewhere, createdAt(w.now.Add(10*tokenDay), 30*tokenDay)),
		w.record(holder, 1))
	// The sticky one's later valid record, unrevoked, as after a platform
	// restore: never a live row (M8), but a valid record of its selector.
	// Another token's valid record that claims the holder's selector.
	if res := w.page(false, w.record(sticky, 2, made), w.record(claimant, 1, elsewhere, made, func(r *kc.TokenRecord) { r.Selector = selectorOf(holder) })); res.Bad != 1 {
		t.Fatalf("the later records: %+v", res)
	}
	if w.token(sticky).Exists {
		t.Fatal("a token held only in the sticky set made a live row")
	}
	date := created.Add(kc.MaxTokenLifetime)
	for name, c := range map[string]struct {
		sel  string
		want *time.Time
	}{
		"another workspace's token":              {selectorOf(other), &date},
		"another workspace's revoked token":      {selectorOf(revoked), &date},
		"a token held only in the sticky set":    {selectorOf(sticky), &date},
		"a bad record's":                         {selectorOf(bad), nil},
		"a selector Wappie holds":                {selectorOf(holder), nil},
		"one created ahead of the clock, capped": {selectorOf(ahead), new(w.now.Add(kc.MaxTokenLifetime))},
	} {
		got := w.dateOf(c.sel)
		if (got == nil) != (c.want == nil) || got != nil && !got.Equal(*c.want) {
			t.Errorf("the date of %s: %v, want %v", name, got, c.want)
		}
	}
	// Each stopped since, with a note; one timed a day ahead.
	selectors := []string{selectorOf(other), selectorOf(revoked), selectorOf(sticky), selectorOf(bad), selectorOf(holder)}
	for _, sel := range selectors {
		if _, err := w.tokens.StopToken(w.ctx(), sel, "root", "leak", w.now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := w.tokens.StopToken(w.ctx(), selectorOf(ahead), "root", "leak", w.now.Add(tokenDay)); err != nil {
		t.Fatal(err)
	}
	// Their dates come: moved back past the database's clock.
	past := w.now.Add(-time.Hour)
	w.datesBack(past, selectorOf(other), selectorOf(revoked), selectorOf(sticky), selectorOf(ahead))
	before := w.letGo()
	w.retain(w.now)
	for name, c := range map[string]struct {
		sel  string
		want bool
	}{
		"another workspace's token":           {selectorOf(other), false},
		"another workspace's revoked token":   {selectorOf(revoked), false},
		"a token held only in the sticky set": {selectorOf(sticky), false},
		"a bad record's":                      {selectorOf(bad), true},
		"a selector Wappie holds":             {selectorOf(holder), true},
		"one timed ahead":                     {selectorOf(ahead), true},
	} {
		if exists, _, _ := w.stopOf(c.sel); exists != c.want {
			t.Errorf("past its selector's date, the stop of %s: there %v, want %v", name, exists, c.want)
		}
	}
	if after := w.letGo(); after == nil || before != nil && !after.After(*before) {
		t.Errorf("the mark of what retention let go: %v, was %v", after, before)
	}
	for _, sel := range []string{selectorOf(bad), selectorOf(holder)} {
		if note, by := w.stopNote(sel); note != "leak" || by != "root" {
			t.Errorf("an undated stop's note %q and author %q, want leak and root", note, by)
		}
	}
	if note, by := w.stopNote(selectorOf(ahead)); note != "" || by != "wappie" {
		t.Errorf("a stop timed ahead, past its date: note %q, by %q", note, by)
	}
	if _, _, ru := w.stopOf(selectorOf(ahead)); ru == nil || !ru.Equal(past) {
		t.Errorf("a stop timed ahead, past its date: record_until %v, want the date %v", ru, past)
	}
	for _, sel := range []string{selectorOf(other), selectorOf(revoked), selectorOf(sticky), selectorOf(ahead)} {
		if d := w.dateOf(sel); d != nil {
			t.Errorf("a date past its until is kept: %v", *d)
		}
	}
}

// stickyClock is a sticky row's lookup state: whether Wappie's clock dates
// it, its generation, and whether it is settled (never asked again).
func (w *tokenWorld) stickyClock(id uuid.UUID) (clock bool, gen *uuid.UUID, settled bool) {
	w.t.Helper()
	if err := w.pool.QueryRow(context.Background(), `SELECT clock_until, clock_gen, coalesce(lookup_after = 'infinity', false)
		FROM contract_token_sticky WHERE token_id = $1`, id).Scan(&clock, &gen, &settled); err != nil {
		w.t.Fatal(err)
	}
	return clock, gen, settled
}

// F3, the applier: a bad record's revocation of a token Wappie holds no
// selector of is dated by Wappie's clock and marked so, with its
// generation; a later valid record of the token clears the mark and lowers
// until to its own date. A valid record's revocation, and a held token's
// bad record, are never marked. After a reset, the token's bad record of
// the new generation marks the row with it, to be asked again.
func TestABadRecordsRevocationIsClockDated(t *testing.T) {
	w := newTokenWorld(t)
	elsewhere := func(r *kc.TokenRecord) { r.WorkspaceID = uuid.NewString() }
	invalid := func(r *kc.TokenRecord) { r.Hash = "not a hash" }
	revoked := revokedBy(kc.RevokedInConsole, w.now.Add(-time.Hour))
	bad, valid, held, again := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	w.page(false, w.record(held, 1))
	w.page(false,
		w.record(bad, 1, invalid, revoked),
		w.record(valid, 1, elsewhere, revoked),
		w.record(held, 2, invalid, revoked),
		w.record(again, 1, elsewhere, invalid, revoked))
	for name, c := range map[string]struct {
		id    uuid.UUID
		clock bool
	}{
		"a bad record of an unknown token":            {bad, true},
		"a valid record of another workspace's token": {valid, false},
		"a held token's bad record":                   {held, false},
		"another workspace's bad record":              {again, true},
	} {
		clock, gen, _ := w.stickyClock(c.id)
		if clock != c.clock || c.clock && (gen == nil || *gen != w.gen) {
			t.Errorf("%s: clock-dated %v (generation %v), want %v (%v)", name, clock, gen, c.clock, w.gen)
		}
	}
	yearOn := w.now.Add(kc.MaxTokenLifetime)
	if u := w.stickyUntil(bad); u == nil || !u.Equal(yearOn) {
		t.Fatalf("a bad record's revocation is kept to %v, want %v", u, yearOn)
	}
	created := w.now.Add(-100 * tokenDay)
	w.page(false, w.record(bad, 2, elsewhere, createdAt(created, 200*tokenDay), revoked))
	if clock, _, _ := w.stickyClock(bad); clock {
		t.Error("a valid record left the revocation dated by Wappie's clock")
	}
	if u := w.stickyUntil(bad); u == nil || !u.Equal(created.Add(kc.MaxTokenLifetime)) {
		t.Errorf("after a valid record, the revocation is kept to %v, want %v", u, created.Add(kc.MaxTokenLifetime))
	}
	// Settled in its generation, then a reset: the new generation's bad
	// record marks it with that one, and asks again.
	w.exec(`UPDATE contract_token_sticky SET lookup_after = 'infinity' WHERE token_id = $1`, again)
	w.reset()
	w.page(false, w.record(again, 1, elsewhere, invalid, revoked))
	if clock, gen, settled := w.stickyClock(again); !clock || gen == nil || *gen != w.gen || settled {
		t.Errorf("a bad record after a reset: clock-dated %v, generation %v (want %v), settled %v", clock, gen, w.gen, settled)
	}
}

// due lists the lookups due at at, as ids and selectors.
func (w *tokenWorld) due(at time.Time) map[string]bool {
	w.t.Helper()
	got, err := w.tokens.DueTokenLookups(w.ctx(), at, 50)
	if err != nil {
		w.t.Fatal(err)
	}
	out := map[string]bool{}
	for _, l := range got {
		if l.ByID() {
			out["id "+l.Token.String()] = true
		} else {
			out["selector "+l.Selector] = true
		}
	}
	return out
}

// stopSettled reports whether a selector's operator stop is never to be
// asked again.
func (w *tokenWorld) stopSettled(selector string) bool {
	w.t.Helper()
	var settled bool
	if err := w.pool.QueryRow(context.Background(), `SELECT coalesce(lookup_after = 'infinity', false) FROM contract_token_stops
		WHERE selector = $1 AND cause = 'operator'`, selector).Scan(&settled); err != nil {
		w.t.Fatal(err)
	}
	return settled
}

// F2(ii) and F3, the store's side of the leader's lookups: what is due (a
// clock-dated revocation of a token Wappie holds no selector of; a stop of
// a selector Wappie does not hold that nothing dates, a replayed one too),
// and never anything else (a held selector's stop, a dated stop, a stop of
// a dated selector, a lapsed stop, a revocation a valid record dated, a
// held token's). A good answer dates the token's revocation and its
// selector's stops and date; a record that cannot date them writes
// nothing; a not_found settles the revocation and lets nothing go, so it
// keeps Wappie's clock's date until a later valid record lowers it, and
// settles a stop undated; a call with no answer puts it off, a bad answer
// doubling each time. A held selector's stop is never shortened by an
// answer.
func TestTheLookupsDateStopsAndBadRevocations(t *testing.T) {
	w := newTokenWorld(t)
	elsewhere := func(r *kc.TokenRecord) { r.WorkspaceID = uuid.NewString() }
	invalid := func(r *kc.TokenRecord) { r.Hash = "not a hash" }
	revoked := revokedBy(kc.RevokedInConsole, w.now.Add(-time.Hour))
	bad, notFound, datedTok, heldTok := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	w.page(false, w.record(heldTok, 1, revoked))
	w.page(false,
		w.record(bad, 1, invalid, revoked),
		w.record(notFound, 1, invalid, revoked),
		w.record(datedTok, 1, invalid, revoked))
	w.page(false, w.record(datedTok, 2, elsewhere, revoked))
	stop := func(sel string, at time.Time) {
		t.Helper()
		if _, err := w.tokens.StopToken(w.ctx(), sel, "root", "leak", at); err != nil {
			t.Fatal(err)
		}
	}
	undated, replayed, lapsed, later, seenBefore := selectorOf(uuid.New()), selectorOf(uuid.New()), selectorOf(uuid.New()), uuid.New(), uuid.New()
	stop(undated, w.now)
	if ok, err := w.tokens.ReplayTokenStop(w.ctx(), replayed, "wappie", "", w.now.Add(-time.Hour), w.now); err != nil || !ok {
		t.Fatalf("the replay: %v %v", ok, err)
	}
	stop(lapsed, w.now.Add(-366*tokenDay))
	stop(selectorOf(bad), w.now)
	stop(selectorOf(heldTok), w.now)
	stop(selectorOf(later), w.now)
	w.page(false, w.record(later, 1, elsewhere), w.record(seenBefore, 1, elsewhere))
	stop(selectorOf(seenBefore), w.now)
	want := map[string]bool{"id " + bad.String(): true, "id " + notFound.String(): true,
		"selector " + undated: true, "selector " + replayed: true, "selector " + selectorOf(bad): true}
	if got := w.due(w.now); !mapsEqual(got, want) {
		t.Fatalf("due: %v, want %v", got, want)
	}

	// A record that cannot date them: nothing written.
	rec := w.record(bad, 3, elsewhere, createdAt(w.now.Add(-100*tokenDay), 200*tokenDay), revoked)
	for name, r := range map[string]kc.TokenRecord{
		"another app's":   func() kc.TokenRecord { r := rec; r.App = "mailie"; return r }(),
		"another token's": w.record(uuid.New(), 1, elsewhere),
		"not valid":       func() kc.TokenRecord { r := rec; r.Hash = "not a hash"; return r }(),
		"another reading key": func() kc.TokenRecord {
			r := rec
			r.ReadingKey = readingKey(t)
			r.ReadingKey.Fingerprint = "ffffffffffffffffffffffffffffffff"
			return r
		}(),
	} {
		if err := w.tokens.TokenLookupAnswered(w.ctx(), store.TokenLookup{Token: bad}, r, w.now); !errors.Is(err, store.ErrTokenLookupRecord) {
			t.Errorf("a lookup answered with %s record: %v", name, err)
		}
	}
	if err := w.tokens.TokenLookupAnswered(w.ctx(), store.TokenLookup{Selector: undated}, w.record(uuid.New(), 1, elsewhere), w.now); !errors.Is(err, store.ErrTokenLookupRecord) {
		t.Errorf("a lookup by selector answered with another selector's record: %v", err)
	}
	if got := w.due(w.now); !mapsEqual(got, want) {
		t.Fatalf("after records that date nothing, due: %v, want %v", got, want)
	}

	// By id, a good record: the revocation and its selector's stop dated,
	// and its selector's date written.
	created := w.now.Add(-100 * tokenDay)
	date := created.Add(kc.MaxTokenLifetime)
	if err := w.tokens.TokenLookupAnswered(w.ctx(), store.TokenLookup{Token: bad}, rec, w.now); err != nil {
		t.Fatal(err)
	}
	if clock, _, _ := w.stickyClock(bad); clock {
		t.Error("an answered lookup left the revocation dated by Wappie's clock")
	}
	if u := w.stickyUntil(bad); u == nil || !u.Equal(date) {
		t.Errorf("an answered lookup: the revocation kept to %v, want %v", u, date)
	}
	if _, _, ru := w.stopOf(selectorOf(bad)); ru == nil || !ru.Equal(date) {
		t.Errorf("an answered lookup: its selector's stop dated %v, want %v", ru, date)
	}
	if d := w.dateOf(selectorOf(bad)); d == nil || !d.Equal(date) {
		t.Errorf("an answered lookup: its selector's date %v, want %v", d, date)
	}
	// By selector, a good record of a token Wappie never saw: dated, and
	// settled.
	answer := w.record(uuid.New(), 1, elsewhere, createdAt(created, 200*tokenDay), func(r *kc.TokenRecord) { r.Selector = undated })
	if err := w.tokens.TokenLookupAnswered(w.ctx(), store.TokenLookup{Selector: undated}, answer, w.now); err != nil {
		t.Fatal(err)
	}
	if _, _, ru := w.stopOf(undated); ru == nil || !ru.Equal(date) || !w.stopSettled(undated) {
		t.Errorf("a stop answered by selector: record_until %v (want %v), settled %v", ru, date, w.stopSettled(undated))
	}
	// A signed not_found by selector: settled, undated, standing to its
	// stopped_at + 365 days.
	if err := w.tokens.TokenLookupNotFound(w.ctx(), store.TokenLookup{Selector: replayed}); err != nil {
		t.Fatal(err)
	}
	if _, _, ru := w.stopOf(replayed); ru != nil || !w.stopSettled(replayed) {
		t.Errorf("a stop the platform does not know: record_until %v, settled %v", ru, w.stopSettled(replayed))
	}
	// A signed not_found by id, in the generation the bad record came in,
	// which is Wappie's: settled, and the revocation stays, dated by
	// Wappie's clock. A not_found never clears a revocation.
	kept := w.stickyUntil(notFound)
	if kept == nil || !kept.Equal(w.now.Add(kc.MaxTokenLifetime)) {
		t.Fatalf("a bad record's revocation is kept to %v, want %v", kept, w.now.Add(kc.MaxTokenLifetime))
	}
	if err := w.tokens.TokenLookupNotFound(w.ctx(), store.TokenLookup{Token: notFound}); err != nil {
		t.Fatal(err)
	}
	if exists, _, _ := w.sticky(notFound); !exists {
		t.Fatal("a not_found by id let the revocation go")
	}
	if clock, _, settled := w.stickyClock(notFound); !clock || !settled {
		t.Errorf("a not_found by id: clock-dated %v, settled %v; want both", clock, settled)
	}
	if u := w.stickyUntil(notFound); u == nil || !u.Equal(*kept) {
		t.Errorf("a not_found by id: the revocation is kept to %v, want %v as before", u, *kept)
	}
	if got := w.due(w.now); len(got) != 0 {
		t.Fatalf("after the answers, due: %v", got)
	}
	// A later valid record of the token still lowers it to its own date.
	w.page(false, w.record(notFound, 2, elsewhere, createdAt(created, 200*tokenDay), revoked))
	if clock, _, _ := w.stickyClock(notFound); clock {
		t.Error("a valid record after a not_found left the revocation dated by Wappie's clock")
	}
	if u := w.stickyUntil(notFound); u == nil || !u.Equal(date) {
		t.Errorf("a valid record after a not_found: the revocation is kept to %v, want %v", u, date)
	}
	// So does one that does not revoke it, as when the platform names the
	// token again unrevoked after a restore: of another workspace; of
	// Wappie's own, which never makes a live row (M8); and one refused for
	// a selector another token holds. It dates the row, revoked as before,
	// and narrows nothing. A valid record makes no row where none is.
	unrevoked := map[string]uuid.UUID{"of another workspace": uuid.New(), "of Wappie's workspace": uuid.New(), "with a taken selector": uuid.New()}
	for _, id := range unrevoked {
		w.page(false, w.record(id, 1, invalid, revoked))
		if err := w.tokens.TokenLookupNotFound(w.ctx(), store.TokenLookup{Token: id}); err != nil {
			t.Fatal(err)
		}
	}
	if got := w.due(w.now); len(got) != 0 {
		t.Fatalf("after the not_founds, due: %v", got)
	}
	res := w.page(false,
		w.record(unrevoked["of another workspace"], 2, elsewhere, createdAt(created, 200*tokenDay)),
		w.record(unrevoked["of Wappie's workspace"], 2, createdAt(created, 200*tokenDay)),
		w.record(unrevoked["with a taken selector"], 2, createdAt(created, 200*tokenDay), func(r *kc.TokenRecord) { r.Selector = selectorOf(heldTok) }))
	if res.Narrowed {
		t.Error("valid records that only date revocations narrowed something")
	}
	for name, id := range unrevoked {
		if exists, rv, _ := w.sticky(id); !exists || !rv {
			t.Errorf("a valid unrevoked record %s after a not_found: the row is there %v, revoked %v", name, exists, rv)
		}
		if clock, _, settled := w.stickyClock(id); clock || settled {
			t.Errorf("a valid unrevoked record %s after a not_found: clock-dated %v, settled %v", name, clock, settled)
		}
		if u := w.stickyUntil(id); u == nil || !u.Equal(date) {
			t.Errorf("a valid unrevoked record %s after a not_found: the revocation is kept to %v, want %v", name, u, date)
		}
		if tok := w.token(id); tok.Exists {
			t.Errorf("a valid unrevoked record %s made a live row", name)
		}
	}
	// One created when the bad record came gives the row the same date,
	// now the token's own, not Wappie's clock's.
	same := uuid.New()
	w.page(false, w.record(same, 1, invalid, revoked))
	if err := w.tokens.TokenLookupNotFound(w.ctx(), store.TokenLookup{Token: same}); err != nil {
		t.Fatal(err)
	}
	w.page(false, w.record(same, 2, elsewhere, createdAt(w.now, 200*tokenDay)))
	if clock, _, _ := w.stickyClock(same); clock {
		t.Error("a valid record dated as the row is left it dated by Wappie's clock")
	}
	if u := w.stickyUntil(same); u == nil || !u.Equal(w.now.Add(kc.MaxTokenLifetime)) {
		t.Errorf("a valid record dated as the row: the revocation is kept to %v, want %v", u, w.now.Add(kc.MaxTokenLifetime))
	}
	if exists, _, _ := w.sticky(later); exists {
		t.Error("a valid unrevoked record of a token Wappie holds nothing of made a sticky row")
	}
	if got := w.due(w.now); len(got) != 0 {
		t.Fatalf("after the dates, due: %v", got)
	}

	// No answer: asked again 15 minutes on. Bad answers: 15 minutes, then
	// 30, the count rising.
	failing := selectorOf(uuid.New())
	stop(failing, w.now)
	const retry, most = 15 * time.Minute, 24 * time.Hour
	l := store.TokenLookup{Selector: failing}
	if n, err := w.tokens.TokenLookupFailed(w.ctx(), l, w.now, false, retry, most); err != nil || n != 0 {
		t.Fatalf("no answer: %d %v", n, err)
	}
	if w.due(w.now.Add(retry - time.Second))["selector "+failing] || !w.due(w.now.Add(retry))["selector "+failing] {
		t.Error("a lookup with no answer is not due again 15 minutes on")
	}
	at := w.now.Add(retry)
	if n, err := w.tokens.TokenLookupFailed(w.ctx(), l, at, true, retry, most); err != nil || n != 1 {
		t.Fatalf("a bad answer: %d %v", n, err)
	}
	if w.due(at.Add(retry - time.Second))["selector "+failing] || !w.due(at.Add(retry))["selector "+failing] {
		t.Error("a first bad answer is not asked again 15 minutes on")
	}
	at = at.Add(retry)
	if n, err := w.tokens.TokenLookupFailed(w.ctx(), l, at, true, retry, most); err != nil || n != 2 {
		t.Fatalf("a second bad answer: %d %v", n, err)
	}
	if w.due(at.Add(2*retry - time.Second))["selector "+failing] || !w.due(at.Add(2 * retry))["selector "+failing] {
		t.Error("a second bad answer is not asked again 30 minutes on")
	}

	// A held selector's stop, answered with a record whose date is long
	// past, is not shortened: it goes with its selector.
	old := w.record(heldTok, 1, createdAt(w.now.Add(-400*tokenDay), 30*tokenDay))
	if err := w.tokens.TokenLookupAnswered(w.ctx(), store.TokenLookup{Selector: selectorOf(heldTok)}, old, w.now); err != nil {
		t.Fatal(err)
	}
	if d := w.dateOf(selectorOf(heldTok)); d != nil {
		t.Errorf("a held selector got a date: %v", *d)
	}
	w.retain(w.now)
	if exists, _, _ := w.stopOf(selectorOf(heldTok)); !exists {
		t.Error("an answer shortened a held selector's stop")
	}
}

func mapsEqual(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}
