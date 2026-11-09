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

	"whatserver2/internal/store"
)

// reset restarts both feeds from the token side into a new generation.
func (w *tokenWorld) reset() {
	w.t.Helper()
	next := uuid.New()
	if ok, err := w.contract.RestartFromTokens(w.ctx(), w.gen, &next, true); err != nil || !ok {
		w.t.Fatalf("the reset: %v %v", ok, err)
	}
	w.gen = next
	// The account documents of the new generation, as the round PUTs them.
	w.exec(`UPDATE contract_accounts SET generation = $1, version = 1`, w.gen)
}

// held are the queued held tokens of the current generation, by id.
func (w *tokenWorld) held() map[uuid.UUID]kc.TokenHeld {
	w.t.Helper()
	out := map[uuid.UUID]kc.TokenHeld{}
	rows, err := w.pool.Query(context.Background(), `SELECT token_id, revoked, expires_at, removed, reading_key FROM contract_token_held_out
		WHERE generation = $1`, w.gen)
	if err != nil {
		w.t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var h kc.TokenHeld
		var expires *time.Time
		var removed []byte
		if err := rows.Scan(&id, &h.Revoked, &expires, &removed, &h.ReadingKey); err != nil {
			w.t.Fatal(err)
		}
		if expires != nil {
			at := kc.T(*expires)
			h.ExpiresAt = &at
		}
		if err := json.Unmarshal(removed, &h.Removed); err != nil {
			w.t.Fatal(err)
		}
		out[id] = h
	}
	return out
}

// TestTheStickySetOutlivesTheContent (M8): retention forgets a revoked
// token's content 30 days after its end, but its sticky row, with its
// revocation and earliest expiry, stays to created_at + 365 days; a record
// that comes back later, with a later expiry and no revocation (a platform
// restore from before them), is applied for its narrowings only and never
// revives it, and the reset's pass reports it held, revoked or expiring
// earlier; an expired token by Wappie's clock sticks as expired. Past until,
// retention lets the token's row, selector, sticky row and pin go through
// their guards, a token's of a workspace Wappie deleted since included,
// with its removed instances.
func TestTheStickySetOutlivesTheContent(t *testing.T) {
	w := newTokenWorld(t)
	device := w.number(uuid.Nil)
	revoked, expiring := uuid.New(), uuid.New()
	expiry := w.now.Add(time.Hour)
	w.page(false, w.record(revoked, 1, grants(device, w.ownerSub, w.now, kc.CanRead)),
		w.record(expiring, 1, func(r *kc.TokenRecord) { r.ExpiresAt = kc.T(expiry) }))
	w.page(false, w.record(revoked, 2, revokedBy(kc.RevokedInConsole, w.now)))

	// The janitor at expiry, on Wappie's clock.
	later := w.now.Add(2 * time.Hour)
	if got, err := w.tokens.RetainTokens(w.ctx(), later); err != nil || got.Expired != 1 {
		t.Fatalf("the janitor: %+v %v", got, err)
	}
	if exists, _, ended := w.sticky(expiring); !exists || ended != "expired" {
		t.Fatalf("an expired token is not sticky: %v %q", exists, ended)
	}
	var earliest time.Time
	if err := w.pool.QueryRow(context.Background(), `SELECT earliest_expires_at FROM contract_token_sticky WHERE token_id = $1`, expiring).
		Scan(&earliest); err != nil || !earliest.Equal(expiry) {
		t.Fatalf("the sticky row's earliest expiry %v, want %v (%v)", earliest, expiry, err)
	}
	// 31 days on, the revoked token's content is forgotten; the sticky row
	// and the selector stay.
	if got, err := w.tokens.RetainTokens(w.ctx(), w.now.Add(31*24*time.Hour)); err != nil || got.Forgotten != 2 {
		t.Fatalf("31 days on: %+v %v", got, err)
	}
	if s := w.token(revoked); !s.Exists || !s.Forgotten || s.Name != "" || len(w.perms(revoked)) != 0 {
		t.Fatalf("the forgotten token: %+v %v", s, w.perms(revoked))
	}
	if exists, rev, _ := w.sticky(revoked); !exists || !rev {
		t.Fatal("the sticky row went with the content")
	}
	// A restored record of each, unrevoked, expiring later and listing a
	// grant: never revived.
	w.reset()
	restored := func(r *kc.TokenRecord) { r.ExpiresAt = kc.T(w.now.Add(200 * 24 * time.Hour)) }
	w.page(false, w.record(revoked, 1, grants(device, w.ownerSub, w.now, kc.CanRead), restored),
		w.record(expiring, 1, grants(device, w.ownerSub, w.now, kc.CanRead), restored))
	for _, id := range []uuid.UUID{revoked, expiring} {
		if s := w.token(id); len(w.perms(id)) != 0 || (id == revoked && !s.Revoked) {
			t.Fatalf("a restored record revived %s: %+v %v", id, s, w.perms(id))
		}
	}
	var stored time.Time
	w.scoped(func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT expires_at FROM contract_tokens WHERE id = $1`, expiring).Scan(&stored)
	})
	if !stored.Equal(expiry) {
		t.Fatalf("a restored record raised the expiry to %v, want %v", stored, expiry)
	}
	held := w.held()
	if h := held[revoked]; !h.Revoked {
		t.Fatalf("the restored revoked token is not held revoked: %+v", held)
	}
	if h := held[expiring]; h.Revoked || h.ExpiresAt == nil || !h.ExpiresAt.Equal(expiry) {
		t.Fatalf("the restored expired token is not held with its earlier expiry %v: %+v", expiry, held)
	}
	// A retention 400 days on by Wappie's clock, but before until by the
	// database's, which the guards read, lets nothing go.
	if _, err := w.tokens.RetainTokens(w.ctx(), w.now.Add(400*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if exists, _, _ := w.sticky(revoked); !exists || !w.token(revoked).Exists {
		t.Fatal("a token went before its until on the database's clock")
	}

	// A token of a second workspace, with a pin and a removed instance,
	// whose workspace Wappie then deletes: its token row goes with it, the
	// rest of no foreign key stays.
	elsewhere, far := uuid.New(), uuid.New()
	w.exec(`INSERT INTO tenants (id, name) VALUES ($1, 'elsewhere')`, elsewhere)
	w.page(false, w.record(far, 1, func(r *kc.TokenRecord) {
		r.WorkspaceID = elsewhere.String()
		r.ReadingKey = readingKey(t)
		r.Items = []kc.TokenItem{{ID: "not-a-number", Kind: kc.ItemNumber, Perms: []kc.TokenPerm{{Perm: kc.CanSend, GrantedBy: w.ownerSub.String(), GrantedAt: kc.T(w.now)}}}}
	}))
	in := func(ws uuid.UUID, query string, args ...any) int {
		t.Helper()
		var n int
		inTenantTx(context.Background(), t, w.pool, ws, func(tx pgx.Tx) error { return tx.QueryRow(context.Background(), query, args...).Scan(&n) })
		return n
	}
	if in(elsewhere, `SELECT count(*) FROM contract_token_pins`) != 1 || in(elsewhere, `SELECT count(*) FROM contract_token_removed`) != 1 {
		t.Fatal("the second workspace's token has no pin or no removed instance")
	}
	w.exec(`DELETE FROM tenants WHERE id = $1`, elsewhere)
	// Its removed instances go at the next pass, before its until.
	if _, err := w.tokens.RetainTokens(w.ctx(), w.now); err != nil {
		t.Fatal(err)
	}
	if in(elsewhere, `SELECT count(*) FROM contract_token_removed`) != 0 || in(elsewhere, `SELECT count(*) FROM contract_token_pins`) != 1 {
		t.Fatal("a deleted workspace's removed instances stayed, or its pin went before its until")
	}

	// Past every until (moved back, the guards set aside for that alone),
	// retention lets everything go through the guards.
	w.exec(`ALTER TABLE contract_token_selectors DISABLE TRIGGER contract_token_selectors_guard;
		UPDATE contract_token_selectors SET until = clock_timestamp() - interval '1 second';
		ALTER TABLE contract_token_selectors ENABLE TRIGGER contract_token_selectors_guard;
		ALTER TABLE contract_token_sticky DISABLE TRIGGER contract_token_sticky_guard;
		UPDATE contract_token_sticky SET until = clock_timestamp() - interval '1 second';
		ALTER TABLE contract_token_sticky ENABLE TRIGGER contract_token_sticky_guard;
		ALTER TABLE contract_token_pins DISABLE TRIGGER contract_token_pins_guard, NO FORCE ROW LEVEL SECURITY;
		UPDATE contract_token_pins SET until = clock_timestamp() - interval '1 second';
		ALTER TABLE contract_token_pins ENABLE TRIGGER contract_token_pins_guard, FORCE ROW LEVEL SECURITY`)
	got, err := w.tokens.RetainTokens(w.ctx(), w.now.Add(400*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if got.Ended != 2 {
		t.Fatalf("retention past until: %+v, want the 2 token rows of the workspace gone", got)
	}
	var selectors, sticky int
	if err := w.pool.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM contract_token_selectors), (SELECT count(*) FROM contract_token_sticky)`).
		Scan(&selectors, &sticky); err != nil {
		t.Fatal(err)
	}
	if selectors != 0 || sticky != 0 {
		t.Fatalf("past until: %d selectors and %d sticky rows left", selectors, sticky)
	}
	for _, ws := range []uuid.UUID{w.tenant, elsewhere} {
		if n := in(ws, `SELECT (SELECT count(*) FROM contract_tokens) + (SELECT count(*) FROM contract_token_pins) +
			(SELECT count(*) FROM contract_token_removed) + (SELECT count(*) FROM contract_token_perms)`); n != 0 {
			t.Fatalf("past until, %d token rows, pins, removed instances or perms left in %s", n, ws)
		}
	}
}

// TestTokenGenerationResetNeverWidens (the plan's 10.2, the design's 3.3):
// against the new generation's record, Wappie keeps the earlier expiry, the
// pin when the record names no key, a dropped grant's instance off and a
// waiting one waiting, and reports in the pass's held what it keeps
// narrower: the expiry, the pin's fingerprint and the dropped instance,
// never the waiting one, which is judged once the giver's document comes.
func TestTokenGenerationResetNeverWidens(t *testing.T) {
	w := newTokenWorld(t)
	waitingOn, droppedOn := w.number(uuid.Nil), w.number(uuid.Nil)
	giverSub := uuid.New()
	w.linked("giver", "admin", giverSub, false)
	id := uuid.New()
	key := readingKey(t)
	early := w.now.Add(-time.Hour)
	first := w.record(id, 1, func(r *kc.TokenRecord) { r.ReadingKey = key },
		grants(waitingOn, giverSub, early, kc.CanSend), grants(droppedOn, w.ownerSub, early, kc.CanRead))
	w.page(false, first)
	if got := w.judge(); got.Waiting != 1 || got.Applied != 1 {
		t.Fatalf("the judge: %+v", got)
	}
	// Shortened, its Read dropped.
	shorter := w.now.Add(10 * 24 * time.Hour)
	w.page(false, w.record(id, 2, func(r *kc.TokenRecord) { r.ReadingKey = key; r.ExpiresAt = kc.T(shorter) },
		grants(waitingOn, giverSub, early, kc.CanSend)))
	pin := func() (fp string, pinned time.Time) {
		t.Helper()
		w.scoped(func(tx pgx.Tx) error {
			return tx.QueryRow(context.Background(), `SELECT fingerprint, pinned_at FROM contract_token_pins WHERE token_id = $1`, id).Scan(&fp, &pinned)
		})
		return fp, pinned
	}
	fp, pinned := pin()

	// A platform restore: the new generation lists the first version again,
	// with no key.
	w.reset()
	restored := first
	restored.Generation, restored.ReadingKey = w.gen.String(), nil
	if res := w.page(true, restored); res.Bad != 0 || res.Failed != 0 {
		t.Fatalf("the restored record: %+v", res)
	}
	var expires time.Time
	var generation uuid.UUID
	w.scoped(func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT t.expires_at, p.generation FROM contract_tokens t
			JOIN contract_token_perms p ON p.token_id = t.id AND p.device_id = $2 AND p.perm = 'send' WHERE t.id = $1`, id, waitingOn).
			Scan(&expires, &generation)
	})
	if !expires.Equal(shorter) {
		t.Fatalf("the expiry rose to %v, want %v", expires, shorter)
	}
	if p := w.perms(id); len(p) != 1 || p[waitingOn.String()+"/send"] != "waiting" || generation != w.gen {
		t.Fatalf("the perms after the restore: %v (the waiting one's generation %s, want %s)", p, generation, w.gen)
	}
	if f, at := pin(); f != fp || !at.Equal(pinned) {
		t.Fatalf("the pin changed: %s at %v, was %s at %v", f, at, fp, pinned)
	}
	h, ok := w.held()[id]
	switch {
	case !ok || h.Revoked:
		t.Fatalf("held: %+v", w.held())
	case h.ExpiresAt == nil || !h.ExpiresAt.Equal(shorter):
		t.Fatalf("held.expires_at %v, want the earlier %v", h.ExpiresAt, shorter)
	case h.ReadingKey == nil || *h.ReadingKey != key.Fingerprint:
		t.Fatalf("held.reading_key %v, want the pin's %s", h.ReadingKey, key.Fingerprint)
	case len(h.Removed) != 1 || h.Removed[0] != (kc.HeldPerm{Item: droppedOn.String(), Perm: kc.CanRead}):
		t.Fatalf("held.removed %+v, want the dropped Read alone", h.Removed)
	}
	// The waiting grant is judged once its giver's document comes.
	w.exec(`INSERT INTO contract_accounts (sub, generation, version, status, doc) VALUES ($1, $2, 1, 'active',
		jsonb_build_object('v', 1, 'workspaces', jsonb_build_array(jsonb_build_object('id', $3::text))))`, giverSub, w.gen, w.tenant)
	if got := w.judge(); got.Applied != 1 || w.perms(id)[waitingOn.String()+"/send"] != "applied" {
		t.Fatalf("the waiting grant with its giver's document: %+v %v", got, w.perms(id))
	}
}

// TestTheResetRemembersWhatWasHeld (H7): at a reset every applied perm is
// held, every pending one goes with a removed row, and waiting stays
// waiting; a judge that races the reset judges nothing of the old
// generation. In the new generation, a perm granted before the old
// generation's last trusted published_through comes back only when it was
// held; one that was not is kept off and reported held.
func TestTheResetRemembersWhatWasHeld(t *testing.T) {
	w := newTokenWorld(t)
	device := w.number(uuid.Nil)
	id := uuid.New()
	early := w.now.Add(-time.Hour)
	w.page(false, w.record(id, 1, grants(device, w.ownerSub, early, kc.CanRead, kc.CanSend)))
	if got := w.judge(); got.Applied != 2 {
		t.Fatalf("the judge: %+v", got)
	}
	// manage, given later, unjudged at the reset.
	w.page(false, w.record(id, 2, grants(device, w.ownerSub, early, kc.CanRead, kc.CanSend, kc.CanManage)))
	old := w.gen
	w.reset()
	if got := w.perms(id); got[device.String()+"/read"] != "applied" || got[device.String()+"/send"] != "applied" || len(got) != 2 {
		t.Fatalf("after the reset: %v", got)
	}
	if n := w.count(`SELECT count(*) FROM contract_token_perms WHERE token_id = $1 AND held_at_reset`, id); n != 2 {
		t.Fatalf("%d perms held at the reset, want 2", n)
	}
	if n := w.count(`SELECT count(*) FROM contract_token_removed WHERE token_id = $1 AND cause = 'reset' AND perm = 'manage'`, id); n != 1 {
		t.Fatal("the pending perm left no removed row")
	}
	// A judge of the old generation finds nothing to judge.
	w.exec(`UPDATE contract_state SET generation = $1`, old)
	if got := w.judge(); got != (store.TokenJudgeResult{}) {
		t.Fatalf("a judge across the reset judged %+v", got)
	}
	w.exec(`UPDATE contract_state SET generation = $1`, w.gen)

	// The new generation's record lists all three, given before the old
	// generation's trusted published_through: read and send come back,
	// manage stays off and is reported held.
	var trusted time.Time
	if err := w.pool.QueryRow(context.Background(), `SELECT reset_trusted_through FROM contract_token_state`).Scan(&trusted); err != nil || !trusted.Equal(w.now) {
		t.Fatalf("reset_trusted_through %v, want %v (%v)", trusted, w.now, err)
	}
	w.page(false, w.record(id, 1, grants(device, w.ownerSub, early, kc.CanRead, kc.CanSend, kc.CanManage)))
	if got := w.perms(id); got[device.String()+"/read"] != "applied" || got[device.String()+"/send"] != "applied" || len(got) != 2 {
		t.Fatalf("the new generation widened: %v", got)
	}
	h, ok := w.held()[id]
	if !ok || len(h.Removed) != 1 || h.Removed[0] != (kc.HeldPerm{Item: device.String(), Perm: kc.CanManage}) {
		t.Fatalf("held: %+v", w.held())
	}
	// A perm given after the reset applies as usual.
	w.page(false, w.record(id, 2, grants(device, w.ownerSub, early, kc.CanRead, kc.CanSend),
		grants(w.number(uuid.Nil), w.ownerSub, w.now.Add(time.Minute), kc.CanManage)))
	if got := w.perms(id); len(got) != 3 {
		t.Fatalf("a later grant: %v", got)
	}
}

// TestUnlistedTokensAreRefusedOnlyAfterTheRoundAndAFullPass: a reset's pass
// finishes only after a page with more false committed while the round ran
// in the new generation; then a token it did not list is unlisted for good,
// sticky, and a later record of it is applied for its narrowings only and
// reported held revoked (TestAnUnlistedTokenIsHeldRevoked).
func TestUnlistedTokensAreRefusedOnlyAfterTheRoundAndAFullPass(t *testing.T) {
	w := newTokenWorld(t)
	device := w.number(uuid.Nil)
	listed, unlisted := uuid.New(), uuid.New()
	w.page(false, w.record(listed, 1), w.record(unlisted, 1, grants(device, w.ownerSub, w.now, kc.CanSend)))
	w.reset()
	finish := func() store.TokenPassResult {
		t.Helper()
		res, err := w.tokens.FinishTokenPass(w.ctx(), w.gen, w.now)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	// The pass lists one token, in a page with more true: not ready.
	if res := w.page(true, w.record(listed, 1)); res.PassReady {
		t.Fatal("a page with more true readied the pass")
	}
	// A page with more false before the round ran in the new generation:
	// not ready either.
	if res := w.page(false); res.PassReady {
		t.Fatal("the pass was ready before the round")
	}
	if res := finish(); res.Done {
		t.Fatal("the pass finished before the round")
	}
	w.exec(`UPDATE contract_state SET round_generation = $1`, w.gen)
	if res := w.page(false); !res.PassReady {
		t.Fatal("a page with more false after the round did not ready the pass")
	}
	res := finish()
	if !res.Done || len(res.Unlisted) != 1 || res.Unlisted[0] != unlisted {
		t.Fatalf("the pass: %+v", res)
	}
	if s := w.token(unlisted); !s.Unlisted {
		t.Fatalf("not unlisted: %+v", s)
	}
	if exists, _, ended := w.sticky(unlisted); !exists || ended != "unlisted" {
		t.Fatal("not sticky as unlisted")
	}
	if s := w.token(listed); s.Unlisted {
		t.Fatal("a listed token was unlisted")
	}
	if n := w.count(`SELECT count(*) FROM contract_token_perms WHERE held_at_reset`); n != 0 {
		t.Fatal("held_at_reset outlived the pass")
	}
	if res := finish(); res.Done {
		t.Fatal("the pass finished twice")
	}
	// TestAnUnlistedTokenIsHeldRevoked: a later record of it.
	w.page(false, w.record(unlisted, 2, grants(device, w.ownerSub, w.now, kc.CanSend, kc.CanManage)))
	if h, ok := w.held()[unlisted]; !ok || !h.Revoked {
		t.Fatalf("an unlisted token's record is not held revoked: %+v", w.held())
	}
	if got := w.perms(unlisted); len(got) > 1 || got[device.String()+"/manage"] != "" {
		t.Fatalf("an unlisted token widened: %v", got)
	}
}

// TestEveryResetResetsTheCommandAndTokenFeeds: restartTx resets the
// command state and the token state together, whichever feed saw the
// reset first: a reset from the command feed (RestartFromCommands) sets
// the token feed from 0 with the new generation's pass, and one from the
// token feed (RestartFromTokens) sets the command feed from 0, forgets the
// wseq memory, drops the old generation's results not delivered, and
// makes every section and person document due afresh, as a reset from the
// command feed does (TestCommandReset).
func TestEveryResetResetsTheCommandAndTokenFeeds(t *testing.T) {
	ctx := context.Background()
	l := newLedgerWorld(t)
	sub := uuid.New()
	if _, err := l.pool.Exec(ctx, `INSERT INTO contract_accounts (sub) VALUES ($1)`, sub); err != nil {
		t.Fatal(err)
	}
	tokenFeed := func() (cursor int64, pass *uuid.UUID) {
		t.Helper()
		if err := l.pool.QueryRow(ctx, `SELECT feed_cursor, pass_generation FROM contract_token_state`).Scan(&cursor, &pass); err != nil {
			t.Fatal(err)
		}
		return cursor, pass
	}
	commandFeed := func() (cursor int64, memory, sections, persons int) {
		t.Helper()
		st, err := l.c.SettingsState(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := l.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM contract_command_wseq),
			(SELECT count(*) FROM contract_sections WHERE due_at <= clock_timestamp() AND tries = 0 AND parked_at IS NULL),
			(SELECT count(*) FROM contract_persons WHERE due_at <= clock_timestamp() AND tries = 0)`).Scan(&memory, &sections, &persons); err != nil {
			t.Fatal(err)
		}
		return st.FeedCursor, memory, sections, persons
	}
	settle := func() {
		t.Helper()
		if _, err := l.pool.Exec(ctx, `UPDATE contract_sections SET due_at = clock_timestamp() + interval '1 hour', tries = 3, parked_at = clock_timestamp();
			UPDATE contract_persons SET due_at = clock_timestamp() + interval '1 hour', tries = 2;
			UPDATE contract_token_state SET feed_cursor = 7, pass_generation = NULL`); err != nil {
			t.Fatal(err)
		}
	}

	// From the command feed: the token feed too.
	l.take(t, l.command(l.ws, 1))
	settle()
	next := uuid.New()
	if ok, err := l.c.RestartFromCommands(ctx, l.gen, &next); err != nil || !ok {
		t.Fatalf("RestartFromCommands: %v %v", ok, err)
	}
	if c, pass := tokenFeed(); c != 0 || pass == nil || *pass != next {
		t.Fatalf("the token feed after the command feed's reset: cursor %d, pass %v (want 0, %s)", c, pass, next)
	}
	l.gen = next

	// From the token feed: the command feed too.
	undelivered, open := l.command(l.ws, 1), l.command(l.ws, 2)
	l.take(t, undelivered, open)
	l.finish(t, undelivered.ID, store.CommandResult{Code: store.CommandKindNotAccepted})
	settle()
	if c, memory, _, _ := commandFeed(); c == 0 || memory == 0 {
		t.Fatalf("before the token feed's reset: command cursor %d, %d memory rows", c, memory)
	}
	if ok, err := l.c.RestartFromTokens(ctx, l.gen, nil, false); err != nil || !ok {
		t.Fatalf("RestartFromTokens: %v %v", ok, err)
	}
	if c, memory, sections, persons := commandFeed(); c != 0 || memory != 0 || sections != 1 || persons != 1 {
		t.Fatalf("after the token feed's reset: command cursor %d, %d memory rows, %d sections and %d persons due afresh",
			c, memory, sections, persons)
	}
	if r := l.row(t, undelivered.ID); r.Delivery != store.DeliveryDropped {
		t.Fatalf("an undelivered result of the old generation after the token feed's reset: %+v", r)
	}
	if r := l.row(t, open.ID); r.Outcome != "" || r.Delivery != "" {
		t.Fatalf("an open row after the token feed's reset: %+v", r)
	}
	if c, _ := tokenFeed(); c != 0 {
		t.Fatalf("the token feed after its own reset: cursor %d", c)
	}
}

// TestOneGenerationResetsBothFeeds: a reset seen first on the account feed
// (Restart) resets the token feed in the same transaction, and one seen
// first on the token feed (RestartFromTokens) resets the account side;
// each compare-and-sets, so a stale one changes nothing; and the token
// feed waits with no generation.
func TestOneGenerationResetsBothFeeds(t *testing.T) {
	w := newTokenWorld(t)
	id := uuid.New()
	w.page(false, w.record(id, 1))
	w.exec(`UPDATE contract_state SET feed_cursor = 9`)
	tokenCursor := func() (int64, *uuid.UUID) {
		var c int64
		var pass *uuid.UUID
		if err := w.pool.QueryRow(context.Background(), `SELECT feed_cursor, pass_generation FROM contract_token_state`).Scan(&c, &pass); err != nil {
			t.Fatal(err)
		}
		return c, pass
	}
	w.exec(`INSERT INTO contract_token_refusals_out (token_id, version, item, perm, code) VALUES ($1, 1, 'x', 'read', 'local_role')`, id)
	w.exec(`UPDATE contract_token_state SET ack_through = 1`)
	// Tokens keep working within their narrowest state until the pass: a
	// reset keeps caught_up_at, which the page with more false set.
	caughtUp := func() *time.Time {
		t.Helper()
		var at *time.Time
		if err := w.pool.QueryRow(context.Background(), `SELECT caught_up_at FROM contract_token_state`).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at
	}
	if at := caughtUp(); at == nil || !at.Equal(w.now) {
		t.Fatalf("caught_up_at %v, want %v", at, w.now)
	}
	// From the account feed.
	next := uuid.New()
	if ok, err := w.contract.Restart(w.ctx(), &w.gen, 9, &next, true); err != nil || !ok {
		t.Fatalf("Restart: %v %v", ok, err)
	}
	if c, pass := tokenCursor(); c != 0 || pass == nil || *pass != next {
		t.Fatalf("the token feed after the account's restart: cursor %d pass %v", c, pass)
	}
	if s := w.token(id); s.Version != nil {
		t.Fatal("the token kept its version")
	}
	if at := caughtUp(); at == nil || !at.Equal(w.now) {
		t.Fatalf("Restart moved caught_up_at: %v", at)
	}
	// The acknowledgement starts again with the generation: none of the old
	// one's unsent refusals, whose versions the new one never published.
	var unsent, acked int
	if err := w.pool.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM contract_token_refusals_out WHERE sent_at IS NULL),
		(SELECT ack_through FROM contract_token_state)`).Scan(&unsent, &acked); err != nil || unsent != 0 || acked != 0 {
		t.Fatalf("after the reset: %d unsent refusals, ack_through %d, %v", unsent, acked, err)
	}
	// A stale token-side restart changes nothing.
	if ok, err := w.contract.RestartFromTokens(w.ctx(), w.gen, nil, false); err != nil || ok {
		t.Fatalf("a stale RestartFromTokens: %v %v", ok, err)
	}
	w.gen = next
	w.page(false, w.record(id, 1))
	w.exec(`UPDATE contract_state SET feed_cursor = 4`)
	// From the token feed, with a signed gone: no generation then.
	w.exec(`UPDATE contract_token_state SET caught_up_at = $1`, w.now.Add(time.Minute))
	if ok, err := w.contract.RestartFromTokens(w.ctx(), w.gen, nil, false); err != nil || !ok {
		t.Fatalf("RestartFromTokens: %v %v", ok, err)
	}
	if at := caughtUp(); at == nil || !at.Equal(w.now.Add(time.Minute)) {
		t.Fatalf("RestartFromTokens moved caught_up_at: %v", at)
	}
	st, err := w.contract.State(context.Background())
	if err != nil || st.Generation != nil || st.FeedCursor != 0 {
		t.Fatalf("the account side after the token's restart: %+v %v", st, err)
	}
	if c, _ := tokenCursor(); c != 0 {
		t.Fatal("the token cursor stayed")
	}
	if _, err := w.tryPage(false, w.record(id, 2)); !errors.Is(err, store.ErrNoGeneration) {
		t.Fatalf("a token page with no generation: %v", err)
	}
	// A page of another generation is a reset; a rewound one too.
	w.exec(`UPDATE contract_state SET generation = $1`, w.gen)
	other := w.record(id, 3, func(r *kc.TokenRecord) { r.Generation = uuid.NewString() })
	if _, err := w.tryPage(false, other); !errors.Is(err, store.ErrPageGeneration) {
		t.Fatalf("a record of another generation: %v", err)
	}
	w.page(false, w.record(id, 3))
	if _, err := w.tokens.CommitTokenPage(w.ctx(), store.TokenPage{After: w.cursor(), SeenGeneration: w.gen, Now: w.now,
		Feed: kc.TokenFeed{Generation: w.gen.String(), Head: 0, NextAfter: 0, PublishedThrough: kc.T(w.now), Items: []kc.TokenFeedItem{}}}); !errors.Is(err, store.ErrFeedRewound) {
		t.Fatalf("a rewound page: %v", err)
	}
}

// TestJudgeGivesEachGrantOnce: each verdict, in the plan's order, and the
// refusal queued with the version that carried the grant; a giver who stops
// reading later takes nothing away, and a refused instance never comes back.
func TestJudgeGivesEachGrantOnce(t *testing.T) {
	w := newTokenWorld(t)
	device, unread := w.number(uuid.Nil), w.number(uuid.Nil)
	memberSub, strangerSub, waitingSub := uuid.New(), uuid.New(), uuid.New()
	w.linked("member", "member", memberSub, true)
	admin := w.linked("admin", "admin", uuid.New(), true)
	_ = admin
	w.linked("waiting", "admin", waitingSub, false)
	adminSub := uuid.New()
	adminUser := w.linked("admin2", "admin", adminSub, true)
	// adminUser reads device, never unread.
	w.reads(adminUser, device)
	gone := w.number(uuid.Nil)

	id, keyed := uuid.New(), uuid.New()
	w.page(false,
		w.record(id, 1,
			grants(device, adminSub, w.now, kc.CanRead, kc.CanSend),
			grants(unread, adminSub, w.now, kc.CanRead, kc.CanManage),
			grants(gone, w.ownerSub, w.now, kc.CanSend)),
		w.record(keyed, 1, grants(device, adminSub, w.now, kc.CanRead), func(r *kc.TokenRecord) { r.ReadingKey = readingKey(t) }))
	// Other givers, in a second version: a member, a stranger, one whose
	// document Wappie does not hold yet.
	w.page(false,
		w.record(id, 2,
			grants(device, adminSub, w.now, kc.CanRead, kc.CanSend),
			grants(unread, adminSub, w.now, kc.CanRead, kc.CanManage),
			grants(gone, w.ownerSub, w.now, kc.CanSend)),
		w.record(keyed, 2, grants(device, adminSub, w.now, kc.CanRead), func(r *kc.TokenRecord) { r.ReadingKey = readingKey(t) }))
	third := uuid.New()
	other := w.number(uuid.Nil)
	w.page(false, w.record(third, 1,
		grants(device, memberSub, w.now, kc.CanSend),
		grants(unread, strangerSub, w.now, kc.CanSend),
		grants(other, waitingSub, w.now, kc.CanSend)))
	// gone is deleted before the judge.
	w.scoped(func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `UPDATE devices SET deleted_at = clock_timestamp(), purge_after = clock_timestamp() + interval '30 days',
			paused = true WHERE id = $1`, gone)
		return err
	})
	got := w.judge()
	want := map[string]string{
		device.String() + "/read": "applied", device.String() + "/send": "applied",
		unread.String() + "/read": "refused:giver_not_reader", unread.String() + "/manage": "applied",
		gone.String() + "/send": "refused:item_unknown",
	}
	if p := w.perms(id); len(p) != len(want) {
		t.Fatalf("the perms: %v", p)
	} else {
		for k, v := range want {
			if p[k] != v {
				t.Errorf("%s: %s, want %s", k, p[k], v)
			}
		}
	}
	if p := w.perms(keyed)[device.String()+"/read"]; p != "refused:reading_key_changed" {
		t.Errorf("a changed key's Read: %s", p)
	}
	thirdWant := map[string]string{device.String() + "/send": "refused:local_role", unread.String() + "/send": "refused:local_role",
		other.String() + "/send": "waiting"}
	for k, v := range thirdWant {
		if p := w.perms(third)[k]; p != v {
			t.Errorf("third %s: %s, want %s", k, p, v)
		}
	}
	if got.Applied != 3 || got.Waiting != 1 || got.Refused != 5 {
		t.Errorf("the verdicts: %+v", got)
	}
	// The refusals name the version that carried the grant.
	if r := strings.Join(w.refused(id), " "); len(w.refused(id)) != 2 || !strings.Contains(r, gone.String()+"/send=item_unknown@1") ||
		!strings.Contains(r, unread.String()+"/read=giver_not_reader@1") {
		t.Errorf("the refusals: %v", r)
	}
	// Judged once: again, nothing changes, even once the giver stops
	// reading; and the waiting one waits for its document.
	w.scoped(func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `DELETE FROM device_key_grants WHERE user_id = $1`, adminUser)
		return err
	})
	if again := w.judge(); again != (store.TokenJudgeResult{}) {
		t.Fatalf("a second judge: %+v", again)
	}
	w.exec(`INSERT INTO contract_accounts (sub, generation, version, status, doc) VALUES ($1, $2, 1, 'active',
		jsonb_build_object('v', 1, 'workspaces', jsonb_build_array(jsonb_build_object('id', $3::text))))`, waitingSub, w.gen, w.tenant)
	if again := w.judge(); again.Applied != 1 {
		t.Fatalf("the waiting grant once its document is held: %+v", again)
	}
	// A refused instance, and an applied one dropped, each listed again,
	// never come back.
	w.page(false, w.record(id, 3, grants(device, adminSub, w.now, kc.CanRead, kc.CanSend), grants(gone, w.ownerSub, w.now, kc.CanSend)))
	w.page(false, w.record(id, 4, grants(device, adminSub, w.now, kc.CanRead, kc.CanSend), grants(unread, adminSub, w.now, kc.CanRead)))
	if p := w.perms(id); p[unread.String()+"/read"] != "" {
		t.Fatalf("a refused instance came back: %v", p)
	}
	w.page(false, w.record(id, 5, grants(device, adminSub, w.now, kc.CanRead, kc.CanSend), grants(unread, adminSub, w.now, kc.CanManage)))
	if p := w.perms(id); p[unread.String()+"/manage"] != "" || len(p) != 2 {
		t.Fatalf("a dropped instance came back: %v", p)
	}

	// The creator is judged as the giver is (steps 2 and 3): given by an
	// admin with a document, a token whose creator has a local account but
	// no document yet waits for it; one whose creator is a member here, or
	// has no local account, is local_role, told with the version that
	// carried the grant.
	creatorSub := uuid.New()
	w.linked("creator", "admin", creatorSub, false)
	createdBy := func(sub uuid.UUID) func(*kc.TokenRecord) {
		return func(r *kc.TokenRecord) { r.CreatedBy = sub.String() }
	}
	byWaiting, byMember, byStranger := uuid.New(), uuid.New(), uuid.New()
	w.page(false, w.record(byWaiting, 1, createdBy(creatorSub), grants(device, adminSub, w.now, kc.CanSend)),
		w.record(byMember, 1, createdBy(memberSub), grants(device, adminSub, w.now, kc.CanSend)),
		w.record(byStranger, 1, createdBy(strangerSub), grants(device, adminSub, w.now, kc.CanSend)))
	if got := w.judge(); got.Waiting != 1 || got.Refused != 2 || got.Applied != 0 {
		t.Fatalf("the creators' verdicts: %+v", got)
	}
	send := device.String() + "/send"
	if p := w.perms(byWaiting)[send]; p != "waiting" {
		t.Errorf("a creator with no document: %s, want waiting", p)
	}
	for name, id := range map[string]uuid.UUID{"a member": byMember, "no local account": byStranger} {
		if p := w.perms(id)[send]; p != "refused:local_role" {
			t.Errorf("a creator with %s: %s, want refused:local_role", name, p)
		}
		if r := w.refused(id); len(r) != 1 || r[0] != send+"=local_role@1" {
			t.Errorf("a creator with %s: the refusals %v", name, r)
		}
	}
	w.exec(`INSERT INTO contract_accounts (sub, generation, version, status, doc) VALUES ($1, $2, 1, 'active',
		jsonb_build_object('v', 1, 'workspaces', jsonb_build_array(jsonb_build_object('id', $3::text))))`, creatorSub, w.gen, w.tenant)
	if got := w.judge(); got.Applied != 1 || w.perms(byWaiting)[send] != "applied" {
		t.Fatalf("the creator's document came: %+v %v", got, w.perms(byWaiting))
	}
}

// ApplyTokenRecord (a by-id GET): a record of the version held stamps
// fetched_at at the request's send time; a lower one stamps nothing; a
// higher one applies; one whose fingerprint is not its key's is bad; one of
// another generation is not stored.
func TestApplyTokenRecordStampsTheGET(t *testing.T) {
	w := newTokenWorld(t)
	id := uuid.New()
	key := readingKey(t)
	w.page(false, w.record(id, 2, func(r *kc.TokenRecord) { r.ReadingKey = key }))
	fetched := func() *time.Time {
		var at *time.Time
		w.scoped(func(tx pgx.Tx) error {
			return tx.QueryRow(context.Background(), `SELECT fetched_at FROM contract_tokens WHERE id = $1`, id).Scan(&at)
		})
		return at
	}
	sent := w.now.Add(-3 * time.Second)
	if res, err := w.tokens.ApplyTokenRecord(w.ctx(), w.record(id, 2, func(r *kc.TokenRecord) { r.ReadingKey = key }), sent, w.now); err != nil || !res.Stamped {
		t.Fatalf("the same version: %+v %v", res, err)
	}
	if at := fetched(); at == nil || !at.Equal(sent) {
		t.Fatalf("fetched_at %v, want %v", at, sent)
	}
	if res, err := w.tokens.ApplyTokenRecord(w.ctx(), w.record(id, 1), w.now, w.now); err != nil || res.Stamped {
		t.Fatalf("a lower version: %+v %v", res, err)
	}
	if at := fetched(); !at.Equal(sent) {
		t.Fatal("a lower version stamped fetched_at")
	}
	if res, err := w.tokens.ApplyTokenRecord(w.ctx(), w.record(id, 3, func(r *kc.TokenRecord) { r.Name = "By GET"; r.ReadingKey = key }), w.now, w.now); err != nil || !res.Stamped {
		t.Fatalf("a higher version: %+v %v", res, err)
	}
	if s := w.token(id); *s.Version != 3 || s.Name != "By GET" {
		t.Fatalf("after the GET: %+v", s)
	}
	bad := *key
	bad.Fingerprint = "00000000000000000000000000000000"
	if res, err := w.tokens.ApplyTokenRecord(w.ctx(), w.record(id, 4, func(r *kc.TokenRecord) { r.ReadingKey = &bad }), w.now, w.now); err != nil || !res.Bad || res.Stamped {
		t.Fatalf("a fingerprint that is not its key's: %+v %v", res, err)
	}
	if s := w.token(id); *s.Version != 3 {
		t.Fatal("a bad GET was applied")
	}
	if res, err := w.tokens.ApplyTokenRecord(w.ctx(), w.record(id, 5, func(r *kc.TokenRecord) { r.Generation = uuid.NewString() }), w.now, w.now); err != nil || !res.OtherGeneration {
		t.Fatalf("another generation: %+v %v", res, err)
	}
	if s := w.token(id); *s.Version != 3 {
		t.Fatal("another generation's record was stored")
	}
}

// The operator's stop: of a selector Wappie holds no record of yet, it
// stands once the token arrives; the feed and a reset never lift it; it
// bumps the token's access_version; lifting is the operator's.
func TestTheOperatorsStopStandsOverTheFeed(t *testing.T) {
	w := newTokenWorld(t)
	id := uuid.New()
	if _, err := w.tokens.StopToken(w.ctx(), selectorOf(id), "root", "lost laptop", w.now); err != nil {
		t.Fatal(err)
	}
	w.page(false, w.record(id, 1))
	before := w.token(id).AccessVersion
	if _, err := w.tokens.StopToken(w.ctx(), selectorOf(id), "root", "again", w.now); err != nil {
		t.Fatal(err)
	}
	if after := w.token(id).AccessVersion; after != before+1 {
		t.Fatalf("access_version %d, want %d", after, before+1)
	}
	w.page(false, w.record(id, 2))
	w.reset()
	w.page(false, w.record(id, 1))
	stops, err := w.tokens.TokenStops(context.Background())
	if err != nil || len(stops) != 1 || stops[0].LiftedAt != nil || stops[0].Token == nil || *stops[0].Token != id || stops[0].Note != "again" {
		t.Fatalf("the stops: %+v %v", stops, err)
	}
	if _, lifted, err := w.tokens.LiftToken(w.ctx(), selectorOf(id), w.now); err != nil || !lifted {
		t.Fatalf("the lift: %v %v", lifted, err)
	}
	if _, lifted, err := w.tokens.LiftToken(w.ctx(), selectorOf(id), w.now); err != nil || lifted {
		t.Fatalf("a second lift: %v %v", lifted, err)
	}
	if _, err := w.tokens.StopToken(w.ctx(), "thc_0123", "root", "", w.now); !errors.Is(err, store.ErrSelector) {
		t.Fatalf("a text that is no selector: %v", err)
	}
}
