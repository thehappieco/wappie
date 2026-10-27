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
// revives it; an expired token by Wappie's clock sticks as expired.
func TestTheStickySetOutlivesTheContent(t *testing.T) {
	w := newTokenWorld(t)
	device := w.number(uuid.Nil)
	revoked, expiring := uuid.New(), uuid.New()
	w.page(false, w.record(revoked, 1, grants(device, w.ownerSub, w.now, kc.CanRead)),
		w.record(expiring, 1, func(r *kc.TokenRecord) { r.ExpiresAt = kc.T(w.now.Add(time.Hour)) }))
	w.page(false, w.record(revoked, 2, revokedBy(kc.RevokedInConsole, w.now)))

	// The janitor at expiry, on Wappie's clock.
	later := w.now.Add(2 * time.Hour)
	if got, err := w.tokens.RetainTokens(w.ctx(), later); err != nil || got.Expired != 1 {
		t.Fatalf("the janitor: %+v %v", got, err)
	}
	if exists, _, ended := w.sticky(expiring); !exists || ended != "expired" {
		t.Fatalf("an expired token is not sticky: %v %q", exists, ended)
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
	// A restored record, unrevoked and expiring later: never revived.
	w.reset()
	w.page(false, w.record(revoked, 1, grants(device, w.ownerSub, w.now, kc.CanRead), func(r *kc.TokenRecord) { r.ExpiresAt = kc.T(w.now.Add(200 * 24 * time.Hour)) }),
		w.record(expiring, 1, func(r *kc.TokenRecord) { r.ExpiresAt = kc.T(w.now.Add(200 * 24 * time.Hour)) }))
	for _, id := range []uuid.UUID{revoked, expiring} {
		if s := w.token(id); len(w.perms(id)) != 0 || (id == revoked && !s.Revoked) {
			t.Fatalf("a restored record revived %s: %+v %v", id, s, w.perms(id))
		}
	}
	if h := w.held()[revoked]; !h.Revoked {
		t.Fatalf("the restored revoked token is not held revoked: %+v", w.held())
	}
	// Past its until, retention lets it go, through the guards.
	if _, err := w.tokens.RetainTokens(w.ctx(), w.now.Add(400*24*time.Hour)); err == nil {
		// The database's clock is not 400 days on: the rows stay.
		if exists, _, _ := w.sticky(revoked); !exists {
			t.Fatal("a sticky row went before its until on the database's clock")
		}
	} else {
		t.Fatal(err)
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
	if ok, err := w.contract.RestartFromTokens(w.ctx(), w.gen, nil, false); err != nil || !ok {
		t.Fatalf("RestartFromTokens: %v %v", ok, err)
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
	w.exec(`INSERT INTO contract_accounts (sub, generation, version, status, doc) VALUES ($1, $2, 1, 'active', '{"v":1}')`, waitingSub, w.gen)
	if again := w.judge(); again.Applied != 1 {
		t.Fatalf("the waiting grant once its document is held: %+v", again)
	}
	// A refused instance listed again stays refused, and dropped and
	// listed again never comes back.
	w.page(false, w.record(id, 3, grants(device, adminSub, w.now, kc.CanRead, kc.CanSend), grants(gone, w.ownerSub, w.now, kc.CanSend)))
	w.page(false, w.record(id, 4, grants(device, adminSub, w.now, kc.CanRead, kc.CanSend), grants(unread, adminSub, w.now, kc.CanRead)))
	if p := w.perms(id); p[unread.String()+"/read"] != "" {
		t.Fatalf("a refused instance came back: %v", p)
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
	if err := w.tokens.StopToken(w.ctx(), selectorOf(id), "root", "lost laptop", w.now); err != nil {
		t.Fatal(err)
	}
	w.page(false, w.record(id, 1))
	before := w.token(id).AccessVersion
	if err := w.tokens.StopToken(w.ctx(), selectorOf(id), "root", "again", w.now); err != nil {
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
	if lifted, err := w.tokens.LiftToken(w.ctx(), selectorOf(id), w.now); err != nil || !lifted {
		t.Fatalf("the lift: %v %v", lifted, err)
	}
	if lifted, err := w.tokens.LiftToken(w.ctx(), selectorOf(id), w.now); err != nil || lifted {
		t.Fatalf("a second lift: %v %v", lifted, err)
	}
	if err := w.tokens.StopToken(w.ctx(), "thc_0123", "root", "", w.now); !errors.Is(err, store.ErrSelector) {
		t.Fatalf("a text that is no selector: %v", err)
	}
}
