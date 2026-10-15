package membership

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/thehappieco/kit/contract/contracttest"
	"github.com/thehappieco/kit/profiles/wappie"

	"whatserver2/internal/membership/membershiptest"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
)

// The round, the sweep and freshness on a real database and the fake
// platform (the plan's 4.6, 4.9, DB8 and DB21).

type world struct {
	pool     *pgxpool.Pool
	fake     *membershiptest.Fake
	members  *Members
	contract *store.Contract
	users    *store.Users
	logs     *membershiptest.Logs
}

func newWorld(t *testing.T) *world {
	t.Helper()
	pool := pgtest.Fresh(t, migrate.Run)
	secret := membershiptest.Secret(t)
	fake := membershiptest.StartFake(t, secret)
	client := NewClient(&http.Client{}, fake.URL, nil)
	if err := client.Use(secret, ""); err != nil {
		t.Fatal(err)
	}
	logs := &membershiptest.Logs{}
	c := store.NewContract(pool)
	w := &world{pool: pool, fake: fake, contract: c, users: store.NewUsers(pool), logs: logs,
		members: &Members{Client: client, Contract: c, Log: logs.Logger(), ModeCache: -1, Pace: time.Millisecond}}
	if _, err := pool.Exec(context.Background(), `UPDATE contract_state SET mode = 'observe', events_from = clock_timestamp()`); err != nil {
		t.Fatal(err)
	}
	return w
}

func random(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// held makes a person Wappie holds, linked to a sub the fake platform has
// an account for, and returns the user and the sub.
func (w *world) held(t *testing.T) (uuid.UUID, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	sub := uuid.New()
	if _, err := w.fake.AddAccount(sub.String()); err != nil {
		t.Fatal(err)
	}
	key := random(t, 32)
	if _, _, err := store.NewPlatformPins(w.pool).InsertPin(ctx, sub.String(), "wappie:1", key); err != nil {
		t.Fatal(err)
	}
	ticket, err := w.users.CreatePlatformTicket(ctx, store.PlatformTicket{Kind: store.TicketNew, Sub: sub, ProductKeyID: "wappie:1", ProductKey: key,
		Email: sub.String()[:8] + "@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	wrap := random(t, wappie.PlatformWrapLen)
	wrap[0] = wappie.PlatformWrapHeader
	user, _, err := w.users.SignupPlatform(ctx, store.NewPlatformUser{Ticket: ticket, PublicKey: random(t, 32), Wrap: wrap})
	if err != nil {
		t.Fatal(err)
	}
	return user.ID, sub
}

// row is sub's contract_accounts row: its version and fresh_at, as the
// database holds them.
func (w *world) row(ctx context.Context, t *testing.T, sub uuid.UUID) (exists bool, version *int64, freshAt *time.Time) {
	t.Helper()
	err := w.pool.QueryRow(ctx, `SELECT version, fresh_at FROM contract_accounts WHERE sub = $1`, sub).Scan(&version, &freshAt)
	if err != nil {
		return false, nil, nil
	}
	return true, version, freshAt
}

func (w *world) exec(ctx context.Context, t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := w.pool.Exec(ctx, sql, args...); err != nil {
		t.Fatal(err)
	}
}

func (w *world) following(sub uuid.UUID) bool { return w.fake.Following("wappie", sub.String()) }

// The round subscribes everyone Wappie holds, and only them: a sub whose
// PUT fails (a not_found, which never means closed) is tried again by the
// next pass, after the others, and the round is done, recorded for the
// stored generation, once nobody is left.
func TestRoundSubscribesEveryone(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	var subs []uuid.UUID
	for range 3 {
		_, sub := w.held(t)
		subs = append(subs, sub)
	}
	// An unheld subscription is not the round's.
	stray := uuid.New()
	if _, err := w.contract.Intend(ctx, stray); err != nil {
		t.Fatal(err)
	}
	// The platform answers not_found for the first one.
	if err := w.fake.Refuse("wappie", contracttest.CallSubscribe, "not_found"); err != nil {
		t.Fatal(err)
	}
	done, err := w.members.Round(ctx)
	if err != nil || done {
		t.Fatalf("a pass with a not_found: done %v, %v", done, err)
	}
	followed := 0
	for _, sub := range subs {
		if w.following(sub) {
			followed++
		}
	}
	if followed != 2 || w.following(stray) {
		t.Fatalf("%d of 3 followed after one refusal (stray %v)", followed, w.following(stray))
	}
	var round *uuid.UUID
	if err := w.pool.QueryRow(ctx, `SELECT round_generation FROM contract_state`).Scan(&round); err != nil || round != nil {
		t.Fatalf("the round recorded as done: %v %v", round, err)
	}
	done, err = w.members.Round(ctx)
	if err != nil || !done {
		t.Fatalf("the second pass: done %v, %v", done, err)
	}
	gen, _ := w.fake.Generation()
	if err := w.pool.QueryRow(ctx, `SELECT round_generation FROM contract_state`).Scan(&round); err != nil || round == nil || round.String() != gen {
		t.Fatalf("round_generation %v, want %s (%v)", round, gen, err)
	}
	for _, sub := range subs {
		if exists, version, fresh := w.row(ctx, t, sub); !exists || version == nil || fresh == nil || !w.following(sub) {
			t.Fatalf("%s: not subscribed with a fresh document", sub)
		}
	}
	if exists, version, _ := w.row(ctx, t, stray); !exists || version != nil {
		t.Fatal("the round touched an unheld sub's row")
	}
	// Nothing left: a pass sends nothing.
	before := w.fake.Count(contracttest.CallSubscribe)
	if done, err := w.members.Round(ctx); err != nil || !done || w.fake.Count(contracttest.CallSubscribe) != before {
		t.Fatalf("an idle pass: %v %v", done, err)
	}
	// With no transport, nothing is tried.
	w.members.Client = nil
	if _, err := w.members.Round(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a round with no transport: %v", err)
	}
}

// TB19, the sweep's and the GET's part: a sign-in's PUT between the sweep's
// read and its DELETE makes the sweep subscribe the sub again; a signed
// not_found on a GET for a held sub forgets its version, wakes the leader,
// and the round PUTs it again.
func TestUnsubscribeRaces(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()

	// An orphan: a refused sign-up's subscription, over an hour old.
	orphan := uuid.New()
	if _, err := w.fake.AddAccount(orphan.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := w.contract.Intend(ctx, orphan); err != nil {
		t.Fatal(err)
	}
	if _, err := w.members.Client.Subscribe(ctx, orphan.String()); err != nil {
		t.Fatal(err)
	}
	w.exec(ctx, t, `UPDATE contract_accounts SET subscribed_at = subscribed_at - interval '61 minutes' WHERE sub = $1`, orphan)
	// A sign-up's intent lands between the sweep's read and its DELETE.
	w.fake.Before(contracttest.CallUnsubscribe, func(string) {
		if _, err := w.contract.Intend(ctx, orphan); err != nil {
			t.Error(err)
		}
	})
	if n, err := w.members.Sweep(ctx); err != nil || n != 0 {
		t.Fatalf("the sweep removed %d rows: %v", n, err)
	}
	w.fake.Before(contracttest.CallUnsubscribe, nil)
	if exists, _, _ := w.row(ctx, t, orphan); !exists || !w.following(orphan) {
		t.Fatalf("the sweep left the newer intent unsubscribed (row %v, following %v)", exists, w.following(orphan))
	}
	if n := w.fake.Count(contracttest.CallSubscribe); n != 2 {
		t.Fatalf("%d PUTs: the sweep did not subscribe again", n)
	}
	// An hour later, with nothing in between, it goes.
	w.exec(ctx, t, `UPDATE contract_accounts SET subscribed_at = subscribed_at - interval '61 minutes' WHERE sub = $1`, orphan)
	if n, err := w.members.Sweep(ctx); err != nil || n != 1 || w.following(orphan) {
		t.Fatalf("the sweep: %d %v", n, err)
	}
	if exists, _, _ := w.row(ctx, t, orphan); exists {
		t.Fatal("the sweep left the row")
	}

	// A held sub the platform no longer follows.
	_, sub := w.held(t)
	if done, err := w.members.Round(ctx); err != nil || !done {
		t.Fatalf("round: %v %v", done, err)
	}
	listen, err := w.pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Release()
	if _, err := listen.Exec(ctx, `LISTEN `+store.ContractModeChannel); err != nil {
		t.Fatal(err)
	}
	w.exec(ctx, t, `UPDATE contract_accounts SET fresh_at = clock_timestamp() - interval '2 hours' WHERE sub = $1`, sub)
	if err := w.fake.Refuse("wappie", contracttest.CallAccount, "not_found"); err != nil {
		t.Fatal(err)
	}
	w.members.Refresh(ctx, sub)
	if _, version, _ := w.row(ctx, t, sub); version != nil {
		t.Fatal("a not_found on a GET kept the version")
	}
	wait, cancel := context.WithTimeout(ctx, 5*time.Second)
	n, err := listen.Conn().WaitForNotification(wait)
	cancel()
	if err != nil || n.Payload != "round" {
		t.Fatalf("the leader was not woken: %v %v", n, err)
	}
	before := w.fake.Count(contracttest.CallSubscribe)
	if done, err := w.members.Round(ctx); err != nil || !done || w.fake.Count(contracttest.CallSubscribe) != before+1 {
		t.Fatalf("the round after a not_found: %v %v", done, err)
	}
	if _, version, _ := w.row(ctx, t, sub); version == nil || !w.following(sub) {
		t.Fatal("the round did not subscribe the sub again")
	}
}

// TB49: only a validated document makes a sub fresh. A signed 503, a
// rate_limited, a replay, a not_found and an unverified answer, on a GET or
// a PUT, each leave fresh_at as it was and give "would refuse"; a GET that
// returns the version Wappie holds refreshes it; and after a restore, with
// the round's PUTs refused, a sub is not fresh although an empty page said
// published_through now (DB8).
func TestFreshnessIsADocument(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	user, sub := w.held(t)
	team, err := w.fake.AddTeam("TBFG", sub.String())
	if err != nil {
		t.Fatal(err)
	}
	tenant := uuid.MustParse(team)
	if done, err := w.members.Round(ctx); err != nil || !done {
		t.Fatalf("round: %v %v", done, err)
	}
	if rec, ok, err := w.contract.Workspace(ctx, tenant); err != nil || !ok || rec.Kind != "team" {
		t.Fatalf("the team is not recorded: %+v %v %v", rec, ok, err)
	}
	stale := func() time.Time {
		t.Helper()
		w.exec(ctx, t, `UPDATE contract_accounts SET fresh_at = clock_timestamp() - interval '2 hours' WHERE sub = $1`, sub)
		_, _, at := w.row(ctx, t, sub)
		return *at
	}
	unchanged := func(name string, want time.Time) {
		t.Helper()
		if _, _, at := w.row(ctx, t, sub); at == nil || !at.Equal(want) {
			t.Fatalf("%s: fresh_at moved from %v to %v", name, want, at)
		}
		if fresh, err := w.members.Fresh(ctx, sub); err != nil || fresh[sub] {
			t.Fatalf("%s: the sub is fresh (%v)", name, err)
		}
	}
	type spoil struct {
		name  string
		apply func(call string)
		lift  func(call string)
	}
	refuse := func(code string) spoil {
		return spoil{code, func(call string) { w.fake.RefuseAlways(call, code) }, func(call string) { w.fake.RefuseAlways(call, "") }}
	}
	spoils := []spoil{refuse("unavailable"), refuse("rate_limited"), refuse("replay"),
		{"unverified", func(call string) {
			if err := w.fake.Corrupt("wappie", call, contracttest.AnotherSecret); err != nil {
				t.Fatal(err)
			}
		}, func(string) {}}}
	// The GET, through the freshness hook of a rare act.
	for _, s := range spoils {
		at := stale()
		s.apply(contracttest.CallAccount)
		v, err := w.members.RequireFresh(ctx, "device.delete", tenant, Party{User: user, How: IfStale})
		s.lift(contracttest.CallAccount)
		if err != nil || !v.Checked || !v.Refuse || v.Actor != nil {
			t.Fatalf("GET %s: %+v %v", s.name, v, err)
		}
		unchanged("GET "+s.name, at)
	}
	if n := len(w.logs.Lines("freshness: would refuse", "act=device.delete", sub.String())); n != len(spoils) {
		t.Fatalf("%d would-refuse lines, want %d", n, len(spoils))
	}
	// The PUT, through a sign-in and the round.
	for _, s := range spoils {
		at := stale()
		s.apply(contracttest.CallSubscribe)
		w.members.SignIn(ctx, sub)
		s.lift(contracttest.CallSubscribe)
		unchanged("PUT "+s.name, at)
	}
	if n := len(w.logs.Lines("contract: sign-in would refuse", sub.String(), "reason=stale")); n != len(spoils) {
		t.Fatalf("%d sign-in would-refuse lines, want %d", n, len(spoils))
	}

	// The version Wappie holds already, answered again: fresh.
	_, held, _ := w.row(ctx, t, sub)
	at := stale()
	v, err := w.members.RequireFresh(ctx, "device.transfer", tenant, Party{User: user, How: Always})
	if err != nil || v.Refuse || v.Actor == nil || v.Actor.Sub != sub || v.Actor.Version != *held {
		t.Fatalf("a GET of the held version: %+v %v", v, err)
	}
	if _, version, fresh := w.row(ctx, t, sub); fresh == nil || !fresh.After(at) || *version != *held {
		t.Fatalf("the held version's answer did not refresh: %v %v", fresh, version)
	}
	// Fresh now: IfStale sends no GET.
	gets := w.fake.Count(contracttest.CallAccount)
	if v, err := w.members.RequireFresh(ctx, "device.delete", tenant, Party{User: user, How: IfStale}); err != nil || v.Refuse || w.fake.Count(contracttest.CallAccount) != gets {
		t.Fatalf("a fresh sub's IfStale: %+v %v", v, err)
	}

	// A not_found on a GET: no document, and the version is forgotten.
	stale()
	w.fake.RefuseAlways(contracttest.CallAccount, "not_found")
	if v, _ := w.members.RequireFresh(ctx, "grant.add", tenant, Party{User: user, How: Always}); !v.Refuse || v.Reasons[user] != "refused:not_found" {
		t.Fatalf("a not_found GET: %+v", v)
	}
	w.fake.RefuseAlways(contracttest.CallAccount, "")

	// A restore: the restart forgot every version and fresh_at (P3b's
	// restart, played here in SQL), and an empty page of the new
	// generation said published_through now.
	gen := w.fake.Restore()
	w.exec(ctx, t, `UPDATE contract_state SET generation = $1, generation_confirmed = false, feed_cursor = 0, published_through = clock_timestamp(), round_generation = NULL`, gen)
	w.exec(ctx, t, `UPDATE contract_accounts SET generation = NULL, version = NULL, fresh_at = NULL`)
	w.fake.RefuseAlways(contracttest.CallSubscribe, "unavailable")
	if done, err := w.members.Round(ctx); err != nil || done {
		t.Fatalf("a round refused: %v %v", done, err)
	}
	if fresh, err := w.members.Fresh(ctx, sub); err != nil || fresh[sub] {
		t.Fatal("published_through made an unfollowed sub fresh")
	}
	if v, _ := w.members.RequireFresh(ctx, "message.send", tenant, Party{User: user, How: Stored}); !v.Refuse || v.Reasons[user] != "stale" {
		t.Fatalf("a Stored check after the restore: %+v", v)
	}
	w.fake.RefuseAlways(contracttest.CallSubscribe, "")
	if done, err := w.members.Round(ctx); err != nil || !done {
		t.Fatalf("the round: %v %v", done, err)
	}
	if fresh, err := w.members.Fresh(ctx, sub); err != nil || !fresh[sub] {
		t.Fatal("the round's PUT did not make the sub fresh")
	}
}

// RequireFresh gates only at observe, only in a recorded team; a party
// with no sub would be refused; Stored makes no call; only Enforce refuses.
func TestRequireFresh(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	user, sub := w.held(t)
	team, err := w.fake.AddTeam("Piloto", sub.String())
	if err != nil {
		t.Fatal(err)
	}
	tenant := uuid.MustParse(team)
	if done, err := w.members.Round(ctx); err != nil || !done {
		t.Fatalf("round: %v %v", done, err)
	}
	personal, err := uuid.Parse(mustPersonal(t, w, sub))
	if err != nil {
		t.Fatal(err)
	}
	calls := func() int { return w.fake.Count(contracttest.CallAccount) }

	for _, ws := range []uuid.UUID{personal, uuid.New()} {
		if v, err := w.members.RequireFresh(ctx, "device.delete", ws, Party{User: uuid.New(), How: Always}); err != nil || v.Checked || v.Refuse {
			t.Fatalf("a workspace that is not a recorded team: %+v %v", v, err)
		}
	}
	// A person with no sub in a platform team.
	stranger := uuid.New()
	v, err := w.members.RequireFresh(ctx, "grant.add", tenant, Party{User: user, How: IfStale}, Party{User: stranger, How: Always})
	if err != nil || !v.Refuse || v.Reasons[stranger] != "no_sub" || v.Reasons[user] != "" {
		t.Fatalf("a recipient with no sub: %+v %v", v, err)
	}
	// Stored: no call, and a stale sub is logged at the act.
	w.exec(ctx, t, `UPDATE contract_accounts SET fresh_at = clock_timestamp() - interval '2 hours' WHERE sub = $1`, sub)
	before := calls()
	if v, _ := w.members.RequireFresh(ctx, "message.send", tenant, Party{User: user, How: Stored}); !v.Refuse || calls() != before {
		t.Fatalf("Stored: %+v, %d calls", v, calls()-before)
	}
	if n := len(w.logs.Lines("freshness: stale at act", "act=message.send", sub.String())); n != 1 {
		t.Fatalf("%d stale-at-act lines", n)
	}
	// Enforce turns the verdict into a refusal.
	w.members.Enforce = true
	w.fake.RefuseAlways(contracttest.CallAccount, "unavailable")
	if _, err := w.members.RequireFresh(ctx, "device.delete", tenant, Party{User: user, How: IfStale}); !errors.Is(err, ErrMembershipsUnconfirmed) {
		t.Fatalf("enforce: %v", err)
	}
	w.fake.RefuseAlways(contracttest.CallAccount, "")
	if _, err := w.members.RequireFresh(ctx, "device.delete", tenant, Party{User: user, How: IfStale}); err != nil {
		t.Fatalf("enforce with a document: %v", err)
	}
	w.members.Enforce = false
	// Off after an observe: nothing is checked, and nothing is asked.
	w.exec(ctx, t, `UPDATE contract_state SET mode = 'off', events_paused_at = clock_timestamp()`)
	w.exec(ctx, t, `UPDATE contract_accounts SET fresh_at = clock_timestamp() - interval '2 hours' WHERE sub = $1`, sub)
	before = calls()
	if v, err := w.members.RequireFresh(ctx, "device.transfer", tenant, Party{User: user, How: Always}); err != nil || v.Checked || calls() != before {
		t.Fatalf("off: %+v %v", v, err)
	}
	w.members.Refresh(ctx, sub)
	if calls() != before {
		t.Fatal("a step-up's refresh asked with the contract off")
	}
}

// mustPersonal is sub's personal workspace on the fake, from its stored
// document.
func mustPersonal(t *testing.T, w *world, sub uuid.UUID) string {
	t.Helper()
	var id string
	if err := w.pool.QueryRow(context.Background(), `SELECT doc->'workspaces'->0->>'id' FROM contract_accounts WHERE sub = $1`, sub).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}
