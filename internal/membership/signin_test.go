package membership

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"sync"
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
	pool *pgxpool.Pool
	// backends are the pool's own sessions, told from other tests'.
	backends *pgtest.Backends
	fake     *membershiptest.Fake
	members  *Members
	contract *store.Contract
	users    *store.Users
	logs     *membershiptest.Logs
}

func newWorld(t *testing.T) *world {
	t.Helper()
	backends := &pgtest.Backends{}
	pool := pgtest.FreshWith(t, migrate.Run, backends.Configure)
	secret := membershiptest.Secret(t)
	fake := membershiptest.StartFake(t, secret)
	client := NewClient(&http.Client{}, fake.URL, nil)
	if err := client.Use(secret, ""); err != nil {
		t.Fatal(err)
	}
	logs := &membershiptest.Logs{}
	c := store.NewContract(pool)
	w := &world{pool: pool, backends: backends, fake: fake, contract: c, users: store.NewUsers(pool), logs: logs,
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
// an account for, and returns the user and the sub. The person signed up
// before the contract's first observe, as everyone the round subscribes
// when Wappie connects, with a home of Wappie's own: once the contract was
// observed, SignupPlatform takes only the platform's.
func (w *world) held(t *testing.T) (uuid.UUID, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	var mode string
	var from, paused *time.Time
	if err := w.pool.QueryRow(ctx, `SELECT mode, events_from, events_paused_at FROM contract_state`).Scan(&mode, &from, &paused); err != nil {
		t.Fatal(err)
	}
	w.exec(ctx, t, `UPDATE contract_state SET mode = 'off', events_from = NULL, events_paused_at = NULL`)
	defer w.exec(ctx, t, `UPDATE contract_state SET mode = $1, events_from = $2, events_paused_at = $3`, mode, from, paused)
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

// age moves sub's intent row back by d, on the database's clock.
func (w *world) age(ctx context.Context, t *testing.T, sub uuid.UUID, d time.Duration) {
	t.Helper()
	w.exec(ctx, t, `UPDATE contract_accounts SET subscribed_at = subscribed_at - $2::interval WHERE sub = $1`, sub, d)
}

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

	// An orphan: a refused sign-up's subscription, over 15 minutes old.
	// Under it, the sweep leaves it: its sign-up may still be under way.
	// Over it, the sweep, run every 15 minutes (P3b), unfollows it well
	// before the platform counts the workspaces its document named as
	// stale (90 minutes without a snapshot, its contract_snapshots_stale
	// alert), which Wappie never records for an orphan and never sends.
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
	w.age(ctx, t, orphan, 14*time.Minute)
	if n, err := w.members.Sweep(ctx); err != nil || n != 0 || !w.following(orphan) || w.fake.Count(contracttest.CallUnsubscribe) != 0 {
		t.Fatalf("the sweep took a subscription 14 minutes old: %d %v", n, err)
	}
	w.age(ctx, t, orphan, 2*time.Minute)
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
	// 16 minutes later, with nothing in between, it goes.
	w.age(ctx, t, orphan, 16*time.Minute)
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
	// Only this test's own notice counts: other packages' tests send it too.
	wait, cancel := context.WithTimeout(ctx, 5*time.Second)
	err = w.backends.Notice(wait, listen.Conn(), store.ContractModeChannel, "round")
	cancel()
	if err != nil {
		t.Fatalf("the leader was not woken: %v", err)
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
	spoils := []spoil{refuse("unavailable"), refuse("rate_limited"), refuse("replay"), refuse("not_found"),
		{"unverified", func(call string) {
			if err := w.fake.Corrupt("wappie", call, contracttest.AnotherSecret); err != nil {
				t.Fatal(err)
			}
		}, func(string) {}}}
	// The GET, through the freshness hook of a rare act. A GET's not_found
	// is last: it forgets the version, which the round's PUT then restores.
	for _, s := range spoils {
		if s.name == "not_found" {
			continue
		}
		at := stale()
		s.apply(contracttest.CallAccount)
		v, err := w.members.RequireFresh(ctx, "device.delete", tenant, Party{User: user, How: IfStale})
		s.lift(contracttest.CallAccount)
		if err != nil || !v.Checked || !v.Refuse || v.Actor != nil {
			t.Fatalf("GET %s: %+v %v", s.name, v, err)
		}
		unchanged("GET "+s.name, at)
	}
	if n := len(w.logs.Lines("freshness: would refuse", "act=device.delete", sub.String())); n != len(spoils)-1 {
		t.Fatalf("%d would-refuse lines, want %d", n, len(spoils)-1)
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

	// A not_found on a GET: no document, fresh_at as it was, and the
	// version is forgotten.
	at = stale()
	w.fake.RefuseAlways(contracttest.CallAccount, "not_found")
	if v, _ := w.members.RequireFresh(ctx, "grant.add", tenant, Party{User: user, How: Always}); !v.Refuse || v.Reasons[user] != "refused:not_found" {
		t.Fatalf("a not_found GET: %+v", v)
	}
	w.fake.RefuseAlways(contracttest.CallAccount, "")
	unchanged("GET not_found", at)
	if n := len(w.logs.Lines("freshness: would refuse", "act=grant.add", sub.String(), "reason=refused:not_found")); n != 1 {
		t.Fatalf("%d would-refuse lines for a not_found GET", n)
	}

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
	// Actor is the first party's document from this call's GET only: none
	// when the actor was fresh and not asked, the actor's and never a
	// recipient's when both were.
	recipient, recipientSub := w.held(t)
	if err := w.fake.SetRole(team, recipientSub.String(), "member"); err != nil {
		t.Fatal(err)
	}
	if done, err := w.members.Round(ctx); err != nil || !done {
		t.Fatalf("round: %v %v", done, err)
	}
	if _, err := w.members.RequireFresh(ctx, "device.delete", tenant, Party{User: user, How: Always}); err != nil {
		t.Fatal(err)
	}
	if v, err := w.members.RequireFresh(ctx, "grant.add", tenant, Party{User: user, How: IfStale}, Party{User: recipient, How: Always}); err != nil || v.Refuse || v.Actor != nil {
		t.Fatalf("a fresh actor and a recipient asked: %+v %v", v, err)
	}
	if v, err := w.members.RequireFresh(ctx, "device.transfer", tenant, Party{User: user, How: Always}, Party{User: recipient, How: Always}); err != nil || v.Refuse || v.Actor == nil || v.Actor.Sub != sub {
		t.Fatalf("both asked: the actor's document is not the actor's: %+v %v", v, err)
	}
	// Enforce turns the verdict into a refusal.
	w.members.Enforce = true
	w.fake.RefuseAlways(contracttest.CallAccount, "unavailable")
	if _, err := w.members.RequireFresh(ctx, "device.delete", tenant, Party{User: user, How: Always}); !errors.Is(err, ErrMembershipsUnconfirmed) {
		t.Fatalf("enforce: %v", err)
	}
	// In a mode this release does not know (the enforce release's), the
	// contract is on: the act is checked, never let through as off.
	w.members.ModeCache = time.Hour
	w.members.mu.Lock()
	w.members.state, w.members.read = store.ContractState{Mode: "enforce"}, time.Now()
	w.members.mu.Unlock()
	if v, err := w.members.RequireFresh(ctx, "device.delete", tenant, Party{User: user, How: Always}); !v.Checked || !errors.Is(err, ErrMembershipsUnconfirmed) {
		t.Fatalf("a mode past observe: %+v %v", v, err)
	}
	w.members.ModeCache, w.members.read = -1, time.Time{}
	w.fake.RefuseAlways(contracttest.CallAccount, "")
	if _, err := w.members.RequireFresh(ctx, "device.delete", tenant, Party{User: user, How: IfStale}); err != nil {
		t.Fatalf("enforce with a document: %v", err)
	}
	// A failure to read: refused with Enforce, allowed at observe (DB4).
	w.members.ModeCache = time.Hour
	if _, err := w.members.RequireFresh(ctx, "device.delete", tenant, Party{User: user, How: IfStale}); err != nil {
		t.Fatal(err)
	}
	gone, cancel := context.WithCancel(ctx)
	cancel()
	if v, err := w.members.RequireFresh(gone, "device.delete", tenant, Party{User: user, How: IfStale}); !errors.Is(err, ErrMembershipsUnconfirmed) || !v.Refuse {
		t.Fatalf("enforce, the database unread: %+v %v", v, err)
	}
	w.members.Enforce = false
	if v, err := w.members.RequireFresh(gone, "device.delete", tenant, Party{User: user, How: IfStale}); err != nil || v.Refuse {
		t.Fatalf("observe, the database unread: %+v %v", v, err)
	}
	if n := len(w.logs.Lines("freshness: could not check", "act=device.delete")); n != 2 {
		t.Fatalf("%d could-not-check lines", n)
	}
	w.members.ModeCache, w.members.read = -1, time.Time{}
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

// The calls a person waits on are bounded (the plan's 4.5 and 4.9): a PUT
// or a GET the platform does not answer in time is no answer, logged as a
// timeout, and the sign-in or the act goes on, as a refusal would. Unset,
// the bound is 5 s.
func TestCallsAreBounded(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	user, sub := w.held(t)
	team, err := w.fake.AddTeam("Bounded", sub.String())
	if err != nil {
		t.Fatal(err)
	}
	tenant := uuid.MustParse(team)
	if done, err := w.members.Round(ctx); err != nil || !done {
		t.Fatalf("round: %v %v", done, err)
	}
	// The platform answers nothing for 3 s, or until the test ends.
	release := make(chan struct{})
	defer close(release)
	hang := func(string) {
		select {
		case <-release:
		case <-time.After(3 * time.Second):
		}
	}
	w.members.Bound = 200 * time.Millisecond
	w.exec(ctx, t, `UPDATE contract_accounts SET fresh_at = clock_timestamp() - interval '2 hours' WHERE sub = $1`, sub)

	w.fake.Before(contracttest.CallSubscribe, hang)
	start := time.Now()
	w.members.SignIn(ctx, sub)
	if took := time.Since(start); took > time.Second {
		t.Fatalf("a sign-in's PUT took %v", took)
	}
	if n := len(w.logs.Lines("contract: a PUT got no document", sub.String(), "class=timeout")); n != 1 {
		t.Fatalf("%d PUT timeout lines: %s", n, w.logs.String())
	}
	if n := len(w.logs.Lines("contract: sign-in would refuse", sub.String(), "reason=stale")); n != 1 {
		t.Fatalf("%d sign-in would-refuse lines", n)
	}

	w.fake.Before(contracttest.CallAccount, hang)
	start = time.Now()
	v, err := w.members.RequireFresh(ctx, "device.delete", tenant, Party{User: user, How: IfStale})
	if took := time.Since(start); took > time.Second {
		t.Fatalf("a freshness GET took %v", took)
	}
	if err != nil || !v.Refuse || v.Reasons[user] != "unavailable" {
		t.Fatalf("a GET past its bound: %+v %v", v, err)
	}
	if n := len(w.logs.Lines("contract: a GET got no document", sub.String(), "class=timeout")); n != 1 {
		t.Fatalf("%d GET timeout lines", n)
	}
	if b := (&Members{}).bound(); b != 5*time.Second {
		t.Fatalf("the default bound is %v", b)
	}
}

// The round's PUTs and the sweep's DELETEs go at the pace, 10 a second
// unset (the plan's 4.6): a fifth of the platform's limit for all of an
// app's calls, so neither crowds out a sign-in's PUT or the feed.
func TestRoundAndSweepArePaced(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	const pace = 80 * time.Millisecond
	w.members.Pace = pace
	var mu sync.Mutex
	var at []time.Time
	stamp := func(string) {
		mu.Lock()
		defer mu.Unlock()
		at = append(at, time.Now())
	}
	// Each call reaches the fake at least the pace after the one before,
	// less the calls' own jitter.
	paced := func(what string, n int) {
		t.Helper()
		mu.Lock()
		defer mu.Unlock()
		if len(at) != n {
			t.Fatalf("%s: %d calls, want %d", what, len(at), n)
		}
		for i := 1; i < len(at); i++ {
			if gap := at[i].Sub(at[i-1]); gap < pace*3/4 {
				t.Fatalf("%s: call %d came %v after the one before, under the pace %v", what, i, gap, pace)
			}
		}
		at = nil
	}
	for range 4 {
		w.held(t)
	}
	w.fake.Before(contracttest.CallSubscribe, stamp)
	if done, err := w.members.Round(ctx); err != nil || !done {
		t.Fatalf("round: %v %v", done, err)
	}
	paced("the round", 4)
	w.fake.Before(contracttest.CallSubscribe, nil)

	for range 4 {
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
		w.age(ctx, t, orphan, OrphanAfter+time.Minute)
	}
	w.fake.Before(contracttest.CallUnsubscribe, stamp)
	if n, err := w.members.Sweep(ctx); err != nil || n != 4 {
		t.Fatalf("the sweep: %d %v", n, err)
	}
	paced("the sweep", 4)
	if p := (&Members{}).pace(); p != 100*time.Millisecond {
		t.Fatalf("the default pace is %v", p)
	}
}
