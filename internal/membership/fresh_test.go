package membership

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kc "github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/contract/contracttest"

	"whatserver2/internal/pg"
	"whatserver2/internal/store"
)

// Test 45's membership part (the plan's 4.9 and 4.12): what the hook asks
// of the platform and logs at each kind of site, on a real database and
// the fake platform. The sites themselves are wsapi's, authapi's and
// mcpauth's TestFreshnessHook.

// staleBy moves sub's freshness back by d, on the database's clock, with
// published_through no younger.
func (w *world) staleBy(ctx context.Context, t *testing.T, sub uuid.UUID, d string) {
	t.Helper()
	w.exec(ctx, t, `UPDATE contract_accounts SET fresh_at = clock_timestamp() - $2::interval WHERE sub = $1`, sub, d)
	w.exec(ctx, t, `UPDATE contract_state SET published_through = least(published_through, clock_timestamp() - $1::interval)`, d)
}

// askedSubs counts the GETs the fake platform got, by sub.
type askedSubs struct {
	mu sync.Mutex
	n  map[string]int
}

func (a *askedSubs) of(sub uuid.UUID) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.n[sub.String()]
}

// asked counts the GETs from now on.
func (w *world) asked() *askedSubs {
	a := &askedSubs{n: map[string]int{}}
	w.fake.Before(contracttest.CallAccount, func(sub string) {
		a.mu.Lock()
		a.n[sub]++
		a.mu.Unlock()
	})
	return a
}

// holder makes user a member of the team with Read and the key to device.
func (w *eventWorld) holder(t *testing.T, device, user uuid.UUID) {
	t.Helper()
	w.localTeam(t, w.team, "", member{user, "member", "active"})
	if err := pg.InTenantTx(context.Background(), w.pool, w.team.String(), func(tx pgx.Tx) error {
		return readsTx(context.Background(), tx, w.team, device, user)
	}); err != nil {
		t.Fatal(err)
	}
}

// In a personal workspace an act never waits (the reply's Q5), and the
// acts README 7.1 lists for a team's items (deleting, recovering, stopping,
// linking or sending from a number) are not gated there at all. An act
// that widens access is: only the actor's own stored status counts, with
// no call, however stale; a document that says disabled is a would-refuse
// there, as in a team, and with the enforce flag a refusal. No sub, or no
// stored document, is nothing to check (fail-static).
func TestFreshnessPersonalWorkspace(t *testing.T) {
	w := newEventWorld(t)
	ctx := context.Background()
	calls := func() int { return w.fake.Count(contracttest.CallAccount) }
	before := calls()
	v, err := w.members.RequireWidening(ctx, "apikeys.create", w.home, Party{User: w.owner, How: Always})
	if err != nil || !v.Checked || v.Refuse || calls() != before {
		t.Fatalf("an active owner at home: %+v %v, %d calls", v, err, calls()-before)
	}
	w.staleBy(ctx, t, w.sub, "2 hours")
	if v, err := w.members.RequireWidening(ctx, "apikeys.create", w.home, Party{User: w.owner, How: IfStale}); err != nil || v.Refuse || calls() != before {
		t.Fatalf("a stale owner at home waited: %+v %v, %d calls", v, err, calls()-before)
	}
	// The platform disables the account; the document reaches Wappie.
	if err := w.fake.Disable(w.sub.String(), dbNow(t, w.pool, "-1 minute")); err != nil {
		t.Fatal(err)
	}
	w.members.SignIn(ctx, w.sub)
	before = calls()
	v, err = w.members.RequireWidening(ctx, "apikeys.create", w.home, Party{User: w.owner, How: Always})
	if err != nil || !v.Refuse || v.Reasons[w.owner] != "account_disabled" || calls() != before {
		t.Fatalf("a disabled owner at home: %+v %v, %d calls", v, err, calls()-before)
	}
	if n := len(w.logs.Lines("freshness: would refuse", "act=apikeys.create", "reason=account_disabled", w.home.String())); n != 1 {
		t.Fatalf("%d would-refuse lines:\n%s", n, w.logs.String())
	}
	// A team number's acts at home: not gated, even for a disabled person.
	teamActs := []string{"device.delete", "device.recover", "device.stop", "pair", "message.send", "group.create"}
	for _, act := range teamActs {
		if v, err := w.members.RequireFresh(ctx, act, w.home, Party{User: w.owner, How: IfStale}); err != nil || v.Checked || v.Refuse || calls() != before {
			t.Fatalf("%s at home: %+v %v", act, v, err)
		}
	}
	if v, err := w.members.RequireMover(ctx, w.home, w.owner); err != nil || v.Checked || v.Mover != "" || calls() != before {
		t.Fatalf("a move at home: %+v %v", v, err)
	}
	if n := len(w.logs.Lines("would refuse", w.home.String())); n != 1 {
		t.Fatalf("%d would-refuse lines at home:\n%s", n, w.logs.String())
	}
	// In the team, the fresh document's status is a refusal too, still
	// with no call.
	if v, err := w.members.RequireFresh(ctx, "device.stop", w.team, Party{User: w.owner, How: IfStale}); err != nil || v.Reasons[w.owner] != "account_disabled" || calls() != before {
		t.Fatalf("a disabled owner in the team: %+v %v", v, err)
	}
	if v, err := w.members.RequireFresh(ctx, "message.send", w.team, Party{User: w.owner, How: Stored}); err != nil || v.Reasons[w.owner] != "account_disabled" || calls() != before {
		t.Fatalf("a disabled sender in the team: %+v %v", v, err)
	}
	// And a GET's document that says disabled.
	if v, err := w.members.RequireFresh(ctx, "device.transfer", w.team, Party{User: w.owner, How: Always}); err != nil || v.Reasons[w.owner] != "account_disabled" || calls() != before+1 {
		t.Fatalf("a disabled document from a GET: %+v %v", v, err)
	}
	before = calls()
	w.members.Enforce = true
	if _, err := w.members.RequireWidening(ctx, "apikeys.create", w.home, Party{User: w.owner, How: IfStale}); !errors.Is(err, ErrMembershipsUnconfirmed) || calls() != before {
		t.Fatalf("enforce at home: %v, %d calls", err, calls()-before)
	}
	for _, act := range teamActs {
		if v, err := w.members.RequireFresh(ctx, act, w.home, Party{User: w.owner, How: IfStale}); err != nil || v.Checked {
			t.Fatalf("enforce, %s at home: %+v %v", act, v, err)
		}
	}
	// Fail-static at home, even with the enforce flag: a person linked to a
	// sub Wappie has no document for, and one with no link.
	linked, unlinked := w.localPerson(t), w.localPerson(t)
	w.exec(ctx, t, `INSERT INTO platform_identities (sub, user_id, email, linked_from) VALUES ($1, $2, $3, 'legacy')`,
		uuid.New(), linked, linked.String()[:8]+"@id.test")
	for name, u := range map[string]uuid.UUID{"no document": linked, "no sub": unlinked} {
		if v, err := w.members.RequireWidening(ctx, "apikeys.create", w.home, Party{User: u, How: IfStale}); err != nil || v.Checked || v.Refuse || calls() != before {
			t.Fatalf("%s at home: %+v %v", name, v, err)
		}
	}
	w.members.Enforce = false
	// A person with no sub, at a home that is no platform workspace: nothing.
	stranger := w.localPerson(t)
	if v, err := w.members.RequireWidening(ctx, "apikeys.create", uuid.New(), Party{User: stranger, How: Always}); err != nil || v.Checked {
		t.Fatalf("an unrecorded workspace: %+v %v", v, err)
	}
}

// Only the workspace's persons are an act's parties (Contract.Persons): a
// service identity has no sub and is never a platform member (design 2.7),
// so a grant to a standing service account, a consent's provisional one or
// a connection's waits only on the person; someone of another workspace,
// whom the act's own store refuses, is neither asked for nor logged under
// this workspace's act. A person of the team with no sub stays a
// would-refuse.
func TestFreshnessParties(t *testing.T) {
	w := newEventWorld(t)
	ctx := context.Background()
	standing, provisional := uuid.New(), uuid.New()
	if err := pg.InTenantTx(ctx, w.pool, w.team.String(), func(tx pgx.Tx) error {
		for _, id := range []uuid.UUID{standing, provisional} {
			if _, err := tx.Exec(ctx, `INSERT INTO users (id, tenant_id, email, public_key, role) VALUES ($1, $2, $3, $4, 'service')`,
				id, w.team, id.String()[:8]+"@service.test", random(t, 32)); err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx, `UPDATE workspace_memberships SET expires_at = clock_timestamp() + interval '30 minutes'
			WHERE tenant_id = $1 AND user_id = $2`, w.team, provisional)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// A membership with a deadline is a consent's, whatever its role; a
	// connection's account, a member by its membership.
	deadline, connection := w.localPerson(t), w.localPerson(t)
	w.localTeam(t, w.team, "", member{deadline, "member", "active"}, member{connection, "member", "active"})
	if err := pg.InTenantTx(ctx, w.pool, w.team.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE workspace_memberships SET expires_at = clock_timestamp() + interval '30 minutes'
			WHERE tenant_id = $1 AND user_id = $2`, w.team, deadline)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var apiKey uuid.UUID
	if err := w.pool.QueryRow(ctx, `INSERT INTO api_keys (tenant_id, prefix, key_hash, created_by) VALUES ($1, $2, 'x', $3) RETURNING id`,
		w.team, uuid.NewString()[:8], w.owner).Scan(&apiKey); err != nil {
		t.Fatal(err)
	}
	if err := pg.InTenantTx(ctx, w.pool, w.team.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO mcp_connections (tenant_id, request_id, api_key_id, created_by, client_name, redirect_host, device_count,
			reader_kid, status, expires_at, kind, service_user_id, key_mode, consent_version, reader)
			VALUES ($1, 'req-parties', $2, $3, 'Claude', 'claude.ai', 1, 'kid', 'active', clock_timestamp() + interval '1 day',
			'content', $4, 'ephemeral', 1, 'enclave')`, w.team, apiKey, w.owner, connection)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	before := w.fake.Count(contracttest.CallAccount)
	v, err := w.members.RequireWidening(ctx, "grant.add", w.team, Party{User: w.owner, How: IfStale},
		Party{User: standing, How: Always}, Party{User: provisional, How: Always}, Party{User: deadline, How: Always}, Party{User: connection, How: Always})
	if err != nil || !v.Checked || v.Refuse || len(v.Reasons) != 0 || w.fake.Count(contracttest.CallAccount) != before {
		t.Fatalf("services were parties: %+v %v", v, err)
	}
	// Someone of another workspace, held and linked: a pairing's grant
	// naming them asks nothing and logs nothing.
	outsider, outsiderSub, _ := w.heldAtHome(t)
	asked := w.asked()
	before = w.fake.Count(contracttest.CallAccount)
	v, err = w.members.RequireFresh(ctx, "pair", w.team, Party{User: w.owner, How: IfStale}, Party{User: outsider, How: Always})
	if err != nil || !v.Checked || v.Refuse || len(v.Reasons) != 0 || w.fake.Count(contracttest.CallAccount) != before || asked.of(outsiderSub) != 0 {
		t.Fatalf("an outsider was a party: %+v %v, %d calls", v, err, w.fake.Count(contracttest.CallAccount)-before)
	}
	if lines := w.logs.Lines("freshness:", outsider.String()); len(lines) != 0 {
		t.Fatalf("an outsider logged under the team's act: %v", lines)
	}
	// A person of the team with no sub stays a would-refuse.
	local := w.localPerson(t)
	w.localTeam(t, w.team, "", member{local, "member", "active"})
	if v, err := w.members.RequireWidening(ctx, "grant.add", w.team, Party{User: w.owner, How: IfStale}, Party{User: local, How: Always}); err != nil || v.Reasons[local] != "no_sub" {
		t.Fatalf("a person with no sub: %+v %v", v, err)
	}
}

// An act's GETs run at once, within one call's bound (the plan's 4.9): a
// pairing that hands the key to several people waits one bound on a
// platform that never answers, not one per party.
func TestFreshnessAtOnce(t *testing.T) {
	w := newEventWorld(t)
	ctx := context.Background()
	parties := []Party{{User: w.owner, How: IfStale}, {User: w.second, How: Always}}
	for range 7 {
		user, _, _ := w.heldAtHome(t)
		w.localTeam(t, w.team, "", member{user, "member", "active"})
		parties = append(parties, Party{User: user, How: Always})
	}
	w.staleBy(ctx, t, w.sub, "2 hours")
	release := make(chan struct{})
	defer close(release)
	w.fake.Before(contracttest.CallAccount, func(string) {
		select {
		case <-release:
		case <-time.After(5 * time.Second):
		}
	})
	w.members.Bound = 500 * time.Millisecond
	start := time.Now()
	v, err := w.members.RequireFresh(ctx, "pair", w.team, parties...)
	// Three rounds of four calls, one bound each, would take 1.5 s; nine
	// in a row, 4.5 s.
	if took := time.Since(start); err != nil || !v.Refuse || len(v.Reasons) != len(parties) || took > time.Second {
		t.Fatalf("hung: %+v %v after %s", v.Reasons, err, took)
	}
	for _, p := range parties {
		if v.Reasons[p.User] != "unavailable" {
			t.Fatalf("%s: %q", p.User, v.Reasons[p.User])
		}
	}
}

// The hook's GETs keep within their budget (budget.go): one act past its
// workspace's burst gets no answer for the rest, throttled, and the
// platform never sees them.
func TestFreshnessBudget(t *testing.T) {
	w := newEventWorld(t)
	ctx := context.Background()
	w.members.calls = &callBudget{perSecond: 100, burst: 100, tenantPerSecond: 0.001, tenantBurst: 2,
		tenants: map[uuid.UUID]*bucket{}, now: time.Now}
	parties := []Party{{User: w.owner, How: Always}, {User: w.second, How: Always}}
	for range 2 {
		user, _, _ := w.heldAtHome(t)
		w.localTeam(t, w.team, "", member{user, "member", "active"})
		parties = append(parties, Party{User: user, How: Always})
	}
	before := w.fake.Count(contracttest.CallAccount)
	v, err := w.members.RequireFresh(ctx, "pair", w.team, parties...)
	throttled := 0
	for _, reason := range v.Reasons {
		if reason == "throttled" {
			throttled++
		}
	}
	if err != nil || !v.Refuse || throttled != 2 || len(v.Reasons) != 2 || w.fake.Count(contracttest.CallAccount) != before+2 {
		t.Fatalf("over the budget: %+v %v, %d calls", v.Reasons, err, w.fake.Count(contracttest.CallAccount)-before)
	}
	if n := len(w.logs.Lines("freshness: would refuse", "act=pair", "reason=throttled")); n != 2 {
		t.Fatalf("%d throttled would-refuse lines:\n%s", n, w.logs.String())
	}
}

// The budget itself, on a clock of its own: a workspace's burst passes at
// once, its next GET waits for its token within the bound and is throttled
// past it, with nothing spent; another workspace has its own bucket, within
// the process's; a workspace quiet long enough is forgotten.
func TestFreshnessBudgetBuckets(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	c := newCallBudget()
	c.now = func() time.Time { return now }
	team, other := uuid.New(), uuid.New()
	for i := range tenantBurst {
		if err := c.take(ctx, now, team); err != nil {
			t.Fatalf("take %d of the burst: %v", i, err)
		}
	}
	// The next token comes in a fifth of a second: past a sooner deadline,
	// throttled, and nothing spent.
	if err := c.take(ctx, now.Add(100*time.Millisecond), team); !errors.Is(err, errThrottled) {
		t.Fatalf("past the burst: %v", err)
	}
	// The process's bucket is empty too: another workspace waits for it.
	if err := c.take(ctx, now, other); !errors.Is(err, errThrottled) {
		t.Fatalf("the process's bucket: %v", err)
	}
	// A second on: the process has 10 more, the team 5 of them.
	now = now.Add(time.Second)
	for i := range tenantPerSecond {
		if err := c.take(ctx, now, team); err != nil {
			t.Fatalf("take %d after a second: %v (a throttled take spent a token)", i, err)
		}
	}
	if err := c.take(ctx, now.Add(100*time.Millisecond), team); !errors.Is(err, errThrottled) {
		t.Fatalf("past the team's rate: %v", err)
	}
	for i := range hookPerSecond - tenantPerSecond {
		if err := c.take(ctx, now, other); err != nil {
			t.Fatalf("the other workspace's take %d: %v", i, err)
		}
	}
	if err := c.take(ctx, now, other); !errors.Is(err, errThrottled) {
		t.Fatalf("past the process's rate: %v", err)
	}
	// Within the bound, a take waits for its token.
	start := time.Now()
	if err := c.take(ctx, now.Add(time.Second), other); err != nil || time.Since(start) < 50*time.Millisecond {
		t.Fatalf("a take within the bound: %v after %s", err, time.Since(start))
	}
	// Two minutes on, a third workspace's take sweeps the quiet ones.
	now = now.Add(2 * time.Minute)
	if err := c.take(ctx, now, uuid.New()); err != nil || len(c.tenants) != 1 {
		t.Fatalf("the sweep: %v, %d workspaces", err, len(c.tenants))
	}
}

// The minute rule (README 7.1, "Acts that narrow who holds a key"; 0040
// "No dormant keys": a removal never strands a number by a race): the
// number's remaining key holders count as backups only on a document under
// a minute old that is active and lists the team; each older one is asked
// for, the one losing the key never; a holder with no sub has no document
// and is no backup. With no confirmed backup left the verdict is a
// would-refuse, all within one call's bound, and only the enforce flag
// refuses; one confirmed backup is enough.
func TestFreshnessBackups(t *testing.T) {
	w := newEventWorld(t)
	ctx := context.Background()
	calls := func() int { return w.fake.Count(contracttest.CallAccount) }
	// Fresh within the minute: nobody is asked.
	before := calls()
	v, err := w.members.RequireBackups(ctx, "grant.revoke", w.team, w.device, w.second)
	if err != nil || !v.Checked || v.Refuse || calls() != before {
		t.Fatalf("fresh backups: %+v %v, %d calls", v, err, calls()-before)
	}
	// Over a minute old: the remaining holder is asked for, the losing one
	// never, though stale too.
	w.staleBy(ctx, t, w.sub, "2 minutes")
	w.staleBy(ctx, t, w.secondSub, "2 minutes")
	asked := w.asked()
	if v, err := w.members.RequireBackups(ctx, "grant.revoke", w.team, w.device, w.second); err != nil || v.Refuse || calls() != before+1 {
		t.Fatalf("a stale backup: %+v %v, %d calls", v, err, calls()-before)
	}
	if asked.of(w.sub) != 1 || asked.of(w.secondSub) != 0 {
		t.Fatalf("asked %v", asked.n)
	}
	// A holder with no sub is nobody to ask and no backup; the one asked
	// for is.
	local := w.localPerson(t)
	w.holder(t, w.device, local)
	w.staleBy(ctx, t, w.sub, "2 minutes")
	before = calls()
	if v, err := w.members.RequireBackups(ctx, "permission.withhold_read", w.team, w.device, w.second); err != nil || v.Refuse ||
		v.Reasons[local] != "no_sub" || v.Reasons[w.owner] != "" || calls() != before+1 {
		t.Fatalf("with a holder without a sub: %+v %v, %d calls", v, err, calls()-before)
	}
	// No answer: no confirmed backup, a would-refuse logged with the
	// number and each holder's reason, and the act goes on.
	w.staleBy(ctx, t, w.sub, "2 minutes")
	w.fake.SetDown(true)
	v, err = w.members.RequireBackups(ctx, "grant.revoke", w.team, w.device, w.second)
	if err != nil || !v.Refuse || v.Reasons[w.owner] != "unavailable" || v.Reasons[local] != "no_sub" {
		t.Fatalf("no answer: %+v %v", v, err)
	}
	if n := len(w.logs.Lines("freshness: would refuse", "act=grant.revoke", "device="+w.device.String(), "reason=no_confirmed_backup",
		w.sub.String()+":unavailable", "user "+local.String()+":no_sub")); n != 1 {
		t.Fatalf("%d would-refuse lines:\n%s", n, w.logs.String())
	}
	w.members.Enforce = true
	if _, err := w.members.RequireBackups(ctx, "grant.revoke", w.team, w.device, w.second); !errors.Is(err, ErrMembershipsUnconfirmed) {
		t.Fatalf("enforce: %v", err)
	}
	w.members.Enforce = false
	// One confirmed backup is enough: the owner fresh within the minute,
	// the other holder unanswered.
	w.fake.SetDown(false)
	w.members.SignIn(ctx, w.sub)
	w.staleBy(ctx, t, w.secondSub, "2 minutes")
	w.exec(ctx, t, `UPDATE contract_accounts SET fresh_at = clock_timestamp() WHERE sub = $1`, w.sub)
	w.fake.SetDown(true)
	if v, err := w.members.RequireBackups(ctx, "grant.revoke", w.team, w.device, local); err != nil || v.Refuse ||
		v.Reasons[w.second] != "unavailable" || v.Reasons[w.owner] != "" {
		t.Fatalf("one confirmed backup: %+v %v", v, err)
	}
	w.fake.SetDown(false)

	// A document that confirms nobody, from a GET and then as stored
	// within the minute, with no call: the platform removed the holder from
	// the team, or disabled their account.
	w.staleBy(ctx, t, w.secondSub, "2 minutes")
	if err := w.fake.RemoveMember(w.team.String(), w.secondSub.String()); err != nil {
		t.Fatal(err)
	}
	for _, how := range []string{"from a GET", "as stored"} {
		before = calls()
		v, err := w.members.RequireBackups(ctx, "grant.revoke", w.team, w.device, w.owner)
		want := before + 1
		if how == "as stored" {
			want = before
		}
		if err != nil || !v.Refuse || v.Reasons[w.second] != "not_a_member" || v.Reasons[local] != "no_sub" || calls() != want {
			t.Fatalf("a holder removed from the team, %s: %+v %v, %d calls", how, v, err, calls()-before)
		}
	}
	w.staleBy(ctx, t, w.sub, "2 minutes")
	if err := w.fake.Disable(w.sub.String(), dbNow(t, w.pool, "-1 minute")); err != nil {
		t.Fatal(err)
	}
	for _, how := range []string{"from a GET", "as stored"} {
		before = calls()
		v, err := w.members.RequireBackups(ctx, "grant.revoke", w.team, w.device, w.second)
		want := before + 1
		if how == "as stored" {
			want = before
		}
		if err != nil || !v.Refuse || v.Reasons[w.owner] != "account_disabled" || calls() != want {
			t.Fatalf("a disabled holder, %s: %+v %v, %d calls", how, v, err, calls()-before)
		}
	}
	if err := w.fake.Enable(w.sub.String()); err != nil {
		t.Fatal(err)
	}
	// The only holder left has no sub: no backup, and nobody to ask.
	alone := w.number(t, w.team, "Suporte", 2, w.owner, local)
	before = calls()
	if v, err := w.members.RequireBackups(ctx, "grant.revoke", w.team, alone, w.owner); err != nil || !v.Refuse || v.Reasons[local] != "no_sub" || calls() != before {
		t.Fatalf("an unlinked holder alone: %+v %v, %d calls", v, err, calls()-before)
	}
	// Nobody left: Wappie's own last_device_reader refuses; nothing to log.
	last := w.number(t, w.team, "Financeiro", 3, w.owner)
	if v, err := w.members.RequireBackups(ctx, "grant.revoke", w.team, last, w.owner); err != nil || !v.Checked || v.Refuse {
		t.Fatalf("no holder left: %+v %v", v, err)
	}
	// A personal workspace, or one no document names, narrows nothing.
	for _, ws := range []uuid.UUID{w.home, uuid.New()} {
		if v, err := w.members.RequireBackups(ctx, "grant.revoke", ws, w.device, w.second); err != nil || v.Checked {
			t.Fatalf("%s: %+v %v", ws, v, err)
		}
	}
	// A platform that never answers holds the act one bound, not one per
	// holder: eleven stale holders, more than run at once.
	subs := []uuid.UUID{w.sub, w.secondSub}
	for range 9 {
		user, sub, _ := w.heldAtHome(t)
		w.holder(t, w.device, user)
		subs = append(subs, sub)
	}
	for _, sub := range subs {
		w.staleBy(ctx, t, sub, "2 minutes")
	}
	release := make(chan struct{})
	defer close(release)
	w.fake.Before(contracttest.CallAccount, func(string) {
		select {
		case <-release:
		case <-time.After(5 * time.Second):
		}
	})
	w.members.Bound = 400 * time.Millisecond
	start := time.Now()
	v, err = w.members.RequireBackups(ctx, "grant.revoke", w.team, w.device, local)
	// Three rounds of four calls, one bound each, would take 1.2 s.
	if took := time.Since(start); err != nil || !v.Refuse || len(v.Reasons) != 11 || took > 900*time.Millisecond {
		t.Fatalf("hung: %d reasons, %v after %s", len(v.Reasons), err, took)
	}
}

// The holders the minute rule asks about are KeyHolders': an active person
// with an active, unexpired membership, Read, and the key at an epoch not
// retired, never a connection's service account (0051's sole_key_holders,
// the backup side).
func TestFreshnessBackupHolders(t *testing.T) {
	w := newEventWorld(t)
	ctx := context.Background()
	in := func(f func(tx pgx.Tx) error) {
		t.Helper()
		if err := pg.InTenantTx(ctx, w.pool, w.team.String(), f); err != nil {
			t.Fatal(err)
		}
	}
	people := map[string]uuid.UUID{}
	for _, name := range []string{"reader", "retired", "disabled_member", "deadline", "disabled_account", "key_only", "connection"} {
		people[name] = w.localPerson(t)
		w.holder(t, w.device, people[name])
	}
	var apiKey uuid.UUID
	if err := w.pool.QueryRow(ctx, `INSERT INTO api_keys (tenant_id, prefix, key_hash, created_by) VALUES ($1, $2, 'x', $3) RETURNING id`,
		w.team, uuid.NewString()[:8], w.owner).Scan(&apiKey); err != nil {
		t.Fatal(err)
	}
	in(func(tx pgx.Tx) error {
		for _, q := range []struct {
			sql  string
			args []any
		}{
			// Their only key is at an epoch a re-seal retired.
			{`DELETE FROM device_key_grants WHERE device_id = $1 AND user_id = $2`, []any{w.device, people["retired"]}},
			{`INSERT INTO device_archive_keys (tenant_id, device_id, epoch, public_key, retired_at)
				VALUES ($1, $2, 2, decode(repeat('cd', 32), 'hex'), clock_timestamp())`, []any{w.team, w.device}},
			{`INSERT INTO device_key_grants (tenant_id, device_id, user_id, epoch, sealed_dsk, granted_by) VALUES ($1, $2, $3, 2, '\x01', $3)`,
				[]any{w.team, w.device, people["retired"]}},
			{`UPDATE workspace_memberships SET status = 'disabled' WHERE tenant_id = $1 AND user_id = $2`, []any{w.team, people["disabled_member"]}},
			{`UPDATE workspace_memberships SET expires_at = clock_timestamp() + interval '1 day' WHERE tenant_id = $1 AND user_id = $2`,
				[]any{w.team, people["deadline"]}},
			{`UPDATE device_permissions SET can_read = false WHERE device_id = $1 AND user_id = $2`, []any{w.device, people["key_only"]}},
			{`INSERT INTO mcp_connections (tenant_id, request_id, api_key_id, created_by, client_name, redirect_host, device_count,
				reader_kid, status, expires_at, kind, service_user_id, key_mode, consent_version, reader)
				VALUES ($1, 'req-holders', $2, $3, 'Claude', 'claude.ai', 1, 'kid', 'active', clock_timestamp() + interval '1 day',
				'content', $4, 'ephemeral', 1, 'enclave')`, []any{w.team, apiKey, w.owner, people["connection"]}},
		} {
			if _, err := tx.Exec(ctx, q.sql, q.args...); err != nil {
				return err
			}
		}
		return nil
	})
	// The account is its home's row, under its home's row-level security.
	var home uuid.UUID
	in(func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT tenant_id FROM users WHERE id = $1`, people["disabled_account"]).Scan(&home)
	})
	if err := pg.InTenantTx(ctx, w.pool, home.String(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE users SET status = 'disabled' WHERE id = $1`, people["disabled_account"])
		if err == nil && tag.RowsAffected() != 1 {
			err = errors.New("the account was not disabled")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	v, err := w.members.RequireBackups(ctx, "grant.revoke", w.team, w.device, w.second)
	if err != nil || v.Reasons[people["reader"]] != "no_sub" || v.Reasons[w.owner] != "" || len(v.Reasons) != 1 {
		t.Fatalf("the holders: %+v %v", v.Reasons, err)
	}
	for name, u := range people {
		if _, counted := v.Reasons[u]; counted && name != "reader" {
			t.Fatalf("%s counted as a key holder", name)
		}
	}
}

// An answer that comes in time is stored, and counts, however late in the
// act's bound: only the GETs share the bound, never their storing (DB8:
// every validated document sets fresh_at).
func TestFreshnessKeepsLateAnswers(t *testing.T) {
	w := newEventWorld(t)
	ctx := context.Background()
	w.staleBy(ctx, t, w.sub, "2 minutes")
	_, _, staleAt := w.row(ctx, t, w.sub)
	// The contract's state is held past the bound: the GET is answered at
	// once, and storing its document waits for the lock.
	tx, err := w.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rolled back below; a second rollback is a no-op
	if _, err := tx.Exec(ctx, `SELECT 1 FROM contract_state FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	w.members.Bound = 300 * time.Millisecond
	type result struct {
		v   Verdict
		err error
	}
	done := make(chan result, 1)
	go func() {
		v, err := w.members.RequireBackups(ctx, "grant.revoke", w.team, w.device, w.second)
		done <- result{v, err}
	}()
	time.Sleep(700 * time.Millisecond)
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	r := <-done
	if r.err != nil || r.v.Refuse || r.v.Reasons[w.owner] != "" {
		t.Fatalf("a late answer did not count: %+v %v", r.v, r.err)
	}
	if _, _, at := w.row(ctx, t, w.sub); at == nil || !at.After(*staleAt) {
		t.Fatalf("a late answer was not stored: %v, was %v", at, staleAt)
	}
}

// A move out of a team (README 7.1, "always with a fresh GET"; decision
// 0043): the mover's document is asked for whatever its freshness, and
// must list them as the team's only owner; one that does not, or none, is
// logged "transfer: would refuse" and the move goes on, unless the
// enforce flag is set.
func TestFreshnessMover(t *testing.T) {
	w := newEventWorld(t)
	ctx := context.Background()
	calls := func() int { return w.fake.Count(contracttest.CallAccount) }
	before := calls()
	v, err := w.members.RequireMover(ctx, w.team, w.owner)
	if err != nil || !v.Checked || v.Refuse || v.Mover != "" || v.Actor == nil || calls() != before+1 {
		t.Fatalf("the only owner: %+v %v, %d calls", v, err, calls()-before)
	}
	if n := len(w.logs.Lines("transfer: would refuse")); n != 0 {
		t.Fatalf("a would-refuse for the only owner:\n%s", w.logs.String())
	}
	// The only owner, disabled: their document lists them so, and it is
	// not active; with the enforce flag a refusal.
	if err := w.fake.Disable(w.sub.String(), dbNow(t, w.pool, "-1 minute")); err != nil {
		t.Fatal(err)
	}
	if v, err := w.members.RequireMover(ctx, w.team, w.owner); err != nil || !v.Refuse || v.Reasons[w.owner] != "account_disabled" {
		t.Fatalf("a disabled only owner: %+v %v", v, err)
	}
	w.members.Enforce = true
	if _, err := w.members.RequireMover(ctx, w.team, w.owner); !errors.Is(err, ErrMembershipsUnconfirmed) {
		t.Fatalf("enforce, a disabled only owner: %v", err)
	}
	w.members.Enforce = false
	if err := w.fake.Enable(w.sub.String()); err != nil {
		t.Fatal(err)
	}
	// A second owner on the platform.
	if err := w.fake.SetRole(w.team.String(), w.secondSub.String(), kc.RoleOwner); err != nil {
		t.Fatal(err)
	}
	if v, err := w.members.RequireMover(ctx, w.team, w.owner); err != nil || v.Mover != "owners_2" {
		t.Fatalf("two owners: %+v %v", v, err)
	}
	if n := len(w.logs.Lines("transfer: would refuse", "reason=owners_2", w.team.String(), w.sub.String())); n != 1 {
		t.Fatalf("%d would-refuse lines:\n%s", n, w.logs.String())
	}
	// The mover is an admin there now.
	if err := w.fake.SetRole(w.team.String(), w.sub.String(), kc.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if v, err := w.members.RequireMover(ctx, w.team, w.owner); err != nil || v.Mover != "role_admin" {
		t.Fatalf("an admin: %+v %v", v, err)
	}
	w.members.Enforce = true
	if _, err := w.members.RequireMover(ctx, w.team, w.owner); !errors.Is(err, ErrNotTheOnlyOwner) {
		t.Fatalf("enforce, an admin: %v", err)
	}
	// No document.
	w.fake.SetDown(true)
	if _, err := w.members.RequireMover(ctx, w.team, w.owner); !errors.Is(err, ErrMembershipsUnconfirmed) {
		t.Fatalf("enforce, no answer: %v", err)
	}
	w.members.Enforce = false
	if v, err := w.members.RequireMover(ctx, w.team, w.owner); err != nil || v.Mover != "no_document:unavailable" {
		t.Fatalf("no answer: %+v %v", v, err)
	}
	w.fake.SetDown(false)
	// The platform removed the mover from the team.
	if err := w.fake.RemoveMember(w.team.String(), w.sub.String()); err != nil {
		t.Fatal(err)
	}
	if v, err := w.members.RequireMover(ctx, w.team, w.owner); err != nil || v.Mover != "not_a_member" {
		t.Fatalf("removed: %+v %v", v, err)
	}
	w.members.Enforce = true
	if _, err := w.members.RequireMover(ctx, w.team, w.owner); !errors.Is(err, ErrNotTheOnlyOwner) {
		t.Fatalf("enforce, removed: %v", err)
	}
	w.members.Enforce = false
	// No team, no mover check.
	if v, err := w.members.RequireMover(ctx, w.home, w.owner); err != nil || v.Mover != "" {
		t.Fatalf("at home: %+v %v", v, err)
	}
	// A team's entry with no owner count is not a count of one.
	raw, err := json.Marshal(kc.AccountDoc{Workspaces: []kc.Workspace{{ID: w.team.String(), Kind: kc.KindTeam, Role: kc.RoleOwner}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := mover(Verdict{Actor: &store.ContractDoc{Raw: raw}}, w.team, w.owner); got != "owners_-1" {
		t.Fatalf("no owner count: %q", got)
	}
}
