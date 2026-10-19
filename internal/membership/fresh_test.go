package membership

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kc "github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/contract/contracttest"

	"whatserver2/internal/pg"
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

// In a personal workspace an act never waits (the reply's Q5): only the
// actor's own stored status counts, with no call, however stale; a
// document that says disabled is a would-refuse there, as in a team, and
// with the enforce flag a refusal.
func TestFreshnessPersonalWorkspace(t *testing.T) {
	w := newEventWorld(t)
	ctx := context.Background()
	calls := func() int { return w.fake.Count(contracttest.CallAccount) }
	before := calls()
	v, err := w.members.RequireFresh(ctx, "device.delete", w.home, Party{User: w.owner, How: Always})
	if err != nil || !v.Checked || v.Refuse || calls() != before {
		t.Fatalf("an active owner at home: %+v %v, %d calls", v, err, calls()-before)
	}
	w.staleBy(ctx, t, w.sub, "2 hours")
	if v, err := w.members.RequireFresh(ctx, "device.delete", w.home, Party{User: w.owner, How: IfStale}); err != nil || v.Refuse || calls() != before {
		t.Fatalf("a stale owner at home waited: %+v %v, %d calls", v, err, calls()-before)
	}
	// The platform disables the account; the document reaches Wappie.
	if err := w.fake.Disable(w.sub.String(), dbNow(t, w.pool, "-1 minute")); err != nil {
		t.Fatal(err)
	}
	w.members.SignIn(ctx, w.sub)
	before = calls()
	v, err = w.members.RequireFresh(ctx, "device.delete", w.home, Party{User: w.owner, How: Always})
	if err != nil || !v.Refuse || v.Reasons[w.owner] != "account_disabled" || calls() != before {
		t.Fatalf("a disabled owner at home: %+v %v, %d calls", v, err, calls()-before)
	}
	if n := len(w.logs.Lines("freshness: would refuse", "act=device.delete", "reason=account_disabled", w.home.String())); n != 1 {
		t.Fatalf("%d would-refuse lines:\n%s", n, w.logs.String())
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
	if _, err := w.members.RequireFresh(ctx, "device.delete", w.home, Party{User: w.owner, How: IfStale}); !errors.Is(err, ErrMembershipsUnconfirmed) || calls() != before {
		t.Fatalf("enforce at home: %v, %d calls", err, calls()-before)
	}
	w.members.Enforce = false
	// A person with no sub, at a home that is no platform workspace: nothing.
	stranger := w.localPerson(t)
	if v, err := w.members.RequireFresh(ctx, "device.delete", uuid.New(), Party{User: stranger, How: Always}); err != nil || v.Checked {
		t.Fatalf("an unrecorded workspace: %+v %v", v, err)
	}
}

// A service identity is never a party: it has no sub and is never a
// platform member (design 2.7), so a grant to a standing service account,
// a consent's provisional one or a connection's waits only on the person.
func TestFreshnessLeavesServicesOut(t *testing.T) {
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
	before := w.fake.Count(contracttest.CallAccount)
	v, err := w.members.RequireFresh(ctx, "grant.add", w.team, Party{User: w.owner, How: IfStale},
		Party{User: standing, How: Always}, Party{User: provisional, How: Always})
	if err != nil || !v.Checked || v.Refuse || len(v.Reasons) != 0 || w.fake.Count(contracttest.CallAccount) != before {
		t.Fatalf("services were parties: %+v %v", v, err)
	}
	// A person with no sub stays a would-refuse.
	local := w.localPerson(t)
	w.localTeam(t, w.team, "", member{local, "member", "active"})
	if v, err := w.members.RequireFresh(ctx, "grant.add", w.team, Party{User: w.owner, How: IfStale}, Party{User: local, How: Always}); err != nil || v.Reasons[local] != "no_sub" {
		t.Fatalf("a person with no sub: %+v %v", v, err)
	}
}

// The minute rule (README 7.1, "Acts that narrow who holds a key"): the
// number's remaining key holders count as backups only on a document
// under a minute old; each older one is asked for, the one losing the key
// never, a holder with no sub cannot be; no answer is a would-refuse, all
// within one call's bound, and only the enforce flag refuses.
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
	asked := map[string]int{}
	w.fake.Before(contracttest.CallAccount, func(sub string) { asked[sub]++ })
	if v, err := w.members.RequireBackups(ctx, "grant.revoke", w.team, w.device, w.second); err != nil || v.Refuse || calls() != before+1 {
		t.Fatalf("a stale backup: %+v %v, %d calls", v, err, calls()-before)
	}
	if asked[w.sub.String()] != 1 || asked[w.secondSub.String()] != 0 {
		t.Fatalf("asked %v", asked)
	}
	// A holder with no sub is nobody to ask, and no refusal.
	local := w.localPerson(t)
	w.localTeam(t, w.team, "", member{local, "member", "active"})
	if err := pg.InTenantTx(ctx, w.pool, w.team.String(), func(tx pgx.Tx) error { return readsTx(ctx, tx, w.team, w.device, local) }); err != nil {
		t.Fatal(err)
	}
	w.staleBy(ctx, t, w.sub, "2 minutes")
	before = calls()
	if v, err := w.members.RequireBackups(ctx, "permission.withhold_read", w.team, w.device, w.second); err != nil || v.Refuse || calls() != before+1 {
		t.Fatalf("with a holder without a sub: %+v %v, %d calls", v, err, calls()-before)
	}
	// No answer: a would-refuse, logged with the number, and the act goes on.
	w.staleBy(ctx, t, w.sub, "2 minutes")
	w.fake.SetDown(true)
	v, err = w.members.RequireBackups(ctx, "grant.revoke", w.team, w.device, w.second)
	if err != nil || !v.Refuse || v.Reasons[w.owner] != "unavailable" {
		t.Fatalf("no answer: %+v %v", v, err)
	}
	if n := len(w.logs.Lines("freshness: would refuse", "act=grant.revoke", "device="+w.device.String(), "reason=unavailable", w.sub.String())); n != 1 {
		t.Fatalf("%d would-refuse lines:\n%s", n, w.logs.String())
	}
	w.members.Enforce = true
	if _, err := w.members.RequireBackups(ctx, "grant.revoke", w.team, w.device, w.second); !errors.Is(err, ErrMembershipsUnconfirmed) {
		t.Fatalf("enforce: %v", err)
	}
	w.members.Enforce = false
	w.fake.SetDown(false)
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
		w.localTeam(t, w.team, "", member{user, "member", "active"})
		if err := pg.InTenantTx(ctx, w.pool, w.team.String(), func(tx pgx.Tx) error { return readsTx(ctx, tx, w.team, w.device, user) }); err != nil {
			t.Fatal(err)
		}
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
	// No team, no mover check.
	if v, err := w.members.RequireMover(ctx, w.home, w.owner); err != nil || v.Mover != "" {
		t.Fatalf("at home: %+v %v", v, err)
	}
}
