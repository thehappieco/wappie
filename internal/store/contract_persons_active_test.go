package store_test

import (
	"context"
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/store"
)

// TestPersonOfActiveMembershipsOnly: a person's document lists the notices
// of the platform workspaces where Wappie's own page would show them, an
// active membership of an active account in an active workspace that has
// not expired; a membership disabled or expired, a disabled account or a
// suspended workspace shows none, and the workspace's change wakes the
// document of every holder of an unseen notice there, not only of a pause
// notice.
func TestPersonOfActiveMembershipsOnly(t *testing.T) {
	ctx := context.Background()
	w := newDelWorld(t)
	c := store.NewContract(w.pool)
	w.recordLocal(t, c)
	member := w.person(t, "member", "member")
	sub := linkSub(t, w.pool, member)
	follow(t, w, sub, "active")
	device := w.number(t, "Vendas")
	w.quarantine(t, device)
	deleted := w.notice(t, w.tenant, device, member, store.NoticeNumberDeleted, &w.owner, "")
	stranded := w.notice(t, w.tenant, uuid.New(), member, store.NoticeNumberStranded, &w.owner, "")

	ids := func(what string) []int64 {
		t.Helper()
		p, ok, err := c.PersonOf(ctx, sub)
		if err != nil || !ok {
			t.Fatalf("%s: the person: %v %v", what, ok, err)
		}
		var got []int64
		for _, n := range p.Notices {
			got = append(got, n.ID)
		}
		slices.Sort(got)
		return got
	}
	if got := ids("active"); !slices.Equal(got, []int64{deleted, stranded}) {
		t.Fatalf("an active member's notices %v, want %v", got, []int64{deleted, stranded})
	}
	if subs, err := c.PersonsOfWorkspace(ctx, w.tenant); err != nil || !slices.Contains(subs, sub) {
		t.Fatalf("the holders of a notice other than a pause's: %v %v", subs, err)
	}
	exec := func(query string, args ...any) {
		t.Helper()
		inTenantTx(ctx, t, w.pool, w.tenant, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, query, args...)
			return err
		})
	}
	for _, c := range []struct {
		what, hide, show string
	}{
		{"a disabled membership", `UPDATE workspace_memberships SET status = 'disabled' WHERE user_id = $1`,
			`UPDATE workspace_memberships SET status = 'active' WHERE user_id = $1`},
		{"an expired membership", `UPDATE workspace_memberships SET expires_at = now() - interval '1 minute' WHERE user_id = $1`,
			`UPDATE workspace_memberships SET expires_at = NULL WHERE user_id = $1`},
	} {
		exec(c.hide+` AND tenant_id = $2`, member, w.tenant)
		if got := ids(c.what); len(got) != 0 {
			t.Fatalf("%s still lists %v", c.what, got)
		}
		exec(c.show+` AND tenant_id = $2`, member, w.tenant)
		if got := ids(c.what + ", undone"); len(got) != 2 {
			t.Fatalf("%s undone lists %v", c.what, got)
		}
	}
	exec(`UPDATE users SET status = 'disabled' WHERE id = $1`, member)
	if got := ids("a disabled account"); len(got) != 0 {
		t.Fatalf("a disabled account still lists %v", got)
	}
	exec(`UPDATE users SET status = 'active' WHERE id = $1`, member)
	if got := ids("an active account again"); len(got) != 2 {
		t.Fatalf("an active account again lists %v", got)
	}
	exec(`UPDATE tenants SET status = 'suspended' WHERE id = $1`, w.tenant)
	if got := ids("a suspended workspace"); len(got) != 0 {
		t.Fatalf("a suspended workspace still lists %v", got)
	}
}
