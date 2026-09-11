package authapi_test

import (
	"context"
	"github.com/jackc/pgx/v5"
	"testing"
	"time"
	"whatserver2/internal/pg"
)

func TestIdentityWithoutTeamFallsBackToPersonalAndCanJoinAgain(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	u, _ := memberAccount(t, h, "identity@test.com", "member")
	if err := pg.InTenantTx(ctx, h.pool, h.tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM workspace_memberships WHERE user_id=$1`, u.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	user, err := h.users.Authenticate(ctx, u.Email, "proof")
	if err != nil {
		t.Fatal(err)
	}
	spaces, err := h.users.Workspaces(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(spaces) != 1 || spaces[0].Kind != "personal" || user.TenantID != spaces[0].ID || user.Role != "owner" {
		t.Fatalf("identity did not retain its personal workspace: %+v", spaces)
	}
	token, _, err := h.users.StartSession(ctx, user, "test")
	if err != nil {
		t.Fatal(err)
	}
	if code := h.get(t, "/v1/auth/me", nil, token); code != 200 {
		t.Fatalf("me=%d", code)
	}
	if code := h.get(t, "/v1/auth/workspaces/members", nil, token); code != 200 {
		t.Fatalf("personal owner could not view own membership: %d", code)
	}
	invite, err := h.users.CreateInvite(ctx, h.tenant, "member", u.Email, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if code := h.post(t, "/v1/auth/workspaces/accept-invite", map[string]string{"invite": invite}, nil, token); code != 200 {
		t.Fatalf("join=%d", code)
	}
	if code := h.post(t, "/v1/auth/workspaces/session", map[string]string{"tenant_id": h.tenant.String()}, nil, token); code != 200 {
		t.Fatalf("switch=%d", code)
	}
}
