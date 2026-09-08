package authapi_test

import (
	"context"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"testing"
	"time"
	"whatserver2/internal/pg"
)

func TestIdentityWithoutWorkspaceCanJoinAgain(t *testing.T) {
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
	if user.TenantID != uuid.Nil || user.Role != "" {
		t.Fatal("identity retained workspace authority")
	}
	token, _, err := h.users.StartSession(ctx, user, "test")
	if err != nil {
		t.Fatal(err)
	}
	if code := h.get(t, "/v1/auth/me", nil, token); code != 200 {
		t.Fatalf("me=%d", code)
	}
	if code := h.get(t, "/v1/auth/workspaces/members", nil, token); code != 403 {
		t.Fatalf("identity administered members: %d", code)
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
