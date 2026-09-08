package authapi_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"whatserver2/internal/pg"
	"whatserver2/internal/store"
)

func TestWorkspaceIdentityAndSessionIsolation(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	body, _ := newAccount(t, h.invite(t, "owner"), "shared@example.com", "original-proof")
	var original sessionReply
	if code := h.post(t, "/v1/auth/signup", body, &original, ""); code != http.StatusOK {
		t.Fatalf("signup: %d", code)
	}
	var target, unrelated uuid.UUID
	for _, id := range []*uuid.UUID{&target, &unrelated} {
		if err := h.pool.QueryRow(ctx, `INSERT INTO tenants(name) VALUES ('another') RETURNING id`).Scan(id); err != nil {
			t.Fatal(err)
		}
	}
	invite, err := h.users.CreateInvite(ctx, target, "member", "shared@example.com", nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if code := h.post(t, "/v1/auth/workspaces/accept-invite", map[string]string{"invite": invite}, nil, original.Token); code != http.StatusOK {
		t.Fatalf("accept: %d", code)
	}
	var spaces struct {
		Workspaces []store.Workspace `json:"workspaces"`
	}
	if code := h.get(t, "/v1/auth/workspaces", &spaces, original.Token); code != http.StatusOK || len(spaces.Workspaces) != 2 {
		t.Fatalf("list: %d %+v", code, spaces)
	}
	var switched sessionReply
	if code := h.post(t, "/v1/auth/workspaces/session", map[string]string{"tenant_id": target.String()}, &switched, original.Token); code != http.StatusOK {
		t.Fatalf("switch: %d", code)
	}
	if switched.User.ID != original.User.ID || switched.User.PublicKey != original.User.PublicKey || switched.User.WrappedUSK != original.User.WrappedUSK {
		t.Fatal("switch replaced identity or keys")
	}
	if switched.User.Role != "member" || switched.User.TenantID != target.String() || switched.Token == original.Token {
		t.Fatalf("incorrect workspace session: %+v", switched)
	}
	_, oldUser, err := h.users.ActiveSession(ctx, original.Token)
	if err != nil || oldUser.TenantID != h.tenant || oldUser.Role != "owner" {
		t.Fatalf("old session moved: %+v %v", oldUser, err)
	}
	oldSession, err := h.users.Session(ctx, original.Token)
	if err != nil {
		t.Fatal(err)
	}
	newSession, err := h.users.Session(ctx, switched.Token)
	if err != nil {
		t.Fatal(err)
	}
	if !newSession.ExpiresAt.Equal(oldSession.ExpiresAt) {
		t.Fatal("workspace switching extended authentication lifetime")
	}
	var me struct {
		Grants []any `json:"grants"`
	}
	if code := h.get(t, "/v1/auth/me", &me, switched.Token); code != http.StatusOK || len(me.Grants) != 0 {
		t.Fatalf("joining granted content: %d %+v", code, me)
	}
	if code := h.post(t, "/v1/auth/workspaces/session", map[string]string{"tenant_id": unrelated.String()}, nil, original.Token); code != http.StatusForbidden {
		t.Fatalf("unrelated space: %d", code)
	}
	if code := h.get(t, "/v1/auth/workspaces", nil, ""); code != http.StatusUnauthorized {
		t.Fatalf("anonymous list: %d", code)
	}

	// Updating credentials through the second space changes the one identity,
	// while preserving its public key and invalidating sessions in both spaces.
	userID := uuid.MustParse(original.User.ID)
	user, err := h.users.Get(ctx, target, userID)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.users.Rekey(ctx, target, userID, store.Rekey{AuthKey: "new-proof", KDFSalt: user.KDFSalt, KDFParams: user.KDFParams, WrappedUSK: user.WrappedUSK}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.users.Authenticate(ctx, user.Email, "original-proof"); err == nil {
		t.Fatal("old password survived")
	}
	updated, err := h.users.Authenticate(ctx, user.Email, "new-proof")
	if err != nil || updated.ID != userID {
		t.Fatalf("shared identity login: %+v %v", updated, err)
	}
	for _, token := range []string{original.Token, switched.Token} {
		if _, _, err := h.users.ActiveSession(ctx, token); err == nil {
			t.Fatal("old session survived global password change")
		}
	}
}

func TestWorkspaceInviteValidationIsAtomic(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	body, _ := newAccount(t, h.invite(t, "owner"), "recipient@example.com", "proof")
	var signed sessionReply
	if code := h.post(t, "/v1/auth/signup", body, &signed, ""); code != http.StatusOK {
		t.Fatalf("signup: %d", code)
	}
	var target uuid.UUID
	if err := h.pool.QueryRow(ctx, `INSERT INTO tenants(name) VALUES ('target') RETURNING id`).Scan(&target); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ role, email string }{{"member", "someone-else@example.com"}, {"service", "recipient@example.com"}} {
		invite, err := h.users.CreateInvite(ctx, target, tc.role, tc.email, nil, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if code := h.post(t, "/v1/auth/workspaces/accept-invite", map[string]string{"invite": invite}, nil, signed.Token); code != http.StatusForbidden {
			t.Fatalf("invalid recipient/type: %d", code)
		}
		if _, err := h.users.RedeemInvite(ctx, invite); err != nil {
			t.Fatalf("invalid attempt consumed invite: %v", err)
		}
	}
	invite, err := h.users.CreateInvite(ctx, target, "member", "", nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if code := h.post(t, "/v1/auth/workspaces/accept-invite", map[string]string{"invite": invite}, nil, signed.Token); code != http.StatusOK {
		t.Fatalf("join: %d", code)
	}
	if code := h.post(t, "/v1/auth/workspaces/accept-invite", map[string]string{"invite": invite}, nil, signed.Token); code != http.StatusForbidden {
		t.Fatalf("invite replay: %d", code)
	}
	// A new owner invite must not silently promote an existing member.
	invite, err = h.users.CreateInvite(ctx, target, "owner", "", nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if code := h.post(t, "/v1/auth/workspaces/accept-invite", map[string]string{"invite": invite}, nil, signed.Token); code != http.StatusForbidden {
		t.Fatalf("duplicate promoted member: %d", code)
	}
	if _, err := h.users.RedeemInvite(ctx, invite); err != nil {
		t.Fatalf("duplicate consumed invite: %v", err)
	}
	var second sessionReply
	if code := h.post(t, "/v1/auth/workspaces/session", map[string]string{"tenant_id": target.String()}, &second, signed.Token); code != http.StatusOK {
		t.Fatalf("session: %d", code)
	}
	if err := pg.InTenantTx(ctx, h.pool, target.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE workspace_memberships SET status = 'disabled' WHERE user_id = $1`, uuid.MustParse(signed.User.ID))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if code := h.get(t, "/v1/auth/me", nil, second.Token); code != http.StatusUnauthorized {
		t.Fatalf("disabled membership session: %d", code)
	}
	if code := h.get(t, "/v1/auth/me", nil, signed.Token); code != http.StatusOK {
		t.Fatalf("disabled wrong space: %d", code)
	}
}

func TestWorkspaceIdentitySurvivesOriginalSpaceDeletion(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	body, _ := newAccount(t, h.invite(t, "owner"), "survivor@example.com", "proof")
	var signed sessionReply
	if code := h.post(t, "/v1/auth/signup", body, &signed, ""); code != http.StatusOK {
		t.Fatalf("signup: %d", code)
	}
	var target uuid.UUID
	if err := h.pool.QueryRow(ctx, `INSERT INTO tenants(name) VALUES ('surviving') RETURNING id`).Scan(&target); err != nil {
		t.Fatal(err)
	}
	invite, err := h.users.CreateInvite(ctx, target, "member", "", nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if code := h.post(t, "/v1/auth/workspaces/accept-invite", map[string]string{"invite": invite}, nil, signed.Token); code != http.StatusOK {
		t.Fatalf("join: %d", code)
	}
	if _, err := h.pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, h.tenant); err != nil {
		t.Fatal(err)
	}
	var login sessionReply
	if code := h.post(t, "/v1/auth/login", map[string]string{"email": body.Email, "auth_key": body.AuthKey}, &login, ""); code != http.StatusOK {
		t.Fatalf("login after original deletion: %d", code)
	}
	if login.User.ID != signed.User.ID || login.User.PublicKey != signed.User.PublicKey || login.User.TenantID != target.String() || login.User.Role != "member" {
		t.Fatalf("identity/default space changed incorrectly: %+v", login)
	}
}
