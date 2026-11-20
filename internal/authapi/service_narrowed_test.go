package authapi_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"whatserver2/internal/store"
)

// TestStandingServiceInvitationsWhileTokensAreOn (step 7's plan, 7.3 and
// 10.7): while keys are narrowed (tokens on, or the keys retired), a
// standing service account's invitation is refused with 409
// tokens_are_the_platforms, issued, regenerated, in the operator's
// whatserverd invite and redeemed (one issued before stays unspent); a
// provisional one, a content consent's, is issued and redeemed. Off the
// narrowing every one works as before.
func TestStandingServiceInvitationsWhileTokensAreOn(t *testing.T) {
	for _, how := range []string{"tokens on", "after a retirement"} {
		t.Run(how, func(t *testing.T) { standingServiceInvitations(t, how) })
	}
}

func standingServiceInvitations(t *testing.T, how string) {
	h := newHarness(t)
	ctx := context.Background()
	owner, token := memberAccount(t, h, "owner@example.com", "owner")
	before, err := h.users.CreateInvite(ctx, h.tenant, store.RoleService, "", &owner.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var pending struct {
		Invite     string           `json:"invite"`
		Invitation store.Invitation `json:"invitation"`
	}
	if code := h.post(t, "/v1/auth/workspaces/invites", map[string]string{"role": store.RoleService}, &pending, token); code != http.StatusCreated {
		t.Fatalf("a standing service invitation with tokens off: %d", code)
	}
	exec := func(sql string) {
		t.Helper()
		if _, err := h.pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	if how == "tokens on" {
		exec(`UPDATE contract_token_state SET mode = 'on'`)
	} else {
		exec(`INSERT INTO key_retirements (revoked, services_removed, services_kept, report, by) VALUES (0, 0, 0, '{}', 'root')`)
	}

	var refused map[string]string
	if code := h.post(t, "/v1/auth/workspaces/invites", map[string]string{"role": store.RoleService}, &refused, token); code != http.StatusConflict ||
		refused["code"] != "tokens_are_the_platforms" {
		t.Fatalf("issuing: %d %v", code, refused)
	}
	if code := h.post(t, "/v1/auth/workspaces/invites/"+pending.Invitation.ID.String()+"/regenerate", map[string]string{}, &refused, token); code != http.StatusConflict ||
		refused["code"] != "tokens_are_the_platforms" {
		t.Fatalf("regenerating: %d %v", code, refused)
	}
	if _, err := h.users.CreateInvite(ctx, h.tenant, store.RoleService, "", nil, time.Hour); !errors.Is(err, store.ErrTokensAreThePlatforms) {
		t.Fatalf("the operator's invite: %v", err)
	}
	if code := h.post(t, "/v1/auth/signup", map[string]string{"invite": before, "name": "erp", "public_key": publicKey(t)}, &refused, ""); code != http.StatusConflict ||
		refused["code"] != "tokens_are_the_platforms" {
		t.Fatalf("registering one issued before: %d %v", code, refused)
	}
	var completed *time.Time
	if err := h.pool.QueryRow(ctx, `SELECT completed_at FROM invites WHERE invite_id = $1`, shaInvite(t, before)).Scan(&completed); err != nil || completed != nil {
		t.Fatalf("the refused code was spent: %v %v", completed, err)
	}
	// A person's invitation is not the narrowing's.
	if code := h.post(t, "/v1/auth/workspaces/invites", map[string]string{"role": "member", "email": "m@example.com"}, nil, token); code != http.StatusCreated {
		t.Fatalf("a person's invitation: %d", code)
	}
	var service struct {
		Invite string `json:"invite"`
	}
	if code := h.post(t, "/v1/auth/workspaces/invites", map[string]any{"role": store.RoleService, "provisional": true}, &service, token); code != http.StatusCreated {
		t.Fatalf("a provisional invitation: %d", code)
	}
	if status := h.post(t, "/v1/auth/signup", map[string]string{"invite": service.Invite, "name": "reader", "public_key": publicKey(t)}, nil, ""); status != http.StatusOK {
		t.Fatalf("registering the provisional service: %d", status)
	}

	// Off the narrowing, the code from before still registers.
	if how != "tokens on" {
		return
	}
	exec(`UPDATE contract_token_state SET mode = 'off'`)
	if status := h.post(t, "/v1/auth/signup", map[string]string{"invite": before, "name": "erp", "public_key": publicKey(t)}, nil, ""); status != http.StatusOK {
		t.Fatalf("registering one issued before, tokens off again: %d", status)
	}
}
