package authapi_test

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"whatserver2/internal/authapi"
	"whatserver2/internal/config"
	"whatserver2/internal/store"
)

// providerUnset serves h's database with the identity provider unset, as a
// self-hosted build (or a rollback of the provider) does: the same
// accounts and sessions, and no account is the platform's.
func providerUnset(t *testing.T, h *platformHarness) *harness {
	t.Helper()
	handler := &authapi.Handler{Users: h.users, Keys: h.keys, Devices: store.NewDevices(h.pool), Storage: store.NewStorage(h.pool)}
	mux := http.NewServeMux()
	handler.Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	out := *h.harness
	out.srv = srv
	return &out
}

// wantManagedElsewhere fails unless an answer is DS53's refusal.
func wantManagedElsewhere(t *testing.T, what string, code int, body map[string]string) {
	t.Helper()
	if code != http.StatusConflict || body["code"] != "managed_elsewhere" || !strings.Contains(body["message"], "console") {
		t.Fatalf("%s: %d %v, want 409 managed_elsewhere", what, code, body)
	}
}

// DS53: in the hosted build a platform account creates no workspace here
// (409 managed_elsewhere, and no tenant is written), while a local
// password account still does, and so does the same platform account on a
// server with the provider unset (self-hosted).
func TestPlatformAccountsCreateNoWorkspace(t *testing.T) {
	h := newPlatformHarness(t, config.LocalLoginOn)
	_, first := h.signIn(t, newPerson(t, "hana@example.com"), 1)
	code, created, _, _ := h.createAccount(t, first.Ticket)
	if code != http.StatusOK || created.User.AuthSource != store.PlatformAuthSource {
		t.Fatalf("account: %d %+v", code, created.User)
	}
	tenants := h.count(t, `SELECT count(*) FROM tenants`)
	memberships := h.count(t, `SELECT count(*) FROM workspace_memberships`)

	var refused map[string]string
	code = h.post(t, "/v1/auth/workspaces", map[string]string{"name": "Piloto C"}, &refused, created.Token)
	wantManagedElsewhere(t, "a platform account's new workspace", code, refused)
	if n := h.count(t, `SELECT count(*) FROM tenants`); n != tenants {
		t.Fatalf("a refused workspace wrote a tenant: %d, was %d", n, tenants)
	}
	if n := h.count(t, `SELECT count(*) FROM workspace_memberships`); n != memberships {
		t.Fatalf("a refused workspace wrote a membership: %d, was %d", n, memberships)
	}
	// Its own workspaces are as they were.
	var spaces struct {
		Workspaces []store.Workspace `json:"workspaces"`
	}
	if code := h.get(t, "/v1/auth/workspaces", &spaces, created.Token); code != http.StatusOK || len(spaces.Workspaces) != 1 || spaces.Workspaces[0].Kind != "personal" {
		t.Fatalf("a platform account's workspaces: %d %+v", code, spaces)
	}

	// A local password account is not the platform's: unchanged.
	var team store.Workspace
	if code := h.post(t, "/v1/auth/workspaces", map[string]string{"name": "Local team"}, &team, h.signed.Token); code != http.StatusCreated ||
		team.Kind != "team" || team.Role != "owner" {
		t.Fatalf("a local account's new workspace: %d %+v", code, team)
	}

	// With the provider unset no account is the platform's: unchanged.
	self := providerUnset(t, h)
	if code := self.post(t, "/v1/auth/workspaces", map[string]string{"name": "Self-hosted team"}, &team, created.Token); code != http.StatusCreated ||
		team.Kind != "team" || team.Role != "owner" {
		t.Fatalf("a new workspace with the provider unset: %d %+v", code, team)
	}
}

// DS53: in the hosted build a platform account invites no person, of any
// role, and regenerates no person's code (409 managed_elsewhere, and the
// old code is not revoked). What is stored stays: a pending person
// invitation is listed, revealed and redeemed as before. A service
// invitation is issued and regenerated. A local account in the same team,
// and the platform account with the provider unset, invite people as
// before.
func TestPlatformAccountsInviteNoPerson(t *testing.T) {
	h := newPlatformHarness(t, config.LocalLoginOn)
	ctx := context.Background()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if err := h.users.SetInviteEncryptionKey(key); err != nil {
		t.Fatal(err)
	}
	type issued struct {
		Invite     string           `json:"invite"`
		Invitation store.Invitation `json:"invitation"`
	}
	invite := func(srv *harness, token, role, what string) issued {
		t.Helper()
		var out issued
		if code := srv.post(t, "/v1/auth/workspaces/invites", map[string]string{"role": role}, &out, token); code != http.StatusCreated || out.Invite == "" {
			t.Fatalf("%s: %d %+v", what, code, out)
		}
		return out
	}

	// Issued by the team's owner while still a local account: a person's
	// invitation and a service's.
	pending := invite(h.harness, h.signed.Token, "member", "a person's invitation before the link")
	service := invite(h.harness, h.signed.Token, store.RoleService, "a service's invitation before the link")

	// The owner links to the platform, and opens the team.
	q := newPerson(t, "passkey@example.com")
	_, b := h.signIn(t, q, 1)
	if b.Kind != "link_required" {
		t.Fatalf("link sign-in: %+v", b)
	}
	var linked platformAnswer
	if code := h.pagePost(t, "/v1/auth/platform/link", map[string]string{"ticket": b.Ticket, "email": "passkey@example.com", "auth_key": h.account.AuthKey,
		"platform_wrap": randomWrap(t)}, &linked, "", nil); code != http.StatusOK || linked.User.AuthSource != store.PlatformAuthSource {
		t.Fatalf("link: %d %+v", code, linked.User)
	}
	var team sessionReply
	if code := h.post(t, "/v1/auth/workspaces/session", map[string]string{"tenant_id": h.tenant.String()}, &team, linked.Token); code != http.StatusOK || team.User.Role != "owner" {
		t.Fatalf("switch to the team: %d %+v", code, team)
	}
	people := func() int {
		return h.count(t, `SELECT count(*) FROM invites WHERE tenant_id = $1 AND role <> 'service'`, h.tenant)
	}
	before := people()

	// Every person's role: refused, nothing written.
	for _, role := range []string{"owner", "admin", "member"} {
		var refused map[string]string
		code := h.post(t, "/v1/auth/workspaces/invites", map[string]string{"role": role, "email": role + "@example.com"}, &refused, team.Token)
		wantManagedElsewhere(t, "a platform account's "+role+" invitation", code, refused)
	}
	if n := people(); n != before {
		t.Fatalf("refused invitations were written: %d, was %d", n, before)
	}
	// Regenerating the person's code: refused, and the old code stays.
	var refused map[string]string
	code := h.post(t, "/v1/auth/workspaces/invites/"+pending.Invitation.ID.String()+"/regenerate", map[string]string{}, &refused, team.Token)
	wantManagedElsewhere(t, "a platform account's regeneration of a person's code", code, refused)
	if n := h.count(t, `SELECT count(*) FROM invites WHERE id = $1 AND revoked_at IS NULL`, pending.Invitation.ID); n != 1 {
		t.Fatal("a refused regeneration revoked the old code")
	}

	// What is stored stays: listed, revealed.
	var listed struct {
		Invites []store.Invitation `json:"invites"`
	}
	if code := h.get(t, "/v1/auth/workspaces/invites", &listed, team.Token); code != http.StatusOK {
		t.Fatalf("list: %d", code)
	}
	found := false
	for _, inv := range listed.Invites {
		found = found || inv.ID == pending.Invitation.ID && inv.Status == "pending"
	}
	if !found {
		t.Fatalf("the pending invitation is not listed as pending: %+v", listed.Invites)
	}
	var revealed map[string]string
	if code := h.post(t, "/v1/auth/workspaces/invites/"+pending.Invitation.ID.String()+"/reveal", map[string]string{}, &revealed, team.Token); code != http.StatusOK ||
		revealed["invite"] != pending.Invite {
		t.Fatalf("reveal: %d %v", code, revealed)
	}

	// Service invitations stay open: issued, and regenerated.
	invite(h.harness, team.Token, store.RoleService, "a platform account's service invitation")
	var regenerated issued
	if code := h.post(t, "/v1/auth/workspaces/invites/"+service.Invitation.ID.String()+"/regenerate", map[string]string{}, &regenerated, team.Token); code != http.StatusCreated ||
		regenerated.Invitation.Role != store.RoleService {
		t.Fatalf("a platform account's regeneration of a service's code: %d %+v", code, regenerated)
	}

	// A local account of the same team invites people as before.
	_, local := memberAccount(t, h.harness, "local-owner@example.com", "owner")
	invite(h.harness, local, "member", "a local account's invitation")

	// With the provider unset, the platform account does too.
	self := providerUnset(t, h)
	invite(self, team.Token, "member", "a platform account's invitation with the provider unset")

	// The pending code is still redeemed, by a platform account too: what
	// is stored stays (enforce decides redemptions, E3).
	_, first := h.signIn(t, newPerson(t, "joiner@example.com"), 1)
	code, joiner, _, _ := h.createAccount(t, first.Ticket)
	if code != http.StatusOK {
		t.Fatalf("joiner: %d %+v", code, joiner)
	}
	var accepted map[string]string
	if code := h.post(t, "/v1/auth/workspaces/accept-invite", map[string]string{"invite": pending.Invite}, &accepted, joiner.Token); code != http.StatusOK ||
		accepted["tenant_id"] != h.tenant.String() {
		t.Fatalf("redeeming the pending code: %d %v", code, accepted)
	}
	if _, err := h.users.Get(ctx, h.tenant, uuid.MustParse(joiner.User.ID)); err != nil {
		t.Fatalf("the joiner is not a member: %v", err)
	}
}
