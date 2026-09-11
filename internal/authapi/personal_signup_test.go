package authapi_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"whatserver2/internal/authapi"
	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

func publicSignupHarness(t *testing.T) (*harness, *[]string) {
	t.Helper()
	h := newHarness(t)
	h.srv.Close()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if err := h.users.SetInviteEncryptionKey(key); err != nil {
		t.Fatal(err)
	}
	sent := []string{}
	handler := &authapi.Handler{Users: h.users, Keys: h.keys, Devices: store.NewDevices(h.pool), PublicSignup: true, SendSignupVerification: func(_ context.Context, _ string, token string) error { sent = append(sent, token); return nil }}
	mux := http.NewServeMux()
	handler.Mount(mux)
	h.srv = httptest.NewServer(mux)
	t.Cleanup(h.srv.Close)
	return h, &sent
}
func signupMap(t *testing.T, body signupBody) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(body)
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
func methodRequest(t *testing.T, h *harness, method, path string, body any, token string, into any) int {
	t.Helper()
	raw, _ := json.Marshal(body)
	r, err := http.NewRequest(method, h.srv.URL+path, strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+token)
	return h.do(t, r, into)
}
func TestPublicSignupVerificationCreatesOnlyOnePersonal(t *testing.T) {
	h, sent := publicSignupHarness(t)
	var cfg map[string]bool
	if code := h.get(t, "/v1/auth/signup/config", &cfg, ""); code != 200 || !cfg["enabled"] {
		t.Fatalf("config %d %+v", code, cfg)
	}
	if code := h.post(t, "/v1/auth/signup/verification", map[string]string{"email": "person@example.com"}, nil, ""); code != 202 || len(*sent) != 1 {
		t.Fatalf("verification %d %d", code, len(*sent))
	}
	if code := h.post(t, "/v1/auth/signup/verification", map[string]string{"email": "person@example.com"}, nil, ""); code != 202 || len(*sent) != 1 {
		t.Fatal("verification cooldown did not hold")
	}
	body, _ := newAccount(t, "", "wrong@example.com", "proof")
	req := signupMap(t, body)
	req["email_verification_token"] = (*sent)[0]
	req["display_name"] = "Person"
	if code := h.post(t, "/v1/auth/signup", req, nil, ""); code != 403 {
		t.Fatalf("wrong recipient %d", code)
	}
	req["email"] = "person@example.com"
	var signed sessionReply
	if code := h.post(t, "/v1/auth/signup", req, &signed, ""); code != 200 {
		t.Fatalf("signup %d", code)
	}
	spaces, err := h.users.Workspaces(context.Background(), uuid.MustParse(signed.User.ID))
	if err != nil || len(spaces) != 1 || spaces[0].Kind != "personal" || spaces[0].Role != "owner" || spaces[0].Name != "Person" {
		t.Fatalf("spaces %+v %v", spaces, err)
	}
	if code := h.post(t, "/v1/auth/signup", req, nil, ""); code != 403 {
		t.Fatalf("verification replay %d", code)
	}
	var profile store.Profile
	if code := h.get(t, "/v1/auth/profile", &profile, signed.Token); code != 200 || profile.Name != "Person" {
		t.Fatalf("profile %d %+v", code, profile)
	}
	if code := methodRequest(t, h, http.MethodPut, "/v1/auth/profile", map[string]string{"name": "Person Updated", "avatar": ""}, signed.Token, &profile); code != 200 || profile.Name != "Person Updated" {
		t.Fatalf("update profile %d %+v", code, profile)
	}
	var me struct {
		User struct {
			Name   string `json:"name"`
			Avatar string `json:"avatar"`
		}
	}
	if code := h.get(t, "/v1/auth/me", &me, signed.Token); code != 200 || me.User.Name != "Person Updated" {
		t.Fatalf("me did not reload profile %d %+v", code, me)
	}
	if code := h.post(t, "/v1/auth/workspaces/invites", map[string]string{"role": "member", "email": "invitee@example.com"}, nil, signed.Token); code != 409 {
		t.Fatalf("personal admitted invitation %d", code)
	}
	var team store.Workspace
	if code := h.post(t, "/v1/auth/workspaces", map[string]string{"name": "New team"}, &team, signed.Token); code != 201 || team.Kind != "team" || team.Role != "owner" {
		t.Fatalf("team creation %d %+v", code, team)
	}
	spaces, err = h.users.Workspaces(context.Background(), uuid.MustParse(signed.User.ID))
	if err != nil || len(spaces) != 2 {
		t.Fatalf("creating team changed personal: %+v %v", spaces, err)
	}
	if code := h.post(t, "/v1/auth/signup/verification", map[string]string{"email": "person@example.com"}, nil, ""); code != 202 || len(*sent) != 1 {
		t.Fatal("existing identity generated signup mail")
	}

	// The identity is stored in Personal, but a Team's manager must continue
	// seeing its profile after disabling the Team membership.
	owner, _ := memberAccount(t, h, "existing-owner@example.com", "owner")
	invite, err := h.users.CreateInvite(context.Background(), h.tenant, "member", "person@example.com", &owner.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if code := h.post(t, "/v1/auth/workspaces/accept-invite", map[string]string{"invite": invite}, nil, signed.Token); code != 200 {
		t.Fatalf("join team %d", code)
	}
	userID := uuid.MustParse(signed.User.ID)
	if err = h.users.UpdateMember(context.Background(), h.tenant, owner.ID, userID, "member", "disabled"); err != nil {
		t.Fatal(err)
	}
	members, err := h.users.Members(context.Background(), h.tenant, owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	foundDisabled := false
	for _, entry := range members {
		if entry.ID == userID {
			foundDisabled = entry.Status == "disabled" && entry.Name == "Person Updated"
		}
	}
	if !foundDisabled {
		t.Fatal("disabled cross-workspace identity disappeared from directory")
	}
}

func TestSignupInvitationFailureDoesNotSpendCode(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	code, err := h.users.CreateInvite(ctx, h.tenant, "member", "correct@example.com", nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := newAccount(t, code, "wrong@example.com", "proof")
	var failure map[string]any
	if status := h.post(t, "/v1/auth/signup", body, &failure, ""); status != 403 {
		t.Fatalf("wrong email %d", status)
	}
	body.Email = "correct@example.com"
	var signed sessionReply
	if status := h.post(t, "/v1/auth/signup", body, &signed, ""); status != 200 {
		t.Fatalf("valid retry %d", status)
	}
	spaces, err := h.users.Workspaces(ctx, uuid.MustParse(signed.User.ID))
	if err != nil || len(spaces) != 2 {
		t.Fatalf("invited signup spaces %+v %v", spaces, err)
	}
	personal := 0
	for _, w := range spaces {
		if w.Kind == "personal" {
			personal++
		}
		if w.ID == h.tenant && w.Role != "member" {
			t.Fatal("invited role changed")
		}
	}
	if personal != 1 || signed.User.TenantID != h.tenant.String() {
		t.Fatal("invited signup did not keep team selected and personal available")
	}
	duplicate, err := h.users.CreateInvite(ctx, h.tenant, "member", body.Email, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	body.Invite = duplicate
	if status := h.post(t, "/v1/auth/signup", body, nil, ""); status != 409 {
		t.Fatalf("duplicate account %d", status)
	}
	if _, err = h.users.RedeemInvite(ctx, duplicate); err != nil {
		t.Fatalf("duplicate spent invite: %v", err)
	}
	var count int
	if err = h.pool.QueryRow(ctx, `SELECT count(*) FROM tenants WHERE personal_owner_id=$1`, uuid.MustParse(signed.User.ID)).Scan(&count); err != nil || count != 1 {
		t.Fatalf("duplicate signup duplicated personal: %d %v", count, err)
	}
}
func TestInvitationManagementAndCiphertext(t *testing.T) {
	h, _ := publicSignupHarness(t)
	owner, token := memberAccount(t, h, "manager@example.com", "owner")
	var created struct {
		Invite     string           `json:"invite"`
		Invitation store.Invitation `json:"invitation"`
		EmailSent  bool             `json:"email_sent"`
	}
	if code := h.post(t, "/v1/auth/workspaces/invites", map[string]string{"role": "member", "email": "invitee@example.com"}, &created, token); code != 201 {
		t.Fatalf("create %d", code)
	}
	if created.Invite == "" || created.Invitation.Status != "pending" || !created.Invitation.CanReveal || created.EmailSent {
		t.Fatalf("metadata %+v", created)
	}
	var stored []byte
	if err := h.pool.QueryRow(context.Background(), `SELECT secret_ciphertext FROM invites WHERE id=$1`, created.Invitation.ID).Scan(&stored); err != nil || strings.Contains(string(stored), created.Invite) {
		t.Fatal("stored code is not ciphertext")
	}
	var listing struct {
		Invites []store.Invitation `json:"invites"`
	}
	if code := h.get(t, "/v1/auth/workspaces/invites", &listing, token); code != 200 || len(listing.Invites) != 1 {
		t.Fatalf("listing %d %+v", code, listing)
	}
	path := "/v1/auth/workspaces/invites/" + created.Invitation.ID.String()
	var reveal map[string]string
	if code := h.post(t, path+"/reveal", map[string]string{}, &reveal, token); code != 200 || reveal["invite"] != created.Invite {
		t.Fatalf("reveal %d %+v", code, reveal)
	}
	member, memberToken := memberAccount(t, h, "ordinary@example.com", "member")
	_ = member
	if code := h.post(t, path+"/reveal", map[string]string{}, nil, memberToken); code != 403 {
		t.Fatalf("member revealed invite %d", code)
	}
	var regenerated struct {
		Invite     string           `json:"invite"`
		Invitation store.Invitation `json:"invitation"`
	}
	if code := h.post(t, path+"/regenerate", map[string]string{}, &regenerated, token); code != 201 || regenerated.Invite == created.Invite {
		t.Fatalf("regenerate %d %+v", code, regenerated)
	}
	if _, err := h.users.RedeemInvite(context.Background(), created.Invite); err == nil {
		t.Fatal("regenerated old code remains valid")
	}
	if code := methodRequest(t, h, http.MethodDelete, "/v1/auth/workspaces/invites/"+regenerated.Invitation.ID.String(), nil, token, nil); code != 204 {
		t.Fatalf("revoke %d", code)
	}
	if _, err := h.users.RedeemInvite(context.Background(), regenerated.Invite); err == nil {
		t.Fatal("revoked invite redeemable")
	}
	legacy, err := h.users.CreateInvite(context.Background(), h.tenant, "member", "legacy@example.com", &owner.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	hash := shaInvite(t, legacy)
	if _, err = h.pool.Exec(context.Background(), `UPDATE invites SET secret_ciphertext=NULL WHERE invite_id=$1`, hash); err != nil {
		t.Fatal(err)
	}
	if code := h.get(t, "/v1/auth/workspaces/invites", &listing, token); code != 200 {
		t.Fatal(code)
	}
	for _, inv := range listing.Invites {
		if inv.Email == "legacy@example.com" && inv.CanReveal {
			t.Fatal("legacy code advertised recoverable")
		}
	}
}
func shaInvite(t *testing.T, code string) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(code)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return sum[:]
}
func TestConcurrentSignupConsumesInvitationOnce(t *testing.T) {
	h := newHarness(t)
	code, err := h.users.CreateInvite(context.Background(), h.tenant, "member", "race@example.com", nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := newAccount(t, code, "race@example.com", "proof")
	var wg sync.WaitGroup
	statuses := make(chan int, 2)
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); statuses <- h.post(t, "/v1/auth/signup", body, nil, "") }()
	}
	wg.Wait()
	close(statuses)
	successes := 0
	for status := range statuses {
		if status == 200 {
			successes++
		} else if status != 403 && status != 409 {
			t.Fatalf("race status %d", status)
		}
	}
	if successes != 1 {
		t.Fatalf("successful redemptions %d", successes)
	}
	var count int
	if err = h.pool.QueryRow(context.Background(), `SELECT count(*) FROM tenants WHERE kind='personal' AND personal_owner_id=(SELECT user_id FROM user_logins WHERE email='race@example.com')`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("concurrent signup personal count=%d err=%v", count, err)
	}
}

func TestInvitationManagerHierarchyAndWorkspaceIsolation(t *testing.T) {
	h, _ := publicSignupHarness(t)
	owner, ownerToken := memberAccount(t, h, "owner@hierarchy.test", "owner")
	_, adminToken := memberAccount(t, h, "admin@hierarchy.test", "admin")
	code, inv, err := h.users.NewMemberInvitation(context.Background(), h.tenant, owner.ID, "owner", "future-owner@hierarchy.test")
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/auth/workspaces/invites/" + inv.ID.String()
	for _, suffix := range []string{"/reveal", "/regenerate"} {
		if status := h.post(t, path+suffix, map[string]string{}, nil, adminToken); status != 403 {
			t.Fatalf("admin managed owner invite: %d", status)
		}
	}
	if status := methodRequest(t, h, http.MethodDelete, path, nil, adminToken, nil); status != 403 {
		t.Fatalf("admin revoked owner invite: %d", status)
	}
	var list struct {
		Invites []store.Invitation `json:"invites"`
	}
	if status := h.get(t, "/v1/auth/workspaces/invites", &list, adminToken); status != 200 {
		t.Fatal(status)
	}
	for _, entry := range list.Invites {
		if entry.ID == inv.ID && entry.CanReveal {
			t.Fatal("admin offered owner invitation recovery")
		}
	}
	var team store.Workspace
	if status := h.post(t, "/v1/auth/workspaces", map[string]string{"name": "Separate"}, &team, ownerToken); status != 201 {
		t.Fatal(status)
	}
	var other sessionReply
	if status := h.post(t, "/v1/auth/workspaces/session", map[string]string{"tenant_id": team.ID.String()}, &other, ownerToken); status != 200 {
		t.Fatal(status)
	}
	if status := h.post(t, path+"/reveal", map[string]string{}, nil, other.Token); status != 404 {
		t.Fatalf("foreign workspace recovered invite %d", status)
	}
	if status := h.get(t, "/v1/auth/workspaces/invites", &list, other.Token); status != 200 || len(list.Invites) != 0 {
		t.Fatalf("foreign invitation listing %d %+v", status, list)
	}
	if _, err = h.users.RedeemInvite(context.Background(), code); err != nil {
		t.Fatalf("unauthorized requests altered invite %v", err)
	}
}
func TestMemberProfilesAndCurrentDeviceAccess(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	owner, token := memberAccount(t, h, "owner@directory.test", "owner")
	member, _ := memberAccount(t, h, "member@directory.test", "member")
	avatar := profileAvatar(t, 32, 32)
	if _, err := h.users.UpdateProfile(ctx, member.ID, "Support person", avatar); err != nil {
		t.Fatal(err)
	}
	device, err := store.NewDevices(h.pool).Create(ctx, h.tenant.String(), "Support number", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.MustParse(device.ID)
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err = h.keys.CreateArchiveKey(ctx, h.tenant, id, 1, pub); err != nil {
		t.Fatal(err)
	}
	if err = h.keys.PutGrant(ctx, store.Grant{TenantID: h.tenant, DeviceID: id, UserID: member.ID, Epoch: 1, SealedDSK: []byte("sealed")}, &owner.ID); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Members []store.Member `json:"members"`
	}
	if status := h.get(t, "/v1/auth/workspaces/members", &result, token); status != 200 {
		t.Fatal(status)
	}
	found := false
	for _, entry := range result.Members {
		if entry.ID != member.ID {
			continue
		}
		found = true
		if entry.Name != "Support person" || entry.Avatar == "" || len(entry.DeviceAccess) != 1 {
			t.Fatalf("member profile/access %+v", entry)
		}
		access := entry.DeviceAccess[0]
		if access.DeviceID != id || !access.HasKey || !access.Read || !access.Send || access.Manage || access.Label != "Support number" {
			t.Fatalf("member access %+v", access)
		}
	}
	if !found {
		t.Fatal("member not listed")
	}
}
func TestSignupServiceFailurePreservesInvitationAndPersonalAllowsSystems(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	owner, _ := memberAccount(t, h, "owner@systems.test", "owner")
	spaces, err := h.users.Workspaces(ctx, owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	var personal uuid.UUID
	for _, space := range spaces {
		if space.Kind == "personal" {
			personal = space.ID
		}
	}
	if personal == uuid.Nil {
		t.Fatal("personal missing")
	}
	code, err := h.users.CreateInvite(ctx, personal, store.RoleService, "", &owner.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.users.SignupService(ctx, code, "invalid name", pub.Bytes()); err == nil {
		t.Fatal("invalid service accepted")
	}
	service, err := h.users.SignupService(ctx, code, "valid-system", pub.Bytes())
	if err != nil || service.Role != store.RoleService || service.TenantID != personal {
		t.Fatalf("service retry %+v %v", service, err)
	}
	var count int
	if err = h.pool.QueryRow(ctx, `SELECT count(*) FROM tenants WHERE personal_owner_id=$1`, service.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("service received personal workspace")
	}
}
func TestInviteEncryptionConfigurationRejectsBadKey(t *testing.T) {
	h := newHarness(t)
	for _, size := range []int{1, 16, 31, 33} {
		if err := h.users.SetInviteEncryptionKey(make([]byte, size)); err == nil {
			t.Fatalf("accepted %d byte key", size)
		}
	}
	if err := h.users.SetInviteEncryptionKey(nil); err != nil {
		t.Fatal(err)
	}
	if err := h.users.SetInviteEncryptionKey(make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
}
