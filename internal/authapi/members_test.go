package authapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

func memberAccount(t *testing.T, h *harness, email, role string) (store.User, string) {
	t.Helper()
	u, err := h.users.Create(context.Background(), store.NewUser{TenantID: h.tenant, Email: email, Role: role, AuthKey: "proof", KDFSalt: make([]byte, 16), KDFParams: store.DefaultKDFParams(), PublicKey: make([]byte, 32), WrappedUSK: []byte("wrapped")})
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := h.users.StartSession(context.Background(), u, "test")
	if err != nil {
		t.Fatal(err)
	}
	return u, token
}

func setMember(t *testing.T, h *harness, token string, id uuid.UUID, role, status string) int {
	t.Helper()
	body, err := json.Marshal(map[string]string{"role": role, "status": status})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPut, h.srv.URL+"/v1/auth/workspaces/members/"+id.String(), bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	return h.do(t, req, nil)
}

func TestMemberManagementPermissions(t *testing.T) {
	h := newHarness(t)
	owner, ownerToken := memberAccount(t, h, "owner@example.com", "owner")
	admin, adminToken := memberAccount(t, h, "admin@example.com", "admin")
	member, memberToken := memberAccount(t, h, "member@example.com", "member")
	for _, tc := range []struct {
		name, token  string
		target       uuid.UUID
		role, status string
		want         int
	}{
		{"last owner demotion", ownerToken, owner.ID, "admin", "active", 409},
		{"last owner disable", ownerToken, owner.ID, "owner", "disabled", 409},
		{"admin cannot edit owner", adminToken, owner.ID, "member", "active", 403},
		{"admin cannot promote self", adminToken, admin.ID, "owner", "active", 403},
		{"admin cannot promote member", adminToken, member.ID, "admin", "active", 403},
		{"member cannot edit", memberToken, member.ID, "admin", "active", 403},
		{"no role conversion", ownerToken, member.ID, "service", "active", 400},
		{"unknown role", ownerToken, member.ID, "superuser", "active", 400},
		{"unknown target", ownerToken, uuid.New(), "member", "active", 404},
		{"admin disables member", adminToken, member.ID, "member", "disabled", 204},
		{"owner restores member", ownerToken, member.ID, "member", "active", 204},
		{"owner promotes member", ownerToken, member.ID, "admin", "active", 204},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if code := setMember(t, h, tc.token, tc.target, tc.role, tc.status); code != tc.want {
				t.Fatalf("status=%d want=%d", code, tc.want)
			}
		})
	}
	if code := h.get(t, "/v1/auth/workspaces/members", nil, memberToken); code != 401 {
		t.Fatalf("old member token retained access: %d", code)
	}
	if code := h.get(t, "/v1/auth/workspaces/members", nil, adminToken); code != 200 {
		t.Fatalf("admin list: %d", code)
	}
	for _, tc := range []struct {
		token, role string
		want        int
	}{{adminToken, "owner", 403}, {adminToken, "admin", 403}, {adminToken, "member", 201}, {adminToken, "service", 201}, {ownerToken, "owner", 201}} {
		if code := h.post(t, "/v1/auth/workspaces/invites", map[string]string{"role": tc.role}, nil, tc.token); code != tc.want {
			t.Fatalf("invite %s: %d", tc.role, code)
		}
	}
}

func TestConcurrentOwnerDemotionsLeaveOneOwner(t *testing.T) {
	h := newHarness(t)
	a, _ := memberAccount(t, h, "a@example.com", "owner")
	b, _ := memberAccount(t, h, "b@example.com", "owner")
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, user := range []store.User{a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- h.users.UpdateMember(context.Background(), h.tenant, user.ID, user.ID, "member", "active")
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	ok, blocked := 0, 0
	for err := range results {
		if err == nil {
			ok++
		} else if errors.Is(err, store.ErrLastOwner) {
			blocked++
		} else {
			t.Fatal(err)
		}
	}
	if ok != 1 || blocked != 1 {
		t.Fatalf("demotions: ok=%d blocked=%d", ok, blocked)
	}
}

func TestSoleMemberOwnerProtectionIsVisibleAndEnforced(t *testing.T) {
	h := newHarness(t)
	owner, token := memberAccount(t, h, "only@example.com", "owner")
	var result struct {
		Members []store.Member `json:"members"`
	}
	if code := h.get(t, "/v1/auth/workspaces/members", &result, token); code != 200 || len(result.Members) != 1 || !result.Members[0].LastOwner {
		t.Fatalf("sole owner was not identified: %d %+v", code, result)
	}
	if code := setMember(t, h, token, owner.ID, "owner", "disabled"); code != 409 {
		t.Fatalf("sole owner disabled: %d", code)
	}
	if code := setMember(t, h, token, owner.ID, "member", "active"); code != 409 {
		t.Fatalf("sole owner demoted: %d", code)
	}
	backup, _ := memberAccount(t, h, "backup@example.com", "owner")
	if code := h.get(t, "/v1/auth/workspaces/members", &result, token); code != 200 || len(result.Members) != 2 || result.Members[0].LastOwner || result.Members[1].LastOwner {
		t.Fatalf("backup did not lift UI protection: %d %+v", code, result)
	}
	if code := setMember(t, h, token, backup.ID, "owner", "disabled"); code != 204 {
		t.Fatalf("could not disable backup: %d", code)
	}
	if code := h.get(t, "/v1/auth/workspaces/members", &result, token); code != 200 || !result.Members[0].LastOwner || result.Members[1].LastOwner {
		t.Fatalf("disabled backup counted as active owner: %d %+v", code, result)
	}
}

func TestDisableMemberIsWorkspaceScopedAndStripsAccess(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	owner, _ := memberAccount(t, h, "owner@example.com", "owner")
	member, token := memberAccount(t, h, "reader@example.com", "member")
	var other uuid.UUID
	if err := h.pool.QueryRow(ctx, `INSERT INTO tenants(name) VALUES ('other') RETURNING id`).Scan(&other); err != nil {
		t.Fatal(err)
	}
	invite, err := h.users.CreateInvite(ctx, other, "member", "", nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.users.AcceptWorkspaceInvite(ctx, member, invite); err != nil {
		t.Fatal(err)
	}
	otherMember, err := h.users.Get(ctx, other, member.ID)
	if err != nil {
		t.Fatal(err)
	}
	otherToken, _, err := h.users.StartSession(ctx, otherMember, "other")
	if err != nil {
		t.Fatal(err)
	}
	device, err := store.NewDevices(h.pool).Create(ctx, h.tenant.String(), "test", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	deviceID := uuid.MustParse(device.ID)
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := h.keys.CreateArchiveKey(ctx, h.tenant, deviceID, 1, pub); err != nil {
		t.Fatal(err)
	}
	grant := store.Grant{TenantID: h.tenant, DeviceID: deviceID, UserID: member.ID, Epoch: 1, SealedDSK: []byte("sealed")}
	if err := h.keys.PutGrant(ctx, grant, &owner.ID); err != nil {
		t.Fatal(err)
	}
	if err := h.users.UpdateMember(ctx, h.tenant, owner.ID, member.ID, "member", "disabled"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.users.ActiveSession(ctx, token); err == nil {
		t.Fatal("disabled membership session survived")
	}
	if _, _, err := h.users.ActiveSession(ctx, otherToken); err != nil {
		t.Fatalf("other workspace affected: %v", err)
	}
	if err := h.keys.PutGrant(ctx, grant, &owner.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("disabled member received grant: %v", err)
	}
	if err := h.users.UpdateMember(ctx, h.tenant, owner.ID, member.ID, "member", "active"); err != nil {
		t.Fatal(err)
	}
	grants, err := h.keys.GrantsFor(ctx, h.tenant, member.ID)
	if err != nil || len(grants) != 0 {
		t.Fatalf("grants restored: %+v %v", grants, err)
	}
	if _, _, err := h.users.ActiveSession(ctx, token); err == nil {
		t.Fatal("reactivation revived old session")
	}
	// A UUID from another workspace cannot be managed through this one.
	if err := h.users.UpdateMember(ctx, other, owner.ID, member.ID, "member", "disabled"); !errors.Is(err, store.ErrMembershipForbidden) {
		t.Fatalf("cross-workspace mutation: %v", err)
	}
}

func TestDisabledServiceCannotRetainOrMintTokens(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	owner, _ := memberAccount(t, h, "owner@example.com", "owner")
	service, err := h.users.CreateService(ctx, h.tenant, "erp", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	keys := store.NewAPIKeys(h.pool)
	key, err := keys.IssueActingAs(ctx, h.tenant.String(), "erp", store.ScopeRead, &owner.ID, &service.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.users.UpdateMember(ctx, h.tenant, owner.ID, service.ID, "service", "disabled"); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.VerifyScoped(ctx, key); !errors.Is(err, store.ErrInvalidKey) {
		t.Fatalf("disabled service token survived: %v", err)
	}
	if _, err := keys.IssueActingAs(ctx, h.tenant.String(), "new", store.ScopeRead, &owner.ID, &service.ID); !errors.Is(err, store.ErrMembershipForbidden) {
		t.Fatalf("minted for disabled service: %v", err)
	}
	if err := h.users.UpdateMember(ctx, h.tenant, owner.ID, service.ID, "service", "active"); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.VerifyScoped(ctx, key); !errors.Is(err, store.ErrInvalidKey) {
		t.Fatalf("reactivation restored revoked key: %v", err)
	}
}

func TestDemotionInvalidatesOutstandingInvitations(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	owner, _ := memberAccount(t, h, "owner@example.com", "owner")
	admin, _ := memberAccount(t, h, "admin@example.com", "admin")
	invite, err := h.users.InviteMember(ctx, h.tenant, admin.ID, "member", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.users.UpdateMember(ctx, h.tenant, owner.ID, admin.ID, "member", "active"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.users.RedeemInvite(ctx, invite); !errors.Is(err, store.ErrInviteInvalid) {
		t.Fatalf("demoted issuer invitation survived: %v", err)
	}
	if _, err := h.users.InviteMember(ctx, h.tenant, admin.ID, "member", ""); !errors.Is(err, store.ErrMembershipForbidden) {
		t.Fatalf("demoted issuer created invitation: %v", err)
	}
}
