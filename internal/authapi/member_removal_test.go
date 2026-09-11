package authapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"whatserver2/internal/authapi"
	"whatserver2/internal/pg"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

func removeMember(t *testing.T, h *harness, token, target string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, h.srv.URL+"/v1/auth/workspaces/members/"+target, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck // Response body cleanup in tests.
	var body struct{ Code string }
	if resp.StatusCode >= 400 {
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
	}
	return resp.StatusCode, body.Code
}

func TestRemoveMemberHierarchyAndLastOwner(t *testing.T) {
	for _, tc := range []struct {
		actor, target string
		want          int
		code          string
	}{
		{"owner", "member", 204, ""}, {"owner", "admin", 204, ""}, {"owner", "service", 204, ""},
		{"owner", "owner", 204, ""}, {"admin", "member", 204, ""}, {"admin", "service", 204, ""},
		{"admin", "admin", 403, "not_authorized"}, {"admin", "owner", 403, "not_authorized"},
		{"member", "member", 403, "not_authorized"},
	} {
		t.Run(tc.actor+"/"+tc.target, func(t *testing.T) {
			h := newHarness(t)
			_, token := memberAccount(t, h, "actor@remove.test", tc.actor)
			var target store.User
			if tc.target == "service" {
				var err error
				target, err = h.users.CreateService(context.Background(), h.tenant, "removed-service", make([]byte, 32))
				if err != nil {
					t.Fatal(err)
				}
			} else {
				target, _ = memberAccount(t, h, "target@remove.test", tc.target)
			}
			if status, code := removeMember(t, h, token, target.ID.String()); status != tc.want || code != tc.code {
				t.Fatalf("remove=%d %s, want %d %s", status, code, tc.want, tc.code)
			}
		})
	}
	h := newHarness(t)
	owner, token := memberAccount(t, h, "owner@remove.test", "owner")
	for _, target := range []string{owner.ID.String(), "invalid", uuid.NewString()} {
		want, wantCode := 409, "last_owner"
		if target == "invalid" {
			want, wantCode = 400, "bad_request"
		} else if target != owner.ID.String() {
			want, wantCode = 404, "not_found"
		}
		if status, code := removeMember(t, h, token, target); status != want || code != wantCode {
			t.Fatalf("remove=%d %s, want %d %s", status, code, want, wantCode)
		}
	}
	spaces, err := h.users.Workspaces(context.Background(), owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, space := range spaces {
		if space.Kind == "personal" {
			personal := browserSwitch(t, h, token, space.ID)
			if status, code := removeMember(t, h, personal.Token, owner.ID.String()); status != 409 || code != "last_owner" {
				t.Fatalf("personal owner removed: %d %s", status, code)
			}
		}
	}
	apiKey, err := store.NewAPIKeys(h.pool).Issue(context.Background(), h.tenant.String(), "machine")
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := removeMember(t, h, apiKey, owner.ID.String()); status != 401 {
		t.Fatalf("API token managed members: %d", status)
	}
}

func TestRemoveMemberRevokesOnlyWorkspaceAndRequiresFreshInvite(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	owner, ownerToken := memberAccount(t, h, "owner@remove.test", "owner")
	target, token := memberAccount(t, h, "target@remove.test", "admin")
	spaces, err := h.users.Workspaces(ctx, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	var personal uuid.UUID
	for _, space := range spaces {
		if space.Kind == "personal" {
			personal = space.ID
		}
	}
	personalSession := browserSwitch(t, h, token, personal)
	other := browserSecondWorkspace(t, h, token)
	otherSession := browserSwitch(t, h, token, other)
	device := protectedNumber(t, h, owner, target)
	if err := h.users.SetReaderMode(ctx, h.tenant, target.ID, device, wa.ModeActive); err != nil {
		t.Fatal(err)
	}
	keys := store.NewAPIKeys(h.pool)
	ownedKey, err := keys.IssueActingAs(ctx, h.tenant.String(), "created by target", store.ScopeFull, &target.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	unrelatedKey, err := keys.IssueActingAs(ctx, h.tenant.String(), "owner key", store.ScopeRead, &owner.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	personalKey, err := keys.IssueActingAs(ctx, personal.String(), "personal key", store.ScopeRead, &target.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := h.users.InviteMember(ctx, h.tenant, target.ID, "member", "guest@remove.test")
	if err != nil {
		t.Fatal(err)
	}
	addressed, err := h.users.InviteMember(ctx, h.tenant, owner.ID, "member", target.Email)
	if err != nil {
		t.Fatal(err)
	}
	unrelatedInvite, err := h.users.InviteMember(ctx, h.tenant, owner.ID, "member", "other@remove.test")
	if err != nil {
		t.Fatal(err)
	}
	if status, code := removeMember(t, h, ownerToken, target.ID.String()); status != 204 {
		t.Fatalf("remove=%d %s", status, code)
	}
	if _, _, err := h.users.ActiveSession(ctx, token); !errors.Is(err, store.ErrNoSession) {
		t.Fatalf("removed workspace token survived: %v", err)
	}
	for _, kept := range []string{personalSession.Token, otherSession.Token} {
		if _, _, err := h.users.ActiveSession(ctx, kept); err != nil {
			t.Fatalf("other workspace session was affected: %v", err)
		}
	}
	if _, err := keys.VerifyScoped(ctx, ownedKey); !errors.Is(err, store.ErrInvalidKey) {
		t.Fatalf("creator's unbound token survived: %v", err)
	}
	for _, kept := range []string{unrelatedKey, personalKey} {
		if _, err := keys.VerifyScoped(ctx, kept); err != nil {
			t.Fatalf("unrelated key revoked: %v", err)
		}
	}
	for _, revoked := range []string{issued, addressed} {
		if _, err := h.users.RedeemInvite(ctx, revoked); !errors.Is(err, store.ErrInviteInvalid) {
			t.Fatalf("old invitation survived: %v", err)
		}
	}
	if _, err := h.users.RedeemInvite(ctx, unrelatedInvite); err != nil {
		t.Fatalf("unrelated invitation affected: %v", err)
	}
	members, err := h.users.Members(ctx, h.tenant, owner.ID)
	if err != nil || len(members) != 1 || members[0].ID != owner.ID {
		t.Fatalf("removed member remained listed: %+v %v", members, err)
	}
	if err := h.users.UpdateMember(ctx, h.tenant, owner.ID, target.ID, "member", "active"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("removed member was reactivated: %v", err)
	}
	for _, table := range []string{"workspace_memberships", "device_permissions", "device_key_grants", "reader_preferences"} {
		if err := pg.InTenantTx(ctx, h.pool, h.tenant.String(), func(tx pgx.Tx) error {
			var count int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE tenant_id=$1 AND user_id=$2`, h.tenant, target.ID).Scan(&count); err != nil {
				return err
			}
			if count != 0 {
				t.Errorf("%s retained target access", table)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	login, err := h.users.Authenticate(ctx, target.Email, "proof")
	if err != nil || login.TenantID != personal || login.ID != target.ID {
		t.Fatalf("personal account was lost: %+v %v", login, err)
	}
	fresh, err := h.users.InviteMember(ctx, h.tenant, owner.ID, "member", target.Email)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.users.AcceptWorkspaceInvite(ctx, login, fresh); err != nil {
		t.Fatalf("fresh invitation cannot restore membership: %v", err)
	}
	if _, _, err := h.users.ActiveSession(ctx, token); !errors.Is(err, store.ErrNoSession) {
		t.Fatalf("rejoin revived an old session: %v", err)
	}
	grants, err := h.keys.GrantsFor(ctx, h.tenant, target.ID)
	if err != nil || len(grants) != 0 {
		t.Fatalf("rejoin restored old grants: %v %v", grants, err)
	}
}

func TestRemoveLastReaderRollsBackBeforeRevokingAnything(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_, token := memberAccount(t, h, "owner@remove.test", "owner")
	target, targetToken := memberAccount(t, h, "only-reader@remove.test", "member")
	device := protectedNumber(t, h, target)
	if status, code := removeMember(t, h, token, target.ID.String()); status != 409 || code != "last_device_reader" {
		t.Fatalf("last reader removed: %d %s", status, code)
	}
	if _, _, err := h.users.ActiveSession(ctx, targetToken); err != nil {
		t.Fatalf("failed removal revoked session: %v", err)
	}
	permission, err := h.users.DevicePermission(ctx, h.tenant, target.ID, device)
	if err != nil || !permission.Allows(store.ActionRead) {
		t.Fatalf("failed removal changed grants: %+v %v", permission, err)
	}
}

func TestRemoveMemberPreservesHistoricalAttributionWithoutProfileAccess(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	owner, _ := memberAccount(t, h, "owner@history.test", "owner")
	// Start this identity in another workspace so the legacy credential-routing
	// policy cannot hide a regression in former-member attribution.
	var home uuid.UUID
	if err := h.pool.QueryRow(ctx, `INSERT INTO tenants(name) VALUES('other home') RETURNING id`).Scan(&home); err != nil {
		t.Fatal(err)
	}
	target, err := h.users.Create(ctx, store.NewUser{TenantID: home, Email: "former@history.test", Role: "owner", AuthKey: "proof", KDFSalt: make([]byte, 16), KDFParams: store.DefaultKDFParams(), PublicKey: make([]byte, 32), WrappedUSK: []byte("wrapped")})
	if err != nil {
		t.Fatal(err)
	}
	invite, err := h.users.InviteMember(ctx, h.tenant, owner.ID, "admin", target.Email)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.users.AcceptWorkspaceInvite(ctx, target, invite); err != nil {
		t.Fatal(err)
	}
	device := protectedNumber(t, h, target)
	if err := h.keys.PutGrant(ctx, store.Grant{TenantID: h.tenant, DeviceID: device, UserID: owner.ID, Epoch: 1, SealedDSK: []byte("backup")}, &target.ID); err != nil {
		t.Fatal(err)
	}
	keys := store.NewAPIKeys(h.pool)
	key, err := keys.IssueActingAs(ctx, h.tenant.String(), "historical key", store.ScopeRead, &target.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.users.RemoveMember(ctx, h.tenant, owner.ID, target.ID); err != nil {
		t.Fatal(err)
	}
	listed, err := keys.List(ctx, h.tenant.String())
	if err != nil || len(listed) != 1 || listed[0].CreatedBy != target.Email || !strings.HasPrefix(key, listed[0].Prefix) || listed[0].RevokedAt.IsZero() {
		t.Fatalf("historical token attribution lost: %+v %v", listed, err)
	}
	readers, err := h.keys.Readers(ctx, h.tenant, device)
	if err != nil || len(readers) != 1 || readers[0].GrantedBy != target.Email {
		t.Fatalf("historical key grant attribution lost: %+v %v", readers, err)
	}
	for _, scope := range []uuid.UUID{h.tenant, home} {
		if err := pg.InTenantTx(ctx, h.pool, scope.String(), func(tx pgx.Tx) error {
			var profiles, history int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM users WHERE id=$1`, target.ID).Scan(&profiles); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM workspace_member_history WHERE tenant_id=$1 AND user_id=$2`, h.tenant, target.ID).Scan(&history); err != nil {
				return err
			}
			if scope == h.tenant && (profiles != 0 || history != 1) || scope == home && history != 0 {
				t.Errorf("history/profile isolation failed: scope=%s profiles=%d history=%d", scope, profiles, history)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRemoveMemberWakesAccessChecksOnlyAfterSuccess(t *testing.T) {
	h := newHarness(t)
	owner, token := memberAccount(t, h, "owner@notify.test", "owner")
	target, _ := memberAccount(t, h, "member@notify.test", "member")
	var changes atomic.Int32
	mux := http.NewServeMux()
	(&authapi.Handler{Users: h.users, AccessChanged: func() { changes.Add(1) }}).Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	h.srv = srv
	if status, _ := removeMember(t, h, token, owner.ID.String()); status != 409 || changes.Load() != 0 {
		t.Fatal("failed removal announced a change")
	}
	if status, _ := removeMember(t, h, token, target.ID.String()); status != 204 || changes.Load() != 1 {
		t.Fatal("successful removal did not wake access validation")
	}
}

func TestRemoveDisabledAndServiceMemberships(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	owner, token := memberAccount(t, h, "owner@removed-service.test", "owner")
	disabled, _ := memberAccount(t, h, "disabled@removed-service.test", "member")
	if err := h.users.UpdateMember(ctx, h.tenant, owner.ID, disabled.ID, "member", "disabled"); err != nil {
		t.Fatal(err)
	}
	if status, code := removeMember(t, h, token, disabled.ID.String()); status != 204 {
		t.Fatalf("disabled removal: %d %s", status, code)
	}
	spaces, err := h.users.Workspaces(ctx, owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, space := range spaces {
		if space.Kind != "personal" {
			continue
		}
		personal := browserSwitch(t, h, token, space.ID)
		service, err := h.users.CreateService(ctx, space.ID, "personal-service", make([]byte, 32))
		if err != nil {
			t.Fatal(err)
		}
		keys := store.NewAPIKeys(h.pool)
		key, err := keys.IssueActingAs(ctx, space.ID.String(), "service", store.ScopeRead, &owner.ID, &service.ID)
		if err != nil {
			t.Fatal(err)
		}
		if status, code := removeMember(t, h, personal.Token, service.ID.String()); status != 204 {
			t.Fatalf("personal service removal: %d %s", status, code)
		}
		if _, err := keys.VerifyScoped(ctx, key); !errors.Is(err, store.ErrInvalidKey) {
			t.Fatalf("removed service token survived: %v", err)
		}
		if _, err := keys.IssueActingAs(ctx, space.ID.String(), "again", store.ScopeRead, &owner.ID, &service.ID); err == nil {
			t.Fatal("removed service received a new token")
		}
	}
}

func TestConcurrentOwnerRemovalsLeaveOneOwner(t *testing.T) {
	h := newHarness(t)
	a, _ := memberAccount(t, h, "a@owner-removal.test", "owner")
	b, _ := memberAccount(t, h, "b@owner-removal.test", "owner")
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, user := range []store.User{a, b} {
		go func() {
			<-start
			results <- h.users.RemoveMember(context.Background(), h.tenant, user.ID, user.ID)
		}()
	}
	close(start)
	allowed, blocked := 0, 0
	for range 2 {
		err := <-results
		if err == nil {
			allowed++
		} else if errors.Is(err, store.ErrLastOwner) {
			blocked++
		} else {
			t.Fatal(err)
		}
	}
	if allowed != 1 || blocked != 1 {
		t.Fatalf("removals: allowed=%d blocked=%d", allowed, blocked)
	}
}

func TestMemberRemovalWinsAgainstSessionIssuanceAlreadyInFlight(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	owner, _ := memberAccount(t, h, "owner@session-removal.test", "owner")
	target, _ := memberAccount(t, h, "target@session-removal.test", "member")
	blocker, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Rollback(context.Background()) }()
	var blockerPID int
	if err := blocker.QueryRow(ctx, `SELECT pg_backend_pid() FROM tenants WHERE id=$1 FOR UPDATE`, h.tenant).Scan(&blockerPID); err != nil {
		t.Fatal(err)
	}
	removed := make(chan error, 1)
	go func() { removed <- h.users.RemoveMember(ctx, h.tenant, owner.ID, target.ID) }()
	waitBrowserBlocked(t, ctx, h.pool, blockerPID, 1)
	issued := make(chan error, 1)
	go func() {
		_, _, err := h.users.StartSession(ctx, target, "login already in flight")
		issued <- err
	}()
	waitBrowserBlocked(t, ctx, h.pool, blockerPID, 2)
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-removed; err != nil {
		t.Fatal(err)
	}
	if err := <-issued; !errors.Is(err, store.ErrNoSession) {
		t.Fatalf("a session was minted after membership removal: %v", err)
	}
}
