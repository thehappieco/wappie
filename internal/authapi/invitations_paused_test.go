package authapi_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/authapi"
	"whatserver2/internal/membership"
	"whatserver2/internal/store"
)

// TB53 (the plan's DB6, the owner's 15.2): person invitations into a team
// a document names are closed, at issue, at regeneration, at redemption
// and in the operator's whatserverd invite (CreateInvite), keyed on the
// record alone: in mode off after an observe and at observe, with the
// contract's routes wired with no transport and without them. A code
// issued before the record stays unspent; service invitations, a content
// consent's provisional one included, are issued and redeemed; a personal
// workspace and a team no document names are as before; contract status
// counts each team's pending person invitations.
func TestPersonInvitationsClosed(t *testing.T) {
	for _, mode := range []string{"off", "observe"} {
		for _, wired := range []bool{false, true} {
			name := mode + "/no contract"
			if wired {
				name = mode + "/contract without a transport"
			}
			t.Run(name, func(t *testing.T) { personInvitationsClosed(t, mode, wired) })
		}
	}
}

func personInvitationsClosed(t *testing.T, mode string, wired bool) {
	h := newHarness(t)
	h.srv.Close()
	ctx := context.Background()
	handler := &authapi.Handler{Users: h.users, Keys: h.keys, Devices: store.NewDevices(h.pool), Storage: store.NewStorage(h.pool)}
	if wired {
		m := &membership.Members{Contract: store.NewContract(h.pool), ModeCache: -1, Log: slog.New(slog.DiscardHandler)}
		handler.Membership, handler.Freshness = m, m
	}
	mux := http.NewServeMux()
	handler.Mount(mux)
	h.srv = httptest.NewServer(mux)
	t.Cleanup(h.srv.Close)

	owner, token := memberAccount(t, h, "owner@example.com", "owner")
	var other store.Workspace
	if code := h.post(t, "/v1/auth/workspaces", map[string]string{"name": "Piloto A"}, &other, token); code != http.StatusCreated {
		t.Fatalf("an unnamed team: %d", code)
	}
	// Issued before the team is recorded: a person's code, one to
	// regenerate, and a service's.
	before, err := h.users.CreateInvite(ctx, h.tenant, "member", "", &owner.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var pending struct {
		Invite     string           `json:"invite"`
		Invitation store.Invitation `json:"invitation"`
	}
	if code := h.post(t, "/v1/auth/workspaces/invites", map[string]string{"role": "admin"}, &pending, token); code != http.StatusCreated {
		t.Fatalf("an invitation before the record: %d", code)
	}
	serviceBefore, err := h.users.CreateInvite(ctx, h.tenant, store.RoleService, "", &owner.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// A document names the team; the mode is the test's.
	if _, err := h.pool.Exec(ctx, `INSERT INTO contract_workspaces (workspace_id, kind) VALUES ($1, 'team')`, h.tenant); err != nil {
		t.Fatal(err)
	}
	state := `UPDATE contract_state SET mode = 'observe', events_from = clock_timestamp(), events_paused_at = NULL`
	if mode == "off" {
		state = `UPDATE contract_state SET mode = 'off', events_from = clock_timestamp() - interval '1 hour', events_paused_at = clock_timestamp()`
	}
	if _, err := h.pool.Exec(ctx, state); err != nil {
		t.Fatal(err)
	}

	// Issuing, every person role, and regenerating: 409 invitations_paused.
	for _, role := range []string{"owner", "admin", "member"} {
		var refused map[string]string
		if code := h.post(t, "/v1/auth/workspaces/invites", map[string]string{"role": role, "email": role + "@example.com"}, &refused, token); code != http.StatusConflict || refused["code"] != "invitations_paused" {
			t.Fatalf("a %s invitation: %d %v", role, code, refused)
		}
	}
	var refused map[string]string
	if code := h.post(t, "/v1/auth/workspaces/invites/"+pending.Invitation.ID.String()+"/regenerate", map[string]string{}, &refused, token); code != http.StatusConflict || refused["code"] != "invitations_paused" {
		t.Fatalf("a regeneration: %d %v", code, refused)
	}
	var revoked *time.Time
	if err := h.pool.QueryRow(ctx, `SELECT revoked_at FROM invites WHERE id = $1`, pending.Invitation.ID).Scan(&revoked); err != nil || revoked != nil {
		t.Fatalf("the regenerated invitation was revoked: %v %v", revoked, err)
	}
	if _, err := h.users.CreateInvite(ctx, h.tenant, "member", "", nil, time.Hour); !errors.Is(err, store.ErrInvitationsPaused) {
		t.Fatalf("the operator's invite: %v", err)
	}
	var issued int
	if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM invites WHERE tenant_id = $1 AND role <> 'service'`, h.tenant).Scan(&issued); err != nil || issued != 2 {
		t.Fatalf("%d person invitations, want the two from before: %v", issued, err)
	}

	// Redeeming the code from before: by a signed-in person, by an
	// invited sign-up, by RedeemInvite; it stays unspent each time.
	var elsewhere uuid.UUID
	if err := h.pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('elsewhere') RETURNING id`).Scan(&elsewhere); err != nil {
		t.Fatal(err)
	}
	_, joiner := memberAccountIn(t, h, elsewhere, "joiner@example.com")
	if code := h.post(t, "/v1/auth/workspaces/accept-invite", map[string]string{"invite": before}, &refused, joiner); code != http.StatusConflict || refused["code"] != "invitations_paused" {
		t.Fatalf("accepting: %d %v", code, refused)
	}
	body, _ := newAccount(t, before, "invited@example.com", "proof")
	if code := h.post(t, "/v1/auth/signup", body, &refused, ""); code != http.StatusConflict || refused["code"] != "invitations_paused" {
		t.Fatalf("an invited sign-up: %d %v", code, refused)
	}
	if _, err := h.users.RedeemInvite(ctx, before); !errors.Is(err, store.ErrInvitationsPaused) {
		t.Fatalf("RedeemInvite: %v", err)
	}
	var completed *time.Time
	if err := h.pool.QueryRow(ctx, `SELECT completed_at FROM invites WHERE invite_id = $1`, shaInvite(t, before)).Scan(&completed); err != nil || completed != nil {
		t.Fatalf("the paused code was spent: %v %v", completed, err)
	}
	var invited int
	if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE email = 'invited@example.com'`).Scan(&invited); err != nil || invited != 0 {
		t.Fatalf("the invited sign-up made an account: %d %v", invited, err)
	}

	// Service invitations stay open: a standing one, issued and
	// registered, the one from before registered, and a provisional one.
	var service struct {
		Invite string `json:"invite"`
	}
	if code := h.post(t, "/v1/auth/workspaces/invites", map[string]string{"role": store.RoleService}, &service, token); code != http.StatusCreated {
		t.Fatalf("a service invitation: %d", code)
	}
	for i, code := range []string{service.Invite, serviceBefore} {
		if status := h.post(t, "/v1/auth/signup", map[string]string{"invite": code, "name": "erp-" + string(rune('a'+i)), "public_key": publicKey(t)}, nil, ""); status != http.StatusOK {
			t.Fatalf("registering service %d: %d", i, status)
		}
	}
	if code := h.post(t, "/v1/auth/workspaces/invites", map[string]any{"role": store.RoleService, "provisional": true}, &service, token); code != http.StatusCreated {
		t.Fatalf("a provisional invitation: %d", code)
	}
	if status := h.post(t, "/v1/auth/signup", map[string]string{"invite": service.Invite, "name": "reader", "public_key": publicKey(t)}, nil, ""); status != http.StatusOK {
		t.Fatalf("registering the provisional service: %d", status)
	}

	// A team no document names is as before; a personal one too.
	otherToken := sessionIn(t, h, owner, other.ID)
	if code := h.post(t, "/v1/auth/workspaces/invites", map[string]string{"role": "member"}, nil, otherToken); code != http.StatusCreated {
		t.Fatalf("an unnamed team's invitation: %d", code)
	}
	unnamed, err := h.users.CreateInvite(ctx, other.ID, "member", "", nil, time.Hour)
	if err != nil {
		t.Fatalf("the operator's invite into an unnamed team: %v", err)
	}
	if code := h.post(t, "/v1/auth/workspaces/accept-invite", map[string]string{"invite": unnamed}, nil, joiner); code != http.StatusOK {
		t.Fatalf("an unnamed team's code: %d", code)
	}
	if _, err := h.users.CreateInvite(ctx, personalOf(t, h, owner.ID), "member", "", nil, time.Hour); !errors.Is(err, store.ErrPersonalWorkspace) {
		t.Fatalf("a personal workspace: %v", err)
	}

	// contract status counts them, and says which team pauses them.
	st, err := store.NewContract(h.pool).Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := map[uuid.UUID]store.ContractTeamInvitations{}
	for _, i := range st.Invitations {
		got[i.Team] = i
	}
	if i := got[h.tenant]; i.Pending != 2 || !i.Recorded {
		t.Fatalf("the recorded team's count: %+v", st.Invitations)
	}
	if i := got[other.ID]; i.Pending != 1 || i.Recorded {
		t.Fatalf("the unnamed team's count: %+v", st.Invitations)
	}
}

// memberAccountIn is a person whose home is tenant, signed in there.
func memberAccountIn(t *testing.T, h *harness, tenant uuid.UUID, email string) (store.User, string) {
	t.Helper()
	u, err := h.users.Create(context.Background(), store.NewUser{TenantID: tenant, Email: email, Role: "member", AuthKey: "proof",
		KDFSalt: make([]byte, 16), KDFParams: store.DefaultKDFParams(), PublicKey: make([]byte, 32), WrappedUSK: []byte("wrapped")})
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := h.users.StartSession(context.Background(), u, "test")
	if err != nil {
		t.Fatal(err)
	}
	return u, token
}

// sessionIn is user's session in another workspace of theirs.
func sessionIn(t *testing.T, h *harness, user store.User, tenant uuid.UUID) string {
	t.Helper()
	user.TenantID = tenant
	user.Role = "owner"
	token, _, err := h.users.StartSession(context.Background(), user, "test")
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// personalOf is user's personal workspace.
func personalOf(t *testing.T, h *harness, user uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := h.pool.QueryRow(context.Background(), `SELECT id FROM tenants WHERE kind = 'personal' AND personal_owner_id = $1`, user).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func publicKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}
