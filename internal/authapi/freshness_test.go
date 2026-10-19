package authapi_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/authapi"
	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/membership"
	"whatserver2/internal/pg"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// Test 45, the routes' part (the plan's 4.12): raising a flag, withholding
// Read, and a standing service account's invitation and registration ask
// the freshness hook, with each party's mode, before the act's store
// transaction (a NOWAIT probe from inside the hook finds the workspace
// unlocked); acts that are none of these never ask; and with the enforce
// flag a refusal is 503 memberships_unconfirmed and nothing changes.

type routeCall struct {
	kind, act      string
	tenant         uuid.UUID
	parties        []membership.Party
	device, losing uuid.UUID
	probe          error
}

type routeRecorder struct {
	pool   *pgxpool.Pool
	mu     sync.Mutex
	calls  []routeCall
	refuse error
}

func (r *routeRecorder) record(ctx context.Context, c routeCall) error {
	c.probe = pg.InTenantTx(ctx, r.pool, c.tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT 1 FROM tenants WHERE id = $1 FOR UPDATE NOWAIT`, c.tenant)
		return err
	})
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, c)
	return r.refuse
}

func (r *routeRecorder) RequireFresh(ctx context.Context, act string, tenant uuid.UUID, parties ...membership.Party) (membership.Verdict, error) {
	return membership.Verdict{}, r.record(ctx, routeCall{kind: "fresh", act: act, tenant: tenant, parties: parties})
}

func (r *routeRecorder) RequireWidening(ctx context.Context, act string, tenant uuid.UUID, parties ...membership.Party) (membership.Verdict, error) {
	return membership.Verdict{}, r.record(ctx, routeCall{kind: "widening", act: act, tenant: tenant, parties: parties})
}

func (r *routeRecorder) RequireBackups(ctx context.Context, act string, tenant, device, losing uuid.UUID) (membership.Verdict, error) {
	return membership.Verdict{}, r.record(ctx, routeCall{kind: "backups", act: act, tenant: tenant, device: device, losing: losing})
}

func (r *routeRecorder) RequireMover(context.Context, uuid.UUID, uuid.UUID) (membership.Verdict, error) {
	panic("no route moves a number")
}

// since are the calls after the first n.
func (r *routeRecorder) since(n int) []routeCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.calls[n:])
}

func (r *routeRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

// one checks that the calls since n are exactly one, for act in tenant
// with these parties, its probe unlocked: the minute rule's, or a widening
// act's (every route's other act widens access, gated at home too).
func (r *routeRecorder) one(t *testing.T, n int, act string, tenant uuid.UUID, parties ...membership.Party) routeCall {
	t.Helper()
	calls := r.since(n)
	if len(calls) != 1 || calls[0].act != act || calls[0].tenant != tenant || !slices.Equal(calls[0].parties, parties) || calls[0].probe != nil {
		t.Fatalf("%s: %+v, want one with %+v", act, calls, parties)
	}
	if want := "widening"; calls[0].kind != "backups" && calls[0].kind != want {
		t.Fatalf("%s asked %s, want %s", act, calls[0].kind, want)
	}
	return calls[0]
}

func (r *routeRecorder) none(t *testing.T, n int, what string) {
	t.Helper()
	if calls := r.since(n); len(calls) != 0 {
		t.Fatalf("%s asked the hook: %+v", what, calls)
	}
}

func TestFreshnessHook(t *testing.T) {
	h := newHarness(t)
	h.srv.Close()
	rec := &routeRecorder{pool: h.pool}
	mux := http.NewServeMux()
	(&authapi.Handler{Users: h.users, Keys: h.keys, Devices: store.NewDevices(h.pool), Storage: store.NewStorage(h.pool), Freshness: rec}).Mount(mux)
	h.srv = httptest.NewServer(mux)
	t.Cleanup(h.srv.Close)
	ctx := context.Background()
	owner, token := memberAccount(t, h, "owner@example.com", "owner")
	member, memberToken := memberAccount(t, h, "member@example.com", "member")
	d, err := store.NewDevices(h.pool).Create(ctx, h.tenant.String(), "Vendas", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	device := uuid.MustParse(d.ID)
	ifStale := func(u uuid.UUID) membership.Party { return membership.Party{User: u, How: membership.IfStale} }
	path := "/v1/auth/workspaces/devices/" + device.String() + "/permissions"
	put := func(tok string, p store.DevicePermission) int {
		t.Helper()
		return methodRequest(t, h, http.MethodPut, path, p, tok, nil)
	}
	flags := func() store.DevicePermission {
		t.Helper()
		p, err := h.users.StoredDevicePermission(ctx, h.tenant, member.ID, device)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}

	// Raising a flag: the actor and the recipient; the same flags again,
	// nothing; a member, whom the store refuses, nothing.
	n := rec.count()
	if code := put(token, store.DevicePermission{UserID: member.ID, Read: true, Send: true}); code != http.StatusNoContent {
		t.Fatalf("raising: %d", code)
	}
	rec.one(t, n, "permission.raise", h.tenant, ifStale(owner.ID), ifStale(member.ID))
	n = rec.count()
	if code := put(token, store.DevicePermission{UserID: member.ID, Read: true, Send: true}); code != http.StatusNoContent {
		t.Fatalf("the same flags: %d", code)
	}
	rec.none(t, n, "the same flags")
	if code := put(memberToken, store.DevicePermission{UserID: member.ID, Read: true, Send: true, Manage: true}); code != http.StatusForbidden {
		t.Fatalf("a member's change: %d", code)
	}
	rec.none(t, n, "a member's change")
	// Withholding Read: the minute rule for the number's other holders.
	n = rec.count()
	if code := put(token, store.DevicePermission{UserID: member.ID, Send: true}); code != http.StatusNoContent {
		t.Fatalf("withholding Read: %d", code)
	}
	if call := rec.one(t, n, "permission.withhold_read", h.tenant); call.device != device || call.losing != member.ID {
		t.Fatalf("withholding Read: %+v", call)
	}
	n = rec.count()
	if code := put(token, store.DevicePermission{UserID: member.ID}); code != http.StatusNoContent {
		t.Fatalf("lowering Send: %d", code)
	}
	rec.none(t, n, "lowering Send without Read or a key")
	// Each flag alone is a raise.
	n = rec.count()
	if code := put(token, store.DevicePermission{UserID: member.ID, Send: true}); code != http.StatusNoContent {
		t.Fatalf("raising Send: %d", code)
	}
	rec.one(t, n, "permission.raise", h.tenant, ifStale(owner.ID), ifStale(member.ID))
	n = rec.count()
	if code := put(token, store.DevicePermission{UserID: member.ID, Send: true, Manage: true}); code != http.StatusNoContent {
		t.Fatalf("raising Manage: %d", code)
	}
	rec.one(t, n, "permission.raise", h.tenant, ifStale(owner.ID), ifStale(member.ID))
	if code := put(token, store.DevicePermission{UserID: member.ID}); code != http.StatusNoContent {
		t.Fatalf("lowering: %d", code)
	}
	// One's own row: the actor alone.
	n = rec.count()
	put(token, store.DevicePermission{UserID: owner.ID, Read: true, Send: true})
	rec.one(t, n, "permission.raise", h.tenant, ifStale(owner.ID))
	// Withholding Read from someone who holds the key without it narrows
	// who holds the key: the store deletes their grants.
	holder, _ := memberAccount(t, h, "holder@example.com", "member")
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := h.keys.CreateArchiveKey(ctx, h.tenant, device, 1, pub); err != nil {
		t.Fatal(err)
	}
	if err := h.keys.PutGrant(ctx, store.Grant{TenantID: h.tenant, DeviceID: device, UserID: holder.ID, Epoch: 1, SealedDSK: []byte("grant")}, &owner.ID); err != nil {
		t.Fatal(err)
	}
	if err := pg.InTenantTx(ctx, h.pool, h.tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE device_permissions SET can_read = false WHERE device_id = $1 AND user_id = $2`, device, holder.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	n = rec.count()
	put(token, store.DevicePermission{UserID: holder.ID})
	if call := rec.one(t, n, "permission.withhold_read", h.tenant); call.device != device || call.losing != holder.ID {
		t.Fatalf("withholding Read from a key holder: %+v", call)
	}

	// A standing service account: its invitation and its registration, the
	// inviting person IfStale; a person's invitation and a provisional one
	// ask nothing.
	n = rec.count()
	var service struct {
		Invite string `json:"invite"`
	}
	if code := h.post(t, "/v1/auth/workspaces/invites", map[string]string{"role": store.RoleService}, &service, token); code != http.StatusCreated {
		t.Fatalf("a service invitation: %d", code)
	}
	rec.one(t, n, "service.invite", h.tenant, ifStale(owner.ID))
	n = rec.count()
	if code := h.post(t, "/v1/auth/signup", map[string]string{"invite": service.Invite, "name": "erp", "public_key": publicKey(t)}, nil, ""); code != http.StatusOK {
		t.Fatalf("its registration: %d", code)
	}
	rec.one(t, n, "service.signup", h.tenant, ifStale(owner.ID))
	n = rec.count()
	if code := h.post(t, "/v1/auth/workspaces/invites", map[string]string{"role": "member"}, nil, token); code != http.StatusCreated {
		t.Fatalf("a person's invitation: %d", code)
	}
	var provisional struct {
		Invite string `json:"invite"`
	}
	if code := h.post(t, "/v1/auth/workspaces/invites", map[string]any{"role": store.RoleService, "provisional": true}, &provisional, token); code != http.StatusCreated {
		t.Fatalf("a provisional invitation: %d", code)
	}
	if code := h.post(t, "/v1/auth/signup", map[string]string{"invite": provisional.Invite, "name": "reader", "public_key": publicKey(t)}, nil, ""); code != http.StatusOK {
		t.Fatalf("its registration: %d", code)
	}
	rec.none(t, n, "a person's or a provisional invitation")

	// The enforce flag: each refused, 503, and nothing changes.
	rec.mu.Lock()
	rec.refuse = membership.ErrMembershipsUnconfirmed
	rec.mu.Unlock()
	refused := func(what string, code int, body map[string]string) {
		t.Helper()
		if code != http.StatusServiceUnavailable || body["code"] != "memberships_unconfirmed" {
			t.Fatalf("%s under the enforce flag: %d %v", what, code, body)
		}
	}
	var body map[string]string
	raise := store.DevicePermission{UserID: member.ID, Read: true}
	refused("raising", methodRequest(t, h, http.MethodPut, path, raise, token, &body), body)
	if p := flags(); p.Read {
		t.Fatalf("a refused raise raised: %+v", p)
	}
	rec.mu.Lock()
	rec.refuse = nil
	rec.mu.Unlock()
	if code := put(token, raise); code != http.StatusNoContent {
		t.Fatalf("raising: %d", code)
	}
	rec.mu.Lock()
	rec.refuse = membership.ErrMembershipsUnconfirmed
	rec.mu.Unlock()
	refused("withholding Read", methodRequest(t, h, http.MethodPut, path, store.DevicePermission{UserID: member.ID}, token, &body), body)
	if p := flags(); !p.Read {
		t.Fatalf("a refused withholding withheld: %+v", p)
	}
	var before int
	if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM invites WHERE tenant_id = $1`, h.tenant).Scan(&before); err != nil {
		t.Fatal(err)
	}
	refused("a service invitation", h.post(t, "/v1/auth/workspaces/invites", map[string]string{"role": store.RoleService}, &body, token), body)
	var after int
	if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM invites WHERE tenant_id = $1`, h.tenant).Scan(&after); err != nil || after != before {
		t.Fatalf("a refused invitation was issued: %d, %d %v", before, after, err)
	}
	waiting, err := h.users.CreateInvite(ctx, h.tenant, store.RoleService, "", &owner.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	refused("a registration", h.post(t, "/v1/auth/signup", map[string]string{"invite": waiting, "name": "erp2", "public_key": publicKey(t)}, &body, ""), body)
	var completed *time.Time
	if err := h.pool.QueryRow(ctx, `SELECT completed_at FROM invites WHERE invite_id = $1`, shaInvite(t, waiting)).Scan(&completed); err != nil || completed != nil {
		t.Fatalf("a refused registration spent its code: %v %v", completed, err)
	}

	// A read the hook needs that fails: 500, nothing changes, and the act
	// is never let through unchecked. The permission's stored row reads the
	// number's epochs, which a raise does not touch; the invitation's
	// issuer is a column the registration itself does not read.
	ddl := func(q string) {
		t.Helper()
		if _, err := h.pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	unread := func(what string, code int, body map[string]string) {
		t.Helper()
		if code != http.StatusInternalServerError || body["code"] != "internal" {
			t.Fatalf("%s with its pre-read failing: %d %v", what, code, body)
		}
	}
	ddl(`ALTER TABLE device_archive_keys RENAME TO device_archive_keys_hidden`)
	unread("a raise", methodRequest(t, h, http.MethodPut, path, store.DevicePermission{UserID: member.ID, Read: true, Send: true, Manage: true}, token, &body), body)
	ddl(`ALTER TABLE device_archive_keys_hidden RENAME TO device_archive_keys`)
	if p := flags(); p.Manage {
		t.Fatalf("a raise went through unchecked: %+v", p)
	}
	ddl(`ALTER TABLE invites RENAME COLUMN created_by TO created_by_hidden`)
	unread("a registration", h.post(t, "/v1/auth/signup", map[string]string{"invite": waiting, "name": "erp3", "public_key": publicKey(t)}, &body, ""), body)
	ddl(`ALTER TABLE invites RENAME COLUMN created_by_hidden TO created_by`)
	if err := h.pool.QueryRow(ctx, `SELECT completed_at FROM invites WHERE invite_id = $1`, shaInvite(t, waiting)).Scan(&completed); err != nil || completed != nil {
		t.Fatalf("a registration went through unchecked: %v %v", completed, err)
	}
}
