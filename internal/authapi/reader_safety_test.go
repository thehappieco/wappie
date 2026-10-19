package authapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.mau.fi/whatsmeow/types"
	"whatserver2/internal/authapi"
	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/pg"
	"whatserver2/internal/ratelimit"
	"whatserver2/internal/stepup"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

func protectedNumber(t *testing.T, h *harness, readers ...store.User) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	d, err := store.NewDevices(h.pool).Create(ctx, h.tenant.String(), "protected", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	device := uuid.MustParse(d.ID)
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := h.keys.CreateArchiveKey(ctx, h.tenant, device, 1, pub); err != nil {
		t.Fatal(err)
	}
	for _, reader := range readers {
		if err := h.keys.PutGrant(ctx, store.Grant{TenantID: h.tenant, DeviceID: device, UserID: reader.ID, Epoch: 1, SealedDSK: []byte("envelope")}, nil); err != nil {
			t.Fatal(err)
		}
	}
	return device
}

func TestLastDeviceReaderCannotBeDisabledOrLoseItsEnvelope(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	owner, token := memberAccount(t, h, "owner@last-reader.test", "owner")
	reader, _ := memberAccount(t, h, "reader@last-reader.test", "member")
	device := protectedNumber(t, h, reader)
	// The owner can manage but has no key: ownership is not a recovery path.
	if code := setMember(t, h, token, reader.ID, "member", "disabled"); code != 409 {
		t.Fatalf("disable=%d", code)
	}
	body, _ := json.Marshal(map[string]string{"role": "member", "status": "disabled"})
	req, err := http.NewRequest(http.MethodPut, h.srv.URL+"/v1/auth/workspaces/members/"+reader.ID.String(), bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	var refusal struct {
		Code string `json:"code"`
	}
	if code := h.do(t, req, &refusal); code != 409 || refusal.Code != "last_device_reader" {
		t.Fatalf("refusal=%d %+v", code, refusal)
	}
	if err := h.keys.RevokeGrant(ctx, h.tenant, device, reader.ID); !errors.Is(err, store.ErrLastDeviceReader) {
		t.Fatalf("revoke=%v", err)
	}
	if err := h.users.SetDevicePermission(ctx, h.tenant, owner.ID, store.DevicePermission{DeviceID: device, UserID: reader.ID, Send: true}); !errors.Is(err, store.ErrLastDeviceReader) {
		t.Fatalf("permission=%v", err)
	}
	p, err := h.users.DevicePermission(ctx, h.tenant, reader.ID, device)
	if err != nil || !p.Allows(store.ActionRead) {
		t.Fatalf("failed operation changed access: %+v %v", p, err)
	}
	// An unrelated keyless device is valid and does not prevent disabling an
	// account which holds no envelopes at all.
	_, err = store.NewDevices(h.pool).Create(ctx, h.tenant.String(), "CLI", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	empty, _ := memberAccount(t, h, "empty@last-reader.test", "member")
	if err := h.users.UpdateMember(ctx, h.tenant, owner.ID, empty.ID, "member", "disabled"); err != nil {
		t.Fatal(err)
	}
}

func TestRevocationPreservesEveryUnretiredArchiveGeneration(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	a, _ := memberAccount(t, h, "a@epochs.test", "member")
	b, _ := memberAccount(t, h, "b@epochs.test", "member")
	owner, _ := memberAccount(t, h, "owner@epochs.test", "owner")
	device := protectedNumber(t, h, a)
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := h.keys.CreateArchiveKey(ctx, h.tenant, device, 2, pub); err != nil {
		t.Fatal(err)
	}
	for _, who := range []store.User{a, b} {
		if err := h.keys.PutGrant(ctx, store.Grant{TenantID: h.tenant, DeviceID: device, UserID: who.ID, Epoch: 2, SealedDSK: []byte("new envelope")}, nil); err != nil {
			t.Fatal(err)
		}
	}
	// Bob can read the current generation, but cannot recover Alice's older
	// envelope. Revocation removes all of Alice's generations, so it must fail.
	if err := h.keys.RevokeGrant(ctx, h.tenant, device, a.ID); !errors.Is(err, store.ErrLastDeviceReader) {
		t.Fatalf("old generation stranded: %v", err)
	}
	if err := h.users.RemoveMember(ctx, h.tenant, owner.ID, a.ID); !errors.Is(err, store.ErrLastDeviceReader) {
		t.Fatalf("member removal stranded old generation: %v", err)
	}
	if err := h.keys.PutGrant(ctx, store.Grant{TenantID: h.tenant, DeviceID: device, UserID: b.ID, Epoch: 1, SealedDSK: []byte("old backup")}, nil); err != nil {
		t.Fatal(err)
	}
	if err := h.keys.RevokeGrant(ctx, h.tenant, device, a.ID); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentAccessRemovalsAlwaysRetainOneReader(t *testing.T) {
	for _, pair := range [][2]string{{"disable", "disable"}, {"disable", "revoke"}, {"disable", "permission"}, {"revoke", "revoke"}, {"permission", "permission"}, {"revoke", "permission"}, {"remove", "remove"}, {"remove", "disable"}, {"remove", "revoke"}, {"remove", "permission"}} {
		t.Run(pair[0]+"/"+pair[1], func(t *testing.T) {
			h := newHarness(t)
			ctx := context.Background()
			owner, _ := memberAccount(t, h, "owner@race.test", "owner")
			a, _ := memberAccount(t, h, "a@race.test", "member")
			b, _ := memberAccount(t, h, "b@race.test", "member")
			device := protectedNumber(t, h, a, b)
			start := make(chan struct{})
			results := make(chan error, 2)
			for i, user := range []store.User{a, b} {
				go func() {
					<-start
					var err error
					switch pair[i] {
					case "remove":
						err = h.users.RemoveMember(ctx, h.tenant, owner.ID, user.ID)
					case "disable":
						err = h.users.UpdateMember(ctx, h.tenant, owner.ID, user.ID, "member", "disabled")
					case "revoke":
						err = h.keys.RevokeGrant(ctx, h.tenant, device, user.ID)
					case "permission":
						err = h.users.SetDevicePermission(ctx, h.tenant, owner.ID, store.DevicePermission{DeviceID: device, UserID: user.ID})
					}
					results <- err
				}()
			}
			close(start)
			allowed, blocked := 0, 0
			for range 2 {
				err := <-results
				if err == nil {
					allowed++
				} else if errors.Is(err, store.ErrLastDeviceReader) {
					blocked++
				} else {
					t.Fatal(err)
				}
			}
			if allowed != 1 || blocked != 1 {
				t.Fatalf("allowed=%d blocked=%d", allowed, blocked)
			}
			readers, err := h.keys.Readers(ctx, h.tenant, device)
			if err != nil || len(readers) != 1 {
				t.Fatalf("remaining readers=%v err=%v", readers, err)
			}
		})
	}
}

// The console removes a content consent's provisional service account when
// the consent does not complete. Its grants are copies sealed to a key that
// lives only in a reader, so the removal never waits for another reader:
// not while the account is inside its window, and not once the window has
// lapsed and the sweep has not reached it yet. The owner holds the only
// other envelope with its read flag withheld, so no person could stand in
// as a backup: the account is let go because of what it is, not because
// someone else reads. The person keeps being the last reader throughout.
func TestRemovingProvisionalServiceNeverNeedsAnotherReader(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	owner, token := memberAccount(t, h, "owner@provisional.test", "owner")
	device := protectedNumber(t, h, owner)
	if err := pg.InTenantTx(ctx, h.pool, h.tenant.String(), func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO device_permissions(tenant_id,device_id,user_id,can_read) VALUES($1,$2,$3,false)
			ON CONFLICT(tenant_id,device_id,user_id) DO UPDATE SET can_read=false`, h.tenant, device, owner.ID)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	for _, lapsed := range []bool{false, true} {
		var created struct {
			Invite string `json:"invite"`
		}
		if code := h.post(t, "/v1/auth/workspaces/invites", map[string]any{"role": "service", "provisional": true}, &created, token); code != http.StatusCreated {
			t.Fatalf("provisional invite: %d", code)
		}
		svc, err := h.users.SignupService(ctx, created.Invite, "assistant-"+uuid.NewString()[:8], make([]byte, 32))
		if err != nil {
			t.Fatal(err)
		}
		if err := h.users.SetDevicePermission(ctx, h.tenant, owner.ID, store.DevicePermission{DeviceID: device, UserID: svc.ID, Read: true}); err != nil {
			t.Fatal(err)
		}
		if err := h.keys.PutGrant(ctx, store.Grant{TenantID: h.tenant, DeviceID: device, UserID: svc.ID, Epoch: 1, SealedDSK: []byte("sealed to the attested key")}, &owner.ID); err != nil {
			t.Fatal(err)
		}
		if lapsed {
			if err := pg.InTenantTx(ctx, h.pool, h.tenant.String(), func(tx pgx.Tx) error {
				_, e := tx.Exec(ctx, `UPDATE workspace_memberships SET expires_at=now()-interval '1 minute' WHERE tenant_id=$1 AND user_id=$2`, h.tenant, svc.ID)
				return e
			}); err != nil {
				t.Fatal(err)
			}
		}
		if code, reason := removeMember(t, h, token, svc.ID.String()); code != http.StatusNoContent {
			t.Fatalf("lapsed=%v: removing the provisional service = %d %s", lapsed, code, reason)
		}
		var held int
		if err := pg.InTenantTx(ctx, h.pool, h.tenant.String(), func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT
				(SELECT count(*) FROM device_key_grants WHERE tenant_id=$1 AND user_id=$2) +
				(SELECT count(*) FROM workspace_memberships WHERE tenant_id=$1 AND user_id=$2)`, h.tenant, svc.ID).Scan(&held)
		}); err != nil || held != 0 {
			t.Fatalf("lapsed=%v: the service kept %d rows (%v)", lapsed, held, err)
		}
	}
	// The person is still the last reader, and still cannot leave.
	if err := h.keys.RevokeGrant(ctx, h.tenant, device, owner.ID); !errors.Is(err, store.ErrLastDeviceReader) {
		t.Fatalf("the owner's envelope: %v", err)
	}
}

// The last key holder of a deleted number is protected until its purge, and
// only an owner is told which number and until when (decision 0038).
func TestLastKeyHolderOfADeletedNumber(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	owner, token := memberAccount(t, h, "owner@deleted.test", "owner")
	_, adminToken := memberAccount(t, h, "admin@deleted.test", "admin")
	reader, _ := memberAccount(t, h, "reader@deleted.test", "member")
	device := protectedNumber(t, h, reader)
	devices := store.NewDevices(h.pool)
	if err := devices.SetIdentity(ctx, h.tenant.String(), device.String(), wa.Identity{PN: types.NewJID("5511912345678", types.DefaultUserServer)}); err != nil {
		t.Fatal(err)
	}
	q, err := devices.Quarantine(ctx, h.tenant, owner.ID, device, []uuid.UUID{reader.ID})
	if err != nil {
		t.Fatal(err)
	}
	disable := func(token string) (int, refusal) {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"role": "member", "status": "disabled"})
		req, err := http.NewRequest(http.MethodPut, h.srv.URL+"/v1/auth/workspaces/members/"+reader.ID.String(), bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		var out refusal
		return h.do(t, req, &out), out
	}
	code, got := disable(token)
	if code != 409 || got.Code != "last_reader_of_deleted" || len(got.Numbers) != 1 || got.Numbers[0].DeviceID != device ||
		got.Numbers[0].Label != "protected" || !got.Numbers[0].PurgeAfter.Equal(q.PurgeAfter) {
		t.Fatalf("an owner's refusal: %d %+v", code, got)
	}
	if code, got := disable(adminToken); code != 409 || got.Code != "last_reader_of_deleted" || len(got.Numbers) != 0 {
		t.Fatalf("an admin's refusal: %d %+v", code, got)
	}
	if status, code := removeMember(t, h, token, reader.ID.String()); status != 409 || code != "last_reader_of_deleted" {
		t.Fatalf("removal: %d %s", status, code)
	}
}

type refusal struct {
	Code    string                   `json:"code"`
	Numbers []store.DeletedNumberRef `json:"numbers"`
}

// deletedNumberOf is a number of the harness's workspace whose only key
// holder is reader, deleted by owner.
func deletedNumberOf(t *testing.T, h *harness, owner, reader store.User, pn string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	device := protectedNumber(t, h, reader)
	devices := store.NewDevices(h.pool)
	if err := devices.SetIdentity(ctx, h.tenant.String(), device.String(), wa.Identity{PN: types.NewJID(pn, types.DefaultUserServer)}); err != nil {
		t.Fatal(err)
	}
	if _, err := devices.Quarantine(ctx, h.tenant, owner.ID, device, []uuid.UUID{reader.ID}); err != nil {
		t.Fatal(err)
	}
	return device
}

// strandRequest is a member change with strand_deleted: a disable (PUT,
// in the body) or a removal (DELETE, in the query string, as query says).
func strandRequest(t *testing.T, h *harness, token, method string, target uuid.UUID, query string) (int, refusal) {
	t.Helper()
	code, out, _ := strandResponse(t, h, token, method, target, query)
	return code, out
}

// strandResponse is strandRequest with the answer's headers.
func strandResponse(t *testing.T, h *harness, token, method string, target uuid.UUID, query string) (int, refusal, http.Header) {
	t.Helper()
	var body *bytes.Reader
	if method == http.MethodPut {
		raw, _ := json.Marshal(map[string]any{"role": "member", "status": "disabled", "strand_deleted": true})
		body = bytes.NewReader(raw)
	} else {
		body = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, h.srv.URL+"/v1/auth/workspaces/members/"+target.String()+query, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck // Response body cleanup in tests.
	var out refusal
	if resp.StatusCode >= 300 {
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
	}
	return resp.StatusCode, out, resp.Header
}

// Test 52 (the plan's DB13, 4.12's routes, and DB2's gate as the owner
// confirmed it): strand_deleted on the disable and remove routes. Anyone
// but an owner gets owner_only before any step-up prompt; an owner needs a
// recent step-up; and the override goes on only where the platform will
// mail the other owners (observing, in a team the platform names), else
// last_reader_of_deleted as without the flag. A live number's last reader
// is never stranded.
func TestMemberStrandNeedsStepUp(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	owner, token := memberAccount(t, h, "owner@strand.test", "owner")
	_, adminToken := memberAccount(t, h, "admin@strand.test", "admin")
	removed, _ := memberAccount(t, h, "removed@strand.test", "member")
	disabled, _ := memberAccount(t, h, "disabled@strand.test", "member")
	liveReader, _ := memberAccount(t, h, "live@strand.test", "member")
	removedNumber := deletedNumberOf(t, h, owner, removed, "5511912340001")
	disabledNumber := deletedNumberOf(t, h, owner, disabled, "5511912340002")
	protectedNumber(t, h, liveReader)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := h.pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	stranded := func() map[uuid.UUID]string {
		t.Helper()
		out := map[uuid.UUID]string{}
		if err := pg.InTenantTx(ctx, h.pool, h.tenant.String(), func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT item_id, cause FROM item_events WHERE type = 'stranded'`)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var id uuid.UUID
				var cause string
				if err := rows.Scan(&id, &cause); err != nil {
					return err
				}
				out[id] = cause
			}
			return rows.Err()
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	both := func(tok string) map[string]func() (int, refusal) {
		return map[string]func() (int, refusal){
			"disable": func() (int, refusal) { return strandRequest(t, h, tok, http.MethodPut, disabled.ID, "") },
			"remove": func() (int, refusal) {
				return strandRequest(t, h, tok, http.MethodDelete, removed.ID, "?strand_deleted=true")
			},
		}
	}

	// Outside the gate (the contract off), an owner's flag is ignored.
	for name, act := range both(token) {
		if code, got := act(); code != http.StatusConflict || got.Code != "last_reader_of_deleted" || len(got.Numbers) != 1 {
			t.Fatalf("%s outside the gate: %d %+v", name, code, got)
		}
	}
	exec(`UPDATE contract_state SET mode = 'observe', events_from = clock_timestamp()`)
	// Observing, in a team the platform does not name: the same.
	for name, act := range both(token) {
		if code, got := act(); code != http.StatusConflict || got.Code != "last_reader_of_deleted" {
			t.Fatalf("%s in an unnamed team: %d %+v", name, code, got)
		}
	}
	exec(`INSERT INTO contract_workspaces (workspace_id, kind) VALUES ($1, 'team')`, h.tenant)

	// An admin: owner_only, fresh or not, never a step-up prompt.
	for _, stale := range []bool{false, true} {
		if stale {
			h.age(t, adminToken)
		}
		for name, act := range both(adminToken) {
			if code, got := act(); code != http.StatusForbidden || got.Code != "owner_only" {
				t.Fatalf("%s by an admin (stale %v): %d %+v", name, stale, code, got)
			}
		}
	}
	// A flag that is not a boolean.
	if code, got := strandRequest(t, h, token, http.MethodDelete, removed.ID, "?strand_deleted=maybe"); code != http.StatusBadRequest || got.Code != "bad_request" {
		t.Fatalf("strand_deleted=maybe: %d %+v", code, got)
	}
	// An owner whose sign-in is over ten minutes old: step_up_required.
	h.age(t, token)
	for name, act := range both(token) {
		if code, got := act(); code != http.StatusForbidden || got.Code != stepup.Code {
			t.Fatalf("%s by a stale owner: %d %+v", name, code, got)
		}
	}
	if s := stranded(); len(s) != 0 {
		t.Fatalf("refusals stranded %v", s)
	}
	// Without the flag, nothing asks for a step-up and release A's refusal
	// stands.
	if status, code := removeMember(t, h, token, removed.ID.String()); status != http.StatusConflict || code != "last_reader_of_deleted" {
		t.Fatalf("a removal without the flag: %d %s", status, code)
	}
	if code := h.post(t, "/v1/auth/step-up/password", map[string]string{"auth_key": "proof"}, nil, token); code != http.StatusOK {
		t.Fatalf("the owner's step-up: %d", code)
	}
	// A live number's last reader stays, flag or not.
	if code, got := strandRequest(t, h, token, http.MethodDelete, liveReader.ID, "?strand_deleted=true"); code != http.StatusConflict || got.Code != "last_device_reader" {
		t.Fatalf("a live number's last reader: %d %+v", code, got)
	}
	// Behind a change to the workspace that outlasts the override's lock
	// timeout: workspace_busy, to try again, and nothing changed.
	blocker, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Rollback(context.Background()) }()
	if _, err := blocker.Exec(ctx, `SELECT 1 FROM tenants WHERE id = $1 FOR UPDATE`, h.tenant); err != nil {
		t.Fatal(err)
	}
	if code, got, header := strandResponse(t, h, token, http.MethodPut, disabled.ID, ""); code != http.StatusServiceUnavailable ||
		got.Code != "workspace_busy" || header.Get("Retry-After") == "" {
		t.Fatalf("a busy workspace: %d %+v %v", code, got, header)
	}
	if err := blocker.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if s := stranded(); len(s) != 0 {
		t.Fatalf("a busy override stranded %v", s)
	}
	for name, act := range both(token) {
		if code, got := act(); code != http.StatusNoContent {
			t.Fatalf("%s by a fresh owner: %d %+v", name, code, got)
		}
	}
	if s := stranded(); len(s) != 2 || s[removedNumber] != "revoked" || s[disabledNumber] != "disabled" {
		t.Fatalf("stranded %v", s)
	}
	// ?strand_deleted=false is no flag.
	again, _ := memberAccount(t, h, "again@strand.test", "member")
	deletedNumberOf(t, h, owner, again, "5511912340003")
	if code, got := strandRequest(t, h, token, http.MethodDelete, again.ID, "?strand_deleted=false"); code != http.StatusConflict || got.Code != "last_reader_of_deleted" {
		t.Fatalf("strand_deleted=false: %d %+v", code, got)
	}
}

// A flagged member change is on the sign-in budget, as a removal is: it
// may hold the contract's state (store.ErrWorkspaceBusy). An unflagged one
// stays off it, as in release A.
func TestMemberStrandIsRateLimited(t *testing.T) {
	h := newHarness(t)
	_, token := memberAccount(t, h, "owner@limit.test", "owner")
	target, _ := memberAccount(t, h, "target@limit.test", "member")
	mux := http.NewServeMux()
	(&authapi.Handler{
		Users: h.users, Keys: h.keys, Devices: store.NewDevices(h.pool),
		Limits: &ratelimit.Auth{PerIP: ratelimit.New(60, 100), PerSubject: ratelimit.New(1, 2)},
	}).Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	limited := &harness{srv: srv, pool: h.pool, users: h.users, keys: h.keys, tenant: h.tenant}
	for i := range 2 {
		if code, got := strandRequest(t, limited, token, http.MethodPut, target.ID, ""); code != http.StatusNoContent {
			t.Fatalf("flagged change %d: %d %+v", i+1, code, got)
		}
	}
	if code, got, header := strandResponse(t, limited, token, http.MethodPut, target.ID, ""); code != http.StatusTooManyRequests ||
		got.Code != "rate_limited" || header.Get("Retry-After") == "" {
		t.Fatalf("a third flagged change: %d %+v", code, got)
	}
	for i := range 3 {
		if code := setMember(t, limited, token, target.ID, "member", "disabled"); code != http.StatusNoContent {
			t.Fatalf("unflagged change %d: %d", i+1, code)
		}
	}
}
