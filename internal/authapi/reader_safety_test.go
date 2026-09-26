package authapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/pg"
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
