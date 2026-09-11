package authapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"whatserver2/internal/crypto/seal"
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
	if err := h.keys.PutGrant(ctx, store.Grant{TenantID: h.tenant, DeviceID: device, UserID: b.ID, Epoch: 1, SealedDSK: []byte("old backup")}, nil); err != nil {
		t.Fatal(err)
	}
	if err := h.keys.RevokeGrant(ctx, h.tenant, device, a.ID); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentAccessRemovalsAlwaysRetainOneReader(t *testing.T) {
	for _, pair := range [][2]string{{"disable", "disable"}, {"disable", "revoke"}, {"disable", "permission"}, {"revoke", "revoke"}, {"permission", "permission"}, {"revoke", "permission"}} {
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
