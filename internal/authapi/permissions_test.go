package authapi_test

import (
	"context"
	"github.com/google/uuid"
	"testing"
	"whatserver2/internal/access"
	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

func TestIndependentDevicePermissions(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	owner, _ := memberAccount(t, h, "owner@permissions.test", "owner")
	member, _ := memberAccount(t, h, "member@permissions.test", "member")
	d, err := store.NewDevices(h.pool).Create(ctx, h.tenant.String(), "test", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	device := uuid.MustParse(d.ID)
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err = h.keys.CreateArchiveKey(ctx, h.tenant, device, 1, pub); err != nil {
		t.Fatal(err)
	}
	actor := access.Actor{Tenant: h.tenant, User: member.ID}
	check := func(a access.Actor, action store.DeviceAction, want bool) {
		t.Helper()
		got, err := access.Allows(ctx, a, device, action, nil, h.users)
		if err != nil || got != want {
			t.Fatalf("%s allowed=%v want=%v err=%v", action, got, want, err)
		}
	}
	check(access.Actor{Tenant: h.tenant, User: owner.ID}, store.ActionRead, false)
	check(access.Actor{Tenant: h.tenant, User: owner.ID}, store.ActionManage, true)
	p := store.DevicePermission{DeviceID: device, UserID: member.ID, Send: true}
	if err = h.users.SetDevicePermission(ctx, h.tenant, owner.ID, p); err != nil {
		t.Fatal(err)
	}
	check(actor, store.ActionSend, true)
	check(actor, store.ActionRead, false)
	check(actor, store.ActionManage, false)
	p.Read = true
	p.Send = false
	if err = h.users.SetDevicePermission(ctx, h.tenant, owner.ID, p); err != nil {
		t.Fatal(err)
	}
	check(actor, store.ActionRead, false)
	if err = h.keys.PutGrant(ctx, store.Grant{TenantID: h.tenant, DeviceID: device, UserID: member.ID, Epoch: 1, SealedDSK: []byte("sealed")}, &owner.ID); err != nil {
		t.Fatal(err)
	}
	check(actor, store.ActionRead, true)
	check(actor, store.ActionSend, false)
	p.Read = false
	p.Manage = true
	if err = h.users.SetDevicePermission(ctx, h.tenant, owner.ID, p); err != nil {
		t.Fatal(err)
	}
	check(actor, store.ActionRead, false)
	check(actor, store.ActionManage, true)
	p.Read = true
	if err = h.users.SetDevicePermission(ctx, h.tenant, owner.ID, p); err != nil {
		t.Fatal(err)
	}
	check(actor, store.ActionRead, false) // Old key envelope was deleted, not silently restored.
	if err = h.users.SetDevicePermission(ctx, h.tenant, member.ID, p); err == nil {
		t.Fatal("member changed permissions")
	}
	p.DeviceID = uuid.New()
	if err = h.users.SetDevicePermission(ctx, h.tenant, owner.ID, p); err == nil {
		t.Fatal("unknown device accepted")
	}
}
