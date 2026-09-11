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
	// Revocation succeeds only because somebody else can still recover the key.
	if err = h.keys.PutGrant(ctx, store.Grant{TenantID: h.tenant, DeviceID: device, UserID: owner.ID, Epoch: 1, SealedDSK: []byte("backup")}, &owner.ID); err != nil {
		t.Fatal(err)
	}
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

func TestEmptyKeyWhitelistDoesNotBecomeUnrestricted(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	keys := store.NewAPIKeys(h.pool)
	devices := store.NewDevices(h.pool)
	first, err := devices.Create(ctx, h.tenant.String(), "first", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	second, err := devices.Create(ctx, h.tenant.String(), "second", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	token, err := keys.Issue(ctx, h.tenant.String(), "restricted")
	if err != nil {
		t.Fatal(err)
	}
	verified, err := keys.VerifyScoped(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.pool.Exec(ctx, `INSERT INTO api_key_devices(api_key_id,device_id) VALUES($1,$2)`, verified.ID, first.ID); err != nil {
		t.Fatal(err)
	}
	if err = keys.ConnectionKey(ctx, verified.ID, h.tenant.String(), verified.Scope, uuid.Nil, verified.AccessVersion); err == nil {
		t.Fatal("old unrestricted connection survived restriction")
	}
	allowed, err := keys.AllowsDevice(ctx, verified.ID, h.tenant, uuid.MustParse(second.ID))
	if err != nil || allowed {
		t.Fatalf("other device allowed=%v err=%v", allowed, err)
	}
	if _, err = h.pool.Exec(ctx, `DELETE FROM api_key_devices WHERE api_key_id=$1`, verified.ID); err != nil {
		t.Fatal(err)
	}
	allowed, err = keys.AllowsDevice(ctx, verified.ID, h.tenant, uuid.MustParse(second.ID))
	if err != nil || allowed {
		t.Fatalf("empty whitelist expanded access: %v %v", allowed, err)
	}
}
