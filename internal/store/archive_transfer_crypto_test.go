package store_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/store"
)

func TestPersonalTransferKeepsOldAndNewArchiveReadable(t *testing.T) {
	a := newArchive(t)
	ctx := context.Background()
	owner, personal := transferOwner(t, a, "owner")
	other, _ := transferOwner(t, a, "member")
	keys := store.NewKeys(a.pool)
	pub, priv, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	userPub, userPriv, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := priv.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	if err := keys.CreateArchiveKey(ctx, a.tenant, a.device, 1, pub); err != nil {
		t.Fatal(err)
	}
	oldGrant, err := seal.SealDirect(userPub, seal.KindDeviceGrant, a.tenant,
		seal.GrantRow(a.tenant, a.device, owner, 1), 1, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.PutGrant(ctx, store.Grant{TenantID: a.tenant, DeviceID: a.device, UserID: owner, Epoch: 1, SealedDSK: oldGrant}, &owner); err != nil {
		t.Fatal(err)
	}
	if err := keys.PutGrant(ctx, store.Grant{TenantID: a.tenant, DeviceID: a.device, UserID: other, Epoch: 1, SealedDSK: []byte("old reader grant")}, &owner); err != nil {
		t.Fatal(err)
	}
	before, err := seal.NewSealer(a.tenant, a.device, pub, 1, keys)
	if err != nil {
		t.Fatal(err)
	}
	uid := uuid.New()
	oldBody, err := before.Seal(ctx, seal.KindBody, uid, []byte("history before transfer"))
	if err != nil {
		t.Fatal(err)
	}
	oldKeyID := before.CurrentKeyID()
	devices := store.NewDevices(a.pool)
	if err := devices.SetPaused(ctx, a.tenant.String(), a.device.String(), true); err != nil {
		t.Fatal(err)
	}
	if _, err := devices.TransferPersonal(ctx, a.tenant, owner, a.device, personal); err != nil {
		t.Fatal(err)
	}
	archiveTenant, err := keys.ArchiveTenant(ctx, personal, a.device)
	if err != nil || archiveTenant != a.tenant {
		t.Fatalf("archive namespace = %s, %v", archiveTenant, err)
	}
	if _, err := keys.ArchiveTenant(ctx, a.tenant, a.device); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("old workspace can resolve namespace: %v", err)
	}
	grants, err := keys.GrantsFor(ctx, personal, owner)
	if err != nil || len(grants) != 1 {
		t.Fatalf("moved grants: %+v, %v", grants, err)
	}
	grant := grants[0]
	if grant.ArchiveTenantID != a.tenant || !bytes.Equal(grant.SealedDSK, oldGrant) {
		t.Fatal("transfer changed the existing grant")
	}
	opened, err := seal.OpenDirect(userPriv, seal.KindDeviceGrant, archiveTenant,
		seal.GrantRow(archiveTenant, a.device, owner, grant.Epoch), grant.SealedDSK)
	if err != nil || !bytes.Equal(opened, raw) {
		t.Fatalf("old grant cannot open after transfer: %v", err)
	}
	clear(opened)
	if grants, err := keys.GrantsFor(ctx, a.tenant, other); err != nil || len(grants) != 0 {
		t.Fatalf("old reader retained access: %+v, %v", grants, err)
	}
	if _, err := keys.SealedContentKey(ctx, a.tenant, a.device, oldKeyID); err == nil {
		t.Fatal("old workspace retained content key access")
	}

	// The key counter continues in Personal while both old and new ciphertext
	// remain bound to the original namespace. No content/private key is re-sealed.
	after, err := seal.NewSealerWithArchiveTenant(personal, archiveTenant, a.device, pub, 1, keys)
	if err != nil {
		t.Fatal(err)
	}
	newBody, err := after.Seal(ctx, seal.KindBody, uid, []byte("history after transfer"))
	if err != nil {
		t.Fatal(err)
	}
	if after.CurrentKeyID() <= oldKeyID {
		t.Fatal("content key counter restarted")
	}
	for _, tc := range []struct {
		id   uint32
		body []byte
		want string
	}{
		{oldKeyID, oldBody, "history before transfer"},
		{after.CurrentKeyID(), newBody, "history after transfer"},
	} {
		sealed, err := keys.SealedContentKey(ctx, personal, a.device, tc.id)
		if err != nil {
			t.Fatal(err)
		}
		key, err := seal.OpenContentKey(priv, archiveTenant, a.device, tc.id, sealed)
		if err != nil {
			t.Fatal(err)
		}
		body, err := key.Open(seal.KindBody, archiveTenant, uid, tc.body)
		if err != nil || string(body) != tc.want {
			t.Fatalf("archive body: %q, %v", body, err)
		}
	}
	newGrant, err := seal.SealDirect(userPub, seal.KindDeviceGrant, archiveTenant,
		seal.GrantRow(archiveTenant, a.device, owner, 1), 1, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.PutGrant(ctx, store.Grant{TenantID: personal, DeviceID: a.device, UserID: owner, Epoch: 1, SealedDSK: newGrant}, &owner); err != nil {
		t.Fatal(err)
	}
	grants, err = keys.GrantsFor(ctx, personal, owner)
	if err != nil || len(grants) != 1 {
		t.Fatalf("new grant: %+v, %v", grants, err)
	}
	opened, err = seal.OpenDirect(userPriv, seal.KindDeviceGrant, archiveTenant,
		seal.GrantRow(archiveTenant, a.device, owner, 1), grants[0].SealedDSK)
	if err != nil || !bytes.Equal(opened, raw) {
		t.Fatalf("new grant cannot open: %v", err)
	}
	clear(opened)
}
