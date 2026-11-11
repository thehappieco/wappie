package wsapi_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/store"
	"whatserver2/internal/wsapi"
)

// TestGrantAddNamesTheKey: grant.add carries the fingerprint of the archive
// key it seals, which the client computes from the key it opened (here it
// equals the one grants.list gives), and the server compares it with the
// number's key (DS49). A client from before DS49 sends none and is
// refused with bad_request. After reset-archive -keep-devices and
// device-key the number has a new key at epoch 1 again:
// a grant sealed with the old key, from a context read before the reset,
// is refused with conflict, and one with the new key's fingerprint is
// taken.
func TestGrantAddNamesTheKey(t *testing.T) {
	c := newConsole(t)
	ctx := context.Background()
	token := c.account(t, "owner@acme.test", "owner")
	owner := wsapi.Hello{Session: token}
	reader := c.accountID(t, "reader@acme.test", "member")
	dev := c.deviceWithKey(t, "phone")
	device := uuid.MustParse(dev)
	keys := store.NewKeys(c.pool)
	_, ownerUser, err := c.users.ActiveSession(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	ownerID := ownerUser.ID
	old := grantFingerprint(t, keys, c.tenant, device, 1)
	if err := keys.PutGrant(ctx, store.Grant{TenantID: c.tenant, DeviceID: device, UserID: ownerID, Epoch: 1,
		SealedDSK: []byte("the owner's"), Fingerprint: old}, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.users.SetDevicePermission(ctx, c.tenant, ownerID, store.DevicePermission{DeviceID: device, UserID: ownerID, Read: true}); err != nil {
		t.Fatal(err)
	}

	// The context: the owner's own grant names the key.
	grants := payload[wsapi.Grants](t, ask(t, c, owner, wsapi.TypeGrantsList, nil))
	if len(grants.Grants) != 1 || grants.Grants[0].Fingerprint != old {
		t.Fatalf("grants.list = %+v, want the key's fingerprint %s", grants.Grants, old)
	}
	grant := func(fingerprint string) wsapi.Frame {
		return ask(t, c, owner, wsapi.TypeGrantAdd, wsapi.GrantRequest{DeviceID: dev, UserID: reader.String(), Epoch: 1,
			SealedDSK: []byte("sealed"), Fingerprint: fingerprint})
	}
	wantError(t, grant(""), wsapi.ErrCodeBadRequest)

	if _, err := store.ResetArchive(ctx, c.pool, c.tenant, true); err != nil {
		t.Fatal(err)
	}
	// Between the reset and device-key the number has no key.
	wantError(t, grant(old), wsapi.ErrCodeConflict)
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.CreateArchiveKey(ctx, c.tenant, device, 1, pub); err != nil {
		t.Fatal(err)
	}
	e := wantError(t, grant(old), wsapi.ErrCodeConflict)
	if ok, err := keys.HasGrant(ctx, c.tenant, device, reader); err != nil || ok {
		t.Fatalf("a grant of the old key was recorded (%q): %v %v", e.Message, ok, err)
	}
	if f := grant(store.ArchiveKeyFingerprint(pub.Bytes())); f.Type != wsapi.TypeReaders {
		t.Fatalf("a grant of the new key: %s %s", f.Type, f.Payload)
	}
}

// TestPairingGrantsNameTheirKey: a pairing's grants carry no fingerprint on
// the wire, since the request carries the key itself. The server names
// that key's fingerprint for each (DS49), so they are taken. With no
// registry here the pairing then fails on the link itself, after its
// grants, and cleans up.
func TestPairingGrantsNameTheirKey(t *testing.T) {
	c := newConsole(t)
	token := c.account(t, "owner@acme.test", "owner")
	reader := c.accountID(t, "reader@acme.test", "member")
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	e := wantError(t, ask(t, c, wsapi.Hello{Session: token}, wsapi.TypePair, wsapi.PairRequest{
		Method: "code", Phone: "+5511999999999", DeviceID: uuid.NewString(), ArchivePublicKey: pub.Bytes(),
		Grants: []wsapi.KeyGrant{{UserID: reader.String(), SealedDSK: []byte("sealed")}},
	}), wsapi.ErrCodeInternal)
	if e.Message != "WhatsApp connection is unavailable" {
		t.Fatalf("the pairing failed before the link: %q", e.Message)
	}
}
