package wsapi_test

import (
	"context"
	"github.com/google/uuid"
	"testing"
	"whatserver2/internal/store"
	"whatserver2/internal/wsapi"
)

func TestPersonalTransferDeliversReceiptAndRejectsOtherActors(t *testing.T) {
	c := newConsole(t)
	ctx := context.Background()
	token := c.account(t, "transfer-owner@example.test", "owner")
	member := c.account(t, "transfer-member@example.test", "member")
	device := c.deviceWithKey(t, "Transfer phone")
	_, owner, err := c.users.ActiveSession(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	var target uuid.UUID
	if err = c.pool.QueryRow(ctx, `SELECT id FROM tenants WHERE personal_owner_id=$1`, owner.ID).Scan(&target); err != nil {
		t.Fatal(err)
	}
	keys := store.NewKeys(c.pool)
	if err = keys.PutGrant(ctx, store.Grant{TenantID: c.tenant, DeviceID: uuid.MustParse(device), UserID: owner.ID, Epoch: 1, SealedDSK: []byte("opaque")}, nil); err != nil {
		t.Fatal(err)
	}
	wantError(t, ask(t, c, wsapi.Hello{Session: member}, wsapi.TypeDeviceTransferPreview, wsapi.DeviceRef{DeviceID: device}), wsapi.ErrCodeNotAuthorized)
	wantError(t, ask(t, c, wsapi.Hello{APIKey: c.apiKey}, wsapi.TypeDeviceTransferPreview, wsapi.DeviceRef{DeviceID: device}), wsapi.ErrCodeNotAuthorized)
	preview := payload[store.PersonalTransferPreview](t, ask(t, c, wsapi.Hello{Session: token}, wsapi.TypeDeviceTransferPreview, wsapi.DeviceRef{DeviceID: device}))
	if !preview.Eligible || preview.TargetWorkspaceID != target.String() {
		t.Fatalf("preview %+v", preview)
	}
	request := wsapi.DeviceTransferRequest{DeviceID: device, Confirm: device, TargetWorkspaceID: target.String()}
	bad := request
	bad.Confirm = ""
	wantError(t, ask(t, c, wsapi.Hello{Session: token}, wsapi.TypeDeviceTransfer, bad), wsapi.ErrCodeBadRequest)
	f := ask(t, c, wsapi.Hello{Session: token}, wsapi.TypeDeviceTransfer, request)
	if f.Type != wsapi.TypeDeviceTransferred {
		t.Fatalf("transfer receipt %s %s", f.Type, f.Payload)
	}
	moved, err := c.devices.Get(ctx, target.String(), device)
	if err != nil || !moved.Paused {
		t.Fatalf("target %+v %v", moved, err)
	}
	grants, err := keys.GrantsFor(ctx, target, owner.ID)
	if err != nil || len(grants) != 1 {
		t.Fatalf("grants %+v %v", grants, err)
	}
}
