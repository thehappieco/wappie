package wsapi_test

import (
	"context"
	"encoding/json"
	"testing"
	"whatserver2/internal/wa"
	"whatserver2/internal/wsapi"
)

func TestDeleteDefaultsToWhatsAppDisconnect(t *testing.T) {
	for _, tc := range []struct {
		body string
		want bool
	}{{`{"device_id":"x"}`, true}, {`{"device_id":"x","unlink":false}`, false}, {`{"device_id":"x","unlink":true}`, true}} {
		var req wsapi.DeleteRequest
		if err := json.Unmarshal([]byte(tc.body), &req); err != nil {
			t.Fatal(err)
		}
		if req.Unlink != tc.want {
			t.Fatalf("unlink %s = %v", tc.body, req.Unlink)
		}
	}
}
func TestRenameRequiresManageAndKeepsIdentityAndKey(t *testing.T) {
	c := newConsole(t)
	device := c.deviceWithKey(t, "before")
	owner := c.account(t, "owner@acme.test", "owner")
	member := c.account(t, "member@acme.test", "member")
	wantError(t, ask(t, c, wsapi.Hello{Session: member}, wsapi.TypeDeviceRename, wsapi.DeviceRename{DeviceID: device, Label: "Denied"}), wsapi.ErrCodeNotAuthorized)
	f := ask(t, c, wsapi.Hello{Session: owner}, wsapi.TypeDeviceRename, wsapi.DeviceRename{DeviceID: device[:8], Label: " Support "})
	if f.Type != wsapi.TypeDeviceDetail {
		t.Fatalf("rename: %s %s", f.Type, f.Payload)
	}
	d := payload[wsapi.DeviceDetail](t, f)
	if d.Device.Label != "Support" || d.Epoch != 1 || !d.Device.CanManage {
		t.Fatalf("rename changed key or wrong name: %+v", d)
	}
}
func TestPauseAndUnpairedRetryValidation(t *testing.T) {
	c := newConsole(t)
	owner := c.account(t, "owner@acme.test", "owner")
	dev, err := c.devices.Create(context.Background(), c.tenant.String(), "pending", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	f := ask(t, c, wsapi.Hello{Session: owner}, wsapi.TypeDeviceStop, wsapi.DeviceRef{DeviceID: dev.ID})
	if f.Type != wsapi.TypeDeviceStatus {
		t.Fatalf("pause: %s %s", f.Type, f.Payload)
	}
	current, err := c.devices.Get(context.Background(), c.tenant.String(), dev.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !current.Paused {
		t.Fatal("pause not persisted")
	}
	wantError(t, ask(t, c, wsapi.Hello{Session: owner}, wsapi.TypeDeviceStart, wsapi.DeviceRef{DeviceID: dev.ID}), wsapi.ErrCodeConflict)
	wantError(t, ask(t, c, wsapi.Hello{Session: owner}, wsapi.TypePair, wsapi.PairRequest{DeviceID: dev.ID, Resume: true, Method: "qr"}), wsapi.ErrCodeConflict)
}

func TestRetryCannotReplaceTheExistingArchiveKey(t *testing.T) {
	c := newConsole(t)
	device := c.deviceWithKey(t, "pending")
	owner := c.account(t, "owner@acme.test", "owner")
	f := ask(t, c, wsapi.Hello{Session: owner}, wsapi.TypePair, wsapi.PairRequest{DeviceID: device, Resume: true, Method: "qr", ArchivePublicKey: make([]byte, 32)})
	wantError(t, f, wsapi.ErrCodeBadRequest)
	got, err := c.devices.Get(context.Background(), c.tenant.String(), device)
	if err != nil || got.Epoch != 1 {
		t.Fatalf("retry damaged existing key: %+v %v", got, err)
	}
}
