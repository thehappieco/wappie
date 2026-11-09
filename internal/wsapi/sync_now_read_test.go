package wsapi_test

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"whatserver2/internal/store"
	"whatserver2/internal/wa"
	"whatserver2/internal/wsapi"
)

// TestSyncNowAsksRead (DS13, the platform's answer 4): a person's sync now
// (device.start on a number not paused) asks Read and the key at the
// number's epoch, as the console's item.sync_now: a member who reads may,
// an admin who does not read may not (the owner's "readers", literally),
// a member with Manage but no Read may not. A key keeps Manage under full
// scope: a read key may not, a full key may.
func TestSyncNowAsksRead(t *testing.T) {
	c := newDeletionConsoleWith(t, deletionOptions{registry: true})
	ctx := context.Background()
	device := c.linkedDevice(t, "Vendas")
	ref := wsapi.DeviceRef{DeviceID: device.String()}
	reader, readerToken := c.person(t, "caio", "member")
	c.reads(t, reader, device)
	_, adminToken := c.person(t, "bia", "admin")
	manager, managerToken := c.person(t, "ana", "member")
	c.reads(t, c.owner, device)
	if err := c.users.SetDevicePermission(ctx, c.tenant, c.owner, store.DevicePermission{DeviceID: device, UserID: manager, Manage: true}); err != nil {
		t.Fatal(err)
	}
	readKey, err := c.keys.IssueActingAsForDevices(ctx, c.tenant.String(), "read", store.ScopeRead, &c.owner, nil, []uuid.UUID{device}, nil)
	if err != nil {
		t.Fatal(err)
	}
	start := func(hello wsapi.Hello) wsapi.Frame {
		t.Helper()
		c.registry.Stop(ctx, device.String())
		if err := c.devices.SetStatus(ctx, c.tenant.String(), device.String(), wa.StatusOffline, ""); err != nil {
			t.Fatal(err)
		}
		return ask(t, c.console, hello, wsapi.TypeDeviceStart, ref) //nolint:contextcheck // the console's helpers run on a context of their own
	}
	if f := start(wsapi.Hello{Session: readerToken}); f.Type != wsapi.TypeDeviceStatus {
		t.Fatalf("a reader's sync now: %s %s", f.Type, f.Payload)
	}
	for who, hello := range map[string]wsapi.Hello{
		"an admin who does not read":       {Session: adminToken},
		"a member with Manage and no Read": {Session: managerToken},
		"a read key":                       {APIKey: readKey},
	} {
		e := wantError(t, start(hello), wsapi.ErrCodeNotAuthorized)
		if who != "a read key" && !strings.Contains(e.Message, "read permission") {
			t.Errorf("%s: %q", who, e.Message)
		}
	}
	if f := start(wsapi.Hello{APIKey: c.apiKey}); f.Type != wsapi.TypeDeviceStatus {
		t.Fatalf("a full key's sync now: %s %s", f.Type, f.Payload)
	}
	if c.paused(t, c.tenant, device) {
		t.Fatal("a sync now paused the number")
	}
}
