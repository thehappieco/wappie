package wsapi_test

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	kc "github.com/thehappieco/kit/contract"

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

// TestSyncNowServiceAccountKeepsManage (DS13): only a person's sync now is
// Read's. A key that acts as a service account keeps the rule it had: the
// key's full scope and the account's own Manage on the number; the
// account's Read, with the number's key, is not enough.
func TestSyncNowServiceAccountKeepsManage(t *testing.T) {
	c := newDeletionConsoleWith(t, deletionOptions{registry: true})
	ctx := context.Background()
	device := c.linkedDevice(t, "Vendas")
	ref := wsapi.DeviceRef{DeviceID: device.String()}
	svc, err := c.users.CreateService(ctx, c.tenant, "erp", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	c.reads(t, svc.ID, device)
	key, err := c.keys.IssueActingAsForDevices(ctx, c.tenant.String(), "erp", store.ScopeFull, &c.owner, &svc.ID, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	start := func() wsapi.Frame {
		t.Helper()
		c.registry.Stop(ctx, device.String())
		if err := c.devices.SetStatus(ctx, c.tenant.String(), device.String(), wa.StatusOffline, ""); err != nil {
			t.Fatal(err)
		}
		return ask(t, c.console, wsapi.Hello{APIKey: key}, wsapi.TypeDeviceStart, ref) //nolint:contextcheck // the console's helpers run on a context of their own
	}
	if e := wantError(t, start(), wsapi.ErrCodeNotAuthorized); !strings.Contains(e.Message, "manage permission") {
		t.Errorf("a service account that reads, without Manage: %q", e.Message)
	}
	if err := c.users.SetDevicePermission(ctx, c.tenant, c.owner, store.DevicePermission{DeviceID: device, UserID: svc.ID, Read: true, Manage: true}); err != nil {
		t.Fatal(err)
	}
	if f := start(); f.Type != wsapi.TypeDeviceStatus {
		t.Fatalf("a service account with Manage: %s %s", f.Type, f.Payload)
	}
}

// TestSyncNowDeletedNumber: Read reaches a live number only. A deleted
// number, kept until its purge, is not found by the sync now of a person
// who read it, in the frame and in the console's runner alike, nor by a
// full key's; the number is not started.
func TestSyncNowDeletedNumber(t *testing.T) {
	p := newParity(t)
	ctx := context.Background()
	reader, readerToken := p.person(t, "caio", "member")
	readerSub := p.link(t, reader, "member")
	device := p.linkedDevice(t, "Gone")
	p.reads(t, p.owner, device)
	p.reads(t, reader, device)
	start := func(hello wsapi.Hello) string {
		t.Helper()
		return frameOutcome(t, ask(t, p.console, hello, wsapi.TypeDeviceStart, wsapi.DeviceRef{DeviceID: device.String()}), wsapi.TypeDeviceStatus)
	}
	syncNow := func() string {
		t.Helper()
		return p.outcome(p.runner.SyncNow(ctx, p.command(t, kc.OpItemSyncNow, reader, readerSub), device)) //nolint:contextcheck // the world's helpers run on a context of their own
	}
	// Live, the reader may, in both.
	if fo, co := start(wsapi.Hello{Session: readerToken}), syncNow(); fo != "ok" || co != "ok" {
		t.Fatalf("a reader of a live number: the frame %s, the runner %s", fo, co)
	}
	p.registry.Stop(ctx, device.String())
	if _, err := p.devices.Quarantine(ctx, p.tenant, p.owner, device, []uuid.UUID{reader}); err != nil {
		t.Fatal(err)
	}
	if fo, co := start(wsapi.Hello{Session: readerToken}), syncNow(); fo != kc.CodeNotFound || co != kc.CodeNotFound {
		t.Errorf("a reader of a deleted number: the frame %s, the runner %s", fo, co)
	}
	if fo := start(wsapi.Hello{APIKey: p.apiKey}); fo != kc.CodeNotFound {
		t.Errorf("a full key on a deleted number: the frame %s", fo)
	}
	if _, running := p.registry.Get(device.String()); running {
		t.Fatal("the deleted number was started")
	}
}
