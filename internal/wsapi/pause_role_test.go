package wsapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"whatserver2/internal/store"
	"whatserver2/internal/wa"
	"whatserver2/internal/wsapi"
)

// Pausing and resuming a number's capture (device.stop, device.start;
// decision 0039) is by role (the owner's answer of 2026-10-26 to question 1
// of the platform's design of that day): in a personal workspace its
// person, in a team its owners and admins, never a member through the
// stored Manage flag. A key keeps it under its scope: full, with the number
// in its list; a key that acts as a service account also needs the
// account's own Manage flag, as before. Every other act of managing a
// number keeps its rule.

// listed is the number as devices.list shows it to hello.
func listed(t *testing.T, c *deletionConsole, hello wsapi.Hello, device uuid.UUID) wsapi.DeviceInfo {
	t.Helper()
	f := ask(t, c.console, hello, wsapi.TypeDevicesList, nil)
	if f.Type != wsapi.TypeDevices {
		t.Fatalf("devices.list: %s %s", f.Type, f.Payload)
	}
	for _, d := range payload[wsapi.Devices](t, f).Devices {
		if d.ID == device.String() {
			return d
		}
	}
	t.Fatalf("%s is not listed", device)
	return wsapi.DeviceInfo{}
}

// listedOverHTTP is the number as GET /v1/devices shows it to token.
func listedOverHTTP(t *testing.T, c *deletionConsole, token string, device uuid.UUID) wsapi.DeviceInfo {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, c.rest.URL+"/v1/devices", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/devices: %d", res.StatusCode)
	}
	var out struct {
		Devices []wsapi.DeviceInfo `json:"devices"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	for _, d := range out.Devices {
		if d.ID == device.String() {
			return d
		}
	}
	t.Fatalf("%s is not listed over HTTP", device)
	return wsapi.DeviceInfo{}
}

// pauses stops and then starts device as hello, each answered with its
// status, and checks the pause in between.
func pauses(t *testing.T, c *deletionConsole, hello wsapi.Hello, tenant, device uuid.UUID, who string) {
	t.Helper()
	ref := wsapi.DeviceRef{DeviceID: device.String()}
	if f := ask(t, c.console, hello, wsapi.TypeDeviceStop, ref); f.Type != wsapi.TypeDeviceStatus {
		t.Fatalf("%s's stop: %s %s", who, f.Type, f.Payload)
	}
	if !c.paused(t, tenant, device) {
		t.Fatalf("%s's stop left the number unpaused", who)
	}
	if f := ask(t, c.console, hello, wsapi.TypeDeviceStart, ref); f.Type != wsapi.TypeDeviceStatus {
		t.Fatalf("%s's start: %s %s", who, f.Type, f.Payload)
	}
	if c.paused(t, tenant, device) {
		t.Fatalf("%s's start left the number paused", who)
	}
}

// refused checks that hello may neither stop device nor resume it once it
// is paused, with a not_authorized whose message holds each of says, and
// that the number's pause is left as it was. On a number that is not
// paused, the console's owner pauses it for the resume, and resumes it after.
func refused(t *testing.T, c *deletionConsole, hello wsapi.Hello, device uuid.UUID, who string, says ...string) {
	t.Helper()
	ref := wsapi.DeviceRef{DeviceID: device.String()}
	owner := wsapi.Hello{Session: c.token}
	was := c.paused(t, c.tenant, device)
	check := func(frame string, paused bool) {
		t.Helper()
		e := wantError(t, ask(t, c.console, hello, frame, ref), wsapi.ErrCodeNotAuthorized)
		for _, s := range says {
			if !strings.Contains(e.Message, s) {
				t.Errorf("%s's %s: the refusal %q does not say %q", who, frame, e.Message, s)
			}
		}
		if c.paused(t, c.tenant, device) != paused {
			t.Fatalf("%s's refused %s changed the pause", who, frame)
		}
	}
	check(wsapi.TypeDeviceStop, was)
	if !was {
		if f := ask(t, c.console, owner, wsapi.TypeDeviceStop, ref); f.Type != wsapi.TypeDeviceStatus {
			t.Fatalf("the owner's stop: %s %s", f.Type, f.Payload)
		}
	}
	check(wsapi.TypeDeviceStart, true)
	if !was {
		if f := ask(t, c.console, owner, wsapi.TypeDeviceStart, ref); f.Type != wsapi.TypeDeviceStatus {
			t.Fatalf("the owner's start: %s %s", f.Type, f.Payload)
		}
	}
}

func TestTeamPausesAndResumesByRole(t *testing.T) {
	c := newDeletionConsoleWith(t, deletionOptions{registry: true})
	ctx := context.Background()
	device := c.linkedDevice(t, "Vendas")
	ref := wsapi.DeviceRef{DeviceID: device.String()}
	c.reads(t, c.owner, device)
	manager, managerToken := c.person(t, "ana", "member")
	c.reads(t, manager, device)
	if err := c.users.SetDevicePermission(ctx, c.tenant, c.owner, store.DevicePermission{DeviceID: device, UserID: manager, Read: true, Send: true, Manage: true}); err != nil {
		t.Fatal(err)
	}
	reader, readerToken := c.person(t, "caio", "member")
	c.reads(t, reader, device)
	_, adminToken := c.person(t, "bia", "admin")
	owner, admin := wsapi.Hello{Session: c.token}, wsapi.Hello{Session: adminToken}
	member := wsapi.Hello{Session: managerToken}

	// What each one is told it may do, over the socket and over HTTP.
	for _, tc := range []struct {
		who     string
		hello   wsapi.Hello
		token   string
		manages bool
		pauses  bool
	}{
		{"the owner", owner, c.token, true, true},
		{"an admin", admin, adminToken, true, true},
		{"a member with Manage", member, managerToken, true, false},
		{"a member without it", wsapi.Hello{Session: readerToken}, readerToken, false, false},
		{"a full key", wsapi.Hello{APIKey: c.apiKey}, c.apiKey, true, true},
	} {
		for _, got := range []wsapi.DeviceInfo{listed(t, c, tc.hello, device), listedOverHTTP(t, c, tc.token, device)} {
			if got.CanManage != tc.manages || got.CanPause != tc.pauses {
				t.Errorf("%s: can_manage %v, can_pause %v; want %v, %v", tc.who, got.CanManage, got.CanPause, tc.manages, tc.pauses)
			}
		}
	}

	// A member with Manage may neither pause nor resume, and is told the
	// rule; nor may a member without it.
	refused(t, c, member, device, "a member with Manage", "owner or an admin", "Manage permission does not include it")
	refused(t, c, wsapi.Hello{Session: readerToken}, device, "a member without Manage", "owner or an admin")

	// The member keeps every other act of managing the number: its name
	// and its receipt mode here; frameAction keeps the rest on Manage
	// (TestOnlyStopAndStartPauseByRole).
	if f := ask(t, c.console, member, wsapi.TypeDeviceRename, wsapi.DeviceRename{DeviceID: device.String(), Label: "Vendas SP"}); f.Type != wsapi.TypeDeviceDetail {
		t.Fatalf("the member's rename: %s %s", f.Type, f.Payload)
	}
	if f := ask(t, c.console, member, wsapi.TypeDeviceMode, wsapi.DeviceModeRequest{DeviceID: device.String(), ReceiptMode: "active"}); f.Type != wsapi.TypeDeviceDetail {
		t.Fatalf("the member's receipt mode: %s %s", f.Type, f.Payload)
	}

	// An admin and the owner pause and resume it; while it is paused, the
	// member still may not resume it.
	for _, tc := range []struct {
		who   string
		hello wsapi.Hello
	}{{"an admin", admin}, {"the owner", owner}} {
		if f := ask(t, c.console, tc.hello, wsapi.TypeDeviceStop, ref); f.Type != wsapi.TypeDeviceStatus {
			t.Fatalf("%s's stop: %s %s", tc.who, f.Type, f.Payload)
		}
		refused(t, c, member, device, "a member with Manage, on a paused number", "owner or an admin")
		if !c.paused(t, c.tenant, device) {
			t.Fatalf("the member's refused start resumed what %s paused", tc.who)
		}
		if f := ask(t, c.console, tc.hello, wsapi.TypeDeviceStart, ref); f.Type != wsapi.TypeDeviceStatus {
			t.Fatalf("%s's start: %s %s", tc.who, f.Type, f.Payload)
		}
		if c.paused(t, c.tenant, device) {
			t.Fatalf("%s's start left the number paused", tc.who)
		}
	}

	// Promoted, the member pauses: the role decides. The promotion ends
	// their sessions; the next one carries the new role.
	if err := c.users.UpdateMember(ctx, c.tenant, c.owner, manager, "admin", "active"); err != nil {
		t.Fatal(err)
	}
	pauses(t, c, wsapi.Hello{Session: c.sessionOf(t, c.tenant, manager)}, c.tenant, device, "the promoted member")
}

// sessionOf starts a session for user in tenant.
func (c *deletionConsole) sessionOf(t *testing.T, tenant, user uuid.UUID) string {
	t.Helper()
	ctx := context.Background()
	u, err := c.users.Get(ctx, tenant, user)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := c.users.StartSession(ctx, u, "test")
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestThePersonalWorkspacesPersonPausesAndResumes(t *testing.T) {
	c := newDeletionConsoleWith(t, deletionOptions{registry: true})
	personal := c.personalOf(t, c.owner)
	device := c.linkedDeviceIn(t, personal, "Meu")
	hello := wsapi.Hello{Session: c.sessionOf(t, personal, c.owner)}
	if got := listed(t, c, hello, device); !got.CanManage || !got.CanPause {
		t.Fatalf("the person's number: can_manage %v, can_pause %v", got.CanManage, got.CanPause)
	}
	pauses(t, c, hello, personal, device, "the personal workspace's person")
}

func TestKeysPauseAndResumeUnderTheirScope(t *testing.T) {
	c := newDeletionConsoleWith(t, deletionOptions{registry: true})
	ctx := context.Background()
	device := c.linkedDevice(t, "Vendas")
	other := c.linkedDevice(t, "Caixa")
	c.reads(t, c.owner, device)
	issue := func(name string, scope store.KeyScope, actsAs *uuid.UUID, devices []uuid.UUID) (wsapi.Hello, string) {
		t.Helper()
		key, err := c.keys.IssueActingAsForDevices(ctx, c.tenant.String(), name, scope, &c.owner, actsAs, devices, nil)
		if err != nil {
			t.Fatal(err)
		}
		return wsapi.Hello{APIKey: key}, key
	}

	// A full key with the number in its list pauses and resumes it.
	full, fullKey := issue("automation", store.ScopeFull, nil, []uuid.UUID{device})
	if got := listedOverHTTP(t, c, fullKey, device); !got.CanPause {
		t.Fatalf("the full key's number: %+v", got)
	}
	pauses(t, c, full, c.tenant, device, "a full key")

	// A full key for another number, a send key and a read key may not.
	elsewhere, _ := issue("elsewhere", store.ScopeFull, nil, []uuid.UUID{other})
	refused(t, c, elsewhere, device, "a full key for another number", "full scope that reaches the number")
	for _, scope := range []store.KeyScope{store.ScopeSend, store.ScopeRead} {
		hello, key := issue(string(scope), scope, nil, nil)
		refused(t, c, hello, device, "a "+string(scope)+" key", "full scope")
		if got := listedOverHTTP(t, c, key, device); got.CanPause {
			t.Fatalf("a %s key's number says can_pause", scope)
		}
	}

	// A key that acts as a service account: the key's full scope and the
	// account's own Manage flag, as before; the account acts as itself.
	svc, err := c.users.CreateService(ctx, c.tenant, "erp", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	acting, actingKey := issue("erp", store.ScopeFull, &svc.ID, nil)
	refused(t, c, acting, device, "a service account without Manage", "service account with the number's Manage permission")
	if err := c.users.SetDevicePermission(ctx, c.tenant, c.owner, store.DevicePermission{DeviceID: device, UserID: svc.ID, Manage: true}); err != nil {
		t.Fatal(err)
	}
	if got := listedOverHTTP(t, c, actingKey, device); !got.CanManage || !got.CanPause {
		t.Fatalf("the service account's number: %+v", got)
	}
	pauses(t, c, acting, c.tenant, device, "a service account with Manage")
	// Its send-scoped key may not, Manage or not.
	sending, _ := issue("erp-send", store.ScopeSend, &svc.ID, nil)
	refused(t, c, sending, device, "a service account's send key", "full scope")
}

// device.start on a number that is not paused is Wappie's "sync now": it
// connects the number now, and keeps Manage (the platform's design of
// 2026-10-26 gives it to readers with the contract's item.sync_now). A
// member with Manage reconnects an offline number nobody paused, lifts no
// pause doing it and leaves none behind when it fails; on a paused number
// the start is a resume, and refused.
func TestSyncNowKeepsManage(t *testing.T) {
	c := newDeletionConsoleWith(t, deletionOptions{registry: true})
	ctx := context.Background()
	device := c.linkedDevice(t, "Vendas")
	ref := wsapi.DeviceRef{DeviceID: device.String()}
	owner := wsapi.Hello{Session: c.token}
	manager, managerToken := c.person(t, "ana", "member")
	if err := c.users.SetDevicePermission(ctx, c.tenant, c.owner, store.DevicePermission{DeviceID: device, UserID: manager, Read: true, Manage: true}); err != nil {
		t.Fatal(err)
	}
	reader, readerToken := c.person(t, "caio", "member")
	c.reads(t, reader, device)
	member := wsapi.Hello{Session: managerToken}
	offline := func() {
		t.Helper()
		c.registry.Stop(ctx, device.String())
		if err := c.devices.SetStatus(ctx, c.tenant.String(), device.String(), wa.StatusOffline, ""); err != nil {
			t.Fatal(err)
		}
	}

	offline()
	if f := ask(t, c.console, member, wsapi.TypeDeviceStart, ref); f.Type != wsapi.TypeDeviceStatus {
		t.Fatalf("the member's sync now: %s %s", f.Type, f.Payload)
	}
	if c.paused(t, c.tenant, device) {
		t.Fatal("the member's sync now paused the number")
	}
	// A member without Manage may not: the refusal is Manage's.
	e := wantError(t, ask(t, c.console, wsapi.Hello{Session: readerToken}, wsapi.TypeDeviceStart, ref), wsapi.ErrCodeNotAuthorized)
	if !strings.Contains(e.Message, "manage permission") {
		t.Errorf("a reader's sync now: %q", e.Message)
	}

	// Paused, the start is a resume: the member is told the role rule, and
	// the pause stays.
	if f := ask(t, c.console, owner, wsapi.TypeDeviceStop, ref); f.Type != wsapi.TypeDeviceStatus {
		t.Fatalf("the owner's stop: %s %s", f.Type, f.Payload)
	}
	e = wantError(t, ask(t, c.console, member, wsapi.TypeDeviceStart, ref), wsapi.ErrCodeNotAuthorized)
	if !strings.Contains(e.Message, "owner or an admin") || !c.paused(t, c.tenant, device) {
		t.Fatalf("the member's start on a paused number: %q, paused %v", e.Message, c.paused(t, c.tenant, device))
	}
	if f := ask(t, c.console, owner, wsapi.TypeDeviceStart, ref); f.Type != wsapi.TypeDeviceStatus {
		t.Fatalf("the owner's start: %s %s", f.Type, f.Payload)
	}

	// A sync now that fails puts back no pause, since it took none.
	offline()
	if _, err := c.pool.Exec(ctx, `DELETE FROM whatsmeow_device`); err != nil {
		t.Fatal(err)
	}
	wantError(t, ask(t, c.console, member, wsapi.TypeDeviceStart, ref), wsapi.ErrCodeConflict)
	if c.paused(t, c.tenant, device) {
		t.Fatal("the member's failed sync now paused the number")
	}
}

// A pairing retry stays Manage's. A retry of a registration that an owner
// or an admin paused also lifts that pause, which is resuming, by role: a
// member with Manage is refused it, and the pause stays.
func TestPairingRetryLiftsAPauseByRole(t *testing.T) {
	// No registry: a retry that passes its checks stops at the connection.
	c := newDeletionConsole(t)
	ctx := context.Background()
	pending := uuid.MustParse(c.deviceWithKey(t, "pending"))
	manager, managerToken := c.person(t, "ana", "member")
	if err := c.users.SetDevicePermission(ctx, c.tenant, c.owner, store.DevicePermission{DeviceID: pending, UserID: manager, Manage: true}); err != nil {
		t.Fatal(err)
	}
	_, adminToken := c.person(t, "bia", "admin")
	member, admin := wsapi.Hello{Session: managerToken}, wsapi.Hello{Session: adminToken}
	retry := wsapi.PairRequest{DeviceID: pending.String(), Resume: true, Method: "qr"}
	passes := func(who string, hello wsapi.Hello) {
		t.Helper()
		e := wantError(t, ask(t, c.console, hello, wsapi.TypePair, retry), wsapi.ErrCodeInternal)
		if !strings.Contains(e.Message, "WhatsApp connection is unavailable") {
			t.Fatalf("%s's retry: %q", who, e.Message)
		}
	}

	// Not paused: the member's retry passes its checks.
	passes("the member", member)

	// Paused by an admin: the member's retry is refused with the role rule.
	if f := ask(t, c.console, admin, wsapi.TypeDeviceStop, wsapi.DeviceRef{DeviceID: pending.String()}); f.Type != wsapi.TypeDeviceStatus {
		t.Fatalf("the admin's stop: %s %s", f.Type, f.Payload)
	}
	e := wantError(t, ask(t, c.console, member, wsapi.TypePair, retry), wsapi.ErrCodeNotAuthorized)
	if !strings.Contains(e.Message, "owner or an admin") {
		t.Errorf("the member's retry of a paused registration: %q", e.Message)
	}
	if !c.paused(t, c.tenant, pending) {
		t.Fatal("the member's refused retry lifted the admin's pause")
	}
	// The admin's own retry passes them.
	passes("the admin", admin)
}
