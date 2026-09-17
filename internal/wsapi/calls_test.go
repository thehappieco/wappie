package wsapi_test

import (
	"context"
	"log/slog"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"whatserver2/internal/calling"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
	"whatserver2/internal/wsapi"
)

func callCommandPayload(kind, device string) any {
	switch kind {
	case wsapi.TypeCallsList:
		return wsapi.CallsListRequest{DeviceID: device}
	case wsapi.TypeCallInvite:
		return wsapi.CallInviteRequest{DeviceID: device, CallID: "pending-call", Participants: []string{"5511888888888@s.whatsapp.net"}}
	case wsapi.TypeCallStart:
		return wsapi.CallStartRequest{DeviceID: device, Chat: streamChat, Video: true}
	default:
		return wsapi.CallRequest{DeviceID: device, CallID: "pending-call"}
	}
}

var callCommands = []string{wsapi.TypeCallsList, wsapi.TypeCallStart, wsapi.TypeCallAnswer, wsapi.TypeCallReject, wsapi.TypeCallHangup, wsapi.TypeCallMedia, wsapi.TypeCallInvite}

func TestCallsRequireSendPermissionForEveryOperation(t *testing.T) {
	c := newConsole(t)
	ctx := context.Background()
	device := c.deviceWithKey(t, "calls")
	readKey, err := c.keys.IssueScoped(ctx, c.tenant.String(), "read-only", store.ScopeRead, nil)
	if err != nil {
		t.Fatal(err)
	}
	memberToken := c.account(t, "reader@calls.test", "member")
	ownerToken := c.account(t, "owner@calls.test", "owner")
	for _, kind := range callCommands {
		for _, hello := range []wsapi.Hello{{APIKey: readKey}, {Session: memberToken}, {Session: ownerToken}} {
			wantError(t, ask(t, c, hello, kind, callCommandPayload(kind, device)), wsapi.ErrCodeNotAuthorized)
		}
	}

	_, owner, err := c.users.ActiveSession(ctx, ownerToken)
	if err != nil {
		t.Fatal(err)
	}
	_, member, err := c.users.ActiveSession(ctx, memberToken)
	if err != nil {
		t.Fatal(err)
	}
	// Call control is a send permission. It does not grant access to the
	// encrypted archive and does not require the archive's decryption key.
	if err := c.users.SetDevicePermission(ctx, c.tenant, owner.ID, store.DevicePermission{
		DeviceID: uuid.MustParse(device), UserID: member.ID, Read: true, Send: true,
	}); err != nil {
		t.Fatal(err)
	}
	f := ask(t, c, wsapi.Hello{Session: memberToken}, wsapi.TypeCallsList, wsapi.CallsListRequest{DeviceID: device})
	if f.Type != wsapi.TypeCallsListResult {
		t.Fatalf("send-authorized member could not list calls: %s %s", f.Type, f.Payload)
	}
	for _, kind := range callCommands[1:] {
		wantError(t, ask(t, c, wsapi.Hello{Session: memberToken}, kind, callCommandPayload(kind, device)), wsapi.ErrCodeConflict)
	}
}

func TestCallsResolveDeviceWithinTenantBeforeUsingProvider(t *testing.T) {
	c := newConsole(t)
	ctx := context.Background()
	var otherTenant uuid.UUID
	if err := c.pool.QueryRow(ctx, `INSERT INTO tenants(name) VALUES('other calls tenant') RETURNING id`).Scan(&otherTenant); err != nil {
		t.Fatal(err)
	}
	other, err := c.devices.Create(ctx, otherTenant.String(), "private number", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range callCommands {
		wantError(t, ask(t, c, wsapi.Hello{APIKey: c.apiKey}, kind, callCommandPayload(kind, other.ID)), wsapi.ErrCodeNotFound)
		wantError(t, ask(t, c, wsapi.Hello{APIKey: c.apiKey}, kind, callCommandPayload(kind, "")), wsapi.ErrCodeBadRequest)
	}
}

func TestCallsDisabledProviderReportsUnavailable(t *testing.T) {
	c := newConsole(t)
	device := c.deviceWithKey(t, "calls disabled")
	f := ask(t, c, wsapi.Hello{APIKey: c.apiKey}, wsapi.TypeCallsList, wsapi.CallsListRequest{DeviceID: device[:8]})
	if f.Type != wsapi.TypeCallsListResult {
		t.Fatalf("list returned %s %s", f.Type, f.Payload)
	}
	result := payload[wsapi.CallsListResult](t, f)
	if result.Available || result.Calls == nil || len(result.Calls) != 0 {
		t.Fatalf("disabled provider returned %+v", result)
	}
	for _, kind := range callCommands[1:] {
		wantError(t, ask(t, c, wsapi.Hello{APIKey: c.apiKey}, kind, callCommandPayload(kind, device)), wsapi.ErrCodeConflict)
	}
}

func TestCallsListingDoesNotStartAnOfflineDevice(t *testing.T) {
	c := newConsole(t)
	calls := calling.New()
	c.srv = httptest.NewServer(wsapi.NewServer(wsapi.Config{
		Keys: c.keys, Sessions: c.users, Accounts: c.users, Devices: c.devices,
		Calls: calls, Log: slog.New(slog.DiscardHandler),
	}))
	t.Cleanup(c.srv.Close)
	device := c.deviceWithKey(t, "offline calls")
	for range 2 {
		f := ask(t, c, wsapi.Hello{APIKey: c.apiKey}, wsapi.TypeCallsList, wsapi.CallsListRequest{DeviceID: device})
		if f.Type != wsapi.TypeCallsListResult {
			t.Fatalf("offline device list returned %s %s", f.Type, f.Payload)
		}
		result := payload[wsapi.CallsListResult](t, f)
		if result.Available || result.Calls == nil || len(result.Calls) != 0 {
			t.Fatalf("listing created a call or claimed an unattached device was available: %+v", result)
		}
	}
}
