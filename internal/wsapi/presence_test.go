package wsapi_test

import (
	"context"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/bus"
	"whatserver2/internal/ingest"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
	"whatserver2/internal/wsapi"
)

func wantPresenceUnavailable(t *testing.T, f wsapi.Frame, device, chat string) {
	t.Helper()
	if f.Type != wsapi.TypePresenceWatch {
		t.Fatalf("presence response=%s %s", f.Type, f.Payload)
	}
	p := payload[wsapi.PresenceSubscription](t, f)
	if p.DeviceID != device || p.Chat != chat || p.Subscribed || p.Reason != "disconnected" {
		t.Fatalf("presence response=%+v, want explicit disconnected state", p)
	}
}

func TestPresenceSubscribeRequiresReadAndCurrentGrant(t *testing.T) {
	c := newConsole(t)
	ctx := context.Background()
	device := uuid.MustParse(c.deviceWithKey(t, "main"))
	other := c.deviceWithKey(t, "private")
	req := wsapi.PresenceSubscribeRequest{DeviceID: device.String(), Chat: streamChat}
	ownerToken := c.account(t, "owner@presence.test", "owner")
	_, owner, err := c.users.ActiveSession(ctx, ownerToken)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"owner", "admin", "member"} {
		token := ownerToken
		if role != "owner" {
			token = c.account(t, role+"@presence.test", role)
		}
		t.Run(role+" without grant", func(t *testing.T) {
			wantError(t, ask(t, c, wsapi.Hello{Session: token}, wsapi.TypePresenceWatch, req), wsapi.ErrCodeNotAuthorized)
		})
	}
	token := c.account(t, "reader@presence.test", "member")
	_, member, err := c.users.ActiveSession(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	permission := store.DevicePermission{DeviceID: device, UserID: member.ID, Read: true}
	if err := c.users.SetDevicePermission(ctx, c.tenant, owner.ID, permission); err != nil {
		t.Fatal(err)
	}
	wantError(t, ask(t, c, wsapi.Hello{Session: token}, wsapi.TypePresenceWatch, req), wsapi.ErrCodeNotAuthorized)
	keys := store.NewKeys(c.pool)
	if err := keys.PutGrant(ctx, store.Grant{TenantID: c.tenant, DeviceID: device, UserID: member.ID, Epoch: 1, SealedDSK: []byte("sealed")}, nil); err != nil {
		t.Fatal(err)
	}
	// Reading is enough: observing a contact must not need send/manage access.
	if err := c.users.SetDevicePermission(ctx, c.tenant, owner.ID, permission); err != nil {
		t.Fatal(err)
	}
	wantPresenceUnavailable(t, ask(t, c, wsapi.Hello{Session: token}, wsapi.TypePresenceWatch, req), device.String(), streamChat)
	wantError(t, ask(t, c, wsapi.Hello{Session: token}, wsapi.TypePresenceWatch,
		wsapi.PresenceSubscribeRequest{DeviceID: other, Chat: streamChat}), wsapi.ErrCodeNotAuthorized)
	if err := keys.PutGrant(ctx, store.Grant{TenantID: c.tenant, DeviceID: device, UserID: owner.ID, Epoch: 1, SealedDSK: []byte("backup")}, nil); err != nil {
		t.Fatal(err)
	}
	permission.Read, permission.Send, permission.Manage = false, true, true
	if err := c.users.SetDevicePermission(ctx, c.tenant, owner.ID, permission); err != nil {
		t.Fatal(err)
	}
	wantError(t, ask(t, c, wsapi.Hello{Session: token}, wsapi.TypePresenceWatch, req), wsapi.ErrCodeNotAuthorized)
}

func TestPresenceSubscribeRejectsGroupsAndNormalizesIndividualAddresses(t *testing.T) {
	c := newConsole(t)
	device := c.deviceWithKey(t, "main")
	key, err := c.keys.IssueScoped(context.Background(), c.tenant.String(), "reader", store.ScopeRead, nil)
	if err != nil {
		t.Fatal(err)
	}
	hello := wsapi.Hello{APIKey: key}
	for _, chat := range []string{"", "not-a-jid", "@s.whatsapp.net", "1234@g.us", "status@broadcast", "1234@newsletter"} {
		t.Run(chat, func(t *testing.T) {
			wantError(t, ask(t, c, hello, wsapi.TypePresenceWatch, wsapi.PresenceSubscribeRequest{DeviceID: device, Chat: chat}), wsapi.ErrCodeBadRequest)
		})
	}
	for _, tc := range []struct{ in, out string }{
		{streamChat, streamChat}, {"91938170638392@lid", "91938170638392@lid"},
		{"5511999999999:2@s.whatsapp.net", streamChat},
	} {
		wantPresenceUnavailable(t, ask(t, c, hello, wsapi.TypePresenceWatch,
			wsapi.PresenceSubscribeRequest{DeviceID: device[:8], Chat: tc.in}), device, tc.out)
	}
	wantError(t, ask(t, c, hello, wsapi.TypePresenceWatch, wsapi.PresenceSubscribeRequest{Chat: streamChat}), wsapi.ErrCodeBadRequest)
	var otherTenant uuid.UUID
	if err := c.pool.QueryRow(context.Background(), `INSERT INTO tenants(name) VALUES('other') RETURNING id`).Scan(&otherTenant); err != nil {
		t.Fatal(err)
	}
	other, err := c.devices.Create(context.Background(), otherTenant.String(), "other tenant", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	wantError(t, ask(t, c, hello, wsapi.TypePresenceWatch, wsapi.PresenceSubscribeRequest{DeviceID: other.ID, Chat: streamChat}), wsapi.ErrCodeNotFound)
}

func TestPresenceServiceTokenUsesItsGrants(t *testing.T) {
	c := newConsole(t)
	ctx := context.Background()
	device := uuid.MustParse(c.deviceWithKey(t, "granted"))
	other := c.deviceWithKey(t, "not granted")
	service, err := c.users.CreateService(ctx, c.tenant, "presence-reader", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	key, err := c.keys.IssueActingAs(ctx, c.tenant.String(), "service", store.ScopeRead, nil, &service.ID)
	if err != nil {
		t.Fatal(err)
	}
	req := wsapi.PresenceSubscribeRequest{DeviceID: device.String(), Chat: streamChat}
	wantError(t, ask(t, c, wsapi.Hello{APIKey: key}, wsapi.TypePresenceWatch, req), wsapi.ErrCodeNotAuthorized)
	if err := store.NewKeys(c.pool).PutGrant(ctx, store.Grant{TenantID: c.tenant, DeviceID: device, UserID: service.ID, Epoch: 1, SealedDSK: []byte("sealed")}, nil); err != nil {
		t.Fatal(err)
	}
	wantPresenceUnavailable(t, ask(t, c, wsapi.Hello{APIKey: key}, wsapi.TypePresenceWatch, req), device.String(), streamChat)
	wantError(t, ask(t, c, wsapi.Hello{APIKey: key}, wsapi.TypePresenceWatch,
		wsapi.PresenceSubscribeRequest{DeviceID: other, Chat: streamChat}), wsapi.ErrCodeNotAuthorized)
}

func TestPresenceStreamIsFilteredByTenantAndGrantedDevice(t *testing.T) {
	c := newConsole(t)
	ctx := context.Background()
	b := bus.New()
	c.srv = httptest.NewServer(wsapi.NewServer(wsapi.Config{
		Keys: c.keys, Sessions: c.users, Accounts: c.users, Devices: c.devices,
		Messages: store.NewMessages(c.pool), Keys2: store.NewKeys(c.pool), Bus: b,
		Log: slog.New(slog.DiscardHandler),
	}))
	t.Cleanup(c.srv.Close)
	device := uuid.MustParse(c.deviceWithKey(t, "granted"))
	other := uuid.MustParse(c.deviceWithKey(t, "not granted"))
	token := c.account(t, "viewer@presence.test", "member")
	_, member, err := c.users.ActiveSession(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	keys := store.NewKeys(c.pool)
	if err := keys.PutGrant(ctx, store.Grant{TenantID: c.tenant, DeviceID: device, UserID: member.ID, Epoch: 1, SealedDSK: []byte("sealed")}, nil); err != nil {
		t.Fatal(err)
	}
	conn := dial(t, c.srv)
	send(t, conn, wsapi.TypeHello, wsapi.Hello{Session: token, Version: wsapi.Version})
	if f := read(t, conn); f.Type != wsapi.TypeWelcome {
		t.Fatalf("hello=%s %s", f.Type, f.Payload)
	}
	send(t, conn, wsapi.TypeSubscribe, wsapi.Subscribe{LiveOnly: true})
	if f := read(t, conn); f.Type != wsapi.TypeReplayEnd {
		t.Fatalf("subscribe=%s %s", f.Type, f.Payload)
	}
	lastSeen := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	publish := func(tenant, source uuid.UUID, state string, seen *time.Time) {
		b.Publish(tenant, ingest.Event{Class: ingest.ClassPresence, TenantID: tenant, DeviceID: source, ChatKey: streamChat, Ephemeral: true,
			Presence: &ingest.Presence{ChatKey: streamChat, SenderKey: streamChat, SenderPN: streamChat, State: state, LastSeen: seen}})
	}
	// Denied events precede an allowed marker, so a leaked frame fails without a timing-sensitive negative assertion.
	publish(uuid.New(), device, "foreign tenant", nil)
	publish(c.tenant, other, "ungranted device", nil)
	publish(c.tenant, device, "available", nil)
	publish(c.tenant, device, "unavailable", &lastSeen)
	for _, state := range []string{"available", "unavailable"} {
		f := read(t, conn)
		if f.Type != wsapi.TypePresence {
			t.Fatalf("presence=%s %s", f.Type, f.Payload)
		}
		p := payload[wsapi.PresenceEvent](t, f)
		if p.DeviceID != device.String() || p.State != state || p.ChatKey != streamChat || p.SenderPN != streamChat {
			t.Fatalf("presence leaked or lost routing: %+v", p)
		}
		if state == "available" && p.LastSeen != nil || state == "unavailable" && (p.LastSeen == nil || !p.LastSeen.Equal(lastSeen)) {
			t.Fatalf("last seen=%v for %s", p.LastSeen, state)
		}
	}
	retainBackupReader(t, c.pool, c.tenant, device)
	if err := keys.RevokeGrant(ctx, c.tenant, device, member.ID); err != nil {
		t.Fatal(err)
	}
	expectAccessClosed(t, conn)
	wantError(t, ask(t, c, wsapi.Hello{Session: token}, wsapi.TypePresenceWatch,
		wsapi.PresenceSubscribeRequest{DeviceID: device.String(), Chat: streamChat}), wsapi.ErrCodeNotAuthorized)
}
