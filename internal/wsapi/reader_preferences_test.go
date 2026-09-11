package wsapi_test

import (
	"context"
	"testing"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
	"whatserver2/internal/wsapi"
)

// Access-revocation fixtures retain a genuinely usable backup envelope. The
// last-reader test separately proves administrators alone are not a backup.
func retainBackupReader(t *testing.T, pool *pgxpool.Pool, tenant, device uuid.UUID) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	user, err := store.NewUsers(pool).Create(ctx, store.NewUser{TenantID: tenant, Email: "backup-" + uuid.NewString() + "@reader.test", Role: "member", AuthKey: "proof", KDFSalt: make([]byte, 16), KDFParams: store.DefaultKDFParams(), PublicKey: make([]byte, 32), WrappedUSK: []byte("wrapped")})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.NewKeys(pool).PutGrant(ctx, store.Grant{TenantID: tenant, DeviceID: device, UserID: user.ID, Epoch: 1, SealedDSK: []byte("backup envelope")}, nil); err != nil {
		t.Fatal(err)
	}
	return user.ID
}

func TestReadingPreferenceBelongsToOnePersonAndNumber(t *testing.T) {
	c := newConsole(t)
	ctx := context.Background()
	device := uuid.MustParse(c.deviceWithKey(t, "shared"))
	second := uuid.MustParse(c.deviceWithKey(t, "second"))
	aToken := c.account(t, "alice@preferences.test", "member")
	bToken := c.account(t, "bob@preferences.test", "member")
	_, a, err := c.users.ActiveSession(ctx, aToken)
	if err != nil {
		t.Fatal(err)
	}
	_, b, err := c.users.ActiveSession(ctx, bToken)
	if err != nil {
		t.Fatal(err)
	}
	for _, who := range []store.User{a, b} {
		for _, id := range []uuid.UUID{device, second} {
			if err := store.NewKeys(c.pool).PutGrant(ctx, store.Grant{TenantID: c.tenant, DeviceID: id, UserID: who.ID, Epoch: 1, SealedDSK: []byte("sealed")}, nil); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Even a read-only member may control their own preference.
	ownerToken := c.account(t, "owner@preferences.test", "owner")
	_, owner, err := c.users.ActiveSession(ctx, ownerToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.users.SetDevicePermission(ctx, c.tenant, owner.ID, store.DevicePermission{DeviceID: device, UserID: a.ID, Read: true}); err != nil {
		t.Fatal(err)
	}
	request := wsapi.DeviceModeRequest{DeviceID: device.String(), ReceiptMode: "active"}
	wantError(t, ask(t, c, wsapi.Hello{APIKey: c.apiKey}, wsapi.TypeReaderMode, request), wsapi.ErrCodeNotAuthorized)
	wantError(t, ask(t, c, wsapi.Hello{Session: ownerToken}, wsapi.TypeReaderMode, request), wsapi.ErrCodeNotAuthorized)
	f := ask(t, c, wsapi.Hello{Session: aToken}, wsapi.TypeReaderMode, request)
	if f.Type != wsapi.TypeReaderMode {
		t.Fatalf("mode=%s %s", f.Type, f.Payload)
	}
	// No registry is connected here. Reaching that explicit conflict proves a
	// read-only person passed authorization, while content/digitation still fail.
	readRequest := wsapi.MarkReadRequest{DeviceID: device.String(), Chat: streamChat, IDs: []string{"seen"}}
	wantError(t, ask(t, c, wsapi.Hello{Session: aToken}, wsapi.TypeMarkRead, readRequest), wsapi.ErrCodeConflict)
	readRequest.Played = true
	wantError(t, ask(t, c, wsapi.Hello{Session: aToken}, wsapi.TypeMarkRead, readRequest), wsapi.ErrCodeConflict)
	wantError(t, ask(t, c, wsapi.Hello{Session: aToken}, wsapi.TypeChatTyping, wsapi.ChatPresenceRequest{DeviceID: device.String(), Chat: streamChat, State: "composing"}), wsapi.ErrCodeNotAuthorized)
	for _, tc := range []struct {
		user, device uuid.UUID
		want         wa.ReceiptMode
	}{{a.ID, device, wa.ModeActive}, {b.ID, device, wa.ModePassive}, {a.ID, second, wa.ModePassive}} {
		mode, err := c.users.ReaderMode(ctx, c.tenant, tc.user, tc.device)
		if err != nil || mode != tc.want {
			t.Fatalf("preference=%s want=%s err=%v", mode, tc.want, err)
		}
	}
	shared, err := c.devices.Get(ctx, c.tenant.String(), device.String())
	if err != nil || shared.ReceiptMode != wa.ModePassive {
		t.Fatalf("personal preference changed shared policy: %+v %v", shared, err)
	}
	listed := payload[wsapi.Devices](t, ask(t, c, wsapi.Hello{Session: aToken}, wsapi.TypeDevicesList, nil))
	found := false
	for _, d := range listed.Devices {
		if d.ID == device.String() {
			found = true
			if d.ReaderReceiptMode != "active" || d.ReceiptMode != "passive" {
				t.Fatalf("device preferences=%+v", d)
			}
		}
	}
	if !found {
		t.Fatal("number missing")
	}
	request.ReceiptMode = "unknown"
	wantError(t, ask(t, c, wsapi.Hello{Session: aToken}, wsapi.TypeReaderMode, request), wsapi.ErrCodeBadRequest)
}

func TestReaderPreferenceBroadcastReachesOnlySamePerson(t *testing.T) {
	c := newConsole(t)
	ctx := context.Background()
	device := uuid.MustParse(c.deviceWithKey(t, "shared"))
	tokens := []string{c.account(t, "a@broadcast.test", "member"), c.account(t, "b@broadcast.test", "member")}
	for _, token := range tokens {
		_, user, err := c.users.ActiveSession(ctx, token)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.NewKeys(c.pool).PutGrant(ctx, store.Grant{TenantID: c.tenant, DeviceID: device, UserID: user.ID, Epoch: 1, SealedDSK: []byte("sealed")}, nil); err != nil {
			t.Fatal(err)
		}
	}
	a, otherTab, b := dial(t, c.srv), dial(t, c.srv), dial(t, c.srv)
	for i, conn := range []*websocket.Conn{a, otherTab, b} {
		token := tokens[0]
		if i == 2 {
			token = tokens[1]
		}
		send(t, conn, wsapi.TypeHello, wsapi.Hello{Session: token, Version: wsapi.Version})
		if f := read(t, conn); f.Type != wsapi.TypeWelcome {
			t.Fatalf("hello: %s %s", f.Type, f.Payload)
		}
	}
	send(t, a, wsapi.TypeReaderMode, wsapi.DeviceModeRequest{DeviceID: device.String(), ReceiptMode: "active"})
	if f := read(t, a); f.Type != wsapi.TypeReaderMode {
		t.Fatalf("reply=%s", f.Type)
	}
	if f := read(t, otherTab); f.Type != wsapi.TypeReaderMode || payload[wsapi.DeviceModeRequest](t, f).ReceiptMode != "active" {
		t.Fatalf("same person=%s %s", f.Type, f.Payload)
	}
	// A request/reply marker catches a leaked preference without a timeout.
	send(t, b, wsapi.TypeDevicesList, nil)
	listedFrame := read(t, b)
	if listedFrame.Type != wsapi.TypeDevices {
		t.Fatalf("another person received preference: %s", listedFrame.Type)
	}
	listed := payload[wsapi.Devices](t, listedFrame)
	if len(listed.Devices) != 1 || listed.Devices[0].ReaderReceiptMode != "passive" {
		t.Fatalf("other user changed: %+v", listed)
	}
}
