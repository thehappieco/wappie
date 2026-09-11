package wsapi_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
	"whatserver2/internal/wsapi"
)

func expectAccessClosed(t *testing.T, conn *websocket.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	_, data, err := conn.Read(ctx)
	if err == nil {
		t.Fatalf("revoked connection delivered a frame: %s", data)
	}
	if websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Fatalf("expected policy close, got %v", err)
	}
}

func TestIdleConnectionsRevalidateAuthorization(t *testing.T) {
	for _, action := range []string{"logout", "expiry", "password", "demotion", "disable", "suspend"} {
		t.Run(action, func(t *testing.T) {
			c := newConsole(t)
			ctx := context.Background()
			ownerToken := c.account(t, "owner@example.com", "owner")
			token := c.account(t, "target@example.com", "admin")
			_, owner, err := c.users.ActiveSession(ctx, ownerToken)
			if err != nil {
				t.Fatal(err)
			}
			sess, user, err := c.users.ActiveSession(ctx, token)
			if err != nil {
				t.Fatal(err)
			}
			conn := dial(t, c.srv)
			send(t, conn, wsapi.TypeHello, wsapi.Hello{Session: token, Version: wsapi.Version})
			if f := read(t, conn); f.Type != wsapi.TypeWelcome {
				t.Fatalf("hello: %s", f.Type)
			}
			switch action {
			case "logout":
				err = c.users.EndSession(ctx, token)
			case "expiry":
				_, err = c.pool.Exec(ctx, `UPDATE sessions SET expires_at=now() WHERE id=$1`, sess.ID)
			case "password":
				err = c.users.Rekey(ctx, c.tenant, user.ID, store.Rekey{AuthKey: "new-proof", KDFSalt: user.KDFSalt, KDFParams: user.KDFParams, WrappedUSK: user.WrappedUSK})
			case "demotion":
				err = c.users.UpdateMember(ctx, c.tenant, owner.ID, user.ID, "member", "active")
			case "disable":
				err = c.users.UpdateMember(ctx, c.tenant, owner.ID, user.ID, "admin", "disabled")
			case "suspend":
				_, err = c.pool.Exec(ctx, `UPDATE tenants SET status='suspended' WHERE id=$1`, c.tenant)
			}
			if err != nil {
				t.Fatal(err)
			}
			expectAccessClosed(t, conn)
			if action != "suspend" {
				f := ask(t, c, wsapi.Hello{Session: ownerToken}, wsapi.TypePing, nil)
				if f.Type != wsapi.TypePong {
					t.Fatalf("unrelated connection affected: %s", f.Type)
				}
			}
		})
	}
}

func TestExternalKeyRevocationStopsLiveDelivery(t *testing.T) {
	s := newStream(t)
	conn := dial(t, s.srv)
	send(t, conn, wsapi.TypeHello, wsapi.Hello{APIKey: s.key, Version: wsapi.Version})
	if f := read(t, conn); f.Type != wsapi.TypeWelcome {
		t.Fatalf("hello: %s", f.Type)
	}
	send(t, conn, wsapi.TypeSubscribe, wsapi.Subscribe{LiveOnly: true})
	if f := read(t, conn); f.Type != wsapi.TypeReplayEnd {
		t.Fatalf("subscribe: %s", f.Type)
	}
	prefix, _, _ := strings.Cut(s.key, ".")
	if err := store.NewAPIKeys(s.pool).Revoke(context.Background(), s.tenant.String(), prefix); err != nil {
		t.Fatal(err)
	}
	s.live(t, "must-not-arrive")
	expectAccessClosed(t, conn)
}

func TestGrantRevocationClosesMemberAndServiceSockets(t *testing.T) {
	for _, service := range []bool{false, true} {
		t.Run(map[bool]string{false: "person", true: "service"}[service], func(t *testing.T) {
			c := newConsole(t)
			ctx := context.Background()
			var user store.User
			var hello wsapi.Hello
			if service {
				var err error
				user, err = c.users.CreateService(ctx, c.tenant, "erp", make([]byte, 32))
				if err != nil {
					t.Fatal(err)
				}
				key, err := c.keys.IssueActingAs(ctx, c.tenant.String(), "erp", store.ScopeRead, nil, &user.ID)
				if err != nil {
					t.Fatal(err)
				}
				hello = wsapi.Hello{APIKey: key, Version: wsapi.Version}
			} else {
				token := c.account(t, "reader@example.com", "member")
				_, u, err := c.users.ActiveSession(ctx, token)
				if err != nil {
					t.Fatal(err)
				}
				user = u
				hello = wsapi.Hello{Session: token, Version: wsapi.Version}
			}
			device, err := c.devices.Create(ctx, c.tenant.String(), "test", wa.ModePassive)
			if err != nil {
				t.Fatal(err)
			}
			id := uuid.MustParse(device.ID)
			keys := store.NewKeys(c.pool)
			pub, _, err := seal.GenerateKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			if err := keys.CreateArchiveKey(ctx, c.tenant, id, 1, pub); err != nil {
				t.Fatal(err)
			}
			if err := keys.PutGrant(ctx, store.Grant{TenantID: c.tenant, DeviceID: id, UserID: user.ID, Epoch: 1, SealedDSK: []byte("sealed")}, nil); err != nil {
				t.Fatal(err)
			}
			conn := dial(t, c.srv)
			send(t, conn, wsapi.TypeHello, hello)
			if f := read(t, conn); f.Type != wsapi.TypeWelcome {
				t.Fatalf("hello: %s", f.Type)
			}
			retainBackupReader(t, c.pool, c.tenant, id)
			if err := keys.RevokeGrant(ctx, c.tenant, id, user.ID); err != nil {
				t.Fatal(err)
			}
			expectAccessClosed(t, conn)
			f := ask(t, c, hello, wsapi.TypeSubscribe, wsapi.Subscribe{})
			wantError(t, f, wsapi.ErrCodeNotAuthorized)
		})
	}
}

func TestMemberSubscriptionFiltersReplayAndLiveDevices(t *testing.T) {
	s := newStream(t)
	ctx := context.Background()
	users := store.NewUsers(s.pool)
	user, err := users.Create(ctx, store.NewUser{TenantID: s.tenant, Email: "reader@example.com", Role: "member", AuthKey: "proof", KDFSalt: make([]byte, 16), KDFParams: store.DefaultKDFParams(), PublicKey: make([]byte, 32), WrappedUSK: []byte("wrapped")})
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := users.StartSession(ctx, user, "test")
	if err != nil {
		t.Fatal(err)
	}
	keys := store.NewKeys(s.pool)
	devices := store.NewDevices(s.pool)
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.CreateArchiveKey(ctx, s.tenant, s.device, 1, pub); err != nil {
		t.Fatal(err)
	}
	if err := keys.PutGrant(ctx, store.Grant{TenantID: s.tenant, DeviceID: s.device, UserID: user.ID, Epoch: 1, SealedDSK: []byte("sealed")}, nil); err != nil {
		t.Fatal(err)
	}
	hiddenDevice, err := devices.Create(ctx, s.tenant.String(), "hidden", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	hidden := *s
	hidden.device = uuid.MustParse(hiddenDevice.ID)
	s.put(t, "allowed-history")
	hidden.put(t, "hidden-history")
	server := wsapi.NewServer(wsapi.Config{Keys: store.NewAPIKeys(s.pool), Sessions: users, Accounts: users, Devices: devices, Keys2: keys, Messages: s.messages, Receipts: s.receipts, Bus: s.bus})
	srv := httptest.NewServer(server)
	t.Cleanup(srv.Close)
	conn := dial(t, srv)
	send(t, conn, wsapi.TypeHello, wsapi.Hello{Session: token, Version: wsapi.Version})
	if f := read(t, conn); f.Type != wsapi.TypeWelcome {
		t.Fatalf("hello: %s", f.Type)
	}
	send(t, conn, wsapi.TypeDevicesList, nil)
	listed := payload[wsapi.Devices](t, read(t, conn))
	if len(listed.Devices) != 1 || listed.Devices[0].ID != s.device.String() {
		t.Fatalf("directory leaked: %+v", listed)
	}
	send(t, conn, wsapi.TypeSubscribe, wsapi.Subscribe{})
	if f := read(t, conn); f.Type != wsapi.TypeReplayBegin {
		t.Fatalf("replay start: %s", f.Type)
	}
	msg := payload[wsapi.SealedMessage](t, read(t, conn))
	if msg.DeviceID != s.device.String() {
		t.Fatalf("hidden history delivered: %+v", msg)
	}
	if f := read(t, conn); f.Type != wsapi.TypeReplayEnd {
		t.Fatalf("extra history frame: %s", f.Type)
	}
	hidden.live(t, "hidden-live")
	s.live(t, "allowed-live")
	msg = payload[wsapi.SealedMessage](t, read(t, conn))
	if msg.DeviceID != s.device.String() {
		t.Fatalf("hidden live event delivered: %+v", msg)
	}
	retainBackupReader(t, s.pool, s.tenant, s.device)
	if err := keys.RevokeGrant(ctx, s.tenant, s.device, user.ID); err != nil {
		t.Fatal(err)
	}
	server.RevalidateAccess()
	s.live(t, "after-revocation")
	expectAccessClosed(t, conn)
}

func TestMemberDeviceAccessFailsClosedWithoutGrantStore(t *testing.T) {
	c := newConsole(t)
	token := c.account(t, "reader@example.com", "member")
	device, err := c.devices.Create(context.Background(), c.tenant.String(), "test", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(wsapi.NewServer(wsapi.Config{Sessions: c.users, Accounts: c.users, Devices: c.devices, Messages: store.NewMessages(c.pool)}))
	t.Cleanup(srv.Close)
	conn := dial(t, srv)
	send(t, conn, wsapi.TypeHello, wsapi.Hello{Session: token, Version: wsapi.Version})
	if f := read(t, conn); f.Type != wsapi.TypeWelcome {
		t.Fatalf("hello: %s", f.Type)
	}
	send(t, conn, wsapi.TypeChatsList, wsapi.DeviceRef{DeviceID: device.ID})
	wantError(t, read(t, conn), wsapi.ErrCodeNotAuthorized)
}

func TestDeviceActionChangeClosesExistingSocket(t *testing.T) {
	c := newConsole(t)
	ctx := context.Background()
	device := uuid.MustParse(c.deviceWithKey(t, "test"))
	ownerToken := c.account(t, "owner@action.test", "owner")
	token := c.account(t, "member@action.test", "member")
	_, owner, err := c.users.ActiveSession(ctx, ownerToken)
	if err != nil {
		t.Fatal(err)
	}
	_, member, err := c.users.ActiveSession(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	p := store.DevicePermission{DeviceID: device, UserID: member.ID, Send: true}
	if err = c.users.SetDevicePermission(ctx, c.tenant, owner.ID, p); err != nil {
		t.Fatal(err)
	}
	conn := dial(t, c.srv)
	send(t, conn, wsapi.TypeHello, wsapi.Hello{Session: token, Version: wsapi.Version})
	if f := read(t, conn); f.Type != wsapi.TypeWelcome {
		t.Fatalf("hello=%s", f.Type)
	}
	p.Send = false
	if err = c.users.SetDevicePermission(ctx, c.tenant, owner.ID, p); err != nil {
		t.Fatal(err)
	}
	expectAccessClosed(t, conn)
}
