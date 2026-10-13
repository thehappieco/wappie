package wsapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/bus"
	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/domain"
	"whatserver2/internal/ingest"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/restapi"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
	"whatserver2/internal/wsapi"
)

// Deleting a number over the socket (decision 0038): who may, in what
// order, what the deleting owner's session still receives, and what every
// other path answers afterwards.

// fakeUnlinker stands in for the WhatsApp logout. It runs the deletion's
// re-check, as the registry does under the device lock, records every
// logout it was asked for, and on success removes the session from the
// session store, as whatsmeow's Logout does.
type fakeUnlinker struct {
	mu       sync.Mutex
	pool     *pgxpool.Pool
	logouts  []string
	marked   map[string]int
	onUnlink func(ctx context.Context, device string) error
}

func (f *fakeUnlinker) BeginUnlink(device string) func() {
	f.mu.Lock()
	if f.marked == nil {
		f.marked = map[string]int{}
	}
	f.marked[device]++
	f.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			f.mu.Lock()
			f.marked[device]--
			f.mu.Unlock()
		})
	}
}

func (f *fakeUnlinker) Unlink(ctx context.Context, _, device string, jid types.JID, recheck func(context.Context) error) error {
	if recheck != nil {
		if err := recheck(ctx); err != nil {
			return err
		}
	}
	f.mu.Lock()
	f.logouts = append(f.logouts, device)
	hook := f.onUnlink
	f.mu.Unlock()
	if hook != nil {
		if err := hook(ctx, device); err != nil {
			return err
		}
	}
	_, err := f.pool.Exec(context.WithoutCancel(ctx), `DELETE FROM whatsmeow_device WHERE jid=$1`, jid.String())
	return err
}

func (f *fakeUnlinker) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.logouts)
}

type deletionConsole struct {
	*console
	bus      *bus.Bus
	unlinker *fakeUnlinker
	owner    uuid.UUID
	token    string
	rest     *httptest.Server
	pns      int
}

func newDeletionConsole(t *testing.T) *deletionConsole {
	t.Helper()
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	var tenantID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('acme') RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	// The session store's table, as whatsmeow creates it beside ours.
	if _, err := pool.Exec(ctx, `CREATE TABLE whatsmeow_device (jid text PRIMARY KEY, registration_id bigint NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	keys := store.NewAPIKeys(pool)
	apiKey, err := keys.Issue(ctx, tenantID, "ci")
	if err != nil {
		t.Fatal(err)
	}
	users, devices, messages := store.NewUsers(pool), store.NewDevices(pool), store.NewMessages(pool)
	b := bus.New()
	unlinker := &fakeUnlinker{pool: pool}
	srv := httptest.NewServer(wsapi.NewServer(wsapi.Config{
		Keys: keys, Sessions: users, Accounts: users, Devices: devices, Messages: messages,
		Keys2: store.NewKeys(pool), Receipts: store.NewReceipts(pool), Bus: b, Unlinker: unlinker, Log: slog.New(slog.DiscardHandler),
	}))
	t.Cleanup(srv.Close)
	mux := http.NewServeMux()
	(&restapi.Handler{APIKeys: keys, Users: users, Keys: store.NewKeys(pool), Devices: devices, Messages: messages,
		Contacts: store.NewContacts(pool), Receipts: store.NewReceipts(pool)}).Mount(mux)
	rest := httptest.NewServer(mux)
	t.Cleanup(rest.Close)
	c := &deletionConsole{
		console: &console{srv: srv, pool: pool, tenant: uuid.MustParse(tenantID), apiKey: apiKey, devices: devices, users: users, keys: keys},
		bus:     b, unlinker: unlinker, rest: rest,
	}
	c.token = c.account(t, "owner@acme.test", "owner")
	c.owner = c.sessionUser(t, c.token)
	return c
}

func (c *deletionConsole) sessionUser(t *testing.T, token string) uuid.UUID {
	t.Helper()
	_, user, err := c.users.ActiveSession(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	return user.ID
}

// person creates someone and returns their id and a session.
func (c *deletionConsole) person(t *testing.T, name, role string) (uuid.UUID, string) {
	t.Helper()
	token := c.account(t, name+"@acme.test", role)
	return c.sessionUser(t, token), token
}

// linkedDevice is a number that paired and connected, with an archive key
// at epoch 1 and a WhatsApp session in the session store. A row made with
// Devices.Create alone has no identity, and deleting it is the hard delete of
// a registration that never linked.
func (c *deletionConsole) linkedDevice(t *testing.T, label string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	c.pns++
	dev, err := c.devices.Create(ctx, c.tenant.String(), label, wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	pn := types.JID{User: fmt.Sprintf("55119%04d5678", c.pns), Server: types.DefaultUserServer}
	if err := c.devices.SetIdentity(ctx, c.tenant.String(), dev.ID, wa.Identity{PN: pn,
		LID: types.JID{User: fmt.Sprintf("1000000%08d", c.pns), Server: types.HiddenUserServer}}); err != nil {
		t.Fatal(err)
	}
	if err := c.devices.SetStatus(ctx, c.tenant.String(), dev.ID, wa.StatusOnline, ""); err != nil {
		t.Fatal(err)
	}
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.NewKeys(c.pool).CreateArchiveKey(ctx, c.tenant, uuid.MustParse(dev.ID), 1, pub); err != nil {
		t.Fatal(err)
	}
	if _, err := c.pool.Exec(ctx, `INSERT INTO whatsmeow_device(jid, registration_id) VALUES ($1, 7)`, pn.String()); err != nil {
		t.Fatal(err)
	}
	return uuid.MustParse(dev.ID)
}

func (c *deletionConsole) reads(t *testing.T, user, device uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	if err := store.NewKeys(c.pool).PutGrant(ctx, store.Grant{TenantID: c.tenant, DeviceID: device, UserID: user, Epoch: 1, SealedDSK: []byte("grant")}, &c.owner); err != nil {
		t.Fatal(err)
	}
	if err := c.users.SetDevicePermission(ctx, c.tenant, c.owner, store.DevicePermission{DeviceID: device, UserID: user, Read: true, Send: true}); err != nil {
		t.Fatal(err)
	}
}

// excludedRow reads the deleted numbers as an owner does, on a connection
// of its own: whether the number is among them, and its status.
func (c *deletionConsole) excludedRow(ctx context.Context, t *testing.T, device uuid.UUID) (deleted bool, status string) {
	t.Helper()
	numbers, err := c.devices.ListDeleted(ctx, c.tenant, c.owner)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range numbers {
		if n.DeviceID == device {
			return true, string(n.Status)
		}
	}
	return false, ""
}

// connect opens an authenticated socket.
func connect(t *testing.T, c *console, hello wsapi.Hello) *websocket.Conn {
	t.Helper()
	conn := dial(t, c.srv)
	hello.Version = wsapi.Version
	send(t, conn, wsapi.TypeHello, hello)
	if f := read(t, conn); f.Type != wsapi.TypeWelcome {
		t.Fatalf("handshake: %s %s", f.Type, f.Payload)
	}
	return conn
}

func request(t *testing.T, conn *websocket.Conn, reqID, frameType string, payload any) {
	t.Helper()
	f := wsapi.Frame{Type: frameType, ReqID: reqID}
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		f.Payload = b
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn.Write(ctx, websocket.MessageText, b); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// replyTo reads until the frame answering reqID, keeping what came before.
func replyTo(t *testing.T, conn *websocket.Conn, reqID string) (wsapi.Frame, []wsapi.Frame) {
	t.Helper()
	var before []wsapi.Frame
	for {
		f := read(t, conn)
		if f.ReqID == reqID && f.Type != wsapi.TypePresence && f.Type != wsapi.TypeMessage {
			return f, before
		}
		before = append(before, f)
	}
}

func deleteFrame(device uuid.UUID, readers ...uuid.UUID) wsapi.DeleteRequest {
	req := wsapi.DeleteRequest{DeviceID: device.String(), Confirm: device.String(), Unlink: true}
	for _, r := range readers {
		req.AcknowledgedReaders = append(req.AcknowledgedReaders, r.String())
	}
	return req
}

func TestDeleteReplyReachesReaderOwner(t *testing.T) {
	c := newDeletionConsole(t)
	ctx := context.Background()
	device, other := c.linkedDevice(t, "Suporte"), c.linkedDevice(t, "Vendas")
	reader, readerToken := c.person(t, "reader", "member")
	c.reads(t, c.owner, device)
	c.reads(t, c.owner, other)
	c.reads(t, reader, device)
	uid := uuid.New()
	if _, err := store.NewMessages(c.pool).Insert(ctx, store.InsertMessage{UID: uid, TenantID: c.tenant, DeviceID: device, WAID: "one",
		ChatKey: "chat", Kind: domain.KindMessage, Type: domain.TypeText, Source: domain.SourceLive, TS: time.Now(), BodySealed: []byte{1}}); err != nil {
		t.Fatal(err)
	}
	owner := wsapi.Hello{Session: c.token}

	// The owner subscribed to the deleted number alone, and to both.
	only := connect(t, c.console, owner)
	request(t, only, "only", wsapi.TypeSubscribe, wsapi.Subscribe{Devices: []string{device.String()}, LiveOnly: true})
	if f, _ := replyTo(t, only, "only"); f.Type != wsapi.TypeReplayEnd {
		t.Fatalf("subscribe: %s %s", f.Type, f.Payload)
	}
	readerConn := connect(t, c.console, wsapi.Hello{Session: readerToken})

	// Positive controls on the live number.
	for _, frame := range []struct {
		kind    string
		payload any
	}{{wsapi.TypeChatPage, wsapi.ChatPageRequest{DeviceID: device.String(), ChatKey: "chat"}},
		{wsapi.TypeKeysGet, wsapi.KeysRequest{DeviceID: device.String(), IDs: []uint32{1}}}} {
		if f := ask(t, c.console, owner, frame.kind, frame.payload); f.Type == wsapi.TypeError {
			t.Fatalf("control %s: %s", frame.kind, f.Payload)
		}
	}

	// Traffic for the workspace while the deletion commits, under -race.
	stop := make(chan struct{})
	var published sync.WaitGroup
	published.Add(1)
	go func() {
		defer published.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			for _, d := range []uuid.UUID{device, other} {
				c.bus.Publish(c.tenant, ingest.Event{Class: ingest.ClassPresence, TenantID: c.tenant, DeviceID: d, Ephemeral: true,
					Presence: &ingest.Presence{ChatKey: "chat", State: "composing"}})
			}
			time.Sleep(time.Millisecond)
		}
	}()

	deleting := connect(t, c.console, owner)
	request(t, deleting, "delete", wsapi.TypeDeviceDelete, deleteFrame(device, reader))
	reply, _ := replyTo(t, deleting, "delete")
	close(stop)
	published.Wait()
	if reply.Type != wsapi.TypeDeviceGone {
		t.Fatalf("delete: %s %s", reply.Type, reply.Payload)
	}
	gone := payload[wsapi.DeviceDeleted](t, reply)
	if gone.Already || gone.DeletedAt == nil || gone.RecoverableUntil == nil || !gone.Unlinked || gone.NoteCode != "" ||
		gone.Messages == nil || *gone.Messages != 1 {
		t.Fatalf("device.deleted = %+v", gone)
	}
	if deleted, _ := c.excludedRow(ctx, t, device); !deleted {
		t.Fatal("the row did not survive, excluded")
	}
	// The socket that deleted stays open.
	request(t, deleting, "ping", wsapi.TypePing, nil)
	if f, _ := replyTo(t, deleting, "ping"); f.Type != wsapi.TypePong {
		t.Fatalf("after the deletion: %s", f.Type)
	}
	// The subscription to the deleted number ends, and nothing follows it.
	for {
		f := read(t, only)
		if f.Type == wsapi.TypeSubscriptionEnded {
			if got := payload[wsapi.SubscriptionEnded](t, f); got.Reason != "device_removed" || f.ReqID != "only" {
				t.Fatalf("subscription.ended = %+v %q", got, f.ReqID)
			}
			break
		}
	}
	c.bus.Publish(c.tenant, ingest.Event{Class: ingest.ClassPresence, TenantID: c.tenant, DeviceID: other, Ephemeral: true,
		Presence: &ingest.Presence{ChatKey: "chat", State: "composing"}})
	quiet, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	for {
		_, data, err := only.Read(quiet)
		if err != nil {
			break
		}
		var f wsapi.Frame
		if err := json.Unmarshal(data, &f); err != nil {
			t.Fatal(err)
		}
		// device.removed is the push every viewer gets; traffic is not.
		if f.Type != wsapi.TypeDeviceRemoved {
			t.Fatalf("an ended subscription delivered %s", data)
		}
	}
	cancel()
	// Another reader is cut off.
	expectAccessClosed(t, readerConn)
	// Every per-request path answers not found.
	wantError(t, ask(t, c.console, owner, wsapi.TypeChatPage, wsapi.ChatPageRequest{DeviceID: device.String(), ChatKey: "chat"}), wsapi.ErrCodeNotFound)
	wantError(t, ask(t, c.console, owner, wsapi.TypeKeysGet, wsapi.KeysRequest{DeviceID: device.String(), IDs: []uint32{1}}), wsapi.ErrCodeNotFound)
	if c.unlinker.count() != 1 {
		t.Fatalf("%d logouts", c.unlinker.count())
	}
}

func TestExcludedFramesRefused(t *testing.T) {
	c := newDeletionConsole(t)
	ctx := context.Background()
	device := c.linkedDevice(t, "Suporte")
	member, _ := c.person(t, "member", "member")
	c.reads(t, c.owner, device)
	uid := uuid.New()
	if _, err := store.NewMessages(c.pool).Insert(ctx, store.InsertMessage{UID: uid, TenantID: c.tenant, DeviceID: device, WAID: "one",
		ChatKey: "chat", Kind: domain.KindMessage, Type: domain.TypeText, Source: domain.SourceLive, TS: time.Now(), BodySealed: []byte{1}}); err != nil {
		t.Fatal(err)
	}
	owner := wsapi.Hello{Session: c.token}
	frames := []struct {
		kind    string
		payload any
	}{
		{wsapi.TypeDeviceInfo, wsapi.DeviceRef{DeviceID: device.String()}},
		{wsapi.TypeDeviceStart, wsapi.DeviceRef{DeviceID: device.String()}},
		{wsapi.TypePair, wsapi.PairRequest{DeviceID: device.String(), Resume: true, Method: "qr"}},
		{wsapi.TypeGrantAdd, wsapi.GrantRequest{DeviceID: device.String(), UserID: member.String(), Epoch: 1, SealedDSK: []byte("x")}},
		{wsapi.TypeSend, wsapi.SendRequest{DeviceID: device.String(), Chat: "5511999999999@s.whatsapp.net", Body: "hi"}},
		{wsapi.TypeDeviceTransfer, wsapi.DeviceTransferRequest{DeviceID: device.String(), Confirm: device.String(), TargetWorkspaceID: uuid.NewString()}},
		{wsapi.TypeKeysGet, wsapi.KeysRequest{DeviceID: device.String(), IDs: []uint32{1}}},
		{wsapi.TypeMessageGet, wsapi.MessageGetRequest{UID: uid.String()}},
		{wsapi.TypeHistory, wsapi.HistoryRequest{UID: uid.String()}},
	}
	notFound := func(f wsapi.Frame) bool {
		return f.Type == wsapi.TypeError && payload[wsapi.Error](t, f).Code == wsapi.ErrCodeNotFound
	}
	restStatus := func(path string) int {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.rest.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		return res.StatusCode
	}
	paths := []string{"/v1/messages/" + uid.String(), "/v1/messages/" + uid.String() + "/history"}
	for _, frame := range frames {
		if f := ask(t, c.console, owner, frame.kind, frame.payload); notFound(f) {
			t.Fatalf("control %s answered not found: %s", frame.kind, f.Payload)
		}
	}
	for _, path := range paths {
		if got := restStatus(path); got == http.StatusNotFound {
			t.Fatalf("control %s: %d", path, got)
		}
	}

	// The control's grant.add made the member a reader.
	if f := ask(t, c.console, owner, wsapi.TypeDeviceDelete, deleteFrame(device, member)); f.Type != wsapi.TypeDeviceGone {
		t.Fatalf("delete: %s %s", f.Type, f.Payload)
	}
	for _, frame := range frames {
		if f := ask(t, c.console, owner, frame.kind, frame.payload); !notFound(f) {
			t.Fatalf("%s on the excluded number: %s %s", frame.kind, f.Type, f.Payload)
		}
	}
	for _, path := range paths {
		if got := restStatus(path); got != http.StatusNotFound {
			t.Fatalf("%s on the excluded number: %d", path, got)
		}
	}
}

func TestDeleteOrder(t *testing.T) {
	c := newDeletionConsole(t)
	ctx := context.Background()
	device := c.linkedDevice(t, "Suporte")
	reader, _ := c.person(t, "reader", "member")
	c.reads(t, reader, device)
	owner := wsapi.Hello{Session: c.token}

	// Unacknowledged readers: refused with the list, and no logout.
	e := wantError(t, ask(t, c.console, owner, wsapi.TypeDeviceDelete, deleteFrame(device)), wsapi.ErrCodeDeviceHasReaders)
	if len(e.Readers) != 1 || e.Readers[0].UserID != reader {
		t.Fatalf("readers = %+v", e.Readers)
	}
	// An admin.
	_, adminToken := c.person(t, "admin", "admin")
	wantError(t, ask(t, c.console, wsapi.Hello{Session: adminToken}, wsapi.TypeDeviceDelete, deleteFrame(device, reader)), wsapi.ErrCodeOwnerOnly)
	// A stale step-up.
	session, err := c.users.Session(ctx, c.token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.pool.Exec(ctx, `UPDATE sessions SET authenticated_at = now() - interval '11 minutes' WHERE id=$1`, session.ID); err != nil {
		t.Fatal(err)
	}
	wantError(t, ask(t, c.console, owner, wsapi.TypeDeviceDelete, deleteFrame(device, reader)), wsapi.ErrCodeStepUpRequired)
	if c.unlinker.count() != 0 {
		t.Fatalf("a refused deletion logged out %d times", c.unlinker.count())
	}
	if deleted, _ := c.excludedRow(ctx, t, device); deleted {
		t.Fatal("a refused deletion excluded the number")
	}
	if err := c.users.MarkStepUp(ctx, session.ID); err != nil {
		t.Fatal(err)
	}

	// Committed first: the logout sees the exclusion on another connection.
	c.unlinker.onUnlink = func(ctx context.Context, id string) error {
		if deleted, _ := c.excludedRow(ctx, t, uuid.MustParse(id)); !deleted {
			return errors.New("logged out before the commit")
		}
		return nil
	}
	f := ask(t, c.console, owner, wsapi.TypeDeviceDelete, deleteFrame(device, reader))
	if f.Type != wsapi.TypeDeviceGone {
		t.Fatalf("delete: %s %s", f.Type, f.Payload)
	}
	if gone := payload[wsapi.DeviceDeleted](t, f); !gone.Unlinked || c.unlinker.count() != 1 {
		t.Fatalf("device.deleted %+v after %d logouts", gone, c.unlinker.count())
	}
	if _, status := c.excludedRow(ctx, t, device); status != "logged_out" {
		t.Fatalf("status %q after an acknowledged logout", status)
	}
}

func TestDeleteNeedsStepUp(t *testing.T) {
	c := newDeletionConsole(t)
	ctx := context.Background()
	device, excluded := c.linkedDevice(t, "Suporte"), c.linkedDevice(t, "Vendas")
	if f := ask(t, c.console, wsapi.Hello{Session: c.token}, wsapi.TypeDeviceDelete, deleteFrame(excluded)); f.Type != wsapi.TypeDeviceGone {
		t.Fatalf("delete: %s", f.Payload)
	}
	_, adminToken := c.person(t, "admin", "admin")
	for _, token := range []string{c.token, adminToken} {
		session, err := c.users.Session(ctx, token)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.pool.Exec(ctx, `UPDATE sessions SET authenticated_at = now() - interval '11 minutes' WHERE id=$1`, session.ID); err != nil {
			t.Fatal(err)
		}
	}
	owner, admin := wsapi.Hello{Session: c.token}, wsapi.Hello{Session: adminToken}
	recover := wsapi.RecoverRequest{DeviceID: excluded.String(), Confirm: excluded.String()}
	wantError(t, ask(t, c.console, owner, wsapi.TypeDeviceDelete, deleteFrame(device)), wsapi.ErrCodeStepUpRequired)
	wantError(t, ask(t, c.console, owner, wsapi.TypeDeviceRecover, recover), wsapi.ErrCodeStepUpRequired)
	if f := ask(t, c.console, owner, wsapi.TypeDeviceDeleteCheck, wsapi.DeviceRef{DeviceID: device.String()}); f.Type != wsapi.TypeDeviceDeleteChecked {
		t.Fatalf("the preflight asked for a step-up: %s", f.Payload)
	}
	if f := ask(t, c.console, owner, wsapi.TypeDeviceRecoverCheck, wsapi.DeviceRef{DeviceID: excluded.String()}); f.Type != wsapi.TypeDeviceRecoverChecked {
		t.Fatalf("the recovery's preflight asked for a step-up: %s", f.Payload)
	}
	// An admin is told it is an owner's act, never asked for a step-up.
	wantError(t, ask(t, c.console, admin, wsapi.TypeDeviceDelete, deleteFrame(device)), wsapi.ErrCodeOwnerOnly)
	wantError(t, ask(t, c.console, admin, wsapi.TypeDeviceRecover, recover), wsapi.ErrCodeOwnerOnly)
	if deleted, _ := c.excludedRow(ctx, t, device); deleted || c.unlinker.count() != 1 {
		t.Fatalf("a refused deletion changed the row (%v) or logged out (%d)", deleted, c.unlinker.count())
	}
}

func TestDeleteAuthorizesBeforeExcludedLookup(t *testing.T) {
	c := newDeletionConsole(t)
	device := c.linkedDevice(t, "Suporte")
	reader, readerToken := c.person(t, "reader", "member")
	former, formerToken := c.person(t, "former", "member")
	_, adminToken := c.person(t, "admin", "admin")
	_, memberToken := c.person(t, "member", "member")
	c.reads(t, c.owner, device)
	c.reads(t, reader, device)
	c.reads(t, former, device)
	ctx := context.Background()
	if err := c.users.RemoveMember(ctx, c.tenant, c.owner, former); err != nil {
		t.Fatal(err)
	}
	if f := ask(t, c.console, wsapi.Hello{Session: c.token}, wsapi.TypeDeviceDelete, deleteFrame(device, reader)); f.Type != wsapi.TypeDeviceGone {
		t.Fatalf("delete: %s", f.Payload)
	}
	wantError(t, ask(t, c.console, wsapi.Hello{Session: readerToken}, wsapi.TypeDeviceDelete, deleteFrame(device)), wsapi.ErrCodeNotFound)
	for name, token := range map[string]string{"member": memberToken, "admin": adminToken} {
		f := ask(t, c.console, wsapi.Hello{Session: token}, wsapi.TypeDeviceDelete, deleteFrame(device))
		e := wantError(t, f, wsapi.ErrCodeNotFound)
		if strings.Contains(string(f.Payload), "deleted_at") || strings.Contains(e.Message, "recover") {
			t.Fatalf("%s learned of the deletion: %s", name, f.Payload)
		}
	}
	// The former reader, removed before the deletion, cannot even ask.
	if _, _, err := c.users.ActiveSession(ctx, formerToken); err == nil {
		if f := ask(t, c.console, wsapi.Hello{Session: formerToken}, wsapi.TypeDeviceDelete, deleteFrame(device)); f.Type != wsapi.TypeError {
			t.Fatalf("a former reader: %s", f.Payload)
		}
	}
	// An owner retrying gets the stored state.
	f := ask(t, c.console, wsapi.Hello{Session: c.token}, wsapi.TypeDeviceDelete, deleteFrame(device))
	if f.Type != wsapi.TypeDeviceGone {
		t.Fatalf("an owner's retry: %s", f.Payload)
	}
	if gone := payload[wsapi.DeviceDeleted](t, f); !gone.Already || gone.RecoverableUntil == nil {
		t.Fatalf("already = %+v", gone)
	}
	// The reader at the deletion is told on purpose, by their notice.
	notices, err := c.devices.Notices(ctx, c.tenant, reader)
	if err != nil || len(notices) != 1 || notices[0].Until == nil {
		t.Fatalf("the reader's notice: %+v %v", notices, err)
	}
	// An admin's storage breakdown has no excluded bucket.
	admin, _ := c.person(t, "admin2", "admin")
	usage, err := store.NewStorage(c.pool).UsageDetailed(ctx, c.tenant, admin)
	if err != nil || usage.Breakdown == nil || usage.Breakdown.Excluded != (store.StorageBytes{}) {
		t.Fatalf("an admin's breakdown: %+v %v", usage.Breakdown, err)
	}
}

func TestDeleteRefusesKeepLinked(t *testing.T) {
	ctx := context.Background()
	c := newDeletionConsole(t)
	device := c.linkedDevice(t, "Suporte")
	owner := wsapi.Hello{Session: c.token}
	keep := wsapi.DeleteRequest{DeviceID: device.String(), Confirm: device.String(), Unlink: false}
	for _, role := range []string{"member", "admin"} {
		_, token := c.person(t, role, role)
		if f := ask(t, c.console, wsapi.Hello{Session: token}, wsapi.TypeDeviceDelete, keep); payload[wsapi.Error](t, f).Code != wsapi.ErrCodeOwnerOnly {
			t.Fatalf("a %s's unlink:false: %s", role, f.Payload)
		}
	}
	wantError(t, ask(t, c.console, owner, wsapi.TypeDeviceDelete, keep), wsapi.ErrCodeBadRequest)
	if deleted, _ := c.excludedRow(ctx, t, device); deleted {
		t.Fatal("unlink:false excluded the number")
	}
	// Omitted means true.
	if f := ask(t, c.console, owner, wsapi.TypeDeviceDelete, map[string]string{"device_id": device.String(), "confirm": device.String()}); f.Type != wsapi.TypeDeviceGone {
		t.Fatalf("omitted unlink: %s", f.Payload)
	}
	// An excluded row's retry ignores it.
	if f := ask(t, c.console, owner, wsapi.TypeDeviceDelete, keep); f.Type != wsapi.TypeDeviceGone || !payload[wsapi.DeviceDeleted](t, f).Already {
		t.Fatalf("a retry with unlink:false: %s", f.Payload)
	}
	// A pending registration ignores it too.
	pending, err := c.devices.Create(ctx, c.tenant.String(), "pending", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	f := ask(t, c.console, owner, wsapi.TypeDeviceDelete, wsapi.DeleteRequest{DeviceID: pending.ID, Confirm: pending.ID})
	if f.Type != wsapi.TypeDeviceGone || !payload[wsapi.DeviceDeleted](t, f).Pending {
		t.Fatalf("a pending registration: %s", f.Payload)
	}
}

func TestPendingStillHardDeleted(t *testing.T) {
	c := newDeletionConsole(t)
	ctx := context.Background()
	_, adminToken := c.person(t, "admin", "admin")
	pending, err := c.devices.Create(ctx, c.tenant.String(), "pending", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	_, memberToken := c.person(t, "member", "member")
	wantError(t, ask(t, c.console, wsapi.Hello{Session: memberToken}, wsapi.TypeDeviceDelete,
		wsapi.DeleteRequest{DeviceID: pending.ID, Confirm: pending.ID}), wsapi.ErrCodeNotAuthorized)
	f := ask(t, c.console, wsapi.Hello{Session: adminToken}, wsapi.TypeDeviceDelete, wsapi.DeleteRequest{DeviceID: pending.ID, Confirm: pending.ID})
	if f.Type != wsapi.TypeDeviceGone || !payload[wsapi.DeviceDeleted](t, f).Pending {
		t.Fatalf("an admin removing a registration: %s", f.Payload)
	}
	var left int
	if err := c.pool.QueryRow(ctx, `SELECT count(*) FROM devices WHERE id=$1`, pending.ID).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if deleted, _ := func() (bool, error) { return left != 0, nil }(); deleted {
		t.Fatal("the registration survived")
	}
	if c.unlinker.count() != 0 {
		t.Fatal("a registration that never linked was logged out")
	}
}

func TestDeletedListAndRecoverFrames(t *testing.T) {
	c := newDeletionConsole(t)
	device := c.linkedDevice(t, "Suporte")
	reader, readerToken := c.person(t, "reader", "member")
	c.reads(t, c.owner, device)
	c.reads(t, reader, device)
	owner := wsapi.Hello{Session: c.token}
	if f := ask(t, c.console, owner, wsapi.TypeDeviceDelete, deleteFrame(device, reader)); f.Type != wsapi.TypeDeviceGone {
		t.Fatalf("delete: %s", f.Payload)
	}
	_, adminToken := c.person(t, "admin", "admin")
	for _, frame := range []string{wsapi.TypeDevicesDeleted, wsapi.TypeDeviceRecoverCheck, wsapi.TypeDeviceRecover} {
		wantError(t, ask(t, c.console, wsapi.Hello{Session: adminToken}, frame, wsapi.RecoverRequest{DeviceID: device.String(), Confirm: device.String()}), wsapi.ErrCodeOwnerOnly)
	}
	wantError(t, ask(t, c.console, wsapi.Hello{APIKey: c.apiKey}, wsapi.TypeDevicesDeleted, nil), wsapi.ErrCodeOwnerOnly)

	f := ask(t, c.console, owner, wsapi.TypeDevicesDeleted, nil)
	if f.Type != wsapi.TypeDeletedNumbers {
		t.Fatalf("devices.deleted: %s", f.Payload)
	}
	list := payload[wsapi.DeletedNumbers](t, f)
	if len(list.Numbers) != 1 {
		t.Fatalf("deleted numbers = %+v", list)
	}
	n := list.Numbers[0]
	if n.DeviceID != device.String() || n.Label != "Suporte" || n.PN == "" || !n.Recoverable || n.Purging ||
		n.Status != "logged_out" || !n.LoggedOut || n.CanResume || n.KeyHolders != 2 || n.DeletedByName == "" {
		t.Fatalf("the deleted number = %+v", n)
	}
	f = ask(t, c.console, owner, wsapi.TypeDeviceRecoverCheck, wsapi.DeviceRef{DeviceID: device.String()})
	check := payload[wsapi.DeviceRecoverChecked](t, f)
	if len(check.Readers) != 1 || check.Readers[0].UserID != reader || check.Status != "logged_out" || check.StatusReason == "" || !check.Recoverable {
		t.Fatalf("device.recover.checked = %+v", check)
	}
	f = ask(t, c.console, owner, wsapi.TypeDeviceRecover, wsapi.RecoverRequest{DeviceID: device.String(), Confirm: device.String()})
	if f.Type != wsapi.TypeDeviceRecovered {
		t.Fatalf("recover: %s", f.Payload)
	}
	recovered := payload[wsapi.DeviceRecovered](t, f)
	if recovered.Already || recovered.Device.ID != device.String() || !recovered.Device.Paused || recovered.Status != "logged_out" || recovered.StatusReason == "" {
		t.Fatalf("device.recovered = %+v", recovered)
	}
	f = ask(t, c.console, owner, wsapi.TypeDeviceRecover, wsapi.RecoverRequest{DeviceID: device.String(), Confirm: device.String()})
	if f.Type != wsapi.TypeDeviceRecovered || !payload[wsapi.DeviceRecovered](t, f).Already {
		t.Fatalf("a retried recovery: %s", f.Payload)
	}
	// The reader reads it again, with no new grant, and a logged-out number
	// cannot be started.
	if f := ask(t, c.console, wsapi.Hello{Session: readerToken}, wsapi.TypeChatPage, wsapi.ChatPageRequest{DeviceID: device.String(), ChatKey: "chat"}); f.Type == wsapi.TypeError {
		t.Fatalf("the reader after the recovery: %s", f.Payload)
	}
	if f := ask(t, c.console, owner, wsapi.TypeDeviceStart, wsapi.DeviceRef{DeviceID: device.String()}); f.Type != wsapi.TypeError {
		t.Fatalf("starting a logged-out number: %s", f.Type)
	}
}

func TestDevicesListCarriesNotices(t *testing.T) {
	c := newDeletionConsole(t)
	device := c.linkedDevice(t, "Suporte")
	other := c.linkedDevice(t, "Vendas")
	reader, readerToken := c.person(t, "reader", "member")
	c.reads(t, reader, device)
	c.reads(t, reader, other)
	owner := wsapi.Hello{Session: c.token}
	if f := ask(t, c.console, owner, wsapi.TypeDeviceDelete, deleteFrame(device, reader)); f.Type != wsapi.TypeDeviceGone {
		t.Fatalf("delete: %s", f.Payload)
	}
	if f := ask(t, c.console, owner, wsapi.TypeDeviceDelete, deleteFrame(other, reader)); f.Type != wsapi.TypeDeviceGone {
		t.Fatalf("delete: %s", f.Payload)
	}
	f := ask(t, c.console, wsapi.Hello{Session: readerToken}, wsapi.TypeDevicesList, nil)
	list := payload[wsapi.Devices](t, f)
	if len(list.Notices) != 2 || list.Notices[0].Kind != store.NoticeNumberDeleted || list.Notices[0].Hint == nil || list.Notices[0].Until == nil {
		t.Fatalf("notices = %+v", list.Notices)
	}
	if own := payload[wsapi.Devices](t, ask(t, c.console, owner, wsapi.TypeDevicesList, nil)); len(own.Notices) != 0 {
		t.Fatalf("the owner is told of their own deletion: %+v", own.Notices)
	}
	if key := payload[wsapi.Devices](t, ask(t, c.console, wsapi.Hello{APIKey: c.apiKey}, wsapi.TypeDevicesList, nil)); key.Notices != nil {
		t.Fatalf("an API key got notices: %+v", key.Notices)
	}

	// device.notice.seen, several at once, the person's own only.
	seen := wsapi.DeviceNoticeSeen{NoticeIDs: []int64{list.Notices[0].ID, list.Notices[1].ID}}
	if f := ask(t, c.console, owner, wsapi.TypeDeviceNoticeSeen, seen); f.Type != wsapi.TypeDeviceNotices {
		t.Fatalf("seen by the owner: %s", f.Payload)
	}
	if again := payload[wsapi.Devices](t, ask(t, c.console, wsapi.Hello{Session: readerToken}, wsapi.TypeDevicesList, nil)); len(again.Notices) != 2 {
		t.Fatalf("another person's seen mark: %+v", again.Notices)
	}
	f = ask(t, c.console, wsapi.Hello{Session: readerToken}, wsapi.TypeDeviceNoticeSeen, seen)
	if left := payload[wsapi.DeviceNotices](t, f); len(left.Notices) != 0 {
		t.Fatalf("left after seen: %+v", left)
	}
	wantError(t, ask(t, c.console, wsapi.Hello{APIKey: c.apiKey}, wsapi.TypeDeviceNoticeSeen, seen), wsapi.ErrCodeNotAuthorized)
}

// The session's context ends right after the commit: the logout and its
// record still run, on a context of their own.
func TestDeleteSurvivesSessionCancel(t *testing.T) {
	ctx := context.Background()
	c := newDeletionConsole(t)
	device := c.linkedDevice(t, "Suporte")
	conn := connect(t, c.console, wsapi.Hello{Session: c.token})
	var logged atomic.Bool
	c.unlinker.onUnlink = func(unlinkCtx context.Context, _ string) error {
		_ = conn.CloseNow()
		time.Sleep(200 * time.Millisecond)
		if unlinkCtx.Err() != nil {
			return unlinkCtx.Err()
		}
		logged.Store(true)
		return nil
	}
	request(t, conn, "delete", wsapi.TypeDeviceDelete, deleteFrame(device))
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, status := c.excludedRow(ctx, t, device); status == "logged_out" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if deleted, status := c.excludedRow(ctx, t, device); !deleted || status != "logged_out" || !logged.Load() {
		t.Fatalf("after the socket closed: excluded %v, status %q, logged out %v", deleted, status, logged.Load())
	}
}
