package wsapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	waStore "go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
	waLog "go.mau.fi/whatsmeow/util/log"

	"whatserver2/internal/bus"
	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/domain"
	"whatserver2/internal/ingest"
	"whatserver2/internal/ledger"
	"whatserver2/internal/membership"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/restapi"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
	"whatserver2/internal/wa/fakewa"
	"whatserver2/internal/wsapi"
)

// Deleting a number over the socket (decision 0038): who may, in what
// order, what the deleting owner's session still receives, and what every
// other path answers afterwards.

// fakeUnlinker stands in for the WhatsApp logout. It runs the deletion's
// re-check, as the registry does under the device lock, records every
// logout it was asked for, on success removes the session from the session
// store, as whatsmeow's Logout does, and then runs the record, as the
// registry does before it lets go of the lock.
type fakeUnlinker struct {
	mu      sync.Mutex
	pool    *pgxpool.Pool
	logouts []string
	marked  map[string]int
	// beforeRecheck runs first, as whatever happens between the commit and
	// the logout.
	beforeRecheck func(ctx context.Context, device string)
	onUnlink      func(ctx context.Context, device string) error
	// fail is what the registry answered instead of asking WhatsApp, after
	// recording it, as it does for a session gone from the store.
	fail error
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

func (f *fakeUnlinker) Unlink(ctx context.Context, _, device string, jid types.JID,
	recheck func(context.Context) error, record func(context.Context, error)) error {
	f.mu.Lock()
	before, fail := f.beforeRecheck, f.fail
	f.mu.Unlock()
	if before != nil {
		before(ctx, device)
	}
	if fail != nil {
		record(ctx, fail)
		return fail
	}
	if err := recheck(ctx); err != nil {
		return err
	}
	f.mu.Lock()
	f.logouts = append(f.logouts, device)
	hook := f.onUnlink
	f.mu.Unlock()
	var err error
	if hook != nil {
		err = hook(ctx, device)
	}
	if err == nil {
		_, err = f.pool.Exec(context.WithoutCancel(ctx), `DELETE FROM whatsmeow_device WHERE jid=$1`, jid.String())
	}
	record(ctx, err)
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
	registry *wa.Registry
	owner    uuid.UUID
	token    string
	rest     *httptest.Server
	pns      int
}

// deletionOptions changes what newDeletionConsoleWith builds: its logger, a
// registry (device.start reaches its status checks only with one), and the
// subscribe's test hook.
type deletionOptions struct {
	log      *slog.Logger
	registry bool
	hook     func(stage string)
	// transfer stands in for the store's move to Personal.
	transfer func(ctx context.Context, source, actor, device, target uuid.UUID) (store.PersonalTransferPreview, error)
	// ledger is a deletion ledger the handlers export to.
	ledger string
	// fresh is the contract's freshness hook.
	fresh membership.Freshness
}

func newDeletionConsole(t *testing.T) *deletionConsole {
	t.Helper()
	return newDeletionConsoleWith(t, deletionOptions{})
}

func newDeletionConsoleWith(t *testing.T, opt deletionOptions) *deletionConsole {
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
	if opt.log == nil {
		opt.log = slog.New(slog.DiscardHandler)
	}
	cfg := wsapi.Config{
		Keys: keys, Sessions: users, Accounts: users, Devices: devices, Messages: messages,
		Keys2: store.NewKeys(pool), Receipts: store.NewReceipts(pool), Bus: b, Unlinker: unlinker, Log: opt.log,
	}
	var registry *wa.Registry
	if opt.registry {
		var err error
		registry, err = wa.NewRegistry(wa.RegistryConfig{Container: &sqlstore.Container{}, Store: devices, Log: slog.New(slog.DiscardHandler),
			NewClient: func(*waStore.Device, waLog.Logger) wa.Client { return fakewa.New() },
			// A session is stored while its row is in the session store's
			// table, so a start runs, on a fake client, until that row goes.
			LoadSession: func(ctx context.Context, jid types.JID) (*waStore.Device, error) {
				var stored bool
				if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM whatsmeow_device WHERE jid=$1)`, jid.String()).Scan(&stored); err != nil || !stored {
					return nil, err
				}
				ds := (&sqlstore.Container{}).NewDevice()
				ds.ID = &jid
				return ds, nil
			}})
		if err != nil {
			t.Fatal(err)
		}
		cfg.Registry = registry
		t.Cleanup(func() { registry.StopAll(context.Background()) })
	}
	if opt.hook != nil {
		wsapi.SetSubscribeHook(&cfg, opt.hook)
	}
	if opt.fresh != nil {
		cfg.Membership = opt.fresh
	}
	if opt.transfer != nil {
		wsapi.SetTransferHook(&cfg, opt.transfer)
	}
	if opt.ledger != "" {
		file := &ledger.File{Path: opt.ledger}
		cfg.ExportLedger = func(ctx context.Context, tenant uuid.UUID) {
			if _, err := store.ExportLedger(ctx, pool, tenant, file); err != nil {
				t.Errorf("the ledger's export: %v", err)
			}
		}
	}
	srv := httptest.NewServer(wsapi.NewServer(cfg))
	t.Cleanup(srv.Close)
	mux := http.NewServeMux()
	(&restapi.Handler{APIKeys: keys, Users: users, Keys: store.NewKeys(pool), Devices: devices, Messages: messages,
		Contacts: store.NewContacts(pool), Receipts: store.NewReceipts(pool)}).Mount(mux)
	rest := httptest.NewServer(mux)
	t.Cleanup(rest.Close)
	c := &deletionConsole{
		console: &console{srv: srv, pool: pool, tenant: uuid.MustParse(tenantID), apiKey: apiKey, devices: devices, users: users, keys: keys},
		bus:     b, unlinker: unlinker, rest: rest, registry: registry,
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

// scoped runs fn in the workspace with excluded numbers visible, as the
// store's quarantine scope does.
func (c *deletionConsole) scoped(ctx context.Context, t *testing.T, fn func(tx pgx.Tx) error) {
	t.Helper()
	if err := pg.InTenantTx(ctx, c.pool, c.tenant.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.device_quarantine', 'on', true)`); err != nil {
			return err
		}
		return fn(tx)
	}); err != nil {
		t.Fatal(err)
	}
}

// row reads a number's status, reason and fingerprint with the scope on.
func (c *deletionConsole) row(t *testing.T, device uuid.UUID) (deleted bool, status, reason string, leftover bool) {
	t.Helper()
	c.scoped(context.Background(), t, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT deleted_at IS NOT NULL, status, status_reason, wa_leftover IS NOT NULL
			FROM devices WHERE id=$1`, device).Scan(&deleted, &status, &reason, &leftover)
	})
	return deleted, status, reason, leftover
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

// listed is the number's row in devices.deleted, as the owner's console
// reads it.
func (c *deletionConsole) listed(t *testing.T, device uuid.UUID) wsapi.DeletedNumber {
	t.Helper()
	f := ask(t, c.console, wsapi.Hello{Session: c.token}, wsapi.TypeDevicesDeleted, nil)
	if f.Type != wsapi.TypeDeletedNumbers {
		t.Fatalf("devices.deleted: %s %s", f.Type, f.Payload)
	}
	for _, n := range payload[wsapi.DeletedNumbers](t, f).Numbers {
		if n.DeviceID == device.String() {
			return n
		}
	}
	t.Fatalf("%s is not among the deleted numbers", device)
	return wsapi.DeletedNumber{}
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

// drain reads every frame of conn into a channel until the connection ends,
// so a test can read several sockets while their replays run.
func drain(conn *websocket.Conn) <-chan wsapi.Frame {
	out := make(chan wsapi.Frame, 4096)
	go func() {
		defer close(out)
		for {
			_, data, err := conn.Read(context.Background())
			if err != nil {
				return
			}
			var f wsapi.Frame
			if json.Unmarshal(data, &f) == nil {
				out <- f
			}
		}
	}()
	return out
}

// next is the next frame of one of the given types, failing on an error
// frame, an ended subscription, or a wait of ten seconds.
func next(t *testing.T, frames <-chan wsapi.Frame, types ...string) wsapi.Frame {
	t.Helper()
	timeout := time.After(10 * time.Second)
	for {
		select {
		case f, ok := <-frames:
			if !ok {
				t.Fatal("the connection ended")
			}
			if f.Type == wsapi.TypeError || f.Type == wsapi.TypeSubscriptionEnded {
				t.Fatalf("%s %s", f.Type, f.Payload)
			}
			if slices.Contains(types, f.Type) {
				return f
			}
		case <-timeout:
			t.Fatalf("no %v frame", types)
		}
	}
}

// presenceOf publishes a presence for each device, in order.
func (c *deletionConsole) presenceOf(chat string, devices ...uuid.UUID) {
	for _, d := range devices {
		c.bus.Publish(c.tenant, ingest.Event{Class: ingest.ClassPresence, TenantID: c.tenant, DeviceID: d, Ephemeral: true,
			Presence: &ingest.Presence{ChatKey: chat, State: "composing"}})
	}
}

// A number is deleted while two replays hold a page read before the
// commit: a key for every number (whose sockets a deletion never closes)
// and the deleting owner's subscription to both numbers. Neither sends a
// row of the deleted number from then on, neither ends, and both go on
// with the other number, live traffic included, under -race.
func TestDeleteDuringReplay(t *testing.T) {
	paged := make(chan struct{}, 16)
	resume := make(chan struct{})
	c := newDeletionConsoleWith(t, deletionOptions{hook: func(stage string) {
		if stage != "page" {
			return
		}
		select {
		case paged <- struct{}{}:
		default:
		}
		<-resume
	}})
	ctx := context.Background()
	device, other := c.linkedDevice(t, "Suporte"), c.linkedDevice(t, "Vendas")
	c.reads(t, c.owner, device)
	c.reads(t, c.owner, other)
	// More than a replay page, so the second page is read after the commit,
	// and mostly the deleted number's: a replay that sent them would also
	// overrun the socket's queue.
	const rows, every = 520, 13
	messages := store.NewMessages(c.pool)
	for i := range rows {
		d := device
		if i%every == 0 {
			d = other
		}
		if _, err := messages.Insert(ctx, store.InsertMessage{UID: uuid.New(), TenantID: c.tenant, DeviceID: d, WAID: fmt.Sprintf("m-%d", i),
			ChatKey: "chat", Kind: domain.KindMessage, Type: domain.TypeText, Source: domain.SourceLive, TS: time.Now(), BodySealed: []byte{1}}); err != nil {
			t.Fatal(err)
		}
	}
	each := (rows + every - 1) / every
	keyConn := connect(t, c.console, wsapi.Hello{APIKey: c.apiKey})
	defer keyConn.CloseNow()
	ownerConn := connect(t, c.console, wsapi.Hello{Session: c.token})
	defer ownerConn.CloseNow()
	request(t, keyConn, "key", wsapi.TypeSubscribe, wsapi.Subscribe{})
	request(t, ownerConn, "owner", wsapi.TypeSubscribe, wsapi.Subscribe{Devices: []string{device.String(), other.String()}})
	streams := map[string]<-chan wsapi.Frame{"key": drain(keyConn), "owner": drain(ownerConn)}
	for range streams {
		select {
		case <-paged:
		case <-time.After(10 * time.Second):
			t.Fatal("a replay never read its first page")
		}
	}

	stop := make(chan struct{})
	var published sync.WaitGroup
	published.Add(1)
	go func() {
		defer published.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			c.presenceOf("chat", device, other)
			time.Sleep(5 * time.Millisecond)
		}
	}()
	if f := ask(t, c.console, wsapi.Hello{Session: c.token}, wsapi.TypeDeviceDelete, deleteFrame(device)); f.Type != wsapi.TypeDeviceGone {
		t.Fatalf("delete: %s %s", f.Type, f.Payload)
	}
	close(resume)

	for name, frames := range streams {
		replayed := 0
		for {
			f := next(t, frames, wsapi.TypeMessage, wsapi.TypeReplayEnd)
			if f.Type == wsapi.TypeReplayEnd {
				break
			}
			if m := payload[wsapi.SealedMessage](t, f); m.DeviceID == device.String() {
				t.Fatalf("%s: the replay sent a deleted number's message after the commit (seq %d)", name, m.Seq)
			}
			replayed++
		}
		if replayed != each {
			t.Fatalf("%s: replayed %d of the other number's %d messages", name, replayed, each)
		}
	}
	close(stop)
	published.Wait()
	c.presenceOf("last", device, other)
	for name, frames := range streams {
		for {
			p := payload[wsapi.PresenceEvent](t, next(t, frames, wsapi.TypePresence))
			if p.DeviceID == device.String() {
				t.Fatalf("%s: presence relayed for the deleted number", name)
			}
			if p.ChatKey == "last" {
				break
			}
		}
	}
}

// A deletion commits after a subscribe checked access and before the bus
// registered it: the subscription still never carries the deleted number.
func TestDeleteBetweenAccessCheckAndSubscribe(t *testing.T) {
	granted := make(chan struct{}, 1)
	resume := make(chan struct{})
	c := newDeletionConsoleWith(t, deletionOptions{hook: func(stage string) {
		if stage != "granted" {
			return
		}
		select {
		case granted <- struct{}{}:
		default:
		}
		<-resume
	}})
	device, other := c.linkedDevice(t, "Suporte"), c.linkedDevice(t, "Vendas")
	c.reads(t, c.owner, device)
	c.reads(t, c.owner, other)
	conn := connect(t, c.console, wsapi.Hello{Session: c.token})
	defer conn.CloseNow()
	request(t, conn, "sub", wsapi.TypeSubscribe, wsapi.Subscribe{Devices: []string{device.String(), other.String()}, LiveOnly: true})
	frames := drain(conn)
	select {
	case <-granted:
	case <-time.After(10 * time.Second):
		t.Fatal("the subscribe never checked access")
	}
	if f := ask(t, c.console, wsapi.Hello{Session: c.token}, wsapi.TypeDeviceDelete, deleteFrame(device)); f.Type != wsapi.TypeDeviceGone {
		t.Fatalf("delete: %s %s", f.Type, f.Payload)
	}
	close(resume)
	next(t, frames, wsapi.TypeReplayEnd)
	c.presenceOf("last", device, other)
	if p := payload[wsapi.PresenceEvent](t, next(t, frames, wsapi.TypePresence)); p.DeviceID != other.String() {
		t.Fatalf("presence relayed for %s", p.DeviceID)
	}
}

func TestExcludedFramesRefused(t *testing.T) {
	c := newDeletionConsole(t)
	ctx := context.Background()
	device, live := c.linkedDevice(t, "Suporte"), c.linkedDevice(t, "Vendas")
	member, _ := c.person(t, "member", "member")
	c.reads(t, c.owner, device)
	// grant.revoke really revokes, so its control runs on another number
	// with the same two key holders.
	c.reads(t, c.owner, live)
	c.reads(t, member, live)
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
	if f := ask(t, c.console, owner, wsapi.TypeGrantRevoke, wsapi.GrantRevoke{DeviceID: live.String(), UserID: member.String()}); f.Type != wsapi.TypeReaders {
		t.Fatalf("control grant.revoke: %s %s", f.Type, f.Payload)
	}

	// The control's grant.add made the member a reader: two key holders.
	if f := ask(t, c.console, owner, wsapi.TypeDeviceDelete, deleteFrame(device, member)); f.Type != wsapi.TypeDeviceGone {
		t.Fatalf("delete: %s %s", f.Type, f.Payload)
	}
	frames = append(frames, struct {
		kind    string
		payload any
	}{wsapi.TypeGrantRevoke, wsapi.GrantRevoke{DeviceID: device.String(), UserID: member.String()}})
	for _, frame := range frames {
		if f := ask(t, c.console, owner, frame.kind, frame.payload); !notFound(f) {
			t.Fatalf("%s on the excluded number: %s %s", frame.kind, f.Type, f.Payload)
		}
	}
	// The store would have revoked it: the handler's lookup is all that
	// keeps a deleted number's key holders.
	var grants int
	c.scoped(ctx, t, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM device_key_grants WHERE device_id=$1`, device).Scan(&grants)
	})
	if grants != 2 {
		t.Fatalf("the deleted number has %d grants, want both key holders'", grants)
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

// An owner recovers the number between the deletion's commit and its
// logout: the handler's own re-check stops the logout, and nothing is
// recorded on the recovered row.
func TestDeleteLogoutNeverAfterRecovery(t *testing.T) {
	c := newDeletionConsole(t)
	device := c.linkedDevice(t, "Suporte")
	c.unlinker.beforeRecheck = func(ctx context.Context, id string) {
		if _, err := c.devices.Recover(ctx, c.tenant, c.owner, uuid.MustParse(id)); err != nil {
			t.Errorf("recover: %v", err)
		}
	}
	f := ask(t, c.console, wsapi.Hello{Session: c.token}, wsapi.TypeDeviceDelete, deleteFrame(device))
	if f.Type != wsapi.TypeDeviceGone {
		t.Fatalf("delete: %s %s", f.Type, f.Payload)
	}
	if gone := payload[wsapi.DeviceDeleted](t, f); gone.Unlinked || gone.NoteCode != store.NoteUnlinkUnconfirmed {
		t.Fatalf("device.deleted = %+v", gone)
	}
	if c.unlinker.count() != 0 {
		t.Fatalf("%d logouts of a recovered number", c.unlinker.count())
	}
	if deleted, status, reason, _ := c.row(t, device); deleted || status != "offline" || reason != "deleted" {
		t.Fatalf("the recovered number: excluded %v, status %q (%q)", deleted, status, reason)
	}
	var sessions int
	if err := c.pool.QueryRow(context.Background(), `SELECT count(*) FROM whatsmeow_device`).Scan(&sessions); err != nil || sessions != 1 {
		t.Fatalf("the recovered number's session: %d, %v", sessions, err)
	}
}

// A number with only a LID has no session a deletion can find: it is never
// logged out, and the reply says WhatsApp had already let it go.
func TestDeleteLIDOnlyNumber(t *testing.T) {
	c := newDeletionConsole(t)
	ctx := context.Background()
	dev, err := c.devices.Create(ctx, c.tenant.String(), "lid", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	lid := types.NewJID("300000000000001", types.HiddenUserServer)
	if err := c.devices.SetIdentity(ctx, c.tenant.String(), dev.ID, wa.Identity{LID: lid}); err != nil {
		t.Fatal(err)
	}
	if err := c.devices.SetStatus(ctx, c.tenant.String(), dev.ID, wa.StatusOnline, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := c.pool.Exec(ctx, `INSERT INTO whatsmeow_device(jid, registration_id) VALUES ($1, 7)`, lid.String()); err != nil {
		t.Fatal(err)
	}
	f := ask(t, c.console, wsapi.Hello{Session: c.token}, wsapi.TypeDeviceDelete, deleteFrame(uuid.MustParse(dev.ID)))
	if f.Type != wsapi.TypeDeviceGone {
		t.Fatalf("delete: %s %s", f.Type, f.Payload)
	}
	if gone := payload[wsapi.DeviceDeleted](t, f); !gone.Unlinked || gone.NoteCode != store.NoteAlreadyDisconnected {
		t.Fatalf("device.deleted = %+v", gone)
	}
	if c.unlinker.count() != 0 {
		t.Fatalf("a LID-only number was logged out %d times", c.unlinker.count())
	}
	if _, status, reason, leftover := c.row(t, uuid.MustParse(dev.ID)); status != "logged_out" || reason != "no session at deletion" || leftover {
		t.Fatalf("the LID-only number: %q (%q), fingerprint %v", status, reason, leftover)
	}
	// The deleted list says the same, for a console whose reply was lost.
	if n := c.listed(t, uuid.MustParse(dev.ID)); !n.Unlinked || n.NoteCode != store.NoteAlreadyDisconnected {
		t.Fatalf("the deleted list's word on WhatsApp: %+v", n)
	}
}

// What a deletion logs never names the phone: not the session's JID, not a
// LID, whether WhatsApp answered or not. A session already gone is no
// warning.
func TestDeleteLogsNoPhone(t *testing.T) {
	logged := &lockedBuffer{}
	c := newDeletionConsoleWith(t, deletionOptions{log: slog.New(slog.NewTextHandler(logged, &slog.HandlerOptions{Level: slog.LevelDebug}))})
	ctx := context.Background()
	owner := wsapi.Hello{Session: c.token}
	gone, failing := c.linkedDevice(t, "Suporte"), c.linkedDevice(t, "Vendas")
	// The registry found the session gone from the store.
	c.unlinker.beforeRecheck = func(ctx context.Context, _ string) {
		if _, err := c.pool.Exec(ctx, `DELETE FROM whatsmeow_device`); err != nil {
			t.Error(err)
		}
	}
	c.unlinker.fail = fmt.Errorf("%w (device %s)", wa.ErrNoSession, gone.String()[:8])
	if f := ask(t, c.console, owner, wsapi.TypeDeviceDelete, deleteFrame(gone)); f.Type != wsapi.TypeDeviceGone || !payload[wsapi.DeviceDeleted](t, f).Unlinked {
		t.Fatalf("delete: %s %s", f.Type, f.Payload)
	}
	if strings.Contains(logged.String(), "not acknowledged") {
		t.Fatalf("a session already gone was logged as a failure: %s", logged)
	}
	// WhatsApp did not answer.
	if _, err := c.pool.Exec(ctx, `INSERT INTO whatsmeow_device(jid, registration_id) VALUES ($1, 7)`,
		types.JID{User: "5511900025678", Server: types.DefaultUserServer}.String()); err != nil {
		t.Fatal(err)
	}
	c.unlinker.beforeRecheck, c.unlinker.fail = nil, nil
	c.unlinker.onUnlink = func(context.Context, string) error { return errors.New("websocket not connected") }
	if f := ask(t, c.console, owner, wsapi.TypeDeviceDelete, deleteFrame(failing)); f.Type != wsapi.TypeDeviceGone {
		t.Fatalf("delete: %s %s", f.Type, f.Payload)
	}
	// The deleted list words the logout WhatsApp never confirmed as a retry's
	// already:true reply does, so a console that lost both still tells the
	// owner to remove the session on the phone.
	retried := ask(t, c.console, owner, wsapi.TypeDeviceDelete, deleteFrame(failing))
	if gone := payload[wsapi.DeviceDeleted](t, retried); !gone.Already || gone.Unlinked || gone.NoteCode != store.NoteUnlinkUnconfirmed {
		t.Fatalf("the retry's reply = %+v", gone)
	}
	if n := c.listed(t, failing); n.Unlinked || n.NoteCode != store.NoteUnlinkUnconfirmed {
		t.Fatalf("the deleted list's word on WhatsApp: %+v", n)
	}
	out := logged.String()
	if !strings.Contains(out, "not acknowledged") || !strings.Contains(out, "number excluded") {
		t.Fatalf("the deletions were not logged: %s", out)
	}
	for _, phone := range []string{"@s.whatsapp.net", "@lid", "5511900015678", "5511900025678"} {
		if strings.Contains(out, phone) {
			t.Fatalf("a deletion logged %q: %s", phone, out)
		}
	}
}

// lockedBuffer is a log sink handlers on several goroutines write to.
type lockedBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
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
	// A former reader is still a member, and had their access taken away
	// before the deletion: Read off, which drops their key too.
	if err := c.users.SetDevicePermission(ctx, c.tenant, c.owner, store.DevicePermission{DeviceID: device, UserID: former}); err != nil {
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
	// The former reader, who kept the id, learns nothing either.
	f := ask(t, c.console, wsapi.Hello{Session: formerToken}, wsapi.TypeDeviceDelete, deleteFrame(device))
	if e := wantError(t, f, wsapi.ErrCodeNotFound); strings.Contains(string(f.Payload), "deleted_at") ||
		strings.Contains(string(f.Payload), "recoverable_until") || strings.Contains(e.Message, "recover") {
		t.Fatalf("a former reader learned of the deletion: %s", f.Payload)
	}
	// An owner retrying gets the stored state.
	f = ask(t, c.console, wsapi.Hello{Session: c.token}, wsapi.TypeDeviceDelete, deleteFrame(device))
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

// ledgerTypes is the types of the lines a ledger holds, in order.
func ledgerTypes(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := ledger.Read(f)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, l := range r.Lines {
		out = append(out, l.Type)
	}
	return out
}

func TestDeletedListAndRecoverFrames(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deletion-ledger.jsonl")
	c := newDeletionConsoleWith(t, deletionOptions{registry: true, ledger: path})
	ctx := context.Background()
	device := c.linkedDevice(t, "Suporte")
	reader, readerToken := c.person(t, "reader", "member")
	c.reads(t, c.owner, device)
	c.reads(t, reader, device)
	owner := wsapi.Hello{Session: c.token}
	if f := ask(t, c.console, owner, wsapi.TypeDeviceDelete, deleteFrame(device, reader)); f.Type != wsapi.TypeDeviceGone {
		t.Fatalf("delete: %s", f.Payload)
	}
	// The deletion is in the ledger as soon as its reply arrives.
	if got := ledgerTypes(t, path); !slices.Equal(got, []string{"deleted"}) {
		t.Fatalf("the ledger after the deletion: %v", got)
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
		n.Status != "logged_out" || !n.LoggedOut || n.CanResume || n.KeyHolders != 2 || n.DeletedByName == "" || !n.Unlinked || n.NoteCode != "" {
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
	if got := ledgerTypes(t, path); !slices.Equal(got, []string{"deleted", "recovered"}) {
		t.Fatalf("the ledger after the recovery: %v", got)
	}
	f = ask(t, c.console, owner, wsapi.TypeDeviceRecover, wsapi.RecoverRequest{DeviceID: device.String(), Confirm: device.String()})
	if f.Type != wsapi.TypeDeviceRecovered || !payload[wsapi.DeviceRecovered](t, f).Already {
		t.Fatalf("a retried recovery: %s", f.Payload)
	}
	// The reader reads it again, with no new grant, and a logged-out number
	// cannot be started; nor can a banned one.
	if f := ask(t, c.console, wsapi.Hello{Session: readerToken}, wsapi.TypeChatPage, wsapi.ChatPageRequest{DeviceID: device.String(), ChatKey: "chat"}); f.Type == wsapi.TypeError {
		t.Fatalf("the reader after the recovery: %s", f.Payload)
	}
	banned := c.linkedDevice(t, "Banido")
	if err := c.devices.SetStatus(ctx, c.tenant.String(), banned.String(), wa.StatusBanned, "temporary"); err != nil {
		t.Fatal(err)
	}
	if f := ask(t, c.console, owner, wsapi.TypeDeviceDelete, deleteFrame(banned)); f.Type != wsapi.TypeDeviceGone {
		t.Fatalf("delete: %s", f.Payload)
	}
	if f := ask(t, c.console, owner, wsapi.TypeDeviceRecover, wsapi.RecoverRequest{DeviceID: banned.String(), Confirm: banned.String()}); f.Type != wsapi.TypeDeviceRecovered ||
		payload[wsapi.DeviceRecovered](t, f).Status != "banned" {
		t.Fatalf("recover the banned number: %s", f.Payload)
	}
	for _, dead := range []uuid.UUID{device, banned} {
		e := wantError(t, ask(t, c.console, owner, wsapi.TypeDeviceStart, wsapi.DeviceRef{DeviceID: dead.String()}), wsapi.ErrCodeConflict)
		if e.Message != "the WhatsApp session is no longer available" {
			t.Fatalf("starting %s: %q", dead, e.Message)
		}
		if d, err := c.devices.Get(ctx, c.tenant.String(), dead.String()); err != nil || !d.Paused {
			t.Fatalf("a refused start unpaused %s: %+v %v", dead, d, err)
		}
		if _, running := c.registry.Get(dead.String()); running {
			t.Fatalf("a refused start started %s", dead)
		}
	}
}

// device.recover's own refusals, over the socket, each with its code, and
// none changes the row.
func TestRecoverRefusalCodes(t *testing.T) {
	c := newDeletionConsole(t)
	ctx := context.Background()
	owner := wsapi.Hello{Session: c.token}
	deleted := func(label string) uuid.UUID {
		t.Helper()
		device := c.linkedDevice(t, label)
		if f := ask(t, c.console, owner, wsapi.TypeDeviceDelete, deleteFrame(device)); f.Type != wsapi.TypeDeviceGone {
			t.Fatalf("delete: %s", f.Payload)
		}
		return device
	}
	exec := func(query string, args ...any) {
		t.Helper()
		c.scoped(ctx, t, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, query, args...)
			return err
		})
	}
	for _, tc := range []struct {
		name  string
		code  string
		setup func(device uuid.UUID) (undo func())
	}{
		{"past its window", wsapi.ErrCodeRecoveryClosed, func(device uuid.UUID) func() {
			exec(`UPDATE devices SET purge_after = clock_timestamp() - interval '1 minute' WHERE id=$1`, device)
			return func() {}
		}},
		{"a purge started", wsapi.ErrCodeRecoveryClosed, func(device uuid.UUID) func() {
			exec(`UPDATE devices SET purge_started_at = clock_timestamp() WHERE id=$1`, device)
			return func() {}
		}},
		{"a logout in flight", wsapi.ErrCodeDeviceBusy, func(device uuid.UUID) func() {
			release, ok, err := pg.NewLocker(c.pool).TryLock(ctx, "device:"+device.String())
			if err != nil || !ok {
				t.Fatalf("lock: %v %v", ok, err)
			}
			return release
		}},
		{"a full plan", wsapi.ErrCodeCapacityReached, func(uuid.UUID) func() {
			c.linkedDevice(t, "live")
			exec(`INSERT INTO workspace_capacity(tenant_id, max_devices) VALUES ($1, (SELECT count(*) FROM devices WHERE deleted_at IS NULL))`, c.tenant)
			return func() { exec(`DELETE FROM workspace_capacity WHERE tenant_id=$1`, c.tenant) }
		}},
		{"its phone linked again", wsapi.ErrCodeIdentityInUse, func(device uuid.UUID) func() {
			var pn string
			c.scoped(ctx, t, func(tx pgx.Tx) error {
				return tx.QueryRow(ctx, `SELECT pn FROM devices WHERE id=$1`, device).Scan(&pn)
			})
			again, err := c.devices.Create(ctx, c.tenant.String(), "again", wa.ModePassive)
			if err != nil {
				t.Fatal(err)
			}
			jid, err := types.ParseJID(pn)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.devices.SetIdentity(ctx, c.tenant.String(), again.ID, wa.Identity{PN: jid}); err != nil {
				t.Fatal(err)
			}
			return func() {}
		}},
	} {
		device := deleted(tc.name)
		undo := tc.setup(device)
		f := ask(t, c.console, owner, wsapi.TypeDeviceRecover, wsapi.RecoverRequest{DeviceID: device.String(), Confirm: device.String()})
		undo()
		if e := wantError(t, f, tc.code); e.Message == "" {
			t.Fatalf("%s: no message", tc.name)
		}
		if deleted, _, _, _ := c.row(t, device); !deleted {
			t.Fatalf("%s: a refused recovery changed the row", tc.name)
		}
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
