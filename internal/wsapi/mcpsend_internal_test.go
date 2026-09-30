package wsapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/domain"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
	"whatserver2/internal/wa/fakewa"
)

// Assistant connections on this socket (docs/mcp-enclave.md §17.3, §17.7a):
// a key a connection holds never sends or manages here, and a person sends
// an assistant's draft once, and only the person who consented to it. The
// number is a fake WhatsApp client behind the device lookup.

const draftChat = "5511911111111@s.whatsapp.net"

type draftWorld struct {
	pool        *pgxpool.Pool
	srv         *httptest.Server
	server      *Server
	tenant      uuid.UUID
	device      uuid.UUID
	owner       store.User
	ownerToken  string
	users       *store.Users
	conns       *store.MCPConnections
	conn        store.SendConnection
	keyID       uuid.UUID
	connKey     string
	fake        *fakewa.Client
	sendAllowed atomic.Bool
}

func newDraftWorld(t *testing.T) *draftWorld {
	t.Helper()
	ctx := context.Background()
	pool := pgtest.Fresh(t, migrate.Run)
	w := &draftWorld{pool: pool, users: store.NewUsers(pool), conns: store.NewMCPConnections(pool), fake: fakewa.New()}
	w.sendAllowed.Store(true)
	if err := pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('acme') RETURNING id`).Scan(&w.tenant); err != nil {
		t.Fatal(err)
	}
	devices := store.NewDevices(pool)
	dev, err := devices.Create(ctx, w.tenant.String(), "phone", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	w.device = uuid.MustParse(dev.ID)
	keys := store.NewKeys(pool)
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.CreateArchiveKey(ctx, w.tenant, w.device, 1, pub); err != nil {
		t.Fatal(err)
	}
	w.owner = w.person(t, "owner")
	w.ownerToken = w.session(t, w.owner)
	if _, err := store.NewMessages(pool).Insert(ctx, store.InsertMessage{
		UID: uuid.New(), TenantID: w.tenant, DeviceID: w.device, WAID: "wa-friend", ChatKey: draftChat, SenderKey: draftChat,
		Kind: domain.KindMessage, Type: domain.TypeText, Source: domain.SourceLive, TS: time.Now(), BodySealed: []byte{1},
	}); err != nil {
		t.Fatal(err)
	}

	// The content connection the console would have recorded: a
	// provisional service account reading the number, a key acting as it,
	// consent version 3 with drafts.
	secret, _, err := w.users.NewProvisionalServiceInvitation(ctx, w.tenant, w.owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	readerKey := make([]byte, 32)
	name := make([]byte, 4)
	if _, err := rand.Read(readerKey); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(name); err != nil {
		t.Fatal(err)
	}
	svc, err := w.users.SignupService(ctx, secret, "mcp-"+hex.EncodeToString(name), readerKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.users.SetDevicePermission(ctx, w.tenant, w.owner.ID, store.DevicePermission{DeviceID: w.device, UserID: svc.ID, Read: true}); err != nil {
		t.Fatal(err)
	}
	if err := keys.PutGrant(ctx, store.Grant{TenantID: w.tenant, DeviceID: w.device, UserID: svc.ID, Epoch: 1, SealedDSK: []byte("sealed")}, &w.owner.ID); err != nil {
		t.Fatal(err)
	}
	in := time.Now().Add(20 * time.Minute)
	apiKeys := store.NewAPIKeys(pool)
	w.connKey, err = apiKeys.IssueActingAsForDevices(ctx, w.tenant.String(), "assistant", store.ScopeRead, &w.owner.ID, &svc.ID, []uuid.UUID{w.device}, &in)
	if err != nil {
		t.Fatal(err)
	}
	prefix, _, _ := strings.Cut(w.connKey, ".")
	conn, err := w.conns.Create(ctx, w.tenant, w.owner.ID, store.CreateMCPConnection{
		RequestID: uuid.NewString(), KeyPrefix: prefix, ClientName: "Claude", RedirectHost: "claude.ai", DeviceCount: 1,
		ReaderKID: "0123456789abcdef", ExpiresAt: time.Now().Add(30 * 24 * time.Hour), Reader: "enclave",
		Kind: store.KindContent, ServiceUserID: svc.ID, KeyMode: store.KeyModeEphemeral, ConsentVersion: store.SendConsentVersion,
		SendMode: store.SendModeDraft, ReaderPublicKey: readerKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.conns.Activate(ctx, "enclave", conn.ID); err != nil {
		t.Fatal(err)
	}
	if w.conn, err = w.conns.SendConnection(ctx, "enclave", conn.ID); err != nil {
		t.Fatal(err)
	}
	verified, err := apiKeys.VerifyScoped(ctx, w.connKey)
	if err != nil {
		t.Fatal(err)
	}
	w.keyID = verified.ID

	live, err := wa.NewDevice(wa.DeviceConfig{ID: w.device.String(), TenantID: w.tenant.String(), Client: w.fake})
	if err != nil {
		t.Fatal(err)
	}
	w.server = NewServer(Config{
		Keys: apiKeys, Sessions: w.users, Accounts: w.users, Devices: devices, Messages: store.NewMessages(pool), Keys2: keys,
		MCP: w.conns, MCPSendAllowed: func(uuid.UUID) bool { return w.sendAllowed.Load() },
		Log: slog.New(slog.DiscardHandler),
	})
	w.server.device = func(id string) (*wa.Device, bool) {
		if id == w.device.String() {
			return live, true
		}
		return nil, false
	}
	w.srv = httptest.NewServer(w.server)
	t.Cleanup(w.srv.Close)
	return w
}

// person is a member of the workspace who may read and send on the number.
func (w *draftWorld) person(t *testing.T, role string) store.User {
	t.Helper()
	ctx := context.Background()
	u, err := w.users.Create(ctx, store.NewUser{
		TenantID: w.tenant, Email: uuid.NewString() + "@example.test", Role: role, AuthKey: "proof",
		KDFSalt: make([]byte, 16), KDFParams: store.DefaultKDFParams(), PublicKey: make([]byte, 32), WrappedUSK: []byte("wrapped"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.NewKeys(w.pool).PutGrant(ctx, store.Grant{TenantID: w.tenant, DeviceID: w.device, UserID: u.ID, Epoch: 1, SealedDSK: []byte("sealed")}, nil); err != nil {
		t.Fatal(err)
	}
	if err := w.users.SetDevicePermission(ctx, w.tenant, u.ID, store.DevicePermission{DeviceID: w.device, UserID: u.ID, Read: true, Send: true}); err != nil {
		// The first owner is the one who grants; a later one is granted by it.
		if err := w.users.SetDevicePermission(ctx, w.tenant, w.owner.ID, store.DevicePermission{DeviceID: w.device, UserID: u.ID, Read: true, Send: true}); err != nil {
			t.Fatal(err)
		}
	}
	return u
}

func (w *draftWorld) session(t *testing.T, u store.User) string {
	t.Helper()
	token, _, err := w.users.StartSession(context.Background(), u, "test")
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// draft records a draft of the connection to the chat.
func (w *draftWorld) draft(t *testing.T) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := w.conns.CreateDraft(context.Background(), w.conn, w.keyID,
		store.NewDraft{ID: id, Device: w.device, ChatKey: draftChat, Epoch: 1, Sealed: []byte("sealed")},
		store.SendLimits{DraftsPerHour: 30, DraftsPending: 20, PerDay: 20, PerChatPerDay: 5, MinInterval: time.Second, TenantPerDay: 100}); err != nil {
		t.Fatal(err)
	}
	return id
}

func (w *draftWorld) status(t *testing.T, id uuid.UUID) (status string, edited bool, decidedBy *uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	if err := pg.InTenantTx(ctx, w.pool, w.tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT status, edited, decided_by FROM mcp_outbound WHERE id=$1`, id).Scan(&status, &edited, &decidedBy)
	}); err != nil {
		t.Fatal(err)
	}
	return status, edited, decidedBy
}

// connect opens a socket with a hello.
func (w *draftWorld) connect(t *testing.T, hello Hello) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(w.srv.URL, "http")+"/v1/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.CloseNow() })
	hello.Version = Version
	wsWrite(t, conn, TypeHello, hello)
	if f := wsRead(t, conn); f.Type != TypeWelcome {
		t.Fatalf("handshake: %s %s", f.Type, f.Payload)
	}
	return conn
}

func wsWrite(t *testing.T, conn *websocket.Conn, frameType string, payload any) {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(Frame{Type: frameType, ReqID: uuid.NewString(), Payload: raw})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn.Write(ctx, websocket.MessageText, b); err != nil {
		t.Fatal(err)
	}
}

func wsRead(t *testing.T, conn *websocket.Conn) Frame {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var f Frame
		if err := json.Unmarshal(data, &f); err != nil {
			t.Fatal(err)
		}
		if f.ReqID == "" && f.Type != TypeWelcome {
			// A broadcast, not the answer.
			continue
		}
		return f
	}
}

// ask sends one frame on a fresh socket and returns the answer.
func (w *draftWorld) ask(t *testing.T, hello Hello, frameType string, payload any) Frame {
	t.Helper()
	conn := w.connect(t, hello)
	wsWrite(t, conn, frameType, payload)
	return wsRead(t, conn)
}

func errorCode(t *testing.T, f Frame) string {
	t.Helper()
	if f.Type != TypeError {
		t.Fatalf("frame = %s %s, want an error", f.Type, f.Payload)
	}
	var e Error
	if err := json.Unmarshal(f.Payload, &e); err != nil {
		t.Fatal(err)
	}
	return e.Code
}

func (w *draftWorld) confirm(draft uuid.UUID, chat string) SendRequest {
	return SendRequest{DeviceID: w.device.String(), Chat: chat, Body: "Oi, chego às 18h", MCPDraft: draft.String(), MCPEdited: true}
}

// ---------------------------------------------------------------------------

// A key a connection holds answers not_authorized to every frame that sends
// or manages, whatever its scope, before any lookup; reading goes on. Any
// other key is left to its scope.
func TestAssistantKeyNeverSendsOrManages(t *testing.T) {
	w := newDraftWorld(t)
	ctx := context.Background()
	// A full key a connection holds: the scope would allow everything.
	full, err := store.NewAPIKeys(w.pool).IssueScoped(ctx, w.tenant.String(), "full", store.ScopeFull, nil)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := store.NewAPIKeys(w.pool).VerifyScoped(ctx, full)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.pool.Exec(ctx, `INSERT INTO mcp_connections (tenant_id, request_id, api_key_id, created_by, client_name, redirect_host,
		device_count, reader_kid, status, expires_at) VALUES ($1, $2, $3, $4, 'Claude', 'claude.ai', 1, '0123456789abcdef', 'revoked', now())`,
		w.tenant, uuid.NewString(), verified.ID, w.owner.ID); err != nil {
		t.Fatal(err)
	}
	other, err := store.NewAPIKeys(w.pool).IssueScoped(ctx, w.tenant.String(), "automation", store.ScopeFull, nil)
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, kind := range features {
		action := frameAction(kind)
		if action != store.ActionSend && action != store.ActionManage || kind == "pair.qr" || kind == "pair.code" {
			continue
		}
		for _, key := range []string{full, w.connKey} {
			f := w.ask(t, Hello{APIKey: key}, kind, map[string]any{"device_id": w.device.String(), "chat": draftChat, "body": "x"})
			if code := errorCode(t, f); code != ErrCodeNotAuthorized || !strings.Contains(string(f.Payload), "assistant connection") {
				t.Fatalf("%s with a connection's key: %s", kind, f.Payload)
			}
		}
		checked++
	}
	if checked < 20 {
		t.Fatalf("only %d frames checked", checked)
	}
	if len(w.fake.Sent()) != 0 {
		t.Fatalf("a connection's key sent: %+v", w.fake.Sent())
	}
	// Reading goes on.
	if f := w.ask(t, Hello{APIKey: full}, TypeChatsList, map[string]string{"device_id": w.device.String()}); f.Type != TypeChats {
		t.Fatalf("reading with a connection's key: %s %s", f.Type, f.Payload)
	}
	// Another key with the same scope sends.
	if f := w.ask(t, Hello{APIKey: other}, TypeSend, SendRequest{DeviceID: w.device.String(), Chat: draftChat, Body: "x"}); f.Type != TypeSendResult {
		t.Fatalf("another key: %s %s", f.Type, f.Payload)
	}
}

// A draft is sent by the person who consented, once, and recorded; nobody
// else, no key and no second frame sends it.
func TestDraftConfirmation(t *testing.T) {
	w := newDraftWorld(t)
	ctx := context.Background()
	id := w.draft(t)
	admin := w.person(t, "admin")

	// Keys never confirm: a key with send scope, and the connection's own.
	sender, err := store.NewAPIKeys(w.pool).IssueScoped(ctx, w.tenant.String(), "sender", store.ScopeSend, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{sender, w.connKey} {
		if code := errorCode(t, w.ask(t, Hello{APIKey: key}, TypeSend, w.confirm(id, draftChat))); code != ErrCodeNotAuthorized {
			t.Fatalf("a key confirmed: %s", code)
		}
	}
	// Another person, an admin who may send on the number.
	if code := errorCode(t, w.ask(t, Hello{Session: w.session(t, admin)}, TypeSend, w.confirm(id, draftChat))); code != ErrCodeNotAuthorized {
		t.Fatalf("another person: %s", code)
	}
	// Another chat.
	if code := errorCode(t, w.ask(t, Hello{Session: w.ownerToken}, TypeSend, w.confirm(id, "5511922222222@s.whatsapp.net"))); code != ErrCodeBadRequest {
		t.Fatalf("another chat: %s", code)
	}
	// Sending switched off.
	w.sendAllowed.Store(false)
	if code := errorCode(t, w.ask(t, Hello{Session: w.ownerToken}, TypeSend, w.confirm(id, draftChat))); code != ErrCodeSendNotAllowed {
		t.Fatalf("switched off: %s", code)
	}
	w.sendAllowed.Store(true)
	if len(w.fake.Sent()) != 0 {
		t.Fatalf("a refused confirmation sent: %+v", w.fake.Sent())
	}
	if status, _, _ := w.status(t, id); status != store.OutboundPending {
		t.Fatalf("a refused confirmation took the draft: %s", status)
	}

	// The person who consented: sent, with the frame's text, and recorded.
	f := w.ask(t, Hello{Session: w.ownerToken}, TypeSend, w.confirm(id, draftChat))
	if f.Type != TypeSendResult {
		t.Fatalf("confirm: %s %s", f.Type, f.Payload)
	}
	sent := w.fake.Sent()
	if len(sent) != 1 || sent[0].To.String() != draftChat || sent[0].Message.GetExtendedTextMessage().GetText() != "Oi, chego às 18h" {
		t.Fatalf("sent = %+v", sent)
	}
	if status, edited, by := w.status(t, id); status != store.OutboundSent || !edited || by == nil || *by != w.owner.ID {
		t.Fatalf("recorded = %s %v %v", status, edited, by)
	}
	// A second frame: draft_state, and nothing sent.
	if code := errorCode(t, w.ask(t, Hello{Session: w.ownerToken}, TypeSend, w.confirm(id, draftChat))); code != ErrCodeDraftState {
		t.Fatalf("again: %s", code)
	}
	if len(w.fake.Sent()) != 1 {
		t.Fatalf("sent twice: %d", len(w.fake.Sent()))
	}

	// Two frames at once, on two sockets: one message.
	twice := w.draft(t)
	a, b := w.connect(t, Hello{Session: w.ownerToken}), w.connect(t, Hello{Session: w.ownerToken})
	var wg sync.WaitGroup
	answers := make([]Frame, 2)
	for i, conn := range []*websocket.Conn{a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wsWrite(t, conn, TypeSend, w.confirm(twice, draftChat))
			answers[i] = wsRead(t, conn)
		}()
	}
	wg.Wait()
	results, states := 0, 0
	for _, f := range answers {
		switch {
		case f.Type == TypeSendResult:
			results++
		case errorCode(t, f) == ErrCodeDraftState:
			states++
		}
	}
	if results != 1 || states != 1 || len(w.fake.Sent()) != 2 {
		t.Fatalf("%d sent, %d refused, %d messages", results, states, len(w.fake.Sent()))
	}

	// Discarded and expired drafts.
	discarded := w.draft(t)
	if _, err := w.conns.DiscardDraft(ctx, w.tenant, w.owner.ID, discarded); err != nil {
		t.Fatal(err)
	}
	expired := w.draft(t)
	if err := pg.InTenantTx(ctx, w.pool, w.tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE mcp_outbound SET expires_at=now()-interval '1 second' WHERE id=$1`, expired)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for name, draft := range map[string]uuid.UUID{"discarded": discarded, "expired": expired, "unknown": uuid.New()} {
		code := errorCode(t, w.ask(t, Hello{Session: w.ownerToken}, TypeSend, w.confirm(draft, draftChat)))
		want := ErrCodeDraftState
		if name == "unknown" {
			want = ErrCodeNotAuthorized
		}
		if code != want {
			t.Fatalf("%s: %s", name, code)
		}
	}

	// A transport error: uncertain, and the person told.
	failing := w.draft(t)
	w.fake.SendErr = errors.New("socket closed")
	if code := errorCode(t, w.ask(t, Hello{Session: w.ownerToken}, TypeSend, w.confirm(failing, draftChat))); code != ErrCodeInternal {
		t.Fatalf("transport error: %s", code)
	}
	w.fake.SendErr = nil
	if status, _, _ := w.status(t, failing); status != store.OutboundUncertain {
		t.Fatalf("after a transport error: %s", status)
	}
	// The person who consented lost send on the number: the frame is
	// refused before the draft is touched.
	lost := w.draft(t)
	if err := w.users.SetDevicePermission(ctx, w.tenant, w.owner.ID, store.DevicePermission{DeviceID: w.device, UserID: w.owner.ID, Read: true}); err != nil {
		t.Fatal(err)
	}
	if code := errorCode(t, w.ask(t, Hello{Session: w.ownerToken}, TypeSend, w.confirm(lost, draftChat))); code != ErrCodeNotAuthorized {
		t.Fatalf("without send: %s", code)
	}
	if status, _, _ := w.status(t, lost); status != store.OutboundPending {
		t.Fatalf("without send, the draft = %s", status)
	}
}

// SendText, the send route's way out: the chat's timer applied and nothing
// else, a number that is not running refused before anything leaves, and
// an archive that failed leaving the message sent with no uid.
func TestSendTextForTheSendRoute(t *testing.T) {
	w := newDraftWorld(t)
	ctx := context.Background()
	if err := store.NewMessages(w.pool).SetChatTimer(ctx, w.tenant, w.device, draftChat, 86400); err != nil {
		t.Fatal(err)
	}
	out, err := w.server.SendText(ctx, Text{Tenant: w.tenant, Device: w.device, Chat: draftChat, Body: "nota"})
	if err != nil || out.WAID == "" || out.UID != nil {
		t.Fatalf("sent = %+v %v", out, err)
	}
	last := w.fake.LastSent()
	info := last.Message.GetEphemeralMessage().GetMessage().GetExtendedTextMessage().GetContextInfo()
	if last.To.String() != draftChat || info.GetExpiration() != 86400 || len(last.Extra) != 0 {
		t.Fatalf("sent = %+v", last)
	}
	if _, err := w.server.SendText(ctx, Text{Tenant: w.tenant, Device: uuid.New(), Chat: draftChat, Body: "x"}); !errors.Is(err, ErrDeviceOffline) || !errors.Is(err, ErrNotSent) {
		t.Fatalf("not running = %v", err)
	}
	w.fake.SendErr = errors.New("socket closed")
	if _, err := w.server.SendText(ctx, Text{Tenant: w.tenant, Device: w.device, Chat: draftChat, Body: "x"}); err == nil || errors.Is(err, ErrNotSent) {
		t.Fatalf("a transport error = %v", err)
	}
}
