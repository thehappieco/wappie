package wsapi_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/domain"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
	"whatserver2/internal/wsapi"
)

// The console is where somebody manages the tenant, which makes it where the
// damage is. Three things are worth testing more than the happy path:
//
//   - An API key cannot mint or revoke API keys. It is the credential most
//     likely to leak, and a leaked key that mints successors survives the
//     revocation of the key that leaked.
//   - Deleting a device destroys an archive with no way back, so the confirm
//     has to actually be checked rather than merely requested.
//   - Revoking a key hangs up the sockets already using it. Otherwise "revoked"
//     means "revoked for anyone who reconnects", which is not the promise.

type console struct {
	srv     *httptest.Server
	pool    *pgxpool.Pool
	tenant  uuid.UUID
	apiKey  string
	devices *store.Devices
	users   *store.Users
	keys    *store.APIKeys
}

func newConsole(t *testing.T) *console {
	t.Helper()
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO tenants (name) VALUES ('acme') RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	keys := store.NewAPIKeys(pool)
	apiKey, err := keys.Issue(ctx, tenantID, "ci")
	if err != nil {
		t.Fatal(err)
	}
	users := store.NewUsers(pool)
	devices := store.NewDevices(pool)

	srv := httptest.NewServer(wsapi.NewServer(wsapi.Config{
		Keys: keys, Sessions: users, Accounts: users,
		Devices: devices, Messages: store.NewMessages(pool),
		Keys2: store.NewKeys(pool),
		Log:   slog.New(slog.DiscardHandler),
	}))
	t.Cleanup(srv.Close)

	return &console{
		srv: srv, pool: pool, tenant: uuid.MustParse(tenantID),
		apiKey: apiKey, devices: devices, users: users, keys: keys,
	}
}

// account creates a person and returns a session token for them.
//
// The key material is nonsense on purpose: nothing here opens anything, and a
// real keypair would suggest this test says something about the crypto.
func (c *console) account(t *testing.T, email, role string) string {
	t.Helper()
	ctx := context.Background()
	user, err := c.users.Create(ctx, store.NewUser{
		TenantID: c.tenant, Email: email, Role: role,
		AuthKey: "auth-" + email, KDFSalt: make([]byte, 16),
		KDFParams: store.DefaultKDFParams(),
		PublicKey: make([]byte, 32), WrappedUSK: []byte("wrapped"),
	})
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := c.users.StartSession(ctx, user, "test")
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// ask sends a frame and returns the reply.
func ask(t *testing.T, c *console, tok wsapi.Hello, frameType string, payload any) wsapi.Frame {
	t.Helper()
	conn := dial(t, c.srv)
	tok.Version = wsapi.Version
	send(t, conn, wsapi.TypeHello, tok)
	if f := read(t, conn); f.Type != wsapi.TypeWelcome {
		t.Fatalf("handshake: %s %s", f.Type, f.Payload)
	}
	send(t, conn, frameType, payload)
	return read(t, conn)
}

func payload[T any](t *testing.T, f wsapi.Frame) T {
	t.Helper()
	var out T
	if err := json.Unmarshal(f.Payload, &out); err != nil {
		t.Fatalf("decoding %s: %v", f.Type, err)
	}
	return out
}

func wantError(t *testing.T, f wsapi.Frame, code string) wsapi.Error {
	t.Helper()
	if f.Type != wsapi.TypeError {
		t.Fatalf("frame = %q, want an error: %s", f.Type, f.Payload)
	}
	e := payload[wsapi.Error](t, f)
	if e.Code != code {
		t.Fatalf("error code = %q, want %q (%s)", e.Code, code, e.Message)
	}
	return e
}

func TestAPIKeyCannotMintAPIKeys(t *testing.T) {
	c := newConsole(t)
	f := ask(t, c, wsapi.Hello{APIKey: c.apiKey},
		wsapi.TypeKeyCreate, wsapi.APIKeyRequest{Name: "another", Scope: "read"})

	e := wantError(t, f, wsapi.ErrCodeNotAuthorized)
	// The message has to say what to do instead. "not authorized" alone sends
	// somebody looking for a permission that does not exist.
	if !strings.Contains(e.Message, "account") {
		t.Errorf("message does not say an account is needed: %q", e.Message)
	}

	keys, err := c.keys.List(context.Background(), c.tenant.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Errorf("keys = %d, want the one it started with", len(keys))
	}
}

func TestAPIKeyCannotRevokeAPIKeys(t *testing.T) {
	c := newConsole(t)
	f := ask(t, c, wsapi.Hello{APIKey: c.apiKey},
		wsapi.TypeKeyRevoke, wsapi.APIKeyRef{Prefix: c.apiKey[:8]})
	wantError(t, f, wsapi.ErrCodeNotAuthorized)

	// Still usable: a refused revocation must not half-happen.
	if _, err := c.keys.Verify(context.Background(), c.apiKey); err != nil {
		t.Errorf("the key stopped working after a refused revocation: %v", err)
	}
}

func TestAMemberCannotMintAPIKeys(t *testing.T) {
	c := newConsole(t)
	token := c.account(t, "member@acme.test", "member")
	f := ask(t, c, wsapi.Hello{Session: token},
		wsapi.TypeKeyCreate, wsapi.APIKeyRequest{Name: "nope", Scope: "read"})

	e := wantError(t, f, wsapi.ErrCodeNotAuthorized)
	if !strings.Contains(e.Message, "member@acme.test") {
		t.Errorf("message does not name who asked: %q", e.Message)
	}
}

func TestAnAdminMintsAKeyThatWorks(t *testing.T) {
	c := newConsole(t)
	token := c.account(t, "owner@acme.test", "owner")

	f := ask(t, c, wsapi.Hello{Session: token},
		wsapi.TypeKeyCreate, wsapi.APIKeyRequest{Name: "billing exporter", Scope: "read"})
	if f.Type != wsapi.TypeAPIKeyNew {
		t.Fatalf("frame = %q: %s", f.Type, f.Payload)
	}
	created := payload[wsapi.APIKeyCreated](t, f)
	if created.Key == "" {
		t.Fatal("no key in the reply, which is the only time it exists")
	}

	tenant, err := c.keys.Verify(context.Background(), created.Key)
	if err != nil {
		t.Fatalf("the minted key does not authenticate: %v", err)
	}
	if tenant != c.tenant.String() {
		t.Errorf("key resolves to tenant %s, want %s", tenant, c.tenant)
	}

	// Authorship is the point of minting it through an account rather than the
	// command line: a key nobody can account for is how a leak goes unnoticed.
	listed := payload[wsapi.APIKeys](t, ask(t, c, wsapi.Hello{Session: token}, wsapi.TypeKeysList, nil))
	var found bool
	for _, k := range listed.Keys {
		if k.Prefix == created.Info.Prefix {
			found = true
			if k.CreatedBy != "owner@acme.test" {
				t.Errorf("created_by = %q, want the account that asked", k.CreatedBy)
			}
			if k.Name != "billing exporter" {
				t.Errorf("name = %q", k.Name)
			}
		}
	}
	if !found {
		t.Error("the new key is not in the list")
	}
}

func TestAKeyNeedsAName(t *testing.T) {
	c := newConsole(t)
	token := c.account(t, "owner@acme.test", "owner")
	f := ask(t, c, wsapi.Hello{Session: token}, wsapi.TypeKeyCreate, wsapi.APIKeyRequest{Name: "  ", Scope: "read"})
	wantError(t, f, wsapi.ErrCodeBadRequest)
}

func TestAKeyNeedsAScope(t *testing.T) {
	c := newConsole(t)
	token := c.account(t, "owner@acme.test", "owner")
	f := ask(t, c, wsapi.Hello{Session: token}, wsapi.TypeKeyCreate, wsapi.APIKeyRequest{Name: "bot"})
	e := wantError(t, f, wsapi.ErrCodeBadRequest)
	if !strings.Contains(e.Message, "scope") {
		t.Errorf("message does not explain the scopes: %q", e.Message)
	}
	f = ask(t, c, wsapi.Hello{Session: token}, wsapi.TypeKeyCreate, wsapi.APIKeyRequest{Name: "bot", Scope: "admin"})
	wantError(t, f, wsapi.ErrCodeBadRequest)
}

// What a key may do is its scope, and the scope is checked on the server.
//
// A key is the credential most likely to leak — it lives in config files and
// never expires — so what a leaked one can do matters. Before scopes, any key
// could send as the paired number, join groups and stop devices.
func TestAReadKeyCannotSpeakForTheNumber(t *testing.T) {
	c := newConsole(t)
	token := c.account(t, "owner@acme.test", "owner")
	created := payload[wsapi.APIKeyCreated](t, ask(t, c, wsapi.Hello{Session: token},
		wsapi.TypeKeyCreate, wsapi.APIKeyRequest{Name: "monitor", Scope: "read"}))
	if created.Info.Scope != "read" {
		t.Fatalf("scope = %q", created.Info.Scope)
	}
	device := c.deviceWithKey(t, "phone")
	read := wsapi.Hello{APIKey: created.Key}

	refused := []struct {
		frame   string
		payload any
	}{
		{wsapi.TypeSend, wsapi.SendRequest{DeviceID: device, Chat: "5511@s.whatsapp.net", Body: "hi"}},
		{wsapi.TypeReact, map[string]string{"device_id": device, "chat": "5511@s.whatsapp.net"}},
		{wsapi.TypeMarkRead, map[string]string{"device_id": device, "chat": "5511@s.whatsapp.net"}},
		{wsapi.TypeGroupJoin, map[string]string{"device_id": device, "group_jid": "1@g.us"}},
		{wsapi.TypeBackfill, map[string]string{"device_id": device, "chat": "5511@s.whatsapp.net"}},
		{wsapi.TypeDeviceStop, wsapi.DeviceRef{DeviceID: device}},
	}
	for _, r := range refused {
		e := wantError(t, ask(t, c, read, r.frame, r.payload), wsapi.ErrCodeNotAuthorized)
		if !strings.Contains(e.Message, "scope") {
			t.Errorf("%s: the refusal does not name the scope: %q", r.frame, e.Message)
		}
	}
	// Reading still works: that is what the key is for.
	if f := ask(t, c, read, wsapi.TypeDevicesList, nil); f.Type != wsapi.TypeDevices {
		t.Fatalf("a read key cannot list devices: %s %s", f.Type, f.Payload)
	}
}

func TestASendKeyStopsAtSending(t *testing.T) {
	c := newConsole(t)
	token := c.account(t, "owner@acme.test", "owner")
	created := payload[wsapi.APIKeyCreated](t, ask(t, c, wsapi.Hello{Session: token},
		wsapi.TypeKeyCreate, wsapi.APIKeyRequest{Name: "bot", Scope: "send"}))
	device := c.deviceWithKey(t, "phone")
	send := wsapi.Hello{APIKey: created.Key}

	// Past the scope check: the refusal is about the device not being
	// connected, which is the next check, not about the key.
	f := ask(t, c, send, wsapi.TypeSend,
		wsapi.SendRequest{DeviceID: device, Chat: "5511@s.whatsapp.net", Body: "hi"})
	if e := wantError(t, f, wsapi.ErrCodeConflict); strings.Contains(e.Message, "scope") {
		t.Errorf("a send key was refused on scope: %q", e.Message)
	}
	wantError(t, ask(t, c, send, wsapi.TypeDeviceStop, wsapi.DeviceRef{DeviceID: device}),
		wsapi.ErrCodeNotAuthorized)
	wantError(t, ask(t, c, send, wsapi.TypeGroupJoin,
		map[string]string{"device_id": device, "group_jid": "1@g.us"}), wsapi.ErrCodeNotAuthorized)
}

func TestAKeyIssuedBeforeScopesKeepsWorking(t *testing.T) {
	c := newConsole(t)
	// The console's own key came from Issue, which is what every key before
	// this migration was: full, so nothing that worked stops working.
	v, err := c.keys.VerifyScoped(context.Background(), c.apiKey)
	if err != nil {
		t.Fatal(err)
	}
	if v.Scope != store.ScopeFull {
		t.Fatalf("scope = %q, want full", v.Scope)
	}
}

func TestRevokingAKeyRefusesTheNextConnection(t *testing.T) {
	c := newConsole(t)
	token := c.account(t, "owner@acme.test", "owner")
	created := payload[wsapi.APIKeyCreated](t, ask(t, c, wsapi.Hello{Session: token},
		wsapi.TypeKeyCreate, wsapi.APIKeyRequest{Name: "temporary", Scope: "read"}))

	f := ask(t, c, wsapi.Hello{Session: token},
		wsapi.TypeKeyRevoke, wsapi.APIKeyRef{Prefix: created.Info.Prefix})
	if f.Type != wsapi.TypeAPIKeyGone {
		t.Fatalf("frame = %q: %s", f.Type, f.Payload)
	}

	conn := dial(t, c.srv)
	send(t, conn, wsapi.TypeHello, wsapi.Hello{APIKey: created.Key, Version: wsapi.Version})
	wantError(t, read(t, conn), wsapi.ErrCodeUnauthorized)
}

func TestRevokingAKeyHangsUpTheSocketsUsingIt(t *testing.T) {
	c := newConsole(t)
	token := c.account(t, "owner@acme.test", "owner")
	created := payload[wsapi.APIKeyCreated](t, ask(t, c, wsapi.Hello{Session: token},
		wsapi.TypeKeyCreate, wsapi.APIKeyRequest{Name: "temporary", Scope: "read"}))

	// A consumer already connected on that key, the way a running exporter is.
	victim := dial(t, c.srv)
	send(t, victim, wsapi.TypeHello, wsapi.Hello{APIKey: created.Key, Version: wsapi.Version})
	if f := read(t, victim); f.Type != wsapi.TypeWelcome {
		t.Fatalf("victim handshake: %s %s", f.Type, f.Payload)
	}

	ask(t, c, wsapi.Hello{Session: token},
		wsapi.TypeKeyRevoke, wsapi.APIKeyRef{Prefix: created.Info.Prefix})

	// The next read fails because the server hung up. Without this, revocation
	// would leave a live socket streaming to a credential that no longer exists.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, _, err := victim.Read(ctx); err == nil {
		t.Fatal("the connection survived the revocation of its key")
	}
}

func TestDeletingADeviceNeedsItsIDRepeated(t *testing.T) {
	c := newConsole(t)
	token := c.account(t, "owner@acme.test", "owner")
	dev, err := c.devices.Create(context.Background(), c.tenant.String(), "phone", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}

	f := ask(t, c, wsapi.Hello{Session: token}, wsapi.TypeDeviceDelete,
		wsapi.DeleteRequest{DeviceID: dev.ID, Confirm: "yes"})
	wantError(t, f, wsapi.ErrCodeBadRequest)

	if _, err := c.devices.Get(context.Background(), c.tenant.String(), dev.ID); err != nil {
		t.Errorf("the device was deleted anyway: %v", err)
	}
}

func TestAnAPIKeyCannotDeleteADevice(t *testing.T) {
	c := newConsole(t)
	dev, err := c.devices.Create(context.Background(), c.tenant.String(), "phone", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	f := ask(t, c, wsapi.Hello{APIKey: c.apiKey}, wsapi.TypeDeviceDelete,
		wsapi.DeleteRequest{DeviceID: dev.ID, Confirm: dev.ID})
	wantError(t, f, wsapi.ErrCodeNotAuthorized)

	if _, err := c.devices.Get(context.Background(), c.tenant.String(), dev.ID); err != nil {
		t.Errorf("the device was deleted anyway: %v", err)
	}
}

func TestDeletingADeviceTakesItsArchiveAndSaysHowMuch(t *testing.T) {
	c := newConsole(t)
	token := c.account(t, "owner@acme.test", "owner")
	dev, err := c.devices.Create(context.Background(), c.tenant.String(), "phone", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	c.archive(t, uuid.MustParse(dev.ID), 3)

	f := ask(t, c, wsapi.Hello{Session: token}, wsapi.TypeDeviceDelete,
		wsapi.DeleteRequest{DeviceID: dev.ID, Confirm: dev.ID})
	if f.Type != wsapi.TypeDeviceGone {
		t.Fatalf("frame = %q: %s", f.Type, f.Payload)
	}
	gone := payload[wsapi.DeviceDeleted](t, f)
	if gone.Messages != 3 {
		t.Errorf("reported %d messages, want 3", gone.Messages)
	}

	var left int
	if err := c.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM messages`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Errorf("%d messages survived the device they belonged to", left)
	}
}

func TestStatsCountWhatEachDeviceArchived(t *testing.T) {
	c := newConsole(t)
	token := c.account(t, "owner@acme.test", "owner")
	one, err := c.devices.Create(context.Background(), c.tenant.String(), "one", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	two, err := c.devices.Create(context.Background(), c.tenant.String(), "two", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	c.archive(t, uuid.MustParse(one.ID), 2)
	c.archive(t, uuid.MustParse(two.ID), 5)

	stats := payload[wsapi.DeviceStats](t,
		ask(t, c, wsapi.Hello{Session: token}, wsapi.TypeDevicesStats, nil))

	got := map[string]int64{}
	for _, s := range stats.Stats {
		got[s.DeviceID] = s.Messages
	}
	if got[one.ID] != 2 || got[two.ID] != 5 {
		t.Errorf("messages = %v, want 2 and 5 for %s and %s", got, one.ID, two.ID)
	}
}

func TestGrantingNeedsTheRightGeneration(t *testing.T) {
	c := newConsole(t)
	token := c.account(t, "owner@acme.test", "owner")
	other := c.accountID(t, "reader@acme.test", "member")
	dev := c.deviceWithKey(t, "phone")

	// Epoch 2 when the device seals under 1. Recorded, it would sit in the
	// list looking like access and fail to open on the day somebody needed it.
	f := ask(t, c, wsapi.Hello{Session: token}, wsapi.TypeGrantAdd, wsapi.GrantRequest{
		DeviceID: dev, UserID: other.String(), Epoch: 2, SealedDSK: []byte("sealed"),
	})
	e := wantError(t, f, wsapi.ErrCodeConflict)
	if !strings.Contains(e.Message, "generation") {
		t.Errorf("message does not explain the mismatch: %q", e.Message)
	}
}

func TestGrantingAndRevoking(t *testing.T) {
	c := newConsole(t)
	token := c.account(t, "owner@acme.test", "owner")
	other := c.accountID(t, "reader@acme.test", "member")
	dev := c.deviceWithKey(t, "phone")

	f := ask(t, c, wsapi.Hello{Session: token}, wsapi.TypeGrantAdd, wsapi.GrantRequest{
		DeviceID: dev, UserID: other.String(), Epoch: 1, SealedDSK: []byte("sealed"),
	})
	if f.Type != wsapi.TypeReaders {
		t.Fatalf("frame = %q: %s", f.Type, f.Payload)
	}
	readers := payload[wsapi.Readers](t, f)
	if len(readers.Readers) != 1 || readers.Readers[0].Email != "reader@acme.test" {
		t.Fatalf("readers = %+v", readers.Readers)
	}
	if readers.Readers[0].GrantedBy != "owner@acme.test" {
		t.Errorf("granted_by = %q, want whoever asked", readers.Readers[0].GrantedBy)
	}

	wantError(t, ask(t, c, wsapi.Hello{Session: token}, wsapi.TypeGrantRevoke, wsapi.GrantRevoke{
		DeviceID: dev, UserID: other.String(),
	}), "last_device_reader")
	backup := retainBackupReader(t, c.pool, c.tenant, uuid.MustParse(dev))
	f = ask(t, c, wsapi.Hello{Session: token}, wsapi.TypeGrantRevoke, wsapi.GrantRevoke{
		DeviceID: dev, UserID: other.String(),
	})
	if f.Type != wsapi.TypeReaders {
		t.Fatalf("frame = %q: %s", f.Type, f.Payload)
	}
	if left := payload[wsapi.Readers](t, f); len(left.Readers) != 1 || left.Readers[0].UserID != backup.String() {
		t.Errorf("readers after revoking = %+v", left.Readers)
	}
}

func TestAnAPIKeyCannotGrant(t *testing.T) {
	c := newConsole(t)
	other := c.accountID(t, "reader@acme.test", "member")
	dev := c.deviceWithKey(t, "phone")

	f := ask(t, c, wsapi.Hello{APIKey: c.apiKey}, wsapi.TypeGrantAdd, wsapi.GrantRequest{
		DeviceID: dev, UserID: other.String(), Epoch: 1, SealedDSK: []byte("sealed"),
	})
	wantError(t, f, wsapi.ErrCodeNotAuthorized)
}

func TestGrantingToADeviceWithNoKey(t *testing.T) {
	c := newConsole(t)
	token := c.account(t, "owner@acme.test", "owner")
	other := c.accountID(t, "reader@acme.test", "member")
	dev, err := c.devices.Create(context.Background(), c.tenant.String(), "unpaired", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}

	f := ask(t, c, wsapi.Hello{Session: token}, wsapi.TypeGrantAdd, wsapi.GrantRequest{
		DeviceID: dev.ID, UserID: other.String(), Epoch: 1, SealedDSK: []byte("sealed"),
	})
	wantError(t, f, wsapi.ErrCodeConflict)
}

// accountID creates an account and returns its id.
func (c *console) accountID(t *testing.T, email, role string) uuid.UUID {
	t.Helper()
	user, err := c.users.Create(context.Background(), store.NewUser{
		TenantID: c.tenant, Email: email, Role: role,
		AuthKey: "auth-" + email, KDFSalt: make([]byte, 16),
		KDFParams: store.DefaultKDFParams(),
		PublicKey: make([]byte, 32), WrappedUSK: []byte("wrapped"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return user.ID
}

// deviceWithKey creates a device that has an archive key at epoch 1, the way
// pairing leaves one.
func (c *console) deviceWithKey(t *testing.T, label string) string {
	t.Helper()
	ctx := context.Background()
	dev, err := c.devices.Create(ctx, c.tenant.String(), label, wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.NewKeys(c.pool).CreateArchiveKey(
		ctx, c.tenant, uuid.MustParse(dev.ID), 1, pub); err != nil {
		t.Fatal(err)
	}
	return dev.ID
}

// archive stores n sealed messages for a device, the way ingest does.
func (c *console) archive(t *testing.T, device uuid.UUID, n int) {
	t.Helper()
	messages := store.NewMessages(c.pool)
	for i := range n {
		_, err := messages.Insert(context.Background(), store.InsertMessage{
			UID: uuid.New(), TenantID: c.tenant, DeviceID: device,
			WAID: "wa-" + uuid.New().String(),
			Kind: domain.KindMessage, Type: domain.TypeText,
			Source: domain.SourceLive, TS: time.Now(),
			ChatKey:    "5511999999999@s.whatsapp.net",
			BodySealed: []byte{byte(i)},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// A member reaches a device through a grant. Before this, any account in the
// tenant could read every device's envelope — who talks to whom, when, who
// read what — with no key for any of it.
func TestAMemberWithoutAGrantSeesNothingOfADevice(t *testing.T) {
	c := newConsole(t)
	device := c.deviceWithKey(t, "phone")
	member := wsapi.Hello{Session: c.account(t, "member@acme.test", "member")}

	e := wantError(t, ask(t, c, member, wsapi.TypeChatsList, map[string]string{"device_id": device}),
		wsapi.ErrCodeNotAuthorized)
	if !strings.Contains(e.Message, "grant") {
		t.Errorf("the refusal does not say a grant is what is missing: %q", e.Message)
	}
	// Even device metadata is hidden without an explicit device permission.
	wantError(t, ask(t, c, member, wsapi.TypeDeviceInfo, wsapi.DeviceRef{DeviceID: device}), wsapi.ErrCodeNotAuthorized)
	wantError(t, ask(t, c, member, wsapi.TypeUsersList, nil), wsapi.ErrCodeNotAuthorized)

	// With a grant, the device opens. Administrative roles do not grant content access.
	memberID := c.accountID(t, "granted@acme.test", "member")
	if err := store.NewKeys(c.pool).PutGrant(context.Background(), store.Grant{
		TenantID: c.tenant, DeviceID: uuid.MustParse(device), UserID: memberID,
		Epoch: 1, SealedDSK: []byte("sealed"),
	}, nil); err != nil {
		t.Fatal(err)
	}
	token, _, err := c.users.StartSession(context.Background(), store.User{ID: memberID, TenantID: c.tenant}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if f := ask(t, c, wsapi.Hello{Session: token}, wsapi.TypeChatsList, map[string]string{"device_id": device}); f.Type == wsapi.TypeError {
		t.Fatalf("a granted member was refused: %s", f.Payload)
	}
	admin := wsapi.Hello{Session: c.account(t, "admin@acme.test", "admin")}
	wantError(t, ask(t, c, admin, wsapi.TypeChatsList, map[string]string{"device_id": device}), wsapi.ErrCodeNotAuthorized)
}

// Changing the legacy receipt policy remains an operator action, even though
// neither receipt mode announces this device online.
func TestOnlyAnOperatorCanChangeADevicesPosture(t *testing.T) {
	c := newConsole(t)
	device := c.deviceWithKey(t, "phone")
	flip := map[string]string{"device_id": device, "receipt_mode": "active"}

	token := c.account(t, "owner@acme.test", "owner")
	created := payload[wsapi.APIKeyCreated](t, ask(t, c, wsapi.Hello{Session: token},
		wsapi.TypeKeyCreate, wsapi.APIKeyRequest{Name: "bot", Scope: "send"}))
	wantError(t, ask(t, c, wsapi.Hello{APIKey: created.Key}, wsapi.TypeDeviceMode, flip), wsapi.ErrCodeNotAuthorized)
	wantError(t, ask(t, c, wsapi.Hello{Session: c.account(t, "m@acme.test", "member")}, wsapi.TypeDeviceMode, flip),
		wsapi.ErrCodeNotAuthorized)

	f := ask(t, c, wsapi.Hello{Session: token}, wsapi.TypeDeviceMode, flip)
	if f.Type != wsapi.TypeDeviceDetail {
		t.Fatalf("an owner could not flip the mode: %s %s", f.Type, f.Payload)
	}
	// The full-scope key the command line uses still can.
	if f := ask(t, c, wsapi.Hello{APIKey: c.apiKey}, wsapi.TypeDeviceMode, flip); f.Type != wsapi.TypeDeviceDetail {
		t.Fatalf("a full key could not flip the mode: %s %s", f.Type, f.Payload)
	}
}

func TestPairingIsAnOperatorsAct(t *testing.T) {
	c := newConsole(t)
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	req := wsapi.PairRequest{
		Method: "code", Phone: "+5511999999999", DeviceID: uuid.NewString(),
		ArchivePublicKey: pub.Bytes(),
	}
	wantError(t, ask(t, c, wsapi.Hello{Session: c.account(t, "m@acme.test", "member")}, wsapi.TypePair, req),
		wsapi.ErrCodeNotAuthorized)

	token := c.account(t, "owner@acme.test", "owner")
	created := payload[wsapi.APIKeyCreated](t, ask(t, c, wsapi.Hello{Session: token},
		wsapi.TypeKeyCreate, wsapi.APIKeyRequest{Name: "bot", Scope: "send"}))
	wantError(t, ask(t, c, wsapi.Hello{APIKey: created.Key}, wsapi.TypePair, req), wsapi.ErrCodeNotAuthorized)

	// An owner may pair, but not into an archive nobody can read unless they
	// say so. No registry here, so a request that gets past the checks fails
	// on the pairing itself — which is later than the refusal being tested.
	e := wantError(t, ask(t, c, wsapi.Hello{Session: token}, wsapi.TypePair, req), wsapi.ErrCodeBadRequest)
	if !strings.Contains(e.Message, "orphan") {
		t.Errorf("a pairing with no grants was refused for another reason: %q", e.Message)
	}
	devices, err := c.devices.List(context.Background(), c.tenant.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 0 {
		t.Errorf("a refused pairing left %d device row(s) behind", len(devices))
	}
}

// A service account is how a system reads the archive without anybody
// handing it a device key by hand: a keypair it keeps, a grant sealed to it,
// and a key that acts as it. This walks the whole path the way a third party
// would, including opening the grant with the private half.
func TestAServiceAccountReadsOnlyWhatItWasGranted(t *testing.T) {
	c := newConsole(t)
	ctx := context.Background()
	owner := wsapi.Hello{Session: c.account(t, "owner@acme.test", "owner")}

	// The system's keypair; only the public half reaches the server.
	servicePub, servicePriv, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	service, err := c.users.CreateService(ctx, c.tenant, "erp-sync", servicePub.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	// Two devices; the service is granted one. The grant is sealed the way
	// the console seals it, from a client that holds the device key.
	granted := c.deviceWithKey(t, "granted")
	other := c.deviceWithKey(t, "other")
	_, devicePriv, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	deviceKey, err := devicePriv.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := seal.SealDirect(servicePub, seal.KindDeviceGrant, c.tenant,
		seal.GrantRow(c.tenant, uuid.MustParse(granted), service.ID, 1), 1, deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	f := ask(t, c, owner, wsapi.TypeGrantAdd, wsapi.GrantRequest{
		DeviceID: granted, UserID: service.ID.String(), Epoch: 1, SealedDSK: sealed,
	})
	if f.Type != wsapi.TypeReaders {
		t.Fatalf("grant.add: %s %s", f.Type, f.Payload)
	}

	// A key that acts as the service. Acting as a person is refused.
	wantError(t, ask(t, c, owner, wsapi.TypeKeyCreate, wsapi.APIKeyRequest{
		Name: "nope", Scope: "read", ActsAs: c.accountID(t, "person@acme.test", "member").String(),
	}), wsapi.ErrCodeBadRequest)
	created := payload[wsapi.APIKeyCreated](t, ask(t, c, owner, wsapi.TypeKeyCreate,
		wsapi.APIKeyRequest{Name: "erp", Scope: "read", ActsAs: service.ID.String()}))
	if created.Info.ActsAs != "erp-sync" {
		t.Errorf("acts_as = %q, want the service's name", created.Info.ActsAs)
	}
	asService := wsapi.Hello{APIKey: created.Key}

	// The granted device answers; the other is refused on the grant, not
	// on the tenant — it exists, the account just cannot open it.
	if f := ask(t, c, asService, wsapi.TypeChatsList, map[string]string{"device_id": granted}); f.Type == wsapi.TypeError {
		t.Fatalf("the granted device was refused: %s", f.Payload)
	}
	e := wantError(t, ask(t, c, asService, wsapi.TypeChatsList, map[string]string{"device_id": other}),
		wsapi.ErrCodeNotAuthorized)
	if !strings.Contains(e.Message, "grant") {
		t.Errorf("refusal does not name the grant: %q", e.Message)
	}

	// The grants come back as ciphertext, and open with the private half.
	grants := payload[wsapi.Grants](t, ask(t, c, asService, wsapi.TypeGrantsList, nil))
	if len(grants.Grants) != 1 || grants.Grants[0].DeviceID != granted {
		t.Fatalf("grants = %+v, want the one device", grants.Grants)
	}
	opened, err := seal.OpenDirect(servicePriv, seal.KindDeviceGrant, c.tenant,
		seal.GrantRow(c.tenant, uuid.MustParse(granted), service.ID, 1), grants.Grants[0].SealedDSK)
	if err != nil {
		t.Fatalf("the grant does not open with the service's key: %v", err)
	}
	if string(opened) != string(deviceKey) {
		t.Fatal("the grant opened to something other than the device key")
	}

	// A key acting as nobody holds no grants and, as before, reaches every
	// device's envelope.
	wantError(t, ask(t, c, wsapi.Hello{APIKey: c.apiKey}, wsapi.TypeGrantsList, nil), wsapi.ErrCodeNotAuthorized)
	if f := ask(t, c, wsapi.Hello{APIKey: c.apiKey}, wsapi.TypeChatsList, map[string]string{"device_id": other}); f.Type == wsapi.TypeError {
		t.Fatalf("a plain full key was refused a device: %s", f.Payload)
	}

	// Revoking the grant is revoking the access.
	retainBackupReader(t, c.pool, c.tenant, uuid.MustParse(granted))
	if f := ask(t, c, owner, wsapi.TypeGrantRevoke, wsapi.GrantRevoke{DeviceID: granted, UserID: service.ID.String()}); f.Type != wsapi.TypeReaders {
		t.Fatalf("revocation failed: %s %s", f.Type, f.Payload)
	}
	wantError(t, ask(t, c, asService, wsapi.TypeChatsList, map[string]string{"device_id": granted}),
		wsapi.ErrCodeNotAuthorized)
}
