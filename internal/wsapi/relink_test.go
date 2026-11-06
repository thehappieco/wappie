package wsapi_test

import (
	"context"
	"log/slog"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/relink"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
	"whatserver2/internal/wsapi"
)

// Fictional accounts only.
const (
	relinkPN  = "155501000951"
	relinkLID = "100000000000951"
)

// scriptedPairer hands each started pairing to the test.
type scriptedPairer struct {
	mu      sync.Mutex
	started chan *scriptedPairing
	// busySince, when set, is a pairing of every number in this process.
	busySince time.Time
}

type scriptedPairing struct{ events chan wa.PairEvent }

func (p *scriptedPairing) Events() <-chan wa.PairEvent { return p.events }
func (p *scriptedPairing) Cancel()                     {}

func (p *scriptedPairer) PairingSince(string) (time.Time, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.busySince, !p.busySince.IsZero()
}
func (*scriptedPairer) Holds(string) bool                         { return false }
func (*scriptedPairer) ReleaseStale(context.Context, string) bool { return false }
func (p *scriptedPairer) StartPairing(context.Context, string, string, wa.ReceiptPolicy, wa.PairOptions) (relink.Pairing, error) {
	s := &scriptedPairing{events: make(chan wa.PairEvent, 8)}
	p.started <- s
	return s, nil
}

// relinkConsole is newConsole with a relink service on a scripted pairer,
// and a log that keeps every line.
type relinkConsole struct {
	*console
	pairer *scriptedPairer
	log    *strings.Builder
	logMu  *sync.Mutex
}

type lockedWriter struct {
	mu *sync.Mutex
	b  *strings.Builder
}

func (w lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func newRelinkConsole(t *testing.T) *relinkConsole {
	t.Helper()
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	var tenantID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('acme') RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	keys := store.NewAPIKeys(pool)
	apiKey, err := keys.Issue(ctx, tenantID, "ci")
	if err != nil {
		t.Fatal(err)
	}
	users, devices := store.NewUsers(pool), store.NewDevices(pool)
	rc := &relinkConsole{pairer: &scriptedPairer{started: make(chan *scriptedPairing, 4)}, log: &strings.Builder{}, logMu: &sync.Mutex{}}
	lg := slog.New(slog.NewTextHandler(lockedWriter{rc.logMu, rc.log}, nil))
	srv := httptest.NewServer(wsapi.NewServer(wsapi.Config{
		Keys: keys, Sessions: users, Accounts: users,
		Devices: devices, Messages: store.NewMessages(pool), Keys2: store.NewKeys(pool),
		Relink: &relink.Service{Devices: devices, Pairer: rc.pairer, Log: lg},
		Log:    lg,
	}))
	t.Cleanup(srv.Close)
	rc.console = &console{srv: srv, pool: pool, tenant: uuid.MustParse(tenantID), apiKey: apiKey, devices: devices, users: users, keys: keys}
	return rc
}

// loggedOut is a number its phone logged out, with the owner's key.
func (c *relinkConsole) loggedOut(t *testing.T, owner uuid.UUID) string {
	t.Helper()
	ctx := context.Background()
	dev, err := c.devices.Create(ctx, c.tenant.String(), "Loja", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.devices.SetIdentity(ctx, c.tenant.String(), dev.ID, wa.Identity{
		PN:  types.JID{User: relinkPN, Device: 3, Server: types.DefaultUserServer},
		LID: types.JID{User: relinkLID, Device: 3, Server: types.HiddenUserServer},
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.devices.SetStatus(ctx, c.tenant.String(), dev.ID, wa.StatusLoggedOut, "unlinked (logged out)"); err != nil {
		t.Fatal(err)
	}
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keys := store.NewKeys(c.pool)
	if err := keys.CreateArchiveKey(ctx, c.tenant, uuid.MustParse(dev.ID), 1, pub); err != nil {
		t.Fatal(err)
	}
	if err := keys.PutGrant(ctx, store.Grant{TenantID: c.tenant, DeviceID: uuid.MustParse(dev.ID), UserID: owner, Epoch: 1, SealedDSK: []byte("grant")}, &owner); err != nil {
		t.Fatal(err)
	}
	return dev.ID
}

func (c *relinkConsole) open(t *testing.T, hello wsapi.Hello) *websocket.Conn {
	t.Helper()
	conn := dial(t, c.srv)
	hello.Version = wsapi.Version
	send(t, conn, wsapi.TypeHello, hello)
	if f := read(t, conn); f.Type != wsapi.TypeWelcome {
		t.Fatalf("handshake: %s %s", f.Type, f.Payload)
	}
	return conn
}

func relinkOf(device string) wsapi.PairRequest {
	return wsapi.PairRequest{DeviceID: device, Relink: true, Method: "qr"}
}

// Who may link a number again, refused in this order: a key of any scope
// (never step_up_required, which would read as if it could pass), a member,
// then an admin whose sign-in is older than the step-up window.
func TestRelinkWho(t *testing.T) {
	ctx := context.Background()
	c := newRelinkConsole(t)
	ownerToken := c.account(t, "owner@acme.test", "owner")
	owner, err := c.users.Session(ctx, ownerToken)
	if err != nil {
		t.Fatal(err)
	}
	device := c.loggedOut(t, owner.UserID)

	wantError(t, ask(t, c.console, wsapi.Hello{APIKey: c.apiKey}, wsapi.TypePair, relinkOf(device)), wsapi.ErrCodeNotAuthorized)
	member := c.account(t, "member@acme.test", "member")
	wantError(t, ask(t, c.console, wsapi.Hello{Session: member}, wsapi.TypePair, relinkOf(device)), wsapi.ErrCodeNotAuthorized)

	admin := c.account(t, "admin@acme.test", "admin")
	session, err := c.users.Session(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.pool.Exec(ctx, `UPDATE sessions SET authenticated_at = now() - interval '11 minutes' WHERE id = $1`, session.ID); err != nil {
		t.Fatal(err)
	}
	wantError(t, ask(t, c.console, wsapi.Hello{Session: admin}, wsapi.TypePair, relinkOf(device)), wsapi.ErrCodeStepUpRequired)

	select {
	case <-c.pairer.started:
		t.Fatal("a refused caller started a pairing")
	default:
	}
}

// A relink keeps the number as it is: anything a new number's pairing would
// carry is refused, and so is a typed code.
func TestRelinkRequestShape(t *testing.T) {
	c := newRelinkConsole(t)
	token := c.account(t, "owner@acme.test", "owner")
	device := uuid.NewString()
	for name, req := range map[string]wsapi.PairRequest{
		"by code":    {DeviceID: device, Relink: true, Method: "code"},
		"a phone":    {DeviceID: device, Relink: true, Phone: "155501000000"},
		"a label":    {DeviceID: device, Relink: true, Label: "x"},
		"a key":      {DeviceID: device, Relink: true, ArchivePublicKey: []byte("k")},
		"grants":     {DeviceID: device, Relink: true, Grants: []wsapi.KeyGrant{{UserID: device, SealedDSK: []byte("g")}}},
		"orphan":     {DeviceID: device, Relink: true, Orphan: true},
		"a resume":   {DeviceID: device, Relink: true, Resume: true},
		"a receipts": {DeviceID: device, Relink: true, ReceiptMode: "active"},
		"no uuid":    {DeviceID: "abc", Relink: true},
	} {
		t.Run(name, func(t *testing.T) {
			wantError(t, ask(t, c.console, wsapi.Hello{Session: token}, wsapi.TypePair, req), wsapi.ErrCodeBadRequest)
		})
	}
}

// The frames of a relink carry no phone number, no LID and no account, and
// item_busy carries whole seconds to wait: a refused scan, then a link.
func TestRelinkFramesCarryNoPhone(t *testing.T) {
	ctx := context.Background()
	c := newRelinkConsole(t)
	token := c.account(t, "owner@acme.test", "owner")
	owner, err := c.users.Session(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	device := c.loggedOut(t, owner.UserID)
	var frames []string

	conn := c.open(t, wsapi.Hello{Session: token})
	send(t, conn, wsapi.TypePair, relinkOf(device))
	p := <-c.pairer.started
	p.events <- wa.PairEvent{Kind: wa.PairEventQR, Code: "2@test-ref-not-real", Expires: time.Now().Add(time.Minute)}
	f := read(t, conn)
	if f.Type != wsapi.TypePairQR {
		t.Fatalf("frame %s %s, want the QR", f.Type, f.Payload)
	}
	frames = append(frames, string(f.Payload))
	p.events <- wa.PairEvent{Kind: wa.PairEventError, Err: &wa.OtherAccount{Half: "phone"}}
	close(p.events)
	f = read(t, conn)
	e := wantError(t, f, wsapi.ErrCodeOtherAccount)
	if e.RetryAfter != 0 {
		t.Fatalf("retry_after %d on other_account", e.RetryAfter)
	}
	frames = append(frames, string(f.Payload))

	send(t, conn, wsapi.TypePair, relinkOf(device))
	p = <-c.pairer.started
	p.events <- wa.PairEvent{Kind: wa.PairEventSuccess}
	close(p.events)
	f = read(t, conn)
	if f.Type != wsapi.TypePairSuccess {
		t.Fatalf("frame %s %s, want success", f.Type, f.Payload)
	}
	frames = append(frames, string(f.Payload))

	c.logMu.Lock()
	logged := c.log.String()
	c.logMu.Unlock()
	for _, text := range append(frames, logged) {
		if strings.Contains(text, relinkPN) || strings.Contains(text, relinkLID) {
			t.Fatalf("a frame or a log line names the account: %s", text)
		}
	}
	if strings.Contains(logged, "test-ref-not-real") {
		t.Fatal("a QR reached the log")
	}
	if !strings.Contains(logged, "relink refused") || !strings.Contains(logged, "code=other_account") || !strings.Contains(logged, "half=phone") {
		t.Fatalf("no refusal line with its code and half: %s", logged)
	}
}

// A second relink of a number while this process pairs it is item_busy,
// with the seconds left in WhatsApp's window, at least 1.
func TestRelinkItemBusyRetryAfter(t *testing.T) {
	ctx := context.Background()
	c := newRelinkConsole(t)
	token := c.account(t, "owner@acme.test", "owner")
	owner, err := c.users.Session(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	device := c.loggedOut(t, owner.UserID)
	for _, since := range []time.Duration{time.Second, wa.PairWindow - 300*time.Millisecond, wa.PairWindow + time.Minute} {
		c.pairer.mu.Lock()
		c.pairer.busySince = time.Now().Add(-since)
		c.pairer.mu.Unlock()
		e := wantError(t, ask(t, c.console, wsapi.Hello{Session: token}, wsapi.TypePair, relinkOf(device)), wsapi.ErrCodeItemBusy)
		if e.RetryAfter < 1 || e.RetryAfter > int(wa.PairWindow.Seconds()) {
			t.Fatalf("paired for %s: retry_after %d, want 1 to 160", since, e.RetryAfter)
		}
	}
}

// A stop keeps a logged-out number logged out, in the row, the answer and
// the broadcast: it stays a number to link again.
func TestPauseKeepsLoggedOut(t *testing.T) {
	ctx := context.Background()
	c := newRelinkConsole(t)
	token := c.account(t, "owner@acme.test", "owner")
	owner, err := c.users.Session(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	device := c.loggedOut(t, owner.UserID)
	f := ask(t, c.console, wsapi.Hello{Session: token}, wsapi.TypeDeviceStop, wsapi.DeviceRef{DeviceID: device})
	if f.Type != wsapi.TypeDeviceStatus {
		t.Fatalf("frame %s %s", f.Type, f.Payload)
	}
	if got := payload[wsapi.DeviceStatus](t, f); got.Status != string(wa.StatusLoggedOut) {
		t.Fatalf("the stop answered %q", got.Status)
	}
	d, err := c.devices.Get(ctx, c.tenant.String(), device)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Paused || d.Status != wa.StatusLoggedOut {
		t.Fatalf("after the stop paused=%v status=%s", d.Paused, d.Status)
	}
}
