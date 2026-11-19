package relink_test

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	waLog "go.mau.fi/whatsmeow/util/log"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/relink"
	wstore "whatserver2/internal/store"
	"whatserver2/internal/wa"
	"whatserver2/internal/wa/fakewa"
)

// Fictional accounts only.
const (
	ownPN  = "155501000901"
	ownLID = "100000000000901"
)

type world struct {
	pool    *pgxpool.Pool
	tenant  uuid.UUID
	owner   uuid.UUID
	devices *wstore.Devices
	users   *wstore.Users
	keys    *wstore.Keys
}

func newWorld(t *testing.T) *world {
	t.Helper()
	ctx := context.Background()
	pool := pgtest.Fresh(t, migrate.Run)
	w := &world{pool: pool, devices: wstore.NewDevices(pool), users: wstore.NewUsers(pool), keys: wstore.NewKeys(pool)}
	if err := pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('acme') RETURNING id`).Scan(&w.tenant); err != nil {
		t.Fatal(err)
	}
	w.owner = w.person(t, "owner")
	if _, err := pool.Exec(ctx, `CREATE TABLE whatsmeow_device (jid text PRIMARY KEY, registration_id bigint NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *world) person(t *testing.T, role string) uuid.UUID {
	t.Helper()
	u, err := w.users.Create(context.Background(), wstore.NewUser{TenantID: w.tenant, Email: role + "-" + uuid.NewString()[:8] + "@acme.test",
		Role: role, AuthKey: "test", KDFSalt: make([]byte, 16), KDFParams: wstore.DefaultKDFParams(), PublicKey: make([]byte, 32), WrappedUSK: []byte("wrapped")})
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}

// number is a number its phone logged out, with a key the owner holds.
func (w *world) number(t *testing.T, pn, lid string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	dev, err := w.devices.Create(ctx, w.tenant.String(), "Loja", wa.ModeActive)
	if err != nil {
		t.Fatal(err)
	}
	id := wa.Identity{}
	if pn != "" {
		id.PN = types.JID{User: pn, Device: 3, Server: types.DefaultUserServer}
	}
	if lid != "" {
		id.LID = types.JID{User: lid, Device: 3, Server: types.HiddenUserServer}
	}
	if id.Known() {
		if err := w.devices.SetIdentity(ctx, w.tenant.String(), dev.ID, id); err != nil {
			t.Fatal(err)
		}
	}
	w.status(t, uuid.MustParse(dev.ID), wa.StatusLoggedOut)
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	device := uuid.MustParse(dev.ID)
	if err := w.keys.CreateArchiveKey(ctx, w.tenant, device, 1, pub); err != nil {
		t.Fatal(err)
	}
	if err := w.keys.PutGrant(ctx, wstore.Grant{TenantID: w.tenant, DeviceID: device, UserID: w.owner, Epoch: 1, SealedDSK: []byte("grant"), Fingerprint: grantFingerprint(t, w.keys, w.tenant, device, 1)}, &w.owner); err != nil {
		t.Fatal(err)
	}
	return device
}

func (w *world) status(t *testing.T, device uuid.UUID, s wa.Status) {
	t.Helper()
	if err := w.devices.SetStatus(context.Background(), w.tenant.String(), device.String(), s, "test"); err != nil {
		t.Fatal(err)
	}
}

func (w *world) exec(t *testing.T, query string, args ...any) {
	t.Helper()
	ctx := context.Background()
	if err := pg.InTenantTx(ctx, w.pool, w.tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, query, args...)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// fakePairer is a registry whose pairings a test ends by hand.
type fakePairer struct {
	mu       sync.Mutex
	since    map[string]time.Time
	held     map[string]bool
	stale    map[string]bool
	startErr error
	started  []*fakePairing
}

type fakePairing struct {
	events   chan wa.PairEvent
	cancels  int
	cancelMu sync.Mutex
}

func (p *fakePairing) Events() <-chan wa.PairEvent { return p.events }
func (p *fakePairing) Cancel() {
	p.cancelMu.Lock()
	p.cancels++
	p.cancelMu.Unlock()
}

func (f *fakePairer) PairingSince(id string) (time.Time, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.since[id]
	return t, ok
}
func (f *fakePairer) Holds(id string) bool { f.mu.Lock(); defer f.mu.Unlock(); return f.held[id] }
func (f *fakePairer) ReleaseStale(_ context.Context, id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stale[id] {
		delete(f.held, id)
		return true
	}
	return false
}
func (f *fakePairer) StartPairing(context.Context, string, string, wa.ReceiptPolicy, wa.PairOptions) (relink.Pairing, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.startErr != nil {
		return nil, f.startErr
	}
	p := &fakePairing{events: make(chan wa.PairEvent, 8)}
	f.started = append(f.started, p)
	return p, nil
}

func code(t *testing.T, err error) *relink.Refusal {
	t.Helper()
	var r *relink.Refusal
	if !errors.As(err, &r) {
		t.Fatalf("error %v, want a refusal", err)
	}
	return r
}

// The checks before any QR, one case each, in spec 14.13's order.
func TestCheckTable(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	pairer := &fakePairer{since: map[string]time.Time{}, held: map[string]bool{}, stale: map[string]bool{}}
	svc := &relink.Service{Devices: w.devices, Pairer: pairer, Log: slog.New(slog.DiscardHandler)}

	device := w.number(t, ownPN, ownLID)
	target, err := svc.Check(ctx, w.tenant, device)
	if err != nil {
		t.Fatalf("a logged-out number = %v", err)
	}
	if target.Expect.PN.User != ownPN || target.Expect.LID.User != ownLID || target.Expect.PN.Device != 0 || target.ReceiptMode != wa.ModeActive {
		t.Fatalf("target %+v", target)
	}

	if _, err := svc.Check(ctx, w.tenant, uuid.New()); !errors.Is(err, wstore.ErrNotFound) {
		t.Fatalf("no such number = %v", err)
	}

	pairer.since[device.String()] = time.Now().Add(-100 * time.Second)
	if r := code(t, func() error { _, err := svc.Check(ctx, w.tenant, device); return err }()); r.Code != relink.CodeItemBusy ||
		r.RetryAfter < time.Second || r.RetryAfter > wa.PairWindow {
		t.Fatalf("a pairing here = %+v", r)
	}
	delete(pairer.since, device.String())
	pairer.held[device.String()] = true
	if r := code(t, func() error { _, err := svc.Check(ctx, w.tenant, device); return err }()); r.Code != relink.CodeItemBusy || r.RetryAfter != wa.PairWindow {
		t.Fatalf("a hold here = %+v", r)
	}
	// A stopped, logged-out hold is released and the relink goes on.
	pairer.stale[device.String()] = true
	if _, err := svc.Check(ctx, w.tenant, device); err != nil {
		t.Fatalf("a stale hold = %v", err)
	}

	w.exec(t, `UPDATE devices SET paused = true, pause_cause = 'move' WHERE id = $1`, device)
	if r := code(t, func() error { _, err := svc.Check(ctx, w.tenant, device); return err }()); r.Code != relink.CodeItemBusy {
		t.Fatalf("a move's pause = %+v", r)
	}
	w.exec(t, `UPDATE devices SET pause_cause = 'person' WHERE id = $1`, device)
	if _, err := svc.Check(ctx, w.tenant, device); err != nil {
		t.Fatalf("a person's pause = %v", err)
	}

	// A number held here and online is not one to link again, not busy.
	pairer.held[device.String()] = true
	pairer.stale[device.String()] = false
	for _, s := range []wa.Status{wa.StatusOnline, wa.StatusOffline, wa.StatusNew, wa.StatusPairing, wa.StatusBanned} {
		w.status(t, device, s)
		if r := code(t, func() error { _, err := svc.Check(ctx, w.tenant, device); return err }()); r.Code != relink.CodeStateChanged {
			t.Fatalf("status %s = %+v", s, r)
		}
	}
	w.status(t, device, wa.StatusLoggedOut)
	delete(pairer.held, device.String())

	half := w.number(t, "155501000902", "")
	if r := code(t, func() error { _, err := svc.Check(ctx, w.tenant, half); return err }()); r.Code != relink.CodeReadOnly {
		t.Fatalf("half an identity = %+v", r)
	}
	svc.LIDs = phoneBook{lid: types.NewJID("100000000000902", types.HiddenUserServer)}
	if target, err := svc.Check(ctx, w.tenant, half); err != nil || !target.FromMap {
		t.Fatalf("half an identity filled from the map = %+v, %v", target, err)
	}

	w.exec(t, `DELETE FROM device_key_grants WHERE device_id = $1`, device)
	if r := code(t, func() error { _, err := svc.Check(ctx, w.tenant, device); return err }()); r.Code != relink.CodeNoReader {
		t.Fatalf("nobody holds the key = %+v", r)
	}

	twin := w.number(t, "155501000903", "100000000000903")
	other, err := w.devices.Create(ctx, w.tenant.String(), "twin", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.devices.SetIdentity(ctx, w.tenant.String(), other.ID, wa.Identity{PN: types.JID{User: "155501000903", Device: 5, Server: types.DefaultUserServer}}); err != nil {
		t.Fatal(err)
	}
	w.status(t, uuid.MustParse(other.ID), wa.StatusOnline)
	if r := code(t, func() error { _, err := svc.Check(ctx, w.tenant, twin); return err }()); r.Code != relink.CodeNumberHeld {
		t.Fatalf("the account linked as another number = %+v", r)
	}
}

type phoneBook struct{ pn, lid types.JID }

func (b phoneBook) PhoneFor(context.Context, types.JID) (types.JID, bool) {
	return b.pn, !b.pn.IsEmpty()
}
func (b phoneBook) LIDFor(context.Context, types.JID) (types.JID, bool) {
	return b.lid, !b.lid.IsEmpty()
}

// A pairing that did not link is named by the number as it is now: a pause,
// a deletion or a storage stop that cancelled it is the reason.
func TestEndNamesTheCause(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		change func(t *testing.T, w *world, device uuid.UUID)
		end    error
		want   string
	}{
		"the window closed": {end: wa.ErrLinkTimeout, want: relink.CodeLinkTimeout},
		"the link failed":   {end: wa.ErrLinkFailed, want: relink.CodeConnectFailed},
		"another account":   {end: &wa.OtherAccount{Half: "lid"}, want: relink.CodeOtherAccount},
		"paused meanwhile": {change: func(t *testing.T, w *world, device uuid.UUID) {
			if _, err := w.devices.Pause(ctx, w.tenant, device, wstore.PauseActor{User: w.owner}); err != nil {
				t.Fatal(err)
			}
		}, end: wa.ErrLinkFailed, want: relink.CodeStateChanged},
		"deleted meanwhile": {change: func(t *testing.T, w *world, device uuid.UUID) {
			if _, err := w.devices.Quarantine(context.Background(), w.tenant, w.owner, device, []uuid.UUID{w.owner}); err != nil {
				t.Fatal(err)
			}
		}, end: wa.ErrLinkFailed, want: relink.CodeStateChanged},
		"storage stopped": {change: func(t *testing.T, w *world, _ uuid.UUID) {
			if _, err := w.pool.Exec(context.Background(), `UPDATE tenants SET storage_paused_at = now() WHERE id = $1`, w.tenant); err != nil {
				t.Fatal(err)
			}
		}, end: wa.ErrLinkFailed, want: relink.CodeStoragePaused},
		"the attach found it held": {end: wstore.ErrRelinkNumberHeld, want: relink.CodeNumberHeld},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			w := newWorld(t)
			pairer := &fakePairer{}
			svc := &relink.Service{Devices: w.devices, Pairer: pairer, Log: slog.New(slog.DiscardHandler)}
			device := w.number(t, ownPN, ownLID)
			target, err := svc.Check(ctx, w.tenant, device)
			if err != nil {
				t.Fatal(err)
			}
			sess, err := svc.Start(ctx, target, relink.Actor{Kind: "person", ID: w.owner})
			if err != nil {
				t.Fatal(err)
			}
			if tc.change != nil {
				tc.change(t, w, device)
			}
			p := pairer.started[0]
			p.events <- wa.PairEvent{Kind: wa.PairEventError, Err: tc.end}
			close(p.events)
			for range sess.Events() {
			}
			if r := code(t, sess.Result()); r.Code != tc.want {
				t.Fatalf("end %+v, want %s", r, tc.want)
			}
		})
	}
}

// sessionRows is whatsmeow's session store as the attach reads it: a fake
// that writes the session row the real one would.
type sessionRows struct {
	pool *pgxpool.Pool
	mu   sync.Mutex
	puts int
}

func (c *sessionRows) PutDevice(ctx context.Context, d *store.Device) error {
	c.mu.Lock()
	c.puts++
	c.mu.Unlock()
	_, err := c.pool.Exec(ctx, `INSERT INTO whatsmeow_device (jid, registration_id) VALUES ($1, 1) ON CONFLICT DO NOTHING`, d.ID.String())
	return err
}
func (c *sessionRows) DeleteDevice(ctx context.Context, d *store.Device) error {
	_, err := c.pool.Exec(ctx, `DELETE FROM whatsmeow_device WHERE jid = $1`, d.ID.String())
	return err
}

type registryRig struct {
	w     *world
	svc   *relink.Service
	r     *wa.Registry
	fake  *fakewa.Client
	inner *sessionRows
	mu    sync.Mutex
	ds    *store.Device
}

func newRegistryRig(t *testing.T) *registryRig {
	t.Helper()
	rig := &registryRig{w: newWorld(t), fake: fakewa.New()}
	rig.inner = &sessionRows{pool: rig.w.pool}
	r, err := wa.NewRegistry(wa.RegistryConfig{
		Container: &sqlstore.Container{}, Store: rig.w.devices, Log: slog.New(slog.DiscardHandler),
		NewPairingDevice: func() *store.Device { return &store.Device{Container: rig.inner} },
		NewPairingClient: func(ds *store.Device, _ waLog.Logger) wa.Client {
			rig.mu.Lock()
			rig.ds = ds
			rig.mu.Unlock()
			return rig.fake
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.StopAll(context.Background()) })
	rig.r = r
	rig.svc = &relink.Service{Devices: rig.w.devices, Pairer: relink.FromRegistry(r), Log: slog.New(slog.DiscardHandler)}
	return rig
}

func (rig *registryRig) scan(t *testing.T, pn, lid types.JID) error {
	t.Helper()
	rig.mu.Lock()
	ds := rig.ds
	rig.mu.Unlock()
	ds.ID, ds.LID = &pn, lid
	return ds.Save(context.Background())
}

func (rig *registryRig) row(t *testing.T, device uuid.UUID) wstore.RelinkRow {
	t.Helper()
	row, err := rig.w.devices.RelinkRow(context.Background(), rig.w.tenant, device)
	if err != nil {
		t.Fatal(err)
	}
	return row
}

func drain(t *testing.T, sess *relink.Session) []wa.PairEvent {
	t.Helper()
	var out []wa.PairEvent
	done := time.After(10 * time.Second)
	for {
		select {
		case e, ok := <-sess.Events():
			if !ok {
				return out
			}
			out = append(out, e)
		case <-done:
			t.Fatal("the relink did not end")
		}
	}
}

// Through the real registry, with whatsmeow's part played on the device the
// pairing built: the number's own account lands in the same row, which
// names the new link and keeps its id, key, epoch, grants and receipt mode;
// another account is refused and changes nothing; and a second relink of
// the number while the first runs is item_busy.
func TestRelinkThroughTheRegistry(t *testing.T) {
	t.Run("the number's own account", func(t *testing.T) {
		ctx := context.Background()
		rig := newRegistryRig(t)
		device := rig.w.number(t, ownPN, ownLID)
		before := rig.row(t, device)
		target, err := rig.svc.Check(ctx, rig.w.tenant, device)
		if err != nil {
			t.Fatal(err)
		}
		sess, err := rig.svc.Start(ctx, target, relink.Actor{Kind: "person", ID: rig.w.owner})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rig.svc.Check(ctx, rig.w.tenant, device); code(t, err).Code != relink.CodeItemBusy {
			t.Fatalf("a second relink while the first runs = %v", err)
		}
		rig.fake.PushQR(whatsmeow.QRChannelItem{Event: whatsmeow.QRChannelEventCode, Code: "2@test-ref-not-real", Timeout: time.Minute})
		newPN := types.JID{User: ownPN, Device: 12, Server: types.DefaultUserServer}
		newLID := types.JID{User: ownLID, Device: 12, Server: types.HiddenUserServer}
		if err := rig.scan(t, newPN, newLID); err != nil {
			t.Fatal(err)
		}
		if row := rig.row(t, device); row.Status != wa.StatusLoggedOut || row.Identity.PN != before.Identity.PN {
			t.Fatalf("the row changed before the attach: %+v", row)
		}
		rig.fake.Emit(&events.ManualLoginReconnect{})
		rig.fake.PushQR(whatsmeow.QRChannelSuccess)
		got := drain(t, sess)
		if len(got) != 1 || got[0].Kind != wa.PairEventQR {
			t.Fatalf("events %+v, want the one QR", got)
		}
		if err := sess.Result(); err != nil {
			t.Fatalf("result %v", err)
		}
		after := rig.row(t, device)
		if after.ID != before.ID || after.Epoch != before.Epoch || after.ReceiptMode != before.ReceiptMode ||
			after.Identity.PN != newPN || after.Identity.LID != newLID || after.Status != wa.StatusOffline {
			t.Fatalf("after the relink %+v, before %+v", after, before)
		}
		if held, err := rig.w.devices.KeyHeld(ctx, rig.w.tenant, device); err != nil || !held {
			t.Fatalf("the owner no longer holds the key: %v %v", held, err)
		}
		dev, ok := rig.r.Get(device.String())
		if !ok || dev.Policy().Mode != wa.ModeActive {
			t.Fatal("the relinked number is not held with its own receipt mode")
		}
		rig.fake.Emit(&events.Connected{})
		if row := rig.row(t, device); row.Status != wa.StatusOnline {
			t.Fatalf("status after connecting %s", row.Status)
		}
	})

	t.Run("another account", func(t *testing.T) {
		ctx := context.Background()
		rig := newRegistryRig(t)
		device := rig.w.number(t, ownPN, ownLID)
		before := rig.row(t, device)
		target, err := rig.svc.Check(ctx, rig.w.tenant, device)
		if err != nil {
			t.Fatal(err)
		}
		sess, err := rig.svc.Start(ctx, target, relink.Actor{Kind: "person", ID: rig.w.owner})
		if err != nil {
			t.Fatal(err)
		}
		refused := rig.scan(t, types.JID{User: "155501000999", Device: 12, Server: types.DefaultUserServer},
			types.JID{User: "100000000000999", Device: 12, Server: types.HiddenUserServer})
		rig.fake.PushQR(whatsmeow.QRChannelItem{Event: whatsmeow.QRChannelEventError, Error: refused})
		drain(t, sess)
		if r := code(t, sess.Result()); r.Code != relink.CodeOtherAccount || r.Half != "phone" {
			t.Fatalf("result %+v", r)
		}
		if after := rig.row(t, device); after != before {
			t.Fatalf("a refused scan changed the row: %+v", after)
		}
		rig.inner.mu.Lock()
		puts := rig.inner.puts
		rig.inner.mu.Unlock()
		if puts != 0 {
			t.Fatalf("the session store got %d writes", puts)
		}
		if rig.r.Holds(device.String()) {
			t.Fatal("the refused pairing still holds the number")
		}
	})
}
