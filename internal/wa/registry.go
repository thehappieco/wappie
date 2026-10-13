package wa

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	// Registers the "pgx" driver with database/sql. whatsmeow's session store
	// is built on database/sql rather than pgx directly, so it needs a driver
	// registered under a name it recognises; dbutil.ParseDialect maps "pgx" to
	// Postgres. Using pgx here rather than lib/pq keeps the whole server on one
	// driver instead of two with different quirks.
	_ "github.com/jackc/pgx/v5/stdlib"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
	waLog "go.mau.fi/whatsmeow/util/log"
)

// Locker guards a device against being supervised by two processes at once.
//
// An interface so internal/wa stays free of any database dependency; the
// Postgres advisory-lock implementation lives in internal/pg. A nil Locker
// means single-instance operation and no locking.
type Locker interface {
	// TryLock returns ok=false when another process already holds key. The
	// returned release function is safe to call once.
	TryLock(ctx context.Context, key string) (release func(), ok bool, err error)
}

// RegistryConfig configures a Registry.
type RegistryConfig struct {
	// LinkedDeviceName identifies new links on the phone. It defaults to whappie;
	// managed hosting sets whappie cloud. The name is fixed for this process.
	LinkedDeviceName string
	// CheckStart enforces installation storage policy before connecting a device.
	CheckStart func(context.Context, string) error
	Container  *sqlstore.Container
	Store      Store
	Sink       Sink
	Locker     Locker
	Log        *slog.Logger
	// WireLog passes whatsmeow's debug output — every protocol node, which
	// is every message in the clear — into the log. Development only; the
	// configuration loader refuses it in prod.
	WireLog bool

	// OnStatus is forwarded to every supervised device.
	OnStatus func(tenantID, deviceID string, status Status, reason string)
	// OnClient installs optional protocol handlers before the first Connect.
	// Its cleanup runs before disconnecting and releasing the device lock.
	OnClient func(tenantID, deviceID string, client *whatsmeow.Client) func()
	// NewClient builds the client for a stored session. Nil is whatsmeow's
	// own client with this server's client policy; a test passes a fake.
	NewClient func(ds *store.Device, log waLog.Logger) Client
}

// Registry owns every supervised device in this process.
//
// The whatsmeow session store is shared: one sqlstore.Container backs all
// devices, which is what lets a restart resume existing sessions instead of
// forcing everyone to pair again. That container holds the Signal keys, and it
// is necessarily readable by this process — the honest limit of the sealed
// archive, documented in the README.
type Registry struct {
	cfg RegistryConfig
	log *slog.Logger

	mu      sync.RWMutex
	devices map[string]*entry
	// unlinking counts the deletions logging a device out in this process
	// (BeginUnlink): the supervisor and the deletion's notification leave
	// their client alone, since the logout runs on it and then stops it.
	unlinking map[string]int
	// loadSession is the session store's lookup, apart so a test of Unlink
	// needs no database.
	loadSession func(ctx context.Context, jid types.JID) (*store.Device, error)
}

type entry struct {
	device     *Device
	release    func()
	stopClient func()
}

// waLogger picks the adapter the configuration allows.
func (r *Registry) waLogger(module string) waLog.Logger {
	if r.cfg.WireLog {
		return NewWireLogger(r.log, module)
	}
	return NewWALogger(r.log, module)
}

// NewRegistry builds a registry.
func NewRegistry(cfg RegistryConfig) (*Registry, error) {
	if cfg.Container == nil {
		return nil, errors.New("wa: registry needs a whatsmeow container")
	}
	if err := configureLinkedDeviceName(cfg.LinkedDeviceName); err != nil {
		return nil, err
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Registry{cfg: cfg, log: cfg.Log, devices: map[string]*entry{}, unlinking: map[string]int{},
		loadSession: cfg.Container.GetDevice}, nil
}

// newClient builds the client for a stored session.
func (r *Registry) newClient(ds *store.Device, module string) Client {
	if r.cfg.NewClient != nil {
		return r.cfg.NewClient(ds, r.waLogger(module))
	}
	client := whatsmeow.NewClient(ds, r.waLogger(module))
	applyClientPolicy(client)
	return client
}

// OpenContainer connects whatsmeow's session store.
//
// It manages its own connection pool rather than sharing one of ours. That is
// deliberate: whatsmeow owns the schema of its whatsmeow_* tables and runs its
// own migrations against them, and entangling that with our migration runner
// would make two systems responsible for one database's shape.
func OpenContainer(ctx context.Context, dsn string, lg *slog.Logger) (*sqlstore.Container, error) {
	c, err := sqlstore.New(ctx, "pgx", dsn, NewWALogger(lg, "wastore"))
	if err != nil {
		return nil, fmt.Errorf("wa: open session store: %w", err)
	}
	return c, nil
}

// ErrAlreadyRunning is returned when a device is supervised elsewhere.
var ErrAlreadyRunning = errors.New("wa: device is already supervised, possibly by another instance")

// StartNew begins supervising a device that has never been paired.
//
// The whatsmeow device is created with no JID; it acquires one when pairing
// completes. Nothing is written to our devices table here — the caller already
// created that row and owns its lifetime, so an abandoned pairing leaves a row
// in status "new" rather than a half-created device nobody can account for.
func (r *Registry) StartNew(ctx context.Context, tenantID, deviceID string, policy ReceiptPolicy) (*Device, error) {
	return r.start(ctx, tenantID, deviceID, policy, r.cfg.Container.NewDevice())
}

// ErrNoSession means the WhatsApp session for a device is gone from the store,
// so it has to be paired again. Distinct from a transient failure, because the
// remedy is different: no amount of retrying brings a deleted session back.
var ErrNoSession = errors.New("wa: no stored session; the device must be paired again")

// StartExisting resumes a paired device.
//
// The candidates are tried in order. A device row carries both a LID and a
// phone number and either may be absent, while whatsmeow's session store is
// keyed by whichever JID the session was established under — so the caller
// passes both and lets this find the one that resolves.
func (r *Registry) StartExisting(ctx context.Context, tenantID, deviceID string,
	policy ReceiptPolicy, candidates ...types.JID) (*Device, error) {
	var tried []string
	for _, jid := range candidates {
		if jid.IsEmpty() {
			continue
		}
		tried = append(tried, jid.String())
		ds, err := r.cfg.Container.GetDevice(ctx, jid)
		if err != nil {
			return nil, fmt.Errorf("wa: load session for %s: %w", jid, err)
		}
		if ds != nil {
			return r.start(ctx, tenantID, deviceID, policy, ds)
		}
	}
	if len(tried) == 0 {
		return nil, fmt.Errorf("%w: device has no identity", ErrNoSession)
	}
	return nil, fmt.Errorf("%w (tried %s)", ErrNoSession, strings.Join(tried, ", "))
}

// start builds a whatsmeow client for an existing session and registers it.
//
// The bookkeeping lives in adopt (registry_adopt path in pairing.go) rather
// than being written twice: the pairing flow has to construct its own client so
// it can call GetQRChannel before Connect, and duplicating the locking and
// slot-reservation logic between the two is how the v1 server ended up with
// four pairs of divergent copies of the same thing.
func (r *Registry) start(ctx context.Context, tenantID, deviceID string, policy ReceiptPolicy, ds *store.Device) (*Device, error) {
	client := r.newClient(ds, "device/"+shortID(deviceID))

	dev, err := r.adopt(ctx, tenantID, deviceID, policy, client)
	if err != nil {
		return nil, err
	}
	if err := dev.Start(ctx); err != nil {
		r.Stop(context.WithoutCancel(ctx), deviceID)
		return nil, err
	}
	return dev, nil
}

// applyClientPolicy sets the whatsmeow options this server depends on.
//
// The two false assignments are load-bearing and must stay false. whatsmeow can
// persist *decrypted* message protobufs — inbound in whatsmeow_event_buffer and
// outbound in whatsmeow_retry_buffer, the latter retained for at least twelve
// hours. Either one would put plaintext on disk and quietly break the promise
// that the server cannot read its own archive. They default to false; setting
// them explicitly makes the requirement visible at the point it matters, and
// TestPlaintextBuffersStayOff enforces it.
//
// The cost of UseRetryMessageStore being off: a retry receipt arriving after a
// process restart cannot be answered, so that one outbound message is lost for
// that recipient. Retry receipts are rare and the window is minutes. Accepted.
func applyClientPolicy(c *whatsmeow.Client) {
	c.EnableDecryptedEventBuffer = false
	c.UseRetryMessageStore = false

	// Without this, app state events are not emitted during a full sync and
	// the contacts table never gets written — the exact failure the v1 server
	// shipped with, where contacts was created, queried, and always empty.
	c.EmitAppStateEventsOnFullSync = true
}

// Get returns a supervised device.
func (r *Registry) Get(deviceID string) (*Device, bool) {
	// A server built without a registry supervises nothing — a read-only
	// deployment, or a test — and answers "not running" rather than panicking.
	if r == nil {
		return nil, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.devices[deviceID]
	if !ok || e.device == nil {
		return nil, false
	}
	return e.device, true
}

// All returns every device this process is supervising.
//
// A snapshot: the slice is the caller's and the registry may change underneath
// it. Callers iterate to do work per device, and a device that stops mid-loop
// simply fails the next call rather than corrupting anything.
func (r *Registry) All() []*Device {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Device, 0, len(r.devices))
	for _, e := range r.devices {
		if e.device != nil {
			out = append(out, e.device)
		}
	}
	return out
}

// Stop stops one device and releases its lock.
func (r *Registry) Stop(ctx context.Context, deviceID string) {
	r.mu.Lock()
	e, ok := r.devices[deviceID]
	delete(r.devices, deviceID)
	r.mu.Unlock()
	if !ok {
		return
	}
	if e.stopClient != nil {
		e.stopClient()
	}
	if e.device != nil {
		e.device.Stop(ctx)
	}
	if e.release != nil {
		e.release()
	}
}

// StopAll stops every device. Used on shutdown.
func (r *Registry) StopAll(ctx context.Context) {
	r.mu.Lock()
	ids := make([]string, 0, len(r.devices))
	for id := range r.devices {
		ids = append(ids, id)
	}
	r.mu.Unlock()

	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Stop(ctx, id)
		}()
	}
	wg.Wait()
}

// Running returns the ids of every supervised device.
func (r *Registry) Running() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.devices))
	for id := range r.devices {
		out = append(out, id)
	}
	return out
}

// HeldDevice is one entry this process holds, for the supervisor's release.
type HeldDevice struct {
	ID, TenantID string
	// Reserved is a reservation with no device yet: a start or a pairing
	// in progress, or a logout's.
	Reserved bool
	// Unlinking is a device a deletion is logging out here (BeginUnlink).
	Unlinking bool
}

// Held returns every entry this process holds. A snapshot, like Running.
func (r *Registry) Held() []HeldDevice {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]HeldDevice, 0, len(r.devices))
	for id, e := range r.devices {
		held := HeldDevice{ID: id, Reserved: e.device == nil, Unlinking: r.unlinking[id] > 0}
		if e.device != nil {
			held.TenantID = e.device.TenantID()
		}
		out = append(out, held)
	}
	return out
}

// BeginUnlink marks a device whose deletion's logout is about to run in this
// process, from before the deletion commits until the logout and the stop
// that follows it are done: neither the supervisor's release nor the
// deletion's own notification stops its client in between. end clears the
// mark, and is safe to call more than once.
func (r *Registry) BeginUnlink(deviceID string) (end func()) {
	if r == nil {
		return func() {}
	}
	r.mu.Lock()
	r.unlinking[deviceID]++
	r.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			r.mu.Lock()
			if r.unlinking[deviceID]--; r.unlinking[deviceID] <= 0 {
				delete(r.unlinking, deviceID)
			}
			r.mu.Unlock()
		})
	}
}

// Unlinking reports whether a deletion is logging the device out here.
func (r *Registry) Unlinking(deviceID string) bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.unlinking[deviceID] > 0
}

// loginWait bounds how long a logout waits for its client to be logged in
// before it asks anyway.
const loginWait = 5 * time.Second

// Unlink logs a deleted number's session out of WhatsApp, which cannot be
// undone: the phone drops this server from its linked devices.
//
// When this process holds the number, the logout runs on its running client,
// which already holds the device lock, once that client is logged in again
// (a client between reconnects would fail the logout at once). Otherwise
// Unlink loads the session, takes the device lock (ErrAlreadyRunning while
// another process or a recovery holds it), and connects a client of its own
// with no sink and no handlers, which captures nothing, so it does not ask
// CheckStart: a workspace whose storage is paused can still be logged out.
//
// recheck runs with the lock held, right before WhatsApp is asked, and an
// error from it aborts with no call: it is the deletion's re-read of the row,
// so no logout ever runs on a number an owner recovered meanwhile. record
// runs with the lock still held, once WhatsApp was asked or the session
// turned out to be gone (ErrNoSession), with what came of it: the caller
// writes what the logout achieved before a recovery can take the lock. It is
// not called when nothing was asked. The caller stops the running client
// afterwards, which releases its lock.
//
// Errors name the device, never the session's JID, which is the phone
// number.
func (r *Registry) Unlink(ctx context.Context, tenantID, deviceID string, jid types.JID,
	recheck func(context.Context) error, record func(context.Context, error)) error {
	return r.unlink(ctx, deviceID, jid, recheck, record, false)
}

// UnlinkLeftover is the janitor's retry of a deletion's logout. Unlike
// Unlink it never touches a number this process holds or a deletion is
// logging out here: it answers ErrAlreadyRunning, and the next pass tries
// again, so it never logs out a client another deletion owns.
func (r *Registry) UnlinkLeftover(ctx context.Context, tenantID, deviceID string, jid types.JID,
	recheck func(context.Context) error, record func(context.Context, error)) error {
	return r.unlink(ctx, deviceID, jid, recheck, record, true)
}

// LockIdle runs f with the device lock held, for a number this process
// neither holds nor is logging out: ErrAlreadyRunning otherwise, or while
// another process or a recovery holds the lock. The janitor records a
// logout whose record was lost under it, so a recovery cannot slip between
// its look and its write.
func (r *Registry) LockIdle(ctx context.Context, deviceID string, f func(context.Context) error) error {
	r.mu.Lock()
	if _, held := r.devices[deviceID]; held || r.unlinking[deviceID] > 0 {
		r.mu.Unlock()
		return ErrAlreadyRunning
	}
	done, err := r.reserveLocked(ctx, deviceID)
	if err != nil {
		return err
	}
	defer done()
	return f(ctx)
}

func (r *Registry) unlink(ctx context.Context, deviceID string, jid types.JID,
	recheck func(context.Context) error, record func(context.Context, error), leftover bool) error {
	if jid.IsEmpty() {
		return fmt.Errorf("%w: no session to log out", ErrNoSession)
	}
	r.mu.Lock()
	e, held := r.devices[deviceID]
	switch {
	case held && (leftover || e.device == nil), leftover && r.unlinking[deviceID] > 0:
		r.mu.Unlock()
		return ErrAlreadyRunning
	case held:
		r.mu.Unlock()
		return logoutOn(ctx, e.device.Client(), recheck, record)
	}
	done, err := r.reserveLocked(ctx, deviceID)
	if err != nil {
		return err
	}
	defer done()

	ds, err := r.loadSession(ctx, jid)
	if err != nil {
		return fmt.Errorf("wa: load the session of device %s: %w", shortID(deviceID), err)
	}
	if ds == nil {
		err := fmt.Errorf("%w (device %s)", ErrNoSession, shortID(deviceID))
		if record != nil {
			record(ctx, err)
		}
		return err
	}
	if recheck != nil {
		if err := recheck(ctx); err != nil {
			return err
		}
	}
	client := r.newClient(ds, "unlink/"+shortID(deviceID))
	if err := client.Connect(); err != nil && !errors.Is(err, whatsmeow.ErrAlreadyConnected) {
		err = fmt.Errorf("wa: connect to log out: %w", err)
		if record != nil {
			record(ctx, err)
		}
		return err
	}
	defer client.Disconnect()
	return logoutOn(ctx, client, nil, record)
}

// reserveLocked, called with r.mu held, which it releases, reserves a device
// this process does not hold and takes its device lock: ErrAlreadyRunning
// while another process or a recovery holds it. done releases the lock, then
// the reservation.
func (r *Registry) reserveLocked(ctx context.Context, deviceID string) (done func(), err error) {
	reserved := &entry{}
	r.devices[deviceID] = reserved
	r.mu.Unlock()
	unreserve := func() {
		r.mu.Lock()
		if r.devices[deviceID] == reserved {
			delete(r.devices, deviceID)
		}
		r.mu.Unlock()
	}
	if r.cfg.Locker == nil {
		return unreserve, nil
	}
	release, ok, err := r.cfg.Locker.TryLock(ctx, "device:"+deviceID)
	if err != nil {
		unreserve()
		return nil, fmt.Errorf("wa: lock device: %w", err)
	}
	if !ok {
		unreserve()
		return nil, ErrAlreadyRunning
	}
	return func() {
		release()
		unreserve()
	}, nil
}

// logoutOn waits up to loginWait for client to be logged in, re-checks, asks
// WhatsApp for the logout, and records what came of it, all under the lock
// the caller holds.
func logoutOn(ctx context.Context, client Client, recheck func(context.Context) error, record func(context.Context, error)) error {
	waitCtx, cancel := context.WithTimeout(ctx, loginWait)
	for !client.IsLoggedIn() && waitCtx.Err() == nil {
		select {
		case <-waitCtx.Done():
		case <-time.After(50 * time.Millisecond):
		}
	}
	cancel()
	if recheck != nil {
		if err := recheck(ctx); err != nil {
			return err
		}
	}
	err := client.Logout(ctx)
	if record != nil {
		record(ctx, err)
	}
	return err
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
