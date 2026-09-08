package wa

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"

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
	Container *sqlstore.Container
	Store     Store
	Sink      Sink
	Locker    Locker
	Log       *slog.Logger
	// WireLog passes whatsmeow's debug output — every protocol node, which
	// is every message in the clear — into the log. Development only; the
	// configuration loader refuses it in prod.
	WireLog bool

	// OnStatus is forwarded to every supervised device.
	OnStatus func(tenantID, deviceID string, status Status, reason string)
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
}

type entry struct {
	device  *Device
	release func()
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
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Registry{cfg: cfg, log: cfg.Log, devices: map[string]*entry{}}, nil
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
	client := whatsmeow.NewClient(ds, r.waLogger("device/"+shortID(deviceID)))
	applyClientPolicy(client)

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

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
