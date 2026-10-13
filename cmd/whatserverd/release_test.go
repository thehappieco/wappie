package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	waStore "go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
	waLog "go.mau.fi/whatsmeow/util/log"

	"whatserver2/internal/bus"
	"whatserver2/internal/ingest"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
	"whatserver2/internal/wa/fakewa"
)

// A process lets go of what it should no longer hold: a number paused,
// deleted (and so hidden from its list), or moved to another workspace.

func released(held []wa.HeldDevice, listed map[string]tenantList) []string {
	var out []string
	for _, h := range toRelease(held, listed) {
		out = append(out, h.ID)
	}
	slices.Sort(out)
	return out
}

func TestReleaseHeld(t *testing.T) {
	live := device("live", wa.StatusOnline)
	paused := device("paused", wa.StatusOnline)
	paused.Paused = true
	listed := map[string]tenantList{"team": {devices: []store.Device{live, paused}}, "personal": {devices: []store.Device{}}}
	held := []wa.HeldDevice{
		{ID: "live", TenantID: "team"},
		{ID: "paused", TenantID: "team"},
		// Deleted: hidden, so not in the list.
		{ID: "deleted", TenantID: "team"},
		// Moved to Personal: in neither list under its old workspace.
		{ID: "moved", TenantID: "team"},
		// A deletion is logging it out here; the deletion stops it.
		{ID: "unlinking", TenantID: "team", Unlinking: true},
	}
	if got, want := released(held, listed), []string{"deleted", "moved", "paused"}; !slices.Equal(got, want) {
		t.Fatalf("released %v, want %v", got, want)
	}
}

func TestReleaseHeldSkipsFailedList(t *testing.T) {
	listed := map[string]tenantList{"broken": {err: errors.New("timeout")}, "team": {devices: []store.Device{}}}
	held := []wa.HeldDevice{
		{ID: "a", TenantID: "broken"},
		{ID: "b", TenantID: "broken"},
		// A pairing or a start in progress has no device yet.
		{ID: "reserved", Reserved: true},
		// A workspace the supervisor did not list this tick.
		{ID: "elsewhere", TenantID: "suspended"},
	}
	if got := released(held, listed); len(got) != 0 {
		t.Fatalf("released %v after a failed list", got)
	}
}

// fakeSessionUnlinker is the janitor's view of the registry: it runs the
// re-check, then counts a logout and removes the session, as whatsmeow does.
type fakeSessionUnlinker struct {
	mu      sync.Mutex
	pool    *pgxpool.Pool
	logouts int
	// hold, when set, is waited on between the listing and the logout.
	hold chan struct{}
	held chan struct{}
	err  error
}

func (f *fakeSessionUnlinker) Unlink(ctx context.Context, _, _ string, jid types.JID, recheck func(context.Context) error) error {
	if f.hold != nil {
		close(f.held)
		<-f.hold
	}
	if f.err != nil {
		return f.err
	}
	if err := recheck(ctx); err != nil {
		return err
	}
	f.mu.Lock()
	f.logouts++
	f.mu.Unlock()
	_, err := f.pool.Exec(ctx, `DELETE FROM whatsmeow_device WHERE jid=$1`, jid.String())
	return err
}

type janitorWorld struct {
	pool    *pgxpool.Pool
	tenant  uuid.UUID
	owner   uuid.UUID
	devices *store.Devices
	app     *app
	logged  *warnings
	n       int
}

func newJanitorWorld(t *testing.T, unlinker sessionUnlinker) *janitorWorld {
	t.Helper()
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `CREATE TABLE whatsmeow_device (jid text PRIMARY KEY, registration_id bigint NOT NULL);
		CREATE TABLE whatsmeow_privacy_tokens (our_jid text, their_jid text, token bytea NOT NULL, timestamp bigint NOT NULL, PRIMARY KEY (our_jid, their_jid))`); err != nil {
		t.Fatal(err)
	}
	var tenant uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO tenants(name) VALUES ('acme') RETURNING id`).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	users := store.NewUsers(pool)
	owner, err := users.Create(ctx, store.NewUser{TenantID: tenant, Email: "owner@acme.test", Role: "owner", AuthKey: "test",
		KDFSalt: make([]byte, 16), KDFParams: store.DefaultKDFParams(), PublicKey: make([]byte, 32), WrappedUSK: []byte("wrapped")})
	if err != nil {
		t.Fatal(err)
	}
	logged := &warnings{}
	w := &janitorWorld{pool: pool, tenant: tenant, owner: owner.ID, devices: store.NewDevices(pool), logged: logged}
	w.app = &app{log: slog.New(logged), pools: &pg.Pools{Live: pool, History: pool, API: pool}, devices: w.devices, unlinker: unlinker}
	return w
}

// deleted is a linked number whose session survived its deletion's logout:
// excluded, with its fingerprint, as a crash before RecordUnlink leaves it.
func (w *janitorWorld) deleted(t *testing.T, reg int64) (uuid.UUID, string) {
	t.Helper()
	ctx := context.Background()
	w.n++
	dev, err := w.devices.Create(ctx, w.tenant.String(), "n", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	pn := types.JID{User: fmt.Sprintf("55119%04d5678", w.n), Server: types.DefaultUserServer}
	if err := w.devices.SetIdentity(ctx, w.tenant.String(), dev.ID, wa.Identity{PN: pn}); err != nil {
		t.Fatal(err)
	}
	if err := w.devices.SetStatus(ctx, w.tenant.String(), dev.ID, wa.StatusOnline, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := w.pool.Exec(ctx, `INSERT INTO whatsmeow_device(jid, registration_id) VALUES ($1, $2)`, pn.String(), reg); err != nil {
		t.Fatal(err)
	}
	q, err := w.devices.Quarantine(ctx, w.tenant, w.owner, uuid.MustParse(dev.ID), nil)
	if err != nil || q.Session == nil {
		t.Fatalf("quarantine: %+v %v", q, err)
	}
	return uuid.MustParse(dev.ID), pn.String()
}

func (w *janitorWorld) state(t *testing.T, device uuid.UUID) (deleted, leftover bool, status string) {
	t.Helper()
	numbers, err := w.devices.ListDeleted(context.Background(), w.tenant, w.owner)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range numbers {
		if n.DeviceID == device {
			left, err := w.devices.LeftoverSessions(context.Background(), w.tenant)
			if err != nil {
				t.Fatal(err)
			}
			for _, l := range left {
				leftover = leftover || l.DeviceID == device
			}
			return true, leftover, string(n.Status)
		}
	}
	d, err := w.devices.Get(context.Background(), w.tenant.String(), device.String())
	if err != nil {
		t.Fatal(err)
	}
	return false, false, string(d.Status)
}

// The deletion's process died before its logout: the janitor logs the
// session out by its fingerprint, and only while the registration matches.
func TestJanitorRetriesLeftoverSessions(t *testing.T) {
	ctx := context.Background()
	unlinker := &fakeSessionUnlinker{}
	w := newJanitorWorld(t, unlinker)
	unlinker.pool = w.pool

	matching, _ := w.deleted(t, 1)
	relinked, relinkedJID := w.deleted(t, 2)
	// The phone linked again under the same JID: another registration.
	if _, err := w.pool.Exec(ctx, `UPDATE whatsmeow_device SET registration_id=99 WHERE jid=$1`, relinkedJID); err != nil {
		t.Fatal(err)
	}
	if _, err := w.pool.Exec(ctx, `INSERT INTO whatsmeow_privacy_tokens VALUES ($1,'x',''::bytea,1)`, relinkedJID); err != nil {
		t.Fatal(err)
	}
	w.app.retryLeftoverSessions(ctx)
	if unlinker.logouts != 1 {
		t.Fatalf("%d logouts, want the matching session's only", unlinker.logouts)
	}
	if _, leftover, status := w.state(t, matching); leftover || status != "logged_out" {
		t.Fatalf("the matching session: leftover %v, status %s", leftover, status)
	}
	var reg int64
	var tokens int
	if err := w.pool.QueryRow(ctx, `SELECT registration_id, (SELECT count(*) FROM whatsmeow_privacy_tokens WHERE our_jid=$1)
		FROM whatsmeow_device WHERE jid=$1`, relinkedJID).Scan(&reg, &tokens); err != nil || reg != 99 || tokens != 1 {
		t.Fatalf("the relinked phone's session: %d, %d tokens, %v", reg, tokens, err)
	}
	if deleted, leftover, _ := w.state(t, relinked); !deleted || leftover {
		t.Fatalf("the relinked number: excluded %v, leftover %v", deleted, leftover)
	}

	// A logout that keeps failing is tried three times, then left to the
	// purge, with one warning.
	failing, _ := w.deleted(t, 3)
	unlinker.err = errors.New("no answer")
	for range 5 {
		w.app.retryLeftoverSessions(ctx)
	}
	if deleted, leftover, status := w.state(t, failing); !deleted || leftover || status == "logged_out" {
		t.Fatalf("after the attempts: excluded %v, still listed %v, status %s", deleted, leftover, status)
	}
	warned := 0
	for _, line := range w.logged.lines {
		if slices.Contains([]string{"a deleted number's WhatsApp session could not be logged out; its purge removes it"}, firstWords(line)) {
			warned++
		}
	}
	if warned != 1 {
		t.Fatalf("warned %d times: %q", warned, w.logged.lines)
	}
	// Held elsewhere: no attempt is spent.
	other, _ := w.deleted(t, 4)
	unlinker.err = wa.ErrAlreadyRunning
	w.app.retryLeftoverSessions(ctx)
	left, err := w.devices.LeftoverSessions(ctx, w.tenant)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range left {
		if l.DeviceID == other && l.Attempts != 0 {
			t.Fatalf("a number held elsewhere spent an attempt: %d", l.Attempts)
		}
	}
}

func firstWords(line string) string {
	for i := range line {
		if line[i] == ' ' && i+len(" device=") <= len(line) && line[i:i+len(" device=")] == " device=" {
			return line[:i]
		}
	}
	return line
}

// The janitor's retry is held between its listing and its logout while an
// owner recovers the number: the logout never runs on the recovered number.
func TestLogoutNeverAfterRecovery(t *testing.T) {
	ctx := context.Background()
	unlinker := &fakeSessionUnlinker{hold: make(chan struct{}), held: make(chan struct{})}
	w := newJanitorWorld(t, unlinker)
	unlinker.pool = w.pool
	device, _ := w.deleted(t, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		w.app.retryLeftoverSessions(ctx)
	}()
	<-unlinker.held
	if _, err := w.devices.Recover(ctx, w.tenant, w.owner, device); err != nil {
		t.Fatal(err)
	}
	close(unlinker.hold)
	<-done
	if unlinker.logouts != 0 {
		t.Fatalf("%d logouts of a recovered number", unlinker.logouts)
	}
	if deleted, _, status := w.state(t, device); deleted || status != "offline" {
		t.Fatalf("the recovered number: excluded %v, status %s", deleted, status)
	}

	// The other order: a logout holding the device lock makes a recovery
	// answer busy, and change nothing.
	again, _ := w.deleted(t, 2)
	release, ok, err := pg.NewLocker(w.pool).TryLock(ctx, "device:"+again.String())
	if err != nil || !ok {
		t.Fatalf("lock: %v %v", ok, err)
	}
	if _, err := w.devices.Recover(ctx, w.tenant, w.owner, again); !errors.Is(err, store.ErrDeviceBusy) {
		t.Fatalf("a recovery during a logout: %v", err)
	}
	release()
	if deleted, _, _ := w.state(t, again); !deleted {
		t.Fatal("a busy recovery changed the number")
	}
}

// Two processes on one database: the one that holds the number lets go of
// it on the deletion's notification, before any supervisor tick: it stops
// and forgets it, and its subscribers (an all-numbers key's among them) stop
// receiving presence for it.
func TestDeviceExcludedNotify(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := newJanitorWorld(t, nil)
	number := func(pn string) uuid.UUID {
		t.Helper()
		dev, err := w.devices.Create(ctx, w.tenant.String(), "n", wa.ModePassive)
		if err != nil {
			t.Fatal(err)
		}
		if err := w.devices.SetIdentity(ctx, w.tenant.String(), dev.ID, wa.Identity{PN: types.NewJID(pn, types.DefaultUserServer)}); err != nil {
			t.Fatal(err)
		}
		return uuid.MustParse(dev.ID)
	}
	deleted, kept := number("5511988887777"), number("5511988886666")

	// The other process: its registry holding the number on a fake client,
	// its bus, and a subscription there that names both numbers.
	registry, err := wa.NewRegistry(wa.RegistryConfig{Container: &sqlstore.Container{}, Store: w.devices,
		Log: slog.New(slog.DiscardHandler), NewClient: func(*waStore.Device, waLog.Logger) wa.Client { return fakewa.New() }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.StartNew(ctx, w.tenant.String(), deleted.String(), wa.ReceiptPolicy{Mode: wa.ModePassive}); err != nil {
		t.Fatal(err)
	}
	other := &app{log: slog.New(slog.DiscardHandler), bus: bus.New(), registry: registry}
	sub := other.bus.Subscribe(w.tenant, bus.Filter{Devices: map[uuid.UUID]struct{}{deleted: {}, kept: {}}})
	defer sub.Close()
	sub.EndReplay(0)
	heard := make(chan uuid.UUID, 4)
	listening := make(chan struct{})
	go func() {
		_ = listenDeviceExcluded(ctx, w.pool, func(tenant, id uuid.UUID) {
			if tenant == w.tenant {
				other.onDeviceExcluded(ctx, tenant, id)
				heard <- id
			}
		}, func() { close(listening) })
	}()
	<-listening

	if _, err := w.devices.Quarantine(ctx, w.tenant, w.owner, deleted, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case id := <-heard:
		if id != deleted {
			t.Fatalf("heard %s, want %s", id, deleted)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the deletion's notification never came")
	}
	if _, held := registry.Get(deleted.String()); held {
		t.Fatal("the process still holds the deleted number")
	}
	for _, id := range []uuid.UUID{deleted, kept} {
		other.bus.Publish(w.tenant, ingest.Event{Class: ingest.ClassPresence, TenantID: w.tenant, DeviceID: id, Ephemeral: true,
			Presence: &ingest.Presence{ChatKey: "chat", State: "composing"}})
	}
	select {
	case ev := <-sub.Events():
		if ev.DeviceID != kept {
			t.Fatalf("relayed presence for %s", ev.DeviceID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the kept number's presence was not relayed")
	}

	// A number a deletion is logging out here is left to the deletion.
	if _, err := registry.StartNew(ctx, w.tenant.String(), kept.String(), wa.ReceiptPolicy{Mode: wa.ModePassive}); err != nil {
		t.Fatal(err)
	}
	end := registry.BeginUnlink(kept.String())
	other.onDeviceExcluded(ctx, w.tenant, kept)
	if _, held := registry.Get(kept.String()); !held {
		t.Fatal("the notification stopped a client a deletion is logging out")
	}
	end()
	registry.StopAll(ctx)
}
