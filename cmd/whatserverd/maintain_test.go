package main

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/config"
	"whatserver2/internal/domain"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// fakeObjects is the bucket, recording what the janitor deletes.
type fakeObjects struct {
	mu      sync.Mutex
	deleted []string
}

func (f *fakeObjects) Configured() bool { return true }

func (f *fakeObjects) Delete(_ context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleted = append(f.deleted, key)
	return nil
}

// warnings keeps every record at WARN or above, with its attributes.
type warnings struct {
	mu    sync.Mutex
	lines []string
}

func (w *warnings) Enabled(context.Context, slog.Level) bool { return true }

func (w *warnings) Handle(_ context.Context, r slog.Record) error {
	if r.Level < slog.LevelWarn {
		return nil
	}
	line := r.Message
	r.Attrs(func(a slog.Attr) bool { line += fmt.Sprintf(" %s=%v", a.Key, a.Value); return true })
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lines = append(w.lines, line)
	return nil
}

func (w *warnings) WithAttrs([]slog.Attr) slog.Handler { return w }
func (w *warnings) WithGroup(string) slog.Handler      { return w }

// One janitor pass, every step on (the assistant ones too), over a
// workspace that holds an excluded number (0050) beside a live one: nothing
// fails or warns, retention still deletes the excluded number's old
// attachment, the orphan pass deletes only what nothing names, and the live
// number keeps archiving.
func TestMaintainOnceWithExcludedNumber(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	var tenant uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO tenants(name, retention_days) VALUES ('acme', 30) RETURNING id`).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	devices, messages, media := store.NewDevices(pool), store.NewMessages(pool), store.NewMedia(pool)
	number := func(label string) uuid.UUID {
		t.Helper()
		dev, err := devices.Create(ctx, tenant.String(), label, wa.ModePassive)
		if err != nil {
			t.Fatal(err)
		}
		return uuid.MustParse(dev.ID)
	}
	excluded, live := number("Suporte"), number("Vendas")
	attachment := func(device uuid.UUID, waID string, ts time.Time) string {
		t.Helper()
		uid := uuid.New()
		if _, err := messages.Insert(ctx, store.InsertMessage{UID: uid, TenantID: tenant, DeviceID: device, WAID: waID, ChatKey: "chat",
			Kind: domain.KindMessage, Type: domain.TypeImage, Source: domain.SourceLive, TS: ts, BodySealed: []byte{1},
			Media: &store.InsertMedia{MediaType: "image", FileEncSHA256: []byte(device.String() + waID)}}); err != nil {
			t.Fatal(err)
		}
		key := device.String() + "/" + waID
		if err := media.MarkDone(ctx, tenant, uid, key, 10); err != nil {
			t.Fatal(err)
		}
		return key
	}
	expired := attachment(excluded, "old", time.Now().Add(-40*24*time.Hour))
	kept := attachment(excluded, "recent", time.Now())
	attachment(live, "recent", time.Now())
	storage := store.NewStorage(pool)
	if err := storage.ReserveObject(ctx, tenant, "orphan", 5); err != nil {
		t.Fatal(err)
	}
	// Excluded as the table owner, with the policy lifted: the deletion that
	// does it for real comes with its own handler.
	if _, err := pool.Exec(ctx, fmt.Sprintf(`ALTER TABLE devices DISABLE ROW LEVEL SECURITY;
		UPDATE devices SET deleted_at=now(), purge_after=now()+interval '30 days', paused=true WHERE id='%s';
		ALTER TABLE devices ENABLE ROW LEVEL SECURITY; ALTER TABLE devices FORCE ROW LEVEL SECURITY`, excluded)); err != nil {
		t.Fatal(err)
	}

	logged := &warnings{}
	a := &app{cfg: config.Config{MCP: config.MCP{Enabled: true}}, log: slog.New(logged),
		pools: &pg.Pools{Live: pool, History: pool, API: pool}, storage: storage}
	objects := &fakeObjects{}
	a.maintainOnce(ctx, 30*24*time.Hour, objects)

	if len(logged.lines) != 0 {
		t.Fatalf("the pass warned: %q", logged.lines)
	}
	slices.Sort(objects.deleted)
	if want := []string{expired, "orphan"}; !slices.Equal(objects.deleted, want) {
		t.Fatalf("deleted %q, want %q (and never %q)", objects.deleted, want, kept)
	}
	var left int
	if err := pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM messages WHERE device_id=$1`, excluded).Scan(&left)
	}); err != nil || left != 1 {
		t.Fatalf("the excluded number keeps %d messages, want its recent one: %v", left, err)
	}
	if _, err := messages.Insert(ctx, store.InsertMessage{UID: uuid.New(), TenantID: tenant, DeviceID: live, WAID: "after", ChatKey: "chat",
		Kind: domain.KindMessage, Type: domain.TypeText, Source: domain.SourceLive, TS: time.Now(), BodySealed: []byte{1}}); err != nil {
		t.Fatalf("the live number after the pass: %v", err)
	}
}

// The hourly housekeeping parks the contract's events never delivered in
// their 29 days (the plan's 4.11), whether or not a leader sends, logs it
// at ERROR by workspace and count, and records it for contract status
// --check.
func TestHousekeepingParksExpiredEvents(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	c := store.NewContract(pool)
	var tenant uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO tenants(name) VALUES ('Equipe') RETURNING id`).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetMode(ctx, store.ContractObserve); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetMode(ctx, store.ContractOff); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE contract_state SET events_from = clock_timestamp() - interval '40 days'`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO contract_workspaces (workspace_id, kind, named_at)
		VALUES ($1, 'team', clock_timestamp() - interval '40 days')`, tenant); err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	if err := pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO item_events (event_id, tenant_id, type, item_id, dedupe_key, occurred_at, actor_kind,
			deleted_at, purge_after, ledgered_at, created_at)
			VALUES ($1, $2, 'deleted', $3, $4, clock_timestamp() - interval '29 days 1 minute', 'person',
			clock_timestamp() - interval '29 days 1 minute', clock_timestamp() + interval '1 day', clock_timestamp(),
			clock_timestamp() - interval '29 days 1 minute')`, id, tenant, uuid.New(), id.String())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	logged := &warnings{}
	a := &app{log: slog.New(logged), pools: &pg.Pools{Live: pool, History: pool, API: pool}}
	a.deletionHousekeeping(ctx, []uuid.UUID{tenant})
	if len(logged.lines) != 1 || !strings.Contains(logged.lines[0], "contract: events never delivered in their 29 days are parked") ||
		!strings.Contains(logged.lines[0], "count=1") || !strings.Contains(logged.lines[0], tenant.String()) {
		t.Fatalf("the housekeeping logged %q", logged.lines)
	}
	if st, err := c.State(ctx); err != nil || st.ErrorClass != store.ContractErrorEventParked {
		t.Fatalf("the ERROR recorded: %+v %v", st, err)
	}
	var code string
	if err := pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT reject_code FROM item_events WHERE event_id = $1`, id).Scan(&code)
	}); err != nil || code != store.EventParkedExpired {
		t.Fatalf("the row: %q %v", code, err)
	}
}
