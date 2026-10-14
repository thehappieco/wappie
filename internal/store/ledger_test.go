package store_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/ledger"
	"whatserver2/internal/store"
)

// The deletion ledger (decision 0038's plan, section 8): every deleted,
// recovered, purged and moved_out row is appended to a file outside the
// database, at least once, and marked only after its line is synced.

func readLedger(t *testing.T, path string) []ledger.Line {
	t.Helper()
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := ledger.Read(f)
	if err != nil {
		t.Fatal(err)
	}
	if r.Duplicates != 0 || r.TornTail {
		t.Fatalf("the ledger holds %d duplicates, torn tail %v", r.Duplicates, r.TornTail)
	}
	return r.Lines
}

// unledgered counts the workspace's rows the ledger has not taken.
func unledgered(t *testing.T, pool *pgxpool.Pool, tenant uuid.UUID) int {
	t.Helper()
	ctx := context.Background()
	var n int
	inTenantTx(ctx, t, pool, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM item_events WHERE ledgered_at IS NULL`).Scan(&n)
	})
	return n
}

// faulty is a ledger file whose Write or Sync fails, or that runs a check
// when it syncs.
type faulty struct {
	*os.File
	failWrite, failSync bool
	onSync              func()
}

func (f faulty) Write(b []byte) (int, error) {
	if f.failWrite {
		n, _ := f.File.Write(b[:len(b)/2])
		return n, errors.New("no space left on device")
	}
	return f.File.Write(b)
}

func (f faulty) Sync() error {
	if f.onSync != nil {
		f.onSync()
	}
	if f.failSync {
		return errors.New("input/output error")
	}
	return f.File.Sync()
}

// TestLedgerExportAtLeastOnce is the plan's test 55: an export that cannot
// write, or whose write or sync fails, marks nothing, and the next one
// writes each event's line exactly once, synced before it is marked.
func TestLedgerExportAtLeastOnce(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	device := w.number(t, "Vendas")
	w.quarantine(t, device)
	dir := t.TempDir()
	path := filepath.Join(dir, "deletion-ledger.jsonl")

	if os.Geteuid() != 0 {
		if err := os.WriteFile(path, nil, 0o400); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ExportLedger(ctx, w.pool, w.tenant, &ledger.File{Path: path}); err == nil {
			t.Fatal("an export to a read-only ledger succeeded")
		}
		if unledgered(t, w.pool, w.tenant) != 1 {
			t.Fatal("a failed export marked its event")
		}
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var mode struct{ write, sync bool }
	synced := 0
	file := &ledger.File{Path: path, Open: func(p string) (ledger.WriteFile, error) {
		f, err := os.OpenFile(p, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0o600)
		return faulty{File: f, failWrite: mode.write, failSync: mode.sync, onSync: func() {
			// Synced before marked: the event is not ledgered yet.
			if unledgered(t, w.pool, w.tenant) == 0 {
				t.Error("the event was marked before its line was synced")
			}
			synced++
		}}, err
	}}
	for _, fail := range []struct{ write, sync bool }{{write: true}, {sync: true}} {
		mode = fail
		if n, err := store.ExportLedger(ctx, w.pool, w.tenant, file); err == nil || n != 0 {
			t.Fatalf("an export whose %+v fails: %d %v", fail, n, err)
		}
		if unledgered(t, w.pool, w.tenant) != 1 {
			t.Fatalf("an export whose %+v failed marked its event", fail)
		}
	}
	mode.write, mode.sync = false, false
	if n, err := store.ExportLedger(ctx, w.pool, w.tenant, file); err != nil || n != 1 {
		t.Fatalf("the export: %d %v", n, err)
	}
	if n, err := store.ExportLedger(ctx, w.pool, w.tenant, file); err != nil || n != 0 {
		t.Fatalf("a second export: %d %v", n, err)
	}
	lines := readLedger(t, path)
	if len(lines) != 1 || lines[0].Type != ledger.TypeDeleted || lines[0].DeviceID != device || lines[0].WorkspaceID != w.tenant ||
		lines[0].DeletedBy == nil || *lines[0].DeletedBy != w.owner || unledgered(t, w.pool, w.tenant) != 0 || synced < 2 {
		t.Fatalf("the ledger: %+v (synced %d)", lines, synced)
	}
}

// The four ledgered types each reach the ledger once; a pause, never
// ledgered, never does. Housekeeping forgets a ledgered row 30 days after
// it was written, and keeps one the ledger has not taken, naming it.
func TestLedgerTakesTheFourTypes(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	device := w.number(t, "Vendas")
	reader := w.person(t, "ana", "member")
	w.reads(t, w.owner, device)
	w.reads(t, reader, device)
	w.pause(t, device, store.PauseActor{User: w.owner})
	first := w.quarantine(t, device, reader)
	w.recover(t, device)
	second := w.quarantine(t, device, reader)
	makeDue(t, w.pool, w.tenant, device)
	if res, err := store.PurgeDevice(ctx, w.pool, w.tenant, device, nil, store.PurgeOptions{}); err != nil || !res.Final {
		t.Fatalf("the purge: %+v %v", res, err)
	}
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	file := &ledger.File{Path: path}
	if n, err := store.ExportLedger(ctx, w.pool, w.tenant, file); err != nil || n != 4 {
		t.Fatalf("the export: %d %v", n, err)
	}
	if n, err := store.ExportLedger(ctx, w.pool, w.tenant, file); err != nil || n != 0 {
		t.Fatalf("again: %d %v", n, err)
	}
	lines := readLedger(t, path)
	var types []string
	for _, l := range lines {
		types = append(types, l.Type)
		if l.DeviceID != device || l.WorkspaceID != w.tenant {
			t.Fatalf("a line names another number or workspace: %+v", l)
		}
	}
	if want := []string{"deleted", "recovered", "deleted", "purged"}; len(types) != len(want) || types[0] != want[0] || types[1] != want[1] ||
		types[2] != want[2] || types[3] != want[3] {
		t.Fatalf("the ledger's types %v, want %v", types, want)
	}
	if !lines[0].DeletedAt.Equal(first.DeletedAt) || !lines[1].DeletedAt.Equal(first.DeletedAt) || lines[1].PurgeAfter != nil ||
		!lines[2].DeletedAt.Equal(second.DeletedAt) || !lines[3].DeletedAt.Equal(second.DeletedAt) || lines[3].DeletedBy != nil {
		t.Fatalf("the lines' dates: %+v", lines)
	}
	if unledgered(t, w.pool, w.tenant) != 0 {
		t.Fatal("an exported row is not marked")
	}

	// Housekeeping, on the database's clock.
	other := w.number(t, "Outra")
	w.quarantine(t, other)
	inTenantTx(ctx, t, w.pool, w.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE item_events SET created_at = clock_timestamp() - interval '31 days'`)
		return err
	})
	counts, err := store.DeletionHousekeeping(ctx, w.pool, w.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if counts.Events != 5 || counts.Unledgered != 1 || counts.Oldest == nil {
		t.Fatalf("housekeeping: %+v", counts)
	}
	if left := readEvents(t, w.pool, w.tenant, other); len(left) != 1 || left[0].Ledgered {
		t.Fatalf("the row the ledger has not taken: %+v", left)
	}
	if left := readEvents(t, w.pool, w.tenant, device); len(left) != 0 {
		t.Fatalf("ledgered rows 30 days old: %+v", left)
	}
}

// The notices' own timers, on the database's clock (the plan's section 5):
// seen ones 30 days after they were seen, a resumed pause unseen 30 days
// after it ended, and an unseen pause notice of someone who no longer reads
// the number; a deletion notice of another number stays.
func TestNoticeHousekeeping(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	device, deleted := w.number(t, "Vendas"), w.number(t, "Outra")
	a, b := w.person(t, "ana", "member"), w.person(t, "bia", "member")
	for _, u := range []uuid.UUID{w.owner, a, b} {
		w.reads(t, u, device)
	}
	w.reads(t, b, deleted)
	w.quarantine(t, deleted, b)
	w.pause(t, device, store.PauseActor{User: w.owner})
	housekeep := func() store.DeletionHousekeepingCounts {
		t.Helper()
		c, err := store.DeletionHousekeeping(ctx, w.pool, w.tenant)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	if c := housekeep(); c.Notices != 0 {
		t.Fatalf("housekeeping took a fresh notice: %+v", c)
	}
	// b loses Read: Notices stops showing the pause, housekeeping deletes
	// it, and b's deletion notice for the other number stays.
	if err := w.users.SetDevicePermission(ctx, w.tenant, w.owner, store.DevicePermission{DeviceID: device, UserID: b}); err != nil {
		t.Fatal(err)
	}
	if n := w.notices(t, b); len(n) != 1 || n[0].Kind != store.NoticeNumberDeleted {
		t.Fatalf("b's notices after losing Read: %+v", n)
	}
	if c := housekeep(); c.Notices != 1 {
		t.Fatalf("housekeeping after b lost Read: %+v", c)
	}
	if n := w.count(t, `SELECT count(*) FROM device_notices WHERE user_id = $1`, b); n != 1 {
		t.Fatalf("b keeps %d notices", n)
	}
	// a's pause notice, resumed and unseen: kept within 30 days of the
	// resume, gone after.
	w.resume(t, device)
	housekeep()
	if n := w.notices(t, a); len(n) != 1 || n[0].ResumedAt == nil {
		t.Fatalf("a's resumed notice: %+v", n)
	}
	inTenantTx(ctx, t, w.pool, w.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE device_notices SET resumed_at = clock_timestamp() - interval '31 days' WHERE user_id = $1`, a)
		return err
	})
	if c := housekeep(); c.Notices != 1 || len(w.notices(t, a)) != 0 {
		t.Fatalf("a resumed notice 30 days on: %+v", c)
	}
	// A seen notice goes 30 days after it was seen.
	n := w.notices(t, b)
	if _, err := w.devices.SeeNotices(ctx, w.tenant, b, []store.SeenNotice{{ID: n[0].ID}}); err != nil {
		t.Fatal(err)
	}
	housekeep()
	if n := w.count(t, `SELECT count(*) FROM device_notices WHERE user_id = $1`, b); n != 1 {
		t.Fatal("a notice seen today went")
	}
	inTenantTx(ctx, t, w.pool, w.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE device_notices SET seen_at = clock_timestamp() - interval '31 days' WHERE user_id = $1`, b)
		return err
	})
	if c := housekeep(); c.Notices != 1 {
		t.Fatalf("a notice seen 31 days ago: %+v", c)
	}
}
