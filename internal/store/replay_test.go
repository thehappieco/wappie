package store_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/ledger"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// The restore's replay (decision 0038's plan, section 9, and its test 17).
// A test cannot restore a snapshot, so each case builds the database a
// snapshot would hold and the ledger lines written after it, with the
// database's own clock for every date.

// dbTime evaluates a timestamptz expression on the database's clock.
func (w *delWorld) dbTime(t *testing.T, expr string, args ...any) time.Time {
	t.Helper()
	var at time.Time
	if err := w.pool.QueryRow(context.Background(), `SELECT `+expr, args...).Scan(&at); err != nil {
		t.Fatal(err)
	}
	return at
}

// window is a deletion at the database's clock plus offset, with its 30
// days added there too.
func (w *delWorld) window(t *testing.T, offset string) (time.Time, time.Time) {
	t.Helper()
	at := w.dbTime(t, `clock_timestamp() + $1::interval`, offset)
	return at, w.dbTime(t, `$1::timestamptz + interval '30 days'`, at)
}

func (w *delWorld) line(kind string, device uuid.UUID, deletedAt, purgeAfter *time.Time, occurred time.Time) ledger.Line {
	l := ledger.Line{V: ledger.Version, EventID: uuid.New(), Type: kind, WorkspaceID: w.tenant, DeviceID: device,
		DeletedAt: deletedAt, PurgeAfter: purgeAfter, OccurredAt: occurred}
	if kind == ledger.TypeDeleted {
		l.DeletedBy = &w.owner
	}
	if kind == ledger.TypeRecovered {
		l.PurgeAfter = nil
	}
	return l
}

func (w *delWorld) replay(t *testing.T, lines []ledger.Line, opts store.ReplayOptions) (store.ReplayReport, error) {
	t.Helper()
	if opts.SnapshotTime.IsZero() {
		opts.SnapshotTime = w.dbTime(t, `clock_timestamp() - interval '90 days'`)
	}
	return store.ReplayLedger(context.Background(), w.pool, lines, opts)
}

// deviceRow is what the replay leaves of a number, read with the scope on.
type deviceRow struct {
	excluded               bool
	deletedAt, purgeAfter  *time.Time
	deletedBy              *uuid.UUID
	paused                 bool
	status, reason         string
	leftover, due, started bool
}

func (w *delWorld) row(t *testing.T, tenant, device uuid.UUID) (deviceRow, bool) {
	t.Helper()
	ctx := context.Background()
	var r deviceRow
	found := true
	inTenantTx(ctx, t, w.pool, tenant, func(tx pgx.Tx) error {
		return store.WithQuarantineForTest(ctx, tx, func() error {
			err := tx.QueryRow(ctx, `SELECT deleted_at IS NOT NULL, deleted_at, purge_after, deleted_by, paused, status, status_reason,
				wa_leftover IS NOT NULL, coalesce(purge_after <= clock_timestamp(), false), purge_started_at IS NOT NULL
				FROM devices WHERE id = $1`, device).Scan(&r.excluded, &r.deletedAt, &r.purgeAfter, &r.deletedBy, &r.paused, &r.status,
				&r.reason, &r.leftover, &r.due, &r.started)
			if errors.Is(err, pgx.ErrNoRows) {
				found = false
				return nil
			}
			return err
		})
	})
	return r, found
}

// replayed reads a number's replayed event rows: their event ids, by type.
func (w *delWorld) replayed(t *testing.T, tenant, device uuid.UUID) map[string][]uuid.UUID {
	t.Helper()
	ctx := context.Background()
	out := map[string][]uuid.UUID{}
	inTenantTx(ctx, t, w.pool, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT type, event_id FROM item_events WHERE item_id = $1 AND replayed_at IS NOT NULL AND ledgered_at IS NOT NULL ORDER BY seq`, device)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var kind string
			var id uuid.UUID
			if err := rows.Scan(&kind, &id); err != nil {
				return err
			}
			out[kind] = append(out[kind], id)
		}
		return rows.Err()
	})
	return out
}

func TestLedgerReplay(t *testing.T) {
	t.Run("a deletion after the snapshot", func(t *testing.T) {
		ctx := context.Background()
		w := newDelWorld(t)
		sessionStore(t, w.pool)
		device := w.number(t, "Vendas")
		key := w.keyBy(t, &w.owner, device)
		banned := w.number(t, "Banido")
		if err := w.devices.SetStatus(ctx, w.tenant.String(), banned.String(), wa.StatusBanned, "temporary"); err != nil {
			t.Fatal(err)
		}
		// The replay needs no owner, and works in a suspended workspace.
		if _, err := w.pool.Exec(ctx, `UPDATE tenants SET status = 'suspended' WHERE id = $1`, w.tenant); err != nil {
			t.Fatal(err)
		}
		inTenantTx(ctx, t, w.pool, w.tenant, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE workspace_memberships SET status = 'disabled' WHERE user_id = $1`, w.owner)
			return err
		})
		deletedAt, purgeAfter := w.window(t, "-1 hour")
		bannedAt, bannedUntil := w.window(t, "-50 minutes")
		lines := []ledger.Line{w.line(ledger.TypeDeleted, device, &deletedAt, &purgeAfter, deletedAt),
			w.line(ledger.TypeDeleted, banned, &bannedAt, &bannedUntil, bannedAt)}
		report, err := w.replay(t, lines, store.ReplayOptions{})
		if err != nil || len(report.Changes) != 2 {
			t.Fatalf("the replay: %v\n%s", err, report)
		}
		r, _ := w.row(t, w.tenant, device)
		if !r.excluded || !r.deletedAt.Equal(deletedAt) || !r.purgeAfter.Equal(purgeAfter) || !r.paused || r.status != "offline" ||
			r.reason != "deleted" || r.deletedBy == nil || *r.deletedBy != w.owner || r.due {
			t.Fatalf("the re-excluded number: %+v", r)
		}
		if b, _ := w.row(t, w.tenant, banned); !b.excluded || b.status != "banned" || b.reason != "temporary" {
			t.Fatalf("the banned number: %+v", b)
		}
		if ok, err := w.apiKeys.AllowsDevice(ctx, key, w.tenant, device); err != nil || ok {
			t.Fatalf("the restricted key still names the number: %v %v", ok, err)
		}
		if n := w.count(t, `SELECT count(*) FROM api_key_devices WHERE device_id = $1`, device); n != 0 {
			t.Fatalf("%d api_key_devices rows left", n)
		}
		if got := w.replayed(t, w.tenant, device); len(got["deleted"]) != 1 || got["deleted"][0] != lines[0].EventID {
			t.Fatalf("the replayed rows: %+v", got)
		}
		// Idempotent: a second replay changes nothing and writes nothing.
		again, err := w.replay(t, lines, store.ReplayOptions{})
		if err != nil || len(again.Changes) != 0 || again.Unchanged != 2 {
			t.Fatalf("a second replay: %v\n%s", err, again)
		}
		if got := w.replayed(t, w.tenant, device); len(got["deleted"]) != 1 {
			t.Fatalf("the second replay wrote rows: %+v", got)
		}
	})

	t.Run("a purge after the snapshot", func(t *testing.T) {
		ctx := context.Background()
		w := newDelWorld(t)
		sessionStore(t, w.pool)
		device := w.number(t, "Vendas")
		jid := w.pn(ctx, t, device)
		if _, err := w.pool.Exec(ctx, `INSERT INTO whatsmeow_device VALUES ($1, 7)`, jid); err != nil {
			t.Fatal(err)
		}
		deletedAt, purgeAfter := w.window(t, "-31 days")
		purgedAt := w.dbTime(t, `$1::timestamptz + interval '1 hour'`, purgeAfter)
		deleted := w.line(ledger.TypeDeleted, device, &deletedAt, &purgeAfter, deletedAt)
		purged := w.line(ledger.TypePurged, device, &deletedAt, &purgeAfter, purgedAt)
		if _, err := w.replay(t, []ledger.Line{deleted, purged}, store.ReplayOptions{}); err != nil {
			t.Fatal(err)
		}
		r, _ := w.row(t, w.tenant, device)
		if !r.excluded || !r.due || !r.leftover || !r.deletedAt.Equal(deletedAt) {
			t.Fatalf("a purged number restored live: %+v", r)
		}
		if got := w.replayed(t, w.tenant, device); len(got["purged"]) != 1 || got["purged"][0] != purged.EventID {
			t.Fatalf("the replayed purge: %+v", got)
		}
		if _, err := w.devices.Recover(ctx, w.tenant, w.owner, device); !errors.Is(err, store.ErrRecoveryClosed) {
			t.Fatalf("recovering a purged number: %v", err)
		}
		// The first janitor pass purges it, and its session, and writes no
		// second purged row.
		res, err := store.PurgeDevice(ctx, w.pool, w.tenant, device, nil, store.PurgeOptions{})
		if err != nil || !res.Final || !res.SessionRemoved {
			t.Fatalf("the janitor's purge: %+v %v", res, err)
		}
		if rows := eventsOf(t, w.pool, w.tenant, device, "purged"); len(rows) != 1 {
			t.Fatalf("%d purged rows", len(rows))
		}
	})

	t.Run("an early purge and an account's closing", func(t *testing.T) {
		w := newDelWorld(t)
		early, closing := w.number(t, "Cedo"), w.number(t, "Fechada")
		deletedAt, purgeAfter := w.window(t, "-2 days")
		purgedAt := w.dbTime(t, `$1::timestamptz + interval '1 hour'`, deletedAt)
		closedAt := w.dbTime(t, `clock_timestamp() - interval '1 day'`)
		lines := []ledger.Line{
			// An operator's --now: the purge came a day after the deletion.
			w.line(ledger.TypeDeleted, early, &deletedAt, &purgeAfter, deletedAt),
			w.line(ledger.TypePurged, early, &deletedAt, &purgedAt, purgedAt),
			// An account's closing: a purge with no deletion before it.
			w.line(ledger.TypePurged, closing, &closedAt, &closedAt, closedAt),
		}
		if _, err := w.replay(t, lines, store.ReplayOptions{}); err != nil {
			t.Fatal(err)
		}
		for _, device := range []uuid.UUID{early, closing} {
			if r, _ := w.row(t, w.tenant, device); !r.excluded || !r.due {
				t.Fatalf("%s is not due at once: %+v", device, r)
			}
		}
	})

	t.Run("a recovery after the snapshot", func(t *testing.T) {
		ctx := context.Background()
		w := newDelWorld(t)
		device := w.number(t, "Vendas")
		w.reads(t, w.owner, device)
		// The snapshot was taken while the number was excluded, and is
		// restored after its old purge_after.
		q := w.quarantine(t, device)
		w.scoped(t, func(tx pgx.Tx) error {
			_, err := tx.Exec(context.Background(), `UPDATE devices SET deleted_at = deleted_at - interval '40 days',
				purge_after = deleted_at - interval '40 days' + interval '30 days' WHERE id = $1`, device)
			return err
		})
		r, _ := w.row(t, w.tenant, device)
		recoveredAt := w.dbTime(t, `$1::timestamptz + interval '1 day'`, *r.deletedAt)
		lines := []ledger.Line{w.line(ledger.TypeDeleted, device, r.deletedAt, r.purgeAfter, *r.deletedAt),
			w.line(ledger.TypeRecovered, device, r.deletedAt, nil, recoveredAt)}
		report, err := w.replay(t, lines, store.ReplayOptions{})
		if err != nil || len(report.Changes) != 1 || report.Changes[0].Action != store.ReplayRecovered {
			t.Fatalf("the replay: %v\n%s", err, report)
		}
		if after, _ := w.row(t, w.tenant, device); after.excluded || !after.paused {
			t.Fatalf("the recovered number: %+v (deleted %+v)", after, q)
		}
		if got := w.replayed(t, w.tenant, device); len(got["recovered"]) != 1 || got["recovered"][0] != lines[1].EventID {
			t.Fatalf("the replayed recovery: %+v", got)
		}
		// The first janitor pass finds nothing due.
		if due, n, err := w.devices.DueDeletions(ctx, w.tenant, 5); err != nil || n != 0 || len(due) != 0 {
			t.Fatalf("due after the replay: %+v %d %v", due, n, err)
		}
		// A swept pair: the database has no rows of an old deleted and
		// recovered pair, and a key was given the number since; the number
		// stays live and the key keeps it.
		swept := w.number(t, "Antigo")
		key := w.keyBy(t, &w.owner, swept)
		oldAt, oldUntil := w.window(t, "-80 days")
		oldBack := w.dbTime(t, `$1::timestamptz + interval '2 days'`, oldAt)
		report, err = w.replay(t, []ledger.Line{w.line(ledger.TypeDeleted, swept, &oldAt, &oldUntil, oldAt),
			w.line(ledger.TypeRecovered, swept, &oldAt, nil, oldBack)}, store.ReplayOptions{})
		if err != nil || len(report.Changes) != 0 {
			t.Fatalf("the swept pair: %v\n%s", err, report)
		}
		if ok, err := w.apiKeys.AllowsDevice(ctx, key, w.tenant, swept); err != nil || !ok {
			t.Fatalf("the key given since: %v %v", ok, err)
		}
	})

	t.Run("identity before capacity", func(t *testing.T) {
		ctx := context.Background()
		// The snapshot holds A excluded and B live with A's phone; the
		// ledger says B was deleted, then A recovered.
		w := newDelWorld(t)
		a := w.number(t, "A")
		pn := w.pn(ctx, t, a)
		qa := w.quarantine(t, a)
		b := linkedNumber(t, w.pool, w.tenant, "B", strings.TrimSuffix(pn, "@s.whatsapp.net"), "200000000000099")
		bAt, bUntil := w.window(t, "+1 minute")
		aBack := w.dbTime(t, `$1::timestamptz + interval '2 minutes'`, bAt)
		lines := []ledger.Line{
			w.line(ledger.TypeDeleted, a, &qa.DeletedAt, &qa.PurgeAfter, qa.DeletedAt),
			w.line(ledger.TypeDeleted, b, &bAt, &bUntil, bAt),
			w.line(ledger.TypeRecovered, a, &qa.DeletedAt, nil, aBack),
		}
		if report, err := w.replay(t, lines, store.ReplayOptions{}); err != nil {
			t.Fatalf("the replay: %v\n%s", err, report)
		}
		if ra, _ := w.row(t, w.tenant, a); ra.excluded {
			t.Fatalf("A: %+v", ra)
		}
		if rb, _ := w.row(t, w.tenant, b); !rb.excluded || !rb.deletedAt.Equal(bAt) {
			t.Fatalf("B: %+v", rb)
		}
	})

	t.Run("a recovery whose phone is in use", func(t *testing.T) {
		ctx := context.Background()
		w := newDelWorld(t)
		a := w.number(t, "A")
		pn := w.pn(ctx, t, a)
		qa := w.quarantine(t, a)
		linkedNumber(t, w.pool, w.tenant, "B", strings.TrimSuffix(pn, "@s.whatsapp.net"), "200000000000099")
		back := w.dbTime(t, `clock_timestamp()`)
		report, err := w.replay(t, []ledger.Line{w.line(ledger.TypeDeleted, a, &qa.DeletedAt, &qa.PurgeAfter, qa.DeletedAt),
			w.line(ledger.TypeRecovered, a, &qa.DeletedAt, nil, back)}, store.ReplayOptions{})
		if !errors.Is(err, store.ErrReplayRefused) || len(report.Refusals) != 1 {
			t.Fatalf("the replay: %v\n%s", err, report)
		}
		if ra, _ := w.row(t, w.tenant, a); !ra.excluded {
			t.Fatalf("A after a refused recovery: %+v", ra)
		}
	})

	t.Run("a move after the snapshot", func(t *testing.T) {
		ctx := context.Background()
		w := newDelWorld(t)
		moved, onlyMoved := w.number(t, "Movido"), w.number(t, "Só movido")
		reader := w.person(t, "ana", "member")
		w.reads(t, reader, moved)
		personal := uuid.MustParse(newTenant(t, w.pool, "personal"))
		movedAt := w.dbTime(t, `clock_timestamp() - interval '40 days'`)
		deletedAt, purgeAfter := w.window(t, "-35 days")
		purgedAt := w.dbTime(t, `$1::timestamptz + interval '1 hour'`, purgeAfter)
		move := func(device uuid.UUID) ledger.Line {
			l := w.line(ledger.TypeMovedOut, device, nil, nil, movedAt)
			l.ToWorkspaceID = &personal
			return l
		}
		inPersonal := func(l ledger.Line) ledger.Line { l.WorkspaceID = personal; l.DeletedBy = nil; return l }
		lines := []ledger.Line{move(moved), inPersonal(w.line(ledger.TypeDeleted, moved, &deletedAt, &purgeAfter, deletedAt)),
			inPersonal(w.line(ledger.TypePurged, moved, &deletedAt, &purgeAfter, purgedAt)), move(onlyMoved)}
		report, err := w.replay(t, lines, store.ReplayOptions{})
		if !errors.Is(err, store.ErrReplayRefused) || len(report.Refusals) != 2 {
			t.Fatalf("a snapshot from before the moves: %v\n%s", err, report)
		}
		for _, device := range []uuid.UUID{moved, onlyMoved} {
			if r, _ := w.row(t, w.tenant, device); r.excluded {
				t.Fatalf("a refused replay changed %s: %+v", device, r)
			}
		}
		report, err = w.replay(t, lines, store.ReplayOptions{LeaveExcluded: []uuid.UUID{moved, onlyMoved}})
		if err != nil || len(report.Changes) != 2 {
			t.Fatalf("with --leave-excluded: %v\n%s", err, report)
		}
		if r, _ := w.row(t, w.tenant, moved); !r.excluded || !r.due {
			t.Fatalf("the moved and purged number in its team: %+v", r)
		}
		if got := w.replayed(t, w.tenant, moved); len(got["purged"]) != 1 {
			t.Fatalf("the purge's row in the team: %+v", got)
		}
		r, _ := w.row(t, w.tenant, onlyMoved)
		if !r.excluded || r.due || r.deletedAt == nil || !r.purgeAfter.Equal(w.dbTime(t, `$1::timestamptz + interval '30 days'`, *r.deletedAt)) {
			t.Fatalf("the moved number left excluded in its team: %+v", r)
		}
		// Nobody in the team reads either.
		for _, device := range []uuid.UUID{moved, onlyMoved} {
			if _, err := w.devices.Get(ctx, w.tenant.String(), device.String()); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("the team still sees %s: %v", device, err)
			}
		}
	})

	t.Run("lines it refuses", func(t *testing.T) {
		w := newDelWorld(t)
		device := w.number(t, "Vendas")
		deletedAt, purgeAfter := w.window(t, "-1 hour")
		short := w.dbTime(t, `$1::timestamptz + interval '1 day'`, deletedAt)
		report, err := w.replay(t, []ledger.Line{w.line(ledger.TypeDeleted, device, &deletedAt, &short, deletedAt)}, store.ReplayOptions{})
		if !errors.Is(err, store.ErrReplayRefused) || !strings.Contains(report.String(), "30 days") {
			t.Fatalf("a deleted line with a short window: %v\n%s", err, report)
		}
		later, laterUntil := w.window(t, "-30 minutes")
		report, err = w.replay(t, []ledger.Line{w.line(ledger.TypeDeleted, device, &deletedAt, &purgeAfter, deletedAt),
			w.line(ledger.TypeDeleted, device, &later, &laterUntil, later)}, store.ReplayOptions{})
		if !errors.Is(err, store.ErrReplayRefused) || !strings.Contains(report.String(), "lines were lost") {
			t.Fatalf("two deletions with no recovery: %v\n%s", err, report)
		}
		if r, _ := w.row(t, w.tenant, device); r.excluded {
			t.Fatalf("a refused replay changed the number: %+v", r)
		}
	})

	t.Run("the snapshot's own ledger", func(t *testing.T) {
		ctx := context.Background()
		// The ledger put back is the snapshot's own copy: nothing in it is
		// newer than what the restored database ledgered.
		w := newDelWorld(t)
		device := w.number(t, "Vendas")
		w.quarantine(t, device)
		path := filepath.Join(t.TempDir(), "ledger.jsonl")
		if _, err := store.ExportLedger(ctx, w.pool, w.tenant, &ledger.File{Path: path}); err != nil {
			t.Fatal(err)
		}
		lines := readLedger(t, path)
		report, err := w.replay(t, lines, store.ReplayOptions{})
		if !errors.Is(err, store.ErrLedgerAddsNothing) || report.LedgerNewest.After(report.RestoredNewest) {
			t.Fatalf("the snapshot's own ledger: %v\n%s", err, report)
		}
		// Nor anything newer than the snapshot's stamp.
		report, err = w.replay(t, lines, store.ReplayOptions{SnapshotTime: w.dbTime(t, `clock_timestamp() + interval '1 hour'`)})
		if !errors.Is(err, store.ErrLedgerAddsNothing) {
			t.Fatalf("a ledger older than the snapshot: %v\n%s", err, report)
		}
		if report, err := w.replay(t, lines, store.ReplayOptions{LedgerAddsNothing: true}); err != nil || report.Unchanged != 1 {
			t.Fatalf("with --ledger-adds-nothing: %v\n%s", err, report)
		}
	})

	t.Run("a dry run", func(t *testing.T) {
		w := newDelWorld(t)
		device := w.number(t, "Vendas")
		deletedAt, purgeAfter := w.window(t, "-1 hour")
		report, err := w.replay(t, []ledger.Line{w.line(ledger.TypeDeleted, device, &deletedAt, &purgeAfter, deletedAt)},
			store.ReplayOptions{DryRun: true})
		if err != nil || len(report.Changes) != 1 || report.Changes[0].Action != store.ReplayExcluded {
			t.Fatalf("the dry run: %v\n%s", err, report)
		}
		if r, _ := w.row(t, w.tenant, device); r.excluded {
			t.Fatalf("a dry run changed the number: %+v", r)
		}
		if n := len(readEvents(t, w.pool, w.tenant, device)); n != 0 {
			t.Fatalf("a dry run wrote %d rows", n)
		}
	})
}
