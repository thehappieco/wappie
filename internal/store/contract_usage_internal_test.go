package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	kitvectors "github.com/thehappieco/kit/vectors"

	"whatserver2/internal/migrate"
	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
)

// The usage report's measurement (E0 slice 18): the date rule of
// usage-dates.json on rows seeded with their exact bytes, the totals, the
// seq, and a measurement that never holds capture back.

// usageRow is one row of a seed, as usage-dates.json writes them.
type usageRow struct {
	ID    string   `json:"id"`
	Kind  string   `json:"kind"`
	What  string   `json:"what"`
	Item  string   `json:"item"`
	TS    *string  `json:"ts"`
	Of    string   `json:"of"`
	Refs  []string `json:"refs"`
	Bytes int64    `json:"bytes"`
}

// usageWorld is a workspace with a database to seed and measure.
type usageWorld struct {
	pool    *pgxpool.Pool
	c       *Contract
	tenant  uuid.UUID
	devices map[string]uuid.UUID
}

func newUsageWorld(t *testing.T) *usageWorld {
	t.Helper()
	pool := pgtest.Fresh(t, migrate.Run)
	w := &usageWorld{pool: pool, c: NewContract(pool), devices: map[string]uuid.UUID{}}
	if err := pool.QueryRow(context.Background(), `INSERT INTO tenants (name) VALUES ('team') RETURNING id`).Scan(&w.tenant); err != nil {
		t.Fatal(err)
	}
	return w
}

// device is the number named item, made at its first use.
func (w *usageWorld) device(ctx context.Context, t *testing.T, tx pgx.Tx, item string) uuid.UUID {
	t.Helper()
	if id, ok := w.devices[item]; ok {
		return id
	}
	var id uuid.UUID
	if err := tx.QueryRow(ctx, `INSERT INTO devices (tenant_id, label) VALUES ($1, $2) RETURNING id`, w.tenant, item).Scan(&id); err != nil {
		t.Fatal(err)
	}
	w.devices[item] = id
	return id
}

// seed writes rows, with the accounting triggers off and each row's bytes
// in storage_inventory or storage_objects exactly as given, then the
// workspace's totals as their sums.
func (w *usageWorld) seed(t *testing.T, rows []usageRow) {
	t.Helper()
	ctx := context.Background()
	tables := []string{"messages", "media", "receipts", "group_changes", "chats", "contacts", "group_participants", "ai_derived", "storage_objects"}
	if err := pg.InTenantTx(ctx, w.pool, w.tenant.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.device_quarantine', 'on', true)`); err != nil {
			return err
		}
		for _, table := range tables {
			if _, err := tx.Exec(ctx, `ALTER TABLE `+table+` DISABLE TRIGGER USER`); err != nil {
				return err
			}
		}
		messages := map[string]uuid.UUID{}
		inventory := func(source string, identity []any, bytes int64) error {
			raw, err := json.Marshal(identity)
			if err != nil {
				return err
			}
			_, err = tx.Exec(ctx, `INSERT INTO storage_inventory (tenant_id, source, identity, bytes) VALUES ($1, $2, $3, $4)`,
				w.tenant, source, string(raw), bytes)
			return err
		}
		for i, r := range rows {
			var ts *time.Time
			if r.TS != nil {
				at, err := time.Parse(time.RFC3339Nano, *r.TS)
				if err != nil {
					return err
				}
				ts = &at
			}
			switch r.Kind {
			case "message":
				dev := w.device(ctx, t, tx, r.Item)
				var uid uuid.UUID
				if err := tx.QueryRow(ctx, `INSERT INTO messages (tenant_id, device_id, seq, wa_id, chat_key, kind, type, source, ts)
					VALUES ($1, $2, $3, $4, 'chat', 'message', 'image', 'live', $5) RETURNING uid`, w.tenant, dev, i+1, r.ID, ts).Scan(&uid); err != nil {
					return err
				}
				messages[r.ID] = uid
				if err := inventory("messages", []any{uid}, r.Bytes); err != nil {
					return err
				}
			case "receipt":
				dev := w.device(ctx, t, tx, r.Item)
				if _, err := tx.Exec(ctx, `INSERT INTO receipts (tenant_id, device_id, seq, chat_key, wa_id, reader_key, kind, ts)
					VALUES ($1, $2, $3, 'chat', $4, 'reader', 'read', $5)`, w.tenant, dev, i+1, r.ID, ts); err != nil {
					return err
				}
				if err := inventory("receipts", []any{dev, "chat", r.ID, "reader", "read"}, r.Bytes); err != nil {
					return err
				}
			case "group_change":
				dev := w.device(ctx, t, tx, r.Item)
				var id int64
				if err := tx.QueryRow(ctx, `INSERT INTO group_changes (tenant_id, device_id, chat_key, ts, action)
					VALUES ($1, $2, 'group@g.us', $3, 'snapshot') RETURNING id`, w.tenant, dev, ts).Scan(&id); err != nil {
					return err
				}
				if err := inventory("group_changes", []any{id}, r.Bytes); err != nil {
					return err
				}
			case "transcript":
				uid := messages[r.Of]
				var dev uuid.UUID
				if err := tx.QueryRow(ctx, `SELECT device_id FROM messages WHERE uid = $1`, uid).Scan(&dev); err != nil {
					return err
				}
				tag := sha256.Sum256([]byte(r.ID))
				if _, err := tx.Exec(ctx, `INSERT INTO ai_derived (message_uid, feature, tenant_id, device_id, epoch, result_sealed, dedupe_tag)
					VALUES ($1, 'audio', $2, $3, 1, '\x01', $4)`, uid, w.tenant, dev, tag[:]); err != nil {
					return err
				}
				if err := inventory("ai_derived", []any{uid, "audio"}, r.Bytes); err != nil {
					return err
				}
			case "object":
				key := "objects/" + r.ID
				if _, err := tx.Exec(ctx, `INSERT INTO storage_objects (tenant_id, object_key, bytes) VALUES ($1, $2, $3)`, w.tenant, key, r.Bytes); err != nil {
					return err
				}
				for _, ref := range r.Refs {
					if _, err := tx.Exec(ctx, `INSERT INTO media (message_uid, tenant_id, media_type, object_key, object_size)
						VALUES ($1, $2, 'image', $3, $4)`, messages[ref], w.tenant, key, r.Bytes); err != nil {
						return err
					}
				}
			case "fixed":
				dev := w.device(ctx, t, tx, r.Item)
				switch r.What {
				case "chat":
					if _, err := tx.Exec(ctx, `INSERT INTO chats (tenant_id, device_id, chat_key) VALUES ($1, $2, $3)`, w.tenant, dev, r.ID); err != nil {
						return err
					}
					if err := inventory("chats", []any{dev, r.ID}, r.Bytes); err != nil {
						return err
					}
				case "contact":
					if _, err := tx.Exec(ctx, `INSERT INTO contacts (tenant_id, device_id, contact_key, uid) VALUES ($1, $2, $3, uuidv7())`,
						w.tenant, dev, r.ID); err != nil {
						return err
					}
					if err := inventory("contacts", []any{dev, r.ID}, r.Bytes); err != nil {
						return err
					}
				case "group_member":
					if _, err := tx.Exec(ctx, `INSERT INTO group_participants (tenant_id, device_id, chat_key, participant_key)
						VALUES ($1, $2, 'group@g.us', $3)`, w.tenant, dev, r.ID); err != nil {
						return err
					}
					if err := inventory("group_participants", []any{dev, "group@g.us", r.ID}, r.Bytes); err != nil {
						return err
					}
				default:
					return fmt.Errorf("a fixed row of %q", r.What)
				}
			default:
				return fmt.Errorf("a row of %q", r.Kind)
			}
		}
		for _, table := range tables {
			if _, err := tx.Exec(ctx, `ALTER TABLE `+table+` ENABLE TRIGGER USER`); err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx, `UPDATE tenants SET
			storage_archive_bytes = (SELECT coalesce(sum(bytes), 0) FROM storage_inventory WHERE tenant_id = $1),
			storage_object_bytes = (SELECT coalesce(sum(bytes), 0) FROM storage_objects WHERE tenant_id = $1) WHERE id = $1`, w.tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// measureAt measures the workspace as MeasureUsage does, at measuredAt.
func (w *usageWorld) measureAt(t *testing.T, measuredAt time.Time) UsageMeasure {
	t.Helper()
	out := UsageMeasure{Workspace: w.tenant, MeasuredAt: measuredAt, Items: []UsageItemMeasure{}}
	if err := pgx.BeginTxFunc(context.Background(), w.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly},
		func(tx pgx.Tx) error { return measureTx(context.Background(), tx, &out) }); err != nil {
		t.Fatal(err)
	}
	return out
}

func (w *usageWorld) item(m UsageMeasure, name string) (UsageItemMeasure, bool) {
	for _, it := range m.Items {
		if it.Device == w.devices[name] {
			return it, true
		}
	}
	return UsageItemMeasure{}, false
}

// TestUsageDateVectors: each of Wappie's sets of usage-dates.json, seeded
// as messages, receipts, group changes, AI transcripts, chats, contacts,
// group members and media with objects on synthetic numbers, then
// measured at its measured_at: every item's four figures and the shared
// bytes are the vector's. Mailie's sets are hers.
func TestUsageDateVectors(t *testing.T) {
	raw, err := fs.ReadFile(kitvectors.FS, "platform/contract-v1/usage-dates.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Dates []struct {
			Name       string     `json:"name"`
			App        string     `json:"app"`
			MeasuredAt time.Time  `json:"measured_at"`
			Rows       []usageRow `json:"rows"`
			Items      map[string]struct {
				Bytes   int64 `json:"bytes"`
				Recent  int64 `json:"recent_bytes"`
				Undated int64 `json:"undated_bytes"`
				Fixed   int64 `json:"fixed_bytes"`
			} `json:"items"`
			Shared int64 `json:"shared_bytes"`
		} `json:"dates"`
		Floors []json.RawMessage `json:"floors"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Dates) != 14 || len(v.Floors) != 2 {
		t.Fatalf("%d sets and %d floors", len(v.Dates), len(v.Floors))
	}
	ran := 0
	for _, c := range v.Dates {
		if c.App != "wappie" {
			continue
		}
		ran++
		t.Run(c.Name, func(t *testing.T) {
			w := newUsageWorld(t)
			w.seed(t, c.Rows)
			m := w.measureAt(t, c.MeasuredAt)
			if m.Shared != c.Shared || len(m.Items) != len(c.Items) || m.Unattributed != 0 {
				t.Fatalf("shared %d (want %d), %d items (want %d), %d unattributed", m.Shared, c.Shared, len(m.Items), len(c.Items), m.Unattributed)
			}
			for name, want := range c.Items {
				got, ok := w.item(m, name)
				if !ok || got.Bytes != want.Bytes || got.Recent != want.Recent || got.Undated != want.Undated || got.Fixed != want.Fixed {
					t.Errorf("%s: %+v, want %+v", name, got, want)
				}
			}
		})
	}
	if ran != 12 {
		t.Fatalf("%d of Wappie's sets ran", ran)
	}
}

// Two numbers sharing an object, an object nothing references, and a
// deleted number under quarantine with its purge date: the items and the
// shared bytes sum to the workspace's totals, the deleted number listed
// deleted with its purge_at.
func TestUsageTotalsMatchTenantTotals(t *testing.T) {
	w := newUsageWorld(t)
	now := time.Now().UTC().Truncate(time.Second)
	day := func(d int) *string { s := now.AddDate(0, 0, d).Format(time.RFC3339); return &s }
	w.seed(t, []usageRow{
		{ID: "m1", Kind: "message", Item: "a", TS: day(-1), Bytes: 100},
		{ID: "m2", Kind: "message", Item: "b", TS: day(-200), Bytes: 200},
		{ID: "m3", Kind: "message", Item: "gone", TS: day(-3), Bytes: 300},
		{ID: "o1", Kind: "object", Refs: []string{"m1", "m2"}, Bytes: 7000},
		{ID: "o2", Kind: "object", Refs: []string{}, Bytes: 500},
		{ID: "o3", Kind: "object", Refs: []string{"m3"}, Bytes: 900},
		{ID: "c1", Kind: "fixed", What: "chat", Item: "a", Bytes: 40},
	})
	ctx := context.Background()
	purge := now.Add(30 * 24 * time.Hour)
	if err := pg.InTenantTx(ctx, w.pool, w.tenant.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.device_quarantine', 'on', true)`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE devices SET deleted_at = clock_timestamp(), purge_after = $2, paused = true, pause_cause = 'deletion'
			WHERE id = $1`, w.devices["gone"], purge)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	m, err := w.c.MeasureUsage(ctx, w.tenant)
	if err != nil {
		t.Fatal(err)
	}
	sum := m.Shared
	for _, it := range m.Items {
		sum += it.Bytes
	}
	if sum != m.Total || m.Total != 100+200+300+7000+500+900+40 || m.Shared != 7500 {
		t.Fatalf("items and shared %d, total %d, shared %d", sum, m.Total, m.Shared)
	}
	gone, ok := w.item(m, "gone")
	if !ok || gone.State != SnapshotDeleted || gone.PurgeAt == nil || !gone.PurgeAt.Equal(purge) || gone.Bytes != 1200 {
		t.Fatalf("the deleted number: %+v", gone)
	}
	if a, _ := w.item(m, "a"); a.State != SnapshotActive || a.Fixed != 40 || a.Recent != 100 {
		t.Fatalf("number a: %+v", a)
	}
	// A total that does not add up is no report.
	if _, err := w.pool.Exec(ctx, `UPDATE tenants SET storage_archive_bytes = storage_archive_bytes + 1 WHERE id = $1`, w.tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := w.c.MeasureUsage(ctx, w.tenant); !errors.Is(err, ErrUsageMismatch) {
		t.Fatalf("a mismatch: %v", err)
	}
}

// A message with no date, its media's object and its AI row are undated;
// chats, contacts and group members are fixed, never recent nor undated.
func TestUsageUndatedAndFixed(t *testing.T) {
	w := newUsageWorld(t)
	w.seed(t, []usageRow{
		{ID: "m1", Kind: "message", Item: "a", Bytes: 100},
		{ID: "t1", Kind: "transcript", Of: "m1", Bytes: 30},
		{ID: "o1", Kind: "object", Refs: []string{"m1"}, Bytes: 5000},
		{ID: "c1", Kind: "fixed", What: "chat", Item: "a", Bytes: 10},
		{ID: "k1", Kind: "fixed", What: "contact", Item: "a", Bytes: 20},
		{ID: "p1", Kind: "fixed", What: "group_member", Item: "a", Bytes: 40},
	})
	m := w.measureAt(t, time.Now())
	a, ok := w.item(m, "a")
	if !ok || a.Bytes != 5200 || a.Undated != 5130 || a.Fixed != 70 || a.Recent != 0 {
		t.Fatalf("number a: %+v", a)
	}
}

// A date after measured_at counts as measured_at: recent.
func TestUsageFutureDateCountsAsMeasuredAt(t *testing.T) {
	w := newUsageWorld(t)
	future := time.Now().Add(400 * 24 * time.Hour).UTC().Format(time.RFC3339)
	w.seed(t, []usageRow{{ID: "m1", Kind: "message", Item: "a", TS: &future, Bytes: 600}})
	if a, _ := w.item(w.measureAt(t, time.Now()), "a"); a.Recent != 600 || a.Undated != 0 {
		t.Fatalf("a future-dated message: %+v", a)
	}
}

// The seq rises across a restart and a clock step back: a row set ahead of
// the clock gives the next one +1.
func TestUsageSeqRisesAcrossRestartAndClockStep(t *testing.T) {
	w := newUsageWorld(t)
	ctx := context.Background()
	first, err := w.c.MeasureUsage(ctx, w.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if ms := time.Now().UnixMilli(); first.Seq < ms-60_000 || first.Seq > ms+60_000 {
		t.Fatalf("the first seq %d is not the clock in milliseconds (%d)", first.Seq, ms)
	}
	ahead := time.Now().Add(time.Hour).UnixMilli()
	if _, err := w.pool.Exec(ctx, `UPDATE contract_usage_seq SET usage_seq = $2 WHERE workspace_id = $1`, w.tenant, ahead); err != nil {
		t.Fatal(err)
	}
	next, err := w.c.MeasureUsage(ctx, w.tenant)
	if err != nil || next.Seq != ahead+1 {
		t.Fatalf("after the clock stepped back: %d %v, want %d", next.Seq, err, ahead+1)
	}
}

// Two measurements at once: the second waits on the seq row, then runs
// again on a later snapshot, so the later seq sees what committed between.
func TestUsageSeqSerializationRetry(t *testing.T) {
	w := newUsageWorld(t)
	ctx := context.Background()
	w.seed(t, []usageRow{{ID: "m1", Kind: "message", Item: "a", Bytes: 100}})
	held, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	usageSeqTaken = func(pgx.Tx) {
		once.Do(func() {
			close(held)
			<-release
		})
	}
	t.Cleanup(func() { usageSeqTaken = nil })
	var first UsageMeasure
	var firstErr error
	done := make(chan struct{})
	go func() {
		first, firstErr = w.c.MeasureUsage(ctx, w.tenant)
		close(done)
	}()
	<-held
	second := make(chan UsageMeasure, 1)
	go func() {
		m, err := w.c.MeasureUsage(ctx, w.tenant)
		if err != nil {
			t.Error(err)
		}
		second <- m
	}()
	time.Sleep(200 * time.Millisecond)
	// A message commits while the first holds the row.
	w.seed(t, []usageRow{{ID: "m2", Kind: "message", Item: "a", Bytes: 50}})
	close(release)
	<-done
	if firstErr != nil {
		t.Fatal(firstErr)
	}
	s := <-second
	if s.Seq <= first.Seq || s.Total != first.Total+50 {
		t.Fatalf("the later measurement: seq %d after %d, total %d after %d", s.Seq, first.Seq, s.Total, first.Total)
	}
}

// A measurement held open (its seq row locked, its snapshot taken) blocks
// no capture: a message, a media row and a deletion commit in another
// connection within a second; and its first measurement takes no lock on
// the workspace's record, which a snapshot and an event's write take.
func TestUsageScanDoesNotBlockCapture(t *testing.T) {
	w := newUsageWorld(t)
	ctx := context.Background()
	if _, err := w.pool.Exec(ctx, `INSERT INTO contract_workspaces (workspace_id, kind) VALUES ($1, 'team')`, w.tenant); err != nil {
		t.Fatal(err)
	}
	w.seed(t, []usageRow{{ID: "m1", Kind: "message", Item: "a", Bytes: 100}})
	held, release := make(chan struct{}), make(chan struct{})
	usageSeqTaken = func(pgx.Tx) {
		close(held)
		<-release
	}
	t.Cleanup(func() { usageSeqTaken = nil })
	done := make(chan error, 1)
	go func() {
		_, err := w.c.MeasureUsage(ctx, w.tenant)
		done <- err
	}()
	<-held
	within := func(what string, f func(ctx context.Context) error) {
		t.Helper()
		cctx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		if err := f(cctx); err != nil {
			t.Errorf("%s while a measurement is held: %v", what, err)
		}
	}
	dev := w.devices["a"]
	within("a message, its media and a deletion", func(ctx context.Context) error {
		return pg.InTenantTx(ctx, w.pool, w.tenant.String(), func(tx pgx.Tx) error {
			var uid uuid.UUID
			if err := tx.QueryRow(ctx, `INSERT INTO messages (tenant_id, device_id, seq, wa_id, chat_key, kind, type, source, ts)
				VALUES ($1, $2, 99, 'new', 'chat', 'message', 'image', 'live', clock_timestamp()) RETURNING uid`, w.tenant, dev).Scan(&uid); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO media (message_uid, tenant_id, media_type, object_key, object_size)
				VALUES ($1, $2, 'image', 'objects/new', 10)`, uid, w.tenant); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO item_events (event_id, tenant_id, type, item_id, dedupe_key, occurred_at, actor_kind, deleted_at, purge_after)
				VALUES (uuidv7(), $1, 'deleted', $2, 'deleted:x', clock_timestamp(), 'person', clock_timestamp(), clock_timestamp() + interval '30 days')`,
				w.tenant, dev)
			return err
		})
	})
	within("the record's lock", func(ctx context.Context) error {
		_, err := w.pool.Exec(ctx, `SELECT 1 FROM contract_workspaces WHERE workspace_id = $1 FOR UPDATE`, w.tenant)
		return err
	})
	within("a numbered snapshot", func(ctx context.Context) error {
		_, _, err := w.c.SnapshotNumbered(ctx, w.tenant)
		return err
	})
	close(release)
	if err := <-done; err != nil && !strings.Contains(err.Error(), "mismatch") {
		t.Fatal(err)
	}
}
