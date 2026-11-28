package migrate

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/pgtest"
)

// Migration 0054, trial codes, the two events, placed_at and the link
// checks (E0 slice 19): its backfill, its down-step and its CHECKs.

// TestMigration0054Backfill: a number with a recovery, one moved into its
// workspace, one with neither, and a pairing that never completed; each
// gets the latest of its creation, its recovery and its move in, and the
// pending row stays NULL. updated_at does not move.
func TestMigration0054Backfill(t *testing.T) {
	ctx := context.Background()
	lg := quietLogger(t)
	pool := pgtest.Empty(t)
	if err := run(ctx, pool, lg, migrationsThrough(t, 53)); err != nil {
		t.Fatal(err)
	}
	w := newContractWorld(t, pool)
	var other uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO tenants(name) VALUES ('other') RETURNING id`).Scan(&other); err != nil {
		t.Fatal(err)
	}
	created := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	recovered, movedIn, movedElsewhere := created.Add(48*time.Hour), created.Add(72*time.Hour), created.Add(96*time.Hour)
	var plain, recovery, moved, pending uuid.UUID
	w.exec(ctx, t, func(tx pgx.Tx) error {
		plain = w.device
		for _, d := range []struct {
			id  *uuid.UUID
			sql string
		}{
			{&recovery, `INSERT INTO devices(tenant_id,label,lid) VALUES ($1,'Rec','100000000000002@lid') RETURNING id`},
			{&moved, `INSERT INTO devices(tenant_id,label,pn) VALUES ($1,'Mov','15550100003@s.whatsapp.net') RETURNING id`},
			{&pending, `INSERT INTO devices(tenant_id,label) VALUES ($1,'Pending') RETURNING id`},
		} {
			if err := tx.QueryRow(ctx, d.sql, w.tenant).Scan(d.id); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `ALTER TABLE devices DISABLE TRIGGER devices_touch`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE devices SET created_at = $1, updated_at = $1`, created); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `ALTER TABLE devices ENABLE TRIGGER devices_touch`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO item_events(event_id,tenant_id,type,item_id,dedupe_key,occurred_at,actor_kind,deleted_at)
			VALUES (uuidv7(),$1,'recovered',$2,'recovered:a',$3,'person',$4)`, w.tenant, recovery, recovered, created)
		return err
	})
	// A move into this workspace, and a later move of another number out
	// of it, which does not count for that number here.
	if _, err := pool.Exec(ctx, `ALTER TABLE device_transfers DISABLE ROW LEVEL SECURITY`); err != nil {
		t.Fatal(err)
	}
	for _, m := range []struct {
		device, from, to uuid.UUID
		at               time.Time
	}{{moved, other, w.tenant, movedIn}, {plain, w.tenant, other, movedElsewhere}} {
		if _, err := pool.Exec(ctx, `INSERT INTO device_transfers(device_id,source_workspace_id,target_workspace_id,actor_id,completed_at)
			VALUES ($1,$2,$3,$4,$5)`, m.device, m.from, m.to, w.owner, m.at); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `ALTER TABLE device_transfers ENABLE ROW LEVEL SECURITY; ALTER TABLE device_transfers FORCE ROW LEVEL SECURITY`); err != nil {
		t.Fatal(err)
	}
	if err := run(ctx, pool, lg, migrationsThrough(t, 54)); err != nil {
		t.Fatal(err)
	}
	want := map[uuid.UUID]*time.Time{plain: &created, recovery: &recovered, moved: &movedIn, pending: nil}
	w.exec(ctx, t, func(tx pgx.Tx) error {
		for id, at := range want {
			var placed *time.Time
			var updated time.Time
			if err := tx.QueryRow(ctx, `SELECT placed_at, updated_at FROM devices WHERE id = $1`, id).Scan(&placed, &updated); err != nil {
				return err
			}
			if (placed == nil) != (at == nil) || (placed != nil && !placed.Equal(*at)) {
				t.Errorf("%s: placed_at %v, want %v", id, placed, at)
			}
			if !updated.Equal(created) {
				t.Errorf("%s: updated_at moved to %v", id, updated)
			}
		}
		return nil
	})
}

// TestMigration0054DownStep: 0054's down-step refuses while a later
// migration is applied, entitlements are on, codes are on with a key, or
// an event of the two types is still owed, and changes nothing then; else
// it says what it drops and leaves 53's schema but the trial key's table,
// which it keeps: 0054 again reuses the same key.
func TestMigration0054DownStep(t *testing.T) {
	ctx := context.Background()
	lg := quietLogger(t)
	base := pgtest.Empty(t)
	if err := run(ctx, base, lg, migrationsThrough(t, 53)); err != nil {
		t.Fatal(err)
	}
	through54 := migrationsThrough(t, 54)
	pool := pgtest.Empty(t)
	if err := run(ctx, pool, lg, through54); err != nil {
		t.Fatal(err)
	}
	w := newContractWorld(t, pool)
	if _, err := pool.Exec(ctx, `INSERT INTO contract_workspaces(workspace_id,kind,wversion,status) VALUES ($1,'team',2,'open')`, w.tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO contract_trial_key(envelope) VALUES ('\x01')`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO contract_link_checks(workspace_id,act,answered,would_refuse) VALUES ($1,'link',true,'new_links_off')`,
		w.tenant); err != nil {
		t.Fatal(err)
	}
	var owed uuid.UUID
	w.exec(ctx, t, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE devices SET placed_at = clock_timestamp() WHERE id = $1`, w.device); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO item_events(event_id,tenant_id,type,item_id,dedupe_key,occurred_at,actor_kind,ledgered_at,settled_at,outcome)
			VALUES (uuidv7(),$1,'linked',$2,'linked:a',now(),'person',now(),now(),'accepted')`, w.tenant, w.device); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO item_events(event_id,tenant_id,type,item_id,dedupe_key,occurred_at,actor_kind,ledgered_at)
			VALUES (uuidv7(),$1,'identity_updated',$2,'identity_updated:a',now(),'app',now()) RETURNING event_id`, w.tenant, w.device).Scan(&owed)
	})

	counts := func() (rows int, has54 bool, events int) {
		t.Helper()
		w.exec(ctx, t, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM schema_migrations),
				EXISTS(SELECT 1 FROM schema_migrations WHERE version = 54), (SELECT count(*) FROM item_events)`).Scan(&rows, &has54, &events)
		})
		return rows, has54, events
	}
	refused := func(want string) {
		t.Helper()
		before, _, events := counts()
		if _, err := pool.Exec(ctx, downStepSQL(t, 54)); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("the down-step with %s: %v", want, err)
		}
		if rows, has54, after := counts(); rows != before || !has54 || after != events {
			t.Fatalf("a refused down-step changed something: %d ledger rows (was %d), version 54 %v, %d events (was %d)",
				rows, before, has54, after, events)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO schema_migrations(version,name,checksum,duration_ms) VALUES (55,'later','x',0)`); err != nil {
		t.Fatal(err)
	}
	refused("a migration after 0054 is applied")
	if _, err := pool.Exec(ctx, `DELETE FROM schema_migrations WHERE version = 55`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE contract_ent_state SET mode = 'observe'`); err != nil {
		t.Fatal(err)
	}
	refused("entitlements are on")
	if _, err := pool.Exec(ctx, `UPDATE contract_ent_state SET mode = 'off'`); err != nil {
		t.Fatal(err)
	}
	refused("trial codes are on: run whatserverd contract trial-key suspend first")
	if _, err := pool.Exec(ctx, `UPDATE contract_trial_key_state SET codes = 'suspended'`); err != nil {
		t.Fatal(err)
	}
	refused("events are still owed")
	w.exec(ctx, t, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE item_events SET settled_at = now(), outcome = 'not_sent' WHERE event_id = $1`, owed)
		return err
	})
	// 0053's guard holds while 54 is applied.
	if _, err := pool.Exec(ctx, downStepSQL(t, 53)); err == nil || !strings.Contains(err.Error(), "a migration after 0053 is applied") {
		t.Fatalf("0053's down-step while 54 is applied: %v", err)
	}

	cfg := pool.Config()
	var mu sync.Mutex
	var notices []string
	cfg.ConnConfig.OnNotice = func(_ *pgconn.PgConn, n *pgconn.Notice) {
		mu.Lock()
		defer mu.Unlock()
		notices = append(notices, n.Message)
	}
	operator, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer operator.Close()
	if _, err := operator.Exec(ctx, downStepSQL(t, 54)); err != nil {
		t.Fatalf("the down-step: %v", err)
	}
	mu.Lock()
	want := "dropping 2 linked and identity_updated rows, 1 placed numbers, 1 link checks; the trial key is kept"
	if !slices.Contains(notices, want) {
		t.Errorf("the down-step's notices: %q, want %q", notices, want)
	}
	mu.Unlock()

	// 53's schema, and the kept key's table, function and triggers.
	kept := func(fact string) bool {
		return strings.Contains(fact, "contract_trial_key")
	}
	var got []string
	for _, f := range schemaShape(t, pool) {
		if !kept(f) {
			got = append(got, f)
		}
	}
	want53 := schemaShape(t, base)
	if !slices.Equal(got, want53) {
		for _, f := range got {
			if !slices.Contains(want53, f) {
				t.Errorf("after the down-step: %q is not 53's", f)
			}
		}
		for _, f := range want53 {
			if !slices.Contains(got, f) {
				t.Errorf("after the down-step: 53's %q is missing", f)
			}
		}
	}
	if err := run(ctx, pool, lg, migrationsThrough(t, 53)); err != nil {
		t.Fatalf("a binary that knows 53 after the down-step: %v", err)
	}
	if err := run(ctx, pool, lg, through54); err != nil {
		t.Fatalf("0054 again: %v", err)
	}
	var keys int
	var codes string
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM contract_trial_key), codes FROM contract_trial_key_state`).
		Scan(&keys, &codes); err != nil || keys != 1 || codes != "on" {
		t.Fatalf("after 0054 again: %d keys, codes %q, %v", keys, codes, err)
	}
	// And the chain: 0054 down (no key opened, codes on: suspended first),
	// then 0053 down.
	if _, err := pool.Exec(ctx, `UPDATE contract_trial_key_state SET codes = 'suspended'`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, downStepSQL(t, 54)); err != nil {
		t.Fatalf("0054's down-step again: %v", err)
	}
	if _, err := pool.Exec(ctx, downStepSQL(t, 53)); err != nil {
		t.Fatalf("0053's down-step after 0054's: %v", err)
	}
}

// TestTrialKeyNeverRotated: the envelope's one row is inserted once; an
// UPDATE and a DELETE raise, and a second row is refused. The state's
// CHECKs and the notice of a key inserted or of the codes switch.
func TestTrialKeyNeverRotated(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Fresh(t, Run)
	if _, err := pool.Exec(ctx, `INSERT INTO contract_trial_key(envelope) VALUES ('\x01')`); err != nil {
		t.Fatal(err)
	}
	for name, sql := range map[string]string{
		"an update":      `UPDATE contract_trial_key SET envelope = '\x02'`,
		"a delete":       `DELETE FROM contract_trial_key`,
		"a second row":   `INSERT INTO contract_trial_key(id, envelope) VALUES (false, '\x02')`,
		"an empty key":   `INSERT INTO contract_trial_key(envelope) VALUES ('')`,
		"a codes switch": `UPDATE contract_trial_key_state SET codes = 'off'`,
		"an open alone":  `UPDATE contract_trial_key_state SET opened_at = clock_timestamp()`,
		"an error alone": `UPDATE contract_trial_key_state SET open_error = 'decrypt'`,
		"a short sha":    `UPDATE contract_trial_key_state SET opened_at = clock_timestamp(), envelope_sha256 = '\x01'`,
		"a check of no reason": `INSERT INTO contract_link_checks(workspace_id, act, answered, would_refuse)
			VALUES (uuidv7(), 'link', true, 'because')`,
		"a check of no act": `INSERT INTO contract_link_checks(workspace_id, act, answered) VALUES (uuidv7(), 'relink', true)`,
	} {
		if _, err := pool.Exec(ctx, sql); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	var envelope []byte
	if err := pool.QueryRow(ctx, `SELECT envelope FROM contract_trial_key`).Scan(&envelope); err != nil || string(envelope) != "\x01" {
		t.Fatalf("the key after: %x %v", envelope, err)
	}
	_, err := pool.Exec(ctx, `UPDATE contract_trial_key SET envelope = '\x02'`)
	if err == nil || !strings.Contains(err.Error(), "the trial key is never rotated") {
		t.Fatalf("an update: %v", err)
	}

	conn, err := pgx.ConnectConfig(ctx, pool.Config().ConnConfig.Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }() //nolint:errcheck // a test's listener
	if _, err := conn.Exec(ctx, `LISTEN wappie_contract_mode`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE contract_trial_key_state SET codes = 'suspended'`); err != nil {
		t.Fatal(err)
	}
	wait, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	n, err := conn.WaitForNotification(wait)
	if err != nil || n.Payload != "trial_key" {
		t.Fatalf("the codes switch's notice: %+v %v", n, err)
	}
}
