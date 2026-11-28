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

// Migration 0053, the contract's entitlements and usage part in observe
// (E0 slices 17 and 18): its down-step, its defaults and its CHECKs.

// TestMigration0053DownStep: 0053's down-step refuses while a later
// migration is applied, the follower is not off or usage is not off, and
// changes nothing then; with both off it says what it drops and leaves
// exactly 52's schema, so a binary that knows 52 starts on it, 0053 applies
// again, and 0052's own guard refuses while 53 is applied.
func TestMigration0053DownStep(t *testing.T) {
	ctx := context.Background()
	lg := quietLogger(t)
	base := pgtest.Empty(t)
	if err := run(ctx, base, lg, migrationsThrough(t, 52)); err != nil {
		t.Fatal(err)
	}
	through53 := migrationsThrough(t, 53)
	pool := pgtest.Empty(t)
	if err := run(ctx, pool, lg, through53); err != nil {
		t.Fatal(err)
	}
	w := newContractWorld(t, pool)
	named, kept := w.tenant, uuid.New()
	for _, step := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO contract_workspaces(workspace_id,kind,wversion,status) VALUES ($1,'team',2,'open')`, []any{named}},
		{`INSERT INTO contract_ent_docs(workspace_id,generation,version,doc,mode,applied_at) VALUES ($1,uuidv7(),3,'{}','observe',clock_timestamp())`, []any{named}},
		{`INSERT INTO contract_ent_docs(workspace_id,generation,version,doc,mode) VALUES ($1,uuidv7(),4,'{}','observe')`, []any{kept}},
		{`INSERT INTO contract_ent_refusals(generation,seq,code) VALUES (uuidv7(),5,'invalid_document')`, nil},
		{`INSERT INTO contract_ent_brakes(workspace_id,platform_told,by_kind) VALUES ($1,false,'enforce_in_e0')`, []any{named}},
		{`INSERT INTO contract_usage_seq(workspace_id,usage_seq) VALUES ($1,7)`, []any{named}},
		{`INSERT INTO contract_usage(workspace_id) VALUES ($1)`, []any{named}},
		{`INSERT INTO contract_usage_reports(workspace_id,usage_seq,measured_at,body) VALUES ($1,7,clock_timestamp(),'{}')`, []any{named}},
	} {
		if _, err := pool.Exec(ctx, step.sql, step.args...); err != nil {
			t.Fatalf("%s: %v", step.sql, err)
		}
	}

	counts := func() (rows int, has53 bool, objects int) {
		t.Helper()
		if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM schema_migrations),
			EXISTS(SELECT 1 FROM schema_migrations WHERE version = 53),
			(SELECT count(*) FROM pg_class WHERE relname LIKE 'contract_%' AND relnamespace = current_schema()::regnamespace)`).
			Scan(&rows, &has53, &objects); err != nil {
			t.Fatal(err)
		}
		return rows, has53, objects
	}
	refused := func(want string) {
		t.Helper()
		before, _, objects := counts()
		var docs int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM contract_ent_docs`).Scan(&docs); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, downStepSQL(t, 53)); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("the down-step with %s: %v", want, err)
		}
		var left int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM contract_ent_docs`).Scan(&left); err != nil {
			t.Fatal(err)
		}
		if rows, has53, after := counts(); rows != before || !has53 || after != objects || left != docs {
			t.Fatalf("a refused down-step changed something: %d ledger rows (was %d), version 53 %v, %d contract objects (was %d), %d documents (was %d)",
				rows, before, has53, after, objects, left, docs)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO schema_migrations(version,name,checksum,duration_ms) VALUES (54,'later','x',0)`); err != nil {
		t.Fatal(err)
	}
	refused("a migration after 0053 is applied")
	if _, err := pool.Exec(ctx, `DELETE FROM schema_migrations WHERE version = 54`); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ set, want string }{
		{`mode = 'observe'`, "entitlements are on: run whatserverd contract entitlements off first"},
		{`mode = 'enforce'`, "entitlements are on: run whatserverd contract entitlements off first"},
		{`usage = 'on'`, "usage is on: run whatserverd contract entitlements usage off first"},
	} {
		if _, err := pool.Exec(ctx, `UPDATE contract_ent_state SET `+c.set); err != nil {
			t.Fatal(err)
		}
		refused(c.want)
		if _, err := pool.Exec(ctx, `UPDATE contract_ent_state SET mode = 'off', usage = 'off'`); err != nil {
			t.Fatal(err)
		}
	}
	// 0052's guard holds while 53 is applied.
	if _, err := pool.Exec(ctx, downStepSQL(t, 52)); err == nil || !strings.Contains(err.Error(), "a migration after 0052 is applied") {
		t.Fatalf("0052's down-step while 53 is applied: %v", err)
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
	if _, err := operator.Exec(ctx, downStepSQL(t, 53)); err != nil {
		t.Fatalf("the down-step: %v", err)
	}
	mu.Lock()
	want := "dropping 2 documents (1 applied), 1 refusals owed, 1 brakes, 1 usage seqs, 1 usage reports"
	if !slices.Contains(notices, want) {
		t.Errorf("the down-step's notices: %q, want %q", notices, want)
	}
	mu.Unlock()

	want52, got := schemaShape(t, base), schemaShape(t, pool)
	if len(got) != len(want52) {
		t.Fatalf("after the down-step: %d schema facts, 52 has %d", len(got), len(want52))
	}
	for i := range want52 {
		if got[i] != want52[i] {
			t.Fatalf("after the down-step: %q where 52 has %q", got[i], want52[i])
		}
	}
	if err := run(ctx, pool, lg, migrationsThrough(t, 52)); err != nil {
		t.Fatalf("a binary that knows 52 after the down-step: %v", err)
	}
	if err := run(ctx, pool, lg, through53); err != nil {
		t.Fatalf("0053 again: %v", err)
	}
	var mode, usage string
	var docs, seqs int
	if err := pool.QueryRow(ctx, `SELECT mode, usage, (SELECT count(*) FROM contract_ent_docs), (SELECT count(*) FROM contract_usage_seq)
		FROM contract_ent_state`).Scan(&mode, &usage, &docs, &seqs); err != nil || mode != "off" || usage != "off" || docs != 0 || seqs != 0 {
		t.Fatalf("after 0053 again: mode %q, usage %q, %d documents, %d seqs, %v", mode, usage, docs, seqs, err)
	}
	// And the chain: 0053 down, 0052 down, then 0051's binary.
	if _, err := pool.Exec(ctx, downStepSQL(t, 53)); err != nil {
		t.Fatalf("0053's down-step again: %v", err)
	}
	if _, err := pool.Exec(ctx, downStepSQL(t, 52)); err != nil {
		t.Fatalf("0052's down-step after 0053's: %v", err)
	}
	if err := run(ctx, pool, lg, migrationsThrough(t, 51)); err != nil {
		t.Fatalf("a binary that knows 51: %v", err)
	}
}

// Every CHECK 0053 adds, each refused beside the shapes it accepts; the one
// state row, off and off; the mode notice; and the usage notice.
func TestMigration0053Checks(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Fresh(t, Run)
	var mode, usage string
	var rows int
	if err := pool.QueryRow(ctx, `SELECT mode, usage, (SELECT count(*) FROM contract_ent_state) FROM contract_ent_state`).
		Scan(&mode, &usage, &rows); err != nil || mode != "off" || usage != "off" || rows != 1 {
		t.Fatalf("contract_ent_state: mode %q, usage %q, %d rows, %v", mode, usage, rows, err)
	}
	for name, sql := range map[string]string{
		"a second state row":            `INSERT INTO contract_ent_state(id) VALUES (false)`,
		"a mode of no kind":             `UPDATE contract_ent_state SET mode = 'on'`,
		"a usage of no kind":            `UPDATE contract_ent_state SET usage = 'observe'`,
		"a cursor below zero":           `UPDATE contract_ent_state SET feed_cursor = -1`,
		"a feed error with no time":     `UPDATE contract_ent_state SET feed_error = 'gone'`,
		"an ack error time alone":       `UPDATE contract_ent_state SET ack_error_at = clock_timestamp()`,
		"an ack with no time":           `UPDATE contract_ent_state SET acked_through = 3`,
		"a page with no first read":     `UPDATE contract_ent_state SET last_page_at = clock_timestamp()`,
		"a placeholder with a version":  `INSERT INTO contract_ent_docs(workspace_id, version) VALUES (uuidv7(), 3)`,
		"a placeholder with a mode":     `INSERT INTO contract_ent_docs(workspace_id, mode) VALUES (uuidv7(), 'observe')`,
		"a document with no mode":       `INSERT INTO contract_ent_docs(workspace_id, version, doc) VALUES (uuidv7(), 3, '{}')`,
		"a placeholder applied":         `INSERT INTO contract_ent_docs(workspace_id, applied_at) VALUES (uuidv7(), clock_timestamp())`,
		"a document mode of no kind":    `INSERT INTO contract_ent_docs(workspace_id, version, doc, mode) VALUES (uuidv7(), 3, '{}', 'off')`,
		"a state of no kind":            `INSERT INTO contract_ent_docs(workspace_id, version, doc, mode, state) VALUES (uuidv7(), 3, '{}', 'observe', 'gone')`,
		"a version of 0":                `INSERT INTO contract_ent_docs(workspace_id, version, doc, mode) VALUES (uuidv7(), 0, '{}', 'observe')`,
		"a generation with no version":  `INSERT INTO contract_ent_docs(workspace_id, generation, doc, mode) VALUES (uuidv7(), uuidv7(), '{}', 'observe')`,
		"a freshness hold not held":     `INSERT INTO contract_ent_docs(workspace_id, feed_fresh_at) VALUES (uuidv7(), clock_timestamp())`,
		"a GET error with no time":      `INSERT INTO contract_ent_docs(workspace_id, get_error) VALUES (uuidv7(), 'unavailable')`,
		"a cap side of no kind":         `INSERT INTO contract_ent_docs(workspace_id, cap_side) VALUES (uuidv7(), 'under')`,
		"a refusal of no code":          `INSERT INTO contract_ent_refusals(generation, seq, code) VALUES (uuidv7(), 1, 'another_workspace')`,
		"a refusal at seq 0":            `INSERT INTO contract_ent_refusals(generation, seq, code) VALUES (uuidv7(), 0, 'invalid_document')`,
		"a brake of no kind":            `INSERT INTO contract_ent_brakes(workspace_id, platform_told, by_kind) VALUES (uuidv7(), false, 'preflight')`,
		"a usage seq below zero":        `INSERT INTO contract_usage_seq(workspace_id, usage_seq) VALUES (uuidv7(), -1)`,
		"a usage row of no workspace":   `INSERT INTO contract_usage(workspace_id) VALUES (uuidv7())`,
		"a report at seq 0":             `INSERT INTO contract_usage_reports(workspace_id, usage_seq, measured_at, body) VALUES (uuidv7(), 0, clock_timestamp(), '{}')`,
		"a usage error with no time":    `INSERT INTO contract_usage(workspace_id, error) SELECT workspace_id, 'timeout' FROM contract_workspaces LIMIT 1`,
		"a usage trigger of no kind":    `INSERT INTO contract_usage(workspace_id, due_trigger) SELECT workspace_id, 'whim' FROM contract_workspaces LIMIT 1`,
		"a negative total":              `INSERT INTO contract_usage(workspace_id, last_total_bytes) SELECT workspace_id, -1 FROM contract_workspaces LIMIT 1`,
		"a usage row's tries below 0":   `INSERT INTO contract_usage(workspace_id, tries) SELECT workspace_id, -1 FROM contract_workspaces LIMIT 1`,
		"a placeholder GET tries below": `INSERT INTO contract_ent_docs(workspace_id, get_tries) VALUES (uuidv7(), -1)`,
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO contract_workspaces(workspace_id,kind) VALUES (uuidv7(),'team')
			ON CONFLICT DO NOTHING`); err != nil {
			t.Fatal(err)
		}
		tag, err := pool.Exec(ctx, sql)
		code := sqlState(err)
		if code != "23514" && code != "23505" && code != "23503" {
			t.Errorf("%s: %v (%d rows), want a violation", name, err, tag.RowsAffected())
		}
	}
	for name, sql := range map[string]string{
		"a placeholder":           `INSERT INTO contract_ent_docs(workspace_id, get_due_at) VALUES (uuidv7(), clock_timestamp())`,
		"a document kept":         `INSERT INTO contract_ent_docs(workspace_id, generation, version, doc, mode) VALUES (uuidv7(), uuidv7(), 3, '{}', 'enforce')`,
		"a document after reset":  `INSERT INTO contract_ent_docs(workspace_id, doc, mode, applied_at) VALUES (uuidv7(), '{}', 'observe', clock_timestamp())`,
		"a held-back placeholder": `INSERT INTO contract_ent_docs(workspace_id, feed_held_back, feed_fresh_at) VALUES (uuidv7(), true, clock_timestamp())`,
	} {
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	// The two notices.
	listen, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Release()
	if _, err := listen.Exec(ctx, `LISTEN wappie_contract_mode; LISTEN wappie_contract_usage`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE contract_ent_state SET mode = 'observe'`); err != nil {
		t.Fatal(err)
	}
	// Every test schema shares one database, whose notices reach every
	// session listening: another test's are skipped.
	wait, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for {
		n, err := listen.Conn().WaitForNotification(wait)
		if err != nil {
			t.Fatalf("the mode notice: %v", err)
		}
		if n.Channel == "wappie_contract_mode" && n.Payload == "entitlements" {
			break
		}
	}
	w := newContractWorld(t, pool)
	w.exec(ctx, t, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO item_events(event_id,tenant_id,type,item_id,dedupe_key,occurred_at,actor_kind,deleted_at,purge_after)
			VALUES (uuidv7(),$1,'deleted',$2,'deleted:1',clock_timestamp(),'person',clock_timestamp(),clock_timestamp()+interval '30 days')`,
			w.tenant, w.device)
		return err
	})
	for {
		n, err := listen.Conn().WaitForNotification(wait)
		if err != nil {
			t.Fatalf("the usage notice: %v", err)
		}
		if n.Channel == "wappie_contract_usage" && n.Payload == w.tenant.String() {
			break
		}
	}
}
