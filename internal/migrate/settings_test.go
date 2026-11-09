package migrate

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
)

// Migration 0052, the contract's settings part (step 12a): its down-step,
// every CHECK, the backfills, and the triggers that keep a number's logout
// cause and pause times and wake the settings sender.

// at51 is a pool at schema 51, as the release before 12a leaves one.
func at51(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := pgtest.Empty(t)
	if err := run(context.Background(), pool, quietLogger(t), migrationsThrough(t, 51)); err != nil {
		t.Fatal(err)
	}
	return pool
}

// command is a contract_commands row as the CHECK tests write it: the
// columns every row has, and any others by name.
type command map[string]any

func (c command) insert(ctx context.Context, pool *pgxpool.Pool) error {
	row := command{"id": uuid.New(), "generation": uuid.New(), "cseq": 1, "body": []byte(`{}`),
		"body_key": make([]byte, 32), "signed_at": time.Now()}
	for k, v := range c {
		row[k] = v
	}
	cols, args, marks := []string{}, []any{}, []string{}
	for k, v := range row {
		cols = append(cols, k)
		args = append(args, v)
		marks = append(marks, "$"+strconv.Itoa(len(args)))
	}
	_, err := pool.Exec(ctx, `INSERT INTO contract_commands (`+strings.Join(cols, ",")+`) VALUES (`+strings.Join(marks, ",")+`)`, args...)
	return err
}

// decoded is what a command that passed ValidateIn adds to a row.
func decoded(extra command) command {
	c := command{"workspace_id": uuid.New(), "wseq": 1, "kind": "item.rename", "section": "numbers",
		"actor": uuid.New(), "actor_role": "owner", "issued_at": time.Now()}
	for k, v := range extra {
		c[k] = v
	}
	return c
}

// refusedAtTake is a row refused before ValidateIn passed: no decoded
// column, its result invalid_command.
func refusedAtTake(extra command) command {
	c := command{"outcome": "refused", "code": "invalid_command", "result_at": time.Now()}
	for k, v := range extra {
		c[k] = v
	}
	return c
}

// TestMigration0052DownStep: 0052's down-step refuses while a later
// migration is applied or settings are not off, and changes nothing then;
// with settings off it says what it drops, as the operator reads it, and
// leaves exactly 51's schema, so a binary that knows 51 starts on it, 0052
// applies again, and 0051's own guard refuses while 52 is applied.
func TestMigration0052DownStep(t *testing.T) {
	ctx := context.Background()
	lg := quietLogger(t)
	base := at51(t)
	pool := pgtest.Empty(t)
	if err := Run(ctx, pool, lg); err != nil {
		t.Fatal(err)
	}
	w := newContractWorld(t, pool)

	sub := uuid.New()
	for _, step := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO contract_workspaces(workspace_id,kind,wversion,status) VALUES ($1,'team',2,'open')`, []any{w.tenant}},
		{`INSERT INTO contract_accounts(sub,generation,version,status,doc,fresh_at) VALUES ($1,uuidv7(),3,'active','{"v":1}',clock_timestamp())`, []any{sub}},
		{`UPDATE contract_persons SET signed_out_everywhere_at = clock_timestamp() WHERE sub = $1`, []any{sub}},
		{`INSERT INTO security_events(kind,detail) VALUES ('contract_command_invalid','{"why":"mac"}'),('platform_linked','{}')`, nil},
	} {
		if _, err := pool.Exec(ctx, step.sql, step.args...); err != nil {
			t.Fatalf("%s: %v", step.sql, err)
		}
	}
	open := decoded(command{"workspace_id": w.tenant})
	undelivered := decoded(command{"workspace_id": w.tenant, "wseq": 2, "outcome": "ran", "state_seq": 9, "result_at": time.Now()})
	delivered := refusedAtTake(command{"cseq": 3, "delivery": "accepted", "delivered_at": time.Now()})
	for _, c := range []command{open, undelivered, delivered} {
		if err := c.insert(ctx, pool); err != nil {
			t.Fatal(err)
		}
	}

	counts := func() (rows int, has52 bool, objects int) {
		t.Helper()
		if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM schema_migrations),
			EXISTS(SELECT 1 FROM schema_migrations WHERE version = 52),
			(SELECT count(*) FROM pg_class WHERE relname LIKE 'contract_%' AND relnamespace = current_schema()::regnamespace)`).
			Scan(&rows, &has52, &objects); err != nil {
			t.Fatal(err)
		}
		return rows, has52, objects
	}
	refused := func(want string) {
		t.Helper()
		before, _, objects := counts()
		var ledger int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM contract_commands`).Scan(&ledger); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, downStepSQL(t, 52)); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("the down-step with %s: %v", want, err)
		}
		var left int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM contract_commands`).Scan(&left); err != nil {
			t.Fatal(err)
		}
		if rows, has52, after := counts(); rows != before || !has52 || after != objects || left != ledger {
			t.Fatalf("a refused down-step changed something: %d ledger rows (was %d), version 52 %v, %d contract objects (was %d), %d commands (was %d)",
				rows, before, has52, after, objects, left, ledger)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO schema_migrations(version,name,checksum,duration_ms) VALUES (53,'later','x',0)`); err != nil {
		t.Fatal(err)
	}
	refused("a migration after 0052 is applied")
	if _, err := pool.Exec(ctx, `DELETE FROM schema_migrations WHERE version = 53`); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"read", "on"} {
		if _, err := pool.Exec(ctx, `UPDATE contract_settings_state SET mode = $1`, mode); err != nil {
			t.Fatal(err)
		}
		refused("settings are on: run whatserverd contract settings off first")
	}
	if _, err := pool.Exec(ctx, `UPDATE contract_settings_state SET mode = 'off'`); err != nil {
		t.Fatal(err)
	}
	// 0051's guard holds while 52 is applied.
	if _, err := pool.Exec(ctx, downStepSQL(t, 51)); err == nil || !strings.Contains(err.Error(), "a migration after 0051 is applied") {
		t.Fatalf("0051's down-step while 52 is applied: %v", err)
	}

	// The down-step's counts, as the operator reads them.
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
	if _, err := operator.Exec(ctx, downStepSQL(t, 52)); err != nil {
		t.Fatalf("the down-step: %v", err)
	}
	mu.Lock()
	want := "dropping 3 ledger rows (1 without a result, 1 results not delivered), 1 sections, 1 persons (1 signed out everywhere), 1 invalid-command security events"
	if !slices.Contains(notices, want) {
		t.Errorf("the down-step's notices: %q, want %q", notices, want)
	}
	mu.Unlock()

	want51, got := schemaShape(t, base), schemaShape(t, pool)
	if len(got) != len(want51) {
		t.Fatalf("after the down-step: %d schema facts, 51 has %d", len(got), len(want51))
	}
	for i := range want51 {
		if got[i] != want51[i] {
			t.Fatalf("after the down-step: %q where 51 has %q", got[i], want51[i])
		}
	}
	constraint := func(p *pgxpool.Pool) (def string, valid bool) {
		t.Helper()
		if err := p.QueryRow(ctx, `SELECT pg_get_constraintdef(oid), convalidated FROM pg_constraint
			WHERE conname = 'security_events_kind_check' AND connamespace = current_schema()::regnamespace`).Scan(&def, &valid); err != nil {
			t.Fatal(err)
		}
		return def, valid
	}
	if def, valid := constraint(pool); !valid || def != func() string { d, _ := constraint(base); return d }() {
		t.Fatalf("security_events_kind_check after the down-step: %q, validated %v", def, valid)
	}
	var invalid, linked int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM security_events WHERE kind = 'contract_command_invalid'),
		(SELECT count(*) FROM security_events WHERE kind = 'platform_linked')`).Scan(&invalid, &linked); err != nil || invalid != 0 || linked != 1 {
		t.Fatalf("security events after the down-step: %d invalid, %d linked, %v", invalid, linked, err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM security_events`); err == nil || !strings.Contains(err.Error(), "insert-only") {
		t.Fatalf("security_events after the down-step: %v", err)
	}

	if err := run(ctx, pool, lg, migrationsThrough(t, 51)); err != nil {
		t.Fatalf("a binary that knows 51 after the down-step: %v", err)
	}
	if err := Run(ctx, pool, lg); err != nil {
		t.Fatalf("0052 again: %v", err)
	}
	var mode string
	var sections, persons, ledger int
	if err := pool.QueryRow(ctx, `SELECT mode, (SELECT count(*) FROM contract_sections WHERE workspace_id = $1 AND section = 'numbers'),
		(SELECT count(*) FROM contract_persons WHERE sub = $2 AND signed_out_everywhere_at IS NULL), (SELECT count(*) FROM contract_commands)
		FROM contract_settings_state`, w.tenant, sub).Scan(&mode, &sections, &persons, &ledger); err != nil ||
		mode != "off" || sections != 1 || persons != 1 || ledger != 0 {
		t.Fatalf("after 0052 again: mode %q, %d sections, %d persons, %d commands, %v", mode, sections, persons, ledger, err)
	}

	// And the chain: 0052 down, 0051 down, then 0050's binary.
	if _, err := pool.Exec(ctx, downStepSQL(t, 52)); err != nil {
		t.Fatalf("0052's down-step again: %v", err)
	}
	if _, err := pool.Exec(ctx, downStepSQL(t, 51)); err != nil {
		t.Fatalf("0051's down-step after 0052's: %v", err)
	}
	if err := run(ctx, pool, lg, migrationsThrough(t, 50)); err != nil {
		t.Fatalf("a binary that knows 50: %v", err)
	}
}

// Every CHECK 0052 adds, each refused in its own statement with 23514
// beside the shapes it accepts; the one settings row; and no row-level
// security on the new tables. The devices CHECKs are proved with their
// triggers lifted in a transaction that rolls back, since the triggers own
// those columns.
func TestMigration0052Checks(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Fresh(t, Run)
	w := newContractWorld(t, pool)

	var mode string
	var cutover *time.Time
	var rows int
	if err := pool.QueryRow(ctx, `SELECT mode, label_cutover_at, (SELECT count(*) FROM contract_settings_state) FROM contract_settings_state`).
		Scan(&mode, &cutover, &rows); err != nil || mode != "off" || cutover == nil || rows != 1 {
		t.Fatalf("contract_settings_state: mode %q, cutover %v, %d rows, %v", mode, cutover, rows, err)
	}
	for name, sql := range map[string]string{
		"a second settings row":         `INSERT INTO contract_settings_state(id) VALUES (false)`,
		"a mode Wappie lacks":           `UPDATE contract_settings_state SET mode = 'enforce'`,
		"a cursor below zero":           `UPDATE contract_settings_state SET feed_cursor = -1`,
		"a feed error with no time":     `UPDATE contract_settings_state SET feed_error = 'gone'`,
		"a feed error time alone":       `UPDATE contract_settings_state SET feed_error_at = clock_timestamp()`,
		"a results error with no time":  `UPDATE contract_settings_state SET results_error = 'gone'`,
		"a results error time alone":    `UPDATE contract_settings_state SET results_error_at = clock_timestamp()`,
		"a read with no first read":     `UPDATE contract_settings_state SET read_at = clock_timestamp()`,
		"a wseq memory of no producer":  `INSERT INTO contract_command_wseq VALUES (uuidv7(), 'mailie', uuidv7(), 1, uuidv7())`,
		"a wseq memory of wseq 0":       `INSERT INTO contract_command_wseq VALUES (uuidv7(), 'wappie', uuidv7(), 0, uuidv7())`,
		"a negative sections seq":       `UPDATE contract_workspaces SET sections_seq = -1`,
		"a section of no name":          `INSERT INTO contract_sections(workspace_id, section) SELECT workspace_id, 'email' FROM contract_workspaces`,
		"a section seq below zero":      `UPDATE contract_sections SET state_seq = -1`,
		"a section's tries below zero":  `UPDATE contract_sections SET tries = -1`,
		"a person's seq below zero":     `INSERT INTO contract_persons(sub, seq) VALUES (uuidv7(), -1)`,
		"a person's sent seq below 0":   `INSERT INTO contract_persons(sub, sent_seq) VALUES (uuidv7(), -1)`,
		"a person's tries below zero":   `INSERT INTO contract_persons(sub, tries) VALUES (uuidv7(), -1)`,
		"a security event of no kind":   `INSERT INTO security_events(kind) VALUES ('contract_command_lost')`,
		"a pause of no actor kind":      `UPDATE devices SET paused_by_kind = 'robot'`,
		"a section of an unrecorded ws": `INSERT INTO contract_sections(workspace_id, section) VALUES (uuidv7(), 'numbers')`,
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO contract_workspaces(workspace_id,kind) VALUES ($1,'team') ON CONFLICT DO NOTHING`, w.tenant); err != nil {
			t.Fatal(err)
		}
		var err error
		if strings.HasPrefix(sql, "UPDATE devices") {
			err = w.try(sql)
		} else {
			_, err = pool.Exec(ctx, sql)
		}
		if code := sqlState(err); code != "23514" && code != "23505" && (code != "23503" || !strings.Contains(name, "unrecorded")) {
			t.Errorf("%s: %v, want a check violation", name, err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO security_events(kind, detail) VALUES ('contract_command_invalid', '{"id":"x","cseq":1,"why":"mac"}')`); err != nil {
		t.Errorf("an invalid-command security event: %v", err)
	}

	// The ledger: the shapes a take and the executor write, then each bad
	// one.
	for name, ok := range map[string]command{
		"an open decoded row":           decoded(nil),
		"a person's kind":               decoded(command{"workspace_id": nil, "wseq": nil, "actor_role": nil, "section": "person", "kind": "person.sign_out_everywhere"}),
		"a row refused at take":         refusedAtTake(nil),
		"a decoded row refused expired": decoded(command{"outcome": "refused", "code": "expired", "result_at": time.Now()}),
		"a ran row delivered":           decoded(command{"outcome": "ran", "state_seq": 5, "result_at": time.Now(), "delivery": "accepted", "delivered_at": time.Now()}),
		"a row parked locally":          refusedAtTake(command{"delivery": "rejected", "delivered_at": time.Now(), "reject_code": "local_invalid"}),
		"a dropped row":                 refusedAtTake(command{"delivery": "dropped", "delivered_at": time.Now()}),
		"a row retrying":                decoded(command{"run_tries": 2, "run_error": "store", "run_after": time.Now()}),
		"a refusal with its retry":      decoded(command{"outcome": "refused", "code": "memberships_behind", "retry_after": 5, "state_seq": 3, "result_at": time.Now()}),
		"a wappie-cloud row":            decoded(command{"producer": "wappie-cloud"}),
		"a result's detail":             decoded(command{"outcome": "refused", "code": "label_changed", "detail": `{"cleaned":"x"}`, "result_at": time.Now()}),
		"in progress":                   decoded(command{"outcome": "in_progress", "result_at": time.Now()}),
	} {
		if err := ok.insert(ctx, pool); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, bad := range map[string]command{
		"an undecoded row with no result":      {},
		"an undecoded row refused expired":     refusedAtTake(command{"code": "expired"}),
		"an undecoded row that ran":            {"outcome": "ran", "result_at": time.Now()},
		"a producer of no app":                 decoded(command{"producer": "mailie"}),
		"a cseq of 0":                          refusedAtTake(command{"cseq": 0}),
		"a wseq of 0":                          decoded(command{"wseq": 0}),
		"a workspace with no wseq":             decoded(command{"wseq": nil}),
		"a wseq with no workspace":             decoded(command{"workspace_id": nil}),
		"a kind with no actor":                 decoded(command{"actor": nil}),
		"a kind with no issued_at":             decoded(command{"issued_at": nil}),
		"a kind with no section":               decoded(command{"section": nil}),
		"a workspace with no kind":             refusedAtTake(command{"workspace_id": uuid.New(), "wseq": 1}),
		"a role of no kind":                    decoded(command{"actor_role": "guest"}),
		"a target that is no object":           decoded(command{"target": `[]`}),
		"based_on docs that are no object":     decoded(command{"based_on_docs": `[]`}),
		"a detail that is no object":           decoded(command{"outcome": "ran", "state_seq": 1, "result_at": time.Now(), "detail": `[]`}),
		"a body key of 31 bytes":               refusedAtTake(command{"body_key": make([]byte, 31)}),
		"an outcome of no kind":                decoded(command{"outcome": "done", "result_at": time.Now()}),
		"an outcome with no time":              decoded(command{"outcome": "ran"}),
		"a result time with no outcome":        decoded(command{"result_at": time.Now()}),
		"a refusal with no code":               decoded(command{"outcome": "refused", "result_at": time.Now()}),
		"a run with a code":                    decoded(command{"outcome": "ran", "code": "expired", "result_at": time.Now()}),
		"a code with no outcome":               decoded(command{"code": "expired"}),
		"a retry of 0 seconds":                 decoded(command{"outcome": "refused", "code": "rate_limited", "retry_after": 0, "result_at": time.Now()}),
		"a retry over an hour":                 decoded(command{"outcome": "refused", "code": "rate_limited", "retry_after": 3601, "result_at": time.Now()}),
		"a state seq of 0":                     decoded(command{"outcome": "ran", "state_seq": 0, "result_at": time.Now()}),
		"a delivery with no result":            decoded(command{"delivery": "accepted", "delivered_at": time.Now()}),
		"a delivery with no time":              refusedAtTake(command{"delivery": "accepted"}),
		"a delivery time alone":                refusedAtTake(command{"delivered_at": time.Now()}),
		"a delivery of no kind":                refusedAtTake(command{"delivery": "lost", "delivered_at": time.Now()}),
		"a rejection with no code":             refusedAtTake(command{"delivery": "rejected", "delivered_at": time.Now()}),
		"a reject code on an accepted result":  refusedAtTake(command{"delivery": "accepted", "delivered_at": time.Now(), "reject_code": "conflict"}),
		"a reject code with no delivery":       refusedAtTake(command{"reject_code": "conflict"}),
		"a reject code the platform lacks":     refusedAtTake(command{"delivery": "rejected", "delivered_at": time.Now(), "reject_code": "gone"}),
		"tries with no error":                  decoded(command{"run_tries": 1}),
		"an error with no tries":               decoded(command{"run_error": "store"}),
		"tries below zero":                     decoded(command{"run_tries": -1, "run_error": "store"}),
		"post tries below zero":                refusedAtTake(command{"post_tries": -1}),
		"an undecoded row refused, then ran":   {"outcome": "ran", "code": "invalid_command", "result_at": time.Now()},
		"a code with no outcome, undecoded":    {"code": "invalid_command"},
		"a reject code with no delivery, open": decoded(command{"reject_code": "local_invalid"}),
	} {
		if err := bad.insert(ctx, pool); sqlState(err) != "23514" {
			t.Errorf("%s: %v, want 23514", name, err)
		}
	}

	// devices: the triggers own the new columns, so their CHECKs are
	// reached only with the triggers lifted.
	lifted := func(name, sql string) {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `ALTER TABLE devices DISABLE TRIGGER devices_logout_cause;
			ALTER TABLE devices DISABLE TRIGGER devices_pause_times`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, w.tenant.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, sql, w.device); sqlState(err) != "23514" {
			t.Errorf("%s: %v, want 23514", name, err)
		}
	}
	lifted("a cause of no kind", `UPDATE devices SET status = 'logged_out', logout_cause = 'ban' WHERE id = $1`)
	lifted("logged out with no cause", `UPDATE devices SET status = 'logged_out' WHERE id = $1`)
	lifted("a cause on a live number", `UPDATE devices SET logout_cause = 'phone' WHERE id = $1`)
	lifted("a pause time on a live number", `UPDATE devices SET paused_at = clock_timestamp() WHERE id = $1`)
	lifted("an actor on a live number", `UPDATE devices SET paused_by_kind = 'app' WHERE id = $1`)
	// A real account, so only the CHECK can refuse (paused_by_user's
	// foreign key checks after it).
	user := "'" + w.owner.String() + "'::uuid"
	lifted("a user on a live number", `UPDATE devices SET paused_by_user = `+user+` WHERE id = $1`)
	lifted("the app naming a user", `UPDATE devices SET paused = true, paused_at = clock_timestamp(), paused_by_kind = 'app',
		paused_by_user = `+user+` WHERE id = $1`)
	lifted("a user with no kind", `UPDATE devices SET paused = true, paused_at = clock_timestamp(), paused_by_user = `+user+` WHERE id = $1`)
	lifted("an actor with no time", `UPDATE devices SET paused = true, paused_by_kind = 'person' WHERE id = $1`)
	lifted("an actor of no kind", `UPDATE devices SET paused = true, paused_at = clock_timestamp(), paused_by_kind = 'robot' WHERE id = $1`)

	for _, table := range []string{"contract_settings_state", "contract_commands", "contract_command_wseq", "contract_sections", "contract_persons"} {
		var enabled, forced bool
		if err := pool.QueryRow(ctx, `SELECT relrowsecurity, relforcerowsecurity FROM pg_class
			WHERE relname = $1 AND relnamespace = current_schema()::regnamespace`, table).Scan(&enabled, &forced); err != nil || enabled || forced {
			t.Errorf("%s: row-level security %v, forced %v (%v); it is read across workspaces", table, enabled, forced, err)
		}
	}
	for _, table := range []string{"devices", "item_events", "device_notices", "device_transfers"} {
		var enabled, forced bool
		if err := pool.QueryRow(ctx, `SELECT relrowsecurity, relforcerowsecurity FROM pg_class
			WHERE relname = $1 AND relnamespace = current_schema()::regnamespace`, table).Scan(&enabled, &forced); err != nil || !enabled || !forced {
			t.Errorf("%s after the backfills: row-level security %v, forced %v (%v)", table, enabled, forced, err)
		}
	}
}

// devicesOf reads one column of every number of the workspace, excluded
// ones included, by id.
func devicesOf[T any](t *testing.T, w contractWorld, column string) map[uuid.UUID]T {
	t.Helper()
	ctx := context.Background()
	out := map[uuid.UUID]T{}
	w.exec(ctx, t, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, `+column+` FROM devices`)
		if err != nil {
			return err
		}
		return forEach(rows, func(r pgx.Rows) error {
			var id uuid.UUID
			var v T
			if err := r.Scan(&id, &v); err != nil {
				return err
			}
			out[id] = v
			return nil
		})
	})
	return out
}

func forEach(rows pgx.Rows, fn func(pgx.Rows) error) error {
	defer rows.Close()
	for rows.Next() {
		if err := fn(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

// number adds a number to the workspace with the given columns, as the
// table owner would on schema 51 or 52.
func (w contractWorld) number(t *testing.T, set string, args ...any) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	id := uuid.New()
	w.exec(ctx, t, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO devices(id,tenant_id,label) VALUES ($1,$2,'x')`, id, w.tenant); err != nil {
			return err
		}
		if set == "" {
			return nil
		}
		_, err := tx.Exec(ctx, `UPDATE devices SET `+set+` WHERE id = $1`, append([]any{id}, args...)...)
		return err
	})
	return id
}

// Numbers logged out before 0052 get their cause from their reason alone;
// every other status none.
func TestMigration0052LogoutCauseBackfill(t *testing.T) {
	ctx := context.Background()
	pool := at51(t)
	w := newContractWorld(t, pool)
	want := map[uuid.UUID]*string{}
	cause := func(c string) *string { return &c }
	for _, n := range []struct {
		status, reason string
		cause          *string
	}{
		{"logged_out", "unlinked (logged out from the phone)", cause("phone")},
		{"logged_out", "session missing at startup", cause("phone")},
		{"logged_out", "session missing", cause("phone")},
		{"logged_out", "no session at deletion", cause("deletion")},
		{"logged_out", "unlinked when deleted", cause("deletion")},
		{"online", "", nil},
		{"offline", "unlinked when deleted", nil},
		{"banned", "no session at deletion", nil},
		{"pairing", "", nil},
	} {
		want[w.number(t, `status = $2, status_reason = $3`, n.status, n.reason)] = n.cause
	}
	// A deleted number logged out by a deletion, hidden but backfilled.
	deleted := w.number(t, `status = 'logged_out', status_reason = 'no session at deletion', paused = true,
		deleted_at = now(), purge_after = now() + interval '30 days'`)
	want[deleted] = cause("deletion")
	want[w.device] = nil
	if err := Run(ctx, pool, quietLogger(t)); err != nil {
		t.Fatal(err)
	}
	got := devicesOf[*string](t, w, "logout_cause")
	for id, c := range want {
		if (got[id] == nil) != (c == nil) || (c != nil && *got[id] != *c) {
			t.Errorf("number %s: cause %v, want %v", id, deref(got[id]), deref(c))
		}
	}
}

func deref(s *string) string {
	if s == nil {
		return "NULL"
	}
	return *s
}

// pauseRow is what devices_pause_times keeps of a number's pause.
type pauseRow struct {
	paused         bool
	at, unpausedAt *time.Time
	kind           *string
	user           *uuid.UUID
}

func (w contractWorld) pause(t *testing.T, id uuid.UUID) pauseRow {
	t.Helper()
	ctx := context.Background()
	var p pauseRow
	w.exec(ctx, t, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT paused, paused_at, paused_by_kind, paused_by_user, unpaused_at FROM devices WHERE id = $1`, id).
			Scan(&p.paused, &p.at, &p.kind, &p.user, &p.unpausedAt)
	})
	return p
}

func (w contractWorld) set(t *testing.T, id uuid.UUID, sql string, args ...any) {
	t.Helper()
	ctx := context.Background()
	w.exec(ctx, t, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE devices SET `+sql+` WHERE id = $1`, append([]any{id}, args...)...)
		return err
	})
}

func sameTime(a, b *time.Time) bool {
	return (a == nil) == (b == nil) && (a == nil || a.Equal(*b))
}

// A pause sets its time; a second stop with the same cause keeps the time
// and the actor; a change of cause starts a new pause with the app or no
// actor; a resume clears all three and stamps unpaused_at; a pause put back
// after it is a new one; an unrelated update, or one that sets only the
// actor, keeps the time; and nobody else writes paused_at or unpaused_at.
func TestMigration0052PauseTimes(t *testing.T) {
	pool := pgtest.Fresh(t, Run)
	w := newContractWorld(t, pool)
	id := w.device
	if p := w.pause(t, id); p.at != nil || p.kind != nil || p.user != nil || p.unpausedAt != nil {
		t.Fatalf("a live number: %+v", p)
	}
	w.set(t, id, `paused = true, pause_cause = 'person', pause_seq = pause_seq + 1`)
	first := w.pause(t, id)
	if first.at == nil || first.kind != nil || first.user != nil {
		t.Fatalf("a person's pause: %+v", first)
	}
	// Who paused is written by a statement of its own, which leaves the time.
	w.set(t, id, `paused_by_kind = 'person', paused_by_user = $2`, w.owner)
	if p := w.pause(t, id); !sameTime(p.at, first.at) || deref(p.kind) != "person" || p.user == nil || *p.user != w.owner {
		t.Fatalf("the actor written: %+v", p)
	}
	w.set(t, id, `paused = true, pause_cause = 'person', pause_seq = pause_seq + 1`)
	w.set(t, id, `label = 'Outro'`)
	w.set(t, id, `paused_at = clock_timestamp() + interval '1 hour', unpaused_at = clock_timestamp()`)
	if p := w.pause(t, id); !sameTime(p.at, first.at) || deref(p.kind) != "person" || p.user == nil || p.unpausedAt != nil {
		t.Fatalf("a second stop, a rename and a write of the times kept the first pause: %+v (first %+v)", p, first)
	}
	// A cause that changes hands: a move's pause is the app's, and a
	// person's stop on it a new pause with no actor yet.
	w.set(t, id, `pause_cause = 'move'`)
	moved := w.pause(t, id)
	if moved.at == nil || !moved.at.After(*first.at) || deref(moved.kind) != "app" || moved.user != nil {
		t.Fatalf("a move's pause: %+v", moved)
	}
	w.set(t, id, `pause_cause = 'person', pause_seq = pause_seq + 1`)
	if p := w.pause(t, id); p.at == nil || !p.at.After(*moved.at) || p.kind != nil || p.user != nil {
		t.Fatalf("a person's stop on a moved number: %+v", p)
	}
	w.set(t, id, `paused = false`)
	resumed := w.pause(t, id)
	if resumed.paused || resumed.at != nil || resumed.kind != nil || resumed.user != nil || resumed.unpausedAt == nil {
		t.Fatalf("a resume: %+v", resumed)
	}
	w.set(t, id, `paused = false, unpaused_at = clock_timestamp() + interval '1 day'`)
	if p := w.pause(t, id); !sameTime(p.unpausedAt, resumed.unpausedAt) {
		t.Fatalf("unpaused_at written by another: %+v", p)
	}
	// RestorePause after a failed resume: a new pause, a move's the app's.
	w.set(t, id, `paused = true, pause_cause = 'move', pause_seq = pause_seq + 1`)
	if p := w.pause(t, id); p.at == nil || !p.at.After(*resumed.unpausedAt) || deref(p.kind) != "app" || !sameTime(p.unpausedAt, resumed.unpausedAt) {
		t.Fatalf("a pause put back: %+v", p)
	}
	// A number inserted paused is paused from its insert.
	inserted := w.number(t, `paused = true, pause_cause = 'deletion', deleted_at = now(), purge_after = now() + interval '30 days'`)
	if p := w.pause(t, inserted); p.at == nil || deref(p.kind) != "app" {
		t.Fatalf("a deletion's pause: %+v", p)
	}
}

// itemEvent writes an event row in the world's workspace, or another.
func (w contractWorld) itemEvent(t *testing.T, tenant, item uuid.UUID, typ, actor string, user *uuid.UUID, at string) {
	t.Helper()
	ctx := context.Background()
	if err := pg.InTenantTx(ctx, w.pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO item_events(event_id,tenant_id,type,item_id,dedupe_key,occurred_at,actor_kind,actor_user_id,
			ledgered_at,deleted_at)
			VALUES (uuidv7(),$1,$2,$3,$6,`+at+`,$4,$5,clock_timestamp(),CASE WHEN $2 = 'recovered' THEN clock_timestamp() END)
			ON CONFLICT DO NOTHING`, tenant, typ, item, actor, user, typ+":"+item.String()+":"+at)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// A sync_paused or recovered event fills the actor of a person's pause it
// follows; an event older than the pause, of another workspace, of another
// type, or on a move's pause changes nothing, and neither does a duplicate
// the log skips.
func TestMigration0052PausedByEvent(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Fresh(t, Run)
	w := newContractWorld(t, pool)
	var other uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO tenants(name) VALUES ('other') RETURNING id`).Scan(&other); err != nil {
		t.Fatal(err)
	}
	key := person(t, pool, w.tenant, "key-creator@example.test", "admin")
	id := w.device
	w.set(t, id, `paused = true, pause_cause = 'person', pause_seq = pause_seq + 1`)
	w.itemEvent(t, w.tenant, id, "sync_paused", "person", &w.owner, "clock_timestamp()")
	if p := w.pause(t, id); deref(p.kind) != "person" || p.user == nil || *p.user != w.owner {
		t.Fatalf("a person's stop and its event: %+v", p)
	}
	// The log skips a second row of the same key, and nothing changes.
	w.itemEvent(t, w.tenant, id, "sync_paused", "key", &key, "clock_timestamp()")
	if p := w.pause(t, id); deref(p.kind) != "person" || p.user == nil || *p.user != w.owner {
		t.Fatalf("an event the log skipped changed the actor: %+v", p)
	}
	w.set(t, id, `paused = false`)
	w.set(t, id, `paused = true, pause_cause = 'person', pause_seq = pause_seq + 1`)
	for name, ev := range map[string]struct {
		tenant         uuid.UUID
		typ, actor, at string
	}{
		"an event older than the pause": {w.tenant, "sync_paused", "person", "clock_timestamp() - interval '1 minute'"},
		"another workspace's event":     {other, "sync_paused", "person", "clock_timestamp()"},
		"a deletion's event":            {w.tenant, "deleted", "person", "clock_timestamp()"},
	} {
		if ev.typ == "deleted" {
			if err := pg.InTenantTx(ctx, pool, ev.tenant.String(), func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `INSERT INTO item_events(event_id,tenant_id,type,item_id,dedupe_key,occurred_at,actor_kind,actor_user_id,
					deleted_at,purge_after) VALUES (uuidv7(),$1,'deleted',$2,'deleted:'||uuidv7(),clock_timestamp(),'person',$3,
					clock_timestamp(),clock_timestamp()+interval '30 days')`, ev.tenant, id, w.owner)
				return err
			}); err != nil {
				t.Fatal(err)
			}
		} else {
			w.itemEvent(t, ev.tenant, id, ev.typ, ev.actor, &w.owner, ev.at)
		}
		if p := w.pause(t, id); p.kind != nil || p.user != nil {
			t.Fatalf("%s filled the actor: %+v", name, p)
		}
	}
	// A recovery names its person, a key's event its creator.
	w.itemEvent(t, w.tenant, id, "recovered", "key", &key, "clock_timestamp()")
	if p := w.pause(t, id); deref(p.kind) != "key" || p.user == nil || *p.user != key {
		t.Fatalf("a key's event: %+v", p)
	}
	// A move's pause is the app's, whatever event follows.
	moved := w.number(t, `paused = true, pause_cause = 'move'`)
	w.itemEvent(t, w.tenant, moved, "sync_paused", "person", &w.owner, "clock_timestamp()")
	if p := w.pause(t, moved); deref(p.kind) != "app" || p.user != nil {
		t.Fatalf("an event on a move's pause: %+v", p)
	}
}

// A removed account leaves no id behind on the numbers it paused, as on
// every other actor column of these tables (devices.deleted_by,
// item_events.actor_user_id): the user goes, the kind stays.
func TestMigration0052PausedByUserGoesWithTheAccount(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Fresh(t, Run)
	w := newContractWorld(t, pool)
	gone := person(t, pool, w.tenant, "gone@example.test", "admin")
	w.set(t, w.device, `paused = true, pause_cause = 'person', pause_seq = pause_seq + 1`)
	w.itemEvent(t, w.tenant, w.device, "sync_paused", "person", &gone, "clock_timestamp()")
	if p := w.pause(t, w.device); p.user == nil || *p.user != gone {
		t.Fatalf("the stop's actor: %+v", p)
	}
	w.exec(ctx, t, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM users WHERE id = $1`, gone)
		return err
	})
	if p := w.pause(t, w.device); p.user != nil || deref(p.kind) != "person" || p.at == nil {
		t.Fatalf("the pause after its actor's account went: %+v", p)
	}
}

// 0052 fills the pauses it finds: a deletion's from deleted_at, a move's
// from its transfer, a person's from its newest event unless a pause notice
// was marked resumed after it; anything else stays unknown.
func TestMigration0052PausedByBackfill(t *testing.T) {
	ctx := context.Background()
	pool := at51(t)
	w := newContractWorld(t, pool)
	var source uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO tenants(name) VALUES ('source') RETURNING id`).Scan(&source); err != nil {
		t.Fatal(err)
	}
	reader := person(t, pool, w.tenant, "reader@example.test", "member")
	at := func(offset string) time.Time {
		var v time.Time
		if err := pool.QueryRow(ctx, `SELECT date_trunc('milliseconds', clock_timestamp() - $1::interval)`, offset).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	deletedAt, movedAt, pausedAt, keyAt := at("3 days"), at("2 days"), at("1 day"), at("20 hours")

	deleted := w.number(t, `paused = true, deleted_at = $2, purge_after = $2::timestamptz + interval '30 days'`, deletedAt)
	moved := w.number(t, `paused = true, pause_cause = 'move'`)
	if err := pg.InTenantTx(ctx, pool, source.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO device_transfers(device_id,source_workspace_id,target_workspace_id,actor_id,completed_at)
			VALUES ($1,$2,$3,$4,$5)`, moved, source, w.tenant, w.owner, movedAt)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	stopped := w.number(t, `paused = true`)
	w.itemEvent(t, w.tenant, stopped, "recovered", "person", &reader, "'"+at("5 days").Format(time.RFC3339Nano)+"'")
	w.itemEvent(t, w.tenant, stopped, "sync_paused", "person", &w.owner, "'"+pausedAt.Format(time.RFC3339Nano)+"'")
	byKey := w.number(t, `paused = true`)
	key := person(t, pool, w.tenant, "key-creator@example.test", "admin")
	w.itemEvent(t, w.tenant, byKey, "sync_paused", "key", &key, "'"+keyAt.Format(time.RFC3339Nano)+"'")
	resumed := w.number(t, `paused = true`)
	w.itemEvent(t, w.tenant, resumed, "sync_paused", "person", &w.owner, "'"+pausedAt.Format(time.RFC3339Nano)+"'")
	w.exec(ctx, t, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO device_notices(tenant_id,device_id,user_id,kind,raised_by_kind,resumed_at)
			VALUES ($1,$2,$3,'sync_paused','person',$4::timestamptz + interval '1 hour')`, w.tenant, resumed, reader, pausedAt)
		return err
	})
	silent := w.number(t, `paused = true`)
	// An exclusion's cause left on a live number, as 0051's snapshot names
	// it: no deletion time to take.
	leftover := w.number(t, `paused = true, pause_cause = 'deletion'`)
	live := w.number(t, ``)
	w.itemEvent(t, w.tenant, live, "sync_paused", "person", &w.owner, "clock_timestamp()")

	if err := Run(ctx, pool, quietLogger(t)); err != nil {
		t.Fatal(err)
	}
	type want struct {
		at   *time.Time
		kind string
		user *uuid.UUID
	}
	for name, c := range map[string]struct {
		id uuid.UUID
		want
	}{
		"a deletion's":                 {deleted, want{&deletedAt, "app", nil}},
		"a move's":                     {moved, want{&movedAt, "app", nil}},
		"a person's, its newest event": {stopped, want{&pausedAt, "person", &w.owner}},
		"a key's":                      {byKey, want{&keyAt, "key", &key}},
		"one resumed since its event":  {resumed, want{}},
		"one that told nobody":         {silent, want{}},
		"a deletion's cause, live":     {leftover, want{}},
		"a live number":                {live, want{}},
	} {
		p := w.pause(t, c.id)
		kind := ""
		if p.kind != nil {
			kind = *p.kind
		}
		if !sameTime(p.at, c.at) || kind != c.kind || (p.user == nil) != (c.user == nil) || (c.user != nil && *p.user != *c.user) {
			t.Errorf("%s: %v %q %v, want %v %q %v", name, p.at, kind, p.user, c.at, c.kind, c.user)
		}
	}
}

// settingsWatch listens on the settings channel; changes go through a
// writer connection, so only its notifications are counted.
type settingsWatch struct {
	listener, writer *pgxpool.Conn
}

func newSettingsWatch(t *testing.T, pool *pgxpool.Pool) *settingsWatch {
	t.Helper()
	ctx := context.Background()
	w := &settingsWatch{}
	var err error
	if w.listener, err = pool.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.listener.Release)
	if w.writer, err = pool.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.writer.Release)
	if _, err := w.listener.Exec(ctx, `LISTEN wappie_contract_settings`); err != nil {
		t.Fatal(err)
	}
	return w
}

// change runs sql in one transaction on the writer, in tenant with excluded
// numbers visible, and returns what it notified, by payload.
func (s *settingsWatch) change(t *testing.T, tenant uuid.UUID, sql string, args ...any) map[string]int {
	t.Helper()
	return s.run(t, tenant, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	})
}

// run is change for a transaction of several statements.
func (s *settingsWatch) run(t *testing.T, tenant uuid.UUID, fn func(context.Context, pgx.Tx) error) map[string]int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tx, err := s.writer.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true), set_config('app.device_quarantine', 'on', true)`,
		tenant.String()); err != nil {
		t.Fatal(err)
	}
	if err := fn(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	fence := "fence:" + uuid.NewString()
	if _, err := s.writer.Exec(ctx, `SELECT pg_notify('wappie_contract_settings', $1)`, fence); err != nil {
		t.Fatal(err)
	}
	writer := s.writer.Conn().PgConn().PID()
	got := map[string]int{}
	for {
		n, err := s.listener.Conn().WaitForNotification(ctx)
		if err != nil {
			t.Fatalf("waiting for the fence: %v", err)
		}
		if n.Payload == fence {
			return got
		}
		if n.PID == writer {
			got[n.Payload]++
		}
	}
}

func heardOnly(got map[string]int, want ...string) bool {
	if len(got) != len(want) {
		return false
	}
	for _, p := range want {
		if got[p] != 1 {
			return false
		}
	}
	return true
}

// TestMigration0052SettingsTrigger: each change a numbers section shows
// notifies its workspace once per transaction, a move both; an online and
// offline flip notifies "c:" only; a later connection time, the push name,
// the label and updated_at alone nothing; capacity and the workspace's own
// status and storage stop notify it, its byte counters nothing; a notice
// raised, changed or deleted notifies its person; and a section or person
// made due sooner, new, or released from its park notifies "due".
func TestMigration0052SettingsTrigger(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Fresh(t, Run)
	w := newContractWorld(t, pool)
	s := newSettingsWatch(t, pool)
	ws, id := w.tenant.String(), w.device
	var personal uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE personal_owner_id = $1`, w.owner).Scan(&personal); err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		name, sql string
		want      []string
	}{
		{"pairing", `UPDATE devices SET status = 'pairing' WHERE id = $1`, []string{ws}},
		{"online", `UPDATE devices SET status = 'online', last_connected_at = now() WHERE id = $1`, []string{ws}},
		{"a later connection time", `UPDATE devices SET last_connected_at = now() + interval '1 second' WHERE id = $1`, nil},
		{"offline", `UPDATE devices SET status = 'offline' WHERE id = $1`, []string{"c:" + ws}},
		{"online again", `UPDATE devices SET status = 'online', last_connected_at = now() WHERE id = $1`, []string{"c:" + ws}},
		{"the push name", `UPDATE devices SET push_name = 'Ana' WHERE id = $1`, nil},
		{"the label", `UPDATE devices SET label = 'Suporte' WHERE id = $1`, nil},
		{"updated_at", `UPDATE devices SET updated_at = now() - interval '1 day' WHERE id = $1`, nil},
		{"the lid", `UPDATE devices SET lid = '1234@lid' WHERE id = $1`, []string{ws}},
		{"the phone number", `UPDATE devices SET pn = '5511900000000@s.whatsapp.net' WHERE id = $1`, []string{ws}},
		{"the epoch", `UPDATE devices SET current_epoch = 2 WHERE id = $1`, []string{ws}},
		{"a pause", `UPDATE devices SET paused = true, pause_cause = 'person', pause_seq = pause_seq + 1 WHERE id = $1`, []string{ws}},
		{"who paused", `UPDATE devices SET paused_by_kind = 'person', paused_by_user = '` + w.owner.String() + `'::uuid WHERE id = $1`, []string{ws}},
		{"a cause", `UPDATE devices SET pause_cause = 'move' WHERE id = $1`, []string{ws}},
		{"a second stop", `UPDATE devices SET pause_seq = pause_seq + 1 WHERE id = $1`, nil},
		{"a resume", `UPDATE devices SET paused = false WHERE id = $1`, []string{ws}},
		{"a logout", `UPDATE devices SET status = 'logged_out', status_reason = 'unlinked (x)' WHERE id = $1`, []string{ws}},
		{"its reason after", `UPDATE devices SET status_reason = 'no session at deletion' WHERE id = $1`, nil},
		{"a deletion", `UPDATE devices SET paused = true, deleted_at = now(), purge_after = now() + interval '30 days' WHERE id = $1`, []string{ws}},
		{"the purge date", `UPDATE devices SET purge_after = now() + interval '1 day' WHERE id = $1`, []string{ws}},
		{"the purge's start", `UPDATE devices SET purge_started_at = now() WHERE id = $1`, []string{ws}},
		{"a recovery", `UPDATE devices SET deleted_at = NULL, purge_after = NULL, purge_started_at = NULL WHERE id = $1`, []string{ws}},
		{"banned", `UPDATE devices SET status = 'banned' WHERE id = $1`, []string{ws}},
		{"a registration", `INSERT INTO devices(tenant_id, label) VALUES ($2, 'Nova')`, []string{ws}},
		{"a registration gone", `DELETE FROM devices WHERE tenant_id = $2 AND label = 'Nova'`, []string{ws}},
		{"a capacity", `INSERT INTO workspace_capacity(tenant_id, max_devices) VALUES ($2, 5)`, []string{ws}},
		{"a capacity changed", `UPDATE workspace_capacity SET max_devices = 6 WHERE tenant_id = $2`, []string{ws}},
		{"a capacity gone", `DELETE FROM workspace_capacity WHERE tenant_id = $2`, []string{ws}},
		{"the workspace suspended", `UPDATE tenants SET status = 'suspended' WHERE id = $2`, []string{ws}},
		{"its storage stop", `UPDATE tenants SET storage_paused_at = now() WHERE id = $2`, []string{ws}},
		{"its storage limit", `UPDATE tenants SET storage_limit_bytes = 1000 WHERE id = $2`, []string{ws}},
		{"its byte counters", `UPDATE tenants SET storage_archive_bytes = 10, storage_object_bytes = 5 WHERE id = $2`, nil},
		{"a notice", `INSERT INTO device_notices(tenant_id, device_id, user_id, kind, raised_by_kind) VALUES ($2, $1, $3, 'number_deleted', 'person')`,
			[]string{"u:" + w.owner.String()}},
		{"a notice seen", `UPDATE device_notices SET seen_at = now() WHERE user_id = $3`, []string{"u:" + w.owner.String()}},
		{"a notice deleted", `DELETE FROM device_notices WHERE user_id = $3`, []string{"u:" + w.owner.String()}},
		{"a move", `UPDATE devices SET tenant_id = $4 WHERE id = $1`, []string{ws, personal.String()}},
	} {
		// Each statement names some of $1 (the number), $2 (the
		// workspace), $3 (the owner) and $4 (their personal workspace):
		// renumbered to the ones it uses.
		all := []any{id, w.tenant, w.owner, personal}
		sql, args := step.sql, []any{}
		for i := range all {
			mark := "$" + strconv.Itoa(i+1)
			if strings.Contains(sql, mark) {
				args = append(args, all[i])
				sql = strings.ReplaceAll(sql, mark, "#"+strconv.Itoa(len(args)))
			}
		}
		sql = strings.ReplaceAll(sql, "#", "$")
		var got map[string]int
		if step.name == "a move" {
			// The move's own scope, as store's transfer opens it.
			got = s.run(t, w.tenant, func(ctx context.Context, tx pgx.Tx) error {
				if _, err := tx.Exec(ctx, `SELECT set_config('app.device_move_id', $1, true), set_config('app.device_move_source', $2, true),
					set_config('app.device_move_target', $3, true)`, id.String(), w.tenant.String(), personal.String()); err != nil {
					return err
				}
				_, err := tx.Exec(ctx, sql, args...)
				return err
			})
		} else {
			got = s.change(t, w.tenant, sql, args...)
		}
		if !heardOnly(got, step.want...) {
			t.Errorf("%s: heard %v, want %v", step.name, got, step.want)
		}
	}

	// The due times.
	if _, err := pool.Exec(ctx, `INSERT INTO contract_workspaces(workspace_id, kind) VALUES ($1, 'team')`, w.tenant); err != nil {
		t.Fatal(err)
	}
	sub := uuid.New()
	for _, step := range []struct {
		name, sql string
		arg       uuid.UUID
		want      []string
	}{
		{"a workspace recorded", `INSERT INTO contract_workspaces(workspace_id, kind) VALUES ($1, 'personal')`, personal, []string{"due"}},
		{"a section due later", `UPDATE contract_sections SET due_at = clock_timestamp() + interval '1 hour' WHERE workspace_id = $1`, personal, nil},
		{"a section due sooner", `UPDATE contract_sections SET due_at = clock_timestamp() + interval '1 minute' WHERE workspace_id = $1`, personal, []string{"due"}},
		{"a section parked", `UPDATE contract_sections SET parked_at = clock_timestamp(), due_at = due_at + interval '1 hour' WHERE workspace_id = $1`, personal, nil},
		{"a park released", `UPDATE contract_sections SET parked_at = NULL WHERE workspace_id = $1`, personal, []string{"due"}},
		{"a section's seq", `UPDATE contract_sections SET state_seq = 7 WHERE workspace_id = $1`, personal, nil},
		{"a sub followed", `INSERT INTO contract_accounts(sub) VALUES ($1)`, sub, []string{"due"}},
		{"its intent again", `INSERT INTO contract_accounts(sub) VALUES ($1) ON CONFLICT (sub) DO UPDATE SET subscribed_at = clock_timestamp()`, sub, nil},
		{"a person due later", `UPDATE contract_persons SET due_at = clock_timestamp() + interval '1 hour' WHERE sub = $1`, sub, nil},
		{"a person due now", `UPDATE contract_persons SET due_at = clock_timestamp() WHERE sub = $1`, sub, []string{"due"}},
		{"a person parked", `UPDATE contract_persons SET parked_at = clock_timestamp(), due_at = due_at + interval '1 hour' WHERE sub = $1`, sub, nil},
		{"a person released", `UPDATE contract_persons SET parked_at = NULL WHERE sub = $1`, sub, []string{"due"}},
	} {
		got := s.change(t, w.tenant, step.sql, step.arg)
		if !heardOnly(got, step.want...) {
			t.Errorf("%s: heard %v, want %v", step.name, got, step.want)
		}
	}
}

// 0052 makes the numbers and person rows of what is recorded; a workspace
// recorded and a sub followed after it get theirs at once, due now.
func TestMigration0052NewRows(t *testing.T) {
	ctx := context.Background()
	pool := at51(t)
	before, sub := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO contract_workspaces(workspace_id, kind) VALUES ($1, 'team')`, before); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO contract_accounts(sub) VALUES ($1)`, sub); err != nil {
		t.Fatal(err)
	}
	if err := Run(ctx, pool, quietLogger(t)); err != nil {
		t.Fatal(err)
	}
	after, later := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO contract_workspaces(workspace_id, kind) VALUES ($1, 'personal')`, after); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO contract_accounts(sub) VALUES ($1)`, later); err != nil {
		t.Fatal(err)
	}
	var sections, persons int
	if err := pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM contract_sections WHERE workspace_id = ANY($1) AND section = 'numbers' AND due_at <= clock_timestamp()
		   AND state_seq = 0 AND tries = 0 AND parked_at IS NULL),
		(SELECT count(*) FROM contract_persons WHERE sub = ANY($2) AND due_at <= clock_timestamp() AND seq = 0 AND sent_seq = 0)`,
		[]uuid.UUID{before, after}, []uuid.UUID{sub, later}).Scan(&sections, &persons); err != nil || sections != 2 || persons != 2 {
		t.Fatalf("%d numbers rows, %d person rows due now, %v", sections, persons, err)
	}
}

// The events not sent yet lose their labels, parked ones too; a settled
// one keeps its; every hint stays.
func TestMigration0052ItemEventsCut(t *testing.T) {
	ctx := context.Background()
	pool := at51(t)
	w := newContractWorld(t, pool)
	insert := func(extra string) uuid.UUID {
		t.Helper()
		id := uuid.New()
		w.exec(ctx, t, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO item_events(event_id,tenant_id,type,item_id,dedupe_key,occurred_at,actor_kind,
				deleted_at,purge_after,label,hint,settled_at,outcome,parked_at,reject_code)
				VALUES ($1,$2,'deleted',$3,$4,clock_timestamp(),'person',clock_timestamp(),clock_timestamp()+interval '30 days',
				'Ana Silva','…5678',`+extra+`)`, id, w.tenant, w.device, "deleted:"+id.String())
			return err
		})
		return id
	}
	unsent := insert(`NULL,NULL,NULL,NULL`)
	parked := insert(`NULL,NULL,clock_timestamp(),'conflict'`)
	settled := insert(`clock_timestamp(),'accepted',NULL,NULL`)
	if err := Run(ctx, pool, quietLogger(t)); err != nil {
		t.Fatal(err)
	}
	labels := map[uuid.UUID]*string{}
	w.exec(ctx, t, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT event_id, label, hint FROM item_events`)
		if err != nil {
			return err
		}
		return forEach(rows, func(r pgx.Rows) error {
			var id uuid.UUID
			var label, hint *string
			if err := r.Scan(&id, &label, &hint); err != nil {
				return err
			}
			if hint == nil || *hint != "…5678" {
				t.Errorf("event %s lost its hint: %v", id, hint)
			}
			labels[id] = label
			return nil
		})
	})
	if labels[unsent] != nil || labels[parked] != nil || labels[settled] == nil || *labels[settled] != "Ana Silva" {
		t.Fatalf("labels after the cut: unsent %v, parked %v, settled %v", deref(labels[unsent]), deref(labels[parked]), deref(labels[settled]))
	}
}

// wappie-billing keeps running while 0052 is applied, and may while its
// down-step runs: a billing request that holds its workspace and has
// counted the numbers finishes first, and the migration after it.
func TestMigration0052WaitsForBilling(t *testing.T) {
	ctx := context.Background()
	lg := quietLogger(t)
	pool := at51(t)
	var tenant uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO tenants(name) VALUES ('team') RETURNING id`).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	owner := person(t, pool, tenant, "owner@example.test", "owner")
	beside := func(name string, migration func() error) {
		t.Helper()
		billing, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer billing.Rollback(ctx)
		if _, err := billing.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenant.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := billing.Exec(ctx, `SELECT m.role FROM tenants t JOIN workspace_memberships m ON m.tenant_id=t.id
			WHERE t.id=$1 AND m.user_id=$2 AND t.status='active' FOR UPDATE OF t,m`, tenant, owner); err != nil {
			t.Fatal(err)
		}
		if _, err := billing.Exec(ctx, `SELECT count(*) FROM devices WHERE tenant_id=$1`, tenant); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- migration() }()
		for blocked := false; !blocked; {
			if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)))`,
				billing.Conn().PgConn().PID()).Scan(&blocked); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				t.Fatalf("%s never waited for the billing request: %v", name, err)
			case <-time.After(5 * time.Millisecond):
			}
		}
		_, countErr := billing.Exec(ctx, `SELECT (SELECT count(*) FROM users), (SELECT count(*) FROM devices WHERE tenant_id=$1)`, tenant)
		if countErr == nil {
			countErr = billing.Commit(ctx)
		}
		if err := <-done; countErr != nil || err != nil {
			t.Fatalf("%s beside a billing request: the request %v, the migration %v", name, countErr, err)
		}
	}
	beside("0052", func() error { return run(ctx, pool, lg, migrationsThrough(t, 52)) })
	beside("0052's down-step", func() error {
		_, err := pool.Exec(ctx, downStepSQL(t, 52))
		return err
	})
	var version int
	if err := pool.QueryRow(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&version); err != nil || version != 51 {
		t.Fatalf("after both: version %d %v", version, err)
	}
}
