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

	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
)

// migrationsThrough is every migration up to version, as a binary that knows
// no later one has them.
func migrationsThrough(t *testing.T, version int) []Migration {
	t.Helper()
	ms, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	var out []Migration
	for _, m := range ms {
		if m.Version <= version {
			out = append(out, m)
		}
	}
	if len(out) == 0 || out[len(out)-1].Version != version {
		t.Fatalf("no migration %04d", version)
	}
	return out
}

// contractWorld is a workspace at schema 51 with an owner and a number.
type contractWorld struct {
	pool   *pgxpool.Pool
	tenant uuid.UUID
	owner  uuid.UUID
	device uuid.UUID
}

func newContractWorld(t *testing.T, pool *pgxpool.Pool) contractWorld {
	t.Helper()
	ctx := context.Background()
	w := contractWorld{pool: pool}
	if err := pool.QueryRow(ctx, `INSERT INTO tenants(name) VALUES ('team') RETURNING id`).Scan(&w.tenant); err != nil {
		t.Fatal(err)
	}
	w.owner = person(t, pool, w.tenant, "owner-"+uuid.NewString()[:8]+"@example.test", "owner")
	w.exec(ctx, t, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `INSERT INTO devices(tenant_id,label,pn) VALUES ($1,'Vendas','5511912345678@s.whatsapp.net') RETURNING id`,
			w.tenant).Scan(&w.device)
	})
	return w
}

// exec runs fn in the workspace with excluded numbers visible.
func (w contractWorld) exec(ctx context.Context, t *testing.T, fn func(tx pgx.Tx) error) {
	t.Helper()
	if err := pg.InTenantTx(ctx, w.pool, w.tenant.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.device_quarantine', 'on', true)`); err != nil {
			return err
		}
		return fn(tx)
	}); err != nil {
		t.Fatal(err)
	}
}

// try is exec for a statement that may be refused: its error.
func (w contractWorld) try(sql string, args ...any) error {
	ctx := context.Background()
	return pg.InTenantTx(ctx, w.pool, w.tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	})
}

// TestMigration0051DownStep is the plan's TB10. 0051's down-step refuses
// while a later migration is applied or the contract is on, and changes
// nothing then; with the contract off it drops what release A cannot hold
// (the stranded rows, the owners' new notices, the home-taken security
// events, each counted, and the stored documents with their tables), and
// leaves exactly 50's schema, security_events' CHECK validated as 0048 wrote
// it, so 0050's down-step, a binary that knows 50 but not 51, and 0051 again
// all run on it.
func TestMigration0051DownStep(t *testing.T) {
	ctx := context.Background()
	lg := quietLogger(t)
	through50 := migrationsThrough(t, 50)
	at50 := pgtest.Empty(t)
	if err := run(ctx, at50, lg, through50); err != nil {
		t.Fatal(err)
	}
	pool := pgtest.Empty(t)
	if err := Run(ctx, pool, lg); err != nil {
		t.Fatal(err)
	}
	w := newContractWorld(t, pool)

	// What only release B writes, and what release A keeps.
	reader := person(t, pool, w.tenant, "reader@example.test", "member")
	sub := uuid.New()
	w.exec(ctx, t, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO item_events(event_id,tenant_id,type,item_id,dedupe_key,occurred_at,actor_kind,
			actor_user_id,person_sub,cause,ledgered_at,reader_user_ids)
			VALUES (uuidv7(),$1,'stranded',$2,'stranded:1',clock_timestamp(),'person',$3,$4,'revoked',clock_timestamp(),ARRAY[$5::uuid])`,
			w.tenant, w.device, w.owner, sub, reader); err != nil {
			return err
		}
		// An unsent deletion, and one settled; both stay as release A's.
		if _, err := tx.Exec(ctx, `INSERT INTO item_events(event_id,tenant_id,type,item_id,dedupe_key,occurred_at,actor_kind,
			deleted_at,purge_after,settled_at,outcome)
			VALUES (uuidv7(),$1,'deleted',$2,'deleted:1',clock_timestamp(),'person',clock_timestamp(),clock_timestamp()+interval '30 days',NULL,NULL),
			       (uuidv7(),$1,'deleted',$2,'deleted:2',clock_timestamp(),'person',clock_timestamp(),clock_timestamp()+interval '30 days',
			        clock_timestamp(),'accepted')`, w.tenant, w.device); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO device_notices(tenant_id,device_id,user_id,kind,raised_by_kind)
			VALUES ($1,$2,$3,'number_stranded','person'),($1,$2,$3,'number_deleted','person')`, w.tenant, w.device, reader)
		return err
	})
	if _, err := pool.Exec(ctx, `INSERT INTO security_events(kind,sub) VALUES ('platform_home_taken',$1),('platform_linked',$1)`, sub); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO contract_accounts(sub,generation,version,status,doc,fresh_at)
		VALUES ($1,uuidv7(),3,'active','{"v":1}',clock_timestamp())`, sub); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO contract_workspaces(workspace_id,kind,wversion,status) VALUES ($1,'team',2,'open')`, w.tenant); err != nil {
		t.Fatal(err)
	}

	counts := func() (rows int, has51 bool, contract int) {
		t.Helper()
		if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM schema_migrations),
			EXISTS(SELECT 1 FROM schema_migrations WHERE version = 51),
			(SELECT count(*) FROM pg_class WHERE relname LIKE 'contract_%' AND relnamespace = current_schema()::regnamespace)`).
			Scan(&rows, &has51, &contract); err != nil {
			t.Fatal(err)
		}
		return rows, has51, contract
	}
	refused := func(want string) {
		t.Helper()
		before, _, tables := counts()
		if _, err := pool.Exec(ctx, downStepSQL(t, 51)); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("the down-step with %s: %v", want, err)
		}
		if rows, has51, left := counts(); rows != before || !has51 || left != tables {
			t.Fatalf("a refused down-step changed something: %d ledger rows (was %d), version 51 %v, %d contract tables (was %d)",
				rows, before, has51, left, tables)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO schema_migrations(version,name,checksum,duration_ms) VALUES (52,'later','x',0)`); err != nil {
		t.Fatal(err)
	}
	refused("a migration after 0051 is applied")
	if _, err := pool.Exec(ctx, `DELETE FROM schema_migrations WHERE version = 52`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE contract_state SET mode='observe', events_from=clock_timestamp()`); err != nil {
		t.Fatal(err)
	}
	refused("the contract is on")
	// Off after an observe, as the rollback leaves it.
	if _, err := pool.Exec(ctx, `UPDATE contract_state SET mode='off', events_paused_at=clock_timestamp()`); err != nil {
		t.Fatal(err)
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
	if _, err := operator.Exec(ctx, downStepSQL(t, 51)); err != nil {
		t.Fatalf("the down-step: %v", err)
	}
	mu.Lock()
	want := "dropping 1 stranded rows, 1 owners' notices, 1 unsent events, 1 home-taken security events"
	if !slices.Contains(notices, want) {
		t.Errorf("the down-step's notices: %q, want %q", notices, want)
	}
	mu.Unlock()

	want50, got := schemaShape(t, at50), schemaShape(t, pool)
	if len(got) != len(want50) {
		t.Fatalf("after the down-step: %d schema facts, 50 has %d", len(got), len(want50))
	}
	for i := range want50 {
		if got[i] != want50[i] {
			t.Fatalf("after the down-step: %q where 50 has %q", got[i], want50[i])
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
	if def, valid := constraint(pool); !valid || def != func() string { d, _ := constraint(at50); return d }() {
		t.Fatalf("security_events_kind_check after the down-step: %q, validated %v", def, valid)
	}
	var stranded, kept, ownersNotices, deletedNotices, homeTaken, linked int
	w.exec(ctx, t, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM item_events WHERE type = 'stranded'),
			(SELECT count(*) FROM item_events WHERE type = 'deleted'),
			(SELECT count(*) FROM device_notices WHERE kind = 'number_stranded'),
			(SELECT count(*) FROM device_notices WHERE kind = 'number_deleted'),
			(SELECT count(*) FROM security_events WHERE kind = 'platform_home_taken'),
			(SELECT count(*) FROM security_events WHERE kind = 'platform_linked')`).
			Scan(&stranded, &kept, &ownersNotices, &deletedNotices, &homeTaken, &linked)
	})
	if stranded != 0 || kept != 2 || ownersNotices != 0 || deletedNotices != 1 || homeTaken != 0 || linked != 1 {
		t.Fatalf("rows after the down-step: %d stranded, %d deleted, %d owners' notices, %d deletion notices, %d home-taken, %d linked",
			stranded, kept, ownersNotices, deletedNotices, homeTaken, linked)
	}
	// security_events is insert-only again.
	if _, err := pool.Exec(ctx, `DELETE FROM security_events`); err == nil || !strings.Contains(err.Error(), "insert-only") {
		t.Fatalf("security_events after the down-step: %v", err)
	}

	if err := run(ctx, pool, lg, through50); err != nil {
		t.Fatalf("a binary that knows 50 after the down-step: %v", err)
	}
	// Numbers paused before 0051 get their cause when it applies again: an
	// excluded one's is the deletion's, a live one's a person's.
	paused := uuid.New()
	w.exec(ctx, t, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO devices(id,tenant_id,label,pn,paused) VALUES ($1,$2,'Pausado','5511912340000@s.whatsapp.net',true)`,
			paused, w.tenant); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE devices SET deleted_at=now(), purge_after=now()+interval '30 days', paused=true WHERE id=$1`, w.device)
		return err
	})
	if err := Run(ctx, pool, lg); err != nil {
		t.Fatalf("0051 again: %v", err)
	}
	causes := map[uuid.UUID]string{}
	w.exec(ctx, t, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, pause_cause FROM devices`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id uuid.UUID
			var cause string
			if err := rows.Scan(&id, &cause); err != nil {
				return err
			}
			causes[id] = cause
		}
		return rows.Err()
	})
	if causes[paused] != "person" || causes[w.device] != "deletion" || len(causes) != 2 {
		t.Fatalf("the causes 0051 gave numbers paused before it: %v", causes)
	}
	// The record starts again empty, the contract off and never observed.
	var mode string
	var observed bool
	var accounts int
	if err := pool.QueryRow(ctx, `SELECT mode, events_from IS NOT NULL, (SELECT count(*) FROM contract_accounts) FROM contract_state`).
		Scan(&mode, &observed, &accounts); err != nil || mode != "off" || observed || accounts != 0 {
		t.Fatalf("contract_state after 0051 again: %q observed %v, %d accounts, %v", mode, observed, accounts, err)
	}

	// And the chain: 0051 down, then 0050 down, then 0049's binary.
	if _, err := pool.Exec(ctx, downStepSQL(t, 51)); err != nil {
		t.Fatalf("0051's down-step again: %v", err)
	}
	w.exec(ctx, t, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE devices SET deleted_at=NULL, purge_after=NULL`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE item_events SET ledgered_at=clock_timestamp() WHERE ledgered_at IS NULL`)
		return err
	})
	if _, err := pool.Exec(ctx, downStepSQL(t, 50)); err != nil {
		t.Fatalf("0050's down-step after 0051's: %v", err)
	}
	if err := run(ctx, pool, lg, migrationsThrough(t, 49)); err != nil {
		t.Fatalf("a binary that knows 49: %v", err)
	}
}

// Every CHECK 0051 adds, each refused in its own transaction with 23514,
// beside the shapes it accepts; and the pause cause's trigger, which
// leaves no paused number without a cause and no live one with one.
func TestMigration0051Checks(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Fresh(t, Run)
	w := newContractWorld(t, pool)
	head := uuid.New()

	event := `INSERT INTO item_events(event_id,tenant_id,type,item_id,dedupe_key,occurred_at,actor_kind,ledgered_at,
		person_sub,cause,settled_at,outcome,coalesced_into,parked_at,reject_code)
		VALUES ($1,$2,$3,$4,$5,clock_timestamp(),'person',clock_timestamp(),$6,$7,$8,$9,$10,$11,$12)`
	type e struct {
		typ                    string
		person, cause          any
		settled, outcome, into any
		parked, code           any
	}
	n := 0
	add := func(v e) error {
		n++
		id := uuid.New()
		if n == 1 {
			id = head
		}
		return w.try(event, id, w.tenant, v.typ, w.device, v.typ+":"+uuid.NewString(), v.person, v.cause, v.settled, v.outcome,
			v.into, v.parked, v.code)
	}
	// The first row is the head the others fold into.
	if err := add(e{typ: "sync_paused"}); err != nil {
		t.Fatalf("a pending pause: %v", err)
	}
	for name, ok := range map[string]e{
		"a stranding with its sub and cause":    {typ: "stranded", person: uuid.New(), cause: "disabled"},
		"a stranding of a person with no sub":   {typ: "stranded", cause: "revoked"},
		"a stranding a membership's end made":   {typ: "stranded"},
		"a delivered pause":                     {typ: "sync_paused", settled: "now", outcome: "accepted"},
		"a duplicate":                           {typ: "sync_paused", settled: "now", outcome: "duplicate"},
		"a pause nobody else reads":             {typ: "sync_paused", settled: "now", outcome: "not_sent"},
		"a pause folded, pending with its head": {typ: "sync_paused", into: head},
		"a pause folded, settled with its head": {typ: "sync_paused", settled: "now", outcome: "coalesced", into: head},
		"a pause folded, parked with its head":  {typ: "sync_paused", into: head, parked: "now", code: "not_found"},
		"a parked event":                        {typ: "sync_paused", parked: "now", code: "conflict"},
		"an expired event":                      {typ: "sync_paused", parked: "now", code: "expired"},
	} {
		if err := add(ok); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, bad := range map[string]e{
		"a sub on a pause":                        {typ: "sync_paused", person: uuid.New()},
		"a cause on a pause":                      {typ: "sync_paused", cause: "revoked"},
		"a cause the contract lacks":              {typ: "stranded", cause: "closed"},
		"an outcome with no time":                 {typ: "sync_paused", outcome: "accepted"},
		"a settled time with no outcome":          {typ: "sync_paused", settled: "now"},
		"an outcome the contract lacks":           {typ: "sync_paused", settled: "now", outcome: "rejected"},
		"coalesced with nothing it was folded in": {typ: "sync_paused", settled: "now", outcome: "coalesced"},
		"folded into a head, and accepted":        {typ: "sync_paused", settled: "now", outcome: "accepted", into: head},
		"folded into a head, and not sent":        {typ: "sync_paused", settled: "now", outcome: "not_sent", into: head},
		"settled and parked":                      {typ: "sync_paused", settled: "now", outcome: "accepted", parked: "now", code: "conflict"},
		"parked with no code":                     {typ: "sync_paused", parked: "now"},
		"a code with no park":                     {typ: "sync_paused", code: "not_found"},
		"a code the contract lacks":               {typ: "sync_paused", parked: "now", code: "rate_limited"},
		"a type the log does not keep":            {typ: "renamed"},
	} {
		if err := add(bad); sqlState(err) != "23514" {
			t.Errorf("%s: %v, want 23514", name, err)
		}
	}
	// stranded is written ledgered, as 0050 requires of every type it does
	// not export.
	if err := w.try(`INSERT INTO item_events(event_id,tenant_id,type,item_id,dedupe_key,occurred_at,actor_kind)
		VALUES (uuidv7(),$1,'stranded',$2,'stranded:unledgered',clock_timestamp(),'person')`, w.tenant, w.device); sqlState(err) != "23514" {
		t.Errorf("an unledgered stranding: %v, want 23514", err)
	}

	for _, kind := range []string{"number_stranded", "number_moved_out"} {
		if err := w.try(`INSERT INTO device_notices(tenant_id,device_id,user_id,kind,raised_by_kind) VALUES ($1,$2,$3,$4,'person')`,
			w.tenant, w.device, w.owner, kind); err != nil {
			t.Errorf("a %s notice: %v", kind, err)
		}
	}

	// The pause cause: a writer that names none gets the default, a resume
	// clears it, and a cause on a live number does not stay.
	cause := func() *string {
		t.Helper()
		var c *string
		w.exec(ctx, t, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT pause_cause FROM devices WHERE id=$1`, w.device).Scan(&c)
		})
		return c
	}
	for _, step := range []struct {
		name, sql string
		want      string
	}{
		{"a pause naming no cause", `UPDATE devices SET paused=true WHERE id=$1`, "person"},
		{"a move's pause", `UPDATE devices SET pause_cause='move' WHERE id=$1`, "move"},
		{"a cause removed while paused", `UPDATE devices SET pause_cause=NULL WHERE id=$1`, "person"},
		{"a resume", `UPDATE devices SET paused=false WHERE id=$1`, ""},
		{"a cause on a live number", `UPDATE devices SET pause_cause='move' WHERE id=$1`, ""},
		{"an exclusion naming no cause", `UPDATE devices SET deleted_at=now(), purge_after=now()+interval '30 days', paused=true WHERE id=$1`, "deletion"},
	} {
		w.exec(ctx, t, func(tx pgx.Tx) error { _, err := tx.Exec(ctx, step.sql, w.device); return err })
		got := ""
		if c := cause(); c != nil {
			got = *c
		}
		if got != step.want {
			t.Errorf("%s: pause_cause %q, want %q", step.name, got, step.want)
		}
	}
	if err := w.try(`INSERT INTO devices(tenant_id,label,paused,pause_cause) VALUES ($1,'x',true,'stopped')`, w.tenant); sqlState(err) != "23514" {
		t.Errorf("a cause the column lacks: %v, want 23514", err)
	}

	// contract_state: one row, and a mode its times agree with.
	for name, sql := range map[string]string{
		"a second row":                       `INSERT INTO contract_state(id) VALUES (false)`,
		"a mode enforce has not widened yet": `UPDATE contract_state SET mode='enforce', events_from=clock_timestamp()`,
		"observe that never started":         `UPDATE contract_state SET mode='observe'`,
		"observe while paused":               `UPDATE contract_state SET mode='observe', events_from=clock_timestamp(), events_paused_at=clock_timestamp()`,
		"off after observe, not paused":      `UPDATE contract_state SET events_from=clock_timestamp()`,
		"a cursor below zero":                `UPDATE contract_state SET feed_cursor=-1`,
		"a version and no generation":        `INSERT INTO contract_accounts(sub,version) VALUES (uuidv7(),1)`,
		"a generation and no version":        `INSERT INTO contract_accounts(sub,generation) VALUES (uuidv7(),uuidv7())`,
		"a document with no status":          `INSERT INTO contract_accounts(sub,doc) VALUES (uuidv7(),'{}')`,
		"a document that is no object":       `INSERT INTO contract_accounts(sub,doc,status) VALUES (uuidv7(),'[]','active')`,
		"an account status the doc lacks":    `INSERT INTO contract_accounts(sub,doc,status) VALUES (uuidv7(),'{}','suspended')`,
		"a version below one":                `INSERT INTO contract_accounts(sub,generation,version) VALUES (uuidv7(),uuidv7(),0)`,
		"a workspace of no kind":             `INSERT INTO contract_workspaces(workspace_id,kind) VALUES (uuidv7(),'mailbox')`,
		"a workspace status the doc lacks":   `INSERT INTO contract_workspaces(workspace_id,kind,status) VALUES (uuidv7(),'team','archived')`,
		"a negative wversion":                `INSERT INTO contract_workspaces(workspace_id,kind,wversion) VALUES (uuidv7(),'team',-1)`,
		"a security event of no kind":        `INSERT INTO security_events(kind) VALUES ('platform_home_lost')`,
	} {
		if _, err := pool.Exec(ctx, sql); sqlState(err) != "23514" && sqlState(err) != "23505" {
			t.Errorf("%s: %v, want a check violation", name, err)
		}
	}
	// In this order: each step is a state the one before allows.
	for _, step := range []struct{ name, sql string }{
		{"observe", `UPDATE contract_state SET mode='observe', events_from=clock_timestamp()`},
		{"off after observe, paused", `UPDATE contract_state SET mode='off', events_paused_at=clock_timestamp()`},
		{"observe again, with the off period", `UPDATE contract_state SET mode='observe',
			events_off = events_off + tstzmultirange(tstzrange(events_paused_at, clock_timestamp())), events_paused_at=NULL`},
		{"an intent row", `INSERT INTO contract_accounts(sub) VALUES (uuidv7())`},
		{"a home taken", `INSERT INTO security_events(kind,sub) VALUES ('platform_home_taken',uuidv7())`},
	} {
		if _, err := pool.Exec(ctx, step.sql); err != nil {
			t.Errorf("%s: %v", step.name, err)
		}
	}
}

// wappie-billing keeps running while 0051 is applied, and may while its
// down-step runs. A billing request that has locked its workspace and
// membership and counted the numbers when the migration starts finishes
// first, and the migration after it: 0051 takes the three tables billing
// locks in a mode its reads never conflict with, and waits at devices;
// its down-step takes them first, as 0050's does, and waits at once.
func TestMigration0051WaitsForBilling(t *testing.T) {
	ctx := context.Background()
	lg := quietLogger(t)
	pool := pgtest.Empty(t)
	if err := run(ctx, pool, lg, migrationsThrough(t, 50)); err != nil {
		t.Fatal(err)
	}
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
		// The rest of the request: its users and numbers again, then its
		// commit.
		_, countErr := billing.Exec(ctx, `SELECT (SELECT count(*) FROM users), (SELECT count(*) FROM devices WHERE tenant_id=$1)`, tenant)
		if countErr == nil {
			countErr = billing.Commit(ctx)
		}
		if err := <-done; countErr != nil || err != nil {
			t.Fatalf("%s beside a billing request: the request %v, the migration %v", name, countErr, err)
		}
	}
	beside("0051", func() error { return Run(ctx, pool, lg) })
	beside("0051's down-step", func() error {
		_, err := pool.Exec(ctx, downStepSQL(t, 51))
		return err
	})
	var version int
	if err := pool.QueryRow(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&version); err != nil || version != 50 {
		t.Fatalf("after both: version %d %v", version, err)
	}
}
