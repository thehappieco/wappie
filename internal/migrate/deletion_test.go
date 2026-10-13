package migrate

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
)

// person adds a password account to a workspace with a role, as a
// migration-era row: the membership and the personal workspace come from
// its triggers.
func person(t *testing.T, pool *pgxpool.Pool, tenant uuid.UUID, email, role string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	var id uuid.UUID
	if err := pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `INSERT INTO users(tenant_id,email,auth_hash,kdf_salt,kdf_params,public_key,wrapped_usk,role)
			VALUES ($1,$2,'hash',decode(repeat('cd',16),'hex'),'{}',decode(repeat('ab',32),'hex'),'wrap',$3) RETURNING id`,
			tenant, email, role).Scan(&id)
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

func sqlState(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

// A key verifies by itself and its workspace only, so one whose creator was
// disabled, or is no longer a member, kept working (removal revoked them,
// disabling did not) and would reach a number recovered later. 0050 revokes
// them on a database from before it; a key with no creator, or whose
// creator is still an active member, is left alone, and so is a disabled
// person's key in a workspace where they are still active. One that had
// expired is revoked as of its expiry, so only the keys that still worked
// carry the migration's own time, and the production record counts them.
func TestMigration0050RevokesKeysOfFormerMembers(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Empty(t)
	ms, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	var through49 []Migration
	for _, m := range ms {
		if m.Version <= 49 {
			through49 = append(through49, m)
		}
	}
	lg := quietLogger(t)
	if err := run(ctx, pool, lg, through49); err != nil {
		t.Fatal(err)
	}
	var team uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO tenants(name) VALUES ('team') RETURNING id`).Scan(&team); err != nil {
		t.Fatal(err)
	}
	active := person(t, pool, team, "active@example.test", "admin")
	disabled := person(t, pool, team, "disabled@example.test", "admin")
	gone := person(t, pool, team, "gone@example.test", "admin")
	if err := pg.InTenantTx(ctx, pool, team.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE workspace_memberships SET status='disabled' WHERE tenant_id=$1 AND user_id=$2`, team, disabled); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM workspace_memberships WHERE tenant_id=$1 AND user_id=$2`, team, gone)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var personal uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE personal_owner_id=$1`, disabled).Scan(&personal); err != nil {
		t.Fatal(err)
	}
	key := func(tenant uuid.UUID, prefix string, creator *uuid.UUID, revoked bool) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := pool.QueryRow(ctx, `INSERT INTO api_keys(tenant_id,prefix,key_hash,name,created_by,revoked_at)
			VALUES ($1,$2,'hash',$2,$3,CASE WHEN $4 THEN now() - interval '1 day' END) RETURNING id`,
			tenant, prefix, creator, revoked).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	keys := map[string]struct {
		id     uuid.UUID
		revoke bool
	}{
		"an active member's":                  {key(team, "active01", &active, false), false},
		"a disabled member's":                 {key(team, "disabl01", &disabled, false), true},
		"a former member's":                   {key(team, "former01", &gone, false), true},
		"a key with no creator":               {key(team, "nobody01", nil, false), false},
		"a disabled member's, in their space": {key(personal, "person01", &disabled, false), false},
	}
	already := key(team, "revoke01", &gone, true)
	var expired uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO api_keys(tenant_id,prefix,key_hash,name,created_by,expires_at)
		VALUES ($1,'expire01','hash','expire01',$2,now() - interval '2 days') RETURNING id`, team, gone).Scan(&expired); err != nil {
		t.Fatal(err)
	}

	if err := Run(ctx, pool, lg); err != nil {
		t.Fatal(err)
	}
	for name, k := range keys {
		var revoked bool
		if err := pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM api_keys WHERE id=$1`, k.id).Scan(&revoked); err != nil {
			t.Fatal(err)
		}
		if revoked != k.revoke {
			t.Errorf("%s key: revoked %v, want %v", name, revoked, k.revoke)
		}
	}
	var kept bool
	if err := pool.QueryRow(ctx, `SELECT revoked_at < now() - interval '1 hour' FROM api_keys WHERE id=$1`, already).Scan(&kept); err != nil || !kept {
		t.Fatalf("a key revoked earlier was revoked again: %v %v", kept, err)
	}
	var atExpiry bool
	if err := pool.QueryRow(ctx, `SELECT revoked_at = expires_at FROM api_keys WHERE id=$1`, expired).Scan(&atExpiry); err != nil || !atExpiry {
		t.Fatalf("an expired former member's key: revoked at its expiry %v %v", atExpiry, err)
	}
	// The count the header gives for the production record: the two keys
	// that still worked.
	var closed int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM api_keys
		WHERE revoked_at = (SELECT applied_at FROM schema_migrations WHERE version = 50)`).Scan(&closed); err != nil || closed != 2 {
		t.Fatalf("the keys 0050 closed while they worked: %d %v", closed, err)
	}
	// workspace_memberships forces its policy again after the migration.
	var forced bool
	if err := pool.QueryRow(ctx, `SELECT relrowsecurity AND relforcerowsecurity FROM pg_class
		WHERE relname='workspace_memberships' AND relnamespace=current_schema()::regnamespace`).Scan(&forced); err != nil || !forced {
		t.Fatalf("workspace_memberships after 0050: forced %v %v", forced, err)
	}
}

// Every CHECK of 0050's two tables, each refused in its own transaction,
// beside the rows they accept.
func TestMigration0050Checks(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Fresh(t, Run)
	var tenant uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO tenants(name) VALUES ('team') RETURNING id`).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	reader := person(t, pool, tenant, "reader@example.test", "member")
	device := uuid.New()
	exec := func(sql string, args ...any) error {
		return pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, sql, append([]any{tenant, device, reader}, args...)...)
			return err
		})
	}
	notice := `INSERT INTO device_notices(tenant_id,device_id,user_id,kind,label,hint,pauses,raised_by_kind,several_actors,resumed_at,purged_at,seen_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`
	type n struct {
		kind, label, hint any
		pauses            int
		by                string
		several           bool
		resumed, purged   any
		seen              any
	}
	addNotice := func(v n) error {
		return exec(notice, v.kind, v.label, v.hint, v.pauses, v.by, v.several, v.resumed, v.purged, v.seen)
	}
	if err := addNotice(n{kind: "number_deleted", label: "Vendas", hint: "…5678", pauses: 1, by: "person"}); err != nil {
		t.Fatalf("a number_deleted notice: %v", err)
	}
	if err := addNotice(n{kind: "sync_paused", label: nil, hint: nil, pauses: 3, by: "key", several: true, resumed: "now"}); err != nil {
		t.Fatalf("a folded sync_paused notice: %v", err)
	}
	for name, c := range map[string]struct {
		v    n
		code string
	}{
		"a kind with no notice":            {n{kind: "number_moved", pauses: 1, by: "person"}, "23514"},
		"an empty label":                   {n{kind: "number_deleted", label: "", pauses: 1, by: "person", seen: "now"}, "23514"},
		"a hint with the number in it":     {n{kind: "number_deleted", hint: "5511912345678", pauses: 1, by: "person", seen: "now"}, "23514"},
		"a hint with no ellipsis":          {n{kind: "number_deleted", hint: "5678", pauses: 1, by: "person", seen: "now"}, "23514"},
		"a folded deletion":                {n{kind: "number_deleted", pauses: 2, by: "person", seen: "now"}, "23514"},
		"no pause at all":                  {n{kind: "sync_paused", pauses: 0, by: "person", seen: "now"}, "23514"},
		"several actors of one pause":      {n{kind: "sync_paused", pauses: 1, by: "person", several: true, seen: "now"}, "23514"},
		"an actor that is neither":         {n{kind: "sync_paused", pauses: 1, by: "app", seen: "now"}, "23514"},
		"a deletion resumed":               {n{kind: "number_deleted", pauses: 1, by: "person", resumed: "now", seen: "now"}, "23514"},
		"a pause purged":                   {n{kind: "sync_paused", pauses: 1, by: "person", purged: "now", seen: "now"}, "23514"},
		"a second unseen notice of a kind": {n{kind: "number_deleted", pauses: 1, by: "person"}, "23505"},
	} {
		if err := addNotice(c.v); sqlState(err) != c.code {
			t.Errorf("%s: %v, want %s", name, err, c.code)
		}
	}

	event := `INSERT INTO item_events(event_id,tenant_id,type,item_id,actor_user_id,dedupe_key,occurred_at,actor_kind,deleted_at,purge_after,to_tenant_id,ledgered_at,replayed_at,label,hint)
		VALUES (uuidv7(),$1,$4,$2,$3,$5,clock_timestamp(),$6,$7,$8,$9,$10,$11,$12,$13)`
	type e struct {
		typ, dedupe, actor               string
		deleted, purge, to, ledger, back any
		label, hint                      any
	}
	addEvent := func(v e) error {
		if v.to == "tenant" {
			v.to = tenant
		}
		return exec(event, v.typ, v.dedupe, v.actor, v.deleted, v.purge, v.to, v.ledger, v.back, v.label, v.hint)
	}
	for _, ok := range []e{
		{typ: "deleted", dedupe: "deleted:1", actor: "person", deleted: "now", purge: "now", label: "Vendas", hint: "…5678"},
		{typ: "sync_paused", dedupe: "sync_paused:1", actor: "key", ledger: "now"},
		{typ: "recovered", dedupe: "recovered:1", actor: "person", deleted: "now"},
		{typ: "purged", dedupe: "purged:1", actor: "app", deleted: "now", purge: "now", ledger: "now", back: "now"},
		{typ: "moved_out", dedupe: "moved_out:1", actor: "person", to: "tenant"},
	} {
		if err := addEvent(ok); err != nil {
			t.Fatalf("a %s event: %v", ok.typ, err)
		}
	}
	for name, c := range map[string]struct {
		v    e
		code string
	}{
		"a type the log does not keep":     {e{typ: "stranded", dedupe: "x1", actor: "person", ledger: "now"}, "23514"},
		"an actor that is neither":         {e{typ: "sync_paused", dedupe: "x2", actor: "owner", ledger: "now"}, "23514"},
		"an unledgered pause":              {e{typ: "sync_paused", dedupe: "x3", actor: "person"}, "23514"},
		"a move with nowhere to go":        {e{typ: "moved_out", dedupe: "x4", actor: "person"}, "23514"},
		"a destination for a deletion":     {e{typ: "deleted", dedupe: "x5", actor: "person", deleted: "now", purge: "now", to: "tenant"}, "23514"},
		"a deletion with no purge date":    {e{typ: "deleted", dedupe: "x6", actor: "person", deleted: "now"}, "23514"},
		"a purge with no deletion date":    {e{typ: "purged", dedupe: "x7", actor: "app", purge: "now"}, "23514"},
		"a recovery of no deletion":        {e{typ: "recovered", dedupe: "x8", actor: "person"}, "23514"},
		"a replay never ledgered":          {e{typ: "deleted", dedupe: "x9", actor: "person", deleted: "now", purge: "now", back: "now"}, "23514"},
		"the same event twice in a tenant": {e{typ: "deleted", dedupe: "deleted:1", actor: "person", deleted: "now", purge: "now"}, "23505"},
		// The phone number never appears in the log: a label, and a hint of
		// "…" and four digits only.
		"an empty label":               {e{typ: "deleted", dedupe: "x10", actor: "person", deleted: "now", purge: "now", label: ""}, "23514"},
		"a hint with the number in it": {e{typ: "deleted", dedupe: "x11", actor: "person", deleted: "now", purge: "now", hint: "5511912345678"}, "23514"},
		"a hint with no ellipsis":      {e{typ: "deleted", dedupe: "x12", actor: "person", deleted: "now", purge: "now", hint: "5678"}, "23514"},
	} {
		if err := addEvent(c.v); sqlState(err) != c.code {
			t.Errorf("%s: %v, want %s", name, err, c.code)
		}
	}
}

// downStepSQL reads the transaction out of a migration's header comment, so
// the statements tested are the ones an operator copies.
func downStepSQL(t *testing.T, version int) string {
	t.Helper()
	ms, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	in := false
	for _, m := range ms {
		if m.Version != version {
			continue
		}
		for line := range strings.SplitSeq(m.SQL, "\n") {
			text, ok := strings.CutPrefix(line, "--      ")
			if !ok {
				continue
			}
			if strings.TrimSpace(text) == "BEGIN;" {
				in = true
			}
			if in {
				out = append(out, text)
			}
			if strings.TrimSpace(text) == "COMMIT;" {
				break
			}
		}
	}
	if len(out) < 3 || out[len(out)-1] != "COMMIT;" {
		t.Fatalf("no down-step transaction in %04d's header", version)
	}
	return strings.Join(out, "\n")
}

// 0050's down-step refuses while a number is excluded or an event row is not
// in the ledger, and changes nothing then, the forced policy on devices
// included; once neither holds, it leaves exactly 49's schema, so a binary
// that knows 49 but not 50 starts on it, and 0050 applies again.
func TestMigration0050DownStep(t *testing.T) {
	ctx := context.Background()
	lg := quietLogger(t)
	ms, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	var through49 []Migration
	for _, m := range ms {
		if m.Version <= 49 {
			through49 = append(through49, m)
		}
	}
	at49 := pgtest.Empty(t)
	if err := run(ctx, at49, lg, through49); err != nil {
		t.Fatal(err)
	}
	pool := pgtest.Empty(t)
	if err := Run(ctx, pool, lg); err != nil {
		t.Fatal(err)
	}
	var tenant uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO tenants(name) VALUES ('team') RETURNING id`).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	var device uuid.UUID
	if err := pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `INSERT INTO devices(tenant_id,label,pn) VALUES ($1,'Vendas','5511912345678@s.whatsapp.net') RETURNING id`, tenant).Scan(&device)
	}); err != nil {
		t.Fatal(err)
	}
	// Excluded as the table owner, with the policy lifted, as the down-step
	// reads it: a migration has no workspace and no quarantine scope.
	if _, err := pool.Exec(ctx, `ALTER TABLE devices DISABLE ROW LEVEL SECURITY;
		UPDATE devices SET deleted_at=now(), purge_after=now()+interval '30 days', paused=true;
		ALTER TABLE devices ENABLE ROW LEVEL SECURITY; ALTER TABLE devices FORCE ROW LEVEL SECURITY`); err != nil {
		t.Fatal(err)
	}
	ledger := func() (rows int, has50, forced bool) {
		t.Helper()
		if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM schema_migrations), EXISTS(SELECT 1 FROM schema_migrations WHERE version = 50),
			(SELECT relrowsecurity AND relforcerowsecurity FROM pg_class WHERE relname='devices' AND relnamespace=current_schema()::regnamespace)`).Scan(&rows, &has50, &forced); err != nil {
			t.Fatal(err)
		}
		return rows, has50, forced
	}
	refused := func(want string) {
		t.Helper()
		before, _, _ := ledger()
		if _, err := pool.Exec(ctx, downStepSQL(t, 50)); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("the down-step with %s: %v", want, err)
		}
		if rows, has50, forced := ledger(); rows != before || !has50 || !forced {
			t.Fatalf("a refused down-step changed something: %d ledger rows (was %d), version 50 %v, devices forced %v", rows, before, has50, forced)
		}
	}
	// A later migration comes down first, before any other guard is asked.
	if _, err := pool.Exec(ctx, `INSERT INTO schema_migrations(version,name,checksum,duration_ms) VALUES (51,'later','x',0)`); err != nil {
		t.Fatal(err)
	}
	refused("a migration after 0050 is applied")
	if _, err := pool.Exec(ctx, `DELETE FROM schema_migrations WHERE version = 51`); err != nil {
		t.Fatal(err)
	}
	refused("excluded numbers exist")
	if _, err := pool.Exec(ctx, `ALTER TABLE devices DISABLE ROW LEVEL SECURITY;
		UPDATE devices SET deleted_at=NULL, purge_after=NULL, paused=false;
		ALTER TABLE devices ENABLE ROW LEVEL SECURITY; ALTER TABLE devices FORCE ROW LEVEL SECURITY`); err != nil {
		t.Fatal(err)
	}
	if err := pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO item_events(event_id,tenant_id,type,item_id,dedupe_key,occurred_at,actor_kind,deleted_at,purge_after)
			VALUES (uuidv7(),$1,'deleted',$2,'deleted:x',now(),'person',now(),now()+interval '30 days')`, tenant, device)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	refused("not in the ledger yet")
	if err := pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE item_events SET ledgered_at=now()`)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := pool.Exec(ctx, downStepSQL(t, 50)); err != nil {
		t.Fatalf("the down-step: %v", err)
	}
	want, got := schemaShape(t, at49), schemaShape(t, pool)
	if len(got) != len(want) {
		t.Fatalf("after the down-step: %d schema facts, 49 has %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("after the down-step: %q where 49 has %q", got[i], want[i])
		}
	}
	if err := run(ctx, pool, lg, through49); err != nil {
		t.Fatalf("a binary that knows 49 after the down-step: %v", err)
	}
	if err := Run(ctx, pool, lg); err != nil {
		t.Fatalf("0050 again: %v", err)
	}
}

// wappie-billing keeps running while 0050 is applied, and may while its
// down-step runs. Its transactions lock the workspace row and the membership
// (FOR UPDATE OF t,m) and then count devices. 0050 and its down-step lock
// those tables before anything else, so a billing request that holds them
// when the migration starts counts its devices and finishes, and the
// migration goes on after it. Had either taken devices first, the two would
// deadlock, and Postgres could abort the migration.
func TestMigration0050WaitsForBilling(t *testing.T) {
	ctx := context.Background()
	lg := quietLogger(t)
	ms, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	var through49 []Migration
	for _, m := range ms {
		if m.Version <= 49 {
			through49 = append(through49, m)
		}
	}
	pool := pgtest.Empty(t)
	if err := run(ctx, pool, lg, through49); err != nil {
		t.Fatal(err)
	}
	var tenant uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO tenants(name) VALUES ('team') RETURNING id`).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	owner := person(t, pool, tenant, "owner@example.test", "owner")
	during := func(name string, migration func() error) {
		t.Helper()
		billing, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer billing.Rollback(ctx)
		if _, err := billing.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenant.String()); err != nil {
			t.Fatal(err)
		}
		// The first statement of commercial's owner-only transactions.
		if _, err := billing.Exec(ctx, `SELECT m.role FROM tenants t JOIN workspace_memberships m ON m.tenant_id=t.id
			WHERE t.id=$1 AND m.user_id=$2 AND t.status='active' FOR UPDATE OF t,m`, tenant, owner); err != nil {
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
		_, countErr := billing.Exec(ctx, `SELECT count(*) FROM devices WHERE tenant_id=$1`, tenant)
		if countErr == nil {
			countErr = billing.Commit(ctx)
		} else {
			// The request failed; the migration still has to finish.
			_ = billing.Rollback(ctx)
		}
		if err := <-done; countErr != nil || err != nil {
			t.Fatalf("%s beside a billing request: the request %v, the migration %v", name, countErr, err)
		}
	}
	during("0050", func() error { return Run(ctx, pool, lg) })
	during("0050's down-step", func() error {
		_, err := pool.Exec(ctx, downStepSQL(t, 50))
		return err
	})
	var version int
	if err := pool.QueryRow(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&version); err != nil || version != 49 {
		t.Fatalf("after both: version %d %v", version, err)
	}
}
