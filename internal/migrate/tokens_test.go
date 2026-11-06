package migrate

import (
	"context"
	"errors"
	"fmt"
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

// tokenRows writes one token of each kind 0053 holds into w's workspace, as
// the table owner with the policies in force: its selector, its row, a
// perm, a removed instance, a pin, its identity with a grant of the
// workspace's number (an archive key at epoch 1), a sticky row, an open and
// a lifted stop, the queues, the usage rows and a retirement.
func tokenRows(t *testing.T, w contractWorld) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	token := uuid.New()
	if _, err := w.pool.Exec(ctx, `INSERT INTO contract_token_selectors (selector, token_id, tenant_id, hash, until)
		VALUES ('0123456789abcdef', $1, $2, decode(repeat('ab', 32), 'hex'), clock_timestamp() + interval '365 days')`, token, w.tenant); err != nil {
		t.Fatal(err)
	}
	w.exec(ctx, t, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO contract_tokens (id, tenant_id, name, created_by, created_at, expires_at, generation, version)
			VALUES ($1, $2, 'Nightly', $3, clock_timestamp(), clock_timestamp() + interval '30 days', $4, 1)`,
			token, w.tenant, uuid.New(), uuid.New()); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO contract_token_perms (token_id, tenant_id, device_id, perm, granted_by, granted_at, generation, version, state)
			VALUES ($1, $2, $3, 'read', $4, clock_timestamp(), $4, 1, 'applied')`, token, w.tenant, w.device, uuid.New()); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO contract_token_removed (token_id, tenant_id, item, perm, granted_at, cause)
			VALUES ($1, $2, 'not-a-number', 'send', clock_timestamp(), 'item_unknown')`, token, w.tenant); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO contract_token_pins (token_id, tenant_id, key, fingerprint, registered_at, until)
			VALUES ($1, $2, decode(repeat('cd', 32), 'hex'), repeat('a', 32), clock_timestamp(), clock_timestamp() + interval '365 days')`,
			token, w.tenant); err != nil {
			return err
		}
		var identity uuid.UUID
		if err := tx.QueryRow(ctx, `INSERT INTO users (tenant_id, email, public_key, role, token_identity)
			VALUES ($1, 't-' || $2::text || '@token.invalid', decode(repeat('cd', 32), 'hex'), 'service', true) RETURNING id`,
			w.tenant, token).Scan(&identity); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE contract_tokens SET identity_user_id = $2 WHERE id = $1`, token, identity); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO device_archive_keys (tenant_id, device_id, epoch, public_key) VALUES ($1, $2, 1, decode(repeat('ef', 32), 'hex'))
			ON CONFLICT DO NOTHING`, w.tenant, w.device); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO device_key_grants (tenant_id, device_id, user_id, epoch, sealed_dsk) VALUES ($1, $2, $3, 1, 'sealed')`,
			w.tenant, w.device, identity)
		return err
	})
	for _, q := range []string{
		`INSERT INTO contract_token_sticky (token_id, revoked_at, ended, until) VALUES (gen_random_uuid(), clock_timestamp(), 'revoked', clock_timestamp() + interval '1 day')`,
		`INSERT INTO contract_token_stops (selector, cause, stopped_by) VALUES ('0123456789abcdef', 'operator', 'root')`,
		`INSERT INTO contract_token_stops (selector, cause, stopped_by, lifted_at) VALUES ('fedcba9876543210', 'operator', 'root', clock_timestamp())`,
		`INSERT INTO contract_token_refusals_out (token_id, version, item, perm, code) VALUES (gen_random_uuid(), 1, 'x', 'read', 'local_role')`,
		`INSERT INTO contract_token_held_out (token_id, generation) VALUES (gen_random_uuid(), gen_random_uuid())`,
		`INSERT INTO contract_token_used (token_id, day) VALUES (gen_random_uuid(), current_date)`,
		`INSERT INTO contract_token_refusals (token_id, day, code, count) VALUES (gen_random_uuid(), current_date, 'revoked', 2)`,
		`INSERT INTO key_retirements (revoked, services_removed, services_kept, report, by) VALUES (1, 0, 0, '{}', 'root')`,
	} {
		if _, err := w.pool.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	return token
}

// TestMigration0053DownStep is 10.2's down-step test: 0053's header text,
// run as the NOSUPERUSER owner role the server uses, refuses while a later
// migration is applied or tokens are on, changing nothing then; otherwise it
// drops every token table with its counts noticed, keeps a key the
// retirement revoked revoked, leaves exactly 52's schema (so a binary that
// knows 52 starts on it, and 0053 applies again), and 0052's own guard
// refuses while 53 is applied.
func TestMigration0053DownStep(t *testing.T) {
	ctx := context.Background()
	lg := quietLogger(t)
	at52 := pgtest.Empty(t)
	if err := run(ctx, at52, lg, migrationsThrough(t, 52)); err != nil {
		t.Fatal(err)
	}
	pool := pgtest.Empty(t)
	if err := Run(ctx, pool, lg); err != nil {
		t.Fatal(err)
	}
	var super, bypass bool
	if err := pool.QueryRow(ctx, `SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&super, &bypass); err != nil || super || bypass {
		t.Fatalf("the test's role must be the server's, a NOSUPERUSER owner with no BYPASSRLS: super %v, bypass %v, %v", super, bypass, err)
	}
	w := newContractWorld(t, pool)
	tokenRows(t, w)
	var key uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO api_keys (tenant_id, prefix, key_hash, name, revoked_at, origin, revoke_reason)
		VALUES ($1, 'abcd1234', 'h', 'old', clock_timestamp(), 'rest', 'platform_tokens') RETURNING id`, w.tenant).Scan(&key); err != nil {
		t.Fatal(err)
	}

	// 0052's guard holds while 53 is applied.
	if _, err := pool.Exec(ctx, downStepSQL(t, 52)); err == nil || !strings.Contains(err.Error(), "a migration after 0052 is applied") {
		t.Fatalf("0052's down-step with 53 applied: %v", err)
	}
	counts := func() (rows int, has53 bool, tables int) {
		t.Helper()
		if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM schema_migrations),
			EXISTS(SELECT 1 FROM schema_migrations WHERE version = 53),
			(SELECT count(*) FROM pg_class WHERE (relname LIKE 'contract_token%' OR relname = 'key_retirements')
			   AND relnamespace = current_schema()::regnamespace AND relkind = 'r')`).Scan(&rows, &has53, &tables); err != nil {
			t.Fatal(err)
		}
		return rows, has53, tables
	}
	refused := func(want string) {
		t.Helper()
		before, _, tables := counts()
		if _, err := pool.Exec(ctx, downStepSQL(t, 53)); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("the down-step with %s: %v", want, err)
		}
		if rows, has53, left := counts(); rows != before || !has53 || left != tables || tables != 14 {
			t.Fatalf("a refused down-step changed something: %d ledger rows (was %d), version 53 %v, %d token tables (was %d, want 14)",
				rows, before, has53, left, tables)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO schema_migrations(version,name,checksum,duration_ms) VALUES (54,'later','x',0)`); err != nil {
		t.Fatal(err)
	}
	refused("a migration after 0053 is applied")
	if _, err := pool.Exec(ctx, `DELETE FROM schema_migrations WHERE version = 54`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE contract_token_state SET mode = 'on'`); err != nil {
		t.Fatal(err)
	}
	refused("tokens are on")
	if _, err := pool.Exec(ctx, `UPDATE contract_token_state SET mode = 'off'`); err != nil {
		t.Fatal(err)
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
	want := "dropping 1 tokens, 1 token identities with 1 grants, 1 local stops (re-apply them after a re-upgrade), 1 retirement rows; 1 keys revoked by the retirement stay revoked"
	if !slices.Contains(notices, want) {
		t.Errorf("the down-step's notices: %q, want %q", notices, want)
	}
	mu.Unlock()

	want52, got := schemaShape(t, at52), schemaShape(t, pool)
	if len(got) != len(want52) {
		t.Fatalf("after the down-step: %d schema facts, 52 has %d", len(got), len(want52))
	}
	for i := range want52 {
		if got[i] != want52[i] {
			t.Fatalf("after the down-step: %q where 52 has %q", got[i], want52[i])
		}
	}
	// No identity and none of its grants is left, the policies forced again.
	var identities, logins int
	w.exec(ctx, t, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM users WHERE email LIKE 't-%@token.invalid'),
			(SELECT count(*) FROM device_key_grants)`).Scan(&identities, &logins)
	})
	if identities != 0 || logins != 0 {
		t.Fatalf("after the down-step: %d identities, %d grants", identities, logins)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM user_logins WHERE email LIKE 't-%@token.invalid'`).Scan(&logins); err != nil || logins != 0 {
		t.Fatalf("after the down-step: %d identity logins, %v", logins, err)
	}
	var revoked bool
	if err := pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM api_keys WHERE id = $1`, key).Scan(&revoked); err != nil || !revoked {
		t.Fatalf("a key the retirement revoked, after the down-step: revoked %v, %v", revoked, err)
	}
	if err := run(ctx, pool, lg, migrationsThrough(t, 52)); err != nil {
		t.Fatalf("a binary that knows 52 after the down-step: %v", err)
	}
	if err := Run(ctx, pool, lg); err != nil {
		t.Fatalf("0053 again: %v", err)
	}
	// And the chain: 0053 down, then 0052 down.
	if _, err := pool.Exec(ctx, downStepSQL(t, 53)); err != nil {
		t.Fatalf("0053's down-step again: %v", err)
	}
	if _, err := pool.Exec(ctx, downStepSQL(t, 52)); err != nil {
		t.Fatalf("0052's down-step after 0053's: %v", err)
	}
}

// The up step on 0052-shaped rows: every number of every workspace gets its
// place by creation, deleted ones included, NULL past 9999, with updated_at
// as it was; and every key its origin by api_key_class's shape-first rule,
// an old local MCP token whose creator was deleted among them.
func TestMigration0053Backfills(t *testing.T) {
	ctx := context.Background()
	lg := quietLogger(t)
	pool := pgtest.Empty(t)
	if err := run(ctx, pool, lg, migrationsThrough(t, 52)); err != nil {
		t.Fatal(err)
	}
	a, b := newContractWorld(t, pool), newContractWorld(t, pool)
	// a's numbers: Vendas (first), a deleted one, then a later one; b's:
	// Vendas and 10 000 more, so its last is past 9999.
	var deleted, later uuid.UUID
	a.exec(ctx, t, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO devices (tenant_id, label, created_at) VALUES ($1, 'Apagado', clock_timestamp() + interval '1 second')
			RETURNING id`, a.tenant).Scan(&deleted); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE devices SET deleted_at = clock_timestamp(), purge_after = clock_timestamp() + interval '30 days', paused = true
			WHERE id = $1`, deleted); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO devices (tenant_id, label, created_at) VALUES ($1, 'Depois', clock_timestamp() + interval '2 seconds')
			RETURNING id`, a.tenant).Scan(&later)
	})
	b.exec(ctx, t, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO devices (tenant_id, label, created_at)
			SELECT $1, 'n' || g, clock_timestamp() + g * interval '1 millisecond' FROM generate_series(1, 10000) g`, b.tenant)
		return err
	})
	var updatedBefore time.Time
	a.exec(ctx, t, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT updated_at FROM devices WHERE id = $1`, a.device).Scan(&updatedBefore)
	})

	// One key of each class (the plan's 7.1).
	service := uuid.New()
	a.exec(ctx, t, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO users (id, tenant_id, email, name, public_key, role) VALUES ($1, $2, 'mcp-local@service.invalid', 'mcp-local',
			decode(repeat('ab', 32), 'hex'), 'service')`, service, a.tenant)
		return err
	})
	keys := map[string]string{}
	add := func(name, sql string, args ...any) {
		t.Helper()
		var id uuid.UUID
		if err := pool.QueryRow(ctx, sql, args...).Scan(&id); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		keys[id.String()] = name
	}
	insert := `INSERT INTO api_keys (tenant_id, prefix, key_hash, name, created_by, scope, devices_restricted, expires_at, acts_as, created_at)
		VALUES ($1, substr(md5(random()::text), 1, 8), 'h', $2, $3, $4, $5, $6, $7, clock_timestamp()) RETURNING id`
	soon := time.Now().Add(20 * time.Minute)
	add("mcp_setup", insert, a.tenant, "MCP · Claude", a.owner, "read", true, soon, nil)
	add("legacy_mcp", insert, a.tenant, "MCP · Local", a.owner, "read", true, nil, nil)
	add("legacy_mcp", insert, a.tenant, "MCP · Local", nil, "read", true, nil, service)
	add("cli", insert, a.tenant, "bootstrap", nil, "full", false, nil, nil)
	add("rest", insert, a.tenant, "Painel", a.owner, "full", false, nil, nil)
	add("rest", insert, a.tenant, "MCP · Local", a.owner, "full", false, nil, nil)
	var connKey uuid.UUID
	if err := pool.QueryRow(ctx, insert, a.tenant, "MCP · Claude", a.owner, "read", true, soon.Add(time.Hour), nil).Scan(&connKey); err != nil {
		t.Fatal(err)
	}
	keys[connKey.String()] = "mcp_setup"
	if _, err := pool.Exec(ctx, `INSERT INTO mcp_connections (tenant_id, request_id, api_key_id, created_by, client_name, redirect_host,
		device_count, reader_kid, status, expires_at) VALUES ($1, 'r', $2, $3, 'Claude', 'claude.ai', 1, 'k', 'active', clock_timestamp() + interval '1 day')`,
		a.tenant, connKey, a.owner); err != nil {
		t.Fatal(err)
	}

	if err := Run(ctx, pool, lg); err != nil {
		t.Fatal(err)
	}
	ordinals := func(w contractWorld) map[uuid.UUID]*int {
		t.Helper()
		out := map[uuid.UUID]*int{}
		w.exec(ctx, t, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT id, ordinal FROM devices`)
			if err != nil {
				return err
			}
			return forEach(rows, func(r pgx.Rows) error {
				var id uuid.UUID
				var o *int
				if err := r.Scan(&id, &o); err != nil {
					return err
				}
				out[id] = o
				return nil
			})
		})
		return out
	}
	got := ordinals(a)
	if *got[a.device] != 1 || *got[deleted] != 2 || *got[later] != 3 {
		t.Fatalf("a's ordinals: %d %d %d", *got[a.device], *got[deleted], *got[later])
	}
	gotB := ordinals(b)
	nulls, top := 0, 0
	for _, o := range gotB {
		if o == nil {
			nulls++
		} else {
			top = max(top, *o)
		}
	}
	if len(gotB) != 10001 || nulls != 2 || top != 9999 || *gotB[b.device] != 1 {
		t.Fatalf("b: %d numbers, %d past 9999, top %d", len(gotB), nulls, top)
	}
	var updatedAfter time.Time
	a.exec(ctx, t, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT updated_at FROM devices WHERE id = $1`, a.device).Scan(&updatedAfter)
	})
	if !updatedAfter.Equal(updatedBefore) {
		t.Fatalf("the backfill touched updated_at: %v, was %v", updatedAfter, updatedBefore)
	}
	rows, err := pool.Query(ctx, `SELECT id::text, origin FROM api_keys`)
	if err != nil {
		t.Fatal(err)
	}
	if err := forEach(rows, func(r pgx.Rows) error {
		var id string
		var origin *string
		if err := r.Scan(&id, &origin); err != nil {
			return err
		}
		if origin == nil || *origin != keys[id] {
			return fmt.Errorf("key %s (%s): origin %v", id, keys[id], origin)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestTheOrdinalSeesDeletedRowsAndTheTarget is 10.2's: under the policies a
// new number gets the lowest free ordinal of its workspace, a deleted
// number's place is never handed out again until its purge frees it, and a
// move-out takes the lowest free one in the target workspace, though the
// mover's session sees the source. The trigger lifts the policies for its
// one query only: after it, in the same transaction, the session's
// workspace and its closed quarantine scope are as they were, so a deleted
// number stays hidden.
func TestTheOrdinalSeesDeletedRowsAndTheTarget(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Fresh(t, Run)
	a, b := newContractWorld(t, pool), newContractWorld(t, pool)
	// scopeKept checks, in tx, that the session's settings are its own
	// again: the workspace of tenant, and no quarantine scope.
	scopeKept := func(tx pgx.Tx, tenant uuid.UUID, when string) error {
		var ws, quarantine string
		if err := tx.QueryRow(ctx, `SELECT coalesce(current_setting('app.tenant_id', true), ''),
			coalesce(current_setting('app.device_quarantine', true), '')`).Scan(&ws, &quarantine); err != nil {
			return err
		}
		if ws != tenant.String() || quarantine != "" {
			t.Errorf("%s: the session's app.tenant_id %q (want %s), app.device_quarantine %q (want none)", when, ws, tenant, quarantine)
		}
		return nil
	}
	// hidden, when not nil, is a deleted number of the workspace, which a
	// SELECT after the insert must not see.
	var hidden *uuid.UUID
	number := func(w contractWorld, label string) (uuid.UUID, int) {
		t.Helper()
		var id uuid.UUID
		var o int
		if err := pg.InTenantTx(ctx, pool, w.tenant.String(), func(tx pgx.Tx) error {
			if err := tx.QueryRow(ctx, `INSERT INTO devices (tenant_id, label) VALUES ($1, $2) RETURNING id, ordinal`, w.tenant, label).Scan(&id, &o); err != nil {
				return err
			}
			if err := scopeKept(tx, w.tenant, "after an insert"); err != nil {
				return err
			}
			if hidden != nil {
				var seen int
				if err := tx.QueryRow(ctx, `SELECT count(*) FROM devices WHERE id = $1`, *hidden).Scan(&seen); err != nil {
					return err
				}
				if seen != 0 {
					t.Error("after an insert, the session sees a deleted number")
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return id, o
	}
	two, o2 := number(a, "dois")
	_, o3 := number(a, "três")
	if o2 != 2 || o3 != 3 {
		t.Fatalf("ordinals %d %d", o2, o3)
	}
	a.exec(ctx, t, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE devices SET deleted_at = clock_timestamp(), purge_after = clock_timestamp() + interval '30 days', paused = true
			WHERE id = $1`, two)
		return err
	})
	// The quarantine scope is closed in this session: the trigger sees the
	// deleted number all the same, and the session, after it, does not.
	hidden = &two
	if _, o := number(a, "quatro"); o != 4 {
		t.Fatalf("a new number beside a deleted one: %d, want 4", o)
	}
	hidden = nil
	a.exec(ctx, t, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM devices WHERE id = $1`, two)
		return err
	})
	if _, o := number(a, "cinco"); o != 2 {
		t.Fatalf("after the purge: %d, want 2", o)
	}
	// A move-out from a to b, as TransferPersonal's session: the source's
	// workspace, with the move's scope.
	moved, _ := number(a, "mudança")
	var o int
	if err := pg.InTenantTx(ctx, pool, a.tenant.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.device_move_id', $1, true), set_config('app.device_move_source', $2, true),
			set_config('app.device_move_target', $3, true)`, moved.String(), a.tenant.String(), b.tenant.String()); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `UPDATE devices SET tenant_id = $2 WHERE id = $1 RETURNING ordinal`, moved, b.tenant).Scan(&o); err != nil {
			return err
		}
		return scopeKept(tx, a.tenant, "after a move-out")
	}); err != nil {
		t.Fatal(err)
	}
	if o != 2 {
		t.Fatalf("the moved-out number's ordinal in b: %d, want 2 (b holds 1)", o)
	}
}

// Every guard and trigger 0053 adds: the never-widen backstop on each of its
// columns, with access_version bumped on a narrowing; the selectors', pins'
// and sticky rows' guards; and the NOTIFYs.
func TestMigration0053Checks(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Fresh(t, Run)
	w := newContractWorld(t, pool)
	token := tokenRows(t, w)
	refused := func(name, sql string, args ...any) {
		t.Helper()
		if err := w.try(sql, args...); sqlState(err) != "P0001" {
			t.Errorf("%s: %v, want P0001", name, err)
		}
	}
	version := func() int64 {
		t.Helper()
		var v int64
		w.exec(ctx, t, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT access_version FROM contract_tokens WHERE id = $1`, token).Scan(&v)
		})
		return v
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		if err := w.try(sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	v := version()
	exec(`UPDATE contract_tokens SET name = 'Renamed' WHERE id = $1`, token)
	if version() != v {
		t.Fatal("a rename bumped access_version")
	}
	exec(`UPDATE contract_tokens SET expires_at = expires_at - interval '1 day' WHERE id = $1`, token)
	if version() != v+1 {
		t.Fatal("an earlier expiry did not bump access_version")
	}
	refused("a later expiry", `UPDATE contract_tokens SET expires_at = expires_at + interval '2 days' WHERE id = $1`, token)
	refused("another workspace", `UPDATE contract_tokens SET tenant_id = gen_random_uuid() WHERE id = $1`, token)
	refused("another creator", `UPDATE contract_tokens SET created_by = gen_random_uuid() WHERE id = $1`, token)
	refused("another creation", `UPDATE contract_tokens SET created_at = created_at - interval '1 second' WHERE id = $1`, token)
	// tokenRows gave it its identity.
	refused("another identity", `UPDATE contract_tokens SET identity_user_id = gen_random_uuid() WHERE id = $1`, token)
	refused("an identity cleared", `UPDATE contract_tokens SET identity_user_id = NULL WHERE id = $1`, token)
	for _, col := range []string{"unlisted_at", "key_changed_at", "identity_dropped_at"} {
		v := version()
		exec(`UPDATE contract_tokens SET `+col+` = clock_timestamp() WHERE id = $1`, token)
		if version() != v+1 {
			t.Errorf("%s set did not bump access_version", col)
		}
		refused(col+" cleared", `UPDATE contract_tokens SET `+col+` = NULL WHERE id = $1`, token)
		refused(col+" changed", `UPDATE contract_tokens SET `+col+` = `+col+` + interval '1 second' WHERE id = $1`, token)
	}
	v = version()
	exec(`UPDATE contract_tokens SET revoked_at = clock_timestamp(), revoked_reason = 'revoked' WHERE id = $1`, token)
	if version() != v+1 {
		t.Error("a revocation did not bump access_version")
	}
	refused("a revocation cleared", `UPDATE contract_tokens SET revoked_at = NULL, revoked_reason = NULL WHERE id = $1`, token)
	refused("a revocation's reason changed", `UPDATE contract_tokens SET revoked_reason = 'operator' WHERE id = $1`, token)
	refused("a revocation's time changed", `UPDATE contract_tokens SET revoked_at = revoked_at - interval '1 second' WHERE id = $1`, token)

	refused("a selector updated", `UPDATE contract_token_selectors SET tenant_id = gen_random_uuid()`)
	refused("a selector deleted before its until", `DELETE FROM contract_token_selectors`)
	refused("a pin updated", `UPDATE contract_token_pins SET key = decode(repeat('ef', 32), 'hex')`)
	refused("a pin deleted before its until", `DELETE FROM contract_token_pins`)
	refused("a sticky revocation cleared", `UPDATE contract_token_sticky SET revoked_at = NULL`)
	refused("a sticky ending changed", `UPDATE contract_token_sticky SET ended = 'expired'`)
	refused("a sticky row deleted before its until", `DELETE FROM contract_token_sticky`)
	exec(`UPDATE contract_token_sticky SET earliest_expires_at = clock_timestamp()`)
	refused("a sticky expiry raised", `UPDATE contract_token_sticky SET earliest_expires_at = earliest_expires_at + interval '1 day'`)
	refused("a sticky expiry cleared", `UPDATE contract_token_sticky SET earliest_expires_at = NULL`)
	// until only lowers: a valid record's created_at + 365 days narrows a
	// bad record's Wappie's clock + 365 days.
	refused("a sticky until raised", `UPDATE contract_token_sticky SET until = until + interval '1 day'`)
	exec(`UPDATE contract_token_sticky SET until = until - interval '1 second'`)
	// Past until, the guards let retention through.
	if _, err := pool.Exec(ctx, `ALTER TABLE contract_token_sticky DISABLE TRIGGER contract_token_sticky_guard;
		UPDATE contract_token_sticky SET until = clock_timestamp() - interval '1 second';
		ALTER TABLE contract_token_sticky ENABLE TRIGGER contract_token_sticky_guard`); err != nil {
		t.Fatal(err)
	}
	exec(`DELETE FROM contract_token_sticky`)

	// The identity: no membership, no personal workspace, no permission row
	// from its grant, and never a password, a recovery or a salt.
	var identity uuid.UUID
	w.exec(ctx, t, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT identity_user_id FROM contract_tokens WHERE id = $1`, token).Scan(&identity)
	})
	var memberships, permissions, personal int
	w.exec(ctx, t, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM workspace_memberships WHERE user_id = $1),
			(SELECT count(*) FROM device_permissions WHERE user_id = $1),
			(SELECT count(*) FROM tenants WHERE personal_owner_id = $1)`, identity).Scan(&memberships, &permissions, &personal)
	})
	if memberships != 0 || permissions != 0 || personal != 0 {
		t.Fatalf("the identity: %d memberships, %d permission rows, %d personal workspaces", memberships, permissions, personal)
	}
	// A service's password, role and sign-in source are 0048's
	// users_credentials_by_source's too; so a person's whole shape, which
	// that one accepts, is the identity shape's alone to refuse.
	for _, c := range []struct {
		name, sql string
		own       bool
	}{
		{"a password", `UPDATE users SET auth_hash = 'h' WHERE id = $1`, false},
		{"a role", `UPDATE users SET role = 'member' WHERE id = $1`, false},
		{"the platform's sign-in", `UPDATE users SET auth_source = 'platform' WHERE id = $1`, false},
		{"a recovery", `UPDATE users SET recovery_hash = 'r' WHERE id = $1`, true},
		{"a salt", `UPDATE users SET kdf_salt = decode(repeat('ab', 16), 'hex') WHERE id = $1`, true},
		{"KDF parameters", `UPDATE users SET kdf_params = '{"m": 65536}' WHERE id = $1`, true},
		{"disabled", `UPDATE users SET status = 'disabled' WHERE id = $1`, true},
		{"a platform person's shape", `UPDATE users SET role = 'member', auth_source = 'platform' WHERE id = $1`, true},
		{"a local person's shape", `UPDATE users SET role = 'member', auth_hash = 'h', kdf_salt = decode(repeat('ab', 16), 'hex'),
			kdf_params = '{"m": 65536}', wrapped_usk = 'w' WHERE id = $1`, true},
	} {
		var pgErr *pgconn.PgError
		err := w.try(c.sql, identity)
		if !errors.As(err, &pgErr) || pgErr.Code != "23514" || c.own && pgErr.ConstraintName != "users_token_identity_shape" {
			t.Errorf("an identity with %s: %v, want 23514 (users_token_identity_shape's: %t)", c.name, err, c.own)
		}
	}

	// A perm only for a token of its own workspace, of a known state.
	if err := w.try(`INSERT INTO contract_token_perms (token_id, tenant_id, device_id, perm, granted_by, granted_at, generation, version)
		VALUES ($1, gen_random_uuid(), $2, 'send', gen_random_uuid(), clock_timestamp(), gen_random_uuid(), 1)`, token, w.device); err == nil {
		t.Error("a perm of another workspace than its token's was written")
	}
	if err := w.try(`INSERT INTO contract_token_perms (token_id, tenant_id, device_id, perm, granted_by, granted_at, generation, version, state)
		VALUES ($1, $2, $3, 'send', gen_random_uuid(), clock_timestamp(), gen_random_uuid(), 1, 'refused')`, token, w.tenant, w.device); sqlState(err) != "23514" {
		t.Errorf("a refused perm with no code: %v", err)
	}

	// The notices: a token's id for its rows, all for the switches and the
	// modes.
	listen, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Release()
	if _, err := listen.Exec(ctx, `LISTEN wappie_contract_tokens`); err != nil {
		t.Fatal(err)
	}
	// An account document, for the belt's notice.
	if _, err := pool.Exec(ctx, `INSERT INTO contract_accounts (sub, generation, version, status, doc)
		VALUES (gen_random_uuid(), gen_random_uuid(), 1, 'active', '{"v":1}')`); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ sql, want string }{
		{`UPDATE contract_tokens SET name = 'Again' WHERE id = '` + token.String() + `'`, token.String()},
		{`DELETE FROM device_key_grants WHERE device_id = '` + w.device.String() + `'`, token.String()},
		{`UPDATE contract_token_perms SET state = 'waiting' WHERE token_id = '` + token.String() + `'`, token.String()},
		{`UPDATE contract_token_stops SET lifted_at = clock_timestamp() WHERE selector = '0123456789abcdef'`, token.String()},
		{`UPDATE tenants SET mcp_text = false WHERE id = '` + w.tenant.String() + `'`, "all"},
		{`UPDATE contract_token_state SET mode = 'on'`, "all"},
		{`UPDATE contract_state SET mode = 'observe', events_from = clock_timestamp()`, "all"},
		{`INSERT INTO contract_token_sticky (token_id, revoked_at, ended, until)
			VALUES ('` + token.String() + `', clock_timestamp(), 'revoked', clock_timestamp() + interval '1 day')`, token.String()},
		{`UPDATE contract_accounts SET doc = '{"v":2}'`, "all"},
		{`UPDATE tenants SET mcp_media = false WHERE id = '` + w.tenant.String() + `'`, "all"},
		// caught_up_at's notice: set and cleared, below.
	} {
		if err := w.try(c.sql); err != nil {
			t.Fatalf("%s: %v", c.sql, err)
		}
		wait, cancel := context.WithTimeout(ctx, 5*time.Second)
		n, err := listen.Conn().WaitForNotification(wait)
		cancel()
		if err != nil || n.Payload != c.want {
			t.Fatalf("%s: notice %+v, %v; want %s", c.sql, n, err, c.want)
		}
		for {
			drain, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
			_, err := listen.Conn().WaitForNotification(drain)
			cancel()
			if err != nil {
				break
			}
		}
	}

	// caught_up_at notifies only when it is set or cleared: a page with more
	// false moves it on at every long-poll, and token auth reads only
	// whether it is set. The writes go on one connection of the test's, so
	// another test's notices on the shared database are told apart.
	writer, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Release()
	pid := writer.Conn().PgConn().PID()
	ours := func(within time.Duration) (string, bool) {
		wait, cancel := context.WithTimeout(ctx, within)
		defer cancel()
		for {
			n, err := listen.Conn().WaitForNotification(wait)
			if err != nil {
				return "", false
			}
			if n.PID == pid {
				return n.Payload, true
			}
		}
	}
	for _, c := range []struct {
		name, sql string
		notifies  bool
	}{
		{"set", `UPDATE contract_token_state SET caught_up_at = clock_timestamp()`, true},
		{"moved on", `UPDATE contract_token_state SET caught_up_at = caught_up_at + interval '25 seconds'`, false},
		{"moved on with the mode unchanged", `UPDATE contract_token_state SET caught_up_at = caught_up_at + interval '25 seconds', mode = mode`, false},
		{"cleared", `UPDATE contract_token_state SET caught_up_at = NULL`, true},
		{"left cleared", `UPDATE contract_token_state SET caught_up_at = NULL`, false},
	} {
		if _, err := writer.Exec(ctx, c.sql); err != nil {
			t.Fatalf("caught_up_at %s: %v", c.name, err)
		}
		within := 5 * time.Second
		if !c.notifies {
			within = 200 * time.Millisecond
		}
		payload, got := ours(within)
		switch {
		case c.notifies && (!got || payload != "all"):
			t.Fatalf("caught_up_at %s: notice %q (%t), want all", c.name, payload, got)
		case !c.notifies && got:
			t.Fatalf("caught_up_at %s: notice %q, want none", c.name, payload)
		}
	}

	// A grant given to the identity notices its token, and a person's grant
	// nothing, on the same connection.
	for _, c := range []struct {
		name string
		user uuid.UUID
		want string
	}{{"the identity's", identity, token.String()}, {"a person's", w.owner, ""}} {
		err := pgx.BeginFunc(ctx, writer, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, w.tenant.String()); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO device_key_grants (tenant_id, device_id, user_id, epoch, sealed_dsk) VALUES ($1, $2, $3, 1, 'sealed')`,
				w.tenant, w.device, c.user)
			return err
		})
		if err != nil {
			t.Fatalf("%s grant: %v", c.name, err)
		}
		within := 5 * time.Second
		if c.want == "" {
			within = 200 * time.Millisecond
		}
		payload, got := ours(within)
		switch {
		case c.want != "" && (!got || payload != c.want):
			t.Fatalf("%s grant: notice %q (%t), want %s", c.name, payload, got, c.want)
		case c.want == "" && got:
			t.Fatalf("%s grant: notice %q, want none", c.name, payload)
		}
	}

	// A stop's record_until, which only retention reads, wakes no socket
	// when it changes alone; the stop's own changes do, with its token's id.
	for _, c := range []struct {
		name, sql string
		notifies  bool
	}{
		{"record_until set", `UPDATE contract_token_stops SET record_until = clock_timestamp() WHERE selector = '0123456789abcdef'`, false},
		{"record_until lowered", `UPDATE contract_token_stops SET record_until = record_until - interval '1 day' WHERE selector = '0123456789abcdef'`, false},
		{"reopened", `UPDATE contract_token_stops SET lifted_at = NULL WHERE selector = '0123456789abcdef'`, true},
		{"stopped again, record_until with it", `UPDATE contract_token_stops SET stopped_at = clock_timestamp(), record_until = NULL
			WHERE selector = '0123456789abcdef'`, true},
		{"deleted", `DELETE FROM contract_token_stops WHERE selector = '0123456789abcdef'`, true},
	} {
		if _, err := writer.Exec(ctx, c.sql); err != nil {
			t.Fatalf("a stop %s: %v", c.name, err)
		}
		within := 5 * time.Second
		if !c.notifies {
			within = 200 * time.Millisecond
		}
		payload, got := ours(within)
		switch {
		case c.notifies && (!got || payload != token.String()):
			t.Fatalf("a stop %s: notice %q (%t), want %s", c.name, payload, got, token)
		case !c.notifies && got:
			t.Fatalf("a stop %s: notice %q, want none", c.name, payload)
		}
	}

	// A removed instance keeps no giver.
	var giver bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'contract_token_removed' AND column_name = 'granted_by')`).Scan(&giver); err != nil || giver {
		t.Fatalf("contract_token_removed has a granted_by column: %v %v", giver, err)
	}
}

// wappie-billing keeps running while 0053 and its down-step run (as 0052's
// test has it): a billing request that holds its workspace and membership
// rows and has counted devices finishes, and the migration goes on after
// it, never deadlocking with it.
func TestMigration0053WaitsForBilling(t *testing.T) {
	ctx := context.Background()
	lg := quietLogger(t)
	pool := pgtest.Empty(t)
	if err := run(ctx, pool, lg, migrationsThrough(t, 52)); err != nil {
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
		_, countErr := billing.Exec(ctx, `SELECT (SELECT count(*) FROM users), (SELECT count(*) FROM devices WHERE tenant_id=$1)`, tenant)
		if countErr == nil {
			countErr = billing.Commit(ctx)
		}
		if err := <-done; countErr != nil || err != nil {
			t.Fatalf("%s beside a billing request: the request %v, the migration %v", name, countErr, err)
		}
	}
	beside("0053", func() error { return Run(ctx, pool, lg) })
	beside("0053's down-step", func() error {
		_, err := pool.Exec(ctx, downStepSQL(t, 53))
		return err
	})
	var version int
	if err := pool.QueryRow(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&version); err != nil || version != 52 {
		t.Fatalf("after both: version %d %v", version, err)
	}
}
