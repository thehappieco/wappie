package migrate

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"whatserver2/internal/pgtest"
)

// TestMigration55UpAndDown: 0055's up step marks every account disabled
// before it as the operator's and changes no other row; its down-step, as
// the header writes it, refuses while a later migration is applied (no
// enforce mode exists before E2 widens the CHECK in this file), changing
// nothing then; otherwise it drops what 0053 cannot hold (counted), keeps
// the ended keys and connections ended, and leaves exactly 53's schema, so
// a binary that knows 53 starts on it and 0055 applies again.
func TestMigration55UpAndDown(t *testing.T) {
	ctx := context.Background()
	lg := quietLogger(t)
	at53 := pgtest.Empty(t)
	if err := run(ctx, at53, lg, migrationsThrough(t, 53)); err != nil {
		t.Fatal(err)
	}
	pool := pgtest.Empty(t)
	if err := run(ctx, pool, lg, migrationsThrough(t, 53)); err != nil {
		t.Fatal(err)
	}
	w := newContractWorld(t, pool)
	disabled := person(t, pool, w.tenant, "gone-"+uuid.NewString()[:8]+"@example.test", "member")
	w.exec(ctx, t, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE users SET status = 'disabled' WHERE id = $1`, disabled)
		return err
	})
	var updated string
	w.exec(ctx, t, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT updated_at::text FROM users WHERE id = $1`, disabled).Scan(&updated)
	})
	if err := Run(ctx, pool, lg); err != nil {
		t.Fatal(err)
	}
	var by, after string
	w.exec(ctx, t, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT coalesce(disabled_by, ''), updated_at::text FROM users WHERE id = $1`, disabled).Scan(&by, &after)
	})
	if by != "operator" || after != updated {
		t.Fatalf("the backfill: disabled_by %q, updated_at %s (was %s)", by, after, updated)
	}
	var active string
	w.exec(ctx, t, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT coalesce(disabled_by, '') FROM users WHERE id = $1`, w.owner).Scan(&active)
	})
	if active != "" {
		t.Fatalf("an active account's disabled_by: %q", active)
	}

	// Rows the down-step must handle: a key and a connection ended with
	// 0055's reasons, a transfer whose actor was forgotten, a notice the
	// app raised, a closing and the apply's markers.
	var key uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO api_keys (tenant_id, prefix, key_hash, name, revoked_at, revoke_reason)
		VALUES ($1, 'abcd5555', 'h', 'k', clock_timestamp(), 'contract') RETURNING id`, w.tenant).Scan(&key); err != nil {
		t.Fatal(err)
	}
	w.exec(ctx, t, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO device_transfers (device_id, source_workspace_id, target_workspace_id, actor_id)
			VALUES ($1, $2, $3, NULL)`, w.device, w.tenant, uuid.New()); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO device_notices (tenant_id, device_id, user_id, kind, raised_by, raised_by_kind)
			VALUES ($1, $2, $3, 'number_stranded', NULL, 'app')`, w.tenant, w.device, w.owner)
		return err
	})
	if _, err := pool.Exec(ctx, `INSERT INTO contract_closings (sub) VALUES ($1)`, uuid.New()); err != nil {
		t.Fatal(err)
	}

	refused := func(want string) {
		t.Helper()
		var before int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM contract_closings`).Scan(&before); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, downStepSQL(t, 55)); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("the down-step with %s: %v", want, err)
		}
		var after int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM contract_closings`).Scan(&after); err != nil || after != before {
			t.Fatalf("a refused down-step changed something: %d closings (was %d), %v", after, before, err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO schema_migrations(version,name,checksum,duration_ms) VALUES (56,'later','x',0)`); err != nil {
		t.Fatal(err)
	}
	refused("a migration after 0055 is applied")
	if _, err := pool.Exec(ctx, `DELETE FROM schema_migrations WHERE version = 56`); err != nil {
		t.Fatal(err)
	}
	// 0053's own guard holds while 55 is applied.
	if _, err := pool.Exec(ctx, downStepSQL(t, 53)); err == nil || !strings.Contains(err.Error(), "a migration after 0053 is applied") {
		t.Fatalf("0053's down-step with 55 applied: %v", err)
	}

	if _, err := pool.Exec(ctx, downStepSQL(t, 55)); err != nil {
		t.Fatalf("the down-step: %v", err)
	}
	if want, got := schemaShape(t, at53), schemaShape(t, pool); !slices.Equal(got, want) {
		for _, f := range got {
			if !slices.Contains(want, f) {
				t.Errorf("after the down-step, not in 53: %q", f)
			}
		}
		for _, f := range want {
			if !slices.Contains(got, f) {
				t.Errorf("after the down-step, missing from 53: %q", f)
			}
		}
		t.FailNow()
	}
	var revoked bool
	if err := pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL AND revoke_reason IS NULL FROM api_keys WHERE id = $1`, key).Scan(&revoked); err != nil || !revoked {
		t.Fatalf("the key ended with 0055's reason: %v %v", revoked, err)
	}
	var transfers, notices int
	w.exec(ctx, t, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM device_transfers), (SELECT count(*) FROM device_notices)`).Scan(&transfers, &notices)
	})
	if transfers != 0 || notices != 0 {
		t.Fatalf("after the down-step: %d transfers with no actor, %d notices of the app", transfers, notices)
	}
	if err := run(ctx, pool, lg, migrationsThrough(t, 53)); err != nil {
		t.Fatalf("a binary that knows 53 after the down-step: %v", err)
	}
	if err := Run(ctx, pool, lg); err != nil {
		t.Fatalf("0055 again: %v", err)
	}
}

// 0055's checks: disabled_by goes with a disabled account and only with
// one, the closing's times come in order, and the new reasons are taken
// where the old CHECKs refused them.
func TestMigration55Checks(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Empty(t)
	if err := Run(ctx, pool, quietLogger(t)); err != nil {
		t.Fatal(err)
	}
	w := newContractWorld(t, pool)
	for name, c := range map[string]struct {
		sql  string
		args []any
		ok   bool
	}{
		"an active account named disabled by someone": {`UPDATE users SET disabled_by = 'operator' WHERE id = $1`, []any{w.owner}, false},
		"a key revoked by the contract": {`INSERT INTO api_keys (tenant_id, prefix, key_hash, name, revoked_at, revoke_reason)
			VALUES ($1, 'abcd6666', 'h', 'k', now(), 'contract')`, []any{w.tenant}, true},
		"a key revoked as an orphan's": {`INSERT INTO api_keys (tenant_id, prefix, key_hash, name, revoked_at, revoke_reason)
			VALUES ($1, 'abcd7777', 'h', 'k', now(), 'orphan_service')`, []any{w.tenant}, true},
		"a closing forgotten unconfirmed":        {`INSERT INTO contract_closings (sub, forgotten_at) VALUES ($1, now())`, []any{uuid.New()}, false},
		"a closing confirmed with no purge date": {`INSERT INTO contract_closings (sub, confirmed_at) VALUES ($1, now())`, []any{uuid.New()}, false},
		"an apply held with no time":             {`INSERT INTO contract_accounts (sub, apply_held) VALUES ($1, 'no_tenant')`, []any{uuid.New()}, false},
		"an unknown hold":                        {`INSERT INTO contract_accounts (sub, apply_held, apply_held_since) VALUES ($1, 'other', now())`, []any{uuid.New()}, false},
	} {
		err := w.try(c.sql, c.args...)
		var pgErr *pgconn.PgError
		switch {
		case c.ok && err != nil:
			t.Errorf("%s: %v", name, err)
		case !c.ok && !(errors.As(err, &pgErr) && pgErr.Code == "23514"):
			t.Errorf("%s: %v, want a CHECK violation", name, err)
		}
	}
}
