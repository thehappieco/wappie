package pg_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/migrate"
	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
)

// seedTenant creates a tenant plus one device belonging to it, and returns the
// tenant id. tenants has no RLS (it is consulted before a tenant is known), so
// it can be inserted directly; the device must go through a tenant transaction
// like any real write.
func seedTenant(t *testing.T, pool *pgxpool.Pool, name, lid string) string {
	t.Helper()
	ctx := context.Background()
	var id string
	if err := pool.QueryRow(ctx,
		`INSERT INTO tenants (name) VALUES ($1) RETURNING id::text`, name).Scan(&id); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	err := pg.InTenantTx(ctx, pool, id, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO devices (tenant_id, lid, status) VALUES ($1, $2, 'online')`, id, lid)
		return err
	})
	if err != nil {
		t.Fatalf("insert device: %v", err)
	}
	return id
}

// TestRLSDeniesWithoutTenant is the load-bearing test of the isolation model.
//
// A query that runs without app.tenant_id set must return nothing at all. Not
// an error the caller might swallow, and certainly not another tenant's rows —
// simply no data. That way a handler that forgets to scope its query fails
// closed, and the mistake shows up as an empty screen rather than as a leak.
func TestRLSDeniesWithoutTenant(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()

	seedTenant(t, pool, "acme", "111@lid")
	seedTenant(t, pool, "globex", "222@lid")

	// A plain query outside any tenant transaction.
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM devices`).Scan(&n); err != nil {
		t.Fatalf("count devices: %v", err)
	}
	if n != 0 {
		t.Fatalf("devices visible without app.tenant_id: %d rows — RLS is not protecting this table", n)
	}

	// Every tenant-scoped table. The list is written out rather than derived,
	// because a new table that nobody added here is exactly the mistake this
	// exists to catch — and a query over pg_class would keep passing while it
	// happened.
	//
	// Absent on purpose: api_keys, sessions, user_logins and invites. Each is
	// looked up before any tenant is known — that lookup is what establishes
	// the tenant — and each holds a hash rather than a secret.
	for _, table := range []string{
		"users", "devices", "device_archive_keys", "device_key_grants", "content_keys",
	} {
		var visible int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&visible); err != nil {
			t.Errorf("%s: %v", table, err)
			continue
		}
		if visible != 0 {
			t.Errorf("%s: %d rows visible with no tenant set", table, visible)
		}
	}
}

// The complement: inside a tenant transaction you see your own rows and only
// your own. A test that only checked "zero without tenant" would also pass if
// the policy denied everything always.
func TestRLSScopesToOneTenant(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()

	acme := seedTenant(t, pool, "acme", "111@lid")
	globex := seedTenant(t, pool, "globex", "222@lid")

	for _, tc := range []struct{ tenant, wantLID string }{
		{acme, "111@lid"},
		{globex, "222@lid"},
	} {
		var lids []string
		err := pg.InTenantTx(ctx, pool, tc.tenant, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT lid FROM devices`)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var lid string
				if err := rows.Scan(&lid); err != nil {
					return err
				}
				lids = append(lids, lid)
			}
			return rows.Err()
		})
		if err != nil {
			t.Fatalf("tenant %s: %v", tc.tenant, err)
		}
		if len(lids) != 1 || lids[0] != tc.wantLID {
			t.Errorf("tenant %s saw %v, want exactly [%s]", tc.tenant, lids, tc.wantLID)
		}
	}
}

// WITH CHECK stops a tenant writing a row labelled as another tenant's, which
// is the write-side counterpart to the read isolation above.
func TestRLSRejectsCrossTenantWrite(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()

	acme := seedTenant(t, pool, "acme", "111@lid")
	globex := seedTenant(t, pool, "globex", "222@lid")

	err := pg.InTenantTx(ctx, pool, acme, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO devices (tenant_id, lid, status) VALUES ($1, $2, 'online')`,
			globex, "333@lid")
		return err
	})
	if err == nil {
		t.Fatal("acme was allowed to insert a device belonging to globex")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "row-level security") {
		t.Errorf("expected an RLS violation, got: %v", err)
	}
}

// The tenant setting is transaction-local, so a pooled connection cannot carry
// one tenant's scope into the next tenant's query. Without is_local => true
// this would be a cross-tenant leak that only appears under connection reuse.
func TestTenantSettingDoesNotLeakAcrossTransactions(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()

	acme := seedTenant(t, pool, "acme", "111@lid")
	seedTenant(t, pool, "globex", "222@lid")

	// Run a scoped transaction, then immediately query unscoped. Both are very
	// likely to land on the same pooled connection.
	if err := pg.InTenantTx(ctx, pool, acme, func(tx pgx.Tx) error {
		var n int
		return tx.QueryRow(ctx, `SELECT count(*) FROM devices`).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	for range 10 {
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM devices`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("tenant scope leaked out of its transaction: %d rows visible", n)
		}
	}
}

// A missing tenant id must fail loudly. Silently running with the GUC unset
// would produce an empty result that reads as "no data" instead of "you asked
// this the wrong way".
func TestInTenantTxRequiresTenant(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	err := pg.InTenantTx(context.Background(), pool, "", func(pgx.Tx) error {
		t.Fatal("callback ran without a tenant")
		return nil
	})
	if !errors.Is(err, pg.ErrNoTenant) {
		t.Fatalf("err = %v, want ErrNoTenant", err)
	}
}

func TestInTenantTxRollsBackOnError(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	tenant := seedTenant(t, pool, "acme", "111@lid")

	sentinel := errors.New("caller changed its mind")
	err := pg.InTenantTx(ctx, pool, tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO devices (tenant_id, lid, status) VALUES ($1,$2,'online')`,
			tenant, "999@lid"); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want the sentinel", err)
	}

	var n int
	if err := pg.InTenantTx(ctx, pool, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM devices WHERE lid='999@lid'`).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("the insert survived a rolled-back transaction")
	}
}

// Identity is a (lid, pn) pair with LID primary; either may be absent. The
// partial unique indexes must therefore allow many rows with a null identifier
// while still preventing a duplicate of one that is present.
func TestDeviceIdentityAllowsMissingHalf(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	tenant := seedTenant(t, pool, "acme", "111@lid")

	// A LID-only contact: WhatsApp may never reveal a phone number for it.
	err := pg.InTenantTx(ctx, pool, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO devices (tenant_id, lid, pn, status) VALUES ($1,'444@lid',NULL,'online')`, tenant)
		return err
	})
	if err != nil {
		t.Fatalf("a LID-only device must be allowed: %v", err)
	}

	// But the same LID twice within a tenant is a duplicate.
	err = pg.InTenantTx(ctx, pool, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO devices (tenant_id, lid, status) VALUES ($1,'444@lid','online')`, tenant)
		return err
	})
	if err == nil {
		t.Fatal("duplicate LID within a tenant was accepted")
	}
}

func TestOpenAndPingAllPools(t *testing.T) {
	ctx := context.Background()
	pgtest.Connect(t) // reachability check only; Open uses the shared DSN

	pools, err := pg.Open(ctx, pgtest.Config())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer pools.Close()

	if err := pools.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	// History is capped below live so a backfill cannot starve ingest.
	if pools.History.Config().MaxConns >= pools.Live.Config().MaxConns {
		t.Error("history pool should be smaller than the live pool")
	}
}

func TestOpenFailsClosedOnBadDSN(t *testing.T) {
	cfg := pgtest.Config()
	cfg.DSN = "postgres://nobody:nobody@127.0.0.1:1/nope?sslmode=disable&connect_timeout=1"
	pools, err := pg.Open(context.Background(), cfg)
	if err == nil {
		pools.Close()
		t.Fatal("Open succeeded against an unreachable database")
	}
	if pools != nil {
		t.Error("Open returned pools alongside an error")
	}
}

// The test role is created NOSUPERUSER NOBYPASSRLS, which is the only reason
// the isolation tests above prove anything. CheckRole is what makes a
// deployment find that out at boot rather than never.
func TestCheckRoleAcceptsTheTestRole(t *testing.T) {
	pool := pgtest.Connect(t)
	p := &pg.Pools{Live: pool, History: pool, API: pool}
	if err := p.CheckRole(context.Background()); err != nil {
		t.Fatalf("the test role should pass: %v", err)
	}
}
