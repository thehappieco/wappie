// Package pgtest gives tests a real Postgres.
//
// Not a mock and not SQLite. Row-level security, partial unique indexes,
// advisory locks, uuidv7 and transaction-local GUCs are the load-bearing parts
// of this schema, and none of them exist in a fake. A test that passes against
// a substitute proves nothing about the thing that ships.
//
// Every test gets its own Postgres schema, isolated by search_path. That is not
// tidiness: `go test ./...` runs packages in parallel, so a shared schema means
// one package can drop tables out from under another. Tests that pass alone and
// fail together are worse than no tests, because they teach the team to rerun
// until green.
//
// Tests skip when no database is reachable, so `go test ./...` still works on a
// machine without one. CI sets WS_TEST_POSTGRES_REQUIRED and treats a skip as a
// failure, so the coverage cannot quietly evaporate.
package pgtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/config"
)

// This is a local development credential for a throwaway database, matching
// docker-compose.dev.yml. It grants nothing anywhere else.
//
//nolint:gosec // G101: local dev DSN, not a secret
const defaultDSN = "postgres://whatserver2_app:dev@localhost:5432/whatserver2_test?sslmode=disable"

// Migrator applies migrations. Taken as a parameter rather than imported so
// that internal/migrate can use this package without an import cycle.
type Migrator func(context.Context, *pgxpool.Pool, *slog.Logger) error

// DSN returns the test database DSN.
func DSN() string {
	if v := os.Getenv("WS_TEST_POSTGRES_DSN"); v != "" {
		return v
	}
	return defaultDSN
}

// Config returns a pool configuration sized for tests.
func Config() config.Postgres {
	return config.Postgres{
		DSN:              DSN(),
		LiveConns:        4,
		HistoryConns:     2,
		APIConns:         4,
		ConnMaxLifetime:  time.Hour,
		ConnMaxIdleTime:  time.Minute,
		StatementTimeout: 15 * time.Second,
	}
}

// Connect returns a pool on the shared default schema.
//
// Prefer Empty or Fresh. This exists for tests that only need to know whether a
// database is reachable, and for those that manage their own isolation.
func Connect(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, DSN())
	if err == nil {
		err = pool.Ping(ctx)
	}
	if err != nil {
		if pool != nil {
			pool.Close()
		}
		skipOrFail(t, err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// Empty returns a pool scoped to a private, empty schema.
func Empty(t *testing.T) *pgxpool.Pool {
	t.Helper()
	return newIsolated(t)
}

// Fresh returns a pool scoped to a private schema with apply already run.
// Pass migrate.Run as apply.
func Fresh(t *testing.T, apply Migrator) *pgxpool.Pool {
	t.Helper()
	pool := newIsolated(t)
	quiet := slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelWarn}))
	if err := apply(context.Background(), pool, quiet); err != nil {
		t.Fatalf("pgtest: migrate: %v", err)
	}
	return pool
}

// safeSchemaName keeps generated identifiers to characters that need no
// quoting, since they are interpolated into DDL that cannot take parameters.
var safeSchemaName = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

func newIsolated(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	schema := schemaName(t)
	if !safeSchemaName.MatchString(schema) {
		t.Fatalf("pgtest: generated an unsafe schema name %q", schema)
	}

	cfg, err := pgxpool.ParseConfig(DSN())
	if err != nil {
		t.Fatalf("pgtest: parse dsn: %v", err)
	}
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	// Every connection from this pool resolves unqualified names inside the
	// private schema, so migrations and queries land there without a single
	// call site needing to know.
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	cfg.MaxConns = 8

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err == nil {
		err = pool.Ping(ctx)
	}
	if err != nil {
		if pool != nil {
			pool.Close()
		}
		skipOrFail(t, err)
	}

	// Postgres accepts a search_path naming a schema that does not exist yet;
	// it simply resolves to nothing until the schema is created.
	if _, err := pool.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS "+schema); err != nil {
		pool.Close()
		t.Fatalf("pgtest: create schema %s: %v", schema, err)
	}

	t.Cleanup(func() {
		pool.Close()
		// A separate short-lived connection: the pool is closed by now, and
		// dropping the schema through it would be a use-after-close.
		dropCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		dropper, err := pgxpool.New(dropCtx, DSN())
		if err != nil {
			return
		}
		defer dropper.Close()
		if _, err := dropper.Exec(dropCtx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE"); err != nil {
			t.Logf("pgtest: could not drop schema %s: %v", schema, err)
		}
	})
	return pool
}

// schemaName derives a readable, unique schema name from the test name. The
// random suffix covers repeated runs and subtests that share a name.
func schemaName(t *testing.T) string {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		t.Fatalf("pgtest: entropy: %v", err)
	}
	base := strings.ToLower(t.Name())
	base = regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(base, "_")
	base = strings.Trim(base, "_")
	if len(base) > 30 {
		base = base[:30]
	}
	if base == "" {
		base = "test"
	}
	return fmt.Sprintf("t_%s_%s", base, hex.EncodeToString(buf[:]))
}

// Reset empties a pool's schema without applying migrations.
//
// Only valid on a pool from Empty or Fresh, where search_path names a private
// schema. Calling it on a shared pool would drop the schema other packages are
// using — which is exactly the failure this package now prevents.
func Reset(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var schema string
	if err := pool.QueryRow(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatalf("pgtest: current schema: %v", err)
	}
	if schema == "public" {
		t.Fatal("pgtest: refusing to reset the shared public schema; use Empty or Fresh")
	}
	if _, err := pool.Exec(ctx,
		"DROP SCHEMA IF EXISTS "+schema+" CASCADE; CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("pgtest: reset schema: %v", err)
	}
}

func skipOrFail(t *testing.T, err error) {
	t.Helper()
	if os.Getenv("WS_TEST_POSTGRES_REQUIRED") != "" {
		t.Fatalf("pgtest: Postgres is required in this environment but unreachable: %v", err)
	}
	t.Skipf("pgtest: no Postgres at %s (%v); set WS_TEST_POSTGRES_DSN or run `make dev-up`",
		DSN(), err)
}

// testWriter routes migration logs into the test output.
type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s", p)
	return len(p), nil
}
