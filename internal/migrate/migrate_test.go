package migrate

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/pgtest"
)

func quietLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(logWriter{t}, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

type logWriter struct{ t *testing.T }

func (w logWriter) Write(p []byte) (int, error) { w.t.Logf("%s", p); return len(p), nil }

func TestLoadEmbedded(t *testing.T) {
	ms, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(ms) == 0 {
		t.Fatal("no migrations embedded")
	}
	for i, m := range ms {
		if i > 0 && m.Version <= ms[i-1].Version {
			t.Errorf("migrations out of order at %d: %d after %d", i, m.Version, ms[i-1].Version)
		}
		if m.Checksum == "" || len(m.Checksum) != 64 {
			t.Errorf("%04d_%s: bad checksum %q", m.Version, m.Name, m.Checksum)
		}
		if strings.TrimSpace(m.SQL) == "" {
			t.Errorf("%04d_%s is empty", m.Version, m.Name)
		}
	}
}

func TestLoadRejectsBadNames(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"no version prefix": {"sql/create_users.sql": "SELECT 1"},
		"short version":     {"sql/001_users.sql": "SELECT 1"},
		"uppercase slug":    {"sql/0001_Users.sql": "SELECT 1"},
		"duplicate version": {"sql/0001_a.sql": "SELECT 1", "sql/0001_b.sql": "SELECT 1"},
	} {
		t.Run(name, func(t *testing.T) {
			fsys := fstest.MapFS{}
			for path, body := range files {
				fsys[path] = &fstest.MapFile{Data: []byte(body)}
			}
			if _, err := loadFS(fsys, "sql"); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestNoTransactionDirective(t *testing.T) {
	fsys := fstest.MapFS{
		"sql/0001_plain.sql":  &fstest.MapFile{Data: []byte("SELECT 1")},
		"sql/0002_concur.sql": &fstest.MapFile{Data: []byte(noTxDirective + "\nSELECT 1")},
	}
	ms, err := loadFS(fsys, "sql")
	if err != nil {
		t.Fatal(err)
	}
	if !ms[0].InTx {
		t.Error("plain migration should run in a transaction")
	}
	if ms[1].InTx {
		t.Error("directive should opt out of the transaction")
	}
}

func TestRunAppliesAndIsIdempotent(t *testing.T) {
	pool := pgtest.Empty(t)
	ctx := context.Background()
	lg := quietLogger(t)

	if err := Run(ctx, pool, lg); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	first := ledgerRows(t, pool)
	if first == 0 {
		t.Fatal("nothing recorded in schema_migrations")
	}

	// A second run must be a no-op, not a re-application.
	if err := Run(ctx, pool, lg); err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if got := ledgerRows(t, pool); got != first {
		t.Fatalf("ledger grew from %d to %d on a repeat run", first, got)
	}
}

// Editing an applied migration is how environments silently diverge. The boot
// must stop rather than paper over it.
func TestChecksumMismatchStopsBoot(t *testing.T) {
	pool := pgtest.Empty(t)
	ctx := context.Background()
	lg := quietLogger(t)

	original := []Migration{{Version: 1, Name: "init", SQL: "CREATE TABLE t (id int)", Checksum: "aaaa", InTx: true}}
	if err := run(ctx, pool, lg, original); err != nil {
		t.Fatalf("apply: %v", err)
	}

	edited := []Migration{{Version: 1, Name: "init", SQL: "CREATE TABLE t (id bigint)", Checksum: "bbbb", InTx: true}}
	err := run(ctx, pool, lg, edited)
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("err = %v, want ErrChecksumMismatch", err)
	}
	if !strings.Contains(err.Error(), "add a new migration") {
		t.Errorf("error should say what to do instead:\n%v", err)
	}
}

// The verification pass runs before anything is applied, so a tampered old
// migration is caught without leaving a half-migrated schema behind.
func TestChecksumIsVerifiedBeforeApplyingAnything(t *testing.T) {
	pool := pgtest.Empty(t)
	ctx := context.Background()
	lg := quietLogger(t)

	if err := run(ctx, pool, lg, []Migration{
		{Version: 1, Name: "init", SQL: "CREATE TABLE a (id int)", Checksum: "aaaa", InTx: true},
	}); err != nil {
		t.Fatal(err)
	}
	err := run(ctx, pool, lg, []Migration{
		{Version: 1, Name: "init", SQL: "CREATE TABLE a (id int)", Checksum: "TAMPERED", InTx: true},
		{Version: 2, Name: "next", SQL: "CREATE TABLE b (id int)", Checksum: "bbbb", InTx: true},
	})
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("err = %v, want ErrChecksumMismatch", err)
	}
	if tableExists(t, pool, "b") {
		t.Error("migration 2 was applied despite the checksum failure on migration 1")
	}
}

// A database ahead of the binary means someone rolled back a deploy. Guessing
// is not safe, so refuse.
func TestDatabaseAheadOfBinaryStopsBoot(t *testing.T) {
	pool := pgtest.Empty(t)
	ctx := context.Background()
	lg := quietLogger(t)

	if err := run(ctx, pool, lg, []Migration{
		{Version: 1, Name: "init", SQL: "CREATE TABLE a (id int)", Checksum: "aaaa", InTx: true},
		{Version: 2, Name: "newer", SQL: "CREATE TABLE b (id int)", Checksum: "bbbb", InTx: true},
	}); err != nil {
		t.Fatal(err)
	}
	err := run(ctx, pool, lg, []Migration{
		{Version: 1, Name: "init", SQL: "CREATE TABLE a (id int)", Checksum: "aaaa", InTx: true},
	})
	if err == nil || !strings.Contains(err.Error(), "newer than this build") {
		t.Fatalf("err = %v, want a complaint about the database being newer", err)
	}
}

// A failing migration must leave nothing behind.
func TestFailedMigrationRollsBack(t *testing.T) {
	pool := pgtest.Empty(t)
	ctx := context.Background()

	err := run(ctx, pool, quietLogger(t), []Migration{{
		Version: 1, Name: "broken", Checksum: "aaaa", InTx: true,
		SQL: `CREATE TABLE good (id int); CREATE TABLE bad (id nonexistent_type);`,
	}})
	if err == nil {
		t.Fatal("expected the migration to fail")
	}
	if tableExists(t, pool, "good") {
		t.Error("the first statement survived a failed migration")
	}
	if ledgerRows(t, pool) != 0 {
		t.Error("a failed migration was recorded in the ledger")
	}
}

// Rolling deploys start several instances at once. One applies; the rest wait
// on the advisory lock and then find nothing to do.
func TestConcurrentRunsAreSafe(t *testing.T) {
	pool := pgtest.Empty(t)
	ctx := context.Background()

	const racers = 6
	var wg sync.WaitGroup
	errs := make([]error, racers)
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Each racer gets its own pool but the same private schema, so
			// they genuinely contend for the advisory lock.
			racer, err := poolOn(ctx, schemaOf(ctx, t, pool))
			if err != nil {
				errs[i] = err
				return
			}
			defer racer.Close()
			errs[i] = Run(ctx, racer, slog.New(slog.DiscardHandler))
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("racer %d: %v", i, err)
		}
	}

	ms, _ := Load()
	if got := ledgerRows(t, pool); got != len(ms) {
		t.Fatalf("ledger has %d rows after %d concurrent runs, want %d", got, racers, len(ms))
	}
}

// schemaOf reports the private schema a pool is scoped to.
func schemaOf(ctx context.Context, t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var schema string
	if err := pool.QueryRow(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatalf("current schema: %v", err)
	}
	return schema
}

// poolOn opens an independent pool scoped to the same schema.
func poolOn(ctx context.Context, schema string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(pgtest.DSN())
	if err != nil {
		return nil, err
	}
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	return pgxpool.NewWithConfig(ctx, cfg)
}

func ledgerRows(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM schema_migrations`).Scan(&n)
	if err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			return 0
		}
		t.Fatalf("count ledger: %v", err)
	}
	return n
}

func tableExists(t *testing.T, pool *pgxpool.Pool, name string) bool {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(context.Background(),
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables
		                WHERE table_schema='public' AND table_name=$1)`, name).Scan(&exists); err != nil {
		t.Fatalf("table lookup: %v", err)
	}
	return exists
}
