// Package migrate applies versioned SQL migrations.
//
// The v1 server had no migration system at all: it re-ran a schema.sql full of
// CREATE TABLE IF NOT EXISTS on every boot, plus one hand-written function that
// dropped legacy columns. That works right up until a column needs to change
// type, and it gives no answer to "which schema is this database actually on".
//
// Three properties this implementation guarantees:
//
//   - Checksums. An already-applied file that has been edited stops the boot.
//     Editing applied migrations is how staging and production silently diverge;
//     the fix is a new migration, and the process refuses to let you forget.
//
//   - An advisory lock. Several instances starting at once is normal in any
//     rolling deploy. One applies, the rest wait and then find nothing to do.
//
//   - One transaction per migration. A migration either lands completely or not
//     at all, so a failure never leaves a half-built schema behind.
package migrate

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed sql/*.sql
var embedded embed.FS

// lockKey is an arbitrary but fixed 64-bit constant for pg_advisory_lock. It
// only has to be unique among advisory locks this application takes.
const lockKey int64 = 0x5748_4154_5345_5256 // "WHATSERV"

// nameRE matches NNNN_description.sql — a zero-padded version and a slug.
var nameRE = regexp.MustCompile(`^(\d{4})_([a-z0-9_]+)\.sql$`)

// noTxDirective opts a migration out of the wrapping transaction, for the
// statements Postgres refuses to run inside one (CREATE INDEX CONCURRENTLY,
// ALTER TYPE ... ADD VALUE on older versions).
const noTxDirective = "-- migrate:no-transaction"

// Migration is one file on disk.
type Migration struct {
	Version  int
	Name     string
	SQL      string
	Checksum string
	InTx     bool
}

// Load reads and validates the embedded migrations.
func Load() ([]Migration, error) { return loadFS(embedded, "sql") }

func loadFS(fsys fs.FS, dir string) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("migrate: read %s: %w", dir, err)
	}
	var out []Migration
	seen := map[int]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		m := nameRE.FindStringSubmatch(e.Name())
		if m == nil {
			return nil, fmt.Errorf("migrate: %q does not match NNNN_description.sql", e.Name())
		}
		version, err := strconv.Atoi(m[1])
		if err != nil { // unreachable: the regex already matched four digits
			return nil, fmt.Errorf("migrate: %q: bad version: %w", e.Name(), err)
		}
		if prev, dup := seen[version]; dup {
			return nil, fmt.Errorf("migrate: version %d used by both %q and %q", version, prev, e.Name())
		}
		seen[version] = e.Name()

		body, readErr := fs.ReadFile(fsys, dir+"/"+e.Name())
		if readErr != nil {
			return nil, fmt.Errorf("migrate: read %s: %w", e.Name(), readErr)
		}
		sum := sha256.Sum256(body)
		out = append(out, Migration{
			Version:  version,
			Name:     m[2],
			SQL:      string(body),
			Checksum: hex.EncodeToString(sum[:]),
			InTx:     !strings.Contains(string(body), noTxDirective),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

// applied is one row of the ledger.
type applied struct {
	Version  int
	Name     string
	Checksum string
}

// ErrChecksumMismatch means a migration already applied to this database has
// been edited since. The remedy is a new migration, never an edit.
var ErrChecksumMismatch = errors.New("migrate: an applied migration has been modified")

// Run applies every pending migration. It is safe to call concurrently from
// several processes.
func Run(ctx context.Context, pool *pgxpool.Pool, lg *slog.Logger) error {
	migrations, err := Load()
	if err != nil {
		return err
	}
	return run(ctx, pool, lg, migrations)
}

func run(ctx context.Context, pool *pgxpool.Pool, lg *slog.Logger, migrations []Migration) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("migrate: acquire: %w", err)
	}
	defer conn.Release()

	// Held for the whole run and released when the session ends, so a crashed
	// migrator cannot deadlock the next deploy.
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", lockKey); err != nil {
		return fmt.Errorf("migrate: acquire advisory lock: %w", err)
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if _, err := conn.Exec(unlockCtx, "SELECT pg_advisory_unlock($1)", lockKey); err != nil {
			lg.Warn("migrate: releasing advisory lock failed; it frees on disconnect", "error", err)
		}
	}()

	if _, err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version     integer     PRIMARY KEY,
			name        text        NOT NULL,
			checksum    text        NOT NULL,
			applied_at  timestamptz NOT NULL DEFAULT now(),
			duration_ms integer     NOT NULL
		)`); err != nil {
		return fmt.Errorf("migrate: create ledger: %w", err)
	}

	rows, err := conn.Query(ctx, `SELECT version, name, checksum FROM schema_migrations ORDER BY version`)
	if err != nil {
		return fmt.Errorf("migrate: read ledger: %w", err)
	}
	ledger := map[int]applied{}
	for rows.Next() {
		var a applied
		if err := rows.Scan(&a.Version, &a.Name, &a.Checksum); err != nil {
			rows.Close()
			return fmt.Errorf("migrate: scan ledger: %w", err)
		}
		ledger[a.Version] = a
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("migrate: read ledger: %w", err)
	}

	// Verify everything already applied before applying anything new: a
	// tampered old migration should stop the boot, not be discovered halfway
	// through a partially-migrated schema.
	for _, m := range migrations {
		a, ok := ledger[m.Version]
		if !ok {
			continue
		}
		if a.Checksum != m.Checksum {
			return fmt.Errorf("%w: %04d_%s (applied %s, on disk %s) — add a new migration instead of editing this one",
				ErrChecksumMismatch, m.Version, m.Name, short(a.Checksum), short(m.Checksum))
		}
	}
	// A database ahead of the binary means someone deployed a newer version
	// and rolled back. Running the old binary against the new schema is not
	// safe to guess at.
	known := map[int]bool{}
	for _, m := range migrations {
		known[m.Version] = true
	}
	for version, a := range ledger {
		if !known[version] {
			return fmt.Errorf("migrate: database has migration %04d_%s which this binary does not know about; it is newer than this build",
				version, a.Name)
		}
	}

	var count int
	for _, m := range migrations {
		if _, done := ledger[m.Version]; done {
			continue
		}
		start := time.Now()
		if err := apply(ctx, conn.Conn(), m); err != nil {
			return fmt.Errorf("migrate: %04d_%s: %w", m.Version, m.Name, err)
		}
		lg.Info("migration applied",
			"version", m.Version, "name", m.Name, "duration", time.Since(start).Round(time.Millisecond))
		count++
	}
	if count == 0 {
		lg.Debug("migrate: schema is up to date", "version", currentVersion(migrations))
	} else {
		lg.Info("migrate: schema updated", "applied", count, "version", currentVersion(migrations))
	}
	return nil
}

func apply(ctx context.Context, conn *pgx.Conn, m Migration) error {
	record := `INSERT INTO schema_migrations (version, name, checksum, duration_ms) VALUES ($1,$2,$3,$4)`
	start := time.Now()

	if !m.InTx {
		if _, err := conn.Exec(ctx, m.SQL); err != nil {
			return err
		}
		_, err := conn.Exec(ctx, record, m.Version, m.Name, m.Checksum, time.Since(start).Milliseconds())
		return err
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	// Rollback after a successful commit returns ErrTxClosed, so the error is
	// expected on the happy path and there is nothing useful to do with it.
	//nolint:errcheck // deferred rollback is a no-op once committed
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, m.SQL); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, record, m.Version, m.Name, m.Checksum, time.Since(start).Milliseconds()); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func currentVersion(ms []Migration) int {
	if len(ms) == 0 {
		return 0
	}
	return ms[len(ms)-1].Version
}

func short(sum string) string {
	if len(sum) > 12 {
		return sum[:12]
	}
	return sum
}
