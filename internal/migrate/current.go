package migrate

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotCurrent is a database whose schema is not exactly this binary's.
var ErrNotCurrent = errors.New("migrate: the database's schema is not this binary's")

// RequireCurrent checks, without changing anything, that the database has
// exactly the migrations this binary knows, each as it is on disk. The
// commands that must never migrate ask it: a dry run against a restored
// snapshot, the deletion ledger's export before a down-step, an operator's
// list. Migrating there would apply what the operator meant to inspect (or,
// before 0049, null the very wraps an older snapshot is kept for), and the
// older release would then refuse the newer schema.
func RequireCurrent(ctx context.Context, pool *pgxpool.Pool) error {
	migrations, err := Load()
	if err != nil {
		return err
	}
	return requireCurrent(ctx, pool, migrations)
}

func requireCurrent(ctx context.Context, pool *pgxpool.Pool, migrations []Migration) error {
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('schema_migrations') IS NOT NULL`).Scan(&exists); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	if !exists {
		return fmt.Errorf("%w: it has no migrations at all, this binary is at %d", ErrNotCurrent, currentVersion(migrations))
	}
	rows, err := pool.Query(ctx, `SELECT version, name, checksum FROM schema_migrations ORDER BY version`)
	if err != nil {
		return fmt.Errorf("migrate: read ledger: %w", err)
	}
	ledger := map[int]applied{}
	top := 0
	for rows.Next() {
		var a applied
		if err := rows.Scan(&a.Version, &a.Name, &a.Checksum); err != nil {
			rows.Close()
			return fmt.Errorf("migrate: scan ledger: %w", err)
		}
		ledger[a.Version] = a
		top = max(top, a.Version)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("migrate: read ledger: %w", err)
	}
	want := currentVersion(migrations)
	for _, m := range migrations {
		a, ok := ledger[m.Version]
		if !ok {
			return fmt.Errorf("%w: it is at %d without %04d_%s, this binary is at %d; run the migrations as their own step first",
				ErrNotCurrent, top, m.Version, m.Name, want)
		}
		if a.Checksum != m.Checksum {
			return fmt.Errorf("%w: %04d_%s was applied from another file (%s, on disk %s)", ErrNotCurrent, m.Version, m.Name, short(a.Checksum), short(m.Checksum))
		}
		delete(ledger, m.Version)
	}
	if len(ledger) > 0 {
		a := ledger[top]
		return fmt.Errorf("%w: it has %04d_%s, which this binary does not know; it is newer than this build", ErrNotCurrent, a.Version, a.Name)
	}
	return nil
}
