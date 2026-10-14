package migrate

import (
	"context"
	"errors"
	"testing"

	"whatserver2/internal/pgtest"
)

// RequireCurrent accepts exactly this binary's migrations, and changes
// nothing when it refuses: no table, one behind, one ahead, or one applied
// from another file.
func TestRequireCurrent(t *testing.T) {
	ctx := context.Background()
	lg := quietLogger(t)
	ms, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	empty := pgtest.Empty(t)
	if err := RequireCurrent(ctx, empty); !errors.Is(err, ErrNotCurrent) {
		t.Fatalf("a database with no migrations: %v", err)
	}
	var exists bool
	if err := empty.QueryRow(ctx, `SELECT to_regclass('schema_migrations') IS NOT NULL`).Scan(&exists); err != nil || exists {
		t.Fatalf("the check created the ledger: %v %v", exists, err)
	}
	pool := pgtest.Empty(t)
	if err := run(ctx, pool, lg, ms[:len(ms)-1]); err != nil {
		t.Fatal(err)
	}
	if err := RequireCurrent(ctx, pool); !errors.Is(err, ErrNotCurrent) {
		t.Fatalf("one version behind: %v", err)
	}
	if err := requireCurrent(ctx, pool, ms[:len(ms)-1]); err != nil {
		t.Fatalf("at the binary's version: %v", err)
	}
	if err := requireCurrent(ctx, pool, ms[:len(ms)-2]); !errors.Is(err, ErrNotCurrent) {
		t.Fatalf("one version ahead: %v", err)
	}
	edited := append([]Migration{}, ms[:len(ms)-1]...)
	edited[3].Checksum = "edited"
	if err := requireCurrent(ctx, pool, edited); !errors.Is(err, ErrNotCurrent) {
		t.Fatalf("a migration applied from another file: %v", err)
	}
}
