package migrate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"whatserver2/internal/pgtest"
)

// preAmendment0048 is the SHA-256 of 0048_platform_identity.sql before step 4
// of the platform sign-in amended it in place (sessions.via_provider and
// platform_login_tickets.auth_time, docs/platform-sign-in.md). That text was
// never deployed; a development database may still have it applied.
const preAmendment0048 = "380b22ad7226c61c603ec731b4778c4a5e7508668127dcc517338a21c45b3be"

// 0048's checksum is the SHA-256 of the file's bytes, the value a release
// records as migration48_sha256 for the down-step check; and a database that
// applied the earlier text stops at boot, as any edited migration does,
// instead of running without the columns this binary reads.
func TestMigration0048IsTheAmendedFile(t *testing.T) {
	ms, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	var m Migration
	for _, candidate := range ms {
		if candidate.Version == 48 {
			m = candidate
		}
	}
	if m.Name != "platform_identity" {
		t.Fatalf("migration 48 is %q", m.Name)
	}
	body, err := embedded.ReadFile("sql/0048_platform_identity.sql")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	if m.Checksum != hex.EncodeToString(sum[:]) || m.Checksum == preAmendment0048 {
		t.Fatalf("checksum %s", m.Checksum)
	}
	for _, want := range []string{
		"ADD COLUMN via_provider       boolean NOT NULL DEFAULT false",
		"auth_time      timestamptz,",
		"WHERE (via_provider OR authenticated_at = '-infinity') AND revoked_at IS NULL;",
		"DROP COLUMN step_up_not_before, DROP COLUMN via_provider;",
	} {
		if !strings.Contains(m.SQL, want) {
			t.Errorf("0048 lacks %q", want)
		}
	}

	pool := pgtest.Empty(t)
	ctx := context.Background()
	lg := quietLogger(t)
	if err := Run(ctx, pool, lg); err != nil {
		t.Fatal(err)
	}
	var recorded string
	if err := pool.QueryRow(ctx, `SELECT checksum FROM schema_migrations WHERE version = 48`).Scan(&recorded); err != nil || recorded != m.Checksum {
		t.Fatalf("the ledger recorded %q %v", recorded, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE schema_migrations SET checksum = $1 WHERE version = 48`, preAmendment0048); err != nil {
		t.Fatal(err)
	}
	if err := Run(ctx, pool, lg); !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("a database on the earlier 0048: %v", err)
	}
}
