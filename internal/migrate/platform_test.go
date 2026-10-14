package migrate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

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

// dataStatement is what 0049 may hold: writes, and the row-level security
// switches a migration lifts and puts back around them (0021).
var dataStatement = regexp.MustCompile(`^(UPDATE [a-z_]+ SET |DELETE FROM [a-z_]+ |ALTER TABLE [a-z_]+ (DISABLE|ENABLE|FORCE) ROW LEVEL SECURITY$)`)

// 0049 changes data only, so its down-step is the ledger row: a database
// that applied it has 48's schema exactly, and once the row is gone a binary
// that knows 48 but not 49 starts on it. Applied again when the release
// comes back, it changes nothing.
func TestMigration0049IsDataOnly(t *testing.T) {
	ms, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	// Through 49 only: 0050 changes the schema, and comes down before 0049.
	var through48, through49 []Migration
	var m Migration
	for _, candidate := range ms {
		if candidate.Version <= 48 {
			through48 = append(through48, candidate)
		}
		if candidate.Version <= 49 {
			through49 = append(through49, candidate)
		}
		if candidate.Version == 49 {
			m = candidate
		}
	}
	if m.Name != "platform_window_end" || !m.InTx {
		t.Fatalf("migration 49 is %q (in a transaction: %v)", m.Name, m.InTx)
	}
	for stmt := range strings.SplitSeq(stripComments(m.SQL), ";") {
		if s := strings.Join(strings.Fields(stmt), " "); s != "" && !dataStatement.MatchString(s) {
			t.Errorf("0049 holds a statement that is not data: %q", s)
		}
	}
	for _, want := range []string{
		"--      DELETE FROM schema_migrations WHERE version = 49;\n",
		"What this migration nulled and deleted does not come back",
	} {
		if !strings.Contains(m.SQL, want) {
			t.Errorf("0049's header lacks %q", want)
		}
	}

	ctx := context.Background()
	lg := quietLogger(t)
	at48 := pgtest.Empty(t)
	if err := run(ctx, at48, lg, through48); err != nil {
		t.Fatal(err)
	}
	at49 := pgtest.Empty(t)
	if err := run(ctx, at49, lg, through49); err != nil {
		t.Fatal(err)
	}
	want := schemaShape(t, at48)
	sameShape := func(when string) {
		t.Helper()
		got := schemaShape(t, at49)
		if len(got) != len(want) {
			t.Fatalf("%s: %d schema facts, 48 has %d", when, len(got), len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s: %q where 48 has %q", when, got[i], want[i])
			}
		}
	}
	sameShape("after 0049")
	if err := run(ctx, at49, lg, through48); err == nil || !strings.Contains(err.Error(), "newer than this build") {
		t.Fatalf("a binary that knows 48 before the down-step: %v", err)
	}
	if _, err := at49.Exec(ctx, `DELETE FROM schema_migrations WHERE version = 49`); err != nil {
		t.Fatal(err)
	}
	if err := run(ctx, at49, lg, through48); err != nil {
		t.Fatalf("a binary that knows 48 after the down-step: %v", err)
	}
	sameShape("after the down-step")
	if err := run(ctx, at49, lg, through49); err != nil {
		t.Fatalf("0049 again: %v", err)
	}
	sameShape("after 0049 again")
	var n int
	if err := at49.QueryRow(ctx, `SELECT count(*) FROM schema_migrations WHERE version = 49`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("the ledger has %d rows for 49: %v", n, err)
	}
}

// 0049 leaves a linked account's key under the provider's product key alone,
// and covers every account linked whenever it runs, a second run included.
// Its header and the contract say both, and neither promises an account
// linked after it its legacy credentials for good.
func TestMigration0049SaysWhatItCosts(t *testing.T) {
	ms, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	var header string
	for _, m := range ms {
		if m.Version == 49 {
			header = m.SQL
		}
	}
	doc, err := os.ReadFile("../../docs/platform-sign-in.md")
	if err != nil {
		t.Fatal(err)
	}
	flat := func(s string) string { return strings.Join(strings.Fields(strings.ReplaceAll(s, "\n-- ", "\n")), " ") }
	for _, c := range []struct {
		name, text  string
		want, never []string
	}{
		{"0049's header", flat(header), []string{
			"So the account key hangs on the provider alone.",
			"After it, platform_wraps is the only one, and the console cannot rewrap a new epoch yet",
			"Until the console's rewrap ships, keep a database backup from before this migration and the old password",
			"It covers every account linked when it runs",
			"until this migration runs again (after its down-step, when a release that carries it comes back), and then loses them too.",
		}, []string{"a replay on a database where this already ran changes nothing"}},
		{"docs/platform-sign-in.md", flat(string(doc)), []string{
			"**What it costs: the account key hangs on id. alone.**",
			"After it, `platform_wraps` is the only one, and the console cannot rewrap a new epoch yet",
			"the operator who runs 0049 keeps a database backup from before it, and the account's owner keeps the old password",
			"0049 is applied anew and nulls and deletes the same things for every account linked by then, the ones linked since its first run included.",
			"after checking the file against `migration49_sha256` in the release's `RELEASE.json`",
		}, []string{"nothing removes them yet", "Run again, it changes nothing."}},
	} {
		for _, want := range c.want {
			if !strings.Contains(c.text, want) {
				t.Errorf("%s does not say %q", c.name, want)
			}
		}
		for _, never := range c.never {
			if strings.Contains(c.text, never) {
				t.Errorf("%s still says %q", c.name, never)
			}
		}
	}
}

// schemaShape lists what a migration can change in the pool's schema, one
// line per fact, sorted: tables and their row-level security, columns,
// constraints, indexes, policies, triggers and functions. The schema's own
// name is left out, so two test schemas compare.
func schemaShape(t *testing.T, pool *pgxpool.Pool) []string {
	t.Helper()
	ctx := context.Background()
	var out []string
	for _, query := range []string{
		`SELECT relname || ' ' || relkind::text || ' rls=' || relrowsecurity || ' force=' || relforcerowsecurity
		   FROM pg_class WHERE relnamespace = current_schema()::regnamespace AND relkind IN ('r', 'p', 'v', 'S')`,
		`SELECT table_name || '.' || column_name || ' ' || udt_name || ' null=' || is_nullable || ' default=' || coalesce(column_default, '')
		   FROM information_schema.columns WHERE table_schema = current_schema()`,
		`SELECT conrelid::regclass::text || ' ' || conname || ' ' || pg_get_constraintdef(oid)
		   FROM pg_constraint WHERE connamespace = current_schema()::regnamespace`,
		`SELECT replace(indexdef, current_schema() || '.', '') FROM pg_indexes WHERE schemaname = current_schema()`,
		`SELECT tablename || ' ' || policyname || ' ' || cmd || ' ' || coalesce(qual, '') || ' ' || coalesce(with_check, '')
		   FROM pg_policies WHERE schemaname = current_schema()`,
		`SELECT replace(pg_get_triggerdef(oid), current_schema() || '.', '') || ' ' || tgenabled::text
		   FROM pg_trigger WHERE NOT tgisinternal AND tgrelid IN (SELECT oid FROM pg_class WHERE relnamespace = current_schema()::regnamespace)`,
		`SELECT proname || ' ' || md5(prosrc) FROM pg_proc WHERE pronamespace = current_schema()::regnamespace`,
	} {
		rows, err := pool.Query(ctx, query)
		if err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		facts, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		out = append(out, facts...)
	}
	sort.Strings(out)
	return out
}
