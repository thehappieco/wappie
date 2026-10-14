package migrate

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
)

// A migration runs with no app.tenant_id set, so any DELETE or UPDATE it makes
// against a table under row-level security matches nothing at all — silently,
// reporting success. The next statement then fails on rows the migration
// believed it had removed, or worse, does not fail and leaves them behind.
//
// The rule covers what a statement READS as well as what it writes, and that
// half was missing. A backfill of the shape "UPDATE a SET x = (SELECT ... FROM
// b)" needs the policy off on both: with it left on for b, the subquery returns
// nothing, the UPDATE runs against no rows or writes nulls, and the migration
// reports success. 0010_order_by_time is exactly that shape and its backfill
// matched nothing on the live archive — found only because 0012 was about to
// repeat it. It self-healed, which is why nobody noticed for two phases.
//
// This cost a failed boot the first time. It is invisible in CI because test
// databases are empty, which is exactly why it is checked as text rather than
// left to a test that would have to seed a realistic database at an
// intermediate schema version to notice.
//
// The fix at every call site is the same: disable the policy for the length of
// the change, and turn it back on.
func TestMigrationsDoNotWriteThroughRowLevelSecurity(t *testing.T) {
	migrations, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	// Tables that carry a tenant policy at some point in the history, and
	// user_passkeys, whose policy is the account's (app.user_id), which a
	// migration has no more of than it has a workspace. Written out because
	// a migration file cannot be asked what the schema looked like when it
	// ran.
	protected := []string{
		"messages", "chats", "contacts", "media", "receipts", "events",
		"content_keys", "devices", "users", "device_archive_keys",
		"device_key_grants", "tenant_archive_keys", "tenant_key_grants",
		"user_passkeys",
	}

	// Already applied everywhere, so it cannot be edited, and it turns out not
	// to matter: 0004 deduplicates receipts and then adds a primary key over
	// the same columns. The delete silently matched nothing, and the constraint
	// that follows would have failed loudly if there had been anything to
	// remove. It did not fail, so there was not. Recorded rather than hidden,
	// because the next one might not have a constraint behind it.
	known := map[string]bool{
		"0004_receipt_identity/receipts": true,
		// Applied everywhere, so it cannot be edited: the files are
		// checksummed and changing one fails the next boot. Its backfill of
		// chats.last_ts reads FROM messages with the policy still on and
		// therefore matched nothing. Harmless in the end — the GREATEST in the
		// insert path repairs one chat per message, and the live archive has
		// no chat left with a missing timestamp — but recorded rather than
		// quietly excluded, because the next one may have nothing behind it.
		"0010_order_by_time/messages": true,
	}

	for _, m := range migrations {
		body := stripComments(m.SQL)
		for _, stmt := range writeStatements(body) {
			for _, table := range protected {
				// Mentioned anywhere in the statement: written, joined,
				// or read in a subquery. All three need the policy off.
				if !regexp.MustCompile(`(?i)\b` + table + `\b`).MatchString(stmt.text) {
					continue
				}
				if known[fmt.Sprintf("%04d_%s/%s", m.Version, m.Name, table)] {
					continue
				}
				disable := regexp.MustCompile(
					`(?i)ALTER\s+TABLE\s+` + table + `\s+DISABLE\s+ROW\s+LEVEL\s+SECURITY`)
				off := disable.FindStringIndex(body)
				if off == nil || off[0] > stmt.at {
					t.Errorf("%04d_%s has a write statement touching %s, which is under "+
						"row-level security, without disabling the policy first — the "+
						"statement will match no rows, silently",
						m.Version, m.Name, table)
				}
			}
		}
	}
}

// writeStatement is one DELETE or UPDATE, whole, with where it starts.
type writeStatement struct {
	at   int
	text string
}

// startsWrite matches a statement that BEGINS with a write.
//
// Anchored on the statement rather than searched for anywhere in it, because
// "UPDATE" appears in plenty of things that write nothing: "ON CONFLICT DO
// UPDATE SET" in an upsert, and "CREATE TRIGGER ... BEFORE UPDATE ON chats" in
// every table that has a touch trigger. Matching those made the guard report
// five migrations that are correct, which is the failure mode that gets a
// guard deleted.
var startsWrite = regexp.MustCompile(`(?is)^\s*(DELETE\s+FROM|UPDATE)\s+[a-z_]`)

// writeStatements returns each top-level write in the file, as the whole
// statement up to its terminating semicolon.
//
// The whole statement, because the tables a backfill READS are what the guard
// above was missing, and they sit after the write target — in a FROM, a JOIN or
// a subquery.
func writeStatements(body string) []writeStatement {
	var out []writeStatement
	at := 0
	for _, stmt := range strings.SplitAfter(body, ";") {
		if startsWrite.MatchString(stmt) {
			out = append(out, writeStatement{at: at, text: stmt})
		}
		at += len(stmt)
	}
	return out
}

// stripComments removes -- comments so the prose in a migration cannot trip the
// patterns above. Every one of these files explains itself at length.
func stripComments(sql string) string {
	var out strings.Builder
	for line := range strings.SplitSeq(sql, "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return out.String()
}

// The two tables 0050 adds hold who was told what about which number, and
// what happened to it: both force their policy, so a query outside a
// workspace sees none of their rows and a workspace sees only its own.
func TestDeletionTablesForceRowLevelSecurity(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Fresh(t, Run)
	for _, table := range []string{"device_notices", "item_events", "devices"} {
		var enabled, forced bool
		if err := pool.QueryRow(ctx, `SELECT relrowsecurity, relforcerowsecurity FROM pg_class
			WHERE relname=$1 AND relnamespace=current_schema()::regnamespace`, table).Scan(&enabled, &forced); err != nil {
			t.Fatal(err)
		}
		if !enabled || !forced {
			t.Errorf("%s: row-level security %v, forced %v", table, enabled, forced)
		}
	}
	tenants := make([]uuid.UUID, 2)
	for i, name := range []string{"one", "two"} {
		if err := pool.QueryRow(ctx, `INSERT INTO tenants(name) VALUES ($1) RETURNING id`, name).Scan(&tenants[i]); err != nil {
			t.Fatal(err)
		}
		reader := person(t, pool, tenants[i], name+"@example.test", "member")
		if err := pg.InTenantTx(ctx, pool, tenants[i].String(), func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `INSERT INTO device_notices(tenant_id,device_id,user_id,kind,raised_by_kind)
				VALUES ($1,$2,$3,'number_deleted','person')`, tenants[i], uuid.New(), reader); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO item_events(event_id,tenant_id,type,item_id,dedupe_key,occurred_at,actor_kind,deleted_at,purge_after)
				VALUES (uuidv7(),$1,'deleted',$2,$3,clock_timestamp(),'person',clock_timestamp(),clock_timestamp()+interval '30 days')`,
				tenants[i], uuid.New(), "deleted:"+name)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	count := func(table string, tenant *uuid.UUID) int {
		t.Helper()
		var n int
		query := func(q interface {
			QueryRow(context.Context, string, ...any) pgx.Row
		}) error {
			// table is one of two literals in this test, never input.
			return q.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&n)
		}
		var err error
		if tenant == nil {
			err = query(pool)
		} else {
			err = pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error { return query(tx) })
		}
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	for _, table := range []string{"device_notices", "item_events"} {
		if n := count(table, nil); n != 0 {
			t.Errorf("%s: %d rows visible with no workspace set", table, n)
		}
		for i := range tenants {
			if n := count(table, &tenants[i]); n != 1 {
				t.Errorf("%s: workspace %d sees %d rows, want its own one", table, i, n)
			}
		}
	}
	// WITH CHECK: a workspace cannot write a row in another's name.
	err := pg.InTenantTx(ctx, pool, tenants[0].String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO item_events(event_id,tenant_id,type,item_id,dedupe_key,occurred_at,actor_kind,ledgered_at)
			VALUES (uuidv7(),$1,'sync_paused',$2,'sync_paused:x',clock_timestamp(),'person',clock_timestamp())`, tenants[1], uuid.New())
		return err
	})
	if sqlState(err) != "42501" {
		t.Fatalf("an event written in another workspace's name: %v", err)
	}
}
