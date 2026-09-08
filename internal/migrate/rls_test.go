package migrate

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
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

	// Tables that carry a tenant policy at some point in the history. Written
	// out because a migration file cannot be asked what the schema looked like
	// when it ran.
	protected := []string{
		"messages", "chats", "contacts", "media", "receipts", "events",
		"content_keys", "devices", "users", "device_archive_keys",
		"device_key_grants", "tenant_archive_keys", "tenant_key_grants",
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
