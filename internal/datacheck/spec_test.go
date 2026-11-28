package datacheck

import (
	"context"
	"slices"
	"testing"

	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
)

// TestEveryColumnIsDecided: every column of a digested table is in exactly
// one of the spec's lists (or is tenant_id or device_id), so a migration
// that adds a column fails here until someone decides whether a digest
// covers it: a new column goes into split (its own digest), so the
// manifests before and after the migration keep the row digest equal. The
// devices and tenants fields the manifest shows exist.
func TestEveryColumnIsDecided(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	columns := func(table string) []string {
		t.Helper()
		rows, err := pool.Query(ctx, `SELECT column_name FROM information_schema.columns
			WHERE table_schema = current_schema() AND table_name = $1 ORDER BY column_name`, table)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var c string
			if err := rows.Scan(&c); err != nil {
				t.Fatal(err)
			}
			out = append(out, c)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		if len(out) == 0 {
			t.Fatalf("no table %s", table)
		}
		return out
	}
	for _, s := range tables {
		seen := map[string]int{"tenant_id": 1}
		if s.device == "" {
			seen["device_id"] = 1
		}
		for _, list := range [][]string{s.key, s.clear, s.split, s.sealed, s.seq, s.leftOut} {
			for _, c := range list {
				seen[c]++
			}
		}
		for _, c := range s.nulls {
			if !slices.Contains(s.clear, c) && !slices.Contains(s.split, c) {
				t.Errorf("%s: a NULL count of %s, which is not a clear or split column", s.name, c)
			}
		}
		have := columns(s.name)
		for _, c := range have {
			switch seen[c] {
			case 0:
				t.Errorf("%s.%s: no digest decides it (key, clear, split, sealed, seq or left out; a new column goes into split)", s.name, c)
			case 1:
			default:
				t.Errorf("%s.%s: in %d lists", s.name, c, seen[c])
			}
		}
		for c := range seen {
			if !slices.Contains(have, c) {
				t.Errorf("%s.%s: no such column", s.name, c)
			}
		}
	}
	for table, fields := range map[string][]string{"devices": deviceFields, "tenants": workspaceFields} {
		have := columns(table)
		for _, f := range fields {
			if !slices.Contains(have, f) {
				t.Errorf("%s.%s: no such column", table, f)
			}
		}
		for _, never := range []string{"label", "pn", "lid", "push_name", "name", "status_reason", "wa_leftover", "avatar"} {
			if slices.Contains(fields, never) {
				t.Errorf("%s.%s is shown", table, never)
			}
		}
	}
}

// TestMatch: "**" spans segments, "*" one.
func TestMatch(t *testing.T) {
	for _, c := range []struct {
		p, k string
		ok   bool
	}{
		{"schema/**", "schema/53/name", true},
		{"schema/**", "schema", true},
		{"workspaces/*/devices/*/tables/messages/rows", "workspaces/a/devices/b/tables/messages/rows", true},
		{"workspaces/*/devices/*/tables/messages/rows", "workspaces/a/devices/b/tables/chats/rows", false},
		{"workspaces/*/inventory/**", "workspaces/a/inventory/messages/bytes", true},
		{"**/max_seq", "workspaces/a/devices/b/tables/events/max_seq", true},
		{"workspaces/*", "workspaces/a/fields", false},
	} {
		if got := Match(c.p, c.k); got != c.ok {
			t.Errorf("Match(%q, %q) = %v", c.p, c.k, got)
		}
	}
}
