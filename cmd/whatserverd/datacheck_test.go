package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"whatserver2/internal/datacheck"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
)

// The data check's command lines: an unknown one is a usage error that
// opens nothing and never serves.
func TestDatacheckCommandLines(t *testing.T) {
	served := 0
	serve := func() error { served++; return nil }
	for _, args := range [][]string{{"datacheck", "now"}, {"datacheck", "compare"}, {"datacheck", "compare", "a.json"},
		{"datacheck", "compare", "a", "b", "c"}} {
		var usage usageError
		if err := runCommand(args, serve); !errors.As(err, &usage) {
			t.Fatalf("%q: %v", args, err)
		}
	}
	if err := runCommand([]string{"datacheck", "-sums", "x"}, serve); err == nil || !strings.Contains(err.Error(), "need -objects") {
		t.Fatalf("-sums without -objects: %v", err)
	}
	if served != 0 {
		t.Fatalf("the data check served %d times", served)
	}
}

// compare exits 3 on a difference nothing declared, and 0 once it is
// declared, printing every difference either way.
func TestDatacheckCompareExits(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	a := write("a.json", `{"format":"wappie-datacheck/1","taken_at":"1","scope":"all","workspaces":{"w":{"fields":{"last_seq":"1"}}}}`)
	b := write("b.json", `{"format":"wappie-datacheck/1","taken_at":"2","scope":"all","workspaces":{"w":{"fields":{"last_seq":"2"}}}}`)
	var out bytes.Buffer
	if err := datacheckCompare([]string{a, a}, &out); err != nil || !strings.Contains(out.String(), "0 unexpected, 0 declared") {
		t.Fatalf("equal: %v\n%s", err, out.String())
	}
	out.Reset()
	var exit exitError
	if err := datacheckCompare([]string{a, b}, &out); !errors.As(err, &exit) || exit.code != exitDataDiffers ||
		!strings.Contains(out.String(), "unexpected workspaces/w/fields/last_seq: 1 -> 2") {
		t.Fatalf("a difference: %v\n%s", err, out.String())
	}
	out.Reset()
	if err := datacheckCompare([]string{"-expect", "seq-offset", "-offset", "1", "-device", "d1", "-device", "d2", a, a}, &out); err != nil {
		t.Fatalf("named numbers: %v\n%s", err, out.String())
	}
	out.Reset()
	if err := datacheckCompare([]string{"-allow", "workspaces/*/fields/last_seq", a, b}, &out); err != nil ||
		!strings.Contains(out.String(), "declared   workspaces/w/fields/last_seq") {
		t.Fatalf("declared: %v\n%s", err, out.String())
	}
}

// The check's connection cannot write, whatever transaction it opens, and
// runDatacheck reads a migrated database in one snapshot.
func TestDatacheckConnectionIsReadOnly(t *testing.T) {
	pgtest.Connect(t) // skips without a database
	ctx := context.Background()
	conn, err := openReadOnly(ctx, pgtest.DSN(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx) //nolint:errcheck // test cleanup
	if _, err := conn.Exec(ctx, `CREATE TEMP TABLE datacheck_probe (a int)`); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("a write on the check's connection: %v", err)
	}

	pool := pgtest.Fresh(t, migrate.Run)
	m, err := runDatacheck(ctx, pool, nil, datacheck.Options{}, datacheck.ObjectOutput{})
	if err != nil {
		t.Fatal(err)
	}
	if m.Format != datacheck.Format || len(m.Schema) == 0 || m.Objects != nil {
		t.Fatalf("manifest: %+v", m)
	}
}

// docs/deployment.md shows the data check's command lines as the code has
// them.
func TestDatacheckIsDocumented(t *testing.T) {
	doc, err := os.ReadFile("../../docs/deployment.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(datacheckUsage, "\n") {
		if !strings.Contains(string(doc), line) {
			t.Errorf("docs/deployment.md does not show %q", line)
		}
	}
	for _, e := range datacheck.Expects {
		if !strings.Contains(string(doc), "`"+e+"`") {
			t.Errorf("docs/deployment.md does not explain -expect %s", e)
		}
	}
}
