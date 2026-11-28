package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"whatserver2/internal/config"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
)

// entitlementsRun is contract entitlements status --check's output,
// findings and exit status.
func entitlementsRun(t *testing.T, c *store.Contract) (string, []string, int) {
	t.Helper()
	var out bytes.Buffer
	err := contractEntitlementsStatus(context.Background(), c, true, &out)
	code := 0
	var exit exitError
	switch {
	case errors.As(err, &exit):
		code = exit.code
	case err != nil:
		t.Fatal(err)
	}
	var findings []string
	for _, line := range strings.Split(out.String(), "\n") {
		if f, ok := strings.CutPrefix(line, "finding: "); ok {
			findings = append(findings, f)
		}
	}
	if (code == 1) != (len(findings) > 0) {
		t.Fatalf("exit %d with %d findings:\n%s", code, len(findings), out.String())
	}
	return out.String(), findings, code
}

// TestContractEntitlementsCommand: off and observe (observe follows the
// contract, exit 3 while it is off; off after a first read needs
// --platform-told, exit 4), enforce refused, usage on and off, hold and
// release, status's lines, and each --check finding, in contract status
// --check too.
func TestContractEntitlementsCommand(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	c := store.NewContract(pool)
	mode := func(verb string, told bool) (string, int) {
		t.Helper()
		var out bytes.Buffer
		err := contractEntitlementsMode(ctx, c, verb, told, &out)
		var exit exitError
		switch {
		case errors.As(err, &exit):
			return exit.Error(), exit.code
		case err != nil:
			t.Fatal(err)
		}
		return out.String(), 0
	}
	if err := contractEntitlementsCommand([]string{"enforce"}, &bytes.Buffer{}); err == nil ||
		err.Error() != "contract entitlements: this release observes only (E0); nothing changed" {
		t.Fatalf("enforce: %v", err)
	}
	if err := contractEntitlementsCommand([]string{"sideways"}, &bytes.Buffer{}); !errors.As(err, new(usageError)) {
		t.Fatalf("sideways: %v", err)
	}
	if err := contractEntitlementsCommand([]string{"usage", "maybe"}, &bytes.Buffer{}); !errors.As(err, new(usageError)) {
		t.Fatalf("usage maybe: %v", err)
	}
	if err := contractEntitlementsCommand([]string{"hold", "-workspace", "nope"}, &bytes.Buffer{}); err == nil ||
		err.Error() != "contract entitlements: -workspace takes a platform workspace's id" {
		t.Fatalf("hold -workspace nope: %v", err)
	}
	if out, code := mode(store.EntObserve, false); code != exitNotReady || !strings.Contains(out, "the contract is off") {
		t.Fatalf("observe with the contract off: %d %q", code, out)
	}
	if _, err := c.SetMode(ctx, store.ContractObserve); err != nil {
		t.Fatal(err)
	}
	gen := uuid.New()
	execSQL(t, pool, `UPDATE contract_state SET generation = $1`, gen)
	if out, code := mode(store.EntObserve, false); code != 0 || !strings.Contains(out, "contract entitlements: off -> observe") {
		t.Fatalf("observe: %d %q", code, out)
	}
	if out, code := mode("usage on", false); code != 0 || !strings.Contains(out, "contract entitlements usage: off -> on") {
		t.Fatalf("usage on: %d %q", code, out)
	}
	if out, code := mode("usage on", false); code != 0 || !strings.Contains(out, "already on") {
		t.Fatalf("usage on again: %d %q", code, out)
	}

	// The status, a document applied, kept, a placeholder and an enforce
	// document held.
	team, kept, home := uuid.New(), uuid.New(), uuid.New()
	for _, ws := range []uuid.UUID{team, home} {
		execSQL(t, pool, `INSERT INTO contract_workspaces (workspace_id, kind) VALUES ($1, 'team')`, ws)
	}
	execSQL(t, pool, `INSERT INTO contract_ent_docs (workspace_id, generation, version, doc, mode, state, received_at, applied_at)
		VALUES ($1, $2, 7, '{}', 'enforce', 'active', clock_timestamp(), clock_timestamp()),
		       ($3, $2, 8, '{}', 'observe', 'trial', clock_timestamp(), NULL)`, team, gen, kept)
	execSQL(t, pool, `INSERT INTO contract_ent_docs (workspace_id, get_due_at) VALUES ($1, clock_timestamp() - interval '11 minutes')`, home)
	execSQL(t, pool, `INSERT INTO contract_ent_brakes (workspace_id, platform_told, by_kind) VALUES ($1, false, 'enforce_in_e0')`, team)
	execSQL(t, pool, `INSERT INTO contract_ent_refusals (generation, seq, workspace_id, code) VALUES ($1, 9, $2, 'invalid_document')`, gen, team)
	execSQL(t, pool, `UPDATE contract_ent_state SET feed_cursor = 9, first_read_at = clock_timestamp() - interval '1 hour',
		last_page_at = clock_timestamp() - interval '16 minutes', published_through = clock_timestamp() - interval '25 hours',
		mode_at = clock_timestamp() - interval '26 hours'`)
	out, findings, code := entitlementsRun(t, c)
	for _, line := range []string{
		"entitlements: observe (since ",
		"entitlements usage: on (since ",
		"entitlements feed: cursor 9, published_through ",
		"entitlements ack: through none, refusals owed 1",
		"entitlements documents: 1 applied, 1 kept for workspaces not named, 1 placeholders",
		"  " + team.String() + ": v7 enforce active fresh ",
		" held at observe frozen",
		"  " + kept.String() + ": v8 observe trial fresh ",
		"  " + home.String() + ": none - - fresh none",
	} {
		if !strings.Contains(out, line) {
			t.Errorf("the status does not say %q:\n%s", line, out)
		}
	}
	want := []string{
		team.String() + ": an enforce document held at observe (E0), not yet reported to the platform",
		"a document refused in the last 24 hours",
		"entitlements feed silent for over 15 minutes",
		"entitlements acknowledgement over 10 minutes old",
		home.String() + ": no document after a GET was due for over 10 minutes",
		team.String() + ": freshness over 24 hours",
	}
	if code != 1 || len(findings) != len(want) {
		t.Fatalf("the findings: %d %q", code, findings)
	}
	for _, w := range want {
		found := false
		for _, f := range findings {
			found = found || strings.HasPrefix(f, w)
		}
		if !found {
			t.Errorf("no finding %q in %q", w, findings)
		}
	}
	// contract status --check carries them too.
	var all bytes.Buffer
	if err := contractStatus(ctx, c, config.Contract{}, true, &all); !errors.As(err, new(exitError)) {
		t.Fatalf("contract status --check: %v", err)
	}
	if !strings.Contains(all.String(), "finding: "+want[0]) || !strings.Contains(all.String(), "entitlements documents: ") {
		t.Fatalf("contract status --check:\n%s", all.String())
	}

	// The brake: the enforce hold is told, never released; an operator's
	// hold and release.
	var b bytes.Buffer
	if err := contractEntitlementsBrake(ctx, c, team, false, true, &b); err == nil || !strings.Contains(err.Error(), "says enforce") {
		t.Fatalf("releasing the enforce hold: %v", err)
	}
	if err := contractEntitlementsBrake(ctx, c, team, true, true, &b); err != nil {
		t.Fatal(err)
	}
	if _, findings, _ := entitlementsRun(t, c); strings.Contains(strings.Join(findings, "\n"), "not yet reported") {
		t.Fatalf("the hold told is still a finding: %q", findings)
	}
	b.Reset()
	if err := contractEntitlementsBrake(ctx, c, kept, true, false, &b); err != nil || !strings.Contains(b.String(), "held at observe") {
		t.Fatalf("hold: %v %q", err, b.String())
	}
	b.Reset()
	if err := contractEntitlementsBrake(ctx, c, kept, false, false, &b); err != nil || !strings.Contains(b.String(), "released") {
		t.Fatalf("release: %v %q", err, b.String())
	}
	if err := contractEntitlementsBrake(ctx, c, kept, false, false, &b); err == nil || !strings.Contains(err.Error(), "not held") {
		t.Fatalf("release of nothing: %v", err)
	}

	// Off after a read needs the platform told; then off, with usage
	// still on in the row but not run.
	if out, code := mode(store.EntOff, false); code != exitTellPlatform || !strings.Contains(out, "--platform-told") {
		t.Fatalf("off untold: %d %q", code, out)
	}
	if out, code := mode(store.EntOff, true); code != 0 || !strings.Contains(out, "observe -> off") {
		t.Fatalf("off told: %d %q", code, out)
	}
	if out, _, _ := entitlementsRun(t, c); !strings.Contains(out, "entitlements: off\n") {
		t.Fatalf("the status after off:\n%s", out)
	}
}

// TestContractEntitlementsUsageStatus: the usage lines of each recorded
// workspace, and their findings: a report refused invalid_request, one
// sent late within the day, and none for over 6 h 15 min while usage is on.
func TestContractEntitlementsUsageStatus(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	c := store.NewContract(pool)
	if _, err := c.SetMode(ctx, store.ContractObserve); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{store.EntObserve, "usage on"} {
		if err := contractEntitlementsMode(ctx, c, v, true, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
	}
	refused, late, quiet := uuid.New(), uuid.New(), uuid.New()
	for _, ws := range []uuid.UUID{refused, late, quiet} {
		execSQL(t, pool, `INSERT INTO contract_workspaces (workspace_id, kind) VALUES ($1, 'team')`, ws)
	}
	execSQL(t, pool, `UPDATE contract_ent_state SET usage_at = clock_timestamp() - interval '1 day', mode_at = clock_timestamp() - interval '1 day',
		last_page_at = clock_timestamp(), first_read_at = clock_timestamp(), acked_through = 0, acked_at = clock_timestamp()`)
	execSQL(t, pool, `INSERT INTO contract_usage (workspace_id, due_at, due_trigger, last_seq, last_measured_at, last_sent_at, last_kept,
		error, error_at, late_at, late_trigger) VALUES
		($1, clock_timestamp() + interval '1 hour', 'floor', 5, clock_timestamp(), clock_timestamp(), true, 'invalid_request', clock_timestamp(), NULL, NULL),
		($2, clock_timestamp() + interval '1 hour', 'floor', 6, clock_timestamp(), clock_timestamp(), false, NULL, NULL, clock_timestamp(), 'usage_after'),
		($3, clock_timestamp() - interval '1 hour', 'floor', 7, clock_timestamp() - interval '7 hours', clock_timestamp() - interval '7 hours', true,
		 NULL, NULL, NULL, NULL)`, refused, late, quiet)
	out, findings, code := entitlementsRun(t, c)
	for _, line := range []string{
		"entitlements usage reports: 3 workspaces",
		"  " + late.String() + " usage: seq 6 at ",
		", kept false, next due ",
		"  " + refused.String() + " usage: seq 5 at ",
		", failing since ",
	} {
		if !strings.Contains(out, line) {
			t.Errorf("the status does not say %q:\n%s", line, out)
		}
	}
	for _, want := range []string{
		refused.String() + ": usage refused (invalid_request) since ",
		late.String() + ": usage report late (usage_after) in the last 24 h",
		quiet.String() + ": no usage report for over 6 h 15 min",
	} {
		found := false
		for _, f := range findings {
			found = found || strings.HasPrefix(f, want)
		}
		if !found {
			t.Errorf("no finding %q in %q", want, findings)
		}
	}
	if code != 1 || len(findings) != 3 {
		t.Fatalf("the findings: %d %q", code, findings)
	}
}
