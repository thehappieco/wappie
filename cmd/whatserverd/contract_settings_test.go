package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/config"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
)

// settingsRun is contract settings status --check's output, findings and
// exit status.
func settingsRun(t *testing.T, c *store.Contract) (string, []string, int) {
	t.Helper()
	var out bytes.Buffer
	err := contractSettingsStatus(context.Background(), c, true, &out)
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

// ledgerRowSQL writes a ledger row in SQL, its other columns and their
// values given as SQL text, in pairs.
func ledgerRowSQL(t *testing.T, pool *pgxpool.Pool, set ...string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	cols, vals := "", ""
	for i := 0; i+1 < len(set); i += 2 {
		cols += ", " + set[i]
		vals += ", " + set[i+1]
	}
	execSQL(t, pool, `INSERT INTO contract_commands (id, generation, cseq, body, body_key, signed_at`+cols+`) VALUES ($1, $2, 1, '\x7b7d',
		decode(repeat('ab', 32), 'hex'), clock_timestamp()`+vals+`)`, id, uuid.New())
	return id
}

// TestContractSettingsCommand: contract settings off|read and status, as
// an operator runs them: read follows the contract (exit 3 while it is
// off), the first read and an off after one need --platform-told (exit 4,
// nothing changed); status's lines; and each --check finding of the
// settings part (the plan's section 10) at both sides of its bound, in
// contract status --check too.
func TestContractSettingsCommand(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	c := store.NewContract(pool)
	mode := func(m string, told bool) (string, int) {
		t.Helper()
		var out bytes.Buffer
		err := contractSettingsMode(ctx, c, m, told, &out)
		var exit exitError
		switch {
		case errors.As(err, &exit):
			return exit.Error(), exit.code
		case err != nil:
			t.Fatal(err)
		}
		return out.String(), 0
	}
	stored := func() string {
		t.Helper()
		s, err := c.SettingsState(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return s.Mode
	}

	if out, code := mode(store.SettingsRead, true); code != exitNotReady || !strings.Contains(out, "the contract is off") || stored() != "off" {
		t.Fatalf("read while the contract is off: %d %q", code, out)
	}
	if _, err := c.SetMode(ctx, store.ContractObserve); err != nil {
		t.Fatal(err)
	}
	if out, code := mode(store.SettingsRead, false); code != exitTellPlatform || !strings.Contains(out, "--platform-told") || stored() != "off" {
		t.Fatalf("the first read without --platform-told: %d %q", code, out)
	}
	if out, code := mode(store.SettingsRead, true); code != 0 || !strings.Contains(out, "contract settings: off -> read") ||
		!strings.Contains(out, "the platform watches it from then on") {
		t.Fatalf("read: %d %q", code, out)
	}
	if out, _ := mode(store.SettingsRead, false); !strings.Contains(out, "contract settings: already read; nothing changed") {
		t.Fatalf("read again: %q", out)
	}

	// Read a minute ago: no finding; the switch three minutes ago with no
	// read: one.
	out, findings, _ := settingsRun(t, c)
	if len(findings) != 0 || !strings.Contains(out, "settings: read (since ") || !strings.Contains(out, "command feed: cursor 0, first read never") {
		t.Fatalf("just switched:\n%s", out)
	}
	execSQL(t, pool, `UPDATE contract_settings_state SET mode_changed_at = clock_timestamp() - interval '3 minutes'`)
	if _, findings, _ := settingsRun(t, c); !has(findings, "settings are read but the command feed was last read never "+
		"(the console shows Wappie down after 2 minutes; the platform alerts after 10)") {
		t.Fatalf("never read: %v", findings)
	}
	execSQL(t, pool, `UPDATE contract_settings_state SET first_read_at = clock_timestamp() - interval '3 minutes',
		read_at = clock_timestamp() - interval '110 seconds'`)
	if _, findings, _ := settingsRun(t, c); has(findings, "command feed was last read") {
		t.Fatalf("read under 2 minutes ago: %v", findings)
	}
	execSQL(t, pool, `UPDATE contract_settings_state SET read_at = clock_timestamp() - interval '130 seconds'`)
	if _, findings, _ := settingsRun(t, c); !has(findings, "settings are read but the command feed was last read 2m10s ago") {
		t.Fatalf("read over 2 minutes ago: %v", findings)
	}
	execSQL(t, pool, `UPDATE contract_settings_state SET read_at = clock_timestamp()`)

	// An invalid_command within the day, and not after it.
	execSQL(t, pool, `UPDATE contract_settings_state SET invalid_at = clock_timestamp() - interval '23 hours'`)
	if _, findings, _ := settingsRun(t, c); !has(findings, "an invalid_command was answered at ") || !has(findings, "(the platform alerts for 24 hours)") {
		t.Fatalf("an invalid_command 23 hours ago: %v", findings)
	}
	execSQL(t, pool, `UPDATE contract_settings_state SET invalid_at = clock_timestamp() - interval '25 hours'`)
	if _, findings, _ := settingsRun(t, c); has(findings, "invalid_command") {
		t.Fatalf("an invalid_command 25 hours ago: %v", findings)
	}

	// The ledger's findings.
	refused := []string{"outcome", "'refused'", "code", "'invalid_command'", "result_at"}
	ledgerRowSQL(t, pool, append(refused, "clock_timestamp() - interval '1 minute'", "delivery", "'rejected'", "delivered_at", "clock_timestamp()",
		"reject_code", "'local_invalid'")...)
	if _, findings, _ := settingsRun(t, c); !has(findings, "1 results are parked (rejected invalid_request or local_invalid), the last at ") ||
		!has(findings, ": they are not delivered") {
		t.Fatalf("a parked result: %v", findings)
	}
	undelivered := ledgerRowSQL(t, pool, append(refused, "clock_timestamp() - interval '4 minutes'", "post_tries", "2",
		"post_error", "'refused:unavailable'")...)
	if _, findings, _ := settingsRun(t, c); has(findings, "not delivered, the oldest") {
		t.Fatalf("a result undelivered for 4 minutes: %v", findings)
	}
	execSQL(t, pool, `UPDATE contract_commands SET result_at = clock_timestamp() - interval '6 minutes' WHERE id = $1`, undelivered)
	if _, findings, _ := settingsRun(t, c); !has(findings, "1 results are not delivered, the oldest for over 5 minutes, since ") ||
		!has(findings, "(refused:unavailable)") {
		t.Fatalf("a result undelivered for 6 minutes: %v", findings)
	}
	open := []string{"kind", "'person.sign_out_everywhere'", "section", "'person'", "actor", "gen_random_uuid()", "issued_at",
		"clock_timestamp()", "taken_at"}
	ledgerRowSQL(t, pool, append(open, "clock_timestamp() - interval '9 minutes'")...)
	if _, findings, _ := settingsRun(t, c); has(findings, "commands have no result") {
		t.Fatalf("a command taken 9 minutes ago: %v", findings)
	}
	ledgerRowSQL(t, pool, append(open, "clock_timestamp() - interval '11 minutes'", "run_tries", "2", "run_error", "'sqlstate_23514'",
		"run_after", "clock_timestamp() + interval '10 seconds'")...)
	_, findings, _ = settingsRun(t, c)
	if !has(findings, "2 commands have no result, the oldest taken over 10 minutes ago, at ") {
		t.Fatalf("a command taken 11 minutes ago: %v", findings)
	}
	if !has(findings, "1 commands are retrying after store errors, the oldest taken at ") || !has(findings, "(sqlstate_23514)") {
		t.Fatalf("a command retrying: %v", findings)
	}
	ledgerRowSQL(t, pool, "kind", "'person.sign_out_everywhere'", "section", "'person'", "actor", "gen_random_uuid()", "issued_at",
		"clock_timestamp()", "outcome", "'refused'", "code", "'rate_limited'", "retry_after", "60", "state_seq", "1", "result_at",
		"clock_timestamp()", "run_tries", "5", "run_error", "'sqlstate_23514'")
	if _, findings, _ := settingsRun(t, c); !has(findings, "a command was answered rate_limited after 5 failed runs at ") {
		t.Fatalf("a stuck command: %v", findings)
	}

	// A section accepted 59 minutes ago, then 61; a parked one.
	ws, parked := uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{ws, parked} {
		execSQL(t, pool, `INSERT INTO contract_workspaces (workspace_id, kind, named_at, status) VALUES ($1, 'team', clock_timestamp(), 'open')`, id)
	}
	execSQL(t, pool, `UPDATE contract_sections SET ok_at = clock_timestamp() - interval '59 minutes', due_at = clock_timestamp() + interval '1 hour'`)
	execSQL(t, pool, `UPDATE contract_sections SET parked_at = clock_timestamp(), error = 'refused:invalid_request' WHERE workspace_id = $1`, parked)
	_, findings, _ = settingsRun(t, c)
	if has(findings, "workspace "+ws.String()) {
		t.Fatalf("a section accepted 59 minutes ago: %v", findings)
	}
	if !has(findings, "workspace "+parked.String()+"'s numbers section is parked since ") || !has(findings, ": it is not sent (refused:invalid_request)") {
		t.Fatalf("a parked section: %v", findings)
	}
	execSQL(t, pool, `UPDATE contract_sections SET ok_at = clock_timestamp() - interval '61 minutes', error = 'refused:unavailable', tries = 3
		WHERE workspace_id = $1`, ws)
	if _, findings, _ := settingsRun(t, c); has(findings, "workspace "+ws.String()) {
		t.Fatalf("a section accepted 61 minutes ago, settings read for 3: %v", findings)
	}
	execSQL(t, pool, `UPDATE contract_settings_state SET mode_changed_at = clock_timestamp() - interval '2 hours'`)
	out, findings, _ = settingsRun(t, c)
	if !has(findings, "workspace "+ws.String()+" has no numbers section accepted for over 60 minutes (the console marks it stale after 90); "+
		"the last one sent: refused:unavailable") {
		t.Fatalf("a section accepted 61 minutes ago: %v", findings)
	}
	if !strings.Contains(out, "numbers sections: 2") || !strings.Contains(out, "failing=refused:unavailable tries=3") ||
		!strings.Contains(out, "results (30 days): refused:invalid_command 2, refused:rate_limited 1") {
		t.Fatalf("status:\n%s", out)
	}
	// contract status --check reports them too.
	if _, all, _ := statusRun(t, c, config.Contract{}); !has(all, "has no numbers section accepted for over 60 minutes") ||
		!has(all, "results are parked") {
		t.Fatalf("contract status --check: %v", all)
	}

	// Off once the feed was read: --platform-told, then a finding while it
	// stays off.
	if out, code := mode(store.SettingsOff, false); code != exitTellPlatform || !strings.Contains(out, "has watched the command feed since") ||
		stored() != "read" {
		t.Fatalf("off without --platform-told: %d %q", code, out)
	}
	if out, code := mode(store.SettingsOff, true); code != 0 || !strings.Contains(out, "contract settings: read -> off") ||
		!strings.Contains(out, "it alerts contract_commands_silent after 10 minutes") {
		t.Fatalf("off: %d %q", code, out)
	}
	_, findings, _ = settingsRun(t, c)
	if !has(findings, "settings are off, but the platform has watched the command feed since ") || !has(findings, ": it alerts contract_commands_silent") {
		t.Fatalf("off after a read: %v", findings)
	}
	if has(findings, "numbers section") {
		t.Fatalf("a section finding while off: %v", findings)
	}

	// contract mode off says what it did to settings, and that the platform
	// watches.
	if _, code := mode(store.SettingsRead, false); code != 0 {
		t.Fatal("read again after a first read needs no --platform-told")
	}
	var modeOut bytes.Buffer
	if err := contractMode(ctx, c, store.ContractOff, nil, &modeOut); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(modeOut.String(), "settings: off with it") || !strings.Contains(modeOut.String(), "the platform watches the command feed since ") ||
		!strings.Contains(modeOut.String(), ": tell it") {
		t.Fatalf("contract mode off: %q", modeOut.String())
	}

	for _, args := range [][]string{nil, {"sideways"}, {"read", "extra"}, {"status", "extra"}} {
		if err := contractSettingsCommand(args, &bytes.Buffer{}); !errors.As(err, new(usageError)) {
			t.Errorf("contract settings %v: %v", args, err)
		}
	}
}
