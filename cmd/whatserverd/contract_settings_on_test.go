package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
)

// TestContractSettingsOn: contract settings on, as an operator runs it
// (the commands release): it follows the contract, and needs no
// --platform-told once the feed was read; read again says the console
// offers nothing; and the persons' --check lines (the plan's section 10,
// line 10): a document not accepted for over an hour (from the switch), and
// one parked, naming no sub.
func TestContractSettingsOn(t *testing.T) {
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
	if out, code := mode(store.SettingsOn, true); code != exitNotReady || !strings.Contains(out, "the contract is off") {
		t.Fatalf("on while the contract is off: %d %q", code, out)
	}
	if _, err := c.SetMode(ctx, store.ContractObserve); err != nil {
		t.Fatal(err)
	}
	if out, code := mode(store.SettingsOn, false); code != exitTellPlatform {
		t.Fatalf("the first on without --platform-told: %d %q", code, out)
	}
	if _, code := mode(store.SettingsRead, true); code != 0 {
		t.Fatal("read")
	}
	execSQL(t, pool, `UPDATE contract_settings_state SET first_read_at = clock_timestamp(), read_at = clock_timestamp()`)
	if out, code := mode(store.SettingsOn, false); code != 0 || !strings.Contains(out, "contract settings: read -> on") ||
		!strings.Contains(out, "the console offers the kinds this binary runs within seconds") {
		t.Fatalf("on: %d %q", code, out)
	}
	if out, code := mode(store.SettingsRead, false); code != 0 || !strings.Contains(out, "contract settings: on -> read") ||
		!strings.Contains(out, "the console offers no kind within seconds") {
		t.Fatalf("read after on: %d %q", code, out)
	}
	if _, code := mode(store.SettingsOn, false); code != 0 {
		t.Fatal("on again")
	}

	// Two persons Wappie sends for: one accepted 61 minutes ago, one
	// parked.
	stale, parked := uuid.New(), uuid.New()
	for _, sub := range []uuid.UUID{stale, parked} {
		execSQL(t, pool, `INSERT INTO contract_accounts (sub, generation, version, status, doc) VALUES ($1, $2, 1, 'active', '{"v":1}')`, sub, uuid.New())
	}
	execSQL(t, pool, `UPDATE contract_settings_state SET mode_changed_at = clock_timestamp() - interval '2 hours', read_at = clock_timestamp()`)
	execSQL(t, pool, `UPDATE contract_persons SET ok_at = clock_timestamp() - interval '59 minutes', error = 'refused:unavailable'
		WHERE sub = $1`, stale)
	execSQL(t, pool, `UPDATE contract_persons SET ok_at = clock_timestamp(), parked_at = clock_timestamp() WHERE sub = $1`, parked)
	out, findings, _ := settingsRun(t, c)
	if has(findings, "person documents not accepted") || !has(findings, "1 person documents parked, the last at ") ||
		!strings.Contains(out, "person documents: 2 (2 accepted, 1 parked)") {
		t.Fatalf("a document accepted 59 minutes ago:\n%s", out)
	}
	execSQL(t, pool, `UPDATE contract_persons SET ok_at = clock_timestamp() - interval '61 minutes' WHERE sub = $1`, stale)
	_, findings, _ = settingsRun(t, c)
	if !has(findings, "1 person documents not accepted for over 60 minutes, the oldest since ") || !has(findings, "(refused:unavailable)") {
		t.Fatalf("a document accepted 61 minutes ago: %v", findings)
	}
	for _, f := range findings {
		if strings.Contains(f, stale.String()) || strings.Contains(f, parked.String()) {
			t.Fatalf("a finding names a sub: %q", f)
		}
	}
	if err := contractSettingsCommand([]string{"on", "extra"}, &bytes.Buffer{}); !errors.As(err, new(usageError)) {
		t.Errorf("contract settings on extra: %v", err)
	}
}
