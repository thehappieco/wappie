package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
)

// The command line's key and bootstrap while the platform's tokens are on
// (step 7's plan, 7.3 and 10.7): they refuse while keys are narrowed (tokens
// on, or the keys retired); -self-hosted issues only off the platform (the
// contract off, tokens off, no retirement), and never what the narrowing
// refuses.
func TestTheCLIKeysRefuseWhileKeysAreNarrowed(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	keys := store.NewAPIKeys(pool)
	check := func(state string, plain, selfHosted bool) {
		t.Helper()
		for flag, want := range map[bool]bool{false: plain, true: selfHosted} {
			err := cliKeysGate(ctx, keys, flag)
			if want && err != nil || !want && err == nil {
				t.Errorf("%s, -self-hosted %t: %v, want issued %t", state, flag, err, want)
			}
			if err != nil && !flag && !errors.Is(err, errCLIKeysNarrowed) {
				t.Errorf("%s: %v, want the narrowing's refusal", state, err)
			}
			if err != nil && flag && !strings.Contains(err.Error(), "connected to The Happie Co") && !errors.Is(err, errCLIKeysNarrowed) {
				t.Errorf("%s, -self-hosted: %v", state, err)
			}
		}
	}
	check("a self-hosted installation", true, true)
	execSQL(t, pool, `UPDATE contract_state SET mode = 'observe', events_from = coalesce(events_from, clock_timestamp()), events_paused_at = NULL`)
	check("the contract on, tokens off", true, false)
	execSQL(t, pool, `UPDATE contract_token_state SET mode = 'on'`)
	check("tokens on", false, false)
	execSQL(t, pool, `UPDATE contract_token_state SET mode = 'off'`)
	execSQL(t, pool, `UPDATE contract_state SET mode = 'off', events_paused_at = clock_timestamp()`)
	execSQL(t, pool, `INSERT INTO key_retirements (revoked, services_removed, services_kept, report, by) VALUES (0, 0, 0, '{}', 'root')`)
	check("everything off after a retirement", false, false)

	// The store refuses the command line's key too, whatever the caller
	// checked.
	var tenant string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('acme') RETURNING id::text`).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.IssueAsked(ctx, tenant, "cli", store.ScopeFull, nil, nil, nil, nil); !errors.Is(err, store.ErrTokensAreThePlatforms) {
		t.Fatalf("the command line's key after a retirement: %v", err)
	}
}
