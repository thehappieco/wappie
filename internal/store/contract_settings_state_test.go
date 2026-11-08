package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
)

// The settings mode (0052's contract_settings_state, DS2 and DS16): it
// follows the contract, its first read and its off after a first read need
// the platform told, and a change makes every document due now.

func TestSettingsModes(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Fresh(t, migrate.Run)
	c := store.NewContract(pool)
	st, err := c.SettingsState(ctx)
	if err != nil || st.Mode != store.SettingsOff || st.Following() || st.FeedCursor != 0 || st.FirstReadAt != nil || st.LabelCutoverAt.IsZero() {
		t.Fatalf("the settings at 0052: %+v %v", st, err)
	}
	if _, err := c.SetSettingsMode(ctx, "enforce", true); !errors.Is(err, store.ErrSettingsMode) {
		t.Fatalf("a mode Wappie lacks: %v", err)
	}
	for _, mode := range []string{store.SettingsRead, store.SettingsOn} {
		if _, err := c.SetSettingsMode(ctx, mode, true); !errors.Is(err, store.ErrSettingsContractOff) {
			t.Fatalf("%s while the contract is off: %v", mode, err)
		}
	}
	if _, err := c.SetMode(ctx, store.ContractObserve); err != nil {
		t.Fatal(err)
	}
	ws := recordWorkspace(t, pool, "team")
	sub := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO contract_accounts (sub) VALUES ($1)`, sub); err != nil {
		t.Fatal(err)
	}
	later := func() {
		t.Helper()
		for _, sql := range []string{`UPDATE contract_sections SET due_at = clock_timestamp() + interval '1 hour'`,
			`UPDATE contract_persons SET due_at = clock_timestamp() + interval '1 hour'`} {
			if _, err := pool.Exec(ctx, sql); err != nil {
				t.Fatal(err)
			}
		}
	}
	dueNow := func() bool {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM contract_sections WHERE workspace_id = $1 AND due_at <= clock_timestamp())
			+ (SELECT count(*) FROM contract_persons WHERE sub = $2 AND due_at <= clock_timestamp())`, ws, sub).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 2
	}
	later()
	// The first read needs the platform told; off before any page needs
	// nothing; and the next read still needs it.
	if _, err := c.SetSettingsMode(ctx, store.SettingsRead, false); !errors.Is(err, store.ErrSettingsTellPlatform) {
		t.Fatalf("the first read untold: %v", err)
	}
	if dueNow() {
		t.Fatal("a refused switch made the documents due")
	}
	change, err := c.SetSettingsMode(ctx, store.SettingsRead, true)
	if err != nil || !change.Changed || change.From != store.SettingsOff || change.To != store.SettingsRead || change.FirstReadAt != nil {
		t.Fatalf("read: %+v %v", change, err)
	}
	if !dueNow() {
		t.Fatal("a switch left the documents due later")
	}
	if change, err := c.SetSettingsMode(ctx, store.SettingsRead, false); err != nil || change.Changed {
		t.Fatalf("read again: %+v %v", change, err)
	}
	if _, err := c.SetSettingsMode(ctx, store.SettingsOff, false); err != nil {
		t.Fatalf("off before a first read: %v", err)
	}
	if _, err := c.SetSettingsMode(ctx, store.SettingsOn, false); !errors.Is(err, store.ErrSettingsTellPlatform) {
		t.Fatalf("on with no first read, untold: %v", err)
	}
	if _, err := c.SetSettingsMode(ctx, store.SettingsOn, true); err != nil {
		t.Fatal(err)
	}
	// After a first read, off needs the platform told; read and on do not.
	if _, err := pool.Exec(ctx, `UPDATE contract_settings_state SET first_read_at = clock_timestamp(), read_at = clock_timestamp()`); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetSettingsMode(ctx, store.SettingsRead, false); err != nil {
		t.Fatalf("on to read after a first read: %v", err)
	}
	later()
	if _, err := c.SetSettingsMode(ctx, store.SettingsOff, false); !errors.Is(err, store.ErrSettingsTellPlatform) {
		t.Fatalf("off after a first read, untold: %v", err)
	}
	change, err = c.SetSettingsMode(ctx, store.SettingsOff, true)
	if err != nil || !change.Changed || change.FirstReadAt == nil || !dueNow() {
		t.Fatalf("off told: %+v %v", change, err)
	}
	// A mode a later release adds reads as read.
	if (store.ContractSettingsState{Mode: "enforce"}).Effective() != store.SettingsRead {
		t.Fatal("an unknown mode is not read as read")
	}
}

// contract mode off turns settings off with it, in its transaction.
func TestSettingsOffWithTheContract(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Fresh(t, migrate.Run)
	c := store.NewContract(pool)
	if _, err := c.SetMode(ctx, store.ContractObserve); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetSettingsMode(ctx, store.SettingsRead, true); err != nil {
		t.Fatal(err)
	}
	change, err := c.SetMode(ctx, store.ContractOff)
	if err != nil || !change.SettingsOff {
		t.Fatalf("contract mode off: %+v %v", change, err)
	}
	if st, err := c.SettingsState(ctx); err != nil || st.Mode != store.SettingsOff {
		t.Fatalf("settings after contract mode off: %+v %v", st, err)
	}
	if _, err := c.SetMode(ctx, store.ContractObserve); err != nil {
		t.Fatal(err)
	}
	if change, err := c.SetMode(ctx, store.ContractOff); err != nil || change.SettingsOff {
		t.Fatalf("contract mode off with settings off: %+v %v", change, err)
	}
}

// The feed's and the results' failures keep the first time of their run.
func TestSettingsFailures(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Fresh(t, migrate.Run)
	c := store.NewContract(pool)
	if err := c.CommandFeedFailed(ctx, "transport"); err != nil {
		t.Fatal(err)
	}
	first, _ := c.SettingsState(ctx)
	time.Sleep(2 * time.Millisecond)
	if err := c.CommandFeedFailed(ctx, "rate_limited"); err != nil {
		t.Fatal(err)
	}
	if err := c.ResultsFailed(ctx, "transport"); err != nil {
		t.Fatal(err)
	}
	st, err := c.SettingsState(ctx)
	if err != nil || st.FeedError != "rate_limited" || st.FeedErrorAt == nil || !st.FeedErrorAt.Equal(*first.FeedErrorAt) ||
		st.ResultsError != "transport" || st.ResultsErrorAt == nil {
		t.Fatalf("the failures: %+v %v", st, err)
	}
	user, sub, _ := heldPerson(t, pool)
	if got, err := c.UserOfSub(ctx, sub); err != nil || got == nil || *got != user {
		t.Fatalf("the user of a sub: %v %v", got, err)
	}
	if got, err := c.UserOfSub(ctx, uuid.New()); err != nil || got != nil {
		t.Fatalf("the user of an unknown sub: %v %v", got, err)
	}
}
