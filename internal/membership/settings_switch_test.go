package membership

import (
	"context"
	"testing"
	"time"

	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/membership/membershiptest"
	"whatserver2/internal/store"
)

// TestSwitchSendsTheNewAccepts: a switch from read to on makes every
// document due in its transaction, but the sender renders accepts from the
// watcher's mode. Here the watcher's read of the settings row waits behind
// a lock queued before the switch commits, so the sender sends the section
// and the person's document first, with read's accepts, and the platform
// accepts them. Once the watcher holds on, both go again at once with on's
// kinds, never 55 minutes later.
func TestSwitchSendsTheNewAccepts(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	w.settingsOn(t, store.SettingsRead)
	run(t, w.settingsLeader(w.members, &membershiptest.Logs{}, settingsTimes()))
	eventually(t, soon, "the section in read", func() bool {
		doc, ok := w.fake.Settings("wappie", w.team.String(), kc.SectionNumbers)
		return ok && len(doc.Accepts) == 0
	})
	eventually(t, soon, "the person's document in read", func() bool {
		doc, ok := w.fake.PersonSettings("wappie", w.sub.String())
		return ok && len(doc.Accepts) == 0
	})

	// The switch, as SetSettingsMode writes it.
	tx, err := w.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // committed below
	for _, q := range []string{
		`SELECT 1 FROM contract_state FOR UPDATE`,
		`UPDATE contract_settings_state SET mode = 'on', mode_changed_at = clock_timestamp(), updated_at = clock_timestamp()`,
		`UPDATE contract_sections SET due_at = clock_timestamp()`,
		`UPDATE contract_persons SET due_at = clock_timestamp()`,
	} {
		if _, err := tx.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec(ctx, `SELECT pg_notify($1, 'settings')`, store.ContractModeChannel); err != nil {
		t.Fatal(err)
	}
	// A lock queued behind the switch: granted at its commit, it holds the
	// watcher's read of the settings row (the numbers path reads none of
	// it) while the sender sends.
	locked, released := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(released)
		ltx, err := w.pool.Begin(ctx)
		if err != nil {
			t.Error(err)
			close(locked)
			return
		}
		defer ltx.Rollback(ctx) //nolint:errcheck // a lock's holder
		if _, err := ltx.Exec(ctx, `LOCK TABLE contract_settings_state IN ACCESS EXCLUSIVE MODE`); err != nil {
			t.Error(err)
		}
		close(locked)
		time.Sleep(1500 * time.Millisecond)
	}()
	time.Sleep(200 * time.Millisecond)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	<-locked
	<-released
	eventually(t, 10*time.Second, "the section with on's kinds", func() bool {
		doc, ok := w.fake.Settings("wappie", w.team.String(), kc.SectionNumbers)
		return ok && len(doc.Accepts) == len(runs[kc.SectionNumbers])
	})
	eventually(t, 10*time.Second, "the person's document with on's kinds", func() bool {
		doc, ok := w.fake.PersonSettings("wappie", w.sub.String())
		return ok && len(doc.Accepts) == len(runs[kc.SectionPerson])
	})
}

// TestAllMakesPersonsDue: an "all" on the dirty channel (an account's
// status: the pause notices it raised for others show or hide) makes every
// person's document due within the debounce, as it does every section.
func TestAllMakesPersonsDue(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	sw := w.executorOf(t, store.SettingsOn, &membershiptest.Logs{})
	if err := w.contract.PersonsDue(ctx); err != nil {
		t.Fatal(err)
	}
	w.exec(ctx, t, `UPDATE contract_persons SET due_at = clock_timestamp() + interval '1 hour', tries = 0`)
	sw.dirty("all")
	if !(&sectionSender{sw: sw}).applyPersonNotices(ctx) {
		t.Fatal("the notices were not applied")
	}
	next, ok, err := w.contract.NextPerson(ctx)
	if err != nil || !ok || next.Wait > or(sw.cfg.SectionDebounce, sectionDebounce) {
		t.Fatalf("the person's document after all: %+v %v %v", next, ok, err)
	}
}
