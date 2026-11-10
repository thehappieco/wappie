package membership

import (
	"context"
	"testing"
	"time"

	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/membership/membershiptest"
	"whatserver2/internal/store"
)

// TestSenderSkipsUnknownSection (DS25): a section row this binary does not
// render (a later binary's mcp, left due after a rollback) is never
// picked: the sender does not loop on it sending numbers, the row stays as
// it was, and the numbers section keeps flowing.
func TestSenderSkipsUnknownSection(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	w.settingsOn(t, store.SettingsRead)
	w.exec(ctx, t, `INSERT INTO contract_sections (workspace_id, section, due_at) VALUES ($1, 'mcp', clock_timestamp() - interval '1 hour')`, w.team)
	run(t, w.settingsLeader(w.members, &membershiptest.Logs{}, settingsTimes()))
	w.settleSection(t, w.team)
	sent := len(w.fake.Sections(w.team.String()))
	// A loop on the mcp row would send the numbers again at the round's
	// pace (a millisecond here).
	time.Sleep(time.Second)
	if more := len(w.fake.Sections(w.team.String())) - sent; more != 0 {
		t.Fatalf("%d more sections sent while nothing changed", more)
	}
	for _, s := range w.fake.Sections(w.team.String()) {
		if s.Section != kc.SectionNumbers {
			t.Fatalf("a %s section was sent", s.Section)
		}
	}
	var tries int
	var ok bool
	if err := w.pool.QueryRow(ctx, `SELECT tries, ok_at IS NOT NULL FROM contract_sections WHERE workspace_id = $1 AND section = 'mcp'`,
		w.team).Scan(&tries, &ok); err != nil || tries != 0 || ok {
		t.Fatalf("the mcp row: %d tries, accepted %v, %v", tries, ok, err)
	}
	// A change the numbers section shows still sends it.
	w.exec(ctx, t, `UPDATE contract_sections SET due_at = clock_timestamp() WHERE workspace_id = $1 AND section = 'numbers'`, w.team)
	eventually(t, soon, "the numbers section sent again", func() bool { return len(w.fake.Sections(w.team.String())) > sent })
}
