package membership

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	kc "github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/contract/contracttest"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/membership/membershiptest"
	"whatserver2/internal/numberacts"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// startRegistry starts every number at once, and counts the starts.
type startRegistry struct {
	mu      sync.Mutex
	started map[string]int
}

func (r *startRegistry) Stop(context.Context, string) {}
func (r *startRegistry) StartExisting(_ context.Context, _, device string, _ wa.ReceiptPolicy, _ ...types.JID) (*wa.Device, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.started[device]++
	return nil, nil
}
func (r *startRegistry) PairingSince(string) (time.Time, bool) { return time.Time{}, false }

func (r *startRegistry) starts(device uuid.UUID) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.started[device.String()]
}

// refusedCode is a result's code, "" when it ran or has none.
func refusedCode(res kc.CommandResult) string {
	if res.Code == nil {
		return ""
	}
	return *res.Code
}

// TestSyncNowFromTheConsole (DS13, the platform's answer 4): in the mode
// on, the numbers section offers item.sync_now, and a member who reads the
// number, with no Manage, syncs it now through the console: ran, at a seq,
// the number started. An admin who does not read it is not_authorized. A
// deleted number, which the section shows paused and read only, is
// not_found if a command comes anyway. Neither starts the number.
func TestSyncNowFromTheConsole(t *testing.T) {
	w := newEventWorld(t)
	ctx := context.Background()
	admin, adminSub, _ := w.heldAtHome(t)
	if err := w.fake.SetRole(w.team.String(), adminSub.String(), kc.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	w.localTeam(t, w.team, "", member{admin, "admin", "active"})
	w.members.SignIn(ctx, adminSub)
	w.settingsOn(t, store.SettingsOn)
	reg := &startRegistry{started: map[string]int{}}
	cfg := settingsTimes()
	cfg.Acts = &numberacts.Runner{Store: w.contract, Devices: store.NewDevices(w.pool), Registry: reg}
	run(t, w.settingsLeader(w.members, &membershiptest.Logs{}, cfg))
	eventually(t, soon, "the section listing the kinds", func() bool {
		doc, ok := w.fake.Settings("wappie", w.team.String(), kc.SectionNumbers)
		return ok && len(doc.Accepts) == len(runs[kc.SectionNumbers])
	})
	syncNow := func(actor uuid.UUID) kc.CommandResult {
		t.Helper()
		id, err := w.fake.IssueCommand("wappie", contracttest.CommandSpec{Kind: kc.OpItemSyncNow, Workspace: w.team.String(),
			Actor: actor.String(), Target: kc.CommandTarget{Item: w.device.String()}})
		if err != nil {
			t.Fatalf("a sync now by %s: %v", actor, err)
		}
		var res kc.CommandResult
		eventually(t, soon, "the sync now's result kept", func() bool {
			var ok bool
			res, ok = w.fake.CommandResult("wappie", id)
			return ok
		})
		return res
	}

	if res := syncNow(w.secondSub); res.Outcome != kc.OutcomeRan || res.StateSeq == nil {
		t.Fatalf("a member who reads: %s %q", res.Outcome, refusedCode(res))
	}
	if n := reg.starts(w.device); n != 1 {
		t.Fatalf("the reader's sync now started the number %d times", n)
	}
	if res := syncNow(adminSub); res.Outcome != kc.OutcomeRefused || refusedCode(res) != kc.CodeNotAuthorized {
		t.Fatalf("an admin who does not read: %s %q", res.Outcome, refusedCode(res))
	}

	if _, err := store.NewDevices(w.pool).Quarantine(ctx, w.team, w.owner, w.device, []uuid.UUID{w.second}); err != nil {
		t.Fatal(err)
	}
	eventually(t, soon, "the deleted number shown paused and read only", func() bool {
		doc, ok := w.fake.Settings("wappie", w.team.String(), kc.SectionNumbers)
		var data kc.NumbersSettings
		if !ok || json.Unmarshal(doc.Data, &data) != nil {
			return false
		}
		for _, it := range data.Items {
			if it.ID == w.device.String() {
				return it.Capture == "paused" && it.ReadOnly
			}
		}
		return false
	})
	if res := syncNow(w.secondSub); res.Outcome != kc.OutcomeRefused || refusedCode(res) != kc.CodeNotFound {
		t.Fatalf("a reader's sync now of a deleted number: %s %q", res.Outcome, refusedCode(res))
	}
	if n := reg.starts(w.device); n != 1 {
		t.Fatalf("the number was started %d times", n)
	}
}
