package membership

import (
	"context"
	"encoding/json"
	"errors"
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

// startRegistry starts every number at once, or fails each start with
// fail, and counts the starts.
type startRegistry struct {
	mu      sync.Mutex
	started map[string]int
	fail    error
}

func (r *startRegistry) Stop(context.Context, string) {}
func (r *startRegistry) StartExisting(_ context.Context, _, device string, _ wa.ReceiptPolicy, _ ...types.JID) (*wa.Device, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.started[device]++
	return nil, r.fail
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

// TestSyncNowWaitsAfterAFailedStart: the executor runs every workspace's
// commands one at a time, and a sync now is any reader's. Once a sync
// now's start fails, a sync now of the number within the runner's
// FailedStartWait starts nothing: rate_limited, at a seq, retry_after the
// seconds left, so readers clicking "try again" on a number that cannot
// connect never hold the other commands for a start each. Past the wait it
// starts the number again.
func TestSyncNowWaitsAfterAFailedStart(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	w.settingsOn(t, store.SettingsOn)
	if err := w.users.SetDevicePermission(ctx, w.team, w.owner, store.DevicePermission{DeviceID: w.device, UserID: w.owner, Read: true}); err != nil {
		t.Fatal(err)
	}
	reg := &startRegistry{started: map[string]int{}, fail: errors.New("wa: connect failed after 8 attempts")}
	syncNow := func(runner *numberacts.Runner) store.CommandResult {
		t.Helper()
		id := w.take(t, row{kind: kc.OpItemSyncNow, ws: &w.team, actor: w.sub, target: item(w.device), docs: nil}) //nolint:contextcheck // the world's helpers run on a context of their own
		act, err := runner.SyncNow(ctx, numberacts.Run{Command: id, Workspace: w.team, Actor: w.sub, User: w.owner}, w.device)
		if err != nil {
			t.Fatal(err)
		}
		return act.Result
	}
	runner := &numberacts.Runner{Store: w.contract, Devices: store.NewDevices(w.pool), Registry: reg}
	if res := syncNow(runner); res.Code != kc.CodeConnectFailed || res.RetryAfter != 0 {
		t.Fatalf("the first sync now: %+v", res)
	}
	for range 3 {
		res := syncNow(runner)
		if res.Outcome != store.CommandRefused || res.Code != kc.CodeRateLimited || res.StateSeq == nil ||
			res.RetryAfter < 1 || res.RetryAfter > int(numberacts.FailedStartWait/time.Second) {
			t.Fatalf("a sync now within the wait: %+v", res)
		}
	}
	if n := reg.starts(w.device); n != 1 {
		t.Fatalf("the number was started %d times, want once", n)
	}

	// Past the wait, the number is started again; once it starts, it ran.
	wait := 50 * time.Millisecond
	short := &numberacts.Runner{Store: w.contract, Devices: store.NewDevices(w.pool), Registry: reg, FailedStartWait: wait}
	if res := syncNow(short); res.Code != kc.CodeConnectFailed {
		t.Fatalf("a sync now on another runner: %+v", res)
	}
	time.Sleep(2 * wait)
	if res := syncNow(short); res.Code != kc.CodeConnectFailed {
		t.Fatalf("a sync now past the wait: %+v", res)
	}
	reg.mu.Lock()
	reg.fail = nil
	reg.mu.Unlock()
	time.Sleep(2 * wait)
	if res := syncNow(short); res.Outcome != store.CommandRan {
		t.Fatalf("a sync now that starts: %+v", res)
	}
	if n := reg.starts(w.device); n != 4 {
		t.Fatalf("the number was started %d times, want 4", n)
	}
}
