package membership

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	kc "github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/contract/contracttest"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/membership/membershiptest"
	"whatserver2/internal/numberacts"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// slowRegistry's StartExisting takes as long as a whatsmeow connect that
// keeps failing (8 tries, full jitter up to 30 s), unless its context ends
// first, as the registry's own start ends with it.
type slowRegistry struct{ d time.Duration }

func (s slowRegistry) Stop(context.Context, string) {}
func (s slowRegistry) StartExisting(ctx context.Context, _, _ string, _ wa.ReceiptPolicy, _ ...types.JID) (*wa.Device, error) {
	select {
	case <-time.After(s.d):
		return nil, errors.New("wa: connect failed after 8 attempts")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (s slowRegistry) PairingSince(string) (time.Time, bool) { return time.Time{}, false }

// TestStartsAreBounded: the executor runs every workspace's commands one at
// a time, and a resume's start (or a sync now's) waits for its number to
// connect: past the runner's StartBound it is cancelled, so another
// workspace's rename waits no longer than that behind a number whose
// connect keeps failing. The resume's ran stands (DS9); a sync now whose
// start is cut answers connect_failed.
func TestStartsAreBounded(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	w.settingsOn(t, store.SettingsOn)
	block, bound := 20*time.Second, 300*time.Millisecond
	cfg := settingsTimes()
	runner := &numberacts.Runner{Store: w.contract, Devices: store.NewDevices(w.pool), Registry: slowRegistry{d: block}, StartBound: bound}
	cfg.Acts = runner
	stopLeader := run(t, w.settingsLeader(w.members, &membershiptest.Logs{}, cfg))
	home := w.number(t, w.home, "Casa", 77, w.owner)
	for _, ws := range []string{w.team.String(), w.home.String()} {
		eventually(t, soon, "the sections listing the kinds", func() bool {
			doc, ok := w.fake.Settings("wappie", ws, kc.SectionNumbers)
			return ok && len(doc.Accepts) == len(runs[kc.SectionNumbers])
		})
	}
	issue := func(spec contracttest.CommandSpec) string {
		t.Helper()
		spec.Actor = w.sub.String()
		id, err := w.fake.IssueCommand("wappie", spec)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	target := kc.CommandTarget{Item: w.device.String()}
	stop := issue(contracttest.CommandSpec{Kind: kc.OpItemSyncStop, Workspace: w.team.String(), Target: target,
		Params: json.RawMessage(`{"before":{"capture":"on"},"after":{"capture":"paused"}}`)})
	eventually(t, soon, "the stop ran", func() bool { r, ok := w.ledgerRow(t, stop); return ok && r.outcome == store.CommandRan })
	eventually(t, soon, "the paused section", func() bool {
		doc, ok := w.fake.Settings("wappie", w.team.String(), kc.SectionNumbers)
		return ok && strings.Contains(string(doc.Data), `"capture":"paused"`)
	})
	resume := issue(contracttest.CommandSpec{Kind: kc.OpItemSyncResume, Workspace: w.team.String(), Target: target,
		Params: json.RawMessage(`{"before":{"capture":"paused"},"after":{"capture":"on"}}`)})
	start := time.Now()
	other := issue(contracttest.CommandSpec{Kind: kc.OpItemRename, Workspace: w.home.String(), Target: kc.CommandTarget{Item: home.String()},
		Params: json.RawMessage(`{"before":{"label":"Casa"},"after":{"label":"Casa SP"}}`)})
	eventually(t, block, "the other workspace's rename ran", func() bool {
		r, ok := w.ledgerRow(t, other)
		return ok && r.outcome == store.CommandRan
	})
	if waited := time.Since(start); waited > bound+5*time.Second {
		t.Fatalf("another workspace's rename waited %v behind a start bounded at %v", waited, bound)
	}
	if r, _ := w.ledgerRow(t, resume); r.outcome != store.CommandRan {
		t.Fatalf("the resume whose start was cut: %+v", r)
	}

	// A sync now, run by the runner itself with the leader stopped:
	// connect_failed once the bound passes.
	stopLeader()
	if err := w.users.SetDevicePermission(ctx, w.team, w.owner, store.DevicePermission{DeviceID: w.device, UserID: w.owner, Read: true}); err != nil {
		t.Fatal(err)
	}
	id := w.take(t, row{kind: kc.OpItemSyncNow, ws: &w.team, actor: w.sub, target: item(w.device), docs: nil})
	start = time.Now()
	act, err := runner.SyncNow(ctx, numberacts.Run{Command: id, Workspace: w.team, Actor: w.sub, User: w.owner}, w.device)
	if err != nil || act.Result.Code != kc.CodeConnectFailed {
		t.Fatalf("a sync now whose start was cut: %+v %v", act, err)
	}
	if waited := time.Since(start); waited > bound+5*time.Second {
		t.Fatalf("a sync now waited %v, bounded at %v", waited, bound)
	}
}
