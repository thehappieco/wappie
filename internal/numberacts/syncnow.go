package numberacts

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/google/uuid"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// SyncNow is item.sync_now (the frame is device.start on a number not
// paused): judged in a transaction of its own (the number live, the
// actor's Read, then paused, storage_paused, not_linked, read_only, and
// item_busy while this process pairs it), then started, then answered at a
// new seq: an act that writes nothing completes its row right after (the
// spec's 14.6). A number that connects, or runs already, ran; one whose
// session is gone is marked logged out and read_only; any other failure,
// a start past StartBound included, connect_failed; one a stop paused
// meanwhile is stopped again, paused.
//
// A person's sync now asks Read (the platform's answer 4, DS13), as the
// socket's own device.start on a number that is not paused asks it.
func (r *Runner) SyncNow(ctx context.Context, run Run, item uuid.UUID) (store.ContractAct, error) {
	act, dev, err := r.Store.JudgeSyncNow(ctx, run.contract(), item, r.busy)
	if err != nil || !act.Open {
		return act, err
	}
	res, err := r.connect(ctx, run.Workspace.String(), dev)
	if err != nil {
		return store.ContractAct{}, err
	}
	return r.Store.FinishSyncNow(ctx, run.contract(), res)
}

// connect starts a number for a sync now, and says what came of it.
func (r *Runner) connect(ctx context.Context, tenant string, dev store.Device) (store.CommandResult, error) {
	refused := func(code string) store.CommandResult {
		return store.CommandResult{Outcome: store.CommandRefused, Code: code}
	}
	if r.Registry == nil {
		return refused(kc.CodeConnectFailed), nil
	}
	startCtx, cancel := r.startCtx(ctx)
	_, err := r.Registry.StartExisting(startCtx, tenant, dev.ID, wa.ReceiptPolicy{Mode: dev.ReceiptMode, Recorder: r.Recorder},
		dev.Identity.PN, dev.Identity.LID)
	cancel()
	switch {
	case err == nil, errors.Is(err, wa.ErrAlreadyRunning):
	case errors.Is(err, wa.ErrNoSession):
		r.sessionMissing(ctx, tenant, dev.ID)
		return refused(kc.CodeReadOnly), nil
	default:
		r.log().Warn("a number the console synced now did not start", "device", dev.ID, "error", err)
		return refused(kc.CodeConnectFailed), nil
	}
	if r.Devices == nil {
		return store.CommandResult{Outcome: store.CommandRan}, nil
	}
	getCtx, cancel := detached(ctx)
	defer cancel()
	current, err := r.Devices.Get(getCtx, tenant, dev.ID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		r.Registry.Stop(getCtx, dev.ID)
		return refused(kc.CodeNotFound), nil
	case err != nil:
		return store.CommandResult{}, err
	case current.Paused:
		r.Registry.Stop(getCtx, dev.ID)
		return refused(kc.CodePaused), nil
	}
	return store.CommandResult{Outcome: store.CommandRan}, nil
}

// busy is item_busy's wait for a number this process pairs now: a
// linked number's pairing is a relink, so what is left of its window, in
// whole seconds, at least one.
func (r *Runner) busy(device uuid.UUID) (int, bool) {
	if r.Registry == nil {
		return 0, false
	}
	since, ok := r.Registry.PairingSince(device.String())
	if !ok {
		return 0, false
	}
	wait := min(wa.PairWindow, time.Until(since.Add(wa.RelinkWindow)))
	return max(1, int(math.Ceil(wait.Seconds()))), true
}
