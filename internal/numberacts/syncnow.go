package numberacts

import (
	"cmp"
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
// meanwhile is stopped again, paused. Within FailedStartWait of this
// runner's failed start of the number it starts nothing, and answers
// rate_limited with the seconds left.
//
// A person's sync now asks Read (the platform's answer 4, DS13), as the
// socket's own device.start on a number that is not paused asks it.
func (r *Runner) SyncNow(ctx context.Context, run Run, item uuid.UUID) (store.ContractAct, error) {
	act, dev, err := r.Store.JudgeSyncNow(ctx, run.contract(), item, r.busy)
	if err != nil || !act.Open {
		return act, err
	}
	if wait, ok := r.failedWait(dev.ID); ok {
		return r.Store.FinishSyncNow(ctx, run.contract(),
			store.CommandResult{Outcome: store.CommandRefused, Code: store.CommandRateLimited, RetryAfter: wait})
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
		// A start the leader's stop cut is not the number's failure.
		if ctx.Err() == nil {
			r.startFailed(dev.ID)
		}
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

// startFailed keeps the time of a sync now's failed start of device, and
// forgets the failures whose FailedStartWait ended. No start happens
// within one, so none needs forgetting at a start that works.
func (r *Runner) startFailed(device string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for d, at := range r.failed {
		if !now.Before(at.Add(r.failedStartWait())) {
			delete(r.failed, d)
		}
	}
	if r.failed == nil {
		r.failed = map[string]time.Time{}
	}
	r.failed[device] = now
}

// failedWait is what is left of device's FailedStartWait after this
// runner's last failed start of it, in whole seconds, at least one.
func (r *Runner) failedWait(device string) (int, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	at, ok := r.failed[device]
	if !ok {
		return 0, false
	}
	left := time.Until(at.Add(r.failedStartWait()))
	if left <= 0 {
		delete(r.failed, device)
		return 0, false
	}
	return min(max(1, int(math.Ceil(left.Seconds()))), kc.MaxRetryAfter), true
}

func (r *Runner) failedStartWait() time.Duration { return cmp.Or(r.FailedStartWait, FailedStartWait) }

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
