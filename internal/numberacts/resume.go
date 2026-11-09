package numberacts

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// SyncResume is item.sync_resume (the frame is device.start on a paused
// number): the pause lifted and its notices marked resumed in the store's
// transaction, then the number started. One divergence from the frame
// (DS9): the frame puts the pause back when the start fails; the console's
// resume does not, since its result, ran, was committed with the lift, and
// the number's connection shows in its row (connection, last connected).
// The supervisor starts it within its tick; a session that went is marked
// logged out ("session missing"), as the frame marks it.
func (r *Runner) SyncResume(ctx context.Context, run Run, item uuid.UUID) (store.ContractAct, error) {
	act, dev, err := r.Store.RunSyncResume(ctx, run.contract(), item)
	if err != nil || !ran(act) {
		return act, err
	}
	r.startResumed(ctx, run.Workspace.String(), dev)
	return act, nil
}

// startResumed starts a number a resume lifted the pause of, and stops it
// again when a stop landed meanwhile, as the frame does.
func (r *Runner) startResumed(ctx context.Context, tenant string, dev store.Device) {
	if r.Registry == nil {
		return
	}
	_, err := r.Registry.StartExisting(ctx, tenant, dev.ID, wa.ReceiptPolicy{Mode: dev.ReceiptMode, Recorder: r.Recorder},
		dev.Identity.PN, dev.Identity.LID)
	switch {
	case err == nil, errors.Is(err, wa.ErrAlreadyRunning):
	case errors.Is(err, wa.ErrNoSession):
		r.sessionMissing(ctx, tenant, dev.ID)
		return
	default:
		r.log().Warn("a number the console resumed did not start; the supervisor tries it again", "device", dev.ID, "error", err)
		return
	}
	if r.Devices == nil {
		return
	}
	getCtx, cancel := detached(ctx)
	defer cancel()
	if current, err := r.Devices.Get(getCtx, tenant, dev.ID); err != nil || current.Paused {
		r.Registry.Stop(getCtx, dev.ID)
	}
}

// sessionMissing records that a number's stored session is gone, as the
// frame does: it is logged out, and its way back is a relink.
func (r *Runner) sessionMissing(ctx context.Context, tenant, device string) {
	if r.Devices == nil {
		return
	}
	statusCtx, cancel := detached(ctx)
	defer cancel()
	if err := r.Devices.SetStatus(statusCtx, tenant, device, wa.StatusLoggedOut, "session missing"); err != nil {
		r.log().Error("could not record missing WhatsApp session", "device", device, "error", err)
	}
}
