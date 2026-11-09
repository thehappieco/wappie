package numberacts

import (
	"context"

	"github.com/google/uuid"

	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// SyncStop is item.sync_stop (the frame is device.stop): the pause in the
// store's transaction, then, as the frame does after its own, in its
// order: a pairing of the number in progress is cancelled, the registry
// stops it, its display status becomes offline ("paused by request",
// unless it is logged out or banned, which a pause keeps), that status is
// broadcast, and the notices the pause raised go to their persons'
// sessions open on this process.
func (r *Runner) SyncStop(ctx context.Context, run Run, item uuid.UUID) (store.ContractAct, error) {
	act, paused, err := r.Store.RunSyncStop(ctx, run.contract(), item)
	if err != nil || !ran(act) {
		return act, err
	}
	tenant, device := run.Workspace.String(), item.String()
	if paused.Changed {
		r.log().Info("sync paused", "device", device, "actor_kind", paused.ActorKind, "via", "console",
			"readers_told", len(paused.Notices), "event", paused.Recorded)
	}
	if r.Sockets != nil {
		r.Sockets.CancelPairing(tenant, device)
	}
	if r.Registry != nil {
		r.Registry.Stop(ctx, device)
	}
	status, reason := wa.StatusOffline, "paused by request"
	if r.Devices != nil {
		statusCtx, cancel := detached(ctx)
		defer cancel()
		s, why, err := r.Devices.MarkPausedOffline(statusCtx, tenant, device)
		if err != nil {
			// The durable pause is committed and supervision has stopped.
			r.log().Warn("device paused but display status could not be updated", "device", device, "error", err)
		} else {
			status, reason = s, why
		}
	}
	if r.Sockets != nil {
		r.Sockets.BroadcastDeviceStatus(tenant, device, string(status), reason)
		r.Sockets.PushNotices(tenant, paused.Notices)
	}
	return act, nil
}
