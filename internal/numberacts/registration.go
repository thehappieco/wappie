package numberacts

import (
	"context"

	"github.com/google/uuid"

	"whatserver2/internal/store"
)

// RegistrationDelete is item.registration_delete (the frame is
// device.delete's deletePending): judged first, writing nothing when it
// passes; then, in the frame's order, a pairing of the registration in
// progress is cancelled and the registry stops it, or the delete races a
// pairing that may still link; then the row is deleted in a transaction
// that judges it again: one that linked meanwhile is state_changed.
func (r *Runner) RegistrationDelete(ctx context.Context, run Run, row uuid.UUID) (store.ContractAct, error) {
	act, err := r.Store.JudgeRegistrationDelete(ctx, run.contract(), row)
	if err != nil || !act.Open {
		return act, err
	}
	if r.Sockets != nil {
		r.Sockets.CancelPairing(run.Workspace.String(), row.String())
	}
	if r.Registry != nil {
		r.Registry.Stop(ctx, row.String())
	}
	return r.Store.RunRegistrationDelete(ctx, run.contract(), row)
}
