package numberacts

import (
	"context"

	"github.com/google/uuid"

	"whatserver2/internal/store"
)

// FlagsRaise is item.flags_raise for the local account user (Wappie's
// screen is PUT …/permissions): the store's transaction does it whole,
// the numbers section and the snapshot due at once. After a ran that
// wrote, this process's sockets check their access again, as the route's
// AccessChanged does; the other processes' within their access loop.
func (r *Runner) FlagsRaise(ctx context.Context, run Run, item, user uuid.UUID, before, after []string) (store.ContractAct, error) {
	act, wrote, err := r.Store.RunFlagsRaise(ctx, run.contract(), item, user, before, after)
	r.accessChanged(wrote)
	return act, err
}

// FlagsDrop is item.flags_drop for the local account user, as FlagsRaise.
func (r *Runner) FlagsDrop(ctx context.Context, run Run, item, user uuid.UUID, before, after []string) (store.ContractAct, error) {
	act, wrote, err := r.Store.RunFlagsDrop(ctx, run.contract(), item, user, before, after)
	r.accessChanged(wrote)
	return act, err
}

// AccessRemove is item.access_remove for the local account user, as
// FlagsRaise.
func (r *Runner) AccessRemove(ctx context.Context, run Run, item, user uuid.UUID) (store.ContractAct, error) {
	act, wrote, err := r.Store.RunAccessRemove(ctx, run.contract(), item, user)
	r.accessChanged(wrote)
	return act, err
}

// accessChanged wakes this process's sockets once after a ran that wrote,
// never after a refusal or a ran that changed nothing.
func (r *Runner) accessChanged(wrote bool) {
	if wrote && r.Sockets != nil {
		r.Sockets.RevalidateAccess()
	}
}
