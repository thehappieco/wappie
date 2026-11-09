package numberacts

import (
	"context"

	"github.com/google/uuid"

	"whatserver2/internal/store"
)

// Rename is item.rename (the frame is device.rename, which stores the
// label and answers the caller alone): the store's transaction does it
// whole, the numbers section and the snapshot due at once (the snapshot
// carries a number's label).
func (r *Runner) Rename(ctx context.Context, run Run, item uuid.UUID, before *string, after string) (store.ContractAct, error) {
	return r.Store.RunRename(ctx, run.contract(), item, before, after)
}
