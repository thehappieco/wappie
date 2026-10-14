package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// A deleted number keeps its devices row for 30 days, marked deleted_at, and
// the restrictive policy device_quarantine (0050) hides that row from every
// query that has not opted in. Opting in is this scope, and only the few
// paths that must see an excluded number take it: deleting, recovering,
// purging and replaying one, and the workspace-wide jobs that would
// otherwise trip over its rows (reconcile, the storage breakdown, a reset).
// Everything else reads devices as if the number were gone, and a query that
// forgets about deletion therefore fails closed.

// ErrExcludedNumbers refuses a workspace-wide change that would skip the
// hidden rows of the numbers awaiting their purge and leave them behind.
var ErrExcludedNumbers = errors.New("store: this workspace has deleted numbers awaiting their purge; recover or purge them first")

// withQuarantine runs fn with excluded numbers visible in tx, then hides
// them again, on success and on error alike. The setting is
// transaction-local, so a rollback discards it too, and it never reaches
// the next user of a pooled connection. This is the only place the
// setting's name appears in Go.
func withQuarantine(ctx context.Context, tx pgx.Tx, fn func() error) (err error) {
	if _, err := tx.Exec(ctx, `SELECT set_config('app.device_quarantine', 'on', true)`); err != nil {
		return fmt.Errorf("store: open the quarantine scope: %w", err)
	}
	defer func() {
		// After a failed statement the transaction is aborted and this fails
		// too; it is rolled back then, and the setting goes with it.
		if _, resetErr := tx.Exec(ctx, `SELECT set_config('app.device_quarantine', '', true)`); resetErr != nil && err == nil {
			err = fmt.Errorf("store: close the quarantine scope: %w", resetErr)
		}
	}()
	return fn()
}

// anyExcludedTx reports whether the workspace of tx has an excluded number.
func anyExcludedTx(ctx context.Context, tx pgx.Tx) (bool, error) {
	var found bool
	err := withQuarantine(ctx, tx, func() error {
		return tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM devices WHERE deleted_at IS NOT NULL)`).Scan(&found)
	})
	return found, err
}

// excludedDevicesTx lists the excluded numbers of the workspace of tx, so
// their bytes, still stored and still charged until the purge, are counted
// apart rather than lost.
func excludedDevicesTx(ctx context.Context, tx pgx.Tx) (map[string]bool, error) {
	out := map[string]bool{}
	err := withQuarantine(ctx, tx, func() error {
		rows, err := tx.Query(ctx, `SELECT id::text FROM devices WHERE deleted_at IS NOT NULL`)
		if err != nil {
			return err
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
		for _, id := range ids {
			out[id] = true
		}
		return err
	})
	return out, err
}
