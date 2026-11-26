package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/pg"
	"whatserver2/internal/wa"
)

// A move of a number out of a workspace (Wappie's own transfer to
// Personal) holds the workspace while it runs: the spec's 14.6 ("item.move_out
// holds the workspace") and 14.13 (a relink meanwhile is workspace_busy,
// judged before the storage pause). The hold is two shared advisory locks,
// one on the workspace (MoveHoldKey) and one on the number it moves
// (NumberMoveKey), taken before the move's pause and released once the
// move has ended, committed or undone. Shared, so two moves of a workspace
// run as before; locks, so a process that dies ends its hold with its
// connection, and a pause_cause move it left behind is a finished move's
// pause, which a relink lifts. Any process sees them (pg.AdvisoryHeld). A
// relink's start asks the workspace's; a pairing asks its number's, so
// another number's move never ends it, whatever pause its number shows.

// MoveBusyRetry is workspace_busy's retry_after for a relink that meets a
// move: a move takes seconds, at most its handler's 2 minutes, and a retry
// that finds it still running waits again.
const MoveBusyRetry = 10 * time.Second

// MoveHoldKey is the advisory lock a move out of workspace holds shared.
func MoveHoldKey(workspace uuid.UUID) string { return "move:" + workspace.String() }

// NumberMoveKey is the advisory lock a move of device out of workspace
// holds shared, beside MoveHoldKey.
func NumberMoveKey(workspace, device uuid.UUID) string {
	return "move:" + workspace.String() + ":" + device.String()
}

// moveRunningTx reports whether a move out of workspace runs now, in any
// process.
func moveRunningTx(ctx context.Context, q pg.Querier, workspace uuid.UUID) (bool, error) {
	return pg.AdvisoryHeld(ctx, q, MoveHoldKey(workspace))
}

// numberMoveRunningTx reports whether a move of device out of workspace
// runs now, in any process.
func numberMoveRunningTx(ctx context.Context, q pg.Querier, workspace, device uuid.UUID) (bool, error) {
	return pg.AdvisoryHeld(ctx, q, NumberMoveKey(workspace, device))
}

// MoveRunning reports whether a move out of workspace runs now, in any
// process.
func (d *Devices) MoveRunning(ctx context.Context, workspace uuid.UUID) (bool, error) {
	return moveRunningTx(ctx, d.pool, workspace)
}

// HoldMove takes the move hold for a move of device out of workspace about
// to start: both keys, shared, on one pooled connection kept for the
// move (pg.Locker.TryLockShared), so each running move takes a connection
// of d's pool out of circulation until it ends. release ends the hold,
// then tells the workspace's sections to measure again
// (contract_settings_mark's channel): a numbers section measured while the
// move ran shows can_relink false. release is idempotent.
func (d *Devices) HoldMove(ctx context.Context, workspace, device uuid.UUID) (release func(), err error) {
	unlock, ok, err := pg.NewLocker(d.pool).TryLockShared(ctx, MoveHoldKey(workspace), NumberMoveKey(workspace, device))
	if err != nil {
		return nil, err
	}
	if !ok {
		// Nothing takes the keys exclusively.
		return nil, errors.New("store: the move hold is taken exclusively")
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			unlock()
			nctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			//nolint:errcheck // the sections measure again on their own schedule
			_, _ = d.pool.Exec(nctx, `SELECT pg_notify('wappie_contract_settings', $1)`, workspace.String())
		})
	}, nil
}

// RelinkHoldKey is the advisory lock a relink holds while it pairs
// device, in any process (HoldRelink). A device lock (wa.DeviceLockKey)
// says less: a process also keeps it for a number logged out while it held
// it, until something stops that client, and nothing pairs then.
func RelinkHoldKey(device uuid.UUID) string { return "relink:" + device.String() }

// HoldRelink takes device's relink hold for a pairing about to start,
// exclusively, on a pooled connection kept until release, as HoldMove's.
// ok is false when another relink of the number holds it, in any process.
// The relink takes it before its pairing's look at the move hold
// (RelinkStartCheck), and a move takes its hold before it looks at this
// one (RelinkLook), so one of the two always sees the other.
func (d *Devices) HoldRelink(ctx context.Context, device uuid.UUID) (release func(), ok bool, err error) {
	release, ok, err = pg.NewLocker(d.pool).TryLock(ctx, RelinkHoldKey(device))
	if err != nil {
		return nil, false, fmt.Errorf("store: hold a relink: %w", err)
	}
	return release, ok, nil
}

// RelinkLook is what a move reads of a number before its pause: whether
// it is logged out, and whether a relink pairs it now (RelinkHoldKey), in
// any process.
func (d *Devices) RelinkLook(ctx context.Context, tenant, device uuid.UUID) (loggedOut, relinking bool, err error) {
	err = pg.InTenantTx(ctx, d.pool, tenant.String(), func(tx pgx.Tx) error {
		var status string
		err := tx.QueryRow(ctx, `SELECT status FROM devices WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL`,
			device, tenant).Scan(&status)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		loggedOut = status == string(wa.StatusLoggedOut)
		relinking, err = pg.AdvisoryHeld(ctx, tx, RelinkHoldKey(device))
		return err
	})
	if err != nil && !errors.Is(err, ErrNotFound) {
		err = fmt.Errorf("store: look at a number before its move: %w", err)
	}
	return loggedOut, relinking, err
}
