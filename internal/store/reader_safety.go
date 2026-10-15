package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrLastDeviceReader prevents an access change from destroying the last
// recoverable envelope for a number. Workspace ownership alone is not a key.
var ErrLastDeviceReader = errors.New("store: the number must retain an active reader with its archive key")

// All grant and permission mutations take the same lock, before touching a
// membership. This also serializes them with UpdateMember's owner checks.
func lockWorkspaceAccess(ctx context.Context, tx pgx.Tx, tenant uuid.UUID) error {
	var id uuid.UUID
	return tx.QueryRow(ctx, `SELECT id FROM tenants WHERE id=$1 FOR UPDATE`, tenant).Scan(&id)
}

// requireRemainingReader is called before deleting this member's grants. A nil
// device checks every number affected by disabling a membership. Existing
// keyless CLI devices remain supported; the check only protects envelopes held
// by active members. Even a holder whose read flag was withheld may be the
// only recoverable copy. Old non-retired epochs need a reader too.
//
// A connection service account never counts: not as a backup, because its
// grants are sealed to a key that lives only in a reader and dies with it
// (after a restart nobody could open them), and not as the one being
// checked, because its grants are copies of someone else's. That is any
// membership with a deadline, and any account a connection names.
func requireRemainingReader(ctx context.Context, tx pgx.Tx, tenant, target uuid.UUID, device *uuid.UUID) error {
	doomed, err := strandedDevicesTx(ctx, tx, tenant, target, device)
	if err != nil {
		return err
	}
	if len(doomed) > 0 {
		return ErrLastDeviceReader
	}
	return nil
}

// strandedDevicesTx is every number whose last recoverable envelope target
// holds, by requireRemainingReader's predicate, which is the database's
// sole_key_holders (0051): the same rule the contract's snapshot lists as
// protected. It never joins devices, so a deleted number keeps protecting
// its last key holder until its purge, as a live one does.
func strandedDevicesTx(ctx context.Context, tx pgx.Tx, tenant, target uuid.UUID, device *uuid.UUID) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `SELECT device_id FROM sole_key_holders($1)
		WHERE user_id = $2 AND ($3::uuid IS NULL OR device_id = $3)
		ORDER BY device_id`, tenant, target, device)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

// DeletedNumberRef names a deleted number to an owner: its raw label inputs,
// which the console turns into a name, and its purge date.
type DeletedNumberRef struct {
	DeviceID   uuid.UUID `json:"device_id"`
	Label      string    `json:"label"`
	PushName   string    `json:"push_name"`
	PN         string    `json:"pn"`
	PurgeAfter time.Time `json:"purge_after"`
}

// ErrLastReaderOfDeleted refuses to remove or disable the last key holder of
// numbers that are deleted and not yet purged. Numbers is for an owner and
// empty for anyone else, who learns neither a label nor a date. The ways out
// are to wait for the purge, at most 30 days, or to recover the number and
// share its key with someone else first.
type ErrLastReaderOfDeleted struct{ Numbers []DeletedNumberRef }

func (e *ErrLastReaderOfDeleted) Error() string {
	return "store: this person holds the last key of a deleted number that is not purged yet"
}

// strandCheckTx refuses removing or disabling target when that would strand
// a number: ErrLastDeviceReader when any of them is live, as 0032 always
// did, and ErrLastReaderOfDeleted, naming them for an owner, when they are
// all deleted. This release has no override for either.
func strandCheckTx(ctx context.Context, tx pgx.Tx, tenant, target uuid.UUID, actorRole string) error {
	doomed, err := strandedDevicesTx(ctx, tx, tenant, target, nil)
	if err != nil || len(doomed) == 0 {
		return err
	}
	refusal := &ErrLastReaderOfDeleted{Numbers: []DeletedNumberRef{}}
	live := false
	err = withQuarantine(ctx, tx, func() error {
		rows, err := tx.Query(ctx, `SELECT id, deleted_at IS NOT NULL, label, push_name, coalesce(pn,''), purge_after
			FROM devices WHERE id = ANY($1) ORDER BY id`, doomed)
		if err != nil {
			return err
		}
		defer rows.Close()
		found := 0
		for rows.Next() {
			var n DeletedNumberRef
			var deleted bool
			var purgeAfter *time.Time
			if err := rows.Scan(&n.DeviceID, &deleted, &n.Label, &n.PushName, &n.PN, &purgeAfter); err != nil {
				return err
			}
			found++
			if !deleted || purgeAfter == nil {
				live = true
				continue
			}
			n.PurgeAfter = *purgeAfter
			refusal.Numbers = append(refusal.Numbers, n)
		}
		// A grant for a number this workspace cannot see counts as live:
		// the refusal fails closed.
		if found < len(doomed) {
			live = true
		}
		return rows.Err()
	})
	switch {
	case err != nil:
		return err
	case live:
		return ErrLastDeviceReader
	}
	if actorRole != "owner" {
		refusal.Numbers = []DeletedNumberRef{}
	}
	return refusal
}
