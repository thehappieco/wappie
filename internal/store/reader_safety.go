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
// holds, by requireRemainingReader's predicate. It never joins devices, so a
// deleted number keeps protecting its last key holder until its purge, as a
// live one does.
func strandedDevicesTx(ctx context.Context, tx pgx.Tx, tenant, target uuid.UUID, device *uuid.UUID) ([]uuid.UUID, error) {
	var connectionService bool
	if err := tx.QueryRow(ctx, `SELECT
		EXISTS(SELECT 1 FROM workspace_memberships WHERE tenant_id=$1 AND user_id=$2 AND expires_at IS NOT NULL)
		OR EXISTS(SELECT 1 FROM mcp_connections WHERE service_user_id=$2)`, tenant, target).Scan(&connectionService); err != nil {
		return nil, err
	}
	if connectionService {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT doomed.device_id
		FROM device_key_grants doomed
		JOIN device_archive_keys k ON k.device_id=doomed.device_id AND k.epoch=doomed.epoch AND k.retired_at IS NULL
		JOIN workspace_memberships m ON m.tenant_id=doomed.tenant_id AND m.user_id=doomed.user_id AND m.status='active'
		JOIN users u ON u.id=m.user_id AND u.status='active'
		WHERE doomed.tenant_id=$1 AND doomed.user_id=$2 AND ($3::uuid IS NULL OR doomed.device_id=$3)
		AND NOT EXISTS(
			SELECT 1 FROM device_key_grants backup
			JOIN workspace_memberships bm ON bm.tenant_id=backup.tenant_id AND bm.user_id=backup.user_id AND bm.status='active'
				AND bm.expires_at IS NULL
			JOIN users bu ON bu.id=bm.user_id AND bu.status='active'
			JOIN device_permissions bp ON bp.tenant_id=backup.tenant_id AND bp.device_id=backup.device_id AND bp.user_id=backup.user_id AND bp.can_read
			WHERE backup.tenant_id=doomed.tenant_id AND backup.device_id=doomed.device_id AND backup.epoch=doomed.epoch AND backup.user_id<>$2
			AND NOT EXISTS(SELECT 1 FROM mcp_connections c WHERE c.service_user_id=backup.user_id)
		)
		ORDER BY doomed.device_id`, tenant, target, device)
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
