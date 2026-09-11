package store

import (
	"context"
	"errors"

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
func requireRemainingReader(ctx context.Context, tx pgx.Tx, tenant, target uuid.UUID, device *uuid.UUID) error {
	var stranded bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM device_key_grants doomed
		JOIN device_archive_keys k ON k.device_id=doomed.device_id AND k.epoch=doomed.epoch AND k.retired_at IS NULL
		JOIN workspace_memberships m ON m.tenant_id=doomed.tenant_id AND m.user_id=doomed.user_id AND m.status='active'
		JOIN users u ON u.id=m.user_id AND u.status='active'
		WHERE doomed.tenant_id=$1 AND doomed.user_id=$2 AND ($3::uuid IS NULL OR doomed.device_id=$3)
		AND NOT EXISTS(
			SELECT 1 FROM device_key_grants backup
			JOIN workspace_memberships bm ON bm.tenant_id=backup.tenant_id AND bm.user_id=backup.user_id AND bm.status='active'
			JOIN users bu ON bu.id=bm.user_id AND bu.status='active'
			JOIN device_permissions bp ON bp.tenant_id=backup.tenant_id AND bp.device_id=backup.device_id AND bp.user_id=backup.user_id AND bp.can_read
			WHERE backup.tenant_id=doomed.tenant_id AND backup.device_id=doomed.device_id AND backup.epoch=doomed.epoch AND backup.user_id<>$2
		)
	)`, tenant, target, device).Scan(&stranded)
	if err != nil {
		return err
	}
	if stranded {
		return ErrLastDeviceReader
	}
	return nil
}
