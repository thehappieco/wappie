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
//
// A connection service account never counts: not as a backup, because its
// grants are sealed to a key that lives only in a reader and dies with it
// (after a restart nobody could open them), and not as the one being
// checked, because its grants are copies of someone else's. That is any
// membership with a deadline, and any account a connection names.
func requireRemainingReader(ctx context.Context, tx pgx.Tx, tenant, target uuid.UUID, device *uuid.UUID) error {
	var connectionService bool
	if err := tx.QueryRow(ctx, `SELECT
		EXISTS(SELECT 1 FROM workspace_memberships WHERE tenant_id=$1 AND user_id=$2 AND expires_at IS NOT NULL)
		OR EXISTS(SELECT 1 FROM mcp_connections WHERE service_user_id=$2)`, tenant, target).Scan(&connectionService); err != nil {
		return err
	}
	if connectionService {
		return nil
	}
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
				AND bm.expires_at IS NULL
			JOIN users bu ON bu.id=bm.user_id AND bu.status='active'
			JOIN device_permissions bp ON bp.tenant_id=backup.tenant_id AND bp.device_id=backup.device_id AND bp.user_id=backup.user_id AND bp.can_read
			WHERE backup.tenant_id=doomed.tenant_id AND backup.device_id=doomed.device_id AND backup.epoch=doomed.epoch AND backup.user_id<>$2
			AND NOT EXISTS(SELECT 1 FROM mcp_connections c WHERE c.service_user_id=backup.user_id)
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
