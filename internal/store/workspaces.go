package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"whatserver2/internal/pg"
)

// Workspace is a membership of an authenticated identity, not an archive grant.
type Workspace struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Avatar    string    `json:"avatar"`
	Kind      string    `json:"kind"`
	Role      string    `json:"role"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	// Present on directory responses only. This counts visible devices rather
	// than subscriptions or implicit permission to read their archives.
	DeviceCount *int64 `json:"device_count,omitempty"`
}

// Workspaces returns only this identity's active memberships. Suspended spaces
// remain visible so the client can explain why they cannot be opened.
func (u *Users) Workspaces(ctx context.Context, userID uuid.UUID) ([]Workspace, error) {
	return u.workspaces(ctx, userID, false)
}

// WorkspacesWithDeviceCounts adds the same device visibility as devices.list,
// without issuing a session or changing the caller's selected workspace.
func (u *Users) WorkspacesWithDeviceCounts(ctx context.Context, userID uuid.UUID) ([]Workspace, error) {
	return u.workspaces(ctx, userID, true)
}

func (u *Users) workspaces(ctx context.Context, userID uuid.UUID, withCounts bool) ([]Workspace, error) {
	options := pgx.TxOptions{}
	if withCounts {
		// Memberships and all counts describe one snapshot, including a transfer
		// between two workspaces while the directory is loading.
		options = pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}
	}
	tx, err := u.pool.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	defer func() {
		//nolint:errcheck // Cleanup after commit normally returns ErrTxClosed; preserve the operation error.
		_ = tx.Rollback(ctx)
	}()
	if _, err = tx.Exec(ctx, `SELECT set_config('app.user_id', $1, true)`, userID.String()); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT t.id, t.name, t.avatar, m.role, t.status, m.created_at, t.kind
		FROM workspace_memberships m JOIN tenants t ON t.id = m.tenant_id
		WHERE m.user_id = $1 AND m.status = 'active' ORDER BY m.created_at, t.id`, userID)
	if err != nil {
		return nil, err
	}
	out := []Workspace{}
	for rows.Next() {
		var w Workspace
		if err := rows.Scan(&w.ID, &w.Name, &w.Avatar, &w.Role, &w.Status, &w.CreatedAt, &w.Kind); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, w)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if withCounts {
		for i := range out {
			if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, out[i].ID.String()); err != nil {
				return nil, err
			}
			var count int64
			// RLS stays enabled with each workspace's transaction-local context.
			// Keep this predicate aligned with DevicePermission.Allows(ActionView).
			err := tx.QueryRow(ctx, `SELECT count(*)
				FROM workspace_memberships m
				JOIN users u ON u.id=m.user_id
				JOIN tenants t ON t.id=m.tenant_id
				JOIN devices d ON d.tenant_id=m.tenant_id
				LEFT JOIN device_permissions p ON p.tenant_id=m.tenant_id AND p.device_id=d.id AND p.user_id=m.user_id
				WHERE m.tenant_id=$1 AND m.user_id=$2
				AND m.status='active' AND u.status='active' AND t.status='active'
				AND (m.role IN ('owner','admin') OR coalesce(p.can_manage,false) OR coalesce(p.can_send,false)
					OR (coalesce(p.can_read,false) AND EXISTS(
						SELECT 1 FROM device_key_grants g WHERE g.tenant_id=m.tenant_id
						AND g.device_id=d.id AND g.user_id=m.user_id AND g.epoch=d.current_epoch)))`, out[i].ID, userID).Scan(&count)
			if err != nil {
				return nil, err
			}
			out[i].DeviceCount = &count
		}
	}
	return out, tx.Commit(ctx)
}

// AcceptWorkspaceInvite joins an existing identity to a space without creating
// keys or granting access to any device. Validation, insertion and consumption
// are atomic; an invalid recipient or a duplicate membership does not spend it.
func (u *Users) AcceptWorkspaceInvite(ctx context.Context, user User, secret string) (uuid.UUID, error) {
	if user.Role == RoleService {
		return uuid.Nil, ErrInviteInvalid
	}
	var tenant uuid.UUID
	err := pg.InTx(ctx, u.pool, func(tx pgx.Tx) error {
		inv, digest, e := lockSignupInvite(ctx, tx, secret, user.Email, false)
		if e != nil {
			return e
		}
		tenant = inv.TenantID
		if _, e = tx.Exec(ctx, `SELECT set_config('app.tenant_id',$1,true)`, tenant.String()); e != nil {
			return e
		}
		tag, e := tx.Exec(ctx, `INSERT INTO workspace_memberships(tenant_id,user_id,role) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, tenant, user.ID, inv.Role)
		if e != nil {
			return e
		}
		if tag.RowsAffected() == 0 {
			return ErrInviteInvalid
		}
		_, e = tx.Exec(ctx, `UPDATE invites SET completed_at=now(),claimed_by=$2 WHERE invite_id=$1`, digest, user.ID)
		return e
	})
	return tenant, err
}

// identityTenant is the legacy storage location of the account's credentials.
// It is not the currently selected workspace and never supplies its role.
func (u *Users) identityTenant(ctx context.Context, userID uuid.UUID) (uuid.UUID, error) {
	var tenant uuid.UUID
	err := u.pool.QueryRow(ctx, `SELECT tenant_id FROM user_logins WHERE user_id = $1`, userID).Scan(&tenant)
	return tenant, err
}

// Preserve the original login destination while it is available. If that
// membership is removed or suspended, another active space can still be used.
func (u *Users) defaultWorkspace(ctx context.Context, user User) (User, error) {
	spaces, err := u.Workspaces(ctx, user.ID)
	if err != nil {
		return User{}, err
	}
	var selected uuid.UUID
	for _, space := range spaces {
		if space.Status != "active" {
			continue
		}
		if selected == uuid.Nil {
			selected = space.ID
		}
		if space.ID == user.TenantID {
			selected = space.ID
			break
		}
	}
	if selected == uuid.Nil {
		user.TenantID = uuid.Nil
		user.Role = ""
		return user, nil
	}
	return u.Get(ctx, selected, user.ID)
}
