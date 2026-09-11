package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"whatserver2/internal/pg"
)

var (
	ErrMembershipForbidden = errors.New("store: membership action is not authorized")
	ErrLastOwner           = errors.New("store: workspace needs an active owner")
	ErrInvalidMembership   = errors.New("store: invalid membership role or status")
)

type MemberDeviceAccess struct {
	DeviceID uuid.UUID `json:"device_id"`
	Label    string    `json:"label"`
	PN       string    `json:"pn"`
	HasKey   bool      `json:"has_key"`
	Read     bool      `json:"read"`
	Send     bool      `json:"send"`
	Manage   bool      `json:"manage"`
}
type Member struct {
	ID           uuid.UUID            `json:"id"`
	Email        string               `json:"email"`
	Name         string               `json:"name"`
	Avatar       string               `json:"avatar"`
	DeviceAccess []MemberDeviceAccess `json:"device_access"`
	Role         string               `json:"role"`
	Status       string               `json:"status"`
	LastOwner    bool                 `json:"last_owner"`
	CreatedAt    time.Time            `json:"created_at"`
}

// lockWorkspaceManager serializes permission changes and last-owner checks on
// one workspace. Never trust a role supplied by the request or an old session.
func lockWorkspaceManager(ctx context.Context, tx pgx.Tx, tenant, actor uuid.UUID) (string, error) {
	if tenant == uuid.Nil {
		return "", ErrMembershipForbidden
	}
	var status string
	if err := tx.QueryRow(ctx, `SELECT status FROM tenants WHERE id = $1 FOR UPDATE`, tenant).Scan(&status); err != nil {
		return "", err
	}
	if status != "active" {
		return "", ErrMembershipForbidden
	}
	var role string
	err := tx.QueryRow(ctx, `SELECT m.role FROM workspace_memberships m JOIN users u ON u.id = m.user_id
		WHERE m.tenant_id = $1 AND m.user_id = $2 AND m.status = 'active' AND u.status = 'active'`, tenant, actor).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrMembershipForbidden
	}
	if err != nil {
		return "", err
	}
	if role != "owner" && role != "admin" {
		return "", ErrMembershipForbidden
	}
	return role, nil
}

func (u *Users) Members(ctx context.Context, tenant, actor uuid.UUID) ([]Member, error) {
	out := []Member{}
	err := pg.InTenantTx(ctx, u.pool, tenant.String(), func(tx pgx.Tx) error {
		if _, err := lockWorkspaceManager(ctx, tx, tenant, actor); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT u.id,u.email,m.role,m.status,m.created_at,
			m.role='owner' AND m.status='active' AND u.status='active' AND
			(SELECT count(*) FROM workspace_memberships owners JOIN users identities ON identities.id=owners.user_id
			 WHERE owners.tenant_id=$1 AND owners.role='owner' AND owners.status='active' AND identities.status='active') <= 1,
 u.name,u.avatar,
 coalesce((SELECT jsonb_agg(jsonb_build_object('device_id',access.id,'label',access.label,'pn',coalesce(access.pn,''),'has_key',access.has_key,'read',access.can_read,'send',access.can_send,'manage',access.can_manage) ORDER BY access.label,access.id)
 FROM (SELECT d.id,d.label,d.pn,
 EXISTS(SELECT 1 FROM device_key_grants g WHERE g.device_id=d.id AND g.user_id=u.id AND g.epoch=d.current_epoch) AS has_key,
 coalesce(p.can_read,false) AS can_read,coalesce(p.can_send,false) AS can_send,
 (m.role IN ('owner','admin') OR coalesce(p.can_manage,false)) AS can_manage
 FROM devices d LEFT JOIN device_permissions p ON p.device_id=d.id AND p.user_id=u.id AND p.tenant_id=$1
 WHERE d.tenant_id=$1 AND m.status='active' AND u.status='active') access
 WHERE access.has_key OR access.can_read OR access.can_send OR access.can_manage),'[]'::jsonb)
			FROM workspace_memberships m JOIN users u ON u.id = m.user_id
			WHERE m.tenant_id = $1 ORDER BY m.created_at,u.id`, tenant)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var member Member
			var devices []byte
			if err := rows.Scan(&member.ID, &member.Email, &member.Role, &member.Status, &member.CreatedAt, &member.LastOwner, &member.Name, &member.Avatar, &devices); err != nil {
				return err
			}
			if err := json.Unmarshal(devices, &member.DeviceAccess); err != nil {
				return err
			}
			if member.Role == RoleService {
				member.Email = ServiceName(User{Email: member.Email, Role: RoleService})
			}
			out = append(out, member)
		}
		return rows.Err()
	})
	return out, err
}

// UpdateMember changes a complete role/status pair. Service identities cannot
// be converted into people, or vice versa. Disabling strips grants and machine
// credentials; re-enabling never silently restores them.
func (u *Users) UpdateMember(ctx context.Context, tenant, actor, target uuid.UUID, role, status string) error {
	if (role != "owner" && role != "admin" && role != "member" && role != RoleService) || (status != "active" && status != "disabled") {
		return ErrInvalidMembership
	}
	return pg.InTenantTx(ctx, u.pool, tenant.String(), func(tx pgx.Tx) error {
		actorRole, err := lockWorkspaceManager(ctx, tx, tenant, actor)
		if err != nil {
			return err
		}
		var oldRole, oldStatus string
		err = tx.QueryRow(ctx, `SELECT role,status FROM workspace_memberships WHERE tenant_id=$1 AND user_id=$2`, tenant, target).Scan(&oldRole, &oldStatus)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if (oldRole == RoleService) != (role == RoleService) {
			return ErrInvalidMembership
		}
		if actorRole != "owner" && (oldRole == "owner" || oldRole == "admin" || role == "owner" || role == "admin") {
			return ErrMembershipForbidden
		}
		if oldRole == role && oldStatus == status {
			return nil
		}
		if oldRole == "owner" && oldStatus == "active" && (role != "owner" || status != "active") {
			var owners int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM workspace_memberships m JOIN users u ON u.id=m.user_id
				WHERE m.tenant_id=$1 AND m.role='owner' AND m.status='active' AND u.status='active'`, tenant).Scan(&owners); err != nil {
				return err
			}
			if owners <= 1 {
				return ErrLastOwner
			}
		}
		if status == "disabled" {
			if err := requireRemainingReader(ctx, tx, tenant, target, nil); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE workspace_memberships SET role=$3,status=$4 WHERE tenant_id=$1 AND user_id=$2`, tenant, target, role, status); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at=now() WHERE tenant_id=$1 AND user_id=$2 AND revoked_at IS NULL`, tenant, target); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE invites SET expires_at=now() WHERE tenant_id=$1 AND created_by=$2 AND completed_at IS NULL`, tenant, target); err != nil {
			return err
		}
		if status == "disabled" {
			if _, err := tx.Exec(ctx, `DELETE FROM device_permissions WHERE tenant_id=$1 AND user_id=$2`, tenant, target); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `DELETE FROM device_key_grants WHERE tenant_id=$1 AND user_id=$2`, tenant, target); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE api_keys SET revoked_at=now() WHERE tenant_id=$1 AND acts_as=$2 AND revoked_at IS NULL`, tenant, target); err != nil {
				return err
			}
		}
		return nil
	})
}

// InviteMember issues a seven-day, one-use invitation without delivering it.
func (u *Users) InviteMember(ctx context.Context, tenant, actor uuid.UUID, role, email string) (string, error) {
	secret, _, err := u.NewMemberInvitation(ctx, tenant, actor, role, email)
	return secret, err
}
