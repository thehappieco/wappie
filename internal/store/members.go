package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
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

type Member struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
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
		rows, err := tx.Query(ctx, `SELECT u.id,u.email,m.role,m.status,m.created_at
			FROM workspace_memberships m JOIN users u ON u.id = m.user_id
			WHERE m.tenant_id = $1 ORDER BY m.created_at,u.id`, tenant)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var member Member
			if err := rows.Scan(&member.ID, &member.Email, &member.Role, &member.Status, &member.CreatedAt); err != nil {
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
	if role != "owner" && role != "admin" && role != "member" && role != RoleService {
		return "", ErrInvalidMembership
	}
	if email != "" && !strings.Contains(normaliseEmail(email), "@") {
		return "", ErrInvalidMembership
	}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	err := pg.InTenantTx(ctx, u.pool, tenant.String(), func(tx pgx.Tx) error {
		actorRole, err := lockWorkspaceManager(ctx, tx, tenant, actor)
		if err != nil {
			return err
		}
		if actorRole != "owner" && (role == "owner" || role == "admin") {
			return ErrMembershipForbidden
		}
		var address *string
		if email != "" {
			normalized := normaliseEmail(email)
			address = &normalized
		}
		_, err = tx.Exec(ctx, `INSERT INTO invites(invite_id,tenant_id,role,created_by,email,expires_at)
			VALUES($1,$2,$3,$4,$5,$6)`, sum[:], tenant, role, actor, address, time.Now().Add(7*24*time.Hour))
		return err
	})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
