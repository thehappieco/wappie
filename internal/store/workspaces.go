package store

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Workspace is a membership of an authenticated identity, not an archive grant.
type Workspace struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

// Workspaces returns only this identity's active memberships. Suspended spaces
// remain visible so the client can explain why they cannot be opened.
func (u *Users) Workspaces(ctx context.Context, userID uuid.UUID) ([]Workspace, error) {
	tx, err := u.pool.Begin(ctx)
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
	rows, err := tx.Query(ctx, `SELECT t.id, t.name, m.role, t.status, m.created_at
		FROM workspace_memberships m JOIN tenants t ON t.id = m.tenant_id
		WHERE m.user_id = $1 AND m.status = 'active' ORDER BY m.created_at, t.id`, userID)
	if err != nil {
		return nil, err
	}
	out := []Workspace{}
	for rows.Next() {
		var w Workspace
		if err := rows.Scan(&w.ID, &w.Name, &w.Role, &w.Status, &w.CreatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, w)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, tx.Commit(ctx)
}

// AcceptWorkspaceInvite joins an existing identity to a space without creating
// keys or granting access to any device. Validation, insertion and consumption
// are atomic; an invalid recipient or a duplicate membership does not spend it.
func (u *Users) AcceptWorkspaceInvite(ctx context.Context, user User, secret string) (uuid.UUID, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(secret))
	if err != nil || len(raw) != 24 || user.Role == RoleService {
		return uuid.Nil, ErrInviteInvalid
	}
	sum := sha256.Sum256(raw)
	tx, err := u.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer func() {
		//nolint:errcheck // Cleanup after commit normally returns ErrTxClosed; preserve the operation error.
		_ = tx.Rollback(ctx)
	}()
	var tenant uuid.UUID
	var role string
	var email *string
	err = tx.QueryRow(ctx, `SELECT i.tenant_id, i.role, i.email FROM invites i
		JOIN tenants t ON t.id = i.tenant_id
		WHERE i.invite_id = $1 AND i.completed_at IS NULL AND i.expires_at > now()
		AND t.status = 'active' FOR UPDATE OF i`, sum[:]).Scan(&tenant, &role, &email)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrInviteInvalid
	}
	if err != nil {
		return uuid.Nil, err
	}
	if role == RoleService || (email != nil && *email != normaliseEmail(user.Email)) {
		return uuid.Nil, ErrInviteInvalid
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenant.String()); err != nil {
		return uuid.Nil, err
	}
	tag, err := tx.Exec(ctx, `INSERT INTO workspace_memberships (tenant_id, user_id, role)
		VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, tenant, user.ID, role)
	if err != nil {
		return uuid.Nil, fmt.Errorf("store: join workspace: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return uuid.Nil, ErrInviteInvalid
	}
	if _, err := tx.Exec(ctx, `UPDATE invites SET completed_at = now() WHERE invite_id = $1`, sum[:]); err != nil {
		return uuid.Nil, err
	}
	return tenant, tx.Commit(ctx)
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
