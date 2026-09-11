package store

import (
	"context"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"whatserver2/internal/pg"
)

type Profile struct {
	ID     uuid.UUID `json:"id"`
	Email  string    `json:"email"`
	Name   string    `json:"name"`
	Avatar string    `json:"avatar"`
}

func (u *Users) Profile(ctx context.Context, id uuid.UUID) (Profile, error) {
	home, err := u.identityTenant(ctx, id)
	if err != nil {
		return Profile{}, err
	}
	out := Profile{ID: id}
	err = pg.InTenantTx(ctx, u.pool, home.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT email,name,avatar FROM users WHERE id=$1 AND role<>'service' AND status='active'`, id).Scan(&out.Email, &out.Name, &out.Avatar)
	})
	return out, err
}
func (u *Users) UpdateProfile(ctx context.Context, id uuid.UUID, name, avatar string) (Profile, error) {
	name = strings.TrimSpace(name)
	if !validProfileName(name, true) {
		return Profile{}, ErrInvalidWorkspaceProfile
	}
	avatar, err := normalizeWorkspaceAvatar(avatar)
	if err != nil {
		return Profile{}, err
	}
	home, err := u.identityTenant(ctx, id)
	if err != nil {
		return Profile{}, err
	}
	out := Profile{ID: id}
	err = pg.InTenantTx(ctx, u.pool, home.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `UPDATE users SET name=$2,avatar=$3,updated_at=now() WHERE id=$1 AND role<>'service' AND status='active' RETURNING email,name,avatar`, id, name, avatar).Scan(&out.Email, &out.Name, &out.Avatar)
	})
	return out, err
}
func (u *Users) CreateWorkspace(ctx context.Context, user User, name, avatar string) (Workspace, error) {
	name = strings.TrimSpace(name)
	if !validProfileName(name, true) {
		return Workspace{}, ErrInvalidWorkspaceProfile
	}
	avatar, err := normalizeWorkspaceAvatar(avatar)
	if err != nil {
		return Workspace{}, err
	}
	if user.Role == RoleService {
		return Workspace{}, ErrMembershipForbidden
	}
	out := Workspace{Name: name, Avatar: avatar, Kind: "team", Role: "owner", Status: "active"}
	home, err := u.identityTenant(ctx, user.ID)
	if err != nil {
		return Workspace{}, err
	}
	err = pg.InTx(ctx, u.pool, func(tx pgx.Tx) error {
		var e error
		if _, e = tx.Exec(ctx, `SELECT set_config('app.tenant_id',$1,true)`, home.String()); e != nil {
			return e
		}
		var active bool
		if e = tx.QueryRow(ctx, `SELECT status='active' AND role<>'service' FROM users WHERE id=$1 FOR SHARE`, user.ID).Scan(&active); e != nil {
			return e
		}
		if !active {
			return ErrMembershipForbidden
		}
		if e = tx.QueryRow(ctx, `INSERT INTO tenants(name,avatar,kind) VALUES($1,$2,'team') RETURNING id,created_at`, name, avatar).Scan(&out.ID, &out.CreatedAt); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `SELECT set_config('app.tenant_id',$1,true)`, out.ID.String()); e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `INSERT INTO workspace_memberships(tenant_id,user_id,role) VALUES($1,$2,'owner')`, out.ID, user.ID)
		return e
	})
	return out, err
}
