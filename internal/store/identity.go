package store

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"whatserver2/internal/pg"
)

func nullableWorkspace(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}
func (u *Users) identity(ctx context.Context, id uuid.UUID) (User, error) {
	home, err := u.identityTenant(ctx, id)
	if err != nil {
		return User{}, ErrNotFound
	}
	out := User{ID: id}
	var raw []byte
	var role string
	err = pg.InTenantTx(ctx, u.pool, home.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT email,kdf_salt,kdf_params,public_key,wrapped_usk,recovery_wrap,recovery_hash IS NOT NULL,status,created_at,role FROM users WHERE id=$1`, id).Scan(&out.Email, &out.KDFSalt, &raw, &out.PublicKey, &out.WrappedUSK, &out.RecoveryWrap, &out.RecoveryUsable, &out.Status, &out.CreatedAt, &role)
	})
	if err != nil {
		return User{}, err
	}
	if role == RoleService {
		return User{}, ErrNoSession
	}
	if len(raw) > 0 {
		if err = json.Unmarshal(raw, &out.KDFParams); err != nil {
			return User{}, err
		}
	}
	return out, nil
}
