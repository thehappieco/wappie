package store

import (
	"context"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"whatserver2/internal/pg"
)

type Capacity struct {
	MaxDevices  *int `json:"max_devices"`
	UsedDevices int  `json:"used_devices"`
}

func (u *Users) Capacity(ctx context.Context, tenant, actor uuid.UUID) (Capacity, error) {
	var out Capacity
	err := pg.InTenantTx(ctx, u.pool, tenant.String(), func(tx pgx.Tx) error {
		if _, err := lockWorkspaceManager(ctx, tx, tenant, actor); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT (SELECT max_devices FROM workspace_capacity WHERE tenant_id=$1),(SELECT count(*) FROM devices WHERE tenant_id=$1)`, tenant).Scan(&out.MaxDevices, &out.UsedDevices)
	})
	return out, err
}
