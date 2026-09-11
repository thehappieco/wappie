package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"whatserver2/internal/pg"
	"whatserver2/internal/wa"
)

// ReaderMode defaults to passive even for a number whose shared transport is
// active. A team member never inherits another person's disclosure choice.
func (u *Users) ReaderMode(ctx context.Context, tenant, user, device uuid.UUID) (wa.ReceiptMode, error) {
	mode := wa.ModePassive
	err := pg.InTenantTx(ctx, u.pool, tenant.String(), func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT receipt_mode FROM reader_preferences WHERE tenant_id=$1 AND user_id=$2 AND device_id=$3`, tenant, user, device).Scan(&mode)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	})
	return mode, err
}

func (u *Users) SetReaderMode(ctx context.Context, tenant, user, device uuid.UUID, mode wa.ReceiptMode) error {
	if _, err := wa.ParseReceiptMode(string(mode)); err != nil {
		return err
	}
	return pg.InTenantTx(ctx, u.pool, tenant.String(), func(tx pgx.Tx) error {
		if err := lockWorkspaceAccess(ctx, tx, tenant); err != nil {
			return err
		}
		// A preference cannot grant access, and stale sessions cannot create it
		// after their membership/key was revoked.
		tag, err := tx.Exec(ctx, `INSERT INTO reader_preferences(tenant_id,user_id,device_id,receipt_mode)
			SELECT m.tenant_id,m.user_id,d.id,$4 FROM workspace_memberships m
			JOIN users u ON u.id=m.user_id AND u.status='active'
			JOIN devices d ON d.tenant_id=m.tenant_id
			JOIN device_permissions p ON p.tenant_id=m.tenant_id AND p.device_id=d.id AND p.user_id=m.user_id AND p.can_read
			WHERE m.tenant_id=$1 AND m.user_id=$2 AND d.id=$3 AND m.status='active'
			AND EXISTS(SELECT 1 FROM device_key_grants g WHERE g.tenant_id=m.tenant_id AND g.device_id=d.id AND g.user_id=m.user_id AND g.epoch=d.current_epoch)
			ON CONFLICT(tenant_id,user_id,device_id) DO UPDATE SET receipt_mode=excluded.receipt_mode,updated_at=now()`, tenant, user, device, mode)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrMembershipForbidden
		}
		return nil
	})
}
