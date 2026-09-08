package store

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"whatserver2/internal/pg"
)

type DeviceAction string

const (
	ActionRead   DeviceAction = "read"
	ActionSend   DeviceAction = "send"
	ActionManage DeviceAction = "manage"
	ActionView   DeviceAction = "view"
)

type DevicePermission struct {
	DeviceID uuid.UUID `json:"device_id"`
	UserID   uuid.UUID `json:"user_id"`
	Read     bool      `json:"read"`
	Send     bool      `json:"send"`
	Manage   bool      `json:"manage"`
	HasKey   bool      `json:"has_key"`
}

func (p DevicePermission) Allows(action DeviceAction) bool {
	switch action {
	case ActionRead:
		return p.Read && p.HasKey
	case ActionSend:
		return p.Send
	case ActionManage:
		return p.Manage
	case ActionView:
		return p.Manage || p.Send || (p.Read && p.HasKey)
	}
	return false
}

func (u *Users) DevicePermission(ctx context.Context, tenant, user, device uuid.UUID) (DevicePermission, error) {
	out := DevicePermission{DeviceID: device, UserID: user}
	err := pg.InTenantTx(ctx, u.pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT coalesce(p.can_read,false),coalesce(p.can_send,false),
   (m.role IN ('owner','admin') OR coalesce(p.can_manage,false)),
   EXISTS(SELECT 1 FROM device_key_grants g WHERE g.device_id=d.id AND g.user_id=m.user_id AND g.epoch=d.current_epoch)
   FROM workspace_memberships m JOIN users u ON u.id=m.user_id JOIN tenants t ON t.id=m.tenant_id
   JOIN devices d ON d.tenant_id=m.tenant_id
   LEFT JOIN device_permissions p ON p.tenant_id=m.tenant_id AND p.device_id=d.id AND p.user_id=m.user_id
   WHERE m.tenant_id=$1 AND m.user_id=$2 AND d.id=$3 AND m.status='active' AND u.status='active' AND t.status='active'`, tenant, user, device).Scan(&out.Read, &out.Send, &out.Manage, &out.HasKey)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	return out, err
}

func (u *Users) SetDevicePermission(ctx context.Context, tenant, actor uuid.UUID, p DevicePermission) error {
	return pg.InTenantTx(ctx, u.pool, tenant.String(), func(tx pgx.Tx) error {
		if _, err := lockWorkspaceManager(ctx, tx, tenant, actor); err != nil {
			return err
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM workspace_memberships m JOIN devices d ON d.tenant_id=m.tenant_id
   WHERE m.tenant_id=$1 AND m.user_id=$2 AND d.id=$3 AND m.status='active')`, tenant, p.UserID, p.DeviceID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
		_, err := tx.Exec(ctx, `INSERT INTO device_permissions(tenant_id,device_id,user_id,can_read,can_send,can_manage)
   VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id,device_id,user_id) DO UPDATE
   SET can_read=excluded.can_read,can_send=excluded.can_send,can_manage=excluded.can_manage`, tenant, p.DeviceID, p.UserID, p.Read, p.Send, p.Manage)
		if err != nil {
			return err
		}
		// Read revocation removes the envelope too. Re-enabling requires an
		// explicit client-side grant by somebody who still holds the archive key.
		if !p.Read {
			_, err = tx.Exec(ctx, `DELETE FROM device_key_grants WHERE tenant_id=$1 AND device_id=$2 AND user_id=$3`, tenant, p.DeviceID, p.UserID)
		}
		return err
	})
}

func (u *Users) DevicePermissions(ctx context.Context, tenant, actor, device uuid.UUID) ([]DevicePermission, error) {
	members, err := u.Members(ctx, tenant, actor)
	if err != nil {
		return nil, err
	}
	out := []DevicePermission{}
	for _, m := range members {
		if m.Status != "active" {
			continue
		}
		p, err := u.DevicePermission(ctx, tenant, m.ID, device)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func (a *APIKeys) AllowsDevice(ctx context.Context, id, tenant, device uuid.UUID) (bool, error) {
	var allowed bool
	err := pg.InTenantTx(ctx, a.pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM api_keys k JOIN devices d ON d.tenant_id=k.tenant_id
  WHERE k.id=$1 AND d.id=$2 AND k.revoked_at IS NULL AND
  (NOT k.devices_restricted OR
   EXISTS(SELECT 1 FROM api_key_devices x WHERE x.api_key_id=k.id AND x.device_id=d.id)))`, id, device).Scan(&allowed)
	})
	return allowed, err
}
