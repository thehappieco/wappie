package store

import (
	"context"
	"errors"
	"fmt"
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
	// ActionPause is pausing and resuming a number's capture (device.stop,
	// device.start; decision 0039), by role only (the owner's answer of
	// 2026-10-26 to the platform's design of that day, question 1): a
	// person who is an owner or an admin of the workspace, which in a
	// personal workspace is its person, and never a member through the
	// stored Manage flag. A service account acts as itself through its
	// keys, so it keeps its own Manage flag here, under the key's scope
	// (internal/access). Every other act of managing a number stays
	// ActionManage. device.start on a number that is not paused ("sync
	// now", which connects it) is a person's ActionRead (the platform's
	// answer 4, DS13) and a key's ActionManage.
	ActionPause DeviceAction = "pause"
)

type DevicePermission struct {
	DeviceID uuid.UUID `json:"device_id"`
	UserID   uuid.UUID `json:"user_id"`
	Read     bool      `json:"read"`
	Send     bool      `json:"send"`
	Manage   bool      `json:"manage"`
	HasKey   bool      `json:"has_key"`
	// Pause is ActionPause: the role owner or admin, or a service
	// account's own Manage flag. Derived, never stored, and never in the
	// permissions' JSON, whose rows carry only the flags above.
	Pause bool `json:"-"`
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
	case ActionPause:
		return p.Pause
	}
	return false
}

func (u *Users) DevicePermission(ctx context.Context, tenant, user, device uuid.UUID) (DevicePermission, error) {
	var out DevicePermission
	err := pg.InTenantTx(ctx, u.pool, tenant.String(), func(tx pgx.Tx) error {
		var err error
		out, err = devicePermissionTx(ctx, tx, tenant, user, device)
		return err
	})
	return out, err
}

// devicePermissionTx is DevicePermission inside a transaction the caller
// holds for the tenant: an active user with an active, unexpired membership
// in an active workspace, and what they may do with the device. ErrNotFound
// when any of that is missing, or when the number is excluded (0050).
// Pause is the role, from the same membership row, or a service account's
// own Manage flag (ActionPause).
func devicePermissionTx(ctx context.Context, tx pgx.Tx, tenant, user, device uuid.UUID) (DevicePermission, error) {
	out := DevicePermission{DeviceID: device, UserID: user}
	err := tx.QueryRow(ctx, `SELECT coalesce(p.can_read,false),coalesce(p.can_send,false),
   (m.role IN ('owner','admin') OR coalesce(p.can_manage,false)),
   EXISTS(SELECT 1 FROM device_key_grants g WHERE g.device_id=d.id AND g.user_id=m.user_id AND g.epoch=d.current_epoch),
   (m.role IN ('owner','admin') OR (m.role='service' AND coalesce(p.can_manage,false)))
   FROM workspace_memberships m JOIN users u ON u.id=m.user_id JOIN tenants t ON t.id=m.tenant_id
   JOIN devices d ON d.tenant_id=m.tenant_id
   LEFT JOIN device_permissions p ON p.tenant_id=m.tenant_id AND p.device_id=d.id AND p.user_id=m.user_id
   WHERE m.tenant_id=$1 AND m.user_id=$2 AND d.id=$3 AND d.deleted_at IS NULL AND m.status='active' AND u.status='active' AND t.status='active'
   AND (m.expires_at IS NULL OR m.expires_at > now())`, tenant, user, device).Scan(&out.Read, &out.Send, &out.Manage, &out.HasKey, &out.Pause)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	return out, err
}

// StoredDevicePermission is user's row for device as stored, before a
// change: the flags themselves, with no role folded in (false without a
// row), and HasKey, whether user holds the number's key at any epoch not
// retired. A permission change reads it first to tell an act that raises a
// flag, or that narrows who holds the key, from one that does neither
// (README 7.1), outside its own transaction.
func (u *Users) StoredDevicePermission(ctx context.Context, tenant, user, device uuid.UUID) (DevicePermission, error) {
	out := DevicePermission{DeviceID: device, UserID: user}
	err := pg.InTenantTx(ctx, u.pool, tenant.String(), func(tx pgx.Tx) error {
		var err error
		out, err = storedDevicePermissionTx(ctx, tx, tenant, user, device)
		return err
	})
	return out, err
}

// storedDevicePermissionTx is StoredDevicePermission in a transaction the
// caller holds for the tenant. It never reads devices, so a deleted
// number's row reads as a live one's.
func storedDevicePermissionTx(ctx context.Context, tx pgx.Tx, tenant, user, device uuid.UUID) (DevicePermission, error) {
	out := DevicePermission{DeviceID: device, UserID: user}
	err := tx.QueryRow(ctx, `SELECT coalesce(p.can_read, false), coalesce(p.can_send, false), coalesce(p.can_manage, false),
			EXISTS (SELECT 1 FROM device_key_grants g JOIN device_archive_keys k ON k.device_id = g.device_id AND k.epoch = g.epoch AND k.retired_at IS NULL
			         WHERE g.tenant_id = $1 AND g.device_id = $3 AND g.user_id = $2)
			FROM (SELECT 1) one LEFT JOIN device_permissions p ON p.tenant_id = $1 AND p.device_id = $3 AND p.user_id = $2`,
		tenant, user, device).Scan(&out.Read, &out.Send, &out.Manage, &out.HasKey)
	return out, err
}

// ErrOwnerTarget is a change of an owner's flags by an admin: only an owner
// changes an owner's (the owner's answer to the platform's Q58). It is an
// ErrMembershipForbidden, so Wappie's screen answers it 403 not_authorized;
// the console's acts answer not_authorized.
var ErrOwnerTarget = fmt.Errorf("%w: only an owner changes an owner's flags", ErrMembershipForbidden)

// ownerTargetTx reports whether user is an owner of tenant, by the local
// membership (whatever its status) or by their stored account document
// (whatever its status or generation): read fail-closed, so a role the two
// sides disagree on counts as an owner's.
func ownerTargetTx(ctx context.Context, tx pgx.Tx, tenant, user uuid.UUID) (bool, error) {
	var owner bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM workspace_memberships WHERE tenant_id = $1 AND user_id = $2 AND role = 'owner')
		OR EXISTS (SELECT 1 FROM platform_identities p JOIN contract_accounts a ON a.sub = p.sub,
			jsonb_array_elements(CASE WHEN jsonb_typeof(a.doc->'workspaces') = 'array' THEN a.doc->'workspaces' ELSE '[]'::jsonb END) w
			WHERE p.user_id = $2 AND w->>'id' = $1::text AND w->>'role' = 'owner')`, tenant, user).Scan(&owner)
	return owner, err
}

func (u *Users) SetDevicePermission(ctx context.Context, tenant, actor uuid.UUID, p DevicePermission) error {
	_, err := u.SetDevicePermissionEnded(ctx, tenant, actor, p)
	return err
}

// SetDevicePermissionEnded is SetDevicePermission, and the person's own
// connections it ended (Read going, or no flag left, ends those that held
// the number, DS47), for their readers to be told after the commit.
func (u *Users) SetDevicePermissionEnded(ctx context.Context, tenant, actor uuid.UUID, p DevicePermission) ([]EndedConnection, error) {
	var ended []EndedConnection
	err := pg.InTenantTx(ctx, u.pool, tenant.String(), func(tx pgx.Tx) error {
		role, err := lockWorkspaceManager(ctx, tx, tenant, actor)
		if err != nil {
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
		if role != "owner" {
			owner, err := ownerTargetTx(ctx, tx, tenant, p.UserID)
			if err != nil {
				return err
			}
			if owner {
				return ErrOwnerTarget
			}
		}
		// Read revocation removes the envelope too. Re-enabling requires an
		// explicit client-side grant by somebody who still holds the archive key.
		ended, err = setDevicePermissionTx(ctx, tx, tenant, p, !p.Read)
		return err
	})
	if err != nil {
		return nil, err
	}
	return ended, nil
}

// setDevicePermissionTx is the write of a permission change, shared by
// Wappie's own screen (SetDevicePermission) and the console's flags acts
// (contract_flags_acts.go): the row upserted to p's flags; with dropKeys,
// first requireRemainingReader (ErrLastDeviceReader), then every grant of
// p.UserID on the number deleted, at every epoch. When Read goes (the
// stored row had it) or no flag is left (the access removed), every one of
// p.UserID's own connections and integrations that holds the number ends
// whole, access_lost (leaveOwnConnectionsTx, DS47, the platform's 0061),
// and they come back for their readers to be told; a change with Read
// already gone that keeps send or manage (a raise, a drop of the other)
// ends none, on the screen as in the acts. The
// caller holds the workspace's lock (the tenants row) and has checked the
// number and the person. A deleted number's row is written only inside
// withQuarantine: 0036's archive_device_owner refuses it otherwise (WS002).
func setDevicePermissionTx(ctx context.Context, tx pgx.Tx, tenant uuid.UUID, p DevicePermission, dropKeys bool) ([]EndedConnection, error) {
	var hadRead bool
	if dropKeys {
		if err := requireRemainingReader(ctx, tx, tenant, p.UserID, &p.DeviceID); err != nil {
			return nil, err
		}
		if err := tx.QueryRow(ctx, `SELECT coalesce((SELECT can_read FROM device_permissions
			WHERE tenant_id = $1 AND device_id = $2 AND user_id = $3), false)`, tenant, p.DeviceID, p.UserID).Scan(&hadRead); err != nil {
			return nil, err
		}
	}
	_, err := tx.Exec(ctx, `INSERT INTO device_permissions(tenant_id,device_id,user_id,can_read,can_send,can_manage)
   VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id,device_id,user_id) DO UPDATE
   SET can_read=excluded.can_read,can_send=excluded.can_send,can_manage=excluded.can_manage`, tenant, p.DeviceID, p.UserID, p.Read, p.Send, p.Manage)
	if err != nil || !dropKeys {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM device_key_grants WHERE tenant_id=$1 AND device_id=$2 AND user_id=$3`, tenant, p.DeviceID, p.UserID); err != nil {
		return nil, err
	}
	// Read did not go and a flag is left: the connections stay.
	if p.Read || !hadRead && (p.Send || p.Manage) {
		return nil, nil
	}
	return leaveOwnConnectionsTx(ctx, tx, tenant, p.UserID, p.DeviceID)
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
  WHERE k.id=$1 AND d.id=$2 AND d.deleted_at IS NULL AND k.revoked_at IS NULL AND
  (NOT k.devices_restricted OR
   EXISTS(SELECT 1 FROM api_key_devices x WHERE x.api_key_id=k.id AND x.device_id=d.id)))`, id, device).Scan(&allowed)
	})
	return allowed, err
}
