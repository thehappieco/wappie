package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// A person's lost Read on a number ends their own MCP connections and AI
// integrations that held it, whole (the owner's answer to the platform's
// Q8 and the platform's decision 0061, DS47; docs/mcp-enclave.md 15.15).
// Wappie's permissions screen and the console's item.flags_drop (of read,
// or of the last flag left) and item.access_remove reach it the same way,
// through setDevicePermissionTx, which decides from the flags it writes.
// The socket's grant.revoke reaches it when the person has the Read flag
// and the revoke leaves them no grant at the number's current epoch
// (grantTakenTx, the platform's 0061, DS48).

// consenterReadsTx refuses a consent of any kind, metadata included, and a
// renewal, with ErrMCPKeyUnsuitable unless actor reads every number of the
// key: Read, and a grant at the number's current epoch, not retired (0053's
// Read, the platform's 0061). The caller holds the tenants row, as a drop
// of Read does, so a consent prepared before the drop and recorded after it
// is refused (DS47).
func consenterReadsTx(ctx context.Context, tx pgx.Tx, tenant, actor, keyID uuid.UUID) error {
	var missing int
	err := tx.QueryRow(ctx, `SELECT count(*) FROM api_key_devices x
		WHERE x.api_key_id = $3 AND NOT EXISTS (SELECT 1 FROM device_permissions p
			JOIN devices d ON d.id = p.device_id AND d.tenant_id = p.tenant_id AND d.deleted_at IS NULL
			JOIN device_key_grants g ON g.tenant_id = p.tenant_id AND g.device_id = p.device_id AND g.user_id = p.user_id AND g.epoch = d.current_epoch
			JOIN device_archive_keys k ON k.device_id = g.device_id AND k.epoch = g.epoch AND k.retired_at IS NULL
			WHERE p.tenant_id = $1 AND p.user_id = $2 AND p.device_id = x.device_id AND p.can_read)`, tenant, actor, keyID).Scan(&missing)
	if err != nil {
		return err
	}
	if missing > 0 {
		return ErrMCPKeyUnsuitable
	}
	return nil
}

// ErrConnectionAccountGrant refuses a grant to a live connection's own
// account (its service_user_id) on a number its key does not name or its
// person does not read (DS48).
var ErrConnectionAccountGrant = errors.New("store: a connection's account takes only a number its key names and its person reads")

// connectionAccountTakesTx refuses, with ErrConnectionAccountGrant, a grant
// to user on device when user is a live connection's own account and its
// key does not name the number or the person who consented does not read
// it, as consenterReadsTx reads it. Such a grant would widen the
// connection past its consent, and the check at the next start would end
// the connection for it (EndConnectionsWithoutRead counts every grant of
// its account as held). Any other account takes any grant. The caller
// holds the tenants row lock, as a consent does.
func connectionAccountTakesTx(ctx context.Context, tx pgx.Tx, tenant, user, device uuid.UUID) error {
	var refused bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM mcp_connections c
		WHERE c.tenant_id = $1 AND c.service_user_id = $2 AND c.status IN ('pending', 'active', 'reseal')
		  AND (NOT EXISTS (SELECT 1 FROM api_key_devices x WHERE x.api_key_id = c.api_key_id AND x.device_id = $3)
		    OR NOT EXISTS (SELECT 1 FROM device_permissions p
			JOIN devices d ON d.id = p.device_id AND d.tenant_id = p.tenant_id AND d.deleted_at IS NULL
			JOIN device_key_grants g ON g.tenant_id = p.tenant_id AND g.device_id = p.device_id AND g.user_id = p.user_id AND g.epoch = d.current_epoch
			JOIN device_archive_keys k ON k.device_id = g.device_id AND k.epoch = g.epoch AND k.retired_at IS NULL
			WHERE p.tenant_id = $1 AND p.user_id = c.created_by AND p.device_id = $3 AND p.can_read)))`,
		tenant, user, device).Scan(&refused)
	if err != nil {
		return err
	}
	if refused {
		return ErrConnectionAccountGrant
	}
	return nil
}

// grantTakenTx is the platform's 0061 third rule (QF3, DS48), for an act
// that deleted some of user's grants on device and kept their flags. It
// took their Read when they have the Read flag and it left them no grant
// at the number's current epoch, its archive key not retired. Then their
// own connections and integrations that held the number end whole,
// access_lost, as a drop of read ends them (leaveOwnConnectionsTx).
//
// Without the Read flag there was no Read to take. Deleting a dormant
// grant ends nothing, as Wappie's screen without Read ends nothing then
// (DS47). An act that left a grant at the current epoch, or put one back
// in the same transaction, took nothing either. grant.revoke deletes every
// epoch, so for it only the flag decides; the other two cases are tested
// through GrantTakenForTest. A rotation deletes no grant and never comes
// here. The caller holds the tenant transaction and the tenants row lock,
// and has deleted the grants.
func grantTakenTx(ctx context.Context, tx pgx.Tx, tenant, user, device uuid.UUID) ([]EndedConnection, error) {
	var taken bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM device_permissions
			WHERE tenant_id = $1 AND device_id = $2 AND user_id = $3 AND can_read)
		AND NOT EXISTS (SELECT 1 FROM device_key_grants g
			JOIN devices d ON d.id = g.device_id AND d.current_epoch = g.epoch
			JOIN device_archive_keys k ON k.device_id = g.device_id AND k.epoch = g.epoch AND k.retired_at IS NULL
			WHERE g.tenant_id = $1 AND g.device_id = $2 AND g.user_id = $3)`, tenant, device, user).Scan(&taken)
	if err != nil || !taken {
		return nil, err
	}
	return leaveOwnConnectionsTx(ctx, tx, tenant, user, device)
}

// leaveOwnConnectionsTx ends, whole and access_lost, every live connection
// of every kind (metadata, content, an AI integration) that user consented
// to or created in tenant and that holds device: by its key's row for the
// number, or its service account's permission or grant on it. One that
// also holds other numbers ends all the same: narrowed, it could never
// renew (a renewal names exactly its key's numbers, while the reader's
// record and an AI integration's ai_config still name the one taken off),
// and the person consents again for the numbers they still read, as a
// deletion or a move ends them (the platform's 0061). endMCPConnectionTx
// takes its key, its drafts still waiting and, for content and AI, its
// service account with every permission and grant.
// Another person's connections, workspace API keys (no connection behind
// them) and legacy MCP tokens are not touched.
//
// The caller holds the tenant transaction and the tenants row lock, and has
// written user's own permission and grants: 3.2's order, then the
// connections in id order, then their own rows. ended are the connections it
// ended, for their readers to be told after the commit.
func leaveOwnConnectionsTx(ctx context.Context, tx pgx.Tx, tenant, user, device uuid.UUID) ([]EndedConnection, error) {
	rows, err := tx.Query(ctx, `SELECT c.id::text, c.reader FROM mcp_connections c
		WHERE c.tenant_id = $1 AND c.created_by = $2 AND c.status IN ('pending', 'active', 'reseal')
		  AND (EXISTS (SELECT 1 FROM api_key_devices x WHERE x.api_key_id = c.api_key_id AND x.device_id = $3)
		       OR EXISTS (SELECT 1 FROM device_key_grants g WHERE g.tenant_id = $1 AND g.device_id = $3 AND g.user_id = c.service_user_id)
		       OR EXISTS (SELECT 1 FROM device_permissions p WHERE p.tenant_id = $1 AND p.device_id = $3 AND p.user_id = c.service_user_id))
		ORDER BY c.id FOR UPDATE OF c`, tenant, user, device)
	if err != nil {
		return nil, err
	}
	own, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (EndedConnection, error) {
		var c EndedConnection
		err := row.Scan(&c.ID, &c.Reader)
		return c, err
	})
	if err != nil || len(own) == 0 {
		return nil, err
	}
	for _, c := range own {
		if _, err := endMCPConnectionTx(ctx, tx, tenant, c.ID, statusRevoked, ReasonAccessLost); err != nil {
			return nil, err
		}
	}
	return own, nil
}
