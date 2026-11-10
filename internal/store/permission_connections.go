package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// A person's own MCP connections and AI integrations lose a number with the
// person's Read on it (the owner's answer to the platform's Q8, DS47;
// docs/mcp-enclave.md 15.15). Wappie's permissions screen and the console's
// item.flags_drop of read and item.access_remove reach it the same way,
// through setDevicePermissionTx.

// ownConnection is one of the person's live connections that reaches the
// number, locked.
type ownConnection struct {
	id      string
	reader  string
	key     uuid.UUID
	service *uuid.UUID
	media   bool
}

// consenterReadsTx refuses a content or AI consent, and its renewal, with
// ErrMCPKeyUnsuitable unless actor reads every number of the key: Read,
// and a grant at the number's current epoch, not retired. The caller holds
// the tenants row, as a drop of Read does, so a consent prepared before
// the drop and recorded after it is refused (DS47).
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

// leaveOwnConnectionsTx takes device off every live connection, of every
// kind, that user consented to or created in tenant: the key's row for the
// number, the service account's permission and grants on it at every epoch,
// and the connection's drafts for it still waiting for a person. A
// connection left with no number ends (access_lost), as a deletion ends it.
// So does a media one, whatever it keeps: the enclave keeps its attachment
// results and text by the numbers its sealed record names, for up to an
// hour, and only an end wipes them (docs/mcp-enclave.md 16.9).
// Another person's connections, workspace API keys (no connection behind
// them) and legacy MCP tokens are not touched.
//
// The caller holds the tenant transaction and the tenants row lock, and has
// written user's own permission and grants: 3.2's order, then the
// connections in id order, then their own rows. ended are the connections it
// ended, for their readers to be told after the commit.
func leaveOwnConnectionsTx(ctx context.Context, tx pgx.Tx, tenant, user, device uuid.UUID) ([]EndedConnection, error) {
	rows, err := tx.Query(ctx, `SELECT c.id::text, c.reader, c.api_key_id, c.service_user_id, c.media FROM mcp_connections c
		WHERE c.tenant_id = $1 AND c.created_by = $2 AND c.status IN ('pending', 'active', 'reseal')
		  AND (EXISTS (SELECT 1 FROM api_key_devices x WHERE x.api_key_id = c.api_key_id AND x.device_id = $3)
		       OR EXISTS (SELECT 1 FROM device_key_grants g WHERE g.tenant_id = $1 AND g.device_id = $3 AND g.user_id = c.service_user_id)
		       OR EXISTS (SELECT 1 FROM device_permissions p WHERE p.tenant_id = $1 AND p.device_id = $3 AND p.user_id = c.service_user_id))
		ORDER BY c.id FOR UPDATE OF c`, tenant, user, device)
	if err != nil {
		return nil, err
	}
	own, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (ownConnection, error) {
		var c ownConnection
		err := row.Scan(&c.id, &c.reader, &c.key, &c.service, &c.media)
		return c, err
	})
	if err != nil {
		return nil, err
	}
	var ended []EndedConnection
	for _, c := range own {
		if c.service != nil {
			if _, err := tx.Exec(ctx, `DELETE FROM device_permissions WHERE tenant_id = $1 AND device_id = $2 AND user_id = $3`,
				tenant, device, *c.service); err != nil {
				return nil, err
			}
			if _, err := tx.Exec(ctx, `DELETE FROM device_key_grants WHERE tenant_id = $1 AND device_id = $2 AND user_id = $3`,
				tenant, device, *c.service); err != nil {
				return nil, err
			}
		}
		// Its drafts for the number go, as an end takes all of them: their
		// text came from a number the person no longer reads.
		if _, err := tx.Exec(ctx, `UPDATE mcp_outbound SET status = 'revoked', sealed = NULL, decided_at = now()
			WHERE connection_id = $1 AND tenant_id = $2 AND device_id = $3 AND status = 'pending'`, c.id, tenant, device); err != nil {
			return nil, err
		}
		// 0026's trigger keeps the key restricted, with no number at the
		// worst, and bumps its access_version, so its sockets check again.
		if _, err := tx.Exec(ctx, `DELETE FROM api_key_devices WHERE api_key_id = $1 AND device_id = $2`, c.key, device); err != nil {
			return nil, err
		}
		var left int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM api_key_devices WHERE api_key_id = $1`, c.key).Scan(&left); err != nil {
			return nil, err
		}
		if left == 0 || c.media {
			if _, err := endMCPConnectionTx(ctx, tx, tenant, c.id, statusRevoked, ReasonAccessLost); err != nil {
				return nil, err
			}
			ended = append(ended, EndedConnection{ID: c.id, Reader: c.reader})
			continue
		}
		if _, err := tx.Exec(ctx, `UPDATE mcp_connections SET device_count = $3 WHERE id = $1 AND tenant_id = $2`,
			c.id, tenant, left); err != nil {
			return nil, err
		}
	}
	return ended, nil
}
