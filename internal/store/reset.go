package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/pg"
)

// ResetCounts reports what a reset removed.
type ResetCounts struct {
	Messages int64
	Chats    int64
	Contacts int64
	Media    int64
	Devices  int64
	// Connections are the live MCP connections and AI integrations the
	// reset ended, revoked and access_lost.
	Connections int64
}

// ResetArchive removes everything sealed for one tenant.
//
// It exists because a change to the key scheme cannot be applied to data
// already sealed: re-sealing means opening, and this server has never been able
// to open its own archive. The only way past one is to discard and start again,
// which is a decision an operator makes deliberately — never a migration.
//
// Object storage is left alone. What is in it is ciphertext addressed by a
// content hash and inert without keys that this removes; deleting it is a long
// remote operation that can half-finish, and a half-finished delete is worse
// than an untidy bucket.
//
// It refuses while a deleted number waits for its purge (0050). Its row is
// hidden from the statements on devices below, so the reset would empty its
// archive and leave the row behind, and its owner was promised 30 days to
// recover it.
//
// It counts as Read taken away from everyone (the platform's 0061, DS48):
// it deletes every grant and leaves none at a number's current epoch. So
// before anything is deleted it ends every live MCP connection and AI
// integration of the workspace, of any kind and status, revoked and
// access_lost, as a revoke ends one (endMCPConnectionTx). It does not
// leave them to the check at the next start: the reset may run while the
// server keeps running, a metadata key asks nothing of a grant, and
// without keepDevices the cascade empties api_key_devices, so no later
// check would find those connections. The workspace's lock comes first,
// as for every act on access (reader_safety.go), so a consent recorded at
// the same time comes before the reset or is refused after it. It holds
// that lock, which ingest needs for every message, to the end.
// wappie-api's watch tells the readers once it runs (WatchRevocations).
//
// It tells every process at its commit (ArchiveKeyChannel, for the whole
// workspace), so a running server drops what ingest built from the keys
// it deleted and needs no restart (DS49).
func ResetArchive(ctx context.Context, pool *pgxpool.Pool, tenant uuid.UUID,
	keepDevices bool) (ResetCounts, error) {
	var out ResetCounts
	err := pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		if err := lockWorkspaceAccess(ctx, tx, tenant); err != nil {
			return fmt.Errorf("store: reset: lock the workspace: %w", err)
		}
		excluded, err := anyExcludedTx(ctx, tx)
		if err != nil {
			return fmt.Errorf("store: reset: look for deleted numbers: %w", err)
		}
		if excluded {
			return ErrExcludedNumbers
		}
		if out.Connections, err = endEveryConnectionTx(ctx, tx, tenant); err != nil {
			return fmt.Errorf("store: reset: end the connections: %w", err)
		}
		// Order matters only for readability: every one of these cascades from
		// devices, and the counts would be zero if devices went first. The
		// journal and the receipts go too: the tenant sequence numbered
		// them, and with the numbers kept the next message would be given
		// a sequence an old event still holds.
		for _, step := range []struct {
			table string
			into  *int64
		}{
			{"media", &out.Media},
			{"messages", &out.Messages},
			{"chats", &out.Chats},
			{"contacts", &out.Contacts},
			{"events", nil},
			{"receipts", nil},
			{"content_keys", nil},
			{"device_key_grants", nil},
			{"device_archive_keys", nil},
		} {
			tag, err := tx.Exec(ctx, "DELETE FROM "+step.table)
			if err != nil {
				return fmt.Errorf("store: reset %s: %w", step.table, err)
			}
			if step.into != nil {
				*step.into = tag.RowsAffected()
			}
		}

		if !keepDevices {
			tag, err := tx.Exec(ctx, `DELETE FROM devices`)
			if err != nil {
				return fmt.Errorf("store: reset devices: %w", err)
			}
			out.Devices = tag.RowsAffected()
		} else {
			// A device with no key cannot seal, and ingest refuses rather than
			// storing plaintext. Saying so here beats discovering it as a
			// stream of errors on the next message.
			if _, err := tx.Exec(ctx, `UPDATE devices SET current_epoch = 0`); err != nil {
				return fmt.Errorf("store: clear device epochs: %w", err)
			}
		}

		// The tenant sequence goes back to zero with the rows it numbered. A
		// client resuming from an old cursor would otherwise wait forever for
		// sequences that will never be issued again.
		if _, err := tx.Exec(ctx,
			`UPDATE tenants SET last_seq = 0 WHERE id = $1`, tenant); err != nil {
			return fmt.Errorf("store: reset sequence: %w", err)
		}
		return notifyArchiveKeyTx(ctx, tx, tenant, nil)
	})
	if err != nil {
		return ResetCounts{}, err
	}
	return out, nil
}

// endEveryConnectionTx ends every live connection of tenant, any kind,
// pending, active or reseal, in id order, revoked and access_lost, and
// counts those it ended. The caller holds the tenants row lock.
func endEveryConnectionTx(ctx context.Context, tx pgx.Tx, tenant uuid.UUID) (int64, error) {
	rows, err := tx.Query(ctx, `SELECT id::text FROM mcp_connections
		WHERE tenant_id = $1 AND status IN ('pending', 'active', 'reseal') ORDER BY id FOR UPDATE`, tenant)
	if err != nil {
		return 0, err
	}
	live, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return 0, err
	}
	var n int64
	for _, id := range live {
		ended, err := endMCPConnectionTx(ctx, tx, tenant, id, statusRevoked, ReasonAccessLost)
		if err != nil {
			return 0, err
		}
		if ended {
			n++
		}
	}
	return n, nil
}
