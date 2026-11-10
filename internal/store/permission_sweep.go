package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/pg"
)

// The upgrade's sweep (DS48, the platform's answer on F4's scope): the
// connections already live whose person no longer reads one of their
// numbers end once, whole and access_lost, as a lost Read ends them since
// F3 and F4. They are the ones the rules before left behind: a metadata
// consent that asked no Read, a content connection or an AI integration
// whose person lost Read before F3, and any connection whose person lost
// their grant through a grant.revoke before F4.

// EndConnectionsWithoutRead ends, whole and access_lost, every live
// connection of every kind (metadata, content, an AI integration; pending,
// active or reseal) whose person does not read one of the numbers it holds.
// It holds a number as leaveOwnConnectionsTx counts it: its key's row, or
// its service account's permission or grant on it. Reading a number is
// what consenterReadsTx asks of a consent: the Read flag and a grant at the
// number's current epoch, its key not retired, the number not deleted. A
// number with no archive key at its current epoch (a keyless one, or one
// after ResetArchive) is read by nobody, so its connections end.
//
// A rotation does not count (0061). A person waits for a number's new key,
// and is passed over for it, when they keep the Read flag and hold a grant
// at an earlier epoch of the number whose key is not retired, and none at
// the current one: the rotation is not finished for them. Once that old
// key is retired, or their old grant is gone, they no longer wait.
//
// Each workspace ends its own in one transaction, under its tenants row
// lock, the connections in id order, each through endMCPConnectionTx, as
// a revoke ends it. It waits at most sweepLockTimeout for each lock: a
// busy workspace fails with ErrWorkspaceBusy, named in the error, rather
// than holding up its caller. One workspace failing does not keep the
// others.
// It returns what it ended, also when some workspace failed, for the
// readers to be told after the commits (WatchRevocations tells them in any
// case). It is the upgrade's work, run once on a database (DS48), not a
// janitor.
func EndConnectionsWithoutRead(ctx context.Context, pool *pgxpool.Pool) ([]EndedConnection, error) {
	// The ledger carries no policy: the workspaces with a live connection
	// are found in one read.
	rows, err := pool.Query(ctx, `SELECT DISTINCT tenant_id FROM mcp_connections
		WHERE status IN ('pending', 'active', 'reseal') ORDER BY tenant_id`)
	if err != nil {
		return nil, fmt.Errorf("store: connections without read: %w", err)
	}
	tenants, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return nil, fmt.Errorf("store: connections without read: %w", err)
	}
	var out []EndedConnection
	var errs []error
	for _, tenant := range tenants {
		var ended []EndedConnection
		err := pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
			var err error
			ended, err = endConnectionsWithoutReadTx(ctx, tx, tenant)
			return err
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("workspace %s: %w", tenant, strandBusy(err)))
			continue
		}
		out = append(out, ended...)
	}
	if err := errors.Join(errs...); err != nil {
		return out, fmt.Errorf("store: connections without read: %w", err)
	}
	return out, nil
}

// sweepLockTimeout is how long the sweep waits for each lock in a
// workspace before it gives that workspace up.
var sweepLockTimeout = 5 * time.Second

// endConnectionsWithoutReadTx is EndConnectionsWithoutRead in one
// workspace's transaction.
func endConnectionsWithoutReadTx(ctx context.Context, tx pgx.Tx, tenant uuid.UUID) ([]EndedConnection, error) {
	if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', $1, true)`,
		strconv.FormatInt(sweepLockTimeout.Milliseconds(), 10)+"ms"); err != nil {
		return nil, err
	}
	if err := lockWorkspaceAccess(ctx, tx, tenant); err != nil {
		return nil, err
	}
	// held is every number a live connection holds. A person reads it, or
	// waits for its new key, with the Read flag and a grant at its current
	// epoch or an earlier one, that key not retired.
	rows, err := tx.Query(ctx, `WITH live AS (
			SELECT id, api_key_id, service_user_id, created_by FROM mcp_connections
			 WHERE tenant_id = $1 AND status IN ('pending', 'active', 'reseal')),
		held AS (
			SELECT c.id, c.created_by, x.device_id FROM live c JOIN api_key_devices x ON x.api_key_id = c.api_key_id
			UNION
			SELECT c.id, c.created_by, g.device_id FROM live c
			  JOIN device_key_grants g ON g.tenant_id = $1 AND g.user_id = c.service_user_id
			UNION
			SELECT c.id, c.created_by, p.device_id FROM live c
			  JOIN device_permissions p ON p.tenant_id = $1 AND p.user_id = c.service_user_id)
		SELECT c.id::text, c.reader FROM mcp_connections c
		 WHERE c.id IN (SELECT h.id FROM held h WHERE NOT EXISTS (SELECT 1 FROM device_permissions p
				JOIN devices d ON d.id = p.device_id AND d.tenant_id = p.tenant_id AND d.deleted_at IS NULL
				JOIN device_key_grants g ON g.tenant_id = p.tenant_id AND g.device_id = p.device_id AND g.user_id = p.user_id
				     AND g.epoch <= d.current_epoch
				JOIN device_archive_keys k ON k.device_id = g.device_id AND k.epoch = g.epoch AND k.retired_at IS NULL
				WHERE p.tenant_id = $1 AND p.user_id = h.created_by AND p.device_id = h.device_id AND p.can_read))
		 ORDER BY c.id FOR UPDATE OF c`, tenant)
	if err != nil {
		return nil, err
	}
	unread, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (EndedConnection, error) {
		var c EndedConnection
		err := row.Scan(&c.ID, &c.Reader)
		return c, err
	})
	if err != nil {
		return nil, err
	}
	var ended []EndedConnection
	for _, c := range unread {
		// Live when picked, under the workspace's lock: always ended here.
		did, err := endMCPConnectionTx(ctx, tx, tenant, c.ID, statusRevoked, ReasonAccessLost)
		if err != nil {
			return nil, err
		}
		if did {
			ended = append(ended, c)
		}
	}
	return ended, nil
}
