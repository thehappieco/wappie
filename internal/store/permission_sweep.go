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

// The check at every start (DS48, the platform's answer on F4's wiring):
// the live connections whose person no longer reads one of their numbers,
// or whose own account no longer reads a number its key names, end, whole
// and access_lost, as a lost Read ends them since F3 and F4. The first
// pass after the upgrade ends what the rules before left behind: a
// metadata consent that asked no Read, a content connection or an AI
// integration whose person lost Read before F3, any connection whose
// person lost their grant through a grant.revoke before F4, and a content
// connection or an AI integration narrowed by a grant.revoke or a PUT on
// its own account before F4. After that first pass it is an invariant
// check: an end then means an older binary served a reset, a lone revoke
// or such a narrowing, or a path missed one.

// SweptConnection is a connection the check ended, in its workspace.
type SweptConnection struct {
	EndedConnection
	Tenant uuid.UUID
	// Keyless are numbers it held that have no archive key at all (epoch
	// 0): reset-archive -keep-devices, a pairing cut off between the row and
	// its key, or a row older than 0009. Their remedy is device-key.
	Keyless []uuid.UUID
	// Orphan are numbers it held that have a key and no grant to anyone
	// but a connection's account or an account whose membership carries a
	// deadline, a consent's (wsctl pair -orphan, or device-key with no
	// account). Their remedy is a grant sealed with the printed key, or
	// the number deleted and paired again with -grant. Those accounts
	// never count: their copies are sealed to keys that live only in a
	// reader, as KeyHolders leaves them out.
	Orphan []uuid.UUID
	// Narrowed are numbers its key names that its person reads and its
	// own account (content, AI) no longer does: a grant.revoke or a PUT on
	// that account before F4 narrowed it. Its person consents again.
	Narrowed []uuid.UUID
}

// ReadCheck is what one pass of EndConnectionsWithoutRead did.
type ReadCheck struct {
	Ended []SweptConnection
	// Busy are the workspaces whose lock the pass did not get within
	// sweepLockTimeout. Nothing changed there; the next start checks them.
	Busy []uuid.UUID
}

// EndConnectionsWithoutRead ends, whole and access_lost, every live
// connection of every kind (metadata, content, an AI integration; pending,
// active or reseal) whose person does not read one of the numbers it holds.
// It holds a number as leaveOwnConnectionsTx counts it: its key's row, or
// its service account's permission or grant on it. Reading a number is
// what consenterReadsTx asks of a consent: the Read flag and a grant at the
// number's current epoch, its key not retired, the number not deleted. A
// number with no archive key at its current epoch, or with a key nobody
// holds, is read by nobody, so its connections end. A content connection
// or an AI integration also ends when its own account (service_user_id)
// does not read, by the same rule, a number its key names: it was
// narrowed, the state 0061 removes, and a revoke or a PUT on that account
// now ends it whole instead (DS48).
//
// A rotation does not count (0061). A person waits for a number's new key,
// and is passed over for it, when they keep the Read flag and hold a grant
// at an earlier epoch of the number whose key is not retired, and none at
// the current one: the rotation is not finished for them. Once that old
// key is retired, or their old grant is gone, they no longer wait. No code
// rotates or retires a key yet.
//
// It locks nothing in the steady state. Each workspace's candidates are
// read first without its lock: the tenants row is also ingest's sequence
// lock (nextSeq), and the check runs while a start's history work ingests.
// Only a workspace with a candidate is locked: one transaction under its
// tenants row, waiting at most sweepLockTimeout for each lock, the
// candidates read again and ended in id order, each through
// endMCPConnectionTx, as a revoke ends it. A busy workspace is left as it
// was and named in Busy; one that fails otherwise is named in the error.
// Neither keeps the others. What it ended comes back also when a workspace
// failed, for the readers to be told after the commits (WatchRevocations
// tells them in any case).
func EndConnectionsWithoutRead(ctx context.Context, pool *pgxpool.Pool) (ReadCheck, error) {
	// The ledger carries no policy: the workspaces with a live connection
	// are found in one read.
	rows, err := pool.Query(ctx, `SELECT DISTINCT tenant_id FROM mcp_connections
		WHERE status IN ('pending', 'active', 'reseal') ORDER BY tenant_id`)
	if err != nil {
		return ReadCheck{}, fmt.Errorf("store: connections without read: %w", err)
	}
	tenants, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return ReadCheck{}, fmt.Errorf("store: connections without read: %w", err)
	}
	var out ReadCheck
	var errs []error
	for _, tenant := range tenants {
		var candidates bool
		err := pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, unreadHeld+`SELECT EXISTS (SELECT 1 FROM candidates)`, tenant).Scan(&candidates)
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("workspace %s: %w", tenant, err))
			continue
		}
		if !candidates {
			continue
		}
		var ended []SweptConnection
		err = pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
			var err error
			ended, err = endConnectionsWithoutReadTx(ctx, tx, tenant)
			return err
		})
		if errors.Is(strandBusy(err), ErrWorkspaceBusy) {
			out.Busy = append(out.Busy, tenant)
			continue
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("workspace %s: %w", tenant, err))
			continue
		}
		out.Ended = append(out.Ended, ended...)
	}
	if err := errors.Join(errs...); err != nil {
		return out, fmt.Errorf("store: connections without read: %w", err)
	}
	return out, nil
}

// sweepLockTimeout is how long the check waits for each lock in a
// workspace before it leaves that workspace for the next start.
var sweepLockTimeout = 5 * time.Second

// unreadHeld names the check's candidates in workspace $1: in unread,
// each live connection with each number it holds that its person does not
// read; in narrowed, each live connection with a service account and each
// number its key names that this account does not read; in candidates,
// the connections of both. A person or an account reads a number, or
// waits for its new key, with the Read flag and a grant at its current
// epoch or an earlier one, that key not retired, the number not deleted.
const unreadHeld = `WITH live AS (
		SELECT id, api_key_id, service_user_id, created_by FROM mcp_connections
		 WHERE tenant_id = $1 AND status IN ('pending', 'active', 'reseal')),
	held AS (
		SELECT c.id, c.created_by, x.device_id FROM live c JOIN api_key_devices x ON x.api_key_id = c.api_key_id
		UNION
		SELECT c.id, c.created_by, g.device_id FROM live c
		  JOIN device_key_grants g ON g.tenant_id = $1 AND g.user_id = c.service_user_id
		UNION
		SELECT c.id, c.created_by, p.device_id FROM live c
		  JOIN device_permissions p ON p.tenant_id = $1 AND p.user_id = c.service_user_id),
	reads AS NOT MATERIALIZED (
		SELECT p.user_id, p.device_id FROM device_permissions p
		  JOIN devices d ON d.id = p.device_id AND d.tenant_id = p.tenant_id AND d.deleted_at IS NULL
		  JOIN device_key_grants g ON g.tenant_id = p.tenant_id AND g.device_id = p.device_id AND g.user_id = p.user_id
		       AND g.epoch <= d.current_epoch
		  JOIN device_archive_keys k ON k.device_id = g.device_id AND k.epoch = g.epoch AND k.retired_at IS NULL
		 WHERE p.tenant_id = $1 AND p.can_read),
	unread AS (
		SELECT h.id, h.device_id FROM held h
		 WHERE NOT EXISTS (SELECT 1 FROM reads r WHERE r.user_id = h.created_by AND r.device_id = h.device_id)),
	narrowed AS (
		SELECT c.id, x.device_id FROM live c JOIN api_key_devices x ON x.api_key_id = c.api_key_id
		 WHERE c.service_user_id IS NOT NULL
		   AND NOT EXISTS (SELECT 1 FROM reads r WHERE r.user_id = c.service_user_id AND r.device_id = x.device_id)),
	candidates AS (SELECT id FROM unread UNION SELECT id FROM narrowed)
	`

// endConnectionsWithoutReadTx is EndConnectionsWithoutRead in one
// workspace's transaction, once its candidates were found without a lock.
func endConnectionsWithoutReadTx(ctx context.Context, tx pgx.Tx, tenant uuid.UUID) ([]SweptConnection, error) {
	if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', $1, true)`,
		strconv.FormatInt(sweepLockTimeout.Milliseconds(), 10)+"ms"); err != nil {
		return nil, err
	}
	if err := lockWorkspaceAccess(ctx, tx, tenant); err != nil {
		return nil, err
	}
	// Read again under the lock: a revoke or a drop may have ended some
	// since, and a consent may have added none (it needs Read).
	rows, err := tx.Query(ctx, unreadHeld+`SELECT c.id::text, c.reader FROM mcp_connections c
		 WHERE c.id IN (SELECT id FROM candidates) ORDER BY c.id FOR UPDATE OF c`, tenant)
	if err != nil {
		return nil, err
	}
	picked, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (SweptConnection, error) {
		c := SweptConnection{Tenant: tenant}
		err := row.Scan(&c.ID, &c.Reader)
		return c, err
	})
	if err != nil || len(picked) == 0 {
		return nil, err
	}
	// Why, for the remedy the log names: a number nobody reads, with no
	// key (epoch 0) or with a key and no grant to anyone but a
	// connection's or a consent's account (Orphan); and a number its
	// person reads and its own account no longer does.
	rows, err = tx.Query(ctx, unreadHeld+`SELECT u.id::text, u.device_id, CASE WHEN d.current_epoch = 0 THEN 'keyless' ELSE 'orphan' END
		FROM unread u JOIN devices d ON d.id = u.device_id AND d.tenant_id = $1 AND d.deleted_at IS NULL
		WHERE d.current_epoch = 0 OR NOT EXISTS (SELECT 1 FROM device_key_grants g WHERE g.tenant_id = $1 AND g.device_id = d.id
			AND NOT EXISTS (SELECT 1 FROM mcp_connections c WHERE c.tenant_id = $1 AND c.service_user_id = g.user_id)
			AND NOT EXISTS (SELECT 1 FROM workspace_memberships m WHERE m.tenant_id = $1 AND m.user_id = g.user_id AND m.expires_at IS NOT NULL))
		UNION ALL
		SELECT n.id::text, n.device_id, 'narrowed' FROM narrowed n
		 WHERE NOT EXISTS (SELECT 1 FROM unread u WHERE u.id = n.id AND u.device_id = n.device_id)
		ORDER BY 1, 2`, tenant)
	if err != nil {
		return nil, err
	}
	type why struct {
		id     string
		device uuid.UUID
		kind   string
	}
	whys, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (why, error) {
		var n why
		err := row.Scan(&n.id, &n.device, &n.kind)
		return n, err
	})
	if err != nil {
		return nil, err
	}
	var ended []SweptConnection
	for _, c := range picked {
		// Live when picked, under the workspace's lock: always ended here.
		did, err := endMCPConnectionTx(ctx, tx, tenant, c.ID, statusRevoked, ReasonAccessLost)
		if err != nil {
			return nil, err
		}
		if !did {
			continue
		}
		for _, n := range whys {
			switch {
			case n.id != c.ID:
			case n.kind == "keyless":
				c.Keyless = append(c.Keyless, n.device)
			case n.kind == "orphan":
				c.Orphan = append(c.Orphan, n.device)
			default:
				c.Narrowed = append(c.Narrowed, n.device)
			}
		}
		ended = append(ended, c)
	}
	return ended, nil
}
