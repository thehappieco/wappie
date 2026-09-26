package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/pg"
)

// ExpireAPIKeys revokes every live key whose deadline has passed and reports
// how many.
//
// The lookup already refuses such a key; this records the fact, so the key
// list shows it revoked at the moment it expired rather than looking live
// with a date in the past. Keys without a deadline are not touched.
func ExpireAPIKeys(ctx context.Context, pool *pgxpool.Pool) (int64, error) {
	tag, err := pool.Exec(ctx, `
		UPDATE api_keys SET revoked_at = expires_at
		 WHERE expires_at < now() AND revoked_at IS NULL`)
	if err != nil {
		return 0, fmt.Errorf("store: expire api keys: %w", err)
	}
	return tag.RowsAffected(), nil
}

// ExpireMCPConnections settles the connections whose time is up and reports
// how many it touched.
//
// A pending connection older than pendingTTL is a consent whose handshake
// never completed: the reader has forgotten the request by now, so the row is
// revoked (pending_expired). A live connection past its deadline is marked
// expired. Either way the connection ends through the one helper, one row at
// a time in its own workspace's transaction: its key goes with it and, for
// content, its service account's grants, permissions and membership, which
// force row-level security and could not be reached from here otherwise.
func ExpireMCPConnections(ctx context.Context, pool *pgxpool.Pool, pendingTTL time.Duration) (int64, error) {
	// The ledger carries no policy, so the candidates are found across
	// every workspace in one read.
	rows, err := pool.Query(ctx, `
		SELECT id::text, tenant_id, status = 'pending' AND created_at < $1 FROM mcp_connections
		 WHERE (status = 'pending' AND created_at < $1)
		    OR (status IN ('active','reseal') AND expires_at <= now())
		 ORDER BY id`, time.Now().Add(-pendingTTL))
	if err != nil {
		return 0, fmt.Errorf("store: expire mcp connections: %w", err)
	}
	type candidate struct {
		id     string
		tenant uuid.UUID
		stale  bool
	}
	var candidates []candidate
	for rows.Next() {
		var c candidate
		if err := rows.Scan(&c.id, &c.tenant, &c.stale); err != nil {
			rows.Close()
			return 0, fmt.Errorf("store: expire mcp connections: %w", err)
		}
		candidates = append(candidates, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("store: expire mcp connections: %w", err)
	}
	m := NewMCPConnections(pool)
	var n int64
	var errs []error
	for _, c := range candidates {
		status, reason := statusExpired, ReasonExpired
		if c.stale {
			status, reason = statusRevoked, ReasonPendingExpired
		}
		// One row failing must not keep the rest alive.
		if err := m.endInTenant(ctx, c.tenant, c.id, status, reason, false); err != nil {
			errs = append(errs, err)
			continue
		}
		n++
	}
	if err := errors.Join(errs...); err != nil {
		return n, fmt.Errorf("store: expire mcp connections: %w", err)
	}
	return n, nil
}

// ExpireServiceAccounts removes the connection service accounts whose
// deadline has passed and that no live connection names: a content consent
// abandoned between registering the account and recording the connection.
// Each goes through removeServiceAccountTx in its workspace's transaction,
// with its keys, grants, permissions and membership. It reports how many.
//
// A provisional account can only come from a provisional invitation, and a
// connection's from a content row, so those name every workspace that can
// hold one; memberships force row-level security and are read per workspace.
func ExpireServiceAccounts(ctx context.Context, pool *pgxpool.Pool) (int64, error) {
	rows, err := pool.Query(ctx, `
		SELECT tenant_id FROM invites WHERE provisional
		UNION SELECT tenant_id FROM mcp_connections WHERE kind = 'content'`)
	if err != nil {
		return 0, fmt.Errorf("store: expire service accounts: %w", err)
	}
	var tenants []uuid.UUID
	for rows.Next() {
		var tenant uuid.UUID
		if err := rows.Scan(&tenant); err != nil {
			rows.Close()
			return 0, fmt.Errorf("store: expire service accounts: %w", err)
		}
		tenants = append(tenants, tenant)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("store: expire service accounts: %w", err)
	}
	var n int64
	var errs []error
	for _, tenant := range tenants {
		removed := 0
		err := pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
			if err := lockWorkspaceAccess(ctx, tx, tenant); err != nil {
				return err
			}
			rows, err := tx.Query(ctx, `SELECT m.user_id FROM workspace_memberships m
				WHERE m.tenant_id=$1 AND m.role='service' AND m.expires_at IS NOT NULL AND m.expires_at <= now()
				  AND NOT EXISTS(SELECT 1 FROM mcp_connections c
				                  WHERE c.service_user_id=m.user_id AND c.status IN ('pending','active','reseal'))
				ORDER BY m.user_id`, tenant)
			if err != nil {
				return err
			}
			var services []uuid.UUID
			for rows.Next() {
				var service uuid.UUID
				if err := rows.Scan(&service); err != nil {
					rows.Close()
					return err
				}
				services = append(services, service)
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
			for _, service := range services {
				if err := removeServiceAccountTx(ctx, tx, tenant, service); err != nil {
					return err
				}
			}
			removed = len(services)
			return nil
		})
		if err != nil {
			errs = append(errs, err)
			continue
		}
		n += int64(removed)
	}
	if err := errors.Join(errs...); err != nil {
		return n, fmt.Errorf("store: expire service accounts: %w", err)
	}
	return n, nil
}
