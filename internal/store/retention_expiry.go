package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
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
// revoked and, because Create already promoted its key to the full lifetime,
// the key is revoked with it. An active connection past its deadline is
// marked expired; its key carries the same deadline and ExpireAPIKeys takes
// care of that half.
func ExpireMCPConnections(ctx context.Context, pool *pgxpool.Pool, pendingTTL time.Duration) (int64, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("store: expire mcp connections: %w", err)
	}
	//nolint:errcheck // deferred rollback is a no-op once committed
	defer func() { _ = tx.Rollback(ctx) }()

	// One statement for both halves, so the count of keys revoked cannot
	// drift from the count of connections that lost them.
	var stale, expired int64
	err = tx.QueryRow(ctx, `
		WITH stale AS (
			UPDATE mcp_connections SET status = 'revoked', revoked_at = now()
			 WHERE status = 'pending' AND created_at < $1
			 RETURNING api_key_id
		), keys AS (
			UPDATE api_keys SET revoked_at = now()
			 WHERE id IN (SELECT api_key_id FROM stale) AND revoked_at IS NULL
		), done AS (
			UPDATE mcp_connections SET status = 'expired'
			 WHERE status = 'active' AND expires_at <= now()
			 RETURNING id
		)
		SELECT (SELECT count(*) FROM stale), (SELECT count(*) FROM done)`,
		time.Now().Add(-pendingTTL)).Scan(&stale, &expired)
	if err != nil {
		return 0, fmt.Errorf("store: expire mcp connections: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("store: expire mcp connections: %w", err)
	}
	return stale + expired, nil
}
