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

// Ended API keys go 13 months after their end (step 7's plan, 7.6; the
// owner's yes of 2026-11-04), on every installation, whatever their class
// or origin: an ended key serves nothing after that. A key's end is the
// earlier of its revocation and its expiry (ExpireAPIKeys records an
// expiry as revoked_at, but a person may revoke an expired key before that
// pass runs); a key with neither never goes. What hangs off a key goes
// with it through its foreign keys, all ON DELETE CASCADE: its numbers
// (api_key_devices) and its MCP connection, with the connection's own rows
// (mcp_send_chats, mcp_outbound, ai_usage_daily, mcp_connection_seen,
// mcp_connection_notices, mcp_revoke_links). An AI integration's derived
// rows stay, with authorization_id NULL, which the pass sets first. The
// service account a key acted as is not the key's (acts_as points from
// the key), nor is a content connection's.

// apiKeyKeep is how long an ended key is kept after its end, in
// PostgreSQL's months.
const apiKeyKeep = `interval '13 months'`

// endedKey is a key (k) whose end is apiKeyKeep before cut, the pass's
// parameter.
func endedKey(cut string) string {
	return `least(k.revoked_at, k.expires_at) + ` + apiKeyKeep + ` <= ` + cut
}

// liveConnectionSQL is a key whose MCP connection has not ended. A key and
// its connection end together, so this belt should hold nothing.
const liveConnectionSQL = `EXISTS (SELECT 1 FROM mcp_connections c WHERE c.api_key_id = k.id AND c.status IN ('pending', 'active', 'reseal'))`

// APIKeyRetention is what RetainAPIKeys did.
type APIKeyRetention struct {
	// Deleted counts the keys deleted, by origin ("" for a key an older
	// binary issued after 0053, which has none).
	Deleted map[string]int64
	// Held counts the keys past their 13 months kept because their
	// connection has not ended.
	Held int64
	// Reports counts the retirement reports whose per-key entries went.
	Reports int64
}

// RetainAPIKeys is the hourly deletion of ended keys (maintainOnce, right
// after ExpireAPIKeys), whatever the token mode, on Wappie's clock now and
// on the database's: a key goes once both say its end is 13 months past.
// It lists the workspaces from api_keys alone, then, one workspace at a
// time, in pg.InTenantTx under its row lock (lockWorkspaceAccess, DB25
// step 3), deletes their keys in one statement, retried on a deadlock. One
// workspace failing never stops the rest: their errors come back joined,
// with what the others did. Then a retirement's report loses its per-key
// entries 13 months after its apply, when the keys it revoked have gone;
// its counts and the services it kept stay.
func RetainAPIKeys(ctx context.Context, pool *pgxpool.Pool, now time.Time) (APIKeyRetention, error) {
	out := APIKeyRetention{Deleted: map[string]int64{}}
	var cut time.Time
	if err := pool.QueryRow(ctx, `SELECT least($1::timestamptz, clock_timestamp())`, now).Scan(&cut); err != nil {
		return out, fmt.Errorf("store: api key retention: %w", err)
	}
	rows, err := pool.Query(ctx, `SELECT DISTINCT k.tenant_id FROM api_keys k WHERE `+endedKey("$1")+` ORDER BY k.tenant_id`, cut)
	if err != nil {
		return out, fmt.Errorf("store: api key retention: %w", err)
	}
	workspaces, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return out, fmt.Errorf("store: api key retention: %w", err)
	}
	var errs []error
	for _, ws := range workspaces {
		var held int64
		deleted := map[string]int64{}
		err := retryDeadlock(ctx, func() error {
			held, deleted = 0, map[string]int64{}
			return pg.InTenantTx(ctx, pool, ws.String(), func(tx pgx.Tx) error {
				if err := lockWorkspaceAccess(ctx, tx, ws); err != nil {
					return err
				}
				if err := tx.QueryRow(ctx, `SELECT count(*) FROM api_keys k WHERE k.tenant_id = $1 AND `+endedKey("$2")+` AND `+liveConnectionSQL,
					ws, cut).Scan(&held); err != nil {
					return err
				}
				// The derived rows the cascade would set NULL, first, with
				// the excluded numbers in sight: the cascade's update runs
				// archive_device_owner, which would not find a deleted
				// number's row and refuse the whole delete. A moved-out
				// number's rows left with it, already NULL.
				if err := withQuarantine(ctx, tx, func() error {
					_, err := tx.Exec(ctx, `UPDATE ai_derived SET authorization_id = NULL WHERE authorization_id IN (
						SELECT c.id FROM mcp_connections c JOIN api_keys k ON k.id = c.api_key_id
						WHERE k.tenant_id = $1 AND `+endedKey("$2")+` AND NOT `+liveConnectionSQL+`)`, ws, cut)
					return err
				}); err != nil {
					return err
				}
				rows, err := tx.Query(ctx, `DELETE FROM api_keys k WHERE k.tenant_id = $1 AND `+endedKey("$2")+` AND NOT `+liveConnectionSQL+`
					RETURNING coalesce(k.origin, '')`, ws, cut)
				if err != nil {
					return err
				}
				return forEachRow(rows, func(r pgx.Rows) error {
					var origin string
					if err := r.Scan(&origin); err != nil {
						return err
					}
					deleted[origin]++
					return nil
				})
			})
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("store: api key retention in workspace %s: %w", ws, err))
			continue
		}
		out.Held += held
		for origin, n := range deleted {
			out.Deleted[origin] += n
		}
	}
	tag, err := pool.Exec(ctx, `UPDATE key_retirements SET report = report - 'keys'
		WHERE applied_at + `+apiKeyKeep+` <= $1 AND report ? 'keys'`, cut)
	if err != nil {
		errs = append(errs, fmt.Errorf("store: api key retention of the retirement reports: %w", err))
	} else {
		out.Reports = tag.RowsAffected()
	}
	return out, errors.Join(errs...)
}
