package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/pg"
)

// What the freshness hook reads (README 7.1; the plan's 4.9 and 4.12):
// each party's stored freshness and account status, which of an act's
// parties are service identities (never platform members, so never
// gated), and the people a narrowing act leaves holding a number's key.

// BackupFreshFor is how fresh a remaining key holder's document must be
// for an act that narrows who holds a number's key to count them as a
// backup without a GET (README 7.1: "when the app's last trusted
// published_through is over a minute old, it first sends GET for the
// remaining holders").
const BackupFreshFor = time.Minute

// ContractStanding is one sub's freshness and its stored document's
// account status (active, disabled or closed; empty with no document).
type ContractStanding struct {
	Fresh  bool
	Status string
}

// Standing is Fresh with each sub's stored account status: one query, on
// the database's clock. An unknown sub is stale, with no status.
func (c *Contract) Standing(ctx context.Context, d time.Duration, subs ...uuid.UUID) (map[uuid.UUID]ContractStanding, error) {
	out := make(map[uuid.UUID]ContractStanding, len(subs))
	if len(subs) == 0 {
		return out, nil
	}
	rows, err := c.pool.Query(ctx, `SELECT q.sub, coalesce(greatest(a.fresh_at,
			CASE WHEN a.version IS NOT NULL AND a.generation = s.generation
			      AND s.published_through <= clock_timestamp() + $3::interval THEN s.published_through END)
			> clock_timestamp() - $2::interval, false), coalesce(a.status, '')
		FROM unnest($1::uuid[]) AS q(sub)
		CROSS JOIN contract_state s
		LEFT JOIN contract_accounts a ON a.sub = q.sub`, subs, d, ContractClockSkew)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var sub uuid.UUID
		var st ContractStanding
		if err := rows.Scan(&sub, &st.Fresh, &st.Status); err != nil {
			return nil, err
		}
		out[sub] = st
	}
	return out, rows.Err()
}

// Services says which of users are service identities in tenant: a
// standing service account (role service), a membership with a deadline
// (a consent's provisional account), or the account a connection names.
// They have no sub and are never platform members (design 2.7), so an act
// never waits on their freshness.
func (c *Contract) Services(ctx context.Context, tenant uuid.UUID, users ...uuid.UUID) (map[uuid.UUID]bool, error) {
	out := map[uuid.UUID]bool{}
	if len(users) == 0 {
		return out, nil
	}
	err := pg.InTenantTx(ctx, c.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT q.user_id FROM unnest($2::uuid[]) AS q(user_id)
			WHERE EXISTS (SELECT 1 FROM workspace_memberships m WHERE m.tenant_id = $1 AND m.user_id = q.user_id
			               AND (m.role = 'service' OR m.expires_at IS NOT NULL))
			   OR EXISTS (SELECT 1 FROM mcp_connections c WHERE c.service_user_id = q.user_id)`, tenant, users)
		if err != nil {
			return err
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		for _, id := range ids {
			out[id] = true
		}
		return err
	})
	return out, err
}

// KeyHolders are the people tenant's device keeps as backups once losing
// no longer holds its key: the backup side of sole_key_holders (0051) at
// any epoch not retired, an active, unexpired member and an active person
// with Read and the key, never a connection's service account; losing
// excluded, in id order. A narrowing act asks the platform for their
// documents when they are not fresh within BackupFreshFor (README 7.1).
func (c *Contract) KeyHolders(ctx context.Context, tenant, device, losing uuid.UUID) ([]uuid.UUID, error) {
	var out []uuid.UUID
	err := pg.InTenantTx(ctx, c.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT DISTINCT g.user_id
			FROM device_key_grants g
			JOIN device_archive_keys k ON k.device_id = g.device_id AND k.epoch = g.epoch AND k.retired_at IS NULL
			JOIN workspace_memberships m ON m.tenant_id = g.tenant_id AND m.user_id = g.user_id AND m.status = 'active' AND m.expires_at IS NULL
			JOIN users u ON u.id = m.user_id AND u.status = 'active'
			JOIN device_permissions p ON p.tenant_id = g.tenant_id AND p.device_id = g.device_id AND p.user_id = g.user_id AND p.can_read
			WHERE g.tenant_id = $1 AND g.device_id = $2 AND g.user_id <> $3
			  AND NOT EXISTS (SELECT 1 FROM mcp_connections c WHERE c.service_user_id = g.user_id)
			ORDER BY g.user_id`, tenant, device, losing)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		return err
	})
	return out, err
}
