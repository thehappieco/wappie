package store

import (
	"context"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/pg"
)

// What the freshness hook reads (README 7.1; the plan's 4.9 and 4.12):
// each party's stored freshness, account status and workspaces, which of an
// act's parties are the workspace's persons (a service identity or someone
// of another workspace is never gated), and the people a narrowing act
// leaves holding a number's key.

// BackupFreshFor is how fresh a remaining key holder's document must be
// for an act that narrows who holds a number's key to count them as a
// backup without a GET (README 7.1: "when the app's last trusted
// published_through is over a minute old, it first sends GET for the
// remaining holders").
const BackupFreshFor = time.Minute

// ContractStanding is one sub's freshness and its stored document's
// account status (active, disabled or closed; empty with no document) and
// workspaces (none with no document).
type ContractStanding struct {
	Fresh      bool
	Status     string
	Workspaces []uuid.UUID
}

// Lists says whether the stored document names workspace.
func (s ContractStanding) Lists(workspace uuid.UUID) bool {
	return slices.Contains(s.Workspaces, workspace)
}

// vouchedThroughSQL is the last trusted published_through as it vouches for
// the sub of row a of contract_accounts, of contract_state s, or NULL: only
// for a sub the platform follows in the stored generation (README 7.1; the
// plan's DB8), and never while it is past the clock by more than $3
// (ContractClockSkew). Standing and Vouched both read it, so one clause
// decides what a page vouches for everywhere.
const vouchedThroughSQL = `CASE WHEN a.version IS NOT NULL AND a.generation = s.generation
	AND s.published_through <= clock_timestamp() + $3::interval THEN s.published_through END`

// Standing says, for each sub, whether it is fresh within d on the
// database's clock, with its stored document's status and workspaces: one
// query. Fresh is the later of its last answer and the last trusted
// published_through, the latter only for a sub the platform follows in the
// stored generation (README 7.1; the plan's DB8), and never while it is past
// the clock by more than ContractClockSkew. An unknown sub is stale, with no
// status.
func (c *Contract) Standing(ctx context.Context, d time.Duration, subs ...uuid.UUID) (map[uuid.UUID]ContractStanding, error) {
	out := make(map[uuid.UUID]ContractStanding, len(subs))
	if len(subs) == 0 {
		return out, nil
	}
	rows, err := c.pool.Query(ctx, `SELECT q.sub, coalesce(greatest(a.fresh_at, `+vouchedThroughSQL+`)
			> clock_timestamp() - $2::interval, false), coalesce(a.status, ''),
			ARRAY(SELECT (w->>'id')::uuid FROM jsonb_array_elements(coalesce(a.doc->'workspaces', '[]')) AS w)
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
		if err := rows.Scan(&sub, &st.Fresh, &st.Status, &st.Workspaces); err != nil {
			return nil, err
		}
		out[sub] = st
	}
	return out, rows.Err()
}

// Persons says which of users are tenant's persons: a membership there,
// whatever its status, that is not a service identity's (role service, a
// deadline, a consent's provisional account; or the account a connection
// names). Only they are an act's parties. A service identity has no sub and
// is never a platform member (design 2.7), and someone of another workspace
// is refused by the act's own store, so an act never waits on, asks for or
// logs either.
func (c *Contract) Persons(ctx context.Context, tenant uuid.UUID, users ...uuid.UUID) (map[uuid.UUID]bool, error) {
	out := map[uuid.UUID]bool{}
	if len(users) == 0 {
		return out, nil
	}
	err := pg.InTenantTx(ctx, c.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT q.user_id FROM unnest($2::uuid[]) AS q(user_id)
			WHERE EXISTS (SELECT 1 FROM workspace_memberships m WHERE m.tenant_id = $1 AND m.user_id = q.user_id
			               AND m.role <> 'service' AND m.expires_at IS NULL)
			  AND NOT EXISTS (SELECT 1 FROM mcp_connections c WHERE c.service_user_id = q.user_id)`, tenant, users)
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
