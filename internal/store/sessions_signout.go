package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// signOutFamiliesBeforeTx ends user's session families begun before
// before (the spec's 14.7 for person.sign_out_everywhere; the plan's 6.5,
// DS11): a family's first row older than before, observe's family rule
// (contract_observe.go), every row of it revoked, its per-workspace
// sessions included, whatever their own age; a family begun at or after
// before, and every credential that is no session (API keys, keys acting
// as the person, MCP connections, AI integrations), stays. It locks as
// endSession does, the passkey registration lock first, which every
// session's start takes too, so no family begins while it runs, then each
// family in id order. It returns the live rows it ended, as endSession
// counts them: rows that had expired unrevoked are revoked with their
// family and not counted. A second run ends nothing new and counts 0.
func signOutFamiliesBeforeTx(ctx context.Context, tx pgx.Tx, user uuid.UUID, before time.Time) (int64, error) {
	if err := lockPasskeyRegistration(ctx, tx, user); err != nil {
		return 0, err
	}
	rows, err := tx.Query(ctx, `SELECT family_id FROM sessions WHERE user_id = $1
		GROUP BY family_id HAVING min(created_at) < $2 AND bool_or(revoked_at IS NULL) ORDER BY family_id`, user, before)
	if err != nil {
		return 0, err
	}
	families, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil || len(families) == 0 {
		return 0, err
	}
	for _, f := range families {
		if err := lockSessionFamily(ctx, tx, f); err != nil {
			return 0, err
		}
	}
	var ended int64
	err = tx.QueryRow(ctx, `WITH ended AS (
			UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND family_id = ANY ($2) AND revoked_at IS NULL RETURNING expires_at)
		SELECT count(*) FILTER (WHERE expires_at > clock_timestamp()) FROM ended`, user, families).Scan(&ended)
	return ended, err
}
