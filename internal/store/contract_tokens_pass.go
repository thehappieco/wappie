package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/pg"
)

// A reset of the token feed (the plan's 4.2, "Restart extended", and the
// design's 3.3): one generation resets every feed, in Restart's transaction,
// and the new generation's records never widen what Wappie held. The pass
// from 0 lists every token the platform still has; once it is done (a page
// with more false after the round ran in the new generation), a token it did
// not list is unlisted, for good.

// tokenWorkspacesTx are the workspaces that hold tokens, in id order: those
// a selector names (contract_token_selectors carries no row-level security)
// and Wappie still has.
func tokenWorkspacesTx(ctx context.Context, tx pgx.Tx) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT s.tenant_id FROM contract_token_selectors s JOIN tenants t ON t.id = s.tenant_id ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

// selectorWorkspacesTx are the workspaces a selector names, in id order,
// those Wappie no longer has included: retention's, which outlives a
// workspace's token rows (its pins and removed instances carry no foreign
// key).
func selectorWorkspacesTx(ctx context.Context, tx pgx.Tx) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT tenant_id FROM contract_token_selectors ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

// restartTokensTx is a restart's token part, in tx, which holds
// contract_state's and contract_token_state's locks: the cursor goes to 0
// and published_through away, the last trusted one kept as
// reset_trusted_through (3.3's granted_at rule); the pass of gen starts.
// caught_up_at stays: tokens keep working within their narrowest state until
// the pass. Every token forgets its version, generation and listing; what
// was held is recorded per workspace (H7): every applied perm is held at the
// reset, and every pending one, never effective, goes with a removed row
// (reset); waiting perms stay waiting. The sticky set, the earliest expiries,
// the removed instances, the pins and the stops stay; a refused perm stays
// refused, and is told again when the new generation lists it. A pending
// Read holds no grant to delete with it: a grant is written only under an
// applied Read, an applied one never goes back to pending, and a Read given
// again as another instance takes its grants in that write (judgeRecord);
// so the reset writes no device_key_grants row, which would lock the
// workspace's row under the token rows (DB25).
func restartTokensTx(ctx context.Context, tx pgx.Tx, gen *uuid.UUID) error {
	// The acknowledgement starts again too: the new generation is told
	// every set whole, and none of the old one's refusals, whose versions
	// it never published, nor its held tokens unsent (the acknowledgement
	// sends only the current generation's), which the new pass queues
	// again, every token's version cleared below, for what is still held.
	if _, err := tx.Exec(ctx, `UPDATE contract_token_state SET feed_cursor = 0,
		reset_trusted_through = coalesce(published_through, reset_trusted_through), published_through = NULL,
		pass_generation = $1, pass_ready_at = NULL, pass_done_at = NULL,
		ack_through = 0, waiting_sent_hash = NULL, suspended_sent_hash = NULL`, gen); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM contract_token_refusals_out WHERE sent_at IS NULL`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM contract_token_held_out WHERE sent_at IS NULL AND generation IS DISTINCT FROM $1`, gen); err != nil {
		return err
	}
	workspaces, err := tokenWorkspacesTx(ctx, tx)
	if err != nil {
		return err
	}
	for _, ws := range workspaces {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, ws.String()); err != nil {
			return err
		}
		// The workspace's token rows in id order, then their perms (DB25
		// steps 4 and 5).
		if _, err := tx.Exec(ctx, `UPDATE contract_tokens t SET generation = NULL, version = NULL, listed_gen = NULL
			FROM (SELECT id FROM contract_tokens ORDER BY id FOR UPDATE) l WHERE t.id = l.id`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT 1 FROM contract_token_perms ORDER BY token_id, device_id, perm FOR UPDATE`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE contract_token_perms SET held_at_reset = true WHERE state = 'applied'`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `WITH gone AS (DELETE FROM contract_token_perms WHERE state = 'pending'
				RETURNING token_id, tenant_id, device_id, perm, granted_at)
			INSERT INTO contract_token_removed (token_id, tenant_id, item, perm, granted_at, cause)
			SELECT token_id, tenant_id, device_id::text, perm, granted_at, 'reset' FROM gone
			ON CONFLICT DO NOTHING`); err != nil {
			return err
		}
	}
	_, err = tx.Exec(ctx, `SELECT set_config('app.tenant_id', '', true)`)
	return err
}

// TokenPassResult is what finishing a reset's pass did.
type TokenPassResult struct {
	// Done: the pass of the generation was finished now; false when it was
	// not the pass in progress, or not ready.
	Done bool
	// Unlisted are the tokens the pass did not list, now refused for good.
	Unlisted []uuid.UUID
}

// FinishTokenPass ends the pass of gen (the plan's 4.2), only after a page
// with more false committed while the round ran in gen (pass_ready_at,
// CommitTokenPage's PassReady): counting it done earlier would refuse
// tokens the round has not reached. Every token the pass did not list gets
// unlisted_at and a sticky row (unlisted): refused, with its narrowest state
// kept, never revived. Its end is the pass, or its expiry if that passed
// before, and its content (its record, name, terms, perms and removed
// instances) goes at once, with what the acknowledgement and the usage
// report hold of it (forgetQueuesTx), as retention forgets one 30 days
// after its end: an unlisting carries no time of its own, so a restore
// whose re-read of the feed runs the pass again would start its 30 days
// again (decision 0056 keeps a record at most 30 days after the platform
// stopped listing it, and lets an app keep less). held_at_reset is
// cleared. now is Wappie's clock.
func (t *Tokens) FinishTokenPass(ctx context.Context, gen uuid.UUID, now time.Time) (TokenPassResult, error) {
	var out TokenPassResult
	err := retryDeadlock(ctx, func() error {
		out = TokenPassResult{}
		return pg.InTx(ctx, t.pool, func(tx pgx.Tx) error {
			var ready bool
			if err := tx.QueryRow(ctx, `SELECT s.pass_generation = $1 AND s.pass_done_at IS NULL AND s.pass_ready_at IS NOT NULL
				FROM (SELECT * FROM contract_token_state FOR UPDATE) s`, gen).Scan(&ready); err != nil {
				return err
			}
			var current, round *uuid.UUID
			if err := tx.QueryRow(ctx, `SELECT generation, round_generation FROM contract_state`).Scan(&current, &round); err != nil {
				return err
			}
			if !ready || current == nil || *current != gen || round == nil || *round != gen {
				return nil
			}
			workspaces, err := tokenWorkspacesTx(ctx, tx)
			if err != nil {
				return err
			}
			// An unlisted token's identity goes, with its grants (DB25
			// step 3 first).
			if err := lockGrantWorkspacesTx(ctx, tx, workspaces, `listed_gen IS DISTINCT FROM $1 AND unlisted_at IS NULL`,
				func(uuid.UUID) []any { return []any{gen} }); err != nil {
				return err
			}
			var sticky []stickyWrite
			for _, ws := range workspaces {
				if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, ws.String()); err != nil {
					return err
				}
				// Its row, then its perms and removed instances, as retention
				// forgets (DB25 steps 4 and 5), then its identity.
				rows, err := tx.Query(ctx, `UPDATE contract_tokens t SET unlisted_at = $2,
						ended_at = coalesce(ended_at, CASE WHEN isfinite(t.expires_at) THEN least(t.expires_at, $2) ELSE $2 END),
						record = NULL, terms = NULL, name = '', forgotten_at = coalesce(forgotten_at, $2)
					FROM (SELECT id FROM contract_tokens WHERE listed_gen IS DISTINCT FROM $1 AND unlisted_at IS NULL ORDER BY id FOR UPDATE) l
					WHERE t.id = l.id RETURNING t.id, t.created_at, t.expires_at`, gen, now)
				if err != nil {
					return err
				}
				var unlisted []uuid.UUID
				err = forEachRow(rows, func(row pgx.Rows) error {
					var s stickyWrite
					var created time.Time
					if err := row.Scan(&s.id, &created, &s.expiresAt); err != nil {
						return err
					}
					s.ended, s.until = "unlisted", created.Add(tokenKeep)
					sticky = append(sticky, s)
					unlisted = append(unlisted, s.id)
					return nil
				})
				if err != nil {
					return err
				}
				if len(unlisted) > 0 {
					if _, err := tx.Exec(ctx, `DELETE FROM contract_token_perms WHERE token_id = ANY ($1)`, unlisted); err != nil {
						return err
					}
					if _, err := tx.Exec(ctx, `DELETE FROM contract_token_removed WHERE token_id = ANY ($1)`, unlisted); err != nil {
						return err
					}
				}
				if err := dropTokenIdentitiesTx(ctx, tx, now, unlisted); err != nil {
					return err
				}
				// What the acknowledgement and the usage report hold of
				// it goes with its content, at this pass, as retention's
				// forget takes it (after the workspace's token rows, perms
				// and removed instances: DB25).
				if _, err := forgetQueuesTx(ctx, tx, ws, false); err != nil {
					return err
				}
				out.Unlisted = append(out.Unlisted, unlisted...)
				if _, err := tx.Exec(ctx, `UPDATE contract_token_perms SET held_at_reset = false WHERE held_at_reset`); err != nil {
					return err
				}
			}
			if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', '', true)`); err != nil {
				return err
			}
			if err := writeStickyTx(ctx, tx, sticky); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE contract_token_state SET pass_done_at = $1`, now); err != nil {
				return err
			}
			out.Done = true
			return nil
		})
	})
	return out, err
}
