package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/pg"
)

// What Wappie keeps of a token after its end, and the operator's stops (the
// plan's 4.2, "Retention", and section 8).

// tokenForgetAfter is how long a token's content (its record, name, terms,
// perms and removed instances) is kept after it ended; its selector, sticky
// row and pin stay until its created_at + 365 days, so a record that comes
// back later never revives it.
const tokenForgetAfter = 30 * 24 * time.Hour

// tokenUsageKeep is how long a reported usage row is kept.
const tokenUsageKeep = 48 * time.Hour

// TokenRetention counts what a retention pass did.
type TokenRetention struct {
	Expired, Forgotten, Ended int64
}

// RetainTokens is the hourly retention of the token part (maintainOnce),
// on Wappie's clock now: the expiry janitor first, then what ended 30 days
// ago is forgotten, then what is past its until goes through its guards,
// then the usage rows reported and over 2 days old and the queues' sent
// entries over 30 days old.
func (t *Tokens) RetainTokens(ctx context.Context, now time.Time) (TokenRetention, error) {
	var out TokenRetention
	err := retryDeadlock(ctx, func() error {
		out = TokenRetention{}
		return pg.InTx(ctx, t.pool, func(tx pgx.Tx) error {
			workspaces, err := tokenWorkspacesTx(ctx, tx)
			if err != nil {
				return err
			}
			var sticky []stickyWrite
			for _, ws := range workspaces {
				if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, ws.String()); err != nil {
					return err
				}
				// The expiry janitor: the token's row first (DB25 step 4),
				// then the sticky row.
				rows, err := tx.Query(ctx, `UPDATE contract_tokens t SET ended_at = $1
					FROM (SELECT id FROM contract_tokens WHERE expires_at <= $1 AND ended_at IS NULL ORDER BY id FOR UPDATE) l
					WHERE t.id = l.id RETURNING t.id, t.created_at, t.expires_at`, now)
				if err != nil {
					return err
				}
				err = forEachRow(rows, func(row pgx.Rows) error {
					var s stickyWrite
					var created time.Time
					if err := row.Scan(&s.id, &created, &s.expiresAt); err != nil {
						return err
					}
					s.ended, s.until = "expired", created.Add(tokenKeep)
					sticky = append(sticky, s)
					out.Expired++
					return nil
				})
				if err != nil {
					return err
				}
				// Its content, then its perms and removed instances (DB25
				// steps 4 and 5).
				rows, err = tx.Query(ctx, `UPDATE contract_tokens t SET record = NULL, terms = NULL, name = '', forgotten_at = $1
					FROM (SELECT id FROM contract_tokens WHERE ended_at <= $2 AND forgotten_at IS NULL ORDER BY id FOR UPDATE) l
					WHERE t.id = l.id RETURNING t.id`, now, now.Add(-tokenForgetAfter))
				if err != nil {
					return err
				}
				forgotten, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
				if err != nil {
					return err
				}
				if len(forgotten) > 0 {
					out.Forgotten += int64(len(forgotten))
					if _, err := tx.Exec(ctx, `DELETE FROM contract_token_perms WHERE token_id = ANY ($1)`, forgotten); err != nil {
						return err
					}
					if _, err := tx.Exec(ctx, `DELETE FROM contract_token_removed WHERE token_id = ANY ($1)`, forgotten); err != nil {
						return err
					}
				}
				// Past until, on both clocks, as the guards check theirs.
				tag, err := tx.Exec(ctx, `DELETE FROM contract_tokens WHERE id IN (
					SELECT token_id FROM contract_token_selectors WHERE until <= $1 AND until <= clock_timestamp())`, now)
				if err != nil {
					return err
				}
				out.Ended += tag.RowsAffected()
				if _, err := tx.Exec(ctx, `DELETE FROM contract_token_pins WHERE until <= $1 AND until <= clock_timestamp()`, now); err != nil {
					return err
				}
			}
			if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', '', true)`); err != nil {
				return err
			}
			if err := writeStickyTx(ctx, tx, sticky); err != nil {
				return err
			}
			for _, q := range []struct {
				sql  string
				args []any
			}{
				// A selector whose token row is gone, its workspace's with it.
				{`DELETE FROM contract_token_selectors s WHERE until <= $1 AND until <= clock_timestamp()
					AND NOT EXISTS (SELECT 1 FROM contract_tokens t WHERE t.id = s.token_id)`, []any{now}},
				{`DELETE FROM contract_token_sticky WHERE until <= $1 AND until <= clock_timestamp()`, []any{now}},
				{`DELETE FROM contract_token_used WHERE reported_at IS NOT NULL AND day < ($1::timestamptz - $2::interval)::date`, []any{now, tokenUsageKeep}},
				{`DELETE FROM contract_token_refusals WHERE reported_count >= count AND day < ($1::timestamptz - $2::interval)::date`, []any{now, tokenUsageKeep}},
				{`DELETE FROM contract_token_refusals_out WHERE sent_at < $1::timestamptz - $2::interval`, []any{now, tokenForgetAfter}},
				{`DELETE FROM contract_token_held_out WHERE sent_at < $1::timestamptz - $2::interval`, []any{now, tokenForgetAfter}},
			} {
				if _, err := tx.Exec(ctx, q.sql, q.args...); err != nil {
					return err
				}
			}
			return nil
		})
	})
	return out, err
}

// TokenStop is one stop of a selector, as tokens list shows it.
type TokenStop struct {
	Selector  string
	Cause     string
	StoppedAt time.Time
	StoppedBy string
	Note      string
	LiftedAt  *time.Time
	// Token is the token id the selector maps to, when Wappie holds one.
	Token *uuid.UUID
}

// ErrSelector is a text that is no token selector.
var ErrSelector = errors.New("store: a token's selector is 16 lowercase hex digits")

// StopToken records the operator's stop of selector (whatserverd tokens
// suspend), even one Wappie holds no record of yet. It writes only to the
// database, so it works with the platform down. A token the selector maps to
// gets its access_version bumped under its row lock (DB25 step 4), so an
// open request's actor no longer matches; the stops' trigger notifies every
// process. The feed and a reset never lift it.
func (t *Tokens) StopToken(ctx context.Context, selector, by, note string, now time.Time) error {
	if !kc.ValidSelector(selector) {
		return ErrSelector
	}
	return t.stopChange(ctx, selector, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO contract_token_stops (selector, cause, stopped_at, stopped_by, note)
			VALUES ($1, 'operator', $2, $3, $4)
			ON CONFLICT (selector, cause) DO UPDATE SET stopped_at = EXCLUDED.stopped_at, stopped_by = EXCLUDED.stopped_by,
				note = EXCLUDED.note, lifted_at = NULL`, selector, now, by, note)
		return err
	})
}

// LiftToken lifts the operator's stop of selector; it reports whether one
// was open.
func (t *Tokens) LiftToken(ctx context.Context, selector string, now time.Time) (bool, error) {
	if !kc.ValidSelector(selector) {
		return false, ErrSelector
	}
	lifted := false
	err := t.stopChange(ctx, selector, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE contract_token_stops SET lifted_at = $2
			WHERE selector = $1 AND cause = 'operator' AND lifted_at IS NULL`, selector, now)
		lifted = tag.RowsAffected() == 1
		return err
	})
	return lifted, err
}

// stopChange runs change, a write of selector's stops, after locking the
// token the selector maps to (if any) and bumping its access_version.
func (t *Tokens) stopChange(ctx context.Context, selector string, change func(pgx.Tx) error) error {
	return retryDeadlock(ctx, func() error {
		return pg.InTx(ctx, t.pool, func(tx pgx.Tx) error {
			var token, ws uuid.UUID
			err := tx.QueryRow(ctx, `SELECT token_id, tenant_id FROM contract_token_selectors WHERE selector = $1`, selector).Scan(&token, &ws)
			switch {
			case errors.Is(err, pgx.ErrNoRows):
			case err != nil:
				return err
			default:
				if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, ws.String()); err != nil {
					return err
				}
				if _, err := tx.Exec(ctx, `UPDATE contract_tokens t SET access_version = t.access_version + 1
					FROM (SELECT id FROM contract_tokens WHERE id = $1 FOR UPDATE) l WHERE t.id = l.id`, token); err != nil {
					return err
				}
				if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', '', true)`); err != nil {
					return err
				}
			}
			return change(tx)
		})
	})
}

// TokenStops lists every stop, open ones first, newest first.
func (t *Tokens) TokenStops(ctx context.Context) ([]TokenStop, error) {
	rows, err := t.pool.Query(ctx, `SELECT x.selector, x.cause, x.stopped_at, x.stopped_by, x.note, x.lifted_at, s.token_id
		FROM contract_token_stops x LEFT JOIN contract_token_selectors s ON s.selector = x.selector
		ORDER BY x.lifted_at IS NOT NULL, x.stopped_at DESC, x.selector, x.cause`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (TokenStop, error) {
		var s TokenStop
		err := row.Scan(&s.Selector, &s.Cause, &s.StoppedAt, &s.StoppedBy, &s.Note, &s.LiftedAt, &s.Token)
		return s, err
	})
}
