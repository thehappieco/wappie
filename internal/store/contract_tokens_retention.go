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
// perms and removed instances) is kept after it ended, at most: all of it
// goes at its selector's until if that comes first. Its selector, sticky
// row, pin and stops stay until its created_at + 365 days, so a record that
// comes back later never revives it.
const tokenForgetAfter = 30 * 24 * time.Hour

// tokenUsageKeep is how long a reported usage row is kept.
const tokenUsageKeep = 48 * time.Hour

// tokenStopKeep is how long a stop of a selector Wappie never held is kept
// after it was made (stopped_at, which a re-stop moves on), unless a record
// of its selector came: then to that record's created_at + 365 days, if
// earlier. A stop of a selector Wappie holds goes with it. A stop is made of
// a token that exists, so 365 days after it the token has expired anyway;
// a replay of the stop record leaves a stop older than that, as its trim
// drops it.
const tokenStopKeep = kc.MaxTokenLifetime

// TokenRetention counts what a retention pass did.
type TokenRetention struct {
	Expired, Forgotten, Ended, Stops int64
}

// RetainTokens is the hourly retention of the token part (maintainOnce),
// on Wappie's clock now: the expiry janitor first, then what ended 30 days
// ago is forgotten, then what is past its until goes through its guards
// (the token's removed instances first, then its row with its perms, then
// its pin; then its stops, then its selector and its sticky row), then the
// stops of selectors Wappie never held at stopped_at + 365 days or at
// their record_until, then the usage rows reported and over 2 days old and
// the queues' sent entries over 30 days old. It visits every workspace a
// selector names, from the selectors alone: one Wappie no longer has
// included, whose token rows went with it but whose pins and removed
// instances (no foreign key) did not; their removed instances, the
// content of tokens that ended with their workspace, go at once, the pins
// at their until.
func (t *Tokens) RetainTokens(ctx context.Context, now time.Time) (TokenRetention, error) {
	var out TokenRetention
	err := retryDeadlock(ctx, func() error {
		out = TokenRetention{}
		return pg.InTx(ctx, t.pool, func(tx pgx.Tx) error {
			// One cut for every past-until delete: Wappie's clock, never
			// past the database's, read once, so the guards (until <=
			// clock_timestamp()) let each through, and a token's row, its
			// pin and its selector go in the same pass.
			var cut time.Time
			if err := tx.QueryRow(ctx, `SELECT least($1::timestamptz, clock_timestamp())`, now).Scan(&cut); err != nil {
				return err
			}
			workspaces, err := selectorWorkspacesTx(ctx, tx)
			if err != nil {
				return err
			}
			// The workspaces whose expiring tokens hold an identity, whose
			// grants go with it (DB25 step 3).
			if err := lockGrantWorkspacesTx(ctx, tx, workspaces, `expires_at <= $1 AND ended_at IS NULL`,
				func(uuid.UUID) []any { return []any{now} }); err != nil {
				return err
			}
			var sticky []stickyWrite
			for _, ws := range workspaces {
				if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, ws.String()); err != nil {
					return err
				}
				// Every token row this pass writes, in one id order (DB25
				// step 4), before any: the expiring, those ended 30 days ago
				// and those past until.
				if _, err := tx.Exec(ctx, `SELECT 1 FROM contract_tokens
					WHERE (expires_at <= $1 AND ended_at IS NULL) OR (ended_at <= $2 AND forgotten_at IS NULL)
					   OR id IN (SELECT token_id FROM contract_token_selectors WHERE until <= $3)
					ORDER BY id FOR UPDATE`, now, now.Add(-tokenForgetAfter), cut); err != nil {
					return err
				}
				// The expiry janitor: the token's row first (DB25 step 4),
				// then its identity with its grants, then the sticky row.
				rows, err := tx.Query(ctx, `UPDATE contract_tokens t SET ended_at = $1
					FROM (SELECT id FROM contract_tokens WHERE expires_at <= $1 AND ended_at IS NULL ORDER BY id FOR UPDATE) l
					WHERE t.id = l.id RETURNING t.id, t.created_at, t.expires_at`, now)
				if err != nil {
					return err
				}
				var expired []uuid.UUID
				err = forEachRow(rows, func(row pgx.Rows) error {
					var s stickyWrite
					var created time.Time
					if err := row.Scan(&s.id, &created, &s.expiresAt); err != nil {
						return err
					}
					s.ended, s.until = "expired", created.Add(tokenKeep)
					sticky = append(sticky, s)
					expired = append(expired, s.id)
					out.Expired++
					return nil
				})
				if err != nil {
					return err
				}
				if err := dropTokenIdentitiesTx(ctx, tx, now, expired); err != nil {
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
				// Past until: the removed instances of every token whose
				// selector's until passed, whether its row ended less than 30
				// days before (a 365-day token that just expired: never
				// forgotten) or went with its workspace; then the token rows,
				// their perms with them; and the pins.
				if _, err := tx.Exec(ctx, `DELETE FROM contract_token_removed WHERE token_id IN (
					SELECT token_id FROM contract_token_selectors WHERE until <= $1)`, cut); err != nil {
					return err
				}
				tag, err := tx.Exec(ctx, `DELETE FROM contract_tokens WHERE id IN (
					SELECT token_id FROM contract_token_selectors WHERE until <= $1)`, cut)
				if err != nil {
					return err
				}
				out.Ended += tag.RowsAffected()
				// A workspace Wappie no longer has: its token rows went with
				// its row, so they ended then, and their removed instances,
				// part of their content, go now.
				if _, err := tx.Exec(ctx, `DELETE FROM contract_token_removed r
					WHERE NOT EXISTS (SELECT 1 FROM tenants w WHERE w.id = r.tenant_id)`); err != nil {
					return err
				}
				if _, err := tx.Exec(ctx, `DELETE FROM contract_token_pins WHERE until <= $1`, cut); err != nil {
					return err
				}
			}
			if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', '', true)`); err != nil {
				return err
			}
			if err := writeStickyTx(ctx, tx, sticky); err != nil {
				return err
			}
			// The stops, after every workspace's token rows (DB25), in
			// (selector, cause) order, before the selectors: one of a
			// selector Wappie holds only with it, past its until, whatever
			// its own dates; any other at stopped_at + 365 days, or at its
			// record_until if that is earlier.
			tag, err := tx.Exec(ctx, `DELETE FROM contract_token_stops x
				USING (SELECT y.selector, y.cause FROM contract_token_stops y
				       LEFT JOIN contract_token_selectors s ON s.selector = y.selector
				       WHERE CASE WHEN s.selector IS NOT NULL THEN s.until <= $1
				                  ELSE least(y.stopped_at + $2::interval, coalesce(y.record_until, 'infinity')) <= $1 END
				       ORDER BY y.selector, y.cause FOR UPDATE OF y) l
				WHERE x.selector = l.selector AND x.cause = l.cause`, cut, tokenStopKeep)
			if err != nil {
				return err
			}
			out.Stops = tag.RowsAffected()
			for _, q := range []struct {
				sql  string
				args []any
			}{
				// The selectors past the cut: the loop deleted their token
				// rows, in every workspace a selector names, and their stops
				// went above.
				{`DELETE FROM contract_token_selectors WHERE until <= $1`, []any{cut}},
				{`DELETE FROM contract_token_sticky WHERE until <= $1`, []any{cut}},
				// UTC days, whatever the session's time zone.
				{`DELETE FROM contract_token_used WHERE reported_at IS NOT NULL
					AND day < (($1::timestamptz AT TIME ZONE 'UTC') - $2::interval)::date`, []any{now, tokenUsageKeep}},
				{`DELETE FROM contract_token_refusals WHERE reported_count >= count
					AND day < (($1::timestamptz AT TIME ZONE 'UTC') - $2::interval)::date`, []any{now, tokenUsageKeep}},
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
// process. The feed and a reset never lift it. A re-stop is made now, and
// keeps the record_until the applier gave the stop.
func (t *Tokens) StopToken(ctx context.Context, selector, by, note string, now time.Time) error {
	if !kc.ValidSelector(selector) {
		return ErrSelector
	}
	_, err := t.stopChange(ctx, selector, func(tx pgx.Tx) (bool, error) {
		_, err := tx.Exec(ctx, `INSERT INTO contract_token_stops (selector, cause, stopped_at, stopped_by, note)
			VALUES ($1, 'operator', $2, $3, $4)
			ON CONFLICT (selector, cause) DO UPDATE SET stopped_at = EXCLUDED.stopped_at, stopped_by = EXCLUDED.stopped_by,
				note = EXCLUDED.note, lifted_at = NULL`, selector, now, by, note)
		return true, err
	})
	return err
}

// LiftToken lifts the operator's stop of selector; it reports whether one
// was open.
func (t *Tokens) LiftToken(ctx context.Context, selector string, now time.Time) (bool, error) {
	if !kc.ValidSelector(selector) {
		return false, ErrSelector
	}
	return t.stopChange(ctx, selector, func(tx pgx.Tx) (bool, error) {
		tag, err := tx.Exec(ctx, `UPDATE contract_token_stops SET lifted_at = $2
			WHERE selector = $1 AND cause = 'operator' AND lifted_at IS NULL`, selector, now)
		return tag.RowsAffected() == 1, err
	})
}

// ReplayTokenStop is StopToken for a line of the stop record (tokens suspend
// -replay, after a restore of Wappie's database), at the line's own time:
// it applies only when nothing the database holds of the selector's
// operator stop is later, neither its stop nor its lift, so a replay never
// rewinds what was done since without the record, and never for a line
// 365 days old by now (Wappie's clock), whose stop retention let go, so a
// replay never brings one back. It reports whether it applied.
func (t *Tokens) ReplayTokenStop(ctx context.Context, selector, by, note string, at, now time.Time) (bool, error) {
	if !kc.ValidSelector(selector) {
		return false, ErrSelector
	}
	if TokenStopLapsed(at, now) {
		return false, nil
	}
	return t.stopChange(ctx, selector, func(tx pgx.Tx) (bool, error) {
		tag, err := tx.Exec(ctx, `INSERT INTO contract_token_stops (selector, cause, stopped_at, stopped_by, note)
			VALUES ($1, 'operator', $2, $3, $4)
			ON CONFLICT (selector, cause) DO UPDATE SET stopped_at = EXCLUDED.stopped_at, stopped_by = EXCLUDED.stopped_by,
				note = EXCLUDED.note, lifted_at = NULL
			WHERE GREATEST(contract_token_stops.stopped_at, contract_token_stops.lifted_at) <= EXCLUDED.stopped_at`, selector, at, by, note)
		return tag.RowsAffected() == 1, err
	})
}

// TokenStopLapsed reports whether a stop made at at is past what retention
// keeps of it by now, 365 days, so the stop record drops its line and a
// replay leaves it.
func TokenStopLapsed(at, now time.Time) bool { return !at.Add(tokenStopKeep).After(now) }

// ReplayTokenLift is LiftToken for a line of the stop record: it lifts the
// open operator stop only when that stop is no later than the lift, so a
// lift the record kept never lifts a stop made since. It reports whether it
// lifted one.
func (t *Tokens) ReplayTokenLift(ctx context.Context, selector string, at time.Time) (bool, error) {
	if !kc.ValidSelector(selector) {
		return false, ErrSelector
	}
	return t.stopChange(ctx, selector, func(tx pgx.Tx) (bool, error) {
		tag, err := tx.Exec(ctx, `UPDATE contract_token_stops SET lifted_at = $2
			WHERE selector = $1 AND cause = 'operator' AND lifted_at IS NULL AND stopped_at <= $2`, selector, at)
		return tag.RowsAffected() == 1, err
	})
}

// stopChange runs change, a write of selector's stops that reports whether
// it changed one, after locking the token the selector maps to (if any;
// DB25 step 4), and bumps that token's access_version when it did.
func (t *Tokens) stopChange(ctx context.Context, selector string, change func(pgx.Tx) (bool, error)) (bool, error) {
	changed := false
	err := retryDeadlock(ctx, func() error {
		return pg.InTx(ctx, t.pool, func(tx pgx.Tx) error {
			var token, ws uuid.UUID
			err := tx.QueryRow(ctx, `SELECT token_id, tenant_id FROM contract_token_selectors WHERE selector = $1`, selector).Scan(&token, &ws)
			held := err == nil
			switch {
			case errors.Is(err, pgx.ErrNoRows):
			case err != nil:
				return err
			default:
				if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, ws.String()); err != nil {
					return err
				}
				if _, err := tx.Exec(ctx, `SELECT 1 FROM contract_tokens WHERE id = $1 FOR UPDATE`, token); err != nil {
					return err
				}
			}
			if changed, err = change(tx); err != nil || !changed || !held {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE contract_tokens SET access_version = access_version + 1 WHERE id = $1`, token); err != nil {
				return err
			}
			_, err = tx.Exec(ctx, `SELECT set_config('app.tenant_id', '', true)`)
			return err
		})
	})
	return changed, err
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
