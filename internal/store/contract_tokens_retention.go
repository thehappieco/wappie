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
// goes at its selector's until if that comes first. Its end is the
// earlier of its revocation's and its expiry's own times, never past
// Wappie's clock (endedAt). A reset's pass that finds it unlisted forgets
// it at once (FinishTokenPass). Its selector, sticky row, pin and stops
// stay until its created_at + 365 days, so a record that comes back later
// never revives it.
const tokenForgetAfter = 30 * 24 * time.Hour

// tokenUsageKeep is how long a reported usage row is kept: a day's rows go
// at the start of the second UTC day after it, so at most this long after
// they were reported (a day is reported once it has begun).
const tokenUsageKeep = 48 * time.Hour

// tokenUsageMost is how long a refusal count is kept after its UTC day,
// reported or not: the platform keeps an app's daily counts of refused
// uses 30 days from the day of use (decision 0056), so one reported later
// would tell it nothing it keeps. A day of use has no such bound: the
// platform keeps each app's last day of use with its token, so an
// unreported one waits for the report until its token is forgotten
// (forgetQueuesTx) or its selector goes.
const tokenUsageMost = 30 * 24 * time.Hour

// tokenStopKeep is how long a stop of a selector Wappie never held is kept
// after it was made (stopped_at, which a re-stop moves on), unless Wappie
// learned of a valid record of its selector (from the feed, before the stop
// or since, or from the lookup by selector): then to that record's
// created_at + 365 days, if earlier. A signed not_found leaves the stop at
// this: the platform does not know its token for Wappie, so the stop is the
// operator's own record. A stop of a selector Wappie holds goes with it, at
// its until, its token's created_at + 365 days, which its expires_at never
// passes. A stop is made of a token that exists, so 365 days after it the
// token has expired anyway. The stop record keeps each line as long after
// its time, as decision 0056 sets (TokenStopLapsed).
const tokenStopKeep = kc.MaxTokenLifetime

// TokenRetention counts what a retention pass did: Queues counts the
// acknowledgement's entries and the usage rows a forgotten token left (its
// days of use, and its items' refusals), deleted or emptied.
type TokenRetention struct {
	Expired, Forgotten, Ended, Stops, Queues int64
}

// RetainTokens is the hourly retention of the token part (maintainOnce),
// on Wappie's clock now. Per workspace a selector names: the expiry janitor
// first, then what ended 30 days ago is forgotten, then what is past its
// selector's until goes, on both clocks (its row with its perms, then its
// removed instances), then what the acknowledgement and the usage report
// hold of a forgotten token, sent or not (forgetQueuesTx), then its pin.
// Then, after every workspace and before the selectors, in one
// statement, every stop due (one of a selector Wappie holds once that
// selector is past its until, whatever its own dates; any other at
// stopped_at + 365 days, or at its record_until or its selector's date if
// earlier; an operator's only once its stop and its lift are at or before
// the cut, and till then only its selector and times kept), with the mark
// of what it let go (contract_token_stops_let_go); then what the
// acknowledgement and the usage report still hold of a token past its
// until, sent or not; then the selectors, the sticky rows and the
// selectors' dates past their until (their guards); then the usage rows
// reported, from the start of the second UTC day after their day, and the
// refusal counts, reported or not, 30 days after their day; the queues'
// entries sent over 30 days ago, an unsent held entry of another
// generation than Wappie's, an unsent held entry of a token Wappie keeps
// nothing of, queued over 30 days ago, and a refusal of a token Wappie
// holds no selector of, sent or not, 30 days after the earlier of its
// queuing and the end its sticky row keeps. It
// visits every workspace a selector names, from the selectors alone, one
// Wappie no longer has included, whose token rows went with it but whose
// pins, removed instances, queue entries and token identities (no foreign
// key) did not: its tokens ended with it, so their removed instances,
// identities and items' queue entries go at once, its pins at their until.
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
			gone, err := goneWorkspacesTx(ctx, tx, workspaces)
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
				// The token ended at its expiry, however late this pass
				// sees it, so its record's 30 days count from then.
				rows, err := tx.Query(ctx, `UPDATE contract_tokens t
					SET ended_at = CASE WHEN isfinite(t.expires_at) THEN least(t.expires_at, $1) ELSE $1 END
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
				// Past until: the token rows, their perms with them; then
				// the removed instances of every token whose selector's
				// until passed, whether its row ended less than 30 days
				// before (a 365-day token that just expired: never
				// forgotten) or went with its workspace. Perms before
				// removed instances, as the forget above and a number's
				// drop (dropNumberTokensTx: its perms, then a removed
				// instance of the same key) take them: the other way, the
				// drop would wait on a removed instance deleted here while
				// this waits on the drop's perm.
				tag, err := tx.Exec(ctx, `DELETE FROM contract_tokens WHERE id IN (
					SELECT token_id FROM contract_token_selectors WHERE until <= $1)`, cut)
				if err != nil {
					return err
				}
				out.Ended += tag.RowsAffected()
				if _, err := tx.Exec(ctx, `DELETE FROM contract_token_removed WHERE token_id IN (
					SELECT token_id FROM contract_token_selectors WHERE until <= $1)`, cut); err != nil {
					return err
				}
				if gone[ws] {
					// A workspace Wappie no longer has: its token rows went
					// with its row, so they ended then; their removed
					// instances, part of their content, go now, and so do
					// their hidden identities (users and user_logins keep
					// no foreign key to the workspace), whose grants went
					// with the workspace's numbers. Its row is gone, so the
					// grants' trigger, which locks it (0034), locks nothing.
					if _, err := tx.Exec(ctx, `DELETE FROM contract_token_removed r
						WHERE NOT EXISTS (SELECT 1 FROM tenants w WHERE w.id = r.tenant_id)`); err != nil {
						return err
					}
					if _, err := tx.Exec(ctx, `DELETE FROM users u WHERE u.token_identity AND u.tenant_id = $1
						AND NOT EXISTS (SELECT 1 FROM tenants w WHERE w.id = $1)
						AND NOT EXISTS (SELECT 1 FROM contract_tokens t WHERE t.identity_user_id = u.id AND t.identity_dropped_at IS NULL)`, ws); err != nil {
						return err
					}
				}
				queues, err := forgetQueuesTx(ctx, tx, ws, gone[ws])
				if err != nil {
					return err
				}
				out.Queues += queues
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
			// record_until or its selector's date if that is earlier. The
			// mark of what retention let go is locked first, as a stop or a
			// lift takes it (between its token's row and its stop), and moves
			// on to the latest time of an operator's stop deleted here: once
			// this commits, no stop or lift is made at or before it
			// (stopChange). An operator's stop goes only once its times are
			// at or before the cut, so the mark never passes Wappie's clock:
			// a stop timed ahead (a clock ahead when it was made) would
			// otherwise give every later stop and lift, of any selector, its
			// time. One due before then keeps only what the stop record may
			// hold, its selector and its times (decision 0056): its note goes
			// and its stopped_by reads wappie. One of a selector that goes
			// now also takes the selector's until as its record_until, so the
			// first pass once its times are past lets it go; one of a
			// selector Wappie does not hold takes that selector's date
			// likewise (contract_token_dates, read here, unlocked, so a stop
			// made before the page that dates its selector committed is dated
			// all the same). It is written once: a later pass finds nothing
			// to change.
			if _, err := tx.Exec(ctx, `SELECT 1 FROM contract_token_stops_let_go FOR UPDATE`); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, `WITH due AS (
					SELECT y.selector, y.cause, s.until AS held_until, d.until AS seen_until,
					       y.cause <> 'operator' OR greatest(y.stopped_at, y.lifted_at) <= $1 AS ripe
					FROM contract_token_stops y
					LEFT JOIN contract_token_selectors s ON s.selector = y.selector
					LEFT JOIN contract_token_dates d ON d.selector = y.selector
					WHERE CASE WHEN s.selector IS NOT NULL THEN s.until <= $1
					           ELSE least(y.stopped_at + $2::interval, coalesce(y.record_until, 'infinity'),
					                      coalesce(d.until, 'infinity')) <= $1 END
					ORDER BY y.selector, y.cause FOR UPDATE OF y),
				gone AS (
					DELETE FROM contract_token_stops x USING due l
					WHERE x.selector = l.selector AND x.cause = l.cause AND l.ripe
					RETURNING x.cause, greatest(x.stopped_at, x.lifted_at) AS last),
				kept AS (
					UPDATE contract_token_stops x SET note = '', stopped_by = 'wappie',
					       record_until = least(x.record_until, l.held_until, l.seen_until)
					FROM due l
					WHERE x.selector = l.selector AND x.cause = l.cause AND NOT l.ripe
					  AND (x.note <> '' OR x.stopped_by <> 'wappie'
					       OR x.record_until IS DISTINCT FROM least(x.record_until, l.held_until, l.seen_until)))
				UPDATE contract_token_stops_let_go
				SET through = greatest(through, (SELECT max(last) FROM gone WHERE cause = 'operator'))
				RETURNING (SELECT count(*) FROM gone)`, cut, tokenStopKeep).Scan(&out.Stops); err != nil {
				return err
			}
			for _, q := range []struct {
				sql  string
				args []any
			}{
				// What the acknowledgement and the usage report still hold
				// of a token past its until, sent or not, before its
				// selector and sticky row go: the queues' entries, which a
				// token Wappie never held has with its sticky row alone or
				// with nothing (an unsent one, below), and the usage rows,
				// written only for a token whose selector Wappie keeps (its
				// secret matched), and so with none left of it.
				{`DELETE FROM contract_token_refusals_out WHERE token_id IN (
					SELECT token_id FROM contract_token_selectors WHERE until <= $1
					UNION ALL SELECT token_id FROM contract_token_sticky WHERE until <= $1)`, []any{cut}},
				{`DELETE FROM contract_token_held_out WHERE token_id IN (
					SELECT token_id FROM contract_token_selectors WHERE until <= $1
					UNION ALL SELECT token_id FROM contract_token_sticky WHERE until <= $1)`, []any{cut}},
				{`DELETE FROM contract_token_used u WHERE NOT EXISTS (
					SELECT 1 FROM contract_token_selectors s WHERE s.token_id = u.token_id AND s.until > $1)`, []any{cut}},
				{`DELETE FROM contract_token_refusals r WHERE NOT EXISTS (
					SELECT 1 FROM contract_token_selectors s WHERE s.token_id = r.token_id AND s.until > $1)`, []any{cut}},
				// The selectors past the cut: the loop deleted their token
				// rows, in every workspace a selector names, and their stops
				// went above, or took their until if timed past the cut.
				{`DELETE FROM contract_token_selectors WHERE until <= $1`, []any{cut}},
				{`DELETE FROM contract_token_sticky WHERE until <= $1`, []any{cut}},
				// The selectors' dates after the stops that read them.
				{`DELETE FROM contract_token_dates WHERE until <= $1`, []any{cut}},
				// A day's usage rows, once reported, from the start of the
				// second UTC day after it, whatever the session's time zone;
				// and its refusal counts, reported or not, 30 days after it.
				// An unreported day of use waits for the report: it goes
				// with its token's forget (forgetQueuesTx), or with its
				// selector above.
				{`DELETE FROM contract_token_used WHERE reported_at IS NOT NULL
					AND day <= (($1::timestamptz AT TIME ZONE 'UTC') - $2::interval)::date`, []any{now, tokenUsageKeep}},
				{`DELETE FROM contract_token_refusals WHERE reported_count >= count
					AND day <= (($1::timestamptz AT TIME ZONE 'UTC') - $2::interval)::date`, []any{now, tokenUsageKeep}},
				{`DELETE FROM contract_token_refusals WHERE day <= (($1::timestamptz AT TIME ZONE 'UTC') - $2::interval)::date`,
					[]any{now, tokenUsageMost}},
				{`DELETE FROM contract_token_refusals_out WHERE sent_at < $1::timestamptz - $2::interval`, []any{now, tokenForgetAfter}},
				{`DELETE FROM contract_token_held_out WHERE sent_at < $1::timestamptz - $2::interval`, []any{now, tokenForgetAfter}},
				// A held entry of another generation than Wappie's, never to
				// be sent (AckBody sends the current one's; a reset's pass
				// queues again what is held): restartTokensTx deletes them,
				// and this is its belt.
				{`DELETE FROM contract_token_held_out WHERE sent_at IS NULL
					AND generation IS DISTINCT FROM (SELECT generation FROM contract_state)`, nil},
				// A refusal of a token Wappie holds no selector of (a bad
				// record's), sent or not, 30 days after the earlier of when
				// it was queued and the end its sticky row keeps (its
				// revocation, or its earliest expiry): its end + 30 days when
				// Wappie knows the end, else 30 days after it came (a token
				// whose end Wappie does not know may live). Whether the
				// acknowledgement is off or refused that long.
				{`DELETE FROM contract_token_refusals_out o
					WHERE NOT EXISTS (SELECT 1 FROM contract_token_selectors s WHERE s.token_id = o.token_id)
					  AND least(o.queued_at, (SELECT least(k.revoked_at, CASE WHEN isfinite(k.earliest_expires_at) THEN k.earliest_expires_at END)
					                          FROM contract_token_sticky k WHERE k.token_id = o.token_id)) <= $1::timestamptz - $2::interval`,
					[]any{now, tokenForgetAfter}},
				// An unsent held entry of a token Wappie keeps nothing of, 30
				// days after it was queued.
				{`DELETE FROM contract_token_held_out o WHERE o.sent_at IS NULL AND o.queued_at <= $1::timestamptz - $2::interval
					AND NOT EXISTS (SELECT 1 FROM contract_token_selectors s WHERE s.token_id = o.token_id)
					AND NOT EXISTS (SELECT 1 FROM contract_token_sticky k WHERE k.token_id = o.token_id)`, []any{now, tokenForgetAfter}},
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

// forgetQueuesTx deletes, in workspace ws (its app.tenant_id set), what the
// acknowledgement and the usage report hold of a token whose record
// retention or a reset's pass forgot, sent or not, at every pass from the
// one that forgot it: its refusals, the items its held entries keep off
// (an entry that then says nothing goes; one still told revoked, expiring
// earlier or with a pinned key stays, which is its security record), its
// usage refusals on a number, and its days of use, which wait for the
// usage report until then. A token of a workspace whose row is gone
// (gone) counts as forgotten: it ended with its workspace. Its
// refusals as a token (presented revoked or expired), which name no item,
// keep their own rule: 30 days after their day. These rows have no step of
// DB25: they come after the workspace's token rows, perms and removed
// instances, as the applier writes its queues. It returns how many it
// deleted or emptied.
func forgetQueuesTx(ctx context.Context, tx pgx.Tx, ws uuid.UUID, gone bool) (int64, error) {
	rows, err := tx.Query(ctx, `SELECT id FROM contract_tokens WHERE forgotten_at IS NOT NULL
		UNION SELECT token_id FROM contract_token_selectors WHERE $1 AND tenant_id = $2`, gone, ws)
	if err != nil {
		return 0, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil || len(ids) == 0 {
		return 0, err
	}
	var n int64
	for _, q := range []string{
		`DELETE FROM contract_token_refusals_out WHERE token_id = ANY ($1)`,
		`UPDATE contract_token_held_out SET removed = '[]' WHERE token_id = ANY ($1) AND removed <> '[]'::jsonb`,
		`DELETE FROM contract_token_held_out WHERE token_id = ANY ($1) AND NOT revoked AND expires_at IS NULL AND reading_key IS NULL`,
		`DELETE FROM contract_token_refusals WHERE token_id = ANY ($1) AND device_id IS NOT NULL`,
		`DELETE FROM contract_token_used WHERE token_id = ANY ($1)`,
	} {
		tag, err := tx.Exec(ctx, q, ids)
		if err != nil {
			return n, err
		}
		n += tag.RowsAffected()
	}
	return n, nil
}

// goneWorkspacesTx are those of workspaces whose tenants row is gone.
func goneWorkspacesTx(ctx context.Context, tx pgx.Tx, workspaces []uuid.UUID) (map[uuid.UUID]bool, error) {
	rows, err := tx.Query(ctx, `SELECT w.id FROM unnest($1::uuid[]) AS w(id)
		WHERE NOT EXISTS (SELECT 1 FROM tenants t WHERE t.id = w.id)`, workspaces)
	if err != nil {
		return nil, err
	}
	gone := map[uuid.UUID]bool{}
	return gone, forEachRow(rows, func(row pgx.Rows) error {
		var id uuid.UUID
		if err := row.Scan(&id); err != nil {
			return err
		}
		gone[id] = true
		return nil
	})
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
// suspend), even one Wappie holds no record of yet, and returns its
// stopped_at. It writes only to the database, so it works with the platform
// down. A token the selector maps to gets its access_version bumped under
// its row lock (DB25 step 4), so an open request's actor no longer matches;
// the stops' trigger notifies every process. The feed and a reset never
// lift it. A re-stop is made now, and keeps the record_until the applier
// gave the stop. A stop's times only go forward: a re-stop timed at or
// before the stop's last change (two commands at once, or a clock stepped
// back) is made just after that change, a microsecond on, so no two
// changes of one stop share a time. A stop is also made after the mark of
// what retention let go (stopChange). The stop record's line carries the
// time returned, and a replay applies a line only when it is later than
// the stop's last change, so it brings the stops back as they stood and
// leaves a stop the database holds as it is.
func (t *Tokens) StopToken(ctx context.Context, selector, by, note string, now time.Time) (time.Time, error) {
	if !kc.ValidSelector(selector) {
		return time.Time{}, ErrSelector
	}
	var at time.Time
	_, err := t.stopChange(ctx, selector, func(tx pgx.Tx, through *time.Time) (bool, error) {
		err := tx.QueryRow(ctx, `INSERT INTO contract_token_stops (selector, cause, stopped_at, stopped_by, note)
			VALUES ($1, 'operator', greatest($2::timestamptz, $5::timestamptz + interval '1 microsecond'), $3, $4)
			ON CONFLICT (selector, cause) DO UPDATE SET stopped_by = EXCLUDED.stopped_by, note = EXCLUDED.note, lifted_at = NULL,
				stopped_at = greatest(EXCLUDED.stopped_at, contract_token_stops.stopped_at + interval '1 microsecond',
					contract_token_stops.lifted_at + interval '1 microsecond')
			RETURNING stopped_at`, selector, now, by, note, through).Scan(&at)
		return true, err
	})
	return at, err
}

// LiftToken lifts the operator's stop of selector at now, but never at or
// before its stopped_at or the mark of what retention let go: then a
// microsecond after the later of them (a stop's times only go forward, as
// in StopToken). It returns when the stop was lifted and whether this call
// lifted it: a stop lifted already gives its own lifted_at, unchanged, and
// none (no operator's stop of selector) the zero time.
func (t *Tokens) LiftToken(ctx context.Context, selector string, now time.Time) (time.Time, bool, error) {
	if !kc.ValidSelector(selector) {
		return time.Time{}, false, ErrSelector
	}
	var at time.Time
	lifted, err := t.stopChange(ctx, selector, func(tx pgx.Tx, through *time.Time) (bool, error) {
		at = time.Time{}
		var was *time.Time
		err := tx.QueryRow(ctx, `SELECT lifted_at FROM contract_token_stops
			WHERE selector = $1 AND cause = 'operator' FOR UPDATE`, selector).Scan(&was)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return false, nil
		case err != nil:
			return false, err
		case was != nil:
			at = *was
			return false, nil
		}
		err = tx.QueryRow(ctx, `UPDATE contract_token_stops
			SET lifted_at = greatest($2::timestamptz, stopped_at + interval '1 microsecond', $3::timestamptz + interval '1 microsecond')
			WHERE selector = $1 AND cause = 'operator' RETURNING lifted_at`, selector, now, through).Scan(&at)
		return err == nil, err
	})
	return at, lifted, err
}

// ReplayTokenStop is StopToken for a line of the stop record (tokens suspend
// -replay, after a restore of Wappie's database), at the line's own time,
// with the note given (a replay's is empty: the record keeps none). It
// leaves a line at or before the mark of what retention let go
// (TokenStopMarked): the restored database holds that stop already, or
// retention let it go before the snapshot. It leaves a line 365 days old
// by now (Wappie's clock), whose stop retention lets go whatever became of
// its selector. Otherwise it applies only when the line is later than the
// database's stop's last change, its stop or its lift: no two changes of
// one stop share a time (StopToken), so a line at that change's time is
// that change. So a replay never rewinds what was done since without the
// record, and never rewrites a stop the database holds as the line has
// it, with its note and who made it. It reports whether it applied.
func (t *Tokens) ReplayTokenStop(ctx context.Context, selector, by, note string, at, now time.Time) (bool, error) {
	if !kc.ValidSelector(selector) {
		return false, ErrSelector
	}
	if TokenStopLapsed(at, now) {
		return false, nil
	}
	return t.stopChange(ctx, selector, func(tx pgx.Tx, through *time.Time) (bool, error) {
		if TokenStopMarked(at, through) {
			return false, nil
		}
		tag, err := tx.Exec(ctx, `INSERT INTO contract_token_stops (selector, cause, stopped_at, stopped_by, note)
			VALUES ($1, 'operator', $2, $3, $4)
			ON CONFLICT (selector, cause) DO UPDATE SET stopped_at = EXCLUDED.stopped_at, stopped_by = EXCLUDED.stopped_by,
				note = EXCLUDED.note, lifted_at = NULL
			WHERE greatest(contract_token_stops.stopped_at, contract_token_stops.lifted_at) < EXCLUDED.stopped_at`, selector, at, by, note)
		return tag.RowsAffected() == 1, err
	})
}

// TokenStopLapsed reports whether a stop made at at is past what retention
// keeps of it by now, 365 days. The stop record drops a line whose time is
// that old, at each append and each hourly pass (decision 0056: 365 days
// after it was written), and a replay leaves it.
func TokenStopLapsed(at, now time.Time) bool { return !at.Add(tokenStopKeep).After(now) }

// TokenStopMarked reports whether a line of the stop record at at is at or
// before through, the mark of what retention let go (nil: none yet). The
// database that holds the mark holds that stop or lift already, or
// retention let its stop go: a replay leaves the line.
func TokenStopMarked(at time.Time, through *time.Time) bool {
	return through != nil && !at.After(*through)
}

// TokenStopsLetGo is the mark of what retention let go: the latest time,
// its stop or its lift, of an operator's stop it deleted, nil before any.
func (t *Tokens) TokenStopsLetGo(ctx context.Context) (*time.Time, error) {
	var through *time.Time
	err := t.pool.QueryRow(ctx, `SELECT through FROM contract_token_stops_let_go`).Scan(&through)
	return through, err
}

// ReplayTokenLift is LiftToken for a line of the stop record: it leaves a
// line at or before the mark of what retention let go, as ReplayTokenStop
// does, and otherwise lifts the open operator stop only when that stop was
// made before the lift, so a lift the record kept never lifts a stop made
// since, nor one made at its time (a re-stop is made after the lift it
// follows). It reports whether it lifted one.
func (t *Tokens) ReplayTokenLift(ctx context.Context, selector string, at time.Time) (bool, error) {
	if !kc.ValidSelector(selector) {
		return false, ErrSelector
	}
	return t.stopChange(ctx, selector, func(tx pgx.Tx, through *time.Time) (bool, error) {
		if TokenStopMarked(at, through) {
			return false, nil
		}
		tag, err := tx.Exec(ctx, `UPDATE contract_token_stops SET lifted_at = $2
			WHERE selector = $1 AND cause = 'operator' AND lifted_at IS NULL AND stopped_at < $2`, selector, at)
		return tag.RowsAffected() == 1, err
	})
}

// stopChange runs change, a write of selector's stops that reports whether
// it changed one, after locking the token the selector maps to (if any;
// DB25 step 4), then the mark of what retention let go, shared, which it
// gives change. A stop or a lift is made after the mark. Retention moves
// the mark under its row lock, so it waits for a change in flight, and a
// change waits for it: once retention commits, no stop or lift is made at
// or before the mark. It bumps the token's access_version when change
// changed a stop.
func (t *Tokens) stopChange(ctx context.Context, selector string, change func(pgx.Tx, *time.Time) (bool, error)) (bool, error) {
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
			var through *time.Time
			if err := tx.QueryRow(ctx, `SELECT through FROM contract_token_stops_let_go FOR SHARE`).Scan(&through); err != nil {
				return err
			}
			if changed, err = change(tx, through); err != nil || !changed || !held {
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
