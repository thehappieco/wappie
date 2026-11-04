package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/pg"
)

// The acknowledgement of the token feed (POST /contract/v1/tokens/applied;
// the plan's 4.2, "Ack queries", and 4.4) and the usage report (4.5): what
// the leader sends, built from the queues the commit and the judge fill.

// tokenSuspendedSQL is, per token of the workspace of the statement (its
// app.tenant_id), its stops of Wappie's own as the acknowledgement names
// them: an operator's open stop of its selector; an apply_failed one, as
// local_rule; its creator's local account disabled here
// (creator_disabled_here); and, before enforce, its creator's local
// membership removed or disabled, or a local role that is not owner or
// admin, or no local account at all (local_rule). Token auth (tokenLiveSQL)
// refuses a token with any.
//
//nolint:gosec // G101: a query, not a credential
const tokenSuspendedSQL = `
	SELECT t.id AS token_id, 'operator' AS cause FROM contract_tokens t
	  JOIN contract_token_selectors s ON s.token_id = t.id
	  JOIN contract_token_stops x ON x.selector = s.selector AND x.cause = 'operator' AND x.lifted_at IS NULL
	UNION
	SELECT t.id, 'local_rule' FROM contract_tokens t
	  JOIN contract_token_selectors s ON s.token_id = t.id
	  JOIN contract_token_stops x ON x.selector = s.selector AND x.cause = 'apply_failed' AND x.lifted_at IS NULL
	UNION
	SELECT t.id, 'creator_disabled_here' FROM contract_tokens t
	  JOIN platform_identities pi ON pi.sub = t.created_by
	  JOIN users u ON u.id = pi.user_id AND u.status = 'disabled'
	UNION
	SELECT t.id, 'local_rule' FROM contract_tokens t
	 WHERE NOT EXISTS (SELECT 1 FROM platform_identities pi
	                     JOIN workspace_memberships m ON m.user_id = pi.user_id AND m.tenant_id = t.tenant_id
	                    WHERE pi.sub = t.created_by AND m.status = 'active' AND m.role IN ('owner', 'admin'))`

// TokenAck is one acknowledgement to send, and what to mark once the
// platform accepts it.
type TokenAck struct {
	Body kc.TokenApplied
	// refused and held are the queue entries the body carries, each with
	// the queued_at it was read at: an entry changed since (a merge) stays
	// due.
	refused []tokenRefusalRow
	held    []heldSent
	// waitingHash and suspendedHash are the sets' hashes, kept when the
	// body carries them (Waiting or Suspended not nil).
	waitingHash, suspendedHash []byte
}

// Empty reports whether the acknowledgement says nothing new: no refusal,
// no held token, no set that changed, and a through already accepted.
func (a TokenAck) Empty(acked int64) bool {
	return len(a.Body.Refused) == 0 && len(a.Body.Held) == 0 && a.Body.Waiting == nil && a.Body.Suspended == nil &&
		a.Body.Through <= acked
}

// heldSent is a held entry a body carries, as it was queued.
type heldSent struct {
	token    uuid.UUID
	queuedAt time.Time
}

// TokenAckState is what the ack sender reads of the acknowledgement's state.
type TokenAckState struct {
	Generation *uuid.UUID
	Through    int64
	Acked      int64
	ReadAt     *time.Time
}

// AckState reads the generation, the cursor and the last through accepted.
func (t *Tokens) AckState(ctx context.Context) (TokenAckState, error) {
	var s TokenAckState
	err := t.pool.QueryRow(ctx, `SELECT c.generation, s.feed_cursor, s.ack_through, s.read_at
		FROM contract_token_state s CROSS JOIN contract_state c`).Scan(&s.Generation, &s.Through, &s.Acked, &s.ReadAt)
	return s, err
}

// AckBody builds the next acknowledgement (the plan's 4.2): one budget of
// kc.MaxAppliedEntries across its four lists (kit tokenwire.go). The queued
// refusals come first, oldest first, then the held tokens of the current
// generation; the waiting set and the suspended set each go whole, and only
// when its hash changed since the last accepted, when it fits what is left
// of the budget, or in an acknowledgement of its own at the same through
// (the next AckBody, once these entries are sent), with waiting_more or
// suspended_more only beside exactly 1000 entries. ok is false while no
// token page has committed in the generation.
func (t *Tokens) AckBody(ctx context.Context) (TokenAck, bool, error) {
	var out TokenAck
	ok := false
	err := pgx.BeginTxFunc(ctx, t.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var gen *uuid.UUID
		var through int64
		var readAt *time.Time
		var waitingSent, suspendedSent []byte
		if err := tx.QueryRow(ctx, `SELECT c.generation, s.feed_cursor, s.read_at, s.waiting_sent_hash, s.suspended_sent_hash
			FROM contract_token_state s CROSS JOIN contract_state c`).Scan(&gen, &through, &readAt, &waitingSent, &suspendedSent); err != nil {
			return err
		}
		if gen == nil || readAt == nil {
			return nil
		}
		ok = true
		out.Body = kc.TokenApplied{Generation: gen.String(), Through: through, AppliedAt: kc.T(*readAt),
			Refused: []kc.TokenRefusal{}, Held: []kc.TokenHeld{}}
		budget := kc.MaxAppliedEntries
		rows, err := tx.Query(ctx, `SELECT token_id, version, item, perm, code, queued_at FROM contract_token_refusals_out
			WHERE sent_at IS NULL ORDER BY queued_at, token_id, version, item, perm LIMIT $1`, budget)
		if err != nil {
			return err
		}
		out.refused, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (tokenRefusalRow, error) {
			var r tokenRefusalRow
			err := row.Scan(&r.token, &r.version, &r.item, &r.perm, &r.code, &r.queuedAt)
			return r, err
		})
		if err != nil {
			return err
		}
		for _, r := range out.refused {
			out.Body.Refused = append(out.Body.Refused, kc.TokenRefusal{Token: r.token.String(), Version: r.version, Item: r.item, Perm: r.perm, Code: r.code})
		}
		budget -= len(out.refused)
		rows, err = tx.Query(ctx, `SELECT token_id, revoked, expires_at, removed, reading_key, queued_at FROM contract_token_held_out
			WHERE sent_at IS NULL AND generation = $1 ORDER BY queued_at, token_id LIMIT $2`, *gen, budget)
		if err != nil {
			return err
		}
		err = forEachRow(rows, func(row pgx.Rows) error {
			var h kc.TokenHeld
			var id uuid.UUID
			var expires *time.Time
			var removed []byte
			var queued time.Time
			if err := row.Scan(&id, &h.Revoked, &expires, &removed, &h.ReadingKey, &queued); err != nil {
				return err
			}
			h.Token = id.String()
			if expires != nil {
				at := kc.T(*expires)
				h.ExpiresAt = &at
			}
			if err := json.Unmarshal(removed, &h.Removed); err != nil {
				return err
			}
			if h.Removed == nil {
				h.Removed = []kc.HeldPerm{}
			}
			if len(h.Removed) > kc.MaxHeldRemoved {
				h.Removed = h.Removed[:kc.MaxHeldRemoved]
			}
			out.Body.Held = append(out.Body.Held, h)
			out.held = append(out.held, heldSent{token: id, queuedAt: queued})
			return nil
		})
		if err != nil {
			return err
		}
		budget -= len(out.held)

		waiting, err := waitingPermsTx(ctx, tx)
		if err != nil {
			return err
		}
		if hash := setHash(waiting); !bytes.Equal(hash, waitingSent) {
			if fits(len(waiting), budget, len(out.refused)+len(out.held)) {
				out.Body.Waiting, out.Body.WaitingMore = capped(waiting)
				out.waitingHash = hash
				budget -= len(out.Body.Waiting)
			}
		}
		suspended, err := suspendedTx(ctx, tx)
		if err != nil {
			return err
		}
		if hash := setHash(suspended); !bytes.Equal(hash, suspendedSent) {
			if fits(len(suspended), budget, len(out.refused)+len(out.held)+len(out.Body.Waiting)) {
				out.Body.Suspended, out.Body.SuspendedMore = capped(suspended)
				out.suspendedHash = hash
			}
		}
		return nil
	})
	return out, ok, err
}

// fits reports whether a whole set of n entries goes in this body: within
// what is left of the budget, or, over the 1000 a set holds, as its first
// 1000 in a body that carries nothing else.
func fits(n, budget, others int) bool {
	if n > kc.MaxAppliedEntries {
		return others == 0
	}
	return n <= budget
}

// capped is a set as a body carries it: whole, or its first 1000 with the
// flag that says it holds more.
func capped[S ~[]E, E any](set S) (S, kc.TrueFlag) {
	if set == nil {
		set = S{}
	}
	if len(set) > kc.MaxAppliedEntries {
		return set[:kc.MaxAppliedEntries], true
	}
	return set, false
}

// setHash is a set's hash, over its JSON in its sorted order.
func setHash(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	sum := sha256.Sum256(b)
	return sum[:]
}

// waitingPermsTx is the whole waiting set, workspace by workspace under each
// one's app.tenant_id, sorted.
func waitingPermsTx(ctx context.Context, tx pgx.Tx) (kc.WaitingPerms, error) {
	workspaces, err := tokenWorkspacesTx(ctx, tx)
	if err != nil {
		return nil, err
	}
	out := kc.WaitingPerms{}
	for _, ws := range workspaces {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, ws.String()); err != nil {
			return nil, err
		}
		rows, err := tx.Query(ctx, `SELECT token_id, device_id, perm, granted_by, granted_at FROM contract_token_perms
			WHERE state = 'waiting' ORDER BY token_id, device_id, perm`)
		if err != nil {
			return nil, err
		}
		err = forEachRow(rows, func(row pgx.Rows) error {
			var token, device, by uuid.UUID
			var perm string
			var at time.Time
			if err := row.Scan(&token, &device, &perm, &by, &at); err != nil {
				return err
			}
			out = append(out, kc.WaitingPerm{Token: token.String(), Item: device.String(), Perm: perm, GrantedBy: by.String(), GrantedAt: kc.T(at)})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	slices.SortFunc(out, func(a, b kc.WaitingPerm) int {
		for _, c := range [][2]string{{a.Token, b.Token}, {a.Item, b.Item}, {a.Perm, b.Perm}} {
			if c[0] != c[1] {
				if c[0] < c[1] {
					return -1
				}
				return 1
			}
		}
		return 0
	})
	_, err = tx.Exec(ctx, `SELECT set_config('app.tenant_id', '', true)`)
	return out, err
}

// suspendedTx is the whole suspended set, computed workspace by workspace
// under each one's app.tenant_id (a view read with no workspace set would
// see nothing of users or memberships), for the tokens that have not ended,
// sorted.
func suspendedTx(ctx context.Context, tx pgx.Tx) (kc.Suspensions, error) {
	workspaces, err := tokenWorkspacesTx(ctx, tx)
	if err != nil {
		return nil, err
	}
	out := kc.Suspensions{}
	for _, ws := range workspaces {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, ws.String()); err != nil {
			return nil, err
		}
		rows, err := tx.Query(ctx, `SELECT s.token_id, s.cause FROM (`+tokenSuspendedSQL+`) s
			JOIN contract_tokens t ON t.id = s.token_id
			WHERE t.revoked_at IS NULL AND t.unlisted_at IS NULL AND t.ended_at IS NULL
			ORDER BY s.token_id, s.cause`)
		if err != nil {
			return nil, err
		}
		err = forEachRow(rows, func(row pgx.Rows) error {
			var token uuid.UUID
			var cause string
			if err := row.Scan(&token, &cause); err != nil {
				return err
			}
			out = append(out, kc.Suspension{Token: token.String(), Cause: cause})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	slices.SortFunc(out, func(a, b kc.Suspension) int {
		if a.Token != b.Token {
			if a.Token < b.Token {
				return -1
			}
			return 1
		}
		switch {
		case a.Cause < b.Cause:
			return -1
		case a.Cause > b.Cause:
			return 1
		}
		return 0
	})
	_, err = tx.Exec(ctx, `SELECT set_config('app.tenant_id', '', true)`)
	return out, err
}

// AckSent marks an acknowledgement the platform accepted (a signed
// {accepted: true}, never anything less): its refusals and held tokens are
// delivered, each only as the body carried it (an entry merged or recoded
// since, whose queued_at moved, stays due), its through and the hashes of
// the sets it carried are kept, and the acknowledgement's failure is
// cleared.
func (t *Tokens) AckSent(ctx context.Context, a TokenAck, at time.Time) error {
	return pg.InTx(ctx, t.pool, func(tx pgx.Tx) error {
		if len(a.refused) > 0 {
			n := len(a.refused)
			tokens, versions, items, perms := make([]uuid.UUID, n), make([]int64, n), make([]string, n), make([]string, n)
			queued := make([]time.Time, n)
			for i, r := range a.refused {
				tokens[i], versions[i], items[i], perms[i], queued[i] = r.token, r.version, r.item, r.perm, r.queuedAt
			}
			if _, err := tx.Exec(ctx, `UPDATE contract_token_refusals_out o SET sent_at = $1
				FROM unnest($2::uuid[], $3::bigint[], $4::text[], $5::text[], $6::timestamptz[]) AS r(token, version, item, perm, queued)
				WHERE o.token_id = r.token AND o.version = r.version AND o.item = r.item AND o.perm = r.perm AND o.sent_at IS NULL
				  AND o.queued_at = r.queued`,
				at, tokens, versions, items, perms, queued); err != nil {
				return err
			}
		}
		if len(a.held) > 0 {
			gen, err := uuid.Parse(a.Body.Generation)
			if err != nil {
				return err
			}
			tokens, queued := make([]uuid.UUID, len(a.held)), make([]time.Time, len(a.held))
			for i, h := range a.held {
				tokens[i], queued[i] = h.token, h.queuedAt
			}
			if _, err := tx.Exec(ctx, `UPDATE contract_token_held_out o SET sent_at = $1
				FROM unnest($2::uuid[], $3::timestamptz[]) AS h(token, queued)
				WHERE o.token_id = h.token AND o.generation = $4 AND o.sent_at IS NULL AND o.queued_at = h.queued`,
				at, tokens, queued, gen); err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx, `UPDATE contract_token_state SET ack_through = GREATEST(ack_through, $1), ack_sent_at = $2,
			ack_error = NULL, ack_error_at = NULL,
			waiting_sent_hash = coalesce($3, waiting_sent_hash), suspended_sent_hash = coalesce($4, suspended_sent_hash)`,
			a.Body.Through, at, a.waitingHash, a.suspendedHash)
		return err
	})
}

// AckFailed records the acknowledgement's failure class, kept from the
// first failure of the run.
func (t *Tokens) AckFailed(ctx context.Context, class string, at time.Time) error {
	_, err := t.pool.Exec(ctx, `UPDATE contract_token_state SET ack_error = $1, ack_error_at = coalesce(ack_error_at, $2)`, class, at)
	return err
}

// TokenUse is one process's counts since its last flush: the (token, UTC
// day) pairs it accepted, and its refusals by (token, day, number, perm,
// code), number and perm unset for a refusal of the token itself.
type TokenUse struct {
	Used     []TokenDay
	Refusals []TokenUseRefusal
}

// TokenDay is a token accepted on a UTC day.
type TokenDay struct {
	Token uuid.UUID
	Day   time.Time
}

// TokenUseRefusal is a count of refused uses.
type TokenUseRefusal struct {
	Token  uuid.UUID
	Day    time.Time
	Device *uuid.UUID
	Perm   *string
	Code   string
	Count  int64
}

// AddTokenUse adds one process's counts: each key is one row, to which the
// flush adds its delta (the plan's 3.6), so several processes never lose a
// count.
func (t *Tokens) AddTokenUse(ctx context.Context, u TokenUse) error {
	if len(u.Used) == 0 && len(u.Refusals) == 0 {
		return nil
	}
	return pg.InTx(ctx, t.pool, func(tx pgx.Tx) error {
		if len(u.Used) > 0 {
			// UTC days, as text, as the refusals' below: a timestamptz cast
			// to date would take the session's time zone.
			tokens, days := make([]uuid.UUID, len(u.Used)), make([]string, len(u.Used))
			for i, d := range u.Used {
				tokens[i], days[i] = d.Token, d.Day.UTC().Format(time.DateOnly)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO contract_token_used (token_id, day)
				SELECT DISTINCT token, day::date FROM unnest($1::uuid[], $2::text[]) AS u(token, day)
				ON CONFLICT DO NOTHING`, tokens, days); err != nil {
				return err
			}
		}
		if len(u.Refusals) > 0 {
			n := len(u.Refusals)
			tokens, days, devices := make([]uuid.UUID, n), make([]string, n), make([]*uuid.UUID, n)
			perms, codes, counts := make([]*string, n), make([]string, n), make([]int64, n)
			for i, r := range u.Refusals {
				tokens[i], days[i], devices[i], perms[i], codes[i], counts[i] = r.Token, r.Day.UTC().Format(time.DateOnly), r.Device, r.Perm, r.Code, r.Count
			}
			if _, err := tx.Exec(ctx, `INSERT INTO contract_token_refusals (token_id, day, device_id, perm, code, count)
				SELECT token, day::date, device, perm, code, sum(count) FROM unnest($1::uuid[], $2::text[], $3::uuid[], $4::text[], $5::text[], $6::bigint[])
					AS r(token, day, device, perm, code, count) WHERE count > 0
				GROUP BY token, day, device, perm, code
				ON CONFLICT (token_id, day, device_id, perm, code) DO UPDATE SET count = contract_token_refusals.count + EXCLUDED.count`,
				tokens, days, devices, perms, codes, counts); err != nil {
				return err
			}
		}
		return nil
	})
}

// TokenUsageBody is one usage report to send, and what to mark once the
// platform accepts it.
type TokenUsageBody struct {
	Body     kc.TokenUsage
	used     []TokenDay
	refusals []TokenUseRefusal
}

// UsageBody builds the next usage report (the plan's 4.5): the days not yet
// reported, and the refusal rows whose count rose since, each with its
// row's absolute count, at most kc.MaxUsageEntries per list and within
// kc.UsageBodyLimit (an entry is far below 256 bytes, so 1000 of each fit;
// the body's size is checked all the same). Empty when there is nothing.
func (t *Tokens) UsageBody(ctx context.Context) (TokenUsageBody, error) {
	out := TokenUsageBody{Body: kc.TokenUsage{Used: []kc.TokenUsed{}, Refusals: []kc.UsageRefusal{}}}
	rows, err := t.pool.Query(ctx, `SELECT token_id, day FROM contract_token_used WHERE reported_at IS NULL
		ORDER BY day, token_id LIMIT $1`, kc.MaxUsageEntries)
	if err != nil {
		return out, err
	}
	err = forEachRow(rows, func(row pgx.Rows) error {
		var d TokenDay
		if err := row.Scan(&d.Token, &d.Day); err != nil {
			return err
		}
		out.used = append(out.used, d)
		out.Body.Used = append(out.Body.Used, kc.TokenUsed{Token: d.Token.String(), Day: d.Day.Format(time.DateOnly)})
		return nil
	})
	if err != nil {
		return out, err
	}
	rows, err = t.pool.Query(ctx, `SELECT token_id, day, device_id, perm, code, count FROM contract_token_refusals
		WHERE count > reported_count ORDER BY day, token_id, device_id NULLS FIRST, perm NULLS FIRST, code LIMIT $1`, kc.MaxUsageEntries)
	if err != nil {
		return out, err
	}
	err = forEachRow(rows, func(row pgx.Rows) error {
		var r TokenUseRefusal
		if err := row.Scan(&r.Token, &r.Day, &r.Device, &r.Perm, &r.Code, &r.Count); err != nil {
			return err
		}
		e := kc.UsageRefusal{Token: r.Token.String(), Day: r.Day.Format(time.DateOnly), Perm: r.Perm, Code: r.Code, Count: r.Count}
		if r.Device != nil {
			item := r.Device.String()
			e.Item = &item
		}
		out.refusals = append(out.refusals, r)
		out.Body.Refusals = append(out.Body.Refusals, e)
		return nil
	})
	if err != nil {
		return out, err
	}
	for {
		b, err := json.Marshal(out.Body)
		if err != nil {
			return out, err
		}
		if len(b) <= kc.UsageBodyLimit || len(out.Body.Refusals) == 0 {
			if len(b) > kc.UsageBodyLimit {
				return out, errors.New("store: a usage report of no refusals is over its limit")
			}
			return out, nil
		}
		half := len(out.Body.Refusals) / 2
		out.Body.Refusals, out.refusals = out.Body.Refusals[:half], out.refusals[:half]
	}
}

// Empty reports whether the report carries nothing.
func (u TokenUsageBody) Empty() bool { return len(u.Body.Used) == 0 && len(u.Body.Refusals) == 0 }

// UsageSent marks a report the platform accepted: its days reported, and
// each refusal row reported up to the count it carried.
func (t *Tokens) UsageSent(ctx context.Context, u TokenUsageBody, at time.Time) error {
	return pg.InTx(ctx, t.pool, func(tx pgx.Tx) error {
		if len(u.used) > 0 {
			tokens, days := make([]uuid.UUID, len(u.used)), make([]time.Time, len(u.used))
			for i, d := range u.used {
				tokens[i], days[i] = d.Token, d.Day
			}
			if _, err := tx.Exec(ctx, `UPDATE contract_token_used x SET reported_at = $1
				FROM unnest($2::uuid[], $3::date[]) AS u(token, day) WHERE x.token_id = u.token AND x.day = u.day`, at, tokens, days); err != nil {
				return err
			}
		}
		for _, r := range u.refusals {
			if _, err := tx.Exec(ctx, `UPDATE contract_token_refusals SET reported_count = GREATEST(reported_count, $6)
				WHERE token_id = $1 AND day = $2 AND device_id IS NOT DISTINCT FROM $3 AND perm IS NOT DISTINCT FROM $4 AND code = $5`,
				r.Token, r.Day, r.Device, r.Perm, r.Code, r.Count); err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx, `UPDATE contract_token_state SET usage_sent_at = $1, usage_error = NULL, usage_error_at = NULL`, at)
		return err
	})
}

// UsageFailed records the usage report's failure class, kept from the
// first failure of the run.
func (t *Tokens) UsageFailed(ctx context.Context, class string, at time.Time) error {
	_, err := t.pool.Exec(ctx, `UPDATE contract_token_state SET usage_error = $1, usage_error_at = coalesce(usage_error_at, $2)`, class, at)
	return err
}
