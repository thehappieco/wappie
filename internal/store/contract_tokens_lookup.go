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

// The leader's lookups (decision 0056; the platform's review of step 7's
// p5, its F2 and F3): a signed GET of one token, by id or by selector, so
// that what Wappie keeps of a token it does not hold ends by the token's
// own date, which only the platform knows:
//
//   - by id (GET /contract/v1/tokens/{id}): the revocation a bad record
//     brought of a token Wappie holds no selector of, dated by Wappie's
//     clock (contract_token_sticky.clock_until);
//   - by selector (GET /contract/v1/token-selectors/{selector}): a stop of
//     a selector Wappie does not hold that no valid record dates (no
//     record_until, no row in contract_token_dates).
//
// The leader asks them one by one, on its pace, with no transaction open
// during a call: DueTokenLookups only reads, and each answer is written in
// a short transaction of its own. Every write is a compare-and-set on what
// made the lookup due, and every date only lowers, so a late write (a
// leader that lost its lock, a record the feed brought meanwhile) changes
// nothing it should not. Nothing of an answer is applied to a token: no
// row, perm, pin or identity is made from it. A platform that never
// answers leaves each row to its outer bound, as before the lookups: a
// sticky row to its receipt + 365 days, a stop to its stopped_at + 365
// days.

// TokenLookup is one signed GET the leader owes: by id (Token) or by
// selector (Selector, Token uuid.Nil).
type TokenLookup struct {
	Token    uuid.UUID
	Selector string
}

// ByID reports whether l is a lookup by id.
func (l TokenLookup) ByID() bool { return l.Token != uuid.Nil }

// ErrTokenLookupRecord is a signed record that cannot date what the lookup
// asked of: not valid, another app's, another token's or selector's, with
// no created_at, or a reading key whose fingerprint is not its own (the
// feed's rules for a good record). Nothing is written; the leader counts
// it as a bad answer (TokenLookupFailed).
var ErrTokenLookupRecord = errors.New("store: the lookup's record cannot date its token")

// DueTokenLookups are the lookups due by now (Wappie's clock), at most limit
// of each kind, the by-id ones first, each kind those never asked first. A
// read of its own: no lock is held once it returns.
//
// By id: a sticky row dated by Wappie's clock, not past its until, of a
// token whose id no selectors row holds. By selector: a selector with a
// stop no valid record dates, not past its stopped_at + 365 days, that no
// selectors row holds and no date row dates. Either one not asked again
// before its lookup_after (infinity: never).
func (t *Tokens) DueTokenLookups(ctx context.Context, now time.Time, limit int) ([]TokenLookup, error) {
	rows, err := t.pool.Query(ctx, `SELECT k.token_id FROM contract_token_sticky k
		WHERE k.clock_until AND k.until > $1 AND (k.lookup_after IS NULL OR k.lookup_after <= $1)
		  AND NOT EXISTS (SELECT 1 FROM contract_token_selectors s WHERE s.token_id = k.token_id)
		ORDER BY k.lookup_after NULLS FIRST, k.token_id LIMIT $2`, now, limit)
	if err != nil {
		return nil, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return nil, err
	}
	rows, err = t.pool.Query(ctx, `SELECT y.selector FROM contract_token_stops y
		WHERE y.record_until IS NULL AND (y.lookup_after IS NULL OR y.lookup_after <= $1)
		  AND y.stopped_at + $2::interval > $1
		  AND NOT EXISTS (SELECT 1 FROM contract_token_selectors s WHERE s.selector = y.selector)
		  AND NOT EXISTS (SELECT 1 FROM contract_token_dates d WHERE d.selector = y.selector)
		GROUP BY y.selector ORDER BY min(coalesce(y.lookup_after, '-infinity')), y.selector LIMIT $3`, now, tokenStopKeep, limit)
	if err != nil {
		return nil, err
	}
	selectors, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	out := make([]TokenLookup, 0, len(ids)+len(selectors))
	for _, id := range ids {
		out = append(out, TokenLookup{Token: id})
	}
	for _, s := range selectors {
		out = append(out, TokenLookup{Selector: s})
	}
	return out, nil
}

// TokenLookupAnswered dates what l asked of with rec, the platform's signed
// answer, on Wappie's clock now: a good record (valid, Wappie's, the token
// or selector asked for, with its created_at, and a reading key whose
// fingerprint is its own), else ErrTokenLookupRecord with nothing written.
// The generation is not compared: a token's created_at never changes. In
// one transaction, in the applier's order (DB25): the token's sticky row,
// if Wappie's clock dates it, to unheldUntil (the record's created_at + 365
// days, one ahead of the clock counting as now); then its selector's stops,
// whose record_until only lowers, never for a selector another token holds
// (narrowStopsTx); then its selector's date, when no selectors row holds it
// (dateSelectorsTx). So an answer by id dates the selector's stops too, and
// one by selector the token's revocation: each is a valid record of both.
// A lookup by selector is settled: never asked again.
func (t *Tokens) TokenLookupAnswered(ctx context.Context, l TokenLookup, rec kc.TokenRecord, now time.Time) error {
	switch {
	case rec.Validate() != nil, rec.App != t.app, rec.CreatedAt.IsZero(),
		rec.ReadingKey != nil && rec.ReadingKey.Check() != nil,
		l.ByID() && rec.ID != l.Token.String(),
		!l.ByID() && rec.Selector != l.Selector:
		return ErrTokenLookupRecord
	}
	id := uuid.MustParse(rec.ID)
	until := unheldUntil(rec, nil, true, now)
	seen := []stopSeen{{selector: rec.Selector, token: id, until: rec.CreatedAt.Add(tokenKeep)}}
	return retryDeadlock(ctx, func() error {
		return pg.InTx(ctx, t.pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `UPDATE contract_token_sticky SET until = least(until, $2), clock_until = false, clock_gen = NULL,
				lookup_after = NULL, lookup_bad = 0 WHERE token_id = $1 AND clock_until`, id, until); err != nil {
				return err
			}
			if err := narrowStopsTx(ctx, tx, seen); err != nil {
				return err
			}
			if !l.ByID() {
				if _, err := tx.Exec(ctx, `UPDATE contract_token_stops SET lookup_after = 'infinity', lookup_bad = 0
					WHERE selector = $1 AND lookup_after IS DISTINCT FROM 'infinity'`, l.Selector); err != nil {
					return err
				}
			}
			return dateSelectorsTx(ctx, tx, seen, now)
		})
	})
}

// TokenLookupNotFound takes the platform's signed not_found to l and
// reports whether it let a sticky row go.
//
// By id: the platform keeps a record that named Wappie, as it did this
// one, until its token's created_at + 365 days and answers not_found after
// (decision 0056), so the token is past its life, and its revocation goes
// at once, in this transaction (its until lowered to the database's clock,
// which the guard asks). Only while Wappie's generation is the one the bad
// record came in: after a restore of the platform's database, not_found
// also means a token the restored platform has never named to Wappie,
// which it may name later unrevoked. Then the row keeps its clock's date
// and is not asked again; a valid record of the token from the feed still
// dates it.
//
// By selector: the platform knows no token of that selector for Wappie, so
// its stops are the operator's own record, kept to their stopped_at + 365
// days; they are not asked again. A valid record of the selector from the
// feed still dates them.
func (t *Tokens) TokenLookupNotFound(ctx context.Context, l TokenLookup) (bool, error) {
	dropped := false
	err := retryDeadlock(ctx, func() error {
		dropped = false
		return pg.InTx(ctx, t.pool, func(tx pgx.Tx) error {
			if !l.ByID() {
				_, err := tx.Exec(ctx, `UPDATE contract_token_stops SET lookup_after = 'infinity', lookup_bad = 0
					WHERE selector = $1 AND record_until IS NULL AND lookup_after IS DISTINCT FROM 'infinity'`, l.Selector)
				return err
			}
			tag, err := tx.Exec(ctx, `UPDATE contract_token_sticky SET until = least(until, clock_timestamp())
				WHERE token_id = $1 AND clock_until AND clock_gen = (SELECT generation FROM contract_state)`, l.Token)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 1 {
				dropped = true
				_, err := tx.Exec(ctx, `DELETE FROM contract_token_sticky WHERE token_id = $1`, l.Token)
				return err
			}
			_, err = tx.Exec(ctx, `UPDATE contract_token_sticky SET lookup_after = 'infinity', lookup_bad = 0
				WHERE token_id = $1 AND clock_until AND lookup_after IS DISTINCT FROM 'infinity'`, l.Token)
			return err
		})
	})
	return dropped, err
}

// TokenLookupFailed puts l off after a call that got nothing Wappie can
// use, on Wappie's clock now: no answer (bad false), asked again after
// retry; or a signed answer whose record Wappie cannot take (bad true: one
// that is not valid, or ErrTokenLookupRecord), counted, and asked again
// after retry doubled for each such answer in a row before it, at most
// most, since the platform answers with the record it stores until that
// record changes. It returns how many such answers in a row l has had (0
// when it is no longer due: answered, or its row gone).
func (t *Tokens) TokenLookupFailed(ctx context.Context, l TokenLookup, now time.Time, bad bool, retry, most time.Duration) (int, error) {
	q, arg := `UPDATE contract_token_sticky SET lookup_bad = lookup_bad + CASE WHEN $2 THEN 1 ELSE 0 END,
			lookup_after = $3::timestamptz + CASE WHEN $2 THEN least($4::interval * power(2::float8, least(lookup_bad, 20)), $5::interval)
			                                      ELSE $4::interval END
		WHERE token_id = $1 AND clock_until AND lookup_after IS DISTINCT FROM 'infinity' RETURNING lookup_bad`, any(l.Token)
	if !l.ByID() {
		q, arg = `UPDATE contract_token_stops SET lookup_bad = lookup_bad + CASE WHEN $2 THEN 1 ELSE 0 END,
				lookup_after = $3::timestamptz + CASE WHEN $2 THEN least($4::interval * power(2::float8, least(lookup_bad, 20)), $5::interval)
				                                      ELSE $4::interval END
			WHERE selector = $1 AND record_until IS NULL AND lookup_after IS DISTINCT FROM 'infinity' RETURNING lookup_bad`, l.Selector
	}
	rows, err := t.pool.Query(ctx, q, arg, bad, now, retry, most)
	if err != nil {
		return 0, err
	}
	counts, err := pgx.CollectRows(rows, pgx.RowTo[int])
	n := 0
	for _, c := range counts {
		n = max(n, c)
	}
	return n, err
}
