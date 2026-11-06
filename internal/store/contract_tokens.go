package store

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/obs"
	"whatserver2/internal/pg"
)

// The platform contract's token part on Wappie's side (migration 0053; step
// 7's plan, 4.2): the token feed's records, judged in Go before anything of
// them is written and applied workspace by workspace in one transaction per
// page, so the cursor moves with the page. A bad record never stalls the
// feed: only what it narrows applies, and a record Wappie cannot apply even
// narrowed stops its token locally (apply_failed) and the feed goes on.
//
// The lock order is DB25's (core/docs/decisions.md): contract_state, then
// contract_token_state, then the workspaces' rows (tenants), then the token
// rows, their perms, and the token identities' users and grants, the last
// three workspace by workspace in workspace id order. A token commit never
// locks contract_state: it reads the generation after its own lock.

// Tokens is the token part's state in the database.
type Tokens struct {
	pool *pgxpool.Pool
	// app is the app whose records apply: wappie, but for the kit's vectors
	// of another app's (SetAppForTest).
	app string
}

// NewTokens returns the token store backed by pool.
func NewTokens(pool *pgxpool.Pool) *Tokens { return &Tokens{pool: pool, app: TokenApp} }

// TokenApp is Wappie's app id in the token part: only its records apply.
const TokenApp = "wappie"

// ContractTokensChannel carries a token's id, or "all", when something token
// auth reads changes (0053's triggers): every process re-checks its open
// sockets and streams at once.
const ContractTokensChannel = "wappie_contract_tokens"

// The token modes (contract_token_state.mode).
const (
	TokensOff = "off"
	TokensOn  = "on"
)

// tokenKeep is how long a token's selector, its sticky row, its pin and its
// selector's stops are kept: its created_at plus the longest life a token
// has, so a selector is never reused while a record of it can come back.
const tokenKeep = kc.MaxTokenLifetime

// The refusal codes Wappie sends (kit tokenwire.go): never not_offered,
// terms_not_current or team_withheld, since Wappie offers every perm, names
// no key terms and withholds no team.
const (
	tokenRefusedGiver   = kc.RefusedGiverNotReader
	tokenRefusedRole    = kc.RefusedLocalRole
	tokenRefusedUnknown = kc.RefusedItemUnknown
	tokenRefusedKey     = kc.RefusedReadingKeyChanged
	tokenRefusedInvalid = kc.RefusedInvalidRecord
)

// The perms' states (contract_token_perms.state).
const (
	tokenPending = "pending"
	tokenWaiting = "waiting"
	tokenApplied = "applied"
	tokenRefused = "refused"
)

var (
	// ErrNoGeneration: contract_state holds no generation (the first
	// observe, or after the account feed's gone). The token follower waits
	// for the account side.
	ErrNoGeneration = errors.New("store: the contract holds no generation; the token feed waits for the account side")
	// ErrFeedRewound: a token page whose head or next_after is behind the
	// cursor in the same generation. A reset never widens, so the follower
	// treats it as one.
	ErrFeedRewound = errors.New("store: a token page behind the cursor is a reset")
)

// The classes of the token part's ERRORs.
const (
	TokenErrorApplyFailed = "token_apply_failed"
	TokenErrorKeyChanged  = "token_reading_key_changed"
)

// TokenPage is one signed token feed answer as the follower commits it: the
// cursor it was asked from, the generation the follower held when it asked
// (contract_state's), the answer itself (validated by the follower:
// TokenFeed.Validate), Wappie's clock, and whether this is a leader's first
// page after a stored read over an hour old (a stale start: token auth holds
// until a page with more false commits).
type TokenPage struct {
	After          int64
	SeenGeneration uuid.UUID
	Feed           kc.TokenFeed
	Now            time.Time
	StaleStart     bool
}

// TokenPageResult is what committing a token page did.
type TokenPageResult struct {
	// Committed: the cursor moved. False when the state was no longer the
	// one the page was asked from: nothing was written.
	Committed bool
	// Narrowed: a record revoked, shortened or dropped something, or a
	// refusal or a held token was queued: the acknowledgement goes at once.
	Narrowed bool
	// Pending is how many grants wait for the judge.
	Pending int
	// Vouched: its published_through was stored; Ahead: it was past
	// Wappie's clock by more than ContractClockSkew, and was not.
	Vouched, Ahead bool
	// PassReady: a reset's pass may finish (FinishTokenPass): this page had
	// more false, after the round ran in the pass's generation.
	PassReady bool
	// Skipped are the records refused whole (another app's, an unknown
	// workspace's, one with no id); Bad the ones applied for their
	// narrowings only; Failed the ones not applied at all, whose tokens
	// Wappie stopped (apply_failed).
	Skipped, Bad, Failed int
}

// tokenItem is one record of a page, decoded and judged on its own (the
// kit's TokenFeed.Validate order).
type tokenItem struct {
	seq int64
	raw json.RawMessage
	rec kc.TokenRecord
	// id is the record's token id; uuid.Nil when it is not one.
	id uuid.UUID
	// bad is why only its narrowings apply: invalid_record (it does not
	// decode or fails Validate) or reading_key_changed (its fingerprint is
	// not its key's); "" for a good record.
	bad string
}

// decodeTokenItems decodes a page's records in its order, leaving out
// another app's (logged), and refuses the page as a reset when one is of
// another valid generation than gen.
func (t *Tokens) decodeTokenItems(ctx context.Context, gen uuid.UUID, items []kc.TokenFeedItem) ([]tokenItem, int, error) {
	out := make([]tokenItem, 0, len(items))
	skipped := 0
	for _, it := range items {
		rec, err := it.Record()
		if kc.ValidApp(rec.App) && rec.App != t.app {
			obs.LoggerFrom(ctx).Info("contract: a token record of another app is skipped", tokenLogAttrs(rec)...)
			skipped++
			continue
		}
		if kc.ValidUUID(rec.Generation) && rec.Generation != gen.String() {
			return nil, 0, ErrPageGeneration
		}
		ti := tokenItem{seq: it.Seq, raw: it.Token, rec: rec}
		switch {
		case err != nil || rec.Validate() != nil:
			ti.bad = tokenRefusedInvalid
		case rec.ReadingKey != nil && rec.ReadingKey.Check() != nil:
			ti.bad = tokenRefusedKey
		}
		if kc.ValidUUID(rec.ID) {
			ti.id = uuid.MustParse(rec.ID)
		}
		out = append(out, ti)
	}
	return out, skipped, nil
}

// tokenLogAttrs names a record in a log line: its id, selector and version
// as they decoded, never its JSON (another app's record may hold what is not
// Wappie's to log).
func tokenLogAttrs(rec kc.TokenRecord) []any {
	return []any{"token", rec.ID, "selector", rec.Selector, "version", rec.Version}
}

// tokenFeedState is contract_token_state as the commit reads it under its
// lock, beside contract_state's generation, read after it with no lock.
type tokenFeedState struct {
	Mode                string
	Cursor              int64
	ReadAt              *time.Time
	ResetTrustedThrough *time.Time
	PassGeneration      *uuid.UUID
	PassDone            bool
	Generation          *uuid.UUID
	RoundGeneration     *uuid.UUID
}

// lockTokenStateTx reads contract_token_state under its row lock (DB25 step
// 2), then contract_state's generation and round with no lock.
func lockTokenStateTx(ctx context.Context, tx pgx.Tx) (tokenFeedState, error) {
	var s tokenFeedState
	if err := tx.QueryRow(ctx, `SELECT mode, feed_cursor, read_at, reset_trusted_through, pass_generation, pass_done_at IS NOT NULL
		FROM contract_token_state FOR UPDATE`).Scan(&s.Mode, &s.Cursor, &s.ReadAt, &s.ResetTrustedThrough, &s.PassGeneration, &s.PassDone); err != nil {
		return s, err
	}
	err := tx.QueryRow(ctx, `SELECT generation, round_generation FROM contract_state`).Scan(&s.Generation, &s.RoundGeneration)
	return s, err
}

// CommitTokenPage applies a signed token page in one transaction (the
// plan's 4.2), contract_token_state locked first and contract_state's
// generation read after it with no lock: none stored is ErrNoGeneration;
// the page's of another generation than the follower held, or a record of
// another valid one, is ErrPageGeneration (a reset); a head or next_after
// behind the cursor is ErrFeedRewound. When the cursor or the generation
// moved since the follower read them, nothing is written (Committed false).
// Each record is decoded and judged before its workspace's writes, which
// run workspace by workspace in id order, set-based, under one savepoint;
// on an unexpected error that workspace is redone record by record, a
// record that fails gets its narrowings only, and one that fails even so
// stops its token (apply_failed), logged at ERROR. The cursor then moves to
// the page's next_after; only a page with more false stores its
// published_through (unless it is past Wappie's clock by more than
// ContractClockSkew) and sets caught_up_at.
func (t *Tokens) CommitTokenPage(ctx context.Context, p TokenPage) (TokenPageResult, error) {
	gen, err := uuid.Parse(p.Feed.Generation)
	if err != nil || !kc.ValidUUID(p.Feed.Generation) {
		return TokenPageResult{}, fmt.Errorf("store: a token page's generation %q is not a UUID", p.Feed.Generation)
	}
	if gen != p.SeenGeneration {
		return TokenPageResult{}, ErrPageGeneration
	}
	items, skipped, err := t.decodeTokenItems(ctx, gen, p.Feed.Items)
	if err != nil {
		return TokenPageResult{}, err
	}
	var res TokenPageResult
	err = retryDeadlock(ctx, func() error {
		res = TokenPageResult{Skipped: skipped}
		return pg.InTx(ctx, t.pool, func(tx pgx.Tx) error {
			state, err := lockTokenStateTx(ctx, tx)
			if err != nil {
				return err
			}
			if state.Generation == nil {
				return ErrNoGeneration
			}
			if *state.Generation != p.SeenGeneration || state.Cursor != p.After {
				return nil
			}
			if p.Feed.Head < p.After || p.Feed.NextAfter < p.After {
				return ErrFeedRewound
			}
			applied, err := t.applyItemsTx(ctx, tx, gen, state, items, p.Now, true)
			if err != nil {
				return err
			}
			res.Narrowed, res.Pending = applied.narrowed, applied.pending
			res.Skipped += applied.skipped
			res.Bad, res.Failed = applied.bad, applied.failed
			res.Ahead = p.Feed.PublishedThrough.After(p.Now.Add(ContractClockSkew))
			res.Vouched = !p.Feed.More && !res.Ahead
			res.PassReady = !p.Feed.More && state.PassGeneration != nil && *state.PassGeneration == gen && !state.PassDone &&
				state.RoundGeneration != nil && *state.RoundGeneration == gen
			tag, err := tx.Exec(ctx, `UPDATE contract_token_state SET feed_cursor = $1,
				published_through = CASE WHEN $2 THEN $3 ELSE published_through END,
				caught_up_at = CASE WHEN NOT $4 THEN $5::timestamptz WHEN $6 THEN NULL ELSE caught_up_at END,
				pass_ready_at = CASE WHEN $7 THEN coalesce(pass_ready_at, $5::timestamptz) ELSE pass_ready_at END,
				read_at = $5::timestamptz, error = NULL, error_at = NULL
				WHERE feed_cursor = $8`,
				p.Feed.NextAfter, res.Vouched, p.Feed.PublishedThrough.Time, p.Feed.More, p.Now, p.StaleStart, res.PassReady, p.After)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return errors.New("store: the token feed's cursor moved under contract_token_state's lock")
			}
			if !p.Feed.More && res.Ahead {
				obs.LoggerFrom(ctx).Error("contract: the token feed's published_through is ahead of the clock; the last trusted one is kept",
					"generation", gen, "cursor", p.Feed.NextAfter)
			}
			res.Committed = true
			return nil
		})
	})
	return res, err
}

// applyResult is what applying a page's records did.
type applyResult struct {
	narrowed              bool
	pending               int
	skipped, bad, failed  int
	held, refused, pinned int
}

func (a *applyResult) add(b applyResult) {
	a.narrowed = a.narrowed || b.narrowed
	a.pending += b.pending
	a.skipped += b.skipped
	a.bad += b.bad
	a.failed += b.failed
	a.held += b.held
	a.refused += b.refused
	a.pinned += b.pinned
}

// selectorRow is a contract_token_selectors row.
type selectorRow struct {
	Selector string
	Token    uuid.UUID
	Tenant   uuid.UUID
	Hash     []byte
	// Until is the token's created_at + 365 days, as stored.
	Until time.Time
}

// stickyRow is what a contract_token_sticky row says of a token.
type stickyRow struct {
	Revoked bool
	Ended   *string
	// Earliest is its earliest expiry, when it holds one.
	Earliest *time.Time
}

// applyItemsTx applies items, all of generation gen, in tx, which holds
// contract_token_state's lock: what Wappie holds of each (its selector, its
// sticky row, whether its workspace exists) is read across workspaces, then
// each workspace's records are applied under its app.tenant_id in id order,
// then the revocations of records Wappie holds no token or workspace for
// join the sticky set, and every valid record lowers the record_until of
// its selector's stops and, when no selectors row holds the selector, its
// date (contract_token_dates). full is false for a by-id GET's record,
// which never moves a pass.
func (t *Tokens) applyItemsTx(ctx context.Context, tx pgx.Tx, gen uuid.UUID, state tokenFeedState, items []tokenItem,
	now time.Time, full bool) (applyResult, error) {
	var res applyResult
	if len(items) == 0 {
		return res, nil
	}
	var ids []uuid.UUID
	var selectors []string
	var workspaces []uuid.UUID
	for _, it := range items {
		if it.id != uuid.Nil {
			ids = append(ids, it.id)
		}
		if kc.ValidSelector(it.rec.Selector) {
			selectors = append(selectors, it.rec.Selector)
		}
		if kc.ValidUUID(it.rec.WorkspaceID) {
			workspaces = append(workspaces, uuid.MustParse(it.rec.WorkspaceID))
		}
	}
	byID, bySelector := map[uuid.UUID]selectorRow{}, map[string]selectorRow{}
	rows, err := tx.Query(ctx, `SELECT selector, token_id, tenant_id, hash, until FROM contract_token_selectors
		WHERE token_id = ANY ($1) OR selector = ANY ($2)`, ids, selectors)
	if err != nil {
		return res, err
	}
	err = forEachRow(rows, func(row pgx.Rows) error {
		var s selectorRow
		if err := row.Scan(&s.Selector, &s.Token, &s.Tenant, &s.Hash, &s.Until); err != nil {
			return err
		}
		byID[s.Token], bySelector[s.Selector] = s, s
		workspaces = append(workspaces, s.Tenant)
		return nil
	})
	if err != nil {
		return res, err
	}
	sticky := map[uuid.UUID]stickyRow{}
	rows, err = tx.Query(ctx, `SELECT token_id, revoked_at IS NOT NULL, ended, CASE WHEN isfinite(earliest_expires_at) THEN earliest_expires_at END
		FROM contract_token_sticky WHERE token_id = ANY ($1)`, ids)
	if err != nil {
		return res, err
	}
	err = forEachRow(rows, func(row pgx.Rows) error {
		var id uuid.UUID
		var s stickyRow
		if err := row.Scan(&id, &s.Revoked, &s.Ended, &s.Earliest); err != nil {
			return err
		}
		sticky[id] = s
		return nil
	})
	if err != nil {
		return res, err
	}
	held := map[uuid.UUID]bool{}
	rows, err = tx.Query(ctx, `SELECT id FROM tenants WHERE id = ANY ($1)`, workspaces)
	if err != nil {
		return res, err
	}
	err = forEachRow(rows, func(row pgx.Rows) error {
		var id uuid.UUID
		if err := row.Scan(&id); err != nil {
			return err
		}
		held[id] = true
		return nil
	})
	if err != nil {
		return res, err
	}

	// Each record's workspace: the stored one for a token Wappie holds (a
	// record never moves it), else the record's own. A record of a
	// workspace Wappie does not hold is skipped, its revocation kept. Every
	// valid record tells its selector's stops their record_until.
	groups := map[uuid.UUID][]tokenItem{}
	var orphans []stickyWrite
	var seen []stopSeen
	for _, it := range items {
		if it.id == uuid.Nil {
			obs.LoggerFrom(ctx).Warn("contract: a token record with no id is skipped", "seq", it.seq, "selector", it.rec.Selector)
			res.skipped++
			continue
		}
		if s, ok := seenStop(it, byID); ok {
			seen = append(seen, s)
		}
		ws, known := uuid.Nil, false
		var kept *selectorRow
		if s, ok := byID[it.id]; ok {
			ws, known, kept = s.Tenant, true, &s
		} else if kc.ValidUUID(it.rec.WorkspaceID) {
			ws = uuid.MustParse(it.rec.WorkspaceID)
		}
		if ws == uuid.Nil || !held[ws] {
			if it.rec.RevokedAt != nil {
				orphans = append(orphans, unheldSticky(it, kept, gen, now))
			}
			if known {
				res.bad++
			} else {
				res.skipped++
			}
			continue
		}
		groups[ws] = append(groups[ws], it)
	}
	order := make([]uuid.UUID, 0, len(groups))
	for ws := range groups {
		order = append(order, ws)
	}
	slices.SortFunc(order, compareIDs)
	// The workspaces' rows, before any token row (DB25 step 3), in one
	// id-ordered pass: FOR UPDATE where the commit may delete a token
	// identity or its grants, else FOR KEY SHARE, what a new token's foreign
	// key takes anyway, taken first, so the commit waits behind a
	// quarantine, a move or a grant write of the workspace (each locks the
	// row FOR UPDATE, then the token rows or perms) instead of inverting
	// against it. A token listed twice counts as one that may: a later
	// record of it may drop the identity an earlier one made.
	if err := lockPageWorkspacesTx(ctx, tx, order, func(ws uuid.UUID) ([]uuid.UUID, bool) {
		ids := make([]uuid.UUID, 0, len(groups[ws]))
		seen, twice := map[uuid.UUID]bool{}, false
		for _, it := range groups[ws] {
			twice = twice || seen[it.id]
			seen[it.id] = true
			ids = append(ids, it.id)
		}
		return ids, twice
	}); err != nil {
		return res, err
	}
	for _, ws := range order {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, ws.String()); err != nil {
			return res, err
		}
		// The live numbers its records name, likewise, before its token
		// rows: a new perm's foreign key takes this lock, and a number's
		// deletion locks the number before it deletes its perms.
		if devices := namedDevices(groups[ws]); len(devices) > 0 {
			if _, err := tx.Exec(ctx, `SELECT 1 FROM devices WHERE id = ANY ($1) ORDER BY id FOR KEY SHARE`, devices); err != nil {
				return res, err
			}
		}
		g := tokenGroup{ws: ws, gen: gen, state: state, now: now, byID: byID, bySelector: bySelector, sticky: sticky, full: full}
		got, err := t.applyGroupTx(ctx, tx, g, groups[ws])
		if err != nil {
			return res, err
		}
		res.add(got)
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', '', true)`); err != nil {
		return res, err
	}
	if len(orphans) > 0 {
		res.narrowed = true
		if err := writeStickyTx(ctx, tx, orphans); err != nil {
			return res, err
		}
	}
	// After every workspace's rows, as retention deletes them (DB25): the
	// stops, then the dates of the selectors Wappie does not hold.
	if err := narrowStopsTx(ctx, tx, seen); err != nil {
		return res, err
	}
	if err := dateSelectorsTx(ctx, tx, seen, now); err != nil {
		return res, err
	}
	return res, nil
}

// unheldUntil is how long the sticky set keeps the revocation of a record
// whose token Wappie holds no row of: its selector's until when Wappie keeps
// that (kept: the stored created_at + 365 days); else, for a valid record
// (good: it decoded and passed Validate and the key check, so it expires by
// its created_at + 365 days), that created_at + 365 days, one past Wappie's
// clock counting as now so that a skewed one never lengthens it; else, a bad
// record, Wappie's clock + 365 days, never a time of its own (H2): a bad
// record's created_at may say anything, and a row it shortened or never made
// would let a later unrevoked record of the token, as after a platform
// restore, make a live row. That one is kept only until the leader's lookup
// by id learns the token's own date from the platform (TokenLookupAnswered).
func unheldUntil(rec kc.TokenRecord, kept *selectorRow, good bool, now time.Time) time.Time {
	switch {
	case kept != nil:
		return kept.Until
	case !good, rec.CreatedAt.IsZero(), rec.CreatedAt.After(now):
		return now.Add(tokenKeep)
	default:
		return rec.CreatedAt.Add(tokenKeep)
	}
}

// unheldSticky is the sticky write of the revocation of item it, of
// generation gen, whose token Wappie holds no row of (kept: the selector
// Wappie keeps of it, if any), to unheldUntil; once that has passed, the
// token's records have left the feed: no row is made, and one there is only
// lowered to it. A bad record's, dated by Wappie's clock alone, is marked
// so (clock): the leader's lookup by id asks the platform for the token's
// own date (TokenLookupAnswered).
func unheldSticky(it tokenItem, kept *selectorRow, gen uuid.UUID, now time.Time) stickyWrite {
	until := unheldUntil(it.rec, kept, it.bad == "", now)
	w := stickyWrite{id: it.id, revokedAt: revokedTime(it.rec, now), until: until, lowerOnly: !until.After(now)}
	if it.bad != "" && kept == nil {
		w.clock, w.gen = true, gen
	}
	return w
}

// stopSeen is a record of a selector the applier saw, and its token's
// created_at + 365 days: a stop of a selector Wappie never held goes then at
// the latest (retention), when the token would have expired anyway.
type stopSeen struct {
	selector string
	token    uuid.UUID
	until    time.Time
}

// seenStop is what a record tells of its token's selector: the one Wappie
// keeps for the token, with its until; else, from a valid record alone (it
// decoded and passed Validate and the key check, so it expires by its
// created_at + 365 days), the record's own selector with that created_at +
// 365 days; nothing otherwise. A bad record never lowers a stop's
// record_until: its created_at may say anything, and a stop it let go
// would leave the token's later good record unstopped. A bad record of a
// token Wappie knows never tells more than Wappie keeps.
func seenStop(it tokenItem, byID map[uuid.UUID]selectorRow) (stopSeen, bool) {
	if s, ok := byID[it.id]; ok {
		return stopSeen{selector: s.Selector, token: it.id, until: s.Until}, true
	}
	if it.bad != "" || !kc.ValidSelector(it.rec.Selector) || it.rec.CreatedAt.IsZero() {
		return stopSeen{}, false
	}
	return stopSeen{selector: it.rec.Selector, token: it.id, until: it.rec.CreatedAt.Add(tokenKeep)}, true
}

// dateSelectorsTx keeps the date of each selector seen that no selectors row
// holds (one this commit inserted included): the earliest until of its
// valid records, at most Wappie's clock + 365 days for a created_at ahead
// of it, only ever lowered, and none once it has passed. Retention reads it
// for a stop of that selector, whenever the stop was made: one made after
// the record still goes by the record's date. A selector another token
// holds, or Wappie's own, gets none: its stops go with that selectors row.
func dateSelectorsTx(ctx context.Context, tx pgx.Tx, seen []stopSeen, now time.Time) error {
	if len(seen) == 0 {
		return nil
	}
	n := len(seen)
	selectors, until := make([]string, n), make([]time.Time, n)
	for i, s := range seen {
		selectors[i], until[i] = s.selector, s.until
		if most := now.Add(tokenKeep); until[i].After(most) {
			until[i] = most
		}
	}
	_, err := tx.Exec(ctx, `INSERT INTO contract_token_dates (selector, until)
		SELECT u.selector, min(u.until) FROM unnest($1::text[], $2::timestamptz[]) AS u(selector, until)
		WHERE u.until > $3
		  AND NOT EXISTS (SELECT 1 FROM contract_token_selectors h WHERE h.selector = u.selector)
		GROUP BY u.selector ORDER BY u.selector
		ON CONFLICT (selector) DO UPDATE SET until = EXCLUDED.until WHERE contract_token_dates.until > EXCLUDED.until`,
		selectors, until, now)
	return err
}

// narrowStopsTx lowers the record_until of the stops of the selectors seen
// to their valid records' earliest until, in (selector, cause) order: never
// for a selector another token holds (a record's claim to it), never
// raising it, and with no write where it would not change. Only retention
// reads it, and the stops' trigger wakes nothing for it.
func narrowStopsTx(ctx context.Context, tx pgx.Tx, seen []stopSeen) error {
	if len(seen) == 0 {
		return nil
	}
	n := len(seen)
	selectors, tokens, until := make([]string, n), make([]uuid.UUID, n), make([]time.Time, n)
	for i, s := range seen {
		selectors[i], tokens[i], until[i] = s.selector, s.token, s.until
	}
	_, err := tx.Exec(ctx, `UPDATE contract_token_stops x SET record_until = l.until
		FROM (SELECT y.selector, y.cause, s.until FROM contract_token_stops y
		      JOIN (SELECT u.selector, min(u.until) AS until
		            FROM unnest($1::text[], $2::uuid[], $3::timestamptz[]) AS u(selector, token, until)
		            WHERE NOT EXISTS (SELECT 1 FROM contract_token_selectors h WHERE h.selector = u.selector AND h.token_id <> u.token)
		            GROUP BY u.selector) s ON s.selector = y.selector
		      WHERE y.record_until IS NULL OR y.record_until > s.until
		      ORDER BY y.selector, y.cause FOR UPDATE OF y) l
		WHERE x.selector = l.selector AND x.cause = l.cause AND (x.record_until IS NULL OR x.record_until > l.until)`,
		selectors, tokens, until)
	return err
}

// namedDevices are the numbers items' records name by a canonical UUID.
func namedDevices(items []tokenItem) []uuid.UUID {
	var out []uuid.UUID
	for _, it := range items {
		for _, item := range it.rec.Items {
			if kc.ValidUUID(item.ID) {
				out = append(out, uuid.MustParse(item.ID))
			}
		}
	}
	return out
}

// revokedTime is a revocation's time: the record's, or Wappie's clock for
// one that came with none (a zero revoked_at beside a revocation).
func revokedTime(rec kc.TokenRecord, now time.Time) time.Time {
	if rec.RevokedAt == nil || rec.RevokedAt.IsZero() {
		return now
	}
	return rec.RevokedAt.Time
}

// endedAt is when a revoked token ended, which its record's 30 days count
// from: its revocation's time, or its expiry's if earlier (a token revoked
// after it expired ended at its expiry; a zero expiry, -infinity, gives no
// time), never past Wappie's clock. A revocation Wappie learns of late (a
// restore's re-read of the feed, a turn-on after a time off) is forgotten
// at the next retention once its 30 days passed. The update moves the end
// back to an earlier expiry the row holds (tokenWrites.run).
func endedAt(revoked time.Time, expires pgtype.Timestamptz, now time.Time) time.Time {
	end := revoked
	if expires.Valid && expires.InfinityModifier == pgtype.Finite && expires.Time.Before(end) {
		end = expires.Time
	}
	if end.After(now) {
		return now
	}
	return end
}

// tokenGroup is what one workspace's records are applied against.
type tokenGroup struct {
	ws, gen    uuid.UUID
	state      tokenFeedState
	now        time.Time
	byID       map[uuid.UUID]selectorRow
	bySelector map[string]selectorRow
	sticky     map[uuid.UUID]stickyRow
	full       bool
}

// applyGroupTx applies one workspace's records under one savepoint. On an
// unexpected error it rolls back to it and redoes them record by record,
// each under its own: one that fails there is applied for its narrowings
// only, and one that fails even so gets an apply_failed stop of its
// selector, an ERROR, and is passed over, so no record holds back the
// revocations behind it.
func (t *Tokens) applyGroupTx(ctx context.Context, tx pgx.Tx, g tokenGroup, items []tokenItem) (applyResult, error) {
	var res applyResult
	err := savepoint(ctx, tx, func(sp pgx.Tx) error {
		var err error
		res, err = t.applyRoundsTx(ctx, sp, g, items, false)
		return err
	})
	if err == nil {
		return res, nil
	}
	if ctx.Err() != nil || !recordFault(err) {
		return res, err
	}
	obs.LoggerFrom(ctx).Warn("contract: a workspace's token records failed together; applying them one by one",
		"workspace", g.ws, "records", len(items), "error", err)
	res = applyResult{}
	for _, it := range items {
		var one applyResult
		err := savepoint(ctx, tx, func(sp pgx.Tx) error {
			var err error
			one, err = t.applyRoundsTx(ctx, sp, g, []tokenItem{it}, false)
			return err
		})
		if err != nil && (ctx.Err() != nil || !recordFault(err)) {
			return res, err
		}
		if err != nil {
			first := err
			err = savepoint(ctx, tx, func(sp pgx.Tx) error {
				var err error
				one, err = t.applyRoundsTx(ctx, sp, g, []tokenItem{it}, true)
				return err
			})
			if err == nil {
				// judgeRecord counted it bad: a narrowings-only apply is.
				obs.LoggerFrom(ctx).Warn("contract: a token record was applied for its narrowings only",
					append(tokenLogAttrs(it.rec), "error", first)...)
			}
		}
		if err != nil && (ctx.Err() != nil || !recordFault(err)) {
			return res, err
		}
		if err != nil {
			obs.LoggerFrom(ctx).Error("contract: a token record could not be applied; its token is stopped here",
				append(tokenLogAttrs(it.rec), "class", TokenErrorApplyFailed, "error", err)...)
			one = applyResult{failed: 1, narrowed: true}
			if err := stopApplyFailedTx(ctx, tx, it, g); err != nil {
				return res, err
			}
			if err := listFailedTx(ctx, tx, it, g); err != nil {
				return res, err
			}
		}
		res.add(one)
	}
	return res, nil
}

// recordFault reports whether err is a record's own: what the database
// refused of its data (a data exception, an integrity constraint, a
// trigger's RAISE) or a Go error of its values, which the fallback works
// around. A deadlock, a serialization failure, a lock or statement timeout,
// a lost connection or an error of the statements themselves is the
// transaction's: it is rolled back whole, and retried (retryDeadlock) or
// returned, never taken for a bad record, which would stop tokens for a
// fault of no record's.
func recordFault(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return true
	}
	switch pgErr.Code[:2] {
	case "22", "23", "P0":
		return true
	}
	return false
}

// savepoint runs fn under a savepoint of tx: its writes stand when it
// returns nil, and are rolled back, leaving tx usable, when it fails.
func savepoint(ctx context.Context, tx pgx.Tx, fn func(pgx.Tx) error) error {
	sp, err := tx.Begin(ctx)
	if err != nil {
		return err
	}
	if err := fn(sp); err != nil {
		if rbErr := sp.Rollback(ctx); rbErr != nil {
			return errors.Join(err, rbErr)
		}
		return err
	}
	return sp.Commit(ctx)
}

// stopApplyFailedTx records Wappie's own stop of a record's token, by the
// selector it holds for it (else the record's), so token auth refuses it
// and the acknowledgement reports it suspended {local_rule}. It lifts when a
// later version applies cleanly.
func stopApplyFailedTx(ctx context.Context, tx pgx.Tx, it tokenItem, g tokenGroup) error {
	selector := it.rec.Selector
	if s, ok := g.byID[it.id]; ok {
		selector = s.Selector
	}
	if !kc.ValidSelector(selector) {
		return nil
	}
	_, err := tx.Exec(ctx, `INSERT INTO contract_token_stops (selector, cause, stopped_at, stopped_by)
		VALUES ($1, 'apply_failed', $2, 'wappie')
		ON CONFLICT (selector, cause) DO UPDATE SET stopped_at = EXCLUDED.stopped_at, lifted_at = NULL
		WHERE contract_token_stops.lifted_at IS NOT NULL`, selector, g.now)
	return err
}

// listFailedTx marks a token Wappie holds, whose record a page listed but
// could not apply even narrowed, as listed by the page (listed_gen), in a
// statement and a savepoint of its own: the platform listed it, so a reset's
// pass must not unlist it, which is terminal, for a fault of Wappie's own;
// the apply_failed stop refuses it meanwhile, and lifts when a later version
// applies. A by-id GET's record lists nothing. Should even this fail, the
// stop stands and the pass may unlist the token, which fails closed too.
func listFailedTx(ctx context.Context, tx pgx.Tx, it tokenItem, g tokenGroup) error {
	if _, held := g.byID[it.id]; !held || !g.full {
		return nil
	}
	err := savepoint(ctx, tx, func(sp pgx.Tx) error {
		_, err := sp.Exec(ctx, `UPDATE contract_tokens SET listed_gen = $2 WHERE id = $1 AND listed_gen IS DISTINCT FROM $2`, it.id, g.gen)
		return err
	})
	if err != nil && (ctx.Err() != nil || !recordFault(err)) {
		return err
	}
	if err != nil {
		obs.LoggerFrom(ctx).Warn("contract: a stopped token could not be marked listed; a reset's pass may unlist it",
			append(tokenLogAttrs(it.rec), "error", err)...)
	}
	return nil
}

// applyRoundsTx applies items in rounds in which each token appears once, in
// the page's order, so a set-based statement never meets one token twice.
// narrowOnly applies every record for its narrowings only (the fallback).
func (t *Tokens) applyRoundsTx(ctx context.Context, tx pgx.Tx, g tokenGroup, items []tokenItem, narrowOnly bool) (applyResult, error) {
	var res applyResult
	for len(items) > 0 {
		seen := map[uuid.UUID]bool{}
		var round, rest []tokenItem
		for _, it := range items {
			if seen[it.id] {
				rest = append(rest, it)
				continue
			}
			seen[it.id] = true
			round = append(round, it)
		}
		got, err := t.applyRoundTx(ctx, tx, g, round, narrowOnly)
		if err != nil {
			return res, err
		}
		res.add(got)
		items = rest
	}
	return res, nil
}

// storedToken is a contract_tokens row as the applier judges against it,
// read under its row lock.
type storedToken struct {
	CreatedBy  uuid.UUID
	CreatedAt  time.Time
	ExpiresAt  pgtype.Timestamptz
	Revoked    bool
	Generation *uuid.UUID
	Version    *int64
	Unlisted   bool
	KeyChanged bool
	// Identity is the token's hidden identity while it stands (not
	// dropped), nil otherwise.
	Identity *uuid.UUID
}

// expiredAt reports whether the stored expiry is at or before now.
func (s storedToken) expiredAt(now time.Time) bool {
	return s.ExpiresAt.InfinityModifier == pgtype.NegativeInfinity ||
		(s.ExpiresAt.InfinityModifier == pgtype.Finite && !s.ExpiresAt.Time.After(now))
}

// permKey is one perm of a token on a number.
type permKey struct {
	Device uuid.UUID
	Perm   string
}

// storedPerm is a contract_token_perms row.
type storedPerm struct {
	GrantedBy  uuid.UUID
	GrantedAt  time.Time
	State      string
	Code       *string
	Generation uuid.UUID
	Version    int64
}

// instanceKey is a grant instance as contract_token_removed keys it.
type instanceKey struct {
	Token     uuid.UUID
	Item      string
	Perm      string
	GrantedAt time.Time
}

// roundState is what Wappie holds of a round's tokens in its workspace.
type roundState struct {
	tokens map[uuid.UUID]storedToken
	perms  map[uuid.UUID]map[permKey]storedPerm
	// removed are the instances never to apply again, by cause.
	removed map[instanceKey]string
	live    map[uuid.UUID]bool
	pins    map[uuid.UUID][]byte
}

// readRoundTx reads, under the workspace's app.tenant_id, the round's token
// rows FOR UPDATE in id order (DB25 step 4), then their perms FOR UPDATE in
// key order (step 5), their removed instances, their pins, and which of the
// numbers their records name are live in the workspace.
func readRoundTx(ctx context.Context, tx pgx.Tx, ids []uuid.UUID, devices []uuid.UUID) (roundState, error) {
	st := roundState{tokens: map[uuid.UUID]storedToken{}, perms: map[uuid.UUID]map[permKey]storedPerm{},
		removed: map[instanceKey]string{}, live: map[uuid.UUID]bool{}, pins: map[uuid.UUID][]byte{}}
	rows, err := tx.Query(ctx, `SELECT id, created_by, created_at, expires_at, revoked_at IS NOT NULL, generation, version,
		unlisted_at IS NOT NULL, key_changed_at IS NOT NULL, CASE WHEN identity_dropped_at IS NULL THEN identity_user_id END
		FROM contract_tokens WHERE id = ANY ($1) ORDER BY id FOR UPDATE`, ids)
	if err != nil {
		return st, err
	}
	err = forEachRow(rows, func(row pgx.Rows) error {
		var id uuid.UUID
		var s storedToken
		if err := row.Scan(&id, &s.CreatedBy, &s.CreatedAt, &s.ExpiresAt, &s.Revoked, &s.Generation, &s.Version, &s.Unlisted, &s.KeyChanged,
			&s.Identity); err != nil {
			return err
		}
		st.tokens[id] = s
		return nil
	})
	if err != nil {
		return st, err
	}
	rows, err = tx.Query(ctx, `SELECT token_id, device_id, perm, granted_by, granted_at, state, code, generation, version
		FROM contract_token_perms WHERE token_id = ANY ($1) ORDER BY token_id, device_id, perm FOR UPDATE`, ids)
	if err != nil {
		return st, err
	}
	err = forEachRow(rows, func(row pgx.Rows) error {
		var id uuid.UUID
		var k permKey
		var p storedPerm
		if err := row.Scan(&id, &k.Device, &k.Perm, &p.GrantedBy, &p.GrantedAt, &p.State, &p.Code, &p.Generation, &p.Version); err != nil {
			return err
		}
		if st.perms[id] == nil {
			st.perms[id] = map[permKey]storedPerm{}
		}
		st.perms[id][k] = p
		return nil
	})
	if err != nil {
		return st, err
	}
	rows, err = tx.Query(ctx, `SELECT token_id, item, perm, granted_at, cause FROM contract_token_removed WHERE token_id = ANY ($1)`, ids)
	if err != nil {
		return st, err
	}
	err = forEachRow(rows, func(row pgx.Rows) error {
		var k instanceKey
		var cause string
		if err := row.Scan(&k.Token, &k.Item, &k.Perm, &k.GrantedAt, &cause); err != nil {
			return err
		}
		// A map key compares the location too: every instance key is UTC.
		k.GrantedAt = k.GrantedAt.UTC()
		st.removed[k] = cause
		return nil
	})
	if err != nil {
		return st, err
	}
	rows, err = tx.Query(ctx, `SELECT token_id, key FROM contract_token_pins WHERE token_id = ANY ($1)`, ids)
	if err != nil {
		return st, err
	}
	err = forEachRow(rows, func(row pgx.Rows) error {
		var id uuid.UUID
		var key []byte
		if err := row.Scan(&id, &key); err != nil {
			return err
		}
		st.pins[id] = key
		return nil
	})
	if err != nil {
		return st, err
	}
	// A deleted number is no live one: the quarantine scope stays closed.
	rows, err = tx.Query(ctx, `SELECT id FROM devices WHERE id = ANY ($1) AND deleted_at IS NULL`, devices)
	if err != nil {
		return st, err
	}
	err = forEachRow(rows, func(row pgx.Rows) error {
		var id uuid.UUID
		if err := row.Scan(&id); err != nil {
			return err
		}
		st.live[id] = true
		return nil
	})
	return st, err
}

// tokenWrites are a round's writes, computed in Go from its records and what
// Wappie holds, then run set-based.
type tokenWrites struct {
	selectors []selectorRow
	inserts   []tokenInsert
	updates   []tokenUpdate
	drops     []permDrop
	grants    []grantDrop
	// identities are the tokens whose hidden identity goes (a
	// revocation), its grants with it.
	identities []uuid.UUID
	keeps      []permKeep
	adds       []permAdd
	removed    []removedRow
	refusals   []tokenRefusalRow
	held       []heldRow
	sticky     []stickyWrite
	pins       []pinRow
	lifts      []string
}

type tokenInsert struct {
	id                   uuid.UUID
	name                 string
	createdBy            uuid.UUID
	createdAt            time.Time
	terms                []byte
	expiresAt            pgtype.Timestamptz
	revokedAt            *time.Time
	reason               *string
	version, seq         int64
	record               []byte
	ended                *time.Time
	generation, listedAt uuid.UUID
}

// tokenUpdate is one held token's row after a record: whole (full) for a
// good record of a higher version, else its narrowings only.
type tokenUpdate struct {
	id           uuid.UUID
	full         bool
	name         string
	terms        []byte
	expiresAt    pgtype.Timestamptz
	revokedAt    *time.Time
	reason       *string
	version, seq int64
	record       []byte
	ended        *time.Time
	bump         bool
}

type permDrop struct {
	token  uuid.UUID
	device uuid.UUID
	perm   string
	cause  string
}

// grantDrop is a token identity's grants on a number, at every epoch,
// deleted in the write that dropped the token's Read there (design 3.5).
type grantDrop struct {
	identity uuid.UUID
	device   uuid.UUID
}

type permKeep struct {
	token   uuid.UUID
	device  uuid.UUID
	perm    string
	version int64
}

type permAdd struct {
	token     uuid.UUID
	device    uuid.UUID
	perm      string
	grantedBy uuid.UUID
	grantedAt time.Time
	version   int64
}

// removedRow is a grant instance never to apply again: its giver is not
// kept, since nothing reads it.
type removedRow struct {
	token     uuid.UUID
	item      string
	perm      string
	grantedAt time.Time
	cause     string
}

// tokenRefusalRow is one entry of the acknowledgement's refused list, and
// when it was queued, as AckBody read it.
type tokenRefusalRow struct {
	token    uuid.UUID
	version  int64
	item     string
	perm     string
	code     string
	queuedAt time.Time
}

// heldRow is a token Wappie holds narrower than a record of a reset's
// generation lists it.
type heldRow struct {
	token      uuid.UUID
	revoked    bool
	expiresAt  *time.Time
	removed    []kc.HeldPerm
	readingKey *string
}

// stickyWrite is a revocation, an expiry or an unlisting that sticks.
type stickyWrite struct {
	id        uuid.UUID
	revokedAt time.Time
	expiresAt pgtype.Timestamptz
	ended     string
	until     time.Time
	// lowerOnly: until has passed, so no row is made, and a row there only
	// gets its until lowered to it (the next retention lets it go).
	lowerOnly bool
	// clock: until is Wappie's clock + 365 days, from a bad record of gen
	// (unheldSticky); a row stays so marked only while every write of it
	// is.
	clock bool
	gen   uuid.UUID
}

type pinRow struct {
	token        uuid.UUID
	key          []byte
	fingerprint  string
	registeredAt time.Time
	until        time.Time
}

// applyRoundTx judges and writes one round of a workspace's records.
func (t *Tokens) applyRoundTx(ctx context.Context, tx pgx.Tx, g tokenGroup, items []tokenItem, narrowOnly bool) (applyResult, error) {
	var res applyResult
	ids := make([]uuid.UUID, 0, len(items))
	for _, it := range items {
		ids = append(ids, it.id)
	}
	st, err := readRoundTx(ctx, tx, ids, namedDevices(items))
	if err != nil {
		return res, err
	}
	var w tokenWrites
	for _, it := range items {
		t.judgeRecord(ctx, g, st, it, narrowOnly, &w, &res)
	}
	if err := w.run(ctx, tx, g); err != nil {
		return res, err
	}
	res.pending = len(w.adds)
	res.held += len(w.held)
	res.refused += len(w.refusals)
	if len(w.drops) > 0 || len(w.held) > 0 || len(w.refusals) > 0 || len(w.sticky) > 0 {
		res.narrowed = true
	}
	for _, u := range w.updates {
		if u.bump || u.revokedAt != nil {
			res.narrowed = true
		}
	}
	return res, nil
}

// judgeRecord decides, in Go, what one record does to the token Wappie holds
// of it (the plan's 4.2) and adds that to w.
func (t *Tokens) judgeRecord(ctx context.Context, g tokenGroup, st roundState, it tokenItem, narrowOnly bool, w *tokenWrites, res *applyResult) {
	rec := it.rec
	stored, holds := st.tokens[it.id]
	sel, known := g.byID[it.id]
	bad := it.bad
	if narrowOnly && bad == "" {
		bad = tokenRefusedInvalid
	}
	revoked := rec.RevokedAt != nil
	expires := recordExpiry(rec)
	s, sticks := g.sticky[it.id]
	// Held (the design's 3.3) is told only in a reset's pass, and of an
	// unlisted token, whose ending is the pass's.
	inPass := g.state.PassGeneration != nil && *g.state.PassGeneration == g.gen && !g.state.PassDone

	if !holds {
		// A selector Wappie keeps with no token row (its workspace's row is
		// gone) or one another token holds: never a live row from it.
		other, taken := g.bySelector[rec.Selector]
		if bad == "" && (known || (taken && other.Token != it.id)) {
			bad = tokenRefusedInvalid
		}
		if bad != "" {
			res.bad++
			var kept *selectorRow
			if known {
				kept = &sel
			}
			// Its until from its own created_at only when it is valid
			// (it.bad unset: it passed Validate and the key check, though
			// refused here for its selector or narrowed only by the
			// fallback).
			if revoked {
				w.sticky = append(w.sticky, unheldSticky(it, kept, g.gen, g.now))
			}
			t.refuseNew(ctx, it, bad, nil, w)
			return
		}
		if sticks && !revoked && (s.Revoked || s.Ended != nil) {
			// A token Wappie holds only in the sticky set (the revocation
			// of a record it could not hold): a later record that lists it
			// unrevoked, as after a platform restore, is applied for its
			// narrowings only, of which there is none to store, and never
			// makes a live row (M8). In a reset's pass the platform is told
			// Wappie holds it revoked, or expiring earlier.
			res.bad++
			h := heldRow{token: it.id, revoked: s.Revoked || *s.Ended != "expired"}
			if s.Earliest != nil {
				h.expiresAt = heldExpiry(pgtype.Timestamptz{Time: *s.Earliest, Valid: true}, expires)
			}
			if inPass && (h.revoked || h.expiresAt != nil) {
				w.held = append(w.held, h)
			}
			return
		}
		t.insertToken(ctx, g, st, it, w)
		return
	}

	until := stored.CreatedAt.Add(tokenKeep)
	// The immutable members are the stored ones; a record that differs in
	// any is bad.
	if bad == "" && (rec.Selector != sel.Selector || !sameHash(rec.Hash, sel.Hash) || rec.WorkspaceID != g.ws.String() ||
		rec.CreatedBy != stored.CreatedBy.String() || !rec.CreatedAt.Truncate(time.Microsecond).Equal(stored.CreatedAt)) {
		bad = tokenRefusedInvalid
	}
	ended := stored.Revoked || stored.Unlisted || s.Ended != nil || stored.expiredAt(g.now)
	higher := stored.Generation == nil || *stored.Generation != g.gen || stored.Version == nil || rec.Version > *stored.Version
	if bad == "" && !ended && !higher {
		// An older or the same version: Wappie holds it already. It lists
		// the token in a reset's pass all the same.
		w.updates = append(w.updates, tokenUpdate{id: it.id, expiresAt: stored.ExpiresAt})
		return
	}
	full := bad == "" && !ended
	if !full {
		res.bad++
	}
	u := tokenUpdate{id: it.id, full: full, expiresAt: expires}
	if revoked && !stored.Revoked {
		at := revokedTime(rec, g.now)
		reason := kc.RevokedInConsole
		if rec.RevokedReason != nil && slices.Contains(kc.RevokedReasons(), *rec.RevokedReason) {
			reason = *rec.RevokedReason
		}
		u.revokedAt, u.reason, u.ended = &at, &reason, new(endedAt(at, expires, g.now))
	}
	if revoked {
		w.sticky = append(w.sticky, stickyWrite{id: it.id, revokedAt: revokedTime(rec, g.now), until: until})
		if stored.Identity != nil {
			w.identities = append(w.identities, it.id)
		}
	}
	if full {
		u.name = rec.Name
		u.terms = marshalTerms(rec.Terms)
		u.version, u.seq, u.record = rec.Version, it.seq, it.raw
		w.lifts = append(w.lifts, sel.Selector)
	}

	// What the record lists of the workspace's live numbers, by perm.
	listed, unknown := listedPerms(rec, st.live)
	perms := st.perms[it.id]
	keys := make([]permKey, 0, len(perms))
	for k := range perms {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, comparePermKeys)
	for _, k := range keys {
		p := perms[k]
		l, ok := listed[k]
		switch {
		case !ok:
			w.drops = append(w.drops, permDrop{token: it.id, device: k.Device, perm: k.Perm, cause: "dropped"})
			u.bump = true
			if k.Perm == kc.CanRead && stored.Identity != nil {
				w.grants = append(w.grants, grantDrop{identity: *stored.Identity, device: k.Device})
			}
		case full && (l.GrantedBy != p.GrantedBy.String() || !l.GrantedAt.Truncate(time.Microsecond).Equal(p.GrantedAt)):
			// Another grant instance in place of the stored one: the
			// stored one goes, and the new one is judged afresh below. A
			// Read given again is a Read dropped (the feed carries only a
			// token's latest version, so an ungrant and a grant between two
			// reads of it arrive so): its grants go with the old instance,
			// and only a fresh seal under the new one opens the number.
			w.drops = append(w.drops, permDrop{token: it.id, device: k.Device, perm: k.Perm, cause: "dropped"})
			u.bump = true
			if k.Perm == kc.CanRead && stored.Identity != nil {
				w.grants = append(w.grants, grantDrop{identity: *stored.Identity, device: k.Device})
			}
		default:
			delete(listed, k)
			if full && p.Generation != g.gen {
				// Kept through a reset and listed again: it is the new
				// generation's now, and a refusal is told again.
				w.keeps = append(w.keeps, permKeep{token: it.id, device: k.Device, perm: k.Perm, version: rec.Version})
				if p.State == tokenRefused && p.Code != nil {
					w.refusals = append(w.refusals, tokenRefusalRow{token: it.id, version: rec.Version, item: k.Device.String(), perm: k.Perm, code: *p.Code})
				}
			}
		}
	}
	if full {
		var removedHeld []kc.HeldPerm
		for _, k := range sortedPermKeys(listed) {
			l := listed[k]
			grantedBy, at := uuid.MustParse(l.GrantedBy), l.GrantedAt.Truncate(time.Microsecond).UTC()
			inst := instanceKey{Token: it.id, Item: k.Device.String(), Perm: k.Perm, GrantedAt: at}
			switch st.removed[inst] {
			case "":
			case "item_deleted", "item_moved":
				// The number left the workspace: a late record of the same
				// grant is refused as no such item.
				w.refusals = append(w.refusals, tokenRefusalRow{token: it.id, version: rec.Version, item: inst.Item, perm: k.Perm, code: tokenRefusedUnknown})
				continue
			case "dropped", "reset":
				removedHeld = append(removedHeld, kc.HeldPerm{Item: inst.Item, Perm: k.Perm})
				continue
			default:
				continue
			}
			if g.state.ResetTrustedThrough != nil && at.Before(*g.state.ResetTrustedThrough) {
				// Granted before the reset and not held at it: never
				// applied again, and held off.
				w.removed = append(w.removed, removedRow{token: it.id, item: inst.Item, perm: k.Perm, grantedAt: at, cause: "reset"})
				removedHeld = append(removedHeld, kc.HeldPerm{Item: inst.Item, Perm: k.Perm})
				continue
			}
			w.adds = append(w.adds, permAdd{token: it.id, device: k.Device, perm: k.Perm, grantedBy: grantedBy, grantedAt: at, version: rec.Version})
		}
		for _, x := range unknown {
			w.removed = append(w.removed, x.removed)
			if kc.ValidItemID(x.removed.item) && rec.Version >= 1 {
				w.refusals = append(w.refusals, tokenRefusalRow{token: it.id, version: rec.Version, item: x.removed.item, perm: x.removed.perm, code: tokenRefusedUnknown})
			}
		}
		if rec.ReadingKey != nil {
			if key, err := decodeReadingKey(rec.ReadingKey.Key); err == nil {
				w.pins = append(w.pins, pinRow{token: it.id, key: key, fingerprint: rec.ReadingKey.Fingerprint,
					registeredAt: rec.ReadingKey.RegisteredAt.Time, until: until})
			}
		}
		h := heldRow{token: it.id, removed: removedHeld, expiresAt: heldExpiry(stored.ExpiresAt, expires)}
		if rec.ReadingKey == nil {
			if pin, ok := st.pins[it.id]; ok {
				fp := readingKeyFingerprint(pin)
				h.readingKey = &fp
			}
		}
		if inPass && (len(h.removed) > 0 || h.expiresAt != nil || h.readingKey != nil) {
			w.held = append(w.held, h)
		}
	} else {
		// An unlisted or revoked token is never revived: the platform is
		// told Wappie holds it revoked (design 3.3). One expired by Wappie's
		// clock, or a bad record's, is told in a reset's pass the earlier
		// expiry Wappie keeps, as a full record's is.
		h := heldRow{token: it.id}
		h.revoked = ended && !revoked && (stored.Unlisted || (inPass && (stored.Revoked || (s.Ended != nil && *s.Ended != "expired"))))
		if inPass {
			h.expiresAt = heldExpiry(stored.ExpiresAt, expires)
		}
		if h.revoked || h.expiresAt != nil {
			w.held = append(w.held, h)
		}
		if bad != "" {
			t.refuseNew(ctx, it, bad, perms, w)
		}
	}
	w.updates = append(w.updates, u)
}

// insertToken adds a token Wappie holds no row of, from its first good
// record: its selector, its row, its pending grants on the workspace's live
// numbers, and its pin.
func (t *Tokens) insertToken(ctx context.Context, g tokenGroup, st roundState, it tokenItem, w *tokenWrites) {
	rec := it.rec
	hash, err := hex.DecodeString(rec.Hash)
	if err != nil {
		// Validate checked it: 64 lowercase hex digits.
		obs.LoggerFrom(ctx).Error("contract: a good token record's hash does not decode", tokenLogAttrs(rec)...)
		return
	}
	until := rec.CreatedAt.Add(tokenKeep)
	w.selectors = append(w.selectors, selectorRow{Selector: rec.Selector, Token: it.id, Tenant: g.ws, Hash: hash, Until: until})
	ins := tokenInsert{id: it.id, name: rec.Name, createdBy: uuid.MustParse(rec.CreatedBy), createdAt: rec.CreatedAt.Time,
		terms: marshalTerms(rec.Terms), expiresAt: recordExpiry(rec), version: rec.Version, seq: it.seq, record: it.raw,
		generation: g.gen, listedAt: g.gen}
	if rec.RevokedAt != nil {
		at, reason := revokedTime(rec, g.now), *rec.RevokedReason
		ins.revokedAt, ins.reason, ins.ended = &at, &reason, new(endedAt(at, ins.expiresAt, g.now))
		w.sticky = append(w.sticky, stickyWrite{id: it.id, revokedAt: at, until: until})
	}
	w.inserts = append(w.inserts, ins)
	listed, unknown := listedPerms(rec, st.live)
	for _, k := range sortedPermKeys(listed) {
		l := listed[k]
		grantedBy, at := uuid.MustParse(l.GrantedBy), l.GrantedAt.Truncate(time.Microsecond).UTC()
		if st.removed[instanceKey{Token: it.id, Item: k.Device.String(), Perm: k.Perm, GrantedAt: at}] != "" {
			continue
		}
		w.adds = append(w.adds, permAdd{token: it.id, device: k.Device, perm: k.Perm, grantedBy: grantedBy, grantedAt: at, version: rec.Version})
	}
	for _, x := range unknown {
		w.removed = append(w.removed, x.removed)
		if kc.ValidItemID(x.removed.item) {
			w.refusals = append(w.refusals, tokenRefusalRow{token: it.id, version: rec.Version, item: x.removed.item, perm: x.removed.perm, code: tokenRefusedUnknown})
		}
	}
	if rec.ReadingKey != nil {
		if key, err := decodeReadingKey(rec.ReadingKey.Key); err == nil {
			w.pins = append(w.pins, pinRow{token: it.id, key: key, fingerprint: rec.ReadingKey.Fingerprint,
				registeredAt: rec.ReadingKey.RegisteredAt.Time, until: until})
		}
	}
	w.lifts = append(w.lifts, rec.Selector)
}

// refuseNew queues a bad record's refusals: each perm it lists that Wappie
// does not hold as that instance, with the record's code, when the entry
// itself would decode (a token id, a version of at least 1, a valid item id
// and a perm); one that would not is only logged, so it never makes the
// whole acknowledgement invalid.
func (t *Tokens) refuseNew(ctx context.Context, it tokenItem, code string, perms map[permKey]storedPerm, w *tokenWrites) {
	for _, item := range it.rec.Items {
		for _, p := range item.Perms {
			if kc.ValidUUID(item.ID) {
				if s, ok := perms[permKey{Device: uuid.MustParse(item.ID), Perm: p.Perm}]; ok && p.GrantedBy == s.GrantedBy.String() &&
					p.GrantedAt.Truncate(time.Microsecond).Equal(s.GrantedAt) {
					continue
				}
			}
			if it.rec.Version < 1 || !kc.ValidItemID(item.ID) || !slices.Contains([]string{kc.CanRead, kc.CanSend, kc.CanAct, kc.CanManage}, p.Perm) {
				obs.LoggerFrom(ctx).Warn("contract: a bad token record's grant is refused, but cannot be told", tokenLogAttrs(it.rec)...)
				continue
			}
			w.refusals = append(w.refusals, tokenRefusalRow{token: it.id, version: it.rec.Version, item: item.ID, perm: p.Perm, code: code})
		}
	}
}

// unknownPerm is a perm on an item that is no live number of the workspace.
type unknownPerm struct{ removed removedRow }

// listedPerms are a good record's perms on the workspace's live numbers, by
// key, and the perms on any other item id (not a canonical UUID, or no live
// number of the workspace): those are item_unknown, never a perm row (H1).
func listedPerms(rec kc.TokenRecord, live map[uuid.UUID]bool) (map[permKey]kc.TokenPerm, []unknownPerm) {
	listed := map[permKey]kc.TokenPerm{}
	var unknown []unknownPerm
	for _, item := range rec.Items {
		ok := kc.ValidUUID(item.ID) && item.Kind == kc.ItemNumber && live[uuid.MustParse(item.ID)]
		for _, p := range item.Perms {
			if !slices.Contains([]string{kc.CanRead, kc.CanSend, kc.CanManage}, p.Perm) || !kc.ValidUUID(p.GrantedBy) || p.GrantedAt.IsZero() {
				continue
			}
			if !ok {
				unknown = append(unknown, unknownPerm{removedRow{token: uuid.MustParse(rec.ID), item: item.ID, perm: p.Perm,
					grantedAt: p.GrantedAt.Truncate(time.Microsecond), cause: "item_unknown"}})
				continue
			}
			listed[permKey{Device: uuid.MustParse(item.ID), Perm: p.Perm}] = p
		}
	}
	return listed, unknown
}

func comparePermKeys(a, b permKey) int {
	if c := compareIDs(a.Device, b.Device); c != 0 {
		return c
	}
	switch {
	case a.Perm < b.Perm:
		return -1
	case a.Perm > b.Perm:
		return 1
	}
	return 0
}

func sortedPermKeys(m map[permKey]kc.TokenPerm) []permKey {
	keys := make([]permKey, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, comparePermKeys)
	return keys
}

// heldExpiry is the expiry Wappie keeps when it is earlier than a record's
// (a held entry's expires_at), else nil: a -infinity one (a zero expiry kept)
// is no time to tell, and a record's -infinity is no later one.
func heldExpiry(kept, rec pgtype.Timestamptz) *time.Time {
	if kept.InfinityModifier != pgtype.Finite || rec.InfinityModifier != pgtype.Finite || !kept.Time.Before(rec.Time) {
		return nil
	}
	at := kept.Time
	return &at
}

// recordExpiry is a record's expires_at as stored: -infinity for a zero one
// (a partly decoded record's "earliest"), so LEAST never loses it.
func recordExpiry(rec kc.TokenRecord) pgtype.Timestamptz {
	if rec.ExpiresAt.IsZero() {
		return pgtype.Timestamptz{InfinityModifier: pgtype.NegativeInfinity, Valid: true}
	}
	return pgtype.Timestamptz{Time: rec.ExpiresAt.Time, Valid: true}
}

func marshalTerms(terms *kc.TokenTerms) []byte {
	if terms == nil {
		return nil
	}
	b, err := json.Marshal(terms)
	if err != nil {
		return nil
	}
	return b
}

func sameHash(text string, stored []byte) bool {
	b, err := hex.DecodeString(text)
	return err == nil && len(text) == 64 && bytes.Equal(b, stored)
}

// run writes a round, in DB25's order within the workspace: the selectors
// and token rows, then the perms, then what the perms leave behind
// (removed instances), then the rows of no lock order (the queues, the
// sticky set, the pins, the stops).
func (w *tokenWrites) run(ctx context.Context, tx pgx.Tx, g tokenGroup) error {
	if len(w.selectors) > 0 {
		n := len(w.selectors)
		sels, ids, tenants, hashes, until := make([]string, n), make([]uuid.UUID, n), make([]uuid.UUID, n), make([][]byte, n), make([]time.Time, n)
		for i, s := range w.selectors {
			sels[i], ids[i], tenants[i], hashes[i], until[i] = s.Selector, s.Token, s.Tenant, s.Hash, s.Until
		}
		tag, err := tx.Exec(ctx, `INSERT INTO contract_token_selectors (selector, token_id, tenant_id, hash, until)
			SELECT * FROM unnest($1::text[], $2::uuid[], $3::uuid[], $4::bytea[], $5::timestamptz[])`, sels, ids, tenants, hashes, until)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != int64(len(sels)) {
			return errors.New("store: a token's selector was taken under contract_token_state's lock")
		}
	}
	if len(w.inserts) > 0 {
		n := len(w.inserts)
		ids, names, by, created := make([]uuid.UUID, n), make([]string, n), make([]uuid.UUID, n), make([]time.Time, n)
		terms, records := make([]*string, n), make([]string, n)
		expires := make([]pgtype.Timestamptz, n)
		revoked, ended := make([]*time.Time, n), make([]*time.Time, n)
		reasons := make([]*string, n)
		versions, seqs := make([]int64, n), make([]int64, n)
		for i, in := range w.inserts {
			ids[i], names[i], by[i], created[i] = in.id, in.name, in.createdBy, in.createdAt
			if in.terms != nil {
				s := string(in.terms)
				terms[i] = &s
			}
			records[i], expires[i], revoked[i], reasons[i], ended[i] = string(in.record), in.expiresAt, in.revokedAt, in.reason, in.ended
			versions[i], seqs[i] = in.version, in.seq
		}
		if _, err := tx.Exec(ctx, `INSERT INTO contract_tokens (id, tenant_id, name, created_by, created_at, terms, expires_at,
				revoked_at, revoked_reason, generation, version, seq, record, applied_at, listed_gen, ended_at)
			SELECT u.id, $1, u.name, u.by, u.created, u.terms::jsonb, u.expires, u.revoked, u.reason, $2, u.version, NULLIF(u.seq, 0),
				u.record::jsonb, $3, CASE WHEN $16 THEN $2::uuid END, u.ended
			FROM unnest($4::uuid[], $5::text[], $6::uuid[], $7::timestamptz[], $8::text[], $9::timestamptz[], $10::timestamptz[],
				$11::text[], $12::bigint[], $13::bigint[], $14::text[], $15::timestamptz[])
				AS u(id, name, by, created, terms, expires, revoked, reason, version, seq, record, ended)`,
			g.ws, g.gen, g.now, ids, names, by, created, terms, expires, revoked, reasons, versions, seqs, records, ended, g.full); err != nil {
			return err
		}
	}
	if len(w.updates) > 0 {
		n := len(w.updates)
		ids, full, bump := make([]uuid.UUID, n), make([]bool, n), make([]bool, n)
		names, terms, records := make([]string, n), make([]*string, n), make([]*string, n)
		expires := make([]pgtype.Timestamptz, n)
		revoked, ended := make([]*time.Time, n), make([]*time.Time, n)
		reasons := make([]*string, n)
		versions, seqs := make([]int64, n), make([]int64, n)
		for i, u := range w.updates {
			ids[i], full[i], bump[i], names[i] = u.id, u.full, u.bump, u.name
			if u.terms != nil {
				s := string(u.terms)
				terms[i] = &s
			}
			if u.record != nil {
				s := string(u.record)
				records[i] = &s
			}
			expires[i], revoked[i], reasons[i], ended[i], versions[i], seqs[i] = u.expiresAt, u.revokedAt, u.reason, u.ended, u.version, u.seq
		}
		// The trigger bumps access_version on a column's narrowing; a perm
		// dropped bumps it here, the row being written anyway. A token's end
		// only moves back, to the earliest of its revocation and its expiry
		// (a finite one) once it has ended or this ends it: a revocation
		// earlier than the expiry the janitor ended it at, or an expiry
		// earlier than the revocation or than the expiry the janitor used,
		// is its end. Every end is at or before Wappie's clock, so the least
		// is too. A token that has only expired keeps none here: the janitor
		// ends it, with its identity and its sticky row.
		if _, err := tx.Exec(ctx, `UPDATE contract_tokens t SET
				name = CASE WHEN u.whole THEN u.name ELSE t.name END,
				terms = CASE WHEN u.whole THEN u.terms::jsonb ELSE t.terms END,
				expires_at = LEAST(t.expires_at, u.expires),
				revoked_at = coalesce(t.revoked_at, u.revoked),
				revoked_reason = coalesce(t.revoked_reason, u.reason),
				ended_at = CASE WHEN coalesce(t.ended_at, u.ended) IS NOT NULL THEN least(t.ended_at, u.ended,
					CASE WHEN isfinite(LEAST(t.expires_at, u.expires)) THEN LEAST(t.expires_at, u.expires) END) END,
				generation = CASE WHEN u.whole THEN $1 ELSE t.generation END,
				version = CASE WHEN u.whole THEN u.version ELSE t.version END,
				seq = CASE WHEN u.whole THEN coalesce(NULLIF(u.seq, 0), t.seq) ELSE t.seq END,
				record = CASE WHEN u.whole THEN u.record::jsonb ELSE t.record END,
				applied_at = CASE WHEN u.whole THEN $2 ELSE t.applied_at END,
				listed_gen = CASE WHEN $15 THEN $1 ELSE t.listed_gen END,
				access_version = t.access_version + CASE WHEN u.bump THEN 1 ELSE 0 END
			FROM unnest($3::uuid[], $4::bool[], $5::text[], $6::text[], $7::timestamptz[], $8::timestamptz[], $9::text[],
				$10::timestamptz[], $11::bigint[], $12::bigint[], $13::text[], $14::bool[])
				AS u(id, whole, name, terms, expires, revoked, reason, ended, version, seq, record, bump)
			WHERE t.id = u.id`,
			g.gen, g.now, ids, full, names, terms, expires, revoked, reasons, ended, versions, seqs, records, bump, g.full); err != nil {
			return err
		}
	}
	if len(w.drops) > 0 {
		n := len(w.drops)
		tokens, devices, perms, causes := make([]uuid.UUID, n), make([]uuid.UUID, n), make([]string, n), make([]string, n)
		for i, d := range w.drops {
			tokens[i], devices[i], perms[i], causes[i] = d.token, d.device, d.perm, d.cause
		}
		if _, err := tx.Exec(ctx, `WITH gone AS (
				DELETE FROM contract_token_perms p USING unnest($1::uuid[], $2::uuid[], $3::text[], $4::text[]) AS d(token, device, perm, cause)
				WHERE p.token_id = d.token AND p.device_id = d.device AND p.perm = d.perm
				RETURNING p.token_id, p.tenant_id, p.device_id, p.perm, p.granted_at, d.cause)
			INSERT INTO contract_token_removed (token_id, tenant_id, item, perm, granted_at, cause, at)
			SELECT token_id, tenant_id, device_id::text, perm, granted_at, cause, $5 FROM gone
			ON CONFLICT DO NOTHING`, tokens, devices, perms, causes, g.now); err != nil {
			return err
		}
	}
	if len(w.keeps) > 0 {
		n := len(w.keeps)
		tokens, devices, perms, versions := make([]uuid.UUID, n), make([]uuid.UUID, n), make([]string, n), make([]int64, n)
		for i, k := range w.keeps {
			tokens[i], devices[i], perms[i], versions[i] = k.token, k.device, k.perm, k.version
		}
		if _, err := tx.Exec(ctx, `UPDATE contract_token_perms p SET generation = $1, version = k.version
			FROM unnest($2::uuid[], $3::uuid[], $4::text[], $5::bigint[]) AS k(token, device, perm, version)
			WHERE p.token_id = k.token AND p.device_id = k.device AND p.perm = k.perm`, g.gen, tokens, devices, perms, versions); err != nil {
			return err
		}
	}
	if len(w.adds) > 0 {
		n := len(w.adds)
		tokens, devices, perms, by := make([]uuid.UUID, n), make([]uuid.UUID, n), make([]string, n), make([]uuid.UUID, n)
		at, versions := make([]time.Time, n), make([]int64, n)
		for i, a := range w.adds {
			tokens[i], devices[i], perms[i], by[i], at[i], versions[i] = a.token, a.device, a.perm, a.grantedBy, a.grantedAt, a.version
		}
		if _, err := tx.Exec(ctx, `INSERT INTO contract_token_perms (token_id, tenant_id, device_id, perm, granted_by, granted_at, generation, version)
			SELECT a.token, $1, a.device, a.perm, a.by, a.at, $2, a.version
			FROM unnest($3::uuid[], $4::uuid[], $5::text[], $6::uuid[], $7::timestamptz[], $8::bigint[]) AS a(token, device, perm, by, at, version)`,
			g.ws, g.gen, tokens, devices, perms, by, at, versions); err != nil {
			return err
		}
	}
	// The identities' grants and the identities (DB25 step 6), in the same
	// write: no tenants lock here, the commit took the workspace's row
	// before its token rows (lockPageWorkspacesTx).
	if err := dropTokenGrantsTx(ctx, tx, w.grants); err != nil {
		return err
	}
	if err := dropTokenIdentitiesTx(ctx, tx, g.now, w.identities); err != nil {
		return err
	}
	if err := insertRemovedTx(ctx, tx, g.ws, g.now, w.removed); err != nil {
		return err
	}
	if err := queueRefusalsTx(ctx, tx, w.refusals); err != nil {
		return err
	}
	if err := queueHeldTx(ctx, tx, g.gen, w.held); err != nil {
		return err
	}
	if err := writeStickyTx(ctx, tx, w.sticky); err != nil {
		return err
	}
	if err := pinTokenKeysTx(ctx, tx, g.ws, g.now, w.pins); err != nil {
		return err
	}
	if len(w.lifts) > 0 {
		if _, err := tx.Exec(ctx, `UPDATE contract_token_stops SET lifted_at = $2
			WHERE cause = 'apply_failed' AND lifted_at IS NULL AND selector = ANY ($1)`, w.lifts, g.now); err != nil {
			return err
		}
	}
	return nil
}

// insertRemovedTx records grant instances never to apply again, in the
// workspace of tx.
func insertRemovedTx(ctx context.Context, tx pgx.Tx, ws uuid.UUID, now time.Time, removed []removedRow) error {
	if len(removed) == 0 {
		return nil
	}
	n := len(removed)
	tokens, items, perms := make([]uuid.UUID, n), make([]string, n), make([]string, n)
	at, causes := make([]time.Time, n), make([]string, n)
	for i, r := range removed {
		tokens[i], items[i], perms[i], at[i], causes[i] = r.token, r.item, r.perm, r.grantedAt, r.cause
	}
	_, err := tx.Exec(ctx, `INSERT INTO contract_token_removed (token_id, tenant_id, item, perm, granted_at, cause, at)
		SELECT r.token, $1, r.item, r.perm, r.at, r.cause, $2
		FROM unnest($3::uuid[], $4::text[], $5::text[], $6::timestamptz[], $7::text[]) AS r(token, item, perm, at, cause)
		ON CONFLICT DO NOTHING`, ws, now, tokens, items, perms, at, causes)
	return err
}

// queueRefusalsTx queues refused entries for the acknowledgement; one queued
// already, unsent, stays as it is.
func queueRefusalsTx(ctx context.Context, tx pgx.Tx, refusals []tokenRefusalRow) error {
	if len(refusals) == 0 {
		return nil
	}
	n := len(refusals)
	tokens, versions, items, perms, codes := make([]uuid.UUID, n), make([]int64, n), make([]string, n), make([]string, n), make([]string, n)
	for i, r := range refusals {
		tokens[i], versions[i], items[i], perms[i], codes[i] = r.token, r.version, r.item, r.perm, r.code
	}
	_, err := tx.Exec(ctx, `INSERT INTO contract_token_refusals_out (token_id, version, item, perm, code)
		SELECT DISTINCT ON (token, version, item, perm) * FROM unnest($1::uuid[], $2::bigint[], $3::text[], $4::text[], $5::text[])
			AS r(token, version, item, perm, code)
		ON CONFLICT (token_id, version, item, perm) DO UPDATE SET code = EXCLUDED.code, queued_at = clock_timestamp(), sent_at = NULL
		WHERE contract_token_refusals_out.code IS DISTINCT FROM EXCLUDED.code`, tokens, versions, items, perms, codes)
	return err
}

// queueHeldTx merges held tokens into the acknowledgement's queue for gen:
// held revoked once, the earliest expiry, every perm kept off, and a pin's
// fingerprint; a change makes the entry due again.
func queueHeldTx(ctx context.Context, tx pgx.Tx, gen uuid.UUID, held []heldRow) error {
	for _, h := range held {
		removed := h.removed
		if removed == nil {
			removed = []kc.HeldPerm{}
		}
		raw, err := json.Marshal(removed)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO contract_token_held_out (token_id, generation, revoked, expires_at, removed, reading_key)
			VALUES ($1, $2, $3, $4, $5::jsonb, $6)
			ON CONFLICT (token_id, generation) DO UPDATE SET
				revoked = contract_token_held_out.revoked OR EXCLUDED.revoked,
				expires_at = CASE WHEN contract_token_held_out.expires_at IS NULL THEN EXCLUDED.expires_at
				                  WHEN EXCLUDED.expires_at IS NULL THEN contract_token_held_out.expires_at
				                  ELSE LEAST(contract_token_held_out.expires_at, EXCLUDED.expires_at) END,
				removed = (SELECT coalesce(jsonb_agg(DISTINCT e), '[]') FROM jsonb_array_elements(contract_token_held_out.removed || EXCLUDED.removed) e),
				reading_key = coalesce(EXCLUDED.reading_key, contract_token_held_out.reading_key),
				queued_at = clock_timestamp(), sent_at = NULL`,
			h.token, gen, h.revoked, h.expiresAt, string(raw), h.readingKey); err != nil {
			return err
		}
	}
	return nil
}

// writeStickyTx keeps revocations, expiries and unlistings in the sticky
// set: a row's revocation and ending are set once, and its earliest expiry
// and its until only lower (a token Wappie never held: a bad record's
// Wappie's clock + 365 days, then a valid record's created_at + 365 days).
// A write past its until makes no row, and lowers one there. A row is
// dated by Wappie's clock (clock_until, for the lookup by id) only while
// every write of it is: a valid record's clears it, and a bad record's
// takes its generation and has the lookup asked again.
func writeStickyTx(ctx context.Context, tx pgx.Tx, sticky []stickyWrite) error {
	if len(sticky) == 0 {
		return nil
	}
	slices.SortFunc(sticky, func(a, b stickyWrite) int { return compareIDs(a.id, b.id) })
	for _, s := range sticky {
		if s.lowerOnly {
			if _, err := tx.Exec(ctx, `UPDATE contract_token_sticky SET until = $2, clock_until = false, clock_gen = NULL,
				lookup_after = NULL, lookup_bad = 0 WHERE token_id = $1 AND until > $2`, s.id, s.until); err != nil {
				return err
			}
			continue
		}
		var revoked *time.Time
		if !s.revokedAt.IsZero() {
			revoked = &s.revokedAt
		}
		var expires *pgtype.Timestamptz
		if s.expiresAt.Valid {
			expires = &s.expiresAt
		}
		ended := s.ended
		if ended == "" && revoked != nil {
			ended = "revoked"
		}
		var endedPtr *string
		if ended != "" {
			endedPtr = &ended
		}
		var gen *uuid.UUID
		if s.clock {
			gen = &s.gen
		}
		if _, err := tx.Exec(ctx, `INSERT INTO contract_token_sticky (token_id, revoked_at, earliest_expires_at, ended, until, clock_until, clock_gen)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (token_id) DO UPDATE SET
				revoked_at = coalesce(contract_token_sticky.revoked_at, EXCLUDED.revoked_at),
				earliest_expires_at = CASE WHEN contract_token_sticky.earliest_expires_at IS NULL THEN EXCLUDED.earliest_expires_at
				                           WHEN EXCLUDED.earliest_expires_at IS NULL THEN contract_token_sticky.earliest_expires_at
				                           ELSE LEAST(contract_token_sticky.earliest_expires_at, EXCLUDED.earliest_expires_at) END,
				ended = coalesce(contract_token_sticky.ended, EXCLUDED.ended),
				until = LEAST(contract_token_sticky.until, EXCLUDED.until),
				clock_until = contract_token_sticky.clock_until AND EXCLUDED.clock_until,
				clock_gen = CASE WHEN contract_token_sticky.clock_until AND EXCLUDED.clock_until THEN EXCLUDED.clock_gen END,
				lookup_after = NULL, lookup_bad = 0`,
			s.id, revoked, expires, endedPtr, s.until, s.clock, gen); err != nil {
			return err
		}
	}
	return nil
}
