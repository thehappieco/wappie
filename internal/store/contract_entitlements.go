package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/pg"
)

// The contract's entitlements part on Wappie's side, in observe only
// (migration 0053; the platform's spec, section 15; E0 slice 17): the
// follower's mode and cursor, each workspace's last document, the bad
// documents owed to an acknowledgement, and the local brake.
// internal/membership speaks the contract and calls these; nothing here
// calls the platform, and nothing here enforces a document.
//
// One lock order for every writer of these rows, Restart's:
// contract_state, contract_workspaces (id order), contract_ent_state,
// contract_ent_docs (id order). The account side's hook
// (recordWorkspacesTx) takes contract_ent_state FOR SHARE after it wrote
// contract_workspaces; a page and a GET take contract_state FOR SHARE, then
// contract_ent_state, then the documents, and lock no contract_workspaces
// row: whether a workspace is named is a plain read. A writer of one
// document row alone (a GET's failure, the timeline's mark) holds nothing
// else.

// The entitlements modes (contract_ent_state.mode).
const (
	// EntOff: nothing of the part runs.
	EntOff = "off"
	// EntObserve: the feed is followed and acknowledged, the GETs sent,
	// and what each document would do logged; nothing is enforced.
	EntObserve = "observe"
	// EntEnforce is a later release's. This one's command refuses it, and
	// reads it as observe (EntState.Effective).
	EntEnforce = "enforce"
)

// The usage sender's switch (contract_ent_state.usage).
const (
	UsageOff = "off"
	UsageOn  = "on"
)

// The brakes' kinds (contract_ent_brakes.by_kind).
const (
	// BrakeOperator: an operator held the workspace at observe.
	BrakeOperator = "operator"
	// BrakeEnforceInE0: E0 held it on a document that said enforce, which
	// the platform never sends before Wappie's E2 (Q54, Q67; P7).
	BrakeEnforceInE0 = "enforce_in_e0"
)

// The classes of the entitlements part's ERRORs, kept by RecordError.
const (
	// ContractErrorEntFeedSilent: no entitlements feed page for 15
	// minutes.
	ContractErrorEntFeedSilent = "ent_feed_silent"
	// ContractErrorEntResetLoop: a second reset from the entitlements feed
	// within a minute, which waits the minute out.
	ContractErrorEntResetLoop = "ent_reset_loop"
	// ContractErrorEntAckFailing: no acknowledgement accepted for 10
	// minutes while the feed runs (the platform's doctor alerts then).
	ContractErrorEntAckFailing = "ent_ack_failing"
	// ContractErrorEntEnforceInE0: a document said enforce; the workspace
	// is held at observe, and the operator reports it at once.
	ContractErrorEntEnforceInE0 = "ent_enforce_in_e0"
)

// EntFreshFor is how long a workspace's document counts as fresh for its
// steps (the spec's 15.6): a step fires while freshness is under it at the
// step's at, and the part freezes past it.
const EntFreshFor = 24 * time.Hour

// EntState is contract_ent_state's one row, and the generation the
// account side holds.
type EntState struct {
	Mode   string
	ModeAt time.Time
	Usage  string
	// UsageAt is the usage switch's last change.
	UsageAt time.Time
	// FeedCursor is the next request's after, under Generation.
	FeedCursor int64
	// PublishedThrough is the last trusted one, from a page with more
	// false; nil before one and after a reset.
	PublishedThrough        *time.Time
	FirstReadAt, LastPageAt *time.Time
	FeedError               string
	FeedErrorAt             *time.Time
	AckedThrough            *int64
	AckedAt, AckDueAt       *time.Time
	AckUrgent               bool
	AckError                string
	AckErrorAt              *time.Time
	UnreadableGetNextAt     *time.Time
	UpdatedAt               time.Time
	// Generation is the account side's (contract_state), and ContractMode
	// the contract's.
	Generation          *uuid.UUID
	GenerationConfirmed bool
	ContractMode        string
}

// Effective is the mode this binary acts on: off, or observe for any other
// (enforce included: this release observes only).
func (s EntState) Effective() string {
	if s.Mode == EntOff {
		return EntOff
	}
	return EntObserve
}

// UsageEffective is the usage sender's switch as this binary acts on it:
// on only while the follower observes too.
func (s EntState) UsageEffective() string {
	if s.Effective() == EntObserve && s.Usage == UsageOn {
		return UsageOn
	}
	return UsageOff
}

const entStateColumns = `e.mode, e.mode_at, e.usage, e.usage_at, e.feed_cursor, e.published_through, e.first_read_at, e.last_page_at,
	coalesce(e.feed_error, ''), e.feed_error_at, e.acked_through, e.acked_at, e.ack_due_at, e.ack_urgent,
	coalesce(e.ack_error, ''), e.ack_error_at, e.unreadable_get_next_at, e.updated_at, s.generation, s.generation_confirmed, s.mode`

func scanEntState(row pgx.Row) (EntState, error) {
	var s EntState
	err := row.Scan(&s.Mode, &s.ModeAt, &s.Usage, &s.UsageAt, &s.FeedCursor, &s.PublishedThrough, &s.FirstReadAt, &s.LastPageAt,
		&s.FeedError, &s.FeedErrorAt, &s.AckedThrough, &s.AckedAt, &s.AckDueAt, &s.AckUrgent, &s.AckError, &s.AckErrorAt,
		&s.UnreadableGetNextAt, &s.UpdatedAt, &s.Generation, &s.GenerationConfirmed, &s.ContractMode)
	return s, err
}

// EntState reads contract_ent_state with the account side's generation.
func (c *Contract) EntState(ctx context.Context) (EntState, error) {
	return scanEntState(c.pool.QueryRow(ctx, `SELECT `+entStateColumns+` FROM contract_ent_state e CROSS JOIN contract_state s`))
}

var (
	// ErrEntMode is a mode this release does not switch to: enforce, or
	// one it does not know.
	ErrEntMode = errors.New("store: this release observes only (E0): entitlements are off or observe")
	// ErrEntUsage is a usage switch that is neither off nor on.
	ErrEntUsage = errors.New("store: usage is off or on")
	// ErrEntContractOff refuses observe and usage on while the contract is
	// off: the part rides on the contract's generation and secrets.
	ErrEntContractOff = errors.New("store: the contract is off; entitlements follow it")
	// ErrEntTellPlatform refuses off once the feed was read, unless the
	// operator says the platform was told: from its first acknowledgement
	// the platform's doctor alerts on documents left unacknowledged.
	ErrEntTellPlatform = errors.New("store: tell the platform first")
	// ErrEntEnforceHeld refuses the release of a brake while the
	// workspace's document says enforce.
	ErrEntEnforceHeld = errors.New("store: the workspace's document says enforce; this release keeps it held at observe")
	// ErrEntNoBrake is a release of a workspace that is not held.
	ErrEntNoBrake = errors.New("store: the workspace is not held")
)

// EntModeChange is what a switch of the follower's mode or the usage
// switch did.
type EntModeChange struct {
	From, To string
	Changed  bool
	// FirstReadAt is the feed's first page, nil before one.
	FirstReadAt *time.Time
}

// SetEntMode switches the follower's mode, contract_state first (the lock
// order). It refuses enforce (ErrEntMode), observe while the contract is
// off, and off once the feed was read unless platformTold. The mode's
// trigger wakes every process's contract loop (0053's contract_ent_mode).
func (c *Contract) SetEntMode(ctx context.Context, mode string, platformTold bool) (EntModeChange, error) {
	if mode != EntOff && mode != EntObserve {
		return EntModeChange{}, ErrEntMode
	}
	var out EntModeChange
	err := retryDeadlock(ctx, func() error {
		return pg.InTx(ctx, c.pool, func(tx pgx.Tx) error {
			state, err := lockStateTx(ctx, tx)
			if err != nil {
				return err
			}
			var from string
			var first *time.Time
			if err := tx.QueryRow(ctx, `SELECT mode, first_read_at FROM contract_ent_state FOR UPDATE`).Scan(&from, &first); err != nil {
				return err
			}
			out = EntModeChange{From: from, To: mode, FirstReadAt: first}
			if from == mode {
				return nil
			}
			switch {
			case mode == EntObserve && !state.On():
				return ErrEntContractOff
			case mode == EntOff && first != nil && !platformTold:
				return ErrEntTellPlatform
			}
			out.Changed = true
			_, err = tx.Exec(ctx, `UPDATE contract_ent_state SET mode = $1, mode_at = clock_timestamp(), updated_at = clock_timestamp()`, mode)
			return err
		})
	})
	return out, err
}

// SetEntUsage switches the usage sender, as SetEntMode does the follower:
// on refused while the contract is off. Usage runs only while the follower
// observes too (EntState.UsageEffective).
func (c *Contract) SetEntUsage(ctx context.Context, usage string) (EntModeChange, error) {
	if usage != UsageOff && usage != UsageOn {
		return EntModeChange{}, ErrEntUsage
	}
	var out EntModeChange
	err := retryDeadlock(ctx, func() error {
		return pg.InTx(ctx, c.pool, func(tx pgx.Tx) error {
			state, err := lockStateTx(ctx, tx)
			if err != nil {
				return err
			}
			var from string
			if err := tx.QueryRow(ctx, `SELECT usage FROM contract_ent_state FOR UPDATE`).Scan(&from); err != nil {
				return err
			}
			out = EntModeChange{From: from, To: usage}
			if from == usage {
				return nil
			}
			if usage == UsageOn && !state.On() {
				return ErrEntContractOff
			}
			out.Changed = true
			_, err = tx.Exec(ctx, `UPDATE contract_ent_state SET usage = $1, usage_at = clock_timestamp(), updated_at = clock_timestamp()`, usage)
			return err
		})
	})
	return out, err
}

// EntDoc is one valid document as the follower stores it: decoded by the
// caller, its raw bytes as received (a feed item's doc) or re-encoded (a
// GET's answer).
type EntDoc struct {
	Workspace  uuid.UUID
	Generation uuid.UUID
	Version    int64
	Raw        []byte
	FromGet    bool
	Doc        kc.EntitlementsDoc
}

// NewEntDoc is d as the store keeps it, raw its bytes; false when its ids
// do not parse (the kit validated them, so never).
func NewEntDoc(d kc.EntitlementsDoc, raw []byte, fromGet bool) (EntDoc, bool) {
	ws, err := uuid.Parse(d.WorkspaceID)
	if err != nil {
		return EntDoc{}, false
	}
	gen, err := uuid.Parse(d.Generation)
	if err != nil {
		return EntDoc{}, false
	}
	return EntDoc{Workspace: ws, Generation: gen, Version: d.Version, Raw: raw, FromGet: fromGet, Doc: d}, true
}

// EntRefusal is a bad document of a page of the app's generation: its seq,
// its workspace when that reads as a UUID (else nil), and its code.
type EntRefusal struct {
	Seq       int64
	Workspace *uuid.UUID
	Code      string
}

// EntPageItem is one item of a page, judged by the caller: a document to
// apply, or a refusal.
type EntPageItem struct {
	Seq     int64
	Doc     *EntDoc
	Refused *EntRefusal
}

// EntPage is one page of the entitlements feed of the generation the
// follower read, asked from After.
type EntPage struct {
	SeenGeneration   uuid.UUID
	After, NextAfter int64
	More             bool
	PublishedThrough time.Time
	Items            []EntPageItem
}

// The outcomes of one item (EntItemResult.Action), as the vectors name them.
const (
	EntApply  = "apply"
	EntKeep   = "keep"
	EntIgnore = "ignore"
	EntRefuse = "refuse"
	EntFresh  = "fresh"
	EntReset  = "reset"
)

// EntItemResult is what a page or a GET did with one document.
type EntItemResult struct {
	Seq       int64
	Workspace uuid.UUID
	Action    string
	// Prev is the document it replaced, raw, nil when none was held.
	Prev []byte
	// Braked: the workspace is held at observe (any brake). NewBrake: this
	// document's enforce set the enforce_in_e0 brake now (a new one, or an
	// operator's it found in place).
	Braked, NewBrake bool
	Doc              *EntDoc
	Refused          *EntRefusal
}

// EntPageResult is what CommitEntPage did.
type EntPageResult struct {
	// Committed is false when the generation or the cursor moved since the
	// page was asked: nothing was stored.
	Committed bool
	Items     []EntItemResult
	// Urgent: the acknowledgement goes at once.
	Urgent bool
	// Ahead: the page's published_through was past the clock by more than
	// ContractClockSkew, and the last trusted one was kept.
	Ahead bool
}

// lockEntRowsTx locks, in id order, the document rows of ids, or every row
// with all.
func lockEntRowsTx(ctx context.Context, tx pgx.Tx, ids []uuid.UUID, all bool) error {
	if all {
		_, err := tx.Exec(ctx, `SELECT 1 FROM contract_ent_docs ORDER BY workspace_id FOR UPDATE`)
		return err
	}
	if len(ids) == 0 {
		return nil
	}
	_, err := tx.Exec(ctx, `SELECT 1 FROM contract_ent_docs WHERE workspace_id = ANY ($1) ORDER BY workspace_id FOR UPDATE`, ids)
	return err
}

// CommitEntPage stores a page of the entitlements feed in one transaction,
// in the lock order: contract_state FOR SHARE, contract_ent_state, then
// the document rows the page touches (every kept one when a refusal's
// workspace cannot be read). It commits only while the generation and the
// cursor are the ones the page was asked with. A valid document is stored
// when no row holds one, the held one's version was forgotten, or its
// version is higher; it then counts as applied when an account document
// names the workspace (else it is kept), clears the workspace's freshness
// hold and its not_found, and a document that says enforce holds the
// workspace at observe at once (contract_ent_brakes, enforce_in_e0): E0
// enforces nothing, and never runs a trim. A refusal is owed to the next
// acknowledgement, makes its workspace's GET due now and holds its
// freshness at the published_through stored before this page; one whose
// workspace cannot be read does so for every kept row, its GETs paced. The
// cursor moves to NextAfter, published_through is stored from a page with
// more false only, and the acknowledgement is made urgent by a refusal or
// a document whose switches, timeline or trim changed.
func (c *Contract) CommitEntPage(ctx context.Context, p EntPage) (EntPageResult, error) {
	var out EntPageResult
	err := retryDeadlock(ctx, func() error {
		out = EntPageResult{}
		return pg.InTx(ctx, c.pool, func(tx pgx.Tx) error {
			var gen *uuid.UUID
			if err := tx.QueryRow(ctx, `SELECT generation FROM contract_state FOR SHARE`).Scan(&gen); err != nil {
				return err
			}
			if gen == nil || *gen != p.SeenGeneration {
				return nil
			}
			var cursor int64
			var through *time.Time
			if err := tx.QueryRow(ctx, `SELECT feed_cursor, published_through FROM contract_ent_state FOR UPDATE`).
				Scan(&cursor, &through); err != nil {
				return err
			}
			if cursor != p.After {
				return nil
			}
			var ids []uuid.UUID
			unreadable := false
			for _, it := range p.Items {
				switch {
				case it.Doc != nil:
					ids = append(ids, it.Doc.Workspace)
				case it.Refused != nil && it.Refused.Workspace != nil:
					ids = append(ids, *it.Refused.Workspace)
				case it.Refused != nil:
					unreadable = true
				}
			}
			slices.SortFunc(ids, compareIDs)
			if err := lockEntRowsTx(ctx, tx, slices.Compact(ids), unreadable); err != nil {
				return err
			}
			for _, it := range p.Items {
				var r EntItemResult
				var err error
				switch {
				case it.Doc != nil:
					r, err = applyEntDocTx(ctx, tx, *it.Doc, it.Seq, nil)
					if r.Action == EntApply || r.Action == EntKeep {
						if changed, cerr := entChanged(r.Prev, it.Doc.Doc); cerr != nil || changed {
							out.Urgent = true
						}
					}
				case it.Refused != nil:
					r, err = refuseEntDocTx(ctx, tx, *gen, *it.Refused, through)
					out.Urgent = true
				default:
					continue
				}
				if err != nil {
					return err
				}
				r.Seq = it.Seq
				out.Items = append(out.Items, r)
			}
			pt := (*time.Time)(nil)
			if !p.More {
				var ok bool
				if err := tx.QueryRow(ctx, `SELECT $1::timestamptz <= clock_timestamp() + $2::interval`, p.PublishedThrough,
					ContractClockSkew).Scan(&ok); err != nil {
					return err
				}
				if ok {
					pt = &p.PublishedThrough
				} else {
					out.Ahead = true
				}
			}
			if _, err := tx.Exec(ctx, `UPDATE contract_ent_state SET feed_cursor = $1,
				published_through = CASE WHEN $2::timestamptz IS NULL THEN published_through
				                         ELSE greatest(published_through, $2::timestamptz) END,
				first_read_at = coalesce(first_read_at, clock_timestamp()), last_page_at = clock_timestamp(),
				feed_error = NULL, feed_error_at = NULL,
				ack_urgent = ack_urgent OR $3, ack_due_at = coalesce(ack_due_at, clock_timestamp()),
				updated_at = clock_timestamp()`, p.NextAfter, pt, out.Urgent); err != nil {
				return err
			}
			out.Committed = true
			return nil
		})
	})
	return out, err
}

// entChanged reports whether d's switches, timeline or trim differ from
// prev's, a stored document's raw bytes (nil: none held, a change).
func entChanged(prev []byte, d kc.EntitlementsDoc) (bool, error) {
	if prev == nil {
		return true, nil
	}
	var p kc.EntitlementsDoc
	if err := json.Unmarshal(prev, &p); err != nil {
		return true, err
	}
	if p.Switches != d.Switches || !bytes.Equal(bytes.TrimSpace(p.Trim), bytes.TrimSpace(d.Trim)) {
		return true, nil
	}
	a, err := json.Marshal(p.Timeline)
	if err != nil {
		return true, err
	}
	b, err := json.Marshal(d.Timeline)
	if err != nil {
		return true, err
	}
	return !bytes.Equal(a, b), nil
}

// applyEntDocTx stores d, of the feed at seq or (seq 0) a GET's answer
// signed at signedAt, under its row's lock: apply or keep when it is newer
// than the row's (no document, a forgotten version, or a higher one),
// ignore otherwise; for a GET, fresh when it is the version held.
func applyEntDocTx(ctx context.Context, tx pgx.Tx, d EntDoc, seq int64, signedAt *time.Time) (EntItemResult, error) {
	r := EntItemResult{Workspace: d.Workspace, Doc: &d}
	var version *int64
	var prev []byte
	exists := true
	err := tx.QueryRow(ctx, `SELECT version, doc FROM contract_ent_docs WHERE workspace_id = $1`, d.Workspace).Scan(&version, &prev)
	if errors.Is(err, pgx.ErrNoRows) {
		exists, err = false, nil
	}
	if err != nil {
		return r, err
	}
	r.Prev = prev
	var named, braked bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM contract_workspaces WHERE workspace_id = $1),
		EXISTS (SELECT 1 FROM contract_ent_brakes WHERE workspace_id = $1)`, d.Workspace).Scan(&named, &braked); err != nil {
		return r, err
	}
	r.Braked = braked
	newer := !exists || prev == nil || version == nil || d.Version > *version
	if !newer {
		if signedAt != nil && version != nil && d.Version == *version {
			r.Action = EntFresh
			_, err := tx.Exec(ctx, `UPDATE contract_ent_docs SET get_fresh_at = greatest(get_fresh_at, $2),
				feed_held_back = false, feed_fresh_at = NULL, not_found_since = NULL,
				get_due_at = NULL, get_tries = 0, get_error = NULL, get_error_at = NULL
				WHERE workspace_id = $1`, d.Workspace, *signedAt)
			return r, err
		}
		r.Action = EntIgnore
		return r, nil
	}
	r.Action = EntKeep
	if named {
		r.Action = EntApply
	}
	doc := d.Doc
	var trial, usageAfter, codesAfter *time.Time
	if doc.State.TrialEndsAt != nil {
		trial = &doc.State.TrialEndsAt.Time
	}
	if doc.Requests.UsageAfter != nil {
		usageAfter = &doc.Requests.UsageAfter.Time
	}
	if doc.Requests.CodesAfter != nil {
		codesAfter = &doc.Requests.CodesAfter.Time
	}
	var seqArg *int64
	if seq > 0 {
		seqArg = &seq
	}
	enforce := doc.Mode == kc.ModeEnforce
	if _, err := tx.Exec(ctx, `INSERT INTO contract_ent_docs AS d (workspace_id, generation, version, seq, doc, doc_from_get, mode, state,
			trial_ends_at, usage_after, codes_after, computed_at, received_at, applied_at, get_fresh_at, ever_enforce_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, clock_timestamp(),
			CASE WHEN $13 THEN clock_timestamp() END, $14, CASE WHEN $15 THEN clock_timestamp() END)
		ON CONFLICT (workspace_id) DO UPDATE SET generation = excluded.generation, version = excluded.version,
			seq = excluded.seq, doc = excluded.doc, doc_from_get = excluded.doc_from_get, mode = excluded.mode,
			state = excluded.state, trial_ends_at = excluded.trial_ends_at, usage_after = excluded.usage_after,
			codes_after = excluded.codes_after, computed_at = excluded.computed_at, received_at = excluded.received_at,
			applied_at = excluded.applied_at,
			get_fresh_at = CASE WHEN excluded.get_fresh_at IS NULL THEN d.get_fresh_at
			                    ELSE greatest(d.get_fresh_at, excluded.get_fresh_at) END,
			get_due_at = CASE WHEN excluded.get_fresh_at IS NOT NULL OR NOT d.feed_held_back THEN NULL ELSE d.get_due_at END,
			get_tries = CASE WHEN excluded.get_fresh_at IS NOT NULL OR NOT d.feed_held_back THEN 0 ELSE d.get_tries END,
			get_error = CASE WHEN excluded.get_fresh_at IS NOT NULL OR NOT d.feed_held_back THEN NULL ELSE d.get_error END,
			get_error_at = CASE WHEN excluded.get_fresh_at IS NOT NULL OR NOT d.feed_held_back THEN NULL ELSE d.get_error_at END,
			feed_held_back = false, feed_fresh_at = NULL, not_found_since = NULL,
			ever_enforce_at = coalesce(d.ever_enforce_at, excluded.ever_enforce_at)`,
		d.Workspace, d.Generation, d.Version, seqArg, d.Raw, d.FromGet, doc.Mode, doc.State.Name,
		trial, usageAfter, codesAfter, doc.ComputedAt.Time, named, signedAt, enforce); err != nil {
		return r, err
	}
	if enforce {
		// E0 has no enforcing path: the workspace is held at observe
		// before anything reads the document (the spec's 15.5, "A local
		// brake"; Q54, Q67, P7). A trim it carries is stored, never run.
		// An operator's hold found in place becomes E0's, not yet told:
		// the enforce document is an incident of its own to report.
		tag, err := tx.Exec(ctx, `INSERT INTO contract_ent_brakes AS b (workspace_id, platform_told, by_kind)
			VALUES ($1, false, 'enforce_in_e0')
			ON CONFLICT (workspace_id) DO UPDATE SET by_kind = 'enforce_in_e0', platform_told = false
			WHERE b.by_kind <> 'enforce_in_e0'`, d.Workspace)
		if err != nil {
			return r, err
		}
		r.NewBrake = tag.RowsAffected() == 1
		r.Braked = true
	}
	return r, nil
}

// refuseEntDocTx owes a bad document to the next acknowledgement, makes
// its workspace's GET due now and holds its freshness at through, the
// published_through stored before the page; with no workspace, every kept
// row's, their GETs paced one every 10 s.
func refuseEntDocTx(ctx context.Context, tx pgx.Tx, gen uuid.UUID, ref EntRefusal, through *time.Time) (EntItemResult, error) {
	r := EntItemResult{Action: EntRefuse, Refused: &ref}
	if ref.Workspace != nil {
		r.Workspace = *ref.Workspace
	}
	if _, err := tx.Exec(ctx, `INSERT INTO contract_ent_refusals (generation, seq, workspace_id, code) VALUES ($1, $2, $3, $4)
		ON CONFLICT (generation, seq) DO NOTHING`, gen, ref.Seq, ref.Workspace, ref.Code); err != nil {
		return r, err
	}
	if ref.Workspace != nil {
		_, err := tx.Exec(ctx, `INSERT INTO contract_ent_docs AS d (workspace_id, get_due_at, feed_held_back, feed_fresh_at)
			VALUES ($1, clock_timestamp(), true, $2)
			ON CONFLICT (workspace_id) DO UPDATE SET get_due_at = clock_timestamp(),
				feed_fresh_at = CASE WHEN d.feed_held_back THEN d.feed_fresh_at ELSE excluded.feed_fresh_at END,
				feed_held_back = true`, *ref.Workspace, through)
		return r, err
	}
	if _, err := tx.Exec(ctx, `UPDATE contract_ent_docs SET get_due_at = clock_timestamp(),
		feed_fresh_at = CASE WHEN feed_held_back THEN feed_fresh_at ELSE $1::timestamptz END, feed_held_back = true
		WHERE doc IS NOT NULL`, through); err != nil {
		return r, err
	}
	_, err := tx.Exec(ctx, `UPDATE contract_ent_state SET unreadable_get_next_at = coalesce(unreadable_get_next_at, clock_timestamp())`)
	return r, err
}

// EntGetResult is what EntGotDoc did with a GET's answer.
type EntGetResult struct {
	EntItemResult
}

// EntGotDoc stores a GET's answer for ws, a document the kit validated and
// held to Wappie's app and ws, signed at signedAt, in the lock order
// (contract_state FOR SHARE, contract_ent_state FOR SHARE, the row). By
// wire-entitlements.json's gets: another generation than the one held is
// a reset (EntReset: nothing stored; the caller restarts and asks again);
// a higher version, or one held with no version, is applied as a feed
// document is, its doc re-encoded, and gives freshness; the version held
// gives freshness only (EntFresh: the feed's bytes stay, and no "applied"
// is logged); a lower one is ignored and gives none.
func (c *Contract) EntGotDoc(ctx context.Context, d EntDoc, signedAt time.Time) (EntGetResult, error) {
	var out EntGetResult
	err := retryDeadlock(ctx, func() error {
		out = EntGetResult{}
		return pg.InTx(ctx, c.pool, func(tx pgx.Tx) error {
			var gen *uuid.UUID
			if err := tx.QueryRow(ctx, `SELECT generation FROM contract_state FOR SHARE`).Scan(&gen); err != nil {
				return err
			}
			if gen == nil || *gen != d.Generation {
				out.Workspace, out.Action = d.Workspace, EntReset
				return nil
			}
			if _, err := tx.Exec(ctx, `SELECT 1 FROM contract_ent_state FOR SHARE`); err != nil {
				return err
			}
			if err := lockEntRowsTx(ctx, tx, []uuid.UUID{d.Workspace}, false); err != nil {
				return err
			}
			r, err := applyEntDocTx(ctx, tx, d, 0, &signedAt)
			out.EntItemResult = r
			return err
		})
	})
	return out, err
}

// EntNotFound records a signed not_found on ws's GET. A workspace an
// account document names keeps its last document, frozen, and is asked no
// more until a document of it reaches the feed; one never named is asked
// again after backoff, as a snapshot's not_found is (the spec's 15.1).
func (c *Contract) EntNotFound(ctx context.Context, ws uuid.UUID, backoff time.Duration) (named bool, err error) {
	err = c.pool.QueryRow(ctx, `UPDATE contract_ent_docs d SET
			not_found_since = CASE WHEN n.named THEN coalesce(d.not_found_since, clock_timestamp()) ELSE d.not_found_since END,
			get_due_at = CASE WHEN n.named THEN NULL ELSE clock_timestamp() + $2::interval END,
			get_tries = CASE WHEN n.named THEN 0 ELSE d.get_tries + 1 END,
			get_error = CASE WHEN n.named THEN NULL ELSE 'not_found' END,
			get_error_at = CASE WHEN n.named THEN NULL ELSE coalesce(d.get_error_at, clock_timestamp()) END
		FROM (SELECT EXISTS (SELECT 1 FROM contract_workspaces WHERE workspace_id = $1) AS named) n
		WHERE d.workspace_id = $1 RETURNING n.named`, ws, backoff).Scan(&named)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return named, err
}

// EntGetFailed records a GET of ws that got no answer it could apply (a
// transport's class, a refusal's code, unverified, foreign): due again
// after backoff, its tries counted.
func (c *Contract) EntGetFailed(ctx context.Context, ws uuid.UUID, class string, backoff time.Duration) error {
	_, err := c.pool.Exec(ctx, `UPDATE contract_ent_docs SET get_tries = get_tries + 1, get_error = $2,
		get_error_at = coalesce(get_error_at, clock_timestamp()), get_due_at = clock_timestamp() + $3::interval
		WHERE workspace_id = $1 AND get_due_at IS NOT NULL`, ws, class, backoff)
	return err
}

// EntGetDue is a workspace whose GET is due, as the gets loop reads it.
type EntGetDue struct {
	Workspace uuid.UUID
	Tries     int
	// Paced: an unreadable bad document made GETs due, which go one every
	// 10 s; Next is when the next may go.
	Paced bool
	Next  *time.Time
}

// EntGetsDue lists, oldest due first, at most limit workspaces whose GET is
// due now, and whether the unreadable document's pacing holds (with when
// the next may go). It clears the pacing once no GET is due now: a row a
// newer document released from its hold still has its GET to send, paced
// with the rest.
func (c *Contract) EntGetsDue(ctx context.Context, limit int) ([]EntGetDue, error) {
	var next *time.Time
	if err := c.pool.QueryRow(ctx, `UPDATE contract_ent_state SET unreadable_get_next_at = NULL
		WHERE unreadable_get_next_at IS NOT NULL
		  AND NOT EXISTS (SELECT 1 FROM contract_ent_docs WHERE get_due_at <= clock_timestamp())
		RETURNING NULL::timestamptz`).Scan(&next); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if err := c.pool.QueryRow(ctx, `SELECT unreadable_get_next_at FROM contract_ent_state`).Scan(&next); err != nil {
		return nil, err
	}
	rows, err := c.pool.Query(ctx, `SELECT workspace_id, get_tries FROM contract_ent_docs
		WHERE get_due_at <= clock_timestamp() ORDER BY get_due_at, workspace_id LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (EntGetDue, error) {
		var d EntGetDue
		err := row.Scan(&d.Workspace, &d.Tries)
		d.Paced, d.Next = next != nil, next
		return d, err
	})
	return out, err
}

// EntGetPaced moves the unreadable document's pacing every on, after a GET
// it let go: false when the next may not go yet (another took the turn).
func (c *Contract) EntGetPaced(ctx context.Context, every time.Duration) (bool, error) {
	tag, err := c.pool.Exec(ctx, `UPDATE contract_ent_state SET unreadable_get_next_at = clock_timestamp() + $1::interval
		WHERE unreadable_get_next_at IS NOT NULL AND unreadable_get_next_at <= clock_timestamp()`, every)
	return tag.RowsAffected() == 1, err
}

// EntAck is the acknowledgement due: the generation and cursor it
// acknowledges, and the bad documents up to the cursor not listed in an
// earlier one, at most kc.MaxAppliedRefused.
type EntAck struct {
	Generation uuid.UUID
	Through    int64
	Refused    []EntRefusal
	// More: more refusals are owed than this one lists.
	More bool
}

// EntAckDue reads the acknowledgement to send now, and false when the
// account side holds no generation or the feed was never read.
func (c *Contract) EntAckDue(ctx context.Context) (EntAck, bool, error) {
	var a EntAck
	var gen *uuid.UUID
	var first *time.Time
	if err := c.pool.QueryRow(ctx, `SELECT s.generation, e.feed_cursor, e.first_read_at FROM contract_state s CROSS JOIN contract_ent_state e`).
		Scan(&gen, &a.Through, &first); err != nil {
		return EntAck{}, false, err
	}
	if gen == nil || first == nil {
		return EntAck{}, false, nil
	}
	a.Generation = *gen
	rows, err := c.pool.Query(ctx, `SELECT seq, workspace_id, code FROM contract_ent_refusals
		WHERE generation = $1 AND acked_at IS NULL AND seq <= $2 ORDER BY seq LIMIT $3`, gen, a.Through, kc.MaxAppliedRefused+1)
	if err != nil {
		return EntAck{}, false, err
	}
	a.Refused, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (EntRefusal, error) {
		var r EntRefusal
		err := row.Scan(&r.Seq, &r.Workspace, &r.Code)
		return r, err
	})
	if err != nil {
		return EntAck{}, false, err
	}
	if len(a.Refused) > kc.MaxAppliedRefused {
		a.Refused, a.More = a.Refused[:kc.MaxAppliedRefused], true
	}
	return a, true, nil
}

// EntAcked records an accepted acknowledgement of a, while its generation
// is still the account side's: the refusals it listed are settled, and it
// stays urgent only while more are owed.
func (c *Contract) EntAcked(ctx context.Context, a EntAck) error {
	return pg.InTx(ctx, c.pool, func(tx pgx.Tx) error {
		var gen *uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT generation FROM contract_state FOR SHARE`).Scan(&gen); err != nil {
			return err
		}
		if gen == nil || *gen != a.Generation {
			return nil
		}
		if _, err := tx.Exec(ctx, `SELECT 1 FROM contract_ent_state FOR UPDATE`); err != nil {
			return err
		}
		seqs := make([]int64, 0, len(a.Refused))
		for _, r := range a.Refused {
			seqs = append(seqs, r.Seq)
		}
		if _, err := tx.Exec(ctx, `UPDATE contract_ent_refusals SET acked_at = clock_timestamp()
			WHERE generation = $1 AND seq = ANY ($2)`, a.Generation, seqs); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE contract_ent_state SET acked_through = $1, acked_at = clock_timestamp(),
			ack_error = NULL, ack_error_at = NULL,
			ack_due_at = CASE WHEN feed_cursor > $1 THEN ack_due_at ELSE NULL END,
			ack_urgent = EXISTS (SELECT 1 FROM contract_ent_refusals WHERE generation = $2 AND acked_at IS NULL)
			             OR (ack_urgent AND feed_cursor > $1),
			updated_at = clock_timestamp()`, a.Through, a.Generation)
		return err
	})
}

// EntAckFailed records that an acknowledgement got no accepted answer: its
// class, and since when.
func (c *Contract) EntAckFailed(ctx context.Context, class string) error {
	_, err := c.pool.Exec(ctx, `UPDATE contract_ent_state SET ack_error = $1, ack_error_at = coalesce(ack_error_at, clock_timestamp())`, class)
	return err
}

// EntFeedFailed records that an entitlements feed call got no page: its
// class, and since when. A page's commit clears both.
func (c *Contract) EntFeedFailed(ctx context.Context, class string) error {
	_, err := c.pool.Exec(ctx, `UPDATE contract_ent_state SET feed_error = $1, feed_error_at = coalesce(feed_error_at, clock_timestamp())`, class)
	return err
}

// EntRecovered makes every GET that backs off due now, its tries
// forgotten, once the feed answers again after a failure. It locks the
// rows in id order, as every other writer of several rows does.
func (c *Contract) EntRecovered(ctx context.Context) (int64, error) {
	var n int64
	err := retryDeadlock(ctx, func() error {
		tag, err := c.pool.Exec(ctx, `UPDATE contract_ent_docs d SET get_due_at = clock_timestamp(), get_tries = 0
			FROM (SELECT workspace_id FROM contract_ent_docs
			      WHERE get_due_at > clock_timestamp() AND get_tries > 0 AND not_found_since IS NULL
			      ORDER BY workspace_id FOR UPDATE) l
			WHERE d.workspace_id = l.workspace_id AND d.get_due_at > clock_timestamp() AND d.get_tries > 0 AND d.not_found_since IS NULL`)
		n = tag.RowsAffected()
		return err
	})
	return n, err
}

// restartEntitlementsTx is the entitlements side of a reset (the spec's
// 15.6; 7.4), in Restart's transaction after the account and command
// state, in the lock order: the state row (the feed from 0, no trusted
// published_through, no acknowledgement), the refusals owed (deleted:
// another generation's), then every document row in id order: its version
// and generation forgotten, codes_after_answered forgotten, the first
// document after it marked, its freshness forgotten (a GET of the old
// generation no longer counts) and its GET due now. The documents, their
// modes and dates, applied_at, ever_enforce_at and the brakes stay: a
// reset never loosens.
func restartEntitlementsTx(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, `UPDATE contract_ent_state SET feed_cursor = 0, published_through = NULL,
		acked_through = NULL, acked_at = NULL, ack_due_at = NULL, ack_urgent = false, unreadable_get_next_at = NULL,
		updated_at = clock_timestamp()`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM contract_ent_refusals`); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE contract_ent_docs d SET generation = NULL, version = NULL, codes_after_answered = NULL,
		first_after_reset = true, feed_held_back = false, feed_fresh_at = NULL, get_fresh_at = NULL,
		get_due_at = clock_timestamp(), get_tries = 0, get_error = NULL, get_error_at = NULL
		FROM (SELECT workspace_id FROM contract_ent_docs ORDER BY workspace_id FOR UPDATE) l WHERE d.workspace_id = l.workspace_id`)
	return err
}

// RestartFromEntitlements is a reset the entitlements feed or a GET asks
// for (a gone, a page or a document of another generation than seen),
// through Restart, so the account, command and entitlements state reset in
// one transaction, as RestartFromCommands is. False when the generation
// moved (another reset came first) or the cursor kept moving.
func (c *Contract) RestartFromEntitlements(ctx context.Context, seen uuid.UUID, gen *uuid.UUID) (bool, error) {
	return c.RestartFromCommands(ctx, seen, gen)
}

// entNamedTx is the account side's hook (recordWorkspacesTx), after it
// recorded the named workspaces, in the lock order: contract_ent_state FOR
// SHARE, then the document rows in id order. A workspace with no row gets
// a placeholder whose GET is due now (the spec's 15.7, "A workspace the app
// does not hold yet"); a document kept for it is applied now.
func entNamedTx(ctx context.Context, tx pgx.Tx, ids []uuid.UUID) error {
	if len(ids) == 0 {
		return nil
	}
	if _, err := tx.Exec(ctx, `SELECT 1 FROM contract_ent_state FOR SHARE`); err != nil {
		return err
	}
	for _, id := range ids {
		if _, err := tx.Exec(ctx, `INSERT INTO contract_ent_docs AS d (workspace_id, get_due_at) VALUES ($1, clock_timestamp())
			ON CONFLICT (workspace_id) DO UPDATE SET applied_at = clock_timestamp()
			WHERE d.applied_at IS NULL AND d.doc IS NOT NULL`, id); err != nil {
			return err
		}
	}
	return nil
}

// EntBrake holds ws at observe (hold) or releases it, for the operator: a
// hold made by E0 on an enforce document keeps its kind, and only says the
// platform was told; a release of any hold, an operator's included, is
// refused while the workspace's document says enforce (ErrEntEnforceHeld).
func (c *Contract) EntBrake(ctx context.Context, ws uuid.UUID, hold, platformTold bool) (changed bool, err error) {
	err = pg.InTx(ctx, c.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT 1 FROM contract_ent_state FOR UPDATE`); err != nil {
			return err
		}
		if hold {
			tag, err := tx.Exec(ctx, `INSERT INTO contract_ent_brakes AS b (workspace_id, platform_told, by_kind)
				VALUES ($1, $2, 'operator')
				ON CONFLICT (workspace_id) DO UPDATE SET platform_told = b.platform_told OR excluded.platform_told
				WHERE NOT b.platform_told AND excluded.platform_told`, ws, platformTold)
			changed = tag.RowsAffected() == 1
			return err
		}
		var enforce bool
		err := tx.QueryRow(ctx, `SELECT coalesce(d.mode = 'enforce', false) FROM contract_ent_brakes b
			LEFT JOIN contract_ent_docs d ON d.workspace_id = b.workspace_id WHERE b.workspace_id = $1 FOR UPDATE OF b`, ws).
			Scan(&enforce)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrEntNoBrake
		}
		if err != nil {
			return err
		}
		if enforce {
			// The document is what keeps it held, whatever the kind.
			return ErrEntEnforceHeld
		}
		_, err = tx.Exec(ctx, `DELETE FROM contract_ent_brakes WHERE workspace_id = $1`, ws)
		changed = true
		return err
	})
	return changed, err
}

// EntRow is one workspace's document row as the timeline, the caps, the
// status and slice 19's checks read it.
type EntRow struct {
	Workspace uuid.UUID
	Version   *int64
	Mode      string
	State     string
	Doc       []byte
	// Named: an account document names the workspace; AppliedAt is set
	// then, once a document is held.
	Named                 bool
	AppliedAt, ReceivedAt *time.Time
	// The freshness inputs (entFreshness): FeedHeldBack, FeedFreshAt and
	// GetFreshAt; Fresh is the result, nil for none.
	FeedHeldBack            bool
	FeedFreshAt, GetFreshAt *time.Time
	Fresh                   *time.Time
	GetDueAt                *time.Time
	GetTries                int
	GetError                string
	GetErrorAt              *time.Time
	NotFoundSince           *time.Time
	EverEnforceAt           *time.Time
	TimelineLoggedThrough   *time.Time
	CapSide                 string
	// The brake: none ("" kind), or its kind and whether the platform was
	// told.
	BrakeKind   string
	BrakeTold   bool
	BrakeHeldAt *time.Time
}

// entFreshness is a workspace's freshness (the spec's 15.6 and 15.7): the
// later of its last valid GET answer of this generation and the feed's
// trusted published_through, held where a bad document held it back. A
// workspace that holds no document has none.
func entFreshness(r EntRow, publishedThrough *time.Time) *time.Time {
	if r.Doc == nil {
		return nil
	}
	feed := publishedThrough
	if r.FeedHeldBack {
		feed = r.FeedFreshAt
	}
	switch {
	case feed == nil:
		return r.GetFreshAt
	case r.GetFreshAt == nil || feed.After(*r.GetFreshAt):
		return feed
	}
	return r.GetFreshAt
}

// EntFreshness is entFreshness, for the follower's own reads.
func EntFreshness(r EntRow, publishedThrough *time.Time) *time.Time {
	return entFreshness(r, publishedThrough)
}

const entRowColumns = `d.workspace_id, d.version, coalesce(d.mode, ''), coalesce(d.state, ''), d.doc,
	EXISTS (SELECT 1 FROM contract_workspaces w WHERE w.workspace_id = d.workspace_id), d.applied_at, d.received_at,
	d.feed_held_back, d.feed_fresh_at, d.get_fresh_at, d.get_due_at, d.get_tries, coalesce(d.get_error, ''), d.get_error_at,
	d.not_found_since, d.ever_enforce_at, d.timeline_logged_through, coalesce(d.cap_side, ''),
	coalesce(b.by_kind, ''), coalesce(b.platform_told, false), b.held_at`

func scanEntRow(row pgx.CollectableRow) (EntRow, error) {
	var r EntRow
	err := row.Scan(&r.Workspace, &r.Version, &r.Mode, &r.State, &r.Doc, &r.Named, &r.AppliedAt, &r.ReceivedAt,
		&r.FeedHeldBack, &r.FeedFreshAt, &r.GetFreshAt, &r.GetDueAt, &r.GetTries, &r.GetError, &r.GetErrorAt, &r.NotFoundSince,
		&r.EverEnforceAt, &r.TimelineLoggedThrough, &r.CapSide, &r.BrakeKind, &r.BrakeTold, &r.BrakeHeldAt)
	return r, err
}

// EntRows reads every document row with its brake and freshness, in id
// order, and the state it was read with.
func (c *Contract) EntRows(ctx context.Context) (EntState, []EntRow, error) {
	var st EntState
	var out []EntRow
	err := pgx.BeginTxFunc(ctx, c.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var err error
		if st, err = scanEntState(tx.QueryRow(ctx, `SELECT `+entStateColumns+` FROM contract_ent_state e CROSS JOIN contract_state s`)); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT `+entRowColumns+` FROM contract_ent_docs d
			LEFT JOIN contract_ent_brakes b ON b.workspace_id = d.workspace_id ORDER BY d.workspace_id`)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, scanEntRow)
		return err
	})
	for i := range out {
		out[i].Fresh = entFreshness(out[i], st.PublishedThrough)
	}
	return st, out, err
}

// EntRow reads ws's document row, false when there is none.
func (c *Contract) EntRow(ctx context.Context, ws uuid.UUID) (EntRow, bool, error) {
	st, err := c.EntState(ctx)
	if err != nil {
		return EntRow{}, false, err
	}
	rows, err := c.pool.Query(ctx, `SELECT `+entRowColumns+` FROM contract_ent_docs d
		LEFT JOIN contract_ent_brakes b ON b.workspace_id = d.workspace_id WHERE d.workspace_id = $1`, ws)
	if err != nil {
		return EntRow{}, false, err
	}
	out, err := pgx.CollectRows(rows, scanEntRow)
	if err != nil || len(out) == 0 {
		return EntRow{}, false, err
	}
	out[0].Fresh = entFreshness(out[0], st.PublishedThrough)
	return out[0], true, nil
}

// EntTimelineLogged records that ws's steps up to through were logged.
func (c *Contract) EntTimelineLogged(ctx context.Context, ws uuid.UUID, through time.Time) error {
	_, err := c.pool.Exec(ctx, `UPDATE contract_ent_docs SET timeline_logged_through = greatest(timeline_logged_through, $2)
		WHERE workspace_id = $1`, ws, through)
	return err
}

// EntCapSide records the side of cap_bytes last logged for ws.
func (c *Contract) EntCapSide(ctx context.Context, ws uuid.UUID, side string) error {
	_, err := c.pool.Exec(ctx, `UPDATE contract_ent_docs SET cap_side = $2 WHERE workspace_id = $1`, ws, side)
	return err
}

// EntTotal is a workspace's stored bytes, tenants' two counters read
// plainly, with no lock: never logged. False when Wappie has no such
// workspace.
func (c *Contract) EntTotal(ctx context.Context, ws uuid.UUID) (int64, bool, error) {
	var total int64
	err := c.pool.QueryRow(ctx, `SELECT storage_archive_bytes + storage_object_bytes FROM tenants WHERE id = $1`, ws).Scan(&total)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	return total, err == nil, err
}

// ContractEntStatus is what contract status reads of the entitlements part.
type ContractEntStatus struct {
	State EntState
	Rows  []EntRow
	// Owed are the refusals not yet acknowledged; LastRefused the newest
	// refusal seen, acknowledged or not.
	Owed        int
	LastRefused *time.Time
	// Usage is each recorded workspace's usage cadence (contract_usage),
	// in id order.
	Usage []UsageRow
	Now   time.Time
}

// EntStatus reads the entitlements part in one read-only snapshot.
func (c *Contract) EntStatus(ctx context.Context) (ContractEntStatus, error) {
	var out ContractEntStatus
	err := pgx.BeginTxFunc(ctx, c.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var err error
		if out.State, err = scanEntState(tx.QueryRow(ctx, `SELECT `+entStateColumns+` FROM contract_ent_state e CROSS JOIN contract_state s`)); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp(), (SELECT count(*) FROM contract_ent_refusals WHERE acked_at IS NULL),
			(SELECT max(seen_at) FROM contract_ent_refusals)`).Scan(&out.Now, &out.Owed, &out.LastRefused); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT `+entRowColumns+` FROM contract_ent_docs d
			LEFT JOIN contract_ent_brakes b ON b.workspace_id = d.workspace_id ORDER BY d.workspace_id`)
		if err != nil {
			return err
		}
		if out.Rows, err = pgx.CollectRows(rows, scanEntRow); err != nil {
			return err
		}
		rows, err = tx.Query(ctx, `SELECT `+usageRowColumns+` FROM contract_usage u
			LEFT JOIN contract_ent_docs d ON d.workspace_id = u.workspace_id ORDER BY u.workspace_id`)
		if err != nil {
			return err
		}
		out.Usage, err = pgx.CollectRows(rows, scanUsageRow)
		return err
	})
	for i := range out.Rows {
		out.Rows[i].Fresh = entFreshness(out.Rows[i], out.State.PublishedThrough)
	}
	return out, err
}
