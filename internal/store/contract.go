package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/obs"
	"whatserver2/internal/pg"
)

// The platform contract's state on Wappie's side (migration 0051, decision
// 0040): the mode, the documents the platform answers for each sub Wappie
// subscribes, and the workspaces they name. internal/membership speaks the
// contract and fills these structs from the kit's; this file only stores
// and reads them, on the database's clock.
//
// The three tables carry no row-level security (0051). Every transaction
// that stores documents locks contract_state's one row first, so the first
// writer of a generation wins and documents are stored one batch at a time;
// within a batch, accounts and then workspaces are written in id order, so
// a transaction that also holds other rows never meets another in the
// opposite order (the plan's DB23), and a deadlock the server still reports
// is retried.

// Contract is the contract's state in the database.
type Contract struct{ pool *pgxpool.Pool }

// NewContract returns the contract store backed by pool.
func NewContract(pool *pgxpool.Pool) *Contract { return &Contract{pool: pool} }

// The contract's modes (contract_state.mode). Enforce widens them.
const (
	ContractOff     = "off"
	ContractObserve = "observe"
)

// The channels the contract's triggers and writers notify.
const (
	// ContractDirtyChannel carries a workspace's id, or "all", when a change
	// its access snapshot shows commits (0051's triggers).
	ContractDirtyChannel = "wappie_contract_dirty"
	// ContractModeChannel wakes every process's contract loop: a mode
	// switch, or an answer of a generation Wappie does not hold.
	ContractModeChannel = "wappie_contract_mode"
)

// FreshFor is how long a validated document, or a trusted
// published_through, keeps a sub fresh (README 7.1).
const FreshFor = time.Hour

// ContractClockSkew is how far past the database's clock a time the
// platform states may be. The platform and the database read one host's
// clock, so a time beyond it is a fault: a revocation time past it would
// be kept for good (they only rise), and a published_through past it would
// keep every followed sub fresh through an outage.
const ContractClockSkew = 5 * time.Minute

// ContractPeriod is one stretch of time the contract was off after its
// first observe.
type ContractPeriod struct{ From, To time.Time }

// ContractState is contract_state's one row.
type ContractState struct {
	Mode          string
	ModeChangedAt time.Time
	// EventsFrom is the first switch to observe; nil until then.
	EventsFrom *time.Time
	// EventsPausedAt is the last switch from observe to off, while off.
	EventsPausedAt *time.Time
	// EventsOff are the off periods after EventsFrom.
	EventsOff []ContractPeriod
	MailFrom  time.Time
	// Generation is the platform database's identity the stored state
	// belongs to; nil before the first answer and after a gone.
	Generation          *uuid.UUID
	GenerationConfirmed bool
	FeedCursor          int64
	PublishedThrough    *time.Time
	RoundGeneration     *uuid.UUID
	// FeedReadAt is the leader's last feed page committed, on the
	// database's clock; FeedError the class of the feed calls' failure
	// since (empty once a page commits), from FeedErrorAt.
	FeedReadAt  *time.Time
	FeedError   string
	FeedErrorAt *time.Time
	// RoundErrorAt is the first pass of the round, in the run that goes on,
	// that left a held sub with no document of the stored generation, and
	// RoundError the class of its last failed PUT; both unset once a pass
	// leaves none (RoundFailed, RoundDone).
	RoundError   string
	RoundErrorAt *time.Time
	// ErrorAt and ErrorClass are the last contract ERROR the leader
	// recorded (RecordError).
	ErrorAt    *time.Time
	ErrorClass string
	UpdatedAt  time.Time
}

// On reports whether the contract is on: every mode but off, so a mode a
// later release adds (enforce) counts as on wherever this code gates on
// the contract, never as off.
func (s ContractState) On() bool { return s.Mode != ContractOff }

// Observed reports whether the contract was ever switched to observe: from
// then on Wappie never goes back to choosing a new account's personal
// workspace itself (the plan's DB2).
func (s ContractState) Observed() bool { return s.EventsFrom != nil }

const contractStateColumns = `mode, mode_changed_at, events_from, events_paused_at, events_off, mail_from,
	generation, generation_confirmed, feed_cursor, published_through, round_generation,
	feed_read_at, coalesce(feed_error, ''), feed_error_at, coalesce(round_error, ''), round_error_at,
	error_at, coalesce(error_class, ''), updated_at`

func scanContractState(row pgx.Row) (ContractState, error) {
	var s ContractState
	var off pgtype.Multirange[pgtype.Range[pgtype.Timestamptz]]
	if err := row.Scan(&s.Mode, &s.ModeChangedAt, &s.EventsFrom, &s.EventsPausedAt, &off, &s.MailFrom,
		&s.Generation, &s.GenerationConfirmed, &s.FeedCursor, &s.PublishedThrough, &s.RoundGeneration,
		&s.FeedReadAt, &s.FeedError, &s.FeedErrorAt, &s.RoundError, &s.RoundErrorAt, &s.ErrorAt, &s.ErrorClass, &s.UpdatedAt); err != nil {
		return ContractState{}, err
	}
	for _, r := range off {
		// The off periods are closed ranges of two known times: an
		// unbounded or empty one is a fault, not a period.
		if !r.Valid || !r.Lower.Valid || !r.Upper.Valid {
			return ContractState{}, errors.New("store: contract_state.events_off holds an unbounded period")
		}
		s.EventsOff = append(s.EventsOff, ContractPeriod{From: r.Lower.Time, To: r.Upper.Time})
	}
	return s, nil
}

// State reads contract_state.
func (c *Contract) State(ctx context.Context) (ContractState, error) {
	return scanContractState(c.pool.QueryRow(ctx, `SELECT `+contractStateColumns+` FROM contract_state`))
}

// lockStateTx reads contract_state under its row lock, which every
// transaction that stores documents or moves the feed takes first.
func lockStateTx(ctx context.Context, tx pgx.Tx) (ContractState, error) {
	return scanContractState(tx.QueryRow(ctx, `SELECT `+contractStateColumns+` FROM contract_state FOR UPDATE`))
}

// ContractDoc is one account's document as the platform answered it
// (README 6.2), validated by the caller; membership fills it from the
// kit's AccountDoc. It holds no email and no person's name.
type ContractDoc struct {
	Sub        uuid.UUID
	Generation uuid.UUID
	Version    int64
	// Status is active, disabled or closed.
	Status string
	// The latest disable, revocation of every session, and recovery.
	DisabledAt           *time.Time
	SessionsRevokedAt    *time.Time
	CredentialsRevokedAt *time.Time
	// Workspaces are the account's, the personal one first.
	Workspaces []ContractDocWorkspace
	// Raw is the document as received, a JSON object.
	Raw []byte
}

// ContractDocWorkspace is one workspace of a document.
type ContractDocWorkspace struct {
	ID uuid.UUID
	// Kind is personal or team; Role owner, admin or member; Status open
	// or closed.
	Kind, Role, Status string
	WVersion           int64
}

// ContractDocOutcome is what storing one document did.
type ContractDocOutcome string

const (
	// ContractDocStored: a newer version of the stored generation, stored;
	// an answer's makes the sub fresh.
	ContractDocStored ContractDocOutcome = "stored"
	// ContractDocKept: the version Wappie holds already, or a lower one:
	// the stored document stays, and an answer makes the sub fresh all the
	// same (the plan's DB8: only the document's columns are newer-only).
	ContractDocKept ContractDocOutcome = "kept"
	// ContractDocOtherGeneration: of a generation Wappie does not hold:
	// nothing stored or refreshed, and every contract loop is woken, so
	// the leader's next feed call finds the new generation or gone.
	ContractDocOtherGeneration ContractDocOutcome = "other_generation"
	// ContractDocKindChanged: it names a workspace with another kind than
	// Wappie recorded for it, or than the local workspace of that id has:
	// nothing stored or refreshed, logged at ERROR (README 6.2: an app
	// refuses, and alerts on, such a document).
	ContractDocKindChanged ContractDocOutcome = "kind_changed"
	// ContractDocInvalid: a document the database would not hold as
	// received (not a JSON object by jsonb's rules: a \u0000 escape, a lone
	// surrogate, a number past numeric's range), or one with a revocation
	// time past the database's clock by more than ContractClockSkew:
	// nothing stored or refreshed, logged at ERROR by sub, and the rest of
	// the batch goes on.
	ContractDocInvalid ContractDocOutcome = "invalid"
)

// ContractSource is where a batch of documents came from, which decides
// whether they make their subs fresh (the plan's DB8).
type ContractSource int

const (
	// ContractAnswer is a PUT's or a GET's answer, computed now for its
	// sub: each document of the stored generation refreshes its sub's
	// fresh_at, whatever its version.
	ContractAnswer ContractSource = iota + 1
	// ContractFeed is a feed page's documents, which refresh nobody: a page
	// vouches for its subs only through published_through, and only when
	// more is false (README 6.3), so a backlog replayed after a stuck
	// publisher never makes a sub fresh.
	ContractFeed
)

// StoreDocuments stores documents in one transaction, as the round, a
// sign-in's PUT and a GET each do (the plan's 4.5, 4.6 and 4.9; the
// follower's page calls storeDocsTx in its own), and says for each, in
// order, what it did. While Wappie holds no generation (the first answer,
// and after a gone) the first document's generation is adopted. Each
// document of the stored generation records every workspace it names and,
// when it is an answer, refreshes its sub's fresh_at; its own columns are
// replaced only by a higher version, and its revocation times only rise.
// Nothing here applies a document: that is enforce's.
func (c *Contract) StoreDocuments(ctx context.Context, from ContractSource, docs ...ContractDoc) ([]ContractDocOutcome, error) {
	var out []ContractDocOutcome
	err := retryDeadlock(ctx, func() error {
		return pg.InTx(ctx, c.pool, func(tx pgx.Tx) error {
			state, err := lockStateTx(ctx, tx)
			if err != nil {
				return err
			}
			out, err = storeDocsTx(ctx, tx, state, from, docs)
			return err
		})
	})
	return out, err
}

// storeDocsTx stores docs, all from one source, in tx, which holds
// contract_state's lock (state is what it read under it): accounts in sub
// order, then their workspaces in id order.
//
// A feed page's document records its workspaces only for a sub Wappie
// holds (a person linked to the platform): a page may carry the document of
// a sign-up refused after its PUT, or of one whose account is not yet
// committed, and such a document's workspaces must never become platform
// workspaces (their snapshots would be owed, the platform's 90-minute alert
// would count them, and their teams' person invitations would close, DB6).
// Its account row is stored all the same, newer only, so the sweep
// unsubscribes an orphan and a sign-up committed later keeps the newer
// version. An answer is always a held sub's (a sign-in's, the round's, a
// GET's), or the sign-up's own, whose identity its transaction has just
// written. A held sub's document that is kept because Wappie stores a
// newer one records the stored one's workspaces too: that one may have
// come from a page while the sub was not yet held (a sign-up's PUT
// answered, then the account was committed with that older answer), and no
// later document need ever name them again. A stored document that
// changes a workspace's members (its sub joins, leaves or changes role)
// makes that workspace's snapshot due now; and every document stored or
// kept that names a workspace the platform refused (not_found), or never
// accepted a snapshot of since the last restart, makes its snapshot and
// event queue due now, releasing a park for not_found (the plan's 4.7,
// "Round 2, recovery"), so a workspace named again comes back at once
// rather than at its backoff.
func storeDocsTx(ctx context.Context, tx pgx.Tx, state ContractState, from ContractSource, docs []ContractDoc) ([]ContractDocOutcome, error) {
	if from != ContractAnswer && from != ContractFeed {
		return nil, fmt.Errorf("store: unknown document source %d", from)
	}
	out := make([]ContractDocOutcome, len(docs))
	if len(docs) == 0 {
		return out, nil
	}
	generation := state.Generation
	if generation == nil {
		g := docs[0].Generation
		if _, err := tx.Exec(ctx, `UPDATE contract_state SET generation = $1, generation_confirmed = false,
			updated_at = clock_timestamp() WHERE generation IS NULL`, g); err != nil {
			return nil, err
		}
		generation = &g
	}

	// The kinds Wappie knows of every workspace the documents name: the
	// record's, and the local workspace's of the same id.
	var ids []uuid.UUID
	for _, d := range docs {
		for _, w := range d.Workspaces {
			ids = append(ids, w.ID)
		}
	}
	kinds := map[uuid.UUID]knownKind{}
	if err := workspaceKindsTx(ctx, tx, ids, kinds); err != nil {
		return nil, err
	}
	// What the database would refuse to hold, asked of it before anything
	// is written, so that one document never aborts the batch: jsonb's
	// input rules (Go's json.Valid passes a \u0000 escape and lone
	// surrogates, and invalid UTF-8 would fail the statement itself), and
	// the latest revocation time it takes for true.
	raws := make([]string, len(docs))
	for i, d := range docs {
		if utf8.Valid(d.Raw) && json.Valid(d.Raw) {
			raws[i] = string(d.Raw)
		}
	}
	var latest time.Time
	var objects []bool
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp() + $2::interval,
		coalesce(array_agg(CASE WHEN pg_input_is_valid(r, 'jsonb') THEN jsonb_typeof(r::jsonb) = 'object' ELSE false END ORDER BY n), '{}')
		FROM unnest($1::text[]) WITH ORDINALITY AS u(r, n)`, raws, ContractClockSkew).Scan(&latest, &objects); err != nil {
		return nil, err
	}
	if len(objects) != len(docs) {
		return nil, fmt.Errorf("store: %d verdicts on %d documents", len(objects), len(docs))
	}

	held := map[uuid.UUID]bool{}
	if from == ContractFeed {
		subs := make([]uuid.UUID, len(docs))
		for i, d := range docs {
			subs[i] = d.Sub
		}
		heldRows, err := tx.Query(ctx, `SELECT sub FROM platform_identities WHERE sub = ANY ($1)`, subs)
		if err != nil {
			return nil, err
		}
		heldSubs, err := pgx.CollectRows(heldRows, pgx.RowTo[uuid.UUID])
		if err != nil {
			return nil, err
		}
		for _, sub := range heldSubs {
			held[sub] = true
		}
	}

	order := make([]int, len(docs))
	for i := range order {
		order[i] = i
	}
	slices.SortStableFunc(order, func(a, b int) int { return compareIDs(docs[a].Sub, docs[b].Sub) })
	named := map[uuid.UUID]ContractDocWorkspace{}
	changed := map[uuid.UUID]bool{}
	// For each held sub's document kept, the workspaces of the one stored,
	// each with its sub.
	type storedName struct {
		sub uuid.UUID
		w   ContractDocWorkspace
	}
	var kept []storedName
	other := false
next:
	for _, i := range order {
		d := docs[i]
		if d.Generation != *generation {
			out[i] = ContractDocOtherGeneration
			other = true
			continue
		}
		if reason := unstorable(d, objects[i], latest); reason != "" {
			obs.LoggerFrom(ctx).Error("contract: a document cannot be stored", "sub", d.Sub, "version", d.Version, "reason", reason)
			out[i] = ContractDocInvalid
			continue
		}
		for _, w := range d.Workspaces {
			if k := kinds[w.ID]; (k.recorded != "" && k.recorded != w.Kind) || (k.local != "" && k.local != w.Kind) {
				obs.LoggerFrom(ctx).Error("contract: workspace kind changed: the document is not stored",
					"sub", d.Sub, "workspace", w.ID, "kind", w.Kind, "recorded", k.recorded, "local", k.local)
				out[i] = ContractDocKindChanged
				continue next
			}
		}
		stored, before, err := storeAccountTx(ctx, tx, d, from == ContractAnswer)
		if err != nil {
			return nil, err
		}
		out[i] = ContractDocKept
		if stored {
			out[i] = ContractDocStored
		}
		if from == ContractFeed && !held[d.Sub] {
			continue
		}
		if stored {
			for _, id := range membersChanged(before, d.Workspaces) {
				changed[id] = true
			}
		} else {
			for _, w := range before {
				kept = append(kept, storedName{d.Sub, w})
			}
		}
		for _, w := range d.Workspaces {
			// A later document of this batch is held to the kind this one
			// recorded.
			if k := kinds[w.ID]; k.recorded == "" {
				k.recorded = w.Kind
				kinds[w.ID] = k
			}
			if n, ok := named[w.ID]; !ok || w.WVersion > n.WVersion {
				named[w.ID] = w
			}
		}
	}
	if len(kept) > 0 {
		var more []uuid.UUID
		for _, k := range kept {
			if _, ok := kinds[k.w.ID]; !ok {
				more = append(more, k.w.ID)
			}
		}
		if err := workspaceKindsTx(ctx, tx, more, kinds); err != nil {
			return nil, err
		}
		for _, k := range kept {
			w := k.w
			if kk := kinds[w.ID]; (kk.recorded != "" && kk.recorded != w.Kind) || (kk.local != "" && kk.local != w.Kind) {
				// The document is kept all the same (its outcome is the
				// incoming one's), so the ERROR is recorded here.
				obs.LoggerFrom(ctx).Error("contract: workspace kind changed: a stored document's workspace is not recorded",
					"sub", k.sub, "workspace", w.ID, "kind", w.Kind, "recorded", kk.recorded, "local", kk.local)
				if err := recordErrorTx(ctx, tx, ContractErrorKindChanged); err != nil {
					return nil, err
				}
				continue
			}
			if n, ok := named[w.ID]; !ok || w.WVersion > n.WVersion {
				named[w.ID] = w
			}
		}
	}
	if err := recordWorkspacesTx(ctx, tx, named); err != nil {
		return nil, err
	}
	if err := workspacesDueTx(ctx, tx, named, changed); err != nil {
		return nil, err
	}
	if other {
		if _, err := tx.Exec(ctx, `SELECT pg_notify($1, 'generation')`, ContractModeChannel); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// knownKind is what Wappie knows of a workspace's kind: the record's, and
// the local workspace's of the same id ("" for none).
type knownKind struct{ recorded, local string }

// workspaceKindsTx adds to into the kinds Wappie knows of each of ids.
func workspaceKindsTx(ctx context.Context, tx pgx.Tx, ids []uuid.UUID, into map[uuid.UUID]knownKind) error {
	if len(ids) == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT w.id, coalesce(cw.kind, ''), coalesce(t.kind, '')
		FROM unnest($1::uuid[]) AS w(id)
		LEFT JOIN contract_workspaces cw ON cw.workspace_id = w.id
		LEFT JOIN tenants t ON t.id = w.id`, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var k knownKind
		if err := rows.Scan(&id, &k.recorded, &k.local); err != nil {
			return err
		}
		into[id] = k
	}
	return rows.Err()
}

// unstorable says why d cannot be stored as received, or "": its JSON is
// not an object jsonb holds, or a revocation time is past latest.
func unstorable(d ContractDoc, object bool, latest time.Time) string {
	if !object {
		return "json"
	}
	for _, t := range []struct {
		name string
		at   *time.Time
	}{{"disabled_at", d.DisabledAt}, {"sessions_revoked_at", d.SessionsRevokedAt}, {"credentials_revoked_at", d.CredentialsRevokedAt}} {
		if t.at != nil && t.at.After(latest) {
			return t.name + "_ahead"
		}
	}
	return ""
}

// storeAccountTx writes one document of the stored generation: the row's
// document columns when its version is higher than the row's (or the row
// has none), the revocation times at the highest seen, and fresh_at when
// fresh. It reports whether the document was the newer one, and the
// workspaces of the document the row held before (the one it replaced, or
// the one it keeps; none for a row without one).
func storeAccountTx(ctx context.Context, tx pgx.Tx, d ContractDoc, fresh bool) (bool, []ContractDocWorkspace, error) {
	// The row is made or locked in one statement, as Intend makes it: an
	// Intend inserting it at the same moment is waited for, not collided
	// with, and a removal in between cannot leave nothing to lock.
	var generation *uuid.UUID
	var version *int64
	var before []byte
	if err := tx.QueryRow(ctx, `INSERT INTO contract_accounts (sub) VALUES ($1)
		ON CONFLICT (sub) DO UPDATE SET subscribed_at = contract_accounts.subscribed_at
		RETURNING generation, version, doc->'workspaces'`, d.Sub).Scan(&generation, &version, &before); err != nil {
		return false, nil, err
	}
	var previous []ContractDocWorkspace
	if len(before) > 0 && !bytes.Equal(before, []byte("null")) {
		var ws []struct {
			ID       uuid.UUID `json:"id"`
			Kind     string    `json:"kind"`
			Role     string    `json:"role"`
			Status   string    `json:"status"`
			WVersion int64     `json:"wversion"`
		}
		if err := json.Unmarshal(before, &ws); err != nil {
			return false, nil, fmt.Errorf("store: a stored document's workspaces: %w", err)
		}
		for _, w := range ws {
			previous = append(previous, ContractDocWorkspace{ID: w.ID, Kind: w.Kind, Role: w.Role, Status: w.Status, WVersion: w.WVersion})
		}
	}
	newer := version == nil || generation == nil || *generation != d.Generation || d.Version > *version
	_, err := tx.Exec(ctx, `UPDATE contract_accounts SET
		generation = CASE WHEN $2 THEN $3 ELSE generation END,
		version    = CASE WHEN $2 THEN $4 ELSE version END,
		status     = CASE WHEN $2 THEN $5 ELSE status END,
		doc        = CASE WHEN $2 THEN $6::jsonb ELSE doc END,
		applied_at = CASE WHEN $2 THEN clock_timestamp() ELSE applied_at END,
		disabled_at            = greatest(disabled_at, $7),
		sessions_revoked_at    = greatest(sessions_revoked_at, $8),
		credentials_revoked_at = greatest(credentials_revoked_at, $9),
		fresh_at   = CASE WHEN $10 THEN clock_timestamp() ELSE fresh_at END
		WHERE sub = $1`,
		d.Sub, newer, d.Generation, d.Version, d.Status, d.Raw, d.DisabledAt, d.SessionsRevokedAt, d.CredentialsRevokedAt, fresh)
	return newer, previous, err
}

// membersChanged lists the workspaces whose members a document changes
// against the one before it: the sub joined or left one, or its role there
// changed.
func membersChanged(before, after []ContractDocWorkspace) []uuid.UUID {
	roles := map[uuid.UUID]string{}
	for _, w := range before {
		roles[w.ID] = w.Role
	}
	var out []uuid.UUID
	for _, w := range after {
		if role, ok := roles[w.ID]; !ok || role != w.Role {
			out = append(out, w.ID)
		}
		delete(roles, w.ID)
	}
	for id := range roles {
		out = append(out, id)
	}
	return out
}

// workspacesDueTx makes due now, in id order, the snapshot of every
// workspace whose members changed, and the snapshot and event queue of
// every named workspace the platform refused (not_found) or that has no
// accepted snapshot since the last restart: the platform knows a workspace
// again once a document names it, so a park for not_found (which keeps
// not_found_since) is released too. A park for any other reason stays
// (invalid_request is a Wappie bug, the plan's 4.10): naming it again
// would only send it to be refused again. (P5 adds the release of the
// events parked not_found to this.)
func workspacesDueTx(ctx context.Context, tx pgx.Tx, named map[uuid.UUID]ContractDocWorkspace, changed map[uuid.UUID]bool) error {
	var names, members []uuid.UUID
	for id := range named {
		names = append(names, id)
	}
	for id := range changed {
		members = append(members, id)
	}
	if len(names) == 0 && len(members) == 0 {
		return nil
	}
	// The rows are locked in id order first (DB23), then written.
	if _, err := tx.Exec(ctx, `SELECT 1 FROM contract_workspaces WHERE workspace_id = ANY ($1) OR workspace_id = ANY ($2)
		ORDER BY workspace_id FOR UPDATE`, names, members); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE contract_workspaces w SET
			snapshot_due_at = least(w.snapshot_due_at, clock_timestamp()),
			snapshot_tries  = CASE WHEN back THEN 0 ELSE w.snapshot_tries END,
			events_due_at   = CASE WHEN back AND w.events_due_at IS NOT NULL THEN least(w.events_due_at, clock_timestamp()) ELSE w.events_due_at END,
			events_tries    = CASE WHEN back THEN 0 ELSE w.events_tries END,
			not_found_since = CASE WHEN back THEN NULL ELSE w.not_found_since END,
			parked_at       = CASE WHEN back AND w.not_found_since IS NOT NULL THEN NULL ELSE w.parked_at END
		FROM (SELECT c.workspace_id, c.workspace_id = ANY ($1)
		             AND (c.not_found_since IS NOT NULL OR c.snapshot_ok_at IS NULL) AS back
		        FROM contract_workspaces c
		       WHERE c.workspace_id = ANY ($1) OR c.workspace_id = ANY ($2)) due
		WHERE w.workspace_id = due.workspace_id AND (due.back OR w.workspace_id = ANY ($2))`, names, members); err != nil {
		return err
	}
	return nil
}

// recordWorkspacesTx records every named workspace for good, in id order:
// a new one with its kind and the time it was first named, and its status
// only with a higher wversion (README 6.2).
func recordWorkspacesTx(ctx context.Context, tx pgx.Tx, named map[uuid.UUID]ContractDocWorkspace) error {
	ids := make([]uuid.UUID, 0, len(named))
	for id := range named {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, compareIDs)
	for _, id := range ids {
		w := named[id]
		if _, err := tx.Exec(ctx, `INSERT INTO contract_workspaces (workspace_id, kind, wversion, status)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (workspace_id) DO UPDATE SET wversion = excluded.wversion, status = excluded.status
			WHERE contract_workspaces.wversion < excluded.wversion`, id, w.Kind, w.WVersion, w.Status); err != nil {
			return err
		}
	}
	return nil
}

// ContractWorkspace is one recorded platform workspace.
type ContractWorkspace struct {
	ID       uuid.UUID
	Kind     string
	NamedAt  time.Time
	WVersion int64
	// Status is open or closed, or empty before a document with a wversion
	// above the record's set it.
	Status string
}

// Workspace reads the record of a platform workspace, and false when no
// document has named it.
func (c *Contract) Workspace(ctx context.Context, id uuid.UUID) (ContractWorkspace, bool, error) {
	w := ContractWorkspace{ID: id}
	err := c.pool.QueryRow(ctx, `SELECT kind, named_at, wversion, coalesce(status, '') FROM contract_workspaces
		WHERE workspace_id = $1`, id).Scan(&w.Kind, &w.NamedAt, &w.WVersion, &w.Status)
	if errors.Is(err, pgx.ErrNoRows) {
		return ContractWorkspace{}, false, nil
	}
	return w, err == nil, err
}

// Intend commits the intent row of a PUT for sub, in its own statement and
// before the PUT is sent (the plan's DB21), and returns its subscribed_at:
// every subscription Wappie makes then has a row the sweep can see, and
// the sweep's removal names the intent it saw.
func (c *Contract) Intend(ctx context.Context, sub uuid.UUID) (time.Time, error) {
	var at time.Time
	err := c.pool.QueryRow(ctx, `INSERT INTO contract_accounts (sub) VALUES ($1)
		ON CONFLICT (sub) DO UPDATE SET subscribed_at = clock_timestamp()
		RETURNING subscribed_at`, sub).Scan(&at)
	return at, err
}

// ForgetIntent removes sub's row after the platform's signed unsubscribe,
// only while it is the intent seen and the sub is still not linked; false
// when a newer PUT or a link came meanwhile, and the caller subscribes
// again.
func (c *Contract) ForgetIntent(ctx context.Context, sub uuid.UUID, seen time.Time) (bool, error) {
	tag, err := c.pool.Exec(ctx, `DELETE FROM contract_accounts WHERE sub = $1 AND subscribed_at = $2
		AND NOT EXISTS (SELECT 1 FROM platform_identities WHERE sub = $1)`, sub, seen)
	return tag.RowsAffected() == 1, err
}

// ContractIntent is a subscription's row as the sweep reads it.
type ContractIntent struct {
	Sub          uuid.UUID
	SubscribedAt time.Time
}

// Orphans lists, oldest first, the subscriptions of subs Wappie does not
// hold whose last PUT's intent is older than after: a sign-up refused after
// its PUT, a failed unsubscribe, a ticket abandoned. The sweep unsubscribes
// them (the plan's 4.6).
func (c *Contract) Orphans(ctx context.Context, after time.Duration, limit int) ([]ContractIntent, error) {
	rows, err := c.pool.Query(ctx, `SELECT a.sub, a.subscribed_at FROM contract_accounts a
		WHERE a.subscribed_at < clock_timestamp() - $1::interval
		  AND NOT EXISTS (SELECT 1 FROM platform_identities pi WHERE pi.sub = a.sub)
		ORDER BY a.subscribed_at, a.sub LIMIT $2`, after, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (ContractIntent, error) {
		var i ContractIntent
		err := row.Scan(&i.Sub, &i.SubscribedAt)
		return i, err
	})
}

// unsubscribedSQL is the round's work: the subs Wappie holds (people linked
// to the platform, pi) whose row (a) is missing or carries no version of
// the stored generation (s). Unsubscribed lists them and RoundDone records
// that none is left, by the same predicate.
const unsubscribedSQL = `platform_identities pi
		CROSS JOIN contract_state s
		LEFT JOIN contract_accounts a ON a.sub = pi.sub
		WHERE a.version IS NULL OR a.generation IS DISTINCT FROM s.generation`

// Unsubscribed lists the subs Wappie holds (people linked to the platform)
// whose row is missing or carries no version of the stored generation: the
// round's work (the plan's 4.6). Those never tried come first, then the
// oldest attempt: every PUT's Intend moves its sub behind the rest, so subs
// whose PUTs keep failing never hide the ones after them.
func (c *Contract) Unsubscribed(ctx context.Context, limit int) ([]uuid.UUID, error) {
	rows, err := c.pool.Query(ctx, `SELECT pi.sub FROM `+unsubscribedSQL+`
		ORDER BY a.subscribed_at NULLS FIRST, pi.sub LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

// RoundDone records that every sub Wappie holds has a document of the
// generation gen (round_generation, the plan's 4.6), only while gen is
// still the stored generation and none is left to subscribe, and ends the
// run of failing passes (RoundFailed); false when either no longer holds,
// and the round is not done.
func (c *Contract) RoundDone(ctx context.Context, gen uuid.UUID) (bool, error) {
	tag, err := c.pool.Exec(ctx, `UPDATE contract_state SET round_generation = generation,
		round_error = NULL, round_error_at = NULL, updated_at = clock_timestamp()
		WHERE generation = $1 AND NOT EXISTS (SELECT 1 FROM `+unsubscribedSQL+`)`, gen)
	return tag.RowsAffected() == 1, err
}

// RoundFailed records that a pass of the round left held subs with no
// document, every PUT tried: class is the last failure's (a refusal's code,
// an outcome, a transport's class; never a message), and the run's start,
// kept from its first such pass, is what contract status --check measures
// (README 6.1: such a PUT is retried, and never means closed, so nothing
// else would tell anyone). RoundDone ends the run.
func (c *Contract) RoundFailed(ctx context.Context, class string) error {
	_, err := c.pool.Exec(ctx, `UPDATE contract_state SET round_error = $1,
		round_error_at = coalesce(round_error_at, clock_timestamp())`, class)
	return err
}

// Held reports whether Wappie holds sub, a person linked to the platform,
// read in a statement of its own: the refusal path of a sign-up asks it
// after the refusal, so a concurrent request that linked the sub since is
// seen (the plan's DB21).
func (c *Contract) Held(ctx context.Context, sub uuid.UUID) (bool, error) {
	var held bool
	err := c.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM platform_identities WHERE sub = $1)`, sub).Scan(&held)
	return held, err
}

// SubsOf maps each of users to the sub it is linked to; a user with no
// link to the platform is absent from the map.
func (c *Contract) SubsOf(ctx context.Context, users ...uuid.UUID) (map[uuid.UUID]uuid.UUID, error) {
	out := make(map[uuid.UUID]uuid.UUID, len(users))
	if len(users) == 0 {
		return out, nil
	}
	rows, err := c.pool.Query(ctx, `SELECT user_id, sub FROM platform_identities WHERE user_id = ANY ($1)`, users)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var user, sub uuid.UUID
		if err := rows.Scan(&user, &sub); err != nil {
			return nil, err
		}
		out[user] = sub
	}
	return out, rows.Err()
}

// Wake tells every contract loop (ContractModeChannel) that something
// changed outside a transaction that could carry the notice: a document of
// another generation in a sign-up whose transaction rolled back
// ("generation"), or a sub the platform answered not_found for, which the
// round subscribes again ("round").
func (c *Contract) Wake(ctx context.Context, why string) error {
	_, err := c.pool.Exec(ctx, `SELECT pg_notify($1, $2)`, ContractModeChannel, why)
	return err
}

// Unfollowed forgets sub's stored version after a signed not_found on a GET
// for it: the platform follows it no more, so its document stops counting
// for freshness through published_through, and the round subscribes it
// again. Its document and fresh_at stay.
func (c *Contract) Unfollowed(ctx context.Context, sub uuid.UUID) error {
	_, err := c.pool.Exec(ctx, `UPDATE contract_accounts SET generation = NULL, version = NULL WHERE sub = $1`, sub)
	return err
}

// Fresh says, for each sub, whether it is fresh within d on the database's
// clock: the later of its last answer and the last trusted
// published_through, the latter only for a sub the platform follows in the
// stored generation (README 7.1; the plan's DB8), and never while it is
// past the clock by more than ContractClockSkew. An unknown sub is stale.
func (c *Contract) Fresh(ctx context.Context, d time.Duration, subs ...uuid.UUID) (map[uuid.UUID]bool, error) {
	out := make(map[uuid.UUID]bool, len(subs))
	if len(subs) == 0 {
		return out, nil
	}
	rows, err := c.pool.Query(ctx, `SELECT q.sub, coalesce(greatest(a.fresh_at,
			CASE WHEN a.version IS NOT NULL AND a.generation = s.generation
			      AND s.published_through <= clock_timestamp() + $3::interval THEN s.published_through END)
			> clock_timestamp() - $2::interval, false)
		FROM unnest($1::uuid[]) AS q(sub)
		CROSS JOIN contract_state s
		LEFT JOIN contract_accounts a ON a.sub = q.sub`, subs, d, ContractClockSkew)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var sub uuid.UUID
		var fresh bool
		if err := rows.Scan(&sub, &fresh); err != nil {
			return nil, err
		}
		out[sub] = fresh
	}
	return out, rows.Err()
}

// Vouched says whether the last trusted published_through vouches for sub
// within d on the database's clock, on the terms Fresh counts it: only for
// a sub the platform follows in the stored generation, never while it is
// past the clock by more than ContractClockSkew. It is README 7.1's rule
// for a sign-in the platform did not answer: a returning person signs in on
// their last document only while it holds.
func (c *Contract) Vouched(ctx context.Context, d time.Duration, sub uuid.UUID) (bool, error) {
	var vouched bool
	err := c.pool.QueryRow(ctx, `SELECT coalesce(bool_or(a.version IS NOT NULL AND a.generation = s.generation
			AND s.published_through <= clock_timestamp() + $3::interval
			AND s.published_through > clock_timestamp() - $2::interval), false)
		FROM contract_state s LEFT JOIN contract_accounts a ON a.sub = $1`, sub, d, ContractClockSkew).Scan(&vouched)
	return vouched, err
}

// compareIDs orders UUIDs as Postgres does, byte by byte.
func compareIDs(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) }

// retryDeadlock runs fn again, at most twice more, when the server aborted
// it as a deadlock (40P01): fn is one whole transaction, so nothing of the
// aborted attempt stands.
func retryDeadlock(ctx context.Context, fn func() error) error {
	var err error
	for range 3 {
		if err = fn(); !isDeadlock(err) {
			return err
		}
		obs.LoggerFrom(ctx).Warn("store: a contract transaction deadlocked; retrying")
	}
	return err
}

func isDeadlock(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "40P01"
}
