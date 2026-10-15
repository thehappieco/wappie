package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/obs"
	"whatserver2/internal/pg"
)

// The contract's leader's writes (the plan's 4.4 and 4.7): the feed's
// pages, the restart a new generation or a gone asks for, the mode, and
// what contract status reads. Every write the leader makes to
// contract_state names what it read (compare-and-set), so a late commit of
// a leader that lost its lock changes nothing: the cursor never moves back
// and an old generation's documents are never stored after a restart.

// ContractPage is one signed feed answer, as the follower commits it
// (README 6.3).
type ContractPage struct {
	// After is the cursor the page was asked from, and SeenGeneration the
	// generation the follower held when it asked: nil while it held none
	// (the first observe, and after a gone).
	After          int64
	SeenGeneration *uuid.UUID
	// Generation and Confirmed are the page's.
	Generation uuid.UUID
	Confirmed  bool
	NextAfter  int64
	More       bool
	// PublishedThrough is trusted only when More is false.
	PublishedThrough time.Time
	// Docs are the page's documents, in its order.
	Docs []ContractDoc
	// Unreadable are the subs of the page's documents the follower could
	// not read (and logged at ERROR): Wappie does not hold their latest.
	Unreadable []uuid.UUID
}

// ContractPageResult is what committing a page did.
type ContractPageResult struct {
	// Committed: the cursor moved. False when the state was no longer the
	// one the page was asked from (another leader moved the cursor, or a
	// restart came in between): nothing was written, and the follower reads
	// the state again.
	Committed bool
	// Outcomes are its documents', in order (StoreDocuments').
	Outcomes []ContractDocOutcome
	// Vouched: its published_through was stored; Ahead: it was past the
	// database's clock by more than ContractClockSkew, and was not.
	Vouched, Ahead bool
}

// The classes of the leader's ERRORs, as RecordError keeps them.
const (
	ContractErrorFeedSilent      = "feed_silent"
	ContractErrorPublishedAhead  = "published_through_ahead"
	ContractErrorDocumentInvalid = "document_invalid"
	ContractErrorKindChanged     = "kind_changed"
	ContractErrorRoundIncomplete = "round_incomplete"
	// ContractErrorSnapshotParked: a workspace's snapshot parked, after a
	// day of not_found or on an invalid_request; ContractErrorSnapshotInvalid:
	// one Wappie would not send (over README 8's limits, or not valid).
	ContractErrorSnapshotParked  = "snapshot_parked"
	ContractErrorSnapshotInvalid = "snapshot_invalid"
)

// ErrPageGeneration is a page of another generation than the one the
// follower held: the follower restarts (Restart) instead.
var ErrPageGeneration = errors.New("store: a feed page of another generation is a restart, not a page")

// CommitPage stores a signed feed page in one transaction (the plan's 4.7,
// step 2), contract_state locked first: when no generation is stored, the
// page's is adopted with its confirmation; its documents are stored as a
// feed's (newer only, refreshing nobody: storeDocsTx); then the cursor
// moves to the page's next_after, by compare-and-set on the cursor and the
// generation the page was asked with, generation_confirmed is stored, and,
// only when more is false, published_through, unless it is past the
// database's clock by more than ContractClockSkew (then it is kept as it
// was, and logged and recorded at ERROR). A document that cannot be stored
// (invalid, kind_changed) or read (Unreadable) never holds the page back:
// the others and the cursor commit, and that sub's version is forgotten,
// as a GET's not_found forgets it (Unfollowed), so the page's
// published_through does not vouch for the older document Wappie still
// holds, and the round PUTs the sub again.
func (c *Contract) CommitPage(ctx context.Context, p ContractPage) (ContractPageResult, error) {
	if p.SeenGeneration != nil && *p.SeenGeneration != p.Generation {
		return ContractPageResult{}, ErrPageGeneration
	}
	if p.NextAfter < p.After {
		return ContractPageResult{}, fmt.Errorf("store: a feed page's next_after %d is behind its cursor %d", p.NextAfter, p.After)
	}
	var res ContractPageResult
	err := retryDeadlock(ctx, func() error {
		res = ContractPageResult{}
		return pg.InTx(ctx, c.pool, func(tx pgx.Tx) error {
			state, err := lockStateTx(ctx, tx)
			if err != nil {
				return err
			}
			if state.FeedCursor != p.After || !sameGeneration(state.Generation, p.SeenGeneration) {
				return nil
			}
			if state.Generation == nil {
				if _, err := tx.Exec(ctx, `UPDATE contract_state SET generation = $1, generation_confirmed = $2,
					updated_at = clock_timestamp() WHERE generation IS NULL`, p.Generation, p.Confirmed); err != nil {
					return err
				}
				g := p.Generation
				state.Generation = &g
			}
			if res.Outcomes, err = storeDocsTx(ctx, tx, state, ContractFeed, p.Docs); err != nil {
				return err
			}
			// The subs whose latest document Wappie does not hold.
			behind := slices.Clone(p.Unreadable)
			for i, o := range res.Outcomes {
				if o == ContractDocInvalid || o == ContractDocKindChanged {
					behind = append(behind, p.Docs[i].Sub)
				}
			}
			if err := forgetVersionsTx(ctx, tx, behind); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, `SELECT $1::timestamptz > clock_timestamp() + $2::interval`,
				p.PublishedThrough, ContractClockSkew).Scan(&res.Ahead); err != nil {
				return err
			}
			res.Vouched = !p.More && !res.Ahead
			tag, err := tx.Exec(ctx, `UPDATE contract_state SET feed_cursor = $1, generation_confirmed = $2,
				published_through = CASE WHEN $3 THEN $4 ELSE published_through END,
				feed_read_at = clock_timestamp(), feed_error = NULL, feed_error_at = NULL, updated_at = clock_timestamp()
				WHERE feed_cursor = $5 AND generation = $6`,
				p.NextAfter, p.Confirmed, res.Vouched, p.PublishedThrough, p.After, p.Generation)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return fmt.Errorf("store: the feed's cursor moved under contract_state's lock")
			}
			res.Committed = true
			class := ""
			if len(p.Unreadable) > 0 {
				class = ContractErrorDocumentInvalid
			}
			if !p.More && res.Ahead {
				obs.LoggerFrom(ctx).Error("contract: published_through ahead of the clock; the last trusted one is kept",
					"generation", p.Generation, "cursor", p.NextAfter)
				class = ContractErrorPublishedAhead
			}
			for _, o := range res.Outcomes {
				switch o {
				case ContractDocInvalid:
					class = ContractErrorDocumentInvalid
				case ContractDocKindChanged:
					class = ContractErrorKindChanged
				}
			}
			if class != "" {
				return recordErrorTx(ctx, tx, class)
			}
			return nil
		})
	})
	return res, err
}

// forgetVersionsTx forgets the stored version of each of subs, in sub
// order (DB23), keeping each row's document and fresh_at.
func forgetVersionsTx(ctx context.Context, tx pgx.Tx, subs []uuid.UUID) error {
	if len(subs) == 0 {
		return nil
	}
	if _, err := tx.Exec(ctx, `SELECT 1 FROM contract_accounts WHERE sub = ANY ($1) ORDER BY sub FOR UPDATE`, subs); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE contract_accounts SET generation = NULL, version = NULL WHERE sub = ANY ($1)`, subs)
	return err
}

func sameGeneration(a, b *uuid.UUID) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// Restart forgets what the stored generation said (README 7.4; the plan's
// 4.7, "The restart"), by compare-and-set on the generation and cursor the
// follower read: generation becomes gen (nil after a gone, and the first
// answer stored adopts the next) with its confirmation, the cursor 0,
// published_through and the round's generation unset; every account loses
// its version and fresh_at, keeping its document and its highest
// disabled_at, sessions_revoked_at and credentials_revoked_at; every
// recorded workspace gets wversion 0 (a restored platform's lower wversion
// is then applied, README 7.4 "forgets ... its stored versions"), keeping
// its status, and a snapshot and event queue due now, with no accepted
// snapshot (the platform may hold none of this generation) and nothing
// parked. (P5 releases the events parked not_found here.) It reports
// whether it restarted: false when the state moved since it was read.
func (c *Contract) Restart(ctx context.Context, seenGeneration *uuid.UUID, seenCursor int64, gen *uuid.UUID, confirmed bool) (bool, error) {
	done := false
	err := retryDeadlock(ctx, func() error {
		done = false
		return pg.InTx(ctx, c.pool, func(tx pgx.Tx) error {
			state, err := lockStateTx(ctx, tx)
			if err != nil {
				return err
			}
			if state.FeedCursor != seenCursor || !sameGeneration(state.Generation, seenGeneration) {
				return nil
			}
			if _, err := tx.Exec(ctx, `UPDATE contract_state SET generation = $1::uuid, generation_confirmed = $2 AND $1::uuid IS NOT NULL,
				feed_cursor = 0, published_through = NULL, round_generation = NULL, updated_at = clock_timestamp()`,
				gen, confirmed); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE contract_accounts SET generation = NULL, version = NULL, fresh_at = NULL
				WHERE version IS NOT NULL OR fresh_at IS NOT NULL`); err != nil {
				return err
			}
			// In id order (DB23), as every writer of these rows.
			if _, err := tx.Exec(ctx, `SELECT 1 FROM contract_workspaces ORDER BY workspace_id FOR UPDATE`); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE contract_workspaces SET wversion = 0,
				snapshot_due_at = clock_timestamp(), snapshot_tries = 0, snapshot_ok_at = NULL,
				events_due_at = CASE WHEN events_due_at IS NULL THEN NULL ELSE clock_timestamp() END, events_tries = 0,
				not_found_since = NULL, parked_at = NULL`); err != nil {
				return err
			}
			done = true
			return nil
		})
	})
	return done, err
}

// Recovered makes due now the snapshot and the event queue of every
// recorded workspace that is backing off, with their tries reset: the
// leader calls it on its first signed feed answer after a run of failures,
// so the snapshots and queues come back with the platform, not up to an
// hour later (the plan's 4.7, "Round 2, recovery"). It returns how many it
// woke.
func (c *Contract) Recovered(ctx context.Context) (int64, error) {
	var n int64
	err := pg.InTx(ctx, c.pool, func(tx pgx.Tx) error {
		// contract_state first, as the follower's writers of several of
		// these rows, then the rows in id order (DB23), locked and written
		// in one statement: a row that starts backing off meanwhile is never
		// locked out of order.
		if _, err := lockStateTx(ctx, tx); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE contract_workspaces w SET
			snapshot_due_at = clock_timestamp(), snapshot_tries = 0,
			events_due_at = CASE WHEN w.events_due_at IS NULL THEN NULL ELSE least(w.events_due_at, clock_timestamp()) END, events_tries = 0
			FROM (`+lockWorkspacesSQL(`snapshot_tries > 0 OR events_tries > 0`)+`) l WHERE w.workspace_id = l.workspace_id`)
		n = tag.RowsAffected()
		return err
	})
	return n, err
}

// FeedFailed records that a feed call got no signed page: its class (an
// outcome, a refusal's code, a transport's class; never a message), and,
// kept from the first failure of the run, since when. A page's commit
// clears both.
func (c *Contract) FeedFailed(ctx context.Context, class string) error {
	_, err := c.pool.Exec(ctx, `UPDATE contract_state SET feed_error = $1,
		feed_error_at = coalesce(feed_error_at, clock_timestamp())`, class)
	return err
}

// RecordError keeps the class of a contract ERROR the leader logged, which
// contract status --check reports for a day: the service user cannot read
// the system journal, and the database is what every process shares.
func (c *Contract) RecordError(ctx context.Context, class string) error {
	_, err := c.pool.Exec(ctx, `UPDATE contract_state SET error_class = $1, error_at = clock_timestamp()`, class)
	return err
}

func recordErrorTx(ctx context.Context, tx pgx.Tx, class string) error {
	_, err := tx.Exec(ctx, `UPDATE contract_state SET error_class = $1, error_at = clock_timestamp()`, class)
	return err
}

// ContractModeChange is what a switch of mode did.
type ContractModeChange struct {
	From, To string
	// Changed: the mode was another; a switch to the mode it is in changes
	// nothing.
	Changed bool
	// At a switch to observe after an off period: ToSend counts the events
	// it will now send (written before the pause and not yet delivered, and
	// the deletions, recoveries and purges written while off); HeldBack the
	// pauses, strandings and moves written while off, never sent (the
	// plan's DB10, 4.4).
	ToSend, HeldBack int64
}

// ErrContractMode is a mode Wappie does not know.
var ErrContractMode = errors.New("store: the contract's mode is off or observe")

// SetMode switches the contract's mode in one transaction (the plan's 4.4)
// and wakes every process's contract loop. To observe: events_from is set
// the first time only, the off period that ends now joins events_off, and
// the round is due again (round_generation unset). To off: the period
// starts (events_paused_at). It waits for a sign-up in flight, which reads
// the state FOR SHARE, so the round that follows subscribes that account.
func (c *Contract) SetMode(ctx context.Context, mode string) (ContractModeChange, error) {
	if mode != ContractOff && mode != ContractObserve {
		return ContractModeChange{}, ErrContractMode
	}
	var out ContractModeChange
	err := pg.InTx(ctx, c.pool, func(tx pgx.Tx) error {
		state, err := lockStateTx(ctx, tx)
		if err != nil {
			return err
		}
		out = ContractModeChange{From: state.Mode, To: mode}
		if state.Mode == mode {
			return nil
		}
		out.Changed = true
		var paused *time.Time
		if mode == ContractObserve {
			paused = state.EventsPausedAt
			_, err = tx.Exec(ctx, `UPDATE contract_state SET mode = 'observe', mode_changed_at = clock_timestamp(),
				events_from = coalesce(events_from, clock_timestamp()),
				events_off = CASE WHEN events_paused_at IS NULL THEN events_off
				                  ELSE events_off + tstzmultirange(tstzrange(events_paused_at, clock_timestamp())) END,
				events_paused_at = NULL, round_generation = NULL, updated_at = clock_timestamp()`)
		} else {
			_, err = tx.Exec(ctx, `UPDATE contract_state SET mode = $1, mode_changed_at = clock_timestamp(),
				events_paused_at = CASE WHEN events_from IS NULL THEN NULL ELSE clock_timestamp() END,
				updated_at = clock_timestamp()`, mode)
		}
		if err != nil {
			return err
		}
		if paused != nil {
			if out.ToSend, out.HeldBack, err = offPeriodCountsTx(ctx, tx, *paused); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, `SELECT pg_notify($1, 'mode')`, ContractModeChannel)
		return err
	})
	return out, err
}

// eligibleEventSQL is the plan's DB10 for a row e of item_events in the
// recorded workspace w, with contract_state s: not settled, not parked,
// and either written (not replayed) at or after both the first observe and
// the workspace's naming, a pause, a stranding or a move not in an off
// period; or replayed, a deletion, a recovery or a purge, which occurred at
// or after both. (P5's sender takes this predicate with its expiry.)
const eligibleEventSQL = `s.events_from IS NOT NULL AND e.settled_at IS NULL AND e.parked_at IS NULL AND (
	(e.replayed_at IS NULL AND e.created_at >= greatest(s.events_from, w.named_at)
	 AND (e.type IN ('deleted', 'recovered', 'purged')
	      OR NOT (s.events_off @> e.created_at OR (s.events_paused_at IS NOT NULL AND e.created_at >= s.events_paused_at))))
	OR (e.replayed_at IS NOT NULL AND e.type IN ('deleted', 'recovered', 'purged')
	 AND e.occurred_at >= greatest(s.events_from, w.named_at)))`

// offPeriodCountsTx counts, after a switch to observe that ended the off
// period begun at paused, the events now to send and the ones held back
// for good, workspace by workspace (item_events is each workspace's).
func offPeriodCountsTx(ctx context.Context, tx pgx.Tx, paused time.Time) (toSend, heldBack int64, err error) {
	rows, err := tx.Query(ctx, `SELECT w.workspace_id FROM contract_workspaces w JOIN tenants t ON t.id = w.workspace_id
		ORDER BY w.workspace_id`)
	if err != nil {
		return 0, 0, err
	}
	workspaces, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return 0, 0, err
	}
	for _, ws := range workspaces {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, ws.String()); err != nil {
			return 0, 0, err
		}
		var send, held int64
		if err := tx.QueryRow(ctx, `SELECT
				count(*) FILTER (WHERE `+eligibleEventSQL+`),
				count(*) FILTER (WHERE e.settled_at IS NULL AND e.parked_at IS NULL AND e.replayed_at IS NULL
				                   AND e.type IN ('sync_paused', 'stranded', 'moved_out')
				                   AND e.created_at >= greatest(s.events_from, w.named_at) AND e.created_at >= $2)
			FROM item_events e CROSS JOIN contract_state s JOIN contract_workspaces w ON w.workspace_id = $1
			WHERE e.tenant_id = $1`, ws, paused).Scan(&send, &held); err != nil {
			return 0, 0, err
		}
		toSend += send
		heldBack += held
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', '', true)`); err != nil {
		return 0, 0, err
	}
	return toSend, heldBack, nil
}

// ContractWorkspaceStatus is one recorded workspace as contract status
// shows it: ids, times and counts.
type ContractWorkspaceStatus struct {
	ID            uuid.UUID
	Kind          string
	Status        string
	NamedAt       time.Time
	SnapshotOKAt  *time.Time
	SnapshotDueAt time.Time
	SnapshotTries int
	// SnapshotError is the class of the last snapshot not accepted, ""
	// once one is.
	SnapshotError string
	NotFoundSince *time.Time
	ParkedAt      *time.Time
	// Local: Wappie has a workspace of this id.
	Local bool
	// The workspace's events: eligible and not yet delivered, parked, and
	// folded into another.
	Pending, Parked, Coalesced int64
}

// ContractStatus is what whatserverd contract status reads, in one
// snapshot of the database, with its clock.
type ContractStatus struct {
	State ContractState
	Now   time.Time
	// Held is how many subs Wappie holds; Followed how many of them have a
	// document of the stored generation; Accounts how many rows there are
	// (subscriptions Wappie made, orphans included).
	Held, Followed, Accounts int64
	Workspaces               []ContractWorkspaceStatus
}

// Status reads the contract's state, its counts and every recorded
// workspace, in one REPEATABLE READ transaction.
func (c *Contract) Status(ctx context.Context) (ContractStatus, error) {
	var out ContractStatus
	err := pgx.BeginTxFunc(ctx, c.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var err error
		if out.State, err = scanContractState(tx.QueryRow(ctx, `SELECT `+contractStateColumns+` FROM contract_state`)); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp(),
				(SELECT count(*) FROM platform_identities),
				(SELECT count(*) FROM platform_identities pi JOIN contract_accounts a ON a.sub = pi.sub
				   CROSS JOIN contract_state s WHERE a.version IS NOT NULL AND a.generation = s.generation),
				(SELECT count(*) FROM contract_accounts)`).Scan(&out.Now, &out.Held, &out.Followed, &out.Accounts); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT w.workspace_id, w.kind, coalesce(w.status, ''), w.named_at, w.snapshot_ok_at,
				w.snapshot_due_at, w.snapshot_tries, coalesce(w.snapshot_error, ''), w.not_found_since, w.parked_at, t.id IS NOT NULL
			FROM contract_workspaces w LEFT JOIN tenants t ON t.id = w.workspace_id ORDER BY w.named_at, w.workspace_id`)
		if err != nil {
			return err
		}
		out.Workspaces, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (ContractWorkspaceStatus, error) {
			var w ContractWorkspaceStatus
			err := row.Scan(&w.ID, &w.Kind, &w.Status, &w.NamedAt, &w.SnapshotOKAt, &w.SnapshotDueAt, &w.SnapshotTries,
				&w.SnapshotError, &w.NotFoundSince, &w.ParkedAt, &w.Local)
			return w, err
		})
		if err != nil {
			return err
		}
		for i := range out.Workspaces {
			w := &out.Workspaces[i]
			if !w.Local {
				continue
			}
			if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, w.ID.String()); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, `SELECT
					count(*) FILTER (WHERE `+eligibleEventSQL+`),
					count(*) FILTER (WHERE e.parked_at IS NOT NULL),
					count(*) FILTER (WHERE e.outcome = 'coalesced' OR (e.coalesced_into IS NOT NULL AND e.settled_at IS NULL))
				FROM item_events e CROSS JOIN contract_state s JOIN contract_workspaces w ON w.workspace_id = $1
				WHERE e.tenant_id = $1`, w.ID).Scan(&w.Pending, &w.Parked, &w.Coalesced); err != nil {
				return err
			}
		}
		return nil
	})
	return out, err
}
