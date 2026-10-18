package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/pg"
)

// The contract's events (README 9; the plan's 4.11, DB10, DB11 and DB23):
// each recorded platform workspace's queue over release A's item_events
// rows, as the leader's sender reads, folds, settles and parks them.
// internal/membership renders each row into the contract's event at send
// time and sends it; nothing here calls the platform, and no row is ever
// rendered inside a writer's transaction.
//
// Every transaction here takes its locks in one order (DB23): the
// workspace's record (contract_workspaces, FOR UPDATE: one queue's state,
// so two leaders' transactions on one queue run one after the other), then
// the workspace itself (FOR KEY SHARE: behind a purge's or a pause's FOR
// UPDATE, never across it), then its item_events rows, in seq order and in
// one statement. None of them takes contract_state's lock or records an
// ERROR inside: a document's store takes contract_state, then records,
// then these rows (the release of a not_found park), and a transaction
// here that held a record and asked for contract_state would cross it.

// The outcomes of an event in the platform's answer (README 9).
const (
	ContractEventAccepted  = "accepted"
	ContractEventDuplicate = "duplicate"
	ContractEventRejected  = "rejected"
)

// Why a row is parked (item_events.reject_code): the platform's verdict on
// it (invalid_request, not_found for a day, conflict), Wappie's own check
// before a send (local_invalid), or its 29 days spent unsent (expired).
const (
	EventParkedInvalid      = "invalid_request"
	EventParkedNotFound     = "not_found"
	EventParkedLocalInvalid = "local_invalid"
	EventParkedConflict     = "conflict"
	EventParkedExpired      = "expired"
)

// ContractEventExpiry is how long after it occurred an event is sent: the
// platform's inbox recognises a duplicate only while it holds the event,
// 30 days (README 11), so a row not delivered by then is parked as expired
// rather than mailed again or late (the plan's 4.11).
const ContractEventExpiry = 29 * 24 * time.Hour

// eventExpirySQL is ContractEventExpiry as an SQL interval, the one every
// statement here reads.
var eventExpirySQL = fmt.Sprintf("interval '%d hours'", int64(ContractEventExpiry/time.Hour))

// ContractEventNotFoundFor is how long a queue is retried after the
// platform first answered not_found for one of its events, before its rows
// are parked (README 9: a workspace the app was not told of).
const ContractEventNotFoundFor = 24 * time.Hour

// owedEventSQL is the plan's DB10 for a row e of item_events in the
// recorded workspace w, with contract_state s: not settled, not parked,
// and either written (not replayed) at or after both the first observe and
// the workspace's naming, a pause, a stranding or a move not in an off
// period (the current one included); or replayed, a deletion, a recovery
// or a purge, which occurred at or after both.
const owedEventSQL = `s.events_from IS NOT NULL AND e.settled_at IS NULL AND e.parked_at IS NULL AND (
	(e.replayed_at IS NULL AND e.created_at >= greatest(s.events_from, w.named_at)
	 AND (e.type IN ('deleted', 'recovered', 'purged')
	      OR NOT (s.events_off @> e.created_at OR (s.events_paused_at IS NOT NULL AND e.created_at >= s.events_paused_at))))
	OR (e.replayed_at IS NOT NULL AND e.type IN ('deleted', 'recovered', 'purged')
	 AND e.occurred_at >= greatest(s.events_from, w.named_at)))`

// eligibleEventSQL is the one predicate the sender, the housekeeping and
// contract status share (the plan's 4.11, "eligible"): owed, and under
// ContractEventExpiry since it occurred. An owed row past it is parked as
// expired, by the sender or by the hourly housekeeping, whichever meets it
// first.
var eligibleEventSQL = owedEventSQL + ` AND e.occurred_at > clock_timestamp() - ` + eventExpirySQL

// releasableEventSQL is a row e parked for the platform's not_found that a
// release sends again: under ContractEventExpiry (it was eligible when it
// was parked, and its periods do not change).
var releasableEventSQL = `e.parked_at IS NOT NULL AND e.reject_code = 'not_found' AND e.settled_at IS NULL
	AND e.occurred_at > clock_timestamp() - ` + eventExpirySQL

// owedFromSQL joins what owedEventSQL reads: e, s and w.
const owedFromSQL = `item_events e CROSS JOIN contract_state s JOIN contract_workspaces w ON w.workspace_id = e.tenant_id`

// ContractEvent is one event of a queue as the sender renders it: an
// item_events row, with the readers of the rows folded into it (DB11).
type ContractEvent struct {
	EventID uuid.UUID
	Seq     int64
	// Type is item_events.type: deleted, sync_paused, recovered, purged,
	// moved_out or stranded.
	Type       string
	ItemID     uuid.UUID
	OccurredAt time.Time
	// ActorKind is person, key or app. ActorSub is the person's sub, or
	// the key's creator's: the row's, else (a replayed row keeps none) the
	// sub its local account is linked to now. ActorUser is the local
	// account, never sent.
	ActorKind string
	ActorSub  *uuid.UUID
	ActorUser *uuid.UUID
	// Readers are the subs of the row's readers just before (the actor
	// among them when they read it), then of each row folded into it, each
	// once.
	Readers []uuid.UUID
	// Label and Hint are the row's (nulled at the purge); a replayed row
	// keeps none, and takes its number's at send time, until its purge.
	Label, Hint *string
	// PurgeAfter is a deletion's.
	PurgeAfter *time.Time
	// PersonSub and Cause are a stranding's.
	PersonSub *uuid.UUID
	Cause     *string
	Replayed  bool
	// Folded counts the rows folded into it.
	Folded int
}

// ActorUnknown reports a person, or a key whose creator is known, with no
// platform sub: a fault where people sign in through the platform (README
// 9: such an actor goes as actor null). A key with no creator has nobody
// behind it, and a replayed row with no local account no sub to miss: the
// ledger keeps no actor of a recovery, and a deletion's deleter may be gone
// since. Both still go as actor null.
func (e ContractEvent) ActorUnknown() bool {
	if e.Replayed && e.ActorUser == nil {
		return false
	}
	switch e.ActorKind {
	case actorPerson:
		return e.ActorSub == nil
	case actorKey:
		return e.ActorSub == nil && e.ActorUser != nil
	}
	return false
}

// ContractEventBatch is the head of one workspace's queue, as EventBatch
// read and folded it.
type ContractEventBatch struct {
	Workspace uuid.UUID
	// ReadAt is the database's clock when it was read: a failure recorded
	// against it leaves a due time someone set since (EventsFailed's Again).
	ReadAt time.Time
	// Events are the queue's first events, at most the limit, in seq order.
	Events []ContractEvent
	// More: the queue holds events past them.
	More bool
	// Expired are the rows this read parked as expired, heads and the rows
	// folded into them.
	Expired []uuid.UUID
	// NotSent counts the pauses settled with nobody but their actor to
	// tell; Coalesced the rows settled into a pause, one delivered before
	// or one not sent.
	NotSent, Coalesced int
}

// pendingEvent is one owed row of a queue while EventBatch folds it.
type pendingEvent struct {
	ContractEvent
	// own are the row's own readers; into its coalesced_into, as the
	// database holds it (was) and as the fold leaves it.
	own       []uuid.UUID
	into, was *uuid.UUID
	expired   bool
	done      bool
}

// deliveredPause is a sync_paused row the platform accepted, or held
// already: a later pause of the same item and actor under an hour after it
// is folded into it and never sent.
type deliveredPause struct {
	seq        int64
	id, item   uuid.UUID
	kind       string
	user       *uuid.UUID
	occurredAt time.Time
}

// sameActor is DB11's actor: the kind and the local account (a key's
// creator for a key), the same nobody included.
func sameActor(kind string, user *uuid.UUID, otherKind string, other *uuid.UUID) bool {
	if kind != otherKind {
		return false
	}
	if user == nil || other == nil {
		return user == nil && other == nil
	}
	return *user == *other
}

// lockQueueTx takes the queue's locks in DB23's order: workspace's record,
// then the workspace, and reads the database's clock. False when no
// document named the workspace.
func lockQueueTx(ctx context.Context, tx pgx.Tx, workspace uuid.UUID) (time.Time, bool, error) {
	var now time.Time
	err := tx.QueryRow(ctx, `SELECT clock_timestamp() FROM contract_workspaces WHERE workspace_id = $1 FOR UPDATE`, workspace).Scan(&now)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	return now, true, shareWorkspaceTx(ctx, tx, workspace)
}

// EventBatch reads the head of the platform workspace's queue, at most
// limit events, in one transaction that locks every owed row (DB23), and
// writes what reading decides (the plan's 4.11):
//   - an owed row whose 29 days are spent is parked as expired, with the
//     rows folded into it;
//   - a pause (DB11): folded, settled at once, into an earlier pause of the
//     same item and actor under an hour before it that the platform took
//     (whose answer is in already); else every later owed pause of the
//     same item and actor under an hour after it is folded into it
//     (coalesced_into, settled only with its answer), and it carries the
//     union of their readers; and then, when nobody but its actor reads,
//     settled as not_sent with its folded rows (README 9);
//   - a row folded into one that is no longer owed heads its own event.
//
// A replayed row's label and hint are its number's, read with deleted
// numbers visible, until its purge.
func (c *Contract) EventBatch(ctx context.Context, workspace uuid.UUID, limit int) (ContractEventBatch, error) {
	if limit < 1 {
		return ContractEventBatch{}, fmt.Errorf("store: an event batch of %d", limit)
	}
	var out ContractEventBatch
	err := retryDeadlock(ctx, func() error {
		out = ContractEventBatch{Workspace: workspace}
		return pg.InTenantTx(ctx, c.pool, workspace.String(), func(tx pgx.Tx) error {
			now, ok, err := lockQueueTx(ctx, tx, workspace)
			if err != nil || !ok {
				return err
			}
			out.ReadAt = now
			rows, err := owedEventsTx(ctx, tx, workspace)
			if err != nil || len(rows) == 0 {
				return err
			}
			delivered, err := deliveredPausesTx(ctx, tx, workspace, rows)
			if err != nil {
				return err
			}
			foldEvents(rows, delivered, limit, &out)
			if err := writeFoldsTx(ctx, tx, workspace, rows); err != nil {
				return err
			}
			return replayedLabelsTx(ctx, tx, out.Events)
		})
	})
	return out, err
}

// owedEventsTx locks and reads every owed row of the workspace of tx, in
// seq order, each marked expired when its 29 days are spent.
func owedEventsTx(ctx context.Context, tx pgx.Tx, workspace uuid.UUID) ([]pendingEvent, error) {
	rows, err := tx.Query(ctx, `SELECT e.seq, e.event_id, e.type, e.item_id, e.occurred_at, e.actor_kind,
			coalesce(e.actor_sub, CASE WHEN e.actor_kind <> 'app' THEN (SELECT pi.sub FROM platform_identities pi WHERE pi.user_id = e.actor_user_id) END),
			e.actor_user_id, e.reader_subs, e.label, e.hint, e.purge_after, e.person_sub, e.cause, e.replayed_at IS NOT NULL,
			e.coalesced_into, e.occurred_at <= clock_timestamp() - `+eventExpirySQL+`
		FROM `+owedFromSQL+`
		WHERE e.tenant_id = $1 AND `+owedEventSQL+`
		ORDER BY e.seq FOR UPDATE OF e`, workspace)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (pendingEvent, error) {
		var p pendingEvent
		e := &p.ContractEvent
		err := row.Scan(&e.Seq, &e.EventID, &e.Type, &e.ItemID, &e.OccurredAt, &e.ActorKind, &e.ActorSub, &e.ActorUser, &p.own,
			&e.Label, &e.Hint, &e.PurgeAfter, &e.PersonSub, &e.Cause, &e.Replayed, &p.was, &p.expired)
		p.into = p.was
		return p, err
	})
}

// deliveredPausesTx reads the pauses the platform took that a pending
// pause of rows could fold into: under an hour before the earliest.
func deliveredPausesTx(ctx context.Context, tx pgx.Tx, workspace uuid.UUID, rows []pendingEvent) ([]deliveredPause, error) {
	var earliest *time.Time
	for i := range rows {
		if r := &rows[i]; r.Type == eventSyncPaused && (earliest == nil || r.OccurredAt.Before(*earliest)) {
			earliest = &r.OccurredAt
		}
	}
	if earliest == nil {
		return nil, nil
	}
	q, err := tx.Query(ctx, `SELECT seq, event_id, item_id, actor_kind, actor_user_id, occurred_at FROM item_events
		WHERE tenant_id = $1 AND type = 'sync_paused' AND outcome IN ('accepted', 'duplicate')
		  AND occurred_at > $2::timestamptz - interval '1 hour' ORDER BY seq`, workspace, *earliest)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(q, func(row pgx.CollectableRow) (deliveredPause, error) {
		var d deliveredPause
		err := row.Scan(&d.seq, &d.id, &d.item, &d.kind, &d.user, &d.occurredAt)
		return d, err
	})
}

// foldEvents decides, in memory, what EventBatch writes: the expired rows,
// the folds and the settled pauses, and the batch's events (the plan's
// 4.11, DB11).
func foldEvents(rows []pendingEvent, delivered []deliveredPause, limit int, out *ContractEventBatch) {
	byID := make(map[uuid.UUID]int, len(rows))
	for i := range rows {
		byID[rows[i].EventID] = i
	}
	// The 29 days: an expired row is parked with every row folded into it.
	for i := range rows {
		r := &rows[i]
		if !r.expired && r.was != nil {
			if j, ok := byID[*r.was]; ok && rows[j].expired && rows[j].was == nil {
				r.expired = true
			}
		}
		if r.expired {
			r.done = true
			out.Expired = append(out.Expired, r.EventID)
		}
	}
	// A row folded into one that is not an owed head heads its own event.
	for i := range rows {
		r := &rows[i]
		if r.done || r.into == nil {
			continue
		}
		if j, ok := byID[*r.into]; !ok || rows[j].done || rows[j].into != nil {
			r.into = nil
		}
	}
	for i := range rows {
		r := &rows[i]
		if r.done || r.into != nil {
			continue
		}
		if len(out.Events) == limit {
			out.More = true
			break
		}
		ev := r.ContractEvent
		ev.Readers = union(r.own)
		if r.Type == eventSyncPaused {
			if d := deliveredWithin(delivered, r); d != nil {
				// Its answer is in already: folded into it, settled now; the
				// rows folded into this one head their own events, each
				// weighed in its turn (they follow it in seq order).
				id := d.id
				r.into, r.done = &id, true
				out.Coalesced++
				for k := range rows {
					if f := &rows[k]; !f.done && f.into != nil && *f.into == r.EventID {
						f.into = nil
					}
				}
				continue
			}
			for k := i + 1; k < len(rows); k++ {
				f := &rows[k]
				if !f.done && f.into == nil && f.Type == eventSyncPaused && f.ItemID == r.ItemID &&
					sameActor(r.ActorKind, r.ActorUser, f.ActorKind, f.ActorUser) && f.OccurredAt.Before(r.OccurredAt.Add(time.Hour)) {
					head := r.EventID
					f.into = &head
				}
			}
			var folded []int
			lists := [][]uuid.UUID{r.own}
			for k := range rows {
				if f := &rows[k]; !f.done && f.into != nil && *f.into == r.EventID {
					folded = append(folded, k)
					lists = append(lists, f.own)
				}
			}
			ev.Readers = union(lists...)
			ev.Folded = len(folded)
			if !othersRead(ev.Readers, ev.ActorSub) {
				// Nobody but the actor to tell (README 9): not sent, its
				// folded rows settled with it.
				r.done = true
				out.NotSent++
				for _, k := range folded {
					rows[k].done = true
					out.Coalesced++
				}
				continue
			}
		}
		out.Events = append(out.Events, ev)
	}
}

// deliveredWithin is the delivered pause r folds into: the same item and
// actor, before it in the queue, under an hour before it.
func deliveredWithin(delivered []deliveredPause, r *pendingEvent) *deliveredPause {
	for i := len(delivered) - 1; i >= 0; i-- {
		d := &delivered[i]
		if d.seq < r.Seq && d.item == r.ItemID && sameActor(d.kind, d.user, r.ActorKind, r.ActorUser) &&
			r.OccurredAt.Sub(d.occurredAt) < time.Hour {
			return d
		}
	}
	return nil
}

// othersRead reports whether anyone but actor is among readers.
func othersRead(readers []uuid.UUID, actor *uuid.UUID) bool {
	for _, r := range readers {
		if actor == nil || r != *actor {
			return true
		}
	}
	return false
}

// union is every sub of lists, in their order, each once.
func union(lists ...[]uuid.UUID) []uuid.UUID {
	out := []uuid.UUID{}
	seen := map[uuid.UUID]bool{}
	for _, l := range lists {
		for _, id := range l {
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	return out
}

// writeFoldsTx writes what foldEvents decided, on rows owedEventsTx locked:
// the expired rows parked; the pauses settled (not_sent, or coalesced into
// a delivered one) with their folded rows; and every other row's
// coalesced_into where it changed.
func writeFoldsTx(ctx context.Context, tx pgx.Tx, workspace uuid.UUID, rows []pendingEvent) error {
	var expired, settled, linked []int64
	var outcomes []string
	var heads, links []*uuid.UUID
	for i := range rows {
		r := &rows[i]
		switch {
		case r.expired:
			expired = append(expired, r.Seq)
		case r.done && r.into != nil:
			settled, outcomes, heads = append(settled, r.Seq), append(outcomes, "coalesced"), append(heads, r.into)
		case r.done:
			settled, outcomes, heads = append(settled, r.Seq), append(outcomes, "not_sent"), append(heads, nil)
		case !sameHead(r.into, r.was):
			linked, links = append(linked, r.Seq), append(links, r.into)
		}
	}
	if len(expired) > 0 {
		if _, err := tx.Exec(ctx, `UPDATE item_events SET parked_at = clock_timestamp(), reject_code = 'expired'
			WHERE tenant_id = $1 AND seq = ANY ($2)`, workspace, expired); err != nil {
			return fmt.Errorf("store: park the expired events: %w", err)
		}
	}
	if len(settled) > 0 {
		if _, err := tx.Exec(ctx, `UPDATE item_events e SET settled_at = clock_timestamp(), outcome = u.outcome, coalesced_into = u.head
			FROM unnest($2::bigint[], $3::text[], $4::uuid[]) AS u(seq, outcome, head)
			WHERE e.tenant_id = $1 AND e.seq = u.seq`, workspace, settled, outcomes, heads); err != nil {
			return fmt.Errorf("store: settle the folded pauses: %w", err)
		}
	}
	if len(linked) > 0 {
		if _, err := tx.Exec(ctx, `UPDATE item_events e SET coalesced_into = u.head
			FROM unnest($2::bigint[], $3::uuid[]) AS u(seq, head)
			WHERE e.tenant_id = $1 AND e.seq = u.seq`, workspace, linked, links); err != nil {
			return fmt.Errorf("store: fold the pauses: %w", err)
		}
	}
	return nil
}

func sameHead(a, b *uuid.UUID) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// replayedLabelsTx gives each replayed event its number's label and hint,
// read with deleted numbers visible: the ledger keeps none. A purged
// number has no row left, and none; a purge has none either, whether or not
// the janitor has purged the number yet, as the live purge's row has none
// (purge.go).
func replayedLabelsTx(ctx context.Context, tx pgx.Tx, events []ContractEvent) error {
	labelled := func(e ContractEvent) bool { return e.Replayed && e.Type != eventPurged }
	var ids []uuid.UUID
	for _, e := range events {
		if labelled(e) {
			ids = append(ids, e.ItemID)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	return withQuarantine(ctx, tx, func() error {
		rows, err := tx.Query(ctx, `SELECT id, label, push_name, coalesce(pn, '') FROM devices WHERE id = ANY ($1)`, ids)
		if err != nil {
			return err
		}
		type names struct{ label, hint *string }
		found := map[uuid.UUID]names{}
		err = forEachRow(rows, func(row pgx.Rows) error {
			var id uuid.UUID
			var name, pushName, pn string
			if err := row.Scan(&id, &name, &pushName, &pn); err != nil {
				return err
			}
			l, h := itemLabel(id, name, pushName, pn)
			found[id] = names{l, h}
			return nil
		})
		if err != nil {
			return err
		}
		for i := range events {
			if n, ok := found[events[i].ItemID]; ok && labelled(events[i]) {
				events[i].Label, events[i].Hint = n.label, n.hint
			}
		}
		return nil
	})
}

// ContractEventResult is the platform's verdict on one event sent, matched
// to it by position (README 9).
type ContractEventResult struct {
	EventID uuid.UUID
	// Outcome is accepted, duplicate or rejected; Code a rejection's:
	// invalid_request, not_found or conflict.
	Outcome, Code string
}

// ContractEventTimes are the queue's backoff after a failure: BackoffMin
// doubled with each failure in a row, up to BackoffMax (README 9: 5 s ×
// 2ⁿ, capped at an hour).
type ContractEventTimes struct {
	BackoffMin, BackoffMax time.Duration
}

// ContractEventPark is one event parked, with why.
type ContractEventPark struct {
	EventID uuid.UUID
	Code    string
}

// ContractEventsRecord is what recording an answer, or a failure, did.
type ContractEventsRecord struct {
	// Recorded: the workspace is recorded (a document named it).
	Recorded bool
	// Delivered counts the events settled on the answer, and Folded the
	// rows settled with them.
	Delivered, Folded int
	// Parked are the events the answer parked (conflict, invalid_request),
	// and NotFound those parked after a day of not_found, every owed row
	// of the queue.
	Parked   []ContractEventPark
	NotFound []uuid.UUID
	// Refused: the platform answered not_found; NotFoundSince is the run's
	// first.
	Refused       bool
	NotFoundSince *time.Time
	// Released counts the rows parked not_found sent again: an event of the
	// workspace was accepted, so the platform knows it now.
	Released int64
	// Again: a due time someone set after the batch was read stands rather
	// than the backoff (a recovery, a name given again), and no try counts.
	Again bool
	// Tries counts the failures in a row, this one included; Before is the
	// failure's class recorded before it, "" for none.
	Tries  int
	Before string
}

type queueState struct {
	due           *time.Time
	tries         int
	notFoundSince *time.Time
	class         string
	now           time.Time
}

// lockedQueueTx is lockQueueTx with the queue's state.
func lockedQueueTx(ctx context.Context, tx pgx.Tx, workspace uuid.UUID) (queueState, bool, error) {
	var q queueState
	err := tx.QueryRow(ctx, `SELECT events_due_at, events_tries, events_not_found_since, coalesce(events_error, ''), clock_timestamp()
		FROM contract_workspaces WHERE workspace_id = $1 FOR UPDATE`, workspace).Scan(&q.due, &q.tries, &q.notFoundSince, &q.class, &q.now)
	if errors.Is(err, pgx.ErrNoRows) {
		return q, false, nil
	}
	if err != nil {
		return q, false, err
	}
	return q, true, shareWorkspaceTx(ctx, tx, workspace)
}

// backoffTx records a failed try of the queue read at readAt with class:
// the next try after the backoff, unless someone made the queue due since
// it was read (Again: that due time stands, and no try counts).
func backoffTx(ctx context.Context, tx pgx.Tx, workspace uuid.UUID, q queueState, readAt time.Time, class string,
	times ContractEventTimes, rec *ContractEventsRecord) error {
	rec.Again, rec.Tries, rec.Before = q.due != nil && q.due.After(readAt), q.tries, q.class
	due := q.due
	if !rec.Again {
		rec.Tries = q.tries + 1
		next := q.now.Add(backoffAfter(q.tries, times.BackoffMin, times.BackoffMax))
		due = &next
	}
	_, err := tx.Exec(ctx, `UPDATE contract_workspaces SET events_due_at = $2, events_tries = $3,
		events_error = $4, events_error_at = coalesce(events_error_at, clock_timestamp())
		WHERE workspace_id = $1`, workspace, due, rec.Tries, class)
	return err
}

// EventsSent records the platform's signed answer to a batch of the
// workspace's queue read at readAt, in one transaction (README 9; the
// plan's 4.11):
//   - accepted, duplicate: delivered, settled with that outcome and the
//     rows folded into it;
//   - rejected conflict or invalid_request: parked with its code, with its
//     folded rows (the queue goes on);
//   - rejected not_found: the queue's not_found run starts (or goes on),
//     retried with the backoff; once it is ContractEventNotFoundFor old,
//     every owed row of the queue is parked not_found.
//
// Without a not_found the queue goes on at once (its backoff and failure
// class cleared), and an event delivered ends a not_found run, releasing
// the rows parked for it: the platform knows the workspace now.
func (c *Contract) EventsSent(ctx context.Context, workspace uuid.UUID, readAt time.Time, results []ContractEventResult,
	times ContractEventTimes) (ContractEventsRecord, error) {
	var heads, delivered []uuid.UUID
	var outcomes []string
	var parks []ContractEventPark
	refused := false
	for _, r := range results {
		heads = append(heads, r.EventID)
		switch {
		case r.Outcome == ContractEventAccepted || r.Outcome == ContractEventDuplicate:
			delivered, outcomes = append(delivered, r.EventID), append(outcomes, r.Outcome)
		case r.Outcome == ContractEventRejected && r.Code == EventParkedNotFound:
			refused = true
		case r.Outcome == ContractEventRejected && (r.Code == EventParkedConflict || r.Code == EventParkedInvalid):
			parks = append(parks, ContractEventPark{r.EventID, r.Code})
		default:
			return ContractEventsRecord{}, fmt.Errorf("store: an event's outcome %q (%q) is not one", r.Outcome, r.Code)
		}
	}
	var rec ContractEventsRecord
	err := retryDeadlock(ctx, func() error {
		rec = ContractEventsRecord{}
		return pg.InTenantTx(ctx, c.pool, workspace.String(), func(tx pgx.Tx) error {
			q, ok, err := lockedQueueTx(ctx, tx, workspace)
			if err != nil || !ok {
				return err
			}
			rec.Recorded = true
			since := q.notFoundSince
			if refused && since == nil {
				since = &q.now
			}
			parkAll := refused && q.now.Sub(*since) >= ContractEventNotFoundFor
			release := !refused && len(delivered) > 0 && q.notFoundSince != nil
			// Every row this answer touches, locked in seq order in one
			// statement.
			if _, err := tx.Exec(ctx, `SELECT 1 FROM `+owedFromSQL+` WHERE e.tenant_id = $1 AND (
					e.event_id = ANY ($2) OR (e.coalesced_into = ANY ($2) AND e.settled_at IS NULL)
					OR ($3 AND `+releasableEventSQL+`) OR ($4 AND `+owedEventSQL+`))
				ORDER BY e.seq FOR UPDATE OF e`, workspace, heads, release, parkAll); err != nil {
				return err
			}
			if len(delivered) > 0 {
				tag, err := tx.Exec(ctx, `UPDATE item_events e SET settled_at = clock_timestamp(), outcome = u.outcome,
					parked_at = NULL, reject_code = NULL
					FROM unnest($2::uuid[], $3::text[]) AS u(id, outcome)
					WHERE e.tenant_id = $1 AND e.event_id = u.id AND e.settled_at IS NULL`, workspace, delivered, outcomes)
				if err != nil {
					return fmt.Errorf("store: settle the delivered events: %w", err)
				}
				rec.Delivered = int(tag.RowsAffected())
				tag, err = tx.Exec(ctx, `UPDATE item_events SET settled_at = clock_timestamp(), outcome = 'coalesced',
					parked_at = NULL, reject_code = NULL
					WHERE tenant_id = $1 AND coalesced_into = ANY ($2) AND settled_at IS NULL`, workspace, delivered)
				if err != nil {
					return fmt.Errorf("store: settle the folded events: %w", err)
				}
				rec.Folded = int(tag.RowsAffected())
			}
			for _, p := range parks {
				tag, err := tx.Exec(ctx, `UPDATE item_events SET parked_at = clock_timestamp(), reject_code = $3
					WHERE tenant_id = $1 AND (event_id = $2 OR coalesced_into = $2) AND settled_at IS NULL AND parked_at IS NULL`,
					workspace, p.EventID, p.Code)
				if err != nil {
					return fmt.Errorf("store: park an event: %w", err)
				}
				if tag.RowsAffected() > 0 {
					rec.Parked = append(rec.Parked, p)
				}
			}
			switch {
			case parkAll:
				rows, err := tx.Query(ctx, `UPDATE item_events e SET parked_at = clock_timestamp(), reject_code = 'not_found'
					FROM contract_state s, contract_workspaces w
					WHERE w.workspace_id = e.tenant_id AND e.tenant_id = $1 AND `+owedEventSQL+` RETURNING e.event_id`, workspace)
				if err != nil {
					return err
				}
				if rec.NotFound, err = pgx.CollectRows(rows, pgx.RowTo[uuid.UUID]); err != nil {
					return fmt.Errorf("store: park the events of a workspace the platform does not know: %w", err)
				}
				rec.Refused, rec.NotFoundSince, rec.Before = true, since, q.class
				// Nothing owed is left to try: the queue is quiet until a row
				// comes, which parks at once, or a release.
				_, err = tx.Exec(ctx, `UPDATE contract_workspaces SET events_not_found_since = $2, events_due_at = NULL,
					events_tries = 0, events_error = NULL, events_error_at = NULL WHERE workspace_id = $1`, workspace, since)
				return err
			case refused:
				rec.Refused, rec.NotFoundSince = true, since
				if _, err := tx.Exec(ctx, `UPDATE contract_workspaces SET events_not_found_since = $2 WHERE workspace_id = $1`,
					workspace, since); err != nil {
					return err
				}
				return backoffTx(ctx, tx, workspace, q, readAt, "refused:"+EventParkedNotFound, times, &rec)
			}
			if release {
				if rec.Released, err = releaseEventsTx(ctx, tx, workspace); err != nil {
					return err
				}
			}
			rec.Before = q.class
			_, err = tx.Exec(ctx, `UPDATE contract_workspaces SET events_due_at = NULL, events_tries = 0,
				events_error = NULL, events_error_at = NULL,
				events_not_found_since = CASE WHEN $2 THEN NULL ELSE events_not_found_since END
				WHERE workspace_id = $1`, workspace, len(delivered) > 0)
			return err
		})
	})
	return rec, err
}

// EventsFailed records a batch of the workspace's queue, read at readAt,
// that got no signed answer, an unverified one, or a refusal of the whole
// call that is no verdict on its events (unavailable, rate_limited): the
// same events again after the backoff (README 9), unless someone made the
// queue due since it was read (Again: a due time after readAt, which the
// sender's own backoff never is, since it reads a batch only once its queue
// is due). class is the failure's (an outcome, a refusal's code, a
// transport's; never a message), kept with the run's start for contract
// status.
func (c *Contract) EventsFailed(ctx context.Context, workspace uuid.UUID, readAt time.Time, class string,
	times ContractEventTimes) (ContractEventsRecord, error) {
	var rec ContractEventsRecord
	err := pg.InTx(ctx, c.pool, func(tx pgx.Tx) error {
		rec = ContractEventsRecord{}
		var q queueState
		err := tx.QueryRow(ctx, `SELECT events_due_at, events_tries, coalesce(events_error, ''), clock_timestamp()
			FROM contract_workspaces WHERE workspace_id = $1 FOR UPDATE`, workspace).Scan(&q.due, &q.tries, &q.class, &q.now)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		rec.Recorded = true
		return backoffTx(ctx, tx, workspace, q, readAt, class, times, &rec)
	})
	return rec, err
}

// EventsParked parks the events of the workspace's queue named in parks,
// each with its code and with the rows folded into it: one Wappie would
// not send (local_invalid), or one the platform refused alone after it
// refused their batch whole (invalid_request). The queue goes on. It
// returns those parked, of the events still owed.
func (c *Contract) EventsParked(ctx context.Context, workspace uuid.UUID, parks []ContractEventPark) ([]ContractEventPark, error) {
	var out []ContractEventPark
	err := retryDeadlock(ctx, func() error {
		out = nil
		return pg.InTenantTx(ctx, c.pool, workspace.String(), func(tx pgx.Tx) error {
			if _, ok, err := lockQueueTx(ctx, tx, workspace); err != nil || !ok {
				return err
			}
			ids := make([]uuid.UUID, len(parks))
			for i, p := range parks {
				ids[i] = p.EventID
			}
			if _, err := tx.Exec(ctx, `SELECT 1 FROM item_events WHERE tenant_id = $1
				AND (event_id = ANY ($2) OR coalesced_into = ANY ($2)) AND settled_at IS NULL AND parked_at IS NULL
				ORDER BY seq FOR UPDATE`, workspace, ids); err != nil {
				return err
			}
			for _, p := range parks {
				tag, err := tx.Exec(ctx, `UPDATE item_events SET parked_at = clock_timestamp(), reject_code = $3
					WHERE tenant_id = $1 AND (event_id = $2 OR coalesced_into = $2) AND settled_at IS NULL AND parked_at IS NULL`,
					workspace, p.EventID, p.Code)
				if err != nil {
					return fmt.Errorf("store: park an event: %w", err)
				}
				if tag.RowsAffected() > 0 {
					out = append(out, p)
				}
			}
			return nil
		})
	})
	return out, err
}

// releaseEventsTx sends again the rows of the workspace of tx parked for
// the platform's not_found, under their 29 days, heads and folded rows
// alike (a folded row whose head stays parked heads its own event: the
// next read sees to it), and wakes the leader's event sender. It locks
// them in seq order, after the workspace (DB23).
func releaseEventsTx(ctx context.Context, tx pgx.Tx, workspace uuid.UUID) (int64, error) {
	if err := shareWorkspaceTx(ctx, tx, workspace); err != nil {
		return 0, err
	}
	tag, err := tx.Exec(ctx, `WITH x AS (SELECT seq FROM item_events e WHERE e.tenant_id = $1 AND `+releasableEventSQL+`
			ORDER BY e.seq FOR UPDATE)
		UPDATE item_events e SET parked_at = NULL, reject_code = NULL FROM x WHERE e.tenant_id = $1 AND e.seq = x.seq`, workspace)
	if err != nil {
		return 0, fmt.Errorf("store: release the events parked not_found: %w", err)
	}
	if tag.RowsAffected() > 0 {
		if _, err := tx.Exec(ctx, `SELECT pg_notify($1, $2)`, ContractEventsChannel, workspace.String()); err != nil {
			return 0, err
		}
	}
	return tag.RowsAffected(), nil
}

// releaseWorkspacesTx is releaseEventsTx for each of workspaces, in id
// order, each under its own row-level security, leaving tx's workspace as
// it found it: a document's store (a name given again) and a restart call
// it with their records locked. Every workspace is taken FOR KEY SHARE, in
// id order and in one statement, before any of their rows (DB23): a purge
// that holds one of them FOR UPDATE and then writes another's rows (a
// number that moved out of it, scrubFormerWorkspacesTx) finds none of
// those rows locked, and the release waits for it.
func releaseWorkspacesTx(ctx context.Context, tx pgx.Tx, workspaces []uuid.UUID) error {
	if len(workspaces) == 0 {
		return nil
	}
	ids := slices.Clone(workspaces)
	slices.SortFunc(ids, compareIDs)
	ids = slices.Compact(ids)
	if _, err := tx.Exec(ctx, `SELECT 1 FROM tenants WHERE id = ANY ($1) ORDER BY id FOR KEY SHARE`, ids); err != nil {
		return err
	}
	var was string
	if err := tx.QueryRow(ctx, `SELECT coalesce(current_setting($1, true), '')`, pg.TenantGUC).Scan(&was); err != nil {
		return err
	}
	for _, id := range ids {
		if _, err := tx.Exec(ctx, `SELECT set_config($1, $2, true)`, pg.TenantGUC, id.String()); err != nil {
			return err
		}
		if _, err := releaseEventsTx(ctx, tx, id); err != nil {
			return err
		}
	}
	_, err := tx.Exec(ctx, `SELECT set_config($1, $2, true)`, pg.TenantGUC, was)
	return err
}

// expireEventsTx parks as expired, in the workspace of tx, every owed row
// whose 29 days are spent and every row folded into such a pause, locked in
// seq order after the workspace (DB23), and returns their event ids: the
// housekeeping's bound on a queue nobody sends (the contract off after an
// observe, a platform gone for weeks).
func expireEventsTx(ctx context.Context, tx pgx.Tx, workspace uuid.UUID) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `WITH x AS (
			SELECT e.seq FROM `+owedFromSQL+`
			 WHERE e.tenant_id = $1 AND `+owedEventSQL+` AND (e.occurred_at <= clock_timestamp() - `+eventExpirySQL+`
			    OR e.coalesced_into IN (SELECT h.event_id FROM item_events h WHERE h.tenant_id = $1 AND h.coalesced_into IS NULL
			         AND h.settled_at IS NULL AND h.parked_at IS NULL AND h.occurred_at <= clock_timestamp() - `+eventExpirySQL+`))
			 ORDER BY e.seq FOR UPDATE OF e)
		UPDATE item_events e SET parked_at = clock_timestamp(), reject_code = 'expired' FROM x
		WHERE e.tenant_id = $1 AND e.seq = x.seq RETURNING e.event_id`, workspace)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

// ContractEventQueue is a recorded workspace's queue state, as the sender
// reads it to choose what to send next.
type ContractEventQueue struct {
	Workspace uuid.UUID
	// DueAt is its backoff's end, nil for none; Due that it is due, on the
	// database's clock, and Wait how long until it is otherwise.
	DueAt *time.Time
	Due   bool
	Wait  time.Duration
	Tries int
}

// EventQueues reads the queue state of each of workspaces that a document
// named, in due order (due ones first, the soonest backoff first).
func (c *Contract) EventQueues(ctx context.Context, workspaces []uuid.UUID) ([]ContractEventQueue, error) {
	rows, err := c.pool.Query(ctx, `SELECT workspace_id, events_due_at, events_tries, clock_timestamp() FROM contract_workspaces
		WHERE workspace_id = ANY ($1) ORDER BY coalesce(events_due_at, '-infinity'), workspace_id`, workspaces)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (ContractEventQueue, error) {
		var q ContractEventQueue
		var now time.Time
		if err := row.Scan(&q.Workspace, &q.DueAt, &q.Tries, &now); err != nil {
			return q, err
		}
		q.Due = q.DueAt == nil || !q.DueAt.After(now)
		if !q.Due {
			q.Wait = q.DueAt.Sub(now)
		}
		return q, nil
	})
}

// EventWorkspaces lists the recorded workspaces Wappie holds whose queue
// owes anything, expired rows included (the next read parks them), in id
// order, in one read-only transaction: the sender's look at every queue,
// at a leader's start and now and then, beside the notices of new rows.
func (c *Contract) EventWorkspaces(ctx context.Context) ([]uuid.UUID, error) {
	var out []uuid.UUID
	err := pgx.BeginTxFunc(ctx, c.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		out = nil
		var observed bool
		if err := tx.QueryRow(ctx, `SELECT events_from IS NOT NULL FROM contract_state`).Scan(&observed); err != nil || !observed {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT w.workspace_id FROM contract_workspaces w JOIN tenants t ON t.id = w.workspace_id
			ORDER BY w.workspace_id`)
		if err != nil {
			return err
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			return err
		}
		for _, id := range ids {
			if _, err := tx.Exec(ctx, `SELECT set_config($1, $2, true)`, pg.TenantGUC, id.String()); err != nil {
				return err
			}
			var owed bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM `+owedFromSQL+` WHERE e.tenant_id = $1 AND `+owedEventSQL+`)`,
				id).Scan(&owed); err != nil {
				return err
			}
			if owed {
				out = append(out, id)
			}
		}
		return nil
	})
	return out, err
}

// backoffAfter is the wait after the failure that follows tries failures
// in a row: least doubled with each, up to most.
func backoffAfter(tries int, least, most time.Duration) time.Duration {
	d := least
	for range min(tries, 40) {
		if d >= most {
			break
		}
		d *= 2
	}
	return min(d, most)
}
