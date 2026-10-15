package membership

import (
	"context"
	"encoding/json"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/store"
)

// The events (README 9; the plan's 4.11, DB10, DB11 and DB23): the
// leader's one sender of every recorded platform workspace's queue, over
// release A's item_events rows, each rendered at send time with the kit's
// types and checked before it goes. One queue per workspace, in seq order;
// a batch is the queue's head, at most 100 events and under 248 KiB, never
// two workspaces'; a failure stops only its own queue, retried with 5 s ×
// 2ⁿ up to an hour; a row is delivered only on a signed accepted or
// duplicate, matched to it by position; and what is never to be sent
// (before the transport or the naming, a pause with nobody else to tell,
// one folded into a pause of the hour) is the store's to decide. A new
// row, a queue made due again and a release of parked rows wake it through
// 0051's notices (wappie_contract_events); it also looks at every queue at
// a leader's start and every few minutes, should a notice be lost.

// The sender's defaults.
const (
	// eventBackoffMin and eventBackoffMax bound the wait after a batch that
	// got no verdict (README 9: 5 s × 2ⁿ, capped at 1 hour).
	eventBackoffMin = 5 * time.Second
	eventBackoffMax = time.Hour
	// eventsScanEvery is how often the sender looks at every queue, beside
	// the notices.
	eventsScanEvery = 5 * time.Minute
	// eventsIdle is the longest it waits without looking at the due times.
	eventsIdle = time.Minute
	// eventsBodyLimit bounds a batch's body under the call's 256 KiB
	// (README 3), with room to spare: one event alone, 5000 readers
	// included, is about 195 KiB.
	eventsBodyLimit = 248 << 10
)

// eventTypes are the contract's names of item_events' types.
var eventTypes = map[string]string{
	"deleted":     kc.EventDeleted,
	"sync_paused": kc.EventSyncPaused,
	"recovered":   kc.EventRecovered,
	"purged":      kc.EventPurged,
	"moved_out":   kc.EventMovedOut,
	"stranded":    kc.EventStranded,
}

// EventOf is the wire's event (README 9) of a queue's event in workspace:
// the row as it is, its actor's sub or null (an app's act, a person with
// none, a key with no creator), its readers, the actor among them when they
// read it, or null above 5000 (the platform then takes its latest
// snapshot's), and what only its type carries: a deletion's purge date, a
// move's destination, a stranding's person and cause (null, and so
// omitted, for a membership the platform ended: it fills the cause from
// its log).
func EventOf(workspace uuid.UUID, e store.ContractEvent) kc.Event {
	ev := kc.Event{
		EventID: e.EventID.String(), WorkspaceID: workspace.String(), Type: eventTypes[e.Type], OccurredAt: kc.T(e.OccurredAt),
		Item:      kc.EventItem{ID: e.ItemID.String(), Kind: kc.ItemNumber, Label: e.Label, Hint: e.Hint},
		ActorKind: e.ActorKind,
	}
	if e.ActorSub != nil {
		actor := e.ActorSub.String()
		ev.Actor = &actor
	}
	if len(e.Readers) <= kc.MaxReaders {
		readers := make([]string, 0, len(e.Readers))
		for _, r := range e.Readers {
			readers = append(readers, r.String())
		}
		ev.Readers = &readers
	}
	switch ev.Type {
	case kc.EventDeleted:
		if e.PurgeAfter != nil {
			at := kc.T(*e.PurgeAfter)
			ev.PurgeAt = &at
		}
	case kc.EventMovedOut:
		to := kc.MovedToPersonal
		ev.To = &to
	case kc.EventStranded:
		if e.PersonSub != nil {
			person := e.PersonSub.String()
			ev.Person = &person
		}
		if e.Cause != nil {
			cause := *e.Cause
			ev.Cause = &cause
		}
	}
	return ev
}

// fitEvents is how many of events, from the first, one batch carries under
// eventsBodyLimit, counted as the kit encodes the batch.
func fitEvents(events []kc.Event) (int, error) {
	size := len(`{"events":[]}`)
	for i, ev := range events {
		b, err := json.Marshal(ev)
		if err != nil {
			return 0, err
		}
		size += len(b)
		if i > 0 {
			size++
		}
		if size > eventsBodyLimit {
			return i, nil
		}
	}
	return len(events), nil
}

// eventResults matches the platform's answer to the events sent, by
// position (README 9: "one per event, in order"; the kit checks only their
// count): false, and nothing is settled, when a result names another event
// (an empty id is the platform's for an event it could not decode), or is
// not one README 9 defines.
func eventResults(events []kc.Event, results []kc.EventResult) ([]store.ContractEventResult, bool) {
	if len(results) != len(events) {
		return nil, false
	}
	out := make([]store.ContractEventResult, 0, len(results))
	for i, r := range results {
		if r.EventID != "" && r.EventID != events[i].EventID {
			return nil, false
		}
		id, err := uuid.Parse(events[i].EventID)
		if err != nil {
			return nil, false
		}
		res := store.ContractEventResult{EventID: id, Outcome: r.Outcome}
		switch r.Outcome {
		case kc.OutcomeAccepted, kc.OutcomeDuplicate:
		case kc.OutcomeRejected:
			if r.Code == nil || !slices.Contains([]string{kc.CodeInvalid, kc.CodeNotFound, kc.CodeConflict}, *r.Code) {
				return nil, false
			}
			res.Code = *r.Code
		default:
			return nil, false
		}
		out = append(out, res)
	}
	return out, true
}

// eventSender is one leader's sender of events.
type eventSender struct {
	l    *Leader
	pace pacer
	wake chan struct{}

	mu sync.Mutex
	// named are the workspaces the notices named since the last look.
	named map[uuid.UUID]bool
	// told are the events whose actor's missing sub was logged.
	told map[uuid.UUID]bool
	// warned spaces the WARNs of failed sends.
	warned time.Time
}

func newEventSender(l *Leader) *eventSender {
	return &eventSender{l: l, pace: pacer{every: l.Members.pace()}, wake: make(chan struct{}, 1),
		named: map[uuid.UUID]bool{}, told: map[uuid.UUID]bool{}}
}

// notice takes a wappie_contract_events payload: a workspace's id. Any
// other payload is no workspace's and is dropped.
func (s *eventSender) notice(payload string) {
	id, err := uuid.Parse(payload)
	if err != nil {
		return
	}
	s.mu.Lock()
	s.named[id] = true
	s.mu.Unlock()
	kick(s.wake)
}

// take returns and forgets the workspaces the notices named.
func (s *eventSender) take() []uuid.UUID {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]uuid.UUID, 0, len(s.named))
	for id := range s.named {
		ids = append(ids, id)
	}
	s.named = map[uuid.UUID]bool{}
	return ids
}

func (l *Leader) eventTimes() store.ContractEventTimes {
	return store.ContractEventTimes{
		BackoffMin: or(l.EventBackoffMin, eventBackoffMin),
		BackoffMax: or(l.EventBackoffMax, eventBackoffMax),
	}
}

// run sends events until ctx ends: every queue that owes anything at the
// leader's start and every EventsScanEvery, and each queue a notice names,
// one batch of each due queue in turn, at the round's pace.
func (s *eventSender) run(ctx context.Context) {
	l, c := s.l, s.l.Members.Contract
	minBack := or(l.BackoffMin, feedBackoffMin)
	pause := func(d time.Duration) bool {
		select {
		case <-ctx.Done():
			return false
		case <-s.wake:
		case <-time.After(d):
		}
		return true
	}
	queues := map[uuid.UUID]bool{}
	var scanAt time.Time
	for ctx.Err() == nil {
		if !time.Now().Before(scanAt) {
			ids, err := c.EventWorkspaces(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				l.log().Warn("contract: could not look for the queues of events", "error", err)
				if !pause(minBack) {
					return
				}
				continue
			}
			for _, id := range ids {
				queues[id] = true
			}
			scanAt = time.Now().Add(or(l.EventsScanEvery, eventsScanEvery))
		}
		for _, id := range s.take() {
			queues[id] = true
		}
		wait := min(max(time.Until(scanAt), 0), or(l.EventsIdle, eventsIdle))
		if len(queues) > 0 {
			ids := make([]uuid.UUID, 0, len(queues))
			for id := range queues {
				ids = append(ids, id)
			}
			qs, err := c.EventQueues(ctx, ids)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				l.log().Warn("contract: could not read the queues of events", "error", err)
				if !pause(minBack) {
					return
				}
				continue
			}
			// A notice of a workspace no document named (another
			// installation's, in tests) names no queue.
			clear(queues)
			sent, failed := false, false
			for _, q := range qs {
				queues[q.Workspace] = true
				if !q.Due {
					wait = min(wait, q.Wait)
					continue
				}
				if err := s.pace.wait(ctx); err != nil {
					return
				}
				more, ok := s.send(ctx, q.Workspace)
				if ctx.Err() != nil {
					return
				}
				if !more {
					delete(queues, q.Workspace)
				}
				sent, failed = true, failed || !ok
			}
			if failed {
				// What could not be stored is due as it was: not again at once.
				if !pause(minBack) {
					return
				}
				continue
			}
			if sent {
				continue
			}
		}
		if !pause(wait) {
			return
		}
	}
}

// send reads the head of the workspace's queue and sends it: its expired
// rows parked and logged, the events Wappie would not send parked, the
// rest in one batch under the body's bound. It reports whether the queue
// may hold more, and false for ok when the store could not be read or
// written (the queue is then due as it was).
func (s *eventSender) send(ctx context.Context, ws uuid.UUID) (more, ok bool) {
	l, c := s.l, s.l.Members.Contract
	batch, err := c.EventBatch(ctx, ws, kc.MaxEvents)
	if err != nil {
		if ctx.Err() == nil {
			l.log().Warn("contract: could not read a queue of events", "workspace", ws, "error", err)
		}
		return true, false
	}
	if len(batch.Expired) > 0 {
		l.log().Error("contract: events never delivered in their 29 days are parked", "workspace", ws, "code", store.EventParkedExpired,
			"count", len(batch.Expired), "first", batch.Expired[0])
		s.recordError(ctx, store.ContractErrorEventParked)
	}
	if len(batch.Events) == 0 {
		return false, true
	}
	events := make([]kc.Event, 0, len(batch.Events))
	var invalid []store.ContractEventPark
	for _, e := range batch.Events {
		ev := EventOf(ws, e)
		if e.ActorUnknown() {
			s.actorUnknown(ctx, ws, e)
		}
		if err := ev.Validate(); err != nil {
			// The kit's refusal names the member that failed, never its value.
			l.log().Error("contract: an event is not sent: Wappie would not send it", "workspace", ws, "event", e.EventID,
				"type", e.Type, "rule", err.Error())
			invalid = append(invalid, store.ContractEventPark{EventID: e.EventID, Code: store.EventParkedLocalInvalid})
			continue
		}
		events = append(events, ev)
	}
	n, err := fitEvents(events)
	if err != nil {
		l.log().Warn("contract: could not encode a batch of events", "workspace", ws, "error", err)
		return true, false
	}
	if n == 0 && len(events) > 0 {
		l.log().Error("contract: an event is not sent: Wappie would not send it", "workspace", ws, "event", events[0].EventID,
			"type", events[0].Type, "rule", "too_large")
		invalid = append(invalid, store.ContractEventPark{EventID: uuid.MustParse(events[0].EventID), Code: store.EventParkedLocalInvalid})
	}
	if len(invalid) > 0 {
		if _, err := c.EventsParked(ctx, ws, invalid); err != nil {
			if ctx.Err() == nil {
				l.log().Warn("contract: could not park the events Wappie would not send", "workspace", ws, "error", err)
			}
			return true, false
		}
		s.recordError(ctx, store.ContractErrorEventParked)
	}
	if n == 0 {
		return true, true
	}
	return true, s.post(ctx, ws, batch.ReadAt, events[:n])
}

// post sends one batch of the workspace's queue, read at readAt, and
// records what the platform answered. A batch the platform refuses whole
// as invalid_request (README 3: a body it cannot take) goes again one
// event per call, so only the bad event parks and the queue goes on. It
// reports false when the outcome could not be stored.
func (s *eventSender) post(ctx context.Context, ws uuid.UUID, readAt time.Time, events []kc.Event) bool {
	l, m := s.l, s.l.Members
	results, err := m.Client.PostEvents(ctx, events)
	if ctx.Err() != nil {
		// The leader is stopping: whatever came back, the next leader sends
		// the same events again, and gets duplicate for those kept.
		return true
	}
	switch {
	case err == nil:
		matched, ok := eventResults(events, results)
		if !ok {
			return s.failed(ctx, ws, readAt, Unverified.String(), nil)
		}
		return s.record(ctx, ws, readAt, matched)
	case RefusalCode(err) == kc.CodeInvalid && len(events) > 1:
		l.log().Error("contract: the platform refused a batch of events whole; sending them one by one", "workspace", ws,
			"count", len(events))
		s.recordError(ctx, store.ContractErrorEventsRefused)
		for _, ev := range events {
			if err := s.pace.wait(ctx); err != nil {
				return true
			}
			if !s.post(ctx, ws, readAt, []kc.Event{ev}) {
				return false
			}
			if !s.due(ctx, ws) {
				// It failed, and backs off: the rest wait with it.
				return true
			}
		}
		return true
	case RefusalCode(err) == kc.CodeInvalid:
		id := uuid.MustParse(events[0].EventID)
		l.log().Error("contract: an event is parked: the platform refused it", "workspace", ws, "event", id, "type", events[0].Type,
			"code", kc.CodeInvalid)
		if _, err := m.Contract.EventsParked(ctx, ws, []store.ContractEventPark{{EventID: id, Code: store.EventParkedInvalid}}); err != nil {
			if ctx.Err() == nil {
				l.log().Warn("contract: could not park an event", "workspace", ws, "error", err)
			}
			return false
		}
		s.recordError(ctx, store.ContractErrorEventParked)
		return true
	}
	return s.failed(ctx, ws, readAt, feedClass(err), err)
}

// due reports whether the workspace's queue is due, as a split batch's
// next event needs: false once one of them failed and backs off, or when
// it cannot be read.
func (s *eventSender) due(ctx context.Context, ws uuid.UUID) bool {
	qs, err := s.l.Members.Contract.EventQueues(ctx, []uuid.UUID{ws})
	return err == nil && len(qs) == 1 && qs[0].Due
}

// record stores a signed answer's verdicts and logs what it parked.
func (s *eventSender) record(ctx context.Context, ws uuid.UUID, readAt time.Time, results []store.ContractEventResult) bool {
	l := s.l
	rec, err := l.Members.Contract.EventsSent(ctx, ws, readAt, results, l.eventTimes())
	if err != nil {
		if ctx.Err() == nil {
			l.log().Warn("contract: could not record the platform's answer to events", "workspace", ws, "error", err)
		}
		return false
	}
	for _, p := range rec.Parked {
		// conflict: the platform holds this event id with other content, a
		// Wappie bug (its duplicate rule ignores the label, and a replay
		// keeps the ledger's id and time); invalid_request: the event alone.
		l.log().Error("contract: an event is parked: the platform refused it", "workspace", ws, "event", p.EventID, "code", p.Code)
	}
	if len(rec.NotFound) > 0 {
		l.log().Error("contract: a workspace's events are parked: the platform has not known it for a day", "workspace", ws,
			"count", len(rec.NotFound), "not_found_since", rec.NotFoundSince.UTC().Format(time.RFC3339))
	}
	if len(rec.Parked) > 0 || len(rec.NotFound) > 0 {
		s.recordError(ctx, store.ContractErrorEventParked)
	}
	switch {
	case rec.Refused && len(rec.NotFound) == 0:
		s.warn("contract: the platform does not know a workspace of these events yet; retrying", "workspace", ws, "tries", rec.Tries,
			"not_found_since", rec.NotFoundSince.UTC().Format(time.RFC3339))
	case rec.Delivered > 0:
		l.log().Debug("contract: events delivered", "workspace", ws, "count", rec.Delivered, "folded", rec.Folded)
	}
	if rec.Released > 0 {
		l.log().Info("contract: events parked for not_found are sent again", "workspace", ws, "count", rec.Released)
	}
	s.forget(results)
	return true
}

// failed records a batch that got no verdict: the same events again after
// the backoff.
func (s *eventSender) failed(ctx context.Context, ws uuid.UUID, readAt time.Time, class string, err error) bool {
	l := s.l
	rec, serr := l.Members.Contract.EventsFailed(ctx, ws, readAt, class, l.eventTimes())
	if serr != nil {
		if ctx.Err() == nil {
			l.log().Warn("contract: could not record a failed send of events", "workspace", ws, "error", serr)
		}
		return false
	}
	attrs := []any{"workspace", ws, "class", class, "tries", rec.Tries}
	if err != nil {
		attrs = append(attrs, callAttrs(err)...)
	}
	s.warn("contract: events were not delivered", attrs...)
	return true
}

// actorUnknown logs, once per event and leader, an actor sent as null for
// want of a sub (README 9: a fault in the cloud), and records it for
// contract status --check.
func (s *eventSender) actorUnknown(ctx context.Context, ws uuid.UUID, e store.ContractEvent) {
	s.mu.Lock()
	told := s.told[e.EventID]
	s.told[e.EventID] = true
	s.mu.Unlock()
	if told {
		return
	}
	attrs := []any{"workspace", ws, "event", e.EventID, "type", e.Type, "actor_kind", e.ActorKind}
	if e.ActorUser != nil {
		attrs = append(attrs, "user", *e.ActorUser)
	}
	s.l.log().Error("contract: an event's actor has no platform sub; it is sent with actor null", attrs...)
	s.recordError(ctx, store.ContractErrorEventActor)
}

// forget drops what was told of the events answered for good: a
// not_found comes back with its retry.
func (s *eventSender) forget(results []store.ContractEventResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range results {
		if r.Code != kc.CodeNotFound {
			delete(s.told, r.EventID)
		}
	}
}

func (s *eventSender) warn(msg string, attrs ...any) {
	s.mu.Lock()
	quiet := time.Since(s.warned) < warnEvery
	if !quiet {
		s.warned = time.Now()
	}
	s.mu.Unlock()
	if !quiet {
		s.l.log().Warn(msg, attrs...)
	}
}

func (s *eventSender) recordError(ctx context.Context, class string) {
	if err := s.l.Members.Contract.RecordError(ctx, class); err != nil && ctx.Err() == nil {
		s.l.log().Warn("contract: could not record an ERROR", "error", err)
	}
}
