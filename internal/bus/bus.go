// Package bus fans events out to connected clients.
//
// Two things here are subtle enough to be worth stating plainly.
//
// # The replay race
//
// A client reconnects with a cursor and wants everything since, then live
// traffic, with nothing missing and nothing duplicated. The obvious order —
// read history, then subscribe — loses every event that arrives in between. The
// reverse order — subscribe, then read history — delivers those events twice
// and out of order.
//
// So a subscription starts in replay mode: it is registered first, so live
// events are captured, but they go into a buffer instead of to the client.
// The caller reads history, then ends replay, which drains the buffer under the
// same lock that stops capturing. Events that the history read already covered
// are dropped by sequence number. The contract is at-least-once, so a client
// still deduplicates, but the window is closed.
//
// # Backpressure
//
// A client that stops reading must not be able to grow a queue without bound.
// The v1 server closed the connection, which turned a slow phone on a train
// into a lost session. Here the subscription is marked lagged and told the
// lowest sequence it missed; the client resumes from its own cursor and
// catches up. Dropping the connection is a last resort, not the first move.
package bus

import (
	"slices"
	"sync"

	"github.com/google/uuid"

	"whatserver2/internal/ingest"
)

// queueDepth is how many events may wait for one subscriber.
//
// Sized for a burst — a backfill landing while a client is mid-render — rather
// than for a client that has genuinely stopped reading. Past this the
// subscription lags rather than blocking the publisher, because one stalled
// client must never slow ingest for everyone. It also bounds what a
// subscription holds back while its history replays (offer).
const queueDepth = 512

// Bus routes events to subscriptions, scoped by tenant.
type Bus struct {
	mu   sync.RWMutex
	subs map[uuid.UUID]map[*Subscription]struct{}
}

// New returns an empty bus.
func New() *Bus { return &Bus{subs: map[uuid.UUID]map[*Subscription]struct{}{}} }

var _ ingest.Publisher = (*Bus)(nil)

// Filter narrows what a subscription receives.
//
// An empty set delivers nothing. It used to mean every device of the
// tenant, and delivery checks no access per event, so a subscription whose
// only number was deleted would have started receiving every other number's
// traffic, including numbers whose key its owner does not hold. Every
// device is All, which nothing sets today.
type Filter struct {
	// Devices limits delivery to these device ids. Never changed in place:
	// DropDevice swaps in a copy.
	Devices map[uuid.UUID]struct{}
	// All delivers every device of the tenant, and Devices is ignored.
	All bool
}

func (f Filter) allows(ev ingest.Event) bool {
	if f.All {
		return true
	}
	_, ok := f.Devices[ev.DeviceID]
	return ok
}

// Subscription is one client's stream.
type Subscription struct {
	bus    *Bus
	tenant uuid.UUID
	filter Filter
	events chan ingest.Event

	mu sync.Mutex
	// replaying is true between Subscribe and EndReplay. While it is set, live
	// events accumulate in buffer rather than being delivered, so a history
	// read cannot race with them.
	replaying bool
	buffer    []ingest.Event
	closed    bool
	// ended is set when DropDevice took the last device of the filter:
	// nothing more is delivered, and done is closed, so the reader can tell
	// its client. The events channel stays open until Close.
	ended bool
	done  chan struct{}

	// lagged records that the queue overflowed, and the sequence at which it
	// happened, so the client can be told where to resume from.
	lagged   bool
	laggedAt int64
	dropped  int
}

// Subscribe registers a subscription in replay mode.
//
// Live events are captured from this moment but held back. The caller reads
// history, then calls EndReplay. Failing to call it leaves the client
// permanently silent, so it belongs in a defer.
func (b *Bus) Subscribe(tenant uuid.UUID, filter Filter) *Subscription {
	sub := &Subscription{
		bus:    b,
		tenant: tenant,
		filter: filter,
		events: make(chan ingest.Event, queueDepth),
		done:   make(chan struct{}),
		// Set before registration, not after: an event arriving between the
		// two must be buffered, and this is the flag that decides.
		replaying: true,
	}
	b.mu.Lock()
	if b.subs[tenant] == nil {
		b.subs[tenant] = map[*Subscription]struct{}{}
	}
	b.subs[tenant][sub] = struct{}{}
	b.mu.Unlock()
	return sub
}

// Events yields delivered events. Closed when the subscription is.
func (s *Subscription) Events() <-chan ingest.Event { return s.events }

// Ended is closed when DropDevice removed the subscription's last device.
// The subscription delivers nothing from then on; its reader tells its
// client and calls Close.
func (s *Subscription) Ended() <-chan struct{} { return s.done }

// EndReplay releases buffered events and switches to live delivery.
//
// throughSeq is the highest sequence the caller already delivered from history;
// anything at or below it is discarded rather than sent twice.
func (s *Subscription) EndReplay(throughSeq int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.replaying || s.closed || s.ended {
		s.replaying = false
		s.buffer = nil
		return
	}
	// The flag is cleared inside the same critical section that drains the
	// buffer. Clearing it first would let a concurrent publish slip past the
	// buffer and arrive before the events already waiting in it.
	s.replaying = false
	buffered := s.buffer
	s.buffer = nil

	for _, ev := range buffered {
		// Against the filter as it is now, not as it was at capture: drop
		// already takes a deleted number's events out of the buffer, and
		// this keeps the handover from releasing one it ever leaves in.
		if ev.Seq <= throughSeq || !s.filter.allows(ev) {
			continue
		}
		s.deliverLocked(ev)
	}
}

// Lagged reports whether the queue overflowed, and the sequence at which it
// did. A lagged client should resume from its own cursor rather than be
// disconnected.
func (s *Subscription) Lagged() (bool, int64, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lagged, s.laggedAt, s.dropped
}

// ClearLag resets the lag marker, after the client has resumed.
func (s *Subscription) ClearLag() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lagged, s.laggedAt, s.dropped = false, 0, 0
}

// Close unregisters the subscription.
func (s *Subscription) Close() {
	s.bus.mu.Lock()
	if subs := s.bus.subs[s.tenant]; subs != nil {
		delete(subs, s)
		if len(subs) == 0 {
			delete(s.bus.subs, s.tenant)
		}
	}
	s.bus.mu.Unlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		close(s.events)
	}
}

// Publish delivers an event to every matching subscription.
//
// Never blocks. Ingest calls this while holding nothing, and one stalled client
// must not be able to slow the pipeline for every other tenant.
func (b *Bus) Publish(tenant uuid.UUID, ev ingest.Event) {
	b.mu.RLock()
	subs := make([]*Subscription, 0, len(b.subs[tenant]))
	for sub := range b.subs[tenant] {
		subs = append(subs, sub)
	}
	b.mu.RUnlock()

	for _, sub := range subs {
		sub.offer(ev)
	}
}

func (s *Subscription) offer(ev ingest.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// The filter is read under the lock: DropDevice replaces it.
	if s.closed || s.ended || !s.filter.allows(ev) {
		return
	}
	if s.replaying {
		// Presence captured during a replay is already stale by the time the
		// replay finishes, and its Seq of zero would see it discarded at the
		// handover in any case. Not held at all, so it cannot take the place
		// of a message in the bounded buffer below.
		if ev.Ephemeral {
			return
		}
		// Bounded at what the handover can deliver: EndReplay releases the
		// buffer into a queue of queueDepth, which is empty then. A replay
		// goes at the pace its client reads it, so a client reading slowly
		// would otherwise make this hold every event its tenant has for as
		// long as it likes; past the bound the subscription lags, as a full
		// queue does.
		if len(s.buffer) < queueDepth {
			s.buffer = append(s.buffer, ev)
			return
		}
		s.dropLocked(ev)
		return
	}
	s.deliverLocked(ev)
}

// deliverLocked sends one event, marking the subscription lagged rather than
// blocking or disconnecting when the queue is full.
func (s *Subscription) deliverLocked(ev ingest.Event) {
	if s.closed || s.ended {
		return
	}
	select {
	case s.events <- ev:
	default:
		s.dropLocked(ev)
	}
}

// DropDevice takes a device out of every subscription of the tenant, when
// the number is deleted: right after the commit in the process that deleted
// it, and on the deletion's notification everywhere else. A subscription it
// was the last device of is ended (see Ended) rather than left with an
// empty filter. Each filter is replaced by a copy under its subscription's
// lock, so a publisher or a replay reading the old one is never raced.
func (b *Bus) DropDevice(tenant, device uuid.UUID) {
	b.mu.RLock()
	subs := make([]*Subscription, 0, len(b.subs[tenant]))
	for sub := range b.subs[tenant] {
		subs = append(subs, sub)
	}
	b.mu.RUnlock()
	for _, sub := range subs {
		sub.drop(device)
	}
}

// Allows reports whether the subscription delivers device now: its filter
// as DropDevice last left it, and nothing once it has ended or closed. A
// replay asks it for every row, so a number deleted mid-replay stops there.
func (s *Subscription) Allows(device uuid.UUID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ended {
		return false
	}
	return s.filter.allows(ingest.Event{DeviceID: device})
}

// Drop takes a device out of this subscription alone, as DropDevice does
// for all of them: a subscriber that finds a number gone after it
// registered drops it itself, since a deletion that committed before the
// registration dropped it from no filter.
func (s *Subscription) Drop(device uuid.UUID) { s.drop(device) }

func (s *Subscription) drop(device uuid.UUID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ended || s.filter.All {
		return
	}
	if _, ok := s.filter.Devices[device]; !ok {
		return
	}
	next := make(map[uuid.UUID]struct{}, len(s.filter.Devices)-1)
	for id := range s.filter.Devices {
		if id != device {
			next[id] = struct{}{}
		}
	}
	if len(next) == 0 {
		s.ended = true
		s.buffer = nil
		close(s.done)
		return
	}
	s.filter = Filter{Devices: next}
	// What a replay captured of the deleted number for its handover goes
	// now, so EndReplay never releases it while other numbers remain.
	s.buffer = slices.DeleteFunc(s.buffer, func(ev ingest.Event) bool { return ev.DeviceID == device })
}

// dropLocked records an event that did not fit, so the client can be told
// where to resume.
func (s *Subscription) dropLocked(ev ingest.Event) {
	if ev.Ephemeral {
		// Dropped in silence, and that is the whole point of the flag.
		//
		// An ephemeral event has no row and no sequence number, so there
		// is nothing for a client to resume from and nothing lost by
		// letting it go: "somebody is typing" stops being true on its own
		// in a few seconds. Marking the subscription lagged would be
		// actively harmful — laggedAt would record this event's Seq, which
		// is zero, and the client would be told to refetch the archive
		// from the beginning because it missed a typing notification.
		return
	}
	if !s.lagged {
		// The first drop is the one worth remembering: it is where the
		// client's view stops being continuous, and therefore where it
		// must resume from.
		s.lagged, s.laggedAt = true, ev.Seq
	}
	s.dropped++
}

// Subscribers reports how many subscriptions a tenant has. For metrics.
func (b *Bus) Subscribers(tenant uuid.UUID) int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs[tenant])
}
