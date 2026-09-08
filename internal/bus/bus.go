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
	"sync"

	"github.com/google/uuid"

	"whatserver2/internal/ingest"
)

// queueDepth is how many events may wait for one subscriber.
//
// Sized for a burst — a backfill landing while a client is mid-render — rather
// than for a client that has genuinely stopped reading. Past this the
// subscription lags rather than blocking the publisher, because one stalled
// client must never slow ingest for everyone.
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
type Filter struct {
	// Devices limits delivery to these device ids. Empty means all of the
	// tenant's devices.
	Devices map[uuid.UUID]struct{}
}

func (f Filter) allows(ev ingest.Event) bool {
	if len(f.Devices) == 0 {
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

// EndReplay releases buffered events and switches to live delivery.
//
// throughSeq is the highest sequence the caller already delivered from history;
// anything at or below it is discarded rather than sent twice.
func (s *Subscription) EndReplay(throughSeq int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.replaying {
		return
	}
	// The flag is cleared inside the same critical section that drains the
	// buffer. Clearing it first would let a concurrent publish slip past the
	// buffer and arrive before the events already waiting in it.
	s.replaying = false
	buffered := s.buffer
	s.buffer = nil

	for _, ev := range buffered {
		// Presence captured during a replay is already stale by the time the
		// replay finishes, and its Seq of zero would see it discarded by the
		// comparison below in any case. Dropped explicitly so the reason is
		// the reason, rather than an accident of the zero value.
		if ev.Ephemeral {
			continue
		}
		if ev.Seq <= throughSeq {
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
	if !s.filter.allows(ev) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	if s.replaying {
		s.buffer = append(s.buffer, ev)
		return
	}
	s.deliverLocked(ev)
}

// deliverLocked sends one event, marking the subscription lagged rather than
// blocking or disconnecting when the queue is full.
func (s *Subscription) deliverLocked(ev ingest.Event) {
	select {
	case s.events <- ev:
	default:
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
}

// Subscribers reports how many subscriptions a tenant has. For metrics.
func (b *Bus) Subscribers(tenant uuid.UUID) int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs[tenant])
}
