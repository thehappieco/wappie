package bus_test

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/bus"
	"whatserver2/internal/ingest"
)

var tenant = uuid.MustParse("01a034b7-d09c-7121-b7f8-41f210a9244a")

func event(seq int64) ingest.Event {
	return ingest.Event{Class: ingest.ClassMessage, Seq: seq, TenantID: tenant, DeviceID: uuid.Nil, ChatKey: "chat"}
}

// drain reads until the channel goes quiet for a moment, or the deadline
// passes. The quiet period rather than a fixed wait keeps the race test fast
// enough to run a hundred times.
func drain(sub *bus.Subscription, timeout time.Duration) []int64 {
	var got []int64
	deadline := time.After(timeout)
	idle := 20 * time.Millisecond
	for {
		select {
		case ev, ok := <-sub.Events():
			if !ok {
				return got
			}
			got = append(got, ev.Seq)
		case <-time.After(idle):
			return got
		case <-deadline:
			return got
		}
	}
}

// TestReplayRace is the reason this package exists.
//
// A client reconnecting wants everything since its cursor and then live
// traffic, with nothing missing and nothing duplicated. Reading history before
// subscribing loses whatever arrives in between; subscribing first delivers
// those events twice and out of order. The subscription therefore starts in
// replay mode, capturing but withholding, and drains under the same lock that
// stops capturing.
//
// This publishes continuously while a simulated history read runs, then asserts
// the client saw every sequence exactly once, in order.
func TestReplayRace(t *testing.T) {
	b := bus.New()
	sub := b.Subscribe(tenant, bus.Filter{})
	defer sub.Close()

	const total = 400

	// Live traffic runs the whole time, overlapping the history read.
	// published tracks the highest sequence that has actually been emitted,
	// because that — not an arbitrary number — is what a history read would
	// have been able to see.
	var published atomic.Int64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for seq := int64(1); seq <= total; seq++ {
			b.Publish(tenant, event(seq))
			published.Store(seq)
		}
	}()

	// The "history read". The caller reads rows up to whatever is committed at
	// that instant and passes that watermark to EndReplay.
	time.Sleep(time.Millisecond)
	historyThrough := published.Load()
	sub.EndReplay(historyThrough)
	wg.Wait()

	// Publish a little more, now definitely live.
	for seq := int64(total + 1); seq <= total+20; seq++ {
		b.Publish(tenant, event(seq))
	}

	got := drain(sub, 500*time.Millisecond)

	seen := map[int64]bool{}
	var prev int64
	for _, seq := range got {
		if seen[seq] {
			t.Fatalf("sequence %d was delivered twice", seq)
		}
		seen[seq] = true
		if seq <= prev {
			t.Fatalf("out of order: %d after %d", seq, prev)
		}
		prev = seq
		if seq <= historyThrough {
			t.Fatalf("sequence %d was delivered live although history already covered it", seq)
		}
	}
	// Everything above the history watermark must have arrived.
	for seq := historyThrough + 1; seq <= total+20; seq++ {
		if !seen[seq] {
			t.Fatalf("sequence %d was lost in the replay handover", seq)
		}
	}
}

// Nothing reaches the client before the handover, or the client would see live
// events interleaved with history it has not finished reading.
func TestNothingIsDeliveredDuringReplay(t *testing.T) {
	b := bus.New()
	sub := b.Subscribe(tenant, bus.Filter{})
	defer sub.Close()

	for seq := int64(1); seq <= 10; seq++ {
		b.Publish(tenant, event(seq))
	}
	select {
	case ev := <-sub.Events():
		t.Fatalf("sequence %d was delivered during replay", ev.Seq)
	case <-time.After(50 * time.Millisecond):
	}

	sub.EndReplay(0)
	if got := len(drain(sub, 200*time.Millisecond)); got != 10 {
		t.Fatalf("received %d events after the handover, want 10", got)
	}
}

// A client that stops reading must not grow a queue without bound, and must not
// be disconnected either: the v1 server dropped the connection, which turned a
// slow phone on a train into a lost session.
func TestSlowClientLagsRatherThanBlocking(t *testing.T) {
	b := bus.New()
	sub := b.Subscribe(tenant, bus.Filter{})
	defer sub.Close()
	sub.EndReplay(0)

	// Far more than the queue holds, with nobody reading.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for seq := int64(1); seq <= 5000; seq++ {
			b.Publish(tenant, event(seq))
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Publish blocked on a client that stopped reading")
	}

	lagged, at, dropped := sub.Lagged()
	if !lagged {
		t.Fatal("the subscription did not report lagging")
	}
	if at == 0 {
		t.Error("the lag was not recorded with a sequence to resume from")
	}
	if dropped == 0 {
		t.Error("no drops were counted")
	}

	// The channel still holds what it could, so a client that comes back
	// reads recent events and then resumes from its cursor.
	if got := len(drain(sub, 200*time.Millisecond)); got == 0 {
		t.Error("the queue was emptied rather than kept")
	}

	sub.ClearLag()
	if lagged, _, _ := sub.Lagged(); lagged {
		t.Error("ClearLag did not reset the marker")
	}
}

// One stalled client must never slow ingest for another tenant.
func TestTenantsAreIsolated(t *testing.T) {
	b := bus.New()
	other := uuid.MustParse("99999999-9999-7999-8999-999999999999")

	mine := b.Subscribe(tenant, bus.Filter{})
	defer mine.Close()
	mine.EndReplay(0)

	theirs := b.Subscribe(other, bus.Filter{})
	defer theirs.Close()
	theirs.EndReplay(0)

	b.Publish(tenant, event(1))

	if got := len(drain(mine, 100*time.Millisecond)); got != 1 {
		t.Errorf("the tenant's own subscription received %d events, want 1", got)
	}
	if got := len(drain(theirs, 100*time.Millisecond)); got != 0 {
		t.Errorf("another tenant received %d events", got)
	}
}

func TestDeviceFilter(t *testing.T) {
	b := bus.New()
	wanted := uuid.New()
	unwanted := uuid.New()

	sub := b.Subscribe(tenant, bus.Filter{Devices: map[uuid.UUID]struct{}{wanted: {}}})
	defer sub.Close()
	sub.EndReplay(0)

	for _, dev := range []uuid.UUID{wanted, unwanted, wanted} {
		ev := event(1)
		ev.DeviceID = dev
		b.Publish(tenant, ev)
	}
	if got := len(drain(sub, 100*time.Millisecond)); got != 2 {
		t.Errorf("received %d events, want the 2 from the requested device", got)
	}
}

// Publishing to a closed subscription, and closing twice, must be safe: a
// client can disconnect at any moment, including mid-publish.
func TestCloseIsSafeUnderTraffic(t *testing.T) {
	b := bus.New()
	sub := b.Subscribe(tenant, bus.Filter{})
	sub.EndReplay(0)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for seq := int64(1); seq <= 2000; seq++ {
			b.Publish(tenant, event(seq))
		}
	}()
	time.Sleep(time.Millisecond)
	sub.Close()
	sub.Close() // idempotent
	wg.Wait()

	if got := b.Subscribers(tenant); got != 0 {
		t.Errorf("%d subscribers remain after close", got)
	}
}

// Many subscriptions, many publishers, run under -race.
func TestConcurrentSubscribersAndPublishers(t *testing.T) {
	b := bus.New()
	const subscribers, publishers, each = 8, 4, 200

	var wg sync.WaitGroup
	subs := make([]*bus.Subscription, subscribers)
	for i := range subs {
		subs[i] = b.Subscribe(tenant, bus.Filter{})
		subs[i].EndReplay(0)
		wg.Add(1)
		go func() {
			defer wg.Done()
			drain(subs[i], 400*time.Millisecond)
		}()
	}
	for p := range publishers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				b.Publish(tenant, event(int64(p*each+i+1)))
			}
		}()
	}
	wg.Wait()
	for _, s := range subs {
		s.Close()
	}
}
