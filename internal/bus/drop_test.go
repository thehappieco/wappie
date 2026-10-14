package bus_test

import (
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/bus"
	"whatserver2/internal/ingest"
)

func deviceEvent(seq int64, device uuid.UUID) ingest.Event {
	ev := event(seq)
	ev.DeviceID = device
	return ev
}

// An empty set never means every device.
func TestAnEmptyFilterDeliversNothing(t *testing.T) {
	b := bus.New()
	sub := b.Subscribe(tenant, bus.Filter{Devices: map[uuid.UUID]struct{}{}})
	defer sub.Close()
	sub.EndReplay(0)
	b.Publish(tenant, deviceEvent(1, uuid.New()))
	if got := drain(sub, 100*time.Millisecond); len(got) != 0 {
		t.Fatalf("an empty filter delivered %v", got)
	}
}

// A deleted number leaves every filter that names it, and a subscription it
// was the only number of ends instead of falling back to everything.
func TestDropDevice(t *testing.T) {
	b := bus.New()
	deleted, kept := uuid.New(), uuid.New()
	both := b.Subscribe(tenant, bus.Filter{Devices: map[uuid.UUID]struct{}{deleted: {}, kept: {}}})
	defer both.Close()
	only := b.Subscribe(tenant, bus.Filter{Devices: map[uuid.UUID]struct{}{deleted: {}}})
	defer only.Close()
	both.EndReplay(0)
	only.EndReplay(0)

	b.DropDevice(tenant, deleted)
	select {
	case <-only.Ended():
	default:
		t.Fatal("the subscription to the deleted number alone did not end")
	}
	select {
	case <-both.Ended():
		t.Fatal("a subscription with another number ended")
	default:
	}
	b.Publish(tenant, deviceEvent(1, deleted))
	b.Publish(tenant, deviceEvent(2, kept))
	if got := drain(both, 100*time.Millisecond); len(got) != 1 || got[0] != 2 {
		t.Fatalf("the narrowed subscription received %v, want only the kept number's event", got)
	}
	if got := drain(only, 100*time.Millisecond); len(got) != 0 {
		t.Fatalf("the ended subscription received %v", got)
	}
	// Dropping again, or after Close, is harmless.
	b.DropDevice(tenant, deleted)
	only.Close()
	b.DropDevice(tenant, kept)
}

// An end during the replay releases nothing from the buffer.
func TestDropDeviceDuringReplay(t *testing.T) {
	b := bus.New()
	device := uuid.New()
	sub := b.Subscribe(tenant, bus.Filter{Devices: map[uuid.UUID]struct{}{device: {}}})
	defer sub.Close()
	b.Publish(tenant, deviceEvent(5, device))
	b.DropDevice(tenant, device)
	sub.EndReplay(0)
	if got := drain(sub, 100*time.Millisecond); len(got) != 0 {
		t.Fatalf("the replay buffer was released after the end: %v", got)
	}
}

// A number deleted while its events wait is not released afterwards. The
// replay's buffer forgets them, even when other numbers keep the
// subscription going; the queue cannot take back what it holds, so its
// reader asks Allows, which no longer passes them.
func TestDropDeviceForgetsWhatWaits(t *testing.T) {
	b := bus.New()
	deleted, kept := uuid.New(), uuid.New()
	both := map[uuid.UUID]struct{}{deleted: {}, kept: {}}

	replaying := b.Subscribe(tenant, bus.Filter{Devices: both})
	defer replaying.Close()
	b.Publish(tenant, deviceEvent(1, deleted))
	b.Publish(tenant, deviceEvent(2, kept))
	b.Publish(tenant, deviceEvent(3, deleted))
	b.DropDevice(tenant, deleted)
	replaying.EndReplay(0)
	if got := drain(replaying, 100*time.Millisecond); len(got) != 1 || got[0] != 2 {
		t.Fatalf("the handover released %v, want only the kept number's event", got)
	}

	live := b.Subscribe(tenant, bus.Filter{Devices: both})
	defer live.Close()
	live.EndReplay(0)
	b.Publish(tenant, deviceEvent(4, deleted))
	b.Publish(tenant, deviceEvent(5, kept))
	b.DropDevice(tenant, deleted)
	var passed []int64
	for range 2 {
		select {
		case ev := <-live.Events():
			if live.Allows(ev.DeviceID) {
				passed = append(passed, ev.Seq)
			}
		case <-time.After(time.Second):
			t.Fatal("an event queued before the drop is missing from the queue")
		}
	}
	if len(passed) != 1 || passed[0] != 5 {
		t.Fatalf("Allows passed %v of the queue, want only the kept number's event", passed)
	}
}

// Under -race: publishers, a replay and DropDevice at once. The filter is
// swapped, never written in place, so nothing races and nothing panics.
func TestDropDeviceUnderTraffic(t *testing.T) {
	b := bus.New()
	devices := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	filter := map[uuid.UUID]struct{}{}
	for _, d := range devices {
		filter[d] = struct{}{}
	}
	var subs []*bus.Subscription
	for range 4 {
		subs = append(subs, b.Subscribe(tenant, bus.Filter{Devices: filter}))
	}
	var wg sync.WaitGroup
	for p := range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 500 {
				b.Publish(tenant, deviceEvent(int64(i+1), devices[(p+i)%len(devices)]))
			}
		}()
	}
	for _, s := range subs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// The replay closures of the session read the same map.
			for range 200 {
				_ = len(filter)
				for range filter {
				}
			}
			s.EndReplay(0)
			drain(s, 200*time.Millisecond)
		}()
	}
	for _, d := range devices {
		b.DropDevice(tenant, d)
	}
	wg.Wait()
	for _, s := range subs {
		select {
		case <-s.Ended():
		default:
			t.Fatal("a subscription survived the deletion of all its numbers")
		}
		s.Close()
	}
}
