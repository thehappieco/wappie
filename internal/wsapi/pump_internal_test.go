package wsapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/bus"
	"whatserver2/internal/ingest"
)

// The live pump against a real bus, with the test reading the session's two
// queues in the writer's place. Presence needs no row read back, so neither
// a database nor a socket is involved.

// pumping subscribes a session to devices, runs before once the
// subscription is live and before its pump starts, then starts the pump.
func pumping(t *testing.T, b *bus.Bus, tenant uuid.UUID, devices []uuid.UUID, before func()) *session {
	t.Helper()
	filter := map[uuid.UUID]struct{}{}
	for _, d := range devices {
		filter[d] = struct{}{}
	}
	sub := b.Subscribe(tenant, bus.Filter{Devices: filter})
	t.Cleanup(sub.Close)
	sub.EndReplay(0)
	before()
	srv := &Server{cfg: Config{Bus: b}, log: slog.New(slog.DiscardHandler)}
	s := &session{srv: srv, tenant: tenant.String(), log: srv.log,
		out: make(chan Frame, 8), stream: make(chan Frame, 8), sub: sub}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.pump(ctx, sub, "sub")
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return s
}

func typing(tenant, device uuid.UUID, chat string) ingest.Event {
	return ingest.Event{Class: ingest.ClassPresence, TenantID: tenant, DeviceID: device, Ephemeral: true,
		Presence: &ingest.Presence{ChatKey: chat, State: "composing"}}
}

// streamed is the next frame the pump queued, failing on one it put on the
// replies' queue instead.
func streamed(t *testing.T, s *session) Frame {
	t.Helper()
	select {
	case f := <-s.stream:
		return f
	case f := <-s.out:
		t.Fatalf("%s went on the replies' queue, which the writer takes first", f.Type)
	case <-time.After(5 * time.Second):
		t.Fatal("the pump queued nothing")
	}
	return Frame{}
}

// Events of a number still in the bus's queue when the number is deleted
// are not relayed: the pump asks the filter as it is now, not as it was
// when the event was queued.
func TestPumpSkipsADeletedNumbersQueuedEvents(t *testing.T) {
	b := bus.New()
	tenant, deleted, kept := uuid.New(), uuid.New(), uuid.New()
	s := pumping(t, b, tenant, []uuid.UUID{deleted, kept}, func() {
		b.Publish(tenant, typing(tenant, deleted, "queued"))
		b.Publish(tenant, typing(tenant, kept, "kept"))
		b.DropDevice(tenant, deleted)
	})

	f := streamed(t, s)
	var p PresenceEvent
	if err := json.Unmarshal(f.Payload, &p); err != nil {
		t.Fatal(err)
	}
	if f.Type != TypePresence || p.DeviceID != kept.String() || p.ChatKey != "kept" {
		t.Fatalf("the pump relayed %s %s first, want the kept number's presence", f.Type, f.Payload)
	}
	if f.device != kept {
		t.Fatalf("the presence was queued for device %s, want %s", f.device, kept)
	}
}

// The end of a subscription is queued behind its last frames, on the same
// queue: a reply is written first and would overtake them.
func TestSubscriptionEndedFollowsItsFrames(t *testing.T) {
	b := bus.New()
	tenant, device := uuid.New(), uuid.New()
	s := pumping(t, b, tenant, []uuid.UUID{device}, func() {})

	b.Publish(tenant, typing(tenant, device, "before"))
	if f := streamed(t, s); f.Type != TypePresence || f.device != device {
		t.Fatalf("the pump queued %s for %s, want the presence of %s", f.Type, f.device, device)
	}
	b.DropDevice(tenant, device)
	f := streamed(t, s)
	var ended SubscriptionEnded
	if err := json.Unmarshal(f.Payload, &ended); err != nil {
		t.Fatal(err)
	}
	if f.Type != TypeSubscriptionEnded || f.ReqID != "sub" || ended.Reason != "device_removed" {
		t.Fatalf("after the drop the pump queued %s %q %s", f.Type, f.ReqID, f.Payload)
	}
	// Untagged, so the writer lets it through with no subscription left.
	if f.device != uuid.Nil {
		t.Fatalf("subscription.ended was queued for device %s", f.device)
	}
	s.subMu.Lock()
	defer s.subMu.Unlock()
	if s.sub != nil {
		t.Fatal("the ended subscription is still the session's")
	}
}
