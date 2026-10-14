package bus_test

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/bus"
	"whatserver2/internal/ingest"
)

// A replay goes at the pace its client reads it, so the live events it holds
// back are bounded too.
//
// The buffer grew without limit, which was harmless while a replay took as
// long as its database reads: a client that fell behind was closed. It no
// longer is, so a client reading a long replay slowly would have this hold
// every event its tenant has for as long as it likes. Past what the handover
// can deliver, the subscription lags, now rather than at the handover.
func TestAReplayHoldsBackABoundedNumberOfEvents(t *testing.T) {
	b := bus.New()
	sub := b.Subscribe(tenant, bus.Filter{All: true})
	defer sub.Close()

	const depth, extra = 512, 40
	for seq := int64(1); seq <= depth+extra; seq++ {
		b.Publish(tenant, event(seq))
	}
	lagged, at, dropped := sub.Lagged()
	if !lagged {
		t.Fatal("the replay held every event back instead of lagging")
	}
	if at != depth+1 || dropped != extra {
		t.Fatalf("lagged at %d with %d dropped, want %d and %d", at, dropped, depth+1, extra)
	}

	// What it held is what the client gets, in order, before resuming.
	sub.EndReplay(0)
	got := drain(sub, 200*time.Millisecond)
	if len(got) != depth || got[0] != 1 || got[len(got)-1] != depth {
		t.Fatalf("the handover delivered %d events (%v...), want 1 to %d", len(got), got[:min(3, len(got))], depth)
	}
}

// Typing seen during a replay is stale once it ends and is discarded there,
// so it must not take the place of a message in the bounded buffer.
func TestTypingDuringAReplayDoesNotCrowdOutAMessage(t *testing.T) {
	b := bus.New()
	tenant := uuid.New()
	sub := b.Subscribe(tenant, bus.Filter{All: true})
	defer sub.Close()

	for range 600 {
		b.Publish(tenant, ingest.Event{Class: ingest.ClassPresence, TenantID: tenant, Ephemeral: true})
	}
	b.Publish(tenant, ingest.Event{Class: ingest.ClassMessage, TenantID: tenant, Seq: 7})
	if lagged, at, _ := sub.Lagged(); lagged {
		t.Fatalf("typing notifications made the replay lag at %d", at)
	}
	sub.EndReplay(0)
	if got := drain(sub, 200*time.Millisecond); len(got) != 1 || got[0] != 7 {
		t.Fatalf("the handover delivered %v, want the one message", got)
	}
}
