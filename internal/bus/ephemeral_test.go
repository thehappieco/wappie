package bus_test

import (
	"testing"

	"github.com/google/uuid"

	"whatserver2/internal/bus"
	"whatserver2/internal/ingest"
)

// A dropped "somebody is typing" must not send a client back to the beginning
// of the archive.
//
// The bus tells a slow consumer where its view stopped being continuous, so it
// can resume rather than be disconnected — and it records that position from
// the event it had to drop. An ephemeral event has no row and no sequence
// number, so its Seq is zero: letting one mark the subscription lagged would
// hand the client a resume point of zero, and the whole archive would be
// refetched because a typing notification did not fit in a queue.
//
// Nothing about the failure is visible from the client's side. It looks like a
// reconnect that decided to re-read everything.
func TestADroppedTypingNotificationDoesNotRewindTheClient(t *testing.T) {
	b := bus.New()
	tenant := uuid.New()
	sub := b.Subscribe(tenant, bus.Filter{})
	defer sub.Close()
	sub.EndReplay(0)

	// Fill the queue past its depth with ephemeral events, without reading.
	for range 600 {
		b.Publish(tenant, ingest.Event{
			Class: ingest.ClassPresence, TenantID: tenant, Ephemeral: true,
		})
	}

	lagged, at, dropped := sub.Lagged()
	if lagged {
		t.Errorf("the subscription was marked lagged at sequence %d after %d dropped "+
			"typing notifications — the client would refetch the archive from the "+
			"beginning because a presence event did not fit in a queue", at, dropped)
	}
}

// A real event still marks the subscription, because a message that was dropped
// genuinely is a gap.
func TestADroppedMessageStillMarksTheSubscription(t *testing.T) {
	b := bus.New()
	tenant := uuid.New()
	sub := b.Subscribe(tenant, bus.Filter{})
	defer sub.Close()
	sub.EndReplay(0)

	for i := range 600 {
		b.Publish(tenant, ingest.Event{
			Class: ingest.ClassMessage, TenantID: tenant, Seq: int64(i + 1),
		})
	}
	lagged, at, _ := sub.Lagged()
	if !lagged {
		t.Fatal("a dropped message did not mark the subscription lagged")
	}
	if at == 0 {
		t.Error("the resume point is zero, which would refetch the whole archive")
	}
}
