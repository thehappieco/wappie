package ingest_test

import (
	"context"
	"testing"

	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"

	"whatserver2/internal/ingest"
	"whatserver2/internal/store"
)

// Typing is published and never stored.
//
// There is nothing to store: it is true for a few seconds and then it is not,
// and a row recording it would be a fact that had stopped being one before
// anybody could read it. What matters structurally is that it carries no
// sequence number — the archive's cursor must not move for something that
// leaves no trace, or a client resuming from that cursor would skip whatever
// was written next.
func TestTypingIsPublishedAndNeverStored(t *testing.T) {
	f := newFixture(t)
	r := f.router(t)
	ctx := context.Background()
	peer := types.JID{User: "5511999999999", Server: types.DefaultUserServer}

	before := f.bus.all()
	r.Handle(ctx, f.device.String(), &events.ChatPresence{
		MessageSource: types.MessageSource{Chat: peer, Sender: peer},
		State:         types.ChatPresenceComposing,
		Media:         types.ChatPresenceMediaAudio,
	})

	got := f.bus.all()
	if len(got) != len(before)+1 {
		t.Fatalf("published %d events, want one more than %d", len(got), len(before))
	}
	ev := got[len(got)-1]
	if ev.Class != ingest.ClassPresence {
		t.Errorf("class = %q, want presence", ev.Class)
	}
	if !ev.Ephemeral {
		t.Error("the event is not marked ephemeral, so the bus may mark a client " +
			"lagged at sequence zero when one is dropped — and the client would " +
			"refetch the whole archive")
	}
	if ev.Seq != 0 {
		t.Errorf("seq = %d, want 0: nothing was written, so the cursor must not move", ev.Seq)
	}
	if ev.Presence == nil || ev.Presence.State != "composing" || ev.Presence.Media != "audio" {
		t.Errorf("presence = %+v, want composing/audio", ev.Presence)
	}

	// And nothing reached the archive.
	rows, err := store.NewMessages(f.pool).Page(ctx, f.tenant, f.device,
		[]string{peer.String()}, store.Cursor{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Errorf("typing wrote %d message rows", len(rows))
	}
}
