package ingest_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"

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

type presencePhones map[types.JID]types.JID

func (p presencePhones) PhoneFor(_ context.Context, lid types.JID) (types.JID, bool) {
	pn, ok := p[lid]
	return pn, ok
}

func TestOnlinePresenceIsEphemeralAndKeepsBothIdentities(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	lid := types.NewJID("91938170638392", types.HiddenUserServer)
	pn := types.NewJID("5511999999999", types.DefaultUserServer)
	r, err := ingest.NewRouter(ingest.RouterConfig{
		Lookup: func(id string) (ingest.DeviceInfo, bool) {
			return ingest.DeviceInfo{TenantID: f.tenant}, id == f.device.String()
		},
		Keys: f.keys, KeyStore: f.keys, Messages: store.NewMessages(f.pool), Bus: f.bus,
		Phones: presencePhones{lid: pn}, Log: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	lastSeen := time.Date(2026, 9, 9, 11, 0, 0, 0, time.UTC)
	for _, unavailable := range []bool{false, true} {
		r.Handle(ctx, f.device.String(), &events.Presence{From: lid, Unavailable: unavailable, LastSeen: lastSeen})
	}
	got := f.bus.all()
	if len(got) != 2 {
		t.Fatalf("published %d events, want online and offline", len(got))
	}
	for i, ev := range got {
		if ev.Class != ingest.ClassPresence || !ev.Ephemeral || ev.Seq != 0 || ev.TenantID != f.tenant || ev.DeviceID != f.device {
			t.Fatalf("invalid ephemeral routing: %+v", ev)
		}
		p := ev.Presence
		if p == nil || p.ChatKey != lid.String() || p.SenderKey != lid.String() || p.SenderLID != lid.String() || p.SenderPN != pn.String() || ev.ChatKey != p.ChatKey {
			t.Fatalf("lost identity: %+v", p)
		}
		if i == 0 && (p.State != "available" || p.LastSeen != nil) {
			t.Fatalf("online retained stale last seen: %+v", p)
		}
		if i == 1 && (p.State != "unavailable" || p.LastSeen == nil || !p.LastSeen.Equal(lastSeen)) {
			t.Fatalf("offline lost last seen: %+v", p)
		}
	}
	seq, err := store.NewMessages(f.pool).MaxSeq(ctx, f.tenant)
	if err != nil || seq != 0 {
		t.Fatalf("presence advanced the archive: seq=%d err=%v", seq, err)
	}
	r.Handle(ctx, f.device.String(), &events.Presence{From: pn, Unavailable: true})
	if p := f.bus.all()[2].Presence; p.LastSeen != nil || p.SenderPN != pn.String() || p.SenderLID != "" {
		t.Fatalf("unknown last seen or PN-only identity was invented: %+v", p)
	}
	for _, id := range []string{uuid.NewString(), "invalid"} {
		r.Handle(ctx, id, &events.Presence{From: pn})
	}
	for _, from := range []types.JID{{}, types.NewJID("1234", types.GroupServer), types.NewJID("status", types.BroadcastServer)} {
		r.Handle(ctx, f.device.String(), &events.Presence{From: from})
	}
	r.Handle(ctx, f.device.String(), (*events.Presence)(nil))
	if len(f.bus.all()) != 3 {
		t.Fatal("invalid device or non-person presence was published")
	}
}
