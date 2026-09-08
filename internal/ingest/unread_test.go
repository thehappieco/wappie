package ingest_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.mau.fi/whatsmeow/proto/waSyncAction"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"google.golang.org/protobuf/proto"

	"whatserver2/internal/domain"
	"whatserver2/internal/ingest"
	"whatserver2/internal/store"
)

func unreadRouter(t *testing.T, f *fixture) (*ingest.Router, *store.Unread) {
	t.Helper()
	unread := store.NewUnread(f.pool)
	r, err := ingest.NewRouter(ingest.RouterConfig{
		Lookup: func(string) (ingest.DeviceInfo, bool) {
			return ingest.DeviceInfo{TenantID: f.tenant}, true
		},
		Keys: f.keys, KeyStore: f.keys,
		Messages: store.NewMessages(f.pool),
		Receipts: store.NewReceipts(f.pool),
		Unread:   unread,
		Bus:      f.bus,
		Log:      slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	return r, unread
}

// inbound puts one countable message in a chat and returns its WhatsApp id.
func inbound(t *testing.T, f *fixture, chat types.JID, id string) string {
	t.Helper()
	_, err := store.NewMessages(f.pool).Insert(context.Background(), store.InsertMessage{
		UID: uuid.New(), TenantID: f.tenant, DeviceID: f.device,
		WAID: id, ChatKey: chat.String(), ChatPN: chat.String(),
		TS: time.Now().Truncate(time.Second), Kind: domain.KindMessage,
		Type: domain.TypeText, Source: domain.SourceLive,
		ContentKeyID: 1, BodySealed: []byte("selado"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// TestOurOwnDeliveryDoesNotClearTheBadge is the trap in the clearing rule.
//
// A read arriving with is_from_me set means one of our own other devices read
// the message, and the badge should follow — the person has read it, just not
// here. But types.ReceiptTypeSender ALSO arrives with is_from_me set, and it
// normalises to a DELIVERY: our own phone confirming it received something. If
// the rule were "is_from_me clears", every message we sent would empty the
// badge of the conversation it went to, because our own phone acknowledged it.
//
// Nothing about that looks wrong from the outside. The badge simply is not
// there, and the messages under it really did arrive.
func TestOurOwnDeliveryDoesNotClearTheBadge(t *testing.T) {
	f := newFixture(t)
	r, unread := unreadRouter(t, f)
	ctx := context.Background()
	peer := types.JID{User: "5511999999999", Server: types.DefaultUserServer}

	id := inbound(t, f, peer, "B1")
	if got, _ := unread.Count(ctx, f.tenant, f.device, peer.String()); got != 1 {
		t.Fatalf("unread = %d after one inbound message, want 1", got)
	}

	// Our own phone says "delivered". Nobody has read anything.
	r.Handle(ctx, f.device.String(), &events.Receipt{
		MessageSource: types.MessageSource{Chat: peer, Sender: peer, IsFromMe: true},
		MessageIDs:    []string{id},
		Timestamp:     time.Now(),
		Type:          types.ReceiptTypeSender,
	})
	if got, _ := unread.Count(ctx, f.tenant, f.device, peer.String()); got != 1 {
		t.Errorf("unread = %d after our own delivery receipt, want 1 — a delivery to "+
			"one of our devices is not somebody reading it", got)
	}

	// Our own phone says "read". Now it goes.
	r.Handle(ctx, f.device.String(), &events.Receipt{
		MessageSource: types.MessageSource{Chat: peer, Sender: peer, IsFromMe: true},
		MessageIDs:    []string{id},
		Timestamp:     time.Now(),
		Type:          types.ReceiptTypeReadSelf,
	})
	if got, _ := unread.Count(ctx, f.tenant, f.device, peer.String()); got != 0 {
		t.Errorf("unread = %d after our own read receipt, want 0", got)
	}
}

// TestAFullSyncDoesNotRelightEveryChatEverMarkedUnread.
//
// The registry turns on EmitAppStateEventsOnFullSync, so pairing a device
// replays the whole of app state. Replaying "read" is free — a watermark never
// moves backwards. Replaying "unread" is not: every conversation the phone has
// ever had marked unread would light up at once, on the first boot after
// pairing, and there is nothing in the archive that says which ones were recent.
func TestAFullSyncDoesNotRelightEveryChatEverMarkedUnread(t *testing.T) {
	f := newFixture(t)
	r, unread := unreadRouter(t, f)
	ctx := context.Background()
	peer := types.JID{User: "5511988887777", Server: types.DefaultUserServer}

	inbound(t, f, peer, "C1")
	r.Handle(ctx, f.device.String(), &events.MarkChatAsRead{
		JID: peer, Timestamp: time.Now(),
		Action: &waSyncAction.MarkChatAsReadAction{Read: proto.Bool(true)},
	})
	if got, _ := unread.Count(ctx, f.tenant, f.device, peer.String()); got != 0 {
		t.Fatalf("unread = %d after the phone marked the chat read, want 0", got)
	}

	// Replayed by a full sync. Must change nothing.
	r.Handle(ctx, f.device.String(), &events.MarkChatAsRead{
		JID: peer, Timestamp: time.Now(), FromFullSync: true,
		Action: &waSyncAction.MarkChatAsReadAction{Read: proto.Bool(false)},
	})
	if got, _ := unread.Count(ctx, f.tenant, f.device, peer.String()); got != 0 {
		t.Errorf("unread = %d after a replayed 'mark unread', want 0", got)
	}

	// A live one, though, is a person asking for a reminder.
	r.Handle(ctx, f.device.String(), &events.MarkChatAsRead{
		JID: peer, Timestamp: time.Now(),
		Action: &waSyncAction.MarkChatAsReadAction{Read: proto.Bool(false)},
	})
	if got, _ := unread.Count(ctx, f.tenant, f.device, peer.String()); got != 1 {
		t.Errorf("unread = %d after the phone marked the chat unread, want 1", got)
	}
}
