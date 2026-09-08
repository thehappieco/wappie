package ingest_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/domain"
	"whatserver2/internal/ingest"
	"whatserver2/internal/store"
)

// TestOurOwnMessagesKnowWhoSentThem.
//
// Every inbound row carries a sender. Outbound rows did not: the send package
// builds the envelope and holds a whatsmeow client, not this device's identity,
// so sender_key went in NULL. The effect is quiet and only shows up later —
// anything that groups a conversation by author, counts distinct participants,
// or resolves a name for the person who wrote a line finds nothing for exactly
// the messages the archive's owner sent. The lookup already carries the
// identity, for precisely this class of question, so IngestOutbound fills it.
func TestOurOwnMessagesKnowWhoSentThem(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	own := domain.Address{
		LID: types.JID{User: "111111111111111", Server: types.HiddenUserServer},
		PN:  types.JID{User: "5511900000000", Server: types.DefaultUserServer},
	}
	r, err := ingest.NewRouter(ingest.RouterConfig{
		Lookup: func(string) (ingest.DeviceInfo, bool) {
			return ingest.DeviceInfo{TenantID: f.tenant, Own: own}, true
		},
		Keys: f.keys, KeyStore: f.keys,
		Messages: store.NewMessages(f.pool),
		Bus:      f.bus,
		Log:      slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}

	res, err := r.IngestOutbound(ctx, f.tenant, f.device.String(), domain.Envelope{
		MessageID: "OUT1",
		Chat:      domain.AddressOf(types.JID{User: "5511999999999", Server: types.DefaultUserServer}),
		Timestamp: time.Now(),
		IsFromMe:  true,
		Kind:      domain.KindMessage,
		Type:      domain.TypeText,
		Content:   domain.Content{Body: "oi"},
	})
	if err != nil {
		t.Fatal(err)
	}

	row, err := store.NewMessages(f.pool).Get(ctx, f.tenant, res.UID)
	if err != nil {
		t.Fatal(err)
	}
	if row.SenderKey != own.LID.String() {
		t.Errorf("sender_key = %q, want %q — our own messages had no author",
			row.SenderKey, own.LID)
	}
	if row.SenderLID != own.LID.String() || row.SenderPN != own.PN.String() {
		t.Errorf("sender identity = (%q, %q), want both halves kept",
			row.SenderLID, row.SenderPN)
	}
}

// TestAnExplicitSenderIsNotOverwritten.
//
// Nothing in this archive rewrites an identifier, and the fill above is a
// default rather than a correction. A caller that already knows the sender —
// a replay, a re-import, anything that reconstructs a row — must keep it.
func TestAnExplicitSenderIsNotOverwritten(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	stated := domain.AddressOf(types.JID{User: "222222222222222", Server: types.HiddenUserServer})
	r, err := ingest.NewRouter(ingest.RouterConfig{
		Lookup: func(string) (ingest.DeviceInfo, bool) {
			return ingest.DeviceInfo{
				TenantID: f.tenant,
				Own:      domain.AddressOf(types.JID{User: "999", Server: types.HiddenUserServer}),
			}, true
		},
		Keys: f.keys, KeyStore: f.keys,
		Messages: store.NewMessages(f.pool),
		Bus:      f.bus,
		Log:      slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}

	res, err := r.IngestOutbound(ctx, f.tenant, f.device.String(), domain.Envelope{
		MessageID: "OUT2",
		Chat:      domain.AddressOf(types.JID{User: "5511999999999", Server: types.DefaultUserServer}),
		Sender:    stated,
		Timestamp: time.Now(),
		IsFromMe:  true,
		Kind:      domain.KindMessage,
		Type:      domain.TypeText,
		Content:   domain.Content{Body: "oi"},
	})
	if err != nil {
		t.Fatal(err)
	}
	row, err := store.NewMessages(f.pool).Get(ctx, f.tenant, res.UID)
	if err != nil {
		t.Fatal(err)
	}
	if row.SenderKey != stated.Primary().String() {
		t.Errorf("sender_key = %q, want the stated %q", row.SenderKey, stated.Primary())
	}
}
