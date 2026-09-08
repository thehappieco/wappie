package ingest_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.mau.fi/whatsmeow/proto/waCommon"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/proto/waHistorySync"
	"go.mau.fi/whatsmeow/proto/waWeb"
	"go.mau.fi/whatsmeow/types/events"
	"google.golang.org/protobuf/proto"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/domain"
	"whatserver2/internal/ingest"
	"whatserver2/internal/store"
)

// The history sync consumer. Everything in phase 2 that reads a bootstrap
// existed except the thing that calls it: normalize.FromHistory was written and
// tested, and no code path reached it, so the sync WhatsApp delivers once per
// pairing went to a counter labelled "ignored".

func (f *fixture) router(t *testing.T) *ingest.Router {
	t.Helper()
	r, err := ingest.NewRouter(ingest.RouterConfig{
		Lookup: func(string) (ingest.DeviceInfo, bool) {
			return ingest.DeviceInfo{TenantID: f.tenant}, true
		},
		Keys:     f.keys,
		KeyStore: f.keys,
		Messages: store.NewMessages(f.pool),
		Contacts: store.NewContacts(f.pool),
		Groups:   store.NewGroups(f.pool),
		Bus:      f.bus,
		Log:      slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// historyMsg builds one message as it appears inside a sync blob.
func historyMsg(id string, msg *waE2E.Message, fromMe bool) *waHistorySync.HistorySyncMsg {
	return &waHistorySync.HistorySyncMsg{
		Message: &waWeb.WebMessageInfo{
			Key: &waCommon.MessageKey{
				RemoteJID: proto.String(chatJID.String()),
				ID:        proto.String(id),
				FromMe:    proto.Bool(fromMe),
			},
			MessageTimestamp: proto.Uint64(uint64(time.Now().Unix())),
			Message:          msg,
		},
	}
}

func text(body string) *waE2E.Message {
	return &waE2E.Message{Conversation: proto.String(body)}
}

// deliver hands a sync chunk to the router and waits for it to be stored.
func (f *fixture) deliver(t *testing.T, r *ingest.Router, sync *waHistorySync.HistorySync, want int) []store.Row {
	t.Helper()
	ctx, stop := context.WithTimeout(context.Background(), 20*time.Second)
	defer stop()
	go r.RunHistory(ctx)

	r.Handle(ctx, f.device.String(), &events.HistorySync{Data: sync})

	messages := store.NewMessages(f.pool)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		rows, err := messages.Page(ctx, f.tenant, f.device, []string{chatJID.String()}, store.Cursor{}, 200)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) >= want {
			return rows
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("only saw fewer than %d messages before giving up", want)
	return nil
}

func conversation(msgs ...*waHistorySync.HistorySyncMsg) *waHistorySync.Conversation {
	return &waHistorySync.Conversation{
		ID:       proto.String(chatJID.String()),
		Messages: msgs,
	}
}

func bootstrap(convs ...*waHistorySync.Conversation) *waHistorySync.HistorySync {
	return &waHistorySync.HistorySync{
		SyncType:      waHistorySync.HistorySync_INITIAL_BOOTSTRAP.Enum(),
		Conversations: convs,
		Progress:      proto.Uint32(100),
	}
}

// TestABootstrapIsIngested is the gap this closes.
func TestABootstrapIsIngested(t *testing.T) {
	f := newFixture(t)
	r := f.router(t)

	rows := f.deliver(t, r, bootstrap(conversation(
		historyMsg("H1", text("primeira"), false),
		historyMsg("H2", text("segunda"), true),
	)), 2)

	if len(rows) != 2 {
		t.Fatalf("stored %d messages, want 2", len(rows))
	}
	bodies := map[string]bool{}
	for _, row := range rows {
		bodies[f.body(t, row)] = true
		if row.Source != domain.SourceHistory {
			t.Errorf("%s has source %q, want history", row.WAID, row.Source)
		}
	}
	if !bodies["primeira"] || !bodies["segunda"] {
		t.Fatalf("bodies came back as %v", bodies)
	}
}

// TestAnEditInHistoryStaysAnEdit.
//
// The documented reason FromHistory stops short of ParseWebMessage: that helper
// overwrites an edit's id with its target's and replaces the content, which is
// convenient for a client wanting the final text and fatal for an archive whose
// whole purpose is the history. Worth an end-to-end test rather than only a
// unit one, because the mistake would be reintroduced by a caller, not by the
// normaliser.
func TestAnEditInHistoryStaysAnEdit(t *testing.T) {
	f := newFixture(t)
	r := f.router(t)

	edit := &waE2E.Message{ProtocolMessage: &waE2E.ProtocolMessage{
		Type: waE2E.ProtocolMessage_MESSAGE_EDIT.Enum(),
		Key:  &waCommon.MessageKey{ID: proto.String("H1")},
		EditedMessage: &waE2E.Message{
			Conversation: proto.String("primeira, corrigida"),
		},
	}}

	rows := f.deliver(t, r, bootstrap(conversation(
		historyMsg("H1", text("primeira"), true),
		historyMsg("H2", edit, true),
	)), 2)

	var found bool
	for _, row := range rows {
		if row.Kind != domain.KindEdit {
			continue
		}
		found = true
		if row.WAID != "H2" {
			t.Errorf("the edit was stored under id %q, want its own H2", row.WAID)
		}
		if row.TargetWAID != "H1" {
			t.Errorf("the edit targets %q, want H1", row.TargetWAID)
		}
		if got := f.body(t, row); got != "primeira, corrigida" {
			t.Errorf("edit body = %q", got)
		}
	}
	if !found {
		t.Fatal("the edit was stored as an ordinary message, so the history is gone")
	}
}

// TestAChatNameArrivesSealed.
//
// Names only come with the history sync — nothing on the live path carries one,
// which is why a group used to show as a numeric id. It is content: for a
// direct chat it is a person's name.
func TestAChatNameArrivesSealed(t *testing.T) {
	f := newFixture(t)
	r := f.router(t)

	conv := conversation(historyMsg("H1", text("oi"), false))
	conv.Name = proto.String("Turma do Prédio")
	conv.UnreadCount = proto.Uint32(3)
	conv.EphemeralExpiration = proto.Uint32(86400)
	f.deliver(t, r, bootstrap(conv), 1)

	chats, err := store.NewMessages(f.pool).Chats(context.Background(), f.tenant, f.device, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(chats) != 1 {
		t.Fatalf("got %d chats, want 1", len(chats))
	}
	c := chats[0]
	if len(c.NameSealed) == 0 {
		t.Fatal("the chat name was not stored")
	}
	if string(c.NameSealed) == "Turma do Prédio" {
		t.Fatal("the chat name is in the database in the clear")
	}
	if c.UID == uuid.Nil {
		t.Fatal("the chat has no identity, so its name is bound to nothing")
	}
	if c.Unread != 3 {
		t.Errorf("unread = %d, want 3", c.Unread)
	}

	// It opens, bound to the chat's own identity.
	got := f.open(t, c.UID, seal.KindContactName, c.NameKeyID, c.NameSealed)
	if string(got) != "Turma do Prédio" {
		t.Fatalf("name opened as %q", got)
	}

	// And the timer travelled with it.
	timer, err := store.NewMessages(f.pool).ChatTimer(context.Background(),
		f.tenant, f.device, chatJID.String())
	if err != nil {
		t.Fatal(err)
	}
	if timer != 86400 {
		t.Fatalf("timer = %d, want 86400", timer)
	}
}

// TestASealedNameDoesNotOpenAgainstAnotherChat. The binding is the point of
// giving a chat an identity at all.
func TestASealedNameDoesNotOpenAgainstAnotherChat(t *testing.T) {
	f := newFixture(t)
	r := f.router(t)

	conv := conversation(historyMsg("H1", text("oi"), false))
	conv.Name = proto.String("Turma do Prédio")
	f.deliver(t, r, bootstrap(conv), 1)

	chats, err := store.NewMessages(f.pool).Chats(context.Background(), f.tenant, f.device, 10)
	if err != nil {
		t.Fatal(err)
	}
	other := store.ChatUID(f.device, "5599999999999@s.whatsapp.net")
	if other == chats[0].UID {
		t.Fatal("two different chats derived the same identity")
	}

	blob, err := f.keys.SealedContentKey(context.Background(), f.tenant, f.device, chats[0].NameKeyID)
	if err != nil {
		t.Fatal(err)
	}
	ck, err := seal.OpenContentKey(f.priv, f.tenant, f.device, chats[0].NameKeyID, blob)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ck.Open(seal.KindContactName, f.tenant, other, chats[0].NameSealed); err == nil {
		t.Fatal("a chat's sealed name opened against a different chat")
	}
}

// TestSyncTypesWithoutMessagesAreSkipped. Push names are contacts, which are
// phase 6, and non-blocking data is settings. Neither is archive content.
func TestSyncTypesWithoutMessagesAreSkipped(t *testing.T) {
	f := newFixture(t)
	r := f.router(t)
	ctx, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	go r.RunHistory(ctx)

	for _, kind := range []waHistorySync.HistorySync_HistorySyncType{
		waHistorySync.HistorySync_PUSH_NAME,
		waHistorySync.HistorySync_NON_BLOCKING_DATA,
	} {
		sync := bootstrap(conversation(historyMsg("S1", text("nao guardar"), false)))
		sync.SyncType = kind.Enum()
		r.Handle(ctx, f.device.String(), &events.HistorySync{Data: sync})
	}
	time.Sleep(300 * time.Millisecond)

	rows, err := store.NewMessages(f.pool).Page(ctx, f.tenant, f.device, []string{chatJID.String()}, store.Cursor{}, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("stored %d messages from sync types that carry none", len(rows))
	}
}

// TestStatusUpdatesInASyncAreStoredLikeAnyOther.
//
// They arrive in their own field rather than as a conversation, and they are
// stored because the live path stores them: a status broadcast received while
// connected becomes an ordinary message row. Skipping them here would mean the
// same broadcast is in the archive or not depending on whether this device
// happened to be online when it was posted.
func TestStatusUpdatesInASyncAreStoredLikeAnyOther(t *testing.T) {
	f := newFixture(t)
	r := f.router(t)
	ctx, stop := context.WithTimeout(context.Background(), 15*time.Second)
	defer stop()
	go r.RunHistory(ctx)

	sync := &waHistorySync.HistorySync{
		SyncType: waHistorySync.HistorySync_INITIAL_STATUS_V3.Enum(),
		StatusV3Messages: []*waWeb.WebMessageInfo{
			historyMsg("ST1", text("um status"), false).GetMessage(),
		},
	}
	// The status pseudo-chat, not the ordinary one.
	sync.StatusV3Messages[0].Key.RemoteJID = proto.String("status@broadcast")
	r.Handle(ctx, f.device.String(), &events.HistorySync{Data: sync})

	messages := store.NewMessages(f.pool)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		rows, err := messages.Page(ctx, f.tenant, f.device, []string{"status@broadcast"}, store.Cursor{}, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) == 1 {
			if got := f.body(t, rows[0]); got != "um status" {
				t.Fatalf("body = %q", got)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the status update was never stored")
}

// TestRedeliveredHistoryIsIdempotent. WhatsApp resends chunks, and a re-pair
// replays the whole bootstrap.
func TestRedeliveredHistoryIsIdempotent(t *testing.T) {
	f := newFixture(t)
	r := f.router(t)

	chunk := bootstrap(conversation(
		historyMsg("H1", text("uma"), false),
		historyMsg("H2", text("duas"), false),
	))
	f.deliver(t, r, chunk, 2)
	f.deliver(t, r, chunk, 2)
	time.Sleep(300 * time.Millisecond)

	rows, err := store.NewMessages(f.pool).Page(context.Background(),
		f.tenant, f.device, []string{chatJID.String()}, store.Cursor{}, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("stored %d messages after two identical chunks, want 2", len(rows))
	}
}
