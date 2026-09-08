package ingest_test

import (
	"context"
	"testing"
	"time"

	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"google.golang.org/protobuf/proto"

	"whatserver2/internal/domain"
	"whatserver2/internal/ingest"
	"whatserver2/internal/store"
)

// A disappearing timer the OTHER side changed.
//
// In a one-to-one chat it arrives as a ProtocolMessage of type
// EPHEMERAL_SETTING inside an ordinary message event, and the classifier
// deliberately skips it — it is not a row. It was skipped and nothing else
// looked at it, so the setting reached the archive only sideways: every message
// in a disappearing chat carries the timer, and the chat row ratchets up from
// it. That ratchet only ever raises, by design.
//
// Which meant turning a timer ON showed up late, whenever the other side next
// spoke, and turning one OFF never showed up at all.

func ephemeralSetting(seconds uint32) *events.Message {
	return &events.Message{
		Info: types.MessageInfo{
			MessageSource: types.MessageSource{Chat: chatJID, Sender: chatJID},
			ID:            "SET-1",
			Timestamp:     time.Now(),
		},
		Message: &waE2E.Message{ProtocolMessage: &waE2E.ProtocolMessage{
			Type:                waE2E.ProtocolMessage_EPHEMERAL_SETTING.Enum(),
			EphemeralExpiration: proto.Uint32(seconds),
		}},
	}
}

func TestTheOtherSideTurningTheTimerOnIsRecorded(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	r := f.router(t)
	messages := store.NewMessages(f.pool)

	r.Handle(ctx, f.device.String(), ephemeralSetting(86400))

	timer, err := messages.ChatTimer(ctx, f.tenant, f.device, chatJID.String())
	if err != nil {
		t.Fatal(err)
	}
	if timer != 86400 {
		t.Fatalf("timer = %d, want 86400 — the setting was dropped as housekeeping", timer)
	}
}

func TestTheOtherSideTurningTheTimerOffIsRecorded(t *testing.T) {
	// The case nothing else can do. The per-message ratchet only raises, and
	// the explicit path that lowers was reachable only from our own outbound
	// handler — so a conversation the other side took out of disappearing mode
	// went on being drawn as temporary indefinitely.
	f := newFixture(t)
	ctx := context.Background()
	r := f.router(t)
	messages := store.NewMessages(f.pool)

	env := f.envelope("M1", domain.KindMessage, domain.TypeText, "some em 24h")
	env.Expiration = 86400
	f.ingest(t, env)

	r.Handle(ctx, f.device.String(), ephemeralSetting(0))

	timer, err := messages.ChatTimer(ctx, f.tenant, f.device, chatJID.String())
	if err != nil {
		t.Fatal(err)
	}
	if timer != 0 {
		t.Fatalf("timer = %d, want 0 — nothing else in the archive can lower it", timer)
	}
}

func TestATimerChangeIsAnnouncedToConnectedClients(t *testing.T) {
	// Recording it is half the job. The only frame that ever carried a timer
	// was the reply to a chats.list request, so a change landed in the database
	// and the open window went on showing the old value until a reload.
	f := newFixture(t)
	ctx := context.Background()
	r := f.router(t)

	r.Handle(ctx, f.device.String(), ephemeralSetting(604800))

	var seen *ingest.ChatUpdate
	for _, ev := range f.bus.all() {
		if ev.Class == ingest.ClassChat && ev.Chat != nil && ev.Chat.Ephemeral != nil {
			seen = ev.Chat
		}
	}
	if seen == nil {
		t.Fatal("nothing was published; the change is invisible until a reload")
	}
	if *seen.Ephemeral != 604800 {
		t.Errorf("announced %d, want 604800", *seen.Ephemeral)
	}
	if seen.Unread != nil {
		t.Error("the same event also claims to know the badge; a patch must " +
			"say nothing about a field it is not about")
	}
}

func TestATimerChangeIsNotArchivedAsAMessage(t *testing.T) {
	// It is a fact about the chat, not a line in it. A row here would put an
	// unreadable blob in the conversation where a setting change happened.
	f := newFixture(t)
	ctx := context.Background()
	r := f.router(t)

	r.Handle(ctx, f.device.String(), ephemeralSetting(86400))

	rows, err := store.NewMessages(f.pool).Page(ctx, f.tenant, f.device,
		[]string{chatJID.String()}, store.Cursor{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("archived %d rows for a setting change, want none", len(rows))
	}
}
