package wa_test

import (
	"context"
	"log/slog"
	"testing"

	"go.mau.fi/whatsmeow/proto/waCommon"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"google.golang.org/protobuf/proto"

	"whatserver2/internal/wa"
	"whatserver2/internal/wa/fakewa"
)

// noopStore satisfies the device's persistence without a database: none of
// these tests is about what gets written down.
type noopStore struct{}

func (noopStore) SetStatus(context.Context, string, string, wa.Status, string) error { return nil }
func (noopStore) SetIdentity(context.Context, string, string, wa.Identity) error     { return nil }

// Some content travels encrypted a second time, under a key derived from the
// message it refers to, so that only somebody who received the original can
// read it. whatsmeow decrypts the outer Signal layer and stops: opening these
// needs the message secret it stored when the original arrived, and it leaves
// that call to the application.
//
// Nothing made the call. So an edit reached the archive as an unreadable blob
// of a type nobody recognised — sitting two lines under the message it was
// correcting. This is what that fix has to do.

func secretEdit(targetID string) *waE2E.Message {
	return &waE2E.Message{
		SecretEncryptedMessage: &waE2E.SecretEncryptedMessage{
			TargetMessageKey: &waCommon.MessageKey{ID: proto.String(targetID)},
			SecretEncType:    waE2E.SecretEncryptedMessage_MESSAGE_EDIT.Enum(),
			EncPayload:       []byte{1, 2, 3},
			EncIV:            []byte{4, 5, 6},
		},
	}
}

var secretChat = types.JID{User: "5511999999999", Server: types.DefaultUserServer}

// deliver runs one message through the supervisor and returns what reached the
// archive, which is the only thing that matters here.
func deliver(t *testing.T, msg *waE2E.Message, secrets map[string]*waE2E.Message) *waE2E.Message {
	t.Helper()
	fake := fakewa.New()
	fake.Secrets = secrets

	var seen *waE2E.Message
	sunk := make(chan struct{}, 1)
	dev, err := wa.NewDevice(wa.DeviceConfig{
		ID:       "11111111-1111-1111-1111-111111111111",
		TenantID: "22222222-2222-2222-2222-222222222222",
		Client:   fake,
		Store:    noopStore{},
		Policy:   wa.ReceiptPolicy{Mode: wa.ModePassive},
		Log:      slog.New(slog.DiscardHandler),
		Sink: wa.SinkFunc(func(_ context.Context, _ string, evt any) {
			if m, ok := evt.(*events.Message); ok {
				seen = m.Message
				select {
				case sunk <- struct{}{}:
				default:
				}
			}
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := dev.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dev.Stop(context.Background()) })

	fake.Emit(&events.Message{
		Info: types.MessageInfo{
			MessageSource: types.MessageSource{Chat: secretChat, Sender: secretChat},
			ID:            "EDIT-1",
		},
		Message: msg,
	})
	<-sunk
	return seen
}

func TestAnEncryptedEditArrivesAsAnEdit(t *testing.T) {
	// The payload carries only the new text, which is one of the two shapes
	// WhatsApp uses. The wrapper is what says this is a correction and what it
	// corrects, so the answer has to come from there.
	inner := &waE2E.Message{Conversation: proto.String("Oiiiii td bem ?")}
	got := deliver(t, secretEdit("ORIGINAL-1"), map[string]*waE2E.Message{"EDIT-1": inner})

	pm := got.GetProtocolMessage()
	if pm == nil {
		t.Fatalf("the message reached the archive still sealed: %+v", got)
	}
	if pm.GetType() != waE2E.ProtocolMessage_MESSAGE_EDIT {
		t.Errorf("type = %s, want MESSAGE_EDIT", pm.GetType())
	}
	if pm.GetKey().GetID() != "ORIGINAL-1" {
		t.Errorf("target = %q, want the message being corrected", pm.GetKey().GetID())
	}
	if pm.GetEditedMessage().GetConversation() != "Oiiiii td bem ?" {
		t.Errorf("new text = %q", pm.GetEditedMessage().GetConversation())
	}
}

func TestAnEncryptedEditThatAlreadySaysSoIsLeftAlone(t *testing.T) {
	// The other shape: the payload is itself a protocol message. Wrapping it
	// again would bury the edit one level deeper than the classifier looks.
	inner := &waE2E.Message{
		ProtocolMessage: &waE2E.ProtocolMessage{
			Type:          waE2E.ProtocolMessage_MESSAGE_EDIT.Enum(),
			Key:           &waCommon.MessageKey{ID: proto.String("ORIGINAL-2")},
			EditedMessage: &waE2E.Message{Conversation: proto.String("corrigido")},
		},
	}
	got := deliver(t, secretEdit("ORIGINAL-2"), map[string]*waE2E.Message{"EDIT-1": inner})

	pm := got.GetProtocolMessage()
	if pm == nil || pm.GetEditedMessage().GetConversation() != "corrigido" {
		t.Fatalf("the payload was rewrapped rather than used: %+v", got)
	}
	if pm.GetEditedMessage().GetProtocolMessage() != nil {
		t.Error("the edit was nested inside itself")
	}
}

func TestAnEncryptedReactionArrivesAsAReaction(t *testing.T) {
	// The same problem in an announcement group: the reaction is encrypted
	// under the secret of the message it is attached to.
	msg := &waE2E.Message{
		EncReactionMessage: &waE2E.EncReactionMessage{
			TargetMessageKey: &waCommon.MessageKey{ID: proto.String("ORIGINAL-3")},
			EncPayload:       []byte{1},
			EncIV:            []byte{2},
		},
		// The fake reads the plain reaction from here, standing in for the
		// decryption whatsmeow would do with the stored secret.
		ReactionMessage: &waE2E.ReactionMessage{Text: proto.String("👍")},
	}
	got := deliver(t, msg, nil)

	if got.GetReactionMessage().GetText() != "👍" {
		t.Fatalf("the reaction reached the archive still sealed: %+v", got)
	}
	if got.GetEncReactionMessage() != nil {
		t.Error("the wrapper survived alongside what it contained")
	}
}

func TestAMessageThatCannotBeOpenedIsStillDelivered(t *testing.T) {
	// No secret for this id. The row must still reach the archive: it keeps the
	// raw protobuf and the name of the field, so a later build that does have
	// the secret can make sense of it. Dropping it would leave a hole nobody
	// could explain.
	got := deliver(t, secretEdit("ORIGINAL-4"), nil)

	if got == nil {
		t.Fatal("the message was dropped rather than archived unopened")
	}
	if got.GetSecretEncryptedMessage() == nil {
		t.Error("the wrapper was discarded, losing the only record of what arrived")
	}
}

func TestAnOrdinaryMessageIsUntouched(t *testing.T) {
	plain := &waE2E.Message{Conversation: proto.String("oi")}
	got := deliver(t, plain, nil)
	if got.GetConversation() != "oi" {
		t.Errorf("an ordinary message was rewritten: %+v", got)
	}
}
