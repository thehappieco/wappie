package normalize_test

import (
	"errors"
	"testing"

	"go.mau.fi/whatsmeow/proto/waCommon"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/proto/waWeb"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"google.golang.org/protobuf/proto"

	"whatserver2/internal/domain"
	"whatserver2/internal/wa/normalize"
)

// WhatsApp wraps ordinary messages in envelopes, and adds new ones every few
// months: group mentions, status mentions, spoilers, bot forwards, event cover
// images. whatsmeow's UnwrapRaw peels exactly nine of them, in one fixed-order
// pass, so anything else — or anything nested in an order that pass did not
// anticipate — reaches the classifier as a message whose only set field is the
// wrapper.
//
// The result is not a visible failure. The row stores, the timestamp is right,
// the sender is right, and the type says "unsupported" with no body at all. One
// real archive had 998 of them: ordinary text, stickers, and edits.
//
// So the classifier looks inside before giving up. These are the shapes that
// were arriving as unsupported.

// liveEvent builds the event whatsmeow delivers, without asserting that it
// produces a row — some messages correctly produce none.
func liveEvent(msg *waE2E.Message) *events.Message {
	evt := &events.Message{
		RawMessage: msg,
		Info: types.MessageInfo{
			MessageSource: types.MessageSource{Chat: chatJID, Sender: chatJID},
			ID:            msgID,
			Timestamp:     sentAt,
		},
	}
	evt.UnwrapRaw()
	return evt
}

func wrap(field func(*waE2E.Message, *waE2E.FutureProofMessage), inner *waE2E.Message) *waE2E.Message {
	out := &waE2E.Message{}
	field(out, &waE2E.FutureProofMessage{Message: inner})
	return out
}

func text(body string) *waE2E.Message {
	return &waE2E.Message{
		ExtendedTextMessage: &waE2E.ExtendedTextMessage{Text: proto.String(body)},
	}
}

func TestTextInsideAWrapperIsStillText(t *testing.T) {
	cases := []struct {
		name string
		set  func(*waE2E.Message, *waE2E.FutureProofMessage)
	}{
		{"groupMentioned", func(m *waE2E.Message, w *waE2E.FutureProofMessage) { m.GroupMentionedMessage = w }},
		{"statusMention", func(m *waE2E.Message, w *waE2E.FutureProofMessage) { m.StatusMentionMessage = w }},
		{"eventCoverImage", func(m *waE2E.Message, w *waE2E.FutureProofMessage) { m.EventCoverImage = w }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := wrap(tc.set, text("oi"))

			for label, env := range map[string]domain.Envelope{
				"live":    live(t, msg),
				"history": history(t, msg),
			} {
				if env.Type != domain.TypeText {
					t.Errorf("%s: type = %s, want text — the message was recorded as "+
						"unreadable while its text was one field away", label, env.Type)
				}
				if env.Content.Body != "oi" {
					t.Errorf("%s: body = %q, want %q", label, env.Content.Body, "oi")
				}
			}
		})
	}
}

func TestAStickerInsideAWrapperIsStillASticker(t *testing.T) {
	inner := &waE2E.Message{
		StickerMessage: &waE2E.StickerMessage{
			Mimetype:   proto.String("image/webp"),
			FileLength: proto.Uint64(4096),
		},
	}
	msg := wrap(func(m *waE2E.Message, w *waE2E.FutureProofMessage) { m.GroupMentionedMessage = w }, inner)

	env := live(t, msg)
	if env.Type != domain.TypeSticker {
		t.Fatalf("type = %s, want sticker", env.Type)
	}
	if env.Content.Media == nil || env.Content.Media.MimeType != "image/webp" {
		t.Errorf("the sticker lost its media: %+v", env.Content.Media)
	}
}

func TestAnEditInsideAWrapperIsStillAnEdit(t *testing.T) {
	// An edit nested under a wrapper UnwrapRaw already tested earlier in its
	// fixed order survives that pass. Filed as content, the original never gets
	// its new text — the archive shows the message as first sent, forever.
	edit := &waE2E.Message{
		ProtocolMessage: &waE2E.ProtocolMessage{
			Type: waE2E.ProtocolMessage_MESSAGE_EDIT.Enum(),
			Key:  &waCommon.MessageKey{ID: proto.String("ORIGINAL-1")},
			EditedMessage: &waE2E.Message{
				Conversation: proto.String("texto corrigido"),
			},
		},
	}
	msg := wrap(func(m *waE2E.Message, w *waE2E.FutureProofMessage) { m.GroupMentionedMessage = w }, edit)

	env := live(t, msg)
	if env.Kind != domain.KindEdit {
		t.Fatalf("kind = %s, want edit", env.Kind)
	}
	if env.TargetID != "ORIGINAL-1" {
		t.Errorf("target = %q, want the message being edited", env.TargetID)
	}
	if env.Content.Body != "texto corrigido" {
		t.Errorf("body = %q, want the new text", env.Content.Body)
	}
}

func TestNestedWrappersAreFollowedDown(t *testing.T) {
	// Two deep, which is what a mention inside an ephemeral chat produces.
	msg := wrap(
		func(m *waE2E.Message, w *waE2E.FutureProofMessage) { m.StatusMentionMessage = w },
		wrap(func(m *waE2E.Message, w *waE2E.FutureProofMessage) { m.GroupMentionedMessage = w }, text("aninhado")),
	)

	env := live(t, msg)
	if env.Type != domain.TypeText || env.Content.Body != "aninhado" {
		t.Errorf("type = %s body = %q, want text/aninhado", env.Type, env.Content.Body)
	}
}

func TestAStatusPostFromHistoryIsMarkedTheWayTheLivePathMarksIt(t *testing.T) {
	// whatsmeow treats a broadcast as a group on the live path — message.go
	// parseMessageSource: `from.Server == types.GroupServer || from.Server ==
	// types.BroadcastServer` — and the live path takes that flag as given. The
	// history importer computed its own answer and only checked for the group
	// server, so the same status post was a group when it arrived over the
	// socket and not a group when it came back in a sync.
	//
	// The cost was visible: a reader that names the author only in groups
	// labelled some status posts and not others, in the one feed where every
	// post is by a different person and the name is the whole point.
	status := types.JID{User: "status", Server: types.BroadcastServer}

	web := &waWeb.WebMessageInfo{
		Key: &waCommon.MessageKey{
			RemoteJID:   proto.String(status.String()),
			ID:          proto.String(msgID),
			FromMe:      proto.Bool(false),
			Participant: proto.String(chatJID.String()),
		},
		Message:          text("olha isso"),
		MessageTimestamp: proto.Uint64(uint64(sentAt.Unix())),
	}
	env, err := normalize.FromHistory(status, web, opts)
	if err != nil {
		t.Fatalf("FromHistory: %v", err)
	}
	if !env.IsGroup {
		t.Error("a status post from history is not marked as a broadcast; the same " +
			"message describes itself differently depending on which path found it")
	}
}

func TestSomethingGenuinelyUnknownIsStillUnsupported(t *testing.T) {
	// The descent must not turn "we do not understand this" into a wrong
	// answer, and an unsupported row must now say what it was carrying —
	// otherwise the payload is sealed and nobody can find out what to
	// implement next.
	// A payment invitation: real, and nothing here reads it. The album that
	// used to stand in here now classifies, which is what reprojection is for
	// — so this test moves to a type that genuinely is not implemented rather
	// than quietly asserting nothing.
	unknown := &waE2E.Message{PaymentInviteMessage: &waE2E.PaymentInviteMessage{}}
	env := live(t, unknown)
	if env.Type != domain.TypeUnsupported {
		t.Fatalf("type = %s, want unsupported", env.Type)
	}
	if env.Content.Unsupported != "paymentInviteMessage" {
		t.Errorf("unsupported field = %q, want paymentInviteMessage — without the name, "+
			"an unsupported row is a dead end", env.Content.Unsupported)
	}
}

func TestAnEmptyWrapperIsRecordedRatherThanDropped(t *testing.T) {
	// A wrapper this build could not open is not the same as protocol
	// machinery. It might be a message; dropping it would leave the hole in the
	// conversation that this package exists to avoid. So it is kept, and named.
	empty := wrap(func(m *waE2E.Message, w *waE2E.FutureProofMessage) { m.GroupMentionedMessage = w }, nil)
	env := live(t, empty)
	if env.Type != domain.TypeUnsupported {
		t.Fatalf("type = %s, want unsupported", env.Type)
	}
	if env.Content.Unsupported != "groupMentionedMessage" {
		t.Errorf("unsupported field = %q, want the wrapper's own name", env.Content.Unsupported)
	}
}

func TestAKeyDistributionMessageIsNotAMessage(t *testing.T) {
	// This one was destroying group traffic.
	//
	// WhatsApp delivers a group message as ONE node with two encrypted
	// children: the first carries only the sender key, the second carries the
	// message. whatsmeow dispatches an event for each, both with the SAME
	// message id. The sender-key event was falling through to "unsupported" and
	// being inserted — so when the real message arrived a moment later, ON
	// CONFLICT (device_id, chat_key, wa_id) rejected it as a duplicate of the
	// stub that had taken its place.
	//
	// On the installation where this was found, 40 of 152 newly archived
	// messages were those stubs, and not one of them was in a one-to-one chat,
	// because sender keys only exist in groups.
	skdm := &waE2E.Message{
		SenderKeyDistributionMessage: &waE2E.SenderKeyDistributionMessage{
			GroupID:                             proto.String("120363029249397928@g.us"),
			AxolotlSenderKeyDistributionMessage: []byte{1, 2, 3},
		},
	}
	if _, err := normalize.FromLive(liveEvent(skdm), opts); !errors.Is(err, normalize.ErrSkip) {
		t.Fatalf("a sender-key distribution produced a row (err=%v); it takes the "+
			"real message's place and the message is lost", err)
	}

	// But a key distribution riding along WITH content is a real message, and
	// dropping it would lose the very thing the stub was stealing.
	withText := &waE2E.Message{
		SenderKeyDistributionMessage: skdm.SenderKeyDistributionMessage,
		Conversation:                 proto.String("olá"),
	}
	env := live(t, withText)
	if env.Type != domain.TypeText || env.Content.Body != "olá" {
		t.Errorf("type = %s body = %q, want the text that came with the key",
			env.Type, env.Content.Body)
	}
}
