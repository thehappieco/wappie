package normalize_test

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"go.mau.fi/whatsmeow/proto/waCommon"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/proto/waWeb"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"google.golang.org/protobuf/proto"

	"whatserver2/internal/domain"
	"whatserver2/internal/wa/normalize"
)

var (
	chatJID = types.JID{User: "5511999999999", Server: types.DefaultUserServer}
	selfJID = types.JID{User: "5511888888888", Server: types.DefaultUserServer}
	msgID   = "3EB0ABCDEF1234567890"
	sentAt  = time.Unix(1770000000, 0).UTC()

	opts = normalize.Options{
		TenantID: "tenant-1",
		DeviceID: "device-1",
		Own:      domain.Address{PN: selfJID},
	}
)

// live builds the event shape whatsmeow delivers over the socket.
func live(t *testing.T, msg *waE2E.Message) domain.Envelope {
	return liveWith(t, msg, nil)
}

// liveWith is live, plus whatever the device managed to decrypt.
//
// The pointer is the whole point and is passed through rather than rebuilt: nil
// means nobody could open the vote, and a non-nil value with no selections
// means somebody withdrew theirs. A helper that collapsed the two would make
// the test that tells them apart impossible to write.
func liveWith(t *testing.T, msg *waE2E.Message, vote *normalize.OpenedVote) domain.Envelope {
	t.Helper()
	options := opts
	options.PollVote = vote
	return classifyLive(t, msg, options)
}

func classifyLive(t *testing.T, msg *waE2E.Message, opts normalize.Options) domain.Envelope {
	t.Helper()
	evt := &events.Message{
		RawMessage: msg,
		Info: types.MessageInfo{
			MessageSource: types.MessageSource{Chat: chatJID, Sender: chatJID},
			ID:            msgID,
			Timestamp:     sentAt,
		},
	}
	evt.UnwrapRaw()
	env, err := normalize.FromLive(evt, opts)
	if err != nil {
		t.Fatalf("FromLive: %v", err)
	}
	return env
}

// history builds the shape the same message takes inside a history sync blob.
func history(t *testing.T, msg *waE2E.Message) domain.Envelope {
	t.Helper()
	web := &waWeb.WebMessageInfo{
		Key: &waCommon.MessageKey{
			RemoteJID: proto.String(chatJID.String()),
			ID:        proto.String(msgID),
			FromMe:    proto.Bool(false),
		},
		Message:          msg,
		MessageTimestamp: proto.Uint64(uint64(sentAt.Unix())),
	}
	env, err := normalize.FromHistory(chatJID, web, opts)
	if err != nil {
		t.Fatalf("FromHistory: %v", err)
	}
	return env
}

// TestLiveAndHistoryAgree is the load-bearing test of this package.
//
// The v1 server dispatched message types separately on the live path and the
// history path, with a comment saying the duplication was intentional. The two
// drifted, and a message looked different depending on whether it had been seen
// live or backfilled. One classifier makes that impossible — and this test is
// what proves the two entry points really do reach it with the same input,
// rather than quietly diverging before they get there.
func TestLiveAndHistoryAgree(t *testing.T) {
	for name, msg := range map[string]*waE2E.Message{
		"plain text": {
			Conversation: proto.String("olá"),
		},
		"extended text": {
			ExtendedTextMessage: &waE2E.ExtendedTextMessage{Text: proto.String("com contexto")},
		},
		"forwarded text": {
			ExtendedTextMessage: &waE2E.ExtendedTextMessage{
				Text: proto.String("encaminhada"),
				ContextInfo: &waE2E.ContextInfo{
					IsForwarded:     proto.Bool(true),
					ForwardingScore: proto.Uint32(7),
				},
			},
		},
		"reply": {
			ExtendedTextMessage: &waE2E.ExtendedTextMessage{
				Text: proto.String("respondendo"),
				ContextInfo: &waE2E.ContextInfo{
					StanzaID: proto.String("TARGET123"),
				},
			},
		},
		"disappearing": {
			ExtendedTextMessage: &waE2E.ExtendedTextMessage{
				Text:        proto.String("some em 24h"),
				ContextInfo: &waE2E.ContextInfo{Expiration: proto.Uint32(86400)},
			},
		},
		"image with caption": {
			ImageMessage: &waE2E.ImageMessage{
				Caption:    proto.String("uma foto"),
				Mimetype:   proto.String("image/jpeg"),
				FileLength: proto.Uint64(12345),
				MediaKey:   []byte("0123456789abcdef0123456789abcdef"),
				DirectPath: proto.String("/v/t62.7118-24/x"),
				Width:      proto.Uint32(1080),
				Height:     proto.Uint32(1920),
			},
		},
		"voice note": {
			AudioMessage: &waE2E.AudioMessage{
				PTT:      proto.Bool(true),
				Seconds:  proto.Uint32(7),
				Waveform: make([]byte, 64),
				Mimetype: proto.String("audio/ogg; codecs=opus"),
				MediaKey: []byte("0123456789abcdef0123456789abcdef"),
			},
		},
		"round video note": {
			PtvMessage: &waE2E.VideoMessage{
				Seconds:  proto.Uint32(4),
				Mimetype: proto.String("video/mp4"),
				MediaKey: []byte("0123456789abcdef0123456789abcdef"),
			},
		},
		"document": {
			DocumentMessage: &waE2E.DocumentMessage{
				FileName: proto.String("contrato.pdf"),
				Mimetype: proto.String("application/pdf"),
				MediaKey: []byte("0123456789abcdef0123456789abcdef"),
			},
		},
		"sticker": {
			StickerMessage: &waE2E.StickerMessage{
				Mimetype: proto.String("image/webp"),
				MediaKey: []byte("0123456789abcdef0123456789abcdef"),
			},
		},
		"location": {
			LocationMessage: &waE2E.LocationMessage{
				DegreesLatitude:  proto.Float64(-23.5505),
				DegreesLongitude: proto.Float64(-46.6333),
				Name:             proto.String("São Paulo"),
			},
		},
		"contact": {
			ContactMessage: &waE2E.ContactMessage{
				DisplayName: proto.String("Fulano"),
				Vcard:       proto.String("BEGIN:VCARD\nEND:VCARD"),
			},
		},
		"poll": {
			PollCreationMessage: &waE2E.PollCreationMessage{
				Name: proto.String("Qual dia?"),
				Options: []*waE2E.PollCreationMessage_Option{
					{OptionName: proto.String("Segunda")},
					{OptionName: proto.String("Terça")},
				},
				SelectableOptionsCount: proto.Uint32(1),
			},
		},
		"view once image": {
			ViewOnceMessageV2: &waE2E.FutureProofMessage{Message: &waE2E.Message{
				ImageMessage: &waE2E.ImageMessage{
					Mimetype: proto.String("image/jpeg"),
					MediaKey: []byte("0123456789abcdef0123456789abcdef"),
				},
			}},
		},
		"ephemeral text": {
			EphemeralMessage: &waE2E.FutureProofMessage{Message: &waE2E.Message{
				Conversation: proto.String("efêmera"),
			}},
		},
		"unknown type": {
			// A type this build does not understand must still produce a row.
			PollAddOptionMessage: &waE2E.PollAddOptionMessage{},
		},
	} {
		t.Run(name, func(t *testing.T) {
			// Cloned because normalising mutates nothing but UnwrapRaw
			// reassigns pointers, and the two paths must not share state.
			l := live(t, proto.Clone(msg).(*waE2E.Message))
			h := history(t, proto.Clone(msg).(*waE2E.Message))

			if d := cmp.Diff(l, h,
				// Source is the one field that must differ: it records which
				// path the envelope arrived by, which ingest uses to decide
				// ordering and duplicate handling.
				cmpopts.IgnoreFields(domain.Envelope{}, "Source"),
				// Raw is the serialised protobuf. Both paths capture it, but
				// from a different point in the wrapper chain, so byte
				// equality is not the property under test.
				cmpopts.IgnoreFields(domain.Content{}, "Raw"),
				cmp.Comparer(func(a, b types.JID) bool { return a.String() == b.String() }),
			); d != "" {
				t.Errorf("live and history disagree (-live +history):\n%s", d)
			}
		})
	}
}

// An edit must survive the history path as an edit.
//
// whatsmeow's ParseWebMessage rewrites an edit into the message it replaces,
// which is convenient for a client that only wants the final text and fatal for
// an archive that exists to show the history. This package rebuilds the message
// info itself for exactly this reason, and this test is what proves it.
func TestEditSurvivesTheHistoryPath(t *testing.T) {
	edit := &waE2E.Message{EditedMessage: &waE2E.FutureProofMessage{
		Message: &waE2E.Message{ProtocolMessage: &waE2E.ProtocolMessage{
			Key:  &waCommon.MessageKey{ID: proto.String("ORIGINAL123")},
			Type: waE2E.ProtocolMessage_MESSAGE_EDIT.Enum(),
			EditedMessage: &waE2E.Message{
				Conversation: proto.String("texto corrigido"),
			},
		}},
	}}

	for name, env := range map[string]domain.Envelope{
		"live":    live(t, proto.Clone(edit).(*waE2E.Message)),
		"history": history(t, proto.Clone(edit).(*waE2E.Message)),
	} {
		t.Run(name, func(t *testing.T) {
			if env.Kind != domain.KindEdit {
				t.Fatalf("kind = %q, want edit — the edit framing was lost", env.Kind)
			}
			if env.TargetID != "ORIGINAL123" {
				t.Errorf("target = %q, want ORIGINAL123", env.TargetID)
			}
			if env.TargetRel != domain.TargetMessage {
				t.Errorf("target rel = %q, want message", env.TargetRel)
			}
			if env.Content.Body != "texto corrigido" {
				t.Errorf("body = %q, want the new text", env.Content.Body)
			}
			// The row keeps its own id, not the target's. Conflating them
			// would make the edit overwrite the original in any store keyed by
			// message id.
			if env.MessageID != msgID {
				t.Errorf("message id = %q, want the edit's own id %q", env.MessageID, msgID)
			}
		})
	}
}

// A revoke from another person arrives as an ordinary message event, because
// whatsmeow's protocol handler returns early for anything not from us. There is
// no events.MessageRevoked to subscribe to; detection is ours to do.
func TestRevokeIsDetected(t *testing.T) {
	revoke := &waE2E.Message{ProtocolMessage: &waE2E.ProtocolMessage{
		Key:  &waCommon.MessageKey{ID: proto.String("VICTIM123")},
		Type: waE2E.ProtocolMessage_REVOKE.Enum(),
	}}
	for name, env := range map[string]domain.Envelope{
		"live":    live(t, proto.Clone(revoke).(*waE2E.Message)),
		"history": history(t, proto.Clone(revoke).(*waE2E.Message)),
	} {
		t.Run(name, func(t *testing.T) {
			if env.Kind != domain.KindDelete {
				t.Fatalf("kind = %q, want delete", env.Kind)
			}
			if env.TargetID != "VICTIM123" {
				t.Errorf("target = %q", env.TargetID)
			}
			// Left unresolved on purpose: whether this deletes a message or
			// withdraws a reaction depends on what the target is, and only the
			// store knows. Ingest resolves it once and records the answer.
			if env.TargetRel != domain.TargetNone {
				t.Errorf("target rel = %q; a revoke's target is resolved during ingest, not here",
					env.TargetRel)
			}
		})
	}
}

func TestReaction(t *testing.T) {
	react := &waE2E.Message{ReactionMessage: &waE2E.ReactionMessage{
		Key:               &waCommon.MessageKey{ID: proto.String("LIKED123")},
		Text:              proto.String("\U0001F44D"),
		SenderTimestampMS: proto.Int64(sentAt.UnixMilli()),
	}}
	env := live(t, react)
	if env.Kind != domain.KindReaction || env.Type != domain.TypeReaction {
		t.Fatalf("kind/type = %q/%q", env.Kind, env.Type)
	}
	if env.TargetID != "LIKED123" || env.Content.Body != "\U0001F44D" {
		t.Errorf("target/body = %q/%q", env.TargetID, env.Content.Body)
	}
}

// Removing a reaction sends an empty emoji. It is a withdrawal, not a blank
// reaction, and ingest turns it into a delete against the previous one.
func TestReactionRemovalKeepsEmptyBody(t *testing.T) {
	env := live(t, &waE2E.Message{ReactionMessage: &waE2E.ReactionMessage{
		Key:  &waCommon.MessageKey{ID: proto.String("LIKED123")},
		Text: proto.String(""),
	}})
	if env.Kind != domain.KindReaction {
		t.Fatalf("kind = %q", env.Kind)
	}
	if env.Content.Body != "" {
		t.Errorf("body = %q, want empty", env.Content.Body)
	}
}

// Protocol housekeeping is not archive content.
func TestHousekeepingIsSkipped(t *testing.T) {
	for name, typ := range map[string]waE2E.ProtocolMessage_Type{
		"key share":     waE2E.ProtocolMessage_APP_STATE_SYNC_KEY_SHARE,
		"history sync":  waE2E.ProtocolMessage_HISTORY_SYNC_NOTIFICATION,
		"ephemeral set": waE2E.ProtocolMessage_EPHEMERAL_SETTING,
	} {
		t.Run(name, func(t *testing.T) {
			evt := &events.Message{
				RawMessage: &waE2E.Message{ProtocolMessage: &waE2E.ProtocolMessage{Type: typ.Enum()}},
				Info:       types.MessageInfo{ID: msgID},
			}
			evt.UnwrapRaw()
			if _, err := normalize.FromLive(evt, opts); err == nil {
				t.Fatal("housekeeping produced an archive row")
			}
		})
	}
}

// An unrecognised message must be kept, not dropped. The v1 server discarded
// them, leaving holes nobody could explain or recover.
func TestUnknownTypeIsKept(t *testing.T) {
	env := live(t, &waE2E.Message{PollAddOptionMessage: &waE2E.PollAddOptionMessage{}})
	if env.Kind != domain.KindMessage {
		t.Fatalf("kind = %q, want message", env.Kind)
	}
	if env.Type != domain.TypeUnsupported {
		t.Fatalf("type = %q, want unsupported", env.Type)
	}
	if env.MessageID != msgID {
		t.Error("routing metadata was lost")
	}
	if len(env.Content.Raw) == 0 {
		t.Error("the raw protobuf was not kept, so this message can never be recovered")
	}
}

// History blobs arrive from the network and are attacker-adjacent. A timestamp
// that wraps to a negative time when narrowed to int64 would sort to the top of
// every conversation — a cheap way to vandalise an archive with one crafted
// message.
func TestImplausibleTimestampIsRefused(t *testing.T) {
	for name, secs := range map[string]uint64{
		"wraps to negative": 1 << 63,
		"far future":        1 << 40,
		"max uint64":        ^uint64(0),
	} {
		t.Run(name, func(t *testing.T) {
			web := &waWeb.WebMessageInfo{
				Key: &waCommon.MessageKey{
					RemoteJID: proto.String(chatJID.String()),
					ID:        proto.String(msgID),
					FromMe:    proto.Bool(false),
				},
				Message:          &waE2E.Message{Conversation: proto.String("oi")},
				MessageTimestamp: proto.Uint64(secs),
			}
			env, err := normalize.FromHistory(chatJID, web, opts)
			if err != nil {
				t.Fatalf("the row should still be stored: %v", err)
			}
			if !env.Timestamp.IsZero() {
				t.Errorf("timestamp = %v, want the zero time", env.Timestamp)
			}
			if env.Content.Body != "oi" {
				t.Error("the message content was lost along with the bad timestamp")
			}
		})
	}
}

func TestPlausibleTimestampIsKept(t *testing.T) {
	web := &waWeb.WebMessageInfo{
		Key: &waCommon.MessageKey{
			RemoteJID: proto.String(chatJID.String()),
			ID:        proto.String(msgID),
			FromMe:    proto.Bool(false),
		},
		Message:          &waE2E.Message{Conversation: proto.String("oi")},
		MessageTimestamp: proto.Uint64(uint64(sentAt.Unix())),
	}
	env, err := normalize.FromHistory(chatJID, web, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !env.Timestamp.Equal(sentAt) {
		t.Errorf("timestamp = %v, want %v", env.Timestamp, sentAt)
	}
}
