package send_test

import (
	"context"
	"errors"
	"testing"

	"whatserver2/internal/wa/fakewa"
	"whatserver2/internal/wa/send"
)

func TestReactionValidatesBeforeTransport(t *testing.T) {
	for _, value := range []string{"text", "👍👍", " ", "🏻", "a\uFE0F"} {
		fake := fakewa.New()
		_, err := send.SendReaction(context.Background(), fake, send.ReactRequest{Chat: dmChat, TargetID: "MSG1", Sender: other, Emoji: value})
		if !errors.Is(err, send.ErrInvalidReaction) || len(fake.Sent()) != 0 {
			t.Fatalf("%q: err=%v sent=%d", value, err, len(fake.Sent()))
		}
	}
}

func TestReactionKeepsWholeEmojiAndCanonicalArchive(t *testing.T) {
	for value, canonical := range map[string]string{"👩🏽‍💻": "👩🏽‍💻", "👨‍👩‍👧‍👦": "👨‍👩‍👧‍👦", "🇪🇪": "🇪🇪", "❤": "❤️", "": ""} {
		fake := fakewa.New()
		sent, err := send.SendReaction(context.Background(), fake, send.ReactRequest{Chat: dmChat, TargetID: "MSG1", Sender: other, Emoji: value})
		if err != nil {
			t.Fatal(err)
		}
		if got := fake.LastSent().Message.GetReactionMessage().GetText(); got != canonical {
			t.Errorf("wire emoji %q, want %q", got, canonical)
		}
		if sent.Envelope.Content.Body != canonical {
			t.Errorf("archive emoji %q, want %q", sent.Envelope.Content.Body, canonical)
		}
	}
}
