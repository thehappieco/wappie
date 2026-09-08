package normalize_test

import (
	"testing"
	"time"

	"go.mau.fi/whatsmeow/proto/waE2E"
	"google.golang.org/protobuf/proto"

	"whatserver2/internal/domain"
)

// Structured content the normaliser understood since phase 2 but nothing
// carried to disk, plus the two it was dropping outright.

// TestMentionsAreCaptured. They were being thrown away on the way in: the
// context copier took the reply id, the forwarded flags and the expiry, and
// walked past MentionedJID.
func TestMentionsAreCaptured(t *testing.T) {
	msg := &waE2E.Message{
		ExtendedTextMessage: &waE2E.ExtendedTextMessage{
			Text: proto.String("@fulano vem?"),
			ContextInfo: &waE2E.ContextInfo{
				MentionedJID: []string{"5511911112222@s.whatsapp.net"},
			},
		},
	}
	env := live(t, msg)
	if len(env.Content.Mentions) != 1 {
		t.Fatalf("mentions = %v, want one", env.Content.Mentions)
	}
	// And they belong to the sealed side of the envelope, not beside chat_key.
	if env.Content.Payload().Empty() {
		t.Fatal("mentions did not reach the sealed payload")
	}
}

// TestALinkPreviewIsKeptButNeverFetched.
//
// Every field comes off the wire, built by the sender's client. Nothing in this
// path resolves a URL, which is both a privacy property — the server does not
// learn which links pass through it — and a safety one: a stranger's message
// must not be able to steer this process into issuing requests.
func TestALinkPreviewIsKeptButNeverFetched(t *testing.T) {
	msg := &waE2E.Message{
		ExtendedTextMessage: &waE2E.ExtendedTextMessage{
			Text:          proto.String("olha isso https://example.invalid/a"),
			MatchedText:   proto.String("https://example.invalid/a"),
			Title:         proto.String("Um título"),
			Description:   proto.String("uma descrição"),
			JPEGThumbnail: []byte{0xFF, 0xD8, 0xFF},
		},
	}
	env := live(t, msg)
	lp := env.Content.LinkPreview
	if lp == nil {
		t.Fatal("the link preview was dropped")
	}
	if lp.URL != "https://example.invalid/a" || lp.Title != "Um título" {
		t.Fatalf("preview came back as %+v", lp)
	}
	if len(lp.Thumbnail) != 3 {
		t.Fatalf("the preview thumbnail was lost: %v", lp.Thumbnail)
	}
}

// TestAPlainTextMessageHasNoPreview: a message with no URL must not produce an
// empty card, which would render as a blank box under every line of text.
func TestAPlainTextMessageHasNoPreview(t *testing.T) {
	env := live(t, &waE2E.Message{
		ExtendedTextMessage: &waE2E.ExtendedTextMessage{Text: proto.String("oi")},
	})
	if env.Content.LinkPreview != nil {
		t.Fatalf("a message with no URL produced a preview: %+v", env.Content.LinkPreview)
	}
	if !env.Content.Payload().Empty() {
		t.Fatal("a plain text message produced a payload, which would seal an empty object")
	}
}

// TestAnEventKeepsItsDetails. Only the name used to be kept, which classified
// the message and told a later reader nothing: an event without its date, place
// or join link is a row saying something happened and refusing to say what.
func TestAnEventKeepsItsDetails(t *testing.T) {
	start := time.Date(2026, 9, 1, 19, 0, 0, 0, time.UTC)
	msg := &waE2E.Message{
		EventMessage: &waE2E.EventMessage{
			Name:        proto.String("Jantar"),
			Description: proto.String("traz sobremesa"),
			JoinLink:    proto.String("https://example.invalid/j"),
			StartTime:   proto.Int64(start.Unix()),
			Location: &waE2E.LocationMessage{
				DegreesLatitude:  proto.Float64(-23.5),
				DegreesLongitude: proto.Float64(-46.6),
				Name:             proto.String("Casa"),
			},
		},
	}
	env := live(t, msg)
	if env.Type != domain.TypeEvent {
		t.Fatalf("type = %q, want event", env.Type)
	}
	ev := env.Content.Event
	if ev == nil {
		t.Fatal("the event details were dropped")
	}
	if !ev.StartTime.Equal(start) {
		t.Fatalf("start = %v, want %v", ev.StartTime, start)
	}
	if ev.Description != "traz sobremesa" || ev.JoinLink == "" {
		t.Fatalf("event came back as %+v", ev)
	}
	if ev.Location == nil || ev.Location.Name != "Casa" {
		t.Fatalf("event location came back as %+v", ev.Location)
	}
}

// TestAnImplausibleEventTimeIsRefused. Event times are signed seconds off the
// wire and go through the same bound as every other timestamp: a value that
// wraps when narrowed would sort an event to the beginning of recorded time.
func TestAnImplausibleEventTimeIsRefused(t *testing.T) {
	env := live(t, &waE2E.Message{
		EventMessage: &waE2E.EventMessage{
			Name:      proto.String("Jantar"),
			StartTime: proto.Int64(1 << 62),
		},
	})
	if env.Content.Event == nil {
		t.Fatal("the event was dropped entirely; only the bad time should be refused")
	}
	if !env.Content.Event.StartTime.IsZero() {
		t.Fatalf("start = %v, want the zero time", env.Content.Event.StartTime)
	}
}

// TestAPayloadRoundTripsThroughItsWireForm. The sealed value is JSON, and every
// field has to come back out of it — this is the seam where a missing struct
// tag silently drops a coordinate.
func TestAPayloadRoundTripsThroughItsWireForm(t *testing.T) {
	want := domain.Payload{
		Mentions: []string{"5511911112222@s.whatsapp.net"},
		Location: &domain.Location{
			Latitude: -23.5613, Longitude: -46.6565,
			Name: "MASP", Address: "Av. Paulista, 1578",
			AccuracyMeters: 12, Speed: 1.5, SequenceNumber: 7,
		},
		Contacts: []domain.Contact{{DisplayName: "Fulano", VCard: "BEGIN:VCARD"}},
		Poll: &domain.Poll{
			Question: "Onde?", Options: []string{"a", "b"}, SelectableCount: 1,
		},
		Event: &domain.Event{
			Name: "Jantar", StartTime: time.Date(2026, 9, 1, 19, 0, 0, 0, time.UTC),
			IsCanceled: true,
		},
		LinkPreview: &domain.LinkPreview{URL: "https://example.invalid", Title: "t"},
	}

	b, err := want.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := domain.ParsePayload(b)
	if err != nil {
		t.Fatal(err)
	}

	switch {
	case got.Location.Latitude != want.Location.Latitude,
		got.Location.Longitude != want.Location.Longitude,
		got.Location.AccuracyMeters != want.Location.AccuracyMeters,
		got.Location.SequenceNumber != want.Location.SequenceNumber:
		t.Fatalf("location came back as %+v", got.Location)
	case got.Poll.SelectableCount != 1 || len(got.Poll.Options) != 2:
		t.Fatalf("poll came back as %+v", got.Poll)
	case !got.Event.StartTime.Equal(want.Event.StartTime) || !got.Event.IsCanceled:
		t.Fatalf("event came back as %+v", got.Event)
	case got.LinkPreview.URL != want.LinkPreview.URL:
		t.Fatalf("preview came back as %+v", got.LinkPreview)
	case len(got.Mentions) != 1 || len(got.Contacts) != 1:
		t.Fatalf("mentions %v contacts %v", got.Mentions, got.Contacts)
	}
}
