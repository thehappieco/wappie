package send_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
	"whatserver2/internal/domain"
	"whatserver2/internal/wa/fakewa"
	"whatserver2/internal/wa/send"
)

func upcomingEvent() send.EventDraft {
	start := time.Now().Add(24 * time.Hour).Truncate(time.Second)
	return send.EventDraft{Name: "  Planning 📅  ", Description: "  Sprint planning  ", StartTime: start, EndTime: start.Add(time.Hour), LocationName: "  Office  ", JoinLink: " https://call.whatsapp.com/video/test-call "}
}

func TestNativeEventKeepsDatesVenueAndSecretAcrossChatTimers(t *testing.T) {
	var previousSecret []byte
	for _, seconds := range []uint32{0, 86400} {
		fake := fakewa.New()
		draft := upcomingEvent()
		draft.StartTime = draft.StartTime.In(time.FixedZone("Brazil", -3*3600)).Add(999 * time.Millisecond)
		sent, err := send.SendEvent(context.Background(), fake, types.NewJID("120363123", types.GroupServer), "EVENT-TEST", draft, send.Options{Expiration: seconds})
		if err != nil {
			t.Fatal(err)
		}
		messages := fake.Sent()
		if len(messages) != 1 || messages[0].Extra[0].ID != "EVENT-TEST" {
			t.Fatalf("expected one native event: %+v", messages)
		}
		msg := messages[0].Message
		secret := msg.GetMessageContextInfo().GetMessageSecret()
		if len(secret) != 32 || bytes.Equal(secret, make([]byte, 32)) || bytes.Equal(secret, previousSecret) {
			t.Fatal("event response secret is absent or reused")
		}
		previousSecret = secret
		if seconds > 0 {
			msg = msg.GetEphemeralMessage().GetMessage()
		}
		card := msg.GetEventMessage()
		if card == nil || card.GetName() != "Planning 📅" || card.GetDescription() != "Sprint planning" || card.GetStartTime() != draft.StartTime.Unix() || card.GetEndTime() != draft.EndTime.Unix() || card.GetJoinLink() != "https://call.whatsapp.com/video/test-call" || card.GetIsCanceled() {
			t.Fatalf("wrong event card: %+v", card)
		}
		if card.GetLocation().GetName() != "Office" || card.Location.DegreesLatitude != nil || card.Location.DegreesLongitude != nil {
			t.Fatal("venue label turned into invented map coordinates")
		}
		if card.GetContextInfo().GetExpiration() != seconds || sent.ID != "EVENT-TEST" || sent.Envelope.Type != domain.TypeEvent || sent.Envelope.Content.Body != card.GetName() || !sent.Envelope.IsGroup {
			t.Fatalf("event or disappearing timer differs: %+v", sent)
		}
		stored := sent.Envelope.Content.Event
		if stored == nil || stored.Name != card.GetName() || stored.Description != card.GetDescription() || stored.StartTime != time.Unix(card.GetStartTime(), 0).UTC() || stored.EndTime != time.Unix(card.GetEndTime(), 0).UTC() || stored.Location.Name != card.GetLocation().GetName() || stored.JoinLink != card.GetJoinLink() {
			t.Fatalf("archive differs from native event: %+v", stored)
		}
	}
}

func TestEventAllowsNoOptionalFieldsWithoutInventingEndOrVenue(t *testing.T) {
	fake := fakewa.New()
	draft := send.EventDraft{Name: "Quick call", StartTime: time.Now().Add(time.Hour)}
	sent, err := send.SendEvent(context.Background(), fake, types.NewJID("5511999999999", types.DefaultUserServer), "", draft, send.Options{})
	if err != nil {
		t.Fatal(err)
	}
	card := fake.Sent()[0].Message.EventMessage
	if card.EndTime != nil || card.Location != nil || card.JoinLink != nil || !sent.Envelope.Content.Event.EndTime.IsZero() || sent.Envelope.Content.Event.Location != nil {
		t.Fatal("optional dates or venue were invented")
	}
}

func TestInvalidEventsNeverReachWhatsApp(t *testing.T) {
	for name, mutate := range map[string]func(*send.EventDraft){
		"empty name":       func(d *send.EventDraft) { d.Name = "  " },
		"long name":        func(d *send.EventDraft) { d.Name = strings.Repeat("é", 101) },
		"long description": func(d *send.EventDraft) { d.Description = strings.Repeat("界", 2049) },
		"long venue":       func(d *send.EventDraft) { d.LocationName = strings.Repeat("é", 501) },
		"missing start":    func(d *send.EventDraft) { d.StartTime = time.Time{} },
		"past start":       func(d *send.EventDraft) { d.StartTime = time.Now().Add(-time.Minute) },
		"past end":         func(d *send.EventDraft) { d.EndTime = d.StartTime.Add(-time.Second) },
		"equal end":        func(d *send.EventDraft) { d.EndTime = d.StartTime.Add(999 * time.Millisecond) },
		"future bound":     func(d *send.EventDraft) { d.StartTime = time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC) },
		"end bound":        func(d *send.EventDraft) { d.EndTime = time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC) },
		"script link":      func(d *send.EventDraft) { d.JoinLink = "javascript:alert(1)" },
		"foreign host":     func(d *send.EventDraft) { d.JoinLink = "https://call.whatsapp.com.evil.example/video/a" },
		"credential link":  func(d *send.EventDraft) { d.JoinLink = "https://user@call.whatsapp.com/video/a" },
		"insecure link":    func(d *send.EventDraft) { d.JoinLink = "http://call.whatsapp.com/video/a" },
		"empty link path":  func(d *send.EventDraft) { d.JoinLink = "https://call.whatsapp.com/" },
		"link port":        func(d *send.EventDraft) { d.JoinLink = "https://call.whatsapp.com:8080/video/a" },
		"link backslash":   func(d *send.EventDraft) { d.JoinLink = "https://call.whatsapp.com/video\\a" },
		"link whitespace":  func(d *send.EventDraft) { d.JoinLink = "https://call.whatsapp.com/video/a b" },
	} {
		t.Run(name, func(t *testing.T) {
			draft := upcomingEvent()
			mutate(&draft)
			fake := fakewa.New()
			if _, err := send.SendEvent(context.Background(), fake, types.NewJID("120363123", types.GroupServer), "", draft, send.Options{}); err == nil || len(fake.Sent()) != 0 {
				t.Fatalf("invalid event sent: %+v %v", draft, err)
			}
		})
	}
	for _, target := range []types.JID{types.NewJID("status", types.BroadcastServer), types.NewJID("12345", types.NewsletterServer), types.NewJID("", types.DefaultUserServer)} {
		fake := fakewa.New()
		if _, err := send.SendEvent(context.Background(), fake, target, "", upcomingEvent(), send.Options{}); err == nil || len(fake.Sent()) != 0 {
			t.Fatalf("invalid event destination sent: %v", target)
		}
	}
	fake := fakewa.New()
	if _, err := send.SendEvent(context.Background(), fake, types.NewJID("12345", types.HiddenUserServer), "", upcomingEvent(), send.Options{ViewOnce: true}); err == nil || len(fake.Sent()) != 0 {
		t.Fatal("view-once event sent")
	}
}

func TestEventUnicodeLimitsAndExplicitHTTPSPort(t *testing.T) {
	draft := upcomingEvent()
	draft.Name, draft.Description, draft.LocationName = strings.Repeat("é", 100), strings.Repeat("界", 2048), strings.Repeat("é", 500)
	draft.JoinLink = "https://call.whatsapp.com:443/video/test-call?x=1#join"
	if _, err := send.ValidateEvent(draft, time.Now()); err != nil {
		t.Fatal(err)
	}
}

type uncertainEventClient struct {
	*fakewa.Client
	calls int
	err   error
}

func (c *uncertainEventClient) SendMessage(context.Context, types.JID, *waE2E.Message, ...whatsmeow.SendRequestExtra) (whatsmeow.SendResponse, error) {
	c.calls++
	return whatsmeow.SendResponse{}, c.err
}

func TestEventUncertainDeliveryIsNotRetriedOrArchivedAsSent(t *testing.T) {
	want := errors.New("connection lost waiting for acknowledgement")
	fake := &uncertainEventClient{Client: fakewa.New(), err: want}
	sent, err := send.SendEvent(context.Background(), fake, types.NewJID("12345", types.HiddenUserServer), "EVENT-TEST", upcomingEvent(), send.Options{})
	if !errors.Is(err, want) || fake.calls != 1 || sent.ID != "" || sent.Envelope.Content.Event != nil {
		t.Fatalf("ambiguous delivery retried or reported sent: calls=%d sent=%+v err=%v", fake.calls, sent, err)
	}
}
