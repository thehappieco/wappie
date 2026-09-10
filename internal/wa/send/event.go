package send

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
	"google.golang.org/protobuf/proto"
	"whatserver2/internal/domain"
)

// EventDraft creates an event. Updates, cancellations and RSVP responses use
// different protocol messages and are deliberately not represented as creates.
type EventDraft struct {
	Name, Description, LocationName, JoinLink string
	StartTime, EndTime                        time.Time
}

func ValidateEvent(event EventDraft, now time.Time) (EventDraft, error) {
	event.Name = strings.TrimSpace(event.Name)
	event.Description = strings.TrimSpace(event.Description)
	event.LocationName = strings.TrimSpace(event.LocationName)
	event.JoinLink = strings.TrimSpace(event.JoinLink)
	if event.Name == "" || utf8.RuneCountInString(event.Name) > 100 {
		return EventDraft{}, fmt.Errorf("event name must contain 1 to 100 characters")
	}
	if utf8.RuneCountInString(event.Description) > 2048 {
		return EventDraft{}, fmt.Errorf("event description allows up to 2048 characters")
	}
	if utf8.RuneCountInString(event.LocationName) > 500 {
		return EventDraft{}, fmt.Errorf("event location allows up to 500 characters")
	}
	// Native event timestamps have second precision. Validate the exact times
	// we send, and retain those same values in the encrypted archive.
	event.StartTime = event.StartTime.UTC().Truncate(time.Second)
	if event.StartTime.IsZero() || !event.StartTime.After(now) || event.StartTime.Year() >= 2200 {
		return EventDraft{}, fmt.Errorf("event start_time must be in the future and before year 2200")
	}
	if !event.EndTime.IsZero() {
		event.EndTime = event.EndTime.UTC().Truncate(time.Second)
		if !event.EndTime.After(event.StartTime) || event.EndTime.Year() >= 2200 {
			return EventDraft{}, fmt.Errorf("event end_time must be after start_time and before year 2200")
		}
	}
	if event.JoinLink != "" {
		link, err := url.Parse(event.JoinLink)
		if err != nil || len(event.JoinLink) > 2048 || !strings.EqualFold(link.Scheme, "https") || !strings.EqualFold(link.Hostname(), "call.whatsapp.com") || (link.Port() != "" && link.Port() != "443") || link.User != nil || strings.Trim(link.Path, "/") == "" || strings.Contains(event.JoinLink, "\\") || strings.ContainsFunc(event.JoinLink, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) {
			return EventDraft{}, fmt.Errorf("event join_link must be an HTTPS WhatsApp call link; put other meeting links in description")
		}
	}
	return event, nil
}

// SendEvent sends WhatsApp's native event card, including the message secret
// used by the protocol for encrypted event responses. Nothing is sent twice
// when the connection fails and its delivery outcome is uncertain.
func SendEvent(ctx context.Context, c Client, chat types.JID, id string, event EventDraft, opts Options) (Sent, error) {
	event, err := ValidateEvent(event, time.Now())
	if err != nil {
		return Sent{}, err
	}
	if chat.User == "" || (chat.Server != types.GroupServer && chat.Server != types.DefaultUserServer && chat.Server != types.HiddenUserServer) {
		return Sent{}, fmt.Errorf("events need an individual chat or a group")
	}
	if opts.ViewOnce {
		return Sent{}, fmt.Errorf("an event cannot be view-once")
	}
	card := &waE2E.EventMessage{
		Name: proto.String(event.Name), Description: proto.String(event.Description),
		StartTime: proto.Int64(event.StartTime.Unix()), IsCanceled: proto.Bool(false),
		ContextInfo: buildContext(chat, opts),
	}
	archived := &domain.Event{Name: event.Name, Description: event.Description, StartTime: event.StartTime, EndTime: event.EndTime, JoinLink: event.JoinLink}
	if !event.EndTime.IsZero() {
		card.EndTime = proto.Int64(event.EndTime.Unix())
	}
	if event.LocationName != "" {
		// A named venue does not imply coordinates: in particular it must not
		// turn into a map marker at zero latitude and longitude.
		card.Location = &waE2E.LocationMessage{Name: proto.String(event.LocationName)}
		archived.Location = &domain.Location{Name: event.LocationName}
	}
	if event.JoinLink != "" {
		card.JoinLink = proto.String(event.JoinLink)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return Sent{}, fmt.Errorf("create event message secret: %w", err)
	}
	msg := wrap(&waE2E.Message{EventMessage: card}, opts)
	// whatsmeow stores the secret from the outer message, including when the
	// chat's disappearing timer puts the event inside EphemeralMessage.
	msg.MessageContextInfo = &waE2E.MessageContextInfo{MessageSecret: secret}
	var extra []whatsmeow.SendRequestExtra
	if id != "" {
		extra = append(extra, whatsmeow.SendRequestExtra{ID: id})
	}
	response, err := c.SendMessage(ctx, chat, msg, extra...)
	if err != nil {
		return Sent{}, fmt.Errorf("send event: %w", err)
	}
	envelope := outboundEnvelope(chat, response, domain.KindMessage, domain.TypeEvent, event.Name, opts)
	envelope.Content.Event = archived
	return Sent{ID: response.ID, Timestamp: response.Timestamp, Envelope: envelope}, nil
}
