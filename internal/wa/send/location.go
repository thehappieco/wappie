package send

import (
	"context"
	"fmt"
	"math"
	"strings"
	"unicode/utf8"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
	"google.golang.org/protobuf/proto"
	"whatserver2/internal/domain"
)

func ValidateLocation(location domain.Location) (domain.Location, error) {
	if math.IsNaN(location.Latitude) || math.IsInf(location.Latitude, 0) || location.Latitude < -90 || location.Latitude > 90 ||
		math.IsNaN(location.Longitude) || math.IsInf(location.Longitude, 0) || location.Longitude < -180 || location.Longitude > 180 {
		return domain.Location{}, fmt.Errorf("latitude must be between -90 and 90 and longitude between -180 and 180")
	}
	location.Name, location.Address = strings.TrimSpace(location.Name), strings.TrimSpace(location.Address)
	if utf8.RuneCountInString(location.Name) > 100 || utf8.RuneCountInString(location.Address) > 500 {
		return domain.Location{}, fmt.Errorf("location name allows 100 characters and address allows 500")
	}
	if location.SequenceNumber != 0 || location.Speed != 0 {
		return domain.Location{}, fmt.Errorf("only a fixed location can be sent; live location updates are not supported")
	}
	return location, nil
}

// SendLocation sends a fixed position. This does not create a live-location
// sharing session, even when its coordinates came from the device's GPS.
func SendLocation(ctx context.Context, c Client, chat types.JID, id string, location domain.Location, opts Options) (Sent, error) {
	location, err := ValidateLocation(location)
	if err != nil {
		return Sent{}, err
	}
	if opts.ViewOnce {
		return Sent{}, fmt.Errorf("a location cannot be view-once")
	}
	msg := wrap(&waE2E.Message{LocationMessage: &waE2E.LocationMessage{
		DegreesLatitude: proto.Float64(location.Latitude), DegreesLongitude: proto.Float64(location.Longitude),
		Name: proto.String(location.Name), Address: proto.String(location.Address), AccuracyInMeters: proto.Uint32(location.AccuracyMeters),
		ContextInfo: buildContext(chat, opts),
	}}, opts)
	var extra []whatsmeow.SendRequestExtra
	if id != "" {
		extra = append(extra, whatsmeow.SendRequestExtra{ID: id})
	}
	response, err := c.SendMessage(ctx, chat, msg, extra...)
	if err != nil {
		return Sent{}, fmt.Errorf("send location: %w", err)
	}
	envelope := outboundEnvelope(chat, response, domain.KindMessage, domain.TypeLocation, "", opts)
	envelope.Content.Location = &location
	return Sent{ID: response.ID, Timestamp: response.Timestamp, Envelope: envelope}, nil
}
