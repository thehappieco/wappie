package send_test

import (
	"context"
	"math"
	"strings"
	"testing"

	"go.mau.fi/whatsmeow/types"
	"whatserver2/internal/domain"
	"whatserver2/internal/wa/fakewa"
	"whatserver2/internal/wa/send"
)

func TestLocationSendMatchesArchivedPositionAndTimer(t *testing.T) {
	for _, lat := range []float64{0, -23.55052, 90} {
		fake := fakewa.New()
		location := domain.Location{Latitude: lat, Longitude: -46.63331, Name: "  Praça  ", Address: "  São Paulo  ", AccuracyMeters: 24}
		sent, err := send.SendLocation(context.Background(), fake, types.NewJID("120363123", types.GroupServer), "LOCATION-TEST", location, send.Options{Expiration: 86400})
		if err != nil {
			t.Fatal(err)
		}
		rows := fake.Sent()
		if len(rows) != 1 {
			t.Fatalf("sent %d messages", len(rows))
		}
		message := rows[0].Message.GetEphemeralMessage().GetMessage().GetLocationMessage()
		if message == nil || message.GetDegreesLatitude() != lat || message.GetDegreesLongitude() != location.Longitude || message.GetName() != "Praça" || message.GetAddress() != "São Paulo" || message.GetAccuracyInMeters() != 24 || message.GetIsLive() {
			t.Fatalf("wrong wire position: %+v", message)
		}
		if message.GetContextInfo().GetExpiration() != 86400 || sent.ID != "LOCATION-TEST" || sent.Envelope.Type != domain.TypeLocation || !sent.Envelope.IsGroup {
			t.Fatalf("wrong message or timer: %+v", sent)
		}
		stored := sent.Envelope.Content.Location
		if stored == nil || stored.Latitude != lat || stored.Longitude != message.GetDegreesLongitude() || stored.Name != message.GetName() || stored.Address != message.GetAddress() || stored.AccuracyMeters != message.GetAccuracyInMeters() {
			t.Fatalf("archive differs from wire: %+v", stored)
		}
	}
}

func TestInvalidLocationNeverReachesWhatsApp(t *testing.T) {
	for _, location := range []domain.Location{
		{Latitude: math.NaN()}, {Longitude: math.Inf(1)}, {Latitude: 90.001}, {Latitude: -91}, {Longitude: -180.001}, {Longitude: 181},
		{Name: strings.Repeat("é", 101)}, {Address: strings.Repeat("界", 501)}, {SequenceNumber: 1}, {Speed: 1},
	} {
		fake := fakewa.New()
		if _, err := send.SendLocation(context.Background(), fake, types.NewJID("5511999999999", types.DefaultUserServer), "", location, send.Options{}); err == nil || len(fake.Sent()) != 0 {
			t.Fatalf("invalid position sent: %+v, %v", location, err)
		}
	}
	if _, err := send.ValidateLocation(domain.Location{Latitude: -90, Longitude: 180}); err != nil {
		t.Fatal("valid boundary rejected", err)
	}
}
