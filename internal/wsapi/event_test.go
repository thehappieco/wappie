package wsapi_test

import (
	"testing"
	"time"

	"whatserver2/internal/wsapi"
)

func TestEventRejectsInvalidDatesAndDetailsBeforeResolvingDevice(t *testing.T) {
	conn, _ := handshake(t)
	start := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	for _, value := range []map[string]any{
		{}, {"name": "Planning"}, {"name": "Planning", "start_time": nil}, {"name": "Planning", "start_time": "2026-01-01T10:00"},
		{"name": "Planning", "start_time": "2099-02-30T10:00:00Z"}, {"name": "Planning", "start_time": 123},
		{"name": "Planning", "start_time": start, "end_time": start}, {"name": "Planning", "start_time": start, "join_link": "https://example.com/meeting"},
	} {
		value["device_id"] = "018f3a2b-9999-7000-8000-00000000dead"
		value["chat"] = "5511999999999@s.whatsapp.net"
		send(t, conn, wsapi.TypeEventCreate, value)
		if response := errorOf(t, read(t, conn)); response.Code != wsapi.ErrCodeBadRequest {
			t.Fatalf("invalid event passed preflight: %v %v", value, response)
		}
	}
}
