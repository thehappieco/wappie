package wsapi_test

import (
	"testing"

	"whatserver2/internal/wsapi"
)

func TestLocationRequiresBothNumericCoordinates(t *testing.T) {
	conn, _ := handshake(t)
	for _, value := range []map[string]any{
		{}, {"lat": 0}, {"lon": 0}, {"lat": nil, "lon": 0}, {"lat": "1", "lon": 2}, {"lat": 91, "lon": 0}, {"lat": 0, "lon": 181},
	} {
		value["device_id"] = "018f3a2b-9999-7000-8000-00000000dead"
		value["chat"] = "5511999999999@s.whatsapp.net"
		send(t, conn, wsapi.TypeLocationSend, value)
		if response := errorOf(t, read(t, conn)); response.Code != wsapi.ErrCodeBadRequest {
			t.Fatalf("invalid coordinates passed preflight: %v %v", value, response)
		}
	}
}
