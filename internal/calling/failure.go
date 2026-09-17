package calling

import (
	"encoding/json"

	"github.com/rs/zerolog"
)

// The pinned meowcaller runMedia error path emits this event without OnEnd.
// Consume only the event name and call ID; never forward or retain diagnostics,
// error details, or media. This adapter must be checked when upgrading meowcaller.
type failureWriter struct{ failed func(string) }

func (w failureWriter) Write(data []byte) (int, error) {
	var event struct {
		Level   string `json:"level"`
		Message string `json:"message"`
		CallID  string `json:"call_id"`
	}
	if json.Unmarshal(data, &event) == nil && event.Level == "warn" && event.Message == "media ended" && event.CallID != "" && w.failed != nil {
		go w.failed(event.CallID)
	}
	return len(data), nil
}

func (s *Service) failureLogger(d *device) zerolog.Logger {
	writer := failureWriter{failed: func(callID string) { s.mediaFailed(d, callID) }}
	return zerolog.New(writer).Level(zerolog.WarnLevel)
}

func (s *Service) mediaFailed(d *device, callID string) {
	s.mu.Lock()
	r := d.active
	valid := s.devices[d.key] == d && r != nil && r.snapshot.ID == callID
	s.mu.Unlock()
	if valid {
		s.end(r, "media_failed", true)
	}
}
