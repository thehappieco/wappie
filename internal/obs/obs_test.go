package obs

import (
	"bytes"
	"context"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestLoggerLevels(t *testing.T) {
	for _, tc := range []struct {
		level                  string
		wantDebug, wantWarning bool
	}{
		{"debug", true, true},
		{"info", false, true},
		{"warn", false, true},
		{"error", false, false},
	} {
		t.Run(tc.level, func(t *testing.T) {
			var buf bytes.Buffer
			lg := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: parseLevel(tc.level)}))
			lg.Debug("dbg")
			lg.Warn("wrn")
			out := buf.String()
			if got := strings.Contains(out, "dbg"); got != tc.wantDebug {
				t.Errorf("debug emitted = %v, want %v", got, tc.wantDebug)
			}
			if got := strings.Contains(out, "wrn"); got != tc.wantWarning {
				t.Errorf("warn emitted = %v, want %v", got, tc.wantWarning)
			}
		})
	}
}

func TestNewLoggerFormats(t *testing.T) {
	for _, format := range []string{"json", "text"} {
		if NewLogger("info", format) == nil {
			t.Errorf("NewLogger(%q) returned nil", format)
		}
	}
}

func TestMetricsRegisterWithoutPanic(t *testing.T) {
	// MustRegister panics on a duplicate metric name; building two independent
	// registries proves the names are unique and the constructor is reusable.
	NewMetrics()
	NewMetrics()
}

func TestMetricsHandlerServesRegisteredSeries(t *testing.T) {
	m := NewMetrics()
	m.EventsHandled.WithLabelValues("Message").Inc()
	m.EventsIgnored.WithLabelValues("Picture").Inc()
	m.ReceiptDecisions.WithLabelValues("read", DecisionSuppressed).Inc()
	m.Sealed.WithLabelValues("body").Add(3)

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), "GET", "/metrics", nil))

	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`whatserver_events_handled_total{type="Message"} 1`,
		`whatserver_events_ignored_total{type="Picture"} 1`,
		`whatserver_receipt_decisions_total{decision="suppressed",kind="read"} 1`,
		`whatserver_sealed_total{kind="body"} 3`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output missing:\n  %s", want)
		}
	}
}

// Ignoring an upstream event must be observable. This asserts the counter is
// real and countable, so a dashboard can show that, say, MediaRetry events are
// piling up unhandled — the failure mode that made v1's contacts table stay
// empty for its entire life.
func TestIgnoredEventsAreCountable(t *testing.T) {
	m := NewMetrics()
	for _, typ := range []string{"Picture", "Picture", "CallOffer"} {
		m.EventsIgnored.WithLabelValues(typ).Inc()
	}
	if got := testutil.ToFloat64(m.EventsIgnored.WithLabelValues("Picture")); got != 2 {
		t.Errorf("Picture ignored count = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.EventsIgnored.WithLabelValues("CallOffer")); got != 1 {
		t.Errorf("CallOffer ignored count = %v, want 1", got)
	}
}

func TestLoggerFromNeverReturnsNil(t *testing.T) {
	if LoggerFrom(context.Background()) == nil {
		t.Fatal("LoggerFrom(background) = nil")
	}
	//nolint:staticcheck // deliberately storing a nil logger to prove the guard
	ctx := context.WithValue(context.Background(), ctxKey{}, (*slog.Logger)(nil))
	if LoggerFrom(ctx) == nil {
		t.Fatal("LoggerFrom with an explicitly nil logger = nil")
	}
}

func TestLoggerRoundTripsThroughContext(t *testing.T) {
	var buf bytes.Buffer
	lg := slog.New(slog.NewTextHandler(&buf, nil))
	LoggerFrom(WithLogger(context.Background(), lg)).Info("hello", "k", "v")
	if !strings.Contains(buf.String(), "hello") {
		t.Fatalf("context logger was not used: %q", buf.String())
	}
}
