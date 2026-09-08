// Package obs provides structured logging and metrics.
//
// Two rules this package exists to enforce:
//
//  1. One logger. The v1 server used slog nearly everywhere but fell back to
//     the global log.Printf in exactly one place — the QR channel drop in
//     Tenant.AddNewClient — and that one line silently swallowed pairing
//     failures because nothing was scraping stderr.
//
//  2. Ignoring an upstream event must cost something. The v1 handler ended with
//     `_ = v // ignore the rest for MVP` and dropped roughly forty event types
//     without a trace, which is why its contacts table was created, queried and
//     never once written to. EventIgnored below makes that visible on a
//     dashboard instead of invisible in a switch statement.
package obs

import (
	"context"
	"log/slog"
	"os"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
)

// NewLogger builds the process logger. level is debug|info|warn|error and
// format is json|text; both are validated by internal/config before arriving.
func NewLogger(level, format string) *slog.Logger {
	// Identifiers are masked in every record; see redact.go for why.
	opts := &slog.HandlerOptions{Level: parseLevel(level), ReplaceAttr: redactAttr}
	var h slog.Handler
	if format == "json" {
		h = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		h = slog.NewTextHandler(os.Stdout, opts)
	}
	return slog.New(h)
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// Metrics holds every collector the process exports. It is passed explicitly
// rather than kept in package state so tests can build an isolated registry and
// assert on counter values.
type Metrics struct {
	reg *prometheus.Registry

	EventsHandled *prometheus.CounterVec // by event type
	EventsIgnored *prometheus.CounterVec // by event type — must stay boring
	EventsFailed  *prometheus.CounterVec // by event type and reason

	IngestDuration *prometheus.HistogramVec // by stage
	Sealed         *prometheus.CounterVec   // by kind: body, media_key, thumbnail, raw

	// Receipt decisions. In incognito the "suppressed" series should be the
	// only one moving; anything landing in "sent" while a device is incognito
	// is a bug worth alerting on.
	ReceiptDecisions *prometheus.CounterVec // by kind (read|played|presence) and decision

	WSConnections   prometheus.Gauge
	WSFramesSent    *prometheus.CounterVec // by frame type
	WSLagEvents     prometheus.Counter     // slow consumer degraded to polling
	WSDisconnects   *prometheus.CounterVec // by reason
	MediaDownloads  *prometheus.CounterVec // by status
	MediaBytes      prometheus.Counter
	HistoryMessages prometheus.Counter
}

func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	counter := func(name, help string, labels ...string) *prometheus.CounterVec {
		c := prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "whatserver", Name: name, Help: help,
		}, labels)
		reg.MustRegister(c)
		return c
	}
	plain := func(name, help string) prometheus.Counter {
		c := prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "whatserver", Name: name, Help: help,
		})
		reg.MustRegister(c)
		return c
	}
	gauge := func(name, help string) prometheus.Gauge {
		g := prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "whatserver", Name: name, Help: help,
		})
		reg.MustRegister(g)
		return g
	}

	m := &Metrics{
		reg:           reg,
		EventsHandled: counter("events_handled_total", "whatsmeow events dispatched by the ingest pipeline.", "type"),
		EventsIgnored: counter("events_ignored_total", "whatsmeow events deliberately not handled. Every series here needs a written justification in the dispatch switch.", "type"),
		EventsFailed:  counter("events_failed_total", "whatsmeow events that errored during ingest.", "type", "reason"),
		IngestDuration: func() *prometheus.HistogramVec {
			h := prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Namespace: "whatserver", Name: "ingest_duration_seconds",
				Help:    "Time spent in each ingest stage.",
				Buckets: prometheus.ExponentialBuckets(0.0005, 2, 12),
			}, []string{"stage"})
			reg.MustRegister(h)
			return h
		}(),
		Sealed:           counter("sealed_total", "Payloads sealed to the tenant public key.", "kind"),
		ReceiptDecisions: counter("receipt_decisions_total", "Receipt policy outcomes. In incognito only the suppressed series should move.", "kind", "decision"),
		WSConnections:    gauge("ws_connections", "Open websocket sessions."),
		WSFramesSent:     counter("ws_frames_sent_total", "Frames written to websocket clients.", "type"),
		WSLagEvents:      plain("ws_lag_total", "Times a slow consumer was sent a lag frame instead of being disconnected."),
		WSDisconnects:    counter("ws_disconnects_total", "Websocket sessions closed.", "reason"),
		MediaDownloads:   counter("media_downloads_total", "Media fetches from the Meta CDN.", "status"),
		MediaBytes:       plain("media_bytes_total", "Ciphertext bytes stored to object storage."),
		HistoryMessages:  plain("history_messages_total", "Messages ingested from history sync."),
	}
	return m
}

// Handler serves the metrics endpoint.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

// Registry exposes the registry so other subsystems (the pgx pool stats
// collector, for instance) can register their own collectors.
func (m *Metrics) Registry() *prometheus.Registry { return m.reg }

// Receipt policy decisions, as metric label values.
const (
	DecisionSent       = "sent"
	DecisionSuppressed = "suppressed"
)

type ctxKey struct{}

// WithLogger returns a context carrying lg.
func WithLogger(ctx context.Context, lg *slog.Logger) context.Context {
	return context.WithValue(ctx, ctxKey{}, lg)
}

// LoggerFrom returns the context logger, or the default if none was attached.
// It never returns nil, so callers do not need a nil check at every use.
func LoggerFrom(ctx context.Context) *slog.Logger {
	if lg, ok := ctx.Value(ctxKey{}).(*slog.Logger); ok && lg != nil {
		return lg
	}
	return slog.Default()
}
