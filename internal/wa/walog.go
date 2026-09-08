package wa

import (
	"context"
	"fmt"
	"log/slog"

	waLog "go.mau.fi/whatsmeow/util/log"
)

// slogAdapter routes whatsmeow's logging into the process logger.
//
// whatsmeow predates log/slog and has its own printf-style interface. Without
// this adapter its output would go somewhere else entirely, which is how the v1
// server ended up with one stray log.Printf that silently swallowed pairing
// failures because nothing was watching stderr.
type slogAdapter struct {
	lg     *slog.Logger
	module string
	wire   bool
}

// NewWALogger adapts a slog.Logger to whatsmeow's logger interface.
//
// Debug output is dropped. whatsmeow's debug level logs every binary node in
// both directions, which is every message in the clear — the exact thing the
// sealed archive exists to keep off disk. A log level is a knob somebody turns
// during an incident, and "everyone's messages are now in the log aggregator"
// is not a consequence a knob should have. See NewWireLogger.
func NewWALogger(lg *slog.Logger, module string) waLog.Logger {
	return &slogAdapter{lg: lg, module: module}
}

// NewWireLogger is NewWALogger with whatsmeow's debug output included.
//
// For development only. The caller is expected to have refused this in
// production already (config does), and the name says what it does so a call
// site cannot look innocuous.
func NewWireLogger(lg *slog.Logger, module string) waLog.Logger {
	return &slogAdapter{lg: lg, module: module, wire: true}
}

func (a *slogAdapter) log(level slog.Level, msg string, args ...any) {
	if !a.lg.Enabled(context.Background(), level) {
		return
	}
	// whatsmeow formats its own messages printf-style, so the arguments are
	// substitution values, not slog key/value pairs.
	a.lg.Log(context.Background(), level, fmt.Sprintf(msg, args...), "module", a.module)
}

func (a *slogAdapter) Errorf(msg string, args ...any) { a.log(slog.LevelError, msg, args...) }
func (a *slogAdapter) Warnf(msg string, args ...any)  { a.log(slog.LevelWarn, msg, args...) }
func (a *slogAdapter) Infof(msg string, args ...any)  { a.log(slog.LevelInfo, msg, args...) }

// Debugf is a no-op unless the wire log was asked for explicitly. This is
// where message plaintext would otherwise reach the log.
func (a *slogAdapter) Debugf(msg string, args ...any) {
	if !a.wire {
		return
	}
	a.log(slog.LevelDebug, msg, args...)
}

func (a *slogAdapter) Sub(module string) waLog.Logger {
	return &slogAdapter{lg: a.lg, module: a.module + "/" + module, wire: a.wire}
}
