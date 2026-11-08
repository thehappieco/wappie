package access

import (
	"log/slog"
	"net/netip"
	"time"

	"whatserver2/internal/ratelimit"
	"whatserver2/internal/store"
)

// TokenLimits bounds token failures (the plan's 3.6), apart from the
// sign-ins' limits: an address over its budget of failures is refused
// before its token is looked at; a wrong secret under a known selector
// spends that selector's budget too, which never refuses (a selector is not
// secret: refusing on it would let anyone lock its token out, and a client
// that reconnects often is never refused) and, past five a minute, logs one
// WARN a minute naming the selector alone. A nil *TokenLimits limits
// nothing.
type TokenLimits struct {
	// Auth's PerIP is the address's budget of failures, PerSubject the
	// selector's (ratelimit.TokenFailures).
	Auth *ratelimit.Auth
	// warn paces the selector's WARN: one a minute.
	warn *ratelimit.Limiter
	Log  *slog.Logger
}

// NewTokenLimits is the production setting.
func NewTokenLimits(proxies []netip.Prefix, log *slog.Logger) *TokenLimits {
	return &TokenLimits{Auth: ratelimit.TokenFailures(proxies), warn: ratelimit.NewWindow(1, time.Minute), Log: log}
}

// allow reports whether an address may try a token: nothing is spent.
func (l *TokenLimits) allow(peer string) bool {
	if l == nil || l.Auth == nil || l.Auth.PerIP == nil || peer == "" {
		return true
	}
	return l.Auth.PerIP.Peek("ip:" + peer)
}

// failed spends what a failure costs.
func (l *TokenLimits) failed(peer string, f store.TokenFailure) {
	if l == nil || l.Auth == nil {
		return
	}
	if peer != "" && l.Auth.PerIP != nil {
		l.Auth.PerIP.Spend("ip:" + peer)
	}
	if f.Class != store.TokenFailMismatch || f.Selector == "" || l.Auth.PerSubject == nil {
		return
	}
	if l.Auth.PerSubject.Spend("selector:"+f.Selector) || l.warn == nil || !l.warn.Spend(f.Selector) {
		return
	}
	log := l.Log
	if log == nil {
		log = slog.Default()
	}
	log.Warn("a platform token's secret keeps failing: someone may be guessing it", "selector", f.Selector)
}
