package mcpauth

import (
	"context"
	"errors"
	"time"
)

// Watching the attested readers from here.
//
// The parent instance watches the enclave too, but the parent is the machine
// the enclave exists to not trust, and its alarms go wherever its operator
// points them. This server asks each reader over the same signed link the
// consents use and logs what the reader says about itself: the image it runs
// (PCR0), the certificate key it serves (SPKI), the KMS policy it sees and
// how long its certificate has left. Every one of those is public, and a
// change in any of them is worth a line in the log. The line also carries
// the reader's clock as its last request here showed it (skew.go), and a 401
// to the health check says a clock past the signature's window is the
// likely cause. From reader 0.6.1 the reader also reports its own clock:
// whether it vouches for it, how sure it is, and how far this server's
// signatures read from it.
//
// The line goes out under one of three messages, and they do not change:
// the release gate (scripts/reader_policy_gate.py in the cloud repo) finds
// the fingerprints by matching them exactly.

const (
	// healthEvery is how often each reader is asked.
	healthEvery = time.Minute
	// healthFailures is how many misses in a row make a warning; one is a
	// restart, three is an outage.
	healthFailures = 3
	// certWarnDays is when a certificate's remaining life becomes a warning.
	// The reader renews at thirty days; twenty means renewal is failing.
	certWarnDays = 20
	// fingerprintLen is how much of a hash the log carries, as the reader's
	// own health line does.
	fingerprintLen = 12
)

// MonitorReaders asks every attested reader for its health once a minute
// until ctx ends. Nothing it learns changes what this server does; it is
// there so the log shows a reader's state before a person notices.
func (h *Handler) MonitorReaders(ctx context.Context) {
	for _, a := range h.Attested {
		go h.monitorReader(ctx, a, healthEvery)
	}
}

func (h *Handler) monitorReader(ctx context.Context, a *AttestedReader, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	failures := 0
	for {
		failures = h.checkReader(ctx, a, failures)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// checkReader asks once and logs the answer. It returns the count of
// consecutive failures after this one.
func (h *Handler) checkReader(parent context.Context, a *AttestedReader, failures int) int {
	ctx, cancel := context.WithTimeout(parent, signedRelayTimeout)
	defer cancel()
	health, err := a.Relay.Health(ctx)
	if err != nil {
		if parent.Err() != nil {
			// Shutting down, not a failure of the reader's.
			return failures
		}
		failures++
		if errors.Is(err, errHealthzUnauthorized) {
			h.noteHealthzRefused(parent, a, time.Now())
		}
		attrs := []any{"reader", a.ID, "failures", failures, "error", err}
		// The code the reader named, 503 clock_unknown above all: a
		// reader that cannot vouch for its clock and found this server's
		// signature outside its window by it.
		var status *HealthStatusError
		if errors.As(err, &status) && status.Code != "" {
			attrs = append(attrs, "code", status.Code)
		}
		if failures >= healthFailures {
			h.log().Warn("an attested reader is not answering its health check", attrs...)
		} else {
			h.log().Info("an attested reader missed a health check", attrs...)
		}
		return failures
	}
	if failures >= healthFailures {
		h.log().Info("an attested reader is answering again", "reader", a.ID, "after", failures)
	}
	attrs := []any{
		"reader", a.ID, "state", health.State, "version", health.ReaderVersion, "boot", health.BootID,
		"pcr0", fingerprint(&health.PCR0), "spki", fingerprint(health.TLSSPKISHA256),
		"policy", fingerprint(health.PolicySHA256), "relay_secrets", health.RelaySecrets,
	}
	// The reader's clock as its last request here showed it, signed or
	// only claimed (skew.go); none until it has sent one.
	attrs = append(attrs, h.clockAttrs(a.ID, time.Now())...)
	// The reader's own account of its clock, from 0.6.1; none from an
	// older reader.
	attrs = append(attrs, readerClockAttrs(health)...)
	days := -1
	if health.CertNotAfter != nil {
		days = int(time.Until(*health.CertNotAfter).Hours() / 24)
		attrs = append(attrs, "cert_days_left", days)
	}
	switch {
	case health.CertNotAfter != nil && days < certWarnDays:
		h.log().Warn("an attested reader's certificate is close to expiry", attrs...)
	case health.State != "ready":
		// A reader that cannot vouch for its clock says
		// "clock_unknown" here.
		h.log().Warn("an attested reader is not ready", attrs...)
	case goSkewWide(health.GoSkewMS):
		// The reader's clock and this server's are skewWarn apart by
		// the reader's own reading of this server's signatures. The
		// reader vouches for its clock, so this server's is the
		// suspect. The message is the usual one: the release gate
		// (reader_policy_gate.py in the cloud repo) matches the three
		// health messages exactly.
		h.log().Warn("attested reader health", attrs...)
	default:
		h.log().Info("attested reader health", attrs...)
	}
	return 0
}

// readerClockAttrs are the health line's fields for the clock the reader
// reports, each only when it sent one.
func readerClockAttrs(health ReaderHealth) []any {
	var attrs []any
	if health.ClockOK != nil {
		attrs = append(attrs, "clock_ok", *health.ClockOK)
	}
	for _, f := range []struct {
		key string
		ms  *int64
	}{
		{"clock_unc_ms", health.ClockUncMS},
		{"nsm_skew_ms", health.NSMSkewMS},
		{"go_skew_ms", health.GoSkewMS},
	} {
		if f.ms != nil {
			attrs = append(attrs, f.key, *f.ms)
		}
	}
	return attrs
}

// goSkewWide reports whether the reader's reading of this server's clock is
// skewWarn or more either way.
func goSkewWide(ms *int64) bool {
	if ms == nil {
		return false
	}
	abs := *ms
	if abs < 0 {
		abs = -abs
	}
	return abs >= skewWarn.Milliseconds()
}

// fingerprint is the first twelve hex characters of a hash, or "none".
func fingerprint(hash *string) string {
	if hash == nil || len(*hash) < fingerprintLen || !isHex(*hash) {
		return "none"
	}
	return (*hash)[:fingerprintLen]
}
