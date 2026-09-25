package mcpauth

import (
	"context"
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
// change in any of them is worth a line in the log.

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
		if failures >= healthFailures {
			h.log().Warn("an attested reader is not answering its health check", "reader", a.ID, "failures", failures, "error", err)
		} else {
			h.log().Info("an attested reader missed a health check", "reader", a.ID, "failures", failures, "error", err)
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
	days := -1
	if health.CertNotAfter != nil {
		days = int(time.Until(*health.CertNotAfter).Hours() / 24)
		attrs = append(attrs, "cert_days_left", days)
	}
	switch {
	case health.CertNotAfter != nil && days < certWarnDays:
		h.log().Warn("an attested reader's certificate is close to expiry", attrs...)
	case health.State != "ready":
		h.log().Warn("an attested reader is not ready", attrs...)
	default:
		h.log().Info("attested reader health", attrs...)
	}
	return 0
}

// fingerprint is the first twelve hex characters of a hash, or "none".
func fingerprint(hash *string) string {
	if hash == nil || len(*hash) < fingerprintLen || !isHex(*hash) {
		return "none"
	}
	return (*hash)[:fingerprintLen]
}
