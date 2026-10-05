package mcpauth

import (
	"context"
	"time"
)

// ResendRevocations runs one round of revocation notices to a reader, for
// tests that cannot wait thirty seconds.
func (h *Handler) ResendRevocations(ctx context.Context, a *AttestedReader) int {
	return h.resendRevocations(ctx, a)
}

// SetRenewalDelay shortens how long after a reseal the renewal notices are
// sent, for tests that cannot wait the round's settling time.
func (h *Handler) SetRenewalDelay(d time.Duration) { h.renewalAfter = d }
