package mcpauth

import "context"

// ResendRevocations runs one round of revocation notices to a reader, for
// tests that cannot wait thirty seconds.
func (h *Handler) ResendRevocations(ctx context.Context, a *AttestedReader) int {
	return h.resendRevocations(ctx, a)
}
