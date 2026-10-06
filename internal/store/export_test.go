package store

import (
	"context"

	"github.com/google/uuid"
)

// EndIfIdle is the idle sweep's re-check of one connection under its row's
// lock, for the test of a connection renewed after the sweep picked it.
func (m *MCPConnections) EndIfIdle(ctx context.Context, tenant uuid.UUID, id string) (bool, error) {
	return m.endIfIdle(ctx, tenant, id)
}
