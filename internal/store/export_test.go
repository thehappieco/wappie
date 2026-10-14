package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// EndIfIdle is the idle sweep's re-check of one connection under its row's
// lock, for the test of a connection renewed after the sweep picked it.
func (m *MCPConnections) EndIfIdle(ctx context.Context, tenant uuid.UUID, id string) (bool, error) {
	return m.endIfIdle(ctx, tenant, id)
}

// WithQuarantineForTest runs fn in tx with excluded numbers visible: the one
// way a test reaches an excluded number's row, to exclude a number, backdate
// its window in SQL or read what it still holds.
func WithQuarantineForTest(ctx context.Context, tx pgx.Tx, fn func() error) error {
	return withQuarantine(ctx, tx, fn)
}

// The reference checks of DeleteObject and of the orphan pass, for the test
// that reads their plans.
const (
	DeleteObjectCheckQuery   = deleteObjectCheck
	UnreferencedObjectsQuery = unreferencedObjects
)
