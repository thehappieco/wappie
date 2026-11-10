package store

import (
	"context"
	"errors"
	"testing"
	"time"

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

// SetStrandLockTimeoutForTest sets how long an owner's override waits for
// each lock once it holds the contract's state, until the test ends.
func SetStrandLockTimeoutForTest(t testing.TB, d time.Duration) {
	old := strandLockTimeout
	strandLockTimeout = d
	t.Cleanup(func() { strandLockTimeout = old })
}

// SetAppForTest makes the token store apply another app's records, for the
// kit's vectors of a record as that app receives it (wire-tokens.json's
// Mailie case).
func (t *Tokens) SetAppForTest(app string) { t.app = app }

// SnapshotSeqForTest numbers a snapshot of workspace measured at measured,
// outside the measurement: the greater of measured's milliseconds and one
// more than the last snapshot's or section's, false when the workspace is
// parked. It is 12a's measure-then-number, which let a snapshot measured
// before an act's commit be numbered after it (the platform's check of
// fcffb55, finding 3), so no code but a test's numbers one so: the sender
// numbers its snapshot where it measures it (SnapshotNumbered). Tests use
// it to set the workspace's clock from a time of their own.
func (c *Contract) SnapshotSeqForTest(ctx context.Context, workspace uuid.UUID, measured time.Time) (int64, bool, error) {
	var seq int64
	err := c.pool.QueryRow(ctx, `UPDATE contract_workspaces SET snapshot_seq = greatest($2::bigint, snapshot_seq + 1, sections_seq + 1)
		WHERE workspace_id = $1 AND parked_at IS NULL RETURNING snapshot_seq`, workspace, measured.UnixMilli()).Scan(&seq)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	return seq, err == nil, err
}
