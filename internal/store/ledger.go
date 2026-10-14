package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/ledger"
	"whatserver2/internal/pg"
)

// The deletion ledger (decision 0038's plan, section 8) is the record a
// restore replays: every deleted, recovered, purged and moved_out row of
// item_events, appended to a file outside the database. An event is marked
// ledgered only after its line was written and synced, so a failed write
// leaves it for the next export, and a crash between the two writes it
// twice, which the replay folds away by event id.

// ExportLedger appends the workspace's events the ledger does not have yet,
// in their order, and marks them ledgered. It holds the ledger's lock from
// the read to the mark, so two processes never export the same rows. It
// returns how many lines it wrote.
func ExportLedger(ctx context.Context, pool *pgxpool.Pool, tenant uuid.UUID, file *ledger.File) (int, error) {
	// Most passes have nothing to export: the file and its lock are left
	// alone then, so a ledger that cannot be written is reported only by
	// the export that needed it.
	var pending bool
	if err := pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM item_events
			WHERE ledgered_at IS NULL AND type IN ('deleted', 'recovered', 'purged', 'moved_out'))`).Scan(&pending)
	}); err != nil || !pending {
		return 0, err
	}
	n := 0
	err := file.Export(func(write func([]ledger.Line) error) error {
		return pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT event_id, type, item_id, deleted_at, purge_after,
				CASE WHEN type = 'deleted' THEN actor_user_id END, to_tenant_id, occurred_at
				FROM item_events WHERE ledgered_at IS NULL AND type IN ('deleted', 'recovered', 'purged', 'moved_out')
				ORDER BY seq`)
			if err != nil {
				return err
			}
			lines, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (ledger.Line, error) {
				l := ledger.Line{V: ledger.Version, WorkspaceID: tenant}
				err := row.Scan(&l.EventID, &l.Type, &l.DeviceID, &l.DeletedAt, &l.PurgeAfter, &l.DeletedBy, &l.ToWorkspaceID, &l.OccurredAt)
				return l, err
			})
			if err != nil || len(lines) == 0 {
				return err
			}
			if err := write(lines); err != nil {
				return err
			}
			ids := make([]uuid.UUID, len(lines))
			for i, l := range lines {
				ids[i] = l.EventID
			}
			if _, err := tx.Exec(ctx, `UPDATE item_events SET ledgered_at = clock_timestamp()
				WHERE event_id = ANY($1) AND ledgered_at IS NULL`, ids); err != nil {
				return fmt.Errorf("store: mark the ledgered events: %w", err)
			}
			n = len(lines)
			return nil
		})
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

// DeletionHousekeepingCounts is what DeletionHousekeeping removed, and the
// events it had to keep.
type DeletionHousekeepingCounts struct {
	Events, Notices int64
	// Unledgered counts the rows 30 days old that the ledger has not taken:
	// they stay, and the oldest is named, until an export takes them.
	Unledgered int64
	Oldest     *uuid.UUID
}

// DeletionHousekeeping removes what the deletions keep only for a while, in
// one workspace, on the database's clock (the plan's sections 5 and 7):
//
//   - an event row 30 days after it was written, once the ledger has it.
//     A row the ledger has not taken stays, however old;
//   - a seen notice 30 days after it was seen; a pause notice still unseen
//     30 days after its pause ended; a deletion notice still unseen 30 days
//     after its number was purged;
//   - an unseen pause notice whose person no longer reads the live number.
//     A deletion notice goes only by its own timers or when it is seen:
//     nobody reads an excluded or purged number.
func DeletionHousekeeping(ctx context.Context, pool *pgxpool.Pool, tenant uuid.UUID) (DeletionHousekeepingCounts, error) {
	var out DeletionHousekeepingCounts
	err := pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM item_events
			WHERE ledgered_at IS NOT NULL AND created_at < clock_timestamp() - interval '30 days'`)
		if err != nil {
			return fmt.Errorf("store: event housekeeping: %w", err)
		}
		out.Events = tag.RowsAffected()
		if err := tx.QueryRow(ctx, `SELECT count(*), (array_agg(event_id ORDER BY seq))[1] FROM item_events
			WHERE ledgered_at IS NULL AND created_at < clock_timestamp() - interval '30 days'`).Scan(&out.Unledgered, &out.Oldest); err != nil {
			return err
		}
		tag, err = tx.Exec(ctx, `DELETE FROM device_notices n WHERE n.tenant_id = $1 AND (
			   n.seen_at < clock_timestamp() - interval '30 days'
			OR (n.seen_at IS NULL AND n.kind = 'sync_paused' AND n.resumed_at < clock_timestamp() - interval '30 days')
			OR (n.seen_at IS NULL AND n.kind = 'number_deleted' AND n.purged_at < clock_timestamp() - interval '30 days')
			OR (n.seen_at IS NULL AND n.kind = 'sync_paused' AND NOT EXISTS (
			    SELECT 1 FROM workspace_memberships m
			    JOIN users r ON r.id = m.user_id
			    JOIN tenants t ON t.id = m.tenant_id
			    JOIN devices d ON d.tenant_id = m.tenant_id AND d.id = n.device_id
			    JOIN device_permissions p ON p.tenant_id = m.tenant_id AND p.device_id = d.id AND p.user_id = m.user_id AND p.can_read
			    WHERE m.tenant_id = n.tenant_id AND m.user_id = n.user_id
			      AND m.status = 'active' AND r.status = 'active' AND t.status = 'active'
			      AND (m.expires_at IS NULL OR m.expires_at > now())
			      AND EXISTS (SELECT 1 FROM device_key_grants g WHERE g.device_id = d.id AND g.user_id = m.user_id AND g.epoch = d.current_epoch))))`,
			tenant)
		if err != nil {
			return fmt.Errorf("store: notice housekeeping: %w", err)
		}
		out.Notices = tag.RowsAffected()
		return nil
	})
	return out, err
}

// NewestLedgeredEvent is the time of the newest ledgered event of the four
// a ledger holds, across every workspace, or the zero time with none: what a
// restored database already knew, for a replay to tell whether its ledger
// adds anything. A replay's own rows came from a ledger, not from the
// snapshot, and are left out, so a replay run again is not refused.
func NewestLedgeredEvent(ctx context.Context, pool *pgxpool.Pool) (time.Time, error) {
	tenants, err := allTenantIDs(ctx, pool)
	if err != nil {
		return time.Time{}, err
	}
	var newest time.Time
	for _, tenant := range tenants {
		var at *time.Time
		if err := pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT max(occurred_at) FROM item_events
				WHERE ledgered_at IS NOT NULL AND replayed_at IS NULL AND type IN ('deleted', 'recovered', 'purged', 'moved_out')`).Scan(&at)
		}); err != nil {
			return time.Time{}, err
		}
		if at != nil && at.After(newest) {
			newest = *at
		}
	}
	return newest, nil
}

// allTenantIDs is every workspace, whatever its status.
func allTenantIDs(ctx context.Context, pool *pgxpool.Pool) ([]uuid.UUID, error) {
	rows, err := pool.Query(ctx, `SELECT id FROM tenants ORDER BY id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}
