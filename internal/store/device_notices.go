package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/pg"
)

// device_notices (0050) is what Wappie tells a person in its own pages
// about a number: that it was deleted (its readers, and the workspace's other
// owners), or that its sync was turned off (its readers). They are required
// until the platform's mails start (decision 0039) and kept afterwards. A
// person has at most one unseen notice per number and kind.

// Notice kinds.
const (
	NoticeSyncPaused    = "sync_paused"
	NoticeNumberDeleted = "number_deleted"
)

// DeviceNotice is one unseen notice. Label and Hint are the snapshot the
// notice took of the number's name, never the number itself, and are null
// after the purge.
type DeviceNotice struct {
	ID            int64
	DeviceID      uuid.UUID
	Kind          string
	Label, Hint   *string
	RaisedAt      time.Time
	LastRaisedAt  *time.Time
	Pauses        int
	SeveralActors bool
	// RaisedByName is the person who acted, or a key's creator; nil when
	// nobody is known.
	RaisedByName *string
	RaisedByKind string
	Until        *time.Time
	ResumedAt    *time.Time
	PurgedAt     *time.Time
}

// Notices is what user has not seen yet: every number_deleted notice, from
// its snapshot, and a sync_paused one only while the number is live and the
// person still reads it.
func (d *Devices) Notices(ctx context.Context, tenant, user uuid.UUID) ([]DeviceNotice, error) {
	var out []DeviceNotice
	err := pg.InTenantTx(ctx, d.pool, tenant.String(), func(tx pgx.Tx) error {
		var err error
		out, err = noticesTx(ctx, tx, tenant, user)
		return err
	})
	return out, err
}

func noticesTx(ctx context.Context, tx pgx.Tx, tenant, user uuid.UUID) ([]DeviceNotice, error) {
	rows, err := tx.Query(ctx, `SELECT n.id, n.device_id, n.kind, n.label, n.hint, n.raised_at, n.last_raised_at, n.pauses,
		n.several_actors, nullif(coalesce(nullif(u.name, ''), u.email, h.email, ''), ''), n.raised_by_kind, n.until,
		n.resumed_at, n.purged_at
		FROM device_notices n
		LEFT JOIN users u ON u.id = n.raised_by
		LEFT JOIN workspace_member_history h ON h.tenant_id = n.tenant_id AND h.user_id = n.raised_by
		WHERE n.tenant_id = $1 AND n.user_id = $2 AND n.seen_at IS NULL
		  AND (n.kind = 'number_deleted' OR EXISTS (
		    SELECT 1 FROM workspace_memberships m
		    JOIN users r ON r.id = m.user_id
		    JOIN tenants t ON t.id = m.tenant_id
		    JOIN devices d ON d.tenant_id = m.tenant_id AND d.id = n.device_id
		    JOIN device_permissions p ON p.tenant_id = m.tenant_id AND p.device_id = d.id AND p.user_id = m.user_id AND p.can_read
		    WHERE m.tenant_id = n.tenant_id AND m.user_id = n.user_id
		      AND m.status = 'active' AND r.status = 'active' AND t.status = 'active'
		      AND (m.expires_at IS NULL OR m.expires_at > now())
		      AND EXISTS (SELECT 1 FROM device_key_grants g WHERE g.device_id = d.id AND g.user_id = m.user_id AND g.epoch = d.current_epoch)))
		ORDER BY n.raised_at, n.id`, tenant, user)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (DeviceNotice, error) {
		var n DeviceNotice
		err := row.Scan(&n.ID, &n.DeviceID, &n.Kind, &n.Label, &n.Hint, &n.RaisedAt, &n.LastRaisedAt, &n.Pauses,
			&n.SeveralActors, &n.RaisedByName, &n.RaisedByKind, &n.Until, &n.ResumedAt, &n.PurgedAt)
		return n, err
	})
}

// SeeNotices marks user's own notices among ids seen, and returns what is
// left unseen. Another person's notice is never touched.
func (d *Devices) SeeNotices(ctx context.Context, tenant, user uuid.UUID, ids []int64) ([]DeviceNotice, error) {
	var out []DeviceNotice
	err := pg.InTenantTx(ctx, d.pool, tenant.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE device_notices SET seen_at = clock_timestamp()
			WHERE tenant_id = $1 AND user_id = $2 AND id = ANY($3) AND seen_at IS NULL`, tenant, user, ids); err != nil {
			return err
		}
		var err error
		out, err = noticesTx(ctx, tx, tenant, user)
		return err
	})
	return out, err
}
