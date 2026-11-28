package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/pg"
)

// The usage report on Wappie's side (migration 0053; the platform's spec,
// section 15.8 and 15.9; E0 slice 18): each platform workspace's bytes per
// hosted number, read from one REPEATABLE READ snapshot that holds no lock
// on tenants or contract_workspaces, its usage_seq from a row of its own
// (contract_usage_seq), the cadence's state (contract_usage) and each
// report sent, kept at least 8 hours. No figure here is ever logged.

// ContractUsageChannel carries a workspace's id when a deletion, a
// recovery, a purge or a move out of one of its numbers commits (0053's
// contract_mark_usage): its usage report is due.
const ContractUsageChannel = "wappie_contract_usage"

// UsageRule is Wappie's measurement rule (the spec's 15.8).
const UsageRule = "wappie-storage/1"

// UsageKeep is how long a report sent is kept after its measured_at (the
// spec's 15.8: the longest an order can name it).
const UsageKeep = 8 * time.Hour

// usageStatementTimeout bounds one measurement: a timeout sends nothing,
// and the report stays due.
const usageStatementTimeout = "300s"

// The classes of the usage sender's ERRORs and findings.
const (
	// ContractErrorUsageMismatch: a measurement whose items and shared
	// bytes do not sum to the workspace's totals; nothing was sent.
	ContractErrorUsageMismatch = "usage_mismatch"
	// ContractErrorUsageInvalid: a report the platform refused
	// invalid_request, parked for an hour.
	ContractErrorUsageInvalid = "usage_invalid"
)

// The triggers that make a report due (contract_usage.due_trigger), the
// earliest deadline first.
const (
	UsageCrossing   = "crossing"
	UsageAfter      = "usage_after"
	UsageEvent      = "event"
	UsagePercent    = "percent"
	UsageFloor      = "floor"
	usageTriggerSQL = `CASE %s WHEN 'crossing' THEN 1 WHEN 'usage_after' THEN 2 WHEN 'event' THEN 3 WHEN 'percent' THEN 4 ELSE 5 END`
)

// ErrUsageMismatch is a measurement whose parts do not sum to the
// workspace's totals.
var ErrUsageMismatch = errors.New("store: the usage measured does not sum to the workspace's totals")

// UsageItemMeasure is one number's bytes in a measurement.
type UsageItemMeasure struct {
	Device  uuid.UUID
	State   string
	PurgeAt *time.Time
	// Bytes, Recent, Undated and Fixed are never logged.
	Bytes, Recent, Undated, Fixed int64
}

// UsageMeasure is one measurement of a workspace: its usage_seq and
// measured_at from one clock reading, its items, its shared bytes and its
// totals as tenants holds them. Never logged but its ids.
type UsageMeasure struct {
	Workspace  uuid.UUID
	Seq        int64
	MeasuredAt time.Time
	// Local: Wappie has the workspace (a tenant of that id); a workspace
	// with none reports nothing (items []).
	Local  bool
	Items  []UsageItemMeasure
	Shared int64
	// Total is tenants' archive and object bytes, read in the same
	// snapshot.
	Total int64
	// Unattributed counts the record rows no number owns (expected none),
	// folded into Shared.
	Unattributed int
}

// usageSeqTaken, nil but in a test, runs in MeasureUsage's transaction
// while it holds the seq row, before it measures.
var usageSeqTaken func(tx pgx.Tx)

// usageMeasureSQL is the measurement (the E0 design's 2.2): each record
// row's number and date (a message's ts, a receipt's and a group change's
// own; media and AI rows their message's; chats, contacts and group
// members fixed, undated), and each object's number and newest date among
// the messages on that number that reference it, shared when several
// numbers or none do. A date after measured_at ($3) counts as measured_at;
// recent is on or after $2.
const usageMeasureSQL = `WITH rec AS (
 SELECT i.bytes, i.source IN ('chats','contacts','group_participants') AS fixed,
  coalesce(m.device_id, g.device_id,
           (CASE WHEN i.source IN ('chats','receipts','contacts','group_participants') THEN i.identity::jsonb->>0 END)::uuid) AS dev,
  -- least() skips a NULL: an undated row stays NULL, never measured_at.
  CASE WHEN coalesce(m.ts, g.ts, r.ts) IS NOT NULL THEN least(coalesce(m.ts, g.ts, r.ts), $3::timestamptz) END AS ts
 FROM storage_inventory i
 LEFT JOIN messages m ON m.uid = (CASE WHEN i.source IN ('messages','media','ai_derived') THEN i.identity::jsonb->>0 END)::uuid
 LEFT JOIN group_changes g ON g.id = (CASE WHEN i.source = 'group_changes' THEN i.identity::jsonb->>0 END)::bigint
 LEFT JOIN receipts r ON i.source = 'receipts' AND (r.device_id::text, r.chat_key, r.wa_id, r.reader_key, r.kind)
   = (i.identity::jsonb->>0, i.identity::jsonb->>1, i.identity::jsonb->>2, i.identity::jsonb->>3, i.identity::jsonb->>4)
 WHERE i.tenant_id = $1
), refs AS (
 SELECT u.k, m.device_id AS dev, max(m.ts) AS newest
 FROM media d JOIN messages m ON m.uid = d.message_uid
 CROSS JOIN LATERAL (SELECT DISTINCT x FROM unnest(ARRAY[d.object_key, d.content_key]) x WHERE x IS NOT NULL) u(k)
 WHERE d.tenant_id = $1 GROUP BY u.k, m.device_id
), obj AS (
 SELECT o.bytes, count(r.dev) AS n, min(r.dev::text)::uuid AS dev, CASE WHEN max(r.newest) IS NULL THEN NULL ELSE least(max(r.newest), $3::timestamptz) END AS newest
 FROM storage_objects o LEFT JOIN refs r ON r.k = o.object_key WHERE o.tenant_id = $1 GROUP BY o.object_key, o.bytes
)
SELECT dev, sum(bytes)::bigint,
 coalesce(sum(bytes) FILTER (WHERE NOT fixed AND ts >= $2), 0)::bigint,
 coalesce(sum(bytes) FILTER (WHERE NOT fixed AND ts IS NULL), 0)::bigint,
 coalesce(sum(bytes) FILTER (WHERE fixed), 0)::bigint,
 count(*) FILTER (WHERE dev IS NULL)
FROM (SELECT bytes, fixed, dev, ts FROM rec
      UNION ALL SELECT bytes, false, dev, newest FROM obj WHERE n = 1) x
GROUP BY dev`

// usageSharedSQL is the objects several numbers or none reference.
const usageSharedSQL = `WITH refs AS (
 SELECT DISTINCT u.k, m.device_id AS dev
 FROM media d JOIN messages m ON m.uid = d.message_uid
 CROSS JOIN LATERAL (SELECT DISTINCT x FROM unnest(ARRAY[d.object_key, d.content_key]) x WHERE x IS NOT NULL) u(k)
 WHERE d.tenant_id = $1
)
SELECT coalesce(sum(bytes), 0)::bigint FROM (
 SELECT o.bytes FROM storage_objects o LEFT JOIN refs r ON r.k = o.object_key WHERE o.tenant_id = $1
 GROUP BY o.object_key, o.bytes HAVING count(r.dev) <> 1) s`

// MeasureUsage measures ws for its usage report (the E0 design's 2.2).
// Its seq row is made, if missing, in a short transaction of its own; the
// measurement then runs in one REPEATABLE READ transaction whose first
// statement takes usage_seq and measured_at from one clock reading under
// that row's lock (greatest of the clock in milliseconds and the last seq
// plus one), so a second measurement of the workspace waits, fails with a
// serialization error and runs again on a later snapshot: a higher
// usage_seq always measures a later snapshot. It is read-only from then on,
// bounded by usageStatementTimeout, scoped to the workspace with deleted
// numbers visible, and takes no lock on tenants or contract_workspaces: it
// never holds capture back. The parts must sum to tenants' totals read in
// the same snapshot (ErrUsageMismatch).
func (c *Contract) MeasureUsage(ctx context.Context, ws uuid.UUID) (UsageMeasure, error) {
	if _, err := c.pool.Exec(ctx, `INSERT INTO contract_usage_seq (workspace_id) VALUES ($1) ON CONFLICT DO NOTHING`, ws); err != nil {
		return UsageMeasure{}, err
	}
	var out UsageMeasure
	err := retrySerialization(ctx, func() error {
		out = UsageMeasure{Workspace: ws, Items: []UsageItemMeasure{}}
		return pgx.BeginTxFunc(ctx, c.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead}, func(tx pgx.Tx) error {
			if err := tx.QueryRow(ctx, `WITH now AS (SELECT clock_timestamp() AS t)
				UPDATE contract_usage_seq s SET usage_seq = greatest(`+clockMillisSQL+`, s.usage_seq + 1)
				FROM now WHERE s.workspace_id = $1 RETURNING s.usage_seq, now.t`, ws).Scan(&out.Seq, &out.MeasuredAt); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `SET TRANSACTION READ ONLY`); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `SET LOCAL statement_timeout = '`+usageStatementTimeout+`'`); err != nil {
				return err
			}
			if usageSeqTaken != nil {
				usageSeqTaken(tx)
			}
			return measureTx(ctx, tx, &out)
		})
	})
	return out, err
}

// measureTx reads out's workspace into out, in a REPEATABLE READ
// transaction that has read out.MeasuredAt.
func measureTx(ctx context.Context, tx pgx.Tx, out *UsageMeasure) error {
	if _, err := tx.Exec(ctx, `SELECT set_config($1, $2, true)`, pg.TenantGUC, out.Workspace.String()); err != nil {
		return err
	}
	var status string
	var archive, object int64
	var quota bool
	err := tx.QueryRow(ctx, `SELECT t.status, t.storage_archive_bytes, t.storage_object_bytes, `+snapshotQuotaSQL+`
		FROM tenants t WHERE t.id = $1`, out.Workspace).Scan(&status, &archive, &object, &quota)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	out.Local, out.Total = true, archive+object
	return withQuarantine(ctx, tx, func() error {
		type device struct {
			state   string
			purgeAt *time.Time
		}
		devices := map[uuid.UUID]device{}
		rows, err := tx.Query(ctx, `SELECT id, status, paused, coalesce(pause_cause, ''), deleted_at IS NOT NULL, purge_after
			FROM devices WHERE tenant_id = $1`, out.Workspace)
		if err != nil {
			return err
		}
		active := status == "active"
		if err := forEachRow(rows, func(row pgx.Rows) error {
			var id uuid.UUID
			var dstatus, cause string
			var paused, deleted bool
			var purge *time.Time
			if err := row.Scan(&id, &dstatus, &paused, &cause, &deleted, &purge); err != nil {
				return err
			}
			state, _ := snapshotState(deleted, paused, cause, dstatus, active, quota)
			d := device{state: state}
			if state == SnapshotDeleted {
				if purge == nil {
					return fmt.Errorf("store: deleted number %s has no purge date", id)
				}
				d.purgeAt = purge
			}
			devices[id] = d
			return nil
		}); err != nil {
			return err
		}
		rows, err = tx.Query(ctx, usageMeasureSQL, out.Workspace, kc.RecentFrom(out.MeasuredAt), out.MeasuredAt)
		if err != nil {
			return err
		}
		if err := forEachRow(rows, func(row pgx.Rows) error {
			var dev *uuid.UUID
			var it UsageItemMeasure
			var orphans int
			if err := row.Scan(&dev, &it.Bytes, &it.Recent, &it.Undated, &it.Fixed, &orphans); err != nil {
				return err
			}
			d, known := devices[ptrOr(dev)]
			if dev == nil || !known {
				// A row no number owns: shared, counted, never an item.
				out.Shared += it.Bytes
				out.Unattributed += max(orphans, 1)
				return nil
			}
			it.Device, it.State, it.PurgeAt = *dev, d.state, d.purgeAt
			if it.Bytes > 0 {
				out.Items = append(out.Items, it)
			}
			return nil
		}); err != nil {
			return err
		}
		var shared int64
		if err := tx.QueryRow(ctx, usageSharedSQL, out.Workspace).Scan(&shared); err != nil {
			return err
		}
		out.Shared += shared
		sum := out.Shared
		for _, it := range out.Items {
			sum += it.Bytes
		}
		if sum != out.Total {
			return ErrUsageMismatch
		}
		return nil
	})
}

func ptrOr(id *uuid.UUID) uuid.UUID {
	if id == nil {
		return uuid.Nil
	}
	return *id
}

// UsageRow is one recorded workspace's cadence, as the sender and the
// status read it.
type UsageRow struct {
	Workspace      uuid.UUID
	DueAt          *time.Time
	DueTrigger     string
	PctAfter       *time.Time
	Tries          int
	Error          string
	ErrorAt        *time.Time
	LastSeq        *int64
	LastMeasuredAt *time.Time
	LastSentAt     *time.Time
	LastKept       *bool
	// LastTotal is never logged.
	LastTotal     *int64
	LateAt        *time.Time
	LateTrigger   string
	StoppedSince  *time.Time
	NotFoundSince *time.Time
}

const usageRowColumns = `u.workspace_id, u.due_at, coalesce(u.due_trigger, ''), u.pct_after, u.tries, coalesce(u.error, ''), u.error_at,
	u.last_seq, u.last_measured_at, u.last_sent_at, u.last_kept, u.last_total_bytes, u.late_at, coalesce(u.late_trigger, ''),
	u.stopped_since, d.not_found_since`

func scanUsageRow(row pgx.CollectableRow) (UsageRow, error) {
	var r UsageRow
	err := row.Scan(&r.Workspace, &r.DueAt, &r.DueTrigger, &r.PctAfter, &r.Tries, &r.Error, &r.ErrorAt, &r.LastSeq,
		&r.LastMeasuredAt, &r.LastSentAt, &r.LastKept, &r.LastTotal, &r.LateAt, &r.LateTrigger, &r.StoppedSince, &r.NotFoundSince)
	return r, err
}

// UsageRows makes a cadence row, due now on the floor's trigger, for each
// recorded workspace that has none, in a short transaction of its own, and
// reads every row in id order.
func (c *Contract) UsageRows(ctx context.Context) ([]UsageRow, error) {
	if _, err := c.pool.Exec(ctx, `INSERT INTO contract_usage (workspace_id, due_at, due_trigger)
		SELECT workspace_id, clock_timestamp(), 'floor' FROM contract_workspaces ORDER BY workspace_id
		ON CONFLICT (workspace_id) DO NOTHING`); err != nil {
		return nil, err
	}
	rows, err := c.pool.Query(ctx, `SELECT `+usageRowColumns+` FROM contract_usage u
		LEFT JOIN contract_ent_docs d ON d.workspace_id = u.workspace_id ORDER BY u.workspace_id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanUsageRow)
}

// UsageDue lists the workspaces whose report is due by now, the earliest
// deadline's trigger first, then the oldest due.
func (c *Contract) UsageDue(ctx context.Context, limit int) ([]UsageRow, error) {
	rows, err := c.pool.Query(ctx, `SELECT `+usageRowColumns+` FROM contract_usage u
		LEFT JOIN contract_ent_docs d ON d.workspace_id = u.workspace_id
		WHERE u.due_at <= clock_timestamp()
		ORDER BY `+fmt.Sprintf(usageTriggerSQL, "u.due_trigger")+`, u.due_at, u.workspace_id LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanUsageRow)
}

// UsageMark makes ws's report due at at for trigger, unless it is due
// sooner already; a trigger of an earlier deadline replaces a later one's
// (a report due for the floor is upgraded, never queued twice).
func (c *Contract) UsageMark(ctx context.Context, ws uuid.UUID, trigger string, at time.Time) error {
	_, err := c.pool.Exec(ctx, `UPDATE contract_usage SET
		due_trigger = CASE WHEN due_at IS NULL OR `+fmt.Sprintf(usageTriggerSQL, "$2::text")+` < `+fmt.Sprintf(usageTriggerSQL, "due_trigger")+`
		                   THEN $2 ELSE due_trigger END,
		due_at = least(coalesce(due_at, $3), $3)
		WHERE workspace_id = $1`, ws, trigger, at)
	return err
}

// UsageSent records a report sent and answered (kept or not, both count
// as delivered), keeps its body, makes the next due on the floor (6 hours
// after measured_at), records a report sent past its trigger's deadline,
// and prunes every report kept past UsageKeep.
func (c *Contract) UsageSent(ctx context.Context, m UsageMeasure, body []byte, kept bool, floor, pct time.Duration, late string) error {
	return pg.InTx(ctx, c.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO contract_usage_reports (workspace_id, usage_seq, measured_at, body, sent_at)
			VALUES ($1, $2, $3, $4, clock_timestamp()) ON CONFLICT (workspace_id, usage_seq) DO UPDATE SET sent_at = excluded.sent_at`,
			m.Workspace, m.Seq, m.MeasuredAt, body); err != nil {
			return err
		}
		var lateTrigger *string
		if late != "" {
			lateTrigger = &late
		}
		if _, err := tx.Exec(ctx, `UPDATE contract_usage SET last_seq = $2, last_measured_at = $3, last_sent_at = clock_timestamp(),
			last_kept = $4, last_total_bytes = $5, tries = 0, error = NULL, error_at = NULL,
			pct_after = clock_timestamp() + $7::interval,
			due_trigger = CASE WHEN due_at > $3 THEN due_trigger ELSE 'floor' END,
			due_at = CASE WHEN due_at > $3 THEN least(due_at, $3 + $6::interval) ELSE $3 + $6::interval END,
			late_at = CASE WHEN $8::text IS NULL THEN late_at ELSE clock_timestamp() END,
			late_trigger = coalesce($8, late_trigger), stopped_since = NULL
			WHERE workspace_id = $1`, m.Workspace, m.Seq, m.MeasuredAt, kept, m.Total, floor, pct, lateTrigger); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM contract_usage_reports WHERE measured_at < clock_timestamp() - $1::interval`, UsageKeep)
		return err
	})
}

// UsageFailed records a report that got no answer, or was refused: its
// class, and when it is due again.
func (c *Contract) UsageFailed(ctx context.Context, ws uuid.UUID, class string, backoff time.Duration) error {
	_, err := c.pool.Exec(ctx, `UPDATE contract_usage SET tries = tries + 1, error = $2, error_at = coalesce(error_at, clock_timestamp()),
		due_at = clock_timestamp() + $3::interval WHERE workspace_id = $1`, ws, class, backoff)
	return err
}

// UsageStopped records that ws's reports stop: its GET answered
// not_found. No report is due until a document of it reaches the feed
// (UsageResumed).
func (c *Contract) UsageStopped(ctx context.Context, ws uuid.UUID) error {
	_, err := c.pool.Exec(ctx, `UPDATE contract_usage SET stopped_since = coalesce(stopped_since, clock_timestamp()), due_at = NULL
		WHERE workspace_id = $1`, ws)
	return err
}

// UsageResumed makes a stopped workspace's report due now, once a document
// of it reached the feed again.
func (c *Contract) UsageResumed(ctx context.Context, ws uuid.UUID) error {
	_, err := c.pool.Exec(ctx, `UPDATE contract_usage SET stopped_since = NULL, due_at = clock_timestamp(), due_trigger = 'event'
		WHERE workspace_id = $1 AND stopped_since IS NOT NULL`, ws)
	return err
}

// UsageEventsSince reports whether ws has a deletion, recovery, purge or
// move out written after since: a notice lost while no leader ran.
func (c *Contract) UsageEventsSince(ctx context.Context, ws uuid.UUID, since time.Time) (bool, error) {
	var found bool
	err := pg.InTenantTx(ctx, c.pool, ws.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM item_events WHERE tenant_id = $1 AND created_at > $2
			AND type IN ('deleted', 'recovered', 'purged', 'moved_out'))`, ws, since).Scan(&found)
	})
	return found, err
}

// EntGetDueNow makes ws's GET computed now due, as a report of a closed
// workspace, or of one no account document names, asks (the spec's 15.8).
func (c *Contract) EntGetDueNow(ctx context.Context, ws uuid.UUID) error {
	_, err := c.pool.Exec(ctx, `INSERT INTO contract_ent_docs AS d (workspace_id, get_due_at) VALUES ($1, clock_timestamp())
		ON CONFLICT (workspace_id) DO UPDATE SET get_due_at = least(coalesce(d.get_due_at, clock_timestamp()), clock_timestamp())
		WHERE d.not_found_since IS NULL`, ws)
	return err
}

// UsageReport is a report kept, as the status and the tests read it.
type UsageReport struct {
	Workspace  uuid.UUID
	Seq        int64
	MeasuredAt time.Time
	Body       []byte
}

// UsageReports lists the reports kept of ws, the latest first.
func (c *Contract) UsageReports(ctx context.Context, ws uuid.UUID) ([]UsageReport, error) {
	rows, err := c.pool.Query(ctx, `SELECT workspace_id, usage_seq, measured_at, body FROM contract_usage_reports
		WHERE workspace_id = $1 ORDER BY usage_seq DESC`, ws)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (UsageReport, error) {
		var r UsageReport
		err := row.Scan(&r.Workspace, &r.Seq, &r.MeasuredAt, &r.Body)
		return r, err
	})
}
