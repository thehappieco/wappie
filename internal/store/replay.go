package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/ledger"
	"whatserver2/internal/pg"
)

// A restore puts back a database older than what happened since: numbers
// deleted, recovered, purged and moved after the snapshot. The replay
// (decision 0038's plan, section 9) brings it level with the deletion
// ledger before wappie-api starts, so no number deleted in the meantime is
// readable again, none recovered is purged by the first janitor pass, and
// none that moved to Personal is back in its team.
//
// It folds the whole ledger first, per number and by cause, and decides
// nothing by whether an event is in the restored database: event rows live
// 30 days and backups up to 90. It looks for each number in every
// workspace, since a move changes a number's. It has its own path, not
// Quarantine's or Recover's: no owner, no role, no readers to acknowledge,
// no window and no capacity check, and the ledger's own dates. It applies
// every exclusion and purge before any recovery, workspace by workspace in
// one transaction each: a recovery may need the phone number another
// number's re-exclusion frees. Each change writes its event row with the
// ledger line's own event id, already ledgered and marked replayed, never
// to be sent. It sends no notice and purges nothing itself: a number the
// ledger says was purged is left due, and the first janitor pass purges it.

var (
	// ErrReplayRefused is a replay that did not finish: its report says
	// why, and wappie-api must not start until it does.
	ErrReplayRefused = errors.New("store: the replay did not finish; read its report")
	// ErrLedgerAddsNothing is a ledger with nothing newer than the restored
	// database: most likely the snapshot's own copy, put back instead of a
	// newer one.
	ErrLedgerAddsNothing = errors.New("store: the ledger holds nothing newer than the restored database")
	// errReplayDryRun rolls back a dry run's transaction once its steps ran.
	errReplayDryRun = errors.New("store: a dry run changes nothing")
)

// ReplayOptions changes what ReplayLedger does.
type ReplayOptions struct {
	// DryRun runs every step, reports what it changed and what refused, and
	// rolls each workspace's transaction back.
	DryRun bool
	// SnapshotTime is the restored snapshot's stamp.
	SnapshotTime time.Time
	// LedgerAddsNothing goes on with a ledger that holds nothing newer than
	// the snapshot and the restored database's own events.
	LedgerAddsNothing bool
	// LeaveExcluded are numbers found in another workspace than their
	// ledger says (a snapshot from before a move): each is excluded where
	// it is, with the ledger's dates, or now and 30 days on for a number
	// that only moved, and left due when the ledger says it was purged.
	LeaveExcluded []uuid.UUID
}

// What a replay did to a number.
const (
	ReplayExcluded     = "excluded"
	ReplayPurgeDue     = "purge_due"
	ReplayRecovered    = "recovered"
	ReplayLeftExcluded = "left_excluded"
)

// ReplayChange is one number the replay changed, or would.
type ReplayChange struct {
	DeviceID, Workspace   uuid.UUID
	Action                string
	DeletedAt, PurgeAfter time.Time
}

// ReplayReport is what a replay found and did.
type ReplayReport struct {
	// LedgerNewest is the ledger's newest line; RestoredNewest the later
	// of the snapshot's stamp and the restored database's newest ledgered
	// event.
	LedgerNewest, RestoredNewest time.Time
	Changes                      []ReplayChange
	// Unchanged counts numbers already as the ledger says.
	Unchanged int
	// Missing are numbers in no workspace: skipped.
	Missing []uuid.UUID
	// Kept are excluded numbers whose deletion the ledger does not have,
	// though it has later lines of theirs: kept excluded, as the restored
	// database has them.
	Kept []uuid.UUID
	// Refusals say why the replay did not finish.
	Refusals []string
	// OverCapacity are workspaces a recovery left over their plan.
	OverCapacity []uuid.UUID
}

type replayRow struct {
	tenant       uuid.UUID
	deletedAt    *time.Time
	purgeStarted bool
}

type replayStep struct {
	device ledger.Device
	row    replayRow
	action string
	// reversal is the recovery a recovered number's event row takes.
	reversal ledger.Reversal
	// onlyMoved is a number left excluded that the ledger never deleted.
	onlyMoved bool
}

// ReplayLedger replays lines (ledger.Read's, deduplicated) over the
// restored database.
func ReplayLedger(ctx context.Context, pool *pgxpool.Pool, lines []ledger.Line, opts ReplayOptions) (ReplayReport, error) {
	var out ReplayReport
	devices, problems := ledger.Fold(lines)
	for _, p := range problems {
		out.Refusals = append(out.Refusals, p.String())
	}
	// A deletion's window is 30 days on the database's clock, as the
	// deletion wrote it: a damaged but parseable line would otherwise
	// purge a live number at the first janitor pass. A purge may be
	// earlier (an operator's --now, an account's closing).
	var deletedAt, purgeAfter []time.Time
	var deletedIDs []uuid.UUID
	for _, l := range lines {
		if l.Type == ledger.TypeDeleted {
			deletedAt, purgeAfter, deletedIDs = append(deletedAt, *l.DeletedAt), append(purgeAfter, *l.PurgeAfter), append(deletedIDs, l.EventID)
		}
		if l.OccurredAt.After(out.LedgerNewest) {
			out.LedgerNewest = l.OccurredAt
		}
	}
	if len(deletedAt) > 0 {
		var bad []int64
		if err := pool.QueryRow(ctx, `SELECT coalesce(array_agg(i ORDER BY i), '{}') FROM unnest($1::timestamptz[], $2::timestamptz[]) WITH ORDINALITY AS x(d, p, i)
			WHERE d + interval '30 days' <> p`, deletedAt, purgeAfter).Scan(&bad); err != nil {
			return out, err
		}
		for _, i := range bad {
			out.Refusals = append(out.Refusals, fmt.Sprintf("deleted line %s: its purge_after is not its deleted_at plus 30 days", deletedIDs[i-1]))
		}
	}
	if len(out.Refusals) > 0 {
		return out, ErrReplayRefused
	}

	restored, err := NewestLedgeredEvent(ctx, pool)
	if err != nil {
		return out, err
	}
	out.RestoredNewest = restored
	if opts.SnapshotTime.After(out.RestoredNewest) {
		out.RestoredNewest = opts.SnapshotTime
	}
	if !out.LedgerNewest.After(out.RestoredNewest) && !opts.LedgerAddsNothing {
		return out, ErrLedgerAddsNothing
	}

	// Where each number is now, in every workspace.
	tenants, err := allTenantIDs(ctx, pool)
	if err != nil {
		return out, err
	}
	ids := make([]uuid.UUID, len(devices))
	for i, d := range devices {
		ids[i] = d.DeviceID
	}
	found := map[uuid.UUID]replayRow{}
	for _, tenant := range tenants {
		err := pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SET LOCAL transaction_read_only = on`); err != nil {
				return err
			}
			return withQuarantine(ctx, tx, func() error {
				rows, err := tx.Query(ctx, `SELECT id, deleted_at, purge_started_at IS NOT NULL FROM devices WHERE id = ANY($1)`, ids)
				if err != nil {
					return err
				}
				defer rows.Close()
				for rows.Next() {
					var id uuid.UUID
					r := replayRow{tenant: tenant}
					if err := rows.Scan(&id, &r.deletedAt, &r.purgeStarted); err != nil {
						return err
					}
					found[id] = r
				}
				return rows.Err()
			})
		})
		if err != nil {
			return out, err
		}
	}

	// What each number needs.
	byTenant := map[uuid.UUID][]replayStep{}
	for _, d := range devices {
		row, ok := found[d.DeviceID]
		if !ok {
			out.Missing = append(out.Missing, d.DeviceID)
			continue
		}
		step := replayStep{device: d, row: row}
		switch {
		case row.tenant != d.Workspace:
			if !slices.Contains(opts.LeaveExcluded, d.DeviceID) {
				out.Refusals = append(out.Refusals, fmt.Sprintf("number %s is in workspace %s, and its ledger puts it in %s (a snapshot from before a move): "+
					"pass --leave-excluded %s to exclude it where it is, or move it by hand after the replay", d.DeviceID, row.tenant, d.Workspace, d.DeviceID))
				continue
			}
			step.action, step.onlyMoved = ReplayLeftExcluded, d.State == ledger.StateLive
			if d.State == ledger.StateExcluded && row.deletedAt != nil && row.deletedAt.Equal(d.DeletedAt) {
				out.Unchanged++
				continue
			}
			if step.onlyMoved && row.deletedAt != nil {
				out.Unchanged++
				continue
			}
		case d.State == ledger.StatePurged:
			step.action = ReplayPurgeDue
		case d.State == ledger.StateExcluded:
			if row.deletedAt != nil && row.deletedAt.Equal(d.DeletedAt) {
				out.Unchanged++
				continue
			}
			step.action = ReplayExcluded
		default: // live
			if row.deletedAt == nil {
				out.Unchanged++
				continue
			}
			i := slices.IndexFunc(d.Reversed, func(r ledger.Reversal) bool { return r.DeletedAt.Equal(*row.deletedAt) })
			if i < 0 {
				out.Kept = append(out.Kept, d.DeviceID)
				continue
			}
			// A started purge has deleted rows already: recovering it would
			// bring the number back with part of its archive gone, which
			// Recover never allows either. Only a damaged ledger pairs the
			// two.
			if row.purgeStarted {
				out.Refusals = append(out.Refusals, fmt.Sprintf("number %s: its purge had started in the restored database, "+
					"and the ledger says its deletion was recovered; it cannot be recovered", d.DeviceID))
				continue
			}
			step.action, step.reversal = ReplayRecovered, d.Reversed[i]
		}
		byTenant[row.tenant] = append(byTenant[row.tenant], step)
	}
	if len(out.Refusals) > 0 {
		return out, ErrReplayRefused
	}

	order := make([]uuid.UUID, 0, len(byTenant))
	for tenant := range byTenant {
		order = append(order, tenant)
	}
	sort.Slice(order, func(i, j int) bool { return order[i].String() < order[j].String() })
	for _, tenant := range order {
		steps := byTenant[tenant]
		// Exclusions and purges first, recoveries after: a recovery may
		// need the identity another number's exclusion frees.
		sort.SliceStable(steps, func(i, j int) bool {
			return steps[i].action != ReplayRecovered && steps[j].action == ReplayRecovered
		})
		// A dry run runs the same steps in the same transaction and rolls
		// it back, so it meets every refusal the real replay would.
		var changes []ReplayChange
		over := false
		err := pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SELECT 1 FROM tenants WHERE id = $1 FOR UPDATE`, tenant); err != nil {
				return err
			}
			err := withQuarantine(ctx, tx, func() error {
				recovered := false
				for _, s := range steps {
					c, err := replayStepTx(ctx, tx, tenant, s)
					if err != nil {
						return err
					}
					changes = append(changes, c)
					recovered = recovered || s.action == ReplayRecovered
				}
				if !recovered {
					return nil
				}
				var capacity *int64
				var used int64
				if err := tx.QueryRow(ctx, `SELECT (SELECT max_devices FROM workspace_capacity WHERE tenant_id = $1), workspace_device_usage($1)`,
					tenant).Scan(&capacity, &used); err != nil {
					return err
				}
				over = capacity != nil && used > *capacity
				return nil
			})
			if err == nil && opts.DryRun {
				return errReplayDryRun
			}
			return err
		})
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			out.Refusals = append(out.Refusals, fmt.Sprintf("workspace %s: a recovered number's phone is linked again as another number there (%s); "+
				"nothing in that workspace was replayed", tenant, pgErr.ConstraintName))
			continue
		}
		if err != nil && !errors.Is(err, errReplayDryRun) {
			return out, fmt.Errorf("store: replay in workspace %s: %w", tenant, err)
		}
		out.Changes = append(out.Changes, changes...)
		if over {
			out.OverCapacity = append(out.OverCapacity, tenant)
		}
	}
	if len(out.Refusals) > 0 {
		return out, ErrReplayRefused
	}
	return out, nil
}

// replayStepTx applies one step, in the workspace of tx, with excluded
// numbers visible.
func replayStepTx(ctx context.Context, tx pgx.Tx, tenant uuid.UUID, s replayStep) (ReplayChange, error) {
	d := s.device
	change := ReplayChange{DeviceID: d.DeviceID, Workspace: tenant, Action: s.action}
	if s.action == ReplayRecovered {
		var name, pushName, pn string
		// Paused as the owner's recovery leaves a number: theirs.
		err := tx.QueryRow(ctx, `UPDATE devices SET deleted_at = NULL, deleted_by = NULL, purge_after = NULL, wa_leftover = NULL,
			pause_cause = 'person'
			WHERE id = $1 AND deleted_at = $2 AND purge_started_at IS NULL RETURNING label, push_name, coalesce(pn, '')`,
			d.DeviceID, s.reversal.DeletedAt).Scan(&name, &pushName, &pn)
		if errors.Is(err, pgx.ErrNoRows) {
			return change, fmt.Errorf("number %s changed during the replay, or its purge started: it was not recovered", d.DeviceID)
		}
		if err != nil {
			return change, err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM device_notices WHERE device_id = $1 AND kind = 'number_deleted'`, d.DeviceID); err != nil {
			return change, err
		}
		if err := recoveredStrandedTx(ctx, tx, d.DeviceID); err != nil {
			return change, err
		}
		at := s.reversal.DeletedAt
		change.DeletedAt = at
		return change, recordEvent(ctx, tx, tenant, itemEvent{EventID: s.reversal.EventID, Replayed: true,
			Type: eventRecovered, ItemID: d.DeviceID, DedupeKey: dedupeKey(eventRecovered, d.DeviceID, at),
			OccurredAt: s.reversal.OccurredAt, ActorKind: actorPerson, DeletedAt: &at})
	}

	deletedAt, purgeAfter := d.DeletedAt, d.PurgeAfter
	if s.onlyMoved {
		if err := tx.QueryRow(ctx, `SELECT t, t + interval '30 days' FROM (SELECT clock_timestamp() AS t) now`).Scan(&deletedAt, &purgeAfter); err != nil {
			return change, err
		}
	}
	purge := d.State == ledger.StatePurged
	same := s.row.deletedAt != nil && s.row.deletedAt.Equal(deletedAt)
	// The fingerprint of the session the restore brought back, as
	// Quarantine takes it: only for a number restored live, whose session
	// is the one under its JID. A number restored excluded keeps the
	// fingerprint its deletion took. Once that logout was confirmed, or
	// when there was no session, whatever holds its JID now is a phone
	// linked again, perhaps in another workspace, which the purge must
	// never delete.
	var session *WASession
	present, err := sessionTableTx(ctx, tx)
	if err != nil {
		return change, err
	}
	if present && s.row.deletedAt == nil {
		var w WASession
		err := tx.QueryRow(ctx, `SELECT w.jid, w.registration_id FROM whatsmeow_device w JOIN devices d ON d.pn = w.jid WHERE d.id = $1`,
			d.DeviceID).Scan(&w.JID, &w.RegistrationID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return change, err
		}
		if err == nil {
			session = &w
		}
	}
	var jid *string
	var reg *int64
	if session != nil {
		jid, reg = &session.JID, &session.RegistrationID
	}
	if same {
		// Already excluded by this deletion: a purge only makes it due, and
		// its fingerprint stays the deletion's.
		err = tx.QueryRow(ctx, `UPDATE devices SET purge_after = least(purge_after, $2, clock_timestamp())
			WHERE id = $1 RETURNING deleted_at, purge_after`, d.DeviceID, purgeAfter).Scan(&change.DeletedAt, &change.PurgeAfter)
		if err != nil {
			return change, err
		}
	} else {
		// As a deletion excludes it: off every key restricted to it, its
		// assistants ended, paused, its dead status kept, and the
		// fingerprint above, which the purge removes; a number excluded by
		// another deletion keeps its own. No notice: nobody is told twice.
		rows, err := tx.Query(ctx, `SELECT DISTINCT c.id FROM mcp_connections c
			JOIN api_key_devices x ON x.api_key_id = c.api_key_id AND x.device_id = $2
			WHERE c.tenant_id = $1 AND c.status IN ('pending', 'active', 'reseal')`, tenant, d.DeviceID)
		if err != nil {
			return change, err
		}
		connections, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			return change, err
		}
		for _, c := range connections {
			if _, err := endMCPConnectionTx(ctx, tx, tenant, c.String(), statusRevoked, ReasonAccessLost); err != nil {
				return change, err
			}
		}
		if _, err := tx.Exec(ctx, `DELETE FROM api_key_devices WHERE device_id = $1`, d.DeviceID); err != nil {
			return change, err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM device_notices WHERE device_id = $1 AND kind = 'sync_paused'`, d.DeviceID); err != nil {
			return change, err
		}
		err = tx.QueryRow(ctx, `UPDATE devices SET deleted_at = $2,
			purge_after = CASE WHEN $4 THEN least($3, clock_timestamp()) ELSE $3 END,
			deleted_by = (SELECT id FROM users WHERE id = $5), paused = true, pause_cause = 'deletion',
			status = CASE WHEN status IN ('logged_out', 'banned') THEN status ELSE 'offline' END,
			status_reason = CASE WHEN status IN ('logged_out', 'banned') THEN status_reason ELSE '`+reasonDeleted+`' END,
			wa_leftover = CASE WHEN deleted_at IS NOT NULL THEN wa_leftover
			                   WHEN $6::text IS NULL THEN NULL ELSE jsonb_build_object('jid', $6::text, 'registration_id', $7::bigint) END
			WHERE id = $1 RETURNING deleted_at, purge_after`, d.DeviceID, deletedAt, purgeAfter, purge, d.DeletedBy, jid, reg).
			Scan(&change.DeletedAt, &change.PurgeAfter)
		if err != nil {
			return change, err
		}
	}
	if s.onlyMoved {
		// No line to mirror: the exclusion is the restore's own.
		return change, nil
	}
	if !same && d.State == ledger.StateExcluded {
		var actor *uuid.UUID
		if d.DeletedBy != nil {
			if err := tx.QueryRow(ctx, `SELECT id FROM users WHERE id = $1`, *d.DeletedBy).Scan(&actor); err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return change, err
			}
		}
		if err := recordEvent(ctx, tx, tenant, itemEvent{EventID: d.EventID, Replayed: true,
			Type: eventDeleted, ItemID: d.DeviceID, DedupeKey: dedupeKey(eventDeleted, d.DeviceID, d.DeletedAt),
			OccurredAt: d.OccurredAt, ActorKind: actorPerson, ActorUserID: actor, DeletedAt: &d.DeletedAt, PurgeAfter: &d.PurgeAfter}); err != nil {
			return change, err
		}
	}
	if purge {
		// The purge's row goes in now, so the janitor's purge of the number
		// finds it by its dedupe key and writes no second one.
		if err := recordEvent(ctx, tx, tenant, itemEvent{EventID: d.EventID, Replayed: true,
			Type: eventPurged, ItemID: d.DeviceID, DedupeKey: dedupeKey(eventPurged, d.DeviceID, d.DeletedAt),
			OccurredAt: d.OccurredAt, ActorKind: actorApp, DeletedAt: &d.DeletedAt, PurgeAfter: &d.PurgeAfter}); err != nil {
			return change, err
		}
	}
	return change, nil
}

// String is the report as the operator reads it.
func (r ReplayReport) String() string {
	var b strings.Builder
	stamp := func(t time.Time) string {
		if t.IsZero() {
			return "none"
		}
		return t.UTC().Format(time.RFC3339)
	}
	fmt.Fprintf(&b, "ledger's newest line      %s\nrestored database's newest %s\n", stamp(r.LedgerNewest), stamp(r.RestoredNewest))
	for _, c := range r.Changes {
		fmt.Fprintf(&b, "%-14s %s in %s", c.Action, c.DeviceID, c.Workspace)
		if !c.DeletedAt.IsZero() {
			fmt.Fprintf(&b, " deleted %s", stamp(c.DeletedAt))
		}
		if !c.PurgeAfter.IsZero() {
			fmt.Fprintf(&b, " purge after %s", stamp(c.PurgeAfter))
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "unchanged %d\n", r.Unchanged)
	for _, id := range r.Missing {
		fmt.Fprintf(&b, "missing   %s: in no workspace, skipped\n", id)
	}
	for _, id := range r.Kept {
		fmt.Fprintf(&b, "kept      %s: excluded by a deletion the ledger does not have; kept excluded\n", id)
	}
	for _, id := range r.OverCapacity {
		fmt.Fprintf(&b, "capacity  workspace %s is over its plan after the recoveries\n", id)
	}
	for _, reason := range r.Refusals {
		fmt.Fprintf(&b, "REFUSED   %s\n", reason)
	}
	return b.String()
}
