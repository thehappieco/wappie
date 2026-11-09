package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"whatserver2/internal/obs"
	"whatserver2/internal/pg"
)

// The settings sections Wappie sends of each platform workspace (0052's
// contract_sections; the plan's 2.5, 2.6 and 3.5): the numbers read model,
// measured in its own transaction after it takes its seq, and the sender's
// state on each section (its last state_seq, due time, backoff, not_found
// run and park), as the snapshot's (contract_snapshot.go).
//
// The workspace's one clock has two columns: snapshot_seq (the snapshot's)
// and sections_seq (the sections' and the acts'). Each takes the greatest
// of the clock in milliseconds and both columns plus one, under the
// record's row lock, so the two documents rise on one clock and a section
// never moves the seq a snapshot in flight compares its outcome with
// (DS3).

// The sections of 12a and the names 0052 already allows.
const (
	SectionNumbers = "numbers"
)

// The bounds of a numbers section (S 14.3): a list that does not fit is
// sent empty with truncated, never cut.
const (
	NumbersMaxPending = 50
	NumbersMaxItems   = 1000
)

// SectionNotFoundFor is how long a section is retried after the platform
// first answered not_found, before it is parked (as SnapshotNotFoundFor).
const SectionNotFoundFor = 24 * time.Hour

// ContractPending is a registration not linked yet: no identity, never
// connected, not deleted.
type ContractPending struct {
	ID        uuid.UUID
	CreatedAt time.Time
	Paused    bool
	Epoch     int
}

// ContractNumber is one number of a numbers section: a number with a known
// identity or a past connection, deleted ones until their purge, in
// Wappie's terms. It carries no label (S 14.3: a number's label lives in
// the snapshot).
type ContractNumber struct {
	ID uuid.UUID
	// Status is devices.status; LogoutCause phone or deletion while it is
	// logged_out; PauseCause person, move or deletion while paused.
	Status, LogoutCause, PauseCause string
	Deleted, Paused                 bool
	// Known: its identity (a LID or a phone number) is known.
	Known bool
	// RecoveryOpen: deleted, its purge date ahead and not started.
	RecoveryOpen    bool
	LastConnectedAt *time.Time
	// PausedAt and PausedByKind (person, key or app) are what 0052's
	// columns know of the pause, nil and "" when not known; PausedBySub is
	// the sub of the person, or of a key's creator, nil for none.
	PausedAt     *time.Time
	PausedByKind string
	PausedBySub  *uuid.UUID
	Epoch        int
}

// ContractNumbers is what Wappie's own tables say of one platform
// workspace's numbers section, measured in the transaction that gave it
// Seq.
type ContractNumbers struct {
	Workspace uuid.UUID
	// Seq is the section's state_seq; SnapshotSeq the workspace's last
	// snapshot_seq (at least 1).
	Seq, SnapshotSeq int64
	MeasuredAt       time.Time
	// Local: Wappie has a workspace of this id. Without one the section is
	// empty.
	Local bool
	// CanLink: a number can be linked now (the workspace active, below its
	// capacity as check_device_capacity counts it, and not stopped by its
	// storage); StoragePaused is the snapshot's quota verdict.
	CanLink, StoragePaused bool
	Pending                []ContractPending
	Items                  []ContractNumber
	// PendingOver and ItemsOver: the list is past its bound (more than
	// NumbersMaxPending or NumbersMaxItems), and goes empty with
	// truncated; the list read is cut at the bound.
	PendingOver, ItemsOver bool
}

// Over reports whether a list of the section does not fit.
func (n ContractNumbers) Over() bool { return n.PendingOver || n.ItemsOver }

// numbersSeqTaken, nil but in a test, runs while NumbersOf holds the
// record with its seq taken.
var numbersSeqTaken func()

// clockMillisSQL is the database's clock in milliseconds, read once as
// now.t: the seq a document or an act takes (with sections_seq and
// snapshot_seq plus one).
const clockMillisSQL = `floor(extract(epoch FROM now.t) * 1000)::bigint`

// NumbersOf reads workspace's numbers section in one REPEATABLE READ
// transaction whose first statement takes its seq under the record's lock
// (the plan's 3.5): an act holding the record makes it wait, and it then
// fails with a serialization error and runs again, with a snapshot that
// sees the act at a higher seq; an act that comes after it waits for it and
// takes a higher seq. So a document at or above a result's seq shows it.
// The section's state_seq is set in the same transaction. False when the
// section is parked, or no snapshot of the workspace has a seq yet (the
// section names one).
//
// CanLink is read before the quarantine scope, as check_device_capacity
// counts (a deleted number takes no place); the items with deleted numbers
// visible, by the snapshot's predicate (a number with a known identity or a
// past connection); the pending registrations, newest first.
func (c *Contract) NumbersOf(ctx context.Context, workspace uuid.UUID) (ContractNumbers, bool, error) {
	var out ContractNumbers
	var ok bool
	err := retrySerialization(ctx, func() error {
		out, ok = ContractNumbers{Workspace: workspace, Pending: []ContractPending{}, Items: []ContractNumber{}}, false
		return pgx.BeginTxFunc(ctx, c.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead}, func(tx pgx.Tx) error {
			err := tx.QueryRow(ctx, `WITH now AS (SELECT clock_timestamp() AS t)
				UPDATE contract_workspaces w SET sections_seq = greatest(`+clockMillisSQL+`, w.sections_seq + 1, w.snapshot_seq + 1)
				FROM now WHERE w.workspace_id = $1 AND w.snapshot_seq > 0
				  AND NOT EXISTS (SELECT 1 FROM contract_sections s WHERE s.workspace_id = $1 AND s.section = 'numbers' AND s.parked_at IS NOT NULL)
				RETURNING w.sections_seq, w.snapshot_seq, now.t`, workspace).Scan(&out.Seq, &out.SnapshotSeq, &out.MeasuredAt)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO contract_sections (workspace_id, section, state_seq) VALUES ($1, 'numbers', $2)
				ON CONFLICT (workspace_id, section) DO UPDATE SET state_seq = excluded.state_seq`, workspace, out.Seq); err != nil {
				return err
			}
			if numbersSeqTaken != nil {
				numbersSeqTaken()
			}
			ok = true
			if _, err := tx.Exec(ctx, `SELECT set_config($1, $2, true)`, pg.TenantGUC, workspace.String()); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, `SELECT t.id IS NOT NULL, `+snapshotQuotaSQL+`,
					coalesce(t.status = 'active' AND (cap.max_devices IS NULL OR workspace_device_usage(t.id) < cap.max_devices), false)
				FROM (SELECT $1::uuid AS id) w LEFT JOIN tenants t ON t.id = w.id LEFT JOIN workspace_capacity cap ON cap.tenant_id = t.id`,
				workspace).Scan(&out.Local, &out.StoragePaused, &out.CanLink); err != nil {
				return err
			}
			out.CanLink = out.CanLink && !out.StoragePaused
			if !out.Local {
				return nil
			}
			rows, err := tx.Query(ctx, `SELECT id, created_at, paused, current_epoch FROM devices
				WHERE tenant_id = $1 AND lid IS NULL AND pn IS NULL AND last_connected_at IS NULL AND deleted_at IS NULL
				ORDER BY created_at DESC, id LIMIT $2`, workspace, NumbersMaxPending+1)
			if err != nil {
				return err
			}
			if err := forEachRow(rows, func(row pgx.Rows) error {
				var p ContractPending
				if err := row.Scan(&p.ID, &p.CreatedAt, &p.Paused, &p.Epoch); err != nil {
					return err
				}
				out.Pending = append(out.Pending, p)
				return nil
			}); err != nil {
				return err
			}
			if len(out.Pending) > NumbersMaxPending {
				out.Pending, out.PendingOver = out.Pending[:NumbersMaxPending], true
			}
			return withQuarantine(ctx, tx, func() error {
				return numbersItemsTx(ctx, tx, workspace, &out)
			})
		})
	})
	return out, ok, err
}

// numbersItemsTx fills out's items, read in tx with deleted numbers
// visible. The predicate is the snapshot's (snapshotItemsTx), so a row and
// the snapshot's item join by id.
func numbersItemsTx(ctx context.Context, tx pgx.Tx, workspace uuid.UUID, out *ContractNumbers) error {
	rows, err := tx.Query(ctx, `SELECT d.id, d.status, coalesce(d.logout_cause, ''), coalesce(d.pause_cause, ''),
			d.deleted_at IS NOT NULL, d.paused, d.lid IS NOT NULL OR d.pn IS NOT NULL,
			coalesce(d.deleted_at IS NOT NULL AND d.purge_after > clock_timestamp() AND d.purge_started_at IS NULL, false),
			d.last_connected_at, d.paused_at, coalesce(d.paused_by_kind, ''),
			CASE WHEN d.paused_by_kind IN ('person', 'key') THEN pi.sub END, d.current_epoch
		FROM devices d LEFT JOIN platform_identities pi ON pi.user_id = d.paused_by_user
		WHERE d.tenant_id = $1 AND (d.lid IS NOT NULL OR d.pn IS NOT NULL OR d.last_connected_at IS NOT NULL)
		ORDER BY d.id LIMIT $2`, workspace, NumbersMaxItems+1)
	if err != nil {
		return err
	}
	err = forEachRow(rows, func(row pgx.Rows) error {
		var n ContractNumber
		if err := row.Scan(&n.ID, &n.Status, &n.LogoutCause, &n.PauseCause, &n.Deleted, &n.Paused, &n.Known, &n.RecoveryOpen,
			&n.LastConnectedAt, &n.PausedAt, &n.PausedByKind, &n.PausedBySub, &n.Epoch); err != nil {
			return err
		}
		out.Items = append(out.Items, n)
		return nil
	})
	if len(out.Items) > NumbersMaxItems {
		out.Items, out.ItemsOver = out.Items[:NumbersMaxItems], true
	}
	return err
}

// actSeqTx is the first statement of every workspace act (the plan's 3.5):
// the record locked, and the act's seq, the workspace's next on its one
// clock. ErrNotFound for a workspace that is not recorded.
func actSeqTx(ctx context.Context, tx pgx.Tx, workspace uuid.UUID) (int64, error) {
	var seq int64
	err := tx.QueryRow(ctx, `WITH now AS (SELECT clock_timestamp() AS t)
		UPDATE contract_workspaces w SET sections_seq = greatest(`+clockMillisSQL+`, w.sections_seq + 1, w.snapshot_seq + 1)
		FROM now WHERE w.workspace_id = $1 RETURNING w.sections_seq`, workspace).Scan(&seq)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNotFound
	}
	return seq, err
}

// sectionsDueNowTx makes the workspace's sections due now, in an act's
// transaction after its writes (3.4: the sections come last but the
// persons): 0052's trigger wakes the leader's sender at once, whichever
// process acted. With none named, the numbers section.
func sectionsDueNowTx(ctx context.Context, tx pgx.Tx, workspace uuid.UUID, sections ...string) error {
	if len(sections) == 0 {
		sections = []string{SectionNumbers}
	}
	_, err := tx.Exec(ctx, `INSERT INTO contract_sections (workspace_id, section) SELECT $1, s FROM unnest($2::text[]) AS s ORDER BY s
		ON CONFLICT (workspace_id, section) DO UPDATE SET due_at = clock_timestamp()`, workspace, sections)
	return err
}

// snapshotDueNowTx makes the workspace's snapshot due now, in an act's
// transaction that holds its record: 0051's contract_due_sooner wakes the
// snapshot sender at once.
func snapshotDueNowTx(ctx context.Context, tx pgx.Tx, workspace uuid.UUID) error {
	_, err := tx.Exec(ctx, `UPDATE contract_workspaces SET snapshot_due_at = clock_timestamp() WHERE workspace_id = $1`, workspace)
	return err
}

// ContractSectionDue is the section due first, as the sender reads it.
type ContractSectionDue struct {
	Workspace uuid.UUID
	Section   string
	// Seq is its last state_seq: what an outcome recorded before a new one
	// is given names.
	Seq   int64
	DueAt time.Time
	Due   bool
	Wait  time.Duration
}

// NextSection reads the section due first, of those not parked whose
// workspace's snapshot has a seq (a section names one); false when none
// is.
func (c *Contract) NextSection(ctx context.Context) (ContractSectionDue, bool, error) {
	var d ContractSectionDue
	var now time.Time
	err := c.pool.QueryRow(ctx, `SELECT s.workspace_id, s.section, s.state_seq, s.due_at, clock_timestamp()
		FROM contract_sections s JOIN contract_workspaces w ON w.workspace_id = s.workspace_id
		WHERE s.parked_at IS NULL AND w.snapshot_seq > 0 ORDER BY s.due_at, s.workspace_id, s.section LIMIT 1`).
		Scan(&d.Workspace, &d.Section, &d.Seq, &d.DueAt, &now)
	if errors.Is(err, pgx.ErrNoRows) {
		return ContractSectionDue{}, false, nil
	}
	if err != nil {
		return ContractSectionDue{}, false, err
	}
	d.Due = !d.DueAt.After(now)
	d.Wait = max(d.DueAt.Sub(now), 0)
	return d, true, nil
}

// lockSectionsSQL selects the sections of which where holds, locked in key
// order, as lockWorkspacesSQL does for the records.
func lockSectionsSQL(where string) string {
	return `SELECT workspace_id, section FROM contract_sections WHERE ` + where + ` ORDER BY workspace_id, section FOR UPDATE`
}

// SectionsDue makes every recorded workspace's numbers section due now, a
// parked one's included, for one try (its not_found_since stays): what a
// leader's start does, as SnapshotsDue. A recorded workspace with no
// numbers row gets one first (the trigger's backstop).
func (c *Contract) SectionsDue(ctx context.Context) error {
	return retryDeadlock(ctx, func() error {
		return pg.InTx(ctx, c.pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `INSERT INTO contract_sections (workspace_id, section)
				SELECT workspace_id, 'numbers' FROM contract_workspaces ORDER BY workspace_id ON CONFLICT DO NOTHING`); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `UPDATE contract_sections s SET due_at = clock_timestamp(), parked_at = NULL
				FROM (`+lockSectionsSQL(`true`)+`) l WHERE s.workspace_id = l.workspace_id AND s.section = l.section`)
			return err
		})
	})
}

// SectionsDirty makes the sections of the workspaces ids (or of every
// recorded workspace, with all) due within debounce: a change they show
// was committed. A section due sooner stays due then; one backing off
// keeps its backoff, and a parked one its park.
func (c *Contract) SectionsDirty(ctx context.Context, ids []uuid.UUID, all bool, debounce time.Duration) error {
	if len(ids) == 0 && !all {
		return nil
	}
	return retryDeadlock(ctx, func() error {
		_, err := c.pool.Exec(ctx, `UPDATE contract_sections s SET due_at = clock_timestamp() + $3::interval
			FROM (`+lockSectionsSQL(`($1 OR workspace_id = ANY ($2)) AND parked_at IS NULL AND tries = 0
				AND due_at > clock_timestamp() + $3::interval`)+`) l
			WHERE s.workspace_id = l.workspace_id AND s.section = l.section`, all, ids, debounce)
		return err
	})
}

// SectionsRecovered makes every section that is backing off, and not
// parked, due now with its tries forgotten, and returns how many: the
// platform answers again after an outage (the command feed's first page),
// as Recovered does for the snapshots and the event queues, so no section
// waits out a backoff of up to an hour. A not_found run and the last
// failure's class stay, so a section refused locally logs no new ERROR.
// It locks only the sections, in key order, as SectionsDirty.
func (c *Contract) SectionsRecovered(ctx context.Context) (int64, error) {
	var n int64
	err := retryDeadlock(ctx, func() error {
		tag, err := c.pool.Exec(ctx, `UPDATE contract_sections s SET due_at = clock_timestamp(), tries = 0
			FROM (`+lockSectionsSQL(`tries > 0 AND parked_at IS NULL`)+`) l
			WHERE s.workspace_id = l.workspace_id AND s.section = l.section`)
		n = tag.RowsAffected()
		return err
	})
	return n, err
}

// SectionSent records the outcome of workspace's section sent as seq and
// measured at measured, by compare-and-set on its state_seq, with
// SnapshotSent's semantics (accepted: due again Every later; not_found:
// retried, parked after SectionNotFoundFor; refused: parked; failed: the
// backoff; a due time set since the measurement stands).
func (c *Contract) SectionSent(ctx context.Context, workspace uuid.UUID, section string, seq int64, measured time.Time,
	outcome ContractSnapshotOutcome, class string, times ContractSnapshotTimes) (ContractSnapshotRecord, error) {
	var rec ContractSnapshotRecord
	err := pg.InTx(ctx, c.pool, func(tx pgx.Tx) error {
		rec = ContractSnapshotRecord{}
		var s sentRow
		err := tx.QueryRow(ctx, `SELECT due_at, not_found_since, tries, coalesce(error, ''), clock_timestamp()
			FROM contract_sections WHERE workspace_id = $1 AND section = $2 AND state_seq = $3 FOR UPDATE`, workspace, section, seq).
			Scan(&s.due, &s.notFound, &s.tries, &s.before, &s.now)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		var w sentWrite
		if rec, w, err = s.decide(measured, outcome, class, times, SectionNotFoundFor); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE contract_sections SET ok_at = coalesce($4, ok_at), due_at = $5, tries = $6, error = $7,
			not_found_since = $8, parked_at = coalesce($9, CASE WHEN $4::timestamptz IS NOT NULL THEN NULL ELSE parked_at END)
			WHERE workspace_id = $1 AND section = $2 AND state_seq = $3`,
			workspace, section, seq, w.accepted, w.due, rec.Tries, w.class, rec.NotFoundSince, w.parked)
		return err
	})
	return rec, err
}

// sentRow is a document row's sender state as an outcome finds it.
type sentRow struct {
	due, now time.Time
	notFound *time.Time
	tries    int
	before   string
}

// sentWrite is what an outcome writes on its row.
type sentWrite struct {
	due              time.Time
	accepted, parked *time.Time
	class            *string
}

// decide is SnapshotSent's table of outcomes (contract_snapshot.go), for a
// section's or a person's document: Again when a due time was set after
// the measurement (it stands, unless the outcome's is sooner, and a
// failure then counts no try).
func (s sentRow) decide(measured time.Time, outcome ContractSnapshotOutcome, class string, times ContractSnapshotTimes,
	notFoundFor time.Duration) (ContractSnapshotRecord, sentWrite, error) {
	rec := ContractSnapshotRecord{Recorded: true, Again: s.due.After(measured), Tries: s.tries, NotFoundSince: s.notFound, Before: s.before}
	w := sentWrite{due: s.due}
	if class != "" {
		w.class = &class
	}
	next := func(at time.Time) {
		if !rec.Again || at.Before(s.due) {
			w.due = at
		}
	}
	backoff := func() {
		if !rec.Again {
			rec.Tries = s.tries + 1
		}
		next(s.now.Add(snapshotBackoff(s.tries, times)))
	}
	now := s.now
	switch outcome {
	case SnapshotAccepted:
		w.accepted, w.class, rec.Tries, rec.NotFoundSince = &now, nil, 0, nil
		next(now.Add(times.Every))
	case SnapshotNotFound:
		if !rec.Again {
			if rec.NotFoundSince == nil {
				rec.NotFoundSince = &now
			}
			if now.Sub(*rec.NotFoundSince) >= notFoundFor {
				rec.Parked, w.parked = true, &now
				break
			}
		}
		backoff()
	case SnapshotRefused:
		rec.Parked, w.parked, rec.NotFoundSince = true, &now, nil
	case SnapshotFailed:
		backoff()
	default:
		return ContractSnapshotRecord{}, sentWrite{}, fmt.Errorf("store: unknown document outcome %d", outcome)
	}
	return rec, w, nil
}

// retrySerialization runs fn, one whole transaction, again when the server
// aborted it as a serialization failure (40001: a REPEATABLE READ document
// read met an act that committed after its snapshot) or a deadlock
// (40P01), at most five times in all.
func retrySerialization(ctx context.Context, fn func() error) error {
	var err error
	for range 5 {
		if err = fn(); !isSerialization(err) && !isDeadlock(err) {
			return err
		}
		if isDeadlock(err) {
			obs.LoggerFrom(ctx).Warn("store: a contract transaction deadlocked; retrying")
		}
	}
	return err
}

func isSerialization(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "40001"
}
