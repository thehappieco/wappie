package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/label"
	"whatserver2/internal/pg"
)

// The access snapshots Wappie sends of each platform workspace (README 8;
// the plan's 4.10): the read model, measured in one snapshot of the
// database with its clock, and the sender's state on each recorded
// workspace (when its snapshot is due, the last snapshot_seq, its backoff,
// a not_found and a park). internal/membership turns the read model into
// the wire's snapshot and sends it; nothing here calls the platform.

// The states and the pause reasons of a snapshot's item (README 8).
const (
	SnapshotActive     = "active"
	SnapshotSyncPaused = "sync_paused"
	SnapshotDeleted    = "deleted"

	SnapshotByPerson    = "by_person"
	SnapshotNeedsReauth = "needs_reauth"
	SnapshotQuota       = "quota"
	SnapshotError       = "error"
)

// ContractSnapshot is what Wappie's own tables say of one platform
// workspace, in Wappie's terms: subs only, never a local account, an
// email or a phone number.
type ContractSnapshot struct {
	Workspace uuid.UUID
	// MeasuredAt is the database's clock in the transaction that read it.
	MeasuredAt time.Time
	// Local: Wappie has a workspace of this id. Without one the snapshot is
	// empty, and is sent all the same (the plan's DB9).
	Local bool
	// Items are its numbers, deleted ones until their purge, by id.
	Items []ContractSnapshotItem
	// Labels counts the items' labels by class, never their values.
	Labels map[label.Class]int
}

// ContractSnapshotItem is one number of a snapshot.
type ContractSnapshotItem struct {
	ID uuid.UUID
	// Label and Hint are the contract's (label.Contract, label.HintFromPN),
	// nil for none.
	Label, Hint *string
	// State is SnapshotActive, SnapshotSyncPaused or SnapshotDeleted; Reason
	// is a paused item's, "" for any other.
	State, Reason string
	// PurgeAt is a deleted number's purge_after.
	PurgeAt *time.Time
	// OtherBackups counts the key holders without a sub that Wappie's own
	// rule counts as a backup.
	OtherBackups int
	// People are everyone with a sub who has a permission row or a key at
	// an epoch not retired, by sub.
	People []ContractSnapshotPerson
	// Protected are the subs Wappie's rule says the number cannot lose
	// (sole_key_holders), each among People, in order.
	Protected []uuid.UUID
}

// ContractSnapshotPerson is one person's standing on a number.
type ContractSnapshotPerson struct {
	Sub uuid.UUID
	// The stored flags only (device_permissions); the console adds what a
	// role allows.
	Read, Send, Manage bool
	// Reads: Read with a key at the current epoch, an active membership
	// with no deadline passed and an active person, whatever the
	// workspace's status and whether the number is deleted. Waiting: the
	// same, without the key yet. HoldsKey: a key at an epoch not retired,
	// with or without Read.
	Reads, Waiting, HoldsKey bool
}

// snapshotQuotaSQL is Storage.Check's verdict on workspace t without its
// write (StorageUsageTx records the stop it finds): capture is refused
// once the stop is recorded, or the bytes are at 105% of the limit, or the
// 72 hours of grace over it are spent.
const snapshotQuotaSQL = `coalesce(t.storage_paused_at IS NOT NULL OR (t.storage_limit_bytes IS NOT NULL AND
	(t.storage_archive_bytes::numeric + t.storage_object_bytes >= t.storage_limit_bytes::numeric * 1.05 OR
	 t.storage_over_since + interval '72 hours' <= clock_timestamp())), false)`

// Snapshot reads what the access snapshot of the platform workspace
// workspace says (README 8; the plan's 4.10), in one REPEATABLE READ
// transaction scoped to it, with deleted numbers visible: each number with
// a known identity or a past connection (a pending registration has
// neither, and is never a number of the workspace's), its label and hint,
// its state and reason, who holds what on it, whom Wappie's own rule
// protects (sole_key_holders, the rule that refuses removing them), and
// how many backups without a sub it counts. A deleted number is reported
// as a live one is until its purge: its readers, holders and protected
// are as they were (its permissions and grants stay), and its state and
// purge date say it is deleted.
func (c *Contract) Snapshot(ctx context.Context, workspace uuid.UUID) (ContractSnapshot, error) {
	var out ContractSnapshot
	err := pgx.BeginTxFunc(ctx, c.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		out = ContractSnapshot{Workspace: workspace, Items: []ContractSnapshotItem{}, Labels: map[label.Class]int{}}
		if _, err := tx.Exec(ctx, `SELECT set_config($1, $2, true)`, pg.TenantGUC, workspace.String()); err != nil {
			return err
		}
		var status string
		var quota bool
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp(), t.id IS NOT NULL, coalesce(t.status, ''), `+snapshotQuotaSQL+`
			FROM (SELECT $1::uuid AS id) w LEFT JOIN tenants t ON t.id = w.id`, workspace).Scan(&out.MeasuredAt, &out.Local, &status, &quota); err != nil {
			return err
		}
		if !out.Local {
			return nil
		}
		return withQuarantine(ctx, tx, func() error {
			return snapshotItemsTx(ctx, tx, workspace, out.MeasuredAt, status == "active", quota, &out)
		})
	})
	return out, err
}

// snapshotItemsTx fills out's items from the workspace's tables, read in
// tx with deleted numbers visible.
func snapshotItemsTx(ctx context.Context, tx pgx.Tx, workspace uuid.UUID, at time.Time, active, quota bool, out *ContractSnapshot) error {
	// The numbers. The predicate is exactly what 0051's devices trigger
	// wakes on, so a number never enters the snapshot unannounced.
	rows, err := tx.Query(ctx, `SELECT id, label, push_name, coalesce(pn, ''), status, paused, coalesce(pause_cause, ''),
			deleted_at IS NOT NULL, purge_after
		FROM devices WHERE tenant_id = $1 AND (lid IS NOT NULL OR pn IS NOT NULL OR last_connected_at IS NOT NULL)
		ORDER BY id`, workspace)
	if err != nil {
		return err
	}
	index := map[uuid.UUID]int{}
	err = forEachRow(rows, func(row pgx.Rows) error {
		var it ContractSnapshotItem
		var name, pushName, pn, status, cause string
		var paused, deleted bool
		var purgeAfter *time.Time
		if err := row.Scan(&it.ID, &name, &pushName, &pn, &status, &paused, &cause, &deleted, &purgeAfter); err != nil {
			return err
		}
		it.Label = label.Contract(name, pushName, pn, it.ID.String())
		it.Hint = label.HintFromPN(pn)
		out.Labels[label.Classify(name, pushName, pn, it.ID.String())]++
		it.State, it.Reason = snapshotState(deleted, paused, cause, status, active, quota)
		if it.State == SnapshotDeleted {
			if purgeAfter == nil {
				// 0050's CHECK pairs them: a fault, not a deleted number.
				return fmt.Errorf("store: deleted number %s has no purge date", it.ID)
			}
			it.PurgeAt = purgeAfter
		}
		it.People, it.Protected = []ContractSnapshotPerson{}, []uuid.UUID{}
		index[it.ID] = len(out.Items)
		out.Items = append(out.Items, it)
		return nil
	})
	if err != nil || len(out.Items) == 0 {
		return err
	}

	// Everyone with a sub who has a permission row or a key at an epoch
	// not retired, on each number: their stored flags, the key at the
	// current epoch, a key at any epoch not retired, and whether they are
	// an active member with no deadline passed and an active person.
	rows, err = tx.Query(ctx, `WITH holders AS (
			SELECT DISTINCT g.device_id, g.user_id FROM device_key_grants g
			  JOIN device_archive_keys k ON k.device_id = g.device_id AND k.epoch = g.epoch AND k.retired_at IS NULL
			 WHERE g.tenant_id = $1)
		SELECT x.device_id, pi.sub, coalesce(p.can_read, false), coalesce(p.can_send, false), coalesce(p.can_manage, false),
			h.user_id IS NOT NULL,
			EXISTS (SELECT 1 FROM device_key_grants g WHERE g.tenant_id = $1 AND g.device_id = x.device_id
			         AND g.user_id = x.user_id AND g.epoch = d.current_epoch),
			EXISTS (SELECT 1 FROM workspace_memberships m JOIN users u ON u.id = m.user_id
			         WHERE m.tenant_id = $1 AND m.user_id = x.user_id AND m.status = 'active' AND u.status = 'active'
			           AND (m.expires_at IS NULL OR m.expires_at > $2))
		  FROM (SELECT device_id, user_id FROM device_permissions WHERE tenant_id = $1
		        UNION SELECT device_id, user_id FROM holders) x
		  JOIN devices d ON d.id = x.device_id AND d.tenant_id = $1
		  JOIN platform_identities pi ON pi.user_id = x.user_id
		  LEFT JOIN device_permissions p ON p.tenant_id = $1 AND p.device_id = x.device_id AND p.user_id = x.user_id
		  LEFT JOIN holders h ON h.device_id = x.device_id AND h.user_id = x.user_id
		 ORDER BY x.device_id, pi.sub`, workspace, at)
	if err != nil {
		return err
	}
	err = forEachRow(rows, func(row pgx.Rows) error {
		var device uuid.UUID
		var p ContractSnapshotPerson
		var currentKey, member bool
		if err := row.Scan(&device, &p.Sub, &p.Read, &p.Send, &p.Manage, &p.HoldsKey, &currentKey, &member); err != nil {
			return err
		}
		p.Reads = p.Read && currentKey && member
		p.Waiting = p.Read && !currentKey && member
		if i, ok := index[device]; ok {
			out.Items[i].People = append(out.Items[i].People, p)
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Whom the number cannot lose, by Wappie's own rule: the one function
	// the removal's refusal reads (strandedDevicesTx). A holder without a
	// sub is the app's own concern, and the snapshot lists only subs.
	rows, err = tx.Query(ctx, `SELECT s.device_id, pi.sub FROM sole_key_holders($1) s
		JOIN platform_identities pi ON pi.user_id = s.user_id ORDER BY s.device_id, pi.sub`, workspace)
	if err != nil {
		return err
	}
	err = forEachRow(rows, func(row pgx.Rows) error {
		var device, sub uuid.UUID
		if err := row.Scan(&device, &sub); err != nil {
			return err
		}
		if i, ok := index[device]; ok {
			out.Items[i].Protected = append(out.Items[i].Protected, sub)
		}
		return nil
	})
	if err != nil {
		return err
	}

	// The backups without a sub, as the backup side of sole_key_holders
	// counts them: an active person with an active membership and no
	// deadline, Read, and a key at an epoch not retired, never a
	// connection's service account. Standing service accounts and local
	// people who never linked to the platform.
	rows, err = tx.Query(ctx, `SELECT g.device_id, count(DISTINCT g.user_id) FROM device_key_grants g
		  JOIN device_archive_keys k ON k.device_id = g.device_id AND k.epoch = g.epoch AND k.retired_at IS NULL
		  JOIN workspace_memberships m ON m.tenant_id = g.tenant_id AND m.user_id = g.user_id
		       AND m.status = 'active' AND m.expires_at IS NULL
		  JOIN users u ON u.id = m.user_id AND u.status = 'active'
		  JOIN device_permissions p ON p.tenant_id = g.tenant_id AND p.device_id = g.device_id AND p.user_id = g.user_id AND p.can_read
		 WHERE g.tenant_id = $1
		   AND NOT EXISTS (SELECT 1 FROM mcp_connections c WHERE c.service_user_id = g.user_id)
		   AND NOT EXISTS (SELECT 1 FROM platform_identities pi WHERE pi.user_id = g.user_id)
		 GROUP BY g.device_id`, workspace)
	if err != nil {
		return err
	}
	return forEachRow(rows, func(row pgx.Rows) error {
		var device uuid.UUID
		var n int
		if err := row.Scan(&device, &n); err != nil {
			return err
		}
		if i, ok := index[device]; ok {
			out.Items[i].OtherBackups = n
		}
		return nil
	})
}

// forEachRow calls fn for each of rows, then closes them.
func forEachRow(rows pgx.Rows, fn func(pgx.Rows) error) error {
	defer rows.Close()
	for rows.Next() {
		if err := fn(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

// snapshotState is a number's state and reason (the plan's DB12): deleted
// until its purge; else paused whenever Wappie captures nothing for it (a
// pause, a logged-out or banned session, a storage stop, a workspace that
// is not active), with the first reason that holds of needs_reauth (logged
// out), error (banned, or the workspace not active), quota, by_person (a
// person's or a key's stop), and error for anything else (a move's pause
// left over, an exclusion's on a live number): a paused number always has
// a reason, and is never active. A number nobody can read is active:
// Wappie does not pause capture for it.
func snapshotState(deleted, paused bool, cause, status string, active, quota bool) (string, string) {
	switch {
	case deleted:
		return SnapshotDeleted, ""
	case status == "logged_out":
		return SnapshotSyncPaused, SnapshotNeedsReauth
	case status == "banned", !active:
		return SnapshotSyncPaused, SnapshotError
	case quota:
		return SnapshotSyncPaused, SnapshotQuota
	case !paused:
		return SnapshotActive, ""
	case cause == PauseByPerson:
		return SnapshotSyncPaused, SnapshotByPerson
	}
	return SnapshotSyncPaused, SnapshotError
}

// ContractSnapshotDue is the recorded workspace whose snapshot is due
// first, as the sender reads it.
type ContractSnapshotDue struct {
	Workspace uuid.UUID
	// Seq is its last snapshot_seq: what an outcome recorded before a new
	// one is given names.
	Seq int64
	// DueAt is when its snapshot is due; Due that it is, on the database's
	// clock, and Wait how long until it is otherwise.
	DueAt time.Time
	Due   bool
	Wait  time.Duration
}

// NextSnapshot reads the workspace whose snapshot is due first, of those
// not parked; false when none is recorded.
func (c *Contract) NextSnapshot(ctx context.Context) (ContractSnapshotDue, bool, error) {
	var d ContractSnapshotDue
	var now time.Time
	err := c.pool.QueryRow(ctx, `SELECT workspace_id, snapshot_seq, snapshot_due_at, clock_timestamp() FROM contract_workspaces
		WHERE parked_at IS NULL ORDER BY snapshot_due_at, workspace_id LIMIT 1`).Scan(&d.Workspace, &d.Seq, &d.DueAt, &now)
	if errors.Is(err, pgx.ErrNoRows) {
		return ContractSnapshotDue{}, false, nil
	}
	if err != nil {
		return ContractSnapshotDue{}, false, err
	}
	d.Due = !d.DueAt.After(now)
	d.Wait = max(d.DueAt.Sub(now), 0)
	return d, true, nil
}

// SnapshotsDue makes every recorded workspace's snapshot due now, a parked
// one's included, in id order: what a leader's start does (README 8: a
// snapshot of every platform workspace; the plan's 4.10). A park is
// released for one try only, since its not_found_since stays: one more
// not_found parks it again at once, and a snapshot refused as invalid (a
// Wappie bug, which a new binary may have fixed) is parked again by its
// refusal.
func (c *Contract) SnapshotsDue(ctx context.Context) error {
	return retryDeadlock(ctx, func() error {
		return pg.InTx(ctx, c.pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SELECT 1 FROM contract_workspaces ORDER BY workspace_id FOR UPDATE`); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `UPDATE contract_workspaces SET
				snapshot_due_at = least(snapshot_due_at, clock_timestamp()), parked_at = NULL`)
			return err
		})
	})
}

// SnapshotsDirty makes the snapshots of the workspaces ids (or of every
// recorded workspace, with all) due within debounce, in id order: a change
// they show was committed (0051's triggers). A snapshot due sooner stays
// due then, so a run of changes waits at most debounce from its first; a
// workspace backing off after a failure keeps its backoff, and a parked
// one its park.
func (c *Contract) SnapshotsDirty(ctx context.Context, ids []uuid.UUID, all bool, debounce time.Duration) error {
	if len(ids) == 0 && !all {
		return nil
	}
	const which = `($1 OR workspace_id = ANY ($2)) AND parked_at IS NULL AND snapshot_tries = 0
		AND snapshot_due_at > clock_timestamp() + $3::interval`
	return retryDeadlock(ctx, func() error {
		return pg.InTx(ctx, c.pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SELECT 1 FROM contract_workspaces WHERE `+which+`
				ORDER BY workspace_id FOR UPDATE`, all, ids, debounce); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `UPDATE contract_workspaces SET snapshot_due_at = clock_timestamp() + $3::interval
				WHERE `+which, all, ids, debounce)
			return err
		})
	})
}

// SnapshotSeq gives the snapshot of workspace measured at measured its
// snapshot_seq, stored before it is sent: the measurement's milliseconds,
// or one more than the last, whichever is higher, so it rises strictly
// for the workspace across leaders and a clock that steps back (README 8).
// False when the workspace is parked meanwhile, and nothing is to be sent.
func (c *Contract) SnapshotSeq(ctx context.Context, workspace uuid.UUID, measured time.Time) (int64, bool, error) {
	var seq int64
	err := c.pool.QueryRow(ctx, `UPDATE contract_workspaces SET snapshot_seq = greatest($2::bigint, snapshot_seq + 1)
		WHERE workspace_id = $1 AND parked_at IS NULL RETURNING snapshot_seq`, workspace, measured.UnixMilli()).Scan(&seq)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	return seq, err == nil, err
}

// ContractSnapshotOutcome is what became of a snapshot sent.
type ContractSnapshotOutcome int

const (
	// SnapshotAccepted: the platform's signed {"accepted": true}.
	SnapshotAccepted ContractSnapshotOutcome = iota + 1
	// SnapshotNotFound: a signed not_found, a workspace never named to the
	// app (README 8: a platform fault): retried for 24 hours, then parked.
	SnapshotNotFound
	// SnapshotRefused: a signed invalid_request, a Wappie bug: parked,
	// and released by no document (a restart, or a leader's start, tries
	// again).
	SnapshotRefused
	// SnapshotFailed: no answer, an unverified one, any other refusal, or
	// a snapshot Wappie could not read or would not send: retried with
	// the backoff.
	SnapshotFailed
)

// ContractSnapshotTimes are the sender's timings: an accepted snapshot's
// next is due Every later (README 8's hourly), and a failure's after
// BackoffMin doubled with each failure in a row, up to BackoffMax.
type ContractSnapshotTimes struct {
	Every, BackoffMin, BackoffMax time.Duration
}

// SnapshotNotFoundFor is how long a workspace's snapshot is retried after
// the platform first answered not_found, before it is parked (README 8).
const SnapshotNotFoundFor = 24 * time.Hour

// ContractSnapshotRecord is what recording an outcome did.
type ContractSnapshotRecord struct {
	// Recorded: the workspace's last snapshot_seq was still the one sent.
	// False when another leader has sent a later one since: nothing was
	// written.
	Recorded bool
	// Again: someone made the snapshot due now after it was measured (a
	// change a document made, a restart, a name given again), and that due
	// time stands rather than the outcome's next or backoff.
	Again bool
	// Parked: this outcome parked it.
	Parked bool
	// Tries counts the failures in a row, this one included.
	Tries int
	// NotFoundSince is the first not_found of the run.
	NotFoundSince *time.Time
}

// SnapshotSent records the outcome of the snapshot of workspace sent as
// seq and measured at measured (with class, a failure's: a refusal's code,
// an outcome, a transport's; never a message), by compare-and-set on seq.
// Accepted: accepted now, due again Every later, the run of failures, a
// not_found and a park ended. Not found: the run's first not_found kept,
// and parked once it is SnapshotNotFoundFor old, else the backoff.
// Refused: parked, with no not_found_since, so no document releases it.
// Failed: the backoff. A due time someone set after the measurement stands
// whatever the outcome (Again), and a failure then counts no try: the
// snapshot measured after that change is what goes next.
func (c *Contract) SnapshotSent(ctx context.Context, workspace uuid.UUID, seq int64, measured time.Time,
	outcome ContractSnapshotOutcome, class string, times ContractSnapshotTimes) (ContractSnapshotRecord, error) {
	var rec ContractSnapshotRecord
	err := pg.InTx(ctx, c.pool, func(tx pgx.Tx) error {
		rec = ContractSnapshotRecord{}
		var due, now time.Time
		var notFound *time.Time
		var tries int
		err := tx.QueryRow(ctx, `SELECT snapshot_due_at, not_found_since, snapshot_tries, clock_timestamp()
			FROM contract_workspaces WHERE workspace_id = $1 AND snapshot_seq = $2 FOR UPDATE`, workspace, seq).
			Scan(&due, &notFound, &tries, &now)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		// Again: due since the measurement, by a writer that asked for it
		// now (a later due time is the sender's own debounce or backoff).
		again := due.After(measured) && !due.After(now)
		rec.Recorded, rec.Again, rec.Tries, rec.NotFoundSince = true, again, tries, notFound
		backoff := func() {
			if rec.Again {
				return
			}
			rec.Tries = tries + 1
			due = now.Add(snapshotBackoff(tries, times))
		}
		var parked *time.Time
		var errClass *string
		if class != "" {
			errClass = &class
		}
		var accepted *time.Time
		switch outcome {
		case SnapshotAccepted:
			accepted, errClass, rec.Tries, rec.NotFoundSince = &now, nil, 0, nil
			if !rec.Again {
				due = now.Add(times.Every)
			}
		case SnapshotNotFound:
			if !rec.Again {
				if rec.NotFoundSince == nil {
					rec.NotFoundSince = &now
				}
				if now.Sub(*rec.NotFoundSince) >= SnapshotNotFoundFor {
					rec.Parked, parked = true, &now
					break
				}
			}
			backoff()
		case SnapshotRefused:
			rec.Parked, parked, rec.NotFoundSince = true, &now, nil
		case SnapshotFailed:
			backoff()
		default:
			return fmt.Errorf("store: unknown snapshot outcome %d", outcome)
		}
		_, err = tx.Exec(ctx, `UPDATE contract_workspaces SET
			snapshot_ok_at = coalesce($3, snapshot_ok_at), snapshot_due_at = $4, snapshot_tries = $5, snapshot_error = $6,
			not_found_since = $7, parked_at = coalesce($8, CASE WHEN $3::timestamptz IS NOT NULL THEN NULL ELSE parked_at END)
			WHERE workspace_id = $1 AND snapshot_seq = $2`,
			workspace, seq, accepted, due, rec.Tries, errClass, rec.NotFoundSince, parked)
		return err
	})
	return rec, err
}

// snapshotBackoff is the wait after the failure that follows tries
// failures in a row: BackoffMin doubled with each, up to BackoffMax.
func snapshotBackoff(tries int, times ContractSnapshotTimes) time.Duration {
	d := times.BackoffMin
	for range min(tries, 40) {
		if d >= times.BackoffMax {
			break
		}
		d *= 2
	}
	return min(d, times.BackoffMax)
}
