package store

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/pg"
)

// The person's settings document (0052's contract_persons; the plan's 2.7
// and 6.6): one person's own settings in Wappie across its platform
// workspaces, their unseen notices and when they last signed out
// everywhere through the console. Each followed sub has a row: its clock
// (seq, which reads and acts take under the row's lock), the last seq
// given to a document (sent_seq, an outcome's compare-and-set), and the
// sender's due time and backoff, as a section's.

// PersonNotFoundFor is how long a person's document is retried after the
// platform first answered not_found (a sub it no longer follows), before
// it is parked.
const PersonNotFoundFor = 24 * time.Hour

// ContractNotice is one unseen notice of a person, in a platform
// workspace, as the person's document reads it: ids and times, the label
// and hint the notice stored, and the number's current label and phone
// number, which the label cutover is judged on (the plan's 2.11). The
// actor is a sub, never a name.
type ContractNotice struct {
	ID               int64
	Workspace        uuid.UUID
	Device           uuid.UUID
	Kind             string
	Label, Hint      *string
	RaisedAt         time.Time
	LastRaisedAt     *time.Time
	Pauses           int
	SeveralActors    bool
	ActorKind        string
	ActorSub         *uuid.UUID
	Until, ResumedAt *time.Time
	PurgedAt         *time.Time
	// DeviceLabel and DevicePN are the number's now, nil once it is gone
	// (purged, or moved out of the workspace).
	DeviceLabel, DevicePN *string
}

// At is when the notice was last raised.
func (n ContractNotice) At() time.Time {
	if n.LastRaisedAt != nil {
		return *n.LastRaisedAt
	}
	return n.RaisedAt
}

// ContractPerson is what Wappie's tables say of one person's document,
// measured in the transaction that gave it Seq.
type ContractPerson struct {
	Sub uuid.UUID
	// User is the local account linked to Sub, nil for none.
	User       *uuid.UUID
	Seq        int64
	MeasuredAt time.Time
	// SignedOutEverywhereAt is the latest issued_at of a
	// person.sign_out_everywhere that ran.
	SignedOutEverywhereAt *time.Time
	// LabelCutoverAt is 0052's migrate time.
	LabelCutoverAt time.Time
	// Notices are the unseen ones of the person's platform workspaces,
	// newest first.
	Notices []ContractNotice
}

// PersonOf reads sub's document in one REPEATABLE READ transaction that
// takes its seq on contract_persons first (the plan's 3.5, as NumbersOf):
// an act of the person that commits after its snapshot makes it run again.
// False when Wappie sends none for sub (no document, or a closed account)
// or its row is parked. The notices are those Devices.Notices lists, per
// platform workspace the person is an active member of (with the
// quarantine scope open, so a deleted number's notice finds its number),
// never a local-only workspace's, nor one where their membership is
// disabled or expired, or the account or the workspace is not active:
// Wappie's own page shows none of those, since no session reaches it.
func (c *Contract) PersonOf(ctx context.Context, sub uuid.UUID) (ContractPerson, bool, error) {
	var out ContractPerson
	var ok bool
	err := retrySerialization(ctx, func() error {
		out, ok = ContractPerson{Sub: sub, Notices: []ContractNotice{}}, false
		return pgx.BeginTxFunc(ctx, c.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead}, func(tx pgx.Tx) error {
			var sendable bool
			if err := tx.QueryRow(ctx, `SELECT coalesce((SELECT `+personSendableSQL+` FROM contract_accounts a WHERE a.sub = $1), false),
				(SELECT user_id FROM platform_identities WHERE sub = $1), s.label_cutover_at
				FROM contract_settings_state s`, sub).Scan(&sendable, &out.User, &out.LabelCutoverAt); err != nil {
				return err
			}
			if !sendable {
				return nil
			}
			err := tx.QueryRow(ctx, `WITH now AS (SELECT clock_timestamp() AS t)
				INSERT INTO contract_persons AS p (sub, seq, sent_seq) SELECT $1, `+clockMillisSQL+`, `+clockMillisSQL+` FROM now
				ON CONFLICT (sub) DO UPDATE SET seq = greatest(excluded.seq, p.seq + 1), sent_seq = greatest(excluded.seq, p.seq + 1)
				WHERE p.parked_at IS NULL
				RETURNING p.seq, p.signed_out_everywhere_at, (SELECT t FROM now)`, sub).Scan(&out.Seq, &out.SignedOutEverywhereAt, &out.MeasuredAt)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			if err != nil {
				return err
			}
			ok = true
			if out.User == nil {
				return nil
			}
			if err := scope(ctx, tx, uuid.Nil, *out.User); err != nil {
				return err
			}
			rows, err := tx.Query(ctx, `SELECT m.tenant_id FROM workspace_memberships m
				JOIN contract_workspaces w ON w.workspace_id = m.tenant_id
				WHERE m.user_id = $1 ORDER BY m.tenant_id`, *out.User)
			if err != nil {
				return err
			}
			workspaces, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
			if err != nil {
				return err
			}
			for _, ws := range workspaces {
				if err := scope(ctx, tx, ws, uuid.Nil); err != nil {
					return err
				}
				if active, err := activeMemberTx(ctx, tx, ws, *out.User); err != nil || !active {
					return err
				}
				if err := withQuarantine(ctx, tx, func() error {
					return personNoticesTx(ctx, tx, ws, *out.User, &out.Notices)
				}); err != nil {
					return err
				}
			}
			slices.SortStableFunc(out.Notices, func(a, b ContractNotice) int {
				if c := b.At().Compare(a.At()); c != 0 {
					return c
				}
				return cmp.Compare(b.ID, a.ID)
			})
			return scope(ctx, tx, uuid.Nil, uuid.Nil)
		})
	})
	return out, ok, err
}

// activeMemberTx reports whether user is a member of workspace that
// Wappie's own screens let in: the membership, the account and the
// workspace active, the membership not expired. tx is scoped to workspace.
func activeMemberTx(ctx context.Context, tx pgx.Tx, workspace, user uuid.UUID) (bool, error) {
	var active bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM workspace_memberships m
		JOIN users u ON u.id = m.user_id JOIN tenants t ON t.id = m.tenant_id
		WHERE m.tenant_id = $1 AND m.user_id = $2 AND m.status = 'active' AND u.status = 'active' AND t.status = 'active'
		  AND (m.expires_at IS NULL OR m.expires_at > now()))`, workspace, user).Scan(&active)
	return active, err
}

// personNoticesTx appends user's unseen notices in workspace, read in tx
// scoped to it with deleted numbers visible. The filter is noticesTx's
// (store/device_notices.go), with a live number for a pause notice spelled
// out, since the scope here shows deleted ones: every notice but a
// sync_paused one, and that one only while the number is live and the
// person still reads it.
func personNoticesTx(ctx context.Context, tx pgx.Tx, workspace, user uuid.UUID, out *[]ContractNotice) error {
	rows, err := tx.Query(ctx, `SELECT n.id, n.tenant_id, n.device_id, n.kind, n.label, n.hint, n.raised_at, n.last_raised_at,
			n.pauses, n.several_actors, n.raised_by_kind, pi.sub, n.until, n.resumed_at, n.purged_at, dv.label, dv.pn
		FROM device_notices n
		LEFT JOIN platform_identities pi ON pi.user_id = n.raised_by
		LEFT JOIN devices dv ON dv.id = n.device_id AND dv.tenant_id = n.tenant_id
		WHERE n.tenant_id = $1 AND n.user_id = $2 AND n.seen_at IS NULL
		  AND (n.kind <> 'sync_paused' OR EXISTS (
		    SELECT 1 FROM workspace_memberships m
		    JOIN users r ON r.id = m.user_id
		    JOIN tenants t ON t.id = m.tenant_id
		    JOIN devices d ON d.tenant_id = m.tenant_id AND d.id = n.device_id AND d.deleted_at IS NULL
		    JOIN device_permissions p ON p.tenant_id = m.tenant_id AND p.device_id = d.id AND p.user_id = m.user_id AND p.can_read
		    WHERE m.tenant_id = n.tenant_id AND m.user_id = n.user_id
		      AND m.status = 'active' AND r.status = 'active' AND t.status = 'active'
		      AND (m.expires_at IS NULL OR m.expires_at > now())
		      AND EXISTS (SELECT 1 FROM device_key_grants g WHERE g.device_id = d.id AND g.user_id = m.user_id AND g.epoch = d.current_epoch)))
		ORDER BY n.raised_at, n.id`, workspace, user)
	if err != nil {
		return err
	}
	return forEachRow(rows, func(row pgx.Rows) error {
		var n ContractNotice
		if err := row.Scan(&n.ID, &n.Workspace, &n.Device, &n.Kind, &n.Label, &n.Hint, &n.RaisedAt, &n.LastRaisedAt,
			&n.Pauses, &n.SeveralActors, &n.ActorKind, &n.ActorSub, &n.Until, &n.ResumedAt, &n.PurgedAt, &n.DeviceLabel, &n.DevicePN); err != nil {
			return err
		}
		*out = append(*out, n)
		return nil
	})
}

// ContractPersonDue is the person's document due first, as the sender
// reads it.
type ContractPersonDue struct {
	Sub uuid.UUID
	// Seq is its last sent_seq: what an outcome recorded before a new one
	// is given names.
	Seq   int64
	DueAt time.Time
	Due   bool
	Wait  time.Duration
}

// NextPerson reads the person's document due first, of the subs Wappie
// sends for whose row is not parked; false when none is.
func (c *Contract) NextPerson(ctx context.Context) (ContractPersonDue, bool, error) {
	var d ContractPersonDue
	var now time.Time
	err := c.pool.QueryRow(ctx, `SELECT p.sub, p.sent_seq, p.due_at, clock_timestamp()
		FROM contract_persons p JOIN contract_accounts a ON a.sub = p.sub
		WHERE p.parked_at IS NULL AND `+personSendableSQL+` ORDER BY p.due_at, p.sub LIMIT 1`).
		Scan(&d.Sub, &d.Seq, &d.DueAt, &now)
	if errors.Is(err, pgx.ErrNoRows) {
		return ContractPersonDue{}, false, nil
	}
	if err != nil {
		return ContractPersonDue{}, false, err
	}
	d.Due = !d.DueAt.After(now)
	d.Wait = max(d.DueAt.Sub(now), 0)
	return d, true, nil
}

// PersonsDue makes every person's document due now, a parked one's
// included, for one try: what a leader's start does. A followed sub with no
// row gets one first (the trigger's backstop).
func (c *Contract) PersonsDue(ctx context.Context) error {
	return retryDeadlock(ctx, func() error {
		return pg.InTx(ctx, c.pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `INSERT INTO contract_persons (sub) SELECT sub FROM contract_accounts ORDER BY sub
				ON CONFLICT DO NOTHING`); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `UPDATE contract_persons p SET due_at = clock_timestamp(), parked_at = NULL
				FROM (SELECT sub FROM contract_persons ORDER BY sub FOR UPDATE) l WHERE p.sub = l.sub`)
			return err
		})
	})
}

// PersonsDirty makes the documents of subs, and of the subs users are
// linked to (a notice's u: payload), due within debounce, as
// SectionsDirty does.
func (c *Contract) PersonsDirty(ctx context.Context, subs, users []uuid.UUID, debounce time.Duration) error {
	if len(subs) == 0 && len(users) == 0 {
		return nil
	}
	return retryDeadlock(ctx, func() error {
		_, err := c.pool.Exec(ctx, `UPDATE contract_persons p SET due_at = clock_timestamp() + $3::interval
			FROM (SELECT sub FROM contract_persons
			      WHERE (sub = ANY ($1) OR sub IN (SELECT sub FROM platform_identities WHERE user_id = ANY ($2)))
			        AND parked_at IS NULL AND tries = 0 AND due_at > clock_timestamp() + $3::interval
			      ORDER BY sub FOR UPDATE) l
			WHERE p.sub = l.sub`, subs, users, debounce)
		return err
	})
}

// PersonsOfWorkspace lists the subs with an unseen notice in workspace:
// whose document a change of the workspace may change (a reader losing
// Read hides a pause notice; a membership disabled, expired or enabled
// again hides or shows every notice of the workspace).
func (c *Contract) PersonsOfWorkspace(ctx context.Context, workspace uuid.UUID) ([]uuid.UUID, error) {
	var out []uuid.UUID
	err := pg.InTenantTx(ctx, c.pool, workspace.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT DISTINCT pi.sub FROM device_notices n JOIN platform_identities pi ON pi.user_id = n.user_id
			WHERE n.tenant_id = $1 AND n.seen_at IS NULL ORDER BY pi.sub`, workspace)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		return err
	})
	return out, err
}

// PersonSent records the outcome of sub's document sent as seq and
// measured at measured, by compare-and-set on its sent_seq (an act's seq
// never moves it), with SnapshotSent's semantics and PersonNotFoundFor.
func (c *Contract) PersonSent(ctx context.Context, sub uuid.UUID, seq int64, measured time.Time,
	outcome ContractSnapshotOutcome, class string, times ContractSnapshotTimes) (ContractSnapshotRecord, error) {
	var rec ContractSnapshotRecord
	err := pg.InTx(ctx, c.pool, func(tx pgx.Tx) error {
		rec = ContractSnapshotRecord{}
		var s sentRow
		err := tx.QueryRow(ctx, `SELECT due_at, not_found_since, tries, coalesce(error, ''), clock_timestamp()
			FROM contract_persons WHERE sub = $1 AND sent_seq = $2 FOR UPDATE`, sub, seq).
			Scan(&s.due, &s.notFound, &s.tries, &s.before, &s.now)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		var w sentWrite
		if rec, w, err = s.decide(measured, outcome, class, times, PersonNotFoundFor); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE contract_persons SET ok_at = coalesce($3, ok_at), due_at = $4, tries = $5, error = $6,
			not_found_since = $7, parked_at = coalesce($8, CASE WHEN $3::timestamptz IS NOT NULL THEN NULL ELSE parked_at END)
			WHERE sub = $1 AND sent_seq = $2`, sub, seq, w.accepted, w.due, rec.Tries, w.class, rec.NotFoundSince, w.parked)
		return err
	})
	return rec, err
}
