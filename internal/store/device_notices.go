package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/pg"
)

// device_notices (0050) is what Wappie tells a person in its own pages
// about a number: that it was deleted (its readers, and the workspace's other
// owners), or that its sync was turned off (its readers). They are required
// until the platform's mails start (decision 0039) and kept afterwards. A
// person has at most one unseen notice per number and kind. 0051 adds the
// owners' two (the plan's DB14): that a number lost its last key holder to
// an owner's override (number_stranded), and that it moved out of the team
// (number_moved_out), each to the workspace's other active owners, never
// the actor, in every edition.

// Notice kinds.
const (
	NoticeSyncPaused     = "sync_paused"
	NoticeNumberDeleted  = "number_deleted"
	NoticeNumberStranded = "number_stranded"
	NoticeNumberMovedOut = "number_moved_out"
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

// Notices is what user has not seen yet: every number_deleted,
// number_stranded and number_moved_out notice, from its snapshot, and a
// sync_paused one only while the number is live and the person still reads
// it.
func (d *Devices) Notices(ctx context.Context, tenant, user uuid.UUID) ([]DeviceNotice, error) {
	var out []DeviceNotice
	err := pg.InTenantTx(ctx, d.pool, tenant.String(), func(tx pgx.Tx) error {
		var err error
		out, err = noticesTx(ctx, tx, tenant, user)
		return err
	})
	return out, err
}

// noticeColumns reads a notice as DeviceNotice holds it, with the name of
// who raised it: the person, or a key's creator, or a former member's
// address from the workspace's history.
const noticeColumns = `SELECT n.id, n.device_id, n.kind, n.label, n.hint, n.raised_at, n.last_raised_at, n.pauses,
	n.several_actors, nullif(coalesce(nullif(u.name, ''), u.email, h.email, ''), ''), n.raised_by_kind, n.until,
	n.resumed_at, n.purged_at
	FROM device_notices n
	LEFT JOIN users u ON u.id = n.raised_by
	LEFT JOIN workspace_member_history h ON h.tenant_id = n.tenant_id AND h.user_id = n.raised_by`

func scanNotices(rows pgx.Rows) ([]DeviceNotice, error) {
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (DeviceNotice, error) {
		var n DeviceNotice
		err := row.Scan(&n.ID, &n.DeviceID, &n.Kind, &n.Label, &n.Hint, &n.RaisedAt, &n.LastRaisedAt, &n.Pauses,
			&n.SeveralActors, &n.RaisedByName, &n.RaisedByKind, &n.Until, &n.ResumedAt, &n.PurgedAt)
		return n, err
	})
}

func noticesTx(ctx context.Context, tx pgx.Tx, tenant, user uuid.UUID) ([]DeviceNotice, error) {
	rows, err := tx.Query(ctx, noticeColumns+`
		WHERE n.tenant_id = $1 AND n.user_id = $2 AND n.seen_at IS NULL
		  AND (n.kind <> 'sync_paused' OR EXISTS (
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
	return scanNotices(rows)
}

// SeenNotice is a notice as its person saw it: a pause notice keeps its id
// when a later pause folds into it, so Pauses says which version was
// shown. Zero is a bare id, which acknowledges only a notice that never
// folds (every kind but sync_paused).
type SeenNotice struct {
	ID     int64
	Pauses int
}

// SeeNotices marks user's own notices among seen as seen, and returns what
// is left unseen. A sync_paused notice is marked only at the version its
// person saw: one a pause folded into since stays unseen, and comes back
// in the reply, so nobody acknowledges a pause they were never shown.
// Another person's notice is never touched.
func (d *Devices) SeeNotices(ctx context.Context, tenant, user uuid.UUID, seen []SeenNotice) ([]DeviceNotice, error) {
	ids, pauses := make([]int64, 0, len(seen)), make([]int64, 0, len(seen))
	for _, n := range seen {
		ids, pauses = append(ids, n.ID), append(pauses, int64(n.Pauses))
	}
	var out []DeviceNotice
	err := pg.InTenantTx(ctx, d.pool, tenant.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE device_notices n SET seen_at = clock_timestamp()
			FROM unnest($3::bigint[], $4::bigint[]) AS s(id, pauses)
			WHERE n.tenant_id = $1 AND n.user_id = $2 AND n.id = s.id AND n.seen_at IS NULL
			  AND (n.kind <> 'sync_paused' OR n.pauses = s.pauses)`, tenant, user, ids, pauses); err != nil {
			return err
		}
		var err error
		out, err = noticesTx(ctx, tx, tenant, user)
		return err
	})
	return out, err
}

// PauseActor is who turns a number's sync off: a person (User), or an API
// key (Key), whose act is its creator's (decision 0040).
type PauseActor struct {
	User uuid.UUID
	Key  uuid.UUID
}

// RaisedNotice is a notice a pause raised, with the person it is for.
type RaisedNotice struct {
	UserID uuid.UUID
	Notice DeviceNotice
}

// Paused is what Pause did. Changed is a live, unpaused number this call
// paused; a repeated stop changes nothing and raises nothing. ActorUser is
// the person behind the act: the person, or the key's creator, and nil for a
// key with no creator. Notices are the readers told, each with their own
// notice, and Recorded whether the sync_paused event was written.
type Paused struct {
	Changed   bool
	ActorKind string
	ActorUser *uuid.UUID
	Notices   []RaisedNotice
	Recorded  bool
}

// Pause turns a number's sync off at a person's or an API key's request
// (device.stop), in one transaction that takes the workspace's row first,
// so the event log's order within a workspace is its commit order. Only the
// transition from live to paused tells anyone: every reader but the actor
// gets their one unseen sync_paused notice for the number, a new one or the
// one still unseen folded (one more pause, the latest date and actor, and
// several_actors when this actor is not the last one); and the sync_paused
// event is written, unless nobody but the actor reads the number, when
// there is nobody to tell.
//
// An API key's act is its creator's: the creator is the actor, is left out
// of the notices as a person actor is, and is the event's actor. In a
// personal workspace that is its owner, so the owner's own key tells nobody
// and records nothing. Only a key with no creator has nobody behind it: then
// every reader is told and the row has no actor.
//
// The pauses Wappie makes on its own (a transfer, a failed resume, the
// pairing resume, a deletion, the storage stop) never come here.
func (d *Devices) Pause(ctx context.Context, tenant, device uuid.UUID, by PauseActor) (Paused, error) {
	var out Paused
	err := pg.InTenantTx(ctx, d.pool, tenant.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT 1 FROM tenants WHERE id = $1 FOR UPDATE`, tenant); err != nil {
			return err
		}
		var name, pushName, pn string
		err := tx.QueryRow(ctx, `UPDATE devices SET paused = true, pause_cause = 'person', pause_seq = pause_seq + 1
			WHERE id = $1 AND NOT paused
			RETURNING label, push_name, coalesce(pn, '')`, device).Scan(&name, &pushName, &pn)
		if errors.Is(err, pgx.ErrNoRows) {
			// Already paused: nobody is told, but the stop still counts, so
			// a failed transfer's undo leaves the number paused, and it is
			// now a person's pause, which a snapshot reports as theirs.
			tag, err := tx.Exec(ctx, `UPDATE devices SET pause_cause = 'person', pause_seq = pause_seq + 1 WHERE id = $1`, device)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				return ErrNotFound
			}
			return nil
		}
		if err != nil {
			return err
		}
		out.Changed = true

		out.ActorKind = actorPerson
		switch {
		case by.Key != uuid.Nil:
			out.ActorKind = actorKey
			var creator *uuid.UUID
			err := tx.QueryRow(ctx, `SELECT created_by FROM api_keys WHERE id = $1 AND tenant_id = $2`, by.Key, tenant).Scan(&creator)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			out.ActorUser = creator
		case by.User != uuid.Nil:
			user := by.User
			out.ActorUser = &user
		default:
			return errors.New("store: a pause needs a person or a key")
		}

		readers, err := readersTx(ctx, tx, tenant, device)
		if err != nil {
			return err
		}
		var told []uuid.UUID
		subs, users := readerIDs(readers)
		for _, r := range readers {
			if out.ActorUser == nil || r.UserID != *out.ActorUser {
				told = append(told, r.UserID)
			}
		}
		// Nobody to tell: the platform would mail nobody, and billing has
		// no use for the event (contract 4.1). The test is on the people,
		// so a reader without a sub still counts.
		if len(told) == 0 {
			return nil
		}
		itemName, hint := itemLabel(device, name, pushName, pn)
		rows, err := tx.Query(ctx, `INSERT INTO device_notices (tenant_id, device_id, user_id, kind, label, hint, raised_by, raised_by_kind)
			SELECT $1, $2, u, 'sync_paused', $3, $4, $5, $6 FROM unnest($7::uuid[]) AS u
			ON CONFLICT (tenant_id, device_id, user_id, kind) WHERE seen_at IS NULL DO UPDATE
			SET pauses = device_notices.pauses + 1, last_raised_at = clock_timestamp(), resumed_at = NULL,
			    several_actors = device_notices.several_actors
			      OR (device_notices.raised_by, device_notices.raised_by_kind) IS DISTINCT FROM (excluded.raised_by, excluded.raised_by_kind),
			    raised_by = excluded.raised_by, raised_by_kind = excluded.raised_by_kind,
			    label = excluded.label, hint = excluded.hint
			RETURNING id`, tenant, device, itemName, hint, out.ActorUser, out.ActorKind, told)
		if err != nil {
			return err
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
		if err != nil {
			return err
		}
		rows, err = tx.Query(ctx, `SELECT n.user_id, `+strings.TrimPrefix(noticeColumns, "SELECT ")+`
			WHERE n.tenant_id = $1 AND n.id = ANY($2) ORDER BY n.id`, tenant, ids)
		if err != nil {
			return err
		}
		if out.Notices, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (RaisedNotice, error) {
			var r RaisedNotice
			n := &r.Notice
			err := row.Scan(&r.UserID, &n.ID, &n.DeviceID, &n.Kind, &n.Label, &n.Hint, &n.RaisedAt, &n.LastRaisedAt, &n.Pauses,
				&n.SeveralActors, &n.RaisedByName, &n.RaisedByKind, &n.Until, &n.ResumedAt, &n.PurgedAt)
			return r, err
		}); err != nil {
			return err
		}

		var sub *uuid.UUID
		if out.ActorUser != nil {
			if sub, err = actorSubTx(ctx, tx, *out.ActorUser); err != nil {
				return err
			}
		}
		var at time.Time
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
			return err
		}
		out.Recorded = true
		return recordEvent(ctx, tx, tenant, itemEvent{
			Type: eventSyncPaused, ItemID: device, DedupeKey: dedupeKey(eventSyncPaused, device, at), OccurredAt: at,
			ActorKind: out.ActorKind, ActorSub: sub, ActorUserID: out.ActorUser, ReaderSubs: subs, ReaderUserIDs: users,
			Label: itemName, Hint: hint,
		})
	})
	return out, err
}

// MarkResumed marks the number's open sync_paused notices resumed, after a
// person or a key turned its sync on again. Nothing is deleted: a reader who
// was away meanwhile still learns, in the past tense, that it was off. It
// takes the workspace's row first, as Pause does, and marks nothing once
// the number is paused again: a pause that committed after the resume
// reopened the notice, which stays open while the number is paused.
func (d *Devices) MarkResumed(ctx context.Context, tenant, device uuid.UUID) error {
	return pg.InTenantTx(ctx, d.pool, tenant.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT 1 FROM tenants WHERE id = $1 FOR UPDATE`, tenant); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE device_notices SET resumed_at = clock_timestamp()
			WHERE tenant_id = $1 AND device_id = $2 AND kind = 'sync_paused' AND resumed_at IS NULL AND seen_at IS NULL
			  AND EXISTS (SELECT 1 FROM devices d WHERE d.id = $2 AND NOT d.paused)`, tenant, device)
		return err
	})
}
