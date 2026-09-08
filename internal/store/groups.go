package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/pg"
)

// Groups records who is in a group and what has happened to it.
//
// The history only starts when this archive does. WhatsApp delivers a group's
// current composition and its live changes, never its past, so "who removed
// Fulano" is answerable from the moment we began listening and not before. That
// is stated in the UI rather than smoothed over: an empty history is not a
// peaceful one.
type Groups struct{ pool *pgxpool.Pool }

// NewGroups returns the group store.
func NewGroups(pool *pgxpool.Pool) *Groups { return &Groups{pool: pool} }

// Participant is one member of a group.
type Participant struct {
	Key          string
	LID          string
	PN           string
	IsAdmin      bool
	IsSuperAdmin bool
	FirstSeenAt  time.Time
	LeftAt       *time.Time
}

// GroupChange is one thing that happened to a group.
type GroupChange struct {
	TS         time.Time
	ActorKey   string
	ActorLID   string
	ActorPN    string
	Action     string
	SubjectKey string
	SubjectLID string
	SubjectPN  string
	Detail     string
}

// Membership actions.
const (
	ChangeSnapshot  = "snapshot"
	ChangeAdd       = "add"
	ChangeRemove    = "remove"
	ChangePromote   = "promote"
	ChangeDemote    = "demote"
	ChangeName      = "name"
	ChangeTopic     = "topic"
	ChangeEphemeral = "ephemeral"
	ChangeAnnounce  = "announce"
	ChangeLocked    = "locked"
)

// Snapshot records a group's composition as WhatsApp reports it now, and writes
// a change for anything that differs from what was already known.
//
// The guard at the top is the important part. A snapshot with nobody in it is
// not a group everybody left — it is a request that failed, or a group this
// account was removed from, or an answer WhatsApp declined to give. Diffing
// against it would write a "removed" for every member, with no author and a
// timestamp of now, and the table whose entire purpose is to say what happened
// would be saying something that did not.
func (g *Groups) Snapshot(ctx context.Context, tenant, device uuid.UUID, chatKey string,
	members []Participant, at time.Time) (int, error) {
	if len(members) == 0 {
		return 0, nil
	}
	var changes int
	err := pg.InTenantTx(ctx, g.pool, tenant.String(), func(tx pgx.Tx) error {
		known, err := readParticipants(ctx, tx, device, chatKey)
		if err != nil {
			return err
		}
		first := len(known) == 0

		incoming := make(map[string]Participant, len(members))
		for _, m := range members {
			incoming[m.Key] = m
		}

		for _, m := range members {
			was, existed := known[m.Key]
			if _, err := tx.Exec(ctx, `
				INSERT INTO group_participants (tenant_id, device_id, chat_key,
					participant_key, participant_lid, participant_pn,
					is_admin, is_super_admin)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
				ON CONFLICT (device_id, chat_key, participant_key) DO UPDATE SET
					participant_lid = COALESCE(EXCLUDED.participant_lid, group_participants.participant_lid),
					participant_pn  = COALESCE(EXCLUDED.participant_pn,  group_participants.participant_pn),
					is_admin        = EXCLUDED.is_admin,
					is_super_admin  = EXCLUDED.is_super_admin,
					left_at         = NULL`,
				tenant, device, chatKey, m.Key, nullable(m.LID), nullable(m.PN),
				m.IsAdmin, m.IsSuperAdmin); err != nil {
				return err
			}

			// The first snapshot is a marker, not a hundred arrivals. Writing
			// an "add" per member would claim a group formed the moment this
			// archive first looked at it.
			if first {
				continue
			}
			switch {
			case !existed || was.LeftAt != nil:
				if err := record(ctx, tx, tenant, device, chatKey, GroupChange{
					TS: at, Action: ChangeAdd,
					SubjectKey: m.Key, SubjectLID: m.LID, SubjectPN: m.PN,
				}); err != nil {
					return err
				}
				changes++
			case m.IsAdmin != was.IsAdmin:
				action := ChangeDemote
				if m.IsAdmin {
					action = ChangePromote
				}
				if err := record(ctx, tx, tenant, device, chatKey, GroupChange{
					TS: at, Action: action,
					SubjectKey: m.Key, SubjectLID: m.LID, SubjectPN: m.PN,
				}); err != nil {
					return err
				}
				changes++
			}
		}

		// Gone: known, not left already, and not in the answer.
		for key, was := range known {
			if _, still := incoming[key]; still || was.LeftAt != nil {
				continue
			}
			if _, err := tx.Exec(ctx, `
				UPDATE group_participants SET left_at = $4
				 WHERE device_id = $1 AND chat_key = $2 AND participant_key = $3`,
				device, chatKey, key, at); err != nil {
				return err
			}
			if first {
				continue
			}
			if err := record(ctx, tx, tenant, device, chatKey, GroupChange{
				TS: at, Action: ChangeRemove,
				SubjectKey: key, SubjectLID: was.LID, SubjectPN: was.PN,
			}); err != nil {
				return err
			}
			changes++
		}

		if first {
			// The marker, so the panel can say when the record begins rather
			// than presenting an empty history as a quiet one.
			return record(ctx, tx, tenant, device, chatKey, GroupChange{
				TS: at, Action: ChangeSnapshot,
				Detail: fmt.Sprintf("%d participantes", len(members)),
			})
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("store: snapshot group %s: %w", chatKey, err)
	}
	return changes, nil
}

// Record writes one change reported by a live event, and applies it.
func (g *Groups) Record(ctx context.Context, tenant, device uuid.UUID, chatKey string,
	c GroupChange) error {
	err := pg.InTenantTx(ctx, g.pool, tenant.String(), func(tx pgx.Tx) error {
		if err := record(ctx, tx, tenant, device, chatKey, c); err != nil {
			return err
		}
		switch c.Action {
		case ChangeAdd:
			_, err := tx.Exec(ctx, `
				INSERT INTO group_participants (tenant_id, device_id, chat_key,
					participant_key, participant_lid, participant_pn)
				VALUES ($1,$2,$3,$4,$5,$6)
				ON CONFLICT (device_id, chat_key, participant_key) DO UPDATE SET
					participant_lid = COALESCE(EXCLUDED.participant_lid, group_participants.participant_lid),
					participant_pn  = COALESCE(EXCLUDED.participant_pn,  group_participants.participant_pn),
					left_at = NULL`,
				tenant, device, chatKey, c.SubjectKey, nullable(c.SubjectLID), nullable(c.SubjectPN))
			return err
		case ChangeRemove:
			_, err := tx.Exec(ctx, `
				UPDATE group_participants SET left_at = $4
				 WHERE device_id = $1 AND chat_key = $2 AND participant_key = $3`,
				device, chatKey, c.SubjectKey, c.TS)
			return err
		case ChangePromote, ChangeDemote:
			_, err := tx.Exec(ctx, `
				UPDATE group_participants SET is_admin = $4
				 WHERE device_id = $1 AND chat_key = $2 AND participant_key = $3`,
				device, chatKey, c.SubjectKey, c.Action == ChangePromote)
			return err
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("store: record group change: %w", err)
	}
	return nil
}

// record inserts one history row, ignoring a redelivery.
//
// WhatsApp resends group events on every resync, and the same removal twice
// reads as two removals of one person — in a table whose entire purpose is to
// say what happened, that is worse than not recording it.
func record(ctx context.Context, tx pgx.Tx, tenant, device uuid.UUID, chatKey string,
	c GroupChange) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO group_changes (tenant_id, device_id, chat_key, ts,
			actor_key, actor_lid, actor_pn, action,
			subject_key, subject_lid, subject_pn, detail)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT DO NOTHING`,
		tenant, device, chatKey, c.TS,
		nullable(c.ActorKey), nullable(c.ActorLID), nullable(c.ActorPN), c.Action,
		nullable(c.SubjectKey), nullable(c.SubjectLID), nullable(c.SubjectPN),
		nullable(c.Detail))
	return err
}

func readParticipants(ctx context.Context, tx pgx.Tx, device uuid.UUID, chatKey string) (
	map[string]Participant, error) {
	rows, err := tx.Query(ctx, `
		SELECT participant_key, coalesce(participant_lid,''), coalesce(participant_pn,''),
		       is_admin, is_super_admin, first_seen_at, left_at
		  FROM group_participants WHERE device_id = $1 AND chat_key = $2`, device, chatKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]Participant{}
	for rows.Next() {
		var p Participant
		if err := rows.Scan(&p.Key, &p.LID, &p.PN, &p.IsAdmin, &p.IsSuperAdmin,
			&p.FirstSeenAt, &p.LeftAt); err != nil {
			return nil, err
		}
		out[p.Key] = p
	}
	return out, rows.Err()
}

// Participants lists a group's current members, admins first.
func (g *Groups) Participants(ctx context.Context, tenant, device uuid.UUID, chatKey string) (
	[]Participant, error) {
	var out []Participant
	err := pg.InTenantTx(ctx, g.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT participant_key, coalesce(participant_lid,''), coalesce(participant_pn,''),
			       is_admin, is_super_admin, first_seen_at, left_at
			  FROM group_participants
			 WHERE device_id = $1 AND chat_key = $2 AND left_at IS NULL
			 ORDER BY is_super_admin DESC, is_admin DESC, participant_key`, device, chatKey)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p Participant
			if err := rows.Scan(&p.Key, &p.LID, &p.PN, &p.IsAdmin, &p.IsSuperAdmin,
				&p.FirstSeenAt, &p.LeftAt); err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("store: list participants: %w", err)
	}
	return out, nil
}

// Changes lists what happened to a group, newest first.
func (g *Groups) Changes(ctx context.Context, tenant, device uuid.UUID, chatKey string,
	limit int) ([]GroupChange, error) {
	var out []GroupChange
	err := pg.InTenantTx(ctx, g.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT ts, coalesce(actor_key,''), coalesce(actor_lid,''), coalesce(actor_pn,''),
			       action, coalesce(subject_key,''), coalesce(subject_lid,''),
			       coalesce(subject_pn,''), coalesce(detail,'')
			  FROM group_changes
			 WHERE device_id = $1 AND chat_key = $2
			 ORDER BY ts DESC, id DESC
			 LIMIT $3`, device, chatKey, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c GroupChange
			if err := rows.Scan(&c.TS, &c.ActorKey, &c.ActorLID, &c.ActorPN,
				&c.Action, &c.SubjectKey, &c.SubjectLID, &c.SubjectPN, &c.Detail); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("store: list group changes: %w", err)
	}
	return out, nil
}

// Since is when the record of this group begins.
//
// Reported so a panel can say "history recorded since <date>" rather than
// presenting an empty list as a group nothing has ever happened to.
func (g *Groups) Since(ctx context.Context, tenant, device uuid.UUID, chatKey string) (
	*time.Time, error) {
	var at *time.Time
	err := pg.InTenantTx(ctx, g.pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT min(ts) FROM group_changes WHERE device_id = $1 AND chat_key = $2`,
			device, chatKey).Scan(&at)
	})
	if err != nil {
		return nil, fmt.Errorf("store: group history start: %w", err)
	}
	return at, nil
}
