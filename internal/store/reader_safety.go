package store

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrLastDeviceReader prevents an access change from destroying the last
// recoverable envelope for a number. Workspace ownership alone is not a key.
var ErrLastDeviceReader = errors.New("store: the number must retain an active reader with its archive key")

// All grant and permission mutations take the same lock, before touching a
// membership. This also serializes them with UpdateMember's owner checks.
func lockWorkspaceAccess(ctx context.Context, tx pgx.Tx, tenant uuid.UUID) error {
	var id uuid.UUID
	return tx.QueryRow(ctx, `SELECT id FROM tenants WHERE id=$1 FOR UPDATE`, tenant).Scan(&id)
}

// requireRemainingReader is called before deleting this member's grants. A nil
// device checks every number affected by disabling a membership. Existing
// keyless CLI devices remain supported; the check only protects envelopes held
// by active members. Even a holder whose read flag was withheld may be the
// only recoverable copy. Old non-retired epochs need a reader too.
//
// A connection service account never counts: not as a backup, because its
// grants are sealed to a key that lives only in a reader and dies with it
// (after a restart nobody could open them), and not as the one being
// checked, because its grants are copies of someone else's. That is any
// membership with a deadline, and any account a connection names.
func requireRemainingReader(ctx context.Context, tx pgx.Tx, tenant, target uuid.UUID, device *uuid.UUID) error {
	doomed, err := strandedDevicesTx(ctx, tx, tenant, target, device)
	if err != nil {
		return err
	}
	if len(doomed) > 0 {
		return ErrLastDeviceReader
	}
	return nil
}

// strandedDevicesTx is every number whose last recoverable envelope target
// holds, by requireRemainingReader's predicate, which is the database's
// sole_key_holders (0051): the same rule the contract's snapshot lists as
// protected. It never joins devices, so a deleted number keeps protecting
// its last key holder until its purge, as a live one does.
func strandedDevicesTx(ctx context.Context, tx pgx.Tx, tenant, target uuid.UUID, device *uuid.UUID) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `SELECT device_id FROM sole_key_holders($1)
		WHERE user_id = $2 AND ($3::uuid IS NULL OR device_id = $3)
		ORDER BY device_id`, tenant, target, device)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

// DeletedNumberRef names a deleted number to an owner: its raw label inputs,
// which the console turns into a name, and its purge date.
type DeletedNumberRef struct {
	DeviceID   uuid.UUID `json:"device_id"`
	Label      string    `json:"label"`
	PushName   string    `json:"push_name"`
	PN         string    `json:"pn"`
	PurgeAfter time.Time `json:"purge_after"`
}

// ErrLastReaderOfDeleted refuses to remove or disable the last key holder of
// numbers that are deleted and not yet purged. Numbers is for an owner and
// empty for anyone else, who learns neither a label nor a date. The ways out
// are to wait for the purge, at most 30 days, or to recover the number and
// share its key with someone else first.
type ErrLastReaderOfDeleted struct{ Numbers []DeletedNumberRef }

func (e *ErrLastReaderOfDeleted) Error() string {
	return "store: this person holds the last key of a deleted number that is not purged yet"
}

// strandCheckTx refuses removing or disabling target when that would strand
// a number: ErrLastDeviceReader when any of them is live, as 0032 always
// did, and ErrLastReaderOfDeleted, naming them for an owner, when they are
// all deleted. With override, an owner's strand override that the gate
// lets through (UpdateMemberStrandDeleted, RemoveMemberStrandDeleted),
// numbers that are all deleted are not refused: they are returned, for
// strandTx to record, and the act goes on. A live number is never
// overridden.
func strandCheckTx(ctx context.Context, tx pgx.Tx, tenant, target uuid.UUID, actorRole string, override bool) ([]DeletedNumberRef, error) {
	doomed, err := strandedDevicesTx(ctx, tx, tenant, target, nil)
	if err != nil || len(doomed) == 0 {
		return nil, err
	}
	refusal := &ErrLastReaderOfDeleted{Numbers: []DeletedNumberRef{}}
	live := false
	err = withQuarantine(ctx, tx, func() error {
		rows, err := tx.Query(ctx, `SELECT id, deleted_at IS NOT NULL, label, push_name, coalesce(pn,''), purge_after
			FROM devices WHERE id = ANY($1) ORDER BY id`, doomed)
		if err != nil {
			return err
		}
		defer rows.Close()
		found := 0
		for rows.Next() {
			var n DeletedNumberRef
			var deleted bool
			var purgeAfter *time.Time
			if err := rows.Scan(&n.DeviceID, &deleted, &n.Label, &n.PushName, &n.PN, &purgeAfter); err != nil {
				return err
			}
			found++
			if !deleted || purgeAfter == nil {
				live = true
				continue
			}
			n.PurgeAfter = *purgeAfter
			refusal.Numbers = append(refusal.Numbers, n)
		}
		// A grant for a number this workspace cannot see counts as live:
		// the refusal fails closed.
		if found < len(doomed) {
			live = true
		}
		return rows.Err()
	})
	switch {
	case err != nil:
		return nil, err
	case live:
		return nil, ErrLastDeviceReader
	case override && actorRole == "owner":
		return refusal.Numbers, nil
	}
	if actorRole != "owner" {
		refusal.Numbers = []DeletedNumberRef{}
	}
	return nil, refusal
}

// ownersMailedTx is the gate of the owner's strand override (the plan's
// DB2, as the owner confirmed it on 2026-10-14): it goes on only where the
// platform will mail the workspace's other owners its item.stranded, which
// is a team the platform names (contract_workspaces), not closed there,
// while the contract is on (observe or later). Everywhere else, a
// self-hosted installation included, where no platform mails anyone,
// release A's refusal stands. It reads contract_state under its share lock,
// held to the commit, so a switch to off waits for the act, whose row is
// then never written in an off period (DB10); and it is called before the
// workspace's lock, since every transaction that takes contract_state takes
// it first (DB23).
func ownersMailedTx(ctx context.Context, tx pgx.Tx, tenant uuid.UUID) (bool, error) {
	var mailed bool
	err := tx.QueryRow(ctx, `SELECT s.mode <> 'off' AND EXISTS (SELECT 1 FROM contract_workspaces w
		WHERE w.workspace_id = $1 AND w.kind = 'team' AND w.status IS DISTINCT FROM 'closed')
		FROM contract_state s FOR SHARE OF s`, tenant).Scan(&mailed)
	return mailed, err
}

// strandTx records what an owner's override takes from each deleted number
// it strands (the plan's DB13), before the act changes target's membership,
// whose readers it reads: one stranded row per number, with target's sub as
// the person it lost (NULL for an account without one), cause (disabled or
// revoked), the owner as the actor and the people who read it just before,
// target among them when they did (README 9); and a number_stranded notice,
// until its purge, for each other active owner of the workspace, never the
// actor or target (DB14). The number keeps its purge_after. The caller holds
// the workspace's row lock.
func strandTx(ctx context.Context, tx pgx.Tx, tenant, actor, target uuid.UUID, cause string, numbers []DeletedNumberRef) error {
	if len(numbers) == 0 {
		return nil
	}
	var person *uuid.UUID
	err := tx.QueryRow(ctx, `SELECT sub FROM platform_identities WHERE user_id = $1`, target).Scan(&person)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	sub, err := actorSubTx(ctx, tx, actor)
	if err != nil {
		return err
	}
	var at time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		return err
	}
	return withQuarantine(ctx, tx, func() error {
		for _, n := range numbers {
			readers, err := readersTx(ctx, tx, tenant, n.DeviceID)
			if err != nil {
				return err
			}
			readerSubs, readerUsers := readerIDs(readers)
			itemName, hint := itemLabel(n.DeviceID, n.Label, n.PushName, n.PN)
			if err := recordEvent(ctx, tx, tenant, itemEvent{
				Type: eventStranded, ItemID: n.DeviceID,
				DedupeKey:  eventStranded + ":" + n.DeviceID.String() + ":" + target.String() + ":" + strconv.FormatInt(at.UnixMicro(), 10),
				OccurredAt: at, ActorKind: actorPerson, ActorSub: sub, ActorUserID: &actor,
				ReaderSubs: readerSubs, ReaderUserIDs: readerUsers, Label: itemName, Hint: hint,
				PersonSub: person, Cause: &cause,
			}); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO device_notices (tenant_id, device_id, user_id, kind, label, hint, raised_by, raised_by_kind, until)
				SELECT $1, $2, m.user_id, 'number_stranded', $3, $4, $5, 'person', $6
				FROM workspace_memberships m JOIN users o ON o.id = m.user_id
				WHERE m.tenant_id = $1 AND m.role = 'owner' AND m.status = 'active' AND o.status = 'active'
				  AND m.user_id <> $5 AND m.user_id <> $7
				ON CONFLICT (tenant_id, device_id, user_id, kind) WHERE seen_at IS NULL DO UPDATE
				SET label = excluded.label, hint = excluded.hint, raised_at = excluded.raised_at, raised_by = excluded.raised_by,
				    raised_by_kind = excluded.raised_by_kind, until = excluded.until`,
				tenant, n.DeviceID, itemName, hint, actor, n.PurgeAfter, target); err != nil {
				return err
			}
		}
		return nil
	})
}
