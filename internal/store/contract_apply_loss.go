package store

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// A membership the platform's document ends (DS54): every effect of
// removeMember, without its refusals (the manager's role, the last owner,
// the strand check), and the person's AI keychain items in that workspace.
// A loss that would strand a number (its last key holder) waits until the
// platform's generation is confirmed, and a closed account's until its
// closing is confirmed too; then each number records
// item.stranded with the app as the actor and no cause (the platform fills
// removed or closed), and its other owners get their number_stranded
// notice. Token rows are not written: DS47 and DS48 keep a person's loss
// away from tokens, and the creator belt is tokenLiveSQL's, read from the
// stored document.

// lossResult is what one membership's loss did, or would do.
type lossResult struct {
	// held: it would strand a number and may not yet (the generation, or
	// a closed account's closing, is not confirmed); nothing was written.
	held bool
	// stranded counts the numbers it stranded.
	stranded int
	// keychain counts the person's keychain items it emptied.
	keychain int64
	// ended are the connections it ended.
	ended []EndedConnection
}

// applyMembershipLossTx applies the loss of user's membership in tenant
// (apply), or says what it would do. confirmed is whether it may strand a
// number: the platform's generation is confirmed and, for a closed
// account, so is its closing (applyRun.loss). email is the person's address, for the history
// and their pending invitations, as removeMember reads it. The caller holds
// app.tenant_id = tenant, the workspace's row lock and the person's row.
func applyMembershipLossTx(ctx context.Context, tx pgx.Tx, tenant, user uuid.UUID, email string, confirmed, apply bool) (lossResult, error) {
	var out lossResult
	stranded, err := strandedDevicesTx(ctx, tx, tenant, user, nil)
	if err != nil {
		return out, err
	}
	if len(stranded) > 0 && !confirmed {
		out.held = true
		return out, nil
	}
	out.stranded = len(stranded)
	if !apply {
		err := tx.QueryRow(ctx, `SELECT count(*) FROM ai_keychain WHERE tenant_id = $1 AND user_id = $2 AND deleted_at IS NULL`,
			tenant, user).Scan(&out.keychain)
		return out, err
	}
	// What the numbers lose is read before the membership goes.
	if err := strandByAppTx(ctx, tx, tenant, user, stranded); err != nil {
		return out, err
	}
	// The person's keychain items in the workspace are emptied, and the AI
	// connections naming them end, before their place there goes.
	ended, n, err := emptyKeychainTx(ctx, tx, tenant, user, nil)
	if err != nil {
		return out, err
	}
	out.keychain = n
	out.ended = append(out.ended, ended...)
	more, err := removeMembershipTx(ctx, tx, tenant, user, email)
	out.ended = append(out.ended, more...)
	return out, err
}

// emptyKeychainTx empties user's live keychain items in tenant (only ids,
// when given), as DeleteKeychainItem does each: the envelope emptied and
// the item marked deleted, and every live AI connection naming one ended
// with ai_key_deleted. It returns the connections ended and the items
// emptied. The caller holds app.tenant_id = tenant and the workspace's row
// lock.
func emptyKeychainTx(ctx context.Context, tx pgx.Tx, tenant, user uuid.UUID, ids []uuid.UUID) ([]EndedConnection, int64, error) {
	rows, err := tx.Query(ctx, `UPDATE ai_keychain SET envelope = '\x', deleted_at = now()
		WHERE tenant_id = $1 AND user_id = $2 AND deleted_at IS NULL AND ($3::uuid[] IS NULL OR id = ANY ($3))
		RETURNING id::text`, tenant, user, ids)
	if err != nil {
		return nil, 0, err
	}
	items, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil || len(items) == 0 {
		return nil, 0, err
	}
	rows, err = tx.Query(ctx, `SELECT id::text, reader FROM mcp_connections
		WHERE tenant_id = $1 AND kind = 'ai' AND status IN ('pending', 'active', 'reseal')
		  AND EXISTS (SELECT 1 FROM jsonb_each(ai_config->'keys') k WHERE k.value->>'keychain_id' = ANY ($2))
		ORDER BY id`, tenant, items)
	if err != nil {
		return nil, 0, err
	}
	targets, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (EndedConnection, error) {
		var e EndedConnection
		err := row.Scan(&e.ID, &e.Reader)
		return e, err
	})
	if err != nil {
		return nil, 0, err
	}
	var ended []EndedConnection
	for _, e := range targets {
		did, err := endMCPConnectionTx(ctx, tx, tenant, e.ID, statusRevoked, ReasonAIKeyDeleted)
		if err != nil {
			return nil, 0, err
		}
		if did {
			ended = append(ended, e)
		}
	}
	return ended, int64(len(items)), nil
}

// strandByAppTx records what a loss the platform made takes from each
// number it strands (target was its last key holder), before the
// membership changes, whose readers it reads: one stranded row per number,
// live or deleted, with the app as the actor, target's sub as the person
// (NULL without one) and no cause, which the platform fills from its own
// record (removed or closed; README 9); and a number_stranded notice,
// until a deleted number's purge, for each other active owner of the
// workspace, raised by the app. The caller holds the workspace's row lock.
func strandByAppTx(ctx context.Context, tx pgx.Tx, tenant, target uuid.UUID, devices []uuid.UUID) error {
	if len(devices) == 0 {
		return nil
	}
	var person *uuid.UUID
	err := tx.QueryRow(ctx, `SELECT sub FROM platform_identities WHERE user_id = $1`, target).Scan(&person)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	var at time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		return err
	}
	return withQuarantine(ctx, tx, func() error {
		rows, err := tx.Query(ctx, `SELECT id, label, coalesce(pn, ''), purge_after FROM devices WHERE id = ANY ($1) ORDER BY id`, devices)
		if err != nil {
			return err
		}
		type number struct {
			id         uuid.UUID
			label, pn  string
			purgeAfter *time.Time
		}
		numbers, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (number, error) {
			var n number
			err := row.Scan(&n.id, &n.label, &n.pn, &n.purgeAfter)
			return n, err
		})
		if err != nil {
			return err
		}
		for _, n := range numbers {
			readers, err := readersTx(ctx, tx, tenant, n.id)
			if err != nil {
				return err
			}
			readerSubs, readerUsers := readerIDs(readers)
			itemName, hint := itemLabel(n.id, n.label, n.pn)
			if err := recordEvent(ctx, tx, tenant, itemEvent{
				Type: eventStranded, ItemID: n.id,
				DedupeKey:  eventStranded + ":" + n.id.String() + ":" + target.String() + ":" + strconv.FormatInt(at.UnixMicro(), 10),
				OccurredAt: at, ActorKind: actorApp,
				ReaderSubs: readerSubs, ReaderUserIDs: readerUsers, Label: itemName, Hint: hint,
				PersonSub: person,
			}); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO device_notices (tenant_id, device_id, user_id, kind, label, hint, raised_by, raised_by_kind, until)
				SELECT $1, $2, m.user_id, 'number_stranded', $3, $4, NULL, 'app', $5
				FROM workspace_memberships m JOIN users o ON o.id = m.user_id
				WHERE m.tenant_id = $1 AND m.role = 'owner' AND m.status = 'active' AND o.status = 'active' AND m.user_id <> $6
				ON CONFLICT (tenant_id, device_id, user_id, kind) WHERE seen_at IS NULL DO UPDATE
				SET label = excluded.label, hint = excluded.hint, raised_at = excluded.raised_at, raised_by = excluded.raised_by,
				    raised_by_kind = excluded.raised_by_kind, until = excluded.until`,
				tenant, n.id, itemName, hint, n.purgeAfter, target); err != nil {
				return err
			}
		}
		return nil
	})
}
