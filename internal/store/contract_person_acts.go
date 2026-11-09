package store

import (
	"context"
	"encoding/json"
	"slices"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/pg"
)

// A person's acts from the console (step 12a's commands release; the
// plan's 6.5 to 6.7): person.sign_out_everywhere and
// person.notices_dismiss, each in one transaction in 3.4's order (DS14):
// the command's ledger row, the person's sessions or notices, then the
// person's row last (the act's seq on the person's clock, DS3, and the
// document due now), with the result at that seq. And the repair of a
// pause notice whose resume lost its mark (DS17).

// NoticeRef is one notice a person dismisses: its id as the person's
// document sends it (the row's id in decimal), at the version they saw.
type NoticeRef struct {
	ID      string
	Version int64
}

// personAct runs one act of run's person in one transaction: the ledger
// row (still without a result), body, then contract_persons (the act's
// seq, signed_out_everywhere_at raised to signedOut when it is set, and
// the document due now, a parked one's included, for one try, or the
// console would never see the act shown), and the result at that seq.
func (c *Contract) personAct(ctx context.Context, run ContractRun, signedOut *time.Time,
	body func(tx pgx.Tx) (CommandResult, error)) (ContractAct, error) {
	var out ContractAct
	err := retryDeadlock(ctx, func() error {
		out = ContractAct{}
		return pg.InTx(ctx, c.pool, func(tx pgx.Tx) error {
			if err := lockOpenCommandTx(ctx, tx, run.ID); err != nil {
				return err
			}
			r, err := body(tx)
			if err != nil {
				return err
			}
			if err := scope(ctx, tx, uuid.Nil, uuid.Nil); err != nil {
				return err
			}
			var seq int64
			if err := tx.QueryRow(ctx, `WITH now AS (SELECT clock_timestamp() AS t)
				INSERT INTO contract_persons AS p (sub, seq, signed_out_everywhere_at, due_at)
				SELECT $1, `+clockMillisSQL+`, $2, now.t FROM now
				ON CONFLICT (sub) DO UPDATE SET seq = greatest(excluded.seq, p.seq + 1), due_at = excluded.due_at, parked_at = NULL,
				  signed_out_everywhere_at = CASE WHEN $2::timestamptz IS NULL THEN p.signed_out_everywhere_at
				    ELSE greatest(coalesce(p.signed_out_everywhere_at, '-infinity'), $2) END
				RETURNING p.seq`, run.Sub, signedOut).Scan(&seq); err != nil {
				return err
			}
			r.StateSeq = &seq
			out = ContractAct{Result: r, Seq: seq}
			return finishCommandTx(ctx, tx, run.ID, r)
		})
	})
	return out, err
}

// RunSignOutEverywhere is person.sign_out_everywhere (the spec's 14.7;
// DS11): every session family of the actor's account begun before
// issuedAt ends, with its per-workspace sessions (the sockets close within
// a second, each checking its session), never a later one, and no API key,
// key acting as the person, MCP connection or AI integration; the result
// counts the live sessions ended (detail sessions_ended), and
// signed_out_everywhere_at keeps the latest issued_at that ran (the ledger
// keeps 30 days only). A rerun, delivered again after Wappie's own
// restore, ends only what began before the command, and counts 0 for what
// it ended already.
func (c *Contract) RunSignOutEverywhere(ctx context.Context, run ContractRun, issuedAt time.Time) (ContractAct, error) {
	return c.personAct(ctx, run, &issuedAt, func(tx pgx.Tx) (CommandResult, error) {
		n, err := signOutFamiliesBeforeTx(ctx, tx, run.User, issuedAt)
		if err != nil {
			return CommandResult{}, err
		}
		detail, err := json.Marshal(map[string]int64{"sessions_ended": n})
		return CommandResult{Outcome: CommandRan, Detail: detail}, err
	})
}

// RunNoticesDismiss is person.notices_dismiss (the spec's 14.7): in each
// platform workspace where the actor's account is an active member (the
// workspaces their document lists notices of), each of refs that is theirs
// and unseen is marked seen, as SeeNotices marks it: a sync_paused notice
// only at the version they saw. Not all or nothing: one already seen, gone
// or not theirs counts as done; one whose version rose since stays, and the
// result is state_changed; else ran.
func (c *Contract) RunNoticesDismiss(ctx context.Context, run ContractRun, refs []NoticeRef) (ContractAct, error) {
	ids, versions := make([]int64, 0, len(refs)), make([]int64, 0, len(refs))
	for _, r := range refs {
		// The document sends the row's id in decimal; another shape names
		// no notice of Wappie's, and counts as gone.
		if id, err := strconv.ParseInt(r.ID, 10, 64); err == nil && id > 0 && strconv.FormatInt(id, 10) == r.ID {
			ids, versions = append(ids, id), append(versions, r.Version)
		}
	}
	return c.personAct(ctx, run, nil, func(tx pgx.Tx) (CommandResult, error) {
		r := CommandResult{Outcome: CommandRan}
		if len(ids) == 0 {
			return r, nil
		}
		if err := scope(ctx, tx, uuid.Nil, run.User); err != nil {
			return r, err
		}
		rows, err := tx.Query(ctx, `SELECT m.tenant_id FROM workspace_memberships m
			JOIN contract_workspaces w ON w.workspace_id = m.tenant_id WHERE m.user_id = $1 ORDER BY m.tenant_id`, run.User)
		if err != nil {
			return r, err
		}
		workspaces, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			return r, err
		}
		for _, ws := range workspaces {
			if err := scope(ctx, tx, ws, uuid.Nil); err != nil {
				return r, err
			}
			if active, err := activeMemberTx(ctx, tx, ws, run.User); err != nil {
				return r, err
			} else if !active {
				continue
			}
			if _, err := tx.Exec(ctx, `UPDATE device_notices n SET seen_at = clock_timestamp()
				FROM (SELECT id FROM device_notices WHERE tenant_id = $1 AND user_id = $2 AND id = ANY ($3) AND seen_at IS NULL
				      ORDER BY id FOR UPDATE) l, unnest($3::bigint[], $4::bigint[]) AS s(id, version)
				WHERE n.id = l.id AND n.id = s.id AND (n.kind <> 'sync_paused' OR n.pauses = s.version)`,
				ws, run.User, ids, versions); err != nil {
				return r, err
			}
			var kept bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM device_notices WHERE tenant_id = $1 AND user_id = $2
				AND id = ANY ($3) AND seen_at IS NULL)`, ws, run.User, ids).Scan(&kept); err != nil {
				return r, err
			}
			if kept {
				r = CommandResult{Outcome: CommandRefused, Code: kc.CodeStateChanged}
			}
		}
		return r, nil
	})
}

// ResumeRepairAfter is how long a number must have been unpaused before
// the repair marks its pause notices resumed: beyond the frame's window
// between lifting a pause and marking it. device.start lifts it, then
// starts the number, which may try to connect 8 times with up to 30
// seconds between tries (a minute and a half, and the dials), and puts the
// pause back if the start fails; a mark made inside that window would say
// resumed of a number paused again.
const ResumeRepairAfter = 10 * time.Minute

// ResumeLostMarks marks resumed every unseen, unresumed sync_paused notice
// whose number is live and has been unpaused for ResumeRepairAfter since
// the notice was last raised (DS17; the platform's correction 3): the
// frames mark after their resume in a transaction of their own, which may
// fail, and that is never lost. The mark's time is the unpause's
// (devices.unpaused_at), or 0052's migrate time for a number unpaused
// before 0052 stamped any. A number paused again is skipped. With subs,
// only the workspaces of their accounts (before each person's read); with
// none, every workspace (the hourly maintenance). A workspace with a
// notice to mark takes its tenants row first, as MarkResumed does; one
// with none takes no lock (most, before most documents). It returns the
// notices marked.
func (c *Contract) ResumeLostMarks(ctx context.Context, subs ...uuid.UUID) (int64, error) {
	var tenants []uuid.UUID
	if len(subs) == 0 {
		rows, err := c.pool.Query(ctx, `SELECT id FROM tenants ORDER BY id`)
		if err != nil {
			return 0, err
		}
		if tenants, err = pgx.CollectRows(rows, pgx.RowTo[uuid.UUID]); err != nil {
			return 0, err
		}
	} else {
		var err error
		if tenants, err = c.workspacesOfSubs(ctx, subs); err != nil {
			return 0, err
		}
	}
	var marked int64
	for _, t := range tenants {
		err := pg.InTenantTx(ctx, c.pool, t.String(), func(tx pgx.Tx) error {
			var lost bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM device_notices n, devices d, contract_settings_state s WHERE `+lostMarkSQL+`)`,
				t, ResumeRepairAfter).Scan(&lost); err != nil || !lost {
				return err
			}
			if _, err := tx.Exec(ctx, `SELECT 1 FROM tenants WHERE id = $1 FOR UPDATE`, t); err != nil {
				return err
			}
			tag, err := tx.Exec(ctx, `UPDATE device_notices n SET resumed_at = coalesce(d.unpaused_at, s.label_cutover_at)
				FROM devices d, contract_settings_state s WHERE `+lostMarkSQL, t, ResumeRepairAfter)
			marked += tag.RowsAffected()
			return err
		})
		if err != nil {
			return marked, err
		}
	}
	return marked, nil
}

// lostMarkSQL is a notice n of workspace $1 whose resume lost its mark, on
// its number d, unpaused for $2: the repair's, checked with no lock first.
const lostMarkSQL = `n.tenant_id = $1 AND n.kind = 'sync_paused' AND n.seen_at IS NULL AND n.resumed_at IS NULL
	AND d.id = n.device_id AND d.tenant_id = n.tenant_id AND d.deleted_at IS NULL AND NOT d.paused
	AND coalesce(d.unpaused_at, s.label_cutover_at) >= coalesce(n.last_raised_at, n.raised_at)
	AND coalesce(d.unpaused_at, s.label_cutover_at) <= clock_timestamp() - $2::interval`

// PersonsDirtyAll makes every person's document due within debounce, as
// PersonsDirty does for some: a change the dirty channel names "all" (an
// account's status) may hide or show the pause notices of anyone.
func (c *Contract) PersonsDirtyAll(ctx context.Context, debounce time.Duration) error {
	return retryDeadlock(ctx, func() error {
		_, err := c.pool.Exec(ctx, `UPDATE contract_persons p SET due_at = clock_timestamp() + $1::interval
			FROM (SELECT sub FROM contract_persons WHERE parked_at IS NULL AND tries = 0 AND due_at > clock_timestamp() + $1::interval
			      ORDER BY sub FOR UPDATE) l
			WHERE p.sub = l.sub`, debounce)
		return err
	})
}

// workspacesOfSubs is the workspaces of the accounts linked to subs, in id
// order.
func (c *Contract) workspacesOfSubs(ctx context.Context, subs []uuid.UUID) ([]uuid.UUID, error) {
	seen := map[uuid.UUID]bool{}
	var out []uuid.UUID
	for _, sub := range subs {
		user, err := c.UserOfSub(ctx, sub)
		if err != nil {
			return nil, err
		}
		if user == nil {
			continue
		}
		err = pgx.BeginTxFunc(ctx, c.pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
			if err := scope(ctx, tx, uuid.Nil, *user); err != nil {
				return err
			}
			rows, err := tx.Query(ctx, `SELECT tenant_id FROM workspace_memberships WHERE user_id = $1`, *user)
			if err != nil {
				return err
			}
			ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
			for _, id := range ids {
				if !seen[id] {
					seen[id] = true
					out = append(out, id)
				}
			}
			return err
		})
		if err != nil {
			return nil, err
		}
	}
	slices.SortFunc(out, compareIDs)
	return out, nil
}
