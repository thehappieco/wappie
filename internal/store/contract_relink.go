package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/pg"
	"whatserver2/internal/wa"
)

// The console's item.relink (kit v0.11.0; the spec's 14.13 and the kit's
// SPEC 11.19, "Linking a number again"): a kind whose first result is
// in_progress. Its checks before the pairing are a judgement that writes
// nothing (JudgeRelink) and the relink's own (relink.Service.Check); then
// StartRelinkCommand writes in_progress in the transaction that starts the
// act, so the workspace's next command runs while the person scans; the
// final result replaces it only while it is still in_progress: ran in the
// attach's own transaction (AttachRelinkCommand), any other end through
// FinishInProgress. A row left in_progress (a restart, another leader) is
// found by InProgressRelinks and answered by the leader's sweep.

// lockInProgressCommandTx locks the command's ledger row, which must be
// in_progress and within its 30 days: ErrCommandFinished otherwise
// (lockOpenCommandTx's counterpart for a final result).
func lockInProgressCommandTx(ctx context.Context, tx pgx.Tx, id uuid.UUID) error {
	tag, err := tx.Exec(ctx, `SELECT 1 FROM contract_commands WHERE id = $1 AND outcome = 'in_progress' AND `+commandLive+` FOR UPDATE`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrCommandFinished
	}
	return nil
}

// finishInProgressTx writes id's final result over its in_progress, by
// compare-and-set (ErrCommandFinished when it is not in_progress), and
// makes it undelivered afresh: the in_progress was posted, or is being
// posted, and the final one goes in turn (the settle compares result_at).
// A result of another generation's command is dropped at once, as
// finishCommandTx drops it. The wseq memory was kept with the in_progress,
// which counted as run.
func finishInProgressTx(ctx context.Context, tx pgx.Tx, id uuid.UUID, r CommandResult) error {
	var retry *int
	if r.RetryAfter > 0 {
		retry = &r.RetryAfter
	}
	var code *string
	if r.Code != "" {
		code = &r.Code
	}
	tag, err := tx.Exec(ctx, `WITH now AS (SELECT clock_timestamp() AS t, (SELECT generation FROM contract_state) AS gen)
		UPDATE contract_commands c SET outcome = $2, code = $3, retry_after = $4, state_seq = $5, detail = $6,
			result_at = now.t, run_after = NULL,
			delivery = CASE WHEN c.generation IS DISTINCT FROM now.gen THEN 'dropped' END,
			delivered_at = CASE WHEN c.generation IS DISTINCT FROM now.gen THEN now.t END,
			reject_code = NULL, post_tries = 0, post_error = NULL
		FROM now WHERE c.id = $1 AND c.outcome = 'in_progress' AND c.`+commandLive,
		id, r.Outcome, code, retry, r.StateSeq, jsonOrNil(r.Detail))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrCommandFinished
	}
	return nil
}

// FinishInProgress writes the final result r of a row left in_progress
// (an item.relink that ended other than linked), in 3.4's order: the
// workspace's record, then the row. With no StateSeq, the judged seq is
// filled as RefuseCommand fills it (never for expired and invalid_command);
// the numbers section is due now, so its can_relink is sent again.
// ErrCommandFinished when the row is not in_progress (the attach answered
// it ran, or another leader's sweep answered it).
func (c *Contract) FinishInProgress(ctx context.Context, id uuid.UUID, r CommandResult) error {
	if r.Outcome == "" {
		r.Outcome = CommandRefused
	}
	return retryDeadlock(ctx, func() error {
		return pg.InTx(ctx, c.pool, func(tx pgx.Tx) error {
			var workspace *uuid.UUID
			err := tx.QueryRow(ctx, `SELECT workspace_id FROM contract_commands WHERE id = $1 AND outcome = 'in_progress'`, id).Scan(&workspace)
			if errors.Is(err, pgx.ErrNoRows) || err == nil && workspace == nil {
				return ErrCommandFinished
			}
			if err != nil {
				return err
			}
			judged := int64(1)
			err = tx.QueryRow(ctx, `SELECT greatest(sections_seq, snapshot_seq, 1) FROM contract_workspaces
				WHERE workspace_id = $1 FOR UPDATE`, *workspace).Scan(&judged)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			if r.StateSeq == nil && r.Code != CommandExpired && r.Code != CommandInvalid {
				r.StateSeq = &judged
			}
			if err := lockInProgressCommandTx(ctx, tx, id); err != nil {
				return err
			}
			if err := finishInProgressTx(ctx, tx, id, r); err != nil {
				return err
			}
			return actSectionDueTx(ctx, tx, *workspace)
		})
	})
}

// JudgeRelink is item.relink's judgement before the relink's own checks,
// writing nothing when it passes (the act goes on): the number live (a
// deleted one not recovered is not_found), then item_busy while this
// process pairs it (busy's retry_after, in seconds) or a move holds it,
// judged before the role as the spec's 14.6 orders it, then the actor's
// RuleAdmin (owners and admins).
func (c *Contract) JudgeRelink(ctx context.Context, run ContractRun, item uuid.UUID, busy func(uuid.UUID) (int, bool)) (ContractAct, error) {
	return c.numbersAct(ctx, run, func(tx pgx.Tx) (actWrite, error) {
		var cause string
		err := tx.QueryRow(ctx, `SELECT coalesce(pause_cause, '') FROM devices WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL FOR UPDATE`,
			item, run.Workspace).Scan(&cause)
		if errors.Is(err, pgx.ErrNoRows) {
			return refusedWith(kc.CodeNotFound), nil
		}
		if err != nil {
			return actWrite{}, err
		}
		wait, held := 0, false
		if busy != nil {
			wait, held = busy(item)
		}
		if !held && cause == PauseForMove {
			// A move's pause: the relink's Check answers it so too, with
			// WhatsApp's whole window (the platform's question 1's default).
			wait, held = int(wa.PairWindow/time.Second), true
		}
		if held {
			w := refusedWith(kc.CodeItemBusy)
			w.result.RetryAfter = min(max(wait, 1), kc.MaxRetryAfter)
			return w, nil
		}
		roles, err := actorRolesTx(ctx, tx, run, &item)
		if err != nil {
			return actWrite{}, err
		}
		if !roles.Allows(RuleAdmin) {
			return refusedWith(kc.CodeNotAuthorized), nil
		}
		return actWrite{open: true}, nil
	})
}

// StartRelinkCommand writes item.relink's in_progress, at the act's seq
// (the state it judged on), in the transaction that starts the act: the
// number still live (not_found), still logged out, paused no more since
// the relink's Check (seen) and not held by a move (state_changed), and no
// pause later than the command's based_on.state_seq (state_changed, the
// pause kept: the spec's 14.13), compared in milliseconds on the clock the
// workspace's seq counts on. basedOn nil compares nothing. A started relink
// is never run again: the row is in_progress before the pairing starts.
func (c *Contract) StartRelinkCommand(ctx context.Context, run ContractRun, item uuid.UUID, seen RelinkSeen, basedOn *int64) (ContractAct, error) {
	return c.numbersAct(ctx, run, func(tx pgx.Tx) (actWrite, error) {
		var status, cause string
		var pauseSeq int64
		var pausedLater bool
		err := tx.QueryRow(ctx, `SELECT status, pause_seq, coalesce(pause_cause, ''),
				coalesce(paused AND paused_at IS NOT NULL AND $3::bigint IS NOT NULL
				  AND floor(extract(epoch FROM paused_at) * 1000)::bigint > $3::bigint, false)
			FROM devices WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL FOR UPDATE`,
			item, run.Workspace, basedOn).Scan(&status, &pauseSeq, &cause, &pausedLater)
		if errors.Is(err, pgx.ErrNoRows) {
			return refusedWith(kc.CodeNotFound), nil
		}
		if err != nil {
			return actWrite{}, err
		}
		if status != string(wa.StatusLoggedOut) || pauseSeq != seen.PauseSeq || cause == PauseForMove || pausedLater {
			return refusedWith(kc.CodeStateChanged), nil
		}
		return actWrite{result: CommandResult{Outcome: CommandInProgress}}, nil
	})
}

// AttachRelinkCommand writes a relink's new link into the number and its
// command's ran in one transaction, in 3.4's order: the workspace's record
// (the act's seq), the command's row (still in_progress, else
// ErrCommandFinished and nothing attached: another end answered it, and
// the link is discarded), the wseq memory, the scope, then the attach's
// compare-and-set (attachRelinkTx: tenants, then the number), the result
// at the act's seq, and the numbers section and the snapshot due now (the
// spec's 14.13: both show it at that seq).
func (c *Contract) AttachRelinkCommand(ctx context.Context, run ContractRun, device uuid.UUID, seen RelinkSeen, linked wa.Identity) (ContractAct, Attached, error) {
	var out ContractAct
	var att Attached
	err := retryDeadlock(ctx, func() error {
		out, att = ContractAct{}, Attached{}
		return pg.InTx(ctx, c.pool, func(tx pgx.Tx) error {
			seq, err := actSeqTx(ctx, tx, run.Workspace)
			if err != nil {
				return err
			}
			if err := lockInProgressCommandTx(ctx, tx, run.ID); err != nil {
				return err
			}
			if err := lockWSeqTx(ctx, tx, run.Workspace); err != nil {
				return err
			}
			if err := scope(ctx, tx, run.Workspace, uuid.Nil); err != nil {
				return err
			}
			if att, err = attachRelinkTx(ctx, tx, run.Workspace, device, seen, linked); err != nil {
				return err
			}
			r := CommandResult{Outcome: CommandRan, StateSeq: &seq}
			if err := finishInProgressTx(ctx, tx, run.ID, r); err != nil {
				return err
			}
			out = ContractAct{Result: r, Seq: seq}
			if err := actSectionDueTx(ctx, tx, run.Workspace); err != nil {
				return err
			}
			return snapshotDueNowTx(ctx, tx, run.Workspace)
		})
	})
	if err != nil {
		return ContractAct{}, Attached{}, err
	}
	return out, att, nil
}

// InProgressRelink is an item.relink row left in_progress: its command,
// workspace and number (uuid.Nil for an item that names none of Wappie's).
type InProgressRelink struct {
	ID, Workspace, Device uuid.UUID
}

// InProgressRelinks reads every item.relink row in_progress within its 30
// days, in take order: what the leader's sweep answers once no pairing of
// its number runs here.
func (c *Contract) InProgressRelinks(ctx context.Context) ([]InProgressRelink, error) {
	rows, err := c.pool.Query(ctx, `SELECT id, workspace_id, coalesce(target->>'item', '') FROM contract_commands
		WHERE kind = $1 AND outcome = 'in_progress' AND workspace_id IS NOT NULL AND `+commandLive+` ORDER BY take_seq`, kc.OpItemRelink)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (InProgressRelink, error) {
		var r InProgressRelink
		var item string
		if err := row.Scan(&r.ID, &r.Workspace, &item); err != nil {
			return r, err
		}
		if id, err := uuid.Parse(item); err == nil {
			r.Device = id
		}
		return r, nil
	})
}
