package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/label"
	"whatserver2/internal/pg"
	"whatserver2/internal/wa"
)

// The console's acts on a platform workspace's numbers (step 12a's commands
// release; the plan's 6.2 and 6.3). Each runs in one transaction in the one
// lock order (DS14): the workspace's record first (the act's seq on the
// workspace's one clock, DS3), the command's ledger row (still without a
// result), the wseq memory, the workspace's tenants row, then the number and
// its notices, the result, and last the numbers section (and, for a rename,
// the snapshot) due now. The target is checked before the role (R5, then
// R6): a number that is deleted, or another workspace's, is not_found, as
// on Wappie's own screens; then the actor's local role and the stored
// document's role must both allow the kind (DS15). Every result, a refusal
// included, is written in its act's transaction at the act's seq. The
// executor (internal/membership) judges R0 to R4 before, and
// internal/numberacts does what the socket's frames do around these
// transactions.

// ContractRun is one ledger row an act runs: its id, the workspace (nil for
// a person's kind), the actor's sub and the local account linked to it.
type ContractRun struct {
	ID        uuid.UUID
	Workspace uuid.UUID
	Sub       uuid.UUID
	User      uuid.UUID
}

// ContractAct is what an act's transaction wrote: its result and the seq it
// was written at (the result's state_seq). Open is a judgement that wrote
// nothing: the act goes on outside it (a sync now's start, a
// registration's pairing cancelled), and a later transaction answers it.
type ContractAct struct {
	Result CommandResult
	Seq    int64
	Open   bool
}

// ActRule is who may run a numbers kind (the plan's 6.2): the rule of
// Wappie's own screens and the stored document's role, both (DS15).
type ActRule int

const (
	// RuleManage is item.rename's: the local ActionManage (an owner, an
	// admin, or the Manage flag), and the document's owner or admin, or its
	// member when the local Manage is the flag's.
	RuleManage ActRule = iota + 1
	// RulePause is item.sync_stop's and item.sync_resume's: the local
	// ActionPause (the role owner or admin; a personal workspace's person
	// is its owner), and the document's owner or admin.
	RulePause
	// RuleRead is item.sync_now's for a person (the platform's answer 4):
	// the local ActionRead (Read and the key at the current epoch), and any
	// role in the document.
	RuleRead
	// RuleAdmin is item.registration_delete's: the local role owner or
	// admin (deletePending's requireAdmin), and the document's owner or
	// admin.
	RuleAdmin
)

// ActorRoles is what an act's transaction reads of its actor.
type ActorRoles struct {
	// Local is the actor's role in the workspace: an active, unexpired
	// membership of an active account in an active workspace; "" for none.
	Local string
	// Device is the actor's permission on the number (devicePermissionTx);
	// HasDevice is false when there is none (no membership, or no live
	// number).
	Device    DevicePermission
	HasDevice bool
	// Flag is the stored Manage flag on the number.
	Flag bool
	// Doc is the role the actor's stored document of the current
	// generation gives the workspace; "" when it names it not, or the
	// document is not active.
	Doc string
}

// Allows reports whether both sides allow rule: a local role the document
// does not confirm, or the reverse, fails closed.
func (r ActorRoles) Allows(rule ActRule) bool {
	switch rule {
	case RuleManage:
		return r.HasDevice && r.Device.Allows(ActionManage) && (managerRole(r.Doc) || r.Doc == "member" && r.Flag)
	case RulePause:
		return r.HasDevice && r.Device.Allows(ActionPause) && managerRole(r.Local) && managerRole(r.Doc)
	case RuleRead:
		return r.HasDevice && r.Device.Allows(ActionRead) && (managerRole(r.Doc) || r.Doc == "member")
	case RuleAdmin:
		return managerRole(r.Local) && managerRole(r.Doc)
	}
	return false
}

// actorRolesTx reads run's actor in tx, scoped to its workspace: the local
// membership's role, the permission on device (none for a nil one), and
// the role the stored document gives the workspace, which it reads with no
// lock (DS14: an act never locks what comes before its record).
func actorRolesTx(ctx context.Context, tx pgx.Tx, run ContractRun, device *uuid.UUID) (ActorRoles, error) {
	var r ActorRoles
	if err := tx.QueryRow(ctx, `SELECT
		coalesce((SELECT m.role FROM workspace_memberships m JOIN users u ON u.id = m.user_id JOIN tenants t ON t.id = m.tenant_id
			WHERE m.tenant_id = $1 AND m.user_id = $2 AND m.status = 'active' AND u.status = 'active' AND t.status = 'active'
			  AND (m.expires_at IS NULL OR m.expires_at > now())), ''),
		coalesce((SELECT w->>'role' FROM contract_accounts a,
				jsonb_array_elements(CASE WHEN jsonb_typeof(a.doc->'workspaces') = 'array' THEN a.doc->'workspaces' ELSE '[]'::jsonb END) w
			WHERE a.sub = $3 AND a.status = 'active' AND a.generation = (SELECT generation FROM contract_state)
			  AND w->>'id' = $1::text LIMIT 1), '')`,
		run.Workspace, run.User, run.Sub).Scan(&r.Local, &r.Doc); err != nil {
		return r, err
	}
	if device == nil {
		return r, nil
	}
	p, err := devicePermissionTx(ctx, tx, run.Workspace, run.User, *device)
	switch {
	case errors.Is(err, ErrNotFound):
	case err != nil:
		return r, err
	default:
		r.Device, r.HasDevice = p, true
	}
	err = tx.QueryRow(ctx, `SELECT coalesce(bool_or(can_manage), false) FROM device_permissions
		WHERE tenant_id = $1 AND device_id = $2 AND user_id = $3`, run.Workspace, *device, run.User).Scan(&r.Flag)
	return r, err
}

// actWrite is what an act's own part decided: the result (its seq filled
// in after), whether it shows in the snapshot, or open, a judgement that
// writes nothing.
type actWrite struct {
	result   CommandResult
	snapshot bool
	open     bool
}

func refusedWith(code string) actWrite {
	return actWrite{result: CommandResult{Outcome: CommandRefused, Code: code}}
}

func ran() actWrite { return actWrite{result: CommandResult{Outcome: CommandRan}} }

// errActOpen rolls back a judgement that passed: it writes nothing.
var errActOpen = errors.New("store: the act was judged and goes on")

// lockOpenCommandTx locks the command's ledger row, which must still have
// no result and be within its 30 days: ErrCommandFinished otherwise
// (another leader answered it, or a copy finished it).
func lockOpenCommandTx(ctx context.Context, tx pgx.Tx, id uuid.UUID) error {
	tag, err := tx.Exec(ctx, `SELECT 1 FROM contract_commands WHERE id = $1 AND outcome IS NULL AND `+commandLive+` FOR UPDATE`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrCommandFinished
	}
	return nil
}

// lockWSeqTx locks the workspace's wseq memory of Wappie's producer, when
// it has one, before the tenants row: the result's transaction writes it
// (finishCommandTx), and 3.4's order puts it there.
func lockWSeqTx(ctx context.Context, tx pgx.Tx, workspace uuid.UUID) error {
	_, err := tx.Exec(ctx, `SELECT 1 FROM contract_command_wseq WHERE workspace_id = $1 AND producer = $2 FOR UPDATE`,
		workspace, ProducerWappie)
	return err
}

// numbersAct runs one act of a numbers kind in one transaction in 3.4's
// order: the record (the act's seq), the ledger row, the wseq memory, the
// workspace's tenants row (not_found when Wappie has no workspace of that
// id), then body, then the result at the act's seq, and the numbers
// section, and for a write the snapshot shows the snapshot, due now. A team
// the record holds closed is team_closed before body: the executor's R3
// read it open outside this transaction, and a document stored since (R4's
// freshness keeps the actor's) may have closed it. A body that leaves the
// act open rolls back: a judgement writes nothing.
func (c *Contract) numbersAct(ctx context.Context, run ContractRun, body func(tx pgx.Tx) (actWrite, error)) (ContractAct, error) {
	var out ContractAct
	err := retryDeadlock(ctx, func() error {
		out = ContractAct{}
		err := pg.InTx(ctx, c.pool, func(tx pgx.Tx) error {
			seq, err := actSeqTx(ctx, tx, run.Workspace)
			if err != nil {
				return err
			}
			if err := lockOpenCommandTx(ctx, tx, run.ID); err != nil {
				return err
			}
			if err := lockWSeqTx(ctx, tx, run.Workspace); err != nil {
				return err
			}
			// The record is this transaction's (actSeqTx): its status
			// cannot change before the commit.
			var status string
			if err := tx.QueryRow(ctx, `SELECT coalesce(status, '') FROM contract_workspaces WHERE workspace_id = $1`,
				run.Workspace).Scan(&status); err != nil {
				return err
			}
			if err := scope(ctx, tx, run.Workspace, uuid.Nil); err != nil {
				return err
			}
			tag, err := tx.Exec(ctx, `SELECT 1 FROM tenants WHERE id = $1 FOR UPDATE`, run.Workspace)
			if err != nil {
				return err
			}
			w := refusedWith(kc.CodeNotFound)
			switch {
			case tag.RowsAffected() == 0:
			case status == "closed":
				w = refusedWith(kc.CodeTeamClosed)
			default:
				if w, err = body(tx); err != nil {
					return err
				}
			}
			out.Seq = seq
			if w.open {
				out.Open = true
				return errActOpen
			}
			w.result.StateSeq = &seq
			out.Result = w.result
			if err := finishCommandTx(ctx, tx, run.ID, w.result); err != nil {
				return err
			}
			if err := actSectionDueTx(ctx, tx, run.Workspace); err != nil {
				return err
			}
			if w.snapshot {
				return snapshotDueNowTx(ctx, tx, run.Workspace)
			}
			return nil
		})
		if errors.Is(err, errActOpen) {
			return nil
		}
		return err
	})
	return out, err
}

// actSectionDueTx makes the workspace's numbers section due now after an
// act, a parked one's included, for one try (its not_found run stays), as
// a leader's start does (SectionsDue): the console shows an act's result
// once a section at or above its seq is accepted, and a parked one is
// never sent (the spec's 14.2: at once for a change a command made). The
// trigger wakes the leader's sender, whichever process acted.
func actSectionDueTx(ctx context.Context, tx pgx.Tx, workspace uuid.UUID) error {
	_, err := tx.Exec(ctx, `INSERT INTO contract_sections (workspace_id, section) VALUES ($1, $2)
		ON CONFLICT (workspace_id, section) DO UPDATE SET due_at = clock_timestamp(), parked_at = NULL`, workspace, SectionNumbers)
	return err
}

// RunRename is item.rename (the plan's 6.3; the frame is device.rename):
// the number live, the actor's RuleManage, params.before against the label
// Wappie publishes (label.Contract, never the one stored: state_changed),
// a label Wappie would set aside (a placeholder, an id, the number itself:
// not_authorized, nothing stored, DS10), the new label as the contract
// cleans it (label_changed with the cleaned text otherwise), then the
// label stored as the frame stores it. The snapshot and the numbers
// section are due now.
func (c *Contract) RunRename(ctx context.Context, run ContractRun, item uuid.UUID, before *string, after string) (ContractAct, error) {
	return c.numbersAct(ctx, run, func(tx pgx.Tx) (actWrite, error) {
		var stored, pn string
		err := tx.QueryRow(ctx, `SELECT label, coalesce(pn, '') FROM devices WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL FOR UPDATE`,
			item, run.Workspace).Scan(&stored, &pn)
		if errors.Is(err, pgx.ErrNoRows) {
			return refusedWith(kc.CodeNotFound), nil
		}
		if err != nil {
			return actWrite{}, err
		}
		roles, err := actorRolesTx(ctx, tx, run, &item)
		if err != nil {
			return actWrite{}, err
		}
		if !roles.Allows(RuleManage) {
			return refusedWith(kc.CodeNotAuthorized), nil
		}
		if published := label.Contract(stored, pn, item.String()); !sameLabel(published, before) {
			return refusedWith(kc.CodeStateChanged), nil
		}
		switch cleaned := label.Clean(after); {
		case cleaned == "":
			// A label the contract leaves nothing of: the console offers
			// none (the kit's ValidLabel), so its state was not Wappie's.
			return refusedWith(kc.CodeStateChanged), nil
		case label.Contract(cleaned, pn, item.String()) == nil:
			// A name Wappie sets aside, as cleaned: the snapshot would
			// publish null, the console would show the rename done and
			// the number unnamed. label_changed cannot say null (its
			// detail.cleaned is a label the kit's ValidLabel takes), so
			// it is Wappie's rule that refuses it (the spec's 8.1 and
			// 14.9, DS10), before a label_changed that would offer it.
			return refusedWith(kc.CodeNotAuthorized), nil
		case cleaned != after:
			w := refusedWith(kc.CodeLabelChanged)
			w.result.Detail, err = json.Marshal(map[string]string{"cleaned": cleaned})
			return w, err
		}
		if _, err := tx.Exec(ctx, `UPDATE devices SET label = $2 WHERE id = $1`, item, after); err != nil {
			return actWrite{}, err
		}
		w := ran()
		w.snapshot = true
		return w, nil
	})
}

func sameLabel(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// RunSyncStop is item.sync_stop (the frame is device.stop): the number
// live and the actor's RulePause, then the person branch of a pause
// (consolePauseTx). A number already paused counts as done (the spec's
// 14.7): the stop still counts and makes the pause a person's, and tells
// nobody. It returns what the pause raised, for the sockets after the
// commit.
func (c *Contract) RunSyncStop(ctx context.Context, run ContractRun, item uuid.UUID) (ContractAct, Paused, error) {
	var out Paused
	act, err := c.numbersAct(ctx, run, func(tx pgx.Tx) (actWrite, error) {
		out = Paused{}
		var paused bool
		var cause string
		err := tx.QueryRow(ctx, `SELECT paused, coalesce(pause_cause, '') FROM devices
			WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL FOR UPDATE`, item, run.Workspace).Scan(&paused, &cause)
		if errors.Is(err, pgx.ErrNoRows) {
			return refusedWith(kc.CodeNotFound), nil
		}
		if err != nil {
			return actWrite{}, err
		}
		roles, err := actorRolesTx(ctx, tx, run, &item)
		if err != nil {
			return actWrite{}, err
		}
		if !roles.Allows(RulePause) {
			return refusedWith(kc.CodeNotAuthorized), nil
		}
		if out, err = consolePauseTx(ctx, tx, run.Workspace, item, run.User, paused, cause); err != nil {
			return actWrite{}, err
		}
		return ran(), nil
	})
	return act, out, err
}

// consolePauseTx is the person branch of Devices.Pause (device_notices.go)
// in an act's transaction, which holds the workspace's tenants row and the
// number's: a copy, since that file is step 7's, which
// TestConsoleParityStop holds to it; the shared pauseTx after step 7 folds
// the two. was and cause are the number's pause as the act read it.
//
// A live number is paused as the person's: every reader but the actor gets
// their one unseen sync_paused notice (a new one, or the unseen one folded)
// and the sync_paused event is written, unless nobody but the actor reads
// it. A paused one counts the stop and becomes the person's pause, telling
// nobody. When the stop paused it or changed its cause, a statement of its
// own names the actor (DS7: the trigger cleared it for a new pause); a
// second stop with the same cause keeps the first pause's actor.
func consolePauseTx(ctx context.Context, tx pgx.Tx, tenant, device, actor uuid.UUID, was bool, cause string) (Paused, error) {
	var out Paused
	name := func() error {
		_, err := tx.Exec(ctx, `UPDATE devices SET paused_by_kind = 'person', paused_by_user = $2 WHERE id = $1`, device, actor)
		return err
	}
	if was {
		if _, err := tx.Exec(ctx, `UPDATE devices SET pause_cause = 'person', pause_seq = pause_seq + 1 WHERE id = $1`, device); err != nil {
			return out, err
		}
		if cause != PauseByPerson {
			return out, name()
		}
		return out, nil
	}
	var itemName, pn string
	if err := tx.QueryRow(ctx, `UPDATE devices SET paused = true, pause_cause = 'person', pause_seq = pause_seq + 1
		WHERE id = $1 RETURNING label, coalesce(pn, '')`, device).Scan(&itemName, &pn); err != nil {
		return out, err
	}
	out.Changed, out.ActorKind, out.ActorUser = true, actorPerson, &actor
	readers, err := readersTx(ctx, tx, tenant, device)
	if err != nil {
		return out, err
	}
	var told []uuid.UUID
	subs, users := readerIDs(readers)
	for _, r := range readers {
		if r.UserID != actor {
			told = append(told, r.UserID)
		}
	}
	if len(told) == 0 {
		return out, name()
	}
	lbl, hint := itemLabel(device, itemName, pn)
	rows, err := tx.Query(ctx, `INSERT INTO device_notices (tenant_id, device_id, user_id, kind, label, hint, raised_by, raised_by_kind)
		SELECT $1, $2, u, 'sync_paused', $3, $4, $5, $6 FROM unnest($7::uuid[]) AS u
		ON CONFLICT (tenant_id, device_id, user_id, kind) WHERE seen_at IS NULL DO UPDATE
		SET pauses = device_notices.pauses + 1, last_raised_at = clock_timestamp(), resumed_at = NULL,
		    several_actors = device_notices.several_actors
		      OR (device_notices.raised_by, device_notices.raised_by_kind) IS DISTINCT FROM (excluded.raised_by, excluded.raised_by_kind),
		    raised_by = excluded.raised_by, raised_by_kind = excluded.raised_by_kind,
		    label = excluded.label, hint = excluded.hint
		RETURNING id`, tenant, device, lbl, hint, actor, actorPerson, told)
	if err != nil {
		return out, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return out, err
	}
	rows, err = tx.Query(ctx, `SELECT n.user_id, `+strings.TrimPrefix(noticeColumns, "SELECT ")+`
		WHERE n.tenant_id = $1 AND n.id = ANY($2) ORDER BY n.id`, tenant, ids)
	if err != nil {
		return out, err
	}
	if out.Notices, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (RaisedNotice, error) {
		var r RaisedNotice
		n := &r.Notice
		err := row.Scan(&r.UserID, &n.ID, &n.DeviceID, &n.Kind, &n.Label, &n.Hint, &n.RaisedAt, &n.LastRaisedAt, &n.Pauses,
			&n.SeveralActors, &n.RaisedByName, &n.RaisedByKind, &n.Until, &n.ResumedAt, &n.PurgedAt)
		return r, err
	}); err != nil {
		return out, err
	}
	sub, err := actorSubTx(ctx, tx, actor)
	if err != nil {
		return out, err
	}
	var at time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		return out, err
	}
	out.Recorded = true
	if err := recordEvent(ctx, tx, tenant, itemEvent{
		Type: eventSyncPaused, ItemID: device, DedupeKey: dedupeKey(eventSyncPaused, device, at), OccurredAt: at,
		ActorKind: actorPerson, ActorSub: sub, ActorUserID: &actor, ReaderSubs: subs, ReaderUserIDs: users,
		Label: lbl, Hint: hint,
	}); err != nil {
		return out, err
	}
	return out, name()
}

// RunSyncResume is item.sync_resume (the frame is device.start on a paused
// number): the number live and the actor's RulePause; not paused, or one
// that cannot run (its identity not known, logged out or banned:
// can_resume was false, the relink is its way) is state_changed. A move's
// pause is lifted as any other, as the frame lifts it. The pause is lifted
// and its open notices marked resumed in the same transaction, as the
// relink's attach marks them (DS17), and the number is returned for the
// start after the commit, which never puts the pause back (DS9).
func (c *Contract) RunSyncResume(ctx context.Context, run ContractRun, item uuid.UUID) (ContractAct, Device, error) {
	var dev Device
	act, err := c.numbersAct(ctx, run, func(tx pgx.Tx) (actWrite, error) {
		dev = Device{}
		err := scanDevice(tx.QueryRow(ctx, selectDevices+` AND id = $1 AND tenant_id = $2 FOR UPDATE`, item, run.Workspace), &dev)
		if errors.Is(err, pgx.ErrNoRows) {
			return refusedWith(kc.CodeNotFound), nil
		}
		if err != nil {
			return actWrite{}, err
		}
		roles, err := actorRolesTx(ctx, tx, run, &item)
		if err != nil {
			return actWrite{}, err
		}
		switch {
		case !roles.Allows(RulePause):
			return refusedWith(kc.CodeNotAuthorized), nil
		case !dev.Paused, !dev.Identity.Known(), dev.Status == wa.StatusLoggedOut, dev.Status == wa.StatusBanned:
			return refusedWith(kc.CodeStateChanged), nil
		}
		if _, err := tx.Exec(ctx, `UPDATE devices SET paused = false WHERE id = $1 AND paused`, item); err != nil {
			return actWrite{}, err
		}
		// MarkResumed's statement, in the lifting transaction.
		if _, err := tx.Exec(ctx, `UPDATE device_notices SET resumed_at = clock_timestamp()
			WHERE tenant_id = $1 AND device_id = $2 AND kind = 'sync_paused' AND resumed_at IS NULL AND seen_at IS NULL`,
			run.Workspace, item); err != nil {
			return actWrite{}, err
		}
		dev.Paused, dev.PauseCause = false, ""
		return ran(), nil
	})
	return act, dev, err
}

// JudgeSyncNow is item.sync_now's judgement (the frame is device.start on
// a number not paused), in the frame's order: the number live, the actor's
// RuleRead, then paused (a move's pause included), the storage verdict,
// its identity not known (not_linked), logged out or banned (read_only),
// and a pairing of it in this process (item_busy, busy's retry_after in
// seconds). A refusal is written there; a number that may connect is
// returned with the act open, written nothing, and FinishSyncNow answers
// it once the start is tried.
func (c *Contract) JudgeSyncNow(ctx context.Context, run ContractRun, item uuid.UUID, busy func(uuid.UUID) (int, bool)) (ContractAct, Device, error) {
	var dev Device
	act, err := c.numbersAct(ctx, run, func(tx pgx.Tx) (actWrite, error) {
		dev = Device{}
		err := scanDevice(tx.QueryRow(ctx, selectDevices+` AND id = $1 AND tenant_id = $2`, item, run.Workspace), &dev)
		if errors.Is(err, pgx.ErrNoRows) {
			return refusedWith(kc.CodeNotFound), nil
		}
		if err != nil {
			return actWrite{}, err
		}
		roles, err := actorRolesTx(ctx, tx, run, &item)
		if err != nil {
			return actWrite{}, err
		}
		if !roles.Allows(RuleRead) {
			return refusedWith(kc.CodeNotAuthorized), nil
		}
		var storage bool
		if err := tx.QueryRow(ctx, `SELECT `+snapshotQuotaSQL+` FROM tenants t WHERE t.id = $1`, run.Workspace).Scan(&storage); err != nil {
			return actWrite{}, err
		}
		switch {
		case dev.Paused:
			return refusedWith(kc.CodePaused), nil
		case storage:
			return refusedWith(kc.CodeStoragePaused), nil
		case !dev.Identity.Known():
			return refusedWith(kc.CodeNotLinked), nil
		case dev.Status == wa.StatusLoggedOut, dev.Status == wa.StatusBanned:
			return refusedWith(kc.CodeReadOnly), nil
		}
		if busy != nil {
			if wait, ok := busy(item); ok {
				w := refusedWith(kc.CodeItemBusy)
				w.result.RetryAfter = min(max(wait, 1), kc.MaxRetryAfter)
				return w, nil
			}
		}
		return actWrite{open: true}, nil
	})
	return act, dev, err
}

// FinishSyncNow answers a sync now JudgeSyncNow left open, once its start
// was tried: an act that writes nothing completes its row right after (the
// spec's 14.6), at a new seq, the numbers section due now. ErrCommandFinished
// when another leader answered it meanwhile.
func (c *Contract) FinishSyncNow(ctx context.Context, run ContractRun, r CommandResult) (ContractAct, error) {
	var out ContractAct
	err := retryDeadlock(ctx, func() error {
		out = ContractAct{}
		return pg.InTx(ctx, c.pool, func(tx pgx.Tx) error {
			seq, err := actSeqTx(ctx, tx, run.Workspace)
			if err != nil {
				return err
			}
			if err := lockOpenCommandTx(ctx, tx, run.ID); err != nil {
				return err
			}
			if err := lockWSeqTx(ctx, tx, run.Workspace); err != nil {
				return err
			}
			r.StateSeq = &seq
			out = ContractAct{Result: r, Seq: seq}
			if err := finishCommandTx(ctx, tx, run.ID, r); err != nil {
				return err
			}
			return actSectionDueTx(ctx, tx, run.Workspace)
		})
	})
	return out, err
}

// registrationTx reads a registration of run's workspace and the actor's
// RuleAdmin: not_found for no row (or a deleted number's, or another
// workspace's: every act reads its number by its workspace too, beside the
// scope's row-level security), not_authorized, and state_changed for one
// that linked (an identity or a connection).
func registrationTx(ctx context.Context, tx pgx.Tx, run ContractRun, row uuid.UUID, lock string) (actWrite, bool, error) {
	var linked bool
	err := tx.QueryRow(ctx, `SELECT lid IS NOT NULL OR pn IS NOT NULL OR last_connected_at IS NOT NULL FROM devices
		WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL`+lock, row, run.Workspace).Scan(&linked)
	if errors.Is(err, pgx.ErrNoRows) {
		return refusedWith(kc.CodeNotFound), false, nil
	}
	if err != nil {
		return actWrite{}, false, err
	}
	roles, err := actorRolesTx(ctx, tx, run, nil)
	switch {
	case err != nil:
		return actWrite{}, false, err
	case !roles.Allows(RuleAdmin):
		return refusedWith(kc.CodeNotAuthorized), false, nil
	case linked:
		return refusedWith(kc.CodeStateChanged), false, nil
	}
	return actWrite{}, true, nil
}

// JudgeRegistrationDelete is item.registration_delete's judgement (the
// frame is device.delete's deletePending), writing nothing when it passes:
// the row is the workspace's, the actor's RuleAdmin, never linked. The
// runner then cancels its pairing and stops it before
// RunRegistrationDelete, or the delete races a pairing that may still link.
func (c *Contract) JudgeRegistrationDelete(ctx context.Context, run ContractRun, row uuid.UUID) (ContractAct, error) {
	return c.numbersAct(ctx, run, func(tx pgx.Tx) (actWrite, error) {
		w, ok, err := registrationTx(ctx, tx, run, row, "")
		if ok {
			w.open = true
		}
		return w, err
	})
}

// RunRegistrationDelete deletes a registration that never linked, as the
// frame's DeleteUnpaired does, judged again in its transaction: one that
// linked meanwhile is state_changed, one gone not_found.
func (c *Contract) RunRegistrationDelete(ctx context.Context, run ContractRun, row uuid.UUID) (ContractAct, error) {
	return c.numbersAct(ctx, run, func(tx pgx.Tx) (actWrite, error) {
		w, ok, err := registrationTx(ctx, tx, run, row, " FOR UPDATE")
		if !ok || err != nil {
			return w, err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM devices WHERE id = $1 AND tenant_id = $2 AND lid IS NULL AND pn IS NULL
			AND last_connected_at IS NULL`, row, run.Workspace)
		if err != nil {
			return actWrite{}, err
		}
		if tag.RowsAffected() == 0 {
			return refusedWith(kc.CodeStateChanged), nil
		}
		return ran(), nil
	})
}

// CommandInvalidAnswered stamps the last invalid_command answered, which
// --check reports for a day (the platform alerts contract_command_invalid
// as long): the executor's, for a row whose fields it cannot read, as the
// take stamps its own. A transaction of its own, after the answer's.
func (c *Contract) CommandInvalidAnswered(ctx context.Context) error {
	_, err := c.pool.Exec(ctx, `UPDATE contract_settings_state SET invalid_at = clock_timestamp(), updated_at = clock_timestamp()`)
	return err
}

// ContractCommandFacts is what the executor reads of a row before its act
// (the plan's 3.2, R1 to R3), in one read-only snapshot with no lock.
type ContractCommandFacts struct {
	// User is the local account linked to the actor's sub, nil for none;
	// Followed: Wappie follows the actor with a document.
	User     *uuid.UUID
	Followed bool
	// Versions are the stored document versions of the current
	// generation, of the subs asked.
	Versions map[uuid.UUID]int64
	// Recorded, Kind and Status are the workspace's record (Status ""
	// before a document set it); Local: Wappie has a workspace of its id.
	Recorded, Local bool
	Kind, Status    string
}

// CommandFacts reads what R1 to R3 judge a row by: actor's link and
// document, the stored versions of subs, and workspace's record (nil for a
// person's kind).
func (c *Contract) CommandFacts(ctx context.Context, actor uuid.UUID, subs []uuid.UUID, workspace *uuid.UUID) (ContractCommandFacts, error) {
	out := ContractCommandFacts{Versions: map[uuid.UUID]int64{}}
	err := readOnly(ctx, c, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT (SELECT user_id FROM platform_identities WHERE sub = $1),
			EXISTS (SELECT 1 FROM contract_accounts WHERE sub = $1 AND doc IS NOT NULL)`, actor).Scan(&out.User, &out.Followed); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT a.sub, a.version FROM contract_accounts a JOIN contract_state s ON a.generation = s.generation
			WHERE a.sub = ANY ($1) AND a.version IS NOT NULL`, subs)
		if err != nil {
			return err
		}
		if err := forEachRow(rows, func(row pgx.Rows) error {
			var sub uuid.UUID
			var v int64
			if err := row.Scan(&sub, &v); err != nil {
				return err
			}
			out.Versions[sub] = v
			return nil
		}); err != nil {
			return err
		}
		if workspace == nil {
			return nil
		}
		err = tx.QueryRow(ctx, `SELECT kind, coalesce(status, '') FROM contract_workspaces WHERE workspace_id = $1`, *workspace).
			Scan(&out.Kind, &out.Status)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
		case err != nil:
			return err
		default:
			out.Recorded = true
		}
		return tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tenants WHERE id = $1)`, *workspace).Scan(&out.Local)
	})
	return out, err
}
