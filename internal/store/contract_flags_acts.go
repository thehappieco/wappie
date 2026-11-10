package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kc "github.com/thehappieco/kit/contract"
)

// The console's flags kinds on a number (step 12b's F1; the plan's 3.1,
// 5.1, DS18 to DS24): item.flags_raise, item.flags_drop and
// item.access_remove. Each runs in numbersAct's one transaction, in its
// lock order (3.2): the record, the ledger row, the wseq memory, the
// tenants row, then the number (FOR SHARE), and the permission row and the
// grants through setDevicePermissionTx, the write Wappie's own screen
// makes. Target refusals come before the role (12a's R5, then R6); a ran
// never does. A ran makes the numbers section and the snapshot due now:
// these kinds show in the snapshot (the spec's 14.7). Wappie keeps no time
// per flag, so its tightenings never answer state_changed (the spec's
// 14.6). The executor judges R0 to R4 before, and internal/numberacts
// wakes this process's sockets after a write.

// ErrInvalidFlags is a flags command whose params are not a change its
// kind allows: a flag that is not a number's, one listed twice, a raise
// that adds read or nothing, a drop that adds a flag or takes none. The
// kit refuses these at take (ValidateIn); the act checks again and writes
// nothing. The executor answers it invalid_command, which carries no
// state_seq (the kit's ValidateFor).
var ErrInvalidFlags = errors.New("store: a flags command's params are not a change its kind allows")

// flagsOf reads a contract flags list (the snapshot's can of a number:
// read, send and manage, each once) as a permission's flags.
func flagsOf(can []string) (DevicePermission, error) {
	var p DevicePermission
	for _, f := range can {
		var flag *bool
		switch f {
		case kc.CanRead:
			flag = &p.Read
		case kc.CanSend:
			flag = &p.Send
		case kc.CanManage:
			flag = &p.Manage
		default:
			return DevicePermission{}, ErrInvalidFlags
		}
		if *flag {
			return DevicePermission{}, ErrInvalidFlags
		}
		*flag = true
	}
	return p, nil
}

// canOf is p's flags as the contract lists them, in the kit's order.
func canOf(p DevicePermission) []string {
	can := []string{}
	if p.Read {
		can = append(can, kc.CanRead)
	}
	if p.Send {
		can = append(can, kc.CanSend)
	}
	if p.Manage {
		can = append(can, kc.CanManage)
	}
	return can
}

// sameFlags compares two permissions' flags, nothing else.
func sameFlags(a, b DevicePermission) bool {
	return a.Read == b.Read && a.Send == b.Send && a.Manage == b.Manage
}

// within reports whether every flag of a is one of b's.
func within(a, b DevicePermission) bool {
	return (!a.Read || b.Read) && (!a.Send || b.Send) && (!a.Manage || b.Manage)
}

// shownRan is a flags act's ran: the snapshot due now too.
func shownRan() actWrite {
	w := ran()
	w.snapshot = true
	return w
}

// flagsNumberTx reads item of workspace for a flags act and holds it FOR
// SHARE to the commit: found, and whether it is deleted. The read alone
// runs inside withQuarantine (DS21). A number gone, or another
// workspace's, deleted or not, is not found: the row-level security of the
// act's scope and the tenant_id both.
func flagsNumberTx(ctx context.Context, tx pgx.Tx, workspace, item uuid.UUID) (found, deleted bool, err error) {
	err = withQuarantine(ctx, tx, func() error {
		return tx.QueryRow(ctx, `SELECT deleted_at IS NOT NULL FROM devices WHERE id = $1 AND tenant_id = $2 FOR SHARE`,
			item, workspace).Scan(&deleted)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, false, nil
	}
	return err == nil, deleted, err
}

// writeFlagsTx is setDevicePermissionTx for a flags act. A deleted
// number's row is written inside withQuarantine, since 0036's ownership
// trigger reads the number under the caller's policies (WS002 otherwise).
func writeFlagsTx(ctx context.Context, tx pgx.Tx, workspace uuid.UUID, p DevicePermission, dropKeys, deleted bool) error {
	write := func() error { return setDevicePermissionTx(ctx, tx, workspace, p, dropKeys) }
	if deleted {
		return withQuarantine(ctx, tx, write)
	}
	return write()
}

// activeTargetTx reports whether user may be given flags in workspace: an
// active membership with no deadline passed, of an active person (DS22).
func activeTargetTx(ctx context.Context, tx pgx.Tx, workspace, user uuid.UUID) (bool, error) {
	var ok bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM workspace_memberships m JOIN users u ON u.id = m.user_id
		WHERE m.tenant_id = $1 AND m.user_id = $2 AND m.status = 'active' AND u.status = 'active'
		  AND (m.expires_at IS NULL OR m.expires_at > now()))`, workspace, user).Scan(&ok)
	return ok, err
}

// memberRowTx reports whether user has any membership row in workspace,
// a suspended or an expired one included (DS22).
func memberRowTx(ctx context.Context, tx pgx.Tx, workspace, user uuid.UUID) (bool, error) {
	var ok bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM workspace_memberships WHERE tenant_id = $1 AND user_id = $2)`,
		workspace, user).Scan(&ok)
	return ok, err
}

// wroteRan reports whether an act ran and its last try wrote.
func wroteRan(act ContractAct, wrote bool, err error) bool {
	return err == nil && wrote && act.Result.Outcome == CommandRan
}

// RunFlagsRaise is item.flags_raise for the local account user (Wappie's
// screen is PUT …/permissions with flags added): the number live (a
// deleted one of the workspace is state_changed, as the platform's own
// retry answers it; one gone or another workspace's is not_found), user an
// active member (not_found), the actor's RuleAdmin (not_authorized, DS18),
// params.before against the stored flags as a set (state_changed), then
// after written. It never touches a grant: a raise never adds read, and
// Wappie's send and manage need no key, so grant_needed is never answered
// (DS24). wrote reports a ran that wrote the row.
func (c *Contract) RunFlagsRaise(ctx context.Context, run ContractRun, item, user uuid.UUID, before, after []string) (act ContractAct, wrote bool, err error) {
	was, errWas := flagsOf(before)
	next, errNext := flagsOf(after)
	if errWas != nil || errNext != nil || !within(was, next) || sameFlags(was, next) || next.Read && !was.Read {
		return ContractAct{}, false, ErrInvalidFlags
	}
	next.DeviceID, next.UserID = item, user
	act, err = c.numbersAct(ctx, run, func(tx pgx.Tx) (actWrite, error) {
		wrote = false
		found, deleted, err := flagsNumberTx(ctx, tx, run.Workspace, item)
		switch {
		case err != nil:
			return actWrite{}, err
		case !found:
			return refusedWith(kc.CodeNotFound), nil
		case deleted:
			return refusedWith(kc.CodeStateChanged), nil
		}
		target, err := activeTargetTx(ctx, tx, run.Workspace, user)
		switch {
		case err != nil:
			return actWrite{}, err
		case !target:
			return refusedWith(kc.CodeNotFound), nil
		}
		roles, err := actorRolesTx(ctx, tx, run, nil)
		switch {
		case err != nil:
			return actWrite{}, err
		case !roles.Allows(RuleAdmin):
			return refusedWith(kc.CodeNotAuthorized), nil
		}
		stored, err := storedDevicePermissionTx(ctx, tx, run.Workspace, user, item)
		switch {
		case err != nil:
			return actWrite{}, err
		case !sameFlags(stored, was):
			return refusedWith(kc.CodeStateChanged), nil
		}
		if err := writeFlagsTx(ctx, tx, run.Workspace, next, false, false); err != nil {
			return actWrite{}, err
		}
		wrote = true
		return shownRan(), nil
	})
	return act, wroteRan(act, wrote, err), err
}

// RunFlagsDrop is item.flags_drop for the local account user, a
// tightening (DS19): the flags params.before has and params.after has not
// are taken from the stored ones, so a flag raised since stays. When read
// is among them, every grant of user on the number goes, at every epoch,
// even when the flag was gone already (no dormant key, 0040), unless user
// is its last reader (last_reader). It runs as access_remove does
// (tightenFlags). wrote reports a ran that wrote.
func (c *Contract) RunFlagsDrop(ctx context.Context, run ContractRun, item, user uuid.UUID, before, after []string) (ContractAct, bool, error) {
	was, errWas := flagsOf(before)
	next, errNext := flagsOf(after)
	if errWas != nil || errNext != nil || !within(next, was) || sameFlags(was, next) {
		return ContractAct{}, false, ErrInvalidFlags
	}
	removed := DevicePermission{Read: was.Read && !next.Read, Send: was.Send && !next.Send, Manage: was.Manage && !next.Manage}
	return c.tightenFlags(ctx, run, item, user, func(stored DevicePermission) (DevicePermission, bool) {
		return DevicePermission{DeviceID: item, UserID: user,
			Read: stored.Read && !removed.Read, Send: stored.Send && !removed.Send, Manage: stored.Manage && !removed.Manage}, removed.Read
	})
}

// RunAccessRemove is item.access_remove for the local account user, a
// tightening (DS20): all three flags false with the row kept, so a later
// key share gives no read or send (0023's grant_initial_permissions), and
// every grant of user on the number deleted, also for a key holder without
// read, unless user is its last reader (last_reader). wrote reports a ran
// that wrote.
func (c *Contract) RunAccessRemove(ctx context.Context, run ContractRun, item, user uuid.UUID) (ContractAct, bool, error) {
	return c.tightenFlags(ctx, run, item, user, func(DevicePermission) (DevicePermission, bool) {
		return DevicePermission{DeviceID: item, UserID: user}, true
	})
}

// tightenFlags is a drop's and a remove's act: the number of the
// workspace, a deleted one included (DS21; not_found otherwise), the
// actor's RuleAdmin; a person with no membership row at all has nothing to
// take (ran, DS22), while a suspended or expired one's flags and grants go
// as an active one's. change maps the stored flags to the new ones and
// says whether the keys go; a change that changes nothing writes nothing.
func (c *Contract) tightenFlags(ctx context.Context, run ContractRun, item, user uuid.UUID,
	change func(stored DevicePermission) (DevicePermission, bool)) (ContractAct, bool, error) {
	var wrote bool
	act, err := c.numbersAct(ctx, run, func(tx pgx.Tx) (actWrite, error) {
		wrote = false
		found, deleted, err := flagsNumberTx(ctx, tx, run.Workspace, item)
		switch {
		case err != nil:
			return actWrite{}, err
		case !found:
			return refusedWith(kc.CodeNotFound), nil
		}
		roles, err := actorRolesTx(ctx, tx, run, nil)
		switch {
		case err != nil:
			return actWrite{}, err
		case !roles.Allows(RuleAdmin):
			return refusedWith(kc.CodeNotAuthorized), nil
		}
		member, err := memberRowTx(ctx, tx, run.Workspace, user)
		switch {
		case err != nil:
			return actWrite{}, err
		case !member:
			return shownRan(), nil
		}
		stored, err := storedDevicePermissionTx(ctx, tx, run.Workspace, user, item)
		if err != nil {
			return actWrite{}, err
		}
		next, dropKeys := change(stored)
		if sameFlags(stored, next) && !dropKeys {
			return shownRan(), nil
		}
		err = writeFlagsTx(ctx, tx, run.Workspace, next, dropKeys, deleted)
		switch {
		case errors.Is(err, ErrLastDeviceReader):
			return refusedWith(kc.CodeLastReader), nil
		case err != nil:
			return actWrite{}, err
		}
		wrote = true
		return shownRan(), nil
	})
	return act, wroteRan(act, wrote, err), err
}

// StoredFlags is what the executor's R4 reads of a flags command's target
// before the act (DS23): user's stored flags on item, as the snapshot's
// can lists them, and whether user holds its key at an epoch not retired.
// It reads them as a drop does, a deleted number's included (the query
// never reads devices), and as Wappie's own screen's freshness hook does
// (StoredDevicePermission). A number of another workspace has none.
func (c *Contract) StoredFlags(ctx context.Context, workspace, item, user uuid.UUID) (can []string, holdsKey bool, err error) {
	var p DevicePermission
	err = readOnly(ctx, c, func(tx pgx.Tx) error {
		if err := scope(ctx, tx, workspace, uuid.Nil); err != nil {
			return err
		}
		var err error
		p, err = storedDevicePermissionTx(ctx, tx, workspace, user, item)
		return err
	})
	if err != nil {
		return nil, false, err
	}
	return canOf(p), p.HasKey, nil
}

// FlagsTargetActive is the executor's look at a raise's target before R4
// (step 12b's F2; the platform's Q6, DS22): user an active, unexpired
// member of workspace with an active local account, and sub's stored
// document active, with no disablement seen later than the one it carries
// (contract_accounts keeps the latest seen). Anything else is a final
// not_found: no retry lifts a suspension, so the raise is never left to
// R4's memberships_unconfirmed. Read-only; the act checks the membership
// again in its transaction.
func (c *Contract) FlagsTargetActive(ctx context.Context, workspace, user, sub uuid.UUID) (bool, error) {
	var ok bool
	err := readOnly(ctx, c, func(tx pgx.Tx) error {
		ok = false
		if err := scope(ctx, tx, workspace, uuid.Nil); err != nil {
			return err
		}
		member, err := activeTargetTx(ctx, tx, workspace, user)
		if err != nil || !member {
			return err
		}
		return tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM contract_accounts WHERE sub = $1 AND status = 'active'
			AND (disabled_at IS NULL OR disabled_at <= coalesce((doc->>'disabled_at')::timestamptz, '-infinity')))`, sub).Scan(&ok)
	})
	return ok, err
}
