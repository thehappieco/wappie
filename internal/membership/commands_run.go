package membership

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/numberacts"
	"whatserver2/internal/store"
)

// The executor's judgement in the commands release (the spec's 14.6; the
// plan's 3.2 and 6.4). Each row is judged in this order, and the first
// check that fails answers it, with the seq it was judged on:
//
//	R0 its kind is in this mode's accepts for its section, Wappie's
//	   producer's (kind_not_accepted);
//	R1 its actor is followed with a document, and linked to a local
//	   account (not_held; a person's with no seq); so is the person its
//	   target names, for the flags kinds (step 12b);
//	R2 every document it was drawn from is applied: based_on.docs at most
//	   the stored version of the current generation (memberships_behind,
//	   retry_after behindRetry);
//	R3 a workspace's kind: the workspace recorded and Wappie's, and open
//	   (not_found, team_closed); then, for item.flags_raise, its target
//	   active locally, read-only (a final not_found: the platform's Q6);
//	R4 the freshness the kind asks before any write (the plan's 3.1; at
//	   observe it only logs): item.sync_stop and item.sync_resume the
//	   actor's in a team (RequireFresh), item.flags_raise the actor's and
//	   the target's in every workspace (RequireWidening), and a drop of
//	   read or an access_remove of someone who reads or holds the key the
//	   minute rule in a team (RequireBackups);
//
// then its kind runs: the numbers kinds through internal/numberacts, a
// person's through person_kinds.go, each checking its target (R5) before
// the roles (R6) in its act's transaction, which writes the result. A
// store error that is no verdict backs the row off (executor.go).
//
// A tightening delivered again (again: after Wappie's own restore) is
// never answered with a retry when it is of a kind this binary runs: the
// platform keeps the first result, takes the same outcome and code as a
// duplicate and any other as a conflict, and never issues it again (the
// spec's 14.8), so a retry would leave undone what the tightening took
// away. Where R0 to R4 (a mode that does not run it yet, a document not yet
// applied), or a store error that keeps failing, would answer it with one,
// it waits instead (againWaits) and is judged again, as long as it takes.

// behindRetry is memberships_behind's retry_after: the actor's newer
// document reaches Wappie within the account feed's long-poll.
const behindRetry = 5 * time.Second

var (
	// errUnreadable is a row whose decoded fields the executor cannot read:
	// ValidateIn passed at take, so it is Wappie's bug, answered
	// invalid_command with an ERROR.
	errUnreadable = errors.New("membership: a command's fields cannot be read")
	// errNotOurs is a target that names nothing of Wappie's: not_found.
	errNotOurs = errors.New("membership: a command's target is not one of Wappie's ids")
	// errNotRun is a kind this binary has no runner for.
	errNotRun = errors.New("membership: no runner for the command's kind")
)

// runCommand judges one row and runs its kind; false when neither a result
// nor a failed run could be recorded.
func (sw *settingsWork) runCommand(ctx context.Context, cmd store.ContractCommand) bool {
	l, c := sw.l, sw.l.Members.Contract
	// A tightening delivered again of a kind this binary runs waits rather
	// than be answered with a retry; one it never runs is answered.
	waits := cmd.Again && cmd.Producer == store.ProducerWappie && slices.Contains(runs[cmd.Section], cmd.Kind)
	failed := func(err error) bool {
		if waits {
			return sw.againWaits(ctx, cmd, storeClass(err), err)
		}
		return sw.runFailed(ctx, cmd, err)
	}
	refuse := func(r store.CommandResult, at string) bool {
		if waits && againRetry(cmd.Kind, r.Code) {
			return sw.againWaits(ctx, cmd, "again_"+r.Code, nil)
		}
		r.Outcome = store.CommandRefused
		err := c.RefuseCommand(ctx, cmd.ID, r)
		if err == nil || ctx.Err() != nil {
			if err == nil {
				l.log().Info("contract: a command was refused", "id", cmd.ID, "kind", cmd.Kind, "code", r.Code, "at", at)
			}
			return true
		}
		return failed(err)
	}
	code := func(c string) store.CommandResult { return store.CommandResult{Code: c} }

	// R0.
	if cmd.Producer != store.ProducerWappie || !slices.Contains(accepts(sw.mode(), cmd.Section), cmd.Kind) {
		return refuse(code(kc.CodeKindNotAccepted), "R0")
	}
	docs, err := basedOnDocs(cmd.BasedOnDocs)
	if err != nil {
		return sw.unreadable(ctx, cmd, refuse)
	}
	person, err := targetPerson(cmd)
	if err != nil {
		return sw.unreadable(ctx, cmd, refuse)
	}
	subs := make([]uuid.UUID, 0, len(docs)+1)
	for sub := range docs {
		subs = append(subs, sub)
	}
	if _, drawn := docs[person]; person != uuid.Nil && !drawn {
		subs = append(subs, person)
	}
	facts, err := c.CommandFacts(ctx, cmd.Actor, subs, cmd.Workspace)
	if err != nil {
		return failed(err)
	}
	// R1.
	if facts.User == nil || !facts.Followed {
		return refuse(code(kc.CodeNotHeld), "R1")
	}
	var target uuid.UUID
	if person != uuid.Nil {
		f := facts.Subs[person]
		if f.User == nil || !f.Followed {
			return refuse(code(kc.CodeNotHeld), "R1")
		}
		target = *f.User
	}
	// R2.
	for sub, v := range docs {
		if facts.Versions[sub] < v {
			r := code(kc.CodeMembershipsBehind)
			r.RetryAfter = int(behindRetry / time.Second)
			return refuse(r, "R2")
		}
	}
	if cmd.Workspace != nil {
		// R3.
		switch {
		case !facts.Recorded, !facts.Local:
			return refuse(code(kc.CodeNotFound), "R3")
		case facts.Status == "closed":
			return refuse(code(kc.CodeTeamClosed), "R3")
		}
		// A raise's target, before R4: one Wappie holds as not active
		// locally is a final not_found, never memberships_unconfirmed (the
		// platform's Q6; the act checks the membership again).
		if cmd.Kind == kc.OpItemFlagsRaise {
			active, err := c.FlagsTargetActive(ctx, *cmd.Workspace, target, person)
			switch {
			case err != nil:
				return failed(err)
			case !active:
				return refuse(code(kc.CodeNotFound), "target")
			}
		}
		// R4.
		unconfirmed, err := sw.fresh(ctx, cmd, *facts.User, target)
		switch {
		case errors.Is(err, errUnreadable):
			return sw.unreadable(ctx, cmd, refuse)
		case err != nil:
			return failed(err)
		case unconfirmed:
			return refuse(code(kc.CodeMembershipsUnconfirmed), "R4")
		}
	}

	act, err := sw.dispatch(ctx, cmd, *facts.User, target)
	switch {
	case errors.Is(err, errUnreadable):
		return sw.unreadable(ctx, cmd, refuse)
	case errors.Is(err, errNotOurs):
		return refuse(code(kc.CodeNotFound), "R5")
	case errors.Is(err, errNotRun):
		return refuse(code(kc.CodeKindNotAccepted), "R0")
	case errors.Is(err, store.ErrCommandFinished):
		// Another leader answered it meanwhile.
		return true
	case errors.Is(err, store.ErrNotFound):
		// The workspace's record went between R3 and the act.
		return refuse(code(kc.CodeNotFound), "R3")
	case err != nil:
		if ctx.Err() != nil {
			return true
		}
		return failed(err)
	}
	attrs := []any{"id", cmd.ID, "kind", cmd.Kind, "outcome", act.Result.Outcome, "state_seq", act.Seq}
	if act.Result.Code != "" {
		attrs = append(attrs, "code", act.Result.Code)
	}
	l.log().Info("contract: a command was run", attrs...)
	kick(sw.sections.wake)
	return true
}

// unreadable answers a row the executor cannot read invalid_command, with
// an ERROR recorded, and the answer's time stamped, for --check (the
// platform alerts contract_command_invalid for a day).
func (sw *settingsWork) unreadable(ctx context.Context, cmd store.ContractCommand, refuse func(store.CommandResult, string) bool) bool {
	l, c := sw.l, sw.l.Members.Contract
	l.log().Error("contract: a command taken could not be read; refused invalid_command", "id", cmd.ID, "kind", cmd.Kind)
	if err := c.RecordError(ctx, store.ContractErrorCommandInvalid); err != nil && ctx.Err() == nil {
		l.log().Warn("contract: could not record an ERROR", "error", err)
	}
	ok := refuse(store.CommandResult{Code: kc.CodeInvalidCommand}, "read")
	if err := c.CommandInvalidAnswered(ctx); err != nil && ctx.Err() == nil {
		l.log().Warn("contract: could not stamp an invalid_command answered", "error", err)
	}
	return ok
}

// againRetry reports whether code, answered for kind, is a retry: what a
// row delivered again must never be answered with.
func againRetry(kind, code string) bool {
	k, known := kc.CommandKindOf(App, kind)
	return kc.CommandRefusalClass(code, !known || k.Tightening) == kc.ClassRetry
}

// againWaits leaves a row delivered again open, waiting the run backoff
// (store.CommandRunFailed, its class "again_" and the code a check would
// have answered, or a store error's), never answered rate_limited after
// store.CommandRunTries: a check that holds it back (a mode that does not
// run it, a document not yet applied) and a store error alike, it is
// judged again until it runs. At the tries a stuck row is answered at,
// one ERROR is recorded (command_stuck), for --check. It reports false
// when the wait could not be recorded.
func (sw *settingsWork) againWaits(ctx context.Context, cmd store.ContractCommand, class string, cause error) bool {
	l, c := sw.l, sw.l.Members.Contract
	if errors.Is(cause, store.ErrCommandFinished) {
		return true
	}
	tries, err := c.CommandRunFailed(ctx, cmd.ID, class)
	switch {
	case errors.Is(err, store.ErrCommandFinished):
		return true
	case err != nil:
		if ctx.Err() == nil {
			l.log().Warn("contract: could not record a command's wait", "id", cmd.ID, "error", err)
		}
		return false
	}
	l.log().Warn("contract: a command delivered again waits; it is never answered with a retry", "id", cmd.ID, "kind", cmd.Kind,
		"class", class, "tries", tries)
	if tries == store.CommandRunTries {
		l.log().Error("contract: a command delivered again keeps waiting", "id", cmd.ID, "kind", cmd.Kind, "class", class, "tries", tries)
		if err := c.RecordError(ctx, store.ContractErrorCommandStuck); err != nil && ctx.Err() == nil {
			l.log().Warn("contract: could not record an ERROR", "error", err)
		}
	}
	return true
}

// basedOnDocs reads a row's based_on.docs: the document versions, by sub,
// the console drew the command from.
func basedOnDocs(raw json.RawMessage) (map[uuid.UUID]int64, error) {
	var docs map[string]int64
	if err := json.Unmarshal(raw, &docs); err != nil {
		return nil, err
	}
	out := make(map[uuid.UUID]int64, len(docs))
	for s, v := range docs {
		sub, err := uuid.Parse(s)
		if err != nil {
			return nil, err
		}
		out[sub] = v
	}
	return out, nil
}

// ourID is a target's id as one of Wappie's: a UUID written as Wappie
// writes one, else errNotOurs.
func ourID(s string) (uuid.UUID, error) {
	id, ok := ours(s)
	if !ok {
		return uuid.Nil, errNotOurs
	}
	return id, nil
}

// ours reads s as one of Wappie's ids, as ourID does.
func ours(s string) (uuid.UUID, bool) {
	id, err := uuid.Parse(s)
	return id, err == nil && id.String() == s
}

// targetPerson is the sub cmd's target names as its person, uuid.Nil for a
// kind whose target names none (the kit's CommandKind.Target).
func targetPerson(cmd store.ContractCommand) (uuid.UUID, error) {
	k, ok := kc.CommandKindOf(App, cmd.Kind)
	if !ok || !slices.Contains(k.Target, kc.TargetPerson) {
		return uuid.Nil, nil
	}
	var target kc.CommandTarget
	if err := json.Unmarshal(cmd.Target, &target); err != nil {
		return uuid.Nil, errUnreadable
	}
	sub, err := uuid.Parse(target.Person)
	if err != nil {
		return uuid.Nil, errUnreadable
	}
	return sub, nil
}

// flagsParams reads a flags kind's params as the kit read them: the
// person's flags on the item (can) before and after, by their exact names.
func flagsParams(raw json.RawMessage) (before, after []string, err error) {
	var p map[string]json.RawMessage
	var b, a map[string][]string
	if json.Unmarshal(raw, &p) != nil || json.Unmarshal(p["before"], &b) != nil || json.Unmarshal(p["after"], &a) != nil ||
		b["can"] == nil || a["can"] == nil {
		return nil, nil, errUnreadable
	}
	return b["can"], a["can"], nil
}

// fresh is R4 for cmd, by actor on target (uuid.Nil for none), outside
// any write transaction (the plan's 3.1): whether the hook refused it
// (only with Enforce), or a read it needs that failed. A drop that keeps
// read, or a target who neither reads nor holds the key, asks nothing; a
// number that is none of Wappie's is left to the act (not_found).
func (sw *settingsWork) fresh(ctx context.Context, cmd store.ContractCommand, actor, target uuid.UUID) (bool, error) {
	m, ws := sw.l.Members, *cmd.Workspace
	var err error
	switch cmd.Kind {
	case kc.OpItemSyncStop, kc.OpItemSyncResume:
		_, err = m.RequireFresh(ctx, cmd.Kind, ws, Party{User: actor, How: IfStale})
	case kc.OpItemFlagsRaise:
		parties := []Party{{User: actor, How: IfStale}}
		if target != actor {
			parties = append(parties, Party{User: target, How: IfStale})
		}
		_, err = m.RequireWidening(ctx, cmd.Kind, ws, parties...)
	case kc.OpItemFlagsDrop, kc.OpItemAccessRemove:
		var t kc.CommandTarget
		if json.Unmarshal(cmd.Target, &t) != nil {
			return false, errUnreadable
		}
		item, ok := ours(t.Item)
		if !ok {
			// None of Wappie's: the act answers it not_found.
			return false, nil
		}
		if cmd.Kind == kc.OpItemFlagsDrop {
			before, after, err := flagsParams(cmd.Params)
			if err != nil {
				return false, err
			}
			if !slices.Contains(before, kc.CanRead) || slices.Contains(after, kc.CanRead) {
				return false, nil
			}
		}
		can, key, err := m.Contract.StoredFlags(ctx, ws, item, target)
		if err != nil {
			return false, err
		}
		if !key && !slices.Contains(can, kc.CanRead) {
			return false, nil
		}
		_, err = m.RequireBackups(ctx, cmd.Kind, ws, item, target)
		return errors.Is(err, ErrMembershipsUnconfirmed), nil
	}
	return errors.Is(err, ErrMembershipsUnconfirmed), nil
}

// dispatch runs cmd's kind for the local account user; person is the
// local account of the person its target names (uuid.Nil for none).
func (sw *settingsWork) dispatch(ctx context.Context, cmd store.ContractCommand, user, person uuid.UUID) (store.ContractAct, error) {
	if cmd.Workspace == nil {
		return sw.runPerson(ctx, cmd, user)
	}
	acts := sw.cfg.Acts
	run := numberacts.Run{Command: cmd.ID, Workspace: *cmd.Workspace, Actor: cmd.Actor, User: user}
	var target kc.CommandTarget
	if err := json.Unmarshal(cmd.Target, &target); err != nil {
		return store.ContractAct{}, errUnreadable
	}
	if cmd.Kind == kc.OpItemRegistrationDelete {
		row, err := ourID(target.Row)
		if err != nil {
			return store.ContractAct{}, err
		}
		return acts.RegistrationDelete(ctx, run, row)
	}
	item, err := ourID(target.Item)
	if err != nil {
		return store.ContractAct{}, err
	}
	switch cmd.Kind {
	case kc.OpItemRename:
		// Member by member, by their exact names, as the kit read them.
		var p map[string]json.RawMessage
		var before map[string]*string
		var after map[string]string
		if json.Unmarshal(cmd.Params, &p) != nil || json.Unmarshal(p["before"], &before) != nil ||
			json.Unmarshal(p["after"], &after) != nil {
			return store.ContractAct{}, errUnreadable
		}
		label, ok := after["label"]
		if !ok {
			return store.ContractAct{}, errUnreadable
		}
		return acts.Rename(ctx, run, item, before["label"], label)
	case kc.OpItemSyncStop:
		return acts.SyncStop(ctx, run, item)
	case kc.OpItemSyncResume:
		return acts.SyncResume(ctx, run, item)
	case kc.OpItemSyncNow:
		return acts.SyncNow(ctx, run, item)
	case kc.OpItemFlagsRaise, kc.OpItemFlagsDrop, kc.OpItemAccessRemove:
		return runFlags(ctx, acts, run, cmd, item, person)
	}
	return store.ContractAct{}, errNotRun
}

// runFlags runs a flags kind on item for the local account target, with
// the params the kit read; params the act refuses (the kit refused them
// first) are errUnreadable, invalid_command.
func runFlags(ctx context.Context, acts *numberacts.Runner, run numberacts.Run, cmd store.ContractCommand, item, target uuid.UUID) (store.ContractAct, error) {
	var act store.ContractAct
	var err error
	if cmd.Kind == kc.OpItemAccessRemove {
		act, err = acts.AccessRemove(ctx, run, item, target)
	} else {
		before, after, perr := flagsParams(cmd.Params)
		if perr != nil {
			return store.ContractAct{}, perr
		}
		if cmd.Kind == kc.OpItemFlagsRaise {
			act, err = acts.FlagsRaise(ctx, run, item, target, before, after)
		} else {
			act, err = acts.FlagsDrop(ctx, run, item, target, before, after)
		}
	}
	if errors.Is(err, store.ErrInvalidFlags) {
		return store.ContractAct{}, errUnreadable
	}
	return act, err
}
