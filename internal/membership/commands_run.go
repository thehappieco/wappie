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
//	   account (not_held; a person's with no seq);
//	R2 every document it was drawn from is applied: based_on.docs at most
//	   the stored version of the current generation (memberships_behind,
//	   retry_after behindRetry);
//	R3 a workspace's kind: the workspace recorded and Wappie's, and open
//	   (not_found, team_closed);
//	R4 the freshness item.sync_stop and item.sync_resume ask in a team
//	   (the frame's: RequireFresh, before any write; at observe it only
//	   logs);
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
	subs := make([]uuid.UUID, 0, len(docs))
	for sub := range docs {
		subs = append(subs, sub)
	}
	facts, err := c.CommandFacts(ctx, cmd.Actor, subs, cmd.Workspace)
	if err != nil {
		return failed(err)
	}
	// R1.
	if facts.User == nil || !facts.Followed {
		return refuse(code(kc.CodeNotHeld), "R1")
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
		// R4.
		if cmd.Kind == kc.OpItemSyncStop || cmd.Kind == kc.OpItemSyncResume {
			_, err := l.Members.RequireFresh(ctx, cmd.Kind, *cmd.Workspace, Party{User: *facts.User, How: IfStale})
			if errors.Is(err, ErrMembershipsUnconfirmed) {
				return refuse(code(kc.CodeMembershipsUnconfirmed), "R4")
			}
		}
	}

	act, err := sw.dispatch(ctx, cmd, *facts.User)
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
	id, err := uuid.Parse(s)
	if err != nil || id.String() != s {
		return uuid.Nil, errNotOurs
	}
	return id, nil
}

// dispatch runs cmd's kind for the local account user.
func (sw *settingsWork) dispatch(ctx context.Context, cmd store.ContractCommand, user uuid.UUID) (store.ContractAct, error) {
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
	}
	return store.ContractAct{}, errNotRun
}
