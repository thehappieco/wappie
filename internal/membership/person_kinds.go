package membership

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/store"
)

// A person's two kinds (the spec's 14.7; the plan's 6.5 and 6.6), on the
// actor's own account, each in one store transaction that writes its
// result at the person's seq and makes their document due now:
// person.sign_out_everywhere ends the session families begun before the
// command was issued, and counts them (DS11); person.notices_dismiss marks
// the notices named seen, but a pause notice whose version rose.

// runPerson runs a person's kind for the local account user.
func (sw *settingsWork) runPerson(ctx context.Context, cmd store.ContractCommand, user uuid.UUID) (store.ContractAct, error) {
	c := sw.l.Members.Contract
	run := store.ContractRun{ID: cmd.ID, Sub: cmd.Actor, User: user}
	switch cmd.Kind {
	case kc.OpPersonSignOutEverywhere:
		act, err := c.RunSignOutEverywhere(ctx, run, cmd.IssuedAt)
		if err == nil {
			var d kc.ResultDetail
			if json.Unmarshal(act.Result.Detail, &d) == nil && d.SessionsEnded != nil {
				sw.l.log().Info("contract: signed out everywhere through the console", "id", cmd.ID, "sessions_ended", *d.SessionsEnded)
			}
		}
		return act, err
	case kc.OpPersonNoticesDismiss:
		// Member by member, by their exact names, as the kit read them.
		var p map[string]json.RawMessage
		var notices []map[string]json.RawMessage
		if json.Unmarshal(cmd.Params, &p) != nil || json.Unmarshal(p["notices"], &notices) != nil {
			return store.ContractAct{}, errUnreadable
		}
		refs := make([]store.NoticeRef, len(notices))
		for i, n := range notices {
			if json.Unmarshal(n["id"], &refs[i].ID) != nil || json.Unmarshal(n["version"], &refs[i].Version) != nil {
				return store.ContractAct{}, errUnreadable
			}
		}
		return c.RunNoticesDismiss(ctx, run, refs)
	}
	return store.ContractAct{}, errNotRun
}
