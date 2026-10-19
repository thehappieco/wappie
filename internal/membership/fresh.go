package membership

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/store"
)

// Freshness per sub (README 7.1; the plan's DB8 and 4.9). A sub is fresh
// while the later of its last validated document, from a PUT or a GET, and
// the last trusted published_through (for a sub the platform follows in
// the stored generation) is under an hour old, on the database's clock.
// The acts README 7.1 and design 2.6 gate ask before their store
// transaction, never inside one: an act on a team's number RequireFresh, an
// act that widens access RequireWidening, an act that narrows who holds a
// number's key RequireBackups (the minute rule), and a move out of a team
// RequireMover. Release B only logs their verdicts (DB4; the owner's 15.1):
// nothing is refused before enforce.

// ErrMembershipsUnconfirmed is RequireFresh's refusal with Enforce:
// a party's memberships could not be confirmed with the platform
// (memberships_unconfirmed). Release B never returns it (DB4).
var ErrMembershipsUnconfirmed = errors.New("membership: the memberships could not be confirmed with the platform")

// ErrNotTheOnlyOwner is RequireMover's refusal with Enforce: the
// platform's document does not list the mover as the team's only owner
// (decision 0043, which the local sole-owner check holds today). Release B
// never returns it (DB5).
var ErrNotTheOnlyOwner = errors.New("membership: the platform does not list the mover as the team's only owner")

// Freshness is what a gated act asks (wsapi, authapi, mcpauth; the plan's
// 4.12).
type Freshness interface {
	// RequireFresh: an act on a team's number (deleting, recovering or
	// stopping it, linking it, sending from it), gated in a recorded team
	// only.
	RequireFresh(ctx context.Context, act string, tenant uuid.UUID, parties ...Party) (Verdict, error)
	// RequireWidening: an act that widens access (sharing a key, raising a
	// permission, creating an API key, a service account, or an MCP or AI
	// connection), gated in every recorded workspace.
	RequireWidening(ctx context.Context, act string, tenant uuid.UUID, parties ...Party) (Verdict, error)
	// RequireBackups: an act that narrows who holds device's key, losing's
	// grant revoked or their Read withheld.
	RequireBackups(ctx context.Context, act string, tenant, device, losing uuid.UUID) (Verdict, error)
	// RequireMover: moving a number out of a team, by actor.
	RequireMover(ctx context.Context, tenant, actor uuid.UUID) (Verdict, error)
}

var _ Freshness = (*Members)(nil)

// How is how a party's freshness is checked.
type How int

const (
	// IfStale: the stored freshness, and a GET when it is over an hour
	// old (README 7.1).
	IfStale How = iota + 1
	// Always: a GET whatever the stored freshness (a transfer's actor, a
	// key's or a renewal's recipient).
	Always
	// Stored: the stored freshness only, and no call: the hot paths at
	// observe (sends, group administration, MCP sends), which never wait.
	Stored
)

// The acts' names in the logs, beside the socket's frame types.
const (
	ActTransfer = "device.transfer"
)

// Party is one person whose freshness an act needs: the actor first.
type Party struct {
	User uuid.UUID
	How  How
}

// Verdict is a hook's.
type Verdict struct {
	// Checked: the act is gated here (the contract on, in a recorded
	// team; in a recorded personal workspace, a widening act on the
	// actor's own status).
	Checked bool
	// Refuse: a party has no document that confirms it now, or a narrowing
	// act no confirmed backup. At observe it is only logged.
	Refuse bool
	// Reasons are, by user, the refusing parties', or the key holders' that
	// are not confirmed backups: no_sub, stale (Stored), account_disabled or
	// account_closed (a document that says so), not_a_member and no_document
	// (a backup's document), or the GET's failure (refused:<code>,
	// unverified, unavailable, throttled, not_stored).
	Reasons map[uuid.UUID]string
	// Actor is the first party's document from this call's GET; nil when
	// none was read.
	Actor *store.ContractDoc
	// Mover is RequireMover's own reason, empty when the document lists
	// the actor as the team's only owner: no_document, not_a_member,
	// role_<role>, owners_<n>.
	Mover string

	// subs are the parties' subs; team, that the workspace is a team.
	subs map[uuid.UUID]uuid.UUID
	team bool
}

// Fresh says, for each sub, whether it is fresh now.
func (m *Members) Fresh(ctx context.Context, subs ...uuid.UUID) (map[uuid.UUID]bool, error) {
	return m.Contract.Fresh(ctx, store.FreshFor, subs...)
}

// RequireFresh is the freshness hook of an act on a team's number in
// tenant (the plan's 4.9 and 4.12), called before the act's store
// transaction, never inside one. It gates only while the contract is on
// (observe, and every mode after it) and only in a recorded team: README
// 7.1 lists these acts for a team's items, and a personal workspace never
// waits (the reply's Q5; design 2.6). Every party who is the team's person
// counts: a party with no sub, a stale Stored party, a party whose GET got
// no document (no answer, an unverified one, a signed refusal of any code),
// and a document that is not active make the verdict a refusal, logged
// "freshness: would refuse"; a Stored party's staleness is logged
// "freshness: stale at act" and makes no call. A service identity, or
// someone of another workspace, is never a party (Contract.Persons). The
// parties' GETs run at once, within one call's bound. Only with Enforce is
// a refusal returned, as ErrMembershipsUnconfirmed; without it the act goes
// on whatever the verdict, a failure to read included.
func (m *Members) RequireFresh(ctx context.Context, act string, tenant uuid.UUID, parties ...Party) (Verdict, error) {
	v, err := m.requireFresh(ctx, act, tenant, parties, false)
	return m.verdict(act, tenant, v, err)
}

// RequireWidening is RequireFresh for an act that widens access, which
// README 7.1 gates in every workspace: in a recorded team as RequireFresh,
// and in a recorded personal workspace, where nobody else's membership is
// at stake and an act never waits, on the actor's own stored status, with
// no call.
func (m *Members) RequireWidening(ctx context.Context, act string, tenant uuid.UUID, parties ...Party) (Verdict, error) {
	v, err := m.requireFresh(ctx, act, tenant, parties, true)
	return m.verdict(act, tenant, v, err)
}

// verdict is what a hook returns: at observe the act goes on whatever the
// verdict, a failure to read included; with Enforce a refusal is returned.
func (m *Members) verdict(act string, tenant uuid.UUID, v Verdict, err error) (Verdict, error) {
	if err != nil {
		m.log().Warn("freshness: could not check", "act", act, "tenant", tenant, "error", err)
		if m.Enforce {
			return Verdict{Checked: true, Refuse: true}, ErrMembershipsUnconfirmed
		}
		return Verdict{}, nil
	}
	if v.Refuse && m.Enforce {
		return v, ErrMembershipsUnconfirmed
	}
	return v, nil
}

// gate reads whether tenant is gated: the contract on, and the workspace
// recorded; its kind says how.
func (m *Members) gate(ctx context.Context, tenant uuid.UUID) (store.ContractWorkspace, bool, error) {
	if !m.on(ctx) {
		return store.ContractWorkspace{}, false, nil
	}
	return m.Contract.Workspace(ctx, tenant)
}

func (m *Members) requireFresh(ctx context.Context, act string, tenant uuid.UUID, parties []Party, widening bool) (Verdict, error) {
	if len(parties) == 0 {
		return Verdict{}, nil
	}
	w, recorded, err := m.gate(ctx, tenant)
	if err != nil || !recorded {
		return Verdict{}, err
	}
	if w.Kind != kc.KindTeam {
		if !widening {
			return Verdict{}, nil
		}
		return m.ownStatus(ctx, act, tenant, parties[0].User)
	}
	users := make([]uuid.UUID, len(parties))
	for i, p := range parties {
		users[i] = p.User
	}
	persons, err := m.Contract.Persons(ctx, tenant, users...)
	if err != nil {
		return Verdict{}, err
	}
	users = slices.DeleteFunc(users, func(u uuid.UUID) bool { return !persons[u] })
	subs, err := m.Contract.SubsOf(ctx, users...)
	if err != nil {
		return Verdict{}, err
	}
	known := make([]uuid.UUID, 0, len(subs))
	for _, sub := range subs {
		known = append(known, sub)
	}
	standing, err := m.Contract.Standing(ctx, store.FreshFor, known...)
	if err != nil {
		return Verdict{}, err
	}
	v := Verdict{Checked: true, Reasons: map[uuid.UUID]string{}, subs: subs, team: true}
	asking := map[uuid.UUID]bool{}
	var ask []uuid.UUID
	for _, p := range parties {
		if !persons[p.User] {
			continue
		}
		sub, linked := subs[p.User]
		st := standing[sub]
		switch {
		case !linked:
			v.Reasons[p.User] = "no_sub"
		case p.How == Stored && !st.Fresh:
			v.Reasons[p.User] = "stale"
			m.log().Info("freshness: stale at act", "act", act, "tenant", tenant, "sub", sub)
		case p.How == Always || (p.How != Stored && !st.Fresh):
			if !asking[p.User] {
				asking[p.User] = true
				ask = append(ask, sub)
			}
		case st.Status != "" && st.Status != kc.AccountActive:
			v.Reasons[p.User] = "account_" + st.Status
		}
	}
	answers := m.getAll(ctx, tenant, ask)
	for i, p := range parties {
		if !asking[p.User] {
			continue
		}
		a := answers[subs[p.User]]
		if a.err != nil {
			v.Reasons[p.User] = noDocument(a.err)
			continue
		}
		if i == 0 {
			doc := a.doc
			v.Actor = &doc
		}
		if a.doc.Status != kc.AccountActive {
			v.Reasons[p.User] = "account_" + a.doc.Status
		}
	}
	logged := map[uuid.UUID]bool{}
	for _, p := range parties {
		reason, ok := v.Reasons[p.User]
		if !ok || logged[p.User] {
			continue
		}
		logged[p.User] = true
		v.Refuse = true
		if reason != "stale" {
			m.log().Warn("freshness: would refuse", "act", act, "tenant", tenant, "user", p.User, "sub", subs[p.User], "reason", reason)
		}
	}
	return v, nil
}

// ownStatus is a widening act's hook in a recorded personal workspace:
// nobody else's membership is at stake and an act never waits there, so
// only the actor's stored document counts, with no call; one that is not
// active is a refusal. No sub, or no document stored, is nothing to check
// (fail-static).
func (m *Members) ownStatus(ctx context.Context, act string, tenant, actor uuid.UUID) (Verdict, error) {
	subs, err := m.Contract.SubsOf(ctx, actor)
	if err != nil {
		return Verdict{}, err
	}
	sub, linked := subs[actor]
	if !linked {
		return Verdict{}, nil
	}
	standing, err := m.Contract.Standing(ctx, store.FreshFor, sub)
	if err != nil {
		return Verdict{}, err
	}
	st := standing[sub]
	if st.Status == "" {
		return Verdict{}, nil
	}
	v := Verdict{Checked: true, Reasons: map[uuid.UUID]string{}, subs: subs}
	if st.Status != kc.AccountActive {
		v.Refuse, v.Reasons[actor] = true, "account_"+st.Status
		m.log().Warn("freshness: would refuse", "act", act, "tenant", tenant, "user", actor, "sub", sub, "reason", v.Reasons[actor])
	}
	return v, nil
}

// RequireBackups is the hook of an act that narrows who holds device's key
// in a recorded team: losing's grant revoked, or their Read withheld
// (README 7.1, "Acts that narrow who holds a key"; 0040 "No dormant keys":
// a removal never strands a number by a race). A remaining key holder
// counts as a backup only on a fresh document that is active and lists the
// team: one fresh within the minute (store.BackupFreshFor) as stored, any
// other's from a GET, outside every write transaction, all within one
// call's bound. A holder with no sub has no document, so is never a backup
// (README: "count a person as an item's backup only on a fresh document").
// When holders remain and none is a confirmed backup, the verdict is a
// refusal, logged "freshness: would refuse" (no_confirmed_backup, with each
// holder's reason). No holder left is Wappie's own last_device_reader,
// unchanged. Otherwise as RequireFresh: logged at observe, refused only with
// Enforce.
func (m *Members) RequireBackups(ctx context.Context, act string, tenant, device, losing uuid.UUID) (Verdict, error) {
	v, err := m.requireBackups(ctx, act, tenant, device, losing)
	return m.verdict(act, tenant, v, err)
}

func (m *Members) requireBackups(ctx context.Context, act string, tenant, device, losing uuid.UUID) (Verdict, error) {
	w, recorded, err := m.gate(ctx, tenant)
	if err != nil || !recorded || w.Kind != kc.KindTeam {
		return Verdict{}, err
	}
	holders, err := m.Contract.KeyHolders(ctx, tenant, device, losing)
	if err != nil {
		return Verdict{}, err
	}
	subs, err := m.Contract.SubsOf(ctx, holders...)
	if err != nil {
		return Verdict{}, err
	}
	known := make([]uuid.UUID, 0, len(subs))
	for _, u := range holders {
		if sub, ok := subs[u]; ok {
			known = append(known, sub)
		}
	}
	standing, err := m.Contract.Standing(ctx, store.BackupFreshFor, known...)
	if err != nil {
		return Verdict{}, err
	}
	v := Verdict{Checked: true, Reasons: map[uuid.UUID]string{}, subs: subs}
	var stale []uuid.UUID
	for _, u := range holders {
		sub, linked := subs[u]
		switch st := standing[sub]; {
		case !linked:
			v.Reasons[u] = "no_sub"
		case st.Fresh:
			if reason := notBackup(st.Status, st.Lists(tenant)); reason != "" {
				v.Reasons[u] = reason
			}
		default:
			stale = append(stale, sub)
		}
	}
	answers := m.getAll(ctx, tenant, stale)
	for _, u := range holders {
		a, asked := answers[subs[u]]
		switch {
		case !asked:
		case a.err != nil:
			v.Reasons[u] = noDocument(a.err)
		default:
			if reason := notBackup(a.doc.Status, listed(a.doc.Workspaces, tenant)); reason != "" {
				v.Reasons[u] = reason
			}
		}
	}
	if len(holders) > 0 && len(v.Reasons) == len(holders) {
		v.Refuse = true
		why := make([]string, 0, len(holders))
		for _, u := range holders {
			who := "user " + u.String()
			if sub, ok := subs[u]; ok {
				who = sub.String()
			}
			why = append(why, who+":"+v.Reasons[u])
		}
		m.log().Warn("freshness: would refuse", "act", act, "tenant", tenant, "device", device, "losing", losing,
			"reason", "no_confirmed_backup", "holders", why)
	}
	return v, nil
}

// notBackup is why a key holder's document does not confirm them as a
// backup in a team, empty when it does: active, and listing the team.
func notBackup(status string, lists bool) string {
	switch {
	case status == "":
		return "no_document"
	case status != kc.AccountActive:
		return "account_" + status
	case !lists:
		return "not_a_member"
	}
	return ""
}

// listed says whether a document's workspaces name workspace.
func listed(ws []store.ContractDocWorkspace, workspace uuid.UUID) bool {
	return slices.ContainsFunc(ws, func(w store.ContractDocWorkspace) bool { return w.ID == workspace })
}

// hookCalls is how many of one act's GETs run at once.
const hookCalls = 4

// answer is one GET's.
type answer struct {
	doc store.ContractDoc
	err error
}

// getAll asks for each of subs at once, at most hookCalls in flight, all
// within one call's bound: an act waits that long at most, however many it
// asks for. Each GET first takes its place in the hook's budget (budget.go),
// waiting for it within the bound, and one that gets none is no answer
// (throttled). An answer is stored on ctx, not on the bound, so one that
// came in time is kept however late in the window.
func (m *Members) getAll(ctx context.Context, tenant uuid.UUID, subs []uuid.UUID) map[uuid.UUID]answer {
	out := make(map[uuid.UUID]answer, len(subs))
	if len(subs) == 0 {
		return out
	}
	deadline := time.Now().Add(m.bound())
	var mu sync.Mutex
	var wg sync.WaitGroup
	slots := make(chan struct{}, hookCalls)
	for _, sub := range subs {
		wg.Add(1)
		slots <- struct{}{}
		go func() {
			defer func() { <-slots; wg.Done() }()
			var a answer
			switch {
			case !time.Now().Before(deadline):
				// The bound ran out while it waited for a slot.
				a.err = context.DeadlineExceeded
			default:
				if a.err = m.budget().take(ctx, deadline, tenant); a.err == nil {
					a.doc, a.err = m.fetch(ctx, deadline, sub)
				}
			}
			mu.Lock()
			out[sub] = a
			mu.Unlock()
		}()
	}
	wg.Wait()
	return out
}

// RequireMover is the hook of a move out of a team (README 7.1: "always
// with a fresh GET"): the actor's document is asked for whatever its
// freshness, as RequireFresh with Always, and must list them as the team's
// owner with an owner count of one (decision 0043: only a team's only
// owner moves a number out; the local sole-owner check decides it today).
// A document that does not, or no document, is logged "transfer: would
// refuse" (tenant, sub, reason); with Enforce it is refused,
// ErrMembershipsUnconfirmed without a document and ErrNotTheOnlyOwner
// with one that says otherwise.
func (m *Members) RequireMover(ctx context.Context, tenant, actor uuid.UUID) (Verdict, error) {
	v, err := m.requireFresh(ctx, ActTransfer, tenant, []Party{{User: actor, How: Always}}, false)
	if err != nil || !v.team {
		return m.verdict(ActTransfer, tenant, v, err)
	}
	v.Mover = mover(v, tenant, actor)
	if v.Mover != "" {
		m.log().Warn("transfer: would refuse", "tenant", tenant, "user", actor, "sub", v.subs[actor], "reason", v.Mover)
	}
	switch {
	case !m.Enforce:
		return v, nil
	case v.Actor == nil && v.Refuse:
		return v, ErrMembershipsUnconfirmed
	case v.Mover != "":
		v.Refuse = true
		return v, ErrNotTheOnlyOwner
	}
	return m.verdict(ActTransfer, tenant, v, nil)
}

// mover is RequireMover's reason, empty when the actor's document lists
// them as the only owner of tenant.
func mover(v Verdict, tenant, actor uuid.UUID) string {
	if v.Actor == nil {
		if reason := v.Reasons[actor]; reason != "" {
			return "no_document:" + reason
		}
		return "no_document"
	}
	var doc kc.AccountDoc
	if err := json.Unmarshal(v.Actor.Raw, &doc); err != nil {
		return "no_document:unreadable"
	}
	for _, w := range doc.Workspaces {
		if w.ID != tenant.String() {
			continue
		}
		switch {
		case w.Role != kc.RoleOwner:
			return "role_" + w.Role
		case w.Owners == nil || *w.Owners != 1:
			n := -1
			if w.Owners != nil {
				n = *w.Owners
			}
			return fmt.Sprintf("owners_%d", n)
		}
		return ""
	}
	return "not_a_member"
}

// noDocument is a GET's failure as a verdict's reason.
func noDocument(err error) string {
	var notStored errNotStored
	switch o := Classify(err); {
	case errors.As(err, &notStored):
		return "not_stored"
	case errors.Is(err, errThrottled):
		return "throttled"
	case o == Refused:
		return "refused:" + RefusalCode(err)
	default:
		return o.String()
	}
}
