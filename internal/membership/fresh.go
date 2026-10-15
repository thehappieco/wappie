package membership

import (
	"context"
	"errors"

	"github.com/google/uuid"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/store"
)

// Freshness per sub (README 7.1; the plan's DB8 and 4.9). A sub is fresh
// while the later of its last validated document, from a PUT or a GET, and
// the last trusted published_through (for a sub the platform follows in
// the stored generation) is under an hour old, on the database's clock.
// The acts README 7.1 and design 2.6 gate ask RequireFresh before their
// store transaction; release B only logs its verdicts (DB4).

// ErrMembershipsUnconfirmed is RequireFresh's refusal with Enforce:
// a party's memberships could not be confirmed with the platform
// (memberships_unconfirmed). Release B never returns it (DB4).
var ErrMembershipsUnconfirmed = errors.New("membership: the memberships could not be confirmed with the platform")

// Freshness is what a gated act asks (wsapi, authapi; the plan's 4.12).
type Freshness interface {
	RequireFresh(ctx context.Context, act string, tenant uuid.UUID, parties ...Party) (Verdict, error)
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

// Party is one person whose freshness an act needs: the actor first.
type Party struct {
	User uuid.UUID
	How  How
}

// Verdict is RequireFresh's.
type Verdict struct {
	// Checked: the act is gated here (the contract on, in a recorded team).
	Checked bool
	// Refuse: a party has no document that confirms it now. At observe it
	// is only logged.
	Refuse bool
	// Reasons are the refusing parties', by user: no_sub, stale (Stored),
	// or the GET's failure (refused:<code>, unverified, unavailable,
	// not_stored).
	Reasons map[uuid.UUID]string
	// Actor is the first party's document from this call's GET; nil when
	// none was read.
	Actor *store.ContractDoc
}

// Fresh says, for each sub, whether it is fresh now.
func (m *Members) Fresh(ctx context.Context, subs ...uuid.UUID) (map[uuid.UUID]bool, error) {
	return m.Contract.Fresh(ctx, store.FreshFor, subs...)
}

// RequireFresh is the freshness hook of a gated act in tenant (the plan's
// 4.9 and 4.12), called before the act's store transaction, never inside
// one. It gates only while the contract is on (observe, and every mode
// after it) and only in a recorded team: personal workspaces never wait
// (the reply's Q5). A party with no sub, a stale Stored party, and a party
// whose GET got no document (no answer, an unverified one, a signed
// refusal of any code) make the verdict a refusal, logged "freshness:
// would refuse"; a Stored party's staleness is logged "freshness: stale at
// act" and makes no call. Only with Enforce is a refusal returned, as
// ErrMembershipsUnconfirmed; without it the act goes on whatever the
// verdict, a failure to read included.
func (m *Members) RequireFresh(ctx context.Context, act string, tenant uuid.UUID, parties ...Party) (Verdict, error) {
	v, err := m.requireFresh(ctx, act, tenant, parties)
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

func (m *Members) requireFresh(ctx context.Context, act string, tenant uuid.UUID, parties []Party) (Verdict, error) {
	if !m.on(ctx) || len(parties) == 0 {
		return Verdict{}, nil
	}
	w, recorded, err := m.Contract.Workspace(ctx, tenant)
	if err != nil {
		return Verdict{}, err
	}
	if !recorded || w.Kind != kc.KindTeam {
		return Verdict{}, nil
	}
	users := make([]uuid.UUID, len(parties))
	for i, p := range parties {
		users[i] = p.User
	}
	subs, err := m.Contract.SubsOf(ctx, users...)
	if err != nil {
		return Verdict{}, err
	}
	known := make([]uuid.UUID, 0, len(subs))
	for _, sub := range subs {
		known = append(known, sub)
	}
	fresh, err := m.Contract.Fresh(ctx, store.FreshFor, known...)
	if err != nil {
		return Verdict{}, err
	}
	v := Verdict{Checked: true, Reasons: map[uuid.UUID]string{}}
	for i, p := range parties {
		sub, linked := subs[p.User]
		switch {
		case !linked:
			v.Reasons[p.User] = "no_sub"
		case p.How == Stored:
			if !fresh[sub] {
				v.Reasons[p.User] = "stale"
				m.log().Info("freshness: stale at act", "act", act, "tenant", tenant, "sub", sub)
			}
		case p.How == Always || !fresh[sub]:
			doc, err := m.get(ctx, sub)
			if err != nil {
				v.Reasons[p.User] = noDocument(err)
				continue
			}
			if i == 0 {
				v.Actor = &doc
			}
		}
	}
	for _, p := range parties {
		reason, ok := v.Reasons[p.User]
		if !ok {
			continue
		}
		v.Refuse = true
		if reason != "stale" {
			m.log().Warn("freshness: would refuse", "act", act, "tenant", tenant, "user", p.User, "sub", subs[p.User], "reason", reason)
		}
	}
	return v, nil
}

// noDocument is a GET's failure as a verdict's reason.
func noDocument(err error) string {
	var notStored errNotStored
	switch o := Classify(err); {
	case errors.As(err, &notStored):
		return "not_stored"
	case o == Refused:
		return "refused:" + RefusalCode(err)
	default:
		return o.String()
	}
}
