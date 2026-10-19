package wsapi

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/membership"
	"whatserver2/internal/store"
)

// The contract's freshness hook at the socket's gated acts (README 7.1;
// design 2.6; the plan's 4.9 and 4.12). Each rare act asks before its
// store transaction, never inside one, so no platform call ever holds a
// lock: a team's delete, recover and person's stop (IfStale), a move out
// of a team (Always, with the mover's role, once the preview finds the move
// possible), a pairing (IfStale, its grants' recipients Always), a grant
// (the actor IfStale, a person recipient Always), a grant's revocation (the
// minute rule for the remaining key holders) and an API key's creation
// (IfStale). A person's sends and group administration from a number are
// checked in the background on the stored freshness only (Stored): a send
// never waits and the platform gets no call for it. An API key's own acts
// are never gated (README 7.1, "Never gated"). The acts on a team's number
// are gated in a team only; a grant and an API key, which widen access, in
// a personal workspace too, on the person's own status, never waiting.
// Release B only logs the verdicts (DB4); with the enforce flag a refusal
// is answered memberships_unconfirmed and the act changes nothing.

const (
	// atActsInFlight bounds the background checks running at once, across
	// the process; one past it is skipped, never waited for.
	atActsInFlight = 16
	// atActEvery is how often one session checks the same act on the same
	// number: a stale verdict lasts at least that long, and a stream of
	// sends, typing or call media must not become a stream of queries.
	atActEvery = time.Minute
	// atActBound bounds a background check.
	atActBound = 5 * time.Second
)

// Membership is the freshness hook the server's acts ask
// (Config.Membership): what serve wired, for its tests.
func (s *Server) Membership() membership.Freshness { return s.cfg.Membership }

// fresh asks the hook for an act on a team's number in this session's
// workspace, before the act's store transaction; false when the act is
// refused, which is answered. Without a hook every act goes on.
func (s *session) fresh(ctx context.Context, reqID, act string, parties ...membership.Party) bool {
	m := s.srv.cfg.Membership
	if m == nil {
		return true
	}
	tenant, err := uuid.Parse(s.tenantID())
	if err != nil {
		return true
	}
	_, err = m.RequireFresh(ctx, act, tenant, parties...)
	return s.freshAnswer(reqID, err)
}

// widening is fresh for an act that widens access (sharing a key, an API
// key), which the hook gates in a personal workspace too.
func (s *session) widening(ctx context.Context, reqID, act string, parties ...membership.Party) bool {
	m := s.srv.cfg.Membership
	if m == nil {
		return true
	}
	tenant, err := uuid.Parse(s.tenantID())
	if err != nil {
		return true
	}
	_, err = m.RequireWidening(ctx, act, tenant, parties...)
	return s.freshAnswer(reqID, err)
}

// freshBackups is fresh for an act that narrows who holds device's key:
// losing's grant revoked.
func (s *session) freshBackups(ctx context.Context, reqID, act string, tenant, device, losing uuid.UUID) bool {
	m := s.srv.cfg.Membership
	if m == nil {
		return true
	}
	_, err := m.RequireBackups(ctx, act, tenant, device, losing)
	return s.freshAnswer(reqID, err)
}

// freshMover is fresh for a move out of a team by actor.
func (s *session) freshMover(ctx context.Context, reqID string, tenant, actor uuid.UUID) bool {
	m := s.srv.cfg.Membership
	if m == nil {
		return true
	}
	_, err := m.RequireMover(ctx, tenant, actor)
	return s.freshAnswer(reqID, err)
}

// freshAnswer answers a hook's refusal, which only the enforce flag makes.
func (s *session) freshAnswer(reqID string, err error) bool {
	switch {
	case err == nil:
		return true
	case errors.Is(err, membership.ErrNotTheOnlyOwner):
		s.replyError(reqID, ErrCodeConflict, "O Team precisa ter você como único proprietário.")
	default:
		s.replyError(reqID, ErrCodeMembershipsUnconfirmed,
			"could not confirm your memberships with The Happie Co; nothing changed, try again in a minute")
	}
	return false
}

// person is the hook's party for this session's person.
func person(who actor, how membership.How) membership.Party {
	return membership.Party{User: who.userID, How: how}
}

// atAct says whether a frame acting with action on a number is a send or
// group administration (design 2.6's "a person's sends from a team number,
// and group administration on WhatsApp"): every frame that needs Send, but
// the call list, which only reads, and the group frames.
func atAct(kind string, action store.DeviceAction) bool {
	switch kind {
	case TypeCallsList:
		return false
	case TypeGroupCreate, TypeGroupParticipants, TypeGroupLeave, TypeGroupJoin:
		return true
	}
	return action == store.ActionSend
}

// freshAtAct checks a person's send or group administration on device in
// the background, on the stored freshness only (membership.Stored): the
// frame goes on at once, whatever the verdict, and the hook logs "stale at
// act". One session checks the same act on the same number at most every
// atActEvery, and a check past atActsInFlight is skipped. The enforce
// release gives these acts a synchronous GET instead (the plan's 4.9).
func (s *session) freshAtAct(ctx context.Context, kind string, tenant, device uuid.UUID) {
	m := s.srv.cfg.Membership
	who := s.actor()
	if m == nil || !who.person {
		return
	}
	key := kind + "/" + device.String()
	now := time.Now()
	s.atActMu.Lock()
	last, seen := s.atActSeen[key]
	s.atActMu.Unlock()
	if seen && now.Sub(last) < atActEvery {
		return
	}
	select {
	case s.srv.atActs <- struct{}{}:
	default:
		s.log.Debug("freshness: a send's check skipped, too many in flight", "act", kind)
		return
	}
	s.atActMu.Lock()
	if s.atActSeen == nil {
		s.atActSeen = map[string]time.Time{}
	}
	for k, at := range s.atActSeen {
		if now.Sub(at) >= atActEvery {
			delete(s.atActSeen, k)
		}
	}
	s.atActSeen[key] = now
	s.atActMu.Unlock()
	// Past the frame's own end: the check finishes, bounded, after the
	// frame is answered.
	check, cancel := context.WithTimeout(context.WithoutCancel(ctx), atActBound)
	go func() {
		defer func() { <-s.srv.atActs }()
		defer cancel()
		_, _ = m.RequireFresh(check, kind, tenant, person(who, membership.Stored)) //nolint:errcheck // logged by the hook; a send never waits on it
	}()
}
