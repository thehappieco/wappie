package membership

import (
	"context"
	"time"

	"whatserver2/internal/store"
)

// stateFor is how long a process trusts the contract's state it read: a
// switch of mode reaches every returning sign-in and every freshness check
// within it (the plan's 4.4). A new account never uses it: whether Wappie
// may still choose its home is read afresh (Observed).
const stateFor = 5 * time.Second

// cachedState is contract_state as read at most ModeCache ago.
func (m *Members) cachedState(ctx context.Context) (store.ContractState, error) {
	keep := m.ModeCache
	if keep == 0 {
		keep = stateFor
	}
	m.mu.Lock()
	if keep > 0 && !m.read.IsZero() && time.Since(m.read) < keep {
		s := m.state
		m.mu.Unlock()
		return s, nil
	}
	m.mu.Unlock()
	s, err := m.Contract.State(ctx)
	if err != nil {
		return store.ContractState{}, err
	}
	m.mu.Lock()
	m.state, m.read = s, time.Now()
	m.mu.Unlock()
	return s, nil
}

// observing reports whether the contract is at observe, by the cached
// state: the mode in which returning sign-ins subscribe and the freshness
// shadow runs (the plan's DB2).
func (m *Members) observing(ctx context.Context) bool {
	s, err := m.cachedState(ctx)
	if err != nil {
		m.log().Warn("contract: could not read the contract's state", "error", err)
		return false
	}
	return s.Mode == store.ContractObserve
}

// Observed reports whether the contract was ever switched to observe, read
// afresh: from then on a new account's home is the platform's, in every
// mode, and an account the platform does not answer for is refused rather
// than given a home of Wappie's choosing (the plan's DB2).
func (m *Members) Observed(ctx context.Context) (bool, error) {
	s, err := m.Contract.State(ctx)
	if err != nil {
		return false, err
	}
	return s.Observed(), nil
}
