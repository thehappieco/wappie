package membership

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	kc "github.com/thehappieco/kit/contract"
)

// A token's record by a signed GET, for the grant page (the plan's 5.4):
// token.grant_context and token.grant need the record fetched under a
// minute ago (store.TokenGrantFresh). Each GET takes its place in the
// freshness hook's budget, the process's and the workspace's, and is
// bounded as a document's GET is (budget.go). A signed not_found is kept
// for a minute: in that time the same token is not asked again.

// tokenMissFor is how long a signed not_found of a token is kept.
const tokenMissFor = time.Minute

// ErrTokenNotFound is a token the platform answered not_found for, by a
// signed GET within the last minute. It clears nothing: the record Wappie
// holds stays as it is, and only its fetched_at stays old.
var ErrTokenNotFound = errors.New("membership: the platform knows no such token for Wappie")

// FetchToken asks the platform for token's record now
// (GET /contract/v1/tokens/{id}) and applies it (store.Tokens.ApplyTokenRecord):
// what it narrows is applied, and fetched_at takes the time the GET was
// sent when its version equals or raises the one Wappie holds. tenant is the
// workspace that asks, for the budget. It answers ErrUnavailable with no
// transport, ErrTokenNotFound for a signed not_found (kept a minute), and
// the call's or the store's error otherwise.
func (m *Members) FetchToken(ctx context.Context, tenant, token uuid.UUID) error {
	if m.Tokens == nil || !m.connected() {
		return ErrUnavailable
	}
	if m.tokenMissed(token, time.Now()) {
		return ErrTokenNotFound
	}
	deadline := time.Now().Add(m.bound())
	if err := m.budget().take(ctx, deadline, tenant); err != nil {
		return err
	}
	call, cancel := context.WithDeadline(ctx, deadline)
	sent := time.Now()
	rec, err := m.Client.Token(call, token.String())
	cancel()
	if err != nil {
		if RefusalCode(err) == kc.CodeNotFound {
			m.tokenMiss(token, time.Now())
			return ErrTokenNotFound
		}
		m.log().Warn("contract: a token's GET got no record", append([]any{"token", token}, callAttrs(err)...)...)
		return err
	}
	_, err = m.Tokens.ApplyTokenRecord(ctx, rec, sent, time.Now())
	return err
}

// tokenMissed reports whether token got a signed not_found within the last
// minute.
func (m *Members) tokenMissed(token uuid.UUID, now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	at, ok := m.tokenMisses[token]
	return ok && now.Sub(at) < tokenMissFor
}

// tokenMiss keeps token's not_found, and forgets those over a minute old.
func (m *Members) tokenMiss(token uuid.UUID, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tokenMisses == nil {
		m.tokenMisses = map[uuid.UUID]time.Time{}
	}
	for id, at := range m.tokenMisses {
		if now.Sub(at) >= tokenMissFor {
			delete(m.tokenMisses, id)
		}
	}
	m.tokenMisses[token] = now
}
