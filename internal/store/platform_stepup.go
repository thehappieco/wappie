package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The step-up of an account that signs in through the identity provider
// (owner decision D3, step 4; docs/platform-sign-in.md, "Step-ups"). The
// session records when it started one (sessions.step_up_not_before, 0048);
// the provider re-authenticates the person with prompt=login; and the finish
// takes the provider's auth_time from userinfo. The proof it records is the
// one every step-up writes, sessions.authenticated_at = now() on the
// database's clock (0047), so nothing that asks for a proof changes.

var (
	// ErrStepUpNotStarted is a finish with no start to answer: none was
	// made for the session, it was used already, a newer start replaced it,
	// or it is older than the window.
	ErrStepUpNotStarted = errors.New("store: no step-up at the identity provider is pending for this session")
	// ErrStepUpStale is a re-authentication the provider dates before the
	// start, beyond the clocks' tolerance: it answered from an earlier
	// sign-in instead of asking the person again.
	ErrStepUpStale = errors.New("store: the identity provider's re-authentication is older than the step-up's start")
)

// StartProviderStepUp records that a live session starts a step-up at the
// identity provider, now on the database's clock, and returns that time. A
// start replaces any earlier one of the session, which then proves nothing.
// ErrNoSession for a session that is not live. The caller has checked that
// the account steps up at the provider.
func (u *Users) StartProviderStepUp(ctx context.Context, session uuid.UUID) (time.Time, error) {
	var notBefore time.Time
	err := u.pool.QueryRow(ctx, `UPDATE sessions SET step_up_not_before = now()
		WHERE id = $1 AND revoked_at IS NULL AND expires_at > now() RETURNING step_up_not_before`, session).Scan(&notBefore)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, ErrNoSession
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("store: start a step-up: %w", err)
	}
	return notBefore, nil
}

// PendingProviderStepUp returns the start of a live session's step-up at the
// identity provider while it is younger than window, on the database's
// clock: what a finish must answer. ErrStepUpNotStarted when there is none
// (never started, used, or too old); ErrNoSession for a session that is not
// live.
func (u *Users) PendingProviderStepUp(ctx context.Context, session uuid.UUID, window time.Duration) (time.Time, error) {
	var notBefore *time.Time
	var pending bool
	err := u.pool.QueryRow(ctx, `SELECT step_up_not_before, coalesce(step_up_not_before > now() - make_interval(secs => $2), false)
		FROM sessions WHERE id = $1 AND revoked_at IS NULL AND expires_at > now()`, session, window.Seconds()).Scan(&notBefore, &pending)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, ErrNoSession
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("store: read a step-up: %w", err)
	}
	if notBefore == nil || !pending {
		return time.Time{}, ErrStepUpNotStarted
	}
	return *notBefore, nil
}

// FinishProviderStepUp records the proof of a step-up at the identity
// provider, in one statement: the session is live, its pending start is
// still notBefore (the value the caller read before asking the provider) and
// younger than window, and the provider's authTime is not earlier than
// notBefore less tolerance (the two clocks). Then authenticated_at becomes
// now() and the start is cleared, so one start makes one proof: a second
// finish of the same start, or the finish of a start a newer one replaced,
// finds nothing (ErrStepUpNotStarted). ErrStepUpStale for an authTime
// before the start; ErrNoSession for a session that is not live. A refusal
// changes nothing: the start stays until it is used, replaced or too old.
func (u *Users) FinishProviderStepUp(ctx context.Context, session uuid.UUID, notBefore, authTime time.Time, window, tolerance time.Duration) error {
	if authTime.IsZero() || authTime.Before(notBefore.Add(-tolerance)) {
		return ErrStepUpStale
	}
	tag, err := u.pool.Exec(ctx, `UPDATE sessions SET authenticated_at = now(), step_up_not_before = NULL
		WHERE id = $1 AND revoked_at IS NULL AND expires_at > now()
		  AND step_up_not_before = $2 AND $2 > now() - make_interval(secs => $3)
		  AND $4::timestamptz >= $2::timestamptz - make_interval(secs => $5)`,
		session, notBefore, window.Seconds(), authTime, tolerance.Seconds())
	if err != nil {
		return fmt.Errorf("store: record a step-up: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	if _, err := u.PendingProviderStepUp(ctx, session, window); errors.Is(err, ErrNoSession) {
		return ErrNoSession
	}
	return ErrStepUpNotStarted
}

// PlatformLinkOf returns the link of an account to the identity provider,
// or ErrNotFound for an account that has none.
func (u *Users) PlatformLinkOf(ctx context.Context, userID uuid.UUID) (PlatformIdentity, error) {
	out := PlatformIdentity{UserID: userID}
	err := u.pool.QueryRow(ctx, `SELECT sub, email, linked_from FROM platform_identities WHERE user_id = $1`, userID).
		Scan(&out.Sub, &out.Email, &out.LinkedFrom)
	if errors.Is(err, pgx.ErrNoRows) {
		return PlatformIdentity{}, ErrNotFound
	}
	if err != nil {
		return PlatformIdentity{}, fmt.Errorf("store: platform link: %w", err)
	}
	return out, nil
}

// Pinned returns the product key pinned for (sub, productKeyID), or
// ErrNotFound, without pinning anything: a step-up compares the key the
// provider presents with the pin and never makes one (Decision 4 of step
// 4). Only a sign-in pins (InsertPin).
func (p *PlatformPins) Pinned(ctx context.Context, sub uuid.UUID, productKeyID string) ([]byte, error) {
	var key []byte
	err := p.pool.QueryRow(ctx, `SELECT product_key FROM platform_key_pins WHERE sub = $1 AND product_key_id = $2`, sub, productKeyID).Scan(&key)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: pin: %w", err)
	}
	return key, nil
}
