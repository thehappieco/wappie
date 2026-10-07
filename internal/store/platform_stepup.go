package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/pg"
)

// The step-up of an account that signs in through the identity provider
// (owner decision D3, step 4; docs/platform-sign-in.md, "Step-ups"). The
// session records when it started one (sessions.step_up_not_before, 0048);
// the provider re-authenticates the person with prompt=login; and the finish
// takes the provider's auth_time from userinfo. The proof it records is the
// one every step-up writes, sessions.authenticated_at = now() on the
// database's clock (0047), so nothing that asks for a proof changes.
//
// The finish may come from another live session of the starter's family, the
// browser sign-in both were derived from (sessions.family_id): the console's
// confirmation window holds only the browser's sign-in token, while the page
// that started works in a session a workspace switch derived from it, and
// the page that confirmed in the same tab reopens a new one from the sign-in.
// So a start voids every other start of its family, a family has one pending
// start at most, and a finish from any session of the family answers it and
// records the proof on the session that started it and on the one that
// finished it: two windows or tabs make one proof. The starts and finishes of
// one family take the family's lock (lockStepUpFamily) and run one after the
// other, so two tabs that start at once leave one start, the later. A session
// of another sign-in, even of the same account, finds no start.

var (
	// ErrStepUpNotStarted is a finish with no start to answer: none was
	// made in the session's family, it was used already, a newer start of
	// the family replaced it, or it is older than the window.
	ErrStepUpNotStarted = errors.New("store: no step-up at the identity provider is pending for this session")
	// ErrStepUpStale is a re-authentication the provider dates before the
	// start, beyond the clocks' tolerance: it answered from an earlier
	// sign-in instead of asking the person again.
	ErrStepUpStale = errors.New("store: the identity provider's re-authentication is older than the step-up's start")
)

// StartProviderStepUp records that a live session starts a step-up at the
// identity provider, now on the database's clock, and returns that time. A
// start replaces every earlier one of the session's family, its own or
// another tab's, which then proves nothing: of two tabs that start one after
// the other, only the later start can be finished, whichever window finishes
// it. ErrNoSession for a session that is not live. The caller has checked
// that the account steps up at the provider.
func (u *Users) StartProviderStepUp(ctx context.Context, session uuid.UUID) (time.Time, error) {
	var notBefore time.Time
	err := pg.InTx(ctx, u.pool, func(tx pgx.Tx) error {
		user, family, err := lockStepUpFamily(ctx, tx, session)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE sessions SET step_up_not_before = NULL
			WHERE user_id = $1 AND family_id = $2 AND id <> $3 AND step_up_not_before IS NOT NULL`, user, family, session); err != nil {
			return err
		}
		err = tx.QueryRow(ctx, `UPDATE sessions SET step_up_not_before = now()
			WHERE id = $1 AND revoked_at IS NULL AND expires_at > now() RETURNING step_up_not_before`, session).Scan(&notBefore)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNoSession
		}
		return err
	})
	if errors.Is(err, ErrNoSession) {
		return time.Time{}, ErrNoSession
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("store: start a step-up: %w", err)
	}
	return notBefore, nil
}

// lockStepUpFamily reads a live session's account and family (the browser
// sign-in it was derived from, sessions.family_id) and takes the family's
// step-up lock until the transaction ends, so the starts and finishes of one
// family run one after the other: a start sees, and voids, the start another
// tab made a moment before, and a finish sees what the start before it left.
// ErrNoSession for a session that is not live.
func lockStepUpFamily(ctx context.Context, tx pgx.Tx, session uuid.UUID) (uuid.UUID, uuid.UUID, error) {
	var user, family uuid.UUID
	err := tx.QueryRow(ctx, `SELECT user_id, family_id FROM sessions WHERE id = $1 AND revoked_at IS NULL AND expires_at > now()`, session).Scan(&user, &family)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, uuid.Nil, ErrNoSession
	}
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "platform-step-up/"+family.String()); err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	return user, family, nil
}

// PendingStepUp is a step-up at the identity provider waiting for its
// finish: the session that started it and when.
type PendingStepUp struct {
	Session   uuid.UUID
	NotBefore time.Time
}

// PendingProviderStepUp returns the start of a step-up at the identity
// provider among the live sessions of a live session's family (the newest,
// though a start leaves no other), while it is younger than window on the
// database's clock: what a finish from that session answers.
// ErrStepUpNotStarted when there is none (never started, used, replaced or
// too old); ErrNoSession for a session that is not live.
func (u *Users) PendingProviderStepUp(ctx context.Context, session uuid.UUID, window time.Duration) (PendingStepUp, error) {
	var live bool
	var starter *uuid.UUID
	var notBefore *time.Time
	err := u.pool.QueryRow(ctx, `WITH caller AS (
			SELECT user_id, family_id FROM sessions WHERE id = $1 AND revoked_at IS NULL AND expires_at > now())
		SELECT EXISTS (SELECT 1 FROM caller), s.id, s.step_up_not_before
		FROM (SELECT 1) one
		LEFT JOIN LATERAL (
			SELECT s.id, s.step_up_not_before FROM sessions s JOIN caller c ON s.user_id = c.user_id AND s.family_id = c.family_id
			WHERE s.revoked_at IS NULL AND s.expires_at > now() AND s.step_up_not_before > now() - make_interval(secs => $2)
			ORDER BY s.step_up_not_before DESC, s.id DESC LIMIT 1) s ON true`, session, window.Seconds()).Scan(&live, &starter, &notBefore)
	if err != nil {
		return PendingStepUp{}, fmt.Errorf("store: read a step-up: %w", err)
	}
	if !live {
		return PendingStepUp{}, ErrNoSession
	}
	if starter == nil || notBefore == nil {
		return PendingStepUp{}, ErrStepUpNotStarted
	}
	return PendingStepUp{Session: *starter, NotBefore: *notBefore}, nil
}

// FinishProviderStepUp records the proof of a step-up at the identity
// provider, under the family's lock and in one statement: the finishing
// session and the starter are live and of one family, the starter's pending
// start is still pending.NotBefore (what the caller read before asking the
// provider) and younger than window, and the provider's authTime is not
// earlier than that start less tolerance (the two clocks). Then the starter's
// authenticated_at becomes now() and its start is cleared, so one start makes
// one proof: a second finish of the same start, from any session of the
// family, or the finish of a start a newer one replaced, finds nothing
// (ErrStepUpNotStarted). The finishing session gets the same proof, and any
// other start of the family no newer than the one answered is cleared too (a
// start leaves none, so this only keeps the rule should one be there).
// ErrStepUpStale for an authTime before the start; ErrNoSession for a
// finishing session that is not live. A refusal changes nothing: the start
// stays until it is used, replaced or too old.
func (u *Users) FinishProviderStepUp(ctx context.Context, session uuid.UUID, pending PendingStepUp, authTime time.Time, window, tolerance time.Duration) error {
	if authTime.IsZero() || authTime.Before(pending.NotBefore.Add(-tolerance)) {
		return ErrStepUpStale
	}
	var proved int
	err := pg.InTx(ctx, u.pool, func(tx pgx.Tx) error {
		user, family, err := lockStepUpFamily(ctx, tx, session)
		if err != nil {
			return err
		}
		err = tx.QueryRow(ctx, `WITH caller AS (
				SELECT id, user_id, family_id FROM sessions WHERE id = $1 AND revoked_at IS NULL AND expires_at > now()),
			started AS (
				UPDATE sessions s SET authenticated_at = now(), step_up_not_before = NULL
				FROM caller c
				WHERE s.id = $2 AND s.user_id = c.user_id AND s.family_id = c.family_id
				  AND s.revoked_at IS NULL AND s.expires_at > now()
				  AND s.step_up_not_before = $3 AND $3 > now() - make_interval(secs => $4)
				  AND $5::timestamptz >= $3::timestamptz - make_interval(secs => $6)
				RETURNING s.id),
			-- Run to completion whether or not the query reads it, as every
			-- data-modifying WITH is.
			finished AS (
				UPDATE sessions s SET authenticated_at = now()
				FROM caller c
				WHERE s.id = c.id AND s.id <> $2 AND EXISTS (SELECT 1 FROM started)
				RETURNING s.id)
			SELECT (SELECT count(*) FROM started)::int`,
			session, pending.Session, pending.NotBefore, window.Seconds(), authTime, tolerance.Seconds()).Scan(&proved)
		if err != nil || proved != 1 {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE sessions SET step_up_not_before = NULL
			WHERE user_id = $1 AND family_id = $2 AND step_up_not_before <= $3`, user, family, pending.NotBefore)
		return err
	})
	if errors.Is(err, ErrNoSession) {
		return ErrNoSession
	}
	if err != nil {
		return fmt.Errorf("store: record a step-up: %w", err)
	}
	if proved == 1 {
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
