// Package stepup is the re-confirmation a signed-in person gives before an
// act that hands their archive on: letting an assistant's reader open message
// text (a content consent or a console token with text), renewing that
// access, an AI integration and its renewal, the provisional service
// invitation those write, and every grant of a number's key, to a member or
// a standing service account as much as to a connection's reader
// (docs/mcp-enclave.md §19.35).
//
// The browser already holds the account key that seals the grants, so the
// proof is not about keys. It is about the person in front of the screen: a
// signed-in browser left open must not be enough to hand a number's key to
// anyone. What hands over no key waits for none: an invitation, a role, an
// API key (one acting as a service account reads only what that account was
// granted) and the pairing of a new number, which needs its phone. A session
// is fresh while its person proved themselves within Window, on the
// database's clock: the sign-in that started the session's family, or a
// later step-up with one of the account's passkeys (a WebAuthn assertion with
// user verification) or the password, each checked by this server
// (internal/authapi).
//
// This is interim (decision D3): once sign-in moves to id.thehappie.co the
// proof becomes that provider's re-authentication (prompt=login). Only how a
// session earns its proof changes then; every guarded write keeps asking a
// Checker, and nothing else here.
package stepup

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Window is how long a proof lasts.
const Window = 10 * time.Minute

// Code is the error code a write refused for want of a fresh proof answers
// with; the console asks for the proof and tries again.
const Code = "step_up_required"

// Message is the text beside Code.
const Message = "confirm it is you first: use your passkey or your password, or sign in again; " +
	"giving an assistant message text, or anyone a number's key, needs it within the last ten minutes"

// Checker answers whether a session's person proved themselves within Window.
type Checker interface {
	Fresh(ctx context.Context, session uuid.UUID) (bool, error)
}

// Sessions is the session store's half of a Checker: whether a live
// session's person proved themselves within a window, on the store's clock.
type Sessions interface {
	AuthenticatedWithin(ctx context.Context, session uuid.UUID, window time.Duration) (bool, error)
}

// Recent is the Checker over a session store: a session is fresh while its
// last proof is within Window.
func Recent(s Sessions) Checker { return recent{s} }

type recent struct{ sessions Sessions }

func (r recent) Fresh(ctx context.Context, session uuid.UUID) (bool, error) {
	if session == uuid.Nil {
		return false, nil
	}
	return r.sessions.AuthenticatedWithin(ctx, session, Window)
}
