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
// This interface is the only one, for every account. What changes with the
// account's source is how its session earns a proof, never what a guarded
// write asks (owner decision D3, docs/platform-sign-in.md, "Step-ups"):
//
//   - An account with auth_source 'local' proves itself here, as above.
//   - An account with auth_source 'platform' signs in through the identity
//     provider (id.thehappie.co in the cloud), and proves itself there:
//     Wappie runs no WebAuthn for it (platform decision 0008) and takes no
//     password from it, so its passkey and password step-ups answer
//     ProviderCode while the provider is configured. Its step-up is step 4
//     of the sign-in plan: POST /v1/auth/platform/step-up/start records
//     sessions.step_up_not_before (migration 0048) for the session; the
//     console sends the person to the provider with prompt=login; POST
//     /v1/auth/platform/step-up/finish takes the access token to the
//     provider's userinfo (never the ID token), requires the linked sub,
//     this client, the pinned account key and an auth_time no more than
//     ProviderClockTolerance before the start, within Window of it, and
//     records the proof as the passkey and password do, in
//     sessions.authenticated_at (0047), clearing the start: one start, one
//     proof (store.Users.FinishProviderStepUp).
//   - A sign-in through the provider is a proof from that userinfo's
//     auth_time, never from the session's creation
//     (store.Users.StartPlatformSession): the console asks for
//     prompt=login, so a fresh sign-in asks nothing more for ten minutes. A
//     link to the provider proves the old password, and so the person, now.
//
// With the provider unconfigured (the switch off for a rollback), a linked
// account signs in with its legacy password again and steps up as a local
// one.
package stepup

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Window is how long a proof lasts, and how long a step-up started at the
// identity provider waits for its finish.
const Window = 10 * time.Minute

// ProviderClockTolerance is how far before a step-up's start the identity
// provider's auth_time may fall and still count (Decision 3 of step 4): the
// two clocks may differ by that much. Nothing is allowed for the other
// direction, since the proof is always recorded at now on this server's
// database clock, never at the provider's time.
const ProviderClockTolerance = time.Minute

// Code is the error code a write refused for want of a fresh proof answers
// with; the console asks for the proof and tries again.
const Code = "step_up_required"

// Message is the text beside Code (E-STEP-01, approved 2026-10-06).
const Message = "confirm it is you first: with your passkey or your password, or at the identity provider your account " +
	"signs in with, or sign in again; giving an assistant message text, or anyone a number's key, needs it within the " +
	"last ten minutes"

// ProviderCode is what a passkey or password step-up answers for an account
// that signs in through the identity provider: its proof is the provider's
// re-authentication (D3), started at POST /v1/auth/platform/step-up/start.
const ProviderCode = "step_up_at_provider"

// ProviderMessage is the text beside ProviderCode (E-STEP-15, approved
// 2026-10-06).
const ProviderMessage = "this account confirms it is you at the identity provider it signs in with, not with a passkey " +
	"or password here: use POST /v1/auth/platform/step-up/start"

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
