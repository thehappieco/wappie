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
//     ProviderCode while the provider is configured. Step 4 of the sign-in
//     plan adds its proof behind this same interface: a start route records
//     sessions.step_up_not_before (migration 0048) for the session; the
//     console sends the person to the provider with prompt=login; a finish
//     route takes the access token to the provider's userinfo (never the ID
//     token), requires the linked sub, this client and an auth_time at or
//     after step_up_not_before, and records the proof as the passkey and
//     password do, in sessions.authenticated_at (0047). A sign-in through
//     the provider may count as a proof only from that userinfo's auth_time.
//
// Until step 4, a session started through the provider holds no proof
// (authenticated_at is -infinity, store.Users.StartPlatformSession): every
// guarded write answers Code for it, and the step-up routes answer
// ProviderCode, so such an account is refused clearly wherever a proof is
// needed. With the provider unconfigured (the switch off for a rollback), a
// linked account signs in with its legacy password again and steps up as a
// local one.
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

// ProviderCode is what a passkey or password step-up answers for an account
// that signs in through the identity provider: its proof is the provider's
// re-authentication (D3), which this server does not take yet (step 4).
const ProviderCode = "step_up_at_provider"

// ProviderMessage is the text beside ProviderCode.
const ProviderMessage = "this account confirms it is you at the identity provider it signs in with, which this server " +
	"does not offer yet; until it does, giving an assistant message text or anyone a number's key is not available to it"

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
