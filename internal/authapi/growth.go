package authapi

import (
	"net/http"

	"whatserver2/internal/store"
)

// Stopping growth (DS53): in the hosted build, an account of The Happie Co
// platform creates no workspace here and invites no person, as the
// platform's console manages both (decision 0040). Nothing stored changes:
// its workspaces, members and pending invitations stay, a pending code is
// still revealed, revoked and redeemed, and service invitations, the
// provisional ones included, stay open (step 7 decides those). Self-hosted
// builds and local accounts are unchanged.

// platformManaged reports whether an account is the platform's on this
// server: one that signs in through the identity provider (auth_source
// platform, as DS52's name rule reads it), while the provider is
// configured, which only the hosted build is (WS_PLATFORM_ISSUER). With the
// provider unset (self-hosted, or a rollback) no account is.
func (h *Handler) platformManaged(user store.User) bool {
	return h.Platform != nil && authSource(user) == store.PlatformAuthSource
}

// managedElsewhereMessage is the 409's message: where these acts went.
const managedElsewhereMessage = "The Happie Co's console manages this account's workspaces and members; create workspaces and invite people there"

// managedElsewhere answers an act the platform's console owns for a
// platform account: 409, the code enforce widens to member changes (E3).
func managedElsewhere(w http.ResponseWriter) {
	fail(w, http.StatusConflict, "managed_elsewhere", managedElsewhereMessage)
}
