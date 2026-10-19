package authapi

import (
	"context"
	"net/http"

	"github.com/google/uuid"

	"whatserver2/internal/membership"
	"whatserver2/internal/store"
)

// The contract's freshness hook at the routes' gated acts (README 7.1;
// design 2.6; the plan's 4.12), each before the act's store transaction:
// raising someone's flags (the actor and the recipient IfStale), withholding
// Read (the minute rule for the number's remaining key holders), and a
// standing service account, at its invitation and at its registration (the
// issuer IfStale). Release B only logs the verdicts (DB4); with the enforce
// flag a refusal is 503 memberships_unconfirmed and nothing changes.

// fresh asks the hook for an act in tenant; false when it is refused,
// which is answered.
func (h *Handler) fresh(ctx context.Context, w http.ResponseWriter, act string, tenant uuid.UUID, parties ...membership.Party) bool {
	if h.Freshness == nil {
		return true
	}
	_, err := h.Freshness.RequireFresh(ctx, act, tenant, parties...)
	return freshAnswer(w, err)
}

// freshAnswer answers a hook's refusal, which only the enforce flag makes.
func freshAnswer(w http.ResponseWriter, err error) bool {
	if err == nil {
		return true
	}
	w.Header().Set("Retry-After", "60")
	fail(w, http.StatusServiceUnavailable, "memberships_unconfirmed",
		"could not confirm the memberships with The Happie Co; nothing changed, try again in a minute")
	return false
}

// The acts' names in the hook's logs.
const (
	actPermissionRaise = "permission.raise"
	actPermissionRead  = "permission.withhold_read"
	actServiceInvite   = "service.invite"
	actServiceSignup   = "service.signup"
)

// freshPermission is the hook of a permission change by actor, read
// against the row as stored: a flag raised gates the actor and the
// recipient, Read withheld from someone who has it or holds the key is the
// minute rule. A change that does neither, or a caller who manages
// nothing (the store refuses them), asks nothing.
func (h *Handler) freshPermission(ctx context.Context, w http.ResponseWriter, user store.User, p store.DevicePermission) bool {
	if h.Freshness == nil || (user.Role != "owner" && user.Role != "admin") {
		return true
	}
	was, err := h.Users.StoredDevicePermission(ctx, user.TenantID, p.UserID, p.DeviceID)
	if err != nil {
		// The store's own read decides the change; the hook asks nothing.
		h.log().Warn("freshness: could not read a permission before its change", "tenant", user.TenantID, "error", err)
		return true
	}
	if (p.Read && !was.Read) || (p.Send && !was.Send) || (p.Manage && !was.Manage) {
		parties := []membership.Party{{User: user.ID, How: membership.IfStale}}
		if p.UserID != user.ID {
			parties = append(parties, membership.Party{User: p.UserID, How: membership.IfStale})
		}
		if !h.fresh(ctx, w, actPermissionRaise, user.TenantID, parties...) {
			return false
		}
	}
	if !p.Read && (was.Read || was.HasKey) {
		_, err := h.Freshness.RequireBackups(ctx, actPermissionRead, user.TenantID, p.DeviceID, p.UserID)
		return freshAnswer(w, err)
	}
	return true
}
