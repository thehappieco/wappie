package authapi

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
	"whatserver2/internal/store"
)

func (h *Handler) workspaces(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	spaces, err := h.Users.Workspaces(r.Context(), user.ID)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", "could not list workspaces")
		return
	}
	send(w, http.StatusOK, struct {
		Workspaces []store.Workspace `json:"workspaces"`
	}{spaces})
}

func (h *Handler) updateWorkspace(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	var req struct {
		Name   string `json:"name"`
		Avatar string `json:"avatar"`
	}
	if !decode(w, r, &req) || !h.allow(w, r, user.Email) {
		return
	}
	space, err := h.Users.UpdateWorkspaceProfile(r.Context(), user.TenantID, user.ID, req.Name, req.Avatar)
	if errors.Is(err, store.ErrInvalidWorkspaceProfile) {
		fail(w, http.StatusBadRequest, "invalid_workspace_profile", "use a name of 1 to 80 characters and a PNG or JPEG avatar of at most 32 KiB and 512 pixels")
		return
	}
	if err != nil {
		h.memberError(w, err)
		return
	}
	send(w, http.StatusOK, space)
}

func (h *Handler) acceptWorkspaceInvite(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	var req struct {
		Invite string `json:"invite"`
	}
	if !decode(w, r, &req) || !h.allow(w, r, user.Email) {
		return
	}
	tenant, err := h.Users.AcceptWorkspaceInvite(r.Context(), user, req.Invite)
	if errors.Is(err, store.ErrInviteInvalid) {
		fail(w, http.StatusForbidden, "invite_invalid", "that workspace invite is not valid")
		return
	}
	if err != nil {
		h.log().Error("joining workspace failed", "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not join workspace")
		return
	}
	send(w, http.StatusOK, struct {
		TenantID uuid.UUID `json:"tenant_id"`
	}{tenant})
}

// A new token has an immutable workspace binding. Other tabs and existing
// WebSockets keep their old workspace; clients reconnect with the new token.
func (h *Handler) workspaceSession(w http.ResponseWriter, r *http.Request) {
	source, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	var req struct {
		TenantID string `json:"tenant_id"`
	}
	if !decode(w, r, &req) || !h.allow(w, r, user.Email) {
		return
	}
	tenant, err := uuid.Parse(req.TenantID)
	if err != nil {
		fail(w, http.StatusBadRequest, "bad_request", "tenant_id must be a UUID")
		return
	}
	member, err := h.Users.Get(r.Context(), tenant, user.ID)
	if errors.Is(err, store.ErrNotFound) {
		fail(w, http.StatusForbidden, "not_authorized", "workspace is unavailable")
		return
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", "could not open workspace")
		return
	}
	spaces, err := h.Users.Workspaces(r.Context(), user.ID)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", "could not open workspace")
		return
	}
	for _, space := range spaces {
		if space.ID == tenant && space.Status == "active" {
			token, session, err := h.Users.StartWorkspaceSession(r.Context(), member, r.UserAgent(), source.ExpiresAt, source.PasskeyID)
			if errors.Is(err, store.ErrNoSession) {
				fail(w, http.StatusForbidden, "not_authorized", "workspace is unavailable")
				return
			}
			if err != nil {
				fail(w, http.StatusInternalServerError, "internal", "could not open workspace")
				return
			}
			send(w, http.StatusOK, sessionReply{Token: token, ExpiresAt: session.ExpiresAt, User: toAccount(member)})
			return
		}
	}
	fail(w, http.StatusForbidden, "not_authorized", "workspace is unavailable")
}
