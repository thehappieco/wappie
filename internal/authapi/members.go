package authapi

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
	"whatserver2/internal/store"
)

func (h *Handler) memberError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrPersonalWorkspace):
		fail(w, http.StatusConflict, "personal_workspace", "create a team workspace to invite people")
	case errors.Is(err, store.ErrInviteInvalid):
		fail(w, http.StatusConflict, "invite_invalid", "the invitation is expired, revoked or already accepted")
	case errors.Is(err, store.ErrInviteNotRecoverable):
		fail(w, http.StatusConflict, "invite_not_recoverable", "the original code cannot be recovered; generate a new invitation")
	case errors.Is(err, store.ErrMembershipForbidden):
		fail(w, http.StatusForbidden, "not_authorized", "this action requires a workspace owner or an authorized administrator")
	case errors.Is(err, store.ErrLastOwner):
		fail(w, http.StatusConflict, "last_owner", "the workspace must retain an active owner")
	case errors.Is(err, store.ErrLastDeviceReader):
		fail(w, http.StatusConflict, "last_device_reader", "give another active member read access to this number before removing its last reader")
	case errors.Is(err, store.ErrInvalidMembership):
		fail(w, http.StatusBadRequest, "bad_request", "invalid role, status or invitation address")
	case errors.Is(err, store.ErrNotFound):
		fail(w, http.StatusNotFound, "not_found", "no such member in this workspace")
	default:
		h.log().Error("workspace membership operation failed", "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not manage workspace members")
	}
}

func (h *Handler) members(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	members, err := h.Users.Members(r.Context(), user.TenantID, user.ID)
	if err != nil {
		h.memberError(w, err)
		return
	}
	send(w, http.StatusOK, struct {
		Members []store.Member `json:"members"`
	}{members})
}

func (h *Handler) updateMember(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	target, err := uuid.Parse(r.PathValue("userID"))
	if err != nil {
		fail(w, http.StatusBadRequest, "bad_request", "user id must be a UUID")
		return
	}
	var req struct {
		Role   string `json:"role"`
		Status string `json:"status"`
	}
	if !decode(w, r, &req) {
		return
	}
	if err := h.Users.UpdateMember(r.Context(), user.TenantID, user.ID, target, req.Role, req.Status); err != nil {
		h.memberError(w, err)
		return
	}
	h.accessChanged()
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) removeMember(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	target, err := uuid.Parse(r.PathValue("userID"))
	if err != nil {
		fail(w, http.StatusBadRequest, "bad_request", "user id must be a UUID")
		return
	}
	if !h.allow(w, r, user.Email) {
		return
	}
	if err := h.Users.RemoveMember(r.Context(), user.TenantID, user.ID, target); err != nil {
		h.memberError(w, err)
		return
	}
	h.accessChanged()
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) inviteMember(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	var req struct {
		Role  string `json:"role"`
		Email string `json:"email"`
	}
	if !decode(w, r, &req) || !h.allow(w, r, user.Email) {
		return
	}
	invite, invitation, err := h.Users.NewMemberInvitation(r.Context(), user.TenantID, user.ID, req.Role, req.Email)
	if err != nil {
		h.memberError(w, err)
		return
	}
	send(w, http.StatusCreated, map[string]any{"invite": invite, "invitation": invitation, "email_sent": h.deliverWorkspaceInvite(r, user, invite, invitation.Email)})
}

func (h *Handler) accessChanged() {
	if h.AccessChanged != nil {
		h.AccessChanged()
	}
}
