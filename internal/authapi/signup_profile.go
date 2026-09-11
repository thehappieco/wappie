package authapi

import (
	"errors"
	"github.com/google/uuid"
	"net/http"
	"strings"
	"whatserver2/internal/store"
)

func (h *Handler) signupConfig(w http.ResponseWriter, r *http.Request) {
	send(w, http.StatusOK, map[string]bool{"enabled": h.PublicSignup && h.SendSignupVerification != nil, "email_verification_required": true})
}
func (h *Handler) signupVerification(w http.ResponseWriter, r *http.Request) {
	if !h.PublicSignup || h.SendSignupVerification == nil {
		fail(w, http.StatusForbidden, "signup_disabled", "public account registration is unavailable")
		return
	}
	var req struct {
		Email string `json:"email"`
	}
	if !decode(w, r, &req) || !h.allow(w, r, strings.ToLower(strings.TrimSpace(req.Email))) {
		return
	}
	token, err := h.Users.CreateSignupVerification(r.Context(), req.Email)
	if err != nil {
		if errors.Is(err, store.ErrInvalidMembership) {
			fail(w, http.StatusBadRequest, "bad_request", "enter a valid email address")
			return
		}
		h.log().Error("could not prepare signup verification")
		fail(w, http.StatusInternalServerError, "internal", "could not start account registration")
		return
	}
	if token != "" {
		if err = h.SendSignupVerification(r.Context(), strings.ToLower(strings.TrimSpace(req.Email)), token); err != nil {
			h.log().Warn("signup verification delivery failed")
		}
	}
	send(w, http.StatusAccepted, map[string]bool{"sent": true})
}
func (h *Handler) profile(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	var out store.Profile
	var err error
	if r.Method == http.MethodPut {
		var req struct {
			Name   string `json:"name"`
			Avatar string `json:"avatar"`
		}
		if !decode(w, r, &req) || !h.allow(w, r, user.Email) {
			return
		}
		out, err = h.Users.UpdateProfile(r.Context(), user.ID, req.Name, req.Avatar)
	} else {
		out, err = h.Users.Profile(r.Context(), user.ID)
	}
	if errors.Is(err, store.ErrInvalidWorkspaceProfile) {
		fail(w, http.StatusBadRequest, "invalid_profile", "use a name of 1 to 80 characters and a small PNG or JPEG avatar")
		return
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", "could not load or update your profile")
		return
	}
	send(w, http.StatusOK, out)
}
func (h *Handler) createWorkspace(w http.ResponseWriter, r *http.Request) {
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
	out, err := h.Users.CreateWorkspace(r.Context(), user, req.Name, req.Avatar)
	if errors.Is(err, store.ErrInvalidWorkspaceProfile) {
		fail(w, http.StatusBadRequest, "invalid_workspace_profile", "use a name of 1 to 80 characters and a small PNG or JPEG avatar")
		return
	}
	if err != nil {
		h.memberError(w, err)
		return
	}
	send(w, http.StatusCreated, out)
}
func (h *Handler) listInvitations(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	out, err := h.Users.Invitations(r.Context(), user.TenantID, user.ID)
	if err != nil {
		h.memberError(w, err)
		return
	}
	send(w, http.StatusOK, map[string]any{"invites": out})
}
func (h *Handler) invitationAction(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("inviteID"))
	if err != nil {
		fail(w, http.StatusBadRequest, "bad_request", "invitation id must be a UUID")
		return
	}
	if !h.allow(w, r, user.Email) {
		return
	}
	if r.Method == http.MethodDelete {
		err = h.Users.RevokeInvitation(r.Context(), user.TenantID, user.ID, id)
		if err != nil {
			h.memberError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/regenerate") {
		code, inv, e := h.Users.RegenerateInvitation(r.Context(), user.TenantID, user.ID, id)
		if e != nil {
			h.memberError(w, e)
			return
		}
		send(w, http.StatusCreated, map[string]any{"invite": code, "invitation": inv, "email_sent": h.deliverWorkspaceInvite(r, user, code, inv.Email)})
	} else {
		code, e := h.Users.RevealInvitation(r.Context(), user.TenantID, user.ID, id)
		if e != nil {
			h.memberError(w, e)
			return
		}
		send(w, http.StatusOK, map[string]string{"invite": code})
	}
}
func (h *Handler) deliverWorkspaceInvite(r *http.Request, user store.User, code, email string) bool {
	if email == "" || h.SendWorkspaceInvite == nil {
		return false
	}
	spaces, err := h.Users.Workspaces(r.Context(), user.ID)
	if err != nil {
		return false
	}
	name := "Wappie"
	for _, space := range spaces {
		if space.ID == user.TenantID {
			name = space.Name
			break
		}
	}
	if err = h.SendWorkspaceInvite(r.Context(), email, code, name); err != nil {
		h.log().Warn("workspace invitation delivery failed")
		return false
	}
	return true
}
