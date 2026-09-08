package authapi

import "net/http"

func (h *Handler) capacity(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	out, err := h.Users.Capacity(r.Context(), user.TenantID, user.ID)
	if err != nil {
		h.memberError(w, err)
		return
	}
	send(w, 200, out)
}
