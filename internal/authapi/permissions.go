package authapi

import (
	"github.com/google/uuid"
	"net/http"
	"whatserver2/internal/store"
)

func (h *Handler) permissions(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	device, err := uuid.Parse(r.PathValue("deviceID"))
	if err != nil {
		fail(w, 400, "bad_request", "invalid device id")
		return
	}
	if r.Method == http.MethodGet {
		rows, err := h.Users.DevicePermissions(r.Context(), user.TenantID, user.ID, device)
		if err != nil {
			h.memberError(w, err)
			return
		}
		send(w, 200, struct {
			Permissions []store.DevicePermission `json:"permissions"`
		}{rows})
		return
	}
	var p store.DevicePermission
	if !decode(w, r, &p) {
		return
	}
	p.DeviceID = device
	if err := h.Users.SetDevicePermission(r.Context(), user.TenantID, user.ID, p); err != nil {
		h.memberError(w, err)
		return
	}
	h.accessChanged()
	w.WriteHeader(204)
}
