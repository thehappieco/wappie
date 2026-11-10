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
	if !h.freshPermission(r.Context(), w, user, p) {
		return
	}
	ended, err := h.Users.SetDevicePermissionEnded(r.Context(), user.TenantID, user.ID, p)
	if err != nil {
		h.memberError(w, err)
		return
	}
	h.accessChanged()
	// Read going, or no flag left, ends the person's own connections that
	// held the number; they are told now, as a revoke is (DS47).
	for _, e := range ended {
		if h.Readers != nil {
			h.Readers.TellRevoked(r.Context(), e.Reader, e.ID)
		}
		h.log().Info("mcp connection revoked", "connection", e.ID, "reason", store.ReasonAccessLost)
	}
	w.WriteHeader(204)
}
