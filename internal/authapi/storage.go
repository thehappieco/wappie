package authapi

import (
	"errors"
	"net/http"
	"whatserver2/internal/store"
)

func (h *Handler) storageUsage(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	if h.Storage == nil {
		fail(w, 503, "storage_unavailable", "storage administration is unavailable")
		return
	}
	if user.Role != "owner" && user.Role != "admin" {
		fail(w, 403, "forbidden", "workspace administrator required")
		return
	}
	if r.Method == http.MethodGet && r.PathValue("action") == "history" {
		out, err := h.Storage.History(r.Context(), user.TenantID)
		if err != nil {
			fail(w, 500, "internal", "could not read storage history")
			return
		}
		send(w, http.StatusOK, out)
		return
	}
	if r.Method == http.MethodPost {
		var err error
		switch r.PathValue("action") {
		case "resume":
			err = h.Storage.Resume(r.Context(), user.TenantID)
		case "reconcile":
			_, err = h.Storage.Reconcile(r.Context(), user.TenantID)
		default:
			fail(w, 404, "not_found", "unknown storage action")
			return
		}
		if errors.Is(err, store.ErrStoragePaused) {
			fail(w, 409, "storage_paused", err.Error())
			return
		}
		if err != nil {
			fail(w, 500, "internal", "storage operation failed")
			return
		}
	}
	out, err := h.Storage.UsageDetailed(r.Context(), user.TenantID)
	if err != nil {
		fail(w, 500, "internal", "could not read storage usage")
		return
	}
	send(w, http.StatusOK, out)
}
