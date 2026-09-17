// Package restapi serves the sealed archive over HTTP. It shares authorization,
// persistence and wire representations with the WebSocket API.
package restapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"whatserver2/internal/access"
	"whatserver2/internal/store"
)

// Handler has no sender, downloader or private archive keys. Reading through
// this API cannot start a WhatsApp connection or resume suspended capture.
type Handler struct {
	APIKeys  *store.APIKeys
	Users    *store.Users
	Keys     *store.Keys
	Devices  *store.Devices
	Messages *store.Messages
	Contacts *store.Contacts
	Receipts *store.Receipts
	Running  func(deviceID string) bool
	Log      *slog.Logger
}

// Mount adds read-only routes; Go's mux refuses unsupported write methods.
func (h *Handler) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/devices", h.authenticated(h.devices))
	mux.HandleFunc("GET /v1/devices/{device}/chats", h.authenticated(h.chats))
	mux.HandleFunc("GET /v1/devices/{device}/messages", h.authenticated(h.page))
	mux.HandleFunc("GET /v1/devices/{device}/contacts", h.authenticated(h.contacts))
	mux.HandleFunc("GET /v1/devices/{device}/messages/scan", h.authenticated(h.scan))
	mux.HandleFunc("GET /v1/devices/{device}/keys", h.authenticated(h.contentKeys))
	mux.HandleFunc("GET /v1/messages/{uid}", h.authenticated(h.message))
	mux.HandleFunc("GET /v1/messages/{uid}/history", h.authenticated(h.history))
	mux.HandleFunc("GET /v1/grants", h.authenticated(h.grants))
	mux.HandleFunc("GET /v1/openapi.json", h.openAPI)
}

type request struct {
	h      *Handler
	w      http.ResponseWriter
	r      *http.Request
	actor  access.Actor
	token  string
	checks map[uuid.UUID]store.DeviceAction
}

func (h *Handler) authenticated(next func(*request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		r = r.WithContext(ctx)
		parts := strings.Fields(r.Header.Get("Authorization"))
		if len(r.Header.Values("Authorization")) != 1 || len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) > 4096 {
			fail(w, http.StatusUnauthorized, "unauthorized", "a bearer session or API key is required")
			return
		}
		actor, err := access.Authenticate(ctx, parts[1], h.APIKeys, h.Users)
		if err != nil {
			fail(w, http.StatusUnauthorized, "unauthorized", "credential expired, revoked or invalid")
			return
		}
		if actor.Tenant == uuid.Nil {
			fail(w, http.StatusForbidden, "not_authorized", "select an active workspace first")
			return
		}
		next(&request{h: h, w: w, r: r, actor: actor, token: parts[1], checks: map[uuid.UUID]store.DeviceAction{}})
	}
}

// finish rechecks both the credential and every returned device immediately
// before serialization. A revoked key/grant must not publish a stale query.
func (q *request) finish(value any) {
	actor, err := access.Authenticate(q.r.Context(), q.token, q.h.APIKeys, q.h.Users)
	if err != nil {
		fail(q.w, http.StatusUnauthorized, "unauthorized", "credential expired, revoked or invalid")
		return
	}
	if actor != q.actor {
		fail(q.w, http.StatusForbidden, "not_authorized", "workspace access changed; retry the request")
		return
	}
	for device, action := range q.checks {
		allowed, err := access.Allows(q.r.Context(), actor, device, action, q.h.APIKeys, q.h.Users)
		if err != nil {
			q.internal(err)
			return
		}
		if !allowed {
			fail(q.w, http.StatusForbidden, "not_authorized", "device access changed; retry the request")
			return
		}
	}
	writeJSON(q.w, http.StatusOK, value)
}

func (q *request) query(allowed ...string) (url.Values, bool) {
	if len(q.r.URL.RawQuery) > 8192 {
		q.bad("query is too long")
		return nil, false
	}
	values, err := url.ParseQuery(q.r.URL.RawQuery)
	if err != nil {
		q.bad("invalid query parameters")
		return nil, false
	}
	for name, items := range values {
		if !slices.Contains(allowed, name) || len(items) != 1 {
			q.bad("unknown or repeated query parameter")
			return nil, false
		}
	}
	return values, true
}

func (q *request) permitted(device uuid.UUID, action store.DeviceAction) (bool, error) {
	ok, err := access.Allows(q.r.Context(), q.actor, device, action, q.h.APIKeys, q.h.Users)
	if ok && err == nil {
		q.checks[device] = action
	}
	return ok, err
}

func (q *request) device(action store.DeviceAction) (store.Device, bool) {
	id, ok := q.uuid(q.r.PathValue("device"))
	if !ok {
		return store.Device{}, false
	}
	device, err := q.h.Devices.Get(q.r.Context(), q.actor.Tenant.String(), id.String())
	if err != nil {
		q.storeError(err)
		return store.Device{}, false
	}
	allowed, err := q.permitted(id, action)
	if err != nil {
		q.internal(err)
		return store.Device{}, false
	}
	if !allowed {
		fail(q.w, http.StatusForbidden, "not_authorized", "this credential cannot access the device")
		return store.Device{}, false
	}
	return device, true
}

func (q *request) uuid(raw string) (uuid.UUID, bool) {
	id, err := uuid.Parse(raw)
	if err != nil || len(raw) != 36 || id == uuid.Nil {
		q.bad("a complete, nonzero UUID is required")
		return uuid.Nil, false
	}
	return id, true
}
func (q *request) limit(values url.Values, fallback, maximum int) (int, bool) {
	raw, exists := values["limit"]
	if !exists {
		return fallback, true
	}
	n, err := strconv.Atoi(raw[0])
	if err != nil || n < 1 || n > maximum {
		q.bad("limit is outside the supported range")
		return 0, false
	}
	return n, true
}
func (q *request) bad(message string) { fail(q.w, http.StatusBadRequest, "bad_request", message) }
func (q *request) storeError(err error) {
	if errors.Is(err, store.ErrNotFound) || errors.Is(err, pgx.ErrNoRows) {
		fail(q.w, http.StatusNotFound, "not_found", "requested archive item was not found")
		return
	}
	q.internal(err)
}
func (q *request) internal(err error) {
	if q.h.Log != nil {
		q.h.Log.Error("REST archive request failed", "error", err)
	}
	fail(q.w, http.StatusInternalServerError, "internal", "could not read the archive")
}
func fail(w http.ResponseWriter, status int, code, message string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="wappie"`)
	}
	writeJSON(w, status, struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}{code, message})
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		return
	} // The requester disconnected; never append another JSON response.
}
