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
	kc "github.com/thehappieco/kit/contract"

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
	// Access authenticates and authorizes every request; nil is a Checker
	// of APIKeys and Users alone, which refuses every platform token.
	Access *access.Checker
	Log    *slog.Logger
}

// checker is the Checker every request goes through.
func (h *Handler) checker() *access.Checker {
	if h.Access != nil {
		return h.Access
	}
	return &access.Checker{Keys: h.APIKeys, Users: h.Users, Log: h.Log}
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
		// A platform token's request, decided on the raw header before
		// anything else reads it: the token's text comes only from the
		// kit's reading of the header, is never trimmed and never tried as a
		// session or a key, and every refusal, from the header's shape to
		// the token's state, is the one token 401 after a fixed wait.
		if values := r.Header.Values("Authorization"); access.TokenRequest(values) {
			text, err := kc.BearerToken(values)
			var actor access.Actor
			if err == nil {
				actor, err = h.checker().AuthenticateToken(ctx, text, h.checker().Peer(r))
			}
			if err != nil {
				access.Wait(ctx)
				fail(w, http.StatusUnauthorized, "unauthorized", "credential expired, revoked or invalid")
				return
			}
			next(&request{h: h, w: w, r: r, actor: actor, token: text, checks: map[uuid.UUID]store.DeviceAction{}})
			return
		}
		parts := strings.Fields(r.Header.Get("Authorization"))
		if len(r.Header.Values("Authorization")) != 1 || len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) > 4096 {
			fail(w, http.StatusUnauthorized, "unauthorized", "a bearer session or API key is required")
			return
		}
		actor, err := h.checker().Authenticate(ctx, parts[1])
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
	actor, err := q.h.checker().Recheck(q.r.Context(), q.token)
	if err != nil {
		fail(q.w, http.StatusUnauthorized, "unauthorized", "credential expired, revoked or invalid")
		return
	}
	if actor != q.actor {
		fail(q.w, http.StatusForbidden, "not_authorized", "workspace access changed; retry the request")
		return
	}
	if actor.IsToken() {
		q.finishToken(value)
		return
	}
	for device, action := range q.checks {
		allowed, err := q.h.checker().Probe(q.r.Context(), actor, device, action)
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

// finishToken is finish's last check for a token: what it reaches now, in
// one query and never counted (F4). Every number the answer holds must
// still be in its set, and with the attachments switch off every row with
// an attachment is withheld.
func (q *request) finishToken(value any) {
	live, err := q.h.checker().TokenSets(q.r.Context(), q.actor)
	if err != nil {
		q.internal(err)
		return
	}
	if !live.Live {
		fail(q.w, http.StatusForbidden, "not_authorized", "workspace access changed; retry the request")
		return
	}
	for device, action := range q.checks {
		if !tokenReaches(live, device, action) {
			fail(q.w, http.StatusForbidden, "not_authorized", "device access changed; retry the request")
			return
		}
	}
	if w, ok := value.(interface{ WithholdAttachments() }); ok && !live.MediaOn {
		w.WithholdAttachments()
	}
	writeJSON(q.w, http.StatusOK, value)
}

// tokenReaches reports whether a token's sets hold device for action: read
// and view are Reads, send Sends, manage and pause Manages.
func tokenReaches(live store.TokenLive, device uuid.UUID, action store.DeviceAction) bool {
	set := live.Reads
	switch action {
	case store.ActionSend:
		set = live.Sends
	case store.ActionManage, store.ActionPause:
		set = live.Manages
	}
	_, ok := set[device]
	return ok
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
	ok, err := q.h.checker().Allows(q.r.Context(), q.actor, device, action)
	if ok && err == nil {
		q.checks[device] = action
	}
	return ok, err
}

func (q *request) device(action store.DeviceAction) (store.Device, bool) {
	raw := q.r.PathValue("device")
	id, ok := q.uuid(raw)
	if !ok {
		return store.Device{}, false
	}
	if q.actor.IsToken() {
		return q.tokenDevice(raw, id, action)
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

// tokenDevice is device for a token: a full canonical id only, and the
// check before any lookup, so a number that does not exist, one deleted,
// another workspace's and one refused all get the same answer, which holds
// no id.
func (q *request) tokenDevice(raw string, id uuid.UUID, action store.DeviceAction) (store.Device, bool) {
	if id.String() != raw {
		q.bad("a complete, nonzero UUID is required")
		return store.Device{}, false
	}
	allowed, err := q.permitted(id, action)
	if err != nil {
		q.internal(err)
		return store.Device{}, false
	}
	var device store.Device
	if allowed {
		device, err = q.h.Devices.Get(q.r.Context(), q.actor.Tenant.String(), id.String())
		if err != nil && !errors.Is(err, store.ErrNotFound) && !errors.Is(err, pgx.ErrNoRows) {
			q.internal(err)
			return store.Device{}, false
		}
	}
	if !allowed || err != nil {
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
