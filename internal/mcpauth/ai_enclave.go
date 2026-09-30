package mcpauth

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/store"
)

// The enclave's AI routes (docs/mcp-enclave.md §18.11, enclave → Go): which
// authorization answers a media connection's request, the stored results,
// their reuse lookup and their storage, the usage and the alerts. Each is
// signed as every reader route is, and carries the path's row's own key as a
// bearer (§17.7): the signature proves the caller is the enclave, the key
// that the enclave holds this row. Everything else is 404.

// aiDerivedBody bounds a stored result's request: a 524,323-byte record in
// base64url, and the rest.
const aiDerivedBody = 768 << 10

// Bounds on one usage increment: far above what one job reports, low
// enough that no sum overflows its column.
const (
	aiUsageCountMax   = 1_000
	aiUsageTokensMax  = 1_000_000_000
	aiUsageSecondsMax = 1_000_000
	aiUsageCostMax    = 100_000_000_000_000_000
)

func (h *Handler) mountEnclaveAI(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/mcp/enclave/connections/{id}/ai", h.signed(maxBody, h.enclaveAIPick))
	mux.HandleFunc("GET /v1/mcp/enclave/connections/{id}/ai/derived", h.signed(maxBody, h.enclaveAIDerived))
	mux.HandleFunc("PUT /v1/mcp/enclave/connections/{id}/ai/derived/{uid}/{feature}", h.signed(aiDerivedBody, h.enclaveAIStore))
	mux.HandleFunc("POST /v1/mcp/enclave/connections/{id}/ai/usage", h.signed(maxBody, h.enclaveAIUsage))
	mux.HandleFunc("GET /v1/mcp/enclave/connections/{id}/ai/usage", h.signed(maxBody, h.enclaveAIMonth))
	mux.HandleFunc("POST /v1/mcp/enclave/connections/{id}/ai/alerts", h.signed(maxBody, h.enclaveAIAlert))
}

// readerRow is the second step of every AI route, after the signature: the
// row is the calling reader's, and the request carries its key, still live,
// as a bearer. Anything else is 404, and so is a route with no store.
func (h *Handler) readerRow(w http.ResponseWriter, r *http.Request, caller *AttestedReader) (store.ReaderRow, reader, bool) {
	id, ok := connectionID(w, r)
	if !ok {
		return store.ReaderRow{}, reader{}, false
	}
	rd, known := h.readerByID(caller.ID)
	row, err := h.Connections.ReaderRow(r.Context(), caller.ID, id)
	if errors.Is(err, store.ErrMCPConnectionNotFound) || err == nil && (!known || h.AI == nil) {
		fail(w, http.StatusNotFound, "not_found", "no such connection")
		return store.ReaderRow{}, reader{}, false
	}
	if err != nil {
		h.log().Error("could not read a reader's connection", "connection", id, "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not read the connection")
		return store.ReaderRow{}, reader{}, false
	}
	token, ok := bearerToken(r)
	if !ok || h.APIKeys == nil {
		fail(w, http.StatusNotFound, "not_found", "no such connection")
		return store.ReaderRow{}, reader{}, false
	}
	key, err := h.APIKeys.VerifyScoped(r.Context(), token)
	if err != nil || key.ID != row.APIKeyID || key.TenantID != row.TenantID.String() {
		fail(w, http.StatusNotFound, "not_found", "no such connection")
		return store.ReaderRow{}, reader{}, false
	}
	return row, rd, true
}

// mediaRow is a media connection that may open attachments now: active,
// its consent with attachments, and attachments allowed for its workspace.
func (h *Handler) mediaRow(row store.ReaderRow, rd reader) bool {
	return row.Kind == store.KindContent && row.Media && row.Active(time.Now()) && h.mediaAllowed(rd, row.TenantID)
}

// aiRow is an AI authorization that may run now: active, and AI allowed
// for its workspace.
func (h *Handler) aiRow(row store.ReaderRow, rd reader) bool {
	return row.Kind == store.KindAI && row.Config != nil && row.Active(time.Now()) && h.aiAllowed(rd, row.TenantID)
}

// strictQuery reads a query of exactly these names, each once.
func strictQuery(r *http.Request, names ...string) (url.Values, bool) {
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(values) != len(names) {
		return nil, false
	}
	for _, name := range names {
		if len(values[name]) != 1 {
			return nil, false
		}
	}
	return values, true
}

// aiPickReply is the authorization that answers a connector's request.
type aiPickReply struct {
	AuthorizationID string `json:"authorization_id"`
	RequesterID     string `json:"requester_id"`
	State           string `json:"state"`
}

// enclaveAIPick answers which authorization serves a media connection's
// request for a function on one of its numbers: PickAIAuthorization with
// the connection's creator as the requester, origin connector. A number
// outside the connection's key, a connection whose attachments are switched
// off now, and no authorization at all are 404 ai_not_enabled.
func (h *Handler) enclaveAIPick(w http.ResponseWriter, r *http.Request, caller *AttestedReader, _ []byte) {
	row, rd, ok := h.readerRow(w, r, caller)
	if !ok {
		return
	}
	values, ok := strictQuery(r, "device_id", "feature")
	device, okDevice := parseID(values.Get("device_id"))
	if !ok || !okDevice || !slices.Contains(store.AIFeatures, values.Get("feature")) {
		fail(w, http.StatusBadRequest, "bad_request", "device_id and feature are required, once each")
		return
	}
	notEnabled := func() {
		fail(w, http.StatusNotFound, "ai_not_enabled", "no AI integration covers this number for this connection")
	}
	if !h.mediaRow(row, rd) || !row.Devices[device] {
		notEnabled()
		return
	}
	pick, err := h.Connections.PickAIAuthorization(r.Context(), row.TenantID, row.CreatedBy, device, values.Get("feature"),
		store.AIOriginConnector, h.AIPolicy(row.TenantID))
	switch {
	case errors.Is(err, store.ErrAINotEnabled):
		notEnabled()
		return
	case err != nil:
		h.log().Error("could not pick an AI authorization", "connection", row.ID, "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not pick an AI authorization")
		return
	}
	send(w, http.StatusOK, aiPickReply{AuthorizationID: pick.AuthorizationID, RequesterID: pick.RequesterID.String(), State: pick.State})
}

// aiDerivedItem is one stored result as the enclave reads it: the sealed
// record and where it belongs. Only the connection's own grant opens it.
type aiDerivedItem struct {
	MessageUID string    `json:"message_uid"`
	Feature    string    `json:"feature"`
	DeviceID   string    `json:"device_id"`
	Epoch      int       `json:"epoch"`
	Sealed     string    `json:"sealed"`
	CreatedAt  time.Time `json:"created_at"`
}

type aiDerivedItems struct {
	Items []aiDerivedItem `json:"items"`
}

func enclaveDerivedItems(rows []store.AIDerived) aiDerivedItems {
	out := aiDerivedItems{Items: make([]aiDerivedItem, 0, len(rows))}
	for _, d := range rows {
		out.Items = append(out.Items, aiDerivedItem{
			MessageUID: d.MessageUID.String(), Feature: d.Feature, DeviceID: d.DeviceID.String(), Epoch: d.Epoch,
			Sealed: base64.RawURLEncoding.EncodeToString(d.Sealed), CreatedAt: d.CreatedAt.UTC(),
		})
	}
	return out
}

// enclaveAIDerived answers the stored results the enclave asks for, in one
// of two forms: a message's (?device_id=&uid=), for a media connection or
// an AI authorization, on one of the row's numbers; or the reuse lookup
// (?feature=&tags=<device_id>.<tag>,…), for an AI authorization, one to
// AI_DEVICES_MAX of its numbers' tags.
func (h *Handler) enclaveAIDerived(w http.ResponseWriter, r *http.Request, caller *AttestedReader, _ []byte) {
	row, rd, ok := h.readerRow(w, r, caller)
	if !ok {
		return
	}
	if values, ok := strictQuery(r, "device_id", "uid"); ok {
		device, okDevice := parseID(values.Get("device_id"))
		uid, okUID := parseID(values.Get("uid"))
		if !okDevice || !okUID {
			fail(w, http.StatusBadRequest, "bad_request", "device_id and uid must be lower-case UUIDs")
			return
		}
		if !h.mediaRow(row, rd) && !h.aiRow(row, rd) || !row.Devices[device] {
			fail(w, http.StatusNotFound, "not_found", "no such connection or number")
			return
		}
		rows, err := h.AI.AIDerivedFor(r.Context(), row.TenantID, device, []uuid.UUID{uid})
		if err != nil {
			h.log().Error("could not read AI results", "connection", row.ID, "error", err)
			fail(w, http.StatusInternalServerError, "internal", "could not read the results")
			return
		}
		send(w, http.StatusOK, enclaveDerivedItems(rows))
		return
	}
	values, ok := strictQuery(r, "feature", "tags")
	if !ok || !slices.Contains(store.AIFeatures, values.Get("feature")) {
		fail(w, http.StatusBadRequest, "bad_request", "the query is device_id and uid, or feature and tags")
		return
	}
	if !h.aiRow(row, rd) {
		fail(w, http.StatusNotFound, "not_found", "no such connection")
		return
	}
	parts := strings.Split(values.Get("tags"), ",")
	if len(parts) < 1 || len(parts) > store.AIDevicesMax {
		fail(w, http.StatusBadRequest, "bad_request", "tags must be 1 to 25 <device_id>.<tag> pairs, comma separated")
		return
	}
	tags := make([]store.AIDedupeTag, 0, len(parts))
	for _, part := range parts {
		rawDevice, rawTag, _ := strings.Cut(part, ".")
		device, okDevice := parseID(rawDevice)
		tag, err := base64.RawURLEncoding.Strict().DecodeString(rawTag)
		if !okDevice || err != nil || len(tag) != 32 || !row.Devices[device] {
			fail(w, http.StatusBadRequest, "bad_request", "each tag must be one of this authorization's numbers, a dot and 43 base64url characters")
			return
		}
		tags = append(tags, store.AIDedupeTag{DeviceID: device, Tag: tag})
	}
	rows, err := h.AI.AIDerivedByTags(r.Context(), row.TenantID, values.Get("feature"), tags)
	if err != nil {
		h.log().Error("could not look AI results up", "connection", row.ID, "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not read the results")
		return
	}
	send(w, http.StatusOK, enclaveDerivedItems(rows))
}

// aiStoreRequest is a result the enclave sealed, to store for a message and
// a function.
type aiStoreRequest struct {
	DeviceID  string `json:"device_id"`
	Epoch     int    `json:"epoch"`
	Sealed    string `json:"sealed"`
	DedupeTag string `json:"dedupe_tag"`
	Redo      bool   `json:"redo"`
}

// enclaveAIStore stores a result an AI authorization made. The function
// must be one it has on that number, and the message must be on the
// number and of the function's type; with redo it replaces a stored one,
// without it a stored one is 409 derived_exists, and the enclave then
// answers with that one.
func (h *Handler) enclaveAIStore(w http.ResponseWriter, r *http.Request, caller *AttestedReader, body []byte) {
	row, rd, ok := h.readerRow(w, r, caller)
	if !ok {
		return
	}
	if !h.aiRow(row, rd) {
		fail(w, http.StatusNotFound, "not_found", "no such connection")
		return
	}
	var req aiStoreRequest
	if err := decodeSigned(body, &req); err != nil {
		fail(w, http.StatusBadRequest, "bad_request", "malformed request: "+err.Error())
		return
	}
	uid, okUID := parseID(r.PathValue("uid"))
	device, okDevice := parseID(req.DeviceID)
	feature := r.PathValue("feature")
	sealed, errSealed := base64.RawURLEncoding.Strict().DecodeString(req.Sealed)
	tag, errTag := base64.RawURLEncoding.Strict().DecodeString(req.DedupeTag)
	_, covered := row.Config.Features[device][feature]
	switch {
	case !okUID || !okDevice:
		fail(w, http.StatusBadRequest, "bad_request", "uid and device_id must be lower-case UUIDs")
		return
	case !slices.Contains(store.AIFeatures, feature) || !row.Devices[device] || !covered:
		fail(w, http.StatusBadRequest, "bad_request", "the function must be one this authorization has on that number")
		return
	case req.Epoch < 1 || req.Epoch > 65535 || errSealed != nil || !store.ValidAIDerived(sealed, req.Epoch):
		fail(w, http.StatusBadRequest, "bad_request", "sealed must be a derived record of that epoch, at most 524323 bytes")
		return
	case errTag != nil || len(tag) != 32:
		fail(w, http.StatusBadRequest, "bad_request", "dedupe_tag must be 43 base64url characters")
		return
	}
	err := h.AI.PutAIDerived(r.Context(), row.TenantID, row.ID,
		store.AIDerived{MessageUID: uid, Feature: feature, DeviceID: device, Epoch: req.Epoch, Sealed: sealed, DedupeTag: tag}, req.Redo)
	switch {
	case errors.Is(err, store.ErrAIDerivedMismatch):
		fail(w, http.StatusBadRequest, "bad_request", "the message is not on that number, or not of a type the function takes")
		return
	case errors.Is(err, store.ErrAIDerivedExists):
		fail(w, http.StatusConflict, "derived_exists", "a result is stored for that message and function")
		return
	case errors.Is(err, store.ErrStoragePaused):
		fail(w, http.StatusConflict, "storage_paused", "the workspace's archive storage is paused")
		return
	case err != nil:
		h.log().Error("could not store an AI result", "connection", row.ID, "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not store the result")
		return
	}
	h.log().Info("mcp_ai_derived", "connection", row.ID, "device", device, "message", uid, "feature", feature, "redo", req.Redo)
	w.WriteHeader(http.StatusNoContent)
}

// aiUsageRequest is one increment the enclave counted after a provider's
// answer.
type aiUsageRequest struct {
	DeviceID       string `json:"device_id"`
	Feature        string `json:"feature"`
	Provider       string `json:"provider"`
	Model          string `json:"model"`
	Origin         string `json:"origin"`
	RequesterID    string `json:"requester_id"`
	Items          int    `json:"items"`
	Reused         int    `json:"reused"`
	Failures       int    `json:"failures"`
	InputTokens    int64  `json:"input_tokens"`
	OutputTokens   int64  `json:"output_tokens"`
	Seconds        int    `json:"seconds"`
	CostMicrocents int64  `json:"cost_microcents"`
}

// enclaveAIUsage adds an increment to today's row of a live AI
// authorization. It is taken whatever the switches say now: a provider that
// answered was paid, and this server's counts may only understate.
func (h *Handler) enclaveAIUsage(w http.ResponseWriter, r *http.Request, caller *AttestedReader, body []byte) {
	row, _, ok := h.readerRow(w, r, caller)
	if !ok {
		return
	}
	if row.Kind != store.KindAI || row.Config == nil || !row.Live(time.Now()) {
		fail(w, http.StatusNotFound, "not_found", "no such connection")
		return
	}
	var req aiUsageRequest
	if err := decodeSigned(body, &req); err != nil {
		fail(w, http.StatusBadRequest, "bad_request", "malformed request: "+err.Error())
		return
	}
	device, okDevice := parseID(req.DeviceID)
	requester, okRequester := parseID(req.RequesterID)
	function, hasFunction := row.Config.Functions[req.Feature]
	inRange := func(v, most int64) bool { return v >= 0 && v <= most }
	switch {
	case !okDevice || !row.Devices[device] || !okRequester:
		fail(w, http.StatusBadRequest, "bad_request", "device_id must be one of this authorization's numbers, and requester_id a lower-case UUID")
		return
	case !hasFunction || function.Provider != req.Provider || !store.ValidAIModel(req.Model):
		fail(w, http.StatusBadRequest, "bad_request", "feature, provider and model must be one of this authorization's functions")
		return
	case req.Origin != store.AIOriginConsole && req.Origin != store.AIOriginConnector:
		fail(w, http.StatusBadRequest, "bad_request", "origin must be console or connector")
		return
	case !inRange(int64(req.Items), aiUsageCountMax) || !inRange(int64(req.Reused), aiUsageCountMax) || !inRange(int64(req.Failures), aiUsageCountMax) ||
		!inRange(req.InputTokens, aiUsageTokensMax) || !inRange(req.OutputTokens, aiUsageTokensMax) ||
		!inRange(int64(req.Seconds), aiUsageSecondsMax) || !inRange(req.CostMicrocents, aiUsageCostMax):
		fail(w, http.StatusBadRequest, "bad_request", "the counts must be whole numbers within their bounds")
		return
	}
	err := h.AI.RecordAIUsage(r.Context(), row.TenantID, row.ID, store.AIUsage{
		DeviceID: device, Feature: req.Feature, Provider: req.Provider, Model: req.Model, Origin: req.Origin, RequesterID: requester,
		Items: req.Items, Reused: req.Reused, Failures: req.Failures, InputTokens: req.InputTokens, OutputTokens: req.OutputTokens,
		Seconds: req.Seconds, CostMicrocents: req.CostMicrocents,
	})
	switch {
	case errors.Is(err, store.ErrAIUsageKey):
		fail(w, http.StatusBadRequest, "bad_request", "this authorization holds no key for that provider")
		return
	case err != nil:
		h.log().Error("could not record AI usage", "connection", row.ID, "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not record the usage")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// aiMonthReply is what the enclave reads back at install and every minute:
// the month's cost and today's items, which it takes as a lower bound.
type aiMonthReply struct {
	Month          string `json:"month"`
	CostMicrocents int64  `json:"cost_microcents"`
	ItemsToday     int64  `json:"items_today"`
}

// monthLayout is YYYY-MM.
const monthLayout = "2006-01"

// enclaveAIMonth totals a live AI authorization's month (UTC).
func (h *Handler) enclaveAIMonth(w http.ResponseWriter, r *http.Request, caller *AttestedReader, _ []byte) {
	row, _, ok := h.readerRow(w, r, caller)
	if !ok {
		return
	}
	if row.Kind != store.KindAI || !row.Live(time.Now()) {
		fail(w, http.StatusNotFound, "not_found", "no such connection")
		return
	}
	values, ok := strictQuery(r, "month")
	month, err := time.Parse(monthLayout, values.Get("month"))
	if !ok || err != nil || month.Format(monthLayout) != values.Get("month") {
		fail(w, http.StatusBadRequest, "bad_request", "month must be YYYY-MM")
		return
	}
	total, err := h.AI.AIMonthUsage(r.Context(), row.TenantID, row.ID, month)
	if err != nil {
		h.log().Error("could not total AI usage", "connection", row.ID, "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not total the usage")
		return
	}
	send(w, http.StatusOK, aiMonthReply{Month: values.Get("month"), CostMicrocents: total.CostMicrocents, ItemsToday: total.ItemsToday})
}

// aiAlertRequest is something the enclave paused on: a key rejected or a
// quota spent (a provider's), or a model gone (a function's).
type aiAlertRequest struct {
	Code     string  `json:"code"`
	Feature  *string `json:"feature"`
	Provider *string `json:"provider"`
}

// enclaveAIAlert keeps what the enclave reported about a live AI
// authorization until its next renewal, for the console.
func (h *Handler) enclaveAIAlert(w http.ResponseWriter, r *http.Request, caller *AttestedReader, body []byte) {
	row, _, ok := h.readerRow(w, r, caller)
	if !ok {
		return
	}
	if row.Kind != store.KindAI || row.Config == nil || !row.Live(time.Now()) {
		fail(w, http.StatusNotFound, "not_found", "no such connection")
		return
	}
	var req aiAlertRequest
	if err := decodeSigned(body, &req); err != nil {
		fail(w, http.StatusBadRequest, "bad_request", "malformed request: "+err.Error())
		return
	}
	alert := store.AIAlert{Code: req.Code, At: time.Now().UTC()}
	if req.Feature != nil {
		if _, ok := row.Config.Functions[*req.Feature]; !ok {
			fail(w, http.StatusBadRequest, "bad_request", "feature must be one of this authorization's functions")
			return
		}
		alert.Feature = *req.Feature
	}
	if req.Provider != nil {
		if _, ok := row.Config.Keys[*req.Provider]; !ok {
			fail(w, http.StatusBadRequest, "bad_request", "provider must be one of this authorization's providers")
			return
		}
		alert.Provider = *req.Provider
	}
	switch {
	case !slices.Contains(store.AIAlertCodes, req.Code):
		fail(w, http.StatusBadRequest, "bad_request", "code must be one of "+strings.Join(store.AIAlertCodes, ", "))
		return
	case req.Code == "ai_model_unavailable" && alert.Feature == "",
		req.Code != "ai_model_unavailable" && alert.Provider == "":
		fail(w, http.StatusBadRequest, "bad_request", "ai_model_unavailable names a feature; ai_key_rejected and ai_quota name a provider")
		return
	}
	if err := h.Connections.RecordAIAlert(r.Context(), caller.ID, row.ID, alert); err != nil {
		if errors.Is(err, store.ErrMCPConnectionNotFound) {
			fail(w, http.StatusNotFound, "not_found", "no such connection")
			return
		}
		h.log().Error("could not record an AI alert", "connection", row.ID, "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not record the alert")
		return
	}
	h.log().Warn("mcp_ai_alert", "connection", row.ID, "code", alert.Code, "feature", alert.Feature, "provider", alert.Provider)
	w.WriteHeader(http.StatusNoContent)
}
