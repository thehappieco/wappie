// Package aiapi serves the console's AI routes, /v1/ai/* (docs/mcp-enclave.md
// §18.11): a person's keychain, the requests that start an AI authorization,
// the authorizations' list and controls, which functions a person may ask
// for on a number, the jobs they ask for, the stored results and the usage.
//
// This server decides who may ask and keeps the record; it never sees an API
// key or a word of content. The keychain holds envelopes only the person's
// account key opens, the results are sealed with the numbers' keys, and the
// work happens in the attested reader, which this package reaches through
// the connector's handler.
//
// While WS_AI_ENABLED is off every route answers 404 but the keychain, the
// listing, the revocation and the deletions: a person can still see and
// delete what they hold.
package aiapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/mcpauth"
	"whatserver2/internal/ratelimit"
	"whatserver2/internal/store"
)

// Handler serves /v1/ai.
type Handler struct {
	Users       *store.Users
	Connections *store.MCPConnections
	AI          *store.AI
	// Enabled is WS_AI_ENABLED, with the connector on: off, every route but
	// the keychain, the listing, the revocation and the deletions is 404.
	Enabled bool
	// MCP is the connector's handler: the switches, and the relays to the
	// attested reader. Nil refuses what needs the reader.
	MCP *mcpauth.Handler
	// RequestLimits bounds POST /v1/ai/requests, per person, like a
	// prepare. Nil allows everything, for tests.
	RequestLimits *ratelimit.Auth
	// ProcessLimits bounds POST /v1/ai/process, per person: 30 a minute.
	// Nil allows everything.
	ProcessLimits *ratelimit.Auth
	Log           *slog.Logger
}

// ProcessPerMinute is how many jobs a person may ask for in a minute.
const ProcessPerMinute = 30

// Mount registers the routes on a mux.
func (h *Handler) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/ai/keychain", h.keychain)
	mux.HandleFunc("POST /v1/ai/keychain", h.addKeychain)
	mux.HandleFunc("DELETE /v1/ai/keychain/{id}", h.deleteKeychain)
	mux.HandleFunc("GET /v1/ai/authorizations", h.authorizations)
	mux.HandleFunc("DELETE /v1/ai/authorizations/{id}", h.revoke)
	mux.HandleFunc("DELETE /v1/ai/derived/{uid}/{feature}", h.deleteDerived)
	mux.HandleFunc("POST /v1/ai/derived/delete", h.deleteDerivedOf)
	mux.HandleFunc("POST /v1/ai/requests", h.enabled(h.request))
	mux.HandleFunc("PATCH /v1/ai/authorizations/{id}", h.enabled(h.controls))
	mux.HandleFunc("GET /v1/ai/available", h.enabled(h.available))
	mux.HandleFunc("POST /v1/ai/process", h.enabled(h.process))
	mux.HandleFunc("GET /v1/ai/jobs/{job}", h.enabled(h.job))
	mux.HandleFunc("GET /v1/ai/derived", h.enabled(h.derived))
	mux.HandleFunc("GET /v1/ai/usage", h.enabled(h.usage))
}

func (h *Handler) log() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.Default()
}

// enabled answers 404 while AI is switched off.
func (h *Handler) enabled(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.Enabled {
			fail(w, http.StatusNotFound, "not_found", "no such route")
			return
		}
		next(w, r)
	}
}

// allowed is AIAllowed for a workspace, as the connector says: false while
// the switch is off, and without a connector.
func (h *Handler) allowed(tenant uuid.UUID) bool {
	return h.Enabled && h.MCP != nil && h.MCP.AIAllowedFor(tenant)
}

// policy is what the switches say for a workspace.
func (h *Handler) policy(tenant uuid.UUID) store.AIPolicy {
	if !h.Enabled || h.MCP == nil {
		return store.AIPolicy{}
	}
	return h.MCP.AIPolicy(tenant)
}

func manager(user store.User) bool { return user.Role == "owner" || user.Role == "admin" }

// ---------------------------------------------------------------------------
// The keychain
// ---------------------------------------------------------------------------

type keychainItem struct {
	ID        string    `json:"id"`
	Provider  string    `json:"provider"`
	Label     string    `json:"label"`
	Suffix    string    `json:"suffix"`
	Envelope  string    `json:"envelope"`
	CreatedAt time.Time `json:"created_at"`
}

func itemOf(i store.AIKeychainItem) keychainItem {
	return keychainItem{ID: i.ID.String(), Provider: i.Provider, Label: i.Label, Suffix: i.Suffix,
		Envelope: base64.RawURLEncoding.EncodeToString(i.Envelope), CreatedAt: i.CreatedAt.UTC()}
}

type keychainReply struct {
	Items []keychainItem `json:"items"`
}

// keychain lists the person's own live items.
func (h *Handler) keychain(w http.ResponseWriter, r *http.Request) {
	user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	items, err := h.AI.Keychain(r.Context(), user.TenantID, user.ID)
	if err != nil {
		h.internal(w, "could not list the keychain", err)
		return
	}
	out := keychainReply{Items: make([]keychainItem, 0, len(items))}
	for _, i := range items {
		out.Items = append(out.Items, itemOf(i))
	}
	send(w, http.StatusOK, out)
}

type addKeychainRequest struct {
	ID       string `json:"id"`
	Provider string `json:"provider"`
	Label    string `json:"label"`
	Suffix   string `json:"suffix"`
	Envelope string `json:"envelope"`
}

// addKeychain stores one of the person's items, sealed in their browser.
func (h *Handler) addKeychain(w http.ResponseWriter, r *http.Request) {
	user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	var req addKeychainRequest
	if !decode(w, r, &req) {
		return
	}
	id, okID := parseID(req.ID)
	envelope, errEnvelope := base64.RawURLEncoding.Strict().DecodeString(req.Envelope)
	switch {
	case !okID:
		fail(w, http.StatusBadRequest, "bad_request", "id must be a lower-case UUID")
		return
	case !contains(store.AIProviders, req.Provider):
		fail(w, http.StatusBadRequest, "bad_request", "provider must be one of "+strings.Join(store.AIProviders, ", "))
		return
	case !store.ValidAILabel(req.Label):
		fail(w, http.StatusBadRequest, "bad_request", "label must be 1 to 60 printable characters")
		return
	case !store.ValidAISuffix(req.Suffix):
		fail(w, http.StatusBadRequest, "bad_request", "suffix must be the key's last 4 characters")
		return
	case errEnvelope != nil || !store.ValidAIEnvelope(envelope):
		fail(w, http.StatusBadRequest, "bad_request", "envelope must be a sealed keychain item, at most 4096 bytes, in unpadded base64url")
		return
	}
	item, err := h.AI.AddKeychainItem(r.Context(), user.TenantID, user.ID,
		store.AIKeychainItem{ID: id, Provider: req.Provider, Label: req.Label, Suffix: req.Suffix, Envelope: envelope})
	switch {
	case errors.Is(err, store.ErrAIKeychainFull):
		fail(w, http.StatusConflict, "keychain_full", "you hold as many keys as you may here; delete one first")
		return
	case errors.Is(err, store.ErrAIKeychainExists):
		fail(w, http.StatusConflict, "keychain_exists", "an item with that id exists")
		return
	case errors.Is(err, store.ErrMembershipForbidden):
		fail(w, http.StatusForbidden, "not_authorized", "you are not an active member of this workspace")
		return
	case err != nil:
		h.internal(w, "could not store the item", err)
		return
	}
	h.log().Info("ai keychain item added", "item", item.ID, "provider", item.Provider)
	send(w, http.StatusCreated, itemOf(item))
}

// deleteKeychain deletes one of the person's items, and ends every
// authorization that names it.
func (h *Handler) deleteKeychain(w http.ResponseWriter, r *http.Request) {
	user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	id, ok := parseID(r.PathValue("id"))
	if !ok {
		fail(w, http.StatusNotFound, "not_found", "no such item")
		return
	}
	ended, err := h.AI.DeleteKeychainItem(r.Context(), user.TenantID, user.ID, id)
	switch {
	case errors.Is(err, store.ErrAINotFound):
		fail(w, http.StatusNotFound, "not_found", "no such item")
		return
	case err != nil:
		h.internal(w, "could not delete the item", err)
		return
	}
	for _, e := range ended {
		h.tellRevoked(r.Context(), e.Reader, e.ID)
		h.log().Info("mcp connection revoked", "connection", e.ID, "reason", store.ReasonAIKeyDeleted)
	}
	h.log().Info("ai keychain item deleted", "item", id, "ended", len(ended))
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) tellRevoked(ctx context.Context, reader, id string) {
	if h.MCP != nil {
		h.MCP.TellRevoked(ctx, reader, id)
	}
}

// ---------------------------------------------------------------------------
// The request that starts an authorization
// ---------------------------------------------------------------------------

type nonceRequest struct {
	Nonce string `json:"nonce"`
}

// request asks the attested reader for a pending AI request, for an owner
// or an admin of a workspace that may have AI now, and relays the prepared
// descriptor; the consent that answers it must be the same person's.
func (h *Handler) request(w http.ResponseWriter, r *http.Request) {
	user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	if !allow(w, r, h.RequestLimits, "ai-request:"+user.ID.String()) {
		return
	}
	var req nonceRequest
	if !decode(w, r, &req) {
		return
	}
	if raw, err := base64.RawURLEncoding.Strict().DecodeString(req.Nonce); err != nil || len(raw) < 16 || len(raw) > 64 {
		fail(w, http.StatusBadRequest, "bad_request", "nonce must be 16 to 64 bytes in unpadded base64url")
		return
	}
	if !manager(user) {
		fail(w, http.StatusForbidden, "not_authorized", "an AI integration is made by a workspace owner or an administrator")
		return
	}
	if !h.allowed(user.TenantID) {
		fail(w, http.StatusForbidden, "ai_not_allowed", "AI integrations are not enabled for this workspace")
		return
	}
	raw, err := h.MCP.PrepareAI(r.Context(), user.TenantID, user.ID, req.Nonce)
	switch {
	case errors.Is(err, mcpauth.ErrTooManyPrepares):
		fail(w, http.StatusTooManyRequests, "too_many_prepares", "too many AI requests are waiting; try again in a few minutes")
		return
	case errors.Is(err, mcpauth.ErrReaderRefused):
		fail(w, http.StatusBadRequest, "bad_request", "the reader refused the request")
		return
	case err != nil:
		h.log().Warn("the reader did not prepare an AI request", "error", err)
		fail(w, http.StatusBadGateway, "reader_unavailable", "the reader is not answering; try again in a moment")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	//nolint:errcheck // the client hung up; there is nothing left to say to it
	_, _ = w.Write(raw)
}

// ---------------------------------------------------------------------------
// Authorizations
// ---------------------------------------------------------------------------

type authorizationsReply struct {
	Authorizations []mcpauth.AIAuthorizationInfo `json:"authorizations"`
}

// authorizations lists the workspace's AI authorizations for an owner or an
// admin, and the person's own for anyone else.
func (h *Handler) authorizations(w http.ResponseWriter, r *http.Request) {
	user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	rows, err := h.Connections.AIAuthorizations(r.Context(), user.TenantID, user.ID, manager(user))
	if err != nil {
		h.internal(w, "could not list the authorizations", err)
		return
	}
	allowed, now := h.allowed(user.TenantID), time.Now()
	out := authorizationsReply{Authorizations: make([]mcpauth.AIAuthorizationInfo, 0, len(rows))}
	for _, a := range rows {
		out.Authorizations = append(out.Authorizations, mcpauth.ListedAIAuthorization(a, user.ID, allowed, now))
	}
	send(w, http.StatusOK, out)
}

type controlsRequest struct {
	Paused   *bool           `json:"paused"`
	Off      *[]string       `json:"off"`
	CapCents json.RawMessage `json:"cap_cents"`
}

// controls pauses, narrows or widens an authorization: pausing and
// narrowing for its creator, an owner or an admin; taking a pause off and
// undoing a narrowing for its creator.
func (h *Handler) controls(w http.ResponseWriter, r *http.Request) {
	user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	id, ok := parseID(r.PathValue("id"))
	if !ok {
		fail(w, http.StatusNotFound, "not_found", "no such authorization")
		return
	}
	var req controlsRequest
	if !decode(w, r, &req) {
		return
	}
	in := store.AIControls{Paused: req.Paused, Off: req.Off}
	if len(req.CapCents) > 0 {
		in.CapSet = true
		if string(req.CapCents) != "null" {
			var capCents int
			if err := json.Unmarshal(req.CapCents, &capCents); err != nil {
				fail(w, http.StatusBadRequest, "bad_request", "cap_cents must be a whole number of cents, or null")
				return
			}
			in.Cap = &capCents
		}
	}
	if in.Paused == nil && in.Off == nil && !in.CapSet {
		fail(w, http.StatusBadRequest, "bad_request", "name paused, off or cap_cents")
		return
	}
	a, err := h.Connections.SetAIControls(r.Context(), user.TenantID, user.ID, id.String(), in)
	if err != nil {
		h.authorizationError(w, err)
		return
	}
	h.log().Info("ai authorization controls", "connection", a.ID, "paused", a.PausedAt != nil, "off", strings.Join(a.Off, ","), "capped", a.CapCents != nil)
	send(w, http.StatusOK, mcpauth.ListedAIAuthorization(a, user.ID, h.allowed(user.TenantID), time.Now()))
}

// revoke ends an authorization, reason console, and with
// delete_results=true deletes its stored results too; then tells the
// reader.
func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	id, ok := parseID(r.PathValue("id"))
	if !ok {
		fail(w, http.StatusNotFound, "not_found", "no such authorization")
		return
	}
	values := r.URL.Query()
	deleteResults := false
	if len(values) > 1 || len(values) == 1 && len(values["delete_results"]) != 1 {
		fail(w, http.StatusBadRequest, "bad_request", "the only query is delete_results=true or false")
		return
	}
	switch values.Get("delete_results") {
	case "", "false":
	case "true":
		deleteResults = true
	default:
		fail(w, http.StatusBadRequest, "bad_request", "delete_results must be true or false")
		return
	}
	reader, deleted, err := h.Connections.RevokeAI(r.Context(), user.TenantID, user.ID, id.String(), deleteResults)
	if err != nil {
		h.authorizationError(w, err)
		return
	}
	h.tellRevoked(r.Context(), reader, id.String())
	h.log().Info("mcp connection revoked", "connection", id, "reason", store.ReasonConsole, "results_deleted", deleted)
	w.WriteHeader(http.StatusNoContent)
}

// authorizationError maps what the ledger says about an authorization.
func (h *Handler) authorizationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrAIConfig):
		fail(w, http.StatusBadRequest, "bad_request", strings.TrimPrefix(err.Error(), store.ErrAIConfig.Error()+": "))
	case errors.Is(err, store.ErrMembershipForbidden):
		fail(w, http.StatusForbidden, "not_authorized", "only its creator, or for some things an owner or an administrator, may do this")
	case errors.Is(err, store.ErrMCPConnectionNotFound):
		fail(w, http.StatusNotFound, "not_found", "no such authorization in this workspace")
	case errors.Is(err, store.ErrMCPConnectionState):
		fail(w, http.StatusConflict, "connection_state", "the authorization has ended")
	default:
		h.internal(w, "could not manage the authorization", err)
	}
}

// ---------------------------------------------------------------------------
// Asking for a function
// ---------------------------------------------------------------------------

// reads reports whether the person reads a number; the answer to a person
// who does not is written.
func (h *Handler) reads(w http.ResponseWriter, r *http.Request, user store.User, device uuid.UUID) bool {
	p, err := h.Users.DevicePermission(r.Context(), user.TenantID, user.ID, device)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		h.internal(w, "could not check the number", err)
		return false
	}
	if err != nil || !p.Allows(store.ActionRead) {
		fail(w, http.StatusForbidden, "not_authorized", "reading this number requires read permission and its key")
		return false
	}
	return true
}

type renewItem struct {
	Feature         string `json:"feature"`
	AuthorizationID string `json:"authorization_id"`
}

type availableReply struct {
	Features []string    `json:"features"`
	Renew    []renewItem `json:"renew"`
}

// available says which functions the person may ask for on a number from
// the console: those an active authorization admits, and those only their
// own authorization in reseal would, where the console offers Renew.
func (h *Handler) available(w http.ResponseWriter, r *http.Request) {
	user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	values := r.URL.Query()
	device, okDevice := parseID(values.Get("device_id"))
	if len(values) != 1 || len(values["device_id"]) != 1 || !okDevice {
		fail(w, http.StatusBadRequest, "bad_request", "device_id is required, once")
		return
	}
	if !h.reads(w, r, user, device) {
		return
	}
	out := availableReply{Features: []string{}, Renew: []renewItem{}}
	policy := h.policy(user.TenantID)
	for _, feature := range store.AIFeatures {
		pick, err := h.Connections.PickAIAuthorization(r.Context(), user.TenantID, user.ID, device, feature, store.AIOriginConsole, policy)
		switch {
		case errors.Is(err, store.ErrAINotEnabled):
			continue
		case err != nil:
			h.internal(w, "could not pick an authorization", err)
			return
		case pick.State == "active":
			out.Features = append(out.Features, feature)
		default:
			out.Renew = append(out.Renew, renewItem{Feature: feature, AuthorizationID: pick.AuthorizationID})
		}
	}
	send(w, http.StatusOK, out)
}

type processRequest struct {
	DeviceID string `json:"device_id"`
	UID      string `json:"uid"`
	Feature  string `json:"feature"`
	Redo     bool   `json:"redo"`
}

type processStarted struct {
	Job             string `json:"job"`
	AuthorizationID string `json:"authorization_id"`
}

type processStored struct {
	Stored bool `json:"stored"`
}

// pausedError is ai_paused with the authorization to renew or resume.
type pausedError struct {
	Code            string `json:"code"`
	Message         string `json:"message"`
	AuthorizationID string `json:"authorization_id"`
}

// budgetError is ai_budget_reached with the authorization it concerns and
// the limit it met, "month" or "day", when the reader says which.
type budgetError struct {
	Code            string `json:"code"`
	Message         string `json:"message"`
	AuthorizationID string `json:"authorization_id"`
	Limit           string `json:"limit,omitempty"`
}

// busyError is ai_busy with when to come back.
type busyError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	RetryAfter int    `json:"retry_after_s"`
}

// process asks for a function on a message from the console: for a person
// who reads the number, on a message of the function's type that was not
// sent to be viewed once, under the authorization PickAIAuthorization
// admits for them. Nothing runs under an authorization that waits for a
// renewal: that is 409 ai_paused with its id.
func (h *Handler) process(w http.ResponseWriter, r *http.Request) {
	user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	if !allow(w, r, h.ProcessLimits, "ai-process:"+user.ID.String()) {
		return
	}
	var req processRequest
	if !decode(w, r, &req) {
		return
	}
	device, okDevice := parseID(req.DeviceID)
	uid, okUID := parseID(req.UID)
	if !okDevice || !okUID || !contains(store.AIFeatures, req.Feature) {
		fail(w, http.StatusBadRequest, "bad_request", "device_id and uid must be lower-case UUIDs, and feature one of "+strings.Join(store.AIFeatures, ", "))
		return
	}
	if !h.reads(w, r, user, device) {
		return
	}
	ctx := r.Context()
	msg, err := h.AI.AIMessage(ctx, user.TenantID, device, uid)
	switch {
	case errors.Is(err, store.ErrAINotFound):
		fail(w, http.StatusNotFound, "not_found", "no such message on this number")
		return
	case err != nil:
		h.internal(w, "could not read the message", err)
		return
	case msg.ViewOnce:
		fail(w, http.StatusUnprocessableEntity, "view_once_excluded", "a message sent to be viewed once is never processed")
		return
	case !store.AIFeatureFits(req.Feature, msg.Type, msg.IsGIF):
		fail(w, http.StatusUnprocessableEntity, "ai_unsupported", "this function does not take this kind of message")
		return
	}
	pick, err := h.Connections.PickAIAuthorization(ctx, user.TenantID, user.ID, device, req.Feature, store.AIOriginConsole, h.policy(user.TenantID))
	switch {
	case errors.Is(err, store.ErrAINotEnabled):
		fail(w, http.StatusForbidden, "ai_not_enabled", "no AI integration covers this number and function for you")
		return
	case err != nil:
		h.internal(w, "could not pick an authorization", err)
		return
	case pick.State != "active":
		send(w, http.StatusConflict, pausedError{Code: "ai_paused", Message: "the AI integration waits for its creator to renew it", AuthorizationID: pick.AuthorizationID})
		return
	}
	started, err := h.MCP.StartAIJob(ctx, mcpauth.AIJobRequest{
		AuthorizationID: pick.AuthorizationID, DeviceID: device.String(), UID: uid.String(), Feature: req.Feature,
		Origin: store.AIOriginConsole, RequesterID: user.ID.String(), Redo: req.Redo,
	})
	var refused *mcpauth.AIJobError
	switch {
	case errors.As(err, &refused) && refused.Code == "ai_busy":
		retry := max(refused.RetryAfter, 1)
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		send(w, http.StatusTooManyRequests, busyError{Code: "ai_busy", Message: "the reader is busy with other AI requests", RetryAfter: retry})
		return
	case errors.As(err, &refused) && refused.Code == "ai_budget_reached":
		send(w, http.StatusConflict, budgetError{Code: "ai_budget_reached", Message: "this AI integration reached its limit for now", AuthorizationID: pick.AuthorizationID, Limit: refused.Limit})
		return
	case errors.As(err, &refused), errors.Is(err, mcpauth.ErrReaderNotFound):
		// Paused at the reader, or a record it does not hold (it restarted
		// and has not been renewed yet): the fix is the same.
		send(w, http.StatusConflict, pausedError{Code: "ai_paused", Message: "the AI integration is paused at the reader", AuthorizationID: pick.AuthorizationID})
		return
	case err != nil:
		h.log().Warn("the reader did not take an AI job", "connection", pick.AuthorizationID, "error", err)
		fail(w, http.StatusBadGateway, "reader_unavailable", "the reader is not answering; try again in a moment")
		return
	}
	h.log().Info("ai job asked", "connection", pick.AuthorizationID, "device", device, "message", uid, "feature", req.Feature,
		"redo", req.Redo, "stored", started.Stored)
	if started.Stored {
		send(w, http.StatusOK, processStored{Stored: true})
		return
	}
	send(w, http.StatusAccepted, processStarted{Job: started.Job, AuthorizationID: pick.AuthorizationID})
}

// job answers a job's state to the person who asked for it. The
// authorization it ran under must be the workspace's; the reader keeps the
// state for the requester only.
func (h *Handler) job(w http.ResponseWriter, r *http.Request) {
	user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	values := r.URL.Query()
	authorization, okID := parseID(values.Get("authorization_id"))
	job := r.PathValue("job")
	if len(values) != 1 || len(values["authorization_id"]) != 1 || !okID || !mcpauth.ValidJobID(job) {
		fail(w, http.StatusNotFound, "not_found", "no such job")
		return
	}
	if _, err := h.Connections.AIAuthorization(r.Context(), user.TenantID, authorization.String()); err != nil {
		if errors.Is(err, store.ErrMCPConnectionNotFound) {
			fail(w, http.StatusNotFound, "not_found", "no such job")
			return
		}
		h.internal(w, "could not read the authorization", err)
		return
	}
	if h.MCP == nil {
		fail(w, http.StatusBadGateway, "reader_unavailable", "the reader is not answering")
		return
	}
	state, err := h.MCP.AIJobStatus(r.Context(), job, user.ID)
	switch {
	case errors.Is(err, mcpauth.ErrReaderNotFound):
		fail(w, http.StatusNotFound, "not_found", "no such job")
		return
	case err != nil:
		h.log().Warn("the reader did not answer for an AI job", "error", err)
		fail(w, http.StatusBadGateway, "reader_unavailable", "the reader is not answering; try again in a moment")
		return
	}
	send(w, http.StatusOK, state)
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

type derivedItem struct {
	MessageUID      string    `json:"message_uid"`
	Feature         string    `json:"feature"`
	DeviceID        string    `json:"device_id"`
	Epoch           int       `json:"epoch"`
	Sealed          string    `json:"sealed"`
	AuthorizationID *string   `json:"authorization_id"`
	CreatedAt       time.Time `json:"created_at"`
}

type derivedReply struct {
	Items []derivedItem `json:"items"`
}

// maxUIDs bounds one question about a page of a conversation.
const maxUIDs = 100

// derived hands the stored results of some of a number's messages to a
// person who reads it; only their own grant opens them.
func (h *Handler) derived(w http.ResponseWriter, r *http.Request) {
	user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	values := r.URL.Query()
	device, okDevice := parseID(values.Get("device_id"))
	if len(values) != 2 || len(values["device_id"]) != 1 || len(values["uids"]) != 1 || !okDevice {
		fail(w, http.StatusBadRequest, "bad_request", "device_id and uids are required, once each")
		return
	}
	parts := strings.Split(values.Get("uids"), ",")
	if len(parts) > maxUIDs {
		fail(w, http.StatusBadRequest, "bad_request", "uids must be 1 to 100 message uids, comma separated")
		return
	}
	uids := make([]uuid.UUID, 0, len(parts))
	for _, part := range parts {
		uid, ok := parseID(part)
		if !ok {
			fail(w, http.StatusBadRequest, "bad_request", "uids must be 1 to 100 message uids, comma separated")
			return
		}
		uids = append(uids, uid)
	}
	if !h.reads(w, r, user, device) {
		return
	}
	rows, err := h.AI.AIDerivedFor(r.Context(), user.TenantID, device, uids)
	if err != nil {
		h.internal(w, "could not read the results", err)
		return
	}
	out := derivedReply{Items: make([]derivedItem, 0, len(rows))}
	for _, d := range rows {
		item := derivedItem{MessageUID: d.MessageUID.String(), Feature: d.Feature, DeviceID: d.DeviceID.String(), Epoch: d.Epoch,
			Sealed: base64.RawURLEncoding.EncodeToString(d.Sealed), CreatedAt: d.CreatedAt.UTC()}
		if d.AuthorizationID != nil {
			id := d.AuthorizationID.String()
			item.AuthorizationID = &id
		}
		out.Items = append(out.Items, item)
	}
	send(w, http.StatusOK, out)
}

// deleteDerived deletes one stored result: for its authorization's creator,
// an owner or an admin.
func (h *Handler) deleteDerived(w http.ResponseWriter, r *http.Request) {
	user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	uid, okUID := parseID(r.PathValue("uid"))
	feature := r.PathValue("feature")
	if !okUID || !contains(store.AIFeatures, feature) {
		fail(w, http.StatusNotFound, "not_found", "no such result")
		return
	}
	err := h.AI.DeleteAIDerived(r.Context(), user.TenantID, user.ID, uid, feature)
	switch {
	case errors.Is(err, store.ErrAINotFound):
		fail(w, http.StatusNotFound, "not_found", "no such result")
		return
	case errors.Is(err, store.ErrMembershipForbidden):
		fail(w, http.StatusForbidden, "not_authorized", "only its authorization's creator, an owner or an administrator may delete it")
		return
	case err != nil:
		h.internal(w, "could not delete the result", err)
		return
	}
	h.log().Info("ai result deleted", "message", uid, "feature", feature)
	w.WriteHeader(http.StatusNoContent)
}

type deleteOfRequest struct {
	AuthorizationID *string `json:"authorization_id"`
	DeviceID        *string `json:"device_id"`
}

type deletedReply struct {
	Deleted int64 `json:"deleted"`
}

// deleteDerivedOf deletes every stored result of an authorization (its
// creator, an owner or an admin) or of a number (an owner or an admin).
func (h *Handler) deleteDerivedOf(w http.ResponseWriter, r *http.Request) {
	user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	var req deleteOfRequest
	if !decode(w, r, &req) {
		return
	}
	var authorization, device *uuid.UUID
	switch {
	case req.AuthorizationID != nil && req.DeviceID == nil:
		id, ok := parseID(*req.AuthorizationID)
		if !ok {
			fail(w, http.StatusBadRequest, "bad_request", "authorization_id must be a lower-case UUID")
			return
		}
		authorization = &id
	case req.DeviceID != nil && req.AuthorizationID == nil:
		id, ok := parseID(*req.DeviceID)
		if !ok {
			fail(w, http.StatusBadRequest, "bad_request", "device_id must be a lower-case UUID")
			return
		}
		device = &id
	default:
		fail(w, http.StatusBadRequest, "bad_request", "name authorization_id or device_id, not both")
		return
	}
	n, err := h.AI.DeleteAIDerivedOf(r.Context(), user.TenantID, user.ID, authorization, device)
	switch {
	case errors.Is(err, store.ErrAINotFound):
		fail(w, http.StatusNotFound, "not_found", "no such authorization")
		return
	case errors.Is(err, store.ErrMembershipForbidden):
		fail(w, http.StatusForbidden, "not_authorized", "only an authorization's creator, an owner or an administrator may delete its results; a number's, an owner or an administrator")
		return
	case err != nil:
		h.internal(w, "could not delete the results", err)
		return
	}
	h.log().Info("ai results deleted", "count", n, "by_authorization", authorization != nil)
	send(w, http.StatusOK, deletedReply{Deleted: n})
}

// ---------------------------------------------------------------------------
// Usage
// ---------------------------------------------------------------------------

type usageItem struct {
	AuthorizationID string `json:"authorization_id"`
	DeviceID        string `json:"device_id"`
	Feature         string `json:"feature"`
	Provider        string `json:"provider"`
	Model           string `json:"model"`
	KeychainID      string `json:"keychain_id"`
	Origin          string `json:"origin"`
	RequesterID     string `json:"requester_id"`
	Items           int64  `json:"items"`
	Reused          int64  `json:"reused"`
	Failures        int64  `json:"failures"`
	InputTokens     int64  `json:"input_tokens"`
	OutputTokens    int64  `json:"output_tokens"`
	Seconds         int64  `json:"seconds"`
	CostMicrocents  int64  `json:"cost_microcents"`
	// ItemsToday and FailuresToday are today's (UTC) calls of the line,
	// answered and failed: what the reader counts against the daily cap.
	ItemsToday    int64 `json:"items_today"`
	FailuresToday int64 `json:"failures_today"`
}

type usageReply struct {
	Month string      `json:"month"`
	Items []usageItem `json:"items"`
}

// usage lists a month's counters (UTC): the workspace's for an owner or an
// admin, the person's own authorizations' for anyone else.
func (h *Handler) usage(w http.ResponseWriter, r *http.Request) {
	user, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	values := r.URL.Query()
	raw := values.Get("month")
	month, err := time.Parse("2006-01", raw)
	if len(values) != 1 || len(values["month"]) != 1 || err != nil || month.Format("2006-01") != raw {
		fail(w, http.StatusBadRequest, "bad_request", "month must be YYYY-MM")
		return
	}
	rows, err := h.AI.AIUsageMonth(r.Context(), user.TenantID, user.ID, manager(user), month)
	if err != nil {
		h.internal(w, "could not list the usage", err)
		return
	}
	out := usageReply{Month: raw, Items: make([]usageItem, 0, len(rows))}
	for _, u := range rows {
		out.Items = append(out.Items, usageItem{
			AuthorizationID: u.AuthorizationID.String(), DeviceID: u.DeviceID.String(), Feature: u.Feature, Provider: u.Provider,
			Model: u.Model, KeychainID: u.KeychainID.String(), Origin: u.Origin, RequesterID: u.RequesterID.String(),
			Items: u.Items, Reused: u.Reused, Failures: u.Failures, InputTokens: u.InputTokens, OutputTokens: u.OutputTokens,
			Seconds: u.Seconds, CostMicrocents: u.CostMicrocents, ItemsToday: u.ItemsToday, FailuresToday: u.FailuresToday,
		})
	}
	send(w, http.StatusOK, out)
}
