package aiapi

import (
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"whatserver2/internal/ratelimit"
	"whatserver2/internal/store"
)

// authenticate resolves a bearer token to a session's account. An expired,
// revoked or unknown session is one answer: sign in again.
func (h *Handler) authenticate(w http.ResponseWriter, r *http.Request) (store.User, bool) {
	token, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	token = strings.TrimSpace(token)
	if !found || token == "" {
		fail(w, http.StatusUnauthorized, "unauthorized", "sign in first")
		return store.User{}, false
	}
	_, user, err := h.Users.ActiveSession(r.Context(), token)
	if err != nil {
		fail(w, http.StatusUnauthorized, "unauthorized", "that session has expired")
		return store.User{}, false
	}
	return user, true
}

// allow applies a rate limit, answering 429 with a Retry-After when it
// bites.
func allow(w http.ResponseWriter, r *http.Request, limits *ratelimit.Auth, subject string) bool {
	ok, wait := limits.Allow(r, subject)
	if ok {
		return true
	}
	w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())))
	fail(w, http.StatusTooManyRequests, "rate_limited", "too many requests; try again in "+wait.String())
	return false
}

// maxBody bounds a request: every body here is small.
const maxBody = 64 << 10

func decode(w http.ResponseWriter, r *http.Request, into any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		fail(w, http.StatusBadRequest, "bad_request", "malformed request: "+err.Error())
		return false
	}
	return true
}

type wireError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func send(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// A person's keys, results and usage: nothing here may be cached.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	//nolint:errcheck // the client hung up; there is nothing left to say to it
	_ = json.NewEncoder(w).Encode(body)
}

func fail(w http.ResponseWriter, status int, code, message string) {
	send(w, status, wireError{Code: code, Message: message})
}

// internal logs a failure and answers 500.
func (h *Handler) internal(w http.ResponseWriter, what string, err error) {
	h.log().Error(what, "error", err)
	fail(w, http.StatusInternalServerError, "internal", what)
}

// parseID reads a lower-case, canonical, non-nil UUID.
func parseID(raw string) (uuid.UUID, bool) {
	id, err := uuid.Parse(raw)
	return id, err == nil && id != uuid.Nil && id.String() == raw
}

func contains(list []string, s string) bool { return slices.Contains(list, s) }
