package mcpauth

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"whatserver2/internal/ratelimit"
	"whatserver2/internal/store"
)

// The routes an attested reader calls: the same questions the hosted reader
// asks over loopback, plus its sealed state.
//
// The reader is on another machine and comes through nginx, so a loopback
// check means nothing here. Instead, in this order: the caller's address
// must be one of the named reader's peers (404 otherwise, as nginx answers
// for anyone else), the request must be signed with one of that reader's
// secrets within a minute of now, and its nonce must be new. Only then does
// the route run, and it acts only on that reader's rows.

const (
	// maxStateBody bounds a state blob: 12 MiB, the reader's 11 MiB
	// plaintext cap plus the envelope and the GCM tag, with room to spare.
	// nginx carries the same limit.
	maxStateBody = 12 << 20
)

// signedHandler is a route behind the signature guard: it is handed the
// reader that signed and the body the signature covered.
type signedHandler func(w http.ResponseWriter, r *http.Request, caller *AttestedReader, body []byte)

func (h *Handler) mountEnclave(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/mcp/enclave/connections/{id}", h.signed(maxBody, func(w http.ResponseWriter, r *http.Request, caller *AttestedReader, _ []byte) {
		h.connectionStatus(w, r, caller.ID)
	}))
	mux.HandleFunc("POST /v1/mcp/enclave/connections/{id}/activate", h.signed(maxBody, func(w http.ResponseWriter, r *http.Request, caller *AttestedReader, _ []byte) {
		h.connectionActivate(w, r, caller.ID)
	}))
	mux.HandleFunc("POST /v1/mcp/enclave/connections/{id}/revoke", h.signed(maxBody, func(w http.ResponseWriter, r *http.Request, caller *AttestedReader, _ []byte) {
		h.connectionRevoke(w, r, caller.ID)
	}))
	mux.HandleFunc("GET /v1/mcp/enclave/cimd", h.signed(maxBody, func(w http.ResponseWriter, r *http.Request, _ *AttestedReader, _ []byte) {
		h.cimd(w, r)
	}))
	mux.HandleFunc("GET /v1/mcp/enclave/state/{name}", h.signed(maxBody, h.stateGet))
	mux.HandleFunc("PUT /v1/mcp/enclave/state/{name}", h.signed(maxStateBody, h.statePut))
}

// signed guards an attested reader's route. The steps and their answers are
// fixed by the contract with the reader: 404 for a caller that is not a
// configured reader's peer, 401 for anything wrong with the signature, 413
// for a body over the route's limit, and 503 when the replay cache is full.
// A 401 says nothing about why; the log says which check failed.
func (h *Handler) signed(limit int64, next signedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		readerIDs := r.Header.Values(HeaderReader)
		var caller *AttestedReader
		if len(readerIDs) == 1 {
			caller = h.attestedByID(readerIDs[0])
		}
		if caller == nil || !caller.peer(ratelimit.ClientIP(r, h.TrustedProxies)) {
			fail(w, http.StatusNotFound, "not_found", "no such route")
			return
		}
		now := time.Now()
		got, err := readSignedHeaders(r.Header, now)
		if err != nil {
			h.refuse(w, caller, err)
			return
		}
		body, err := readLimited(r, limit)
		if errors.Is(err, errBodyTooLarge) {
			fail(w, http.StatusRequestEntityTooLarge, "body_too_large", "the request body is larger than this route accepts")
			return
		}
		if err != nil {
			fail(w, http.StatusBadRequest, "bad_request", "the request body could not be read")
			return
		}
		if !signedBy(caller.Secrets, got, DirectionToGo, caller.ID, r.Method, r.RequestURI, body) {
			h.refuse(w, caller, errors.New("hmac_bad"))
			return
		}
		switch err := h.replay.admit(DirectionToGo, caller.ID, got.nonce, got.unix, now); {
		case errors.Is(err, errReplayFull):
			h.log().Error("the replay cache is full; refusing signed requests until it drains", "reader", caller.ID)
			fail(w, http.StatusServiceUnavailable, "replay_cache_full", "too many requests in flight; try again shortly")
			return
		case err != nil:
			h.refuse(w, caller, err)
			return
		}
		next(w, r, caller, body)
	}
}

// refuse answers 401 and logs which check failed, and nothing else about the
// request: not the nonce, not the signature, not the body.
func (h *Handler) refuse(w http.ResponseWriter, caller *AttestedReader, reason error) {
	h.log().Warn("a signed reader request was refused", "reader", caller.ID, "code", reason.Error())
	fail(w, http.StatusUnauthorized, "unauthorized", "request authentication required")
}

var errBodyTooLarge = errors.New("mcpauth: body too large")

// readLimited reads a whole body up to limit bytes. The signature covers the
// body, so it has to be in hand before anything is decided; the limit keeps
// that from being a way to make this server buffer without bound.
func readLimited(r *http.Request, limit int64) ([]byte, error) {
	if r.ContentLength > limit {
		return nil, errBodyTooLarge
	}
	// Sized up front when the length is declared, so a 12 MiB state blob
	// is one allocation rather than a series of doublings.
	buf := new(bytes.Buffer)
	if r.ContentLength > 0 {
		buf = bytes.NewBuffer(make([]byte, 0, r.ContentLength))
	}
	n, err := buf.ReadFrom(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if n > limit {
		return nil, errBodyTooLarge
	}
	return buf.Bytes(), nil
}

// ---------------------------------------------------------------------------
// Sealed state
// ---------------------------------------------------------------------------

// generationPattern is a decimal generation with no sign and no leading zero.
var generationPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,17})$`)

// stateGet hands a reader back one of its sealed collections, with the
// generation a write must name to replace it.
func (h *Handler) stateGet(w http.ResponseWriter, r *http.Request, caller *AttestedReader, _ []byte) {
	name := r.PathValue("name")
	if !store.ValidMCPReaderStateName(name) {
		fail(w, http.StatusBadRequest, "bad_request", "not a state name")
		return
	}
	generation, blob, err := h.States.Get(r.Context(), caller.ID, name)
	switch {
	case errors.Is(err, store.ErrReaderStateNotFound):
		fail(w, http.StatusNotFound, "not_found", "that state has never been written")
		return
	case err != nil:
		h.log().Error("could not read reader state", "reader", caller.ID, "name", name, "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not read the state")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Wappie-Generation", strconv.FormatInt(generation, 10))
	w.Header().Set("Content-Length", strconv.Itoa(len(blob)))
	w.WriteHeader(http.StatusOK)
	//nolint:errcheck,gosec // the reader hung up; G705: an opaque blob for a signed client, not a page
	_, _ = w.Write(blob)
}

// generationReply answers a state write, and a conflict with what is there.
type generationReply struct {
	Generation int64 `json:"generation"`
}

type generationConflict struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	Generation int64  `json:"generation"`
}

// statePut replaces one of a reader's sealed collections, provided the
// generation it names is the current one. The blob is opaque here; the
// reader sealed it and only the reader can open it.
func (h *Handler) statePut(w http.ResponseWriter, r *http.Request, caller *AttestedReader, body []byte) {
	name := r.PathValue("name")
	if !store.ValidMCPReaderStateName(name) {
		fail(w, http.StatusBadRequest, "bad_request", "not a state name")
		return
	}
	values := r.URL.Query()["if_generation"]
	if len(values) != 1 || !generationPattern.MatchString(values[0]) {
		fail(w, http.StatusBadRequest, "bad_request", "one if_generation, a decimal generation, is required")
		return
	}
	ifGeneration, err := strconv.ParseInt(values[0], 10, 64)
	if err != nil {
		fail(w, http.StatusBadRequest, "bad_request", "one if_generation, a decimal generation, is required")
		return
	}
	if len(body) == 0 {
		fail(w, http.StatusBadRequest, "bad_request", "the state blob is empty")
		return
	}
	generation, err := h.States.Put(r.Context(), caller.ID, name, ifGeneration, body)
	switch {
	case errors.Is(err, store.ErrReaderStateConflict):
		// A second writer, or a blob from before the last write: the
		// reader stops and reloads rather than overwrite what it has not
		// seen.
		h.log().Warn("a reader state write named a stale generation", "reader", caller.ID, "name", name,
			"if_generation", ifGeneration, "generation", generation)
		send(w, http.StatusConflict, generationConflict{
			Code: "generation_mismatch", Message: "the state has moved on; reload it", Generation: generation,
		})
		return
	case err != nil:
		h.log().Error("could not write reader state", "reader", caller.ID, "name", name, "error", err)
		fail(w, http.StatusInternalServerError, "internal", "could not write the state")
		return
	}
	h.log().Debug("reader state written", "reader", caller.ID, "name", name, "generation", generation, "bytes", len(body))
	send(w, http.StatusOK, generationReply{Generation: generation})
}
