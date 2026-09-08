package media

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"whatserver2/internal/access"
	"whatserver2/internal/blob"
	"whatserver2/internal/store"
)

// Handler serves attachment ciphertext over HTTP.
//
// Deliberately not over the websocket. Framing a two hundred megabyte video
// through the same connection that carries live messages would stall every
// other frame behind it, and would put the whole attachment in memory on both
// ends. HTTP gives ranges, resumption and streaming for free.
//
// What it serves is ciphertext. The client already holds the sealed media key
// from the message row and decrypts locally, so this endpoint hands out bytes
// that are useless to anyone who intercepts them — which is also why it can
// stream them without the server ever holding the plaintext.
type Handler struct {
	Keys *store.APIKeys
	// Sessions lets a signed-in browser fetch attachments with the same token
	// it opened the websocket with. Without it only API keys are accepted.
	Sessions *store.Users
	Media    *store.Media
	Blob     BlobReader
	Log      *slog.Logger
}

// BlobReader is the read half of object storage.
type BlobReader interface {
	Get(ctx context.Context, key string) (io.ReadCloser, int64, error)
}

// ServeHTTP answers GET /v1/media/{uid}.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log := h.Log
	if log == nil {
		log = slog.Default()
	}

	actor, ok := authenticateActor(r, h.Keys, h.Sessions)
	tenant := actor.Tenant
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="whatserver2"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	uid, err := uuid.Parse(r.PathValue("uid"))
	if err != nil {
		http.Error(w, "not a message id", http.StatusBadRequest)
		return
	}

	ref, err := h.Media.Object(r.Context(), tenant, uid)
	if errors.Is(err, store.ErrNoMedia) {
		// Row level security answers a cross-tenant lookup with no rows, so
		// "not yours" and "does not exist" are the same answer here. They
		// should be.
		http.Error(w, "no such attachment", http.StatusNotFound)
		return
	}
	if err != nil {
		log.Error("could not locate an attachment", "uid", uid, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	allowed, err := access.Allows(r.Context(), actor, ref.DeviceID, store.ActionRead, h.Keys, h.Sessions)
	if err != nil || !allowed {
		http.Error(w, "no such attachment", http.StatusNotFound)
		return
	}
	if ref.Status != "done" || ref.ObjectKey == "" {
		// A distinct code, because the caller should come back rather than
		// treat this as missing. 409 rather than 404: the attachment exists
		// and is not ready.
		w.Header().Set("X-Media-Status", ref.Status)
		http.Error(w, "attachment is not downloaded yet: "+ref.Status, http.StatusConflict)
		return
	}

	if h.Blob == nil {
		http.Error(w, "object storage is not configured on this server",
			http.StatusServiceUnavailable)
		return
	}
	body, size, err := h.Blob.Get(r.Context(), ref.ObjectKey)
	if errors.Is(err, blob.ErrNotFound) {
		log.Error("an attachment is recorded as stored but is not in the bucket",
			"uid", uid, "object", ref.ObjectKey)
		http.Error(w, "attachment is missing from storage", http.StatusNotFound)
		return
	}
	if err != nil {
		log.Error("could not open an attachment", "uid", uid, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	//nolint:errcheck // the object stream is done; a close error changes nothing for the caller
	defer func() { _ = body.Close() }()

	// application/octet-stream, always. These bytes are ciphertext: labelling
	// them image/jpeg would be false, would hint at what they hold, and would
	// invite a browser to try to render them.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.Header().Set("X-Media-Type", ref.MediaType)
	// Nothing here is renderable and nothing should be sniffed into being.
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", "attachment")
	// The ciphertext for a given message never changes, and it is useless
	// without a key, so it is safe to cache — privately.
	w.Header().Set("Cache-Control", "private, max-age=86400, immutable")

	if r.Method == http.MethodHead {
		return
	}
	if _, err := io.Copy(w, body); err != nil {
		// The client went away mid-stream, which is ordinary. Nothing to
		// report to it; the connection is already gone.
		log.Debug("attachment stream ended early", "uid", uid, "error", err)
	}
}

// authenticateActor retains the principal so HTTP checks the same device
// permissions as WebSocket, including service accounts and key restrictions.
func authenticateActor(r *http.Request, keys *store.APIKeys, users *store.Users) (access.Actor, bool) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return access.Actor{}, false
	}
	actor, err := access.Authenticate(r.Context(), token, keys, users)
	return actor, err == nil
}
