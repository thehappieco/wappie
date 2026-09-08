package media

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"

	"github.com/google/uuid"
	"go.mau.fi/whatsmeow"

	"whatserver2/internal/access"
	"whatserver2/internal/domain"
	"whatserver2/internal/store"
)

// Uploader is the part of a paired device this endpoint needs.
//
// An interface so this package does not depend on the device registry: what it
// wants is the ability to hand bytes to WhatsApp, not knowledge of how
// connections are supervised.
type Uploader interface {
	UploadReader(ctx context.Context, plaintext io.Reader, tempFile io.ReadWriteSeeker,
		appInfo whatsmeow.MediaType) (whatsmeow.UploadResponse, error)
}

// DeviceResolver finds the device an upload should go through.
type DeviceResolver func(ctx context.Context, tenant uuid.UUID, deviceID string) (Uploader, error)

// UploadHandler accepts a file and puts it on WhatsApp's servers.
//
// This is the one place in the system where attachment plaintext exists, and it
// is worth being plain about why. WhatsApp's upload takes the cleartext and
// encrypts it on the way out; the exported API offers no way to hand it
// ciphertext that somebody else produced. So an attachment being *sent* passes
// through here in the clear, exactly as outbound text already does, and is
// sealed the moment it is archived.
//
// Inbound media has no such compromise: it is fetched as ciphertext and stored
// without ever being opened. Making the outbound side match would mean
// reimplementing the upload handshake, whose authorisation token whatsmeow
// keeps to itself — a fork, and a standing maintenance cost. It is written down
// here rather than papered over.
type UploadHandler struct {
	Keys *store.APIKeys
	// Sessions lets a signed-in browser upload with the token it already has.
	Sessions *store.Users
	Devices  *store.Devices
	Resolve  DeviceResolver
	MaxBytes int64
	// TempDir is where the ciphertext is staged during the upload. Ciphertext:
	// whatsmeow encrypts as it streams, so the file on disk is already
	// unreadable.
	TempDir string
	Log     *slog.Logger
}

// UploadResult is what the caller needs in order to send the attachment.
//
// The media key comes back to the client because the client is the one that
// will archive and later open it. It is the tenant's own key material; the
// server holds it only for the moment it takes to build the response.
type UploadResult struct {
	// Type is the attachment kind this upload was encrypted for.
	//
	// Reported back so the send that follows can be checked against it. The
	// two calls are otherwise unrelated, and a kind that changes between them
	// produces bytes sealed under one HKDF label and described as another —
	// which succeeds at every step and opens for nobody afterwards.
	Type          string `json:"type"`
	URL           string `json:"url"`
	DirectPath    string `json:"direct_path"`
	MediaKey      []byte `json:"media_key"`
	FileSHA256    []byte `json:"file_sha256"`
	FileEncSHA256 []byte `json:"file_enc_sha256"`
	FileLength    uint64 `json:"file_length"`
}

// ServeHTTP answers POST /v1/upload.
func (h *UploadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

	kind := r.URL.Query().Get("type")
	appInfo, err := appInfoFor(kind)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	deviceRef := r.URL.Query().Get("device")
	if deviceRef == "" {
		http.Error(w, "device is required", http.StatusBadRequest)
		return
	}
	// A unique prefix is accepted, the same as everywhere else: the listing
	// shows a short form, and an identifier you cannot type back is a trap.
	dev, err := h.Devices.Resolve(r.Context(), tenant.String(), deviceRef)
	if err != nil {
		if errors.Is(err, store.ErrAmbiguous) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, "no such device", http.StatusNotFound)
		return
	}
	allowed, err := access.Allows(r.Context(), actor, uuid.MustParse(dev.ID), store.ActionSend, h.Keys, h.Sessions)
	if err != nil || !allowed {
		http.Error(w, "this credential cannot send on this number", http.StatusForbidden)
		return
	}
	client, err := h.Resolve(r.Context(), tenant, dev.ID)
	if err != nil {
		http.Error(w, "that device is not connected: "+err.Error(), http.StatusConflict)
		return
	}

	// Staged on disk rather than in memory. whatsmeow encrypts as it streams,
	// so what lands here is ciphertext, and a video does not have to fit in
	// RAM twice to be sent.
	temp, err := os.CreateTemp(h.TempDir, "wa-upload-*.enc")
	if err != nil {
		log.Error("could not open a staging file", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer func() {
		name := temp.Name()
		//nolint:errcheck // the upload is finished; this file is spent
		_ = temp.Close()
		//nolint:errcheck // best effort cleanup of a temporary file
		_ = os.Remove(name)
	}()

	// MaxBytes+1 so a file exactly at the limit is allowed and one byte over
	// is caught, rather than being silently truncated to the limit and sent as
	// a corrupt attachment.
	body := io.LimitReader(r.Body, h.MaxBytes+1)
	counted := &countingReader{r: body}

	resp, err := client.UploadReader(r.Context(), counted, temp, appInfo)
	if err != nil {
		log.Error("upload to WhatsApp failed", "device", dev.ID, "error", err)
		http.Error(w, "upload failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	if counted.n > h.MaxBytes {
		http.Error(w, fmt.Sprintf("attachment is over the %d byte limit", h.MaxBytes),
			http.StatusRequestEntityTooLarge)
		return
	}
	if resp.FileLength == 0 {
		http.Error(w, "refusing to send an empty attachment", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(UploadResult{
		Type: kind,
		URL:  resp.URL, DirectPath: resp.DirectPath,
		MediaKey: resp.MediaKey, FileSHA256: resp.FileSHA256,
		FileEncSHA256: resp.FileEncSHA256, FileLength: resp.FileLength,
	}); err != nil {
		log.Debug("upload response was not delivered", "error", err)
	}
}

// countingReader counts what passed through, so a limit can be enforced after
// a streaming read rather than by trusting Content-Length.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// appInfoFor maps our media type onto whatsmeow's upload category.
//
// The category picks the HKDF label the keys are derived from, so it is not
// cosmetic: uploading a voice note as an image produces a file the recipient's
// client cannot open, with no error anywhere to explain it.
func appInfoFor(kind string) (whatsmeow.MediaType, error) {
	switch domain.KeyClass(domain.Type(kind)) {
	case "image":
		return whatsmeow.MediaImage, nil
	case "video":
		return whatsmeow.MediaVideo, nil
	case "audio":
		return whatsmeow.MediaAudio, nil
	case "document":
		return whatsmeow.MediaDocument, nil
	default:
		if kind == "" {
			return "", errors.New("type is required: image, video, ptv, audio, ptt, document or sticker")
		}
		return "", fmt.Errorf("%q is not an attachment type", kind)
	}
}
