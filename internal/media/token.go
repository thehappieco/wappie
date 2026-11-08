package media

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/access"
	"whatserver2/internal/blob"
	"whatserver2/internal/store"
)

// A platform token's download (the plan's 4.6 and 6.2). It reads the
// attachment only with Read on its number, a grant at the number's current
// epoch, and the workspace's text and attachments switches on; every
// refusal is the one 404 an attachment that does not exist gets. MCP's
// gate never sees a token. The body goes out in chunks while a monitor
// checks again at least every second, and at once on the token's NOTIFY:
// once the token no longer reads the number, or attachments go off, the
// response ends short of its Content-Length, so the client never holds a
// complete body.

// streamChunk is what one write of a token's download carries.
const streamChunk = 256 << 10

// streamRecheck bounds how long a token's download goes between checks,
// and how long one check may take: a check that cannot answer in time (a
// pool at its limit, a stalled database) is a failed one, and the body
// ends, so a stuck check never lets the copy run on.
const streamRecheck = time.Second

func (h *Handler) serveToken(w http.ResponseWriter, r *http.Request, actor access.Actor, uid uuid.UUID, log *slog.Logger) {
	checker := h.checker()
	ctx := r.Context()
	ref, err := h.Media.Object(ctx, actor.Tenant, uid)
	if errors.Is(err, store.ErrNoMedia) {
		http.Error(w, "no such attachment", http.StatusNotFound)
		return
	}
	if err != nil {
		log.Error("could not locate an attachment", "uid", uid, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	v, err := checker.TokenAllows(ctx, actor, ref.DeviceID, store.TokenNeed{Action: store.ActionRead, Media: true})
	if err != nil || !v.OK {
		http.Error(w, "no such attachment", http.StatusNotFound)
		return
	}
	if ref.Status != "done" || ref.ObjectKey == "" {
		w.Header().Set("X-Media-Status", ref.Status)
		http.Error(w, "attachment is not downloaded yet: "+ref.Status, http.StatusConflict)
		return
	}
	if h.Blob == nil {
		http.Error(w, "object storage is not configured on this server", http.StatusServiceUnavailable)
		return
	}
	// Registered before the first byte, so a NOTIFY during the open is not
	// missed.
	wake, cancel := checker.Watch.Register(actor.Token.ID)
	defer cancel()
	body, size, err := h.Blob.Get(ctx, ref.ObjectKey)
	if errors.Is(err, blob.ErrNotFound) {
		log.Error("an attachment is recorded as stored but is not in the bucket", "uid", uid, "object", ref.ObjectKey)
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

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.Header().Set("X-Media-Type", ref.MediaType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", "attachment")
	// Not cached: a token's access can end at any moment.
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		return
	}

	var cut atomic.Bool
	done := make(chan struct{})
	// The response controller is the handler's until it returns: the
	// monitor sets its deadline only under mu, and never once finished.
	var mu sync.Mutex
	finished := false
	defer func() {
		mu.Lock()
		finished = true
		mu.Unlock()
		close(done)
	}()
	rc := http.NewResponseController(w)
	go func() {
		t := time.NewTicker(streamRecheck)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
			case <-wake:
			}
			if !streamAllowed(ctx, checker, actor, ref.DeviceID) {
				cut.Store(true)
				// A write blocked on a slow client fails now.
				mu.Lock()
				if !finished {
					//nolint:errcheck // a writer without deadlines is cut at its next chunk
					_ = rc.SetWriteDeadline(time.Now())
				}
				mu.Unlock()
				h.hook("cut")
				return
			}
		}
	}()
	h.hook("streaming")
	buf := make([]byte, streamChunk)
	for {
		n, rerr := io.ReadFull(body, buf)
		if cut.Load() {
			abort()
		}
		if n > 0 {
			if _, err := w.Write(buf[:n]); err != nil {
				if cut.Load() {
					abort()
				}
				log.Debug("attachment stream ended early", "uid", uid, "error", err)
				return
			}
		}
		if errors.Is(rerr, io.EOF) || errors.Is(rerr, io.ErrUnexpectedEOF) {
			return
		}
		if rerr != nil {
			log.Debug("attachment stream ended early", "uid", uid, "error", rerr)
			return
		}
	}
}

// streamAllowed is a token download's check between chunks: the token is
// live, reads the number now, and its attachments switch is on, as read
// within streamRecheck.
func streamAllowed(ctx context.Context, checker *access.Checker, actor access.Actor, device uuid.UUID) bool {
	ctx, cancel := context.WithTimeout(ctx, streamRecheck)
	defer cancel()
	live, err := checker.TokenSets(ctx, actor)
	if err != nil || !live.Live || !live.MediaOn {
		return false
	}
	_, ok := live.Reads[device]
	return ok
}

// abort ends the response short of its Content-Length: over HTTP/1.1 the
// connection closes, over HTTP/2 the stream is reset, and net/http logs
// nothing for it.
func abort() { panic(http.ErrAbortHandler) }
