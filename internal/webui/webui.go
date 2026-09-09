// Package webui serves the browser client.
//
// From a directory rather than from the binary. Embedding the built assets
// would make `go build` depend on a frontend toolchain — CI has no Node — and
// would mean rebuilding and restarting the server to change a stylesheet. The
// cost is that a deployment has to ship two things instead of one, which is
// what a Dockerfile is for.
//
// The client holds the archive private key in the page, which is what makes the
// headers below load-bearing rather than decoration: anything that can run
// script in this origin, or frame it, can ask the unlocked session for
// plaintext.
package webui

import (
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path"
	"strings"
)

// contentSecurityPolicy is the same policy index.html carries in a meta tag.
//
// Set in both places deliberately. The meta tag survives being served by some
// other static server; the header is the one that cannot be stripped by
// rewriting the HTML, and it is the only one that applies to responses that are
// not documents.
const contentSecurityPolicy = "default-src 'self'; " +
	"script-src 'self'; " +
	"worker-src 'self'; " +
	"img-src 'self' blob: data:; " +
	"media-src 'self' blob:; " +
	"connect-src 'self'; " +
	"frame-src 'none'; " +
	"frame-ancestors 'none'; " +
	"base-uri 'none'; " +
	"object-src 'none'"

const sessionBridgePath = "/session-bridge.html"
const sessionBridgeHost = "api.wappie.thehappie.co"
const sessionBridgeURL = "https://" + sessionBridgeHost + sessionBridgePath

// The session bridge has no application UI. Only these two hosted clients
// may embed it; its messages are independently authenticated by the bridge.
const sessionBridgePolicy = "default-src 'self'; " +
	"script-src 'self'; worker-src 'self'; connect-src 'self'; " +
	"frame-src 'none'; " +
	"frame-ancestors https://app.wappie.thehappie.co https://console.wappie.thehappie.co; " +
	"base-uri 'none'; object-src 'none'; form-action 'none'"

// Handler serves a built single-page client out of a directory.
type Handler struct {
	dir   string
	files http.Handler
	log   *slog.Logger
}

// ErrNotBuilt says the directory holds no client.
var ErrNotBuilt = errors.New("webui: no index.html in that directory")

// New opens the directory, or reports why it cannot be served.
//
// The caller is expected to carry on without a client rather than refuse to
// boot: a headless server is a perfectly good deployment, and failing at
// startup because a frontend was not built would be a poor trade.
func New(dir string, log *slog.Logger) (*Handler, error) {
	if dir == "" {
		return nil, ErrNotBuilt
	}
	info, err := os.Stat(path.Join(dir, "index.html"))
	if err != nil {
		return nil, errors.Join(ErrNotBuilt, err)
	}
	if info.IsDir() {
		return nil, ErrNotBuilt
	}
	if log == nil {
		log = slog.Default()
	}
	return &Handler{dir: dir, files: http.FileServer(http.Dir(dir)), log: log}, nil
}

// Dir reports where the client is being served from, for the boot log.
func (h *Handler) Dir() string { return h.dir }

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clean := path.Clean("/" + r.URL.Path)
	if clean == sessionBridgePath {
		// This exception must never turn an SPA fallback or another host's
		// application page into a frameable document.
		if r.Host != sessionBridgeHost || r.URL.Path != sessionBridgePath || !hasAsset(h.dir, clean) {
			h.headers(w, "/", r.Host)
			http.NotFound(w, r)
			return
		}
		h.headers(w, clean, r.Host)
		h.files.ServeHTTP(w, r)
		return
	}

	if clean != "/" && hasAsset(h.dir, clean) {
		h.headers(w, clean, r.Host)
		h.files.ServeHTTP(w, r)
		return
	}

	// A missing file that looks like a file must 404. Falling back to the page
	// for everything answers a stale script URL with HTML, and the browser
	// reports that as a syntax error in a file that does not exist — an hour of
	// confusion for a one-word cause.
	if clean != "/" && path.Ext(clean) != "" {
		h.headers(w, clean, r.Host)
		http.NotFound(w, r)
		return
	}

	h.headers(w, "/", r.Host)
	http.ServeFile(w, r, path.Join(h.dir, "index.html"))
}

// headers sets what protects a page holding the archive key.
func (h *Handler) headers(w http.ResponseWriter, clean, host string) {
	header := w.Header()
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("Cross-Origin-Opener-Policy", "same-origin")
	header.Set("Cross-Origin-Resource-Policy", "same-origin")
	header.Set("X-Frame-Options", "DENY")
	// Voice notes need an explicit browser grant. The policy permits that
	// prompt only in this origin; it never grants microphone access itself.
	header.Set("Permissions-Policy", "camera=(), microphone=(self), geolocation=(), payment=()")

	switch {
	case clean == sessionBridgePath && host == sessionBridgeHost:
		header.Set("Content-Security-Policy", sessionBridgePolicy)
		header.Del("X-Frame-Options")
		header.Set("Cross-Origin-Resource-Policy", "same-site")
		header.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		header.Set("Cache-Control", "no-cache, no-store")
	case clean == "/" || clean == "/index.html":
		policy := contentSecurityPolicy
		if host == "app.wappie.thehappie.co" || host == "console.wappie.thehappie.co" {
			policy = strings.Replace(policy, "frame-src 'none';", "frame-src "+sessionBridgeURL+";", 1)
		}
		header.Set("Content-Security-Policy", policy)
		// The page is a shell around live data. Caching it means a client
		// speaking an older protocol version after a deploy.
		header.Set("Cache-Control", "no-cache")
	case strings.HasPrefix(clean, "/assets/"):
		// The build puts a content hash in these names, so what sits behind
		// one never changes.
		header.Set("Cache-Control", "public, max-age=31536000, immutable")
	default:
		header.Set("Cache-Control", "public, max-age=3600")
	}
}

// hasAsset reports whether a real file sits at that path.
func hasAsset(dir, clean string) bool {
	if clean == "/" {
		return false
	}
	info, err := fs.Stat(os.DirFS(dir), strings.TrimPrefix(clean, "/"))
	return err == nil && !info.IsDir()
}
