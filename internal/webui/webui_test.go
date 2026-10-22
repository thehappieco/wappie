package webui_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"whatserver2/internal/webui"
)

// build lays out a directory shaped like a vite build.
func build(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write(t, filepath.Join(dir, "index.html"), "<!doctype html><title>whatserver2</title>")
	if err := os.MkdirAll(filepath.Join(dir, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "assets", "index-abc123.js"), "console.log(1)")
	write(t, filepath.Join(dir, "assets", "index-abc123.css"), "body{}")
	return dir
}

func write(t *testing.T, at, body string) {
	t.Helper()
	if err := os.WriteFile(at, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func get(t *testing.T, h http.Handler, target string) *http.Response {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec.Result()
}

func TestServesThePage(t *testing.T) {
	h, err := webui.New(build(t), nil)
	if err != nil {
		t.Fatal(err)
	}

	resp := get(t, h, "/")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / returned %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Security-Policy"); got == "" {
		t.Error("the page is served without a content security policy")
	}
	if got := resp.Header.Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options is %q; a page holding the archive key must not be framed", got)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-cache" {
		t.Errorf("the page is cached as %q, so a deploy would leave old clients running", got)
	}
	policy := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(policy, "script-src 'self';") || strings.Contains(policy, "'unsafe-inline'") || strings.Contains(policy, "'unsafe-eval'") {
		t.Errorf("scripts must remain confined to files from this origin: %q", policy)
	}
	if !strings.Contains(policy, "worker-src 'self';") {
		t.Errorf("the password worker needs an explicit same-origin policy: %q", policy)
	}
	if got := resp.Header.Get("Permissions-Policy"); !strings.Contains(got, "microphone=(self)") {
		t.Errorf("voice notes must be allowed to request microphone permission: %q", got)
	}
	if got := resp.Header.Get("Permissions-Policy"); !strings.Contains(got, "camera=(self)") {
		t.Errorf("video recording must be allowed to request camera permission: %q", got)
	}
	if got := resp.Header.Get("Permissions-Policy"); !strings.Contains(got, "geolocation=(self)") {
		t.Errorf("location sharing must be allowed to request position permission: %q", got)
	}
	// The hosted MCP consent form posts from this document to the reader on
	// another origin. Under "no-referrer" or "same-origin" the browser sends
	// `Origin: null` there and the reader refuses the consent, so those two
	// policies must never come back for the document.
	switch got := resp.Header.Get("Referrer-Policy"); got {
	case "no-referrer", "same-origin", "":
		t.Errorf("Referrer-Policy is %q: the consent form post would arrive with Origin: null", got)
	}
}

func TestServesAssets(t *testing.T) {
	h, err := webui.New(build(t), nil)
	if err != nil {
		t.Fatal(err)
	}

	resp := get(t, h, "/assets/index-abc123.js")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the script returned %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Errorf("hashed asset cached as %q", got)
	}
	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options is %q", got)
	}
}

// The cloud console's sign-in bundles its font (Schibsted Grotesk, woff2 with
// a woff fallback) under /assets/, so that the document's CSP, default-src
// 'self' with no font-src, needs no font host. Under nosniff a font answered
// as anything else is refused: Go's own table has no woff2, and the host's
// mime.types or the file server's sniffing (wOF2, wOFF) must name them.
func TestFontAssetsAreServedAsFonts(t *testing.T) {
	dir := build(t)
	write(t, filepath.Join(dir, "assets", "schibsted-grotesk-latin-400-normal-abc123.woff2"), "wOF2\x00\x01\x00\x00 synthetic font bytes")
	write(t, filepath.Join(dir, "assets", "schibsted-grotesk-latin-400-normal-abc123.woff"), "wOFF\x00\x01\x00\x00 synthetic font bytes")
	h, err := webui.New(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"woff2": "font/woff2", "woff": "font/woff"} {
		resp := get(t, h, "/assets/schibsted-grotesk-latin-400-normal-abc123."+name)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("the %s font returned %d", name, resp.StatusCode)
		}
		if got := resp.Header.Get("Content-Type"); got != want {
			t.Errorf("the %s font is served as %q, want %q", name, got, want)
		}
		for header, value := range map[string]string{"X-Content-Type-Options": "nosniff", "Cross-Origin-Resource-Policy": "same-origin", "Cache-Control": "public, max-age=31536000, immutable"} {
			if got := resp.Header.Get(header); got != value {
				t.Errorf("the %s font's %s is %q, want %q", name, header, got, value)
			}
		}
	}
}

// The cloud console's first-frame files have no hash in their names and
// shape the first paint of every release. The document names each with the
// version of its bytes (?v=, the first 16 hex digits of their SHA-256), which
// is then cached for good, so that no page load waits on a revalidation
// before it draws; asked for without it, or with any other (a document of
// another release), the file is revalidated like the document. Any other
// file at the root keeps its hour.
func TestTheFirstFrameFilesAreCachedByTheirVersion(t *testing.T) {
	dir := build(t)
	script, style := "document.documentElement.setAttribute('data-theme', 'light')", "html{}"
	write(t, filepath.Join(dir, "boot.js"), script)
	write(t, filepath.Join(dir, "boot.css"), style)
	write(t, filepath.Join(dir, "favicon-32.png"), "png")
	h, err := webui.New(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	version := func(body string) string { sum := sha256.Sum256([]byte(body)); return hex.EncodeToString(sum[:8]) }

	for target, want := range map[string]string{
		"/boot.js?v=" + version(script): "public, max-age=31536000, immutable",
		"/boot.css?v=" + version(style): "public, max-age=31536000, immutable",
		"/boot.js":                      "no-cache",
		"/boot.css":                     "no-cache",
		"/boot.js?v=1":                  "no-cache",
		// Another release's version (the other file's), and the right one cut short or with more after it.
		"/boot.js?v=" + version(style):                   "no-cache",
		"/boot.js?v=" + version(script)[:15]:             "no-cache",
		"/boot.js?v=" + version(script) + "0":            "no-cache",
		"/boot.js?v=" + strings.ToUpper(version(script)): "no-cache",
	} {
		resp := get(t, h, target)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s returned %d", target, resp.StatusCode)
		}
		if got := resp.Header.Get("Cache-Control"); got != want {
			t.Errorf("%s is cached as %q, want %q", target, got, want)
		}
		if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("%s: X-Content-Type-Options is %q", target, got)
		}
		wantType, wantBody := "text/javascript; charset=utf-8", script
		if strings.HasPrefix(target, "/boot.css") {
			wantType, wantBody = "text/css; charset=utf-8", style
		}
		if got := resp.Header.Get("Content-Type"); got != wantType {
			t.Errorf("%s: Content-Type is %q", target, got)
		}
		if string(body) != wantBody {
			t.Errorf("%s served %q", target, body)
		}
	}
	// A HEAD, and a revalidation of the unversioned name, as the browser makes them.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, "/boot.css?v="+version(style), nil))
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 || rec.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
		t.Errorf("HEAD of the versioned file: %d, %d bytes, %q", rec.Code, rec.Body.Len(), rec.Header().Get("Cache-Control"))
	}
	resp := get(t, h, "/boot.js")
	resp.Body.Close()
	again := httptest.NewRequest(http.MethodGet, "/boot.js", nil)
	again.Header.Set("If-Modified-Since", resp.Header.Get("Last-Modified"))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, again)
	if rec.Code != http.StatusNotModified {
		t.Errorf("revalidating the unversioned file returned %d", rec.Code)
	}

	// The file changes under its name (the next release): the old version is no longer it.
	write(t, filepath.Join(dir, "boot.js"), script+";")
	resp = get(t, h, "/boot.js?v="+version(script))
	resp.Body.Close()
	if got := resp.Header.Get("Cache-Control"); got != "no-cache" {
		t.Errorf("the old version of a changed file is cached as %q, so a release could draw its first frame with the other's bytes", got)
	}
	resp = get(t, h, "/favicon-32.png")
	resp.Body.Close()
	if got := resp.Header.Get("Cache-Control"); got != "public, max-age=3600" {
		t.Errorf("another root file is cached as %q", got)
	}
}

func TestAMissingScriptIsNotAnsweredWithThePage(t *testing.T) {
	h, err := webui.New(build(t), nil)
	if err != nil {
		t.Fatal(err)
	}

	// The failure this prevents is nasty to diagnose: after a deploy a cached
	// page asks for a script that no longer exists, an SPA fallback hands back
	// HTML, and the browser reports a syntax error in a file nobody can find.
	resp := get(t, h, "/assets/index-old.js")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a missing script returned %d, want 404", resp.StatusCode)
	}
}

func TestAnUnknownRouteGetsThePage(t *testing.T) {
	h, err := webui.New(build(t), nil)
	if err != nil {
		t.Fatal(err)
	}

	// There is no router yet, but a bookmarked deep link must not 404 the
	// moment one arrives.
	resp := get(t, h, "/conversa/qualquer")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("a deep link returned %d, want the page", resp.StatusCode)
	}
}

func TestConsoleDocumentsUseTheAppOriginWithoutLosingReturnContext(t *testing.T) {
	h, err := webui.New(build(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	query := "workspace=11111111-1111-4111-8111-111111111111&device=22222222-2222-4222-8222-222222222222&billing=change&locale=pt-BR&extra=a%2Bb%26c"
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		for _, route := range []string{"/", "/index.html", "/console", "/console/", "/settings/security"} {
			t.Run(method+route, func(t *testing.T) {
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, httptest.NewRequest(method, "https://console.wappie.thehappie.co"+route+"?"+query, nil))
				if rec.Code != http.StatusTemporaryRedirect {
					t.Fatalf("console document returned %d, want 307", rec.Code)
				}
				if got, want := rec.Header().Get("Location"), "https://app.wappie.thehappie.co/console?"+query; got != want {
					t.Errorf("Location = %q, want %q", got, want)
				}
				if rec.Header().Get("Cache-Control") != "no-store" {
					t.Error("temporary migration must not be cached")
				}
				if method == http.MethodHead && rec.Body.Len() != 0 {
					t.Error("HEAD must not return an HTML body")
				}
			})
		}
	}
	for _, host := range []string{"app.wappie.thehappie.co", "api.wappie.thehappie.co", "console.wappie.thehappie.co.example.com", "localhost"} {
		resp := get(t, h, "https://"+host+"/console?"+query)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Location") != "" {
			t.Errorf("%s redirected or failed: %d", host, resp.StatusCode)
		}
	}
}

func TestConsoleRedirectLeavesAssetsBridgeAndAPIRoutesAlone(t *testing.T) {
	dir := build(t)
	write(t, filepath.Join(dir, "session-bridge.html"), "session bridge")
	h, err := webui.New(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
	mux.Handle("/", h)
	for _, test := range []struct {
		method, route string
		status        int
	}{
		{http.MethodGet, "/assets/index-abc123.js", http.StatusOK},
		{http.MethodHead, "/assets/index-abc123.css", http.StatusOK},
		{http.MethodGet, "/assets/missing.js", http.StatusNotFound},
		{http.MethodGet, "/session-bridge.html", http.StatusNotFound},
		{http.MethodGet, "/v1/billing", http.StatusUnauthorized},
		{http.MethodPost, "/v1/auth/login", http.StatusUnauthorized},
		{http.MethodPost, "/console", http.StatusMethodNotAllowed},
	} {
		t.Run(test.method+test.route, func(t *testing.T) {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(test.method, "https://console.wappie.thehappie.co"+test.route, nil))
			if rec.Code != test.status || rec.Header().Get("Location") != "" {
				t.Errorf("got %d and Location %q, want %d without a redirect", rec.Code, rec.Header().Get("Location"), test.status)
			}
		})
	}
	for _, route := range []string{"/v1", "/v1/unknown", "/assets", "/assets/unknown"} {
		// Unknown API/asset paths must not become migration redirects even
		// when the UI fallback receives them directly.
		resp := get(t, h, "https://console.wappie.thehappie.co"+route)
		resp.Body.Close()
		if resp.Header.Get("Location") != "" {
			t.Errorf("fallback redirected %s", route)
		}
	}
}

func TestItRefusesToEscapeTheDirectory(t *testing.T) {
	dir := build(t)
	write(t, filepath.Join(dir, "..", "secret.txt"), "not for the browser")

	h, err := webui.New(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"/../secret.txt", "/assets/../../secret.txt"} {
		resp := get(t, h, target)
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			body := make([]byte, 32)
			n, _ := resp.Body.Read(body)
			t.Errorf("%s served %q", target, body[:n])
		}
	}
}

func TestOnlyReading(t *testing.T) {
	h, err := webui.New(build(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST / returned %d, want 405", rec.Code)
	}
}

func TestNoClientBuilt(t *testing.T) {
	// A headless server is a fine deployment. It must say so rather than fail
	// to boot or answer every request with a mystery 404.
	if _, err := webui.New(t.TempDir(), nil); !errors.Is(err, webui.ErrNotBuilt) {
		t.Fatalf("an empty directory gave %v, want ErrNotBuilt", err)
	}
	if _, err := webui.New("", nil); !errors.Is(err, webui.ErrNotBuilt) {
		t.Fatalf("an unset directory gave %v, want ErrNotBuilt", err)
	}
}

func TestSessionBridgeOnlyAllowsTheHostedClientsToFrameIt(t *testing.T) {
	dir := build(t)
	write(t, filepath.Join(dir, "session-bridge.html"), "<!doctype html><title>session bridge</title>")
	h, err := webui.New(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(method, "https://api.wappie.thehappie.co/session-bridge.html", nil))
			resp := rec.Result()
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("bridge returned %d", resp.StatusCode)
			}
			policy := resp.Header.Get("Content-Security-Policy")
			for name, want := range map[string]string{
				"default-src": "'self'", "script-src": "'self'", "worker-src": "'self'", "connect-src": "'self'",
				"frame-src": "'none'", "base-uri": "'none'", "object-src": "'none'", "form-action": "'none'",
				"frame-ancestors": "https://app.wappie.thehappie.co https://console.wappie.thehappie.co",
			} {
				if got := directive(policy, name); got != want {
					t.Errorf("%s = %q, want %q", name, got, want)
				}
			}
			for name, want := range map[string]string{
				"X-Frame-Options": "", "Cross-Origin-Resource-Policy": "same-site", "Referrer-Policy": "no-referrer",
				"Cache-Control": "no-cache, no-store", "X-Content-Type-Options": "nosniff",
				"Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
			} {
				if got := resp.Header.Get(name); got != want {
					t.Errorf("%s = %q, want %q", name, got, want)
				}
			}
			body, _ := io.ReadAll(resp.Body)
			if method == http.MethodGet && !strings.Contains(string(body), "session bridge") {
				t.Errorf("bridge served another page: %s", body)
			}
		})
	}
}

func TestSessionBridgeDoesNotRelaxOtherHostsOrFallbackPages(t *testing.T) {
	dir := build(t)
	write(t, filepath.Join(dir, "session-bridge.html"), "session bridge")
	h, err := webui.New(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{
		"https://app.wappie.thehappie.co/session-bridge.html",
		"https://console.wappie.thehappie.co/session-bridge.html",
		"https://localhost/session-bridge.html",
		"https://api.wappie.thehappie.co.example.com/session-bridge.html",
		"https://api.wappie.thehappie.co/session-bridge.html/",
		"https://api.wappie.thehappie.co//session-bridge.html",
	} {
		t.Run(target, func(t *testing.T) {
			resp := get(t, h, target)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("bridge alias returned %d, want 404", resp.StatusCode)
			}
			if resp.Header.Get("X-Frame-Options") != "DENY" || directive(resp.Header.Get("Content-Security-Policy"), "frame-ancestors") != "'none'" {
				t.Errorf("bridge alias became frameable: %v", resp.Header)
			}
		})
	}
	if err := os.Remove(filepath.Join(dir, "session-bridge.html")); err != nil {
		t.Fatal(err)
	}
	resp := get(t, h, "https://api.wappie.thehappie.co/session-bridge.html")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound || resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Errorf("missing bridge must not become a frameable SPA fallback: %d %v", resp.StatusCode, resp.Header)
	}
}

func TestOnlyHostedApplicationPagesCanLoadTheSessionBridge(t *testing.T) {
	h, err := webui.New(build(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"app.wappie.thehappie.co", "console.wappie.thehappie.co", "api.wappie.thehappie.co", "localhost", "app.wappie.thehappie.co.example.com"} {
		for _, route := range []string{"/", "/index.html", "/settings/security"} {
			t.Run(host+route, func(t *testing.T) {
				resp := get(t, h, "https://"+host+route)
				defer resp.Body.Close()
				want := "'none'"
				if host == "app.wappie.thehappie.co" || host == "console.wappie.thehappie.co" {
					want = "https://api.wappie.thehappie.co/session-bridge.html"
				}
				policy := resp.Header.Get("Content-Security-Policy")
				if got := directive(policy, "frame-src"); got != want {
					t.Errorf("frame-src = %q, want %q", got, want)
				}
				if directive(policy, "frame-ancestors") != "'none'" || resp.Header.Get("X-Frame-Options") != "DENY" || resp.Header.Get("Cross-Origin-Resource-Policy") != "same-origin" {
					t.Errorf("main application became frameable: %v", resp.Header)
				}
			})
		}
	}
}

func directive(policy, name string) string {
	for _, part := range strings.Split(policy, ";") {
		fields := strings.Fields(part)
		if len(fields) > 0 && fields[0] == name {
			return strings.Join(fields[1:], " ")
		}
	}
	return ""
}

func TestExternalDocumentCSPIsOptInAndExact(t *testing.T) {
	for _, tc := range []struct {
		enabled bool
		origin  string
		want    bool
	}{
		{false, "https://remote.example:8443", false},
		{true, "https://remote.example:8443", true},
		{true, "http://remote.example", false},
		{true, "https://user:secret@remote.example", false},
		{true, "https://remote.example/path", false},
		{true, "https://remote.example; script-src *", false},
	} {
		h, err := webui.New(build(t), nil)
		if err != nil {
			t.Fatal(err)
		}
		h.ExternalServers = tc.enabled
		resp := get(t, h, "/?server_origin="+url.QueryEscape(tc.origin))
		resp.Body.Close()
		csp := resp.Header.Get("Content-Security-Policy")
		got := strings.Contains(csp, "connect-src 'self' https://remote.example:8443 wss://remote.example:8443;")
		if got != tc.want {
			t.Fatalf("enabled=%v origin=%s: %s", tc.enabled, tc.origin, csp)
		}
		if strings.Contains(csp, "script-src *") {
			t.Fatal("policy injected")
		}
	}
}

// The console reads an AI key's model list from the provider, in the
// person's browser (docs/mcp-enclave.md §18.7): the document may connect to
// the three providers only while AI integrations are advertised, and nothing
// else is relaxed for it.
func TestAIModelListsAreAllowedOnlyWhileAIIsOn(t *testing.T) {
	const providers = "https://api.anthropic.com https://api.openai.com https://generativelanguage.googleapis.com"
	for _, tc := range []struct {
		ai, external bool
		want         string
	}{
		{false, false, "'self'"},
		{true, false, "'self' " + providers},
		{false, true, "'self' https://remote.example:8443 wss://remote.example:8443"},
		{true, true, "'self' https://remote.example:8443 wss://remote.example:8443 " + providers},
	} {
		dir := build(t)
		write(t, filepath.Join(dir, "session-bridge.html"), "<!doctype html><title>session bridge</title>")
		h, err := webui.New(dir, nil)
		if err != nil {
			t.Fatal(err)
		}
		h.AIModelLists, h.ExternalServers = tc.ai, tc.external
		resp := get(t, h, "/?server_origin="+url.QueryEscape("https://remote.example:8443"))
		resp.Body.Close()
		csp := resp.Header.Get("Content-Security-Policy")
		if got := directive(csp, "connect-src"); got != tc.want {
			t.Errorf("ai=%v external=%v: connect-src %q, want %q", tc.ai, tc.external, got, tc.want)
		}
		if directive(csp, "script-src") != "'self'" || directive(csp, "default-src") != "'self'" {
			t.Errorf("ai=%v: another directive changed: %s", tc.ai, csp)
		}
		// Only the document: an asset and the session bridge keep their own.
		asset := get(t, h, "/assets/index-abc123.js")
		asset.Body.Close()
		if strings.Contains(asset.Header.Get("Content-Security-Policy"), "api.openai.com") {
			t.Errorf("ai=%v: an asset's policy names a provider", tc.ai)
		}
		req := httptest.NewRequest(http.MethodGet, "https://api.wappie.thehappie.co/session-bridge.html", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if strings.Contains(rec.Header().Get("Content-Security-Policy"), "api.openai.com") {
			t.Errorf("ai=%v: the session bridge's policy names a provider", tc.ai)
		}
	}
}

// Nothing under the API's prefixes is a page. An unknown or removed API
// route, or an OpenID or domain-verification probe, that reached the
// fallback with the console document would tell its client that it exists,
// with HTML where it expected JSON: on every host, for every method, it
// answers the API's JSON 404 instead, never redirected.
func TestAPIPathsAreNotPages(t *testing.T) {
	h, err := webui.New(build(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"api.wappie.thehappie.co", "app.wappie.thehappie.co", "console.wappie.thehappie.co", "localhost"} {
		for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodDelete} {
			for _, route := range []string{
				"/v1", "/v1/", "/v1/nope", "/v1/mcp/nope", "/v1/mcp/enclave/cimd", "/v1/mcp/enclave/nope?x=1",
				"/v1/index.html", "/.well-known", "/.well-known/openid-configuration",
				"/.well-known/openai-apps-challenge", "/.well-known/anything/else",
			} {
				t.Run(host+" "+method+" "+route, func(t *testing.T) {
					rec := httptest.NewRecorder()
					h.ServeHTTP(rec, httptest.NewRequest(method, "https://"+host+route, nil))
					if rec.Code != http.StatusNotFound {
						t.Fatalf("status %d, want 404", rec.Code)
					}
					for name, want := range map[string]string{
						"Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store",
						"X-Content-Type-Options": "nosniff", "Location": "",
					} {
						if got := rec.Header().Get(name); got != want {
							t.Errorf("%s = %q, want %q", name, got, want)
						}
					}
					if got, want := rec.Body.String(), `{"code":"not_found","message":"no such route"}`+"\n"; got != want {
						t.Errorf("body = %q, want %q", got, want)
					}
				})
			}
		}
	}
	for _, route := range []string{"/v1x", "/v10/nope", "/well-known/x", "/console/v1/nope"} {
		resp := get(t, h, "https://app.wappie.thehappie.co"+route)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
			t.Errorf("%s is not under an API prefix but answered %d %q", route, resp.StatusCode, resp.Header.Get("Content-Type"))
		}
	}
}

// The console's own addresses are the document: the archive at /, the
// console at /console and its settings screens at /console/{screen}
// (commercial web/src/ui/settingsScreens.ts), the end of a sign-in at
// /auth/callback, each with whatever query it carries.
func TestTheConsoleRoutesGetThePage(t *testing.T) {
	h, err := webui.New(build(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"app.wappie.thehappie.co", "api.wappie.thehappie.co", "localhost"} {
		for _, route := range []string{
			"/", "/?device=22222222-2222-4222-8222-222222222222", "/console", "/console/",
			"/console?mcp_connect=r_1", "/console/numbers", "/console/integrations", "/console/mcp",
			"/console/installations", "/auth/callback?code=c&state=s", "/conversa/qualquer",
		} {
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				t.Run(host+" "+method+" "+route, func(t *testing.T) {
					rec := httptest.NewRecorder()
					h.ServeHTTP(rec, httptest.NewRequest(method, "https://"+host+route, nil))
					if rec.Code != http.StatusOK {
						t.Fatalf("status %d, want 200", rec.Code)
					}
					if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
						t.Errorf("Content-Type = %q", got)
					}
					// The shell's screens are never stored (speculation.go); the console's own documents are revalidated.
					cache := "no-cache"
					if strings.HasPrefix(route, "/console/") && route != "/console/" {
						cache = "no-store"
					}
					if rec.Header().Get("Content-Security-Policy") == "" || rec.Header().Get("Cache-Control") != cache {
						t.Errorf("served without the document's headers: %v", rec.Header())
					}
					if method == http.MethodGet && !strings.Contains(rec.Body.String(), "<title>whatserver2</title>") {
						t.Errorf("served another body: %q", rec.Body.String())
					}
				})
			}
		}
	}
}

// Sign-in through the identity provider changes the document's headers only
// while it is on: the issuer may be connected to (the sign-in's token
// request), and /auth/callback, served as any page, carries strict-origin,
// so its ?code never rides in a Referer, even to this origin's own assets.
// The shared shell's data is read from The Happie Co's console: its origin
// joins connect-src only beside the issuer, and frame-ancestors stays 'none'
// (shell contract v1 2.2).
func TestPlatformConsoleJoinsConnectSrcOnly(t *testing.T) {
	const issuer, console = "https://id.thehappie.co", "https://console.thehappie.co"
	for _, tc := range []struct {
		issuer, console, connect string
	}{
		{issuer, console, "'self' " + issuer + " " + console},
		{"http://id.thehappie.localhost:8290", "http://console.thehappie.localhost:8290", "'self' http://id.thehappie.localhost:8290 http://console.thehappie.localhost:8290"},
		// Without the issuer, or anything but a bare origin, it is never spliced in.
		{"", console, "'self'"},
		{issuer, "", "'self' " + issuer},
		{issuer, issuer, "'self' " + issuer},
		{issuer, "https://console.thehappie.co; script-src *", "'self' " + issuer},
		{issuer, "https://console.thehappie.co/", "'self' " + issuer},
		{issuer, "http://console.example.com", "'self' " + issuer},
	} {
		h, err := webui.New(build(t), nil)
		if err != nil {
			t.Fatal(err)
		}
		h.PlatformIssuer, h.PlatformConsole = tc.issuer, tc.console
		for _, target := range []string{"/", "/console", "/console/numbers?workspace=01a08e0e-c546-7db3-9c44-e6352636d330"} {
			resp := get(t, h, target)
			resp.Body.Close()
			csp := resp.Header.Get("Content-Security-Policy")
			if got := directive(csp, "connect-src"); got != tc.connect {
				t.Errorf("%q %q %s: connect-src %q, want %q", tc.issuer, tc.console, target, got, tc.connect)
			}
			if got := directive(csp, "frame-ancestors"); got != "'none'" {
				t.Errorf("%q %q %s: frame-ancestors %q", tc.issuer, tc.console, target, got)
			}
			if directive(csp, "script-src") != "'self'" {
				t.Errorf("%q %q %s: script-src changed: %s", tc.issuer, tc.console, target, csp)
			}
		}
	}
}

// The pilot's document has the AI providers too: the console's origin comes
// right after the issuer, and the providers after it, each once.
func TestPlatformConsoleBesideTheAIProviders(t *testing.T) {
	h, err := webui.New(build(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	h.AIModelLists, h.PlatformIssuer, h.PlatformConsole = true, "https://id.thehappie.co", "https://console.thehappie.co"
	resp := get(t, h, "/console/mcp?workspace=01a08e0e-c546-7db3-9c44-e6352636d330")
	resp.Body.Close()
	csp := resp.Header.Get("Content-Security-Policy")
	want := "'self' https://id.thehappie.co https://console.thehappie.co https://api.anthropic.com https://api.openai.com https://generativelanguage.googleapis.com"
	if got := directive(csp, "connect-src"); got != want {
		t.Fatalf("connect-src %q, want %q", got, want)
	}
	if got := directive(csp, "frame-ancestors"); got != "'none'" {
		t.Fatalf("frame-ancestors %q", got)
	}
}

func TestPlatformSignInHeadersOnlyWhileItIsOn(t *testing.T) {
	const issuer = "https://id.thehappie.co"
	for _, tc := range []struct {
		issuer, connect, referrer string
	}{
		{"", "'self'", "strict-origin-when-cross-origin"},
		{issuer, "'self' " + issuer, "strict-origin"},
		{"http://id.thehappie.localhost:8290", "'self' http://id.thehappie.localhost:8290", "strict-origin"},
		// Anything but a bare origin is never spliced into the policy.
		{"https://id.thehappie.co; script-src *", "'self'", "strict-origin-when-cross-origin"},
		{"http://id.example.com", "'self'", "strict-origin-when-cross-origin"},
	} {
		h, err := webui.New(build(t), nil)
		if err != nil {
			t.Fatal(err)
		}
		h.PlatformIssuer = tc.issuer
		for _, target := range []string{"/auth/callback?code=thid_c_secret&state=s&iss=" + url.QueryEscape(issuer), "/", "/console"} {
			resp := get(t, h, target)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("%q %s: %d", tc.issuer, target, resp.StatusCode)
			}
			csp := resp.Header.Get("Content-Security-Policy")
			if got := directive(csp, "connect-src"); got != tc.connect {
				t.Errorf("%q %s: connect-src %q, want %q", tc.issuer, target, got, tc.connect)
			}
			if directive(csp, "script-src") != "'self'" {
				t.Errorf("%q %s: script-src changed: %s", tc.issuer, target, csp)
			}
			if got := resp.Header.Get("Referrer-Policy"); got != tc.referrer {
				t.Errorf("%q %s: Referrer-Policy %q, want %q", tc.issuer, target, got, tc.referrer)
			}
		}
		asset := get(t, h, "/assets/index-abc123.js")
		asset.Body.Close()
		if asset.Header.Get("Referrer-Policy") != "no-referrer" || strings.Contains(asset.Header.Get("Content-Security-Policy"), "id.thehappie") {
			t.Errorf("%q: an asset's headers changed", tc.issuer)
		}
	}
}
