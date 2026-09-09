package webui_test

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
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
