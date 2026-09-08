package webui_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
}

func TestServesAssets(t *testing.T) {
	h, err := webui.New(build(t), nil)
	if err != nil {
		t.Fatal(err)
	}

	resp := get(t, h, "/assets/index-abc123.js")
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
