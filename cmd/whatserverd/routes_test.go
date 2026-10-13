package main

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"whatserver2/internal/config"
	"whatserver2/internal/pg"
	"whatserver2/internal/webui"
	"whatserver2/internal/wsapi"
)

const noSuchRoute = `{"code":"not_found","message":"no such route"}` + "\n"

// testRoutes is the server's handler as the pilot mounts it: the assistant
// connector with an attested reader, and the web client unless headless.
// Nothing behind a route is reached by these tests, so nothing is opened.
func testRoutes(t *testing.T, headless bool) http.Handler {
	t.Helper()
	a := &app{
		cfg: config.Config{MetricsAddr: "127.0.0.1:0", MCP: enclaveConfig()},
		log: slog.New(slog.DiscardHandler), pools: &pg.Pools{}, ws: &wsapi.Server{},
	}
	if !headless {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html><title>wappie</title>"), 0o644); err != nil {
			t.Fatal(err)
		}
		web, err := webui.New(dir, nil)
		if err != nil {
			t.Fatal(err)
		}
		a.web = web
	}
	return a.routes()
}

func ask(h http.Handler, method, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	return rec
}

// A route this server does not have under /v1/ or /.well-known/, a removed
// one included (the enclave's CIMD relay, gone in wappie#43), answers the
// API's JSON 404 on the API's host and the application's alike, for every
// method: the console document there told a client the route still existed.
// It is the answer the routes give a caller they are not there for.
func TestAnUnknownAPIRouteIsAJSON404(t *testing.T) {
	for _, headless := range []bool{false, true} {
		h := testRoutes(t, headless)
		mounted := ask(h, http.MethodGet, "https://api.wappie.thehappie.co/v1/mcp/enclave/connections/x")
		if mounted.Code != http.StatusNotFound || mounted.Body.String() != noSuchRoute {
			t.Fatalf("a mounted route's own 404 changed: %d %q", mounted.Code, mounted.Body.String())
		}
		// A route that is not there until it is configured answers the same.
		unset := ask(h, http.MethodGet, "https://api.wappie.thehappie.co/.well-known/openai-apps-challenge")
		if unset.Code != http.StatusNotFound || unset.Body.String() != noSuchRoute {
			t.Errorf("the unset OpenAI challenge: %d %q", unset.Code, unset.Body.String())
		}
		for _, host := range []string{"api.wappie.thehappie.co", "app.wappie.thehappie.co", "console.wappie.thehappie.co"} {
			for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodDelete} {
				for _, route := range []string{
					"/v1", "/v1/", "/v1/nope", "/v1/mcp/nope", "/v1/mcp/enclave/nope", "/v1/mcp/enclave/cimd",
					"/v1/mcp/internal/nope?x=1", "/v1/auth/nope/index.html", "/.well-known/nope",
					"/.well-known/openid-configuration",
				} {
					rec := ask(h, method, "https://"+host+route)
					if rec.Code != http.StatusNotFound {
						t.Errorf("headless %v: %s %s%s: status %d, want 404", headless, method, host, route, rec.Code)
						continue
					}
					if got := rec.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
						t.Errorf("headless %v: %s %s%s: Content-Type %q", headless, method, host, route, got)
					}
					if got := rec.Body.String(); got != mounted.Body.String() {
						t.Errorf("headless %v: %s %s%s: body %q", headless, method, host, route, got)
					}
				}
			}
		}
	}
}

// A route asked with a method it does not take keeps the router's 405, with
// the methods it does take (docs/rest-api.md): neither the console document
// nor a 404.
func TestARouteKeepsItsMethodNotAllowed(t *testing.T) {
	for _, headless := range []bool{false, true} {
		h := testRoutes(t, headless)
		for _, tc := range []struct{ method, route, allow string }{
			{http.MethodPost, "/v1/devices", "GET, HEAD"},
			{http.MethodDelete, "/v1/grants", "GET, HEAD"},
			{http.MethodGet, "/v1/auth/login", "POST"},
			{http.MethodHead, "/v1/mcp/token-requests", "POST"},
			{http.MethodPost, "/.well-known/wappie", "GET, HEAD"},
		} {
			rec := ask(h, tc.method, "https://app.wappie.thehappie.co"+tc.route)
			if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != tc.allow {
				t.Errorf("headless %v: %s %s: %d, Allow %q; want 405, Allow %q",
					headless, tc.method, tc.route, rec.Code, rec.Header().Get("Allow"), tc.allow)
			}
		}
	}
}

// The routes still answer, and the console's own addresses are still the
// document, on the application's host and the API's.
func TestTheConsoleKeepsItsPages(t *testing.T) {
	h := testRoutes(t, false)
	for _, route := range []string{"/v1/discovery", "/.well-known/wappie"} {
		rec := ask(h, http.MethodGet, "https://api.wappie.thehappie.co"+route)
		if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" {
			t.Errorf("%s: %d %q", route, rec.Code, rec.Header().Get("Content-Type"))
		}
	}
	for _, host := range []string{"app.wappie.thehappie.co", "api.wappie.thehappie.co"} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			for _, route := range []string{
				"/", "/console", "/console/", "/console/mcp?workspace=01a08e0e-c546-7db3-9c44-e6352636d330",
				"/console/numbers", "/auth/callback?code=c&state=s", "/conversa/qualquer",
			} {
				rec := ask(h, method, "https://"+host+route)
				if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
					t.Errorf("%s %s%s: %d %q, want the document", method, host, route, rec.Code, rec.Header().Get("Content-Type"))
				}
				if method == http.MethodGet && !strings.Contains(rec.Body.String(), "<title>wappie</title>") {
					t.Errorf("%s %s%s: served %q", method, host, route, rec.Body.String())
				}
			}
		}
	}
	// A page asked with a method it does not take is still the client's 405.
	if rec := ask(h, http.MethodPost, "https://app.wappie.thehappie.co/console"); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /console: %d", rec.Code)
	}
	// A path that is not clean is still redirected to the clean one, under
	// /v1/ and elsewhere, before anything answers it (301 up to Go 1.26, 307
	// since).
	for route, want := range map[string]string{"/v1//nope": "/v1/nope", "/console/../console/mcp": "/console/mcp"} {
		rec := ask(h, http.MethodGet, "https://app.wappie.thehappie.co"+route)
		if rec.Code != http.StatusMovedPermanently && rec.Code != http.StatusTemporaryRedirect || rec.Header().Get("Location") != want {
			t.Errorf("%s: %d to %q, want a redirect to %q", route, rec.Code, rec.Header().Get("Location"), want)
		}
	}
}
