package webui_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"whatserver2/internal/webui"
)

// Prerendering between The Happie Co's console and the shared shell's
// screens (platform decision 0047, shell contract 2.4): what the server
// adds to a screen's document, the rules it names, and what it leaves alone.

const (
	shellIssuer  = "https://id.thehappie.co"
	shellConsole = "https://console.thehappie.co"
	shellApp     = "https://app.wappie.thehappie.co"
	shellTenant  = "01a08e0e-c546-7db3-9c44-e6352636d330"
)

// shellScreens are the four screens, with the query a console link gives them.
var shellScreens = []string{
	"/console/numbers?workspace=" + shellTenant,
	"/console/integrations?workspace=" + shellTenant + "&return=%2Fworkspaces%2F" + shellTenant,
	"/console/mcp?workspace=" + shellTenant,
	"/console/installations",
}

// shellHandler is the pilot's handler: the issuer and the console set, with
// a session bridge in the directory.
func shellHandler(t *testing.T, issuer, console string) *webui.Handler {
	t.Helper()
	dir := build(t)
	write(t, filepath.Join(dir, "session-bridge.html"), "<!doctype html><title>session bridge</title>")
	h, err := webui.New(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.PlatformIssuer, h.PlatformConsole = issuer, console
	return h
}

// serve answers method target on the app's host, with referers as its Referer headers.
func serve(h http.Handler, method, target string, referers ...string) *httptest.ResponseRecorder {
	if !strings.HasPrefix(target, "https://") {
		target = shellApp + target
	}
	r := httptest.NewRequest(method, target, nil)
	for _, ref := range referers {
		r.Header.Add("Referer", ref)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestConsoleScreensNameTheRules(t *testing.T) {
	on := shellHandler(t, shellIssuer, shellConsole)
	off := shellHandler(t, "", "")
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		for _, target := range append(slices.Clone(shellScreens), "/console/anything/deeper", "/console/numbers/") {
			rec := serve(on, method, target, shellConsole+"/")
			if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
				t.Fatalf("%s %s: %d %q", method, target, rec.Code, rec.Header().Get("Content-Type"))
			}
			if got := rec.Header().Values("Speculation-Rules"); len(got) != 1 || got[0] != `"/speculation-rules.json"` {
				t.Errorf("%s %s: Speculation-Rules %q", method, target, got)
			}
			if method == http.MethodHead && rec.Body.Len() != 0 {
				t.Errorf("HEAD %s has a body", target)
			}
			if got := serve(off, method, target, shellConsole+"/").Header().Get("Speculation-Rules"); got != "" {
				t.Errorf("%s %s with the shell off: Speculation-Rules %q", method, target, got)
			}
		}
	}
	// The archive, the console, the sign-in's callback, other pages, assets,
	// a missing file, the bridge and the API name none.
	for _, target := range []string{
		"/", "/?device=22222222-2222-4222-8222-222222222222", "/index.html", "/console", "/console/", "/console?workspace=" + shellTenant,
		"/auth/callback?code=c&state=s", "/conversa/qualquer", "/consoles/numbers", "/assets/index-abc123.js", "/assets/missing.js",
		"/console/missing.js", "/v1/shell", "/speculation-rules.json", "https://api.wappie.thehappie.co/session-bridge.html",
	} {
		rec := serve(on, http.MethodGet, target, shellConsole+"/")
		if got := rec.Header().Get("Speculation-Rules"); got != "" {
			t.Errorf("%s: Speculation-Rules %q", target, got)
		}
		if got := rec.Header().Get("Supports-Loading-Mode"); got != "" {
			t.Errorf("%s: Supports-Loading-Mode %q", target, got)
		}
	}
	// The old console host's documents are a redirect, with no rules.
	rec := serve(on, http.MethodGet, "https://console.wappie.thehappie.co/console/numbers?workspace="+shellTenant, shellConsole+"/")
	if rec.Code != http.StatusTemporaryRedirect || rec.Header().Get("Speculation-Rules") != "" || rec.Header().Get("Supports-Loading-Mode") != "" {
		t.Errorf("the console.wappie redirect: %d %v", rec.Code, rec.Header())
	}
}

func TestCredentialedPrerenderOnlyFromTheConsole(t *testing.T) {
	optIn := func(rec *httptest.ResponseRecorder) bool {
		return rec.Header().Get("Supports-Loading-Mode") == "credentialed-prerender"
	}
	on := shellHandler(t, shellIssuer, shellConsole)
	// The console's page asks: its Referer is its origin (strict-origin-when-cross-origin), or more of its address.
	for _, ref := range []string{shellConsole, shellConsole + "/", shellConsole + "/workspaces/" + shellTenant, shellConsole + "/account?tab=1", shellConsole + "/#x"} {
		for _, target := range shellScreens {
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				if rec := serve(on, method, target, ref); !optIn(rec) || rec.Header().Values("Supports-Loading-Mode")[0] != "credentialed-prerender" {
					t.Errorf("%s %s from %q: no opt-in", method, target, ref)
				}
			}
		}
	}
	// Anyone else: another scheme, port, host or neighbour on the same site,
	// user info, this origin itself, id., a malformed Referer, none.
	for _, ref := range []string{
		"", "http://console.thehappie.co/", "https://console.thehappie.co:443/", "https://console.thehappie.co:8443/",
		"https://console.thehappie.co.example/", "https://evil.console.thehappie.co/", "https://wappie.thehappie.co/",
		"https://neighbour.thehappie.co/", "https://user@console.thehappie.co/", "https://user:pw@console.thehappie.co/",
		shellApp + "/", shellIssuer + "/", "HTTPS://CONSOLE.THEHAPPIE.CO/", "console.thehappie.co", "//console.thehappie.co/",
		"nope", "::", "https://console.thehappie.co%2F/", "https://[::1/", "about:blank", "null",
	} {
		var refs []string
		if ref != "" {
			refs = []string{ref}
		}
		rec := serve(on, http.MethodGet, shellScreens[0], refs...)
		if rec.Code != http.StatusOK || optIn(rec) {
			t.Errorf("Referer %q: %d, opted in %t", ref, rec.Code, optIn(rec))
		}
		if rec.Header().Get("Speculation-Rules") == "" {
			t.Errorf("Referer %q: the screen lost its rules", ref)
		}
	}
	// Two Referers, even both the console's, are nobody's.
	if optIn(serve(on, http.MethodGet, shellScreens[0], shellConsole+"/", shellConsole+"/")) {
		t.Error("two Referers opted in")
	}
	// Never another page, whoever asks.
	for _, target := range []string{"/", "/console", "/auth/callback?code=c&state=s", "/conversa/qualquer", "/speculation-rules.json"} {
		if optIn(serve(on, http.MethodGet, target, shellConsole+"/")) {
			t.Errorf("%s opted in", target)
		}
	}
	// With the shell off, or half-configured, never.
	for _, tc := range []struct{ issuer, console string }{
		{"", ""}, {"", shellConsole}, {shellIssuer, ""}, {shellIssuer, shellIssuer},
		{shellIssuer, shellConsole + "/"}, {"https://id.thehappie.co; script-src *", shellConsole},
	} {
		h := shellHandler(t, tc.issuer, tc.console)
		rec := serve(h, http.MethodGet, shellScreens[0], shellConsole+"/")
		if optIn(rec) || rec.Header().Get("Speculation-Rules") != "" {
			t.Errorf("issuer %q console %q: %v", tc.issuer, tc.console, rec.Header())
		}
	}
}

func TestConsoleScreensAreNeverStored(t *testing.T) {
	for _, tc := range []struct{ issuer, console string }{{shellIssuer, shellConsole}, {"", ""}} {
		h := shellHandler(t, tc.issuer, tc.console)
		// The page as a browser holding a copy asks for it again.
		plain := serve(h, http.MethodGet, "/")
		lastModified := plain.Header().Get("Last-Modified")
		if lastModified == "" {
			t.Fatal("the document has no Last-Modified to revalidate with")
		}
		conditional := map[string]string{
			"If-Modified-Since": lastModified, "If-None-Match": `"*"`, "If-Unmodified-Since": "Mon, 01 Jan 1990 00:00:00 GMT",
			"If-Match": `"nope"`, "Range": "bytes=0-3", "If-Range": lastModified,
		}
		for _, target := range append(slices.Clone(shellScreens), "/console/anything") {
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				rec := serve(h, method, target, "https://neighbour.thehappie.co/")
				if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
					t.Errorf("issuer %q %s %s: %d, Cache-Control %q", tc.issuer, method, target, rec.Code, rec.Header().Get("Cache-Control"))
				}
			}
			for name, value := range conditional {
				r := httptest.NewRequest(http.MethodGet, shellApp+target, nil)
				r.Header.Set(name, value)
				r.Header.Set("Referer", "https://neighbour.thehappie.co/")
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, r)
				if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "<title>whatserver2</title>") || rec.Header().Get("Content-Range") != "" {
					t.Errorf("issuer %q %s with %s: %d, %q, Content-Range %q: not answered whole", tc.issuer, target, name, rec.Code, rec.Body.String(), rec.Header().Get("Content-Range"))
				}
				if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Supports-Loading-Mode") != "" {
					t.Errorf("issuer %q %s with %s: %v", tc.issuer, target, name, rec.Header())
				}
			}
		}
		// / and /console are the console's own documents: no-cache, and revalidated as before.
		for _, target := range []string{"/", "/console", "/console/", "/auth/callback?code=c&state=s"} {
			rec := serve(h, http.MethodGet, target)
			if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-cache" {
				t.Errorf("issuer %q %s: %d, Cache-Control %q", tc.issuer, target, rec.Code, rec.Header().Get("Cache-Control"))
			}
			r := httptest.NewRequest(http.MethodGet, shellApp+target, nil)
			r.Header.Set("If-Modified-Since", lastModified)
			again := httptest.NewRecorder()
			h.ServeHTTP(again, r)
			if again.Code != http.StatusNotModified {
				t.Errorf("issuer %q %s: a revalidation returned %d, want 304", tc.issuer, target, again.Code)
			}
		}
	}
}

func TestSpeculationRulesFile(t *testing.T) {
	for _, tc := range []struct{ issuer, console string }{
		{shellIssuer, shellConsole},
		{"http://id.thehappie.localhost:8290", "http://console.thehappie.localhost:8290"},
	} {
		h := shellHandler(t, tc.issuer, tc.console)
		rec := serve(h, http.MethodGet, "/speculation-rules.json")
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: the rules returned %d", tc.console, rec.Code)
		}
		if got := rec.Header().Values("Content-Type"); len(got) != 1 || got[0] != "application/speculationrules+json" {
			t.Errorf("%s: Content-Type %q", tc.console, got)
		}
		for name, want := range map[string]string{"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Speculation-Rules": "", "Supports-Loading-Mode": ""} {
			if got := rec.Header().Get(name); got != want {
				t.Errorf("%s: %s %q, want %q", tc.console, name, got, want)
			}
		}
		want := `{"prerender":[{"source":"document","where":{"or":[` +
			`{"href_matches":"` + tc.console + `/workspaces"},` +
			`{"href_matches":"` + tc.console + `/workspaces/*"},` +
			`{"href_matches":"` + tc.console + `/account"},` +
			`{"href_matches":"` + tc.console + `/contacts"},` +
			`{"href_matches":"` + tc.console + `/ai"}]},"eagerness":"moderate"}]}`
		if rec.Body.String() != want {
			t.Errorf("the rules are\n%s\nwant\n%s", rec.Body.String(), want)
		}
		if got := rec.Header().Get("Content-Length"); got != strconv.Itoa(len(want)) {
			t.Errorf("Content-Length %q", got)
		}
		// Decoded: exactly the console's pages the shell links to, never its sign-in, sign-out or API.
		var rules struct {
			Prerender []struct {
				Source string `json:"source"`
				Where  struct {
					Or []struct {
						HrefMatches string `json:"href_matches"`
					} `json:"or"`
				} `json:"where"`
				Eagerness string `json:"eagerness"`
			} `json:"prerender"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &rules); err != nil || len(rules.Prerender) != 1 {
			t.Fatalf("the rules do not decode: %v", err)
		}
		var patterns []string
		for _, m := range rules.Prerender[0].Where.Or {
			patterns = append(patterns, m.HrefMatches)
		}
		wantPatterns := []string{tc.console + "/workspaces", tc.console + "/workspaces/*", tc.console + "/account", tc.console + "/contacts", tc.console + "/ai"}
		if !slices.Equal(patterns, wantPatterns) || rules.Prerender[0].Eagerness != "moderate" || rules.Prerender[0].Source != "document" {
			t.Errorf("the rules: %+v", rules)
		}
		for _, p := range patterns {
			for _, never := range []string{"/auth", "/signout", "/v1", "/invitation"} {
				if strings.Contains(p, never) {
					t.Errorf("the rules prerender %s", p)
				}
			}
		}
		// HEAD: the headers alone. POST: refused.
		head := serve(h, http.MethodHead, "/speculation-rules.json")
		if head.Code != http.StatusOK || head.Body.Len() != 0 || head.Header().Get("Content-Type") != "application/speculationrules+json" {
			t.Errorf("HEAD: %d, %d bytes, %q", head.Code, head.Body.Len(), head.Header().Get("Content-Type"))
		}
		if post := serve(h, http.MethodPost, "/speculation-rules.json"); post.Code != http.StatusMethodNotAllowed || post.Header().Get("Allow") != "GET, HEAD" {
			t.Errorf("POST: %d, Allow %q", post.Code, post.Header().Get("Allow"))
		}
	}

	// A file of that name in the client's directory is never served instead, on or off.
	for _, tc := range []struct {
		issuer, console string
		status          int
	}{
		{shellIssuer, shellConsole, http.StatusOK},
		{"", "", http.StatusNotFound},
		{"", shellConsole, http.StatusNotFound},
		{shellIssuer, "", http.StatusNotFound},
		{shellIssuer, shellIssuer, http.StatusNotFound},
		{shellIssuer, shellConsole + "/", http.StatusNotFound},
		{shellIssuer, "https://console.thehappie.co; script-src *", http.StatusNotFound},
		{"https://id.thehappie.co/", shellConsole, http.StatusNotFound},
		{shellIssuer, "http://console.example.com", http.StatusNotFound},
	} {
		dir := build(t)
		write(t, filepath.Join(dir, "speculation-rules.json"), `{"prerender":[{"source":"list","urls":["https://elsewhere.example/"]}]}`)
		h, err := webui.New(dir, nil)
		if err != nil {
			t.Fatal(err)
		}
		h.PlatformIssuer, h.PlatformConsole = tc.issuer, tc.console
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			rec := serve(h, method, "/speculation-rules.json")
			if rec.Code != tc.status || strings.Contains(rec.Body.String(), "elsewhere") || rec.Header().Get("Cache-Control") != "no-store" {
				t.Errorf("issuer %q console %q %s: %d %q, Cache-Control %q", tc.issuer, tc.console, method, rec.Code, rec.Body.String(), rec.Header().Get("Cache-Control"))
			}
		}
	}
}

func TestPrerenderLeavesThePoliciesAlone(t *testing.T) {
	for _, tc := range []struct {
		name            string
		issuer, console string
		ai              bool
		referrer        string
	}{
		{"shell on", shellIssuer, shellConsole, false, "strict-origin"},
		{"shell on, AI on", shellIssuer, shellConsole, true, "strict-origin"},
		{"issuer only", shellIssuer, "", false, "strict-origin"},
		{"shell off", "", "", false, "strict-origin-when-cross-origin"},
		{"shell off, AI on", "", shellConsole, true, "strict-origin-when-cross-origin"},
	} {
		h := shellHandler(t, tc.issuer, tc.console)
		h.AIModelLists = tc.ai
		base := serve(h, http.MethodGet, "/")
		policy := base.Header().Get("Content-Security-Policy")
		if policy == "" || !strings.Contains(policy, "frame-ancestors 'none'") {
			t.Fatalf("%s: the document's policy is %q", tc.name, policy)
		}
		for _, target := range append([]string{"/", "/console", "/console/", "/auth/callback?code=thid_c_secret&state=s"}, shellScreens...) {
			for _, refs := range [][]string{nil, {shellConsole + "/"}} {
				rec := serve(h, http.MethodGet, target, refs...)
				if got := rec.Header().Get("Content-Security-Policy"); got != policy {
					t.Errorf("%s %s: the policy is\n%s\nnot the document's\n%s", tc.name, target, got, policy)
				}
				// The consent post needs an Origin (no-referrer sends "null"), and the console's opt-in this origin.
				if got := rec.Header().Get("Referrer-Policy"); got != tc.referrer {
					t.Errorf("%s %s: Referrer-Policy %q, want %q", tc.name, target, got, tc.referrer)
				}
				for name, want := range map[string]string{
					"X-Frame-Options": "DENY", "Cross-Origin-Opener-Policy": "same-origin", "Cross-Origin-Resource-Policy": "same-origin",
					"X-Content-Type-Options": "nosniff", "Vary": "",
				} {
					if got := rec.Header().Get(name); got != want {
						t.Errorf("%s %s: %s %q, want %q", tc.name, target, name, got, want)
					}
				}
			}
		}
		// The rules add nothing to connect-src: the console is there only as the shell's reader, beside the issuer.
		want := "'self'"
		if tc.issuer != "" {
			want += " " + tc.issuer
			if tc.console != "" {
				want += " " + tc.console
			}
		}
		if tc.ai {
			want += " https://api.anthropic.com https://api.openai.com https://generativelanguage.googleapis.com"
		}
		if got := directive(policy, "connect-src"); got != want {
			t.Errorf("%s: connect-src %q, want %q", tc.name, got, want)
		}
		for _, name := range []string{"script-src", "default-src", "worker-src"} {
			if got := directive(policy, name); got != "'self'" {
				t.Errorf("%s: %s %q", tc.name, name, got)
			}
		}
	}
}
