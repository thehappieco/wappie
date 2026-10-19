package webui

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Prerendering between The Happie Co's console and the shared shell's
// screens (platform decision 0047, shell 1.4.0, shell contract 2.4): the
// console prerenders a screen of this page on hover, and a screen
// prerenders the console's pages its menu links to, so the click shows a
// page already drawn. Only while the shared shell is on (shellConsole).
//
// The rules it enforces:
//   - a screen's document (/console/{screen}, a 200 text/html answer)
//     names the rules in the Speculation-Rules header: a JSON file served
//     at /speculation-rules.json as application/speculationrules+json, the
//     one type Chromium takes header rules in; /, /console and every other
//     page name none;
//   - the rules prerender, at moderate eagerness, exactly the console's
//     pages the shell links to: every workspace (/workspaces), a
//     workspace's pages and an app's overview and AI tab (/workspaces/*),
//     My account, Contacts and AI integrations; never the console's
//     sign-in (/auth), its sign-out page (/signout), its API (/v1) or an
//     invitation;
//   - a screen's document opts in to a credentialed prerender
//     (Supports-Loading-Mode: credentialed-prerender) only when its
//     request's one Referer has the console's exact origin: the console's
//     rules ask for it, and a neighbour on the same site never gets it,
//     which would otherwise prerender a screen with this page's session.
//     Sec-Fetch-Site cannot say who asked: a prerender sends "none";
//   - so a screen's document is never stored (Cache-Control: no-store),
//     whatever its status and whether the shell is on, and is always
//     answered whole: a stored copy revalidated with a 304 would keep the
//     headers of the answer it was stored from, the opt-in included, for
//     whichever page asked next;
//   - nothing else changes: the rules are same-origin, so the policy's
//     'self' covers them, a navigation has no directive, and the
//     Referrer-Policy stays the document's (strict-origin, or
//     strict-origin-when-cross-origin without the issuer), which sends the
//     console this origin, as its opt-in needs.

// speculationRulesPath is where the screens' rules are served.
const speculationRulesPath = "/speculation-rules.json"

// speculationRulesType is the only type Chromium takes header rules in.
const speculationRulesType = "application/speculationrules+json"

// consolePages are the console's pages the shell links to (shell contract
// 1.3 and 2.4), as URL patterns on the console's origin.
var consolePages = []string{"/workspaces", "/workspaces/*", "/account", "/contacts", "/ai"}

// shellScreenPrefix is where the shared shell's screens live: every
// document under it is a screen (commercial web/src/ui/settingsScreens.ts
// names them; a new one needs nothing here).
const shellScreenPrefix = "/console/"

// shellConsole is the console's origin while the shared shell is on: a
// valid issuer, and a valid console origin that is not the issuer's. ""
// otherwise. The document's connect-src and the rules both follow it, so
// they never disagree.
func (h *Handler) shellConsole() string {
	issuer := platformIssuer(h.PlatformIssuer)
	if issuer == "" {
		return ""
	}
	if console := platformIssuer(h.PlatformConsole); console != "" && console != issuer {
		return console
	}
	return ""
}

// speculationRules is the rules file for the console at consoleOrigin.
func speculationRules(consoleOrigin string) []byte {
	type match struct {
		HrefMatches string `json:"href_matches"`
	}
	type rule struct {
		Source string `json:"source"`
		Where  struct {
			Or []match `json:"or"`
		} `json:"where"`
		Eagerness string `json:"eagerness"`
	}
	r := rule{Source: "document", Eagerness: "moderate"}
	for _, p := range consolePages {
		r.Where.Or = append(r.Where.Or, match{HrefMatches: consoleOrigin + p})
	}
	b, err := json.Marshal(struct {
		Prerender []rule `json:"prerender"`
	}{[]rule{r}})
	if err != nil {
		panic("webui: the speculation rules do not marshal: " + err.Error())
	}
	return b
}

// serveSpeculationRules answers speculationRulesPath (GET or HEAD): the
// rules while the shell is on, else a 404 as for any missing file. A file of
// that name in the client's directory is never served instead.
func (h *Handler) serveSpeculationRules(w http.ResponseWriter, r *http.Request) {
	h.headers(w, speculationRulesPath, r.Host, "")
	// Never stored, nor its 404: the switch may turn on, or the console
	// move, under a copy a browser kept.
	w.Header().Set("Cache-Control", "no-store")
	console := h.shellConsole()
	if console == "" {
		http.NotFound(w, r)
		return
	}
	rules := speculationRules(console)
	header := w.Header()
	header.Set("Content-Type", speculationRulesType)
	header.Set("Content-Length", strconv.Itoa(len(rules)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		//nolint:errcheck // the client hung up; there is nothing left to say to it
		_, _ = w.Write(rules)
	}
}

// wholeRequest is r without the headers that make a request conditional or
// partial: a screen's document is answered whole, every time.
func wholeRequest(r *http.Request) *http.Request {
	c := r.Clone(r.Context())
	for _, name := range []string{"If-Modified-Since", "If-None-Match", "If-Match", "If-Unmodified-Since", "If-Range", "Range"} {
		c.Header.Del(name)
	}
	return c
}

// fromOrigin reports whether r's one Referer is on origin exactly: http or
// https, a host, no user info, and scheme://host byte for byte. A path or a
// query after it is fine; another port, scheme or host is not.
func fromOrigin(r *http.Request, origin string) bool {
	refs := r.Header.Values("Referer")
	if len(refs) != 1 {
		return false
	}
	u, err := url.Parse(refs[0])
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.Opaque != "" {
		return false
	}
	return u.Scheme+"://"+u.Host == origin
}

// screenWriter makes every answer of a screen's path no-store, and adds the
// rules (rules) and, for a request from the console (optIn), the opt-in to
// a screen's page document: a 200 text/html answer.
type screenWriter struct {
	http.ResponseWriter
	rules bool
	optIn bool
	wrote bool
}

func (s *screenWriter) WriteHeader(status int) {
	if !s.wrote && status >= 200 {
		s.wrote = true
		header := s.Header()
		header.Set("Cache-Control", "no-store")
		mt, _, _ := strings.Cut(header.Get("Content-Type"), ";")
		if s.rules && status == http.StatusOK && strings.EqualFold(strings.TrimSpace(mt), "text/html") {
			header.Set("Speculation-Rules", strconv.Quote(speculationRulesPath))
			if s.optIn {
				header.Set("Supports-Loading-Mode", "credentialed-prerender")
			}
		}
	}
	s.ResponseWriter.WriteHeader(status)
}

func (s *screenWriter) Write(b []byte) (int, error) {
	if !s.wrote {
		s.WriteHeader(http.StatusOK)
	}
	return s.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (s *screenWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }
