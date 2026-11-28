package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"

	"whatserver2/internal/wsapi"
)

// serveOptions are serve's command line: whatserverd serve [-maintenance
// [-allow NAME]...]. The zero value is a normal start.
type serveOptions struct {
	// maintenance is a maintenance start (docs/deployment.md, "Maintenance
	// start"): no capture, no workers, MCP and API keys off, and every
	// write refused but sign-in and the allowed ones.
	maintenance bool
	// allow names the declared change's writes, from maintenanceWrites.
	allow []string
}

// parseServe reads serve's flags. Anything it does not know is a usage
// error, so a mistyped flag never starts a server, least of all a normal
// one in place of a maintenance one; so is -allow without -maintenance, or
// a name maintenanceWrites does not have.
func parseServe(args []string) (serveOptions, error) {
	var opts serveOptions
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.BoolVar(&opts.maintenance, "maintenance", false, "start in maintenance (docs/deployment.md)")
	fs.Func("allow", "with -maintenance, a declared change's write to allow, by name", func(name string) error {
		opts.allow = append(opts.allow, name)
		return nil
	})
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return serveOptions{}, usageError{arg: strings.TrimSpace("serve " + strings.Join(args, " "))}
	}
	if len(opts.allow) > 0 && !opts.maintenance {
		return serveOptions{}, exitError{code: 2, err: errors.New("whatserverd serve: -allow is only for a maintenance start (-maintenance)")}
	}
	for _, name := range opts.allow {
		if _, ok := maintenanceWrites[name]; !ok {
			return serveOptions{}, exitError{code: 2, err: fmt.Errorf("whatserverd serve: %q is not a write a maintenance start can allow (it can allow: %s)",
				name, knownWrites())}
		}
	}
	return opts, nil
}

// maintenanceWrite is one write a declared change may need from a
// maintenance start: the socket frames and the HTTP routes, as the mux
// mounts them ("PUT /v1/example"), it lets a person's session through to.
// An API key is refused all the same.
type maintenanceWrite struct {
	frames []string
	routes []string
}

// maintenanceWrites are the writes a maintenance start can be told to
// allow with -allow, by name: none today. A slice whose change needs a
// person to write while capture is stopped (a key act in the key page, a
// check that posts its counts) adds its write here under the name its
// kit's manifest declares, with only the frames and routes that write
// needs, and a test that it is refused without -allow. A name that is not
// here stops the start.
var maintenanceWrites = map[string]maintenanceWrite{}

// knownWrites lists maintenanceWrites' names for an error: "none" today.
func knownWrites() string {
	names := slices.Sorted(maps.Keys(maintenanceWrites))
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}

// maintenance is a maintenance start's limits, nil on a normal start.
type maintenance struct {
	// allowed are the -allow names, as given.
	allowed []string
	// frames and routes are what they let through.
	frames []string
	routes map[string]bool
}

func newMaintenance(allow []string) *maintenance {
	m := &maintenance{allowed: slices.Clone(allow), routes: map[string]bool{}}
	for _, name := range allow {
		w := maintenanceWrites[name]
		m.frames = append(m.frames, w.frames...)
		for _, route := range w.routes {
			m.routes[route] = true
		}
	}
	return m
}

// socket is the websocket server's part of m: its reads and the allowed
// frames. A nil m is a normal start's socket, which answers everything.
func (m *maintenance) socket() *wsapi.Maintenance {
	if m == nil {
		return nil
	}
	return wsapi.NewMaintenance(m.frames...)
}

// maintenanceHeader is on every answer of a maintenance start, its probes
// and metrics included, so a kit sees which start answered it.
const maintenanceHeader = "Wappie-Maintenance"

// marked is next with the maintenance header on every answer, for the
// probes' own listener (WS_METRICS_ADDR), which the gate does not see. A
// nil m is next.
func (m *maintenance) marked(next http.Handler) http.Handler {
	if m == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(maintenanceHeader, "on")
		next.ServeHTTP(w, r)
	})
}

// signInRoutes are the writes every maintenance start lets through: a
// person signing in (by password, passkey or the platform) and out, into
// another of their workspaces, and the step-up a key page may ask. They
// write the person's session, and a sign-in through the platform the
// account's pinned key and e-mail; nothing of a number, a message or an
// object. Signing up, accepting an invitation, creating a workspace and
// every account or workspace setting stay refused.
var signInRoutes = map[string]bool{
	"POST /v1/auth/challenge":               true,
	"POST /v1/auth/login":                   true,
	"POST /v1/auth/logout":                  true,
	"POST /v1/auth/passkeys/login/options":  true,
	"POST /v1/auth/passkeys/login/finish":   true,
	"POST /v1/auth/platform/session":        true,
	"POST /v1/auth/workspaces/session":      true,
	"POST /v1/auth/step-up/passkey/options": true,
	"POST /v1/auth/step-up/passkey":         true,
	"POST /v1/auth/step-up/password":        true,
	"POST /v1/auth/platform/step-up/start":  true,
	"POST /v1/auth/platform/step-up/finish": true,
}

// keyBearer reports whether r carries an API key as its bearer. A key is
// its prefix, a dot and its secret (store.APIKeys.Issue); a person's
// session token is base64url and has no dot, and no route takes anything
// else as a bearer (the platform's tokens come in the body).
func keyBearer(r *http.Request) bool {
	for _, value := range r.Header.Values("Authorization") {
		scheme, token, ok := strings.Cut(strings.TrimSpace(value), " ")
		if ok && strings.EqualFold(scheme, "Bearer") && strings.Contains(token, ".") {
			return true
		}
	}
	return false
}

// lets reports whether a maintenance start answers r: a read (GET, HEAD,
// OPTIONS; the socket's own frames are judged by the socket), a sign-in,
// an allowed route, or what no route claims, which unrouted answers with
// the router's 404 or 405 or the web client and which writes nothing.
func (m *maintenance) lets(mux *http.ServeMux, r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	_, pattern := mux.Handler(r)
	return pattern == "" || signInRoutes[pattern] || m.routes[pattern]
}

// gate is next behind a maintenance start's HTTP limits: every answer says
// it is a maintenance start, and a request with an API key, or a write it
// does not let through, is refused 503 maintenance before any handler
// runs. The key gets maintenance, as on the socket, and not the 401 of a
// revoked key, so a client keeps a key that works again after the window.
// A nil m is next.
func (m *maintenance) gate(mux *http.ServeMux, next http.Handler) http.Handler {
	if m == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(maintenanceHeader, "on")
		if !keyBearer(r) && m.lets(mux, r) {
			next.ServeHTTP(w, r)
			return
		}
		header := w.Header()
		header.Set("Content-Type", "application/json; charset=utf-8")
		header.Set("Cache-Control", "no-store")
		header.Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusServiceUnavailable)
		//nolint:errcheck // the client hung up; there is nothing left to say to it
		_, _ = io.WriteString(w, maintenanceRefusal)
	})
}

// maintenanceRefusal is a refused write's body, in the API's error shape.
const maintenanceRefusal = `{"code":"` + wsapi.ErrCodeMaintenance + `","message":"this server is in maintenance: it answers a person's reads and sign-in only; API keys are off"}` + "\n"

// logMaintenance says, once at the start, that this is a maintenance
// start and what it leaves off, with the allowed writes by name.
func (a *app) logMaintenance() {
	if a.maintenance == nil {
		return
	}
	allowed := a.maintenance.allowed
	if allowed == nil {
		allowed = []string{}
	}
	a.log.Warn("MAINTENANCE START: no WhatsApp supervisor or resume, no attachment, picture or history worker, "+
		"no janitor, no contract leader, MCP and API keys off, no object written; "+
		"people may sign in and read, every other write is refused",
		"maintenance", true, "allowed", allowed)
}
