// Command fakecontract is the kit's fake platform (contract/contracttest)
// served where Wappie's production transport dials the real one: a unix
// socket, root's in the host simulation, with the mode and group the
// platform's socket unit gives its own (root:platform-contract 0660). Or,
// for development, loopback TCP, as the platform's development transport.
// It is for development and the host simulation only, never a host that
// serves people: it signs with test secrets and keeps everything in memory.
//
//	fakecontract -socket /run/platform/contract.sock -group platform-contract \
//	    -secret-file /etc/fakecontract/secret -control /run/fakecontract.sock
//
// The secret files hold test secrets in plain text, 43 characters. The
// control socket (0600, its owner's alone) plays the platform's side of the
// tests: the rotation's steps (POST /secrets), a new generation, a restore,
// the directory (accounts and teams), refusals and corruptions, and reads
// what Wappie sent. Every request and answer is JSON; every answer of the
// control socket names no secret.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	kc "github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/contract/contracttest"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stderr, nil); err != nil {
		fmt.Fprintf(os.Stderr, "fakecontract: %v\n", err)
		os.Exit(1)
	}
}

// options are the command line.
type options struct {
	socket, addr, group, control string
	mode                         os.FileMode
	app, secretFile, otherFile   string
}

func parse(args []string, stderr io.Writer) (options, error) {
	var o options
	fs := flag.NewFlagSet("fakecontract", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&o.socket, "socket", "", "serve on this unix socket (the platform's is /run/platform/contract.sock)")
	fs.StringVar(&o.addr, "addr", "", "serve on this loopback address instead (the platform's development transport, 127.0.0.1:8291)")
	mode := fs.String("mode", "0660", "the socket's mode")
	fs.StringVar(&o.group, "group", "", "the socket's group (platform-contract); empty keeps the process's")
	fs.StringVar(&o.control, "control", "", "the control socket, 0600 (empty: no control)")
	fs.StringVar(&o.app, "app", "wappie", "the app served")
	fs.StringVar(&o.secretFile, "secret-file", "", "the app's current secret, 43 characters in plain text (a test secret)")
	fs.StringVar(&o.otherFile, "other-file", "", "the app's other secret, accepted on requests too (a rotation)")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	m, err := strconv.ParseUint(*mode, 8, 32)
	if err != nil || m > 0o777 {
		return o, errors.New("-mode must be an octal mode such as 0660")
	}
	o.mode = os.FileMode(m)
	switch {
	case fs.NArg() != 0:
		return o, fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	case (o.socket == "") == (o.addr == ""):
		return o, errors.New("set one of -socket and -addr")
	case o.secretFile == "":
		return o, errors.New("-secret-file is required")
	}
	if o.addr != "" {
		host, _, err := net.SplitHostPort(o.addr)
		if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() {
			return o, errors.New("-addr must be a loopback IP and a port")
		}
	}
	return o, nil
}

// readSecret reads a test secret file: one line.
func readSecret(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	b, err := os.ReadFile(path) //nolint:gosec // G304: the operator names the test secret's file
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(string(b), "\n"), nil
}

// run serves until ctx ends. ready, when set, is told the listeners'
// addresses once both listen.
func run(ctx context.Context, args []string, stderr io.Writer, ready func(contract, control string)) error {
	o, err := parse(args, stderr)
	if err != nil {
		return err
	}
	current, err := readSecret(o.secretFile)
	if err != nil {
		return err
	}
	other, err := readSecret(o.otherFile)
	if err != nil {
		return err
	}
	p, err := contracttest.New(contracttest.Options{
		Apps:         []contracttest.App{{ID: o.app, Current: current, Other: other}},
		StrictLabels: true,
	})
	if err != nil {
		return err
	}
	defer p.Close()
	log := slog.New(slog.NewTextHandler(stderr, nil))

	ln, err := listen(ctx, o)
	if err != nil {
		return err
	}
	servers := []*http.Server{{Handler: p, ReadHeaderTimeout: 10 * time.Second}}
	listeners := []net.Listener{ln}
	controlAddr := ""
	if o.control != "" {
		cl, err := listenUnix(ctx, o.control, 0o600, "")
		if err != nil {
			_ = ln.Close() //nolint:errcheck // already failing
			return err
		}
		controlAddr = cl.Addr().String()
		servers = append(servers, &http.Server{Handler: control(p, o.app), ReadHeaderTimeout: 10 * time.Second})
		listeners = append(listeners, cl)
	}
	log.Warn("fakecontract: a fake platform for development and tests, never for people's data",
		"contract", ln.Addr().String(), "control", controlAddr, "app", o.app)
	if ready != nil {
		ready(ln.Addr().String(), controlAddr)
	}
	errs := make(chan error, len(servers))
	for i, srv := range servers {
		go func() { errs <- srv.Serve(listeners[i]) }()
	}
	select {
	case <-ctx.Done():
	case err := <-errs:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	// Closing a unix listener removes its socket, as the platform's socket
	// unit does when it stops (RemoveOnStop=yes).
	for _, srv := range servers {
		_ = srv.Close() //nolint:errcheck // shutting down
	}
	return nil
}

func listen(ctx context.Context, o options) (net.Listener, error) {
	if o.addr != "" {
		var lc net.ListenConfig
		return lc.Listen(ctx, "tcp", o.addr)
	}
	return listenUnix(ctx, o.socket, o.mode, o.group)
}

// listenUnix listens on path, replacing a socket left by a process that
// died, never a socket another process serves (platformd's, or a second
// fake's) and never any other file, with mode and, when set, group.
func listenUnix(ctx context.Context, path string, mode os.FileMode, group string) (net.Listener, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		// Only a refused connection says nobody listens: anything else (an
		// answer, a permission denied) may be a live server's socket.
		d := net.Dialer{Timeout: time.Second}
		conn, err := d.DialContext(ctx, "unix", path)
		if err == nil {
			_ = conn.Close() //nolint:errcheck // a probe
		}
		if !errors.Is(err, syscall.ECONNREFUSED) {
			return nil, fmt.Errorf("%s is served by another process, or may be: not replaced", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (net.Listener, error) {
		_ = ln.Close() //nolint:errcheck // already failing
		return nil, err
	}
	if err := os.Chmod(path, mode); err != nil {
		return fail(err)
	}
	if group != "" {
		g, err := user.LookupGroup(group)
		if err != nil {
			return fail(err)
		}
		gid, err := strconv.Atoi(g.Gid)
		if err != nil {
			return fail(err)
		}
		if err := os.Lchown(path, -1, gid); err != nil {
			return fail(err)
		}
	}
	return ln, nil
}

// control is the platform's side of a test, over the control socket.
func control(p *contracttest.Platform, app string) http.Handler {
	mux := http.NewServeMux()
	type body = map[string]any
	post := func(path string, f func(in map[string]string) (body, error)) {
		mux.HandleFunc("POST "+path, func(w http.ResponseWriter, r *http.Request) {
			in := map[string]string{}
			if r.ContentLength != 0 {
				if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&in); err != nil {
					reply(w, http.StatusBadRequest, body{"error": "the body must be a JSON object of strings"})
					return
				}
			}
			for k, v := range r.URL.Query() {
				if len(v) > 0 {
					in[k] = v[0]
				}
			}
			out, err := f(in)
			if err != nil {
				reply(w, http.StatusBadRequest, body{"error": err.Error()})
				return
			}
			if out == nil {
				out = body{"ok": true}
			}
			reply(w, http.StatusOK, out)
		})
	}
	get := func(path string, f func(q map[string]string) body) {
		mux.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) {
			q := map[string]string{}
			for k, v := range r.URL.Query() {
				if len(v) > 0 {
					q[k] = v[0]
				}
			}
			reply(w, http.StatusOK, f(q))
		})
	}
	none := func(err error) (body, error) { return nil, err }

	// The rotation's steps (README 7.3): current signs the answers, and
	// requests signed with current or other are accepted.
	post("/secrets", func(in map[string]string) (body, error) {
		return none(p.SetSecrets(app, in["current"], in["other"]))
	})
	post("/generation/new", func(map[string]string) (body, error) { return body{"generation": p.NewGeneration()}, nil })
	post("/generation/confirm", func(map[string]string) (body, error) { p.ConfirmGeneration(); return nil, nil })
	post("/restore", func(map[string]string) (body, error) { return body{"generation": p.Restore()}, nil })
	post("/hold", func(map[string]string) (body, error) { return none(p.HoldPublishing(app)) })
	post("/release", func(map[string]string) (body, error) { return none(p.Release(app)) })
	post("/refuse", func(in map[string]string) (body, error) { return none(p.Refuse(app, in["call"], in["code"])) })
	post("/corrupt", func(in map[string]string) (body, error) {
		how := map[string]contracttest.Corruption{
			"unsigned": contracttest.Unsigned, "another_nonce": contracttest.AnotherNonce,
			"another_body": contracttest.AnotherBody, "another_secret": contracttest.AnotherSecret, "stale": contracttest.Stale,
		}[in["how"]]
		return none(p.Corrupt(app, in["call"], how))
	})

	// The directory.
	post("/accounts", func(in map[string]string) (body, error) {
		personal, err := p.AddAccount(in["sub"])
		if err != nil {
			return nil, err
		}
		return body{"personal": personal}, nil
	})
	post("/accounts/disable", func(in map[string]string) (body, error) { return none(p.Disable(in["sub"], time.Now())) })
	post("/accounts/enable", func(in map[string]string) (body, error) { return none(p.Enable(in["sub"])) })
	post("/accounts/revoke-sessions", func(in map[string]string) (body, error) {
		return none(p.RevokeSessions(in["sub"], time.Now(), in["recovery"] == "true"))
	})
	post("/accounts/close", func(in map[string]string) (body, error) { return none(p.CloseAccount(in["sub"])) })
	post("/teams", func(in map[string]string) (body, error) {
		id, err := p.AddTeam(in["name"], in["owner"])
		if err != nil {
			return nil, err
		}
		return body{"id": id}, nil
	})
	post("/teams/role", func(in map[string]string) (body, error) { return none(p.SetRole(in["team"], in["sub"], in["role"])) })
	post("/teams/remove", func(in map[string]string) (body, error) { return none(p.RemoveMember(in["team"], in["sub"])) })
	post("/teams/rename", func(in map[string]string) (body, error) { return none(p.RenameTeam(in["team"], in["name"])) })
	post("/teams/close", func(in map[string]string) (body, error) { return none(p.CloseTeam(in["team"])) })
	post("/teams/reopen", func(in map[string]string) (body, error) { return none(p.ReopenTeam(in["team"])) })

	// What Wappie sent, and what it follows.
	get("/generation", func(map[string]string) body {
		id, confirmed := p.Generation()
		return body{"generation": id, "confirmed": confirmed}
	})
	get("/following", func(q map[string]string) body { return body{"following": p.Following(app, q["sub"])} })
	get("/named", func(q map[string]string) body { return body{"named": p.Named(app, q["workspace"])} })
	get("/snapshot", func(q map[string]string) body {
		s, ok := p.Snapshot(app, q["workspace"])
		if !ok {
			return body{"snapshot": nil}
		}
		return body{"snapshot": s}
	})
	get("/events", func(map[string]string) body {
		events := p.Events(app)
		if events == nil {
			events = []kc.Event{}
		}
		return body{"events": events}
	})
	return mux
}

func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v) //nolint:errcheck // the client hung up
}
