package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"whatserver2/internal/membership"
	"whatserver2/internal/membership/membershiptest"
)

// TestFakeContractOnASocket serves the fake where Wappie's production
// transport dials it, and plays the platform's side through the control
// socket.
func TestFakeContractOnASocket(t *testing.T) {
	dir := membershiptest.SocketDir(t)
	secret, next := membershiptest.Secret(t), membershiptest.Secret(t)
	secretFile := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secretFile, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sock, ctl := filepath.Join(dir, "contract.sock"), filepath.Join(dir, "control.sock")
	// A socket a dead process left is replaced.
	stale, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var logs bytes.Buffer
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{"-socket", sock, "-control", ctl, "-secret-file", secretFile}, &logs,
			func(string, string) { close(ready) })
	}()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("run: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("not listening")
	}
	for path, mode := range map[string]os.FileMode{sock: 0o660, ctl: 0o600} {
		fi, err := os.Lstat(path)
		if err != nil || fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != mode {
			t.Fatalf("%s: %v %v", path, fi.Mode(), err)
		}
	}

	d := &membership.SocketDialer{Path: sock, Owner: os.Getuid()}
	client := membership.NewClient(membership.HTTP(d.DialContext), membership.Base, nil)
	if err := client.Use(secret, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Feed(ctx, 0, 0); err != nil {
		t.Fatalf("feed: %v", err)
	}

	control := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "unix", ctl)
	}}}
	call := func(method, path string, in map[string]string) map[string]any {
		t.Helper()
		body, _ := json.Marshal(in)
		req, err := http.NewRequestWithContext(ctx, method, "http://control"+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if in == nil {
			req.Body, req.ContentLength = http.NoBody, 0
		}
		res, err := control.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		var out map[string]any
		if err := json.Unmarshal(raw, &out); err != nil || res.StatusCode != http.StatusOK {
			t.Fatalf("%s %s: %d %s", method, path, res.StatusCode, raw)
		}
		return out
	}
	sub := "0199a0c2-7d3e-7b51-9f0a-2c4e6b8d1f20"
	personal, _ := call("POST", "/accounts", map[string]string{"sub": sub})["personal"].(string)
	team, _ := call("POST", "/teams", map[string]string{"name": "TBFG", "owner": sub})["id"].(string)
	doc, err := client.Subscribe(ctx, sub)
	if err != nil || len(doc.Workspaces) != 2 || doc.Workspaces[0].ID != personal || doc.Workspaces[1].ID != team {
		t.Fatalf("subscribe: %+v %v", doc, err)
	}
	if call("GET", "/following?sub="+sub, nil)["following"] != true || call("GET", "/named?workspace="+team, nil)["named"] != true {
		t.Fatal("following, named")
	}
	// A rotation's step 1 and a refused secret, as the platform plays them.
	call("POST", "/secrets", map[string]string{"current": secret, "other": next})
	if _, err := client.Feed(ctx, 0, 0); err != nil {
		t.Fatalf("after secret-next: %v", err)
	}
	gen, _ := call("POST", "/restore", nil)["generation"].(string)
	f, err := client.Feed(ctx, 0, 0)
	if err != nil || f.Generation != gen || f.GenerationConfirmed {
		t.Fatalf("after a restore: %+v %v", f, err)
	}
	// A signed unavailable is asked again once, signed afresh; a not_found
	// is the answer.
	call("POST", "/refuse", map[string]string{"call": "feed", "code": "unavailable"})
	if _, err := client.Feed(ctx, 0, 0); err != nil {
		t.Fatalf("unavailable once, retried: %v", err)
	}
	call("POST", "/refuse", map[string]string{"call": "account", "code": "not_found"})
	if _, err := client.Account(ctx, sub); membership.RefusalCode(err) != "not_found" {
		t.Fatalf("not_found: %v", err)
	}
	if out := call("GET", "/events", nil); out["events"] == nil {
		t.Fatal("events")
	}
	if strings.Contains(logs.String(), secret) || strings.Contains(logs.String(), next) {
		t.Fatal("the log holds a secret")
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(sock); !os.IsNotExist(err) {
		t.Fatalf("the socket outlived the fake: %v", err)
	}
}

func TestFakeContractFlags(t *testing.T) {
	file := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"-secret-file", file},
		{"-socket", "/tmp/x.sock", "-addr", "127.0.0.1:8291", "-secret-file", file},
		{"-addr", "10.0.0.1:8291", "-secret-file", file},
		{"-socket", "/tmp/x.sock"},
		{"-socket", "/tmp/x.sock", "-secret-file", file, "-mode", "999"},
		{"-socket", "/tmp/x.sock", "-secret-file", file, "extra"},
	} {
		if _, err := parse(args, io.Discard); err == nil {
			t.Errorf("%v: accepted", args)
		}
	}
	// A file that is not a socket is never removed.
	if _, err := listenUnix(context.Background(), file, 0o660, ""); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("%v", err)
	}
	// An invalid secret is refused by the fake itself.
	err := run(context.Background(), []string{"-addr", "127.0.0.1:0", "-secret-file", file}, io.Discard, nil)
	if err == nil {
		t.Fatal("an empty secret")
	}
}

// TestListenUnixNeverTakesALiveSocket: a socket a process still serves is
// never replaced (in the host simulation, platformd's or a second fake's);
// one left by a process that died is.
func TestListenUnixNeverTakesALiveSocket(t *testing.T) {
	dir := membershiptest.SocketDir(t)
	live := filepath.Join(dir, "live.sock")
	ln, err := net.Listen("unix", live)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if _, err := listenUnix(context.Background(), live, 0o660, ""); err == nil || !strings.Contains(err.Error(), "served by another process") {
		t.Fatalf("a live socket: %v", err)
	}
	// The first listener still has the path.
	accepted := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.Close()
		}
		accepted <- err
	}()
	conn, err := net.Dial("unix", live)
	if err != nil {
		t.Fatalf("the live socket was taken: %v", err)
	}
	_ = conn.Close()
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}

	stale := filepath.Join(dir, "stale.sock")
	old, err := net.Listen("unix", stale)
	if err != nil {
		t.Fatal(err)
	}
	old.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	fresh, err := listenUnix(context.Background(), stale, 0o660, "")
	if err != nil {
		t.Fatalf("a dead process's socket: %v", err)
	}
	_ = fresh.Close()
}
