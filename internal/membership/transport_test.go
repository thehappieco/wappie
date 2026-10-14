package membership

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"whatserver2/internal/membership/membershiptest"
)

// serveOK answers every request on a unix socket at path with 200 "ok".
func serveOK(t *testing.T, path string) {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok "+r.Host)
	}), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
}

func get(t *testing.T, d *SocketDialer, url string) (string, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := HTTP(d.DialContext).Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	return string(b), err
}

// TestSocketPeerChecks is TB6 of release B's plan: README 2's peer check on
// Wappie's own dialer, which the kit's fake (TCP, no peer uid) cannot make.
func TestSocketPeerChecks(t *testing.T) {
	me := os.Getuid()
	dir := membershiptest.SocketDir(t)
	path := filepath.Join(dir, "contract.sock")
	serveOK(t, path)

	t.Run("the platform's socket, whatever the URL's host", func(t *testing.T) {
		d := &SocketDialer{Path: path, Owner: me}
		got, err := get(t, d, "http://elsewhere.example:9/contract/v1/feed")
		if err != nil || got != "ok elsewhere.example:9" {
			t.Fatalf("%q %v", got, err)
		}
	})

	peer := func(t *testing.T, d *SocketDialer, why string) {
		t.Helper()
		_, err := d.DialContext(context.Background(), "tcp", "contract:80")
		if !errors.Is(err, ErrPeer) || errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), why) {
			t.Fatalf("want ErrPeer (%s), got %v", why, err)
		}
	}
	unavailable := func(t *testing.T, d *SocketDialer) {
		t.Helper()
		_, err := d.DialContext(context.Background(), "tcp", "contract:80")
		if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrPeer) {
			t.Fatalf("want ErrUnavailable, got %v", err)
		}
	}

	t.Run("another owner", func(t *testing.T) {
		peer(t, &SocketDialer{Path: path, Owner: me + 1}, "not owned by uid")
	})
	t.Run("a socket another uid owns", func(t *testing.T) {
		if me != 0 {
			t.Skip("chown needs root: CI runs this case under sudo (ci.yml, \"Socket peer check as root\")")
		}
		other := filepath.Join(dir, "other.sock")
		serveOK(t, other)
		if err := os.Lchown(other, 4242, -1); err != nil {
			t.Fatal(err)
		}
		peer(t, &SocketDialer{Path: other, Owner: 0}, "it is not owned by uid 0")
	})
	t.Run("a symlinked directory", func(t *testing.T) {
		link := filepath.Join(membershiptest.SocketDir(t), "run")
		if err := os.Symlink(dir, link); err != nil {
			t.Fatal(err)
		}
		peer(t, &SocketDialer{Path: filepath.Join(link, "contract.sock"), Owner: me}, "symbolic link")
	})
	t.Run("a group-writable directory", func(t *testing.T) {
		loose := membershiptest.SocketDir(t)
		serveOK(t, filepath.Join(loose, "contract.sock"))
		if err := os.Chmod(loose, 0o770); err != nil {
			t.Fatal(err)
		}
		peer(t, &SocketDialer{Path: filepath.Join(loose, "contract.sock"), Owner: me}, "group or others")
		if err := os.Chmod(loose, 0o707); err != nil {
			t.Fatal(err)
		}
		peer(t, &SocketDialer{Path: filepath.Join(loose, "contract.sock"), Owner: me}, "group or others")
	})
	t.Run("a regular file", func(t *testing.T) {
		file := filepath.Join(dir, "regular")
		if err := os.WriteFile(file, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		peer(t, &SocketDialer{Path: file, Owner: me}, "not a socket")
	})
	t.Run("the directory is a file", func(t *testing.T) {
		peer(t, &SocketDialer{Path: filepath.Join(dir, "regular", "contract.sock"), Owner: me}, "not a directory")
	})
	t.Run("a missing socket", func(t *testing.T) {
		unavailable(t, &SocketDialer{Path: filepath.Join(dir, "absent.sock"), Owner: me})
		unavailable(t, &SocketDialer{Path: filepath.Join(dir, "absent", "contract.sock"), Owner: me})
	})
	t.Run("a socket nobody listens on", func(t *testing.T) {
		stale := filepath.Join(dir, "stale.sock")
		ln, err := net.Listen("unix", stale)
		if err != nil {
			t.Fatal(err)
		}
		ln.(*net.UnixListener).SetUnlinkOnClose(false)
		if err := ln.Close(); err != nil {
			t.Fatal(err)
		}
		unavailable(t, &SocketDialer{Path: stale, Owner: me})
	})
	t.Run("a socket this process may not connect to is no answer, not a peer failure", func(t *testing.T) {
		if me == 0 {
			t.Skip("root connects to any socket")
		}
		denied := filepath.Join(dir, "denied.sock")
		serveOK(t, denied)
		if err := os.Chmod(denied, 0); err != nil {
			t.Fatal(err)
		}
		_, err := (&SocketDialer{Path: denied, Owner: me}).DialContext(context.Background(), "tcp", "contract:80")
		if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrPeer) || !errors.Is(err, fs.ErrPermission) {
			t.Fatalf("want ErrUnavailable (permission denied), got %v", err)
		}
	})
	t.Run("a peer that failed is refused for a minute, and said once", func(t *testing.T) {
		loose := membershiptest.SocketDir(t)
		sock := filepath.Join(loose, "contract.sock")
		serveOK(t, sock)
		if err := os.Chmod(loose, 0o770); err != nil {
			t.Fatal(err)
		}
		var logs bytes.Buffer
		now := time.Now()
		d := &SocketDialer{Path: sock, Owner: me, Log: slog.New(slog.NewTextHandler(&logs, nil)), Now: func() time.Time { return now }}
		peer(t, d, "group or others")
		if err := os.Chmod(loose, 0o700); err != nil {
			t.Fatal(err)
		}
		now = now.Add(59 * time.Second)
		peer(t, d, "group or others")
		if n := strings.Count(logs.String(), "level=ERROR"); n != 1 {
			t.Fatalf("%d ERROR lines: %s", n, logs.String())
		}
		now = now.Add(2 * time.Second)
		if got, err := get(t, d, "http://contract/"); err != nil || !strings.HasPrefix(got, "ok") {
			t.Fatalf("after the minute: %q %v", got, err)
		}
	})
	t.Run("through the client, a peer failure is no answer", func(t *testing.T) {
		d := &SocketDialer{Path: path, Owner: me + 1}
		c := NewClient(HTTP(d.DialContext), Base, nil)
		if err := c.Use(membershiptest.Secret(t), ""); err != nil {
			t.Fatal(err)
		}
		_, err := c.Feed(context.Background(), 0, 0)
		if Classify(err) != Unavailable || !errors.Is(err, ErrPeer) || strings.Contains(err.Error(), "feed?after") {
			t.Fatalf("%v (%s)", err, Classify(err))
		}
	})
}

func TestTransportShape(t *testing.T) {
	c := HTTP((&net.Dialer{}).DialContext)
	tr, ok := c.Transport.(*http.Transport)
	if !ok || tr.Proxy != nil || tr.MaxIdleConnsPerHost != 4 || tr.IdleConnTimeout != time.Minute || c.Timeout != 0 {
		t.Fatalf("%+v", c)
	}
	if err := c.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("redirects: %v", err)
	}
	// The development transport dials its loopback address whatever the
	// URL's host, and a closed port is no answer.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := (TCPDialer{Addr: addr}).DialContext(context.Background(), "tcp", "contract:80"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("closed port: %v", err)
	}
}

// TestTCPTransport: the development transport reaches the kit's fake on
// loopback TCP, whatever host the URL names: a feed page and a probe, each
// answered and verified.
func TestTCPTransport(t *testing.T) {
	current := membershiptest.Secret(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: membershiptest.Platform(t, current, ""), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	c := NewClient(HTTP(TCPDialer{Addr: ln.Addr().String()}.DialContext), Base, nil)
	if err := c.Use(current, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Feed(context.Background(), 0, 0); err != nil {
		t.Fatalf("the feed over TCP: %v", err)
	}
	if res := c.Probe(context.Background(), ProbeBoth); res.Code != ProbeVerified || !strings.HasPrefix(res.Line, "signed answer: generation ") {
		t.Fatalf("%+v", res)
	}
}
