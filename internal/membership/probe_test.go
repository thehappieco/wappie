package membership

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/membership/membershiptest"
)

// probeFeed is a valid, empty feed page.
const probeFeed = `{"generation":"0199b1e0-0000-7000-8000-0000000000ff","generation_confirmed":true,"head":0,` +
	`"published_through":"2026-10-14T12:00:00Z","items":[],"next_after":0,"more":false}`

// TestProbeExitCodes: every answer contract check sorts, by the exit status
// the installer acts on and the line the owner reads (4.3, and the P1
// build notes).
func TestProbeExitCodes(t *testing.T) {
	current, other, third := membershiptest.Secret(t), membershiptest.Secret(t), membershiptest.Secret(t)
	unsigned := func(status int, body string) roundTrip {
		return func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
		}
	}
	signed := func(secret string, status int, body string) roundTrip {
		return func(r *http.Request) (*http.Response, error) {
			return signedAnswer(r, secret, status, []byte(body), time.Now()), nil
		}
	}
	for _, tc := range []struct {
		name  string
		mode  ProbeMode
		other bool // an other secret is loaded
		rt    roundTrip
		code  int
		line  string // the line's start
	}{
		{"a signed feed page", ProbeBoth, false, signed(current, 200, probeFeed), ProbeVerified,
			"signed answer: generation 0199b1e0-0000-7000-8000-0000000000ff confirmed true head 0"},
		{"a signed refusal proves the secret", ProbeBoth, false, signed(current, 503, `{"code":"unavailable","message":"busy"}`), ProbeVerified,
			"signed refusal: unavailable"},
		{"an unsigned stale_timestamp is the clocks", ProbeBoth, false, unsigned(401, `{"code":"stale_timestamp","message":"x"}`), ProbeFailed,
			"unsigned 401 stale_timestamp: this host's clock"},
		{"an unsigned 401 is not the platform's secret", ProbeBoth, false, unsigned(401, `{"code":"unauthenticated","message":"x"}`), ProbeRejected,
			"unsigned 401: not the platform's secret"},
		{"an unsigned 401 without a body", ProbeBoth, false, unsigned(401, ``), ProbeRejected, "unsigned 401: not the platform's secret"},
		{"an unsigned 429", ProbeBoth, false, unsigned(429, `{"code":"rate_limited","message":"x"}`), ProbeNoAnswer, "unsigned 429: the platform is busy"},
		{"an unsigned 503", ProbeBoth, false, unsigned(503, ``), ProbeNoAnswer, "unsigned 503: the platform is busy"},
		{"an unsigned 404", ProbeBoth, false, unsigned(404, `{"code":"not_found","message":"x"}`), ProbeFailed,
			"unsigned 404: the platform does not serve this caller: wappie is not mapped (PLATFORM_CONTRACT_APPS), or this process is not the wappie user"},
		{"an unsigned 500", ProbeBoth, false, unsigned(500, ``), ProbeFailed, "unsigned 500"},
		{"a signed answer that is not a feed", ProbeBoth, false, signed(current, 200, `{"subscribed":false}`), ProbeFailed,
			"a signed answer that is not a valid feed page"},
		{"a signed answer that is not JSON", ProbeBoth, false, signed(current, 200, `feed`), ProbeFailed, "a signed answer that is not a feed page"},
		{"an answer signed with a third secret", ProbeBoth, true, signed(third, 200, probeFeed), ProbeFailed,
			"an answer (200) whose signature does not hold"},
		{"only current, signed with the other", ProbeOnlyCurrent, true, signed(other, 200, probeFeed), ProbeExcluded,
			"signed answer, but signed with the other secret"},
		{"only current, signed with the current", ProbeOnlyCurrent, true, signed(current, 200, probeFeed), ProbeVerified, "signed answer: generation"},
		{"only current, steady, signed with a third", ProbeOnlyCurrent, false, signed(third, 200, probeFeed), ProbeFailed, "an answer (200)"},
		{"only other, signed with the current", ProbeOnlyOther, true, signed(current, 200, probeFeed), ProbeExcluded,
			"signed answer, but signed with the current secret"},
		{"only other, signed with the other", ProbeOnlyOther, true, signed(other, 200, probeFeed), ProbeVerified, "signed answer: generation"},
		{"other, answered with the current", ProbeOther, true, signed(current, 200, probeFeed), ProbeVerified, "signed answer: generation"},
		{"other without an other secret", ProbeOther, false, signed(current, 200, probeFeed), ProbeFailed, "no other secret is installed"},
		{"only other without an other secret", ProbeOnlyOther, false, signed(current, 200, probeFeed), ProbeFailed, "no other secret is installed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wantSigner := current
			if tc.mode == ProbeOther || tc.mode == ProbeOnlyOther {
				wantSigner = other
			}
			c := clientOn(func(r *http.Request) (*http.Response, error) {
				got, err := kc.Scheme().Read(r.Header, time.Now())
				if err != nil || !kc.Scheme().SignedBy([]string{wantSigner}, got, kc.ToPlatform, App, r.Method, r.URL.RequestURI(), nil) ||
					r.URL.RequestURI() != probeTarget {
					t.Errorf("the probe was not signed as its mode says, or not the feed: %s %v", r.URL.RequestURI(), err)
				}
				return tc.rt(r)
			}, nil)
			o := ""
			if tc.other {
				o = other
			}
			if err := c.Use(current, o); err != nil {
				t.Fatal(err)
			}
			res := c.Probe(context.Background(), tc.mode)
			if res.Code != tc.code || !strings.HasPrefix(res.Line, tc.line) {
				t.Fatalf("%d %q, want %d %q", res.Code, res.Line, tc.code, tc.line)
			}
			for _, s := range []string{current, other, third} {
				if strings.Contains(res.Line, s) {
					t.Fatal("the line holds a secret")
				}
			}
		})
	}

	t.Run("no secret loaded", func(t *testing.T) {
		if res := clientOn(nil, nil).Probe(context.Background(), ProbeBoth); res.Code != ProbeFailed || res.Line != "no contract secret is loaded" {
			t.Fatalf("%+v", res)
		}
	})

	t.Run("a transport that blocks past the timeout", func(t *testing.T) {
		c := clientOn(func(r *http.Request) (*http.Response, error) {
			<-r.Context().Done()
			return nil, r.Context().Err()
		}, nil)
		if err := c.Use(current, ""); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		if res := c.Probe(ctx, ProbeBoth); res.Code != ProbeNoAnswer || res.Line != "no answer from the platform: timeout" {
			t.Fatalf("%+v", res)
		}
	})

	// On the socket, as contract check dials it: each cause named, never
	// the path.
	me := os.Getuid()
	dir := membershiptest.SocketDir(t)
	path := filepath.Join(dir, "contract.sock")
	serveOK(t, path)
	probe := func(t *testing.T, d *SocketDialer) ProbeResult {
		t.Helper()
		c := NewClient(HTTP(d.DialContext), Base, nil)
		if err := c.Use(current, ""); err != nil {
			t.Fatal(err)
		}
		res := c.Probe(context.Background(), ProbeBoth)
		if strings.Contains(res.Line, dir) {
			t.Fatalf("the line names the path: %q", res.Line)
		}
		return res
	}
	t.Run("a peer that fails its checks", func(t *testing.T) {
		res := probe(t, &SocketDialer{Path: path, Owner: me + 1})
		if res.Code != ProbeFailed || !strings.HasPrefix(res.Line, ErrPeer.Error()+": its directory is not owned by uid") {
			t.Fatalf("%+v", res)
		}
	})
	t.Run("no socket", func(t *testing.T) {
		res := probe(t, &SocketDialer{Path: filepath.Join(dir, "absent.sock"), Owner: me})
		if res.Code != ProbeNoAnswer || res.Line != "no answer from the platform: no socket at the configured path (the platform is down or restarting)" {
			t.Fatalf("%+v", res)
		}
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
		res := probe(t, &SocketDialer{Path: stale, Owner: me})
		if res.Code != ProbeNoAnswer || res.Line != "no answer from the platform: the connection was refused (the platform is down or restarting)" {
			t.Fatalf("%+v", res)
		}
	})
	t.Run("a socket this process may not connect to", func(t *testing.T) {
		if me == 0 {
			t.Skip("root connects to any socket")
		}
		denied := filepath.Join(dir, "denied.sock")
		serveOK(t, denied)
		if err := os.Chmod(denied, 0); err != nil {
			t.Fatal(err)
		}
		res := probe(t, &SocketDialer{Path: denied, Owner: me})
		if res.Code != ProbeNoAnswer || res.Line != "no answer from the platform: permission denied on the socket "+
			"(run as wappie with SupplementaryGroups=platform-contract)" {
			t.Fatalf("%+v", res)
		}
	})
}
