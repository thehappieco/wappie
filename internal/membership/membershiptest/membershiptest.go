// Package membershiptest is what the contract's tests share: a KMS key in
// memory, fresh secrets, and the kit's fake platform served on a unix
// socket, where Wappie's production transport dials it. Tests only.
package membershiptest

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thehappieco/kit/contract/contracttest"
	"github.com/thehappieco/kit/kms"
)

// Secret is a fresh contract secret: 32 random bytes as 43 base64url
// characters.
func Secret(tb testing.TB) string {
	tb.Helper()
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		tb.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// KMS is a kms.Wrapper whose key lives in memory: each data key wrapped
// with AES-GCM under it, bound to the encryption context as KMS binds one.
type KMS struct {
	mu   sync.Mutex
	aead cipher.AEAD
	// fail makes every call fail as KMS does when it cannot be reached or
	// refuses (an error that is not kms.ErrUnwrap); describe makes Open
	// fail, as awskms.New does when DescribeKey does.
	fail, describe error
	calls          int
}

// NewKMS is a key of its own: envelopes of another KMS never open.
func NewKMS(tb testing.TB) *KMS {
	tb.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		tb.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		tb.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		tb.Fatal(err)
	}
	return &KMS{aead: aead}
}

// Provider is the development provider's byte: these envelopes never pass
// for production ones.
func (k *KMS) Provider() byte { return kms.ProviderLocal }

// SetFail makes every later call fail with err, or succeed again with nil.
func (k *KMS) SetFail(err error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.fail = err
}

// SetDescribeFail makes Open fail with err, or succeed again with nil.
func (k *KMS) SetDescribeFail(err error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.describe = err
}

// Calls counts GenerateDataKey and Decrypt.
func (k *KMS) Calls() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.calls
}

// Open is a membership.OpenWrapper over k: as awskms.New, it fails when
// DescribeKey would (SetDescribeFail).
func (k *KMS) Open(context.Context, string, string) (kms.Wrapper, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.describe != nil {
		return nil, k.describe
	}
	return k, nil
}

func aad(ec kms.Context) []byte {
	return []byte(ec.Service + "\x00" + ec.Env + "\x00" + ec.Purpose + "\x00" + ec.Ref)
}

// GenerateDataKey returns a fresh data key and its wrap under ec.
func (k *KMS) GenerateDataKey(_ context.Context, ec kms.Context) ([]byte, []byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.calls++
	if k.fail != nil {
		return nil, nil, k.fail
	}
	if err := ec.Validate(); err != nil {
		return nil, nil, err
	}
	dk := make([]byte, kms.DataKeyLen)
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(dk); err != nil {
		return nil, nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return dk, k.aead.Seal(nonce, nonce, dk, aad(ec)), nil
}

// Decrypt unwraps a data key wrapped under ec, or kms.ErrUnwrap.
func (k *KMS) Decrypt(_ context.Context, wrapped []byte, ec kms.Context) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.calls++
	if k.fail != nil {
		return nil, k.fail
	}
	n := k.aead.NonceSize()
	if len(wrapped) < n {
		return nil, kms.ErrUnwrap
	}
	dk, err := k.aead.Open(nil, wrapped[:n], wrapped[n:], aad(ec))
	if err != nil {
		return nil, kms.ErrUnwrap
	}
	return dk, nil
}

// ErrUnreachable is a KMS that cannot be reached.
var ErrUnreachable = errors.New("membershiptest: KMS unreachable")

// SocketDir makes a short directory for unix sockets, 0700 and the test's
// own (a socket's path is at most 104 bytes on darwin, which t.TempDir
// passes), removed when the test ends.
func SocketDir(tb testing.TB) string {
	tb.Helper()
	dir, err := os.MkdirTemp("/tmp", "wsct-")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = os.RemoveAll(dir) }) //nolint:errcheck // a leftover test directory is harmless
	return dir
}

// Served is a fake platform on a unix socket.
type Served struct {
	Path string
	srv  *http.Server
	once sync.Once
}

// Serve serves p on a unix socket in dir until Stop or the test's end. A
// Platform stopped may be served again, as platformd's socket comes back
// after a restart.
func Serve(tb testing.TB, p *contracttest.Platform, dir string) *Served {
	tb.Helper()
	path := filepath.Join(dir, "contract.sock")
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "unix", path)
	if err != nil {
		tb.Fatal(err)
	}
	// The platform's socket unit's mode: root:platform-contract 0660.
	if err := os.Chmod(path, 0o660); err != nil { //nolint:gosec // G302: a socket's group is who may connect
		tb.Fatal(err)
	}
	s := &Served{Path: path, srv: &http.Server{Handler: p, ReadHeaderTimeout: 5 * time.Second}}
	go func() { _ = s.srv.Serve(ln) }() //nolint:errcheck // Serve ends with ErrServerClosed at Stop
	tb.Cleanup(s.Stop)
	return s
}

// Stop closes the socket, which removes it, and every connection on it (a
// long-poll waiting there answers at once): as the platform's socket unit
// does whenever it restarts (RemoveOnStop=yes).
func (s *Served) Stop() {
	s.once.Do(func() {
		_ = s.srv.Close() //nolint:errcheck // closing a test server
	})
}

// Platform starts a fake platform for wappie with these secrets, strict
// about labels as Wappie's tests want it.
func Platform(tb testing.TB, current, other string) *contracttest.Platform {
	tb.Helper()
	p, err := contracttest.New(contracttest.Options{
		Apps:         []contracttest.App{{ID: "wappie", Current: current, Other: other}},
		StrictLabels: true,
	})
	if err != nil {
		tb.Fatal(err)
	}
	return p
}

// Fake is a fake platform for wappie on loopback TCP (the development
// transport, README 2) whose calls a test may refuse every time, watch, or
// leave unanswered: contracttest's Refuse spoils only the next answer, and
// Wappie's client asks once more after a signed replay or unavailable.
type Fake struct {
	*contracttest.Platform
	// URL is the base the client is given.
	URL string

	mu     sync.Mutex
	refuse map[string]string
	before map[string]func(arg string)
	counts map[string]int
	down   bool
}

// StartFake serves a fake platform for wappie, with secret as its current
// one, until the test ends. Its rate is far above the platform's, so a
// test's burst of calls is never refused for it.
func StartFake(tb testing.TB, secret string) *Fake {
	tb.Helper()
	p, err := contracttest.New(contracttest.Options{
		Apps:         []contracttest.App{{ID: "wappie", Current: secret}},
		StrictLabels: true, PerSecond: 10000,
	})
	if err != nil {
		tb.Fatal(err)
	}
	f := &Fake{Platform: p, refuse: map[string]string{}, before: map[string]func(string){}, counts: map[string]int{}}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	tb.Cleanup(srv.Close)
	f.URL = srv.URL
	return f
}

// callOf names a request's call as contracttest does, with its argument
// (a sub or a workspace).
func callOf(r *http.Request) (string, string) {
	rest := strings.TrimPrefix(r.URL.Path, "/contract/v1/")
	switch {
	case rest == "feed":
		return contracttest.CallFeed, ""
	case rest == "events":
		return contracttest.CallEvents, ""
	case strings.HasPrefix(rest, "accounts/"):
		sub := strings.TrimPrefix(rest, "accounts/")
		switch r.Method {
		case http.MethodPut:
			return contracttest.CallSubscribe, sub
		case http.MethodGet:
			return contracttest.CallAccount, sub
		case http.MethodDelete:
			return contracttest.CallUnsubscribe, sub
		}
	case strings.HasPrefix(rest, "workspaces/"):
		ws, _, _ := strings.Cut(strings.TrimPrefix(rest, "workspaces/"), "/")
		return contracttest.CallAccess, ws
	}
	return "", ""
}

func (f *Fake) serve(w http.ResponseWriter, r *http.Request) {
	call, arg := callOf(r)
	f.mu.Lock()
	f.counts[call]++
	down, code, before := f.down, f.refuse[call], f.before[call]
	f.mu.Unlock()
	if down {
		// No answer at all: the connection goes, as when platformd stops.
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				_ = conn.Close() //nolint:errcheck // the point is to close it
				return
			}
		}
		panic(http.ErrAbortHandler)
	}
	if before != nil {
		before(arg)
	}
	if code != "" {
		if err := f.Refuse("wappie", call, code); err != nil {
			panic(err)
		}
	}
	f.ServeHTTP(w, r)
}

// RefuseAlways refuses every request to call with code, signed as the
// platform signs it, until it is called again with "".
func (f *Fake) RefuseAlways(call, code string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if code == "" {
		delete(f.refuse, call)
		return
	}
	f.refuse[call] = code
}

// Before runs fn with each request's argument before the fake serves a
// request to call, until it is called again with nil.
func (f *Fake) Before(call string, fn func(arg string)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if fn == nil {
		delete(f.before, call)
		return
	}
	f.before[call] = fn
}

// Count is how many requests to call reached the fake.
func (f *Fake) Count(call string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.counts[call]
}

// SetDown makes every request get no answer, or answers again.
func (f *Fake) SetDown(down bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.down = down
}

// Logs is a log a test reads back: a text handler's lines, safe for the
// goroutines that write them.
type Logs struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

// Write takes one record's line.
func (l *Logs) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

// Logger writes every level to l.
func (l *Logs) Logger() *slog.Logger {
	return slog.New(slog.NewTextHandler(l, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// String is everything logged so far.
func (l *Logs) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// Lines are the lines logged so far that hold every one of parts.
func (l *Logs) Lines(parts ...string) []string {
	var out []string
	for _, line := range strings.Split(l.String(), "\n") {
		all := line != ""
		for _, p := range parts {
			all = all && strings.Contains(line, p)
		}
		if all {
			out = append(out, line)
		}
	}
	return out
}
