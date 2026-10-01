package cimdegress

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// The document egress proxy (docs/mcp-enclave.md §19.9, §19.26): the shared
// host vectors; the single resolution, with a public, a private, a mixed and
// an own answer and a rebinding attempt; the addresses dialed in order; the
// budgets per registrable domain, overall and in flight; the 6-second and
// 16 KiB limits; proxy variables ignored; and the journal line.

var (
	publicV4 = netip.MustParseAddr("93.184.216.34")
	publicV6 = netip.MustParseAddr("2606:2800:220:1::1")
	ownAddr  = netip.MustParseAddr("54.1.2.3")
)

// fakeResolver answers each host from a table and counts the questions;
// next, when set, is what a second question about a host would get.
type fakeResolver struct {
	mu      sync.Mutex
	answers map[string][]netip.Addr
	next    map[string][]netip.Addr
	calls   map[string]int
}

func (r *fakeResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if network != "ip" {
		return nil, fmt.Errorf("network %s", network)
	}
	r.calls[host]++
	if r.calls[host] > 1 && r.next[host] != nil {
		return append([]netip.Addr(nil), r.next[host]...), nil
	}
	answer, ok := r.answers[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	return append([]netip.Addr(nil), answer...), nil
}

func (r *fakeResolver) asked(host string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[host]
}

// dialer records every address dialed; an address in refuse fails, and any
// other is answered by serve on the far end of a pipe.
type dialer struct {
	mu     sync.Mutex
	dialed []string
	refuse map[string]bool
	serve  func(net.Conn)
}

func (d *dialer) dial(_ context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.dialed = append(d.dialed, address)
	refused, serve := d.refuse[address], d.serve
	d.mu.Unlock()
	if network != "tcp" || refused {
		return nil, errors.New("connection refused")
	}
	near, far := net.Pipe()
	if serve == nil {
		serve = echo
	}
	go serve(far)
	return near, nil
}

func (d *dialer) addresses() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.dialed...)
}

// echo answers whatever it reads, until the tunnel closes.
func echo(c net.Conn) {
	defer c.Close()
	//nolint:errcheck // the tunnel's end
	_, _ = io.Copy(c, c)
}

// journal is the proxy's log, safe for the goroutines that write it.
type journal struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (j *journal) Write(p []byte) (int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.buf.Write(p)
}

func (j *journal) lines(t *testing.T) []map[string]any {
	t.Helper()
	j.mu.Lock()
	defer j.mu.Unlock()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(j.buf.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("journal line %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

type harness struct {
	proxy    *Proxy
	resolver *fakeResolver
	dialer   *dialer
	journal  *journal
}

func newHarness() *harness {
	h := &harness{
		resolver: &fakeResolver{answers: map[string][]netip.Addr{}, next: map[string][]netip.Addr{}, calls: map[string]int{}},
		dialer:   &dialer{refuse: map[string]bool{}},
		journal:  &journal{},
	}
	h.proxy = New([]netip.Addr{ownAddr}, slog.New(slog.NewJSONHandler(h.journal, nil)))
	h.proxy.Resolver, h.proxy.Dial = h.resolver, h.dialer.dial
	return h
}

// answer has every host resolve to the public addresses unless told
// otherwise.
func (h *harness) answer(host string, addrs ...netip.Addr) {
	h.resolver.mu.Lock()
	defer h.resolver.mu.Unlock()
	h.resolver.answers[host] = addrs
}

// connect sends one request through a fresh connection and reads the
// answer's status and egress code; a 200 leaves the tunnel open until the
// test closes it, or ends.
func (h *harness) connect(t *testing.T, request string) (int, string, net.Conn, *bufio.Reader) {
	t.Helper()
	near, far := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.proxy.Serve(far)
	}()
	closed := &closer{Conn: near, done: done}
	t.Cleanup(func() { closed.Close() })
	if err := near.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	go func() {
		//nolint:errcheck // a refusal may close before the whole request is read
		_, _ = io.WriteString(near, request)
	}()
	reader := bufio.NewReader(near)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("%q: %v", request, err)
	}
	return resp.StatusCode, resp.Header.Get("X-Wappie-Egress"), closed, reader
}

// closer closes the near end of a test's connection and waits for the
// proxy to be done with it, journal line included.
type closer struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func (c *closer) Close() error {
	c.once.Do(func() {
		//nolint:errcheck // the test's end of a pipe
		_ = c.Conn.Close()
		<-c.done
	})
	return nil
}

func connectTo(target string) string {
	return "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"
}

// tunnel connects to host:443 and expects a tunnel, or the refusal code.
func (h *harness) tunnel(t *testing.T, host, wantCode string) {
	t.Helper()
	status, code, conn, _ := h.connect(t, connectTo(host+":443"))
	conn.Close()
	switch {
	case wantCode == "" && status != http.StatusOK:
		t.Fatalf("%s: %d %s, want a tunnel", host, status, code)
	case wantCode != "" && (status != http.StatusForbidden || code != wantCode):
		t.Fatalf("%s: %d %q, want 403 %s", host, status, code, wantCode)
	}
}

// ---------------------------------------------------------------------------

type vector struct {
	ID     string `json:"id"`
	OK     bool   `json:"ok"`
	Host   string `json:"host"`
	Reason string `json:"reason"`
}

// hostReasons are the refusals of §19.5 step 4, the ones the proxy applies.
var hostReasons = []string{"host_chars", "host_labels", "ip_literal", "special_use", "own_domain", "public_suffix", "shared_host"}

// The shared vectors: a host every accepted id names gets a tunnel; a host
// refused by the host predicate gets host_refused, before any budget or
// resolution.
func TestSharedVectors(t *testing.T) {
	paths := []string{filepath.Join("..", "netguard", "testdata", "cimd-ids.json")}
	if shared := filepath.Join("..", "..", "packages", "mcp-http", "test", "vectors", "cimd-ids.json"); fileExists(shared) {
		paths = append(paths, shared)
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var vectors []vector
		if err := json.Unmarshal(raw, &vectors); err != nil {
			t.Fatal(err)
		}
		accepted, refused := 0, 0
		for _, v := range vectors {
			switch {
			case v.OK:
				h := newHarness()
				h.answer(v.Host, publicV4)
				h.tunnel(t, v.Host, "")
				accepted++
			case slices.Contains(hostReasons, v.Reason):
				rest, _ := strings.CutPrefix(v.ID, "https://")
				host, _, _ := strings.Cut(rest, "/")
				if strings.ContainsAny(host, " \r\n") || host == "" {
					continue
				}
				h := newHarness()
				h.answer(host, publicV4)
				h.tunnel(t, host, CodeHostRefused)
				if h.resolver.asked(host) != 0 {
					t.Fatalf("%s: a refused host was resolved", host)
				}
				refused++
			}
		}
		if accepted < 10 || refused < 20 {
			t.Fatalf("%s: %d accepted, %d refused", path, accepted, refused)
		}
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// One resolution: any address that is not public, or that is the
// deployment's own, refuses the host whatever its other records; a second
// answer is never asked for, so a rebinding name meets the first.
func TestResolution(t *testing.T) {
	h := newHarness()
	h.answer("public.example.com", publicV4, publicV6)
	h.tunnel(t, "public.example.com", "")
	if got := h.dialer.addresses(); len(got) != 1 || got[0] != "93.184.216.34:443" {
		t.Fatalf("dialed %v", got)
	}
	for host, addrs := range map[string][]netip.Addr{
		"private.example.com":    {netip.MustParseAddr("10.0.0.1")},
		"metadata.example.com":   {netip.MustParseAddr("169.254.169.254")},
		"mixed.example.com":      {publicV4, netip.MustParseAddr("192.168.1.1")},
		"mapped.example.com":     {netip.MustParseAddr("::ffff:127.0.0.1")},
		"nat64.example.com":      {netip.MustParseAddr("64:ff9b::a9fe:a9fe")},
		"ec2v6.example.com":      {publicV6, netip.MustParseAddr("fd00:ec2::254")},
		"own.example.com":        {ownAddr},
		"own-mapped.example.com": {netip.MustParseAddr("::ffff:54.1.2.3")},
	} {
		h := newHarness()
		h.answer(host, addrs...)
		h.tunnel(t, host, CodePrivateAddress)
		if got := h.dialer.addresses(); len(got) != 0 {
			t.Fatalf("%s: dialed %v", host, got)
		}
	}

	// Rebinding: the second answer would be private; the proxy never asks
	// for it.
	h = newHarness()
	h.answer("rebind.example.com", publicV4)
	h.resolver.mu.Lock()
	h.resolver.next["rebind.example.com"] = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	h.resolver.mu.Unlock()
	h.tunnel(t, "rebind.example.com", "")
	if n := h.resolver.asked("rebind.example.com"); n != 1 {
		t.Fatalf("resolved %d times", n)
	}
	if got := h.dialer.addresses(); len(got) != 1 || got[0] != "93.184.216.34:443" {
		t.Fatalf("dialed %v", got)
	}

	// A name that does not resolve is remembered for a minute.
	h = newHarness()
	h.tunnel(t, "nowhere.example.com", CodeDNSFailed)
	h.answer("nowhere.example.com", publicV4)
	h.tunnel(t, "nowhere.example.com", CodeNegativeCached)
	if n := h.resolver.asked("nowhere.example.com"); n != 1 {
		t.Fatalf("resolved %d times", n)
	}
}

// Each address in order, port 443 only, until one answers; none answering
// is connect_failed, remembered for a minute.
func TestDialOrder(t *testing.T) {
	h := newHarness()
	h.answer("dual.example.com", publicV6, publicV4)
	h.dialer.refuse["[2606:2800:220:1::1]:443"] = true
	h.tunnel(t, "dual.example.com", "")
	if got := h.dialer.addresses(); !slices.Equal(got, []string{"[2606:2800:220:1::1]:443", "93.184.216.34:443"}) {
		t.Fatalf("dialed %v", got)
	}
	h = newHarness()
	h.answer("down.example.com", publicV4, publicV6)
	h.dialer.refuse["93.184.216.34:443"], h.dialer.refuse["[2606:2800:220:1::1]:443"] = true, true
	h.tunnel(t, "down.example.com", CodeConnectFailed)
	h.tunnel(t, "down.example.com", CodeNegativeCached)
	if got := h.dialer.addresses(); len(got) != 2 {
		t.Fatalf("dialed %v", got)
	}
}

// Only CONNECT, only to port 443; the request line's target is what counts.
func TestRequestShape(t *testing.T) {
	h := newHarness()
	h.answer("docs.example.com", publicV4)
	for request, want := range map[string]int{
		"GET https://docs.example.com/c.json HTTP/1.1\r\nHost: docs.example.com\r\n\r\n": http.StatusMethodNotAllowed,
		connectTo("docs.example.com:80"):                                                 http.StatusMethodNotAllowed,
		connectTo("docs.example.com"):                                                    http.StatusMethodNotAllowed,
		"not http\r\n\r\n":                                                               http.StatusBadRequest,
	} {
		if status, _, _, _ := h.connect(t, request); status != want {
			t.Errorf("%q: %d, want %d", request, status, want)
		}
	}
	for _, host := range []string{"[::1]", "127.0.0.1", "Docs.example.com", "api.wappie.thehappie.co", "bucket.s3.amazonaws.com", "github.io",
		"localhost", "metadata.google.internal"} {
		h.tunnel(t, host, CodeHostRefused)
	}
	if got := h.dialer.addresses(); len(got) != 0 {
		t.Fatalf("dialed %v", got)
	}
	// Without a Host header, or with another, the target alone counts.
	for _, request := range []string{"CONNECT docs.example.com:443 HTTP/1.1\r\n\r\n",
		"CONNECT docs.example.com:443 HTTP/1.1\r\nHost: other.example.com:443\r\n\r\n"} {
		status, _, conn, _ := h.connect(t, request)
		conn.Close()
		if status != http.StatusOK {
			t.Fatalf("%q: %d", request, status)
		}
	}
	if got := h.dialer.addresses(); !slices.Equal(got, []string{"93.184.216.34:443", "93.184.216.34:443"}) {
		t.Fatalf("dialed %v", got)
	}
}

// Ten tunnels a minute per registrable domain, sixty overall with a burst of
// twenty, and four at once.
func TestBudgets(t *testing.T) {
	h := newHarness()
	for i := range 10 {
		host := fmt.Sprintf("tenant%d.example.com", i)
		h.answer(host, publicV4)
		h.tunnel(t, host, "")
	}
	h.answer("eleventh.example.com", publicV4)
	h.tunnel(t, "eleventh.example.com", CodeRateLimited)
	if h.resolver.asked("eleventh.example.com") != 0 {
		t.Fatal("a tunnel over the budget was resolved")
	}
	h.answer("docs.example.org", publicV4)
	h.tunnel(t, "docs.example.org", "")

	h = newHarness()
	for i := range 20 {
		host := fmt.Sprintf("docs.domain%d.com", i)
		h.answer(host, publicV4)
		h.tunnel(t, host, "")
	}
	h.answer("docs.domain20.com", publicV4)
	h.tunnel(t, "docs.domain20.com", CodeRateLimited)

	// Four tunnels held open; the fifth is busy, and a place frees when
	// one ends.
	h = newHarness()
	release := make(chan struct{})
	h.dialer.serve = func(c net.Conn) {
		<-release
		c.Close()
	}
	var open []net.Conn
	for i := range 4 {
		host := fmt.Sprintf("held%d.example.net", i)
		h.answer(host, publicV4)
		status, _, conn, _ := h.connect(t, connectTo(host+":443"))
		if status != http.StatusOK {
			t.Fatalf("tunnel %d: %d", i, status)
		}
		open = append(open, conn)
	}
	h.answer("fifth.example.net", publicV4)
	h.tunnel(t, "fifth.example.net", CodeBusy)
	close(release)
	for _, c := range open {
		c.Close()
	}
	h.dialer.serve = nil
	h.tunnel(t, "fifth.example.net", "")
}

// At most 16 KiB each way and 6 seconds, then the tunnel closes; a tunnel
// that ends by itself is ok.
func TestPipeLimits(t *testing.T) {
	h := newHarness()
	h.answer("big.example.com", publicV4)
	h.dialer.serve = func(c net.Conn) {
		defer c.Close()
		//nolint:errcheck // the proxy closes the tunnel at its limit
		_, _ = c.Write(bytes.Repeat([]byte("x"), 20<<10))
	}
	status, _, conn, reader := h.connect(t, connectTo("big.example.com:443"))
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	got, _ := io.ReadAll(reader)
	conn.Close()
	if len(got) != DefaultPipeBytes {
		t.Fatalf("carried %d bytes", len(got))
	}

	h.proxy.PipeFor = 300 * time.Millisecond
	h.answer("slow.example.com", publicV4)
	h.dialer.serve = func(c net.Conn) {
		defer c.Close()
		//nolint:errcheck // waits for the proxy to give up
		_, _ = io.Copy(io.Discard, c)
	}
	start := time.Now()
	status, _, conn, reader = h.connect(t, connectTo("slow.example.com:443"))
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	//nolint:errcheck // reading to the tunnel's end
	_, _ = io.ReadAll(reader)
	conn.Close()
	if d := time.Since(start); d < 250*time.Millisecond || d > 3*time.Second {
		t.Fatalf("the tunnel lasted %v", d)
	}

	h.dialer.serve = nil
	h.answer("echo.example.com", publicV4)
	status, _, conn, reader = h.connect(t, connectTo("echo.example.com:443"))
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	if _, err := io.WriteString(conn, "hello"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(reader, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("echoed %q %v", buf, err)
	}
	conn.Close()

	codes := map[string]string{}
	for _, line := range h.journal.lines(t) {
		codes[line["host"].(string)] = line["code"].(string)
	}
	if codes["big.example.com"] != CodeLimit || codes["slow.example.com"] != CodeLimit || codes["echo.example.com"] != CodeOK {
		t.Fatalf("codes = %v", codes)
	}
}

// A tunnel is a plain TCP connection: HTTPS_PROXY and its kin change
// nothing.
func TestProxyVariablesIgnored(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		for {
			c, err := upstream.Accept()
			if err != nil {
				return
			}
			go echo(c)
		}
	}()
	for _, name := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "ALL_PROXY"} {
		t.Setenv(name, "http://127.0.0.1:1")
	}
	h := newHarness()
	h.proxy.Dial = (&net.Dialer{}).DialContext
	h.proxy.Public = func(netip.Addr) bool { return true }
	h.proxy.dialPort = uint16(upstream.Addr().(*net.TCPAddr).Port)
	h.answer("local.example.com", netip.MustParseAddr("127.0.0.1"))
	status, _, conn, reader := h.connect(t, connectTo("local.example.com:443"))
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	if _, err := io.WriteString(conn, "direct"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 6)
	if _, err := io.ReadFull(reader, buf); err != nil || string(buf) != "direct" {
		t.Fatalf("echoed %q %v", buf, err)
	}
}

// One line per tunnel: the host, the code and the duration, and nothing
// else of the request or the tunnel.
func TestJournal(t *testing.T) {
	h := newHarness()
	h.answer("docs.example.com", publicV4)
	h.tunnel(t, "docs.example.com", "")
	h.tunnel(t, "github.io", CodeHostRefused)
	lines := h.journal.lines(t)
	if len(lines) != 2 {
		t.Fatalf("lines = %v", lines)
	}
	for _, line := range lines {
		keys := make([]string, 0, len(line))
		for k := range line {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		if !slices.Equal(keys, []string{"code", "host", "level", "ms", "msg", "time"}) || line["msg"] != "cimd egress" {
			t.Fatalf("line = %v", line)
		}
	}
	if lines[1]["host"] != "github.io" || lines[1]["code"] != CodeHostRefused {
		t.Fatalf("refusal line = %v", lines[1])
	}
}

func TestParseOwn(t *testing.T) {
	own, err := ParseOwn(" 54.1.2.3, ,2600:1f18::1 ,::ffff:10.0.0.1")
	if err != nil || len(own) != 3 || own[0] != ownAddr || own[2] != netip.MustParseAddr("10.0.0.1") {
		t.Fatalf("own = %v %v", own, err)
	}
	for _, raw := range []string{"", " , ", "api.wappie.thehappie.co", "10.0.0.0/8", "fe80::1%eth0"} {
		if _, err := ParseOwn(raw); err == nil {
			t.Errorf("%q was accepted", raw)
		}
	}
}
