// Package cimdegress is the parent's document egress proxy
// (docs/mcp-enclave.md §19.9): the one path by which the attested reader
// reaches a client metadata document on a host nobody configured.
//
// The reader opens a CONNECT tunnel to <host>:443 and speaks TLS through it,
// verifying the certificate itself, so the parent can refuse or delay a
// document but never read or forge one. What the parent decides is where a
// tunnel may go: the host must pass the same host predicate as the reader's
// (internal/netguard, over the same Public Suffix List snapshot), the name is
// resolved once and every address must be public and none the deployment's
// own, and only port 443 is ever dialed, address by address, without a second
// resolution, so a DNS answer that changes between the check and the
// connection is never used. Budgets bound the tunnels overall and per
// registrable domain, a short negative cache spares a failing host, and each
// tunnel carries at most 16 KiB each way for at most 6 seconds. Proxy
// variables in the environment mean nothing here: a tunnel is a plain TCP
// connection.
//
// One journal line per tunnel names the host, the result code and the
// duration. The parent sees the hosts, the timing and the sizes, as the Go
// API did when it fetched the documents itself; it never sees a document.
package cimdegress

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"whatserver2/internal/netguard"
	"whatserver2/internal/ratelimit"
)

// Refusal codes, sent in the X-Wappie-Egress header of a 403 and written to
// the journal. The reader logs every one of them as proxy_refused.
const (
	CodeHostRefused    = "host_refused"
	CodePrivateAddress = "private_address"
	CodeDNSFailed      = "dns_failed"
	CodeConnectFailed  = "connect_failed"
	CodeBusy           = "busy"
	CodeRateLimited    = "rate_limited"
	CodeNegativeCached = "negative_cached"
)

// Journal-only codes: a tunnel that ran, one its time or size cap ended, a
// request that was not a CONNECT to port 443, and one that did not parse.
const (
	CodeOK               = "ok"
	CodeLimit            = "limit"
	CodeMethodNotAllowed = "method_not_allowed"
	CodeBadRequest       = "bad_request"
)

// Defaults of §19.9.
const (
	DefaultPerMinute       = 60
	DefaultBurst           = 20
	DefaultDomainPerMinute = 10
	DefaultTunnels         = 4
	DefaultNegativeTTL     = 60 * time.Second
	DefaultNegativeMax     = 2000
	DefaultResolveTimeout  = 1500 * time.Millisecond
	DefaultDialAttempt     = 1500 * time.Millisecond
	DefaultDialTotal       = 3 * time.Second
	DefaultPipeFor         = 6 * time.Second
	DefaultPipeBytes       = 16 << 10
	// headerTimeout and headerBytes bound the CONNECT request itself.
	headerTimeout = 2 * time.Second
	headerBytes   = 4 << 10
	// port is the only port a tunnel goes to.
	port = "443"
)

// Resolver resolves a name once; *net.Resolver is one.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Proxy is the egress proxy. The zero value is not usable; New fills the
// defaults.
type Proxy struct {
	// Own are the deployment's own addresses (WS_CIMD_EGRESS_OWN_ADDRESSES),
	// never dialed: at least the parent's Elastic IP and the API host's.
	Own []netip.Addr
	// Resolver resolves a tunnel's host, once. Dial opens a TCP connection
	// to one address; a net.Dialer's DialContext, which no proxy setting
	// reaches.
	Resolver Resolver
	Dial     func(ctx context.Context, network, address string) (net.Conn, error)
	// Public reports whether an address may be dialed at all;
	// netguard.Public unless a test says otherwise.
	Public func(netip.Addr) bool
	// Log receives the journal lines.
	Log *slog.Logger

	ResolveTimeout, DialAttempt, DialTotal, PipeFor time.Duration
	PipeBytes                                       int64

	overall, perDomain *ratelimit.Limiter
	tunnels            chan struct{}
	negative           *negativeCache
	// dialPort is 443; a test points it at a listener of its own.
	dialPort uint16
}

// New builds a proxy with the defaults of §19.9 and the deployment's own
// addresses.
func New(own []netip.Addr, log *slog.Logger) *Proxy {
	dialer := &net.Dialer{}
	return &Proxy{
		Own: own, Resolver: net.DefaultResolver, Dial: dialer.DialContext, Public: netguard.Public, Log: log,
		ResolveTimeout: DefaultResolveTimeout, DialAttempt: DefaultDialAttempt, DialTotal: DefaultDialTotal,
		PipeFor: DefaultPipeFor, PipeBytes: DefaultPipeBytes,
		overall:   ratelimit.New(DefaultPerMinute, DefaultBurst),
		perDomain: ratelimit.New(DefaultDomainPerMinute, DefaultDomainPerMinute),
		tunnels:   make(chan struct{}, DefaultTunnels),
		negative:  newNegativeCache(DefaultNegativeTTL, DefaultNegativeMax),
		dialPort:  443,
	}
}

// ParseOwn parses WS_CIMD_EGRESS_OWN_ADDRESSES: IP addresses, comma
// separated, at least one.
func ParseOwn(raw string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, part := range strings.Split(raw, ",") {
		if part = strings.TrimSpace(part); part == "" {
			continue
		}
		addr, err := netip.ParseAddr(part)
		if err != nil || addr.Zone() != "" {
			return nil, errors.New("WS_CIMD_EGRESS_OWN_ADDRESSES: " + strconv.Quote(part) + " is not an IP address")
		}
		out = append(out, addr.Unmap())
	}
	if len(out) == 0 {
		return nil, errors.New("WS_CIMD_EGRESS_OWN_ADDRESSES must list the deployment's own addresses (the parent's Elastic IP and the API host's)")
	}
	return out, nil
}

// Serve handles one connection from the reader: one CONNECT, one tunnel or
// one refusal, then it closes the connection.
func (p *Proxy) Serve(client net.Conn) {
	start := time.Now()
	defer func() {
		//nolint:errcheck // the tunnel is over either way
		_ = client.Close()
	}()
	host, code, buffered := p.open(client)
	if code != "" {
		p.journal(host, code, start)
		return
	}
	upstream, code := p.connect(host)
	if code != "" {
		refuse(client, code)
		p.journal(host, code, start)
		return
	}
	defer func() {
		<-p.tunnels
		//nolint:errcheck // the tunnel is over either way
		_ = upstream.Close()
	}()
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		p.journal(host, CodeConnectFailed, start)
		return
	}
	p.journal(host, p.pipe(client, upstream, buffered), start)
}

// open reads the CONNECT request and applies every check that needs no
// network. It answers a refusal itself; on success it returns the host and
// any bytes the reader sent after the request.
func (p *Proxy) open(client net.Conn) (host, code string, buffered []byte) {
	//nolint:errcheck // a connection that cannot take a deadline fails its read below
	_ = client.SetReadDeadline(time.Now().Add(headerTimeout))
	reader := bufio.NewReaderSize(io.LimitReader(client, headerBytes), headerBytes)
	req, err := http.ReadRequest(reader)
	if err != nil {
		reply(client, http.StatusBadRequest, "", "")
		return "", CodeBadRequest, nil
	}
	//nolint:errcheck // cleared for the tunnel, which sets its own
	_ = client.SetReadDeadline(time.Time{})
	target := req.RequestURI
	h, portPart, err := net.SplitHostPort(target)
	if req.Method != http.MethodConnect || err != nil || portPart != port || req.URL == nil || req.URL.Host != target {
		reply(client, http.StatusMethodNotAllowed, "", "CONNECT")
		return h, CodeMethodNotAllowed, nil
	}
	checked, reason := netguard.CheckHost(h)
	if reason != "" {
		refuse(client, CodeHostRefused)
		return h, CodeHostRefused, nil
	}
	now := time.Now()
	if p.negative.has(h, now) {
		refuse(client, CodeNegativeCached)
		return h, CodeNegativeCached, nil
	}
	if ok, _ := p.overall.Allow("all"); !ok {
		refuse(client, CodeRateLimited)
		return h, CodeRateLimited, nil
	}
	if ok, _ := p.perDomain.Allow(checked.Registrable); !ok {
		refuse(client, CodeRateLimited)
		return h, CodeRateLimited, nil
	}
	select {
	case p.tunnels <- struct{}{}:
	default:
		refuse(client, CodeBusy)
		return h, CodeBusy, nil
	}
	if n := reader.Buffered(); n > 0 {
		if peeked, err := reader.Peek(n); err == nil {
			buffered = append([]byte(nil), peeked...)
		}
	}
	return h, "", buffered
}

// connect resolves the host once and dials its addresses in order. It holds
// a tunnel's place, and gives it back on a refusal.
func (p *Proxy) connect(host string) (net.Conn, string) {
	release := func(code string) (net.Conn, string) {
		<-p.tunnels
		return nil, code
	}
	ctx, cancel := context.WithTimeout(context.Background(), p.ResolveTimeout)
	addrs, err := p.Resolver.LookupNetIP(ctx, "ip", host)
	cancel()
	if err != nil || len(addrs) == 0 {
		p.negative.add(host, time.Now())
		return release(CodeDNSFailed)
	}
	for i, addr := range addrs {
		addr = addr.Unmap()
		addrs[i] = addr
		// A name with any address that is not public, or that is the
		// deployment's own, is not a document host, whatever its other
		// records say.
		if !p.Public(addr) || slices.Contains(p.Own, addr) {
			return release(CodePrivateAddress)
		}
	}
	ctx, cancel = context.WithTimeout(context.Background(), p.DialTotal)
	defer cancel()
	for _, addr := range addrs {
		attempt, stop := context.WithTimeout(ctx, p.DialAttempt)
		conn, err := p.Dial(attempt, "tcp", netip.AddrPortFrom(addr, p.dialPort).String())
		stop()
		if err == nil {
			return conn, ""
		}
		if ctx.Err() != nil {
			break
		}
	}
	p.negative.add(host, time.Now())
	return release(CodeConnectFailed)
}

// pipe copies bytes both ways until either side is done, the time is up or
// either direction has carried its limit, and says which.
func (p *Proxy) pipe(client, upstream net.Conn, buffered []byte) string {
	deadline := time.Now().Add(p.PipeFor)
	//nolint:errcheck // a connection that cannot take a deadline is closed when the copy ends
	_ = client.SetDeadline(deadline)
	//nolint:errcheck // as above
	_ = upstream.SetDeadline(deadline)
	over := make(chan bool, 2)
	go func() { over <- p.copyCapped(upstream, client, buffered) }()
	go func() { over <- p.copyCapped(client, upstream, nil) }()
	first := <-over
	// Either side finishing ends the tunnel: both close, so the other copy
	// returns at once.
	//nolint:errcheck // closing to end the other copy
	_ = client.Close()
	//nolint:errcheck // as above
	_ = upstream.Close()
	<-over
	if first || !time.Now().Before(deadline) {
		return CodeLimit
	}
	return CodeOK
}

// copyCapped copies src to dst, at most PipeBytes in all, the bytes already
// read from src first, and reports whether src had more than that to send.
func (p *Proxy) copyCapped(dst, src net.Conn, already []byte) bool {
	budget := p.PipeBytes
	if len(already) > 0 {
		if int64(len(already)) > budget {
			return true
		}
		n, err := dst.Write(already)
		budget -= int64(n)
		if err != nil {
			return false
		}
	}
	n, err := io.Copy(dst, io.LimitReader(src, budget))
	if err != nil || n < budget {
		return false
	}
	// The budget is spent; one byte more is over it, and is not sent.
	var more [1]byte
	m, err := src.Read(more[:])
	if err != nil && m == 0 {
		return false
	}
	return m > 0
}

// refuse answers a 403 with the refusal's code.
func refuse(client net.Conn, code string) {
	reply(client, http.StatusForbidden, code, "")
}

// reply writes a bodiless answer and nothing else.
func reply(client net.Conn, status int, code, allow string) {
	head := "HTTP/1.1 " + strconv.Itoa(status) + " " + http.StatusText(status) + "\r\n"
	if code != "" {
		head += "X-Wappie-Egress: " + code + "\r\n"
	}
	if allow != "" {
		head += "Allow: " + allow + "\r\n"
	}
	head += "Content-Length: 0\r\nConnection: close\r\n\r\n"
	//nolint:errcheck // a reader that hung up has its answer
	_ = client.SetWriteDeadline(time.Now().Add(headerTimeout))
	//nolint:errcheck // as above
	_, _ = io.WriteString(client, head)
}

// journal writes a tunnel's one line: the host, the code and how long it
// took. Nothing else of the request, and never a byte of the tunnel.
func (p *Proxy) journal(host, code string, start time.Time) {
	if p.Log == nil {
		return
	}
	p.Log.Info("cimd egress", "host", host, "code", code, "ms", time.Since(start).Milliseconds())
}

// negativeCache remembers, for a while, the hosts whose name or connection
// failed, at most max of them, dropping the oldest.
type negativeCache struct {
	mu    sync.Mutex
	ttl   time.Duration
	max   int
	until map[string]time.Time
	order []string
}

func newNegativeCache(ttl time.Duration, max int) *negativeCache {
	return &negativeCache{ttl: ttl, max: max, until: map[string]time.Time{}}
}

func (c *negativeCache) has(host string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	until, ok := c.until[host]
	return ok && now.Before(until)
}

func (c *negativeCache) add(host string, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.until[host]; !ok {
		c.order = append(c.order, host)
	}
	c.until[host] = now.Add(c.ttl)
	for len(c.order) > c.max {
		delete(c.until, c.order[0])
		c.order = c.order[1:]
	}
}
