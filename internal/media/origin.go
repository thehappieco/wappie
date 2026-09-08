package media

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// Origins decides where this process is willing to fetch from.
//
// The URL of an attachment arrives inside the message that carries it. It is
// whatever the sender's client put there, which means whoever sends a message
// to a paired number chooses a URL this server will fetch. Left unchecked, that
// is a server-side request forgery from anyone with a phone: the cloud metadata
// endpoint, an internal admin port, anything routable from here. The download
// is hash-checked and size-capped, so the body rarely leaks, but the request
// still goes out — and "blind" is not the same as harmless.
//
// So a URL is checked before it is used, and again at every redirect, and the
// dialer refuses addresses that are not public even when the name resolved
// somewhere it should not have. Three layers, because each catches what the
// others miss: a plain allowlist stops the obvious URL, the redirect check
// stops a CDN-looking host that bounces elsewhere, and the address check stops
// a name that resolves to an internal address.
type Origins struct {
	// Hosts are the names allowed: an exact host, or a suffix starting with a
	// dot, which matches every subdomain. Nil means any host, which only a
	// test against a local server should want.
	Hosts []string
	// AllowPlaintext permits http://. WhatsApp serves media over TLS only.
	AllowPlaintext bool
	// AllowAnyPort permits a port other than the scheme's default.
	AllowAnyPort bool
	// AllowPrivateAddresses permits loopback, link-local and RFC 1918 targets.
	AllowPrivateAddresses bool
}

// ErrOrigin reports a URL this process refuses to fetch from.
var ErrOrigin = errors.New("media: refusing to fetch from that origin")

// WhatsAppOrigins is where attachments and profile pictures actually live.
//
// One suffix covers the media CDN (mmg.whatsapp.net, media-*.cdn.whatsapp.net)
// and profile pictures (pps.whatsapp.net). Nothing WhatsApp serves to a client
// comes from anywhere else.
func WhatsAppOrigins() Origins {
	return Origins{Hosts: []string{".whatsapp.net"}}
}

// AnyOrigin permits everything. For tests that stand up a local server and
// nothing else: in a running server it turns the fetcher back into the request
// forgery this type exists to prevent.
func AnyOrigin() Origins {
	return Origins{AllowPlaintext: true, AllowAnyPort: true, AllowPrivateAddresses: true}
}

// Check reports whether a URL may be fetched.
func (o Origins) Check(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrOrigin, err)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !o.AllowPlaintext {
			return fmt.Errorf("%w: plaintext http", ErrOrigin)
		}
	default:
		return fmt.Errorf("%w: scheme %q", ErrOrigin, u.Scheme)
	}
	if u.User != nil {
		return fmt.Errorf("%w: credentials in the url", ErrOrigin)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return fmt.Errorf("%w: no host", ErrOrigin)
	}
	if port := u.Port(); port != "" && !o.AllowAnyPort {
		if (u.Scheme == "https" && port != "443") || (u.Scheme == "http" && port != "80") {
			return fmt.Errorf("%w: port %s", ErrOrigin, port)
		}
	}
	if !o.hostAllowed(host) {
		return fmt.Errorf("%w: host %q", ErrOrigin, host)
	}
	if !o.AllowPrivateAddresses {
		// A literal address gets checked here, before any dial. A name is
		// checked when it resolves, in dial.
		if addr, err := netip.ParseAddr(host); err == nil && !public(addr) {
			return fmt.Errorf("%w: %s is not a public address", ErrOrigin, host)
		}
	}
	return nil
}

func (o Origins) hostAllowed(host string) bool {
	if o.Hosts == nil {
		return true
	}
	for _, allowed := range o.Hosts {
		allowed = strings.ToLower(allowed)
		if strings.HasPrefix(allowed, ".") {
			if strings.HasSuffix(host, allowed) || host == allowed[1:] {
				return true
			}
			continue
		}
		if host == allowed {
			return true
		}
	}
	return false
}

// Client builds an HTTP client that enforces these origins on the first
// request, on every redirect, and on the address a name resolves to.
func (o Origins) Client(timeout time.Duration, maxRedirects int) *http.Client {
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	var transport *http.Transport
	if def, ok := http.DefaultTransport.(*http.Transport); ok {
		transport = def.Clone()
	} else {
		transport = &http.Transport{}
	}
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return o.dial(ctx, dialer, network, addr)
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return errors.New("media: too many redirects")
			}
			// The redirect target is a URL the remote side chose, which is
			// exactly as trustworthy as the one in the message.
			return o.Check(req.URL.String())
		},
	}
}

// dial resolves the name itself so the addresses can be checked before a
// connection exists. Resolving inside net.Dialer would decide for us.
func (o Origins) dial(ctx context.Context, d *net.Dialer, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if o.AllowPrivateAddresses {
		return d.DialContext(ctx, network, addr)
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, ip := range addrs {
		ip = ip.Unmap()
		if !public(ip) {
			lastErr = fmt.Errorf("%w: %s resolves to %s", ErrOrigin, host, ip)
			continue
		}
		conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("%w: %s resolves to nothing", ErrOrigin, host)
	}
	return nil, lastErr
}

// public reports whether an address is one a CDN could plausibly answer from.
func public(ip netip.Addr) bool {
	ip = ip.Unmap()
	switch {
	case !ip.IsValid(), ip.IsUnspecified(), ip.IsLoopback(), ip.IsPrivate(),
		ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast(), ip.IsMulticast(),
		ip.IsInterfaceLocalMulticast():
		return false
	}
	// Carrier-grade NAT and the IPv4-mapped/6to4 ranges are not private by the
	// standard library's definition and are not reachable CDNs either.
	if ip.Is4() {
		if cgnat.Contains(ip) || benchmarking.Contains(ip) {
			return false
		}
	}
	return true
}

var (
	cgnat        = netip.MustParsePrefix("100.64.0.0/10")
	benchmarking = netip.MustParsePrefix("198.18.0.0/15")
)
