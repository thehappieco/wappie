package mcpauth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// CIMD fetches OAuth client metadata documents on the reader's behalf.
//
// An assistant may identify itself by URL instead of registering: the URL
// serves a JSON document naming its redirect addresses. The reader runs
// with no network access beyond this host, so it asks this server to fetch
// the document, and this server fetches only what the reader could have been
// allowed to reach anyway — https, on one of the listed hosts, a real path,
// no redirects, a small JSON body. Everything else is a request to make this
// server call somewhere it should not, and is refused before any connection
// is opened.
type CIMD struct {
	// Hosts are the exact hosts a document may live on.
	Hosts []string
	// Transport carries the fetch; nil is the default transport. Tests hand
	// in one that answers locally.
	Transport http.RoundTripper
}

// maxCIMDBody bounds a document. A metadata document is a client id, a
// name and a handful of redirect addresses; eight kilobytes is several
// times that.
const maxCIMDBody = 8 << 10

const cimdTimeout = 5 * time.Second

var (
	// ErrCIMDURL is a document address this server will not fetch.
	ErrCIMDURL = errors.New("mcpauth: not a client metadata address")
	// ErrCIMDUnavailable is a document that could not be fetched as a
	// small JSON body over one hop.
	ErrCIMDUnavailable = errors.New("mcpauth: client metadata document unavailable")
)

// Address checks a document URL against the rules and returns it parsed.
// The check is strict on purpose: the host list is compared byte for byte,
// a port would let the same name reach another service, userinfo and a
// query are ways of smuggling, and the root path is never a document.
func (c *CIMD) Address(raw string) (*url.URL, error) {
	if raw == "" || len(raw) > 2048 || strings.ContainsAny(raw, " \t\r\n") {
		return nil, ErrCIMDURL
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Host == "" {
		return nil, ErrCIMDURL
	}
	if u.Port() != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return nil, ErrCIMDURL
	}
	host := strings.ToLower(u.Hostname())
	if host != u.Host || !slices.Contains(c.Hosts, host) {
		return nil, ErrCIMDURL
	}
	if u.Path == "" || u.Path == "/" || !strings.HasPrefix(u.Path, "/") || strings.Contains(u.Path, "/../") || strings.HasSuffix(u.Path, "/..") {
		return nil, ErrCIMDURL
	}
	return u, nil
}

// Fetch retrieves a document and returns its bytes as served.
func (c *CIMD) Fetch(ctx context.Context, raw string) ([]byte, error) {
	u, err := c.Address(raw)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, cimdTimeout)
	defer cancel()
	// The address passed Address: https, an allowed host byte for byte, no
	// port, no userinfo, a real path. That check is the SSRF guard.
	//nolint:gosec // G704: the address is allowlisted by Address above
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCIMDUnavailable, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "wappie-cimd-relay/1")
	client := &http.Client{
		Timeout:   cimdTimeout,
		Transport: c.Transport,
		// A redirect is another address, one the rules above never saw.
		// The 3xx comes back as the answer and is refused below.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	//nolint:gosec // G704: the address is allowlisted by Address above
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCIMDUnavailable, err)
	}
	defer func() {
		//nolint:errcheck // the body is drained; a close error changes nothing
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: answered %d", ErrCIMDUnavailable, resp.StatusCode)
	}
	if mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || mediaType != "application/json" {
		return nil, fmt.Errorf("%w: not application/json", ErrCIMDUnavailable)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCIMDBody+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCIMDUnavailable, err)
	}
	if len(body) > maxCIMDBody {
		return nil, fmt.Errorf("%w: larger than %d bytes", ErrCIMDUnavailable, maxCIMDBody)
	}
	return body, nil
}
