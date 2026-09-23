package config

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strings"
)

// MCP is the hosted assistant connector: the Go half of a remote MCP reader
// that runs as a separate process on this host and talks to this server over
// loopback only.
//
// Off by default. A deployment that does not run the reader gains nothing
// from the routes and should not carry them; when it is on, every value is
// required, because a half-configured relay is one that answers the console
// with a 502 at the moment somebody consents.
type MCP struct {
	Enabled bool
	// ReaderURL is where the reader listens. Loopback http only: the relay
	// carries a sealed bundle and a shared secret, and neither may leave the
	// host.
	ReaderURL string
	// RelaySecret authenticates the two processes to each other. Never
	// logged; String renders only whether it is set.
	RelaySecret string
	// PublicOrigin is where the reader is reachable from the internet. The
	// console derives the completion URL from it, so it must match what
	// nginx serves — https in prod, http localhost in development.
	PublicOrigin string
	// RedirectHosts are the exact hosts an OAuth client may redirect to and
	// whose client metadata documents this server will fetch on the reader's
	// behalf. The reader carries the same list under its own name; the
	// runbook says they must match.
	RedirectHosts []string
	// OpenAIAppsChallenge is the domain-verification token OpenAI's plugin
	// portal issues for the MCP server's origin, served verbatim at
	// /.well-known/openai-apps-challenge. Empty until a submission asks for
	// one; the path answers 404 until then.
	OpenAIAppsChallenge string
}

// defaultRedirectHosts are the assistants the pilot serves.
const defaultRedirectHosts = "claude.ai,chatgpt.com"

func loadMCP(errs *[]error) MCP {
	m := MCP{
		Enabled:             boolean("WS_MCP_ENABLED", false, errs),
		ReaderURL:           strings.TrimSpace(os.Getenv("WS_MCP_READER_URL")),
		RelaySecret:         os.Getenv("WS_MCP_RELAY_SECRET"),
		PublicOrigin:        strings.TrimSpace(os.Getenv("WS_MCP_PUBLIC_ORIGIN")),
		OpenAIAppsChallenge: strings.TrimSpace(os.Getenv("WS_MCP_OPENAI_APPS_CHALLENGE")),
	}
	for _, host := range strings.Split(str("WS_MCP_REDIRECT_HOSTS", defaultRedirectHosts), ",") {
		if host = strings.ToLower(strings.TrimSpace(host)); host != "" {
			m.RedirectHosts = append(m.RedirectHosts, host)
		}
	}
	return m
}

// Validate checks the block when it is enabled. A disabled connector is not
// inspected: a leftover value must not stop a server that does not use it.
func (m MCP) Validate(prod bool) error {
	if !m.Enabled {
		return nil
	}
	var errs []error
	if err := validReaderURL(m.ReaderURL); err != nil {
		errs = append(errs, err)
	}
	if len(m.RelaySecret) < 32 {
		errs = append(errs, errors.New("WS_MCP_RELAY_SECRET must be at least 32 bytes when WS_MCP_ENABLED is set"))
	}
	if err := validPublicOrigin(m.PublicOrigin, prod); err != nil {
		errs = append(errs, err)
	}
	if len(m.RedirectHosts) == 0 {
		errs = append(errs, errors.New("WS_MCP_REDIRECT_HOSTS must name at least one host when WS_MCP_ENABLED is set"))
	}
	for _, host := range m.RedirectHosts {
		if !validHostname(host) {
			errs = append(errs, fmt.Errorf("WS_MCP_REDIRECT_HOSTS: %q is not a bare host name", host))
		}
	}
	if !validChallenge(m.OpenAIAppsChallenge) {
		errs = append(errs, errors.New("WS_MCP_OPENAI_APPS_CHALLENGE must be up to 256 printable characters without spaces"))
	}
	return errors.Join(errs...)
}

// validChallenge keeps the token to something a response body can carry
// verbatim: printable ASCII, no whitespace, bounded. Empty is allowed.
func validChallenge(token string) bool {
	if len(token) > 256 {
		return false
	}
	for _, r := range token {
		if r <= ' ' || r > '~' {
			return false
		}
	}
	return true
}

// validReaderURL accepts http://127.0.0.1:18093 and its kin, nothing else.
func validReaderURL(raw string) error {
	invalid := errors.New("WS_MCP_READER_URL must be an http loopback origin such as http://127.0.0.1:18093")
	if raw == "" {
		return errors.New("WS_MCP_READER_URL is required when WS_MCP_ENABLED is set")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return invalid
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" {
		return nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.Unmap().IsLoopback() {
		return invalid
	}
	return nil
}

// validPublicOrigin wants an https origin; a local http one passes outside
// prod so the whole flow can be exercised on a laptop.
func validPublicOrigin(raw string, prod bool) error {
	if raw == "" {
		return errors.New("WS_MCP_PUBLIC_ORIGIN is required when WS_MCP_ENABLED is set")
	}
	invalid := errors.New("WS_MCP_PUBLIC_ORIGIN must be an https origin with no path (http localhost is allowed outside prod)")
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return invalid
	}
	host := strings.ToLower(u.Hostname())
	local := host == "localhost"
	if ip, parseErr := netip.ParseAddr(host); parseErr == nil {
		local = ip.Unmap().IsLoopback()
	}
	secure := u.Scheme == "https" || !prod && local && u.Scheme == "http"
	if !secure {
		return invalid
	}
	return nil
}

// validHostname is a lower-case DNS name: labels of letters, digits and
// hyphens, no scheme, port, path or wildcard. The list is compared byte for
// byte against what a client presents, so anything looser would be a hole.
func validHostname(host string) bool {
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "/:*@ \t\n") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		if strings.ContainsFunc(label, func(char rune) bool { return !hostChar(char) }) {
			return false
		}
	}
	return true
}

func hostChar(char rune) bool {
	return char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-'
}

// String renders the block for startup logs without the relay secret.
func (m MCP) String() string {
	if !m.Enabled {
		return "mcp=disabled"
	}
	secret := "unset"
	if m.RelaySecret != "" {
		secret = "set"
	}
	return fmt.Sprintf("mcp=enabled reader=%s origin=%s relay_secret=%s redirect_hosts=%s",
		m.ReaderURL, m.PublicOrigin, secret, strings.Join(m.RedirectHosts, ","))
}
