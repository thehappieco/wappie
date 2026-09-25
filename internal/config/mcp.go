package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// MCP is the hosted assistant connector: the Go half of the remote MCP
// readers. The "hosted" reader runs as a separate process on this host and
// talks to this server over loopback only; an attested reader runs in a
// Nitro Enclave and talks to it over HMAC-signed HTTPS.
//
// Off by default. A deployment that does not run a reader gains nothing
// from the routes and should not carry them; when it is on, every value of
// every listed reader is required, because a half-configured relay is one
// that answers the console with a 502 at the moment somebody consents.
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
	// Readers are the reader ids WS_MCP_READERS lists, in its order;
	// "hosted" alone by default. The four fields above are the hosted
	// reader's and are required only when it is listed.
	Readers []string
	// Attested are the listed readers other than "hosted": readers that run
	// off this host (a Nitro Enclave) and talk to this server over
	// HMAC-signed HTTPS, each with its own WS_MCP_READER_<ID>_* block.
	Attested []MCPReader

	// readersErr is what was wrong with WS_MCP_READERS itself, and
	// strayHosted the WS_MCP_READER_HOSTED_* names that were set. Both are
	// reported by Validate, because a disabled connector is not inspected.
	readersErr  error
	strayHosted []string
}

// MCPReader is one attested reader's block, WS_MCP_READER_<ID>_*.
type MCPReader struct {
	// ID matches ^[a-z][a-z0-9]{0,15}$; its upper case is the environment
	// suffix.
	ID string
	// URL is where this server reaches the reader's internal listener:
	// https://<host>:<port>, on the public origin's host.
	URL string
	// PublicOrigin is where assistants reach the reader.
	PublicOrigin string
	// Secret signs every request in both directions. 43 base64url
	// characters; the HMAC key is the string's bytes as written.
	Secret string
	// SecretNext is accepted alongside Secret during a rotation. Optional.
	SecretNext string
	// Peers are the addresses the reader's calls may come from: the
	// parent instance's Elastic IP.
	Peers []netip.Prefix
	// Tenants are the workspaces that may consent to this reader;
	// AllTenants is the single value "*".
	Tenants    []uuid.UUID
	AllTenants bool

	// tenantErr is a TENANTS value that did not parse, kept for Validate.
	tenantErr error
	// peerErrs are PEER entries that did not parse.
	peerErrs []error
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
	m.Readers, m.readersErr = readerIDs(str("WS_MCP_READERS", hostedReader))
	for _, id := range m.Readers {
		if id != hostedReader {
			m.Attested = append(m.Attested, loadReader(id))
		}
	}
	for _, kv := range os.Environ() {
		if name, _, _ := strings.Cut(kv, "="); strings.HasPrefix(name, "WS_MCP_READER_HOSTED_") {
			m.strayHosted = append(m.strayHosted, name)
		}
	}
	return m
}

// hostedReader is the reader on this host, configured by the original
// variables. Every other id is an attested reader.
const hostedReader = "hosted"

// readerIDPattern is the shape of a reader id: short, lower case, and safe
// to upper-case into an environment variable name.
var readerIDPattern = regexp.MustCompile(`^[a-z][a-z0-9]{0,15}$`)

// readerIDs parses WS_MCP_READERS. The ids come back trimmed, in order; an
// id of the wrong shape or a duplicate is an error, and so is an empty list.
func readerIDs(raw string) ([]string, error) {
	var ids []string
	var errs []error
	for _, id := range strings.Split(raw, ",") {
		id = strings.TrimSpace(id)
		switch {
		case id == "":
			continue
		case !readerIDPattern.MatchString(id):
			errs = append(errs, fmt.Errorf("WS_MCP_READERS: %q is not a reader id (^[a-z][a-z0-9]{0,15}$)", id))
			continue
		case slices.Contains(ids, id):
			errs = append(errs, fmt.Errorf("WS_MCP_READERS: %q is listed twice", id))
			continue
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 && len(errs) == 0 {
		errs = append(errs, errors.New("WS_MCP_READERS must name at least one reader"))
	}
	return ids, errors.Join(errs...)
}

// loadReader reads one attested reader's block. Nothing is judged here
// beyond parsing; Validate says what is wrong, once, with the variable's name.
func loadReader(id string) MCPReader {
	prefix := "WS_MCP_READER_" + strings.ToUpper(id) + "_"
	r := MCPReader{
		ID:           id,
		URL:          strings.TrimSpace(os.Getenv(prefix + "URL")),
		PublicOrigin: strings.TrimSpace(os.Getenv(prefix + "PUBLIC_ORIGIN")),
		Secret:       strings.TrimSpace(os.Getenv(prefix + "SECRET")),
		SecretNext:   strings.TrimSpace(os.Getenv(prefix + "SECRET_NEXT")),
	}
	var peerErrs []error
	r.Peers = prefixes(prefix+"PEER", &peerErrs)
	r.peerErrs = peerErrs
	tenants := strings.TrimSpace(os.Getenv(prefix + "TENANTS"))
	if tenants == "*" {
		r.AllTenants = true
		return r
	}
	for _, part := range strings.Split(tenants, ",") {
		if part = strings.TrimSpace(part); part == "" {
			continue
		}
		tenant, err := uuid.Parse(part)
		if err != nil || len(part) != 36 || tenant == uuid.Nil {
			r.tenantErr = fmt.Errorf("%sTENANTS: %q is not a workspace id (a UUID, or the single value *)", prefix, part)
			continue
		}
		r.Tenants = append(r.Tenants, tenant)
	}
	return r
}

// Hosted reports whether the reader on this host is listed. An empty list
// is the default, which is the hosted reader alone.
func (m MCP) Hosted() bool {
	return len(m.Readers) == 0 || slices.Contains(m.Readers, hostedReader)
}

// Reader returns the attested reader with this id.
func (m MCP) Reader(id string) (MCPReader, bool) {
	i := slices.IndexFunc(m.Attested, func(r MCPReader) bool { return r.ID == id })
	if i < 0 {
		return MCPReader{}, false
	}
	return m.Attested[i], true
}

// Validate checks the block when it is enabled. A disabled connector is not
// inspected: a leftover value must not stop a server that does not use it.
func (m MCP) Validate(prod bool) error {
	if !m.Enabled {
		return nil
	}
	var errs []error
	if m.readersErr != nil {
		errs = append(errs, m.readersErr)
	}
	for _, name := range m.strayHosted {
		errs = append(errs, fmt.Errorf("%s: the hosted reader is configured by WS_MCP_READER_URL, WS_MCP_RELAY_SECRET and WS_MCP_PUBLIC_ORIGIN, not by WS_MCP_READER_HOSTED_*", name))
	}
	if m.Hosted() {
		errs = append(errs, m.validateHosted(prod)...)
	}
	for _, r := range m.Attested {
		errs = append(errs, r.validate()...)
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

// validateHosted is today's check of the hosted reader, unchanged: a
// loopback http reader, a bearer secret of at least 32 bytes, and a public
// origin.
func (m MCP) validateHosted(prod bool) []error {
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
	return errs
}

// validate checks an attested reader's block. Everything is required but
// SECRET_NEXT, and nothing is relaxed outside prod: the reader is an enclave
// with its own certificate, and a laptop has no business pretending to be one.
func (r MCPReader) validate() []error {
	prefix := "WS_MCP_READER_" + strings.ToUpper(r.ID) + "_"
	var errs []error
	origin, err := attestedOrigin(r.PublicOrigin)
	if err != nil {
		errs = append(errs, fmt.Errorf("%sPUBLIC_ORIGIN %w", prefix, err))
	}
	if err := attestedReaderURL(r.URL, origin); err != nil {
		errs = append(errs, fmt.Errorf("%sURL %w", prefix, err))
	}
	if !validReaderSecret(r.Secret) {
		errs = append(errs, fmt.Errorf("%sSECRET must be exactly 43 base64url characters (32 random bytes)", prefix))
	}
	if r.SecretNext != "" && !validReaderSecret(r.SecretNext) {
		errs = append(errs, fmt.Errorf("%sSECRET_NEXT must be exactly 43 base64url characters (32 random bytes)", prefix))
	}
	if r.SecretNext != "" && r.SecretNext == r.Secret {
		errs = append(errs, fmt.Errorf("%sSECRET_NEXT must differ from %sSECRET", prefix, prefix))
	}
	errs = append(errs, r.peerErrs...)
	if len(r.Peers) == 0 && len(r.peerErrs) == 0 {
		errs = append(errs, fmt.Errorf("%sPEER must list the addresses the reader calls from", prefix))
	}
	switch {
	case r.tenantErr != nil:
		errs = append(errs, r.tenantErr)
	case !r.AllTenants && len(r.Tenants) == 0:
		errs = append(errs, fmt.Errorf("%sTENANTS must list the workspaces that may use this reader, or be *", prefix))
	}
	return errs
}

// attestedOrigin wants an https origin with no path, and returns its host.
func attestedOrigin(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("is required for an attested reader")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery ||
		u.Fragment != "" || (u.Path != "" && u.Path != "/") || !validHostname(u.Hostname()) {
		return "", errors.New("must be an https origin with no path, such as https://mcp.wappie.thehappie.co")
	}
	return u.Hostname(), nil
}

// attestedReaderURL wants https://<host>:<port> with nothing else, on the
// public origin's host: the certificate the reader serves on its internal
// listener is the one it serves the public, and it names that host only.
func attestedReaderURL(raw, originHost string) error {
	if raw == "" {
		return errors.New("is required for an attested reader")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Port() == "" || u.User != nil || u.RawQuery != "" ||
		u.ForceQuery || u.Fragment != "" || u.Path != "" || !validHostname(u.Hostname()) {
		return errors.New("must be https://<host>:<port> with no path, such as https://mcp.wappie.thehappie.co:8443")
	}
	if port, err := strconv.Atoi(u.Port()); err != nil || port < 1 || port > 65535 {
		return errors.New("must carry a port between 1 and 65535")
	}
	if originHost != "" && u.Hostname() != originHost {
		return fmt.Errorf("must be on the public origin's host, %s", originHost)
	}
	return nil
}

// validReaderSecret is 43 base64url characters that decode to 32 bytes. The
// HMAC key is the string itself; the shape only makes sure it was generated
// rather than typed.
func validReaderSecret(secret string) bool {
	if len(secret) != 43 {
		return false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(secret)
	return err == nil && len(raw) == 32
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
	var b strings.Builder
	b.WriteString("mcp=enabled")
	if m.Hosted() {
		fmt.Fprintf(&b, " reader=%s origin=%s relay_secret=%s", m.ReaderURL, m.PublicOrigin, setOrUnset(m.RelaySecret))
	}
	fmt.Fprintf(&b, " redirect_hosts=%s readers=%s", strings.Join(m.RedirectHosts, ","), strings.Join(m.Readers, ","))
	for _, r := range m.Attested {
		b.WriteString(" ")
		b.WriteString(r.String())
	}
	return b.String()
}

// String renders an attested reader without either secret.
func (r MCPReader) String() string {
	tenants := strconv.Itoa(len(r.Tenants))
	if r.AllTenants {
		tenants = "*"
	}
	return fmt.Sprintf("reader[%s]=url:%s,origin:%s,secret:%s,secret_next:%s,peers:%d,tenants:%s",
		r.ID, r.URL, r.PublicOrigin, setOrUnset(r.Secret), setOrUnset(r.SecretNext), len(r.Peers), tenants)
}

// GoString keeps %#v from printing the secrets field by field.
func (r MCPReader) GoString() string { return r.String() }

func setOrUnset(secret string) string {
	if secret == "" {
		return "unset"
	}
	return "set"
}
