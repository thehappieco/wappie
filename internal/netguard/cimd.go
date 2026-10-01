package netguard

import (
	"net/netip"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Which client_id is a CIMD identifier (docs/mcp-enclave.md §19.5). The
// enclave's cimdURL, the egress proxy and the consent check apply the same
// steps to a string S, and the first step that fails names the refusal:
//
//  1. S is 1 to 512 bytes with no white space or control character [shape].
//  2. S starts with https:// and, parsed, has no userinfo, port, query or
//     fragment, and is its own canonical serialization [shape].
//  3. The path is not "/" [path_root].
//  4. The host passes CheckHost.
//  5. The path is 2 to 1,024 characters of a narrow set, with no empty, "."
//     or ".." segment and no %2e, %2f or %5c [path_chars].

// Refusal reasons, the codes of the shared vectors
// (packages/mcp-http/test/vectors/cimd-ids.json).
const (
	ReasonShape        = "shape"
	ReasonPathRoot     = "path_root"
	ReasonHostChars    = "host_chars"
	ReasonHostLabels   = "host_labels"
	ReasonIPLiteral    = "ip_literal"
	ReasonSpecialUse   = "special_use"
	ReasonOwnDomain    = "own_domain"
	ReasonPublicSuffix = "public_suffix"
	ReasonSharedHost   = "shared_host"
	ReasonPathChars    = "path_chars"
)

// SharedHosts serve many tenants by path, let an uploader choose the content
// type, or log every request with its query: as a host or any subdomain of
// one, none identifies anybody, so none is a client's domain. The image's
// SHARED_HOSTS, the same list.
var SharedHosts = []string{"amazonaws.com", "storage.googleapis.com", "firebasestorage.googleapis.com",
	"googleusercontent.com", "githubusercontent.com", "webhook.site", "cdn.jsdelivr.net", "unpkg.com", "raw.githack.com",
	"pipedream.net", "requestbin.com", "beeceptor.com"}

// OwnDomains are Wappie's registrable domains: no host under them is a
// client's, so no card shows Wappie's own name and no fetch loops back in.
// The image's OWN_DOMAINS.
var OwnDomains = []string{"thehappie.co"}

// specialUse are the names that are never on the public internet.
var specialUse = []string{"localhost", "localdomain", "local", "internal", "intranet", "private", "corp", "home", "lan",
	"arpa", "test", "example", "invalid", "onion", "alt"}

// Host is a host that may identify a client: the host itself, its
// registrable domain, and the shared-hosting suffix it sits under when its
// public suffix is in the List's private section ("" otherwise).
type Host struct {
	Host, Registrable, SharedSuffix string
}

// CheckHost applies the host predicate (§19.5 step 4) and returns the host's
// domains, or the reason it is refused.
func CheckHost(h string) (Host, string) {
	if len(h) < 4 || len(h) > 253 || strings.ContainsFunc(h, func(r rune) bool { return !hostByte(r) }) {
		return Host{}, ReasonHostChars
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return Host{}, ReasonHostLabels
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return Host{}, ReasonHostLabels
		}
	}
	// Every IPv4 form ends in a label of digits (or 0x...), and no top
	// level domain does.
	last := labels[len(labels)-1]
	if len(last) < 2 || !strings.HasPrefix(last, "xn--") && strings.ContainsFunc(last, func(r rune) bool { return r < 'a' || r > 'z' }) {
		return Host{}, ReasonIPLiteral
	}
	if under(h, specialUse) {
		return Host{}, ReasonSpecialUse
	}
	registrable, shared, ok := Registrable(h)
	if ok && contains(OwnDomains, registrable) {
		return Host{}, ReasonOwnDomain
	}
	if !ok {
		return Host{}, ReasonPublicSuffix
	}
	if under(h, SharedHosts) {
		return Host{}, ReasonSharedHost
	}
	return Host{Host: h, Registrable: registrable, SharedSuffix: shared}, ""
}

// CIMD is a client id that passed every step: its host's domains and its
// path.
type CIMD struct {
	Host
	Path string
}

// ParseCIMDID applies §19.5 to s and returns the client id's parts, or the
// reason it is refused.
func ParseCIMDID(s string) (CIMD, string) {
	if s == "" || len(s) > 512 || !utf8.ValidString(s) || strings.ContainsFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return CIMD{}, ReasonShape
	}
	host, path, ok := canonicalHTTPS(s)
	if !ok {
		return CIMD{}, ReasonShape
	}
	if path == "/" {
		return CIMD{}, ReasonPathRoot
	}
	h, reason := CheckHost(host)
	if reason != "" {
		return CIMD{}, reason
	}
	if !validPath(path) {
		return CIMD{}, ReasonPathChars
	}
	return CIMD{Host: h, Path: path}, ""
}

// canonicalHTTPS is step 2: s is https with no userinfo, port, query or
// fragment, and it is what a WHATWG URL parser serializes it as (the
// enclave's test is new URL(s).href === s). Every way a parser would rewrite
// a URL that could otherwise pass is refused here, so that the steps after
// this one see the same string on both sides: a backslash (a slash to
// WHATWG), a host in another case, percent-encoded, outside ASCII, an IPv4
// address in any but its dotted decimal form or an IPv6 address in any but
// its compressed form, an empty port or the default one, a missing path, a
// "." or ".." segment in any spelling, and a path character WHATWG would
// percent-encode.
func canonicalHTTPS(s string) (host, path string, ok bool) {
	rest, found := strings.CutPrefix(s, "https://")
	if !found || strings.ContainsAny(s, "?#\\") {
		return "", "", false
	}
	slash := strings.IndexByte(rest, '/')
	if slash <= 0 {
		return "", "", false
	}
	host, path = rest[:slash], rest[slash:]
	if !canonicalHost(host) || !canonicalPath(path) {
		return "", "", false
	}
	return host, path, true
}

// canonicalHost is a host WHATWG keeps as written: an IPv6 literal in its
// own serialization, or a name in lower-case ASCII without the forbidden
// code points, the percent sign, a port or userinfo, that is either not an
// IPv4 address at all or one in dotted decimal. A name WHATWG accepts may
// still fail CheckHost, which refuses it for its own reason.
func canonicalHost(host string) bool {
	if strings.HasPrefix(host, "[") {
		inner, closed := strings.CutSuffix(host[1:], "]")
		addr, err := netip.ParseAddr(inner)
		return closed && err == nil && addr.Is6() && addr.Zone() == "" && whatwgIPv6(addr) == inner
	}
	for i := 0; i < len(host); i++ {
		c := host[i]
		if c >= 0x80 || c >= 'A' && c <= 'Z' || strings.IndexByte(" #%/:<>?@[\\]^|\x7f", c) >= 0 || c < 0x20 {
			return false
		}
	}
	if !endsInNumber(host) {
		return true
	}
	// WHATWG parses a host that ends in a number as IPv4 and serializes it
	// in dotted decimal, or fails: only that form survives unchanged.
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 || strconv.Itoa(n) != p {
			return false
		}
	}
	return true
}

// endsInNumber is WHATWG's test: the last label (the one before a trailing
// dot, if any) is decimal digits or 0x followed by hex digits.
func endsInNumber(host string) bool {
	parts := strings.Split(host, ".")
	if len(parts) > 1 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	last := parts[len(parts)-1]
	if last != "" && !strings.ContainsFunc(last, func(r rune) bool { return r < '0' || r > '9' }) {
		return true
	}
	hex, isHex := strings.CutPrefix(strings.ToLower(last), "0x")
	return isHex && !strings.ContainsFunc(hex, func(r rune) bool { return (r < '0' || r > '9') && (r < 'a' || r > 'f') })
}

// whatwgIPv6 serializes an IPv6 address as WHATWG does: eight groups of
// lower-case hex without leading zeros, the first longest run of two or more
// zero groups compressed, and never a dotted IPv4 tail.
func whatwgIPv6(addr netip.Addr) string {
	raw := addr.As16()
	var groups [8]uint16
	for i := range groups {
		groups[i] = uint16(raw[2*i])<<8 | uint16(raw[2*i+1])
	}
	start, length := -1, 1
	for i := 0; i < 8; {
		if groups[i] != 0 {
			i++
			continue
		}
		j := i
		for j < 8 && groups[j] == 0 {
			j++
		}
		if j-i > length {
			start, length = i, j-i
		}
		i = j
	}
	var b strings.Builder
	for i := 0; i < 8; i++ {
		if i == start {
			b.WriteString("::")
			i += length - 1
			continue
		}
		if i > 0 && i != start+length {
			b.WriteByte(':')
		}
		b.WriteString(strconv.FormatUint(uint64(groups[i]), 16))
	}
	return b.String()
}

// canonicalPath is a path WHATWG keeps as written: no character of its path
// percent-encode set and no dot segment, which it would resolve, in any of
// its spellings.
func canonicalPath(path string) bool {
	for i := 0; i < len(path); i++ {
		if c := path[i]; c < 0x20 || c >= 0x7f || strings.IndexByte("\"<>`{} ", c) >= 0 {
			return false
		}
	}
	for _, segment := range strings.Split(path[1:], "/") {
		switch strings.ToLower(segment) {
		case ".", "%2e", "..", ".%2e", "%2e.", "%2e%2e":
			return false
		}
	}
	return true
}

// validPath is step 5.
func validPath(path string) bool {
	if len(path) < 2 || len(path) > 1024 || strings.Contains(path, "//") {
		return false
	}
	for i := 0; i < len(path); i++ {
		if !pathByte(path[i]) {
			return false
		}
	}
	for _, segment := range strings.Split(path[1:], "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	lower := strings.ToLower(path)
	return !strings.Contains(lower, "%2e") && !strings.Contains(lower, "%2f") && !strings.Contains(lower, "%5c")
}

func pathByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("._~!$&'()*+,;=:@%/-", c) >= 0
}

func hostByte(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-'
}

// under reports whether host is one of names or ends in "." and one of them.
func under(host string, names []string) bool {
	for _, name := range names {
		if host == name || strings.HasSuffix(host, "."+name) {
			return true
		}
	}
	return false
}

func contains(names []string, name string) bool {
	for _, n := range names {
		if n == name {
			return true
		}
	}
	return false
}
