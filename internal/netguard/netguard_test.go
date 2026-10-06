package netguard_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"whatserver2/internal/netguard"
)

// PSL_SHA256 pins the snapshot: the enclave's suite pins the same value for
// its copy at packages/mcp-http/psl/, so the two cannot drift apart.
const pslSHA256 = "c525730712d4db475211ced98ddac44b06e4b288e50d95b69c68adb1e4e83e80"

func TestTheSnapshotIsPinned(t *testing.T) {
	raw, err := os.ReadFile(netguard.PSLFile)
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != pslSHA256 {
		t.Fatalf("the snapshot's SHA-256 is %x, pinned %s: a refresh changes both copies and both pins", sum, pslSHA256)
	}
	// The enclave's copy is the same file, byte for byte: the three host
	// checks read one list.
	copies, err := filepath.Glob(readerPSL)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := os.ReadFile(filepath.Join("..", "..", "packages", "mcp-http", netguard.PSLFile))
	if err != nil || len(copies) != 1 || !bytes.Equal(raw, reader) {
		t.Fatalf("packages/mcp-http/psl/ holds %v, not the same bytes as %s (%v)", copies, netguard.PSLFile, err)
	}
}

// readerPSL is where the enclave's copies of the snapshot live.
var readerPSL = filepath.Join("..", "..", "packages", "mcp-http", "psl", "psl-*.json")

// Every range docs/mcp-enclave.md §19.9 refuses, at both ends, as an IPv4
// address and IPv4-mapped; and the public addresses just beside them.
func TestPublic(t *testing.T) {
	refused := []string{
		"0.0.0.0", "0.255.255.255", "10.0.0.0", "10.255.255.255", "100.64.0.0", "100.127.255.255", "127.0.0.1",
		"127.255.255.255", "169.254.0.0", "169.254.169.254", "169.254.255.255", "172.16.0.0", "172.31.255.255",
		"192.0.0.0", "192.0.0.255", "192.0.2.0", "192.0.2.255", "192.88.99.0", "192.88.99.255", "192.168.0.0",
		"192.168.255.255", "198.18.0.0", "198.19.255.255", "198.51.100.0", "198.51.100.255", "203.0.113.0",
		"203.0.113.255", "224.0.0.0", "239.255.255.255", "240.0.0.0", "254.255.255.255", "255.255.255.255",
		"::", "::1", "64:ff9b::", "64:ff9b::a9fe:a9fe", "64:ff9b:1::", "64:ff9b:1:ffff:ffff:ffff:ffff:ffff",
		"100::", "100::ffff:ffff:ffff:ffff", "2001::", "2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff", "2001:db8::",
		"2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", "2002::", "2002:a9fe:a9fe::1", "fc00::", "fd00:ec2::254",
		"fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "fe80::", "fe80::1%eth0", "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		"fec0::", "feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "ff00::", "ff02::1",
		"::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:10.0.0.1", "::ffff:0.0.0.0",
	}
	for _, s := range refused {
		if netguard.Public(netip.MustParseAddr(s)) {
			t.Errorf("%s is public", s)
		}
	}
	public := []string{
		"1.0.0.0", "8.8.8.8", "9.255.255.255", "11.0.0.0", "100.63.255.255", "100.128.0.0", "126.255.255.255",
		"128.0.0.0", "169.253.255.255", "169.255.0.0", "172.15.255.255", "172.32.0.0", "192.0.1.0", "192.0.3.0",
		"192.88.98.255", "192.88.100.0", "192.167.255.255", "192.169.0.0", "198.17.255.255", "198.20.0.0",
		"198.51.99.255", "198.51.101.0", "203.0.112.255", "203.0.114.0", "223.255.255.255",
		"64:ff9a:ffff:ffff:ffff:ffff:ffff:ffff", "64:ff9b:0:1::", "100:0:0:1::", "2001:200::", "2001:4860:4860::8888",
		"2001:db9::", "2003::", "2606:4700:4700::1111", "fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		"::ffff:8.8.8.8",
	}
	for _, s := range public {
		if !netguard.Public(netip.MustParseAddr(s)) {
			t.Errorf("%s is not public", s)
		}
	}
	if netguard.Public(netip.Addr{}) {
		t.Error("the zero address is public")
	}
}

func TestRegistrable(t *testing.T) {
	for host, want := range map[string][2]string{
		"example.com":                    {"example.com", ""},
		"www.example.com":                {"example.com", ""},
		"www.example.co.uk":              {"example.co.uk", ""},
		"team.github.io":                 {"team.github.io", "github.io"},
		"docs.team.github.io":            {"team.github.io", "github.io"},
		"bucket.s3.amazonaws.com":        {"bucket.s3.amazonaws.com", "s3.amazonaws.com"},
		"x.y.compute.amazonaws.com":      {"x.y.compute.amazonaws.com", "y.compute.amazonaws.com"},
		"www.ck":                         {"www.ck", ""},
		"a.www.ck":                       {"www.ck", ""},
		"foo.bar.ck":                     {"foo.bar.ck", ""},
		"example.unlistedtld":            {"example.unlistedtld", ""},
		"raw.githubusercontent.com":      {"raw.githubusercontent.com", "githubusercontent.com"},
		"city.kawasaki.jp":               {"city.kawasaki.jp", ""},
		"example.xn--p1ai":               {"example.xn--p1ai", ""},
		"wappie.thehappie.co":            {"thehappie.co", ""},
		"a.b.c.d.example.com.br":         {"example.com.br", ""},
		"thehappieco.github.io":          {"thehappieco.github.io", "github.io"},
		"claude.ai.attacker.example.net": {"example.net", ""},
	} {
		registrable, shared, ok := netguard.Registrable(host)
		if !ok || registrable != want[0] || shared != want[1] {
			t.Errorf("%s: %q %q %v, want %q %q", host, registrable, shared, ok, want[0], want[1])
		}
	}
	for _, suffix := range []string{"com", "co.uk", "github.io", "s3.amazonaws.com", "foo.ck", "x.kawasaki.jp", "x.compute.amazonaws.com"} {
		if registrable, _, ok := netguard.Registrable(suffix); ok {
			t.Errorf("%s is a public suffix, got registrable %q", suffix, registrable)
		}
	}
}

// vector is one entry of the CIMD-id vectors.
type vector struct {
	ID           string  `json:"id"`
	OK           bool    `json:"ok"`
	Host         string  `json:"host"`
	Registrable  string  `json:"registrable"`
	SharedSuffix *string `json:"shared_suffix"`
	Reason       string  `json:"reason"`
}

func runVectors(t *testing.T, path string) int {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var vectors []vector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	reasons := map[string]bool{}
	for _, v := range vectors {
		got, reason := netguard.ParseCIMDID(v.ID)
		if !v.OK {
			reasons[v.Reason] = true
			if reason != v.Reason {
				t.Errorf("%q: reason %q, want %q", v.ID, reason, v.Reason)
			}
			continue
		}
		shared := ""
		if v.SharedSuffix != nil {
			shared = *v.SharedSuffix
		}
		if reason != "" || got.Host.Host != v.Host || got.Registrable != v.Registrable || got.SharedSuffix != shared {
			t.Errorf("%q: %+v %q, want %s %s %q", v.ID, got, reason, v.Host, v.Registrable, shared)
		}
		// What passes the whole algorithm passes the host predicate the
		// egress proxy applies alone.
		if h, reason := netguard.CheckHost(v.Host); reason != "" || h != got.Host {
			t.Errorf("%q: the host alone %+v %q", v.ID, h, reason)
		}
	}
	for _, r := range []string{netguard.ReasonShape, netguard.ReasonPathRoot, netguard.ReasonHostChars, netguard.ReasonHostLabels,
		netguard.ReasonIPLiteral, netguard.ReasonSpecialUse, netguard.ReasonOwnDomain, netguard.ReasonPublicSuffix,
		netguard.ReasonSharedHost, netguard.ReasonPathChars} {
		if !reasons[r] {
			t.Errorf("%s: no vector refused for %s", path, r)
		}
	}
	return len(vectors)
}

// The shared vectors the enclave and the egress proxy run too
// (docs/mcp-enclave.md §19.5): one file, packages/mcp-http/test/vectors/,
// so the three host checks cannot disagree.
func TestCIMDIDVectors(t *testing.T) {
	path := filepath.Join("..", "..", "packages", "mcp-http", "test", "vectors", "cimd-ids.json")
	if n := runVectors(t, path); n < 200 {
		t.Fatalf("only %d vectors", n)
	}
}

// The host predicate on its own, as the egress proxy applies it to a
// CONNECT target.
func TestCheckHost(t *testing.T) {
	for host, reason := range map[string]string{
		"example.com": "", "thehappieco.github.io": "", "github.io": netguard.ReasonPublicSuffix,
		"EXAMPLE.com": netguard.ReasonHostChars, "127.0.0.1": netguard.ReasonIPLiteral, "localhost": netguard.ReasonHostLabels,
		"metadata.google.internal": netguard.ReasonSpecialUse, "169.254.169.254.nip.io": "", "api.wappie.thehappie.co": netguard.ReasonOwnDomain,
		"bucket.s3.amazonaws.com": netguard.ReasonSharedHost, "example.com:443": netguard.ReasonHostChars, "": netguard.ReasonHostChars,
	} {
		if _, got := netguard.CheckHost(host); got != reason {
			t.Errorf("%q: %q, want %q", host, got, reason)
		}
	}
}
