// Package netguard decides where this code may connect on someone else's
// say: which addresses are public, and which strings are client ids a
// document may be fetched from (docs/mcp-enclave.md §19.5, §19.9).
//
// Three callers share it, so that they never disagree: the media fetcher,
// whose URLs arrive inside messages; the MCP consent check in
// internal/mcpauth, which holds a reader's descriptor to the same host rules
// the reader applied; and cmd/cimd-egress, the parent's proxy through which
// the enclave fetches client metadata documents. The enclave runs the same
// algorithm in packages/mcp-http/cimd.mjs over the same Public Suffix List
// snapshot, and all three test suites read the same vectors.
package netguard

import "net/netip"

// refused are the address ranges no fetch on someone else's say may reach:
// this network and the private ones, loopback, link-local (the instance
// metadata service among them), shared address space, documentation and
// benchmarking, IETF assignments, 6to4 relays and the 6to4 and Teredo
// tunnels, NAT64, unique local addresses (EC2's own fd00:ec2::/32 among
// them), multicast, reserved space and the broadcast address.
var refused = func() []netip.Prefix {
	var out []netip.Prefix
	for _, p := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
		"::/128", "::1/128", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32",
		"2002::/16", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
	} {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}()

// Public reports whether an address is one a fetch on someone else's say may
// connect to. An IPv4-mapped IPv6 address is judged as the IPv4 address it
// carries, and a zone is ignored: a link-local address is refused with or
// without one.
func Public(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap().WithZone("")
	for _, p := range refused {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}
