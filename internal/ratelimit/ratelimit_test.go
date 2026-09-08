package ratelimit

import (
	"net/http"
	"net/netip"
	"testing"
	"time"
)

func TestABurstThenASteadyRate(t *testing.T) {
	l := New(60, 3) // one a second after the first three
	now := time.Unix(1_700_000_000, 0)
	l.now = func() time.Time { return now }

	for i := range 3 {
		if ok, _ := l.Allow("a"); !ok {
			t.Fatalf("attempt %d of the burst was refused", i+1)
		}
	}
	ok, wait := l.Allow("a")
	if ok {
		t.Fatal("the fourth attempt in the same instant was allowed")
	}
	if wait < time.Second || wait > 3*time.Second {
		t.Fatalf("retry-after = %v, want about a second or two", wait)
	}
	// Another key is another bucket.
	if ok, _ := l.Allow("b"); !ok {
		t.Fatal("a different key was refused because of the first")
	}
	now = now.Add(time.Second)
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("a second later there should be one token back")
	}
	if ok, _ := l.Allow("a"); ok {
		t.Fatal("and only one")
	}
}

func TestQuietKeysAreForgotten(t *testing.T) {
	l := New(60, 2)
	now := time.Unix(1_700_000_000, 0)
	l.now = func() time.Time { return now }
	l.Allow("gone")
	now = now.Add(5 * time.Minute)
	l.Allow("here")
	if _, found := l.buckets["gone"]; found {
		t.Fatal("a key quiet for five minutes is still in the map")
	}
}

func TestClientIPTrustsOnlyNamedProxies(t *testing.T) {
	trusted := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("192.168.1.5/32"),
	}
	req := func(remote, xff string) *http.Request {
		r := &http.Request{RemoteAddr: remote, Header: http.Header{}}
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}
	cases := []struct {
		name    string
		r       *http.Request
		trusted []netip.Prefix
		want    string
	}{
		{"direct", req("203.0.113.9:4242", "198.51.100.1"), trusted, "203.0.113.9"},
		{"through a trusted proxy", req("10.1.2.3:80", "198.51.100.1"), trusted, "198.51.100.1"},
		{"two trusted hops", req("10.1.2.3:80", "198.51.100.1, 192.168.1.5"), trusted, "198.51.100.1"},
		{"header from an untrusted peer is ignored", req("203.0.113.9:1", "1.1.1.1"), trusted, "203.0.113.9"},
		{"no proxies configured", req("10.1.2.3:80", "198.51.100.1"), nil, "10.1.2.3"},
		{"ipv6 mapped", req("[::ffff:203.0.113.9]:1", ""), trusted, "203.0.113.9"},
		{"garbage header falls back to the peer", req("10.1.2.3:80", "not-an-ip"), trusted, "10.1.2.3"},
	}
	for _, c := range cases {
		if got := ClientIP(c.r, c.trusted); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
