package ratelimit

import (
	"net/http"
	"net/netip"
	"strconv"
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

// clock sets one fake clock on every limiter of a, so a test controls the
// time each bucket refills by.
func clock(a *Auth, now *time.Time) {
	for _, l := range []*Limiter{a.PerIP, a.PerSubject} {
		l.now = func() time.Time { return *now }
	}
}

// A Renew all right after a console reload: the reload's workspace switches
// and the step-up spend the sign-in budget, and each renewal's provisional
// service invitation and its completion spend the setups' own, per account
// and per address; the service's sign-up between them stays on the sign-in
// budget's address limit. Ten renewals and a few AI integrations at the same
// instant all go through, the setups' budget refuses past its thirty, and the
// sign-in budget is what it was.
func TestRenewAllOfTenAfterWorkspaceSwitches(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	auth, setups := DefaultAuth(nil), DefaultSetups(nil)
	clock(auth, &now)
	clock(setups, &now)
	r := &http.Request{RemoteAddr: "203.0.113.7:4242"}
	const email, account = "owner@example.test", "018f3a2b-2222-7000-8000-00000000aaaa"

	// Four switches and a step-up: the account's sign-in budget is gone.
	for i := range 5 {
		if ok, _ := auth.Allow(r, email); !ok {
			t.Fatalf("switch or step-up %d was refused", i+1)
		}
	}
	if ok, wait := auth.Allow(r, email); ok || wait <= 0 {
		t.Fatalf("a sixth sign-in-budget request = %v, %v; want refused with a wait", ok, wait)
	}

	// Ten renewals, then four AI integrations: an invitation, the service's
	// sign-up (address only) and the completion each.
	for i := range 14 {
		if ok, _ := setups.Allow(r, account); !ok {
			t.Fatalf("setup %d: the invitation was refused", i+1)
		}
		if ok, _ := auth.Allow(r, ""); !ok {
			t.Fatalf("setup %d: the service's sign-up was refused", i+1)
		}
		if ok, _ := setups.Allow(r, account); !ok {
			t.Fatalf("setup %d: the completion was refused", i+1)
		}
	}
	// Two left of thirty, then a refusal that says when to come back.
	for range 2 {
		if ok, _ := setups.Allow(r, account); !ok {
			t.Fatal("the budget refused before its thirty")
		}
	}
	ok, wait := setups.Allow(r, account)
	if ok {
		t.Fatal("a thirty-first setup request in the same instant was allowed")
	}
	if wait < 12*time.Second || wait > 14*time.Second {
		t.Fatalf("retry-after = %v, want the twelve seconds a token takes at five a minute", wait)
	}
	// Another account has its own thirty.
	if ok, _ := setups.Allow(r, "018f3a2b-2222-7000-8000-00000000bbbb"); !ok {
		t.Fatal("another account was refused because of the first")
	}

	// The sign-in budget is unchanged: still spent for the account, five a
	// minute, and twenty per address of which the switches, the refusal and
	// the sign-ups took twenty.
	if ok, _ := auth.Allow(r, ""); ok {
		t.Fatal("the address limit of the sign-in budget grew")
	}
	now = now.Add(12 * time.Second)
	if ok, _ := auth.Allow(&http.Request{RemoteAddr: "198.51.100.2:1"}, email); !ok {
		t.Fatal("twelve seconds on, the sign-in budget has no token back")
	}
	if ok, _ := auth.Allow(&http.Request{RemoteAddr: "198.51.100.3:1"}, email); ok {
		t.Fatal("and should have only one")
	}
	if ok, _ := setups.Allow(r, account); !ok {
		t.Fatal("twelve seconds on, the setups' budget has no token back")
	}
}

// The setups' address limit is their own and roomier than the sign-in one,
// but it still bounds an address that spreads setups across accounts.
func TestSetupsAreBoundedPerAddress(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	setups := DefaultSetups(nil)
	clock(setups, &now)
	r := &http.Request{RemoteAddr: "203.0.113.7:4242"}
	for i := range 60 {
		if ok, _ := setups.Allow(r, "account-"+strconv.Itoa(i)); !ok {
			t.Fatalf("setup %d from one address was refused", i+1)
		}
	}
	if ok, wait := setups.Allow(r, "account-61"); ok || wait <= 0 {
		t.Fatalf("the sixty-first from one address = %v, %v; want refused with a wait", ok, wait)
	}
	if ok, _ := setups.Allow(&http.Request{RemoteAddr: "198.51.100.2:1"}, "account-61"); !ok {
		t.Fatal("another address was refused because of the first")
	}
}
