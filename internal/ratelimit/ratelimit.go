// Package ratelimit bounds how often one caller may try something.
//
// It exists for the authentication paths. Each sign-in attempt runs Argon2id
// on the server — 19 MiB and a few milliseconds — which is cheap for a person
// and free for a script that tries a password list against every address it
// can think of. Without a limit that script gets unmetered guesses and, run
// wide enough, a memory-exhaustion attack for the price of a few thousand
// requests a second.
//
// Token buckets, in memory, per key. One instance, so a deployment with more
// than one process has independent limits per process; the number to divide
// by is small and the alternative is a shared store on the sign-in path.
package ratelimit

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Limiter allows a burst and then a steady rate, per key.
type Limiter struct {
	rate  float64 // tokens per second
	burst float64

	mu      sync.Mutex
	buckets map[string]*bucket
	swept   time.Time
	now     func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// New builds a limiter that admits burst attempts at once and perMinute
// thereafter, per key.
func New(perMinute, burst int) *Limiter {
	if perMinute < 1 {
		perMinute = 1
	}
	if burst < 1 {
		burst = 1
	}
	return &Limiter{
		rate:    float64(perMinute) / 60,
		burst:   float64(burst),
		buckets: map[string]*bucket{},
		now:     time.Now,
	}
}

// Allow spends one token for key. When it cannot, it says how long until it
// could, which is what a Retry-After header wants.
func (l *Limiter) Allow(key string) (ok bool, retryAfter time.Duration) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	l.sweep(now)
	b, found := l.buckets[key]
	if !found {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
	return false, wait.Round(time.Second) + time.Second
}

// sweep forgets keys that have been quiet long enough to be full again, so
// the map does not grow with every address that ever tried once.
func (l *Limiter) sweep(now time.Time) {
	if now.Sub(l.swept) < time.Minute {
		return
	}
	l.swept = now
	full := time.Duration(l.burst / l.rate * float64(time.Second))
	for key, b := range l.buckets {
		if now.Sub(b.last) > full {
			delete(l.buckets, key)
		}
	}
}

// ClientIP is the address to limit on.
//
// The connection's own address, unless the connection came from a proxy the
// deployment has named in trusted: then the last hop before that proxy, from
// X-Forwarded-For. Trusting the header from anywhere else would let a caller
// pick a fresh "address" per request and the limit would bound nothing.
func ClientIP(r *http.Request, trusted []netip.Prefix) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	peer = peer.Unmap()
	if !within(peer, trusted) {
		return peer.String()
	}
	// Walk the chain from the right: the rightmost address not belonging to
	// a trusted proxy is the client. Anything to its left was written by
	// whoever sent the request and is not evidence.
	hops := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		addr = addr.Unmap()
		if !within(addr, trusted) {
			return addr.String()
		}
	}
	return peer.String()
}

func within(addr netip.Addr, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// Auth is what an authentication endpoint applies: one limit per address and
// a tighter one per subject (an email, a key prefix), so a single script
// cannot spread its guesses across addresses it does not control, and one
// account cannot be hammered from many.
//
// A nil *Auth allows everything, so a test harness or a headless deployment
// need not build one.
type Auth struct {
	PerIP      *Limiter
	PerSubject *Limiter
	// Proxies are the addresses whose X-Forwarded-For is believed.
	Proxies []netip.Prefix
}

// DefaultAuth is the production setting: generous per address, because a
// NAT hides a whole office behind one, and tight per subject, because a
// person mistypes a password a few times and a script tries thousands.
func DefaultAuth(proxies []netip.Prefix) *Auth {
	return &Auth{
		PerIP:      New(60, 20),
		PerSubject: New(5, 5),
		Proxies:    proxies,
	}
}

// Allow spends a token for the request's address and, when subject is not
// empty, for the subject too. Both must have one.
func (a *Auth) Allow(r *http.Request, subject string) (ok bool, retryAfter time.Duration) {
	if a == nil {
		return true, 0
	}
	if a.PerIP != nil {
		if ok, wait := a.PerIP.Allow("ip:" + ClientIP(r, a.Proxies)); !ok {
			return false, wait
		}
	}
	if subject != "" && a.PerSubject != nil {
		if ok, wait := a.PerSubject.Allow("subject:" + strings.ToLower(strings.TrimSpace(subject))); !ok {
			return false, wait
		}
	}
	return true, 0
}
