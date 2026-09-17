// Package browserorigin authorizes browser origins independently of API credentials.
// Non-browser clients still authenticate normally and need no Origin header.
package browserorigin

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

type Policy struct {
	Origins        []string
	AllowLocalHTTP bool
}

func Parse(raw string, allowLocalHTTP bool) (Policy, error) {
	p := Policy{AllowLocalHTTP: allowLocalHTTP}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		u, err := originURL(entry)
		if err != nil {
			return Policy{}, err
		}
		localHTTP := allowLocalHTTP && u.Scheme == "http" && loopback(u.Hostname())
		if u.Scheme != "https" && !localHTTP {
			return Policy{}, fmt.Errorf("browser origin must use HTTPS: %q", entry)
		}
		canonical := u.Scheme + "://" + strings.ToLower(u.Host)
		if !slices.Contains(p.Origins, canonical) {
			p.Origins = append(p.Origins, canonical)
		}
	}
	return p, nil
}

func originURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(raw, "*\\ \t\r\n,#") {
		return nil, fmt.Errorf("invalid exact browser origin %q", raw)
	}
	return u, nil
}

func loopback(host string) bool {
	ip := net.ParseIP(host)
	return host == "localhost" || (ip != nil && ip.IsLoopback())
}

func (p Policy) Allows(r *http.Request) bool {
	values := r.Header.Values("Origin")
	if len(values) == 0 {
		return true
	}
	if len(values) != 1 {
		return false
	}
	u, err := originURL(values[0])
	if err != nil {
		return false
	}
	// Production browser documents use HTTPS, including behind TLS termination.
	// A same host with an HTTP Origin is still a different, untrusted origin.
	// Development permits cleartext only on explicitly enabled loopback hosts.
	if strings.EqualFold(u.Host, r.Host) {
		return u.Scheme == "https" || (p.AllowLocalHTTP && loopback(u.Hostname()))
	}
	return slices.Contains(p.Origins, u.Scheme+"://"+strings.ToLower(u.Host))
}

func (p Policy) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v1/") && r.URL.Path != "/.well-known/wappie" {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Add("Vary", "Origin")
		if !p.Allows(r) {
			http.Error(w, "browser origin is not allowed", http.StatusForbidden)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Expose-Headers", "Content-Range, Accept-Ranges, ETag")
			if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
				w.Header().Add("Vary", "Access-Control-Request-Method")
				w.Header().Add("Vary", "Access-Control-Request-Headers")
				if !slices.Contains([]string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}, r.Header.Get("Access-Control-Request-Method")) {
					http.Error(w, "method is not allowed", http.StatusForbidden)
					return
				}
				for _, h := range strings.Split(r.Header.Get("Access-Control-Request-Headers"), ",") {
					if !slices.Contains([]string{"", "authorization", "content-type", "range", "if-match", "if-none-match", "idempotency-key"}, strings.ToLower(strings.TrimSpace(h))) {
						http.Error(w, "header is not allowed", http.StatusForbidden)
						return
					}
				}
				w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, POST, PUT, PATCH, DELETE")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Range, If-Match, If-None-Match, Idempotency-Key")
				w.Header().Set("Access-Control-Max-Age", "600")
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
