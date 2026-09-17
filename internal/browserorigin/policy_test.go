package browserorigin

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExplicitOriginsAndDefaultIsolation(t *testing.T) {
	p, err := Parse("https://app.example.com,https://console.example.com:8443", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		origin  string
		allowed bool
	}{
		{"", true}, {"https://server.example.com", true}, {"https://app.example.com", true},
		{"https://console.example.com:8443", true}, {"https://console.example.com", false},
		{"http://server.example.com", false}, {"http://app.example.com", false}, {"https://app.example.com.evil.test", false},
		{"null", false}, {"https://app.example.com/path", false},
	} {
		r := httptest.NewRequest("GET", "https://server.example.com/v1/ws", nil)
		if tt.origin != "" {
			r.Header.Set("Origin", tt.origin)
		}
		if p.Allows(r) != tt.allowed {
			t.Errorf("origin %q: want %v", tt.origin, tt.allowed)
		}
	}
	r := httptest.NewRequest("GET", "https://server.example.com/v1/ws", nil)
	r.Header.Set("Origin", "https://app.example.com")
	if (Policy{}).Allows(r) {
		t.Fatal("unconfigured server accepted foreign app")
	}
}

func TestRejectUnsafeConfiguration(t *testing.T) {
	for _, raw := range []string{"*", "https://*.example.com", "http://app.example.com", "https://user:pass@app.example.com", "https://app.example.com/x", "https://app.example.com?x", "https://app.example.com#x", "null"} {
		if _, err := Parse(raw, false); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	if _, err := Parse("http://localhost:5173", true); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse("http://localhost:5173", false); err == nil {
		t.Fatal("production accepted HTTP")
	}
}

func TestPreflightDoesNotReachAPIAndCredentialsStayRequired(t *testing.T) {
	p, _ := Parse("https://app.example.com", false)
	called := 0
	h := p.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called++; w.WriteHeader(401) }))
	r := httptest.NewRequest("OPTIONS", "https://server.example.com/v1/auth/me", nil)
	r.Header.Set("Origin", "https://app.example.com")
	r.Header.Set("Access-Control-Request-Method", "GET")
	r.Header.Set("Access-Control-Request-Headers", "authorization, content-type")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 204 || called != 0 || w.Header().Get("Access-Control-Allow-Origin") != "https://app.example.com" {
		t.Fatalf("preflight: %d %v calls=%d", w.Code, w.Header(), called)
	}
	r.Method = "GET"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 || called != 1 {
		t.Fatalf("CORS bypassed API auth: %d", w.Code)
	}
	r.Header.Set("Origin", "https://evil.test")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 || called != 1 {
		t.Fatalf("foreign origin reached handler: %d", w.Code)
	}
	r.Method = "OPTIONS"
	r.Header.Set("Origin", "https://app.example.com")
	r.Header.Set("Access-Control-Request-Headers", "X-Secret-Header")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("unknown header accepted: %d", w.Code)
	}
}

func TestSameHostHTTPOnlyForDevelopmentLoopback(t *testing.T) {
	for _, tt := range []struct {
		dev  bool
		host string
		want bool
	}{{true, "localhost:8090", true}, {false, "localhost:8090", false}, {true, "app.example.com", false}} {
		p, _ := Parse("", tt.dev)
		r := httptest.NewRequest("GET", "http://"+tt.host+"/v1/ws", nil)
		r.Header.Set("Origin", "http://"+tt.host)
		if p.Allows(r) != tt.want {
			t.Fatalf("%+v", tt)
		}
	}
}
