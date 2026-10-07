package mcpauth_test

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"whatserver2/internal/mcpauth"
	"whatserver2/internal/ratelimit"
)

// The connector's steps of an assistant setup (the consent, a renewal, a
// token's bundle) spend the setups' budget, per account and shared with the
// provisional service invitation each asked for first, and not the sign-in
// budget, which a console reload's workspace switches and step-up spend. A
// Renew all of ten and a few AI integrations go through after it is gone;
// past the setups' thirty, 429 with a Retry-After.
func TestSetupsSpendTheirOwnBudget(t *testing.T) {
	h := newHarness(t)
	limits, setups := ratelimit.DefaultAuth(nil), ratelimit.DefaultSetups(nil)
	h.mux = http.NewServeMux()
	(&mcpauth.Handler{
		Connections: h.conns, APIKeys: h.keys, Users: h.users,
		Reader: mcpauth.NewRelay(h.reader.srv.URL, relaySecret), PublicOrigin: publicOrigin, RelaySecret: relaySecret,
		RedirectHosts: []string{"claude.ai", "chatgpt.com"}, Log: slog.New(slog.DiscardHandler),
		Limits: limits, SetupLimits: setups,
	}).Mount(h.mux)
	h.srv.Close()
	h.srv = httptest.NewServer(h.mux)
	t.Cleanup(h.srv.Close)
	owner := h.session(t, h.owner)
	account := h.owner.ID.String()
	local := &http.Request{RemoteAddr: "127.0.0.1:1"}

	// The sign-in budget of this account is gone, under the key these
	// routes spent it by before.
	for range 5 {
		limits.Allow(local, account)
	}
	if ok, _ := limits.Allow(local, account); ok {
		t.Fatal("the sign-in budget should be spent")
	}

	// Each step reaches its own checks (the empty bodies are refused there),
	// never the limiter's 429.
	steps := map[string]string{
		"renewal": "/v1/mcp/connections/" + uuid.NewString() + "/renew",
		"consent": "/v1/mcp/connections",
		"token":   "/v1/mcp/token-requests/x/bundle",
	}
	step := func(name string) {
		t.Helper()
		if r := h.call(t, http.MethodPost, steps[name], map[string]any{}, bearer(owner)); r.status == http.StatusTooManyRequests {
			t.Fatalf("a %s was refused by a rate limit: %s", name, r.body)
		}
	}
	invitation := func() {
		t.Helper()
		// What the provisional invitation spent at /v1/auth (internal/authapi).
		if ok, _ := setups.Allow(local, account); !ok {
			t.Fatal("a provisional invitation was refused")
		}
	}
	for range 10 {
		invitation()
		step("renewal")
	}
	for range 4 { // a few AI integrations
		invitation()
		step("consent")
	}
	invitation()
	step("token")

	// Thirty spent: the next step is refused, and says when to retry.
	req, err := http.NewRequest(http.MethodPost, h.srv.URL+steps["renewal"], nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+owner)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("a thirty-first setup step: status %d, Retry-After %q", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	// The sign-in budget is still spent: the steps neither used nor refilled it.
	if ok, _ := limits.Allow(local, account); ok {
		t.Fatal("the sign-in budget has a token back")
	}
}
