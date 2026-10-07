package authapi_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"whatserver2/internal/authapi"
	"whatserver2/internal/ratelimit"
	"whatserver2/internal/store"
)

// A Renew all right after a console reload: the reload's workspace switches
// spend the account's sign-in budget, and each renewal's provisional service
// invitation spends the setups' own (ratelimit.DefaultSetups), which the
// switches never touch, while an ordinary invitation, which may send an
// e-mail, stays on the sign-in budget. The production budgets, over HTTP.
func TestProvisionalInvitationsHaveTheirOwnBudget(t *testing.T) {
	h := newHarness(t)
	body, _ := newAccount(t, h.invite(t, "owner"), "renews@example.com", "auth")
	var signed sessionReply
	if code := h.post(t, "/v1/auth/signup", body, &signed, ""); code != http.StatusOK {
		t.Fatalf("signup returned %d", code)
	}

	// A fresh handler with the production budgets, on the same store.
	mux := http.NewServeMux()
	(&authapi.Handler{
		Users: h.users, Keys: h.keys, Devices: store.NewDevices(h.pool),
		Limits: ratelimit.DefaultAuth(nil), SetupLimits: ratelimit.DefaultSetups(nil),
	}).Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	limited := &harness{srv: srv, pool: h.pool, users: h.users, keys: h.keys, tenant: h.tenant}
	refused := func(what string, path string, payload any) {
		t.Helper()
		status, retryAfter := limited.postFor(t, path, payload, signed.Token)
		if status != http.StatusTooManyRequests || retryAfter == "" {
			t.Fatalf("%s: status %d, Retry-After %q; want 429 with a wait", what, status, retryAfter)
		}
	}

	// Five switches spend the sign-in budget; the sixth is refused, as before.
	switchTo := map[string]string{"tenant_id": h.tenant.String()}
	for i := range 5 {
		if code := limited.post(t, "/v1/auth/workspaces/session", switchTo, nil, signed.Token); code != http.StatusOK {
			t.Fatalf("switch %d returned %d", i+1, code)
		}
	}
	refused("a sixth switch", "/v1/auth/workspaces/session", switchTo)

	// Ordinary invitations still spend the sign-in budget, which the
	// switches emptied, while the setups' is still whole: refused, an
	// e-mail invitation as much as a service's, and neither spends a setup.
	refused("an e-mail invitation", "/v1/auth/workspaces/invites", map[string]any{"role": "member", "email": "colleague@example.com"})
	refused("an ordinary service invitation", "/v1/auth/workspaces/invites", map[string]any{"role": "service", "email": ""})

	// Fifteen provisional invitations go through: the setups' whole
	// invitation bucket, Renew all of ten and a few AI integrations. In
	// production each setup's completion at the connector (internal/mcpauth)
	// spends a bucket of its own.
	provisional := map[string]any{"role": "service", "email": "", "provisional": true}
	for i := range 15 {
		if code := limited.post(t, "/v1/auth/workspaces/invites", provisional, nil, signed.Token); code != http.StatusCreated {
			t.Fatalf("provisional invitation %d returned %d", i+1, code)
		}
	}
	// The sixteenth is past the setups' budget.
	refused("a sixteenth provisional invitation", "/v1/auth/workspaces/invites", provisional)
}

// postFor posts as post does and answers the status and the Retry-After.
func (h *harness) postFor(t *testing.T, path string, body any, token string) (int, string) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, h.srv.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	//nolint:errcheck // the status and headers are what matter
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode, resp.Header.Get("Retry-After")
}

// The fallback a harness without SetupLimits gets: the sign-in budget, as
// before the setups had their own.
func TestProvisionalInvitationsFallBackToTheSignInBudget(t *testing.T) {
	h := newHarness(t)
	body, _ := newAccount(t, h.invite(t, "owner"), "fallback@example.com", "auth")
	var signed sessionReply
	if code := h.post(t, "/v1/auth/signup", body, &signed, ""); code != http.StatusOK {
		t.Fatalf("signup returned %d", code)
	}
	mux := http.NewServeMux()
	(&authapi.Handler{
		Users: h.users, Keys: h.keys, Devices: store.NewDevices(h.pool),
		Limits: &ratelimit.Auth{PerIP: ratelimit.New(60, 100), PerSubject: ratelimit.New(1, 2)},
	}).Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	limited := &harness{srv: srv, pool: h.pool, users: h.users, keys: h.keys, tenant: h.tenant}
	provisional := map[string]any{"role": "service", "email": "", "provisional": true}
	for i := range 2 {
		if code := limited.post(t, "/v1/auth/workspaces/invites", provisional, nil, signed.Token); code != http.StatusCreated {
			t.Fatalf("provisional invitation %d returned %d", i+1, code)
		}
	}
	if code := limited.post(t, "/v1/auth/workspaces/invites", provisional, nil, signed.Token); code != http.StatusTooManyRequests {
		t.Fatalf("a third provisional invitation returned %d, want 429", code)
	}
}
