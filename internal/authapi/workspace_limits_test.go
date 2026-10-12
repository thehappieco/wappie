package authapi_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"whatserver2/internal/authapi"
	"whatserver2/internal/ratelimit"
	"whatserver2/internal/store"
)

const switchPath = "/v1/auth/workspaces/session"

// withLimits serves h's store from a fresh handler with these budgets.
func withLimits(t *testing.T, h *harness, limits, sessions *ratelimit.Auth) *harness {
	t.Helper()
	mux := http.NewServeMux()
	(&authapi.Handler{
		Users: h.users, Keys: h.keys, Devices: store.NewDevices(h.pool),
		Limits: limits, WorkspaceSessionLimits: sessions,
	}).Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &harness{srv: srv, pool: h.pool, users: h.users, keys: h.keys, tenant: h.tenant}
}

// switcher signs a person up in h's workspace.
func switcher(t *testing.T, h *harness, email string) (signupBody, sessionReply) {
	t.Helper()
	body, _ := newAccount(t, h.invite(t, "owner"), email, "switch-proof")
	var signed sessionReply
	if code := h.post(t, "/v1/auth/signup", body, &signed, ""); code != http.StatusOK {
		t.Fatalf("signup returned %d", code)
	}
	return body, signed
}

// A person hopping between console tabs and Wappie in a workspace other
// than the one the sign-in opened, and through the workspace selector: each
// hop is a switch on the base login's token. With the production budgets
// the sixth, the tenth and the thirtieth in a minute go through, where the
// sign-in budget refused the sixth, and the switches leave that budget
// whole: five sign-ins still go through before it refuses, the account's
// e-mail being what the password step-up spends too, and its address limit,
// which every sign-in and the provider step-up's start spend, still has
// what the sign-ins left of its twenty.
func TestWorkspaceSwitchesHaveTheirOwnBudget(t *testing.T) {
	h := newHarness(t)
	body, signed := switcher(t, h, "hops@example.com")
	other := browserSecondWorkspace(t, h, signed.Token)
	limits := ratelimit.DefaultAuth(nil)
	limited := withLimits(t, h, limits, ratelimit.DefaultWorkspaceSessions(nil))

	for i := range 30 {
		target := other
		if i%2 == 1 {
			target = h.tenant
		}
		var switched sessionReply
		if code := limited.post(t, switchPath, map[string]string{"tenant_id": target.String()}, &switched, signed.Token); code != http.StatusOK {
			t.Fatalf("switch %d in a minute returned %d", i+1, code)
		}
		if switched.User.TenantID != target.String() {
			t.Fatalf("switch %d opened %s, want %s", i+1, switched.User.TenantID, target)
		}
	}

	login := map[string]string{"email": body.Email, "auth_key": body.AuthKey}
	for i := range 5 {
		if code := limited.post(t, "/v1/auth/login", login, nil, ""); code != http.StatusOK {
			t.Fatalf("sign-in %d after the switches returned %d", i+1, code)
		}
	}
	if status, retryAfter := limited.postFor(t, "/v1/auth/login", login, ""); status != http.StatusTooManyRequests || retryAfter == "" {
		t.Fatalf("a sixth sign-in: status %d, Retry-After %q; want 429 with a wait", status, retryAfter)
	}
	local := &http.Request{RemoteAddr: "127.0.0.1:1"}
	for i := range 14 {
		if ok, _ := limits.Allow(local, ""); !ok {
			t.Fatalf("the sign-in budget's address limit refused its %d of twenty", 7+i)
		}
	}
}

// The switches' budget is per account: a person who spent theirs is
// refused with a Retry-After, and another account is not held back. Its
// address limit still bounds an address that spreads switches across
// accounts.
func TestWorkspaceSwitchBudgetIsPerAccountAndPerAddress(t *testing.T) {
	h := newHarness(t)
	_, first := switcher(t, h, "first@example.com")
	_, second := switcher(t, h, "second@example.com")
	switchTo := map[string]string{"tenant_id": h.tenant.String()}

	perAccount := withLimits(t, h, nil, &ratelimit.Auth{PerIP: ratelimit.New(60, 100), PerSubject: ratelimit.New(1, 3)})
	for i := range 3 {
		if code := perAccount.post(t, switchPath, switchTo, nil, first.Token); code != http.StatusOK {
			t.Fatalf("switch %d returned %d", i+1, code)
		}
	}
	if status, retryAfter := perAccount.postFor(t, switchPath, switchTo, first.Token); status != http.StatusTooManyRequests || retryAfter == "" {
		t.Fatalf("a fourth switch: status %d, Retry-After %q; want 429 with a wait", status, retryAfter)
	}
	if code := perAccount.post(t, switchPath, switchTo, nil, second.Token); code != http.StatusOK {
		t.Fatalf("another account's switch returned %d", code)
	}

	perAddress := withLimits(t, h, nil, &ratelimit.Auth{PerIP: ratelimit.New(1, 3), PerSubject: ratelimit.New(60, 100)})
	for i, token := range []string{first.Token, second.Token, first.Token} {
		if code := perAddress.post(t, switchPath, switchTo, nil, token); code != http.StatusOK {
			t.Fatalf("switch %d from one address returned %d", i+1, code)
		}
	}
	if status, retryAfter := perAddress.postFor(t, switchPath, switchTo, second.Token); status != http.StatusTooManyRequests || retryAfter == "" {
		t.Fatalf("a fourth switch from one address: status %d, Retry-After %q; want 429 with a wait", status, retryAfter)
	}
}

// The fallback a harness without WorkspaceSessionLimits gets: the sign-in
// budget, per e-mail, as before the switches had their own.
func TestWorkspaceSwitchesFallBackToTheSignInBudget(t *testing.T) {
	h := newHarness(t)
	_, signed := switcher(t, h, "fallback-switch@example.com")
	switchTo := map[string]string{"tenant_id": h.tenant.String()}
	limited := withLimits(t, h, &ratelimit.Auth{PerIP: ratelimit.New(60, 100), PerSubject: ratelimit.New(1, 2)}, nil)
	for i := range 2 {
		if code := limited.post(t, switchPath, switchTo, nil, signed.Token); code != http.StatusOK {
			t.Fatalf("switch %d returned %d", i+1, code)
		}
	}
	if code := limited.post(t, switchPath, switchTo, nil, signed.Token); code != http.StatusTooManyRequests {
		t.Fatalf("a third switch returned %d, want 429", code)
	}
}
