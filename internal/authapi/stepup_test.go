package authapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"whatserver2/internal/stepup"
	"whatserver2/internal/store"
)

// The step-up (docs/mcp-enclave.md §19.35): a sign-in is a proof for ten
// minutes; past them the password's auth key or a passkey assertion with user
// verification, each checked here, renews it; and a content consent's service
// invitation waits for it.

type stepUpState struct {
	Fresh            bool `json:"fresh"`
	RemainingSeconds int  `json:"remaining_seconds"`
	WindowSeconds    int  `json:"window_seconds"`
	Passkey          bool `json:"passkey"`
}

func (h *harness) age(t *testing.T, token string) {
	t.Helper()
	s, err := h.users.Session(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(context.Background(), `UPDATE sessions SET authenticated_at = now() - interval '11 minutes' WHERE id=$1`, s.ID); err != nil {
		t.Fatal(err)
	}
}

func TestStepUpWithPassword(t *testing.T) {
	h := newHarness(t)
	body, _ := newAccount(t, h.invite(t, "owner"), "owner@example.com", "the-auth-key")
	var signed sessionReply
	if code := h.post(t, "/v1/auth/signup", body, &signed, ""); code != http.StatusOK {
		t.Fatalf("signup: %d", code)
	}
	var state stepUpState
	if code := h.get(t, "/v1/auth/step-up", &state, signed.Token); code != http.StatusOK || !state.Fresh || state.Passkey ||
		state.WindowSeconds != 600 || state.RemainingSeconds < 500 {
		t.Fatalf("after sign-up = %d %+v", code, state)
	}
	if code := h.get(t, "/v1/auth/step-up", &state, ""); code != http.StatusUnauthorized {
		t.Fatalf("without a session: %d", code)
	}
	provisional := map[string]any{"role": "service", "email": "", "provisional": true}
	if code := h.post(t, "/v1/auth/workspaces/invites", provisional, nil, signed.Token); code != http.StatusCreated {
		t.Fatalf("a fresh provisional invitation: %d", code)
	}

	h.age(t, signed.Token)
	if code := h.get(t, "/v1/auth/step-up", &state, signed.Token); code != http.StatusOK || state.Fresh || state.RemainingSeconds != 0 {
		t.Fatalf("eleven minutes on = %d %+v", code, state)
	}
	var refusal struct {
		Code string `json:"code"`
	}
	if code := h.post(t, "/v1/auth/workspaces/invites", provisional, &refusal, signed.Token); code != http.StatusForbidden || refusal.Code != stepup.Code {
		t.Fatalf("a stale provisional invitation: %d %+v", code, refusal)
	}
	// An ordinary invitation asks for nothing.
	if code := h.post(t, "/v1/auth/workspaces/invites", map[string]any{"role": "service", "email": ""}, nil, signed.Token); code != http.StatusCreated {
		t.Fatalf("an ordinary invitation: %d", code)
	}
	if code := h.post(t, "/v1/auth/step-up/password", map[string]string{"auth_key": "wrong"}, nil, signed.Token); code != http.StatusUnauthorized {
		t.Fatalf("a wrong password: %d", code)
	}
	if code := h.post(t, "/v1/auth/step-up/password", map[string]string{"auth_key": "the-auth-key"}, &state, signed.Token); code != http.StatusOK || !state.Fresh {
		t.Fatalf("the password = %d %+v", code, state)
	}
	if code := h.post(t, "/v1/auth/workspaces/invites", provisional, nil, signed.Token); code != http.StatusCreated {
		t.Fatalf("a provisional invitation after the step-up: %d", code)
	}
	// Passkeys are not configured here.
	if code := h.post(t, "/v1/auth/step-up/passkey/options", map[string]any{}, nil, signed.Token); code != http.StatusNotFound {
		t.Fatalf("passkey options without passkeys: %d", code)
	}
}

func TestStepUpWithPasskey(t *testing.T) {
	h := newPasskeyHarness(t)
	var state stepUpState
	if code := h.get(t, "/v1/auth/step-up", &state, h.signed.Token); code != http.StatusOK || state.Passkey {
		t.Fatalf("before a passkey = %d %+v", code, state)
	}
	if code := h.request(t, "POST", "/v1/auth/step-up/passkey/options", passkeyApp, h.signed.Token, map[string]any{}, nil); code != http.StatusConflict {
		t.Fatalf("options with no passkey: %d", code)
	}
	p, _ := h.register(t)
	if code := h.get(t, "/v1/auth/step-up", &state, h.signed.Token); code != http.StatusOK || !state.Passkey {
		t.Fatalf("after a passkey = %d %+v", code, state)
	}
	h.age(t, h.signed.Token)
	options := func(origin string) testPasskeyFlow {
		t.Helper()
		var flow testPasskeyFlow
		if code := h.request(t, "POST", "/v1/auth/step-up/passkey/options", origin, h.signed.Token, map[string]any{}, &flow); code != http.StatusOK {
			t.Fatalf("options: %d", code)
		}
		// The account's own credentials, verified, and no PRF salt to use.
		if flow.ID == "" || len(flow.PublicKey.AllowCredentials) != 1 || flow.PublicKey.UserVerification != "required" {
			t.Fatalf("options = %+v", flow)
		}
		return flow
	}
	// No user verification: refused, and the flow is spent.
	flow := options(passkeyApp)
	if code := h.request(t, "POST", "/v1/auth/step-up/passkey", passkeyApp, h.signed.Token,
		map[string]any{"flow_id": flow.ID, "credential": p.assertion(t, flow, passkeyApp, passkeyRP, 0x01, 1)}, nil); code != http.StatusUnauthorized {
		t.Fatalf("without user verification: %d", code)
	}
	if code := h.get(t, "/v1/auth/step-up", &state, h.signed.Token); code != http.StatusOK || state.Fresh {
		t.Fatalf("a refused assertion made the session fresh: %+v", state)
	}
	// Another session cannot finish this session's flow.
	flow = options(passkeyApp)
	var other sessionReply
	if code := h.post(t, "/v1/auth/login", map[string]string{"email": h.account.Email, "auth_key": h.account.AuthKey}, &other, ""); code != http.StatusOK {
		t.Fatalf("second sign-in: %d", code)
	}
	if code := h.request(t, "POST", "/v1/auth/step-up/passkey", passkeyApp, other.Token,
		map[string]any{"flow_id": flow.ID, "credential": p.assertion(t, flow, passkeyApp, passkeyRP, 0x05, 2)}, nil); code != http.StatusUnauthorized {
		t.Fatalf("another session's flow: %d", code)
	}
	// From another allowed origin than the flow's: refused.
	flow = options(passkeyApp)
	if code := h.request(t, "POST", "/v1/auth/step-up/passkey", passkeyConsole, h.signed.Token,
		map[string]any{"flow_id": flow.ID, "credential": p.assertion(t, flow, passkeyConsole, passkeyRP, 0x05, 3)}, nil); code != http.StatusUnauthorized {
		t.Fatalf("another origin: %d", code)
	}
	flow = options(passkeyApp)
	if code := h.request(t, "POST", "/v1/auth/step-up/passkey", passkeyApp, h.signed.Token,
		map[string]any{"flow_id": flow.ID, "credential": p.assertion(t, flow, passkeyApp, passkeyRP, 0x05, 4)}, &state); code != http.StatusOK || !state.Fresh {
		t.Fatalf("a verified assertion = %d %+v", code, state)
	}
	// The flow is single use.
	if code := h.request(t, "POST", "/v1/auth/step-up/passkey", passkeyApp, h.signed.Token,
		map[string]any{"flow_id": flow.ID, "credential": p.assertion(t, flow, passkeyApp, passkeyRP, 0x05, 5)}, nil); code != http.StatusUnauthorized {
		t.Fatalf("a replayed flow: %d", code)
	}
}

// The console's language reaches the account, and the profile says it.
func TestAccountLocaleRoute(t *testing.T) {
	h := newHarness(t)
	body, _ := newAccount(t, h.invite(t, "owner"), "lang@example.com", "k")
	var signed sessionReply
	if code := h.post(t, "/v1/auth/signup", body, &signed, ""); code != http.StatusOK {
		t.Fatalf("signup: %d", code)
	}
	put := func(locale string) (int, store.Profile) {
		t.Helper()
		raw, err := json.Marshal(map[string]string{"locale": locale})
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequest(http.MethodPut, h.srv.URL+"/v1/auth/locale", bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+signed.Token)
		var out store.Profile
		return h.do(t, req, &out), out
	}
	if code, out := put("de"); code != http.StatusOK || out.Locale != "de" {
		t.Fatalf("de = %d %+v", code, out)
	}
	if code, _ := put("it"); code != http.StatusBadRequest {
		t.Fatalf("it = %d", code)
	}
	var profile store.Profile
	if code := h.get(t, "/v1/auth/profile", &profile, signed.Token); code != http.StatusOK || profile.Locale != "de" {
		t.Fatalf("profile = %d %+v", code, profile)
	}
}
