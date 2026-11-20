package mcpauth_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"whatserver2/internal/access"
	"whatserver2/internal/store"
	"whatserver2/internal/tokentest"
)

// liveToken is a platform token of the harness's workspace, live, with
// perms on its number: the strongest text a route could mistake for its
// connection's key.
func liveToken(t *testing.T, h *attestedHarness, perms []tokentest.Perm) *tokentest.Token {
	t.Helper()
	w := tokentest.New(t, h.pool, h.tenant)
	tok := w.Token(perms...)
	c := &access.Checker{Keys: store.NewAPIKeys(h.pool), Users: w.Users, Tokens: w.Tokens}
	if a, err := c.Authenticate(context.Background(), tok.Text); err != nil || !a.IsToken() || a.Tenant != h.tenant {
		t.Fatalf("the token is not live: %+v %v", a, err)
	}
	return tok
}

// tokenPerms are Send and Manage on the harness's number. (Read would need
// the token's creator to read it here too.)
func tokenPerms(h *attestedHarness) []tokentest.Perm {
	return []tokentest.Perm{tokentest.Send(h.device), tokentest.Manage(h.device)}
}

// TestAThcTokenNeverReachesMCP (the plan's 3.2): the enclave's send and AI
// routes take only their connection's own key as the bearer, through
// VerifyScoped, which never reads a thc_ text as a key. A live token of the
// connection's workspace, with Send and Manage on its number, in any case,
// gets what a wrong key gets: not_found, and nothing is sent or read.
func TestAThcTokenNeverReachesMCP(t *testing.T) {
	t.Run("send", func(t *testing.T) {
		h := newSendHarness(t)
		c := h.consentSending(t, h.ownerToken, nil)
		tok := liveToken(t, h.attestedHarness, tokenPerms(h.attestedHarness))
		for _, text := range []string{tok.Text, strings.ToUpper(tok.Text[:4]) + tok.Text[4:]} {
			expect(t, h.asConnection(t, http.MethodPost, "/v1/mcp/enclave/connections/"+c.id+"/send", text,
				map[string]any{"client_ref": clientRef(), "kind": "self", "device_id": h.device.String(), "text": "x"}), http.StatusNotFound, "not_found")
			expect(t, h.draft(t, sending{id: c.id, key: text}, friend, nil), http.StatusNotFound, "not_found")
			expect(t, h.asConnection(t, http.MethodGet, "/v1/mcp/enclave/connections/"+c.id+"/outbound", text, nil), http.StatusNotFound, "not_found")
		}
		if sent := h.sender.sent(); len(sent) != 0 {
			t.Fatalf("a token's send reached the sender: %+v", sent)
		}
		expect(t, h.selfSend(t, c, clientRef(), "x"), http.StatusOK, "")
	})
	t.Run("AI", func(t *testing.T) {
		h := newAIHarness(t)
		aiID, ac := h.consentAI(t, h.owner, nil)
		tok := liveToken(t, h.attestedHarness, tokenPerms(h.attestedHarness))
		month := "/v1/mcp/enclave/connections/" + aiID + "/ai/usage?month=" + time.Now().UTC().Format("2006-01")
		for _, text := range []string{tok.Text, strings.ToUpper(tok.Text[:4]) + tok.Text[4:]} {
			expect(t, h.asRow(t, http.MethodGet, month, text, nil), http.StatusNotFound, "not_found")
			expect(t, h.asRow(t, http.MethodGet, "/v1/mcp/enclave/connections/"+aiID+"/ai?device_id="+h.device.String()+"&feature=audio", text, nil),
				http.StatusNotFound, "not_found")
		}
		expect(t, h.asRow(t, http.MethodGet, month, ac.key, nil), http.StatusOK, "")
	})
}
