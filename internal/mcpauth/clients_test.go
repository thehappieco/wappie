package mcpauth_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/browserorigin"
	"whatserver2/internal/mailer"
	"whatserver2/internal/mcpauth"
	"whatserver2/internal/ratelimit"
	"whatserver2/internal/store"
)

// Any MCP client on Go's side (docs/mcp-enclave.md §19.21, §19.22): consents
// to a reader that describes its client in a version-2 descriptor, the
// switches, the notice precondition and the caps; the list's new members
// and the seen mark; the notice on activation and on a budget hit, its
// e-mail and its revoke-only link; console tokens; and the attested live
// list. The enclave is the fake on the far side of the signed relay.

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// mailbox records the notice e-mails instead of sending them.
type mailbox struct {
	mu   sync.Mutex
	sent []sentMail
	fail bool
}

type sentMail struct {
	to string
	n  mailer.MCPNotice
}

func (m *mailbox) send(_ context.Context, to string, n mailer.MCPNotice) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return errors.New("the mail server is down")
	}
	m.sent = append(m.sent, sentMail{to, n})
	return nil
}

func (m *mailbox) mails() []sentMail {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]sentMail(nil), m.sent...)
}

// clientsHarness is the attested harness with WS_MCP_CIMD_MODE=any, the
// default DCR hosts, a notice origin and a mailbox.
type clientsHarness struct {
	*attestedHarness
	mail       *mailbox
	ownerToken string
}

const noticeOrigin = "https://api.example.test"

func newClientsHarness(t *testing.T) *clientsHarness {
	t.Helper()
	h := &clientsHarness{attestedHarness: newAttestedHarness(t), mail: &mailbox{}}
	h.handler.UnknownAllowed = true
	h.handler.DCRHosts = []string{"claude.ai", "claude.com", "chatgpt.com"}
	h.handler.MailNotice = h.mail.send
	h.handler.NoticeOrigin = noticeOrigin
	h.ownerToken = h.session(t, h.owner)
	t.Cleanup(h.handler.WaitNotices)
	return h
}

// verify records that a person's address was confirmed at sign-up.
func (h *clientsHarness) verify(t *testing.T, user store.User) {
	t.Helper()
	sum := sha256.Sum256(randomBytes(t, 16))
	if _, err := h.pool.Exec(context.Background(), `INSERT INTO email_signup_verifications (token_hash, email, expires_at, completed_at)
		VALUES ($1, $2, now(), now())`, sum[:], user.Email); err != nil {
		t.Fatal(err)
	}
}

// The clients a 0.6.0 reader describes, as pendingV2 overrides: an untested
// client is pendingV2's default.
var (
	testedWeb = map[string]any{
		"client_kind": "dcr", "client_id": "dcr-4f2a9c", "tested_id": "claude_dcr", "client_host": "claude.ai", "registrable": "claude.ai",
		"client_name": "Claude", "claimed_name": nil, "trust": "tested", "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
		"redirect_host": "claude.ai", "limits_tier": "web_tested",
	}
	testedLocal = map[string]any{
		"client_kind": "cimd", "client_id": "https://claude.ai/oauth/claude-code-client-metadata", "tested_id": "claude_code",
		"client_host": "claude.ai", "registrable": "claude.ai", "client_local": true, "client_name": "Claude Code",
		"claimed_name": "Claude Code", "trust": "tested", "redirect_uri": "http://localhost:53682/callback", "redirect_host": "claude.ai",
		"redirect_local": true, "limits_tier": "local_tested",
	}
)

// v2Body is a metadata consent's body for a version-2 descriptor that
// describes client (pendingV2's defaults, then client's overrides).
func v2Body(t *testing.T, requestID, prefix string, client map[string]any) map[string]any {
	t.Helper()
	b := consent(requestID, prefix)
	b["kid"], b["sealed"] = enclaveKID, sealed(t)
	b["expires_at"] = time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)
	b["client_name"], b["trust"], b["client_host"], b["client_local"], b["claimed_name"] = "agent.example.com", "unknown", "agent.example.com", false, "Example Agent"
	b["history_days"] = 30
	if client != nil {
		for _, k := range []string{"client_name", "trust", "client_host", "client_local", "claimed_name"} {
			if v, ok := client[k]; ok {
				b[k] = v
			}
		}
		if client["trust"] == "tested" {
			b["history_days"] = nil
		}
	}
	return b
}

// prepareV2 registers and prepares a version-2 request and mints the key a
// metadata consent binds, the owner's.
func (h *clientsHarness) prepareV2(t *testing.T, client map[string]any) (requestID, prefix string) {
	t.Helper()
	return h.prepareV2For(t, client, h.owner.ID)
}

// prepareV2For is prepareV2 with the key actor's, for actor's consent.
func (h *clientsHarness) prepareV2For(t *testing.T, client map[string]any, actor uuid.UUID) (requestID, prefix string) {
	t.Helper()
	requestID = h.enclave.pendingV2(t, randomKey(t), client)
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/requests/"+requestID+"/prepare", prepareNonce(t, 32), nil), http.StatusOK, "")
	in := time.Now().Add(20 * time.Minute)
	key, err := h.keys.IssueActingAsForDevices(context.Background(), h.tenant.String(), "v2", store.ScopeRead, &actor, nil, []uuid.UUID{h.device}, &in)
	if err != nil {
		t.Fatal(err)
	}
	prefix, _, _ = strings.Cut(key, ".")
	return requestID, prefix
}

// v2Content prepares a version-2 request for text and builds its body: a
// version-4 content consent with its service account.
func (h *clientsHarness) v2Content(t *testing.T, client map[string]any) (requestID string, body map[string]any) {
	t.Helper()
	pub := randomKey(t)
	requestID = h.enclave.pendingV2(t, pub, client)
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/requests/"+requestID+"/prepare", prepareNonce(t, 32), nil), http.StatusOK, "")
	service, _, prefix := h.serviceFor(t, h.owner.ID, pub)
	body = v2Body(t, requestID, prefix, client)
	body["kind"], body["service_user_id"], body["key_mode"], body["consent_version"] = "content", service.String(), "ephemeral", 4
	return requestID, body
}

// created reads a consent's 201.
func created(t *testing.T, r reply) string {
	t.Helper()
	expect(t, r, http.StatusCreated, "")
	var c struct {
		ID string `json:"id"`
	}
	r.into(t, &c)
	return c.ID
}

// listedClient is a connection's client as the console lists it.
type listedClient struct {
	ID             string            `json:"id"`
	Status         string            `json:"status"`
	ClientName     string            `json:"client_name"`
	RedirectHost   string            `json:"redirect_host"`
	ClientKind     string            `json:"client_kind"`
	ClientID       *string           `json:"client_id"`
	ClientHost     *string           `json:"client_host"`
	Registrable    *string           `json:"registrable"`
	ClientLocal    bool              `json:"client_local"`
	Trust          *string           `json:"trust"`
	ClaimedName    *string           `json:"claimed_name"`
	HistoryDays    *int              `json:"history_days"`
	FirstUsedAt    *time.Time        `json:"first_used_at"`
	CreatedByEmail *string           `json:"created_by_email"`
	Seen           bool              `json:"seen"`
	BudgetHits     []store.BudgetHit `json:"budget_hits"`
}

func (h *clientsHarness) client(t *testing.T, token, id string) listedClient {
	t.Helper()
	r := h.call(t, http.MethodGet, "/v1/mcp/connections", nil, bearer(token))
	expect(t, r, http.StatusOK, "")
	var out struct {
		Connections []listedClient `json:"connections"`
	}
	r.into(t, &out)
	for _, c := range out.Connections {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("connection %s not listed: %s", id, r.body)
	return listedClient{}
}

// ---------------------------------------------------------------------------

func TestVersion2Consent(t *testing.T) {
	h := newClientsHarness(t)

	// An untested client, metadata: the relay carries its three members,
	// the ledger and the list the client.
	requestID, prefix := h.prepareV2(t, nil)
	id := created(t, h.call(t, http.MethodPost, "/v1/mcp/connections", v2Body(t, requestID, prefix, nil), bearer(h.ownerToken)))
	relayed := h.enclave.bundle(requestID)
	if relayed["trust"] != "unknown" || relayed["client_local"] != false || relayed["history_days"] != float64(30) {
		t.Fatalf("relayed = %v", relayed)
	}
	c := h.client(t, h.ownerToken, id)
	if c.ClientKind != "cimd" || deref(c.ClientID) != "https://agent.example.com/oauth/client.json" || deref(c.ClientHost) != "agent.example.com" ||
		deref(c.Registrable) != "example.com" ||
		deref(c.Trust) != "unknown" || deref(c.ClaimedName) != "Example Agent" || c.HistoryDays == nil || *c.HistoryDays != 30 ||
		c.ClientName != "agent.example.com" || c.RedirectHost != "agent.example.com" || deref(c.CreatedByEmail) != h.owner.Email ||
		c.Seen || c.FirstUsedAt != nil || c.BudgetHits == nil || len(c.BudgetHits) != 0 {
		t.Fatalf("listed = %+v", c)
	}

	// A tested web client registered dynamically: no history window, and
	// its random client id is not kept.
	requestID, prefix = h.prepareV2(t, testedWeb)
	id = created(t, h.call(t, http.MethodPost, "/v1/mcp/connections", v2Body(t, requestID, prefix, testedWeb), bearer(h.ownerToken)))
	relayed = h.enclave.bundle(requestID)
	if v, ok := relayed["history_days"]; !ok || v != nil || relayed["trust"] != "tested" {
		t.Fatalf("relayed = %v", relayed)
	}
	if c := h.client(t, h.ownerToken, id); c.ClientKind != "dcr" || c.ClientID != nil || deref(c.ClientHost) != "claude.ai" || c.HistoryDays != nil ||
		c.ClientName != "Claude" || c.ClaimedName != nil {
		t.Fatalf("listed = %+v", c)
	}

	// A tested local app.
	requestID, prefix = h.prepareV2(t, testedLocal)
	id = created(t, h.call(t, http.MethodPost, "/v1/mcp/connections", v2Body(t, requestID, prefix, testedLocal), bearer(h.ownerToken)))
	if c := h.client(t, h.ownerToken, id); !c.ClientLocal || deref(c.Trust) != "tested" || c.RedirectHost != "claude.ai" {
		t.Fatalf("listed = %+v", c)
	}
	if h.enclave.bundle(requestID)["client_local"] != true {
		t.Fatal("client_local was not relayed")
	}

	// Claude's document client on its pinned claude.com callback: the
	// client is claude.ai's, the redirect host the callback's (§19.12).
	claudeCom := map[string]any{
		"client_kind": "cimd", "client_id": "https://claude.ai/oauth/mcp-oauth-client-metadata", "tested_id": "claude", "client_host": "claude.ai",
		"registrable": "claude.ai", "client_name": "Claude", "claimed_name": nil, "trust": "tested", "redirect_uri": "https://claude.com/api/mcp/auth_callback",
		"redirect_host": "claude.com", "limits_tier": "web_tested",
	}
	requestID, prefix = h.prepareV2(t, claudeCom)
	id = created(t, h.call(t, http.MethodPost, "/v1/mcp/connections", v2Body(t, requestID, prefix, claudeCom), bearer(h.ownerToken)))
	if c := h.client(t, h.ownerToken, id); c.ClientKind != "cimd" || deref(c.ClientHost) != "claude.ai" || c.RedirectHost != "claude.com" || c.ClientName != "Claude" ||
		deref(c.Registrable) != "claude.ai" {
		t.Fatalf("listed = %+v", c)
	}

	// An untested client whose name the reader kept under Script_Extensions
	// (Thaana with Arabic-Indic digits): Go does not judge scripts.
	thaana := map[string]any{"claimed_name": "\u0785\u0786 \u0661\u0662"}
	requestID, prefix = h.prepareV2(t, thaana)
	id = created(t, h.call(t, http.MethodPost, "/v1/mcp/connections", v2Body(t, requestID, prefix, thaana), bearer(h.ownerToken)))
	if c := h.client(t, h.ownerToken, id); deref(c.ClaimedName) != "\u0785\u0786 \u0661\u0662" {
		t.Fatalf("listed = %+v", c)
	}

	// A version-1 descriptor gets none of it, and refuses the members.
	requestID = h.enclave.pending(t)
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/requests/"+requestID+"/prepare", prepareNonce(t, 32), nil), http.StatusOK, "")
	_, prefix = h.provisionalKey(t, "v1")
	body := consent(requestID, prefix)
	body["kid"], body["sealed"], body["trust"] = enclaveKID, sealed(t), "tested"
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", body, bearer(h.ownerToken)), http.StatusBadRequest, "bad_request")
	delete(body, "trust")
	created(t, h.call(t, http.MethodPost, "/v1/mcp/connections", body, bearer(h.ownerToken)))
	for _, k := range []string{"trust", "client_local", "history_days"} {
		if _, ok := h.enclave.bundle(requestID)[k]; ok {
			t.Fatalf("a version-1 reader was sent %s", k)
		}
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// What a version-2 consent is refused for, each before the ledger and the
// reader: the body disagreeing with the descriptor (400), a descriptor that
// does not hold together (502), the switches (403), the ceilings by tier,
// and an unprepared request.
func TestVersion2ConsentRefusals(t *testing.T) {
	h := newClientsHarness(t)
	for name, tc := range map[string]struct {
		client map[string]any
		mutate func(map[string]any)
		status int
		code   string
	}{
		"another trust":         {nil, func(b map[string]any) { b["trust"] = "tested"; b["history_days"] = nil }, 400, "bad_request"},
		"another host":          {nil, func(b map[string]any) { b["client_host"] = "evil.example.com" }, 400, "bad_request"},
		"local said web":        {testedLocal, func(b map[string]any) { b["client_local"] = false }, 400, "bad_request"},
		"another claimed name":  {nil, func(b map[string]any) { b["claimed_name"] = "Claude" }, 400, "bad_request"},
		"a claimed name added":  {testedWeb, func(b map[string]any) { b["claimed_name"] = "Claude" }, 400, "bad_request"},
		"no client fields":      {nil, func(b map[string]any) { delete(b, "trust"); delete(b, "client_host"); delete(b, "client_local") }, 400, "bad_request"},
		"no history window":     {nil, func(b map[string]any) { b["history_days"] = nil }, 400, "bad_request"},
		"fourteen days":         {nil, func(b map[string]any) { b["history_days"] = 14 }, 400, "bad_request"},
		"a tested one's window": {testedWeb, func(b map[string]any) { b["history_days"] = 30 }, 400, "bad_request"},
		"untested for 100 days": {nil, func(b map[string]any) {
			b["expires_at"] = time.Now().Add(100 * 24 * time.Hour).UTC().Format(time.RFC3339)
		}, 400, "bad_request"},
		"a public suffix": {map[string]any{"client_host": "github.io", "client_id": "https://github.io/c.json", "client_name": "github.io",
			"redirect_uri": "https://github.io/cb", "redirect_host": "github.io"}, func(b map[string]any) {
			b["client_host"], b["client_name"] = "github.io", "github.io"
		}, 502, "reader_unavailable"},
		"a host not the id's":   {map[string]any{"client_id": "https://other.example.com/c.json"}, nil, 502, "reader_unavailable"},
		"the wrong registrable": {map[string]any{"registrable": "agent.example.com"}, nil, 502, "reader_unavailable"},
		"a shared suffix missed": {map[string]any{"client_id": "https://team.github.io/c.json", "client_host": "team.github.io",
			"registrable": "team.github.io", "client_name": "team.github.io", "redirect_uri": "https://team.github.io/cb", "redirect_host": "team.github.io"},
			func(b map[string]any) { b["client_host"], b["client_name"] = "team.github.io", "team.github.io" }, 502, "reader_unavailable"},
		"a tier that does not follow": {map[string]any{"limits_tier": "web_tested"}, nil, 502, "reader_unavailable"},
		"an untested redirect elsewhere": {map[string]any{"redirect_uri": "https://evil.example.net/cb", "redirect_host": "evil.example.net"},
			nil, 502, "reader_unavailable"},
		"an untested name":            {map[string]any{"client_name": "Claude"}, func(b map[string]any) { b["client_name"] = "Claude" }, 502, "reader_unavailable"},
		"a claim with a bidi control": {map[string]any{"claimed_name": "Cl\u202eaude"}, func(b map[string]any) { b["claimed_name"] = "Cl\u202eaude" }, 502, "reader_unavailable"},
		"a redirect host not the redirect's": {map[string]any{"client_id": "https://claude.ai/oauth/mcp-oauth-client-metadata", "tested_id": "claude",
			"client_host": "claude.ai", "registrable": "claude.ai", "client_name": "Claude", "claimed_name": nil, "trust": "tested",
			"redirect_uri": "https://claude.com/api/mcp/auth_callback", "redirect_host": "claude.ai", "limits_tier": "web_tested"}, func(b map[string]any) {
			b["client_host"], b["client_name"], b["claimed_name"], b["trust"], b["history_days"] = "claude.ai", "Claude", nil, "tested", nil
		}, 502, "reader_unavailable"},
		"a DCR host not listed": {map[string]any{"client_kind": "dcr", "client_id": "dcr-1", "tested_id": "evil", "client_host": "example.org",
			"registrable": "example.org", "client_name": "Evil", "claimed_name": nil, "trust": "tested", "redirect_uri": "https://example.org/cb",
			"redirect_host": "example.org", "limits_tier": "web_tested"}, func(b map[string]any) {
			b["client_host"], b["client_name"], b["claimed_name"], b["trust"], b["history_days"] = "example.org", "Evil", nil, "tested", nil
		}, 502, "reader_unavailable"},
		"a loopback over https": {map[string]any{"client_local": true, "redirect_local": true, "redirect_uri": "https://localhost/cb"},
			func(b map[string]any) { b["client_local"] = true }, 502, "reader_unavailable"},
	} {
		t.Run(name, func(t *testing.T) {
			requestID, prefix := h.prepareV2(t, tc.client)
			body := v2Body(t, requestID, prefix, tc.client)
			if tc.mutate != nil {
				tc.mutate(body)
			}
			expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", body, bearer(h.ownerToken)), tc.status, tc.code)
			if h.enclave.bundle(requestID) != nil {
				t.Fatal("a refused consent reached the reader")
			}
		})
	}

	// The switches: allowlist mode refuses every untested client; a
	// blocked tested client is refused whatever the mode.
	h.handler.UnknownAllowed = false
	requestID, prefix := h.prepareV2(t, nil)
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", v2Body(t, requestID, prefix, nil), bearer(h.ownerToken)),
		http.StatusForbidden, "client_not_allowed")
	requestID, prefix = h.prepareV2(t, testedWeb)
	created(t, h.call(t, http.MethodPost, "/v1/mcp/connections", v2Body(t, requestID, prefix, testedWeb), bearer(h.ownerToken)))
	h.handler.BlockedClients = []string{"claude_code", "claude_dcr"}
	requestID, prefix = h.prepareV2(t, testedWeb)
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", v2Body(t, requestID, prefix, testedWeb), bearer(h.ownerToken)),
		http.StatusForbidden, "client_not_allowed")
	h.handler.UnknownAllowed, h.handler.BlockedClients = true, nil

	// A version-2 request this process did not prepare.
	requestID = h.enclave.pendingV2(t, randomKey(t), nil)
	_, prefix = h.provisionalKey(t, "unprepared")
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", v2Body(t, requestID, prefix, nil), bearer(h.ownerToken)),
		http.StatusConflict, "attestation_required")
	if listed, err := h.conns.List(context.Background(), h.tenant); err != nil || len(listed) != 1 {
		t.Fatalf("refused consents left rows: %d %v", len(listed), err)
	}
}

// Text for a client Wappie has not tested: version 4 only, never drafting,
// thirty days at most, and only while the notice can go to a verified
// address. Three untested connections at most.
func TestVersion2Text(t *testing.T) {
	h := newClientsHarness(t)
	h.contentOn.Store(true)
	// Sending switched on, so that what refuses a draft is the client.
	h.handler.SendAllowed = func(uuid.UUID) bool { return true }

	reason := ""
	untested := func() bool {
		t.Helper()
		r := h.call(t, http.MethodGet, "/v1/mcp/content", nil, bearer(h.ownerToken))
		expect(t, r, http.StatusOK, "")
		var c struct {
			UntestedText       bool    `json:"untested_text"`
			UntestedTextReason *string `json:"untested_text_reason"`
		}
		r.into(t, &c)
		if c.UntestedTextReason == nil {
			t.Fatal("no untested_text_reason")
		}
		reason = *c.UntestedTextReason
		return c.UntestedText
	}
	_, body := h.v2Content(t, nil)
	if untested() || reason != "email_unverified" {
		t.Fatalf("an unverified address may give an untested assistant text, or is not told so (%q)", reason)
	}
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", body, bearer(h.ownerToken)), http.StatusForbidden, "email_unverified")
	h.verify(t, h.owner)
	if !untested() || reason != "" {
		t.Fatalf("a verified address may not give an untested assistant text (%q)", reason)
	}
	h.handler.NoticeOrigin = ""
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", body, bearer(h.ownerToken)), http.StatusForbidden, "email_unverified")
	// The server, not the person: the card says so rather than asking to confirm an address.
	if untested() || reason != "notices_off" {
		t.Fatalf("untested text with no notice e-mail, or the wrong reason (%q)", reason)
	}
	h.handler.NoticeOrigin = noticeOrigin
	for name, mutate := range map[string]func(map[string]any){
		"version 3": func(b map[string]any) { b["consent_version"], b["send"] = 3, "draft" },
		"drafting":  func(b map[string]any) { b["send"] = "draft" },
		"for 31 days": func(b map[string]any) {
			b["expires_at"] = time.Now().Add(31 * 24 * time.Hour).UTC().Format(time.RFC3339)
		},
	} {
		t.Run(name, func(t *testing.T) {
			b := map[string]any{}
			for k, v := range body {
				b[k] = v
			}
			mutate(b)
			expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", b, bearer(h.ownerToken)), http.StatusBadRequest, "bad_request")
		})
	}
	requestID := body["request_id"].(string)
	created(t, h.call(t, http.MethodPost, "/v1/mcp/connections", body, bearer(h.ownerToken)))
	if relayed := h.enclave.bundle(requestID); relayed["kind"] != "content" || relayed["trust"] != "unknown" || relayed["history_days"] != float64(30) {
		t.Fatalf("relayed = %v", relayed)
	}

	// A tested local app may read text, never draft; a tested web client
	// may draft on version 4.
	_, local := h.v2Content(t, testedLocal)
	local["send"] = "draft"
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", local, bearer(h.ownerToken)), http.StatusBadRequest, "bad_request")
	delete(local, "send")
	created(t, h.call(t, http.MethodPost, "/v1/mcp/connections", local, bearer(h.ownerToken)))

	// Two more untested connections fill the three; the fourth is refused.
	for range 2 {
		requestID, prefix := h.prepareV2(t, nil)
		created(t, h.call(t, http.MethodPost, "/v1/mcp/connections", v2Body(t, requestID, prefix, nil), bearer(h.ownerToken)))
	}
	requestID, prefix := h.prepareV2(t, nil)
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", v2Body(t, requestID, prefix, nil), bearer(h.ownerToken)),
		http.StatusConflict, "too_many_unknown")
	requestID, prefix = h.prepareV2(t, testedWeb)
	created(t, h.call(t, http.MethodPost, "/v1/mcp/connections", v2Body(t, requestID, prefix, testedWeb), bearer(h.ownerToken)))
}

// An activation raises the notice: the banner shows the connection to every
// manager until each marks it seen, and the e-mail goes once, to the person
// who consented and the owners with a verified address, with a revoke-only
// link and never the client's claimed name.
func TestActivationNotice(t *testing.T) {
	h := newClientsHarness(t)
	admin := h.person(t, "admin")
	member := h.person(t, "member")
	unverified := h.person(t, "owner")
	_ = unverified
	h.verify(t, h.owner)
	h.verify(t, admin)
	h.verify(t, member)
	adminToken := h.session(t, admin)

	requestID, prefix := h.prepareV2For(t, nil, admin.ID)
	id := created(t, h.call(t, http.MethodPost, "/v1/mcp/connections", v2Body(t, requestID, prefix, nil), bearer(adminToken)))
	if len(h.mail.mails()) != 0 {
		t.Fatal("a consent sent a notice before its activation")
	}
	a, _ := h.signedCall(t, http.MethodPost, "/v1/mcp/enclave/connections/"+id+"/activate", asEnclave(t))
	expect(t, a, http.StatusNoContent, "")
	h.handler.WaitNotices()
	mails := h.mail.mails()
	if len(mails) != 2 {
		t.Fatalf("mails = %+v", mails)
	}
	to := map[string]bool{}
	for _, m := range mails {
		to[m.to] = true
		n := m.n
		if n.Event != "activated" || n.ClientHost != "agent.example.com" || n.Tier != "unknown" || n.Numbers != 1 || n.Text || n.HistoryDays != 30 ||
			!strings.HasPrefix(n.RevokeLink, noticeOrigin+"/v1/mcp/revoke-link/") || len(strings.TrimPrefix(n.RevokeLink, noticeOrigin+"/v1/mcp/revoke-link/")) != 43 {
			t.Fatalf("notice = %+v", n)
		}
		if mails[0].n.RevokeLink != n.RevokeLink {
			t.Fatal("two recipients got two links")
		}
	}
	if !to[admin.Email] || !to[h.owner.Email] {
		t.Fatalf("recipients = %v", to)
	}

	// The banner: unseen for every viewer until each marks it.
	for _, token := range []string{h.ownerToken, adminToken} {
		if h.client(t, token, id).Seen {
			t.Fatal("a new connection was seen")
		}
	}
	memberToken := h.session(t, member)
	for range 2 {
		expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections/"+id+"/seen", nil, bearer(memberToken)), http.StatusNoContent, "")
	}
	if !h.client(t, memberToken, id).Seen || h.client(t, h.ownerToken, id).Seen {
		t.Fatal("seen is not the viewer's own")
	}
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections/"+uuid.NewString()+"/seen", nil, bearer(memberToken)), http.StatusNotFound, "not_found")
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections/"+id+"/seen", nil, nil), http.StatusUnauthorized, "unauthorized")

	// The first active status is the first use.
	if s := h.standing(t, id); s.Status != "active" {
		t.Fatalf("standing = %+v", s)
	}
	if h.client(t, h.ownerToken, id).FirstUsedAt == nil {
		t.Fatal("no first use")
	}

	// Without a notice origin nothing is mailed, and the banner still
	// shows the next one.
	h.handler.NoticeOrigin = ""
	requestID, prefix = h.prepareV2(t, testedWeb)
	other := created(t, h.call(t, http.MethodPost, "/v1/mcp/connections", v2Body(t, requestID, prefix, testedWeb), bearer(h.ownerToken)))
	a, _ = h.signedCall(t, http.MethodPost, "/v1/mcp/enclave/connections/"+other+"/activate", asEnclave(t))
	expect(t, a, http.StatusNoContent, "")
	h.handler.WaitNotices()
	if len(h.mail.mails()) != 2 || h.client(t, h.ownerToken, other).Seen {
		t.Fatal("a notice without an origin went, or the banner missed it")
	}
}

// A reader's budget_hit: its own live rows only, a strict body, the banner
// raised again, the limit listed, and one e-mail per code.
func TestBudgetHit(t *testing.T) {
	h := newClientsHarness(t)
	h.verify(t, h.owner)
	requestID, prefix := h.prepareV2(t, nil)
	id := created(t, h.call(t, http.MethodPost, "/v1/mcp/connections", v2Body(t, requestID, prefix, nil), bearer(h.ownerToken)))
	a, _ := h.signedCall(t, http.MethodPost, "/v1/mcp/enclave/connections/"+id+"/activate", asEnclave(t))
	expect(t, a, http.StatusNoContent, "")
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections/"+id+"/seen", nil, bearer(h.ownerToken)), http.StatusNoContent, "")
	h.handler.WaitNotices()

	hit := func(body string) reply {
		s := asEnclave(t)
		s.body = []byte(body)
		r, _ := h.signedCall(t, http.MethodPost, "/v1/mcp/enclave/connections/"+id+"/budget-hit", s)
		return r
	}
	for _, body := range []string{``, `{}`, `{"code":"weekly_messages"}`, `{"code":"daily_messages","conn":"x"}`, `{"code":"daily_messages"} {}`} {
		expect(t, hit(body), http.StatusBadRequest, "bad_request")
	}
	for range 2 {
		expect(t, hit(`{"code":"daily_messages"}`), http.StatusNoContent, "")
	}
	h.handler.WaitNotices()
	c := h.client(t, h.ownerToken, id)
	if c.Seen || len(c.BudgetHits) != 1 || c.BudgetHits[0].Code != "daily_messages" {
		t.Fatalf("after a budget hit = %+v", c)
	}
	var limits []mailer.MCPNotice
	for _, m := range h.mail.mails() {
		if m.n.Event != "activated" {
			limits = append(limits, m.n)
		}
	}
	if len(limits) != 1 || limits[0].Event != "daily_messages" {
		t.Fatalf("limit mails = %+v", limits)
	}
	// Signed by another reader, unsigned, or for a row that is not there.
	s := signed{reader: "staging", secret: stagingSecret, direction: "to-go", at: time.Now(), nonce: freshNonce(t), body: []byte(`{"code":"network"}`)}
	if r := h.serveSigned(t, http.MethodPost, "/v1/mcp/enclave/connections/"+id+"/budget-hit", s, int64(len(s.body))); r.Code != http.StatusNotFound {
		t.Fatalf("another reader: %d", r.Code)
	}
	s = asEnclave(t)
	s.body = []byte(`{"code":"network"}`)
	r, _ := h.signedCall(t, http.MethodPost, "/v1/mcp/enclave/connections/"+uuid.NewString()+"/budget-hit", s)
	expect(t, r, http.StatusNotFound, "not_found")
}

// The revoke-only link: a look changes nothing, the first POST revokes that
// one connection and tells its reader, and every link of the connection is
// dead after it, as an unknown or malformed one is. Each notice e-mail
// carries a link of its own, and an earlier one keeps working after a later
// one went. The page carries one form and no link, and is served behind the
// API's browser-origin guard as in production: the form posts from the page
// itself, whose same-origin referrer policy lets the browser send the page's
// own origin (a no-referrer page would send Origin: null, which the guard
// refuses).
func TestRevokeLink(t *testing.T) {
	h := newClientsHarness(t)
	h.verify(t, h.owner)
	h.handler.RevokeLinkLimits = &ratelimit.Auth{PerIP: ratelimit.New(600, 600)}
	requestID, prefix := h.prepareV2(t, nil)
	id := created(t, h.call(t, http.MethodPost, "/v1/mcp/connections", v2Body(t, requestID, prefix, nil), bearer(h.ownerToken)))
	a, _ := h.signedCall(t, http.MethodPost, "/v1/mcp/enclave/connections/"+id+"/activate", asEnclave(t))
	expect(t, a, http.StatusNoContent, "")
	h.handler.WaitNotices()
	// A reading limit later the same hour: a second e-mail, a second link.
	limit := asEnclave(t)
	limit.body = []byte(`{"code":"first_hour_messages"}`)
	hit, _ := h.signedCall(t, http.MethodPost, "/v1/mcp/enclave/connections/"+id+"/budget-hit", limit)
	expect(t, hit, http.StatusNoContent, "")
	h.handler.WaitNotices()
	mails := h.mail.mails()
	if len(mails) != 2 || mails[0].n.RevokeLink == mails[1].n.RevokeLink {
		t.Fatalf("mails = %+v", mails)
	}
	first := strings.TrimPrefix(mails[0].n.RevokeLink, noticeOrigin)
	later := strings.TrimPrefix(mails[1].n.RevokeLink, noticeOrigin)

	const apiHost = "api.wappie.thehappie.co"
	guarded := browserorigin.Policy{}.Wrap(h.mux)
	page := func(method, path, lang, origin string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		req.Host = apiHost
		req.RemoteAddr = "198.51.100.7:4242"
		if lang != "" {
			req.Header.Set("Accept-Language", lang)
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		guarded.ServeHTTP(w, req)
		return w
	}
	for _, path := range []string{first, later, first} {
		w := page(http.MethodGet, path, "", "")
		body := w.Body.String()
		if w.Code != http.StatusOK || !strings.Contains(body, "agent.example.com") || !strings.Contains(body, "Revoke only this connection") ||
			strings.Contains(body, "<a ") || strings.Count(body, "<form") != 1 || !strings.Contains(body, `method="post"`) ||
			!strings.Contains(body, `<meta name="referrer" content="same-origin">`) || strings.Contains(body, "no-referrer") ||
			!strings.Contains(body, "Wappie&#39;s e-mails about assistants never ask for your password. Their only button revokes one connection.") {
			t.Fatalf("page = %d %s", w.Code, body)
		}
		if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "form-action 'self'") ||
			w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "same-origin" {
			t.Fatalf("headers = %v", w.Header())
		}
	}
	if c := h.client(t, h.ownerToken, id); c.Status != "active" {
		t.Fatalf("a look changed the status to %s", c.Status)
	}
	if w := page(http.MethodGet, first, "pt-BR,pt;q=0.9,en;q=0.5", ""); !strings.Contains(w.Body.String(), "Revogar só esta conexão") || !strings.Contains(w.Body.String(), `lang="pt"`) {
		t.Fatalf("Portuguese page = %s", w.Body.String())
	}
	if w := page(http.MethodGet, first, "de;q=0.2, fr", ""); !strings.Contains(w.Body.String(), `lang="fr"`) {
		t.Fatalf("French page = %s", w.Body.String())
	}
	if w := page(http.MethodGet, first, "de", ""); !strings.Contains(w.Body.String(), "zu Ihrem Wappie") || strings.Contains(w.Body.String(), "dein") {
		t.Fatalf("German page = %s", w.Body.String())
	}

	// What a browser sends from a no-referrer page is refused by the guard
	// and revokes nothing.
	if w := page(http.MethodPost, first, "", "null"); w.Code != http.StatusForbidden {
		t.Fatalf("Origin null = %d %s", w.Code, w.Body.String())
	}
	if c := h.client(t, h.ownerToken, id); c.Status != "active" {
		t.Fatalf("a refused POST changed the status to %s", c.Status)
	}
	// The page's own origin, as its form sends it: the earlier e-mail's link revokes.
	w := page(http.MethodPost, first, "", "https://"+apiHost)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Connection revoked") ||
		!strings.Contains(w.Body.String(), "agent.example.com loses access to your Wappie within a minute.") || strings.Contains(w.Body.String(), "<form") {
		t.Fatalf("revoked page = %d %s", w.Code, w.Body.String())
	}
	if c := h.client(t, h.ownerToken, id); c.Status != "revoked" {
		t.Fatalf("status = %s", c.Status)
	}
	if got := h.enclave.revocations(); len(got) != 1 || got[0] != id {
		t.Fatalf("the reader was told %v", got)
	}
	// Every link of the connection is spent with it.
	for _, p := range []string{first, later, first[:len(first)-1] + "x", "/v1/mcp/revoke-link/short", "/v1/mcp/revoke-link/" + strings.Repeat("A", 43)} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			if w := page(method, p, "", ""); w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "This link no longer works") ||
				!strings.Contains(w.Body.String(), "open the Wappie console yourself") || strings.Contains(w.Body.String(), "<form") {
				t.Fatalf("%s %s = %d %s", method, p, w.Code, w.Body.String())
			}
		}
	}
	// The path is limited per address.
	h.handler.RevokeLinkLimits = &ratelimit.Auth{PerIP: ratelimit.New(1, 1)}
	page(http.MethodGet, first, "", "")
	if w := page(http.MethodGet, first, "", ""); w.Code != http.StatusTooManyRequests {
		t.Fatalf("no limit: %d", w.Code)
	}
}

// tokenBody is a metadata token's consent.
func tokenBody(t *testing.T, prefix string) map[string]any {
	t.Helper()
	return map[string]any{
		"kind": "metadata", "key_prefix": prefix, "expires_at": time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339),
		"kid": enclaveKID, "sealed": sealed(t), "label": "Cursor on the laptop", "history_days": 30, "media": false,
	}
}

// tokenRequest asks for a token request as the owner and returns its id.
func (h *clientsHarness) tokenRequest(t *testing.T, token string) string {
	t.Helper()
	r := h.call(t, http.MethodPost, "/v1/mcp/token-requests", prepareNonce(t, 32), bearer(token))
	expect(t, r, http.StatusOK, "")
	var d struct {
		RequestID string `json:"request_id"`
		Kind      string `json:"kind"`
	}
	r.into(t, &d)
	if d.Kind != "token" {
		t.Fatalf("descriptor = %s", r.body)
	}
	return d.RequestID
}

// activateTokens makes the fake enclave activate each token over Go's own
// route before it answers, as the real one does.
func (h *clientsHarness) activateTokens(t *testing.T) {
	h.enclave.mu.Lock()
	h.enclave.onTokenBundle = func(body map[string]any) (int, any) {
		w := h.serveSigned(t, http.MethodPost, "/v1/mcp/enclave/connections/"+body["connection_id"].(string)+"/activate", asEnclave(t), 0)
		if w.Code != http.StatusNoContent {
			t.Errorf("activation = %d %s", w.Code, w.Body.String())
		}
		return http.StatusNoContent, nil
	}
	h.enclave.mu.Unlock()
}

func TestConsoleToken(t *testing.T) {
	h := newClientsHarness(t)
	h.verify(t, h.owner)
	h.activateTokens(t)

	// Only an owner or an admin asks, only while untested clients may
	// connect, and the descriptor is relayed as the reader made it.
	member := h.session(t, h.person(t, "member"))
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/token-requests", prepareNonce(t, 32), bearer(member)), http.StatusForbidden, "not_authorized")
	h.handler.UnknownAllowed = false
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/token-requests", prepareNonce(t, 32), bearer(h.ownerToken)), http.StatusForbidden, "client_not_allowed")
	h.handler.UnknownAllowed = true
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/token-requests", map[string]any{"nonce": "short"}, bearer(h.ownerToken)), http.StatusBadRequest, "bad_request")
	requestID := h.tokenRequest(t, h.ownerToken)

	// The bundle: this person's request with its kid, a label by the name
	// rule, a window, and the token's ceilings.
	_, prefix := h.provisionalKey(t, "token")
	for name, mutate := range map[string]func(map[string]any){
		"a bidi label":   func(b map[string]any) { b["label"] = "Cursor \u202ethe laptop" },
		"an empty label": func(b map[string]any) { b["label"] = " " },
		"no window":      func(b map[string]any) { b["history_days"] = 0 },
		"for 91 days": func(b map[string]any) {
			b["expires_at"] = time.Now().Add(92 * 24 * time.Hour).UTC().Format(time.RFC3339)
		},
		"media without text": func(b map[string]any) { b["media"] = true },
		"not a kind":         func(b map[string]any) { b["kind"] = "ai" },
	} {
		t.Run(name, func(t *testing.T) {
			b := tokenBody(t, prefix)
			mutate(b)
			expect(t, h.call(t, http.MethodPost, "/v1/mcp/token-requests/"+requestID+"/bundle", b, bearer(h.ownerToken)), http.StatusBadRequest, "bad_request")
		})
	}
	admin := h.person(t, "admin")
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/token-requests/"+requestID+"/bundle", tokenBody(t, prefix), bearer(h.session(t, admin))),
		http.StatusConflict, "attestation_required")
	wrongKID := tokenBody(t, prefix)
	wrongKID["kid"] = enclaveRenewalKID
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/token-requests/"+requestID+"/bundle", wrongKID, bearer(h.ownerToken)),
		http.StatusConflict, "attestation_required")

	r := h.call(t, http.MethodPost, "/v1/mcp/token-requests/"+requestID+"/bundle", tokenBody(t, prefix), bearer(h.ownerToken))
	expect(t, r, http.StatusCreated, "")
	var made struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	r.into(t, &made)
	if made.Status != "active" {
		t.Fatalf("token = %s", r.body)
	}
	h.enclave.mu.Lock()
	relayed := h.enclave.tokenBundles[requestID]
	h.enclave.mu.Unlock()
	if relayed["kind"] != "metadata" || relayed["history_days"] != float64(30) || relayed["media"] != false || relayed["connection_id"] != made.ID {
		t.Fatalf("relayed = %v", relayed)
	}
	c := h.client(t, h.ownerToken, made.ID)
	if c.ClientKind != "token" || deref(c.Trust) != "unknown" || c.ClientHost != nil || c.Registrable != nil || c.ClientName != "Cursor on the laptop" ||
		c.RedirectHost != "token" || c.HistoryDays == nil || *c.HistoryDays != 30 {
		t.Fatalf("listed = %+v", c)
	}
	h.handler.WaitNotices()
	mails := h.mail.mails()
	if len(mails) != 1 || mails[0].n.Tier != "token" || mails[0].n.ClientHost != "" || mails[0].n.Label != "Cursor on the laptop" {
		t.Fatalf("mails = %+v", mails)
	}
	// Its revoke-only link names the token by its label, never a host.
	look := httptest.NewRequest(http.MethodGet, strings.TrimPrefix(mails[0].n.RevokeLink, noticeOrigin), nil)
	look.RemoteAddr = "198.51.100.8:4242"
	page := httptest.NewRecorder()
	h.mux.ServeHTTP(page, look)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "console connection token “Cursor on the laptop”") {
		t.Fatalf("token page = %d %s", page.Code, page.Body.String())
	}
	// A request is answered once.
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/token-requests/"+requestID+"/bundle", tokenBody(t, prefix), bearer(h.ownerToken)),
		http.StatusUnprocessableEntity, "key_unsuitable")

	// Text: the content switch, then the notice precondition.
	textBody := func(t *testing.T) (string, map[string]any) {
		requestID := h.tokenRequest(t, h.ownerToken)
		h.enclave.mu.Lock()
		pub, err := base64.RawURLEncoding.DecodeString(h.enclave.tokenRequests[requestID]["reader_public_key"].(string))
		h.enclave.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		service, _, prefix := h.serviceFor(t, h.owner.ID, pub)
		b := tokenBody(t, prefix)
		b["kind"], b["service_user_id"], b["key_mode"], b["consent_version"] = "content", service.String(), "ephemeral", 4
		b["expires_at"] = time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
		return requestID, b
	}
	requestID, b := textBody(t)
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/token-requests/"+requestID+"/bundle", b, bearer(h.ownerToken)), http.StatusForbidden, "content_not_allowed")
	h.contentOn.Store(true)
	h.handler.NoticeOrigin = ""
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/token-requests/"+requestID+"/bundle", b, bearer(h.ownerToken)), http.StatusForbidden, "email_unverified")
	h.handler.NoticeOrigin = noticeOrigin
	long := map[string]any{}
	for k, v := range b {
		long[k] = v
	}
	long["expires_at"] = time.Now().Add(31 * 24 * time.Hour).UTC().Format(time.RFC3339)
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/token-requests/"+requestID+"/bundle", long, bearer(h.ownerToken)), http.StatusBadRequest, "bad_request")

	// The reader's refusals: a 400 passes with its code, its own cap with
	// its, anything else is 502; each undoes the row and its key.
	for _, tc := range []struct {
		status int
		code   string
		want   int
	}{{400, "grant_proof_failed", 400}, {409, "too_many_unknown", 409}, {500, "boom", 502}} {
		h.enclave.mu.Lock()
		h.enclave.onTokenBundle = func(map[string]any) (int, any) { return tc.status, map[string]string{"code": tc.code} }
		h.enclave.mu.Unlock()
		requestID, b := textBody(t)
		r := h.call(t, http.MethodPost, "/v1/mcp/token-requests/"+requestID+"/bundle", b, bearer(h.ownerToken))
		want := tc.code
		if tc.want == 502 {
			want = "reader_unavailable"
		}
		expect(t, r, tc.want, want)
	}
	if listed, err := h.conns.List(context.Background(), h.tenant); err != nil || len(listed) != 1 {
		t.Fatalf("refused tokens left rows: %d %v", len(listed), err)
	}
	h.activateTokens(t)
	requestID, b = textBody(t)
	r = h.call(t, http.MethodPost, "/v1/mcp/token-requests/"+requestID+"/bundle", b, bearer(h.ownerToken))
	expect(t, r, http.StatusCreated, "")
	h.enclave.mu.Lock()
	relayed = h.enclave.tokenBundles[requestID]
	h.enclave.mu.Unlock()
	if relayed["kind"] != "content" {
		t.Fatalf("relayed = %v", relayed)
	}
	// The token request is not a consent's, nor a consent's request a
	// token's.
	requestID = h.tokenRequest(t, h.ownerToken)
	_, prefix = h.provisionalKey(t, "crossed")
	body := consent(requestID, prefix)
	body["kid"], body["sealed"] = enclaveKID, sealed(t)
	if r := h.call(t, http.MethodPost, "/v1/mcp/connections", body, bearer(h.ownerToken)); r.status == http.StatusCreated {
		t.Fatalf("a token request was taken as a consent: %s", r.body)
	}
	consentID, consentPrefix := h.prepareV2(t, nil)
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/token-requests/"+consentID+"/bundle", tokenBody(t, consentPrefix), bearer(h.ownerToken)),
		http.StatusConflict, "attestation_required")
}

func TestLiveListRelay(t *testing.T) {
	h := newClientsHarness(t)
	h.handler.LiveListLimits = ratelimit.New(10, 10)
	path := "/v1/mcp/workspaces/" + h.tenant.String() + "/live-list"
	member := h.session(t, h.person(t, "member"))

	nonce := prepareNonce(t, 32)
	r := h.call(t, http.MethodPost, path, nonce, bearer(member))
	expect(t, r, http.StatusOK, "")
	var list struct {
		Kind          string   `json:"kind"`
		WorkspaceID   string   `json:"workspace_id"`
		Nonce         string   `json:"nonce"`
		ConnectionIDs []string `json:"connection_ids"`
	}
	r.into(t, &list)
	if list.Kind != "live_list" || list.WorkspaceID != h.tenant.String() || list.Nonce != nonce["nonce"] || list.ConnectionIDs == nil {
		t.Fatalf("list = %s", r.body)
	}
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/workspaces/"+uuid.NewString()+"/live-list", prepareNonce(t, 32), bearer(member)),
		http.StatusNotFound, "not_found")
	expect(t, h.call(t, http.MethodPost, path, map[string]any{"nonce": "short"}, bearer(member)), http.StatusBadRequest, "bad_request")
	expect(t, h.call(t, http.MethodPost, path, prepareNonce(t, 32), nil), http.StatusUnauthorized, "unauthorized")

	// An answer that is not the list asked for is not relayed.
	for name, reply := range map[string]func(workspace, nonce string) map[string]any{
		"another nonce": func(w, _ string) map[string]any { return liveListDocument(t, h.enclave, w, "other", []string{}) },
		"another workspace": func(_, n string) map[string]any {
			return liveListDocument(t, h.enclave, uuid.NewString(), n, []string{})
		},
		"unsorted ids": func(w, n string) map[string]any {
			return liveListDocument(t, h.enclave, w, n, []string{"ffffffff-0000-4000-8000-000000000000", "00000000-0000-4000-8000-000000000000"})
		},
		"an id in upper case": func(w, n string) map[string]any {
			return liveListDocument(t, h.enclave, w, n, []string{"FFFFFFFF-0000-4000-8000-000000000000"})
		},
		"a request's attestation": func(w, n string) map[string]any {
			d := liveListDocument(t, h.enclave, w, n, []string{})
			d["attestation"].(map[string]any)["request_id"] = "AAAAAAAAAAAAAAAAAAAAAA"
			return d
		},
		"version 1": func(w, n string) map[string]any {
			d := liveListDocument(t, h.enclave, w, n, []string{})
			delete(d, "descriptor_version")
			return d
		},
	} {
		t.Run(name, func(t *testing.T) {
			h.enclave.mu.Lock()
			h.enclave.liveListReply = func(w, n string) (int, any) { return http.StatusOK, reply(w, n) }
			h.enclave.mu.Unlock()
			expect(t, h.call(t, http.MethodPost, path, prepareNonce(t, 32), bearer(member)), http.StatusBadGateway, "reader_unavailable")
		})
	}
	h.enclave.mu.Lock()
	h.enclave.liveListReply = func(string, string) (int, any) { return http.StatusNotFound, map[string]string{"code": "not_found"} }
	h.enclave.mu.Unlock()
	expect(t, h.call(t, http.MethodPost, path, prepareNonce(t, 32), bearer(member)), http.StatusNotFound, "not_found")
	// Ten a minute per workspace: nine more so far, then refused.
	h.enclave.mu.Lock()
	h.enclave.liveListReply = nil
	asked := len(h.enclave.liveLists)
	h.enclave.mu.Unlock()
	for i := asked; i < 10; i++ {
		expect(t, h.call(t, http.MethodPost, path, prepareNonce(t, 32), bearer(member)), http.StatusOK, "")
	}
	expect(t, h.call(t, http.MethodPost, path, prepareNonce(t, 32), bearer(member)), http.StatusTooManyRequests, "rate_limited")
}

// Version-2 renewals: a content connection's renewal says renewal and an AI
// authorization's ai_renewal; the client switches reach a renewal too.
func TestVersion2Renewal(t *testing.T) {
	h := newClientsHarness(t)
	h.contentOn.Store(true)
	id, _, _ := h.consentContent(t, h.owner)
	h.enclave.mu.Lock()
	h.enclave.renewalKey = randomKey(t)
	h.enclave.renewalExtra = map[string]any{"descriptor_version": 2, "kind": "ai_renewal"}
	pub := h.enclave.renewalKey
	h.enclave.mu.Unlock()
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections/"+id+"/renewal", prepareNonce(t, 32), bearer(h.ownerToken)),
		http.StatusBadGateway, "reader_unavailable")
	h.enclave.mu.Lock()
	h.enclave.renewalExtra = map[string]any{"descriptor_version": 2, "kind": "renewal", "client_kind": "cimd", "trust": "unknown",
		"tested_id": nil, "client_host": "agent.example.com"}
	h.enclave.mu.Unlock()
	r := h.call(t, http.MethodPost, "/v1/mcp/connections/"+id+"/renewal", prepareNonce(t, 32), bearer(h.ownerToken))
	expect(t, r, http.StatusOK, "")
	var renewal struct {
		RenewalID string `json:"renewal_id"`
	}
	r.into(t, &renewal)
	service, _, prefix := h.serviceFor(t, h.owner.ID, pub)
	renew := map[string]any{"renewal_id": renewal.RenewalID, "key_prefix": prefix, "service_user_id": service.String(), "kid": enclaveRenewalKID, "sealed": sealed(t)}
	h.handler.UnknownAllowed = false
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections/"+id+"/renew", renew, bearer(h.ownerToken)), http.StatusForbidden, "client_not_allowed")
	h.handler.UnknownAllowed = true
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections/"+id+"/renew", renew, bearer(h.ownerToken)), http.StatusOK, "")

	// A descriptor version this server does not read.
	h.enclave.mu.Lock()
	h.enclave.renewalExtra = map[string]any{"descriptor_version": 3}
	h.enclave.mu.Unlock()
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections/"+id+"/renewal", prepareNonce(t, 32), bearer(h.ownerToken)),
		http.StatusBadGateway, "reader_unavailable")
}

// A version-2 prepare is a connect descriptor; any other kind is refused.
func TestVersion2PrepareShape(t *testing.T) {
	h := newClientsHarness(t)
	for _, client := range []map[string]any{{"kind": "renewal"}, {"kind": "token"}, {"descriptor_version": 3}, {"descriptor_version": "2"}} {
		requestID := h.enclave.pendingV2(t, randomKey(t), client)
		expect(t, h.call(t, http.MethodPost, "/v1/mcp/requests/"+requestID+"/prepare", prepareNonce(t, 32), nil), http.StatusBadGateway, "reader_unavailable")
	}
}

// The relay's body for a version-2 consent has the three members, history
// null for the whole history; without a client it is as before.
func TestBundleRelayClientMembers(t *testing.T) {
	base := mcpauth.BundleRelay{ConnectionID: "c", TenantID: "t", KID: "k", Sealed: "s", ExpiresAt: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)}
	plain, err := json.Marshal(base)
	if err != nil || string(plain) != `{"connection_id":"c","tenant_id":"t","kid":"k","sealed":"s","expires_at":"2026-10-01T00:00:00Z"}` {
		t.Fatalf("plain = %s %v", plain, err)
	}
	tested := base
	tested.Client = &mcpauth.RelayClient{Trust: "tested"}
	if raw, err := json.Marshal(tested); err != nil || !strings.HasSuffix(string(raw), `"trust":"tested","client_local":false,"history_days":null}`) {
		t.Fatalf("tested = %s %v", raw, err)
	}
	days := 7
	unknown := base
	unknown.Kind, unknown.Client = "content", &mcpauth.RelayClient{Trust: "unknown", ClientLocal: true, HistoryDays: &days}
	if raw, err := json.Marshal(unknown); err != nil || !strings.HasSuffix(string(raw), `"kind":"content","trust":"unknown","client_local":true,"history_days":7}`) {
		t.Fatalf("unknown = %s %v", raw, err)
	}
}
