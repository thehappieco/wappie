package aiapi_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/aiapi"
	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/domain"
	"whatserver2/internal/mcpauth"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/ratelimit"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// The console's AI routes (docs/mcp-enclave.md §18.11) over HTTP, with the
// ledger in real Postgres under an ordinary role and the enclave a fake
// that answers the AI relays.

const enclaveOrigin = "https://mcp.example.test"

// fakeEnclave answers the relay's AI calls. It checks no signature: the
// connector's tests do.
type fakeEnclave struct {
	srv *httptest.Server

	mu       sync.Mutex
	jobs     []map[string]any
	jobReply func(body map[string]any) (int, any)
	state    func(job, requester string) (int, any)
	revoked  []string
}

func newFakeEnclave(t *testing.T) *fakeEnclave {
	t.Helper()
	f := &fakeEnclave{}
	mux := http.NewServeMux()
	write := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if err := json.NewEncoder(w).Encode(v); err != nil {
			t.Error(err)
		}
	}
	mux.HandleFunc("POST /internal/ai/requests", func(w http.ResponseWriter, _ *http.Request) {
		id := base64.RawURLEncoding.EncodeToString(random(t, 16))
		write(w, http.StatusOK, map[string]any{
			"request_id": id, "kind": "ai", "reader_public_key": base64.RawURLEncoding.EncodeToString(random(t, 32)), "kid": "fedcba9876543210",
			"resource": enclaveOrigin + "/mcp", "reader_version": "0.5.0", "expires_at": time.Now().Add(20 * time.Minute).UTC().Format(time.RFC3339),
			"attestation": map[string]any{"document": base64.RawURLEncoding.EncodeToString(random(t, 400)), "request_id": id, "pcr0": strings.Repeat("0a", 48)},
		})
	})
	mux.HandleFunc("POST /internal/ai/jobs", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.jobs = append(f.jobs, body)
		if f.jobReply != nil {
			status, reply := f.jobReply(body)
			write(w, status, reply)
			return
		}
		write(w, http.StatusAccepted, map[string]any{"job": "job-0123456789abcdef"})
	})
	mux.HandleFunc("GET /internal/ai/jobs/{job}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.state != nil {
			status, reply := f.state(r.PathValue("job"), r.URL.Query().Get("requester_id"))
			write(w, status, reply)
			return
		}
		write(w, http.StatusOK, map[string]any{"state": "done"})
	})
	mux.HandleFunc("POST /internal/connections/{id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.revoked = append(f.revoked, r.PathValue("id"))
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeEnclave) revocations() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.revoked...)
}

func random(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

type harness struct {
	srv     *httptest.Server
	pool    *pgxpool.Pool
	users   *store.Users
	keys    *store.APIKeys
	conns   *store.MCPConnections
	ai      *store.AI
	enclave *fakeEnclave
	api     *aiapi.Handler
	tenant  uuid.UUID
	device  uuid.UUID
	owner   store.User
	// aiOn is the AI switch: with it off AIAllowed is false. Content and
	// attachments are on throughout.
	aiOn atomic.Bool
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	var unsafeRole bool
	if err := pool.QueryRow(ctx, `SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user`).Scan(&unsafeRole); err != nil || unsafeRole {
		t.Fatalf("ordinary RLS role required: %v %v", unsafeRole, err)
	}
	var tenantID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('acme') RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	dev, err := store.NewDevices(pool).Create(ctx, tenantID, "phone", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{
		users: store.NewUsers(pool), keys: store.NewAPIKeys(pool), conns: store.NewMCPConnections(pool), ai: store.NewAI(pool),
		enclave: newFakeEnclave(t), tenant: uuid.MustParse(tenantID), device: uuid.MustParse(dev.ID), pool: pool,
	}
	h.aiOn.Store(true)
	h.owner = h.person(t, "owner")
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.NewKeys(pool).CreateArchiveKey(ctx, h.tenant, h.device, 1, pub); err != nil {
		t.Fatal(err)
	}
	h.reads(t, h.owner.ID)

	roots := x509.NewCertPool()
	roots.AddCert(h.enclave.srv.Certificate())
	allowed := func(tenant uuid.UUID) bool { return tenant == h.tenant }
	connector := &mcpauth.Handler{
		Connections: h.conns, APIKeys: h.keys, Users: h.users,
		Attested: []*mcpauth.AttestedReader{{
			ID: "enclave", PublicOrigin: enclaveOrigin, Relay: mcpauth.NewSignedRelay("enclave", h.enclave.srv.URL, strings.Repeat("s", 43), roots),
			Secrets: []string{strings.Repeat("s", 43)}, Peers: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, Tenants: []uuid.UUID{h.tenant},
		}},
		Log: slog.New(slog.DiscardHandler), ContentReader: "enclave", ContentAllowed: allowed, MediaAllowed: allowed,
		AIAllowed: func(tenant uuid.UUID) bool { return h.aiOn.Load() && tenant == h.tenant },
		AI:        h.ai,
	}
	mux := http.NewServeMux()
	connector.Mount(mux)
	h.api = &aiapi.Handler{Users: h.users, Connections: h.conns, AI: h.ai, Enabled: true, MCP: connector, Log: slog.New(slog.DiscardHandler)}
	h.api.Mount(mux)
	h.srv = httptest.NewServer(mux)
	t.Cleanup(h.srv.Close)
	return h
}

func (h *harness) person(t *testing.T, role string) store.User {
	t.Helper()
	user, err := h.users.Create(context.Background(), store.NewUser{
		TenantID: h.tenant, Email: uuid.NewString() + "@example.test", Role: role, AuthKey: "auth-" + role,
		KDFSalt: make([]byte, 16), KDFParams: store.DefaultKDFParams(), PublicKey: make([]byte, 32), WrappedUSK: []byte("wrapped"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return user
}

func (h *harness) session(t *testing.T, user store.User) string {
	t.Helper()
	token, _, err := h.users.StartSession(context.Background(), user, "test")
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// reads gives a person the number's grant and read permission.
func (h *harness) reads(t *testing.T, person uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	if err := store.NewKeys(h.pool).PutGrant(ctx, store.Grant{TenantID: h.tenant, DeviceID: h.device, UserID: person, Epoch: 1, SealedDSK: []byte("a person's")}, &h.owner.ID); err != nil {
		t.Fatal(err)
	}
	if err := h.users.SetDevicePermission(ctx, h.tenant, h.owner.ID, store.DevicePermission{DeviceID: h.device, UserID: person, Read: true}); err != nil {
		t.Fatal(err)
	}
}

// authorization records and activates an AI authorization of user's on
// the harness's number, as the console and the enclave would: Gemini for
// audio and a Claude model for documents, requesters as given.
func (h *harness) authorization(t *testing.T, user store.User, requesters string) (string, map[string]uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	secret, _, err := h.users.NewProvisionalServiceInvitation(ctx, h.tenant, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	pub := random(t, 32)
	service, err := h.users.SignupService(ctx, secret, "mcp-"+hex.EncodeToString(random(t, 4)), pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.users.SetDevicePermission(ctx, h.tenant, user.ID, store.DevicePermission{DeviceID: h.device, UserID: service.ID, Read: true}); err != nil {
		t.Fatal(err)
	}
	if err := store.NewKeys(h.pool).PutGrant(ctx, store.Grant{TenantID: h.tenant, DeviceID: h.device, UserID: service.ID, Epoch: 1, SealedDSK: []byte("sealed")}, &user.ID); err != nil {
		t.Fatal(err)
	}
	in := time.Now().Add(20 * time.Minute)
	key, err := h.keys.IssueActingAsForDevices(ctx, h.tenant.String(), "ai", store.ScopeRead, &user.ID, &service.ID, []uuid.UUID{h.device}, &in)
	if err != nil {
		t.Fatal(err)
	}
	prefix, _, _ := strings.Cut(key, ".")
	keys := map[string]uuid.UUID{}
	for _, provider := range []string{"google", "anthropic"} {
		item, err := h.ai.AddKeychainItem(ctx, h.tenant, user.ID, store.AIKeychainItem{ID: uuid.New(), Provider: provider, Label: provider,
			Suffix: "a1B2", Envelope: append([]byte("WKC1"), random(t, 60)...)})
		if err != nil {
			t.Fatal(err)
		}
		keys[provider] = item.ID
	}
	request := base64.RawURLEncoding.EncodeToString(random(t, 16))
	expires := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	d := h.device.String()
	cfg := map[string]any{
		"version": 1, "request": request, "kid": "fedcba9876543210", "service_user_id": service.ID.String(),
		"epochs": map[string]any{d: 1}, "ns": map[string]any{d: h.tenant.String()},
		"keys": map[string]any{
			"google":    map[string]any{"keychain_id": keys["google"].String(), "sha256": strings.Repeat("ab", 32), "label": "google", "suffix": "a1B2"},
			"anthropic": map[string]any{"keychain_id": keys["anthropic"].String(), "sha256": strings.Repeat("cd", 32), "label": "anthropic", "suffix": "a1B2"},
		},
		"functions": map[string]any{"audio": map[string]any{"provider": "google", "model": "gemini-3.8-flash"},
			"document": map[string]any{"provider": "anthropic", "model": "claude-sonnet-5-5"}},
		"features": map[string]any{d: map[string]any{"audio": map[string]any{"mode": "request", "requesters": requesters},
			"document": map[string]any{"mode": "request", "requesters": requesters}}},
		"budget":     map[string]any{"monthly_tokens": 5_000_000, "request_items_per_day": 100},
		"expires_at": expires.UTC().Format(time.RFC3339), "key_mode": "ephemeral",
		"cfg_tags": map[string]any{d: base64.RawURLEncoding.EncodeToString(random(t, 32))},
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := store.ParseAIConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := h.conns.Create(ctx, h.tenant, user.ID, store.CreateMCPConnection{
		RequestID: request, KeyPrefix: prefix, ClientName: store.AIClientName, RedirectHost: store.AIRedirectHost, DeviceCount: 1,
		ReaderKID: "fedcba9876543210", ExpiresAt: expires, Reader: "enclave", Kind: store.KindAI, ServiceUserID: service.ID,
		KeyMode: store.KeyModeEphemeral, ConsentVersion: store.AIConsentVersion, ReaderPublicKey: pub, AIConfig: &parsed,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.conns.Activate(ctx, "enclave", conn.ID); err != nil {
		t.Fatal(err)
	}
	return conn.ID, keys
}

// message archives a message of a type on the harness's number.
func (h *harness) message(t *testing.T, kind domain.Type, viewOnce bool) uuid.UUID {
	t.Helper()
	uid := uuid.New()
	in := store.InsertMessage{UID: uid, TenantID: h.tenant, DeviceID: h.device, WAID: "wa-" + uid.String(), ChatKey: "5511911111111@s.whatsapp.net",
		Kind: domain.KindMessage, Type: kind, Source: domain.SourceLive, TS: time.Now(), BodySealed: []byte{1}, ViewOnce: viewOnce}
	if kind != domain.TypeText {
		in.Media = &store.InsertMedia{MediaType: string(kind), FileEncSHA256: random(t, 32)}
	}
	if _, err := store.NewMessages(h.pool).Insert(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	return uid
}

// result stores a result of an authorization's for a message.
func (h *harness) result(t *testing.T, authorization string, uid uuid.UUID, feature string) {
	t.Helper()
	sealed := append([]byte("WDRV"), 1, 0, 0)
	binary.BigEndian.PutUint16(sealed[5:7], 1)
	sealed = append(sealed, random(t, 60)...)
	if err := h.ai.PutAIDerived(context.Background(), h.tenant, authorization, store.AIDerived{MessageUID: uid, Feature: feature, DeviceID: h.device,
		Epoch: 1, Sealed: sealed, DedupeTag: random(t, 32)}, false); err != nil {
		t.Fatal(err)
	}
}

type reply struct {
	status int
	header http.Header
	body   []byte
}

func (r reply) code(t *testing.T) string {
	t.Helper()
	var e struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(r.body, &e); err != nil {
		t.Fatalf("not an error body: %s", r.body)
	}
	return e.Code
}

func (r reply) into(t *testing.T, v any) {
	t.Helper()
	if err := json.Unmarshal(r.body, v); err != nil {
		t.Fatalf("decoding %d reply %s: %v", r.status, r.body, err)
	}
}

func (h *harness) call(t *testing.T, method, path, token string, body any) reply {
	t.Helper()
	var payload io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		payload = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, h.srv.URL+path, payload)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusNoContent && resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("%s %s: missing Cache-Control: no-store", method, path)
	}
	return reply{status: resp.StatusCode, header: resp.Header, body: raw}
}

func expect(t *testing.T, r reply, status int, code string) {
	t.Helper()
	if r.status != status {
		t.Fatalf("status = %d, want %d: %s", r.status, status, r.body)
	}
	if code != "" && r.code(t) != code {
		t.Fatalf("code = %q, want %q: %s", r.code(t), code, r.body)
	}
}

// ---------------------------------------------------------------------------

// With the switch off every route answers 404 but the keychain, the listing,
// the revocation and the deletions.
func TestAIRoutesWhileOff(t *testing.T) {
	h := newHarness(t)
	token := h.session(t, h.owner)
	id, _ := h.authorization(t, h.owner, "self")
	voice := h.message(t, domain.TypePTT, false)
	h.result(t, id, voice, "audio")
	h.api.Enabled = false
	d := h.device.String()
	for _, route := range [][2]string{
		{http.MethodPost, "/v1/ai/requests"}, {http.MethodPatch, "/v1/ai/authorizations/" + id}, {http.MethodGet, "/v1/ai/available?device_id=" + d},
		{http.MethodPost, "/v1/ai/process"}, {http.MethodGet, "/v1/ai/jobs/job-0123456789abcdef?authorization_id=" + id},
		{http.MethodGet, "/v1/ai/derived?device_id=" + d + "&uids=" + voice.String()}, {http.MethodGet, "/v1/ai/usage?month=2026-10"},
	} {
		expect(t, h.call(t, route[0], route[1], token, map[string]any{}), http.StatusNotFound, "not_found")
	}
	expect(t, h.call(t, http.MethodGet, "/v1/ai/keychain", token, nil), http.StatusOK, "")
	var listed struct {
		Authorizations []mcpauth.AIAuthorizationInfo `json:"authorizations"`
	}
	r := h.call(t, http.MethodGet, "/v1/ai/authorizations", token, nil)
	expect(t, r, http.StatusOK, "")
	r.into(t, &listed)
	if len(listed.Authorizations) != 1 || listed.Authorizations[0].Renewable {
		t.Fatalf("listed = %s", r.body)
	}
	expect(t, h.call(t, http.MethodDelete, "/v1/ai/derived/"+voice.String()+"/audio", token, nil), http.StatusNoContent, "")
	expect(t, h.call(t, http.MethodPost, "/v1/ai/derived/delete", token, map[string]any{"authorization_id": id}), http.StatusOK, "")
	expect(t, h.call(t, http.MethodDelete, "/v1/ai/authorizations/"+id, token, nil), http.StatusNoContent, "")
	// Nothing without a session.
	expect(t, h.call(t, http.MethodGet, "/v1/ai/keychain", "", nil), http.StatusUnauthorized, "unauthorized")
}

func TestAIKeychainRoutes(t *testing.T) {
	h := newHarness(t)
	token := h.session(t, h.owner)
	admin := h.person(t, "admin")
	envelope := base64.RawURLEncoding.EncodeToString(append([]byte("WKC1"), random(t, 60)...))
	item := map[string]any{"id": uuid.NewString(), "provider": "openai", "label": "Wappie", "suffix": "x9Z!", "envelope": envelope}
	r := h.call(t, http.MethodPost, "/v1/ai/keychain", token, item)
	expect(t, r, http.StatusCreated, "")
	var created struct {
		ID, Provider, Label, Suffix, Envelope string
		CreatedAt                             time.Time `json:"created_at"`
	}
	r.into(t, &created)
	if created.ID != item["id"] || created.Envelope != envelope || created.CreatedAt.IsZero() {
		t.Fatalf("created = %s", r.body)
	}
	expect(t, h.call(t, http.MethodPost, "/v1/ai/keychain", token, item), http.StatusConflict, "keychain_exists")
	for name, change := range map[string]map[string]any{
		"an id in upper case":    {"id": strings.ToUpper(uuid.NewString())},
		"a provider not listed":  {"provider": "mistral"},
		"an empty label":         {"label": ""},
		"a suffix of three":      {"suffix": "abc"},
		"a key in the clear":     {"envelope": base64.RawURLEncoding.EncodeToString([]byte("sk-0123456789abcdefghijklmnop"))},
		"an envelope too large":  {"envelope": base64.RawURLEncoding.EncodeToString(append([]byte("WKC1"), random(t, 4096)...))},
		"an envelope not base64": {"envelope": "not base64!"},
		"an unknown field":       {"api_key": "no"},
	} {
		b := map[string]any{}
		for k, v := range item {
			b[k] = v
		}
		b["id"] = uuid.NewString()
		for k, v := range change {
			b[k] = v
		}
		t.Run(name, func(t *testing.T) {
			expect(t, h.call(t, http.MethodPost, "/v1/ai/keychain", token, b), http.StatusBadRequest, "bad_request")
		})
	}
	for range store.AIKeychainMax - 1 {
		b := map[string]any{"id": uuid.NewString(), "provider": "google", "label": "g", "suffix": "abcd", "envelope": envelope}
		expect(t, h.call(t, http.MethodPost, "/v1/ai/keychain", token, b), http.StatusCreated, "")
	}
	b := map[string]any{"id": uuid.NewString(), "provider": "google", "label": "g", "suffix": "abcd", "envelope": envelope}
	expect(t, h.call(t, http.MethodPost, "/v1/ai/keychain", token, b), http.StatusConflict, "keychain_full")
	// Own items only.
	var items struct {
		Items []map[string]any `json:"items"`
	}
	h.call(t, http.MethodGet, "/v1/ai/keychain", token, nil).into(t, &items)
	if len(items.Items) != store.AIKeychainMax {
		t.Fatalf("%d items", len(items.Items))
	}
	adminToken := h.session(t, admin)
	h.call(t, http.MethodGet, "/v1/ai/keychain", adminToken, nil).into(t, &items)
	if len(items.Items) != 0 {
		t.Fatalf("another person's items: %v", items.Items)
	}
	expect(t, h.call(t, http.MethodDelete, "/v1/ai/keychain/"+created.ID, adminToken, nil), http.StatusNotFound, "not_found")
	expect(t, h.call(t, http.MethodDelete, "/v1/ai/keychain/"+created.ID, token, nil), http.StatusNoContent, "")
	expect(t, h.call(t, http.MethodDelete, "/v1/ai/keychain/"+created.ID, token, nil), http.StatusNotFound, "not_found")
	// Deleting a key an authorization uses ends it, and the reader is told.
	id, keys := h.authorization(t, admin, "self")
	expect(t, h.call(t, http.MethodDelete, "/v1/ai/keychain/"+keys["google"].String(), adminToken, nil), http.StatusNoContent, "")
	a, err := h.conns.AIAuthorization(context.Background(), h.tenant, id)
	if err != nil || a.Status != "revoked" || a.RevokeReason != store.ReasonAIKeyDeleted {
		t.Fatalf("authorization = %+v %v", a, err)
	}
	if got := h.enclave.revocations(); len(got) != 1 || got[0] != id {
		t.Fatalf("revocations = %v", got)
	}
}

// Only an owner or an admin of a workspace that may have AI starts one;
// the reader's descriptor is passed on as it came.
func TestAIRequestRoute(t *testing.T) {
	h := newHarness(t)
	token := h.session(t, h.owner)
	nonce := map[string]any{"nonce": base64.RawURLEncoding.EncodeToString(random(t, 32))}
	r := h.call(t, http.MethodPost, "/v1/ai/requests", token, nonce)
	expect(t, r, http.StatusOK, "")
	var d map[string]any
	r.into(t, &d)
	if d["kind"] != "ai" || d["attestation"] == nil {
		t.Fatalf("descriptor = %s", r.body)
	}
	member := h.person(t, "member")
	expect(t, h.call(t, http.MethodPost, "/v1/ai/requests", h.session(t, member), nonce), http.StatusForbidden, "not_authorized")
	expect(t, h.call(t, http.MethodPost, "/v1/ai/requests", token, map[string]any{"nonce": "short"}), http.StatusBadRequest, "bad_request")
	h.aiOn.Store(false)
	expect(t, h.call(t, http.MethodPost, "/v1/ai/requests", token, nonce), http.StatusForbidden, "ai_not_allowed")
	h.aiOn.Store(true)
	// Rate-limited per person, like a prepare.
	h.api.RequestLimits = &ratelimit.Auth{PerSubject: ratelimit.New(1, 1)}
	expect(t, h.call(t, http.MethodPost, "/v1/ai/requests", token, nonce), http.StatusOK, "")
	expect(t, h.call(t, http.MethodPost, "/v1/ai/requests", token, nonce), http.StatusTooManyRequests, "rate_limited")
}

func TestAIAuthorizationRoutes(t *testing.T) {
	h := newHarness(t)
	ownerToken := h.session(t, h.owner)
	admin := h.person(t, "admin")
	adminToken := h.session(t, admin)
	member := h.person(t, "member")
	memberToken := h.session(t, member)
	h.reads(t, admin.ID)
	id, _ := h.authorization(t, h.owner, "self")
	theirs, _ := h.authorization(t, admin, "readers")

	list := func(token string) []mcpauth.AIAuthorizationInfo {
		t.Helper()
		var out struct {
			Authorizations []mcpauth.AIAuthorizationInfo `json:"authorizations"`
		}
		r := h.call(t, http.MethodGet, "/v1/ai/authorizations", token, nil)
		expect(t, r, http.StatusOK, "")
		r.into(t, &out)
		return out.Authorizations
	}
	if got := list(ownerToken); len(got) != 2 || got[0].ID != theirs || got[1].ID != id || !got[1].Renewable || got[0].Renewable {
		t.Fatalf("an owner's list = %+v", got)
	}
	if got := list(memberToken); len(got) != 0 {
		t.Fatalf("a member's list = %+v", got)
	}
	h.aiOn.Store(false)
	if got := list(ownerToken); got[1].Renewable {
		t.Fatal("renewable with AI off")
	}
	h.aiOn.Store(true)

	patch := func(token, id string, body map[string]any) reply {
		return h.call(t, http.MethodPatch, "/v1/ai/authorizations/"+id, token, body)
	}
	r := patch(adminToken, id, map[string]any{"paused": true, "off": []string{"document"}, "cap_tokens": 2_500_000})
	expect(t, r, http.StatusOK, "")
	var got mcpauth.AIAuthorizationInfo
	r.into(t, &got)
	if !got.Paused || strings.Join(got.Off, ",") != "document" || got.CapTokens == nil || *got.CapTokens != 2_500_000 {
		t.Fatalf("narrowed = %s", r.body)
	}
	expect(t, patch(adminToken, id, map[string]any{"paused": false}), http.StatusForbidden, "not_authorized")
	expect(t, patch(adminToken, id, map[string]any{"cap_tokens": nil}), http.StatusForbidden, "not_authorized")
	expect(t, patch(memberToken, id, map[string]any{"paused": true}), http.StatusForbidden, "not_authorized")
	expect(t, patch(ownerToken, id, map[string]any{}), http.StatusBadRequest, "bad_request")
	expect(t, patch(ownerToken, id, map[string]any{"cap_tokens": 1.5}), http.StatusBadRequest, "bad_request")
	expect(t, patch(ownerToken, id, map[string]any{"cap_tokens": 0}), http.StatusBadRequest, "bad_request")
	expect(t, patch(ownerToken, id, map[string]any{"cap_tokens": 1_000_000_001}), http.StatusBadRequest, "bad_request")
	expect(t, patch(ownerToken, id, map[string]any{"cap_cents": 300}), http.StatusBadRequest, "bad_request")
	expect(t, patch(ownerToken, id, map[string]any{"off": []string{"translate"}}), http.StatusBadRequest, "bad_request")
	expect(t, patch(ownerToken, uuid.NewString(), map[string]any{"paused": true}), http.StatusNotFound, "not_found")
	r = patch(ownerToken, id, map[string]any{"paused": false, "off": []string{}, "cap_tokens": nil})
	expect(t, r, http.StatusOK, "")
	r.into(t, &got)
	if got.Paused || len(got.Off) != 0 || got.CapTokens != nil {
		t.Fatalf("undone = %s", r.body)
	}

	// Revocation: a member may not; the creator may, with or without the
	// results; the reader is told.
	voice := h.message(t, domain.TypePTT, false)
	h.result(t, id, voice, "audio")
	expect(t, h.call(t, http.MethodDelete, "/v1/ai/authorizations/"+id, memberToken, nil), http.StatusForbidden, "not_authorized")
	expect(t, h.call(t, http.MethodDelete, "/v1/ai/authorizations/"+id+"?delete_results=maybe", ownerToken, nil), http.StatusBadRequest, "bad_request")
	expect(t, h.call(t, http.MethodDelete, "/v1/ai/authorizations/"+id+"?delete_results=true", ownerToken, nil), http.StatusNoContent, "")
	if items, _ := h.ai.AIDerivedFor(context.Background(), h.tenant, h.device, []uuid.UUID{voice}); len(items) != 0 {
		t.Fatalf("the results stayed: %+v", items)
	}
	if got := h.enclave.revocations(); len(got) != 1 || got[0] != id {
		t.Fatalf("revocations = %v", got)
	}
	expect(t, patch(ownerToken, id, map[string]any{"paused": true}), http.StatusConflict, "connection_state")
	// An admin revokes another person's; the results stay by default.
	h.result(t, theirs, voice, "audio")
	expect(t, h.call(t, http.MethodDelete, "/v1/ai/authorizations/"+theirs, ownerToken, nil), http.StatusNoContent, "")
	if items, _ := h.ai.AIDerivedFor(context.Background(), h.tenant, h.device, []uuid.UUID{voice}); len(items) != 1 {
		t.Fatalf("the results went: %+v", items)
	}
}

// What the console may ask for on a number, and asking for it.
func TestAIAvailableAndProcess(t *testing.T) {
	h := newHarness(t)
	ownerToken := h.session(t, h.owner)
	admin := h.person(t, "admin")
	h.reads(t, admin.ID)
	outsider := h.person(t, "member")
	d := h.device.String()
	available := func(token string) (features []string, renew []map[string]string) {
		t.Helper()
		var out struct {
			Features []string            `json:"features"`
			Renew    []map[string]string `json:"renew"`
		}
		r := h.call(t, http.MethodGet, "/v1/ai/available?device_id="+d, token, nil)
		expect(t, r, http.StatusOK, "")
		r.into(t, &out)
		return out.Features, out.Renew
	}
	if f, r := available(ownerToken); len(f)+len(r) != 0 {
		t.Fatalf("nothing yet = %v %v", f, r)
	}
	expect(t, h.call(t, http.MethodGet, "/v1/ai/available?device_id="+d, h.session(t, outsider), nil), http.StatusForbidden, "not_authorized")
	expect(t, h.call(t, http.MethodGet, "/v1/ai/available", ownerToken, nil), http.StatusBadRequest, "bad_request")

	id, _ := h.authorization(t, h.owner, "self")
	if f, r := available(ownerToken); strings.Join(f, ",") != "audio,document" || len(r) != 0 {
		t.Fatalf("available = %v %v", f, r)
	}
	if f, _ := available(h.session(t, admin)); len(f) != 0 {
		t.Fatalf("another person's self authorization = %v", f)
	}

	voice := h.message(t, domain.TypePTT, false)
	secret := h.message(t, domain.TypePTT, true)
	photo := h.message(t, domain.TypeImage, false)
	process := func(token string, body map[string]any) reply {
		return h.call(t, http.MethodPost, "/v1/ai/process", token, body)
	}
	ask := func(uid uuid.UUID, feature string) map[string]any {
		return map[string]any{"device_id": d, "uid": uid.String(), "feature": feature}
	}
	r := process(ownerToken, ask(voice, "audio"))
	expect(t, r, http.StatusAccepted, "")
	var started struct {
		Job             string `json:"job"`
		AuthorizationID string `json:"authorization_id"`
	}
	r.into(t, &started)
	if started.AuthorizationID != id || started.Job != "job-0123456789abcdef" {
		t.Fatalf("started = %s", r.body)
	}
	h.enclave.mu.Lock()
	relayed := h.enclave.jobs[0]
	h.enclave.mu.Unlock()
	if relayed["authorization_id"] != id || relayed["origin"] != "console" || relayed["requester_id"] != h.owner.ID.String() ||
		relayed["uid"] != voice.String() || relayed["redo"] != false || len(relayed) != 7 {
		t.Fatalf("relayed = %v", relayed)
	}
	expect(t, process(ownerToken, ask(secret, "audio")), http.StatusUnprocessableEntity, "view_once_excluded")
	expect(t, process(ownerToken, ask(photo, "audio")), http.StatusUnprocessableEntity, "ai_unsupported")
	expect(t, process(ownerToken, ask(uuid.New(), "audio")), http.StatusNotFound, "not_found")
	expect(t, process(ownerToken, ask(photo, "image")), http.StatusForbidden, "ai_not_enabled")
	expect(t, process(h.session(t, outsider), ask(voice, "audio")), http.StatusForbidden, "not_authorized")
	expect(t, process(ownerToken, map[string]any{"device_id": d, "uid": voice.String(), "feature": "translate"}), http.StatusBadRequest, "bad_request")

	// The enclave's answers.
	for _, tc := range []struct {
		status int
		reply  any
		want   int
		code   string
	}{
		{http.StatusOK, map[string]any{"stored": true}, http.StatusOK, ""},
		{http.StatusTooManyRequests, map[string]any{"code": "ai_busy", "retry_after_s": 20}, http.StatusTooManyRequests, "ai_busy"},
		{http.StatusConflict, map[string]any{"code": "ai_budget_reached"}, http.StatusConflict, "ai_budget_reached"},
		{http.StatusConflict, map[string]any{"code": "ai_budget_reached", "limit": "day"}, http.StatusConflict, "ai_budget_reached"},
		{http.StatusConflict, map[string]any{"code": "ai_paused"}, http.StatusConflict, "ai_paused"},
		{http.StatusNotFound, map[string]any{"code": "not_found"}, http.StatusConflict, "ai_paused"},
		{http.StatusInternalServerError, map[string]any{"code": "internal"}, http.StatusBadGateway, "reader_unavailable"},
	} {
		h.enclave.mu.Lock()
		h.enclave.jobReply = func(map[string]any) (int, any) { return tc.status, tc.reply }
		h.enclave.mu.Unlock()
		r := process(ownerToken, ask(voice, "audio"))
		expect(t, r, tc.want, tc.code)
		switch tc.code {
		case "ai_busy":
			if r.header.Get("Retry-After") != "20" || !strings.Contains(string(r.body), `"retry_after_s":20`) {
				t.Fatalf("busy = %v %s", r.header, r.body)
			}
		case "ai_paused":
			if !strings.Contains(string(r.body), `"authorization_id":"`+id+`"`) {
				t.Fatalf("paused = %s", r.body)
			}
		case "ai_budget_reached":
			// The authorization, and which limit it met when the reader says, and only then.
			if limit, _ := tc.reply.(map[string]any)["limit"].(string); strings.Contains(string(r.body), `"limit"`) != (limit != "") ||
				limit != "" && !strings.Contains(string(r.body), `"limit":"`+limit+`"`) || !strings.Contains(string(r.body), `"authorization_id":"`+id+`"`) {
				t.Fatalf("budget = %s", r.body)
			}
		case "":
			if strings.TrimSpace(string(r.body)) != `{"stored":true}` {
				t.Fatalf("stored = %s", r.body)
			}
		}
	}
	h.enclave.mu.Lock()
	h.enclave.jobReply = nil
	h.enclave.mu.Unlock()

	// After a reseal: Renew in place of the button, and 409 ai_paused with
	// the authorization to renew; nothing is asked of the enclave.
	if err := h.conns.Reseal(context.Background(), "enclave", id); err != nil {
		t.Fatal(err)
	}
	if f, r := available(ownerToken); len(f) != 0 || len(r) != 2 || r[0]["feature"] != "audio" || r[0]["authorization_id"] != id {
		t.Fatalf("available after a reseal = %v %v", f, r)
	}
	h.enclave.mu.Lock()
	before := len(h.enclave.jobs)
	h.enclave.mu.Unlock()
	r = process(ownerToken, ask(voice, "audio"))
	expect(t, r, http.StatusConflict, "ai_paused")
	if !strings.Contains(string(r.body), `"authorization_id":"`+id+`"`) {
		t.Fatalf("paused = %s", r.body)
	}
	h.enclave.mu.Lock()
	after := len(h.enclave.jobs)
	h.enclave.mu.Unlock()
	if after != before {
		t.Fatal("a job was asked under a reseal")
	}
	// Thirty a minute per person.
	h.api.ProcessLimits = &ratelimit.Auth{PerSubject: ratelimit.New(1, 1)}
	process(ownerToken, ask(voice, "audio"))
	expect(t, process(ownerToken, ask(voice, "audio")), http.StatusTooManyRequests, "rate_limited")
}

func TestAIJobRoute(t *testing.T) {
	h := newHarness(t)
	token := h.session(t, h.owner)
	id, _ := h.authorization(t, h.owner, "self")
	h.enclave.state = func(job, requester string) (int, any) {
		if requester != h.owner.ID.String() {
			return http.StatusNotFound, map[string]any{"code": "not_found"}
		}
		return http.StatusOK, map[string]any{"state": "failed", "code": "ai_model_unavailable"}
	}
	r := h.call(t, http.MethodGet, "/v1/ai/jobs/job-0123456789abcdef?authorization_id="+id, token, nil)
	expect(t, r, http.StatusOK, "")
	if strings.TrimSpace(string(r.body)) != `{"state":"failed","code":"ai_model_unavailable"}` {
		t.Fatalf("state = %s", r.body)
	}
	other := h.person(t, "admin")
	expect(t, h.call(t, http.MethodGet, "/v1/ai/jobs/job-0123456789abcdef?authorization_id="+id, h.session(t, other), nil), http.StatusNotFound, "not_found")
	expect(t, h.call(t, http.MethodGet, "/v1/ai/jobs/job-0123456789abcdef?authorization_id="+uuid.NewString(), token, nil), http.StatusNotFound, "not_found")
	expect(t, h.call(t, http.MethodGet, "/v1/ai/jobs/x?authorization_id="+id, token, nil), http.StatusNotFound, "not_found")
	expect(t, h.call(t, http.MethodGet, "/v1/ai/jobs/job-0123456789abcdef", token, nil), http.StatusNotFound, "not_found")
}

func TestAIDerivedRoutes(t *testing.T) {
	h := newHarness(t)
	ownerToken := h.session(t, h.owner)
	admin := h.person(t, "admin")
	adminToken := h.session(t, admin)
	member := h.person(t, "member")
	h.reads(t, member.ID)
	memberToken := h.session(t, member)
	outsider := h.person(t, "member")
	id, _ := h.authorization(t, h.owner, "readers")
	voice := h.message(t, domain.TypePTT, false)
	doc := h.message(t, domain.TypeDocument, false)
	h.result(t, id, voice, "audio")
	h.result(t, id, doc, "document")
	d := h.device.String()

	var items struct {
		Items []map[string]any `json:"items"`
	}
	r := h.call(t, http.MethodGet, "/v1/ai/derived?device_id="+d+"&uids="+voice.String()+","+doc.String()+","+uuid.NewString(), memberToken, nil)
	expect(t, r, http.StatusOK, "")
	r.into(t, &items)
	if len(items.Items) != 2 || items.Items[0]["authorization_id"] != id || len(items.Items[0]) != 7 {
		t.Fatalf("items = %s", r.body)
	}
	expect(t, h.call(t, http.MethodGet, "/v1/ai/derived?device_id="+d+"&uids="+voice.String(), h.session(t, outsider), nil), http.StatusForbidden, "not_authorized")
	many := strings.TrimSuffix(strings.Repeat(voice.String()+",", 101), ",")
	for _, q := range []string{"?device_id=" + d, "?device_id=" + d + "&uids=" + many, "?device_id=" + d + "&uids=nope", "?uids=" + voice.String()} {
		expect(t, h.call(t, http.MethodGet, "/v1/ai/derived"+q, memberToken, nil), http.StatusBadRequest, "bad_request")
	}

	// One result: a reader who did not make it may not delete it; its
	// authorization's creator may, and so may an admin.
	expect(t, h.call(t, http.MethodDelete, "/v1/ai/derived/"+voice.String()+"/audio", memberToken, nil), http.StatusForbidden, "not_authorized")
	expect(t, h.call(t, http.MethodDelete, "/v1/ai/derived/"+voice.String()+"/audio", ownerToken, nil), http.StatusNoContent, "")
	expect(t, h.call(t, http.MethodDelete, "/v1/ai/derived/"+voice.String()+"/audio", ownerToken, nil), http.StatusNotFound, "not_found")
	expect(t, h.call(t, http.MethodDelete, "/v1/ai/derived/"+doc.String()+"/translate", ownerToken, nil), http.StatusNotFound, "not_found")
	expect(t, h.call(t, http.MethodDelete, "/v1/ai/derived/"+doc.String()+"/document", adminToken, nil), http.StatusNoContent, "")

	// Many: by authorization (its creator, an owner or an admin), by number
	// (an owner or an admin).
	h.result(t, id, voice, "audio")
	del := func(token string, body map[string]any) reply {
		return h.call(t, http.MethodPost, "/v1/ai/derived/delete", token, body)
	}
	expect(t, del(memberToken, map[string]any{"authorization_id": id}), http.StatusForbidden, "not_authorized")
	expect(t, del(memberToken, map[string]any{"device_id": d}), http.StatusForbidden, "not_authorized")
	expect(t, del(ownerToken, map[string]any{"authorization_id": id, "device_id": d}), http.StatusBadRequest, "bad_request")
	expect(t, del(ownerToken, map[string]any{}), http.StatusBadRequest, "bad_request")
	expect(t, del(ownerToken, map[string]any{"authorization_id": uuid.NewString()}), http.StatusNotFound, "not_found")
	r = del(ownerToken, map[string]any{"authorization_id": id})
	expect(t, r, http.StatusOK, "")
	if strings.TrimSpace(string(r.body)) != `{"deleted":1}` {
		t.Fatalf("deleted = %s", r.body)
	}
	h.result(t, id, voice, "audio")
	r = del(adminToken, map[string]any{"device_id": d})
	expect(t, r, http.StatusOK, "")
	if strings.TrimSpace(string(r.body)) != `{"deleted":1}` {
		t.Fatalf("deleted = %s", r.body)
	}
}

func TestAIUsageRoute(t *testing.T) {
	h := newHarness(t)
	ownerToken := h.session(t, h.owner)
	admin := h.person(t, "admin")
	h.reads(t, admin.ID)
	adminToken := h.session(t, admin)
	mine, _ := h.authorization(t, h.owner, "self")
	theirs, _ := h.authorization(t, admin, "self")
	ctx := context.Background()
	for _, id := range []string{mine, theirs} {
		if err := h.ai.RecordAIUsage(ctx, h.tenant, id, store.AIUsage{DeviceID: h.device, Feature: "audio", Provider: "google", Model: "gemini-3.8-flash",
			Origin: "console", RequesterID: h.owner.ID, Items: 1, InputTokens: 10, ChargedTokens: 99}); err != nil {
			t.Fatal(err)
		}
	}
	month := time.Now().UTC().Format("2006-01")
	usage := func(token string) (string, []map[string]any) {
		t.Helper()
		var out struct {
			Month string           `json:"month"`
			Items []map[string]any `json:"items"`
		}
		r := h.call(t, http.MethodGet, "/v1/ai/usage?month="+month, token, nil)
		expect(t, r, http.StatusOK, "")
		r.into(t, &out)
		return out.Month, out.Items
	}
	if m, items := usage(ownerToken); m != month || len(items) != 2 || len(items[0]) != 17 {
		t.Fatalf("an owner's = %s %v", m, items)
	}
	// Today's calls, answered and failed, beside the month's counters.
	if err := h.ai.RecordAIUsage(ctx, h.tenant, mine, store.AIUsage{DeviceID: h.device, Feature: "audio", Provider: "google", Model: "gemini-3.8-flash",
		Origin: "console", RequesterID: h.owner.ID, Failures: 2, ChargedTokens: 5}); err != nil {
		t.Fatal(err)
	}
	for _, item := range func() []map[string]any { _, items := usage(ownerToken); return items }() {
		if item["authorization_id"] == mine && (item["items_today"] != float64(1) || item["failures_today"] != float64(2) || item["items"] != float64(1) ||
			item["charged_tokens"] != float64(104) || item["input_tokens"] != float64(10)) {
			t.Fatalf("today = %v", item)
		}
	}
	member := h.person(t, "member")
	if _, items := usage(h.session(t, member)); len(items) != 0 {
		t.Fatalf("a member's = %v", items)
	}
	// An admin is a manager too.
	if _, items := usage(adminToken); len(items) != 2 {
		t.Fatalf("an admin's = %v", items)
	}
	for _, q := range []string{"", "?month=2026-1", "?month=2026-13", "?month=" + month + "&x=1", "?month=october"} {
		expect(t, h.call(t, http.MethodGet, "/v1/ai/usage"+q, ownerToken, nil), http.StatusBadRequest, "bad_request")
	}
}
