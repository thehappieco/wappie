package mcpauth_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/mcpauth"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/ratelimit"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// The secret is a fixed run of characters, not a token; the tests only need
// two processes to agree on it.
var relaySecret = strings.Repeat("relay-", 8)

const (
	readerKID    = "0123456789abcdef"
	publicOrigin = "https://api.example.test"
)

// fakeReader stands in for the Node reader on the far side of the relay: it
// holds pending requests by id, records the bundles and revocations it is
// handed, and can be told to fail the hand-off.
type fakeReader struct {
	srv *httptest.Server

	mu          sync.Mutex
	requests    map[string]map[string]any
	bundles     map[string]map[string]any
	revoked     []string
	bundleReply int // 0 answers 204; anything else is returned as-is
	seenSecret  bool
}

func newFakeReader(t *testing.T) *fakeReader {
	t.Helper()
	f := &fakeReader{requests: map[string]map[string]any{}, bundles: map[string]map[string]any{}}
	mux := http.NewServeMux()
	guard := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			f.mu.Lock()
			f.seenSecret = r.Header.Get("Authorization") == "Bearer "+relaySecret
			ok := f.seenSecret
			f.mu.Unlock()
			if !ok {
				http.Error(w, `{"code":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			next(w, r)
		}
	}
	mux.HandleFunc("GET /internal/requests/{id}", guard(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		d, ok := f.requests[r.PathValue("id")]
		f.mu.Unlock()
		if !ok {
			http.Error(w, `{"code":"not_found"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(d); err != nil {
			t.Error(err)
		}
	}))
	mux.HandleFunc("POST /internal/requests/{id}/bundle", guard(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, `{"code":"bad_request"}`, http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.bundleReply != 0 {
			http.Error(w, `{"code":"reader_says_no"}`, f.bundleReply)
			return
		}
		if _, ok := f.requests[r.PathValue("id")]; !ok {
			http.Error(w, `{"code":"not_found"}`, http.StatusNotFound)
			return
		}
		f.bundles[r.PathValue("id")] = body
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.HandleFunc("POST /internal/connections/{id}/revoke", guard(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.revoked = append(f.revoked, r.PathValue("id"))
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// pending registers a request the way the reader would after /mcp/authorize.
func (f *fakeReader) pending(t *testing.T, clientName, redirectHost string) (id string, descriptor map[string]any) {
	t.Helper()
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	id = base64.RawURLEncoding.EncodeToString(raw)
	descriptor = map[string]any{
		"request_id": id, "kid": readerKID, "reader_public_key": base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		"client_id": "client-" + id[:6], "client_name": clientName, "redirect_host": redirectHost,
		"code_challenge": strings.Repeat("c", 43), "resource": publicOrigin + "/mcp",
		"expires_at": time.Now().Add(20 * time.Minute).UTC().Format(time.RFC3339),
	}
	f.mu.Lock()
	f.requests[id] = descriptor
	f.mu.Unlock()
	return id, descriptor
}

func (f *fakeReader) bundle(id string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bundles[id]
}

func (f *fakeReader) sawSecret() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.seenSecret
}

func (f *fakeReader) revocations() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.revoked...)
}

type harness struct {
	srv    *httptest.Server
	mux    *http.ServeMux
	pool   *pgxpool.Pool
	reader *fakeReader
	users  *store.Users
	keys   *store.APIKeys
	conns  *store.MCPConnections
	tenant uuid.UUID
	device uuid.UUID
	owner  store.User
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
	tenant := uuid.MustParse(tenantID)
	dev, err := store.NewDevices(pool).Create(ctx, tenantID, "phone", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	reader := newFakeReader(t)
	h := &harness{
		mux: http.NewServeMux(), pool: pool, reader: reader,
		users: store.NewUsers(pool), keys: store.NewAPIKeys(pool), conns: store.NewMCPConnections(pool),
		tenant: tenant, device: uuid.MustParse(dev.ID),
	}
	h.owner = h.person(t, "owner")
	(&mcpauth.Handler{
		Connections: h.conns, APIKeys: h.keys, Users: h.users,
		Reader:       mcpauth.NewRelay(reader.srv.URL, relaySecret),
		PublicOrigin: publicOrigin, RelaySecret: relaySecret,
		RedirectHosts: []string{"claude.ai", "chatgpt.com"},
		Log:           slog.New(slog.DiscardHandler),
	}).Mount(h.mux)
	h.srv = httptest.NewServer(h.mux)
	t.Cleanup(h.srv.Close)
	return h
}

// person creates an account in the workspace. The key material is nonsense
// on purpose: nothing here opens anything.
func (h *harness) person(t *testing.T, role string) store.User {
	t.Helper()
	user, err := h.users.Create(context.Background(), store.NewUser{
		TenantID: h.tenant, Email: uuid.NewString() + "@example.test", Role: role,
		AuthKey: "auth-" + role, KDFSalt: make([]byte, 16), KDFParams: store.DefaultKDFParams(),
		PublicKey: make([]byte, 32), WrappedUSK: []byte("wrapped"),
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

// provisionalKey issues what the console mints before a consent: read-only,
// restricted to the number, dead in twenty minutes unless a consent extends it.
func (h *harness) provisionalKey(t *testing.T, name string) (key, prefix string) {
	t.Helper()
	in := time.Now().Add(20 * time.Minute)
	key, err := h.keys.IssueActingAsForDevices(context.Background(), h.tenant.String(), name, store.ScopeRead, &h.owner.ID, nil, []uuid.UUID{h.device}, &in)
	if err != nil {
		t.Fatal(err)
	}
	prefix, _, _ = strings.Cut(key, ".")
	return key, prefix
}

// sealed is random bytes of the right shape. The reader is a fake and opens
// nothing; the relay must carry them through unchanged.
func sealed(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32+120)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func consent(requestID, prefix string) map[string]any {
	return map[string]any{
		"request_id": requestID, "key_prefix": prefix, "client_name": "Claude",
		"expires_at": time.Now().Add(90 * 24 * time.Hour).UTC().Format(time.RFC3339),
		"kid":        readerKID, "sealed": "",
	}
}

type reply struct {
	status int
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

// call sends a request to the server. A body of []byte goes as-is; anything
// else is JSON.
func (h *harness) call(t *testing.T, method, path string, body any, headers map[string]string) reply {
	t.Helper()
	var payload io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		payload = bytes.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		payload = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, h.srv.URL+path, payload)
	if err != nil {
		t.Fatal(err)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
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
	return reply{status: resp.StatusCode, body: raw}
}

func bearer(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

func internal() map[string]string { return bearer(relaySecret) }

func expect(t *testing.T, r reply, status int, code string) {
	t.Helper()
	if r.status != status {
		t.Fatalf("status = %d, want %d: %s", r.status, status, r.body)
	}
	if code != "" && r.code(t) != code {
		t.Fatalf("code = %q, want %q: %s", r.code(t), code, r.body)
	}
}

// approve runs a consent through to a pending connection and returns it.
func (h *harness) approve(t *testing.T, token string) (id string, requestID string) {
	t.Helper()
	requestID, _ = h.reader.pending(t, "Claude", "claude.ai")
	_, prefix := h.provisionalKey(t, "consent")
	body := consent(requestID, prefix)
	body["sealed"] = sealed(t)
	r := h.call(t, http.MethodPost, "/v1/mcp/connections", body, bearer(token))
	expect(t, r, http.StatusCreated, "")
	var created struct {
		ID string `json:"id"`
	}
	r.into(t, &created)
	return created.ID, requestID
}

// ---------------------------------------------------------------------------

// The whole hand-off, in order: the console reads the descriptor, consents,
// the reader activates over the internal route, the list shows it, and a
// revocation ends it on both sides.
func TestConnectionLifecycle(t *testing.T) {
	h := newHarness(t)
	owner := h.session(t, h.owner)
	requestID, descriptor := h.reader.pending(t, "Claude", "claude.ai")

	// Descriptor relay, unauthenticated, byte for byte what the reader said.
	r := h.call(t, http.MethodGet, "/v1/mcp/requests/"+requestID, nil, nil)
	expect(t, r, http.StatusOK, "")
	var relayed map[string]any
	r.into(t, &relayed)
	for _, k := range []string{"request_id", "kid", "reader_public_key", "client_name", "redirect_host", "code_challenge", "resource", "expires_at"} {
		if relayed[k] != descriptor[k] {
			t.Fatalf("descriptor field %s = %v, want %v", k, relayed[k], descriptor[k])
		}
	}
	if !h.reader.sawSecret() {
		t.Fatal("the relay did not present the secret")
	}

	// Consent.
	key, prefix := h.provisionalKey(t, "consent")
	body := consent(requestID, prefix)
	body["sealed"] = sealed(t)
	r = h.call(t, http.MethodPost, "/v1/mcp/connections", body, bearer(owner))
	expect(t, r, http.StatusCreated, "")
	var created struct {
		ID          string    `json:"id"`
		Status      string    `json:"status"`
		ExpiresAt   time.Time `json:"expires_at"`
		CompleteURL string    `json:"complete_url"`
	}
	r.into(t, &created)
	if created.Status != "pending" || created.CompleteURL != publicOrigin+"/mcp/authorize/complete" || uuid.MustParse(created.ID) == uuid.Nil {
		t.Fatalf("created = %+v", created)
	}
	want, _ := time.Parse(time.RFC3339, body["expires_at"].(string))
	if !created.ExpiresAt.Equal(want) {
		t.Fatalf("expires_at = %v, want the consented %v", created.ExpiresAt, want)
	}
	// The reader got exactly the sealed bytes, with the ledger's ids around them.
	got := h.reader.bundle(requestID)
	if got == nil || got["connection_id"] != created.ID || got["tenant_id"] != h.tenant.String() || got["kid"] != readerKID || got["sealed"] != body["sealed"] {
		t.Fatalf("bundle relayed = %v", got)
	}
	if at, err := time.Parse(time.RFC3339, got["expires_at"].(string)); err != nil || !at.Equal(want) {
		t.Fatalf("relayed expires_at = %v (%v)", got["expires_at"], err)
	}
	// And the key was promoted from twenty minutes to the consented lifetime.
	keys, err := h.keys.List(context.Background(), h.tenant.String())
	if err != nil || len(keys) != 1 || keys[0].ExpiresAt == nil || !keys[0].ExpiresAt.Truncate(time.Second).Equal(want) {
		t.Fatalf("keys = %+v %v", keys, err)
	}

	// The reader's view, over the internal route.
	r = h.call(t, http.MethodGet, "/v1/mcp/internal/connections/"+created.ID, nil, internal())
	expect(t, r, http.StatusOK, "")
	var standing struct {
		Status    string    `json:"status"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	r.into(t, &standing)
	if standing.Status != "pending" || !standing.ExpiresAt.Equal(want) {
		t.Fatalf("standing = %+v", standing)
	}
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/internal/connections/"+created.ID+"/activate", nil, internal()), http.StatusNoContent, "")
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/internal/connections/"+created.ID+"/activate", nil, internal()), http.StatusConflict, "connection_state")
	r = h.call(t, http.MethodGet, "/v1/mcp/internal/connections/"+created.ID, nil, internal())
	r.into(t, &standing)
	if standing.Status != "active" {
		t.Fatalf("after activation: %+v", standing)
	}

	// The console's list: every field the card shows, and no secret.
	r = h.call(t, http.MethodGet, "/v1/mcp/connections", nil, bearer(owner))
	expect(t, r, http.StatusOK, "")
	if strings.Contains(string(r.body), key) || strings.Contains(string(r.body), body["sealed"].(string)) || strings.Contains(string(r.body), requestID) {
		t.Fatal("the list carries something it should not")
	}
	var listed struct {
		Connections []struct {
			ID           string     `json:"id"`
			ClientName   string     `json:"client_name"`
			RedirectHost string     `json:"redirect_host"`
			Status       string     `json:"status"`
			DeviceCount  int        `json:"device_count"`
			KeyPrefix    string     `json:"key_prefix"`
			CreatedAt    time.Time  `json:"created_at"`
			ActivatedAt  *time.Time `json:"activated_at"`
			ExpiresAt    time.Time  `json:"expires_at"`
			LastSeenAt   *time.Time `json:"last_seen_at"`
		} `json:"connections"`
	}
	r.into(t, &listed)
	if len(listed.Connections) != 1 {
		t.Fatalf("listed = %s", r.body)
	}
	c := listed.Connections[0]
	if c.ID != created.ID || c.ClientName != "Claude" || c.RedirectHost != "claude.ai" || c.Status != "active" ||
		c.DeviceCount != 1 || c.KeyPrefix != prefix || c.CreatedAt.IsZero() || c.ActivatedAt == nil || c.LastSeenAt == nil || !c.ExpiresAt.Equal(want) {
		t.Fatalf("listed connection = %+v", c)
	}

	// Revocation: the row, the key, and a word to the reader.
	expect(t, h.call(t, http.MethodDelete, "/v1/mcp/connections/"+created.ID, nil, bearer(owner)), http.StatusNoContent, "")
	if got := h.reader.revocations(); len(got) != 1 || got[0] != created.ID {
		t.Fatalf("reader told about %v", got)
	}
	if _, err := h.keys.Verify(context.Background(), key); !errors.Is(err, store.ErrInvalidKey) {
		t.Fatalf("the key still opens after revocation: %v", err)
	}
	r = h.call(t, http.MethodGet, "/v1/mcp/connections", nil, bearer(owner))
	r.into(t, &listed)
	if len(listed.Connections) != 1 || listed.Connections[0].Status != "revoked" {
		t.Fatalf("after revocation: %s", r.body)
	}
	r = h.call(t, http.MethodGet, "/v1/mcp/internal/connections/"+created.ID, nil, internal())
	r.into(t, &standing)
	if standing.Status != "revoked" {
		t.Fatalf("the reader would still see %+v", standing)
	}
	// Ending it again, from either side, is not an error.
	expect(t, h.call(t, http.MethodDelete, "/v1/mcp/connections/"+created.ID, nil, bearer(owner)), http.StatusNoContent, "")
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/internal/connections/"+created.ID+"/revoke", nil, internal()), http.StatusNoContent, "")
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/internal/connections/"+uuid.NewString()+"/revoke", nil, internal()), http.StatusNoContent, "")
	expect(t, h.call(t, http.MethodDelete, "/v1/mcp/connections/"+uuid.NewString(), nil, bearer(owner)), http.StatusNotFound, "not_found")
	expect(t, h.call(t, http.MethodGet, "/v1/mcp/internal/connections/"+uuid.NewString(), nil, internal()), http.StatusNotFound, "not_found")
	expect(t, h.call(t, http.MethodGet, "/v1/mcp/internal/connections/not-a-uuid", nil, internal()), http.StatusNotFound, "not_found")
}

// The reader ending a connection on its own word — a burnt request, a bad
// bundle — revokes the key too.
func TestReaderRevocationRevokesKey(t *testing.T) {
	h := newHarness(t)
	id, _ := h.approve(t, h.session(t, h.owner))
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/internal/connections/"+id+"/revoke", nil, internal()), http.StatusNoContent, "")
	keys, err := h.keys.List(context.Background(), h.tenant.String())
	if err != nil || len(keys) != 1 || keys[0].RevokedAt.IsZero() {
		t.Fatalf("keys after the reader's revocation = %+v %v", keys, err)
	}
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/internal/connections/"+id+"/activate", nil, internal()), http.StatusConflict, "connection_state")
}

// A member may look but may not consent or revoke; nobody may without a
// session.
func TestMemberCannotConsent(t *testing.T) {
	h := newHarness(t)
	member := h.session(t, h.person(t, "member"))
	owner := h.session(t, h.owner)
	requestID, _ := h.reader.pending(t, "Claude", "claude.ai")
	_, prefix := h.provisionalKey(t, "member")
	body := consent(requestID, prefix)
	body["sealed"] = sealed(t)

	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", body, bearer(member)), http.StatusForbidden, "not_authorized")
	if h.reader.bundle(requestID) != nil {
		t.Fatal("a refused consent reached the reader")
	}
	if listed, err := h.conns.List(context.Background(), h.tenant); err != nil || len(listed) != 0 {
		t.Fatalf("a refused consent left a row: %+v %v", listed, err)
	}

	id, _ := h.approve(t, owner)
	expect(t, h.call(t, http.MethodDelete, "/v1/mcp/connections/"+id, nil, bearer(member)), http.StatusForbidden, "not_authorized")
	expect(t, h.call(t, http.MethodGet, "/v1/mcp/connections", nil, bearer(member)), http.StatusOK, "")

	expect(t, h.call(t, http.MethodGet, "/v1/mcp/connections", nil, nil), http.StatusUnauthorized, "unauthorized")
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", body, bearer("not-a-session")), http.StatusUnauthorized, "unauthorized")
	expect(t, h.call(t, http.MethodDelete, "/v1/mcp/connections/"+id, nil, nil), http.StatusUnauthorized, "unauthorized")
}

// Every field of a consent has one shape.
func TestConsentValidation(t *testing.T) {
	h := newHarness(t)
	owner := h.session(t, h.owner)
	requestID, _ := h.reader.pending(t, "Claude", "claude.ai")
	_, prefix := h.provisionalKey(t, "shape")
	good := func() map[string]any {
		b := consent(requestID, prefix)
		b["sealed"] = sealed(t)
		return b
	}

	oversize := good()
	oversize["sealed"] = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 65<<10))
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", oversize, bearer(owner)), http.StatusBadRequest, "bad_request")

	for name, mutate := range map[string]func(map[string]any){
		"unknown field":     func(b map[string]any) { b["device_ids"] = []string{} },
		"short request id":  func(b map[string]any) { b["request_id"] = requestID[:21] },
		"padded request id": func(b map[string]any) { b["request_id"] = requestID[:20] + "==" },
		"bad prefix":        func(b map[string]any) { b["key_prefix"] = "ABCDEF01" },
		"short kid":         func(b map[string]any) { b["kid"] = readerKID[:15] },
		"other kid":         func(b map[string]any) { b["kid"] = "fedcba9876543210" },
		"empty client name": func(b map[string]any) { b["client_name"] = "  " },
		"long client name":  func(b map[string]any) { b["client_name"] = strings.Repeat("x", 101) },
		"long in code points": func(b map[string]any) {
			// 101 code points of two bytes each: the reader counts code
			// points, so must this side.
			b["client_name"] = strings.Repeat("é", 101)
		},
		"control characters": func(b map[string]any) { b["client_name"] = "Cla\x00ude" },
		"c1 control":         func(b map[string]any) { b["client_name"] = "Cla\u0085ude" },
		"outside the plane":  func(b map[string]any) { b["client_name"] = "Claude \U0001F680" },
		"other client name":  func(b map[string]any) { b["client_name"] = "ChatGPT" },
		"bad expiry":         func(b map[string]any) { b["expires_at"] = "tomorrow" },
		"past expiry":        func(b map[string]any) { b["expires_at"] = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339) },
		"far expiry": func(b map[string]any) {
			b["expires_at"] = time.Now().Add(366 * 24 * time.Hour).UTC().Format(time.RFC3339)
		},
		"padded sealed": func(b map[string]any) { b["sealed"] = base64.URLEncoding.EncodeToString(make([]byte, 50)) },
		"standard base64": func(b map[string]any) {
			b["sealed"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xfb, 0xff}, 40))
		},
		"short sealed": func(b map[string]any) { b["sealed"] = base64.RawURLEncoding.EncodeToString(make([]byte, 47)) },
		"empty sealed": func(b map[string]any) { b["sealed"] = "" },
	} {
		t.Run(name, func(t *testing.T) {
			b := good()
			mutate(b)
			expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", b, bearer(owner)), http.StatusBadRequest, "bad_request")
		})
	}
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", []byte("{"), bearer(owner)), http.StatusBadRequest, "bad_request")
	if h.reader.bundle(requestID) != nil {
		t.Fatal("a refused consent reached the reader")
	}
	if listed, err := h.conns.List(context.Background(), h.tenant); err != nil || len(listed) != 0 {
		t.Fatalf("refused consents left rows: %+v %v", listed, err)
	}
}

// The key must be this workspace's and the right kind; the request must be
// one the reader still holds.
func TestConsentRefusals(t *testing.T) {
	h := newHarness(t)
	owner := h.session(t, h.owner)
	admin := h.person(t, "admin")
	ctx := context.Background()

	t.Run("unknown key", func(t *testing.T) {
		requestID, _ := h.reader.pending(t, "Claude", "claude.ai")
		b := consent(requestID, "0123abcd")
		b["sealed"] = sealed(t)
		expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", b, bearer(owner)), http.StatusNotFound, "not_found")
	})
	t.Run("unrestricted key", func(t *testing.T) {
		requestID, _ := h.reader.pending(t, "Claude", "claude.ai")
		in := time.Now().Add(20 * time.Minute)
		key, err := h.keys.IssueActingAsForDevices(ctx, h.tenant.String(), "all", store.ScopeRead, &h.owner.ID, nil, nil, &in)
		if err != nil {
			t.Fatal(err)
		}
		prefix, _, _ := strings.Cut(key, ".")
		b := consent(requestID, prefix)
		b["sealed"] = sealed(t)
		expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", b, bearer(owner)), http.StatusUnprocessableEntity, "key_unsuitable")
	})
	t.Run("send key", func(t *testing.T) {
		requestID, _ := h.reader.pending(t, "Claude", "claude.ai")
		in := time.Now().Add(20 * time.Minute)
		key, err := h.keys.IssueActingAsForDevices(ctx, h.tenant.String(), "send", store.ScopeSend, &h.owner.ID, nil, []uuid.UUID{h.device}, &in)
		if err != nil {
			t.Fatal(err)
		}
		prefix, _, _ := strings.Cut(key, ".")
		b := consent(requestID, prefix)
		b["sealed"] = sealed(t)
		expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", b, bearer(owner)), http.StatusUnprocessableEntity, "key_unsuitable")
	})
	t.Run("key without deadline", func(t *testing.T) {
		requestID, _ := h.reader.pending(t, "Claude", "claude.ai")
		key, err := h.keys.IssueActingAsForDevices(ctx, h.tenant.String(), "forever", store.ScopeRead, &h.owner.ID, nil, []uuid.UUID{h.device}, nil)
		if err != nil {
			t.Fatal(err)
		}
		prefix, _, _ := strings.Cut(key, ".")
		b := consent(requestID, prefix)
		b["sealed"] = sealed(t)
		expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", b, bearer(owner)), http.StatusUnprocessableEntity, "key_unsuitable")
	})
	t.Run("another admin's key", func(t *testing.T) {
		// A provisional key someone else minted is not this person's to
		// bind, and to them it does not exist.
		requestID, _ := h.reader.pending(t, "Claude", "claude.ai")
		in := time.Now().Add(20 * time.Minute)
		key, err := h.keys.IssueActingAsForDevices(ctx, h.tenant.String(), "theirs", store.ScopeRead, &admin.ID, nil, []uuid.UUID{h.device}, &in)
		if err != nil {
			t.Fatal(err)
		}
		prefix, _, _ := strings.Cut(key, ".")
		b := consent(requestID, prefix)
		b["sealed"] = sealed(t)
		expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", b, bearer(owner)), http.StatusNotFound, "not_found")
	})
	t.Run("key with a long deadline", func(t *testing.T) {
		requestID, _ := h.reader.pending(t, "Claude", "claude.ai")
		in := time.Now().Add(7 * 24 * time.Hour)
		key, err := h.keys.IssueActingAsForDevices(ctx, h.tenant.String(), "week", store.ScopeRead, &h.owner.ID, nil, []uuid.UUID{h.device}, &in)
		if err != nil {
			t.Fatal(err)
		}
		prefix, _, _ := strings.Cut(key, ".")
		b := consent(requestID, prefix)
		b["sealed"] = sealed(t)
		expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", b, bearer(owner)), http.StatusUnprocessableEntity, "key_unsuitable")
	})
	t.Run("request the reader forgot", func(t *testing.T) {
		_, prefix := h.provisionalKey(t, "late")
		b := consent(base64.RawURLEncoding.EncodeToString(make([]byte, 16)), prefix)
		b["sealed"] = sealed(t)
		expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", b, bearer(owner)), http.StatusNotFound, "not_found")
	})
	t.Run("redirect host outside the list", func(t *testing.T) {
		requestID, _ := h.reader.pending(t, "Claude", "evil.example")
		_, prefix := h.provisionalKey(t, "host")
		b := consent(requestID, prefix)
		b["sealed"] = sealed(t)
		expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", b, bearer(owner)), http.StatusBadRequest, "bad_request")
	})
	t.Run("reader on another origin", func(t *testing.T) {
		// The reader's public origin and this server's have drifted apart:
		// the console would refuse the completion address, so the ledger is
		// not touched and the key stays as it was.
		for _, resource := range []string{"https://other.example.test/mcp", publicOrigin + "/", publicOrigin, ""} {
			requestID, descriptor := h.reader.pending(t, "Claude", "claude.ai")
			h.reader.mu.Lock()
			descriptor["resource"] = resource
			h.reader.mu.Unlock()
			key, prefix := h.provisionalKey(t, "origin")
			b := consent(requestID, prefix)
			b["sealed"] = sealed(t)
			expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", b, bearer(owner)), http.StatusBadGateway, "reader_unavailable")
			if h.reader.bundle(requestID) != nil {
				t.Fatalf("resource %q: a refused consent reached the reader", resource)
			}
			if _, err := h.keys.Verify(context.Background(), key); err != nil {
				t.Fatalf("resource %q: the provisional key was touched: %v", resource, err)
			}
		}
	})
	if listed, err := h.conns.List(ctx, h.tenant); err != nil || len(listed) != 0 {
		t.Fatalf("refused consents left rows: %+v %v", listed, err)
	}
	t.Run("sixth live connection", func(t *testing.T) {
		for i := 0; i < 5; i++ {
			h.approve(t, owner)
		}
		requestID, _ := h.reader.pending(t, "Claude", "claude.ai")
		_, prefix := h.provisionalKey(t, "sixth")
		b := consent(requestID, prefix)
		b["sealed"] = sealed(t)
		expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", b, bearer(owner)), http.StatusConflict, "too_many_connections")
		if h.reader.bundle(requestID) != nil {
			t.Fatal("a refused consent reached the reader")
		}
	})
}

// A client name the reader accepted must pass a consent: same character
// class (printable ASCII and the Basic Multilingual Plane from U+00A0),
// counted in code points, trimmed the way the console's trim trims. A name
// registered with a no-break space or sixty accented characters is the
// common case, not the corner.
func TestClientNameMatchesReader(t *testing.T) {
	h := newHarness(t)
	owner := h.session(t, h.owner)
	for name, tc := range map[string]struct{ registered, consented string }{
		"no-break space":       {"Claude\u00a0Web", "Claude\u00a0Web"},
		"hundred accented":     {strings.Repeat("é", 100), strings.Repeat("é", 100)},
		"dashes and symbols":   {"Claude – Web ✓", "Claude – Web ✓"},
		"trimmed like the web": {"\u00a0\ufeffClaude \u2028", "Claude"},
	} {
		t.Run(name, func(t *testing.T) {
			requestID, _ := h.reader.pending(t, tc.registered, "claude.ai")
			_, prefix := h.provisionalKey(t, name)
			b := consent(requestID, prefix)
			b["client_name"] = tc.consented
			b["sealed"] = sealed(t)
			r := h.call(t, http.MethodPost, "/v1/mcp/connections", b, bearer(owner))
			expect(t, r, http.StatusCreated, "")
			if h.reader.bundle(requestID) == nil {
				t.Fatal("the consent did not reach the reader")
			}
		})
	}
	r := h.call(t, http.MethodGet, "/v1/mcp/connections", nil, bearer(owner))
	expect(t, r, http.StatusOK, "")
	var listed struct {
		Connections []struct {
			ClientName string `json:"client_name"`
		} `json:"connections"`
	}
	r.into(t, &listed)
	names := map[string]bool{}
	for _, c := range listed.Connections {
		names[c.ClientName] = true
	}
	for _, want := range []string{"Claude\u00a0Web", strings.Repeat("é", 100), "Claude – Web ✓", "Claude"} {
		if !names[want] {
			t.Fatalf("listed names %v lack %q", names, want)
		}
	}
}

// The descriptor is read on every render of the consent card, so it is
// metered on its own budget, per request id, and not on the sign-in one.
func TestDescriptorHasItsOwnBudget(t *testing.T) {
	h := newHarness(t)
	h.mux = http.NewServeMux()
	(&mcpauth.Handler{
		Connections: h.conns, APIKeys: h.keys, Users: h.users,
		Reader: mcpauth.NewRelay(h.reader.srv.URL, relaySecret), PublicOrigin: publicOrigin, RelaySecret: relaySecret,
		RedirectHosts: []string{"claude.ai", "chatgpt.com"}, Log: slog.New(slog.DiscardHandler),
		// The sign-in budget would refuse the second fetch; the
		// descriptor's own allows three, and refills too slowly to matter.
		Limits:           &ratelimit.Auth{PerIP: ratelimit.New(1, 1), PerSubject: ratelimit.New(1, 1)},
		DescriptorLimits: &ratelimit.Auth{PerIP: ratelimit.New(1, 10), PerSubject: ratelimit.New(1, 3)},
	}).Mount(h.mux)
	h.srv.Close()
	h.srv = httptest.NewServer(h.mux)
	t.Cleanup(h.srv.Close)

	first, _ := h.reader.pending(t, "Claude", "claude.ai")
	second, _ := h.reader.pending(t, "Claude", "claude.ai")
	for i := range 3 {
		if r := h.call(t, http.MethodGet, "/v1/mcp/requests/"+first, nil, nil); r.status != http.StatusOK {
			t.Fatalf("fetch %d: status = %d: %s", i+1, r.status, r.body)
		}
	}
	// The fourth in a row on one id is refused, and says when to retry.
	req, err := http.NewRequest(http.MethodGet, h.srv.URL+"/v1/mcp/requests/"+first, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("fourth fetch: status = %d, Retry-After = %q", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	// Per id: another request from the same address is still served.
	expect(t, h.call(t, http.MethodGet, "/v1/mcp/requests/"+second, nil, nil), http.StatusOK, "")
}

// A hand-off the reader did not take leaves nothing behind: no row, and the
// provisional key is revoked rather than left to expire.
func TestRelayFailureLeavesNothing(t *testing.T) {
	h := newHarness(t)
	owner := h.session(t, h.owner)
	for name, tc := range map[string]struct {
		readerStatus int
		want         int
		code         string
	}{
		"reader down":    {http.StatusInternalServerError, http.StatusBadGateway, "reader_unavailable"},
		"reader refuses": {http.StatusBadRequest, http.StatusBadRequest, "bad_request"},
		"reader forgot":  {http.StatusNotFound, http.StatusNotFound, "not_found"},
	} {
		t.Run(name, func(t *testing.T) {
			requestID, _ := h.reader.pending(t, "Claude", "claude.ai")
			key, prefix := h.provisionalKey(t, name)
			b := consent(requestID, prefix)
			b["sealed"] = sealed(t)
			h.reader.mu.Lock()
			h.reader.bundleReply = tc.readerStatus
			h.reader.mu.Unlock()
			expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", b, bearer(owner)), tc.want, tc.code)
			h.reader.mu.Lock()
			h.reader.bundleReply = 0
			h.reader.mu.Unlock()

			if listed, err := h.conns.List(context.Background(), h.tenant); err != nil || len(listed) != 0 {
				t.Fatalf("the failed consent left a row: %+v %v", listed, err)
			}
			if _, err := h.keys.Verify(context.Background(), key); !errors.Is(err, store.ErrInvalidKey) {
				t.Fatalf("the key survived a failed hand-off: %v", err)
			}
		})
	}
	t.Run("reader unreachable", func(t *testing.T) {
		requestID, _ := h.reader.pending(t, "Claude", "claude.ai")
		_, prefix := h.provisionalKey(t, "gone")
		b := consent(requestID, prefix)
		b["sealed"] = sealed(t)
		h.reader.srv.Close()
		expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", b, bearer(owner)), http.StatusBadGateway, "reader_unavailable")
		expect(t, h.call(t, http.MethodGet, "/v1/mcp/requests/"+requestID, nil, nil), http.StatusBadGateway, "reader_unavailable")
	})
}

// The descriptor route is public; what it will not do is relay for an id
// that is not one, or for one the reader does not hold.
func TestDescriptorRoute(t *testing.T) {
	h := newHarness(t)
	expect(t, h.call(t, http.MethodGet, "/v1/mcp/requests/"+base64.RawURLEncoding.EncodeToString(make([]byte, 16)), nil, nil), http.StatusNotFound, "not_found")
	expect(t, h.call(t, http.MethodGet, "/v1/mcp/requests/too-short", nil, nil), http.StatusNotFound, "not_found")
	expect(t, h.call(t, http.MethodGet, "/v1/mcp/requests/"+strings.Repeat("a", 21)+".", nil, nil), http.StatusNotFound, "not_found")
}

// The internal routes answer only the reader: loopback, no proxy in between,
// and the secret. A caller that came through nginx gets the same 404 nginx
// gives; a loopback caller without the secret is told it needs one.
func TestInternalRoutesRefuseProxiedCallers(t *testing.T) {
	h := newHarness(t)
	id, _ := h.approve(t, h.session(t, h.owner))
	path := "/v1/mcp/internal/connections/" + id

	expect(t, h.call(t, http.MethodGet, path, nil, map[string]string{"Authorization": "Bearer " + relaySecret, "X-Forwarded-For": "203.0.113.5"}), http.StatusNotFound, "not_found")
	expect(t, h.call(t, http.MethodGet, path, nil, map[string]string{"Authorization": "Bearer " + relaySecret, "X-Forwarded-For": ""}), http.StatusNotFound, "not_found")
	expect(t, h.call(t, http.MethodGet, path, nil, bearer(strings.Repeat("wrong-", 8))), http.StatusUnauthorized, "unauthorized")
	expect(t, h.call(t, http.MethodGet, path, nil, bearer(relaySecret+"x")), http.StatusUnauthorized, "unauthorized")
	expect(t, h.call(t, http.MethodGet, path, nil, nil), http.StatusUnauthorized, "unauthorized")
	expect(t, h.call(t, http.MethodPost, path+"/activate", nil, nil), http.StatusUnauthorized, "unauthorized")
	expect(t, h.call(t, http.MethodGet, "/v1/mcp/internal/cimd?url=https://claude.ai/x", nil, nil), http.StatusUnauthorized, "unauthorized")

	// A peer that is not this host, even with the secret: the test server
	// only ever sees loopback, so the handler is called directly.
	for _, addr := range []string{"203.0.113.5:4242", "10.0.0.5:4242", "[2001:db8::1]:4242"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = addr
		req.Header.Set("Authorization", "Bearer "+relaySecret)
		w := httptest.NewRecorder()
		h.mux.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Fatalf("peer %s: status = %d, want 404", addr, w.Code)
		}
	}
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = "[::1]:4242"
	req.Header.Set("Authorization", "Bearer "+relaySecret)
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("IPv6 loopback: status = %d, want 200", w.Code)
	}

	// Still fine with the secret and no proxy.
	expect(t, h.call(t, http.MethodGet, path, nil, internal()), http.StatusOK, "")
}

// A transport that answers as the allowed host would, without a network.
type cimdHost struct {
	handler http.Handler
	mu      sync.Mutex
	seen    []string
}

func (c *cimdHost) fetched() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.seen...)
}

func (c *cimdHost) RoundTrip(req *http.Request) (*http.Response, error) {
	c.mu.Lock()
	c.seen = append(c.seen, req.URL.String())
	c.mu.Unlock()
	w := httptest.NewRecorder()
	c.handler.ServeHTTP(w, req)
	resp := w.Result()
	resp.Request = req
	return resp, nil
}

// The CIMD relay fetches exactly what the reader could have been allowed to
// reach: https, an allowed host, a real path, one hop, a small JSON body.
func TestCIMDRelayMatrix(t *testing.T) {
	h := newHarness(t)
	document := `{"client_id":"https://claude.ai/.well-known/oauth-client","redirect_uris":["https://claude.ai/api/mcp/auth_callback"]}`
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-client", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		//nolint:errcheck // test server
		_, _ = w.Write([]byte(document))
	})
	mux.HandleFunc("GET /moved", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://claude.ai/.well-known/oauth-client", http.StatusFound)
	})
	mux.HandleFunc("GET /large", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		//nolint:errcheck // test server
		_, _ = w.Write([]byte(`{"pad":"` + strings.Repeat("x", 9<<10) + `"}`))
	})
	mux.HandleFunc("GET /html", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		//nolint:errcheck // test server
		_, _ = w.Write([]byte(`<html>`))
	})
	mux.HandleFunc("GET /broken", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	})
	host := &cimdHost{handler: mux}
	// Re-mount with the local transport; the harness handler is rebuilt.
	h.mux = http.NewServeMux()
	(&mcpauth.Handler{
		Connections: h.conns, APIKeys: h.keys, Users: h.users,
		Reader: mcpauth.NewRelay(h.reader.srv.URL, relaySecret), PublicOrigin: publicOrigin, RelaySecret: relaySecret,
		RedirectHosts: []string{"claude.ai", "chatgpt.com"}, CIMDTransport: host, Log: slog.New(slog.DiscardHandler),
	}).Mount(h.mux)
	h.srv.Close()
	h.srv = httptest.NewServer(h.mux)
	t.Cleanup(h.srv.Close)

	r := h.call(t, http.MethodGet, "/v1/mcp/internal/cimd?url=https://claude.ai/.well-known/oauth-client", nil, internal())
	expect(t, r, http.StatusOK, "")
	if string(r.body) != document {
		t.Fatalf("document relayed = %s", r.body)
	}
	if fetched := host.fetched(); len(fetched) != 1 || fetched[0] != "https://claude.ai/.well-known/oauth-client" {
		t.Fatalf("fetched %v", fetched)
	}

	for name, tc := range map[string]struct {
		url  string
		want int
		code string
	}{
		"subdomain":       {"https://evil.claude.ai/.well-known/oauth-client", http.StatusBadRequest, "bad_request"},
		"suffix":          {"https://claude.ai.attacker.example/x", http.StatusBadRequest, "bad_request"},
		"plain http":      {"http://claude.ai/.well-known/oauth-client", http.StatusBadRequest, "bad_request"},
		"root path":       {"https://claude.ai/", http.StatusBadRequest, "bad_request"},
		"no path":         {"https://claude.ai", http.StatusBadRequest, "bad_request"},
		"explicit port":   {"https://claude.ai:443/x", http.StatusBadRequest, "bad_request"},
		"other port":      {"https://claude.ai:8443/x", http.StatusBadRequest, "bad_request"},
		"userinfo":        {"https://claude.ai@evil.example/x", http.StatusBadRequest, "bad_request"},
		"userinfo 2":      {"https://user@claude.ai/x", http.StatusBadRequest, "bad_request"},
		"query":           {"https://claude.ai/x?y=1", http.StatusBadRequest, "bad_request"},
		"fragment":        {"https://claude.ai/x%23frag", http.StatusBadRequest, "bad_request"},
		"dot dot":         {"https://claude.ai/a/../x", http.StatusBadRequest, "bad_request"},
		"upper host":      {"https://CLAUDE.AI/x", http.StatusBadRequest, "bad_request"},
		"not a url":       {"::", http.StatusBadRequest, "bad_request"},
		"empty":           {"", http.StatusBadRequest, "bad_request"},
		"redirect":        {"https://claude.ai/moved", http.StatusBadGateway, "cimd_unavailable"},
		"nine kilobytes":  {"https://claude.ai/large", http.StatusBadGateway, "cimd_unavailable"},
		"not json":        {"https://claude.ai/html", http.StatusBadGateway, "cimd_unavailable"},
		"server error":    {"https://claude.ai/broken", http.StatusBadGateway, "cimd_unavailable"},
		"missing":         {"https://claude.ai/absent", http.StatusBadGateway, "cimd_unavailable"},
		"other host path": {"https://chatgpt.com/absent", http.StatusBadGateway, "cimd_unavailable"},
	} {
		t.Run(name, func(t *testing.T) {
			before := len(host.fetched())
			q := "?url=" + strings.NewReplacer("#", "%23", "&", "%26", "?", "%3F").Replace(tc.url)
			expect(t, h.call(t, http.MethodGet, "/v1/mcp/internal/cimd"+q, nil, internal()), tc.want, tc.code)
			if after := host.fetched(); tc.want == http.StatusBadRequest && len(after) != before {
				t.Fatalf("a refused address was fetched: %v", after[before:])
			}
		})
	}
	expect(t, h.call(t, http.MethodGet, "/v1/mcp/internal/cimd", nil, internal()), http.StatusBadRequest, "bad_request")
	expect(t, h.call(t, http.MethodGet, "/v1/mcp/internal/cimd?url=https://claude.ai/x&url=https://claude.ai/y", nil, internal()), http.StatusBadRequest, "bad_request")
	expect(t, h.call(t, http.MethodGet, "/v1/mcp/internal/cimd?url=https://claude.ai/x", nil, nil), http.StatusUnauthorized, "unauthorized")
}

// The relay client on its own: bounded bodies, the secret on every call,
// and the reader's answers mapped to the three errors the handler knows.
func TestRelayClient(t *testing.T) {
	var gotAuth string
	var status int
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		//nolint:errcheck // test server
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	relay := mcpauth.NewRelay(srv.URL+"/", relaySecret)
	ctx := context.Background()

	status, body = http.StatusOK, `{"request_id":"x"}`
	if raw, err := relay.Descriptor(ctx, "x"); err != nil || string(raw) != body {
		t.Fatalf("descriptor = %s %v", raw, err)
	}
	if gotAuth != "Bearer "+relaySecret {
		t.Fatalf("authorization = %q", gotAuth)
	}
	status, body = http.StatusOK, `[1]`
	if _, err := relay.Descriptor(ctx, "x"); !errors.Is(err, mcpauth.ErrReaderUnavailable) {
		t.Fatalf("a non-object descriptor: %v", err)
	}
	status, body = http.StatusOK, `{"pad":"`+strings.Repeat("x", 65<<10)+`"}`
	if _, err := relay.Descriptor(ctx, "x"); !errors.Is(err, mcpauth.ErrReaderUnavailable) {
		t.Fatalf("an oversize descriptor: %v", err)
	}
	status, body = http.StatusNotFound, `{"code":"not_found"}`
	if _, err := relay.Descriptor(ctx, "x"); !errors.Is(err, mcpauth.ErrReaderNotFound) {
		t.Fatalf("404: %v", err)
	}
	status, body = http.StatusInternalServerError, ``
	if _, err := relay.Descriptor(ctx, "x"); !errors.Is(err, mcpauth.ErrReaderUnavailable) {
		t.Fatalf("500: %v", err)
	}
	status, body = http.StatusConflict, `{"code":"already_answered"}`
	if err := relay.Bundle(ctx, "x", mcpauth.BundleRelay{ConnectionID: "x"}); !errors.Is(err, mcpauth.ErrReaderRefused) || !strings.Contains(err.Error(), "already_answered") {
		t.Fatalf("409: %v", err)
	}
	status, body = http.StatusNotFound, ``
	if err := relay.Revoke(ctx, "x"); err != nil {
		t.Fatalf("a revoke the reader does not know is not an error: %v", err)
	}
	status, body = http.StatusBadGateway, ``
	if err := relay.Revoke(ctx, "x"); !errors.Is(err, mcpauth.ErrReaderUnavailable) {
		t.Fatalf("502 on revoke: %v", err)
	}
	// A bad base URL is unavailable, not a panic.
	if _, err := (&mcpauth.Relay{BaseURL: "http://127.0.0.1:1", Secret: relaySecret}).Descriptor(ctx, "x"); !errors.Is(err, mcpauth.ErrReaderUnavailable) {
		t.Fatalf("closed port: %v", err)
	}
}

// OpenAI's portal reads the whole response body as the token; until a
// submission issues one the path does not exist. Needs no database.
func TestOpenAIAppsChallenge(t *testing.T) {
	for _, tc := range []struct {
		token  string
		status int
	}{{"", http.StatusNotFound}, {"oa-verify-3f9c2e", http.StatusOK}} {
		mux := http.NewServeMux()
		(&mcpauth.Handler{OpenAIAppsChallenge: tc.token}).Mount(mux)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/openai-apps-challenge", nil))
		if rec.Code != tc.status {
			t.Fatalf("token %q: status %d, want %d", tc.token, rec.Code, tc.status)
		}
		if tc.token == "" {
			continue
		}
		if got := rec.Body.String(); got != tc.token {
			t.Errorf("body = %q, want exactly the token", got)
		}
		if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
			t.Errorf("Content-Type = %q", got)
		}
	}
}
