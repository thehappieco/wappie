package mcpauth_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/mcpauth"
	"whatserver2/internal/store"
)

// Two made-up attested readers. The secrets are 43 base64url characters, as
// the configuration requires, and mean nothing anywhere.
var (
	enclaveSecret     = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
	enclaveSecretNext = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32))
	stagingSecret     = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x33}, 32))
)

const (
	enclaveOrigin = "https://mcp.example.test"
	stagingOrigin = "https://mcp-staging.example.test"
	enclaveKID    = "fedcba9876543210"
	// enclaveRenewalKID is the kid every renewal of the fake attests.
	enclaveRenewalKID = "0f1e2d3c4b5a6978"
	enclavePCR0       = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

// fakeEnclave stands in for the reader in the enclave on the far side of the
// signed relay. It checks every request's signature the way the real one
// must, holds pending requests, and answers prepares with a document of
// random bytes: this server never verifies it, so its content is irrelevant
// and its hash is what matters.
type fakeEnclave struct {
	srv    *httptest.Server
	id     string
	secret string
	origin string

	mu           sync.Mutex
	requests     map[string]map[string]any
	bundles      map[string]map[string]any
	revoked      []string
	documents    map[string][]byte
	prepares     map[string]int
	prepareReply func(id string) (int, any) // nil answers normally
	unsigned     int
	lastNonce    string
	// bundleStatus and bundleCode, when set, answer every bundle hand-off
	// (consent or renewal) with that refusal; revokeStatus answers every
	// revocation notice.
	bundleStatus int
	bundleCode   string
	revokeStatus int
	// renewalKey is the key a renewal attests; renewalBundles are the
	// renewal hand-offs by renewal id.
	renewalKey     []byte
	renewalBundles map[string]map[string]any
	renewals       int
}

func newFakeEnclave(t *testing.T, id, secret, origin string) *fakeEnclave {
	t.Helper()
	f := &fakeEnclave{
		id: id, secret: secret, origin: origin,
		requests: map[string]map[string]any{}, bundles: map[string]map[string]any{},
		documents: map[string][]byte{}, prepares: map[string]int{},
		renewalBundles: map[string]map[string]any{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /internal/requests/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		d, ok := f.requests[r.PathValue("id")]
		f.mu.Unlock()
		if !ok {
			http.Error(w, `{"code":"not_found"}`, http.StatusNotFound)
			return
		}
		writeJSON(t, w, http.StatusOK, d)
	})
	mux.HandleFunc("POST /internal/requests/{id}/prepare", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var body struct {
			Nonce string `json:"nonce"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, `{"code":"bad_request"}`, http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.lastNonce = body.Nonce
		if f.prepareReply != nil {
			status, reply := f.prepareReply(id)
			writeJSON(t, w, status, reply)
			return
		}
		d, ok := f.requests[id]
		if !ok {
			http.Error(w, `{"code":"not_found"}`, http.StatusNotFound)
			return
		}
		f.prepares[id]++
		document := make([]byte, 4000)
		if _, err := rand.Read(document); err != nil {
			t.Error(err)
		}
		f.documents[id] = document
		prepared := map[string]any{}
		for k, v := range d {
			prepared[k] = v
		}
		prepared["attestation"] = map[string]any{
			"format": "aws-nitro-v1", "document": base64.RawURLEncoding.EncodeToString(document),
			"request_id": id, "resource": f.origin + "/mcp", "reader_id": f.id, "reader_version": "0.2.0",
			"tls_spki_sha256": strings.Repeat("a", 64), "policy_sha256": strings.Repeat("b", 64), "pcr0": enclavePCR0,
		}
		writeJSON(t, w, http.StatusOK, prepared)
	})
	mux.HandleFunc("POST /internal/requests/{id}/bundle", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, `{"code":"bad_request"}`, http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if _, ok := f.requests[r.PathValue("id")]; !ok {
			http.Error(w, `{"code":"not_found"}`, http.StatusNotFound)
			return
		}
		if f.bundleStatus != 0 {
			writeJSON(t, w, f.bundleStatus, map[string]string{"code": f.bundleCode})
			return
		}
		f.bundles[r.PathValue("id")] = body
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /internal/connections/{id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.revokeStatus != 0 {
			writeJSON(t, w, f.revokeStatus, map[string]string{"code": "unavailable"})
			return
		}
		f.revoked = append(f.revoked, r.PathValue("id"))
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /internal/connections/{id}/renewal", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Nonce string `json:"nonce"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, `{"code":"bad_request"}`, http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.lastNonce = body.Nonce
		f.renewals++
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			t.Error(err)
		}
		renewalID := base64.RawURLEncoding.EncodeToString(raw)
		document := make([]byte, 4000)
		if _, err := rand.Read(document); err != nil {
			t.Error(err)
		}
		f.documents[renewalID] = document
		writeJSON(t, w, http.StatusOK, map[string]any{
			"renewal_id": renewalID, "connection_id": r.PathValue("id"), "kid": enclaveRenewalKID,
			"reader_public_key": base64.RawURLEncoding.EncodeToString(f.renewalKey), "resource": f.origin + "/mcp",
			"device_ids": []string{}, "expires_at": time.Now().Add(20 * time.Minute).UTC().Format(time.RFC3339),
			"connection_expires_at": time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339),
			"attestation": map[string]any{
				"format": "aws-nitro-v1", "document": base64.RawURLEncoding.EncodeToString(document),
				"request_id": renewalID, "resource": f.origin + "/mcp", "reader_id": f.id, "reader_version": "0.3.0",
				"tls_spki_sha256": strings.Repeat("a", 64), "policy_sha256": strings.Repeat("b", 64), "pcr0": enclavePCR0,
			},
		})
	})
	mux.HandleFunc("POST /internal/connections/{id}/renewal/{renewal}/bundle", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, `{"code":"bad_request"}`, http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.bundleStatus != 0 {
			writeJSON(t, w, f.bundleStatus, map[string]string{"code": f.bundleCode})
			return
		}
		f.renewalBundles[r.PathValue("renewal")] = body
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /internal/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"ok": true, "reader_id": f.id, "reader_version": "0.2.0", "boot_id": "0011223344556677", "state": "ready",
			"pcr0": enclavePCR0, "tls_spki_sha256": strings.Repeat("a", 64), "cert_not_after": time.Now().Add(80 * 24 * time.Hour),
			"policy_sha256": strings.Repeat("b", 64), "acme_account_uri": "https://acme.example/acct/1", "relay_secrets": 1,
		})
	})
	f.srv = httptest.NewTLSServer(f.verify(t, mux))
	t.Cleanup(f.srv.Close)
	return f
}

// verify is the reader's side of the signature: the same canonical string,
// over the raw request target, with direction to-reader.
func (f *fakeEnclave) verify(t *testing.T, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		want := mcpauth.Signature(f.secret, mcpauth.DirectionToReader, f.id, r.Method, r.RequestURI,
			r.Header.Get(mcpauth.HeaderTimestamp), r.Header.Get(mcpauth.HeaderNonce), body)
		ts, _ := strconv.ParseInt(r.Header.Get(mcpauth.HeaderTimestamp), 10, 64)
		if r.Header.Get(mcpauth.HeaderReader) != f.id || r.Header.Get(mcpauth.HeaderSignature) != want ||
			len(r.Header.Get(mcpauth.HeaderNonce)) != 22 || time.Since(time.Unix(ts, 0)).Abs() > time.Minute {
			f.mu.Lock()
			f.unsigned++
			f.mu.Unlock()
			http.Error(w, `{"code":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		next.ServeHTTP(w, r)
	})
}

func writeJSON(t *testing.T, w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Error(err)
	}
}

// pendingKey registers a request whose per-request key is pub.
func (f *fakeEnclave) pendingKey(t *testing.T, pub []byte) string {
	t.Helper()
	id := f.pending(t)
	f.mu.Lock()
	f.requests[id]["reader_public_key"] = base64.RawURLEncoding.EncodeToString(pub)
	f.mu.Unlock()
	return id
}

// pending registers a request as the enclave would after /mcp/authorize.
func (f *fakeEnclave) pending(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	id := base64.RawURLEncoding.EncodeToString(raw)
	f.mu.Lock()
	f.requests[id] = map[string]any{
		"request_id": id, "kid": enclaveKID, "reader_public_key": base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		"client_id": "client-" + id[:6], "client_name": "Claude", "redirect_host": "claude.ai", "redirect_local": false,
		"code_challenge": strings.Repeat("c", 43), "resource": f.origin + "/mcp",
		"expires_at": time.Now().Add(20 * time.Minute).UTC().Format(time.RFC3339),
	}
	f.mu.Unlock()
	return id
}

func (f *fakeEnclave) relay() *mcpauth.SignedRelay {
	pool := x509.NewCertPool()
	pool.AddCert(f.srv.Certificate())
	return mcpauth.NewSignedRelay(f.id, f.srv.URL, f.secret, pool)
}

func (f *fakeEnclave) bundle(id string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bundles[id]
}

func (f *fakeEnclave) document(id string) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.documents[id]
}

func (f *fakeEnclave) revocations() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.revoked...)
}

func (f *fakeEnclave) refusedSignatures() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.unsigned
}

func (f *fakeEnclave) setPrepareReply(reply func(id string) (int, any)) {
	f.mu.Lock()
	f.prepareReply = reply
	f.mu.Unlock()
}

// attestedHarness is the ordinary harness with two attested readers beside
// the hosted one. The enclave's calls come from loopback, which is its peer;
// the staging reader's peer is an address the test never calls from, and it
// admits only a workspace that is not the harness's.
type attestedHarness struct {
	*harness
	enclave *fakeEnclave
	staging *fakeEnclave
	// contentOn is the content switch; the harness's workspace is the only
	// one listed. Off unless a test turns it on.
	contentOn atomic.Bool
	handler   *mcpauth.Handler
}

func newAttestedHarness(t *testing.T) *attestedHarness {
	t.Helper()
	h := &attestedHarness{
		harness: newHarness(t),
		enclave: newFakeEnclave(t, "enclave", enclaveSecret, enclaveOrigin),
		staging: newFakeEnclave(t, "staging", stagingSecret, stagingOrigin),
	}
	h.mux = http.NewServeMux()
	h.handler = &mcpauth.Handler{
		Connections: h.conns, APIKeys: h.keys, Users: h.users,
		Reader:       mcpauth.NewRelay(h.reader.srv.URL, relaySecret),
		PublicOrigin: publicOrigin, RelaySecret: relaySecret,
		RedirectHosts: []string{"claude.ai", "chatgpt.com"},
		Attested: []*mcpauth.AttestedReader{
			{
				ID: "enclave", PublicOrigin: enclaveOrigin, Relay: h.enclave.relay(),
				Secrets: []string{enclaveSecret, enclaveSecretNext},
				Peers:   []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("::1/128")},
				Tenants: []uuid.UUID{h.tenant},
			},
			{
				ID: "staging", PublicOrigin: stagingOrigin, Relay: h.staging.relay(),
				Secrets: []string{stagingSecret},
				Peers:   []netip.Prefix{netip.MustParsePrefix("203.0.113.9/32")},
				Tenants: []uuid.UUID{uuid.New()},
			},
		},
		States: store.NewMCPReaderStates(h.pool),
		// No network in tests: every metadata fetch fails, which is how
		// the guard tests tell a request that got through.
		CIMDTransport: noNetwork{},
		Log:           slog.New(slog.DiscardHandler),
		ContentReader: "enclave",
		ContentAllowed: func(tenant uuid.UUID) bool {
			return h.contentOn.Load() && tenant == h.tenant
		},
	}
	h.handler.Mount(h.mux)
	h.srv.Close()
	h.srv = httptest.NewServer(h.mux)
	t.Cleanup(h.srv.Close)
	return h
}

type noNetwork struct{}

func (noNetwork) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("no network in tests")
}

// serveSigned sends a signed request straight to the mux from the enclave's
// address, with no socket in between: for bodies a real client would still
// be writing when the server has already refused them.
func (h *attestedHarness) serveSigned(t *testing.T, method, target string, s signed, contentLength int64) *httptest.ResponseRecorder {
	t.Helper()
	ts := strconv.FormatInt(s.at.Unix(), 10)
	req := httptest.NewRequest(method, target, bytes.NewReader(s.body))
	req.ContentLength = contentLength
	req.RemoteAddr = "127.0.0.1:4242"
	req.Header.Set(mcpauth.HeaderReader, s.reader)
	req.Header.Set(mcpauth.HeaderTimestamp, ts)
	req.Header.Set(mcpauth.HeaderNonce, s.nonce)
	req.Header.Set(mcpauth.HeaderSignature, mcpauth.Signature(s.secret, s.direction, s.reader, method, target, ts, s.nonce, s.body))
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, req)
	return w
}

// signed is a request the enclave would send: headers built from the parts,
// so a test can get any one of them wrong.
type signed struct {
	reader, secret, direction string
	at                        time.Time
	nonce                     string
	body                      []byte
	// tamper, when set, changes the body after it was signed.
	tamper []byte
}

func freshNonce(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// asEnclave signs a request as the enclave, with a fresh nonce and now.
func asEnclave(t *testing.T) signed {
	return signed{reader: "enclave", secret: enclaveSecret, direction: mcpauth.DirectionToGo, at: time.Now(), nonce: freshNonce(t)}
}

func (h *attestedHarness) signedCall(t *testing.T, method, target string, s signed) (reply, http.Header) {
	t.Helper()
	body := s.body
	if s.tamper != nil {
		body = s.tamper
	}
	req, err := http.NewRequest(method, h.srv.URL+target, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if body == nil {
		req.Body = http.NoBody
	}
	ts := strconv.FormatInt(s.at.Unix(), 10)
	if s.reader != "" {
		req.Header.Set(mcpauth.HeaderReader, s.reader)
	}
	if s.secret != "" {
		req.Header.Set(mcpauth.HeaderTimestamp, ts)
		req.Header.Set(mcpauth.HeaderNonce, s.nonce)
		req.Header.Set(mcpauth.HeaderSignature, mcpauth.Signature(s.secret, s.direction, s.reader, method, target, ts, s.nonce, s.body))
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
		t.Errorf("%s %s: missing Cache-Control: no-store", method, target)
	}
	return reply{status: resp.StatusCode, body: raw}, resp.Header
}

func prepareNonce(t *testing.T, n int) map[string]any {
	t.Helper()
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return map[string]any{"nonce": base64.RawURLEncoding.EncodeToString(raw)}
}

// ---------------------------------------------------------------------------

// The contract's vectors, so the Node reader and this server agree on the
// canonical string byte for byte.
func TestSignatureVectors(t *testing.T) {
	const secret = "wappie-test-relay-secret-0123456789abcdefghij"
	body := []byte(`{"nonce":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"}`)
	if sum := sha256.Sum256(body); hex.EncodeToString(sum[:]) != "5abfe6385851c7e99e840bf25362e735b4adc8b617704a5cab1c8cf3aeae5a8f" {
		t.Fatalf("body hash = %x", sum)
	}
	got := mcpauth.Signature(secret, mcpauth.DirectionToReader, "enclave", "POST",
		"/internal/requests/AAAAAAAAAAAAAAAAAAAAAA/prepare", "1790300000", "BBBBBBBBBBBBBBBBBBBBBB", body)
	if got != "v1=4966d2e42ab13456589657b9df8429cd70b95f1ec2f9273e6e27b76aabe53456" {
		t.Fatalf("to-reader vector = %s", got)
	}
	got = mcpauth.Signature(secret, mcpauth.DirectionToGo, "enclave", "GET",
		"/v1/mcp/enclave/cimd?url=https%3A%2F%2Fclaude.ai%2Foauth%2Fmcp-oauth-client-metadata", "1790300000", "CCCCCCCCCCCCCCCCCCCCCC", nil)
	if got != "v1=9d67d123516b7dc431b14a28223a654d8f57299cc83022ae17cbc4554baef616" {
		t.Fatalf("to-go vector = %s", got)
	}
	// The method is upper-cased into the string, whatever the caller passed.
	if mcpauth.Signature(secret, mcpauth.DirectionToGo, "enclave", "get", "/x", "1", "n", nil) !=
		mcpauth.Signature(secret, mcpauth.DirectionToGo, "enclave", "GET", "/x", "1", "n", nil) {
		t.Fatal("method case changes the signature")
	}
}

// The whole attested hand-off: the console reads the descriptor (which only
// the enclave holds), is refused a consent until it prepared, prepares, and
// consents; the enclave gets the bundle over the signed relay, activates
// over its own route, and a revocation reaches it. The row names the reader
// and what it declared.
func TestAttestedConsentLifecycle(t *testing.T) {
	h := newAttestedHarness(t)
	owner := h.session(t, h.owner)
	requestID := h.enclave.pending(t)

	r := h.call(t, http.MethodGet, "/v1/mcp/requests/"+requestID, nil, nil)
	expect(t, r, http.StatusOK, "")
	var d map[string]any
	r.into(t, &d)
	if d["resource"] != enclaveOrigin+"/mcp" || d["kid"] != enclaveKID {
		t.Fatalf("descriptor = %v", d)
	}

	_, prefix := h.provisionalKey(t, "consent")
	body := consent(requestID, prefix)
	body["kid"] = enclaveKID
	body["sealed"] = sealed(t)
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", body, bearer(owner)), http.StatusConflict, "attestation_required")

	nonce := prepareNonce(t, 32)
	r = h.call(t, http.MethodPost, "/v1/mcp/requests/"+requestID+"/prepare", nonce, nil)
	expect(t, r, http.StatusOK, "")
	var prepared struct {
		RequestID   string `json:"request_id"`
		Attestation struct {
			Document string `json:"document"`
			PCR0     string `json:"pcr0"`
		} `json:"attestation"`
	}
	r.into(t, &prepared)
	if prepared.RequestID != requestID || prepared.Attestation.PCR0 != enclavePCR0 || prepared.Attestation.Document == "" {
		t.Fatalf("prepared = %s", r.body)
	}
	h.enclave.mu.Lock()
	sentNonce := h.enclave.lastNonce
	h.enclave.mu.Unlock()
	if sentNonce != nonce["nonce"] {
		t.Fatalf("the enclave was asked with nonce %q, not the browser's", sentNonce)
	}

	// A kid other than the prepared one is refused before the ledger.
	wrong := consent(requestID, prefix)
	wrong["kid"] = "0000000000000000"
	wrong["sealed"] = sealed(t)
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", wrong, bearer(owner)), http.StatusConflict, "attestation_required")

	r = h.call(t, http.MethodPost, "/v1/mcp/connections", body, bearer(owner))
	expect(t, r, http.StatusCreated, "")
	var created struct {
		ID          string `json:"id"`
		CompleteURL string `json:"complete_url"`
	}
	r.into(t, &created)
	if created.CompleteURL != enclaveOrigin+"/mcp/authorize/complete" {
		t.Fatalf("complete_url = %q, want the enclave's origin", created.CompleteURL)
	}
	if got := h.enclave.bundle(requestID); got == nil || got["connection_id"] != created.ID || got["kid"] != enclaveKID || got["sealed"] != body["sealed"] {
		t.Fatalf("bundle at the enclave = %v", got)
	}
	if h.reader.bundle(requestID) != nil {
		t.Fatal("the hosted reader was handed an enclave's bundle")
	}
	if n := h.enclave.refusedSignatures(); n != 0 {
		t.Fatalf("the enclave refused %d of this server's signatures", n)
	}

	rows, err := h.conns.List(context.Background(), h.tenant)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows = %+v %v", rows, err)
	}
	sum := sha256.Sum256(h.enclave.document(requestID))
	if rows[0].Reader != "enclave" || rows[0].ReaderMeasurement != "nitro:pcr0="+enclavePCR0+";doc="+hex.EncodeToString(sum[:]) {
		t.Fatalf("reader = %q, measurement = %q", rows[0].Reader, rows[0].ReaderMeasurement)
	}

	// The enclave's view, over its own signed route.
	r, _ = h.signedCall(t, http.MethodGet, "/v1/mcp/enclave/connections/"+created.ID, asEnclave(t))
	expect(t, r, http.StatusOK, "")
	var standing struct {
		Status string `json:"status"`
	}
	r.into(t, &standing)
	if standing.Status != "pending" {
		t.Fatalf("standing = %+v", standing)
	}
	// The hosted reader cannot see, activate or revoke the enclave's row.
	expect(t, h.call(t, http.MethodGet, "/v1/mcp/internal/connections/"+created.ID, nil, internal()), http.StatusNotFound, "not_found")
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/internal/connections/"+created.ID+"/activate", nil, internal()), http.StatusNotFound, "not_found")
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/internal/connections/"+created.ID+"/revoke", nil, internal()), http.StatusNoContent, "")

	r, _ = h.signedCall(t, http.MethodPost, "/v1/mcp/enclave/connections/"+created.ID+"/activate", asEnclave(t))
	expect(t, r, http.StatusNoContent, "")
	r, _ = h.signedCall(t, http.MethodPost, "/v1/mcp/enclave/connections/"+created.ID+"/activate", asEnclave(t))
	expect(t, r, http.StatusConflict, "connection_state")
	r, _ = h.signedCall(t, http.MethodPost, "/v1/mcp/enclave/connections/"+uuid.NewString()+"/activate", asEnclave(t))
	expect(t, r, http.StatusNotFound, "not_found")

	// The person revokes in the console; the enclave is told, the hosted
	// reader is not.
	expect(t, h.call(t, http.MethodDelete, "/v1/mcp/connections/"+created.ID, nil, bearer(owner)), http.StatusNoContent, "")
	if got := h.enclave.revocations(); len(got) != 1 || got[0] != created.ID {
		t.Fatalf("enclave revocations = %v", got)
	}
	if got := h.reader.revocations(); len(got) != 0 {
		t.Fatalf("hosted revocations = %v", got)
	}
	r, _ = h.signedCall(t, http.MethodGet, "/v1/mcp/enclave/connections/"+created.ID, asEnclave(t))
	r.into(t, &standing)
	if standing.Status != "revoked" {
		t.Fatalf("after revoke: %+v", standing)
	}
	// An unknown id is as revoked as it gets.
	r, _ = h.signedCall(t, http.MethodPost, "/v1/mcp/enclave/connections/"+uuid.NewString()+"/revoke", asEnclave(t))
	expect(t, r, http.StatusNoContent, "")
}

// A hosted connection is the enclave's to neither read nor end.
func TestEnclaveCannotReachHostedRows(t *testing.T) {
	h := newAttestedHarness(t)
	id, _ := h.approve(t, h.session(t, h.owner))
	rows, err := h.conns.List(context.Background(), h.tenant)
	if err != nil || len(rows) != 1 || rows[0].Reader != "hosted" || rows[0].ReaderMeasurement != "" {
		t.Fatalf("hosted row = %+v %v", rows, err)
	}
	r, _ := h.signedCall(t, http.MethodGet, "/v1/mcp/enclave/connections/"+id, asEnclave(t))
	expect(t, r, http.StatusNotFound, "not_found")
	r, _ = h.signedCall(t, http.MethodPost, "/v1/mcp/enclave/connections/"+id+"/activate", asEnclave(t))
	expect(t, r, http.StatusNotFound, "not_found")
	r, _ = h.signedCall(t, http.MethodPost, "/v1/mcp/enclave/connections/"+id+"/revoke", asEnclave(t))
	expect(t, r, http.StatusNoContent, "")
	// Still there for its own reader.
	r = h.call(t, http.MethodGet, "/v1/mcp/internal/connections/"+id, nil, internal())
	expect(t, r, http.StatusOK, "")
	var standing struct {
		Status string `json:"status"`
	}
	r.into(t, &standing)
	if standing.Status != "pending" {
		t.Fatalf("the enclave's revoke reached a hosted row: %+v", standing)
	}
	// And the console's revocation of a hosted row tells the hosted reader only.
	expect(t, h.call(t, http.MethodDelete, "/v1/mcp/connections/"+id, nil, bearer(h.session(t, h.owner))), http.StatusNoContent, "")
	if got := h.reader.revocations(); len(got) != 1 || got[0] != id {
		t.Fatalf("hosted revocations = %v", got)
	}
	if got := h.enclave.revocations(); len(got) != 0 {
		t.Fatalf("enclave revocations = %v", got)
	}
}

// Which reader holds a request is found by asking them all: the first 200
// wins, all 404 is 404, and no 200 with any failure is a 502 because the
// request may be with the reader that failed.
func TestReaderResolution(t *testing.T) {
	h := newAttestedHarness(t)

	hostedID, _ := h.reader.pending(t, "Claude", "claude.ai")
	r := h.call(t, http.MethodGet, "/v1/mcp/requests/"+hostedID, nil, nil)
	expect(t, r, http.StatusOK, "")
	var d map[string]any
	r.into(t, &d)
	if d["resource"] != publicOrigin+"/mcp" {
		t.Fatalf("hosted descriptor = %v", d)
	}

	stagingID := h.staging.pending(t)
	r = h.call(t, http.MethodGet, "/v1/mcp/requests/"+stagingID, nil, nil)
	expect(t, r, http.StatusOK, "")
	r.into(t, &d)
	if d["resource"] != stagingOrigin+"/mcp" {
		t.Fatalf("staging descriptor = %v", d)
	}

	expect(t, h.call(t, http.MethodGet, "/v1/mcp/requests/"+base64.RawURLEncoding.EncodeToString(make([]byte, 16)), nil, nil), http.StatusNotFound, "not_found")

	// One reader down: a request nobody else holds is unavailable, one
	// another reader holds is still served.
	h.staging.srv.Close()
	expect(t, h.call(t, http.MethodGet, "/v1/mcp/requests/"+base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16)), nil, nil), http.StatusBadGateway, "reader_unavailable")
	enclaveID := h.enclave.pending(t)
	expect(t, h.call(t, http.MethodGet, "/v1/mcp/requests/"+enclaveID, nil, nil), http.StatusOK, "")
	// A resolved request stays with its reader: the staging request is
	// remembered, so its reader is asked directly, and it is down.
	expect(t, h.call(t, http.MethodGet, "/v1/mcp/requests/"+stagingID, nil, nil), http.StatusBadGateway, "reader_unavailable")
}

// Prepare is for attested readers only, takes a nonce of 16 to 64 bytes and
// nothing else, and maps the reader's refusals.
func TestPrepareRules(t *testing.T) {
	h := newAttestedHarness(t)
	id := h.enclave.pending(t)
	path := "/v1/mcp/requests/" + id + "/prepare"

	hostedID, _ := h.reader.pending(t, "Claude", "claude.ai")
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/requests/"+hostedID+"/prepare", prepareNonce(t, 32), nil), http.StatusConflict, "attestation_unsupported")

	for name, body := range map[string]any{
		"15 bytes":       prepareNonce(t, 15),
		"65 bytes":       prepareNonce(t, 65),
		"padded":         map[string]any{"nonce": base64.URLEncoding.EncodeToString(make([]byte, 32))},
		"standard b64":   map[string]any{"nonce": strings.Repeat("+", 43)},
		"missing":        map[string]any{},
		"unknown key":    map[string]any{"nonce": prepareNonce(t, 32)["nonce"], "extra": 1},
		"not an object":  []byte(`"nonce"`),
		"nonce a number": map[string]any{"nonce": 12},
	} {
		t.Run(name, func(t *testing.T) {
			expect(t, h.call(t, http.MethodPost, path, body, nil), http.StatusBadRequest, "bad_request")
		})
	}
	expect(t, h.call(t, http.MethodPost, path, prepareNonce(t, 16), nil), http.StatusOK, "")
	expect(t, h.call(t, http.MethodPost, path, prepareNonce(t, 64), nil), http.StatusOK, "")
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/requests/"+base64.RawURLEncoding.EncodeToString(make([]byte, 16))+"/prepare", prepareNonce(t, 32), nil), http.StatusNotFound, "not_found")
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/requests/short/prepare", prepareNonce(t, 32), nil), http.StatusNotFound, "not_found")

	good := func(id string) map[string]any {
		return map[string]any{
			"request_id": id, "kid": enclaveKID, "resource": enclaveOrigin + "/mcp",
			"attestation": map[string]any{"document": base64.RawURLEncoding.EncodeToString(make([]byte, 100)), "pcr0": enclavePCR0},
		}
	}
	for name, tc := range map[string]struct {
		status int
		reply  func(id string) any
		want   int
		code   string
	}{
		"too many":      {http.StatusTooManyRequests, func(string) any { return map[string]string{"code": "too_many_prepares"} }, http.StatusTooManyRequests, "too_many_prepares"},
		"cannot attest": {http.StatusServiceUnavailable, func(string) any { return map[string]string{"code": "policy_unknown"} }, http.StatusBadGateway, "reader_unavailable"},
		"gone":          {http.StatusNotFound, func(string) any { return map[string]string{"code": "not_found"} }, http.StatusNotFound, "not_found"},
		"good":          {http.StatusOK, func(id string) any { return good(id) }, http.StatusOK, ""},
		"other request": {http.StatusOK, func(string) any {
			return good(base64.RawURLEncoding.EncodeToString(make([]byte, 16)))
		}, http.StatusBadGateway, "reader_unavailable"},
		"other resource": {http.StatusOK, func(id string) any {
			d := good(id)
			d["resource"] = publicOrigin + "/mcp"
			return d
		}, http.StatusBadGateway, "reader_unavailable"},
		"no attestation": {http.StatusOK, func(id string) any {
			d := good(id)
			delete(d, "attestation")
			return d
		}, http.StatusBadGateway, "reader_unavailable"},
		"document too large": {http.StatusOK, func(id string) any {
			d := good(id)
			d["attestation"] = map[string]any{"document": base64.RawURLEncoding.EncodeToString(make([]byte, 16<<10+1)), "pcr0": enclavePCR0}
			return d
		}, http.StatusBadGateway, "reader_unavailable"},
		"short pcr0": {http.StatusOK, func(id string) any {
			d := good(id)
			d["attestation"] = map[string]any{"document": "AAAA", "pcr0": enclavePCR0[:64]}
			return d
		}, http.StatusBadGateway, "reader_unavailable"},
		"not an object": {http.StatusOK, func(string) any { return []int{1} }, http.StatusBadGateway, "reader_unavailable"},
	} {
		t.Run(name, func(t *testing.T) {
			h.enclave.setPrepareReply(func(id string) (int, any) { return tc.status, tc.reply(id) })
			expect(t, h.call(t, http.MethodPost, path, prepareNonce(t, 32), nil), tc.want, tc.code)
		})
	}
}

// A reader limited to other workspaces refuses this one's consent, before
// the attestation question and before the ledger.
func TestAttestedTenantAllowlist(t *testing.T) {
	h := newAttestedHarness(t)
	owner := h.session(t, h.owner)
	id := h.staging.pending(t)
	_, prefix := h.provisionalKey(t, "staging")
	body := consent(id, prefix)
	body["kid"] = enclaveKID
	body["sealed"] = sealed(t)
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", body, bearer(owner)), http.StatusForbidden, "tenant_not_allowed")
	if rows, err := h.conns.List(context.Background(), h.tenant); err != nil || len(rows) != 0 {
		t.Fatalf("rows = %+v %v", rows, err)
	}
	if h.staging.bundle(id) != nil {
		t.Fatal("a refused consent reached the reader")
	}
}

// Each reader is held to its own resource: an enclave that advertises the
// hosted reader's is a deployment whose origins have drifted, and is refused
// before the ledger, as for the hosted reader.
func TestAttestedResourcePerReader(t *testing.T) {
	h := newAttestedHarness(t)
	owner := h.session(t, h.owner)
	id := h.enclave.pending(t)
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/requests/"+id+"/prepare", prepareNonce(t, 32), nil), http.StatusOK, "")
	h.enclave.mu.Lock()
	h.enclave.requests[id]["resource"] = publicOrigin + "/mcp"
	h.enclave.mu.Unlock()
	_, prefix := h.provisionalKey(t, "drift")
	body := consent(id, prefix)
	body["kid"] = enclaveKID
	body["sealed"] = sealed(t)
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", body, bearer(owner)), http.StatusBadGateway, "reader_unavailable")
	if rows, err := h.conns.List(context.Background(), h.tenant); err != nil || len(rows) != 0 {
		t.Fatalf("rows = %+v %v", rows, err)
	}
}

// The guard in front of every enclave route, check by check.
func TestSignedRoutesGuard(t *testing.T) {
	h := newAttestedHarness(t)
	const path = "/v1/mcp/enclave/cimd?url=https%3A%2F%2Fclaude.ai%2Fx"
	// A known connection id that is not the enclave's answers 404 once
	// through the guard, so a 404 below would be ambiguous; the cimd route
	// answers 502 for an address that fails to fetch, which only a request
	// that passed the guard can reach.
	passed := func(r reply) bool { return r.status == http.StatusBadGateway }

	ok := asEnclave(t)
	r, _ := h.signedCall(t, http.MethodGet, path, ok)
	if !passed(r) {
		t.Fatalf("a good request did not pass: %d %s", r.status, r.body)
	}

	for name, tc := range map[string]struct {
		s      func() signed
		status int
		code   string
	}{
		"no headers":     {func() signed { return signed{} }, http.StatusNotFound, "not_found"},
		"reader only":    {func() signed { return signed{reader: "enclave"} }, http.StatusUnauthorized, "unauthorized"},
		"unknown reader": {func() signed { s := asEnclave(t); s.reader = "nobody"; return s }, http.StatusNotFound, "not_found"},
		"hosted reader":  {func() signed { s := asEnclave(t); s.reader = "hosted"; return s }, http.StatusNotFound, "not_found"},
		"another reader's peer": {func() signed {
			return signed{reader: "staging", secret: stagingSecret, direction: mcpauth.DirectionToGo, at: time.Now(), nonce: freshNonce(t)}
		}, http.StatusNotFound, "not_found"},
		"61 seconds old":   {func() signed { s := asEnclave(t); s.at = time.Now().Add(-61 * time.Second); return s }, http.StatusUnauthorized, "unauthorized"},
		"61 seconds ahead": {func() signed { s := asEnclave(t); s.at = time.Now().Add(61 * time.Second); return s }, http.StatusUnauthorized, "unauthorized"},
		"wrong secret":     {func() signed { s := asEnclave(t); s.secret = stagingSecret; return s }, http.StatusUnauthorized, "unauthorized"},
		"other direction":  {func() signed { s := asEnclave(t); s.direction = mcpauth.DirectionToReader; return s }, http.StatusUnauthorized, "unauthorized"},
		"short nonce":      {func() signed { s := asEnclave(t); s.nonce = s.nonce[:21]; return s }, http.StatusUnauthorized, "unauthorized"},
		"nonce not b64url": {func() signed { s := asEnclave(t); s.nonce = strings.Repeat("+", 22); return s }, http.StatusUnauthorized, "unauthorized"},
		"tampered body":    {func() signed { s := asEnclave(t); s.tamper = []byte("x"); return s }, http.StatusUnauthorized, "unauthorized"},
		"next secret":      {func() signed { s := asEnclave(t); s.secret = enclaveSecretNext; return s }, http.StatusBadGateway, "cimd_unavailable"},
	} {
		t.Run(name, func(t *testing.T) {
			r, _ := h.signedCall(t, http.MethodGet, path, tc.s())
			expect(t, r, tc.status, tc.code)
		})
	}

	// Replay: the same signed request twice. The second is refused, and so
	// is the same nonce under a fresh timestamp and signature.
	replay := asEnclave(t)
	r, _ = h.signedCall(t, http.MethodGet, path, replay)
	if !passed(r) {
		t.Fatalf("first use refused: %d %s", r.status, r.body)
	}
	r, _ = h.signedCall(t, http.MethodGet, path, replay)
	expect(t, r, http.StatusUnauthorized, "unauthorized")
	replay.at = time.Now().Add(time.Second)
	r, _ = h.signedCall(t, http.MethodGet, path, replay)
	expect(t, r, http.StatusUnauthorized, "unauthorized")

	// The target is signed as sent: a signature over another query does not
	// cover this one.
	other := asEnclave(t)
	req, err := http.NewRequest(http.MethodGet, h.srv.URL+path+"y", nil)
	if err != nil {
		t.Fatal(err)
	}
	ts := strconv.FormatInt(other.at.Unix(), 10)
	req.Header.Set(mcpauth.HeaderReader, "enclave")
	req.Header.Set(mcpauth.HeaderTimestamp, ts)
	req.Header.Set(mcpauth.HeaderNonce, other.nonce)
	req.Header.Set(mcpauth.HeaderSignature, mcpauth.Signature(enclaveSecret, mcpauth.DirectionToGo, "enclave", "GET", path, ts, other.nonce, nil))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a signature over another target passed: %d", resp.StatusCode)
	}

	// Headers present twice are not well formed.
	dup := asEnclave(t)
	req, err = http.NewRequest(http.MethodGet, h.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	ts = strconv.FormatInt(dup.at.Unix(), 10)
	req.Header.Set(mcpauth.HeaderReader, "enclave")
	req.Header.Add(mcpauth.HeaderTimestamp, ts)
	req.Header.Add(mcpauth.HeaderTimestamp, ts)
	req.Header.Set(mcpauth.HeaderNonce, dup.nonce)
	req.Header.Set(mcpauth.HeaderSignature, mcpauth.Signature(enclaveSecret, mcpauth.DirectionToGo, "enclave", "GET", path, ts, dup.nonce, nil))
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a doubled timestamp passed: %d", resp.StatusCode)
	}

	// The peer check reads the socket's address, and the trusted proxies
	// when there are any: from anywhere else the route does not exist,
	// signature or not.
	for _, addr := range []string{"203.0.113.5:4242", "10.0.0.5:4242"} {
		s := asEnclave(t)
		ts := strconv.FormatInt(s.at.Unix(), 10)
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = addr
		req.Header.Set(mcpauth.HeaderReader, "enclave")
		req.Header.Set(mcpauth.HeaderTimestamp, ts)
		req.Header.Set(mcpauth.HeaderNonce, s.nonce)
		req.Header.Set(mcpauth.HeaderSignature, mcpauth.Signature(enclaveSecret, mcpauth.DirectionToGo, "enclave", "GET", path, ts, s.nonce, nil))
		w := httptest.NewRecorder()
		h.mux.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Fatalf("peer %s: status = %d, want 404", addr, w.Code)
		}
	}

	// The hosted bearer opens nothing here.
	expect(t, h.call(t, http.MethodGet, path, nil, internal()), http.StatusNotFound, "not_found")
}

// The state routes: a compare-and-swap per collection, generations from 1,
// a conflict that says where the state is, and names from a fixed list.
func TestReaderStateCAS(t *testing.T) {
	h := newAttestedHarness(t)
	put := func(name, gen string, blob []byte) (reply, http.Header) {
		s := asEnclave(t)
		s.body = blob
		return h.signedCall(t, http.MethodPut, "/v1/mcp/enclave/state/"+name+"?if_generation="+gen, s)
	}
	get := func(name string) (reply, http.Header) {
		return h.signedCall(t, http.MethodGet, "/v1/mcp/enclave/state/"+name, asEnclave(t))
	}
	generation := func(r reply) int64 {
		var g struct {
			Generation int64 `json:"generation"`
		}
		r.into(t, &g)
		return g.Generation
	}

	r, _ := get("as-tokens")
	expect(t, r, http.StatusNotFound, "not_found")
	r, _ = put("as-tokens", "1", []byte("WMCPSEAL first"))
	expect(t, r, http.StatusConflict, "generation_mismatch")
	if generation(r) != 0 {
		t.Fatalf("conflict on a missing row reports %s", r.body)
	}
	r, _ = put("as-tokens", "0", []byte("WMCPSEAL first"))
	expect(t, r, http.StatusOK, "")
	if generation(r) != 1 {
		t.Fatalf("create = %s", r.body)
	}
	r, _ = put("as-tokens", "0", []byte("WMCPSEAL again"))
	expect(t, r, http.StatusConflict, "generation_mismatch")
	if generation(r) != 1 {
		t.Fatalf("second create reports %s", r.body)
	}
	r, _ = put("as-tokens", "1", []byte("WMCPSEAL second"))
	expect(t, r, http.StatusOK, "")
	if generation(r) != 2 {
		t.Fatalf("update = %s", r.body)
	}
	r, _ = put("as-tokens", "1", []byte("WMCPSEAL stale"))
	expect(t, r, http.StatusConflict, "generation_mismatch")
	if generation(r) != 2 {
		t.Fatalf("stale write reports %s", r.body)
	}
	r, header := get("as-tokens")
	expect(t, r, http.StatusOK, "")
	if string(r.body) != "WMCPSEAL second" || header.Get("X-Wappie-Generation") != "2" || header.Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("get = %q %v", r.body, header)
	}
	// Collections are separate.
	r, _ = get("infra")
	expect(t, r, http.StatusNotFound, "not_found")

	for name, target := range map[string]string{
		"bad name":        "/v1/mcp/enclave/state/keys?if_generation=0",
		"no generation":   "/v1/mcp/enclave/state/infra",
		"negative":        "/v1/mcp/enclave/state/infra?if_generation=-1",
		"leading zero":    "/v1/mcp/enclave/state/infra?if_generation=01",
		"plus":            "/v1/mcp/enclave/state/infra?if_generation=%2B1",
		"not a number":    "/v1/mcp/enclave/state/infra?if_generation=one",
		"two generations": "/v1/mcp/enclave/state/infra?if_generation=0&if_generation=1",
		"huge":            "/v1/mcp/enclave/state/infra?if_generation=99999999999999999999",
	} {
		t.Run(name, func(t *testing.T) {
			s := asEnclave(t)
			s.body = []byte("WMCPSEAL x")
			r, _ := h.signedCall(t, http.MethodPut, target, s)
			expect(t, r, http.StatusBadRequest, "bad_request")
		})
	}
	s := asEnclave(t)
	r, _ = h.signedCall(t, http.MethodGet, "/v1/mcp/enclave/state/keys", s)
	expect(t, r, http.StatusBadRequest, "bad_request")
	r, _ = put("infra", "0", nil)
	expect(t, r, http.StatusBadRequest, "bad_request")
}

// The state route takes a body up to 12 MiB on its own reader, never through
// the 64 KiB JSON decoder: 11 MiB passes, 13 MiB is refused whether or not
// the length is declared up front. Other routes keep the 64 KiB limit.
func TestReaderStateSizeLimit(t *testing.T) {
	h := newAttestedHarness(t)
	blob := make([]byte, 11<<20)
	if _, err := rand.Read(blob); err != nil {
		t.Fatal(err)
	}
	s := asEnclave(t)
	s.body = blob
	r, _ := h.signedCall(t, http.MethodPut, "/v1/mcp/enclave/state/as-clients?if_generation=0", s)
	expect(t, r, http.StatusOK, "")
	r, _ = h.signedCall(t, http.MethodGet, "/v1/mcp/enclave/state/as-clients", asEnclave(t))
	expect(t, r, http.StatusOK, "")
	if !bytes.Equal(r.body, blob) {
		t.Fatal("the blob came back changed")
	}

	// 13 MiB, declared up front or streamed with no length: refused either
	// way, and exactly 12 MiB is still accepted.
	const target = "/v1/mcp/enclave/state/as-clients?if_generation=1"
	for name, length := range map[string]int64{"declared": 13 << 20, "streamed": -1} {
		s = asEnclave(t)
		s.body = make([]byte, 13<<20)
		w := h.serveSigned(t, http.MethodPut, target, s, length)
		if w.Code != http.StatusRequestEntityTooLarge || !strings.Contains(w.Body.String(), "body_too_large") {
			t.Fatalf("%s 13 MiB body: %d %s", name, w.Code, w.Body)
		}
	}
	s = asEnclave(t)
	s.body = make([]byte, 12<<20)
	if w := h.serveSigned(t, http.MethodPut, target, s, -1); w.Code != http.StatusOK {
		t.Fatalf("exactly 12 MiB: %d %s", w.Code, w.Body)
	}

	// 64 KiB elsewhere.
	s = asEnclave(t)
	s.body = make([]byte, 64<<10+1)
	w := h.serveSigned(t, http.MethodPost, "/v1/mcp/enclave/connections/"+uuid.NewString()+"/revoke", s, -1)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("65 KiB on a connection route: %d %s", w.Code, w.Body)
	}

	r, header := h.signedCall(t, http.MethodGet, "/v1/mcp/enclave/state/as-clients", asEnclave(t))
	expect(t, r, http.StatusOK, "")
	if header.Get("X-Wappie-Generation") != "2" || len(r.body) != 12<<20 {
		t.Fatalf("after the refused writes: generation %q, %d bytes", header.Get("X-Wappie-Generation"), len(r.body))
	}
}

// The signed relay on its own: every request signed as the reader checks it,
// WebPKI against the given roots, no redirects, a bounded answer, the
// reader's answers mapped to the handler's errors.
func TestSignedRelayClient(t *testing.T) {
	f := newFakeEnclave(t, "enclave", enclaveSecret, enclaveOrigin)
	relay := f.relay()
	ctx := context.Background()

	// Ten seconds, TLS 1.2 and up, the URL's host as the name to verify,
	// and no proxy from the environment between this server and the
	// enclave.
	transport, ok := relay.Client.Transport.(*http.Transport)
	if relay.Client.Timeout != 10*time.Second || !ok || transport.Proxy != nil ||
		transport.TLSClientConfig.MinVersion != tls.VersionTLS12 || transport.TLSClientConfig.ServerName != "127.0.0.1" {
		t.Fatalf("client = %+v", relay.Client)
	}
	if prod := mcpauth.NewSignedRelay("enclave", "https://mcp.example.test:8443", enclaveSecret, nil); prod.Client.Transport.(*http.Transport).TLSClientConfig.ServerName != "mcp.example.test" {
		t.Fatal("the server name is not the URL's host")
	}
	id := f.pending(t)
	if raw, err := relay.Descriptor(ctx, id); err != nil || !strings.Contains(string(raw), id) {
		t.Fatalf("descriptor = %s %v", raw, err)
	}
	if _, err := relay.Descriptor(ctx, base64.RawURLEncoding.EncodeToString(make([]byte, 16))); !errors.Is(err, mcpauth.ErrReaderNotFound) {
		t.Fatalf("unknown: %v", err)
	}
	if raw, err := relay.Prepare(ctx, id, strings.Repeat("A", 43)); err != nil || !strings.Contains(string(raw), "aws-nitro-v1") {
		t.Fatalf("prepare = %s %v", raw, err)
	}
	if err := relay.Bundle(ctx, id, mcpauth.BundleRelay{ConnectionID: uuid.NewString()}); err != nil {
		t.Fatalf("bundle: %v", err)
	}
	if err := relay.Revoke(ctx, uuid.NewString()); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	health, err := relay.Health(ctx)
	if err != nil || health.ReaderID != "enclave" || health.PCR0 != enclavePCR0 || health.CertNotAfter == nil {
		t.Fatalf("health = %+v %v", health, err)
	}
	if n := f.refusedSignatures(); n != 0 {
		t.Fatalf("the reader refused %d signatures", n)
	}

	// Signed with the wrong secret, the reader refuses and the relay says
	// unavailable.
	wrong := mcpauth.NewSignedRelay("enclave", f.srv.URL, stagingSecret, nil)
	wrong.Client = relay.Client
	if _, err := wrong.Descriptor(ctx, id); !errors.Is(err, mcpauth.ErrReaderUnavailable) {
		t.Fatalf("wrong secret: %v", err)
	}
	// System roots do not trust the test certificate: no connection.
	untrusted := mcpauth.NewSignedRelay("enclave", f.srv.URL, enclaveSecret, nil)
	if _, err := untrusted.Descriptor(ctx, id); !errors.Is(err, mcpauth.ErrReaderUnavailable) {
		t.Fatalf("untrusted certificate: %v", err)
	}

	// Answers mapped: 429 on prepare, 503 on prepare, a redirect, an
	// oversize body, the relay-secret codes.
	var status int
	var body string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status == http.StatusFound {
			http.Redirect(w, r, "https://example.com/elsewhere", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		//nolint:errcheck // test server
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	mapped := mcpauth.NewSignedRelay("enclave", srv.URL, enclaveSecret, pool)
	status, body = http.StatusTooManyRequests, `{"code":"too_many_prepares"}`
	if _, err := mapped.Prepare(ctx, id, "n"); !errors.Is(err, mcpauth.ErrTooManyPrepares) {
		t.Fatalf("429: %v", err)
	}
	status, body = http.StatusServiceUnavailable, `{"code":"tls_not_ready"}`
	if _, err := mapped.Prepare(ctx, id, "n"); !errors.Is(err, mcpauth.ErrReaderUnavailable) || !strings.Contains(err.Error(), "tls_not_ready") {
		t.Fatalf("503: %v", err)
	}
	status, body = http.StatusFound, ``
	if _, err := mapped.Descriptor(ctx, id); !errors.Is(err, mcpauth.ErrReaderUnavailable) {
		t.Fatalf("redirect followed: %v", err)
	}
	status, body = http.StatusOK, `{"pad":"`+strings.Repeat("x", 65<<10)+`"}`
	if _, err := mapped.Descriptor(ctx, id); !errors.Is(err, mcpauth.ErrReaderUnavailable) {
		t.Fatalf("oversize: %v", err)
	}
	// A reader answering under another id is not this reader's health.
	status, body = http.StatusOK, `{"ok":true,"reader_id":"staging","state":"ready"}`
	if _, err := mapped.Health(ctx); !errors.Is(err, mcpauth.ErrReaderUnavailable) {
		t.Fatalf("health under another id: %v", err)
	}
	status, body = http.StatusNoContent, ``
	if err := mapped.RelaySecret(ctx, "AAAA"); err != nil {
		t.Fatalf("relay secret: %v", err)
	}
	status, body = http.StatusBadRequest, `{"code":"bad_request"}`
	if err := mapped.RelaySecret(ctx, "AAAA"); !errors.Is(err, mcpauth.ErrReaderRefused) {
		t.Fatalf("relay secret 400: %v", err)
	}
	status, body = http.StatusBadGateway, `{"code":"kms_failed"}`
	if err := mapped.RelaySecret(ctx, "AAAA"); !errors.Is(err, mcpauth.ErrReaderUnavailable) || !strings.Contains(err.Error(), "kms_failed") {
		t.Fatalf("relay secret 502: %v", err)
	}
}
