package mcpauth_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/pg"
	"whatserver2/internal/store"
)

// Content connections over HTTP: gating, the consent, the reader's routes,
// renewal and the repeated revocation notice. The ledger is real Postgres
// under an ordinary role; the enclave is the fake on the far side of the
// signed relay.

func randomKey(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// archiveKey gives the harness's device an archive key at epoch 1, once.
func (h *attestedHarness) archiveKey(t *testing.T) {
	t.Helper()
	keys := store.NewKeys(h.pool)
	if ok, err := keys.HasArchiveKey(context.Background(), h.tenant, h.device); err != nil || ok {
		return
	}
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.CreateArchiveKey(context.Background(), h.tenant, h.device, 1, pub); err != nil {
		t.Fatal(err)
	}
}

// serviceFor builds what the console builds before a content consent: a
// provisional service account whose public key is pub, read-only on the
// device with one grant, and a twenty-minute key acting as it, issued by
// actor.
func (h *attestedHarness) serviceFor(t *testing.T, actor uuid.UUID, pub []byte) (service uuid.UUID, key, prefix string) {
	t.Helper()
	ctx := context.Background()
	h.archiveKey(t)
	secret, _, err := h.users.NewProvisionalServiceInvitation(ctx, h.tenant, actor)
	if err != nil {
		t.Fatal(err)
	}
	name := make([]byte, 4)
	if _, err := rand.Read(name); err != nil {
		t.Fatal(err)
	}
	svc, err := h.users.SignupService(ctx, secret, "mcp-"+hex.EncodeToString(name), pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.users.SetDevicePermission(ctx, h.tenant, actor, store.DevicePermission{DeviceID: h.device, UserID: svc.ID, Read: true}); err != nil {
		t.Fatal(err)
	}
	if err := store.NewKeys(h.pool).PutGrant(ctx, store.Grant{TenantID: h.tenant, DeviceID: h.device, UserID: svc.ID, Epoch: 1, SealedDSK: []byte("sealed")}, &actor); err != nil {
		t.Fatal(err)
	}
	in := time.Now().Add(20 * time.Minute)
	key, err = h.keys.IssueActingAsForDevices(ctx, h.tenant.String(), "assistant", store.ScopeRead, &actor, &svc.ID, []uuid.UUID{h.device}, &in)
	if err != nil {
		t.Fatal(err)
	}
	prefix, _, _ = strings.Cut(key, ".")
	return svc.ID, key, prefix
}

func contentBody(t *testing.T, requestID, prefix string, service uuid.UUID) map[string]any {
	t.Helper()
	body := consent(requestID, prefix)
	body["kid"] = enclaveKID
	body["sealed"] = sealed(t)
	body["kind"] = "content"
	body["service_user_id"] = service.String()
	body["key_mode"] = "ephemeral"
	body["consent_version"] = 1
	body["expires_at"] = time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)
	return body
}

// consentContent runs a content consent through to an active connection.
func (h *attestedHarness) consentContent(t *testing.T, actor store.User) (id string, service uuid.UUID, key string) {
	t.Helper()
	token := h.session(t, actor)
	pub := randomKey(t)
	requestID := h.enclave.pendingKey(t, pub)
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/requests/"+requestID+"/prepare", prepareNonce(t, 32), nil), http.StatusOK, "")
	service, key, prefix := h.serviceFor(t, actor.ID, pub)
	r := h.call(t, http.MethodPost, "/v1/mcp/connections", contentBody(t, requestID, prefix, service), bearer(token))
	expect(t, r, http.StatusCreated, "")
	var created struct {
		ID string `json:"id"`
	}
	r.into(t, &created)
	a, _ := h.signedCall(t, http.MethodPost, "/v1/mcp/enclave/connections/"+created.ID+"/activate", asEnclave(t))
	expect(t, a, http.StatusNoContent, "")
	return created.ID, service, key
}

type attestedStanding struct {
	Status        string  `json:"status"`
	Kind          string  `json:"kind"`
	ServiceUserID *string `json:"service_user_id"`
}

func (h *attestedHarness) standing(t *testing.T, id string) attestedStanding {
	t.Helper()
	r, _ := h.signedCall(t, http.MethodGet, "/v1/mcp/enclave/connections/"+id, asEnclave(t))
	expect(t, r, http.StatusOK, "")
	var s attestedStanding
	r.into(t, &s)
	return s
}

type listed struct {
	ID           string  `json:"id"`
	Status       string  `json:"status"`
	Kind         string  `json:"kind"`
	KeyMode      *string `json:"key_mode"`
	RevokeReason *string `json:"revoke_reason"`
	Renewable    bool    `json:"renewable"`
}

func (h *attestedHarness) listed(t *testing.T, token, id string) listed {
	t.Helper()
	r := h.call(t, http.MethodGet, "/v1/mcp/connections", nil, bearer(token))
	expect(t, r, http.StatusOK, "")
	var out struct {
		Connections []listed `json:"connections"`
	}
	r.into(t, &out)
	for _, c := range out.Connections {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("connection %s not listed: %s", id, r.body)
	return listed{}
}

// serviceHolds counts what an account still holds in the workspace, read in
// the workspace's transaction.
func (h *attestedHarness) serviceHolds(t *testing.T, service uuid.UUID) int {
	t.Helper()
	var n int
	if err := pg.InTenantTx(context.Background(), h.pool, h.tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT
			(SELECT count(*) FROM device_key_grants WHERE user_id=$1) +
			(SELECT count(*) FROM device_permissions WHERE user_id=$1) +
			(SELECT count(*) FROM workspace_memberships WHERE user_id=$1)`, service).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// ---------------------------------------------------------------------------

// Text is let through only when the request is the enclave's, prepared by
// this process, with the switch on and the workspace listed; everything
// else is refused before the ledger and before the reader.
func TestContentConsentGating(t *testing.T) {
	h := newAttestedHarness(t)
	owner := h.session(t, h.owner)
	pub := randomKey(t)
	requestID := h.enclave.pendingKey(t, pub)
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/requests/"+requestID+"/prepare", prepareNonce(t, 32), nil), http.StatusOK, "")
	service, _, prefix := h.serviceFor(t, h.owner.ID, pub)
	body := contentBody(t, requestID, prefix, service)

	enabled := func() bool {
		r := h.call(t, http.MethodGet, "/v1/mcp/content", nil, bearer(owner))
		expect(t, r, http.StatusOK, "")
		var out struct {
			Enabled bool `json:"enabled"`
		}
		r.into(t, &out)
		return out.Enabled
	}
	expect(t, h.call(t, http.MethodGet, "/v1/mcp/content", nil, nil), http.StatusUnauthorized, "unauthorized")

	// The switch is off.
	if enabled() {
		t.Fatal("content enabled with the switch off")
	}
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", body, bearer(owner)), http.StatusForbidden, "content_not_allowed")
	h.contentOn.Store(true)
	if !enabled() {
		t.Fatal("content not enabled for a listed workspace with the switch on")
	}

	// The hosted reader never gets text.
	hostedID, _ := h.reader.pending(t, "Claude", "claude.ai")
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", contentBody(t, hostedID, prefix, service), bearer(owner)), http.StatusForbidden, "content_not_allowed")
	// Nor a request this process did not prepare.
	unprepared := h.enclave.pendingKey(t, pub)
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", contentBody(t, unprepared, prefix, service), bearer(owner)), http.StatusConflict, "attestation_required")

	for name, mutate := range map[string]func(map[string]any){
		"persisted key": func(b map[string]any) { b["key_mode"] = "persisted" },
		"other consent": func(b map[string]any) { b["consent_version"] = 2 },
		"no service":    func(b map[string]any) { delete(b, "service_user_id") },
		"unknown kind":  func(b map[string]any) { b["kind"] = "text" },
		"a hundred days": func(b map[string]any) {
			b["expires_at"] = time.Now().Add(100 * 24 * time.Hour).UTC().Format(time.RFC3339)
		},
		"metadata and service": func(b map[string]any) { b["kind"] = "metadata" },
	} {
		t.Run(name, func(t *testing.T) {
			b := contentBody(t, requestID, prefix, service)
			mutate(b)
			expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", b, bearer(owner)), http.StatusBadRequest, "bad_request")
		})
	}
	// A service account whose key is not the attested one.
	other, _, otherPrefix := h.serviceFor(t, h.owner.ID, randomKey(t))
	wrong := contentBody(t, requestID, otherPrefix, other)
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", wrong, bearer(owner)), http.StatusUnprocessableEntity, "key_unsuitable")
	if rows, err := h.conns.List(context.Background(), h.tenant); err != nil || len(rows) != 0 {
		t.Fatalf("refused consents left rows: %+v %v", rows, err)
	}
	if h.enclave.bundle(requestID) != nil {
		t.Fatal("a refused consent reached the enclave")
	}

	// The consent itself.
	r := h.call(t, http.MethodPost, "/v1/mcp/connections", body, bearer(owner))
	expect(t, r, http.StatusCreated, "")
	var created struct {
		ID string `json:"id"`
	}
	r.into(t, &created)
	if got := h.enclave.bundle(requestID); got == nil || got["kind"] != "content" || got["connection_id"] != created.ID {
		t.Fatalf("bundle at the enclave = %v", got)
	}
	l := h.listed(t, owner, created.ID)
	if l.Kind != "content" || l.KeyMode == nil || *l.KeyMode != "ephemeral" || l.Status != "pending" || l.Renewable {
		t.Fatalf("listed = %+v", l)
	}
	s := h.standing(t, created.ID)
	if s.Kind != "content" || s.ServiceUserID == nil || *s.ServiceUserID != service.String() || s.Status != "pending" {
		t.Fatalf("standing = %+v", s)
	}
	a, _ := h.signedCall(t, http.MethodPost, "/v1/mcp/enclave/connections/"+created.ID+"/activate", asEnclave(t))
	expect(t, a, http.StatusNoContent, "")
	if l := h.listed(t, owner, created.ID); !l.Renewable || l.Status != "active" {
		t.Fatalf("after activation = %+v", l)
	}

	// The switch goes off: the reader hears reseal, the ledger keeps active.
	h.contentOn.Store(false)
	if s := h.standing(t, created.ID); s.Status != "reseal" {
		t.Fatalf("switched off = %+v", s)
	}
	if l := h.listed(t, owner, created.ID); l.Status != "active" || l.Renewable {
		t.Fatalf("listed while off = %+v", l)
	}
	h.contentOn.Store(true)

	// The reader's reseal and revoke.
	rs, _ := h.signedCall(t, http.MethodPost, "/v1/mcp/enclave/connections/"+created.ID+"/reseal", asEnclave(t))
	expect(t, rs, http.StatusNoContent, "")
	if s := h.standing(t, created.ID); s.Status != "reseal" {
		t.Fatalf("after reseal = %+v", s)
	}
	for _, body := range map[string][]byte{
		"other reason":  []byte(`{"reason":"console"}`),
		"unknown field": []byte(`{"reason":"reuse_detected","extra":1}`),
		"trailing":      []byte(`{"reason":"reuse_detected"}{}`),
		"not json":      []byte(`reuse_detected`),
	} {
		call := asEnclave(t)
		call.body = body
		rv, _ := h.signedCall(t, http.MethodPost, "/v1/mcp/enclave/connections/"+created.ID+"/revoke", call)
		expect(t, rv, http.StatusBadRequest, "bad_request")
	}
	call := asEnclave(t)
	call.body = []byte(`{"reason":"reuse_detected"}`)
	rv, _ := h.signedCall(t, http.MethodPost, "/v1/mcp/enclave/connections/"+created.ID+"/revoke", call)
	expect(t, rv, http.StatusNoContent, "")
	if l := h.listed(t, owner, created.ID); l.Status != "revoked" || l.RevokeReason == nil || *l.RevokeReason != "reuse_detected" {
		t.Fatalf("after reuse = %+v", l)
	}
	if h.serviceHolds(t, service) != 0 {
		t.Fatal("the service account survived the reader's revocation")
	}
	// The reader said so itself: no notice is owed.
	if ids, err := h.conns.Unnotified(context.Background(), "enclave", 10); err != nil || len(ids) != 0 {
		t.Fatalf("unnotified = %v %v", ids, err)
	}
	// A metadata row cannot be resealed.
	metaID := h.enclave.pending(t)
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/requests/"+metaID+"/prepare", prepareNonce(t, 32), nil), http.StatusOK, "")
	_, metaPrefix := h.provisionalKey(t, "meta")
	meta := consent(metaID, metaPrefix)
	meta["kid"], meta["sealed"] = enclaveKID, sealed(t)
	r = h.call(t, http.MethodPost, "/v1/mcp/connections", meta, bearer(owner))
	expect(t, r, http.StatusCreated, "")
	r.into(t, &created)
	a, _ = h.signedCall(t, http.MethodPost, "/v1/mcp/enclave/connections/"+created.ID+"/activate", asEnclave(t))
	expect(t, a, http.StatusNoContent, "")
	rs, _ = h.signedCall(t, http.MethodPost, "/v1/mcp/enclave/connections/"+created.ID+"/reseal", asEnclave(t))
	expect(t, rs, http.StatusConflict, "connection_state")
	if s := h.standing(t, created.ID); s.Kind != "metadata" || s.ServiceUserID != nil {
		t.Fatalf("metadata standing = %+v", s)
	}
}

// A bundle the enclave refuses (a grant that does not open with the attested
// key) undoes the whole consent: the row, the key and the service account.
func TestContentBundleRefusedUndoes(t *testing.T) {
	h := newAttestedHarness(t)
	h.contentOn.Store(true)
	owner := h.session(t, h.owner)
	pub := randomKey(t)
	requestID := h.enclave.pendingKey(t, pub)
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/requests/"+requestID+"/prepare", prepareNonce(t, 32), nil), http.StatusOK, "")
	service, key, prefix := h.serviceFor(t, h.owner.ID, pub)
	h.enclave.mu.Lock()
	h.enclave.bundleStatus, h.enclave.bundleCode = http.StatusBadRequest, "grant_proof_failed"
	h.enclave.mu.Unlock()
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", contentBody(t, requestID, prefix, service), bearer(owner)),
		http.StatusBadRequest, "grant_proof_failed")
	if rows, err := h.conns.List(context.Background(), h.tenant); err != nil || len(rows) != 0 {
		t.Fatalf("rows = %+v %v", rows, err)
	}
	if _, err := h.keys.Verify(context.Background(), key); !errors.Is(err, store.ErrInvalidKey) {
		t.Fatalf("the key survived a refused bundle: %v", err)
	}
	if n := h.serviceHolds(t, service); n != 0 {
		t.Fatalf("the service account kept %d rows", n)
	}
}

// Renewal: the reader restarted, the person renews with a new key and a new
// service account, and the connection keeps its id.
func TestContentRenewal(t *testing.T) {
	h := newAttestedHarness(t)
	h.contentOn.Store(true)
	owner := h.session(t, h.owner)
	id, oldService, oldKey := h.consentContent(t, h.owner)
	rs, _ := h.signedCall(t, http.MethodPost, "/v1/mcp/enclave/connections/"+id+"/reseal", asEnclave(t))
	expect(t, rs, http.StatusNoContent, "")
	if l := h.listed(t, owner, id); l.Status != "reseal" || !l.Renewable {
		t.Fatalf("listed = %+v", l)
	}

	newPub := randomKey(t)
	h.enclave.mu.Lock()
	h.enclave.renewalKey = newPub
	h.enclave.mu.Unlock()

	// Only the person who consented renews.
	admin := h.person(t, "admin")
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections/"+id+"/renewal", prepareNonce(t, 32), bearer(h.session(t, admin))),
		http.StatusForbidden, "not_authorized")
	// Not while content is off.
	h.contentOn.Store(false)
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections/"+id+"/renewal", prepareNonce(t, 32), bearer(owner)),
		http.StatusForbidden, "content_not_allowed")
	h.contentOn.Store(true)
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections/"+id+"/renewal", map[string]any{"nonce": "short"}, bearer(owner)),
		http.StatusBadRequest, "bad_request")
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections/"+uuid.NewString()+"/renewal", prepareNonce(t, 32), bearer(owner)),
		http.StatusNotFound, "not_found")

	r := h.call(t, http.MethodPost, "/v1/mcp/connections/"+id+"/renewal", prepareNonce(t, 32), bearer(owner))
	expect(t, r, http.StatusOK, "")
	var renewal struct {
		RenewalID       string `json:"renewal_id"`
		ConnectionID    string `json:"connection_id"`
		KID             string `json:"kid"`
		ReaderPublicKey string `json:"reader_public_key"`
	}
	r.into(t, &renewal)
	if renewal.ConnectionID != id || renewal.KID != enclaveRenewalKID || renewal.ReaderPublicKey != base64.RawURLEncoding.EncodeToString(newPub) {
		t.Fatalf("renewal = %s", r.body)
	}

	service, newKey, prefix := h.serviceFor(t, h.owner.ID, newPub)
	renew := func(renewalID, kid string) map[string]any {
		return map[string]any{"renewal_id": renewalID, "key_prefix": prefix, "service_user_id": service.String(), "kid": kid, "sealed": sealed(t)}
	}
	// A renewal this process did not prepare, or another kid.
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections/"+id+"/renew", renew(base64.RawURLEncoding.EncodeToString(make([]byte, 16)), enclaveRenewalKID), bearer(owner)),
		http.StatusConflict, "attestation_required")
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections/"+id+"/renew", renew(renewal.RenewalID, enclaveKID), bearer(owner)),
		http.StatusConflict, "attestation_required")
	// A renewal id is not a consent's request id.
	body := contentBody(t, renewal.RenewalID, prefix, service)
	body["kid"] = enclaveRenewalKID
	if r := h.call(t, http.MethodPost, "/v1/mcp/connections", body, bearer(owner)); r.status == http.StatusCreated {
		t.Fatalf("a renewal was taken as a consent: %s", r.body)
	}

	r = h.call(t, http.MethodPost, "/v1/mcp/connections/"+id+"/renew", renew(renewal.RenewalID, enclaveRenewalKID), bearer(owner))
	expect(t, r, http.StatusOK, "")
	var renewed struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	r.into(t, &renewed)
	if renewed.ID != id || renewed.Status != "active" {
		t.Fatalf("renewed = %s", r.body)
	}
	h.enclave.mu.Lock()
	staged := h.enclave.renewalBundles[renewal.RenewalID]
	h.enclave.mu.Unlock()
	if staged == nil || staged["kind"] != "content" || staged["connection_id"] != id || staged["kid"] != enclaveRenewalKID ||
		staged["tenant_id"] != h.tenant.String() {
		t.Fatalf("renewal bundle at the enclave = %v", staged)
	}
	// The expiry is the connection's, in UTC as the consent carried it.
	if at, _ := staged["expires_at"].(string); !strings.HasSuffix(at, "Z") {
		t.Fatalf("renewal expiry = %q", at)
	}
	if s := h.standing(t, id); s.Status != "active" || s.ServiceUserID == nil || *s.ServiceUserID != service.String() {
		t.Fatalf("standing after renewal = %+v", s)
	}
	if _, err := h.keys.Verify(context.Background(), oldKey); !errors.Is(err, store.ErrInvalidKey) {
		t.Fatalf("the old key still works: %v", err)
	}
	if _, err := h.keys.Verify(context.Background(), newKey); err != nil {
		t.Fatalf("the new key does not work: %v", err)
	}
	if n := h.serviceHolds(t, oldService); n != 0 {
		t.Fatalf("the old service account kept %d rows", n)
	}

	// A renewal the enclave refuses leaves the connection as it was and
	// removes the new account.
	r = h.call(t, http.MethodPost, "/v1/mcp/connections/"+id+"/renewal", prepareNonce(t, 32), bearer(owner))
	expect(t, r, http.StatusOK, "")
	r.into(t, &renewal)
	third, _, thirdPrefix := h.serviceFor(t, h.owner.ID, newPub)
	h.enclave.mu.Lock()
	h.enclave.bundleStatus, h.enclave.bundleCode = http.StatusBadRequest, "invalid_bundle"
	h.enclave.mu.Unlock()
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections/"+id+"/renew", map[string]any{
		"renewal_id": renewal.RenewalID, "key_prefix": thirdPrefix, "service_user_id": third.String(), "kid": enclaveRenewalKID, "sealed": sealed(t),
	}, bearer(owner)), http.StatusBadRequest, "invalid_bundle")
	if n := h.serviceHolds(t, third); n != 0 {
		t.Fatalf("a refused renewal's account kept %d rows", n)
	}
	if s := h.standing(t, id); s.Status != "active" || *s.ServiceUserID != service.String() {
		t.Fatalf("a refused renewal changed the connection: %+v", s)
	}
}

// A revocation the enclave did not confirm is sent again until it is, and
// so is an end the enclave was never told about (the janitor's).
func TestRevokeNoticeRepeated(t *testing.T) {
	h := newAttestedHarness(t)
	h.contentOn.Store(true)
	owner := h.session(t, h.owner)
	ctx := context.Background()
	id, _, _ := h.consentContent(t, h.owner)

	h.enclave.mu.Lock()
	h.enclave.revokeStatus = http.StatusServiceUnavailable
	h.enclave.mu.Unlock()
	expect(t, h.call(t, http.MethodDelete, "/v1/mcp/connections/"+id, nil, bearer(owner)), http.StatusNoContent, "")
	if ids, err := h.conns.Unnotified(ctx, "enclave", 10); err != nil || len(ids) != 1 || ids[0] != id {
		t.Fatalf("unnotified = %v %v", ids, err)
	}
	enclave := h.handler.Attested[0]
	if n := h.handler.ResendRevocations(ctx, enclave); n != 0 {
		t.Fatalf("confirmed %d while the enclave refuses", n)
	}
	h.enclave.mu.Lock()
	h.enclave.revokeStatus = 0
	h.enclave.mu.Unlock()
	if n := h.handler.ResendRevocations(ctx, enclave); n != 1 {
		t.Fatalf("confirmed %d, want 1", n)
	}
	if got := h.enclave.revocations(); len(got) != 1 || got[0] != id {
		t.Fatalf("enclave revocations = %v", got)
	}
	if n := h.handler.ResendRevocations(ctx, enclave); n != 0 {
		t.Fatalf("a confirmed notice was sent again: %d", n)
	}

	// The janitor ends a connection nobody told the enclave about.
	id, _, _ = h.consentContent(t, h.owner)
	if _, err := h.pool.Exec(ctx, `UPDATE mcp_connections SET expires_at=now()-interval '1 minute' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if n, err := store.ExpireMCPConnections(ctx, h.pool, 20*time.Minute); err != nil || n != 1 {
		t.Fatalf("settled %d %v", n, err)
	}
	if n := h.handler.ResendRevocations(ctx, enclave); n != 1 {
		t.Fatalf("the expiry was not told: %d", n)
	}
	if got := h.enclave.revocations(); len(got) != 2 || got[1] != id {
		t.Fatalf("enclave revocations = %v", got)
	}
}
