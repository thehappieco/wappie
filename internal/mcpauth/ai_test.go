package mcpauth_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/domain"
	"whatserver2/internal/mcpauth"
	"whatserver2/internal/store"
)

// AI integrations over HTTP (docs/mcp-enclave.md §18): the request bound to
// the person it was prepared for, the consent with its configuration and the
// 30-second relay, the enclave's refusals, the status with ai_off, renewal,
// and the enclave's AI routes. The ledger is real Postgres under an ordinary
// role; the enclave is the fake on the far side of the signed relay.

// Example model ids for the fixtures; no model name is a constant of the
// server.
const (
	geminiModel = "gemini-3.8-flash"
	claudeModel = "claude-sonnet-5-5"
)

type aiHarness struct {
	*attestedHarness
	ai         *store.AI
	ownerToken string
	// keychains are each person's items for Google and Anthropic, made
	// once: a person holds at most twenty.
	keychains map[uuid.UUID]map[string]uuid.UUID
}

// newAIHarness is the attested harness with content, attachments and AI on
// for its workspace, the owner reading the number, and an enclave that
// activates an AI authorization before it answers its bundle, as the real
// one does.
func newAIHarness(t *testing.T) *aiHarness {
	t.Helper()
	ctx := context.Background()
	h := &aiHarness{attestedHarness: newAttestedHarness(t), keychains: map[uuid.UUID]map[string]uuid.UUID{}}
	h.contentOn.Store(true)
	h.mediaOn.Store(true)
	h.aiOn.Store(true)
	h.ai = store.NewAI(h.pool)
	h.ownerToken = h.session(t, h.owner)
	h.archiveKey(t)
	h.reads(t, h.owner.ID)
	h.enclave.onAIBundle = func(body map[string]any) {
		if err := h.conns.Activate(ctx, "enclave", body["connection_id"].(string)); err != nil {
			t.Error(err)
		}
	}
	return h
}

// reads gives a person the number's grant and read permission.
func (h *aiHarness) reads(t *testing.T, person uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	if err := store.NewKeys(h.pool).PutGrant(ctx, store.Grant{TenantID: h.tenant, DeviceID: h.device, UserID: person, Epoch: 1, SealedDSK: []byte("a person's")}, &h.owner.ID); err != nil {
		t.Fatal(err)
	}
	if err := h.users.SetDevicePermission(ctx, h.tenant, h.owner.ID, store.DevicePermission{DeviceID: h.device, UserID: person, Read: true}); err != nil {
		t.Fatal(err)
	}
}

func (h *aiHarness) keychainItem(t *testing.T, user uuid.UUID, provider string) uuid.UUID {
	t.Helper()
	item, err := h.ai.AddKeychainItem(context.Background(), h.tenant, user, store.AIKeychainItem{
		ID: uuid.New(), Provider: provider, Label: provider, Suffix: "a1B2", Envelope: append([]byte("WKC1"), randomKey(t)...),
	})
	if err != nil {
		t.Fatal(err)
	}
	return item.ID
}

// aiRequest prepares an AI request for a person, as POST /v1/ai/requests
// does, and returns its id and the key it attested.
func (h *aiHarness) aiRequest(t *testing.T, user store.User) (string, []byte) {
	t.Helper()
	raw, err := h.handler.PrepareAI(context.Background(), h.tenant, user.ID, base64.RawURLEncoding.EncodeToString(randomKey(t)))
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		RequestID       string `json:"request_id"`
		ReaderPublicKey string `json:"reader_public_key"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	pub, err := base64.RawURLEncoding.DecodeString(d.ReaderPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return d.RequestID, pub
}

// aiConfigFor is the mirror the console sends: Gemini for audio and a Claude
// model for documents on every number named, and mutate's changes.
func aiConfigFor(request, kid string, service uuid.UUID, devices []uuid.UUID, keys map[string]uuid.UUID, expires time.Time, mutate func(map[string]any)) map[string]any {
	epochs, ns, features, tags := map[string]any{}, map[string]any{}, map[string]any{}, map[string]any{}
	for _, d := range devices {
		epochs[d.String()] = 1
		ns[d.String()] = uuid.NewString()
		features[d.String()] = map[string]any{
			"audio":    map[string]any{"mode": "request", "lang": "pt-BR", "requesters": "self"},
			"document": map[string]any{"mode": "request", "requesters": "self"},
		}
		tags[d.String()] = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	}
	mirror := map[string]any{}
	for provider, id := range keys {
		mirror[provider] = map[string]any{"keychain_id": id.String(), "sha256": strings.Repeat("ab", 32), "label": provider, "suffix": "a1B2"}
	}
	cfg := map[string]any{
		"version": 1, "request": request, "kid": kid, "service_user_id": service.String(), "epochs": epochs, "ns": ns, "keys": mirror,
		"functions": map[string]any{
			"audio":    map[string]any{"provider": "google", "model": geminiModel},
			"document": map[string]any{"provider": "anthropic", "model": claudeModel},
		},
		"features": features,
		"budget": map[string]any{"monthly_usd_cents": 1000, "request_items_per_day": 100, "rates": map[string]any{
			"google:" + geminiModel: map[string]any{"in": 30, "out": 250, "sec": 0}, "anthropic:" + claudeModel: map[string]any{"in": 300, "out": 1500, "sec": 0},
		}},
		"expires_at": expires.UTC().Format(time.RFC3339), "key_mode": "ephemeral", "cfg_tags": tags,
	}
	if mutate != nil {
		mutate(cfg)
	}
	return cfg
}

// aiConsent is everything an AI consent carries, ready to post.
type aiConsent struct {
	body    map[string]any
	service uuid.UUID
	key     string
	request string
	keys    map[string]uuid.UUID
}

// prepareAI builds what the console sends to consent an AI authorization
// for user: a request prepared for them, a service account on the key it
// attested, their keychain items and the mirror.
func (h *aiHarness) prepareAI(t *testing.T, user store.User, mutate func(map[string]any)) aiConsent {
	t.Helper()
	request, pub := h.aiRequest(t, user)
	service, key, prefix := h.serviceFor(t, user.ID, pub)
	keys, ok := h.keychains[user.ID]
	if !ok {
		keys = map[string]uuid.UUID{"google": h.keychainItem(t, user.ID, "google"), "anthropic": h.keychainItem(t, user.ID, "anthropic")}
		h.keychains[user.ID] = keys
	}
	expires := time.Now().Add(30 * 24 * time.Hour)
	cfg := aiConfigFor(request, enclaveKID, service, []uuid.UUID{h.device}, keys, expires, mutate)
	body := map[string]any{
		"kind": "ai", "request_id": request, "key_prefix": prefix, "service_user_id": service.String(), "key_mode": "ephemeral",
		"consent_version": 1, "expires_at": expires.UTC().Format(time.RFC3339), "kid": enclaveKID, "sealed": sealed(t), "ai_config": cfg,
	}
	return aiConsent{body: body, service: service, key: key, request: request, keys: keys}
}

// consentAI runs an AI consent through to an active authorization.
func (h *aiHarness) consentAI(t *testing.T, user store.User, mutate func(map[string]any)) (string, aiConsent) {
	t.Helper()
	c := h.prepareAI(t, user, mutate)
	r := h.call(t, http.MethodPost, "/v1/mcp/connections", c.body, bearer(h.session(t, user)))
	expect(t, r, http.StatusCreated, "")
	var created mcpauth.AIAuthorizationInfo
	r.into(t, &created)
	return created.ID, c
}

// ---------------------------------------------------------------------------

// An AI request is remembered for the person it was prepared for, and only
// their consent answers it; the consent is checked and relayed with the
// bundle kind "ai", and the answer is the authorization the enclave
// activated.
func TestAIConsent(t *testing.T) {
	h := newAIHarness(t)
	admin := h.person(t, "admin")
	h.reads(t, admin.ID)

	c := h.prepareAI(t, h.owner, nil)
	// Another owner or admin may not answer it, nor may anyone answer one
	// that was not prepared here.
	other := c.body["request_id"]
	r := h.call(t, http.MethodPost, "/v1/mcp/connections", c.body, bearer(h.session(t, admin)))
	expect(t, r, http.StatusConflict, "attestation_required")
	c.body["request_id"] = base64.RawURLEncoding.EncodeToString(randomKey(t)[:16])
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", c.body, bearer(h.ownerToken)), http.StatusConflict, "attestation_required")
	c.body["request_id"] = other

	r = h.call(t, http.MethodPost, "/v1/mcp/connections", c.body, bearer(h.ownerToken))
	expect(t, r, http.StatusCreated, "")
	var created mcpauth.AIAuthorizationInfo
	r.into(t, &created)
	if created.Status != "active" || created.CreatedBy != h.owner.ID.String() || created.DeviceCount != 1 || created.Paused ||
		len(created.Off) != 0 || created.CapCents != nil || !created.Renewable || created.RevokeReason != nil {
		t.Fatalf("created = %s", r.body)
	}
	var mirror map[string]any
	if err := json.Unmarshal(created.AIConfig, &mirror); err != nil || mirror["request"] != c.request {
		t.Fatalf("ai_config = %s %v", created.AIConfig, err)
	}
	// The relay is BundleRelay plus kind "ai", nothing else.
	bundle := h.enclave.aiBundles[c.request]
	if len(bundle) != 6 || bundle["kind"] != "ai" || bundle["connection_id"] != created.ID || bundle["tenant_id"] != h.tenant.String() ||
		bundle["kid"] != enclaveKID || bundle["sealed"] != c.body["sealed"] {
		t.Fatalf("relayed = %v", bundle)
	}
	// It is not an assistant's connection.
	var listed struct {
		Connections []json.RawMessage `json:"connections"`
	}
	h.call(t, http.MethodGet, "/v1/mcp/connections", nil, bearer(h.ownerToken)).into(t, &listed)
	if len(listed.Connections) != 0 {
		t.Fatalf("listed with the assistants: %s", listed.Connections)
	}
	// A request answers once.
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", c.body, bearer(h.ownerToken)), http.StatusUnprocessableEntity, "key_unsuitable")
	// An admin makes their own; a member may not.
	h.consentAI(t, admin, nil)
	// A member's request can be prepared, but the store refuses their
	// consent: in B1 an owner or an admin makes an authorization.
	member := h.person(t, "member")
	request, pub := h.aiRequest(t, member)
	service, _, prefix := h.serviceFor(t, h.owner.ID, pub)
	keys := map[string]uuid.UUID{"google": h.keychainItem(t, member.ID, "google"), "anthropic": h.keychainItem(t, member.ID, "anthropic")}
	expires := time.Now().Add(30 * 24 * time.Hour)
	body := map[string]any{
		"kind": "ai", "request_id": request, "key_prefix": prefix, "service_user_id": service.String(), "key_mode": "ephemeral",
		"consent_version": 1, "expires_at": expires.UTC().Format(time.RFC3339), "kid": enclaveKID, "sealed": sealed(t),
		"ai_config": aiConfigFor(request, enclaveKID, service, []uuid.UUID{h.device}, keys, expires, nil),
	}
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", body, bearer(h.session(t, member))), http.StatusForbidden, "not_authorized")
}

// Every refusal before the ledger leaves nothing behind; every refusal of
// the enclave undoes the consent, its key and its service account.
func TestAIConsentRefusals(t *testing.T) {
	h := newAIHarness(t)
	for name, tc := range map[string]struct {
		mutate func(body map[string]any)
		status int
		code   string
	}{
		"consent version 2":   {func(b map[string]any) { b["consent_version"] = 2 }, http.StatusBadRequest, "bad_request"},
		"media":               {func(b map[string]any) { b["media"] = true }, http.StatusBadRequest, "bad_request"},
		"sending":             {func(b map[string]any) { b["send"] = "draft" }, http.StatusBadRequest, "bad_request"},
		"an assistant's name": {func(b map[string]any) { b["client_name"] = "Claude" }, http.StatusBadRequest, "bad_request"},
		"no configuration":    {func(b map[string]any) { delete(b, "ai_config") }, http.StatusBadRequest, "bad_request"},
		"a configuration of 26": {func(b map[string]any) {
			cfg := b["ai_config"].(map[string]any)
			for range store.AIDevicesMax {
				d := uuid.NewString()
				cfg["epochs"].(map[string]any)[d] = 1
			}
		}, http.StatusBadRequest, "bad_request"},
		"the configuration of another request": {func(b map[string]any) {
			b["ai_config"].(map[string]any)["request"] = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16))
		}, http.StatusBadRequest, "bad_request"},
		"another person's key": {func(b map[string]any) {
			b["ai_config"].(map[string]any)["keys"].(map[string]any)["google"].(map[string]any)["keychain_id"] = uuid.NewString()
		}, http.StatusBadRequest, "bad_request"},
		"longer than ninety days": {func(b map[string]any) {
			b["expires_at"] = time.Now().Add(92 * 24 * time.Hour).UTC().Format(time.RFC3339)
		}, http.StatusBadRequest, "bad_request"},
		"unknown field": {func(b map[string]any) { b["auto"] = true }, http.StatusBadRequest, "bad_request"},
	} {
		t.Run(name, func(t *testing.T) {
			c := h.prepareAI(t, h.owner, nil)
			tc.mutate(c.body)
			expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", c.body, bearer(h.ownerToken)), tc.status, tc.code)
			if got := h.serviceHolds(t, c.service); got == 0 {
				t.Fatal("the service account was removed by a refusal before the ledger")
			}
		})
	}
	t.Run("AI off", func(t *testing.T) {
		c := h.prepareAI(t, h.owner, nil)
		for _, off := range []func(bool){h.aiOn.Store, h.mediaOn.Store, h.contentOn.Store} {
			off(false)
			expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", c.body, bearer(h.ownerToken)), http.StatusForbidden, "ai_not_allowed")
			off(true)
		}
	})
	t.Run("a provider or function switched off", func(t *testing.T) {
		c := h.prepareAI(t, h.owner, nil)
		h.handler.AIOffProviders = []string{"anthropic"}
		expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", c.body, bearer(h.ownerToken)), http.StatusForbidden, "ai_not_allowed")
		h.handler.AIOffProviders, h.handler.AIOffFeatures = nil, []string{"audio"}
		expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", c.body, bearer(h.ownerToken)), http.StatusForbidden, "ai_not_allowed")
		h.handler.AIOffFeatures = []string{"video"}
		expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", c.body, bearer(h.ownerToken)), http.StatusCreated, "")
		h.handler.AIOffFeatures = nil
	})
	// The enclave's AI codes reach the console as 400 with that code;
	// anything else is 502. Either way the consent is undone.
	for status, codes := range map[int][]string{
		http.StatusBadRequest: {"invalid_bundle", "grant_proof_failed", "ai_key_rejected", "ai_model_unavailable"},
		http.StatusConflict:   {"bundle_exists"},
		http.StatusNotFound:   {"not_found"},
		http.StatusBadGateway: {"ai_provider_failed"},
	} {
		for _, code := range codes {
			t.Run(code, func(t *testing.T) {
				c := h.prepareAI(t, h.owner, nil)
				h.enclave.mu.Lock()
				h.enclave.bundleStatus, h.enclave.bundleCode = status, code
				h.enclave.mu.Unlock()
				defer func() {
					h.enclave.mu.Lock()
					h.enclave.bundleStatus, h.enclave.bundleCode = 0, ""
					h.enclave.mu.Unlock()
				}()
				r := h.call(t, http.MethodPost, "/v1/mcp/connections", c.body, bearer(h.ownerToken))
				if status == http.StatusBadRequest {
					expect(t, r, http.StatusBadRequest, code)
				} else {
					expect(t, r, http.StatusBadGateway, "reader_unavailable")
				}
				if got := h.serviceHolds(t, c.service); got != 0 {
					t.Fatalf("the service account kept %d rows", got)
				}
				var left int
				if err := h.pool.QueryRow(context.Background(), `SELECT count(*) FROM mcp_connections WHERE request_id=$1`, c.request).Scan(&left); err != nil || left != 0 {
					t.Fatalf("a refused consent left %d rows %v", left, err)
				}
			})
		}
	}
}

// The longest configuration, at AI_DEVICES_MAX numbers with four functions
// and the longest fields, and a sealed bundle of its size, fit the route's
// 64 KiB and pass its parse; one number more does not.
func TestAIConsentAtDevicesMax(t *testing.T) {
	h := newAIHarness(t)
	longest := func(n int) func(map[string]any) {
		return func(cfg map[string]any) {
			var devices []uuid.UUID
			for range n {
				devices = append(devices, uuid.New())
			}
			model := func(c string) string { return c + strings.Repeat("x", 63) }
			fresh := aiConfigFor(cfg["request"].(string), enclaveKID, uuid.MustParse(cfg["service_user_id"].(string)), devices,
				map[string]uuid.UUID{"openai": uuid.New(), "google": uuid.New(), "anthropic": uuid.New()}, time.Now(), nil)
			for _, field := range []string{"epochs", "ns", "features", "cfg_tags", "keys"} {
				cfg[field] = fresh[field]
			}
			functions := map[string]any{
				"audio": map[string]any{"provider": "openai", "model": model("a")}, "video": map[string]any{"provider": "google", "model": model("b")},
				"image": map[string]any{"provider": "anthropic", "model": model("c")}, "document": map[string]any{"provider": "google", "model": model("d")},
			}
			cfg["functions"] = functions
			rates := map[string]any{}
			for _, fn := range functions {
				fn := fn.(map[string]any)
				rates[fn["provider"].(string)+":"+fn["model"].(string)] = map[string]any{"in": 100_000_000, "out": 100_000_000, "sec": 100_000_000}
			}
			cfg["budget"].(map[string]any)["rates"] = rates
			for _, k := range cfg["keys"].(map[string]any) {
				k.(map[string]any)["label"] = strings.Repeat("ç", 60)
			}
			for d := range cfg["features"].(map[string]any) {
				byFeature := map[string]any{}
				for _, feature := range store.AIFeatures {
					byFeature[feature] = map[string]any{"mode": "request", "lang": "abc-abcdefgh-abcdefgh-abcdefgh", "requesters": "readers"}
				}
				cfg["features"].(map[string]any)[d] = byFeature
				cfg["epochs"].(map[string]any)[d] = 65535
			}
		}
	}
	big := make([]byte, 16<<10)
	if _, err := rand.Read(big); err != nil {
		t.Fatal(err)
	}
	c := h.prepareAI(t, h.owner, longest(store.AIDevicesMax))
	c.body["sealed"] = base64.RawURLEncoding.EncodeToString(big)
	raw, err := json.Marshal(c.body)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > 64<<10 || len(raw) < 30<<10 {
		t.Fatalf("the consent body is %d bytes", len(raw))
	}
	// Past the decoder and the parse: the store then finds these numbers
	// are not the key's.
	r := h.call(t, http.MethodPost, "/v1/mcp/connections", raw, bearer(h.ownerToken))
	expect(t, r, http.StatusBadRequest, "bad_request")
	if !strings.Contains(string(r.body), "the key's numbers") {
		t.Fatalf("refused for another reason: %s", r.body)
	}
	c = h.prepareAI(t, h.owner, longest(store.AIDevicesMax+1))
	r = h.call(t, http.MethodPost, "/v1/mcp/connections", c.body, bearer(h.ownerToken))
	expect(t, r, http.StatusBadRequest, "bad_request")
	if !strings.Contains(string(r.body), "1 to 25 numbers") {
		t.Fatalf("26 numbers refused for another reason: %s", r.body)
	}
}

// An AI row's status is decided with the AI switch, and says what is off.
func TestAIStatusAnswer(t *testing.T) {
	h := newAIHarness(t)
	id, c := h.consentAI(t, h.owner, nil)
	h.handler.MediaOff = []string{"pdf"}
	status := func() map[string]any {
		t.Helper()
		r, _ := h.signedCall(t, http.MethodGet, "/v1/mcp/enclave/connections/"+id, asEnclave(t))
		expect(t, r, http.StatusOK, "")
		var out map[string]any
		r.into(t, &out)
		return out
	}
	got := status()
	want := map[string]any{"status": "active", "kind": "ai", "service_user_id": c.service.String(), "media": false, "media_off": []any{"pdf"},
		"ai_off": map[string]any{"functions": []any{}, "providers": []any{}, "paused": false, "monthly_usd_cents": nil}}
	for k, v := range want {
		if fmt.Sprint(got[k]) != fmt.Sprint(v) {
			t.Fatalf("%s = %v, want %v (%v)", k, got[k], v, got)
		}
	}
	if _, ok := got["send"]; ok || len(got) != 7 {
		t.Fatalf("fields = %v", got)
	}
	// The switches, the pause, the row's off and the cap.
	h.handler.AIOffProviders, h.handler.AIOffFeatures = []string{"anthropic"}, []string{"video"}
	paused, capCents := true, 250
	if _, err := h.conns.SetAIControls(context.Background(), h.tenant, h.owner.ID, id, store.AIControls{Paused: &paused, Off: &[]string{"image"}, CapSet: true, Cap: &capCents}); err != nil {
		t.Fatal(err)
	}
	off := status()["ai_off"].(map[string]any)
	if fmt.Sprint(off) != "map[functions:[document image video] monthly_usd_cents:250 paused:true providers:[anthropic]]" {
		t.Fatalf("ai_off = %v", off)
	}
	h.handler.AIOffProviders, h.handler.AIOffFeatures = nil, nil
	// AI off: reseal, never written.
	for _, off := range []func(bool){h.aiOn.Store, h.mediaOn.Store, h.contentOn.Store} {
		off(false)
		if got := status(); got["status"] != "reseal" {
			t.Fatalf("with a switch off = %v", got)
		}
		off(true)
	}
	if got := status(); got["status"] != "active" {
		t.Fatalf("back on = %v", got)
	}
	// A content connection's answer is as it was.
	contentID, _, _ := h.consentContent(t, h.owner)
	r, _ := h.signedCall(t, http.MethodGet, "/v1/mcp/enclave/connections/"+contentID, asEnclave(t))
	var content map[string]any
	r.into(t, &content)
	if _, ok := content["ai_off"]; ok || content["kind"] != "content" {
		t.Fatalf("content = %v", content)
	}
	// And the reseal the enclave records after a restart is kept.
	a, _ := h.signedCall(t, http.MethodPost, "/v1/mcp/enclave/connections/"+id+"/reseal", asEnclave(t))
	expect(t, a, http.StatusNoContent, "")
	if got := status(); got["status"] != "reseal" {
		t.Fatalf("resealed = %v", got)
	}
}

// GET /v1/mcp/content says whether the workspace may have AI now.
func TestContentReplyAI(t *testing.T) {
	h := newAIHarness(t)
	ai := func() bool {
		t.Helper()
		var out struct {
			AI *bool `json:"ai"`
		}
		h.call(t, http.MethodGet, "/v1/mcp/content", nil, bearer(h.ownerToken)).into(t, &out)
		if out.AI == nil {
			t.Fatal("no ai field")
		}
		return *out.AI
	}
	if !ai() {
		t.Fatal("AI not allowed with every switch on")
	}
	for _, off := range []func(bool){h.aiOn.Store, h.mediaOn.Store, h.contentOn.Store} {
		off(false)
		if ai() {
			t.Fatal("AI allowed with a switch off")
		}
		off(true)
	}
}

// An AI authorization renews like a content connection, with a new
// configuration within its providers and the 30-second relay; the switch
// is AI's, the descriptor must say "ai", and a content connection takes no
// configuration.
func TestAIRenewal(t *testing.T) {
	h := newAIHarness(t)
	id, c := h.consentAI(t, h.owner, nil)
	if err := h.conns.RecordAIAlert(context.Background(), "enclave", id, store.AIAlert{Code: "ai_quota", Provider: "google", At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	renewal := func(t *testing.T) (renewalID string, service uuid.UUID, prefix string) {
		t.Helper()
		h.enclave.mu.Lock()
		h.enclave.renewalKey = randomKey(t)
		h.enclave.renewalExtra = map[string]any{"kind": "ai"}
		pub := h.enclave.renewalKey
		h.enclave.mu.Unlock()
		r := h.call(t, http.MethodPost, "/v1/mcp/connections/"+id+"/renewal", prepareNonce(t, 32), bearer(h.ownerToken))
		expect(t, r, http.StatusOK, "")
		var d struct {
			RenewalID string `json:"renewal_id"`
		}
		r.into(t, &d)
		service, _, prefix = h.serviceFor(t, h.owner.ID, pub)
		return d.RenewalID, service, prefix
	}
	current, err := h.conns.AIAuthorization(context.Background(), h.tenant, id)
	if err != nil {
		t.Fatal(err)
	}
	body := func(renewalID string, service uuid.UUID, prefix string, keys map[string]uuid.UUID, mutate func(map[string]any)) map[string]any {
		return map[string]any{
			"renewal_id": renewalID, "key_prefix": prefix, "service_user_id": service.String(), "kid": enclaveRenewalKID, "sealed": sealed(t),
			"ai_config": aiConfigFor(renewalID, enclaveRenewalKID, service, []uuid.UUID{h.device}, keys, current.ExpiresAt, mutate),
		}
	}

	// AI off refuses the renewal before the reader.
	h.aiOn.Store(false)
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections/"+id+"/renewal", prepareNonce(t, 32), bearer(h.ownerToken)), http.StatusForbidden, "ai_not_allowed")
	h.aiOn.Store(true)
	// A descriptor that does not say "ai" is not this authorization's.
	h.enclave.mu.Lock()
	h.enclave.renewalKey = randomKey(t)
	h.enclave.renewalExtra = nil
	h.enclave.mu.Unlock()
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections/"+id+"/renewal", prepareNonce(t, 32), bearer(h.ownerToken)), http.StatusBadGateway, "reader_unavailable")

	renewalID, service, prefix := renewal(t)
	for name, b := range map[string]map[string]any{
		"no configuration": func() map[string]any {
			b := body(renewalID, service, prefix, c.keys, nil)
			delete(b, "ai_config")
			return b
		}(),
		"another renewal's": body(renewalID, service, prefix, c.keys, func(m map[string]any) {
			m["request"] = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 16))
		}),
		"the budget's limit changed": body(renewalID, service, prefix, c.keys, func(m map[string]any) { m["budget"].(map[string]any)["monthly_usd_cents"] = 5 }),
		"one number more": body(renewalID, service, prefix, c.keys, func(m map[string]any) {
			for range store.AIDevicesMax {
				m["epochs"].(map[string]any)[uuid.NewString()] = 1
			}
		}),
	} {
		t.Run(name, func(t *testing.T) {
			expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections/"+id+"/renew", b, bearer(h.ownerToken)), http.StatusBadRequest, "bad_request")
		})
	}
	// The enclave's AI refusal reaches the console with its code, and the
	// new account goes.
	h.enclave.mu.Lock()
	h.enclave.bundleStatus, h.enclave.bundleCode = http.StatusBadRequest, "ai_model_unavailable"
	h.enclave.mu.Unlock()
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections/"+id+"/renew", body(renewalID, service, prefix, c.keys, nil), bearer(h.ownerToken)),
		http.StatusBadRequest, "ai_model_unavailable")
	h.enclave.mu.Lock()
	h.enclave.bundleStatus, h.enclave.bundleCode = 0, ""
	h.enclave.mu.Unlock()
	if got := h.serviceHolds(t, service); got != 0 {
		t.Fatalf("the refused renewal's account kept %d rows", got)
	}

	// A rotation passes, with the bundle relayed as kind "ai" after a wait
	// longer than an ordinary relay's.
	renewalID, service, prefix = renewal(t)
	rotated := map[string]uuid.UUID{"google": h.keychainItem(t, h.owner.ID, "google"), "anthropic": c.keys["anthropic"]}
	r := h.call(t, http.MethodPost, "/v1/mcp/connections/"+id+"/renew", body(renewalID, service, prefix, rotated, nil), bearer(h.ownerToken))
	expect(t, r, http.StatusOK, "")
	if relayed := h.enclave.renewalBundles[renewalID]; relayed["kind"] != "ai" || relayed["connection_id"] != id {
		t.Fatalf("relayed = %v", relayed)
	}
	got, err := h.conns.AIAuthorization(context.Background(), h.tenant, id)
	if err != nil || got.Status != "active" || len(got.Alerts) != 0 || !strings.Contains(string(got.Config), rotated["google"].String()) {
		t.Fatalf("renewed = %+v %v", got, err)
	}

	// A content connection's renewal takes no configuration.
	contentID, _, _ := h.consentContent(t, h.owner)
	h.enclave.mu.Lock()
	h.enclave.renewalKey = randomKey(t)
	h.enclave.renewalExtra = nil
	pub := h.enclave.renewalKey
	h.enclave.mu.Unlock()
	rr := h.call(t, http.MethodPost, "/v1/mcp/connections/"+contentID+"/renewal", prepareNonce(t, 32), bearer(h.ownerToken))
	expect(t, rr, http.StatusOK, "")
	var d struct {
		RenewalID string `json:"renewal_id"`
	}
	rr.into(t, &d)
	contentService, _, contentPrefix := h.serviceFor(t, h.owner.ID, pub)
	b := body(d.RenewalID, contentService, contentPrefix, c.keys, nil)
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections/"+contentID+"/renew", b, bearer(h.ownerToken)), http.StatusBadRequest, "bad_request")
}

// The AI bundle's relay waits longer than any other: an enclave that
// checks keys and models past the ordinary deadline still lands.
func TestAIBundleWait(t *testing.T) {
	f := newFakeEnclave(t, "enclave", enclaveSecret, enclaveOrigin)
	relay := f.relay()
	relay.Client.Timeout = 200 * time.Millisecond
	f.bundleDelay = 600 * time.Millisecond
	ctx := context.Background()
	raw, err := relay.AIRequest(ctx, base64.RawURLEncoding.EncodeToString(randomKey(t)))
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	in := mcpauth.BundleRelay{ConnectionID: uuid.NewString(), TenantID: uuid.NewString(), KID: enclaveKID, Sealed: "AAAA", ExpiresAt: time.Now(), Kind: "ai"}
	if err := relay.AIBundle(ctx, d.RequestID, in); err != nil {
		t.Fatalf("the AI bundle did not wait: %v", err)
	}
	if err := relay.Bundle(ctx, d.RequestID, in); !errors.Is(err, mcpauth.ErrReaderUnavailable) {
		t.Fatalf("an ordinary relay waited as long: %v", err)
	}
}

// The job routes' answers.
func TestAIJobRelay(t *testing.T) {
	f := newFakeEnclave(t, "enclave", enclaveSecret, enclaveOrigin)
	relay := f.relay()
	ctx := context.Background()
	in := mcpauth.AIJobRequest{AuthorizationID: uuid.NewString(), DeviceID: uuid.NewString(), UID: uuid.NewString(), Feature: "audio",
		Origin: "console", RequesterID: uuid.NewString()}
	started, err := relay.AIJob(ctx, in)
	if err != nil || !mcpauth.ValidJobID(started.Job) || started.Stored {
		t.Fatalf("job = %+v %v", started, err)
	}
	if got, _ := json.Marshal(f.jobs[0]); !strings.Contains(string(got), `"origin":"console"`) || !strings.Contains(string(got), `"redo":false`) {
		t.Fatalf("relayed = %s", got)
	}
	for _, tc := range []struct {
		status int
		reply  any
		check  func(mcpauth.AIJobStarted, error) bool
	}{
		{http.StatusOK, map[string]any{"stored": true}, func(s mcpauth.AIJobStarted, err error) bool { return err == nil && s.Stored }},
		{http.StatusConflict, map[string]any{"code": "ai_paused"}, func(_ mcpauth.AIJobStarted, err error) bool {
			var e *mcpauth.AIJobError
			return errors.As(err, &e) && e.Code == "ai_paused"
		}},
		{http.StatusTooManyRequests, map[string]any{"code": "ai_busy", "retry_after_s": 10}, func(_ mcpauth.AIJobStarted, err error) bool {
			var e *mcpauth.AIJobError
			return errors.As(err, &e) && e.Code == "ai_busy" && e.RetryAfter == 10
		}},
		{http.StatusNotFound, map[string]any{"code": "not_found"}, func(_ mcpauth.AIJobStarted, err error) bool { return errors.Is(err, mcpauth.ErrReaderNotFound) }},
		{http.StatusBadRequest, map[string]any{"code": "bad_request"}, func(_ mcpauth.AIJobStarted, err error) bool { return errors.Is(err, mcpauth.ErrReaderUnavailable) }},
		{http.StatusAccepted, map[string]any{"job": "x"}, func(_ mcpauth.AIJobStarted, err error) bool { return errors.Is(err, mcpauth.ErrReaderUnavailable) }},
	} {
		f.mu.Lock()
		f.jobReply = func(map[string]any) (int, any) { return tc.status, tc.reply }
		f.mu.Unlock()
		if got, err := relay.AIJob(ctx, in); !tc.check(got, err) {
			t.Fatalf("%d %v = %+v %v", tc.status, tc.reply, got, err)
		}
	}
	f.mu.Lock()
	f.jobState = func(job, requester string) (int, any) {
		if requester != in.RequesterID {
			return http.StatusNotFound, map[string]any{"code": "not_found"}
		}
		return http.StatusOK, map[string]any{"state": "failed", "code": "ai_quota"}
	}
	f.mu.Unlock()
	if state, err := relay.AIJobStatus(ctx, started.Job, in.RequesterID); err != nil || state.State != "failed" || state.Code != "ai_quota" {
		t.Fatalf("state = %+v %v", state, err)
	}
	if _, err := relay.AIJobStatus(ctx, started.Job, uuid.NewString()); !errors.Is(err, mcpauth.ErrReaderNotFound) {
		t.Fatalf("another requester = %v", err)
	}
}

// ---------------------------------------------------------------------------
// The enclave's AI routes
// ---------------------------------------------------------------------------

// asRow calls an enclave route for a row, signed as the enclave and with
// the row's key as the bearer.
func (h *aiHarness) asRow(t *testing.T, method, target, key string, body any) reply {
	t.Helper()
	return (&sendHarness{attestedHarness: h.attestedHarness}).asConnection(t, method, target, key, body)
}

// message archives a message of a type on the harness's number.
func (h *aiHarness) message(t *testing.T, kind domain.Type) uuid.UUID {
	t.Helper()
	uid := uuid.New()
	in := store.InsertMessage{UID: uid, TenantID: h.tenant, DeviceID: h.device, WAID: "wa-" + uid.String(), ChatKey: friend,
		Kind: domain.KindMessage, Type: kind, Source: domain.SourceLive, TS: time.Now(), BodySealed: []byte{1}}
	if kind != domain.TypeText {
		in.Media = &store.InsertMedia{MediaType: string(kind), FileEncSHA256: randomKey(t)}
	}
	if _, err := store.NewMessages(h.pool).Insert(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	return uid
}

func record(t *testing.T, epoch int) string {
	t.Helper()
	out := append([]byte("WDRV"), 1, 0, 0)
	binary.BigEndian.PutUint16(out[5:7], uint16(epoch))
	return base64.RawURLEncoding.EncodeToString(append(out, randomKey(t)...))
}

func TestEnclaveAIRoutes(t *testing.T) {
	h := newAIHarness(t)
	ctx := context.Background()
	aiID, ac := h.consentAI(t, h.owner, nil)
	mediaID, _, mediaKey := h.consentMedia(t, h.ownerToken, true)
	_, _, textKey := h.consentMedia(t, h.ownerToken, false)
	textID := ""
	for _, c := range func() []store.MCPConnection { l, _ := h.conns.List(ctx, h.tenant); return l }() {
		if !c.Media {
			textID = c.ID
		}
	}
	voice := h.message(t, domain.TypePTT)
	photo := h.message(t, domain.TypeImage)
	other := uuid.New()

	// Which authorization answers a media connection.
	pick := func(id, key, query string) reply {
		return h.asRow(t, http.MethodGet, "/v1/mcp/enclave/connections/"+id+"/ai?"+query, key, nil)
	}
	r := pick(mediaID, mediaKey, "device_id="+h.device.String()+"&feature=audio")
	expect(t, r, http.StatusOK, "")
	var picked struct {
		AuthorizationID string `json:"authorization_id"`
		RequesterID     string `json:"requester_id"`
		State           string `json:"state"`
	}
	r.into(t, &picked)
	if picked.AuthorizationID != aiID || picked.RequesterID != h.owner.ID.String() || picked.State != "active" {
		t.Fatalf("picked = %s", r.body)
	}
	for name, got := range map[string]reply{
		"a function nobody configured": pick(mediaID, mediaKey, "device_id="+h.device.String()+"&feature=video"),
		"a number outside the key":     pick(mediaID, mediaKey, "device_id="+other.String()+"&feature=audio"),
		"a text-only connection":       pick(textID, textKey, "device_id="+h.device.String()+"&feature=audio"),
	} {
		t.Run(name, func(t *testing.T) { expect(t, got, http.StatusNotFound, "ai_not_enabled") })
	}
	expect(t, pick(mediaID, textKey, "device_id="+h.device.String()+"&feature=audio"), http.StatusNotFound, "not_found")
	expect(t, pick(mediaID, "", "device_id="+h.device.String()+"&feature=audio"), http.StatusNotFound, "not_found")
	expect(t, pick(mediaID, mediaKey, "feature=audio"), http.StatusBadRequest, "bad_request")
	expect(t, pick(mediaID, mediaKey, "device_id="+h.device.String()+"&feature=translate"), http.StatusBadRequest, "bad_request")
	h.aiOn.Store(false)
	expect(t, pick(mediaID, mediaKey, "device_id="+h.device.String()+"&feature=audio"), http.StatusNotFound, "ai_not_enabled")
	h.aiOn.Store(true)
	// After a reseal the requester's own answers reseal.
	if err := h.conns.Reseal(ctx, "enclave", aiID); err != nil {
		t.Fatal(err)
	}
	pick(mediaID, mediaKey, "device_id="+h.device.String()+"&feature=audio").into(t, &picked)
	if picked.State != "reseal" || picked.AuthorizationID != aiID {
		t.Fatalf("resealed pick = %+v", picked)
	}
	// The owner renews; here the row is simply made active again.
	if _, err := h.pool.Exec(ctx, `UPDATE mcp_connections SET status='active' WHERE id=$1`, aiID); err != nil {
		t.Fatal(err)
	}

	// Storing a result.
	put := func(uid uuid.UUID, feature string, body map[string]any) reply {
		return h.asRow(t, http.MethodPut, "/v1/mcp/enclave/connections/"+aiID+"/ai/derived/"+uid.String()+"/"+feature, ac.key, body)
	}
	tag := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	stored := map[string]any{"device_id": h.device.String(), "epoch": 1, "sealed": record(t, 1), "dedupe_tag": tag, "redo": false}
	expect(t, put(voice, "audio", stored), http.StatusNoContent, "")
	expect(t, put(voice, "audio", stored), http.StatusConflict, "derived_exists")
	stored["redo"] = true
	expect(t, put(voice, "audio", stored), http.StatusNoContent, "")
	stored["redo"] = false
	for name, got := range map[string]reply{
		"the type not the function's": put(photo, "document", stored),
		"a function it does not have": put(photo, "image", stored),
		"a message that is not":       put(uuid.New(), "audio", stored),
		"another epoch inside": put(voice, "audio", map[string]any{"device_id": h.device.String(), "epoch": 2, "sealed": record(t, 1),
			"dedupe_tag": tag, "redo": true}),
		"a number outside the key": put(voice, "audio", map[string]any{"device_id": other.String(), "epoch": 1, "sealed": record(t, 1),
			"dedupe_tag": tag, "redo": true}),
		"an unknown field": put(voice, "audio", map[string]any{"device_id": h.device.String(), "epoch": 1, "sealed": record(t, 1),
			"dedupe_tag": tag, "redo": true, "text": "no"}),
	} {
		t.Run(name, func(t *testing.T) { expect(t, got, http.StatusBadRequest, "bad_request") })
	}
	// A media connection stores nothing; another row's key opens nothing.
	expect(t, h.asRow(t, http.MethodPut, "/v1/mcp/enclave/connections/"+mediaID+"/ai/derived/"+voice.String()+"/audio", mediaKey, stored),
		http.StatusNotFound, "not_found")
	expect(t, h.asRow(t, http.MethodPut, "/v1/mcp/enclave/connections/"+aiID+"/ai/derived/"+voice.String()+"/audio", mediaKey, stored),
		http.StatusNotFound, "not_found")
	// Storage paused.
	second := h.message(t, domain.TypeAudio)
	if _, err := h.pool.Exec(ctx, `UPDATE tenants SET storage_paused_at=now() WHERE id=$1`, h.tenant); err != nil {
		t.Fatal(err)
	}
	expect(t, put(second, "audio", stored), http.StatusConflict, "storage_paused")
	if _, err := h.pool.Exec(ctx, `UPDATE tenants SET storage_paused_at=NULL WHERE id=$1`, h.tenant); err != nil {
		t.Fatal(err)
	}

	// Reading it back: a message's, by the media connection and by the
	// authorization; the reuse lookup, by the authorization only.
	var items struct {
		Items []map[string]any `json:"items"`
	}
	msg := "?device_id=" + h.device.String() + "&uid=" + voice.String()
	for _, c := range []struct{ id, key string }{{mediaID, mediaKey}, {aiID, ac.key}} {
		r := h.asRow(t, http.MethodGet, "/v1/mcp/enclave/connections/"+c.id+"/ai/derived"+msg, c.key, nil)
		expect(t, r, http.StatusOK, "")
		r.into(t, &items)
		if len(items.Items) != 1 || items.Items[0]["feature"] != "audio" || items.Items[0]["message_uid"] != voice.String() || len(items.Items[0]) != 6 {
			t.Fatalf("items = %s", r.body)
		}
	}
	expect(t, h.asRow(t, http.MethodGet, "/v1/mcp/enclave/connections/"+textID+"/ai/derived"+msg, textKey, nil), http.StatusNotFound, "not_found")
	expect(t, h.asRow(t, http.MethodGet, "/v1/mcp/enclave/connections/"+mediaID+"/ai/derived?device_id="+other.String()+"&uid="+voice.String(), mediaKey, nil),
		http.StatusNotFound, "not_found")
	tags := "?feature=audio&tags=" + h.device.String() + "." + tag
	r = h.asRow(t, http.MethodGet, "/v1/mcp/enclave/connections/"+aiID+"/ai/derived"+tags, ac.key, nil)
	expect(t, r, http.StatusOK, "")
	r.into(t, &items)
	if len(items.Items) != 1 {
		t.Fatalf("by tag = %s", r.body)
	}
	expect(t, h.asRow(t, http.MethodGet, "/v1/mcp/enclave/connections/"+mediaID+"/ai/derived"+tags, mediaKey, nil), http.StatusNotFound, "not_found")
	for _, bad := range []string{
		"?feature=audio&tags=" + other.String() + "." + tag,
		"?feature=audio&tags=" + h.device.String() + ".AAAA",
		"?feature=audio&tags=" + strings.Repeat(h.device.String()+"."+tag+",", 25) + h.device.String() + "." + tag,
		"?feature=audio",
		"?device_id=" + h.device.String(),
	} {
		expect(t, h.asRow(t, http.MethodGet, "/v1/mcp/enclave/connections/"+aiID+"/ai/derived"+bad, ac.key, nil), http.StatusBadRequest, "bad_request")
	}

	// Usage, and the month's total.
	usage := map[string]any{"device_id": h.device.String(), "feature": "audio", "provider": "google", "model": geminiModel, "origin": "connector",
		"requester_id": h.owner.ID.String(), "items": 1, "reused": 0, "failures": 0, "input_tokens": 1500, "output_tokens": 300, "seconds": 60,
		"cost_microcents": 120_000}
	expect(t, h.asRow(t, http.MethodPost, "/v1/mcp/enclave/connections/"+aiID+"/ai/usage", ac.key, usage), http.StatusNoContent, "")
	expect(t, h.asRow(t, http.MethodPost, "/v1/mcp/enclave/connections/"+aiID+"/ai/usage", ac.key, usage), http.StatusNoContent, "")
	for name, change := range map[string]map[string]any{
		"another provider": {"provider": "openai"}, "a model of the wrong shape": {"model": "Gemini"}, "origin auto": {"origin": "auto"},
		"a negative count": {"items": -1}, "a number outside": {"device_id": other.String()}, "a function it lacks": {"feature": "video"},
	} {
		b := map[string]any{}
		for k, v := range usage {
			b[k] = v
		}
		for k, v := range change {
			b[k] = v
		}
		t.Run(name, func(t *testing.T) {
			expect(t, h.asRow(t, http.MethodPost, "/v1/mcp/enclave/connections/"+aiID+"/ai/usage", ac.key, b), http.StatusBadRequest, "bad_request")
		})
	}
	month := time.Now().UTC().Format("2006-01")
	r = h.asRow(t, http.MethodGet, "/v1/mcp/enclave/connections/"+aiID+"/ai/usage?month="+month, ac.key, nil)
	expect(t, r, http.StatusOK, "")
	if string(bytes.TrimSpace(r.body)) != `{"month":"`+month+`","cost_microcents":240000,"items_today":2}` {
		t.Fatalf("month = %s", r.body)
	}
	expect(t, h.asRow(t, http.MethodGet, "/v1/mcp/enclave/connections/"+aiID+"/ai/usage?month=2026-13", ac.key, nil), http.StatusBadRequest, "bad_request")
	expect(t, h.asRow(t, http.MethodGet, "/v1/mcp/enclave/connections/"+mediaID+"/ai/usage?month="+month, mediaKey, nil), http.StatusNotFound, "not_found")

	// Alerts, kept for the console.
	for _, b := range []map[string]any{
		{"code": "ai_key_rejected", "provider": "google"}, {"code": "ai_model_unavailable", "feature": "document"}, {"code": "ai_quota", "provider": "anthropic"},
	} {
		expect(t, h.asRow(t, http.MethodPost, "/v1/mcp/enclave/connections/"+aiID+"/ai/alerts", ac.key, b), http.StatusNoContent, "")
	}
	for _, b := range []map[string]any{
		{"code": "ai_bored"}, {"code": "ai_key_rejected"}, {"code": "ai_model_unavailable", "provider": "google"},
		{"code": "ai_quota", "provider": "openai"}, {"code": "ai_model_unavailable", "feature": "video"},
	} {
		expect(t, h.asRow(t, http.MethodPost, "/v1/mcp/enclave/connections/"+aiID+"/ai/alerts", ac.key, b), http.StatusBadRequest, "bad_request")
	}
	a, err := h.conns.AIAuthorization(ctx, h.tenant, aiID)
	if err != nil || len(a.Alerts) != 3 {
		t.Fatalf("alerts = %+v %v", a.Alerts, err)
	}

	// Once revoked, its key opens nothing.
	if _, _, err := h.conns.RevokeAI(ctx, h.tenant, h.owner.ID, aiID, false); err != nil {
		t.Fatal(err)
	}
	expect(t, h.asRow(t, http.MethodPost, "/v1/mcp/enclave/connections/"+aiID+"/ai/usage", ac.key, usage), http.StatusNotFound, "not_found")
}
