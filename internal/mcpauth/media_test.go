package mcpauth_test

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// Attachments over HTTP (docs/mcp-enclave.md §16.3): the media flag on a
// consent, what the list, the reader's status and GET /v1/mcp/content say
// about it, and exactly which fields reach the reader. The shapes are those
// pinned in packages/mcp-http/enclave/test/go-a0-shapes.json, which the
// enclave's tests feed to the reader that is live today (0.3.0).

// mediaBody is a version-2 content consent, with attachments or without.
func mediaBody(t *testing.T, requestID, prefix string, service uuid.UUID, media bool) map[string]any {
	t.Helper()
	body := contentBody(t, requestID, prefix, service)
	body["consent_version"] = 2
	body["media"] = media
	return body
}

// prepareContent prepares a fresh request of the enclave and builds the
// service account and key a content consent to it needs.
func (h *attestedHarness) prepareContent(t *testing.T, actor uuid.UUID) (requestID string, service uuid.UUID, key, prefix string) {
	t.Helper()
	pub := randomKey(t)
	requestID = h.enclave.pendingKey(t, pub)
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/requests/"+requestID+"/prepare", prepareNonce(t, 32), nil), http.StatusOK, "")
	service, key, prefix = h.serviceFor(t, actor, pub)
	return requestID, service, key, prefix
}

// consentMedia runs a version-2 consent through to an active connection and
// returns it with the request it answered.
func (h *attestedHarness) consentMedia(t *testing.T, token string, media bool) (id, requestID string, key string) {
	t.Helper()
	requestID, service, key, prefix := h.prepareContent(t, h.owner.ID)
	r := h.call(t, http.MethodPost, "/v1/mcp/connections", mediaBody(t, requestID, prefix, service, media), bearer(token))
	expect(t, r, http.StatusCreated, "")
	var created struct {
		ID string `json:"id"`
	}
	r.into(t, &created)
	a, _ := h.signedCall(t, http.MethodPost, "/v1/mcp/enclave/connections/"+created.ID+"/activate", asEnclave(t))
	expect(t, a, http.StatusNoContent, "")
	return created.ID, requestID, key
}

// mediaListing is a listed connection's consent fields; pointers, so a
// missing field fails instead of reading as zero.
type mediaListing struct {
	ConsentVersion *int  `json:"consent_version"`
	Media          *bool `json:"media"`
}

func (h *attestedHarness) mediaListed(t *testing.T, token, id string) mediaListing {
	t.Helper()
	r := h.call(t, http.MethodGet, "/v1/mcp/connections", nil, bearer(token))
	expect(t, r, http.StatusOK, "")
	var out struct {
		Connections []struct {
			ID string `json:"id"`
			mediaListing
		} `json:"connections"`
	}
	r.into(t, &out)
	for _, c := range out.Connections {
		if c.ID == id {
			if c.Media == nil {
				t.Fatalf("connection %s listed without media: %s", id, r.body)
			}
			return c.mediaListing
		}
	}
	t.Fatalf("connection %s not listed: %s", id, r.body)
	return mediaListing{}
}

// mediaStanding is the attested status answer with its media fields.
type mediaStanding struct {
	Status   string    `json:"status"`
	Media    *bool     `json:"media"`
	MediaOff *[]string `json:"media_off"`
}

func (h *attestedHarness) mediaStanding(t *testing.T, id string) (status string, media bool, off []string) {
	t.Helper()
	r, _ := h.signedCall(t, http.MethodGet, "/v1/mcp/enclave/connections/"+id, asEnclave(t))
	expect(t, r, http.StatusOK, "")
	var s mediaStanding
	r.into(t, &s)
	if s.Media == nil || s.MediaOff == nil {
		t.Fatalf("status without media or media_off: %s", r.body)
	}
	return s.Status, *s.Media, *s.MediaOff
}

func fieldNames(m map[string]any) string {
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	slices.Sort(names)
	return strings.Join(names, ",")
}

// The fields of the consent relay: a reader before attachments parses it
// strictly, so media goes on the wire only as true.
const (
	relayFields      = "connection_id,expires_at,kid,kind,sealed,tenant_id"
	mediaRelayFields = "connection_id,expires_at,kid,kind,media,sealed,tenant_id"
)

// A consent asks for attachments only on version 2 and only where the
// switch allows them; the list, the status and the relay carry the flag,
// and the switch narrows the status without ever turning it into reseal.
func TestMediaConsent(t *testing.T) {
	h := newAttestedHarness(t)
	h.contentOn.Store(true)
	owner := h.session(t, h.owner)
	mediaEnabled := func() bool {
		t.Helper()
		r := h.call(t, http.MethodGet, "/v1/mcp/content", nil, bearer(owner))
		expect(t, r, http.StatusOK, "")
		var out struct {
			Enabled  bool  `json:"enabled"`
			Attested bool  `json:"attested"`
			Media    *bool `json:"media"`
		}
		r.into(t, &out)
		if out.Media == nil || !out.Enabled || !out.Attested && *out.Media {
			t.Fatalf("content reply = %s", r.body)
		}
		return *out.Media
	}

	// Off: the console hears so, and a consent asking anyway is refused
	// before the ledger and before the reader.
	if mediaEnabled() {
		t.Fatal("media enabled with the switch off")
	}
	requestID, service, _, prefix := h.prepareContent(t, h.owner.ID)
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", mediaBody(t, requestID, prefix, service, true), bearer(owner)),
		http.StatusBadRequest, "media_not_allowed")
	if rows, err := h.conns.List(context.Background(), h.tenant); err != nil || len(rows) != 0 {
		t.Fatalf("a refused media consent left rows: %+v %v", rows, err)
	}
	if h.enclave.bundle(requestID) != nil {
		t.Fatal("a refused media consent reached the enclave")
	}
	// It rides on content: the media switch alone allows nothing.
	h.mediaOn.Store(true)
	h.contentOn.Store(false)
	r := h.call(t, http.MethodGet, "/v1/mcp/content", nil, bearer(owner))
	expect(t, r, http.StatusOK, "")
	if !strings.Contains(string(r.body), `"media":false`) {
		t.Fatalf("media enabled with content off: %s", r.body)
	}
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", mediaBody(t, requestID, prefix, service, true), bearer(owner)),
		http.StatusForbidden, "content_not_allowed")
	h.contentOn.Store(true)
	if !mediaEnabled() {
		t.Fatal("media not enabled for a listed workspace with both switches on")
	}
	// A metadata consent never carries it.
	metaID := h.enclave.pending(t)
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/requests/"+metaID+"/prepare", prepareNonce(t, 32), nil), http.StatusOK, "")
	_, metaPrefix := h.provisionalKey(t, "meta")
	meta := consent(metaID, metaPrefix)
	meta["kid"], meta["sealed"], meta["media"] = enclaveKID, sealed(t), true
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", meta, bearer(owner)), http.StatusBadRequest, "bad_request")
	delete(meta, "media")
	r = h.call(t, http.MethodPost, "/v1/mcp/connections", meta, bearer(owner))
	expect(t, r, http.StatusCreated, "")
	var metaConn struct {
		ID string `json:"id"`
	}
	r.into(t, &metaConn)

	// Version 2 without attachments: the relay every reader takes.
	textID, textRequest, _ := h.consentMedia(t, owner, false)
	if got := fieldNames(h.enclave.bundle(textRequest)); got != relayFields {
		t.Fatalf("text-only relay fields = %s", got)
	}
	// With them: the relay says so, for the reader to compare with the seal.
	mediaID, mediaRequest, _ := h.consentMedia(t, owner, true)
	bundle := h.enclave.bundle(mediaRequest)
	if got := fieldNames(bundle); got != mediaRelayFields || bundle["media"] != true {
		t.Fatalf("media relay = %v", bundle)
	}
	v1ID, _, _ := h.consentContent(t, h.owner)
	if got := fieldNames(h.enclave.bundle(h.requestOf(t, v1ID))); got != relayFields {
		t.Fatalf("version-1 relay fields = %s", got)
	}

	// The list names the consent: version and media, null for metadata.
	for id, want := range map[string]struct {
		version int
		media   bool
	}{v1ID: {1, false}, textID: {2, false}, mediaID: {2, true}, metaConn.ID: {0, false}} {
		l := h.mediaListed(t, owner, id)
		if want.version == 0 && l.ConsentVersion != nil || want.version != 0 && (l.ConsentVersion == nil || *l.ConsentVersion != want.version) ||
			*l.Media != want.media {
			t.Fatalf("%s listed as version %v media %v, want %+v", id, l.ConsentVersion, *l.Media, want)
		}
	}

	// The status: media only for the media connection, and the kinds off.
	for id, want := range map[string]bool{v1ID: false, textID: false, mediaID: true, metaConn.ID: false} {
		if _, media, off := h.mediaStanding(t, id); media != want || len(off) != 0 {
			t.Fatalf("%s: media %v off %v, want %v", id, media, off, want)
		}
	}
	h.handler.MediaOff = []string{"pdf", "zip"}
	if _, media, off := h.mediaStanding(t, mediaID); !media || strings.Join(off, ",") != "pdf,zip" {
		t.Fatalf("with kinds off: media %v off %v", media, off)
	}
	h.handler.MediaOff = nil
	// The media switch off: attachments stop, text does not; the consent
	// is unchanged in the list.
	h.mediaOn.Store(false)
	if status, media, _ := h.mediaStanding(t, mediaID); status != "active" || media {
		t.Fatalf("media switched off: %s media %v", status, media)
	}
	if l := h.mediaListed(t, owner, mediaID); !*l.Media {
		t.Fatal("switching media off changed the consent")
	}
	h.mediaOn.Store(true)
	// Content off: reseal, and no attachments either.
	h.contentOn.Store(false)
	if status, media, _ := h.mediaStanding(t, mediaID); status != "reseal" || media {
		t.Fatalf("content switched off: %s media %v", status, media)
	}
	h.contentOn.Store(true)
	// An ended connection opens nothing.
	expect(t, h.call(t, http.MethodDelete, "/v1/mcp/connections/"+mediaID, nil, bearer(owner)), http.StatusNoContent, "")
	if status, media, _ := h.mediaStanding(t, mediaID); status != "revoked" || media {
		t.Fatalf("revoked: %s media %v", status, media)
	}
	// The hosted reader's answer never grows.
	hosted, _ := h.approve(t, owner)
	r = h.call(t, http.MethodGet, "/v1/mcp/internal/connections/"+hosted, nil, internal())
	expect(t, r, http.StatusOK, "")
	if strings.Contains(string(r.body), "media") {
		t.Fatalf("hosted status = %s", r.body)
	}
}

// requestOf finds the request a relayed consent answered, by the connection
// id the relay carried.
func (h *attestedHarness) requestOf(t *testing.T, connectionID string) string {
	t.Helper()
	h.enclave.mu.Lock()
	defer h.enclave.mu.Unlock()
	for requestID, body := range h.enclave.bundles {
		if body["connection_id"] == connectionID {
			return requestID
		}
	}
	t.Fatalf("no relay for %s", connectionID)
	return ""
}

// A renewal renews the key and never the consent: its relay carries no
// media, and the connection keeps its version and its attachments.
func TestMediaRenewalKeepsConsent(t *testing.T) {
	h := newAttestedHarness(t)
	h.contentOn.Store(true)
	h.mediaOn.Store(true)
	owner := h.session(t, h.owner)
	id, _, _ := h.consentMedia(t, owner, true)
	rs, _ := h.signedCall(t, http.MethodPost, "/v1/mcp/enclave/connections/"+id+"/reseal", asEnclave(t))
	expect(t, rs, http.StatusNoContent, "")

	newPub := randomKey(t)
	h.enclave.mu.Lock()
	h.enclave.renewalKey = newPub
	h.enclave.mu.Unlock()
	r := h.call(t, http.MethodPost, "/v1/mcp/connections/"+id+"/renewal", prepareNonce(t, 32), bearer(owner))
	expect(t, r, http.StatusOK, "")
	var renewal struct {
		RenewalID string `json:"renewal_id"`
	}
	r.into(t, &renewal)
	service, _, prefix := h.serviceFor(t, h.owner.ID, newPub)
	r = h.call(t, http.MethodPost, "/v1/mcp/connections/"+id+"/renew", map[string]any{
		"renewal_id": renewal.RenewalID, "key_prefix": prefix, "service_user_id": service.String(), "kid": enclaveRenewalKID, "sealed": sealed(t),
	}, bearer(owner))
	expect(t, r, http.StatusOK, "")
	h.enclave.mu.Lock()
	staged := h.enclave.renewalBundles[renewal.RenewalID]
	h.enclave.mu.Unlock()
	if got := fieldNames(staged); got != relayFields {
		t.Fatalf("renewal relay fields = %s", got)
	}
	if l := h.mediaListed(t, owner, id); l.ConsentVersion == nil || *l.ConsentVersion != 2 || !*l.Media {
		t.Fatalf("after renewal: version %v media %v", l.ConsentVersion, *l.Media)
	}
	if status, media, _ := h.mediaStanding(t, id); status != "active" || !media {
		t.Fatalf("after renewal: %s media %v", status, media)
	}
}
