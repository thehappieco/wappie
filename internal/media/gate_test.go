package media_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/domain"
	"whatserver2/internal/mcpauth"
	"whatserver2/internal/media"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// /v1/media and the assistant connections of the attested reader
// (docs/mcp-enclave.md §16.3). A content connection's key is a read-only
// key restricted to its numbers, acting as the connection's own service
// account; these tests settle that such a key reaches the ciphertext of its
// own numbers' attachments through the usual checks, and that the gate
// refuses it, before any lookup and in the same bytes as an attachment that
// is not the caller's, unless its consent includes attachments and the
// switch allows them; and that it refuses every other key acting as a
// connection's service account, a renewal's new one included.

// serviceKey makes what the console makes before a consent or a renewal
// reaches the reader: a provisional service account whose public key is the
// attested one, read-only on the fixture's device with a grant sealed to
// that key, and a twenty-minute key acting as it. No connection holds it
// yet.
func (f *fixture) serviceKey(t *testing.T, owner store.User) (service uuid.UUID, pub []byte, key string) {
	t.Helper()
	ctx := context.Background()
	users := store.NewUsers(f.pool)
	pub = make([]byte, 32)
	name := make([]byte, 4)
	if _, err := rand.Read(pub); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(name); err != nil {
		t.Fatal(err)
	}
	secret, _, err := users.NewProvisionalServiceInvitation(ctx, f.tenant, owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	account, err := users.SignupService(ctx, secret, "mcp-"+hex.EncodeToString(name), pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := users.SetDevicePermission(ctx, f.tenant, owner.ID, store.DevicePermission{DeviceID: f.device, UserID: account.ID, Read: true}); err != nil {
		t.Fatal(err)
	}
	if err := store.NewKeys(f.pool).PutGrant(ctx, store.Grant{TenantID: f.tenant, DeviceID: f.device, UserID: account.ID, Epoch: 1, SealedDSK: []byte("sealed to the attested key")}, &owner.ID); err != nil {
		t.Fatal(err)
	}
	in := time.Now().Add(20 * time.Minute)
	key, err = f.apiKeys.IssueActingAsForDevices(ctx, f.tenant.String(), "assistant", store.ScopeRead, &owner.ID, &account.ID, []uuid.UUID{f.device}, &in)
	if err != nil {
		t.Fatal(err)
	}
	return account.ID, pub, key
}

// connectionKey records and activates a content connection on the
// fixture's device, as the console and the enclave would, and returns its
// service account and key. version and media are the consent's.
func (f *fixture) connectionKey(t *testing.T, owner store.User, version int, media bool) (uuid.UUID, string) {
	t.Helper()
	ctx := context.Background()
	service, pub, key := f.serviceKey(t, owner)
	prefix, _, _ := strings.Cut(key, ".")
	conns := store.NewMCPConnections(f.pool)
	conn, err := conns.Create(ctx, f.tenant, owner.ID, store.CreateMCPConnection{
		RequestID: uuid.NewString(), KeyPrefix: prefix, ClientName: "Claude", RedirectHost: "claude.ai", DeviceCount: 1,
		ReaderKID: "0123456789abcdef", ExpiresAt: time.Now().Add(30 * 24 * time.Hour), Reader: "enclave",
		Kind: store.KindContent, ServiceUserID: service, KeyMode: store.KeyModeEphemeral, ConsentVersion: version, Media: media,
		ReaderPublicKey: pub,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := conns.Activate(ctx, "enclave", conn.ID); err != nil {
		t.Fatal(err)
	}
	return service, key
}

// aiConnectionKey records and activates an AI authorization on the
// fixture's device, as the console and the enclave would, with Gemini for
// audio, and returns its id and key.
func (f *fixture) aiConnectionKey(t *testing.T, owner store.User) (string, string) {
	t.Helper()
	ctx := context.Background()
	service, pub, key := f.serviceKey(t, owner)
	prefix, _, _ := strings.Cut(key, ".")
	item, err := store.NewAI(f.pool).AddKeychainItem(ctx, f.tenant, owner.ID, store.AIKeychainItem{
		ID: uuid.New(), Provider: "google", Label: "Gemini", Suffix: "a1B2", Envelope: []byte("WKC1" + strings.Repeat("s", 60)),
	})
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	request, expires := base64.RawURLEncoding.EncodeToString(id[:]), time.Now().Add(30*24*time.Hour).Truncate(time.Second)
	device := f.device.String()
	raw := `{"version":1,"request":"` + request + `","kid":"0123456789abcdef","service_user_id":"` + service.String() + `",
		"epochs":{"` + device + `":1},"ns":{"` + device + `":"` + f.tenant.String() + `"},
		"keys":{"google":{"keychain_id":"` + item.ID.String() + `","sha256":"` + strings.Repeat("ab", 32) + `","label":"Gemini","suffix":"a1B2"}},
		"functions":{"audio":{"provider":"google","model":"gemini-3.8-flash"}},
		"features":{"` + device + `":{"audio":{"mode":"request","requesters":"self"}}},
		"budget":{"monthly_usd_cents":1000,"request_items_per_day":100,"rates":{"google:gemini-3.8-flash":{"in":30,"out":250,"sec":0}}},
		"expires_at":"` + expires.UTC().Format(time.RFC3339) + `","key_mode":"ephemeral","cfg_tags":{"` + device + `":"` + strings.Repeat("A", 43) + `"}}`
	cfg, err := store.ParseAIConfig([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	conns := store.NewMCPConnections(f.pool)
	conn, err := conns.Create(ctx, f.tenant, owner.ID, store.CreateMCPConnection{
		RequestID: request, KeyPrefix: prefix, ClientName: store.AIClientName, RedirectHost: store.AIRedirectHost, DeviceCount: 1,
		ReaderKID: "0123456789abcdef", ExpiresAt: expires, Reader: "enclave", Kind: store.KindAI, ServiceUserID: service,
		KeyMode: store.KeyModeEphemeral, ConsentVersion: store.AIConsentVersion, ReaderPublicKey: pub, AIConfig: &cfg,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := conns.Activate(ctx, "enclave", conn.ID); err != nil {
		t.Fatal(err)
	}
	return conn.ID, key
}

// answer is everything a caller sees of a response.
type answer struct {
	status int
	header http.Header
	body   string
}

func TestTheGateLetsOnlyMediaConnectionsThrough(t *testing.T) {
	f := newFixture(t, []byte(strings.Repeat("uma foto aberta no enclave. ", 50)))
	ref := f.run(t, f.worker(t))
	if ref.Status != "done" {
		t.Fatalf("status = %q, want done", ref.Status)
	}
	ctx := context.Background()
	users := store.NewUsers(f.pool)
	owner, err := users.Create(ctx, store.NewUser{TenantID: f.tenant, Email: "owner@gate.test", Role: "owner", AuthKey: "proof",
		KDFSalt: make([]byte, 16), KDFParams: store.DefaultKDFParams(), PublicKey: make([]byte, 32), WrappedUSK: []byte("wrapped")})
	if err != nil {
		t.Fatal(err)
	}
	archivePub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.NewKeys(f.pool).CreateArchiveKey(ctx, f.tenant, f.device, 1, archivePub); err != nil {
		t.Fatal(err)
	}
	if err := store.NewKeys(f.pool).PutGrant(ctx, store.Grant{TenantID: f.tenant, DeviceID: f.device, UserID: owner.ID, Epoch: 1, SealedDSK: []byte("the owner's")}, &owner.ID); err != nil {
		t.Fatal(err)
	}
	if err := users.SetDevicePermission(ctx, f.tenant, owner.ID, store.DevicePermission{DeviceID: f.device, UserID: owner.ID, Read: true}); err != nil {
		t.Fatal(err)
	}

	// Another number in the workspace, with the same attachment stored.
	dev, err := store.NewDevices(f.pool).Create(ctx, f.tenant.String(), "second", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	otherNumber := f.insertAttachment(t, f.tenant, uuid.MustParse(dev.ID))
	f.exec(t, `UPDATE media SET download_status='done', object_key='`+ref.ObjectKey+`', object_size=`+
		itoa(ref.Size)+` WHERE message_uid='`+otherNumber.String()+`'`)
	// And another workspace's.
	var otherID string
	if err := f.pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('elsewhere') RETURNING id::text`).Scan(&otherID); err != nil {
		t.Fatal(err)
	}
	otherTenant := uuid.MustParse(otherID)
	otherDev, err := store.NewDevices(f.pool).Create(ctx, otherID, "theirs", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	otherWorkspace := f.insertAttachment(t, otherTenant, uuid.MustParse(otherDev.ID))

	var mediaOn, aiOn atomic.Bool
	mediaOn.Store(true)
	aiOn.Store(true)
	gate := mcpauth.MediaGate(store.NewMCPConnections(f.pool), func(tenant uuid.UUID) bool { return mediaOn.Load() && tenant == f.tenant },
		func(tenant uuid.UUID) bool { return aiOn.Load() && tenant == f.tenant })
	mux, ungated := http.NewServeMux(), http.NewServeMux()
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		mux.Handle(method+" /v1/media/{uid}", &media.Handler{Keys: f.apiKeys, Sessions: users, Media: f.media, Blob: f.blob, Gate: gate,
			Log: slog.New(slog.DiscardHandler)})
		ungated.Handle(method+" /v1/media/{uid}", &media.Handler{Keys: f.apiKeys, Sessions: users, Media: f.media, Blob: f.blob,
			Log: slog.New(slog.DiscardHandler)})
	}
	serve := func(mux *http.ServeMux, method, key string, uid uuid.UUID) answer {
		t.Helper()
		req := httptest.NewRequest(method, "/v1/media/"+uid.String(), nil)
		req.Header.Set("Authorization", "Bearer "+key)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return answer{w.Code, w.Header(), w.Body.String()}
	}
	fetch := func(method, key string, uid uuid.UUID) answer {
		t.Helper()
		return serve(mux, method, key, uid)
	}

	mediaService, withMedia := f.connectionKey(t, owner, store.MediaConsentVersion, true)
	_, textOnly := f.connectionKey(t, owner, store.MediaConsentVersion, false)
	_, versionOne := f.connectionKey(t, owner, store.ContentConsentVersion, false)
	// AI authorizations: one live, one paused, one whose reader lost its key.
	conns := store.NewMCPConnections(f.pool)
	aiConnection, aiKey := f.aiConnectionKey(t, owner)
	aiPaused, aiPausedKey := f.aiConnectionKey(t, owner)
	paused := true
	if _, err := conns.SetAIControls(ctx, f.tenant, owner.ID, aiPaused, store.AIControls{Paused: &paused}); err != nil {
		t.Fatal(err)
	}
	aiResealed, aiResealedKey := f.aiConnectionKey(t, owner)
	if err := conns.Reseal(ctx, "enclave", aiResealed); err != nil {
		t.Fatal(err)
	}
	// A renewal's new key: the reader holds it while it proves the grants,
	// before the ledger points the connection at it, and for the account's
	// thirty minutes if the renewal fails and the account cannot be
	// removed. So is a consent's, and so is any other key issued acting as
	// a connection's account.
	_, _, staged := f.serviceKey(t, owner)
	in := time.Now().Add(20 * time.Minute)
	second, err := f.apiKeys.IssueActingAsForDevices(ctx, f.tenant.String(), "second", store.ScopeRead, &owner.ID, &mediaService, []uuid.UUID{f.device}, &in)
	if err != nil {
		t.Fatal(err)
	}

	// Every one of these keys reads its number's ciphertext through the
	// usual checks: without the gate, nothing below would refuse them.
	for name, key := range map[string]string{"version-2 key without media": textOnly, "version-1 key": versionOne,
		"staged key": staged, "second key on a media account": second, "paused AI key": aiPausedKey, "resealed AI key": aiResealedKey} {
		if got := serve(ungated, http.MethodGet, key, f.msgUID); got.status != http.StatusOK || got.body != string(f.cipher) {
			t.Fatalf("ungated %s: %d", name, got.status)
		}
	}

	// A media connection's key reads its own number's attachment, GET and
	// HEAD, the ciphertext and nothing else.
	got := fetch(http.MethodGet, withMedia, f.msgUID)
	if got.status != http.StatusOK || got.body != string(f.cipher) || got.header.Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("media key on its number: %d %q", got.status, got.header.Get("Content-Type"))
	}
	if head := fetch(http.MethodHead, withMedia, f.msgUID); head.status != http.StatusOK || head.header.Get("Content-Length") != itoa(int64(len(f.cipher))) {
		t.Fatalf("media key HEAD: %d %v", head.status, head.header)
	}
	// So does a live AI authorization's key, while AI is allowed.
	if got := fetch(http.MethodGet, aiKey, f.msgUID); got.status != http.StatusOK || got.body != string(f.cipher) {
		t.Fatalf("AI key on its number: %d", got.status)
	}

	// Not yours: another workspace's attachment, and one that does not
	// exist. Every refusal below is this answer, byte for byte.
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		notYours := fetch(method, withMedia, otherWorkspace)
		if notYours.status != http.StatusNotFound {
			t.Fatalf("%s another workspace: %d", method, notYours.status)
		}
		same := func(name string, a answer) {
			t.Helper()
			if a.status != notYours.status || a.body != notYours.body || !reflect.DeepEqual(a.header, notYours.header) {
				t.Fatalf("%s %s = %d %v %.40q, not the answer for an attachment that is not the caller's (%d %v %q)",
					method, name, a.status, a.header, a.body, notYours.status, notYours.header, notYours.body)
			}
		}
		same("unknown attachment", fetch(method, withMedia, uuid.New()))
		same("media key on another number", fetch(method, withMedia, otherNumber))
		same("version-2 key without media", fetch(method, textOnly, f.msgUID))
		same("version-1 key", fetch(method, versionOne, f.msgUID))
		same("staged key", fetch(method, staged, f.msgUID))
		same("second key on a media account", fetch(method, second, f.msgUID))
		mediaOn.Store(false)
		same("media key with the switch off", fetch(method, withMedia, f.msgUID))
		mediaOn.Store(true)
		same("AI key on another workspace's", fetch(method, aiKey, otherWorkspace))
		same("paused AI key", fetch(method, aiPausedKey, f.msgUID))
		same("resealed AI key", fetch(method, aiResealedKey, f.msgUID))
		aiOn.Store(false)
		same("AI key with AI off", fetch(method, aiKey, f.msgUID))
		aiOn.Store(true)
	}
	// An ended authorization's key ended with it, before any gate.
	if _, _, err := conns.RevokeAI(ctx, f.tenant, owner.ID, aiConnection, false); err != nil {
		t.Fatal(err)
	}
	if got := fetch(http.MethodGet, aiKey, f.msgUID); got.status == http.StatusOK {
		t.Fatalf("an ended AI key: %d", got.status)
	}

	// Keys that are no content connection's and act as no connection's
	// account are not the gate's to judge: an automation key and a metadata
	// connection's key still read ciphertext as they always have.
	if got := fetch(http.MethodGet, f.apiKey, f.msgUID); got.status != http.StatusOK || got.body != string(f.cipher) {
		t.Fatalf("an ordinary key: %d", got.status)
	}
	metaKey, err := f.apiKeys.IssueActingAsForDevices(ctx, f.tenant.String(), "hosted", store.ScopeRead, &owner.ID, nil, []uuid.UUID{f.device}, &in)
	if err != nil {
		t.Fatal(err)
	}
	metaPrefix, _, _ := strings.Cut(metaKey, ".")
	if _, err := store.NewMCPConnections(f.pool).Create(ctx, f.tenant, owner.ID, store.CreateMCPConnection{
		RequestID: uuid.NewString(), KeyPrefix: metaPrefix, ClientName: "Claude", RedirectHost: "claude.ai", DeviceCount: 1,
		ReaderKID: "0123456789abcdef", ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if got := fetch(http.MethodGet, metaKey, f.msgUID); got.status != http.StatusOK {
		t.Fatalf("a metadata connection's key: %d", got.status)
	}
}

// insertAttachment files a pending image message on a device.
func (f *fixture) insertAttachment(t *testing.T, tenant, device uuid.UUID) uuid.UUID {
	t.Helper()
	uid := uuid.New()
	if _, err := store.NewMessages(f.pool).Insert(context.Background(), store.InsertMessage{
		UID: uid, TenantID: tenant, DeviceID: device, WAID: "M-" + uid.String()[:8], ChatKey: "5511999999999@s.whatsapp.net",
		Kind: domain.KindMessage, Type: domain.TypeImage, Source: domain.SourceLive, TS: time.Now(),
		Media: &store.InsertMedia{
			MediaType: "image", MimeType: "image/jpeg", FileLength: int64(len(f.plain)),
			FileEncSHA256: []byte(strings.Repeat("h", 32)), URL: f.cdn.URL + "/blob", MediaKeySealed: []byte("sealed-not-real"),
		},
	}); err != nil {
		t.Fatal(err)
	}
	return uid
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
