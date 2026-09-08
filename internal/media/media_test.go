package media_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/crypto/wamedia"
	"whatserver2/internal/domain"
	"whatserver2/internal/media"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// memStore is object storage in a map. Enough to prove what the worker does
// with a claim; minio-go signing a request is minio-go's problem.
type memStore struct {
	mu      sync.Mutex
	objects map[string][]byte
	failPut error
}

func newMemStore() *memStore { return &memStore{objects: map[string][]byte{}} }

func (m *memStore) Configured() bool { return true }

func (m *memStore) Put(_ context.Context, key string, r io.Reader, _ int64) error {
	if m.failPut != nil {
		return m.failPut
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objects[key] = b
	return nil
}

func (m *memStore) Get(_ context.Context, key string) (io.ReadCloser, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.objects[key]
	if !ok {
		return nil, 0, fmt.Errorf("no such object %s", key)
	}
	return io.NopCloser(bytes.NewReader(b)), int64(len(b)), nil
}

func (m *memStore) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.objects)
}

// fixture is a tenant, a device, a message with an attachment, and a fake CDN
// serving real WhatsApp-format ciphertext for it.
type fixture struct {
	pool     *pgxpool.Pool
	tenant   uuid.UUID
	device   uuid.UUID
	msgUID   uuid.UUID
	media    *store.Media
	blob     *memStore
	cdn      *httptest.Server
	hits     *int32
	mediaKey []byte
	plain    []byte
	cipher   []byte
	apiKeys  *store.APIKeys
	apiKey   string
}

func newFixture(t *testing.T, plaintext []byte) *fixture {
	t.Helper()
	ctx := context.Background()
	pool := pgtest.Fresh(t, migrate.Run)

	var tenantID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO tenants (name) VALUES ('acme') RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	tenant := uuid.MustParse(tenantID)

	dev, err := store.NewDevices(pool).Create(ctx, tenantID, "test", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	device := uuid.MustParse(dev.ID)

	// Real WhatsApp media crypto, so the ciphertext the fake CDN serves is the
	// shape the fetcher will meet in production.
	mediaKey := wamedia.NewKey()
	cipher, err := wamedia.Encrypt(plaintext, mediaKey, wamedia.Image)
	if err != nil {
		t.Fatal(err)
	}
	encSHA := sha256.Sum256(cipher)

	var hits int32
	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Query().Get("broken") == "1" {
			// Truncated: the transport failure the hash check exists to catch.
			_, _ = w.Write(cipher[:len(cipher)/2])
			return
		}
		if r.URL.Query().Get("gone") == "1" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(cipher)
	}))
	t.Cleanup(cdn.Close)

	msgUID := uuid.New()
	messages := store.NewMessages(pool)
	if _, err := messages.Insert(ctx, store.InsertMessage{
		UID: msgUID, TenantID: tenant, DeviceID: device,
		WAID: "M1", ChatKey: "5511999999999@s.whatsapp.net",
		Kind: domain.KindMessage, Type: domain.TypeImage,
		Source: domain.SourceLive, TS: time.Now(),
		Media: &store.InsertMedia{
			MediaType: "image", MimeType: "image/jpeg",
			FileLength:    int64(len(plaintext)),
			FileEncSHA256: encSHA[:],
			URL:           cdn.URL + "/blob",
			// A sealed key that nothing in this package will ever open.
			MediaKeySealed: []byte("sealed-not-real"),
		},
	}); err != nil {
		t.Fatal(err)
	}

	apiKeys := store.NewAPIKeys(pool)
	key, err := apiKeys.Issue(ctx, tenantID, "test")
	if err != nil {
		t.Fatal(err)
	}

	return &fixture{
		pool: pool, tenant: tenant, device: device, msgUID: msgUID,
		media: store.NewMedia(pool), blob: newMemStore(), cdn: cdn, hits: &hits,
		mediaKey: mediaKey, plain: plaintext, cipher: cipher,
		apiKeys: apiKeys, apiKey: key,
	}
}

func (f *fixture) worker(t *testing.T) *media.Worker {
	t.Helper()
	w, err := media.New(media.Config{
		Media:   f.media,
		Blob:    f.blob,
		Fetcher: media.NewFetcherFrom(media.AnyOrigin(), 10<<20, t.TempDir()),
		Tenants: func(context.Context) ([]uuid.UUID, error) {
			return []uuid.UUID{f.tenant}, nil
		},
		Log: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// exec runs one statement inside the tenant's scope, for the tests that need to
// bend a row before the worker sees it.
func (f *fixture) exec(t *testing.T, sql string) {
	t.Helper()
	err := pg.InTenantTx(context.Background(), f.pool, f.tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), sql)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// run starts the worker and stops it once the attachment has settled.
func (f *fixture) run(t *testing.T, w *media.Worker) store.ObjectRef {
	t.Helper()
	ctx, stop := context.WithTimeout(context.Background(), 30*time.Second)
	defer stop()
	go w.Run(ctx)
	return f.waitFor(t, func(ref store.ObjectRef) bool {
		return ref.Status == "done" || ref.Status == "failed" || ref.Status == "gone"
	})
}

func (f *fixture) waitFor(t *testing.T, ok func(store.ObjectRef) bool) store.ObjectRef {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		ref, err := f.media.Object(context.Background(), f.tenant, f.msgUID)
		if err != nil {
			t.Fatal(err)
		}
		if ok(ref) {
			return ref
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("the attachment never reached a settled state")
	return store.ObjectRef{}
}

// TestTheServerStoresCiphertextItCannotRead is the central claim of the media
// design, stated as a test.
//
// What lands in object storage is byte-for-byte what the CDN served: WhatsApp's
// own AES-256-CBC ciphertext with its trailing MAC. The plaintext never exists
// in this process — not in memory, not in a temp file — and the bytes only
// become a picture after a key the server has never held is applied.
func TestTheServerStoresCiphertextItCannotRead(t *testing.T) {
	plaintext := []byte(strings.Repeat("uma foto que ninguem deveria ler. ", 400))
	f := newFixture(t, plaintext)

	ref := f.run(t, f.worker(t))
	if ref.Status != "done" {
		t.Fatalf("status = %q, want done", ref.Status)
	}
	if ref.ObjectKey == "" {
		t.Fatal("stored, but with no object key")
	}

	body, size, err := f.blob.Get(context.Background(), ref.ObjectKey)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := io.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, f.cipher) {
		t.Fatal("what was stored is not what the CDN served")
	}
	if bytes.Contains(stored, []byte("ninguem deveria ler")) {
		t.Fatal("the plaintext is in the object store")
	}
	if size != int64(len(f.cipher)) {
		t.Fatalf("size = %d, want %d", size, len(f.cipher))
	}

	// And a holder of the key gets the picture back, byte for byte.
	opened, err := wamedia.Decrypt(stored, f.mediaKey, wamedia.Image)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatal("the round trip did not reproduce the original")
	}
}

// TestTruncatedBytesAreRefused. The published hash is of the ciphertext, which
// is what lets a download be verified without a key — and this is the failure
// it exists to catch.
func TestTruncatedBytesAreRefused(t *testing.T) {
	f := newFixture(t, []byte(strings.Repeat("x", 5000)))

	// Point the row at the CDN's truncating endpoint, and remove the direct
	// path so there is no second candidate that would succeed.
	f.exec(t, `UPDATE media SET url = url || '?broken=1', direct_path = NULL`)

	ref := f.run(t, f.worker(t))
	if ref.Status == "done" {
		t.Fatal("truncated bytes were accepted")
	}
	if f.blob.count() != 0 {
		t.Fatal("unverified bytes reached the object store")
	}
}

// TestAGoneAttachmentIsNotRetriedForever. A 404 does not become a 200 by
// waiting, and a row that retries forever crowds out the ones that would work.
func TestAGoneAttachmentIsNotRetriedForever(t *testing.T) {
	f := newFixture(t, []byte("small"))
	f.exec(t, `UPDATE media SET url = url || '?gone=1', direct_path = NULL`)

	ref := f.run(t, f.worker(t))
	if ref.Status != "gone" {
		t.Fatalf("status = %q, want gone: a 404 is final", ref.Status)
	}
}

// TestTheMediaEndpointServesCiphertextAndNothingElse.
//
// It must not label the bytes, must not let a browser sniff them into being
// media, and must refuse a caller with no key.
func TestTheMediaEndpointServesCiphertextAndNothingElse(t *testing.T) {
	f := newFixture(t, []byte(strings.Repeat("y", 3000)))
	if ref := f.run(t, f.worker(t)); ref.Status != "done" {
		t.Fatalf("status = %q, want done", ref.Status)
	}

	h := &media.Handler{Keys: f.apiKeys, Media: f.media, Blob: f.blob,
		Log: slog.New(slog.DiscardHandler)}
	mux := http.NewServeMux()
	mux.Handle("GET /v1/media/{uid}", h)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// No credentials.
	resp, err := http.Get(srv.URL + "/v1/media/" + f.msgUID.String()) //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated request got %d, want 401", resp.StatusCode)
	}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
		srv.URL+"/v1/media/"+f.msgUID.String(), nil)
	req.Header.Set("Authorization", "Bearer "+f.apiKey)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("content type = %q; ciphertext must not be labelled as media", ct)
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("a browser is allowed to sniff these bytes into being media")
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, f.cipher) {
		t.Fatal("the endpoint did not serve the stored ciphertext")
	}
}

// TestTheEndpointReportsTheLengthTheDecryptorNeeds.
//
// A regression. The streaming decryptor is told how many bytes to read before
// the trailing MAC begins, and that number is the *ciphertext* length — the
// plaintext padded to a block boundary plus ten. The first client written
// against this endpoint passed file_length, the plaintext size the sender
// declared, and every download failed the block-size check on bytes that were
// perfectly good.
//
// So the contract is pinned here rather than in a comment: whatever
// Content-Length says is what DecryptTo must be given.
func TestTheEndpointReportsTheLengthTheDecryptorNeeds(t *testing.T) {
	plaintext := []byte(strings.Repeat("uma foto de verdade. ", 137)) // not block-aligned
	f := newFixture(t, plaintext)
	if ref := f.run(t, f.worker(t)); ref.Status != "done" {
		t.Fatalf("status = %q, want done", ref.Status)
	}

	mux := http.NewServeMux()
	mux.Handle("GET /v1/media/{uid}", &media.Handler{Keys: f.apiKeys, Media: f.media,
		Blob: f.blob, Log: slog.New(slog.DiscardHandler)})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
		srv.URL+"/v1/media/"+f.msgUID.String(), nil)
	req.Header.Set("Authorization", "Bearer "+f.apiKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.ContentLength <= 0 {
		t.Fatal("no Content-Length, so a streaming client cannot find the MAC")
	}
	if resp.ContentLength == int64(len(plaintext)) {
		t.Fatal("Content-Length equals the plaintext size; the two must differ, " +
			"or this test proves nothing about which one to use")
	}

	var out bytes.Buffer
	n, err := wamedia.DecryptTo(&out, resp.Body, resp.ContentLength,
		f.mediaKey, wamedia.Image)
	if err != nil {
		t.Fatalf("decrypting with Content-Length failed: %v", err)
	}
	if n != int64(len(plaintext)) || !bytes.Equal(out.Bytes(), plaintext) {
		t.Fatalf("got %d bytes back, want %d", n, len(plaintext))
	}

	// And the number that used to be passed instead is genuinely wrong, so a
	// future refactor cannot quietly reintroduce it.
	if _, err := wamedia.DecryptTo(io.Discard, bytes.NewReader(f.cipher),
		int64(len(plaintext)), f.mediaKey, wamedia.Image); err == nil {
		t.Fatal("the plaintext length was accepted as a ciphertext length")
	}
}

// TestAnUnknownAttachmentIsNotFound, and a tenant cannot reach another's.
func TestAnUnknownAttachmentIsNotFound(t *testing.T) {
	f := newFixture(t, []byte("z"))
	h := &media.Handler{Keys: f.apiKeys, Media: f.media, Blob: f.blob,
		Log: slog.New(slog.DiscardHandler)}
	mux := http.NewServeMux()
	mux.Handle("GET /v1/media/{uid}", h)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
		srv.URL+"/v1/media/"+uuid.New().String(), nil)
	req.Header.Set("Authorization", "Bearer "+f.apiKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

// fakeUploader stands in for a paired device. What matters about the upload
// endpoint is what it does before and after handing bytes over, not that
// whatsmeow can talk to WhatsApp.
type fakeUploader struct {
	got     []byte
	appInfo whatsmeow.MediaType
	err     error
}

func (f *fakeUploader) UploadReader(_ context.Context, plaintext io.Reader,
	_ io.ReadWriteSeeker, appInfo whatsmeow.MediaType) (whatsmeow.UploadResponse, error) {
	b, err := io.ReadAll(plaintext)
	if err != nil {
		return whatsmeow.UploadResponse{}, err
	}
	f.got, f.appInfo = b, appInfo
	if f.err != nil {
		return whatsmeow.UploadResponse{}, f.err
	}
	return whatsmeow.UploadResponse{
		URL: "https://mmg.whatsapp.net/x", DirectPath: "/x",
		MediaKey: make([]byte, 32), FileLength: uint64(len(b)),
	}, nil
}

func (f *fixture) uploadServer(t *testing.T, up *fakeUploader, maxBytes int64) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle("POST /v1/upload", &media.UploadHandler{
		Keys:    f.apiKeys,
		Devices: store.NewDevices(f.pool),
		Resolve: func(context.Context, uuid.UUID, string) (media.Uploader, error) {
			return up, nil
		},
		MaxBytes: maxBytes,
		TempDir:  t.TempDir(),
		Log:      slog.New(slog.DiscardHandler),
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func (f *fixture) postUpload(t *testing.T, srv *httptest.Server, query string,
	body []byte, auth bool) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		srv.URL+"/v1/upload?"+query, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if auth {
		req.Header.Set("Authorization", "Bearer "+f.apiKey)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// TestUploadPicksTheRightKeyDerivation.
//
// The media category chooses the HKDF label the keys come from, so it is not
// cosmetic: a voice note uploaded as an image produces a file the recipient's
// client cannot open, and nothing anywhere says why.
func TestUploadPicksTheRightKeyDerivation(t *testing.T) {
	f := newFixture(t, []byte("x"))
	up := &fakeUploader{}
	srv := f.uploadServer(t, up, 1<<20)

	for _, c := range []struct {
		kind string
		want whatsmeow.MediaType
	}{
		{"image", whatsmeow.MediaImage},
		{"sticker", whatsmeow.MediaImage},
		{"video", whatsmeow.MediaVideo},
		{"ptv", whatsmeow.MediaVideo},
		{"audio", whatsmeow.MediaAudio},
		{"ptt", whatsmeow.MediaAudio},
		{"document", whatsmeow.MediaDocument},
	} {
		resp := f.postUpload(t, srv, "device="+f.device.String()+"&type="+c.kind,
			[]byte("conteudo"), true)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status %d", c.kind, resp.StatusCode)
		}
		if up.appInfo != c.want {
			t.Errorf("%s uploaded as %q, want %q", c.kind, up.appInfo, c.want)
		}
	}

	resp := f.postUpload(t, srv, "device="+f.device.String()+"&type=carrier-pigeon",
		[]byte("x"), true)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("an unknown type got %d, want 400", resp.StatusCode)
	}
}

// TestUploadRefusesWhatItShould: no credentials, nothing to send, too much to
// send.
func TestUploadRefusesWhatItShould(t *testing.T) {
	f := newFixture(t, []byte("x"))
	up := &fakeUploader{}
	srv := f.uploadServer(t, up, 100)
	query := "device=" + f.device.String() + "&type=image"

	resp := f.postUpload(t, srv, query, []byte("conteudo"), false)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated upload got %d, want 401", resp.StatusCode)
	}

	resp = f.postUpload(t, srv, query, []byte{}, true)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("an empty upload got %d, want 400", resp.StatusCode)
	}

	// One byte over the limit. Truncating to the ceiling instead would send a
	// corrupt attachment that nobody could open and nothing would explain.
	resp = f.postUpload(t, srv, query, bytes.Repeat([]byte("a"), 101), true)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("an oversized upload got %d, want 413", resp.StatusCode)
	}

	// And exactly at the limit is allowed.
	resp = f.postUpload(t, srv, query, bytes.Repeat([]byte("a"), 100), true)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("an upload exactly at the limit got %d, want 200", resp.StatusCode)
	}
}

// fakeRetryClient records the retry receipts that were sent.
type fakeRetryClient struct {
	mu   sync.Mutex
	sent []types.MessageID
	err  error
}

func (f *fakeRetryClient) SendMediaRetryReceipt(_ context.Context,
	info *types.MessageInfo, key []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	if len(key) != 32 {
		return fmt.Errorf("media key was %d bytes", len(key))
	}
	f.sent = append(f.sent, info.ID)
	return nil
}

func (f *fakeRetryClient) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sent)
}

func (f *fixture) retrier(t *testing.T, client media.RetryClient) *media.Retrier {
	t.Helper()
	return &media.Retrier{
		Messages: store.NewMessages(f.pool),
		Media:    f.media,
		Devices: func(context.Context, uuid.UUID, string) (media.RetryClient, error) {
			return client, nil
		},
		Log: slog.New(slog.DiscardHandler),
	}
}

// TestARetryNeedsTheKeyFromTheClient.
//
// The request is authenticated with the media key and the answer is encrypted
// under it, and this server cannot open the sealed copy it holds. So the key
// arrives from the client — refused if it is not the right shape, because
// sending a malformed one produces a silent nothing rather than an error.
func TestARetryNeedsTheKeyFromTheClient(t *testing.T) {
	f := newFixture(t, []byte("x"))
	client := &fakeRetryClient{}
	r := f.retrier(t, client)
	ctx := context.Background()

	if err := r.Request(ctx, f.tenant, f.device, f.msgUID, []byte("short")); err == nil {
		t.Fatal("a key that is not 32 bytes was accepted")
	}
	if client.count() != 0 {
		t.Fatal("a receipt was sent with a malformed key")
	}

	if err := r.Request(ctx, f.tenant, f.device, f.msgUID, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if client.count() != 1 {
		t.Fatalf("sent %d receipts, want 1", client.count())
	}
	if r.Pending() != 1 {
		t.Fatalf("pending = %d, want 1", r.Pending())
	}
}

// TestAFailedSendDoesNotLeaveKeyMaterialBehind. The map exists to hold a key
// for an exchange; an exchange that never started must not leave one there.
func TestAFailedSendDoesNotLeaveKeyMaterialBehind(t *testing.T) {
	f := newFixture(t, []byte("x"))
	client := &fakeRetryClient{err: errors.New("not connected")}
	r := f.retrier(t, client)

	if err := r.Request(context.Background(), f.tenant, f.device, f.msgUID,
		make([]byte, 32)); err == nil {
		t.Fatal("a failed send was reported as success")
	}
	if r.Pending() != 0 {
		t.Fatalf("pending = %d after a failed send, want 0", r.Pending())
	}
}

// TestAnAnswerNobodyAskedForIsIgnored. A retry answered after the key was
// swept, or asked for by another process, must not crash or act on a key it
// does not have.
func TestAnAnswerNobodyAskedForIsIgnored(t *testing.T) {
	f := newFixture(t, []byte("x"))
	r := f.retrier(t, &fakeRetryClient{})

	r.Handle(context.Background(), &events.MediaRetry{
		MessageID: "never-asked-for",
		Timestamp: time.Now(),
	})
	if r.Pending() != 0 {
		t.Fatal("an unsolicited answer left something behind")
	}
}

// TestARefreshedPathGoesBackInTheQueue. The recovery is only worth anything if
// the attachment is then actually fetched.
func TestARefreshedPathGoesBackInTheQueue(t *testing.T) {
	f := newFixture(t, []byte("x"))
	ctx := context.Background()

	f.exec(t, `UPDATE media SET download_status = 'gone',
	                            download_error = 'http 403', url = NULL`)
	if err := f.media.Refresh(ctx, f.tenant, f.msgUID, "/v/new-path?oe=ffffffff"); err != nil {
		t.Fatal(err)
	}

	ref, err := f.media.Object(ctx, f.tenant, f.msgUID)
	if err != nil {
		t.Fatal(err)
	}
	if ref.Status != "pending" {
		t.Fatalf("status = %q after a refresh, want pending", ref.Status)
	}
	claimed, err := f.media.Claim(ctx, f.tenant, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(claimed) != 1 || claimed[0].DirectPath != "/v/new-path?oe=ffffffff" {
		t.Fatalf("claimed %+v, want the refreshed path", claimed)
	}
	if claimed[0].URL != "" {
		t.Fatal("the dead url survived the refresh; the fetcher would spend its " +
			"first attempt on an address that cannot work")
	}
}

// TestExpiredAttachmentsAreListedSeparately. They are not retryable by
// downloading, so they must not sit in the same queue as things that are.
func TestExpiredAttachmentsAreListedSeparately(t *testing.T) {
	f := newFixture(t, []byte("x"))
	ctx := context.Background()

	if ids, err := f.media.Expired(ctx, f.tenant, f.device, 10); err != nil || len(ids) != 0 {
		t.Fatalf("got %v (err %v), want none before anything failed", ids, err)
	}

	f.exec(t, `UPDATE media SET download_status = 'gone',
	           download_error = 'media: the CDN will not serve this attachment: http 403'`)
	ids, err := f.media.Expired(ctx, f.tenant, f.device, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != f.msgUID {
		t.Fatalf("got %v, want the expired attachment", ids)
	}

	// A 404 is a deletion, not an expiry, and no re-upload recovers it.
	f.exec(t, `UPDATE media SET download_error = 'media: ... http 404'`)
	if ids, err = f.media.Expired(ctx, f.tenant, f.device, 10); err != nil || len(ids) != 0 {
		t.Fatalf("got %v (err %v), want none: a 404 is not an expiry", ids, err)
	}
}

func TestMediaDownloadRequiresDeviceReadPermission(t *testing.T) {
	f := newFixture(t, []byte("permission boundary"))
	f.run(t, f.worker(t))
	ctx := context.Background()
	users := store.NewUsers(f.pool)
	create := func(email, role string) store.User {
		t.Helper()
		u, err := users.Create(ctx, store.NewUser{TenantID: f.tenant, Email: email, Role: role, AuthKey: "proof", KDFSalt: make([]byte, 16), KDFParams: store.DefaultKDFParams(), PublicKey: make([]byte, 32), WrappedUSK: []byte("wrapped")})
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	owner := create("owner@media.test", "owner")
	member := create("member@media.test", "member")
	token, _, err := users.StartSession(ctx, member, "test")
	if err != nil {
		t.Fatal(err)
	}
	handler := &media.Handler{Keys: f.apiKeys, Sessions: users, Media: f.media, Blob: f.blob, Log: slog.New(slog.DiscardHandler)}
	mux := http.NewServeMux()
	mux.Handle("GET /v1/media/{uid}", handler)
	check := func(want int) {
		t.Helper()
		req := httptest.NewRequest("GET", "/v1/media/"+f.msgUID.String(), nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != want {
			t.Fatalf("download=%d want=%d", w.Code, want)
		}
	}
	check(404)
	p := store.DevicePermission{DeviceID: f.device, UserID: member.ID, Send: true}
	if err = users.SetDevicePermission(ctx, f.tenant, owner.ID, p); err != nil {
		t.Fatal(err)
	}
	check(404)
	p.Read = true
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err = store.NewKeys(f.pool).CreateArchiveKey(ctx, f.tenant, f.device, 1, pub); err != nil {
		t.Fatal(err)
	}
	if err = users.SetDevicePermission(ctx, f.tenant, owner.ID, p); err != nil {
		t.Fatal(err)
	}
	if err = store.NewKeys(f.pool).PutGrant(ctx, store.Grant{TenantID: f.tenant, DeviceID: f.device, UserID: member.ID, Epoch: 1, SealedDSK: []byte("sealed")}, &owner.ID); err != nil {
		t.Fatal(err)
	}
	check(200)
	p.Read = false
	if err = users.SetDevicePermission(ctx, f.tenant, owner.ID, p); err != nil {
		t.Fatal(err)
	}
	check(404)
}
