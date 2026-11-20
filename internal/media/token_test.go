package media_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/thehappieco/kit/vectors"
	"go.mau.fi/whatsmeow"

	"whatserver2/internal/access"
	"whatserver2/internal/domain"
	"whatserver2/internal/media"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
	"whatserver2/internal/tokentest"
)

// The one 401 of media and upload, whatever refused a token.
const mediaUnauthorized = "unauthorized\n"

// gatedBlob serves its objects' first bytes at once and the rest only once
// released, so a test can change a token's access while its download is
// under way.
type gatedBlob struct {
	mu      sync.Mutex
	objects map[string][]byte
	first   int
	release chan struct{}
}

func (g *gatedBlob) Get(_ context.Context, key string) (io.ReadCloser, int64, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	b, ok := g.objects[key]
	if !ok {
		return nil, 0, errors.New("no such object")
	}
	return io.NopCloser(io.MultiReader(bytes.NewReader(b[:g.first]), &waitReader{g.release, bytes.NewReader(b[g.first:])})), int64(len(b)), nil
}

type waitReader struct {
	release chan struct{}
	r       io.Reader
}

func (w *waitReader) Read(p []byte) (int, error) {
	<-w.release
	return w.r.Read(p)
}

type tokenMedia struct {
	w        *tokentest.World
	pool     *pgxpool.Pool
	checker  *access.Checker
	blob     *gatedBlob
	handler  *media.Handler
	mux      *http.ServeMux
	uploader *hookedUploader
}

// hookedUploader is an upload that runs a hook while WhatsApp holds the
// file, before its keys come back.
type hookedUploader struct{ during func() }

func (h *hookedUploader) UploadReader(_ context.Context, plaintext io.Reader, _ io.ReadWriteSeeker, _ whatsmeow.MediaType) (whatsmeow.UploadResponse, error) {
	b, err := io.ReadAll(plaintext)
	if err != nil {
		return whatsmeow.UploadResponse{}, err
	}
	if h.during != nil {
		h.during()
	}
	return whatsmeow.UploadResponse{URL: "https://mmg.whatsapp.net/x", DirectPath: "/x", MediaKey: []byte("the media key, 32 bytes long....."),
		FileLength: uint64(len(b))}, nil
}

func newTokenMedia(t *testing.T) *tokenMedia {
	t.Helper()
	pool := pgtest.Fresh(t, migrate.Run)
	m := &tokenMedia{w: tokentest.New(t, pool, uuid.Nil), pool: pool, blob: &gatedBlob{objects: map[string][]byte{}, release: make(chan struct{})},
		mux: http.NewServeMux(), uploader: &hookedUploader{}}
	close(m.blob.release)
	users := store.NewUsers(pool)
	m.checker = &access.Checker{Keys: store.NewAPIKeys(pool), Users: users, Tokens: m.w.Tokens, Switches: store.TokenSwitches{Default: true},
		Watch: access.NewTokenWatch(), Use: &access.TokenUse{Store: m.w.Tokens}}
	gate := func(context.Context, uuid.UUID, uuid.UUID) (bool, error) {
		t.Error("the MCP gate was asked about a platform token")
		return false, nil
	}
	m.handler = &media.Handler{Keys: store.NewAPIKeys(pool), Sessions: users, Media: store.NewMedia(pool), Blob: m.blob, Gate: gate,
		Access: m.checker, Log: slog.New(slog.DiscardHandler)}
	m.mux.Handle("GET /v1/media/{uid}", m.handler)
	m.mux.Handle("HEAD /v1/media/{uid}", m.handler)
	m.mux.Handle("POST /v1/upload", &media.UploadHandler{Keys: store.NewAPIKeys(pool), Sessions: users, Devices: store.NewDevices(pool),
		Resolve:  func(context.Context, uuid.UUID, string) (media.Uploader, error) { return m.uploader, nil },
		MaxBytes: 1 << 20, TempDir: t.TempDir(), Access: m.checker, Log: slog.New(slog.DiscardHandler)})
	return m
}

// attachment stores an image on device whose ciphertext is downloaded,
// size bytes long.
func (m *tokenMedia) attachment(t *testing.T, device uuid.UUID, size int) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	uid := uuid.New()
	if _, err := store.NewMessages(m.pool).Insert(ctx, store.InsertMessage{UID: uid, TenantID: m.w.Tenant, DeviceID: device, WAID: "M-" + uid.String(),
		ChatKey: "5511999999999@s.whatsapp.net", Kind: domain.KindMessage, Type: domain.TypeImage, Source: domain.SourceLive, TS: time.Now(),
		Media: &store.InsertMedia{MediaType: "image", MimeType: "image/jpeg", FileLength: int64(size), MediaKeySealed: []byte("sealed")}}); err != nil {
		t.Fatal(err)
	}
	key := "media/" + uid.String()
	m.blob.mu.Lock()
	m.blob.objects[key] = bytes.Repeat([]byte{0xab}, size)
	m.blob.mu.Unlock()
	if err := store.NewMedia(m.pool).MarkDone(ctx, m.w.Tenant, uid, key, int64(size)); err != nil {
		t.Fatal(err)
	}
	return uid
}

func (m *tokenMedia) do(t *testing.T, method, path string, body io.Reader, auth ...string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, body)
	if len(auth) > 0 {
		req.Header["Authorization"] = auth
	}
	rec := httptest.NewRecorder()
	m.mux.ServeHTTP(rec, req)
	if rec.Code == http.StatusUnauthorized && rec.Header().Get("WWW-Authenticate") != `Bearer realm="whatserver2"` {
		t.Fatalf("%s %s: a 401 without its challenge", method, path)
	}
	return rec.Code, rec.Body.String()
}

// TestTokenMediaGivesOneAnswer: a token fetches an attachment of a number
// it reads, with Bearer in any case and never through MCP's gate; a number
// it cannot read, an attachment that does not exist and the attachments
// switch off each get the one 404; HEAD answers the same; only refusals on
// a number of its workspace are counted.
func TestTokenMediaGivesOneAnswer(t *testing.T) {
	m := newTokenMedia(t)
	w := m.w
	readable, refused := w.Number("Vendas"), w.Number("Suporte")
	tok := w.Token(tokentest.Read(readable), tokentest.Send(refused))
	mine, theirs := m.attachment(t, readable, 1000), m.attachment(t, refused, 1000)
	for _, scheme := range []string{"Bearer", "bearer", "BEARER"} {
		if code, body := m.do(t, http.MethodGet, "/v1/media/"+mine.String(), nil, scheme+" "+tok.Text); code != http.StatusOK || len(body) != 1000 {
			t.Fatalf("%s: %d %d bytes", scheme, code, len(body))
		}
	}
	if code, body := m.do(t, http.MethodHead, "/v1/media/"+mine.String(), nil, "Bearer "+tok.Text); code != http.StatusOK || body != "" {
		t.Fatalf("HEAD: %d %q", code, body)
	}
	_, missing := m.do(t, http.MethodGet, "/v1/media/"+uuid.NewString(), nil, "Bearer "+tok.Text)
	for name, uid := range map[string]uuid.UUID{"refused": theirs} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			code, body := m.do(t, method, "/v1/media/"+uid.String(), nil, "Bearer "+tok.Text)
			if code != http.StatusNotFound || (method == http.MethodGet && body != missing) {
				t.Fatalf("%s %s: %d %q, want %q", name, method, code, body, missing)
			}
		}
	}
	yes, no := true, false
	w.Switches(&yes, &no)
	if code, body := m.do(t, http.MethodGet, "/v1/media/"+mine.String(), nil, "Bearer "+tok.Text); code != http.StatusNotFound || body != missing {
		t.Fatalf("attachments off: %d %q", code, body)
	}
	w.Switches(nil, nil)
	if err := m.checker.Use.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := w.Refusals(tok)
	if len(got) != 2 || got[refused.String()+"/read=no_permission"] != 2 || got[readable.String()+"/read=switch_off"] != 1 {
		t.Fatalf("the refusals: %v", got)
	}
}

// TestATokensDownloadEndsShortOnceItsAccessEnds (the plan's 4.6): a
// download of a token that loses its access mid-body ends short of its
// Content-Length, by the next second's check, or at once on the token's
// NOTIFY; a download that keeps its access completes.
func TestATokensDownloadEndsShortOnceItsAccessEnds(t *testing.T) {
	m := newTokenMedia(t)
	w := m.w
	device := w.Number("Vendas")
	srv := httptest.NewServer(m.mux)
	defer srv.Close()
	const size = 3 << 20
	get := func(t *testing.T, tok *tokentest.Token, uid uuid.UUID, during func()) (int, error) {
		t.Helper()
		m.blob.release = make(chan struct{})
		m.blob.first = 512 << 10
		release := m.blob.release
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/v1/media/"+uid.String(), nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+tok.Text)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		if res.StatusCode != http.StatusOK || res.ContentLength != size {
			t.Fatalf("the download: %d %d", res.StatusCode, res.ContentLength)
		}
		head := make([]byte, 256<<10)
		if _, err := io.ReadFull(res.Body, head); err != nil {
			t.Fatalf("the first chunk: %v", err)
		}
		during()
		close(release)
		rest, err := io.ReadAll(res.Body)
		return len(head) + len(rest), err
	}
	cases := []struct {
		name   string
		narrow func(tok *tokentest.Token)
	}{
		{"attachments off", func(*tokentest.Token) {
			no := false
			w.Switches(nil, &no)
		}},
		{"a revocation", func(tok *tokentest.Token) { w.Revoke(tok) }},
		{"a rotation", func(*tokentest.Token) { w.Rotate(device, 2) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w.Switches(nil, nil)
			tok := w.Token(tokentest.Read(device))
			uid := m.attachment(t, device, size)
			start := time.Now()
			n, err := get(t, tok, uid, func() {
				c.narrow(tok)
				time.Sleep(1500 * time.Millisecond) // the monitor's next check
			})
			if err == nil || n >= size {
				t.Fatalf("the body came whole: %d bytes, %v", n, err)
			}
			if elapsed := time.Since(start); elapsed > 5*time.Second {
				t.Fatalf("the cut took %s", elapsed)
			}
		})
	}
	t.Run("at once on the NOTIFY", func(t *testing.T) {
		w.Switches(nil, nil)
		tok := w.Token(tokentest.Read(device))
		uid := m.attachment(t, device, size)
		n, err := get(t, tok, uid, func() {
			w.Revoke(tok)
			m.checker.Watch.Notify(tok.ID.String())
			time.Sleep(200 * time.Millisecond) // well under the second's tick
		})
		if err == nil || n >= size {
			t.Fatalf("the body came whole: %d bytes, %v", n, err)
		}
	})
	t.Run("a download that keeps its access", func(t *testing.T) {
		tok := w.Token(tokentest.Read(device))
		uid := m.attachment(t, device, size)
		n, err := get(t, tok, uid, func() { time.Sleep(1200 * time.Millisecond) })
		if err != nil || n != size {
			t.Fatalf("a whole download: %d %v", n, err)
		}
	})
}

// TestATokensDownloadEndsWhenItsCheckCannotRun (the plan's 4.6): a check
// that cannot answer within its second, its pool at its limit or its
// database stalled, is a failed one. A token revoked while its download's
// checks wait for a connection never gets the whole body.
func TestATokensDownloadEndsWhenItsCheckCannotRun(t *testing.T) {
	m := newTokenMedia(t)
	w := m.w
	cut := make(chan struct{})
	var once sync.Once
	media.SetStreamHook(m.handler, func(stage string) {
		if stage == "cut" {
			once.Do(func() { close(cut) })
		}
	})
	// The checker's own pool, of two connections, which the test takes
	// once the download is under way.
	cfg := m.pool.Config().Copy()
	cfg.MaxConns = 2
	busy, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(busy.Close)
	m.checker.Tokens = store.NewTokens(busy)
	device := w.Number("Vendas")
	srv := httptest.NewServer(m.mux)
	defer srv.Close()
	const size = 3 << 20
	tok := w.Token(tokentest.Read(device))
	uid := m.attachment(t, device, size)
	m.blob.release = make(chan struct{})
	m.blob.first = 512 << 10
	var held []*pgxpool.Conn
	// Whatever happens, the body and the pool go on before the server
	// closes, which waits for the handler.
	var unblock sync.Once
	release := func() {
		unblock.Do(func() {
			close(m.blob.release)
			for _, c := range held {
				c.Release()
			}
		})
	}
	defer release()
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/v1/media/"+uid.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tok.Text)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK || res.ContentLength != size {
		t.Fatalf("the download: %d %d", res.StatusCode, res.ContentLength)
	}
	head := make([]byte, 256<<10)
	if _, err := io.ReadFull(res.Body, head); err != nil {
		t.Fatalf("the first chunk: %v", err)
	}
	for range 2 {
		c, err := busy.Acquire(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
	}
	w.Revoke(tok)
	select {
	case <-cut:
	case <-time.After(10 * time.Second):
		t.Fatal("the download was not cut while its check could not run")
	}
	release()
	rest, err := io.ReadAll(res.Body)
	if n := len(head) + len(rest); err == nil || n >= size {
		t.Fatalf("the body came whole: %d bytes, %v", n, err)
	}
}

// TestATokensUploadIsCheckedAgainBeforeItsKeys (F11, the plan's 6.3): a
// token uploads only on a number it sends on, named by its full id; a
// number it cannot send on, a missing one and another workspace's get one
// 403; a token stopped while WhatsApp holds the file gets the 403 and no
// keys; the attachments switch never refuses an upload.
func TestATokensUploadIsCheckedAgainBeforeItsKeys(t *testing.T) {
	m := newTokenMedia(t)
	w := m.w
	device, refused := w.Number("Vendas"), w.Number("Suporte")
	tok := w.Token(tokentest.Send(device), tokentest.Read(refused))
	upload := func(dev string) (int, string) {
		t.Helper()
		return m.do(t, http.MethodPost, "/v1/upload?type=image&device="+dev, strings.NewReader("a photo"), "Bearer "+tok.Text)
	}
	no := false
	w.Switches(nil, &no)
	if code, body := upload(device.String()); code != http.StatusOK || !strings.Contains(body, `"media_key"`) {
		t.Fatalf("an upload: %d %s", code, body)
	}
	_, refusal := upload(refused.String())
	for name, dev := range map[string]string{"missing": uuid.NewString(), "refused": refused.String()} {
		if code, body := upload(dev); code != http.StatusForbidden || body != refusal || strings.Contains(body, dev) {
			t.Fatalf("%s: %d %q", name, code, body)
		}
	}
	for name, dev := range map[string]string{"a prefix": device.String()[:8], "upper case": strings.ToUpper(device.String())} {
		if code, body := upload(dev); code != http.StatusBadRequest || strings.Contains(body, device.String()) {
			t.Fatalf("%s: %d %q", name, code, body)
		}
	}
	m.uploader.during = func() {
		m.uploader.during = nil
		w.ExecIn(`INSERT INTO contract_workspaces (workspace_id, kind, status) VALUES ($1, 'team', 'closed')`, w.Tenant)
	}
	code, body := upload(device.String())
	if code != http.StatusForbidden || strings.Contains(body, "media_key") || strings.Contains(body, "mmg.whatsapp.net") {
		t.Fatalf("a token closed out mid-upload: %d %s", code, body)
	}
}

// TestEveryAuthorizationVectorGetsItsPinnedBodyOnMedia: as on REST, for
// GET and HEAD /v1/media and POST /v1/upload.
func TestEveryAuthorizationVectorGetsItsPinnedBodyOnMedia(t *testing.T) {
	m := newTokenMedia(t)
	w := m.w
	raw, err := fs.ReadFile(vectors.FS, "platform/contract-v1/tokens.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Tokens []struct {
			Name, Token, Selector, Hash string
		} `json:"tokens"`
		Refused []struct {
			Name, Token string
		} `json:"refused"`
		Authorization []struct {
			Name   string
			Values []string
			Valid  bool
		} `json:"authorization"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	device := w.Number("Vendas")
	for _, k := range v.Tokens {
		w.TokenWith(k.Token, k.Selector, k.Hash, tokentest.Read(device), tokentest.Send(device))
	}
	uid := m.attachment(t, device, 100)
	type route struct{ method, path, ok string }
	routes := []route{
		{http.MethodGet, "/v1/media/" + uid.String(), strings.Repeat("\xab", 100)},
		{http.MethodHead, "/v1/media/" + uid.String(), ""},
		{http.MethodPost, "/v1/upload?type=image&device=" + device.String(), ""},
	}
	body := func(r route) io.Reader {
		if r.method == http.MethodPost {
			return strings.NewReader("a photo")
		}
		return nil
	}
	for _, r := range routes {
		for _, c := range v.Authorization {
			code, got := m.do(t, r.method, r.path, body(r), c.Values...)
			switch {
			case c.Valid:
				if code != http.StatusOK || (r.method == http.MethodGet && got != r.ok) {
					t.Errorf("%s %s: %d", r.method, c.Name, code)
				}
			case r.method == http.MethodHead:
				if code != http.StatusUnauthorized {
					t.Errorf("%s %s: %d", r.method, c.Name, code)
				}
			default:
				if code != http.StatusUnauthorized || got != mediaUnauthorized {
					t.Errorf("%s %s: %d %q", r.method, c.Name, code, got)
				}
			}
		}
		for _, c := range v.Refused {
			code, got := m.do(t, r.method, r.path, body(r), "Bearer "+c.Token)
			if code != http.StatusUnauthorized || (r.method != http.MethodHead && got != mediaUnauthorized) {
				t.Errorf("%s refused %q: %d %q", r.method, c.Name, code, got)
			}
		}
	}
}
