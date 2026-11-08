package wsapi_test

import (
	"bytes"
	"context"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	kc "github.com/thehappieco/kit/contract"
	"go.mau.fi/whatsmeow"

	"whatserver2/internal/access"
	"whatserver2/internal/media"
	"whatserver2/internal/restapi"
	"whatserver2/internal/store"
	"whatserver2/internal/tokentest"
	"whatserver2/internal/wsapi"
)

// syncBuffer is a buffer several goroutines write.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type noUpload struct{}

func (noUpload) UploadReader(context.Context, io.Reader, io.ReadWriteSeeker, whatsmeow.MediaType) (whatsmeow.UploadResponse, error) {
	return whatsmeow.UploadResponse{}, io.ErrUnexpectedEOF
}

// TestNoLogHoldsAToken (the plan's 9.3): every way a token is refused, on
// REST, media, upload and the hello, a revoked one, a wrong secret, a
// garbled text and one with a space around it, leaves no secret in any log
// (each handler's, slog's default, the log package's and the HTTP server's
// ErrorLog) nor in any answer; the selector alone may appear. Another
// app's record logs its id, selector and version, never its hash or name.
func TestNoLogHoldsAToken(t *testing.T) {
	var logs syncBuffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	previous := slog.Default()
	slog.SetDefault(logger)
	defer slog.SetDefault(previous)
	log.SetOutput(&logs)
	defer log.SetOutput(io.Discard)

	ts := newTokenSocket(t, func(cfg *wsapi.Config) { cfg.Log = logger })
	w := ts.w
	ts.checker.Log = logger
	ts.checker.Limits = access.NewTokenLimits(nil, logger)
	device := w.Number("Vendas")
	tok := w.Token(tokentest.Read(device), tokentest.Send(device))
	revoked := w.Token(tokentest.Read(device))
	w.Revoke(revoked)
	other, _, _ := tokentest.Mint()
	texts := []string{
		revoked.Text,
		tok.Text[:21] + other[21:], // the right selector, a wrong secret
		tok.Text[:50],              // garbled
		" " + tok.Text,
		strings.ToUpper(tok.Text[:4]) + tok.Text[4:],
	}
	secrets := []string{tok.Text[21:], revoked.Text[21:], other[21:], tok.Text[21:50]}

	mux := http.NewServeMux()
	(&restapi.Handler{APIKeys: store.NewAPIKeys(ts.pool), Users: w.Users, Keys: w.Keys, Devices: w.Devices, Messages: store.NewMessages(ts.pool),
		Contacts: store.NewContacts(ts.pool), Access: ts.checker, Log: logger}).Mount(mux)
	mux.Handle("GET /v1/media/{uid}", &media.Handler{Media: store.NewMedia(ts.pool), Access: ts.checker, Log: logger})
	mux.Handle("POST /v1/upload", &media.UploadHandler{Devices: w.Devices, Access: ts.checker, Log: logger, MaxBytes: 1 << 20, TempDir: t.TempDir(),
		Resolve: func(context.Context, uuid.UUID, string) (media.Uploader, error) { return noUpload{}, nil }})
	srv := httptest.NewUnstartedServer(mux)
	srv.Config.ErrorLog = log.New(&logs, "", 0)
	srv.Start()
	defer srv.Close()

	var answers bytes.Buffer
	for _, text := range texts {
		for _, path := range []string{"/v1/devices", "/v1/media/" + uuid.NewString(), "/v1/upload?type=image&device=" + device.String()} {
			method := http.MethodGet
			if strings.HasPrefix(path, "/v1/upload") {
				method = http.MethodPost
			}
			req, err := http.NewRequest(method, srv.URL+path, strings.NewReader("a photo"))
			if err != nil {
				t.Fatal(err)
			}
			req.Header["Authorization"] = []string{"Bearer " + text}
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(res.Body)
			_ = res.Body.Close()
			if res.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s with %q: %d", path, text[:8], res.StatusCode)
			}
			answers.Write(body)
		}
		_, f := ts.hello(t, wsapi.Hello{APIKey: text})
		answers.Write(f.Payload)
	}
	// An upload WhatsApp refuses: its error is WhatsApp's, never the token's.
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/upload?type=image&device="+device.String(), strings.NewReader("a photo"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tok.Text)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	answers.Write(body)
	// Another app's record.
	theirs := &tokentest.Token{ID: uuid.New(), Selector: "0123456789abcdef", Hash: strings.Repeat("ab", 32), Perms: nil}
	rec := w.Record(theirs, func(r *kc.TokenRecord) { r.App, r.Name = "mailie", "a name only mailie may hold" })
	w.Page(rec)

	for _, s := range secrets {
		if strings.Contains(logs.String(), s) || strings.Contains(answers.String(), s) {
			t.Fatalf("a secret leaked:\nlogs:\n%s\nanswers:\n%s", logs.String(), answers.String())
		}
	}
	if strings.Contains(logs.String(), theirs.Hash) || strings.Contains(logs.String(), "a name only mailie may hold") {
		t.Fatalf("another app's record was logged:\n%s", logs.String())
	}
}
