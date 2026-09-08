package wsapi_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/ratelimit"
	"whatserver2/internal/store"
	"whatserver2/internal/wsapi"
)

func newServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()

	var tenant string
	if err := pool.QueryRow(ctx,
		`INSERT INTO tenants (name) VALUES ('acme') RETURNING id::text`).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	keys := store.NewAPIKeys(pool)
	key, err := keys.Issue(ctx, tenant, "test")
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(wsapi.NewServer(wsapi.Config{
		Keys:    keys,
		Devices: store.NewDevices(pool),
		Log:     slog.New(slog.DiscardHandler),
	}))
	t.Cleanup(srv.Close)
	return srv, key
}

func dial(t *testing.T, srv *httptest.Server) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/v1/ws", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.CloseNow() })
	return conn
}

func send(t *testing.T, conn *websocket.Conn, frameType string, payload any) {
	t.Helper()
	f := wsapi.Frame{Type: frameType}
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		f.Payload = b
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn.Write(ctx, websocket.MessageText, b); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func read(t *testing.T, conn *websocket.Conn) wsapi.Frame {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var f wsapi.Frame
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestHandshakeSucceeds(t *testing.T) {
	srv, key := newServer(t)
	conn := dial(t, srv)

	send(t, conn, wsapi.TypeHello, wsapi.Hello{APIKey: key, Version: wsapi.Version, ClientID: "test"})
	f := read(t, conn)
	if f.Type != wsapi.TypeWelcome {
		t.Fatalf("frame = %q, want welcome: %s", f.Type, f.Payload)
	}
	var w wsapi.Welcome
	if err := json.Unmarshal(f.Payload, &w); err != nil {
		t.Fatal(err)
	}
	if w.TenantID == "" {
		t.Error("welcome carries no tenant")
	}
	if w.Version != wsapi.Version {
		t.Errorf("version = %d, want %d", w.Version, wsapi.Version)
	}
}

// Nothing is served before authentication, and the failure is reported with a
// code the client can branch on.
func TestHandshakeRejections(t *testing.T) {
	for name, tc := range map[string]struct {
		frameType string
		payload   any
		wantCode  string
	}{
		"wrong key": {
			wsapi.TypeHello, wsapi.Hello{APIKey: "00000000.nope", Version: wsapi.Version},
			wsapi.ErrCodeUnauthorized,
		},
		"no key": {
			wsapi.TypeHello, wsapi.Hello{Version: wsapi.Version},
			wsapi.ErrCodeUnauthorized,
		},
		"old client": {
			wsapi.TypeHello, wsapi.Hello{APIKey: "x", Version: 0},
			wsapi.ErrCodeVersion,
		},
		"future client": {
			wsapi.TypeHello, wsapi.Hello{APIKey: "x", Version: 99},
			wsapi.ErrCodeVersion,
		},
		"command before hello": {
			wsapi.TypeDevicesList, nil,
			wsapi.ErrCodeUnauthorized,
		},
	} {
		t.Run(name, func(t *testing.T) {
			srv, _ := newServer(t)
			conn := dial(t, srv)
			send(t, conn, tc.frameType, tc.payload)

			f := read(t, conn)
			if f.Type != wsapi.TypeError {
				t.Fatalf("frame = %q, want error", f.Type)
			}
			var e wsapi.Error
			if err := json.Unmarshal(f.Payload, &e); err != nil {
				t.Fatal(err)
			}
			if e.Code != tc.wantCode {
				t.Errorf("code = %q, want %q (message: %s)", e.Code, tc.wantCode, e.Message)
			}
		})
	}
}

// A version mismatch must be refused rather than served something the client
// may misread. Refusing is the whole point of announcing a version.
func TestVersionMismatchClosesTheConnection(t *testing.T) {
	srv, _ := newServer(t)
	conn := dial(t, srv)
	send(t, conn, wsapi.TypeHello, wsapi.Hello{APIKey: "x", Version: 99})

	read(t, conn) // the error frame
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, _, err := conn.Read(ctx); err == nil {
		t.Fatal("the connection stayed open after a version mismatch")
	}
}

// An unauthenticated connection must not be able to sit open indefinitely.
func TestUnauthenticatedConnectionsAreEvicted(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the hello timeout")
	}
	srv, _ := newServer(t)
	conn := dial(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, _, err := conn.Read(ctx); err == nil {
		t.Fatal("a silent connection was not evicted")
	}
}

func TestUnknownFrameIsRejectedNotFatal(t *testing.T) {
	srv, key := newServer(t)
	conn := dial(t, srv)
	send(t, conn, wsapi.TypeHello, wsapi.Hello{APIKey: key, Version: wsapi.Version})
	read(t, conn)

	send(t, conn, "does.not.exist", nil)
	f := read(t, conn)
	if f.Type != wsapi.TypeError {
		t.Fatalf("frame = %q, want error", f.Type)
	}

	// The session survives: a bad command is not a reason to drop a client.
	send(t, conn, wsapi.TypePing, nil)
	if f := read(t, conn); f.Type != wsapi.TypePong {
		t.Fatalf("frame = %q, want pong; the session did not survive a bad command", f.Type)
	}
}

// Pairing options are validated before any device row is created, so a typo
// cannot leave an orphan behind — and cannot burn the 160-second window either.
func TestPairValidationHappensBeforeAnyWrite(t *testing.T) {
	srv, key := newServer(t)
	conn := dial(t, srv)
	send(t, conn, wsapi.TypeHello, wsapi.Hello{APIKey: key, Version: wsapi.Version})
	read(t, conn)

	send(t, conn, wsapi.TypePair, wsapi.PairRequest{Method: "code", Phone: "011999999999"})
	f := read(t, conn)
	if f.Type != wsapi.TypeError {
		t.Fatalf("frame = %q, want error", f.Type)
	}
	var e wsapi.Error
	if err := json.Unmarshal(f.Payload, &e); err != nil {
		t.Fatal(err)
	}
	if e.Code != wsapi.ErrCodeBadRequest {
		t.Errorf("code = %q, want bad_request", e.Code)
	}
	if !strings.Contains(e.Message, "country code") {
		t.Errorf("message should explain the format: %q", e.Message)
	}

	// And no device row was created.
	send(t, conn, wsapi.TypeDevicesList, nil)
	list := read(t, conn)
	var devices wsapi.Devices
	if err := json.Unmarshal(list.Payload, &devices); err != nil {
		t.Fatal(err)
	}
	if len(devices.Devices) != 0 {
		t.Fatalf("a rejected pairing left %d device rows behind", len(devices.Devices))
	}
}

// An API key is verified with Argon2id, so an unlimited hello is both a
// guessing surface and a way to make the server spend memory on request.
func TestHelloIsRateLimited(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	var tenantID string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO tenants (name) VALUES ('acme') RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	keys := store.NewAPIKeys(pool)
	apiKey, err := keys.Issue(context.Background(), tenantID, "ci")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(wsapi.NewServer(wsapi.Config{
		Keys: keys, Devices: store.NewDevices(pool),
		Limits: &ratelimit.Auth{PerIP: ratelimit.New(1, 2)},
		Log:    slog.New(slog.DiscardHandler),
	}))
	t.Cleanup(srv.Close)

	for i := range 2 {
		conn := dial(t, srv)
		send(t, conn, wsapi.TypeHello, wsapi.Hello{APIKey: "0000000.wrong", Version: wsapi.Version})
		if f := read(t, conn); f.Type != wsapi.TypeError {
			t.Fatalf("attempt %d: %s", i+1, f.Type)
		}
	}
	conn := dial(t, srv)
	send(t, conn, wsapi.TypeHello, wsapi.Hello{APIKey: apiKey, Version: wsapi.Version})
	f := read(t, conn)
	if f.Type != wsapi.TypeError {
		t.Fatalf("the third hello from one address was answered with %s, want a rate-limit error", f.Type)
	}
	var e wsapi.Error
	if err := json.Unmarshal(f.Payload, &e); err != nil {
		t.Fatal(err)
	}
	if e.Code != wsapi.ErrCodeRateLimited {
		t.Fatalf("code = %q, want %q", e.Code, wsapi.ErrCodeRateLimited)
	}
}
