package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/authapi"
	"whatserver2/internal/config"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
	"whatserver2/internal/wsapi"
)

// serve's flags: -maintenance is a maintenance start, -allow names a write
// from maintenanceWrites and only with -maintenance, and anything else
// stops before serving (TestUnknownCommandNeverServes has the usage
// errors).
func TestServeFlags(t *testing.T) {
	served := 0
	var got serveOptions
	serve := func(opts serveOptions) error { served++; got = opts; return nil }
	if err := runCommand([]string{"serve", "-maintenance"}, serve); err != nil || !got.maintenance || len(got.allow) != 0 {
		t.Fatalf("serve -maintenance: %v %+v", err, got)
	}
	for _, args := range [][]string{
		{"serve", "-allow", "anything"},
		{"serve", "-maintenance", "-allow", "anything"},
		{"serve", "-maintenance", "-allow", ""},
	} {
		var exit exitError
		if err := runCommand(args, serve); !errors.As(err, &exit) || exit.code != 2 {
			t.Fatalf("%q: %v", args, err)
		}
	}
	if served != 1 {
		t.Fatalf("served %d times, want 1", served)
	}

	// The hook: a write a slice adds to maintenanceWrites is allowed by its
	// name, and lets its frames and routes through, nothing else.
	maintenanceWrites["test.write"] = maintenanceWrite{frames: []string{wsapi.TypeDeviceRename}, routes: []string{"PUT /v1/auth/locale"}}
	t.Cleanup(func() { delete(maintenanceWrites, "test.write") })
	if err := runCommand([]string{"serve", "-maintenance", "-allow", "test.write"}, serve); err != nil ||
		!got.maintenance || !slices.Equal(got.allow, []string{"test.write"}) {
		t.Fatalf("serve -maintenance -allow test.write: %v %+v", err, got)
	}
	m := newMaintenance(got.allow)
	if sock := m.socket(); !sock.Permits(wsapi.TypeDeviceRename) || sock.Permits(wsapi.TypeSend) {
		t.Fatal("the allowed frame is refused, or another write is let through")
	}
	if !m.routes["PUT /v1/auth/locale"] || len(m.routes) != 1 {
		t.Fatalf("routes: %v", m.routes)
	}
	if newMaintenance(nil).socket().Permits(wsapi.TypeDeviceRename) {
		t.Fatal("a maintenance start with nothing allowed lets a write through")
	}
}

// What a maintenance socket answers: its reads, never a frame that sends,
// pairs, starts a number, manages, or writes a contact row; and a normal
// start's socket answers every frame.
func TestMaintenanceSocketReads(t *testing.T) {
	m := wsapi.NewMaintenance()
	for _, frame := range []string{wsapi.TypePing, wsapi.TypeDevicesList, wsapi.TypeSubscribe, wsapi.TypeChatsList, wsapi.TypeChatPage,
		wsapi.TypeHistory, wsapi.TypeMessageGet, wsapi.TypeKeysGet, wsapi.TypeGrantsList} {
		if !m.Permits(frame) {
			t.Errorf("%s is refused", frame)
		}
	}
	for _, frame := range []string{wsapi.TypePair, wsapi.TypeSend, wsapi.TypeSendMedia, wsapi.TypeDeviceStart, wsapi.TypeDeviceStop,
		wsapi.TypeDeviceRename, wsapi.TypeDeviceDelete, wsapi.TypeGrantAdd, wsapi.TypeGrantRevoke, wsapi.TypeKeyCreate,
		wsapi.TypeResolve, wsapi.TypeAvatar, wsapi.TypeMarkRead, wsapi.TypeMediaRetry, wsapi.TypeBackfill, wsapi.TypeReaderMode,
		wsapi.TypeDeviceNoticeSeen, wsapi.TypeCallStart, "unknown.frame"} {
		if m.Permits(frame) {
			t.Errorf("%s is let through", frame)
		}
	}
	var normal *wsapi.Maintenance
	if !normal.Permits(wsapi.TypeSend) {
		t.Fatal("a normal start's socket refuses a frame")
	}
}

// Every route a maintenance start lets a write through is mounted as
// written: a typo would refuse a sign-in.
func TestSignInRoutesAreMounted(t *testing.T) {
	mux := http.NewServeMux()
	(&authapi.Handler{}).Mount(mux)
	for route := range signInRoutes {
		method, path, _ := strings.Cut(route, " ")
		if _, pattern := mux.Handler(httptest.NewRequest(method, path, nil)); pattern != route {
			t.Errorf("%s: the mux has %q", route, pattern)
		}
	}
}

// maintenanceRoutes is the handler a maintenance start mounts, with the
// assistant connector configured and the web client: nothing behind a
// route is reached, so nothing is opened.
func maintenanceRoutes(t *testing.T) (*app, http.Handler) {
	t.Helper()
	a := &app{
		cfg: config.Config{MetricsAddr: "127.0.0.1:0", MCP: enclaveConfig(), CallsEnabled: true},
		log: slog.New(slog.DiscardHandler), pools: &pg.Pools{}, ws: &wsapi.Server{},
		maintenance: newMaintenance(nil),
	}
	return a, a.routes()
}

// A maintenance start's HTTP side: discovery says so and advertises no
// connector, every answer carries the header, MCP is not mounted whatever
// WS_MCP_ENABLED says, and a write that is not a sign-in is refused 503
// maintenance before any handler runs.
func TestMaintenanceRoutes(t *testing.T) {
	a, h := maintenanceRoutes(t)
	if a.mcp != nil {
		t.Fatal("the connector is mounted")
	}
	rec := ask(h, http.MethodGet, "https://api.wappie.thehappie.co/v1/discovery")
	var disc struct {
		Maintenance  bool              `json:"maintenance"`
		Capabilities []string          `json:"capabilities"`
		Endpoints    map[string]string `json:"endpoints"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &disc); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("discovery: %d %v", rec.Code, err)
	}
	if !disc.Maintenance || slices.Contains(disc.Capabilities, "mcp.remote.v1") || disc.Endpoints["mcp_server_attested"] != "" {
		t.Fatalf("discovery: %+v", disc)
	}
	if rec.Header().Get(maintenanceHeader) != "on" {
		t.Fatal("discovery: no maintenance header")
	}
	for _, probe := range []string{"/healthz", "/readyz"} {
		rec := httptest.NewRecorder()
		a.markMaintenance(rec)
		if rec.Header().Get(maintenanceHeader) != "on" {
			t.Fatalf("%s: no maintenance header", probe)
		}
	}

	for _, tc := range []struct{ method, route string }{
		{http.MethodPost, "/v1/auth/workspaces"},
		{http.MethodPut, "/v1/auth/profile"},
		{http.MethodPut, "/v1/auth/locale"},
		{http.MethodPost, "/v1/auth/signup"},
		{http.MethodPost, "/v1/auth/workspaces/accept-invite"},
		{http.MethodPost, "/v1/auth/password"},
		{http.MethodPost, "/v1/auth/platform/account"},
		{http.MethodDelete, "/v1/auth/passkeys/x"},
		{http.MethodPost, "/v1/auth/workspaces/storage/resume"},
		{http.MethodPut, "/v1/auth/workspaces/devices/" + uuid.NewString() + "/permissions"},
		{http.MethodPost, "/v1/upload"},
	} {
		rec := ask(h, tc.method, "https://api.wappie.thehappie.co"+tc.route)
		if rec.Code != http.StatusServiceUnavailable || rec.Body.String() != maintenanceRefusal {
			t.Errorf("%s %s: %d %q", tc.method, tc.route, rec.Code, rec.Body.String())
		}
	}
	// Not mounted: the connector's routes and the call media answer the
	// API's 404, as on an installation without them.
	for _, tc := range []struct{ method, route string }{
		{http.MethodPost, "/v1/mcp/token-requests"},
		{http.MethodGet, "/v1/calls/media"},
	} {
		if rec := ask(h, tc.method, "https://api.wappie.thehappie.co"+tc.route); rec.Code != http.StatusNotFound {
			t.Errorf("%s %s: %d", tc.method, tc.route, rec.Code)
		}
	}

	// A normal start has neither the field nor the header.
	normal := testRoutes(t, true)
	rec = ask(normal, http.MethodGet, "https://api.wappie.thehappie.co/v1/discovery")
	if strings.Contains(rec.Body.String(), "maintenance") || rec.Header().Get(maintenanceHeader) != "" {
		t.Fatalf("a normal start says maintenance: %q", rec.Body.String())
	}
}

// The start's line names the maintenance start and what it allows, and a
// normal start says nothing of it.
func TestMaintenanceLogLine(t *testing.T) {
	var buf bytes.Buffer
	a := &app{log: slog.New(slog.NewJSONHandler(&buf, nil)), maintenance: newMaintenance(nil)}
	a.logMaintenance()
	var line struct {
		Level, Msg  string
		Maintenance bool
		Allowed     []string
	}
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatalf("%v: %q", err, buf.String())
	}
	if line.Level != "WARN" || !strings.HasPrefix(line.Msg, "MAINTENANCE START") || !line.Maintenance || line.Allowed == nil || len(line.Allowed) != 0 {
		t.Fatalf("the line: %+v", line)
	}
	buf.Reset()
	(&app{log: slog.New(slog.NewJSONHandler(&buf, nil))}).logMaintenance()
	if buf.Len() != 0 {
		t.Fatalf("a normal start logged %q", buf.String())
	}
}

// fakeBucket is object storage that records every request and answers it
// as a bucket that exists would.
type fakeBucket struct {
	mu    sync.Mutex
	asked []string
}

func (b *fakeBucket) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	b.asked = append(b.asked, r.Method+" "+r.URL.Path)
	b.mu.Unlock()
	if r.Method == http.MethodDelete {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// writes are the requests that would change the bucket.
func (b *fakeBucket) writes() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []string
	for _, req := range b.asked {
		if !strings.HasPrefix(req, http.MethodGet) && !strings.HasPrefix(req, http.MethodHead) {
			out = append(out, req)
		}
	}
	return out
}

// startServe runs serve as opts says against the environment, and returns
// its app and base URL once it listens; stop ends it and waits.
func startServe(t *testing.T, opts serveOptions) (*app, string, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	type up struct {
		a    *app
		addr net.Addr
	}
	ups := make(chan up, 1)
	done := make(chan error, 1)
	go func() {
		done <- runServe(ctx, make(chan os.Signal), opts, func(a *app, addr net.Addr) { ups <- up{a, addr} })
	}()
	var u up
	select {
	case u = <-ups:
	case err := <-done:
		cancel()
		t.Fatalf("serve stopped before it listened: %v", err)
	case <-time.After(60 * time.Second):
		cancel()
		t.Fatal("serve did not listen within a minute")
	}
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			if err := <-done; err != nil {
				t.Errorf("serve: %v", err)
			}
		})
	}
	t.Cleanup(stop)
	return u.a, "http://" + u.addr.String(), stop
}

// dataRows is what a maintenance start must leave as it found it: every
// number's row whole, the messages and attachments, and which whatsmeow
// tables exist (a normal start creates them).
func dataRows(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `ALTER TABLE devices DISABLE ROW LEVEL SECURITY; ALTER TABLE messages DISABLE ROW LEVEL SECURITY; ALTER TABLE media DISABLE ROW LEVEL SECURITY`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := pool.Exec(ctx, `ALTER TABLE devices ENABLE ROW LEVEL SECURITY; ALTER TABLE devices FORCE ROW LEVEL SECURITY;
			ALTER TABLE messages ENABLE ROW LEVEL SECURITY; ALTER TABLE messages FORCE ROW LEVEL SECURITY;
			ALTER TABLE media ENABLE ROW LEVEL SECURITY; ALTER TABLE media FORCE ROW LEVEL SECURITY`); err != nil {
			t.Fatal(err)
		}
	}()
	var out string
	if err := pool.QueryRow(ctx, `SELECT
		  (SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY d.id), '[]') FROM devices d)::text
		  || (SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY to_jsonb(m)::text), '[]') FROM messages m)::text
		  || (SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text), '[]') FROM media x)::text
		  || (SELECT coalesce(string_agg(table_name, ',' ORDER BY table_name), '') FROM information_schema.tables
		       WHERE table_schema = current_schema() AND table_name LIKE 'whatsmeow%')`).Scan(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

// postJSON posts body to base+route with token, if any, and returns the
// status and the body.
func postJSON(t *testing.T, method, url, token string, body any) (int, []byte) {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, url, bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck // read to the end below
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, out
}

// helloWithKey opens the socket with an API key and returns the first
// frame the server sends.
func helloWithKey(t *testing.T, base, key string) wsapi.Frame {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	//nolint:bodyclose // coder/websocket: "You never need to close resp.Body yourself."
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(base, "http")+"/v1/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow() //nolint:errcheck // the test is done with it
	hello, err := json.Marshal(wsapi.Hello{APIKey: key, Version: wsapi.Version, ClientID: "maintenance test"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(wsapi.Frame{Type: wsapi.TypeHello, Payload: hello})
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Write(ctx, websocket.MessageText, b); err != nil {
		t.Fatal(err)
	}
	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var f wsapi.Frame
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

// TestMaintenanceStart is slice 3a's test, on the real start against the
// database and an object store that records every request: a maintenance
// start claims no WhatsApp session, changes no number's row, writes no
// object and starts none of the workers; a person signs in and reads the
// numbers; a write is refused, on the socket and over HTTP, and an API
// key is refused everywhere. Then the same seed under a normal start does
// what the maintenance start did not: it resumes the number (whose session
// is gone, so its row says so) and its janitor purges the due number,
// deleting its object.
func TestMaintenanceStart(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Fresh(t, migrate.Run)
	w := &purgeWorld{pool: pool, devices: store.NewDevices(pool), users: store.NewUsers(pool), log: &recorder{},
		ledger: filepath.Join(t.TempDir(), "deletion-ledger.jsonl")}
	team, owner := w.workspace(t, "maint")
	live, _ := w.number(t, team)
	if err := w.devices.SetStatus(ctx, team.String(), live.String(), wa.StatusOnline, ""); err != nil {
		t.Fatal(err)
	}
	due, _ := w.number(t, team)
	w.deleteNumber(t, team, owner, due, "-1 hour")
	apiKey, err := store.NewAPIKeys(pool).Issue(ctx, team.String(), "maintenance test")
	if err != nil {
		t.Fatal(err)
	}

	bucket := &fakeBucket{}
	objects := httptest.NewServer(bucket)
	t.Cleanup(objects.Close)
	commandEnv(t, pool, w.ledger)
	t.Setenv("WS_HTTP_ADDR", "127.0.0.1:0")
	t.Setenv("WS_S3_ENDPOINT", objects.URL)
	t.Setenv("WS_S3_USE_SSL", "false")
	t.Setenv("WS_S3_BUCKET", "media")
	t.Setenv("WS_S3_ACCESS_KEY", "test")
	t.Setenv("WS_S3_SECRET_KEY", "test-secret")
	before := dataRows(t, pool)

	a, base, stop := startServe(t, serveOptions{maintenance: true})
	if len(a.started) != 0 {
		t.Fatalf("a maintenance start started %q", a.started)
	}
	if a.leader != nil || a.mcp != nil || a.calls != nil {
		t.Fatal("a maintenance start has a contract leader, the connector or calls")
	}
	if _, running := a.registry.Get(live.String()); running {
		t.Fatal("a maintenance start supervises a number")
	}

	// A person signs in, and reads.
	status, body := postJSON(t, http.MethodPost, base+"/v1/auth/login", "", map[string]string{"email": "maint-owner@example.test", "auth_key": "test"})
	if status != http.StatusOK {
		t.Fatalf("sign-in: %d %s", status, body)
	}
	var signedIn struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &signedIn); err != nil || signedIn.Token == "" {
		t.Fatalf("sign-in: %v %s", err, body)
	}
	listed := decode[wsapi.Devices](t, askAt(t, base, signedIn.Token, wsapi.TypeDevicesList, nil), wsapi.TypeDevices)
	if !slices.ContainsFunc(listed.Devices, func(d wsapi.DeviceInfo) bool { return d.ID == live.String() }) {
		t.Fatalf("the number is not listed: %+v", listed.Devices)
	}
	status, body = postJSON(t, http.MethodGet, base+"/v1/devices", signedIn.Token, nil)
	if status != http.StatusOK || !strings.Contains(string(body), live.String()) {
		t.Fatalf("the REST read with a session: %d %s", status, body)
	}

	// Writes are refused: on the socket before any handler, over HTTP
	// before any handler.
	wantError(t, askAt(t, base, signedIn.Token, wsapi.TypeDeviceRename, map[string]string{"device_id": live.String(), "name": "x"}), wsapi.ErrCodeMaintenance)
	wantError(t, askAt(t, base, signedIn.Token, wsapi.TypeDeviceStart, map[string]string{"device_id": live.String()}), wsapi.ErrCodeMaintenance)
	wantError(t, askAt(t, base, signedIn.Token, wsapi.TypeSend, map[string]string{"device_id": live.String()}), wsapi.ErrCodeMaintenance)
	wantError(t, askAt(t, base, signedIn.Token, wsapi.TypePair, nil), wsapi.ErrCodeMaintenance)
	status, body = postJSON(t, http.MethodPost, base+"/v1/auth/workspaces", signedIn.Token, map[string]string{"name": "another"})
	if status != http.StatusServiceUnavailable || string(body) != maintenanceRefusal {
		t.Fatalf("a workspace created: %d %s", status, body)
	}
	status, _ = postJSON(t, http.MethodPost, base+"/v1/upload", signedIn.Token, nil)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("an upload: %d", status)
	}

	// API keys are off: the socket, REST and attachments.
	wantError(t, helloWithKey(t, base, apiKey), wsapi.ErrCodeMaintenance)
	if status, body := postJSON(t, http.MethodGet, base+"/v1/devices", apiKey, nil); status != http.StatusUnauthorized {
		t.Fatalf("the REST read with a key: %d %s", status, body)
	}
	if status, _ := postJSON(t, http.MethodGet, base+"/v1/media/"+uuid.NewString(), apiKey, nil); status != http.StatusUnauthorized {
		t.Fatalf("an attachment with a key: %d", status)
	}

	// Health: the probe and discovery say so.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/readyz", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close() //nolint:errcheck,gosec // only the status and the header
	if resp.StatusCode != http.StatusOK || resp.Header.Get(maintenanceHeader) != "on" {
		t.Fatalf("readyz: %d %q", resp.StatusCode, resp.Header.Get(maintenanceHeader))
	}

	// Given the time a janitor's first pass and a resume take, nothing.
	time.Sleep(500 * time.Millisecond)
	stop()
	if after := dataRows(t, pool); after != before {
		t.Fatalf("a maintenance start changed the data:\nbefore %s\nafter  %s", before, after)
	}
	if writes := bucket.writes(); len(writes) != 0 {
		t.Fatalf("a maintenance start wrote to the bucket: %q", writes)
	}

	// The same seed, a normal start.
	a, _, stop = startServe(t, serveOptions{})
	for _, worker := range []string{"resume", "supervisor", "attachment worker", "janitor", "read check"} {
		if !slices.Contains(a.started, worker) {
			t.Errorf("a normal start did not start the %s: %q", worker, a.started)
		}
	}
	eventually(t, "the normal start's resume and purge", func() bool {
		d, err := w.devices.Get(ctx, team.String(), live.String())
		return err == nil && d.Status == wa.StatusLoggedOut && !w.exists(t, team, due) && len(bucket.writes()) > 0 //nolint:contextcheck // the world's helpers run on a context of their own
	})
	stop()
	if after := dataRows(t, pool); after == before {
		t.Fatal("the normal start changed nothing: the test shows nothing")
	}
}
