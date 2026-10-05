package authapi_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/thehappieco/kit/oidcrp"
	"github.com/thehappieco/kit/profiles/platform"

	"whatserver2/internal/authapi"
	"whatserver2/internal/config"
	"whatserver2/internal/pg"
	"whatserver2/internal/ratelimit"
	"whatserver2/internal/store"
)

// The provider's development issuer, as the console and id. name it; the
// fake answers on a loopback port that WS_PLATFORM_ID_ADDR dials.
const testIssuer = "http://id.thehappie.localhost:8290"
const testIDHost = "id.thehappie.localhost:8290"

// fakeID is id.'s userinfo endpoint: each token is answered once, with what
// was registered for it, and every request is checked for what a
// server-to-server userinfo call must and must not carry. Ported from the
// platform's tools/fakeproduct tests.
type fakeID struct {
	t        *testing.T
	srv      *httptest.Server
	mu       sync.Mutex
	answers  map[string]func(w http.ResponseWriter)
	requests atomic.Int64
}

func newFakeID(t *testing.T) *fakeID {
	t.Helper()
	f := &fakeID{t: t, answers: map[string]func(http.ResponseWriter){}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeID) serve(w http.ResponseWriter, r *http.Request) {
	f.requests.Add(1)
	if r.Host != testIDHost {
		f.t.Errorf("userinfo went to Host %q, want %q", r.Host, testIDHost)
	}
	if r.Method != http.MethodGet || r.URL.Path != oidcrp.UserinfoPath || r.URL.RawQuery != "" {
		f.t.Errorf("userinfo request is %s %s", r.Method, r.URL.Path)
	}
	for _, h := range []string{"Cookie", "Origin", "Referer", "Sec-Fetch-Site"} {
		if r.Header.Get(h) != "" {
			f.t.Errorf("the server-to-server userinfo call carries %s", h)
		}
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	f.mu.Lock()
	answer, known := f.answers[token]
	delete(f.answers, token)
	f.mu.Unlock()
	if !ok || !known {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	answer(w)
}

func newAccessToken(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return oidcrp.AccessTokenPrefix + platform.EncodeB64(raw)
}

// issue registers a userinfo answer for a fresh token.
func (f *fakeID) issue(t *testing.T, body map[string]any) string {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return f.raw(t, http.StatusOK, "application/json", string(data))
}

// raw registers any answer for a fresh token.
func (f *fakeID) raw(t *testing.T, status int, contentType, body string) string {
	t.Helper()
	token := newAccessToken(t)
	f.mu.Lock()
	f.answers[token] = func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
	f.mu.Unlock()
	return token
}

// person is an account at id.: its sub, its root (from which each product
// key derives) and its verified address.
type person struct {
	sub   string
	root  []byte
	email string
	name  string
}

func newPerson(t *testing.T, email string) person {
	t.Helper()
	sub, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	root := make([]byte, 32)
	if _, err := rand.Read(root); err != nil {
		t.Fatal(err)
	}
	return person{sub: sub.String(), root: root, email: email, name: "Ana"}
}

func (p person) productKey(t *testing.T, epoch int) string {
	t.Helper()
	sk, pub, err := platform.ProductKey(p.root, "wappie", epoch)
	if err != nil {
		t.Fatal(err)
	}
	clear(sk)
	return platform.EncodeB64(pub)
}

// userinfo is what id.'s userinfo says of p for the wappie-app client.
func (p person) userinfo(t *testing.T, epoch int) map[string]any {
	t.Helper()
	return map[string]any{
		"sub": p.sub, "client_id": "wappie-app", "auth_time": time.Now().Unix() - 5, "amr": []string{"pwd"},
		"email": p.email, "email_verified": true, "locale": "pt-BR", "name": p.name,
		"product_key_id": platform.ProductKeyID("wappie", epoch), "product_key": p.productKey(t, epoch),
	}
}

type platformHarness struct {
	*passkeyHarness
	id      *fakeID
	handler *authapi.Handler
	alerts  chan string
}

// newPlatformHarness serves the auth routes with the provider configured as
// in development (issuer on *.localhost, the dial address set), passkeys on,
// and one legacy password account: passkey@example.com, with a recovery
// code, signed in.
func newPlatformHarness(t *testing.T, local config.LocalLogin) *platformHarness {
	t.Helper()
	p := newPasskeyHarness(t)
	id := newFakeID(t)
	login, err := authapi.NewPlatformLogin(config.Platform{
		Issuer: testIssuer, ClientID: "wappie-app", AppOrigin: passkeyApp, IDAddr: id.srv.Listener.Addr().String(),
		LocalLogin: local, AlertEmail: "operator@example.com",
	}, store.NewPlatformPins(p.pool))
	if err != nil {
		t.Fatal(err)
	}
	alerts := make(chan string, 8)
	login.Alert = func(_ context.Context, to string) error { alerts <- to; return nil }
	provider, err := authapi.NewPasskeyProvider(config.Passkeys{RPID: passkeyRP, Origins: []string{passkeyApp, passkeyConsole}})
	if err != nil {
		t.Fatal(err)
	}
	handler := &authapi.Handler{Users: p.users, Keys: p.keys, Devices: store.NewDevices(p.pool), Passkeys: provider, Platform: login, LocalLogin: local}
	mux := http.NewServeMux()
	handler.Mount(mux)
	p.srv.Close()
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return &platformHarness{passkeyHarness: p, id: id, handler: handler, alerts: alerts}
}

// pagePost posts as the console's own page does: its exact Origin,
// Sec-Fetch-Site: same-origin and JSON. headers override any of the three
// ("" removes one).
func (h *platformHarness) pagePost(t *testing.T, path string, body, into any, token string, headers map[string]string) int {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, h.srv.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", passkeyApp)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return h.do(t, req, into)
}

type platformAnswer struct {
	Kind         string `json:"kind"`
	Code         string `json:"code"`
	ProductKeyID string `json:"product_key_id"`
	Pin          struct {
		Sub          string `json:"sub"`
		ProductKeyID string `json:"product_key_id"`
		ProductKey   string `json:"product_key"`
	} `json:"pin"`
	Token string `json:"token"`
	User  struct {
		ID         string `json:"id"`
		TenantID   string `json:"tenant_id"`
		Email      string `json:"email"`
		PublicKey  string `json:"public_key"`
		WrappedUSK string `json:"wrapped_usk"`
		AuthSource string `json:"auth_source"`
	} `json:"user"`
	PlatformWrap string `json:"platform_wrap"`
	Ticket       string `json:"ticket"`
	Email        string `json:"email"`
	Name         string `json:"name"`
	UserID       string `json:"user_id"`
	PublicKey    string `json:"public_key"`
	WrappedUSK   string `json:"wrapped_usk"`
	RecoveryWrap string `json:"recovery_wrap"`
}

// signIn posts a fresh access token for p at epoch to the session route.
func (h *platformHarness) signIn(t *testing.T, p person, epoch int) (int, platformAnswer) {
	t.Helper()
	var out platformAnswer
	code := h.pagePost(t, "/v1/auth/platform/session", map[string]string{"access_token": h.id.issue(t, p.userinfo(t, epoch))}, &out, "", nil)
	return code, out
}

func randomWrap(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 61)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	raw[0] = 1
	return base64.StdEncoding.EncodeToString(raw)
}

func randomKey(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// createAccount answers a "new" sign-in with an account.
func (h *platformHarness) createAccount(t *testing.T, ticket string) (int, platformAnswer, string, string) {
	t.Helper()
	pub, wrap := randomKey(t), randomWrap(t)
	var out platformAnswer
	code := h.pagePost(t, "/v1/auth/platform/account", map[string]string{"ticket": ticket, "public_key": pub, "platform_wrap": wrap}, &out, "", nil)
	return code, out, pub, wrap
}

func (h *platformHarness) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	if err := h.pool.QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestPlatformSignInIsOffUnlessConfigured(t *testing.T) {
	h := newHarness(t)
	var out platformAnswer
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/v1/auth/platform/session", strings.NewReader(`{"access_token":"x"}`))
	req.Header.Set("Origin", passkeyApp)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Content-Type", "application/json")
	if code := h.do(t, req, &out); code != http.StatusForbidden || out.Code != "platform_login_disabled" {
		t.Fatalf("unconfigured server: %d %+v", code, out)
	}
}

// The kit's session-handler rules, before the body is read: exactly the
// console's Origin, Sec-Fetch-Site: same-origin and JSON. None of these
// requests reaches userinfo, so no token leaves this server.
func TestPlatformSessionRefusesAnythingButThePageItself(t *testing.T) {
	h := newPlatformHarness(t, config.LocalLoginOn)
	p := newPerson(t, "ana@example.com")
	for _, tc := range []struct {
		headers map[string]string
		status  int
	}{
		{map[string]string{"Origin": ""}, http.StatusForbidden},
		{map[string]string{"Origin": "null"}, http.StatusForbidden},
		{map[string]string{"Origin": "https://evil.example"}, http.StatusForbidden},
		{map[string]string{"Origin": passkeyConsole}, http.StatusForbidden},
		{map[string]string{"Sec-Fetch-Site": ""}, http.StatusForbidden},
		{map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
		{map[string]string{"Sec-Fetch-Site": "same-site"}, http.StatusForbidden},
		{map[string]string{"Content-Type": "text/plain;charset=UTF-8"}, http.StatusUnsupportedMediaType},
		{map[string]string{"Content-Type": ""}, http.StatusUnsupportedMediaType},
	} {
		token := h.id.issue(t, p.userinfo(t, 1))
		var out platformAnswer
		if code := h.pagePost(t, "/v1/auth/platform/session", map[string]string{"access_token": token}, &out, "", tc.headers); code != tc.status {
			t.Errorf("%v: %d %+v", tc.headers, code, out)
		}
	}
	if n := h.id.requests.Load(); n != 0 {
		t.Fatalf("a refused request reached userinfo %d times", n)
	}
	if n := h.count(t, `SELECT count(*) FROM platform_key_pins`); n != 0 {
		t.Fatalf("%d pins after refusals", n)
	}
}

func TestPlatformNewAccountThenSession(t *testing.T) {
	h := newPlatformHarness(t, config.LocalLoginOn)
	ctx := context.Background()
	p := newPerson(t, "Bea@Example.com")

	code, first := h.signIn(t, p, 1)
	if code != http.StatusOK || first.Kind != "new" || first.Ticket == "" || first.Email != "Bea@Example.com" {
		t.Fatalf("first sign-in: %d %+v", code, first)
	}
	if first.Pin.Sub != p.sub || first.Pin.ProductKeyID != "wappie:1" || first.Pin.ProductKey != p.productKey(t, 1) {
		t.Fatalf("the answer does not name the pinned triple: %+v", first.Pin)
	}
	code, created, pub, wrap := h.createAccount(t, first.Ticket)
	if code != http.StatusOK || created.Kind != "session" || created.Token == "" {
		t.Fatalf("account: %d %+v", code, created)
	}
	if created.User.ID != p.sub || created.User.AuthSource != "platform" || created.User.PublicKey != pub ||
		created.User.WrappedUSK != "" || created.User.Email != "bea@example.com" {
		t.Fatalf("the new account: %+v", created.User)
	}
	// A ticket works once.
	if code, again, _, _ := h.createAccount(t, first.Ticket); code != http.StatusUnauthorized || again.Code != "ticket_invalid" {
		t.Fatalf("a spent ticket: %d %+v", code, again)
	}
	var me struct {
		User struct {
			ID         string `json:"id"`
			AuthSource string `json:"auth_source"`
			WrappedUSK string `json:"wrapped_usk"`
		} `json:"user"`
	}
	if code := h.get(t, "/v1/auth/me", &me, created.Token); code != http.StatusOK || me.User.ID != p.sub || me.User.AuthSource != "platform" || me.User.WrappedUSK != "" {
		t.Fatalf("me: %d %+v", code, me)
	}
	// The interim personal workspace (D6), as for every person.
	spaces, err := h.users.Workspaces(ctx, uuid.MustParse(p.sub))
	if err != nil || len(spaces) != 1 || spaces[0].Kind != "personal" || spaces[0].Role != "owner" {
		t.Fatalf("workspaces: %+v %v", spaces, err)
	}

	code, second := h.signIn(t, p, 1)
	if code != http.StatusOK || second.Kind != "session" || second.PlatformWrap != wrap || second.User.ID != p.sub || second.Token == "" {
		t.Fatalf("second sign-in: %d %+v", code, second)
	}
	if second.Pin != first.Pin {
		t.Fatalf("the pin moved: %+v %+v", first.Pin, second.Pin)
	}
	if n := h.count(t, `SELECT count(*) FROM platform_key_pins WHERE sub = $1`, p.sub); n != 1 {
		t.Fatalf("%d pins", n)
	}
	if n := h.count(t, `SELECT count(*) FROM security_events WHERE kind = 'platform_linked' AND sub = $1 AND detail->>'from' = 'new'`, p.sub); n != 1 {
		t.Fatalf("%d link events", n)
	}
	// No password exists to sign in with.
	if code := h.post(t, "/v1/auth/login", map[string]string{"email": "bea@example.com", "auth_key": ""}, nil, ""); code != http.StatusUnauthorized {
		t.Fatalf("password sign-in of a platform account: %d", code)
	}
}

// A sign-in whose key differs from the pin is refused, the pin kept, no
// session started, and the alert raised: the event, and a mail to the
// operator and the account.
func TestPlatformAccountKeyChangedIsRefusedAndRaised(t *testing.T) {
	h := newPlatformHarness(t, config.LocalLoginOn)
	p := newPerson(t, "carla@example.com")
	_, first := h.signIn(t, p, 1)
	if code, _, _, _ := h.createAccount(t, first.Ticket); code != http.StatusOK {
		t.Fatalf("account: %d", code)
	}
	sessions := h.count(t, `SELECT count(*) FROM sessions WHERE user_id = $1`, p.sub)

	swapped := p
	swapped.root = make([]byte, 32)
	if _, err := rand.Read(swapped.root); err != nil {
		t.Fatal(err)
	}
	code, out := h.signIn(t, swapped, 1)
	if code != http.StatusConflict || out.Code != "account_key_changed" || out.ProductKeyID != "wappie:1" || out.Token != "" {
		t.Fatalf("a changed key: %d %+v", code, out)
	}
	var pinned string
	if err := h.pool.QueryRow(context.Background(), `SELECT encode(product_key, 'base64') FROM platform_key_pins WHERE sub = $1`, p.sub).Scan(&pinned); err != nil {
		t.Fatal(err)
	}
	if want, _ := platform.DecodeB64(p.productKey(t, 1), 32); pinned != base64.StdEncoding.EncodeToString(want) {
		t.Fatal("the pin was replaced")
	}
	if n := h.count(t, `SELECT count(*) FROM sessions WHERE user_id = $1`, p.sub); n != sessions {
		t.Fatalf("a refused sign-in started a session: %d -> %d", sessions, n)
	}
	if n := h.count(t, `SELECT count(*) FROM security_events WHERE kind = 'platform_account_key_changed' AND sub = $1 AND user_id = $1
		AND detail = '{"product_key_id":"wappie:1"}'::jsonb`, p.sub); n != 1 {
		t.Fatalf("%d alert events", n)
	}
	got := map[string]bool{}
	for range 2 {
		select {
		case to := <-h.alerts:
			got[to] = true
		case <-time.After(5 * time.Second):
			t.Fatalf("alerts sent: %v", got)
		}
	}
	if !got["operator@example.com"] || !got["carla@example.com"] {
		t.Fatalf("alerts sent: %v", got)
	}
	// And the right key still signs in.
	if code, again := h.signIn(t, p, 1); code != http.StatusOK || again.Kind != "session" {
		t.Fatalf("the pinned key after a refusal: %d %+v", code, again)
	}
}

// Two first sign-ins of one sub with different keys, at once: the pin store
// is atomic, so one pins and the other is refused against it.
func TestPlatformConcurrentFirstSignInsAgreeOnOnePin(t *testing.T) {
	h := newPlatformHarness(t, config.LocalLoginOn)
	p := newPerson(t, "dora@example.com")
	q := p
	q.root = make([]byte, 32)
	if _, err := rand.Read(q.root); err != nil {
		t.Fatal(err)
	}
	tokens := []string{h.id.issue(t, p.userinfo(t, 1)), h.id.issue(t, q.userinfo(t, 1))}
	codes := make([]int, 2)
	var wg sync.WaitGroup
	for i := range tokens {
		wg.Go(func() {
			codes[i] = h.pagePost(t, "/v1/auth/platform/session", map[string]string{"access_token": tokens[i]}, nil, "", nil)
		})
	}
	wg.Wait()
	if oneWonOneConflicted := codes[0] == http.StatusOK && codes[1] == http.StatusConflict || codes[0] == http.StatusConflict && codes[1] == http.StatusOK; !oneWonOneConflicted {
		t.Fatalf("codes %v", codes)
	}
}

func TestPlatformRefusalsOfUserinfo(t *testing.T) {
	h := newPlatformHarness(t, config.LocalLoginOn)
	p := newPerson(t, "eva@example.com")
	post := func(token string) (int, platformAnswer) {
		var out platformAnswer
		return h.pagePost(t, "/v1/auth/platform/session", map[string]string{"access_token": token}, &out, "", nil), out
	}

	wrongClient := p.userinfo(t, 1)
	wrongClient["client_id"] = "thehappie-console"
	if code, out := post(h.id.issue(t, wrongClient)); code != http.StatusForbidden || out.Code != "wrong_client" {
		t.Errorf("another client's token: %d %+v", code, out)
	}
	// Refused once, never retried: the token works once.
	before := h.id.requests.Load()
	if code, out := post(newAccessToken(t)); code != http.StatusUnauthorized || out.Code != "token_refused" {
		t.Errorf("a refused token: %d %+v", code, out)
	}
	if n := h.id.requests.Load() - before; n != 1 {
		t.Errorf("a refused token was sent %d times", n)
	}
	before = h.id.requests.Load()
	if code, _ := post("not-a-token"); code != http.StatusBadRequest || h.id.requests.Load() != before {
		t.Errorf("a string that is not a token: %d, sent %d times", code, h.id.requests.Load()-before)
	}
	for name, token := range map[string]string{
		"text/plain":    h.id.raw(t, 200, "text/plain", `{}`),
		"500":           h.id.raw(t, 500, "application/json", `{}`),
		"two objects":   h.id.raw(t, 200, "application/json", `{"sub":"x"}{}`),
		"uppercase sub": h.id.issue(t, map[string]any{"sub": strings.ToUpper(p.sub), "client_id": "wappie-app", "product_key_id": "wappie:1", "product_key": p.productKey(t, 1)}),
		"other product": h.id.issue(t, map[string]any{"sub": p.sub, "client_id": "wappie-app", "product_key_id": "mailie:1", "product_key": p.productKey(t, 1)}),
		"no key":        h.id.issue(t, map[string]any{"sub": p.sub, "client_id": "wappie-app", "email": p.email, "email_verified": true}),
		"unverified":    h.id.issue(t, func() map[string]any { u := p.userinfo(t, 1); u["email_verified"] = false; return u }()),
	} {
		if code, out := post(token); code != http.StatusBadGateway || out.Code != "userinfo" {
			t.Errorf("%s: %d %+v", name, code, out)
		}
	}
	if n := h.count(t, `SELECT count(*) FROM platform_key_pins`); n != 1 {
		// Only the unverified address got as far as the pin.
		t.Errorf("%d pins", n)
	}
}

// The link ceremony: the provider's address names an unlinked password
// account, so only a link is offered; the old password proves it here and,
// in the browser, opens the account key that the browser wraps under sk_p.
// The link revokes every old session and Wappie passkey, and keeps users.id.
func TestPlatformLinkRequiredThenLink(t *testing.T) {
	h := newPlatformHarness(t, config.LocalLoginOn)
	ctx := context.Background()
	legacyID := h.signed.User.ID
	if _, pk := h.register(t); pk.ID == uuid.Nil {
		t.Fatal("no passkey")
	}
	p := newPerson(t, "passkey@example.com")

	code, answer := h.signIn(t, p, 1)
	if code != http.StatusOK || answer.Kind != "link_required" || answer.Email != "passkey@example.com" || answer.Ticket == "" {
		t.Fatalf("sign-in: %d %+v", code, answer)
	}
	// No twin account under that address.
	if code, out, _, _ := h.createAccount(t, answer.Ticket); code != http.StatusUnauthorized || out.Code != "ticket_invalid" {
		t.Fatalf("an account for a link ticket: %d %+v", code, out)
	}
	link := func(path string, body map[string]string) (int, platformAnswer) {
		body["ticket"], body["email"] = answer.Ticket, "passkey@example.com"
		var out platformAnswer
		return h.pagePost(t, path, body, &out, "", nil), out
	}
	if code, out := link("/v1/auth/platform/link/prepare", map[string]string{"auth_key": "wrong"}); code != http.StatusUnauthorized || out.Code != "bad_credentials" {
		t.Fatalf("a wrong password: %d %+v", code, out)
	}
	if n := h.count(t, `SELECT attempts FROM platform_login_tickets WHERE used_at IS NULL`); n != 1 {
		t.Fatalf("attempts %d", n)
	}
	code, prepared := link("/v1/auth/platform/link/prepare", map[string]string{"auth_key": h.account.AuthKey})
	if code != http.StatusOK || prepared.UserID != legacyID || prepared.PublicKey != h.account.PublicKey || prepared.WrappedUSK != h.account.WrappedUSK || prepared.RecoveryWrap != "" {
		t.Fatalf("prepare: %d %+v", code, prepared)
	}
	wrap := randomWrap(t)
	code, linked := link("/v1/auth/platform/link", map[string]string{"auth_key": h.account.AuthKey, "platform_wrap": wrap})
	if code != http.StatusOK || linked.Kind != "session" || linked.User.ID != legacyID || linked.User.AuthSource != "platform" || linked.Token == "" ||
		linked.User.WrappedUSK != "" {
		t.Fatalf("link: %d %+v", code, linked)
	}
	// The old session, and the passkey, are gone.
	if code := h.get(t, "/v1/auth/me", nil, h.signed.Token); code != http.StatusUnauthorized {
		t.Fatalf("the old session after the link: %d", code)
	}
	var live int
	if err := pg.InTx(ctx, h.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.user_id', $1, true)`, legacyID); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM user_passkeys WHERE user_id = $1 AND revoked_at IS NULL`, legacyID).Scan(&live)
	}); err != nil || live != 0 {
		t.Fatalf("live passkeys after the link: %d %v", live, err)
	}
	if code := h.get(t, "/v1/auth/me", nil, linked.Token); code != http.StatusOK {
		t.Fatalf("the new session: %d", code)
	}
	if n := h.count(t, `SELECT count(*) FROM security_events WHERE kind = 'platform_linked' AND user_id = $1 AND sub = $2 AND detail->>'from' = 'legacy'`, legacyID, p.sub); n != 1 {
		t.Fatalf("%d link events", n)
	}

	code, again := h.signIn(t, p, 1)
	if code != http.StatusOK || again.Kind != "session" || again.User.ID != legacyID || again.PlatformWrap != wrap {
		t.Fatalf("signing in after the link: %d %+v", code, again)
	}
	// The sign-in's answer goes to whoever holds an access token for the
	// sub: it never carries the legacy password wrap. /me still hands it to
	// the session, for the password step-ups of steps 1 to 3
	// (docs/platform-sign-in.md, "The rollback window").
	if again.User.WrappedUSK != "" {
		t.Fatal("the sign-in's answer carries the legacy password wrap")
	}
	var me struct {
		User struct {
			WrappedUSK string `json:"wrapped_usk"`
		} `json:"user"`
	}
	if code := h.get(t, "/v1/auth/me", &me, again.Token); code != http.StatusOK || me.User.WrappedUSK != h.account.WrappedUSK {
		t.Fatalf("me of a linked account in the window: %d %+v", code, me)
	}
	// Another id. account cannot take the same Wappie account.
	q := newPerson(t, "someone-else@example.com")
	_, other := h.signIn(t, q, 1)
	var out platformAnswer
	if code := h.pagePost(t, "/v1/auth/platform/link/prepare", map[string]string{"ticket": other.Ticket, "email": "passkey@example.com", "auth_key": h.account.AuthKey}, &out, "", nil); code != http.StatusConflict || out.Code != "already_linked" {
		t.Fatalf("a second link: %d %+v", code, out)
	}
	// Both doors stay open while WS_LOCAL_LOGIN=on: the legacy password
	// still signs the linked account in, until the end of the window.
	if code := h.post(t, "/v1/auth/login", map[string]string{"email": "passkey@example.com", "auth_key": h.account.AuthKey}, nil, ""); code != http.StatusOK {
		t.Fatalf("legacy sign-in of a linked account with local login on: %d", code)
	}
}

func TestPlatformLinkWithTheRecoveryCode(t *testing.T) {
	h := newPlatformHarness(t, config.LocalLoginLinkOnly)
	p := newPerson(t, "another-address@example.com")
	code, answer := h.signIn(t, p, 1)
	if code != http.StatusOK || answer.Kind != "new" {
		t.Fatalf("sign-in: %d %+v", code, answer)
	}
	body := map[string]string{"ticket": answer.Ticket, "email": "passkey@example.com", "recovery_proof": h.account.RecoveryProof}
	var prepared platformAnswer
	if code := h.pagePost(t, "/v1/auth/platform/link/prepare", body, &prepared, "", nil); code != http.StatusOK ||
		prepared.RecoveryWrap != h.account.RecoveryWrap || prepared.WrappedUSK != "" || prepared.UserID != h.signed.User.ID {
		t.Fatalf("prepare: %d %+v", code, prepared)
	}
	body["platform_wrap"] = randomWrap(t)
	var linked platformAnswer
	if code := h.pagePost(t, "/v1/auth/platform/link", body, &linked, "", nil); code != http.StatusOK || linked.User.ID != h.signed.User.ID {
		t.Fatalf("link: %d %+v", code, linked)
	}
	if n := h.count(t, `SELECT count(*) FROM security_events WHERE kind = 'platform_linked' AND detail->>'from' = 'legacy_recovery'`); n != 1 {
		t.Fatalf("%d events", n)
	}
	// Both the auth key and the proof together are refused.
	_, again := h.signIn(t, newPerson(t, "third@example.com"), 1)
	var out platformAnswer
	if code := h.pagePost(t, "/v1/auth/platform/link/prepare", map[string]string{"ticket": again.Ticket, "email": "passkey@example.com", "auth_key": "a", "recovery_proof": "b"}, &out, "", nil); code != http.StatusBadRequest {
		t.Fatalf("both proofs: %d %+v", code, out)
	}
}

func TestPlatformLinkRefusals(t *testing.T) {
	h := newPlatformHarness(t, config.LocalLoginOn)
	ctx := context.Background()
	ticket := func() string {
		_, a := h.signIn(t, newPerson(t, uuid.NewString()+"@example.com"), 1)
		return a.Ticket
	}
	prepare := func(ticket, email, authKey string) (int, platformAnswer) {
		var out platformAnswer
		return h.pagePost(t, "/v1/auth/platform/link/prepare", map[string]string{"ticket": ticket, "email": email, "auth_key": authKey}, &out, "", nil), out
	}

	// A service account has no password to prove.
	invite := h.invite(t, "service")
	var service sessionReply
	if code := h.post(t, "/v1/auth/signup", map[string]string{"invite": invite, "name": "erp", "public_key": randomKey(t)}, &service, ""); code != http.StatusOK {
		t.Fatalf("service: %d", code)
	}
	if code, out := prepare(ticket(), "erp@service."+h.tenant.String(), ""); code != http.StatusBadRequest {
		t.Fatalf("a service with no proof: %d %+v", code, out)
	}
	if code, out := prepare(ticket(), "erp@service."+h.tenant.String(), "x"); code != http.StatusUnauthorized || out.Code != "bad_credentials" {
		t.Fatalf("a service: %d %+v", code, out)
	}

	// Five wrong passwords spend a ticket.
	spent := ticket()
	for range 5 {
		if code, _ := prepare(spent, "passkey@example.com", "wrong"); code != http.StatusUnauthorized {
			t.Fatalf("wrong password: %d", code)
		}
	}
	if code, out := prepare(spent, "passkey@example.com", h.account.AuthKey); code != http.StatusUnauthorized || out.Code != "ticket_invalid" {
		t.Fatalf("a ticket after five failures: %d %+v", code, out)
	}

	// An expired ticket.
	expired := ticket()
	if _, err := h.pool.Exec(ctx, `UPDATE platform_login_tickets SET expires_at = now() - interval '1 second' WHERE used_at IS NULL`); err != nil {
		t.Fatal(err)
	}
	if code, out := prepare(expired, "passkey@example.com", h.account.AuthKey); code != http.StatusUnauthorized || out.Code != "ticket_invalid" {
		t.Fatalf("an expired ticket: %d %+v", code, out)
	}
	if code, out := prepare("not-a-ticket", "passkey@example.com", h.account.AuthKey); code != http.StatusUnauthorized || out.Code != "ticket_invalid" {
		t.Fatalf("a malformed ticket: %d %+v", code, out)
	}

	// A disabled account.
	var tenant uuid.UUID
	if err := h.pool.QueryRow(ctx, `SELECT tenant_id FROM user_logins WHERE user_id = $1`, h.signed.User.ID).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	if err := pg.InTenantTx(ctx, h.pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE users SET status = 'disabled' WHERE id = $1`, h.signed.User.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if code, out := prepare(ticket(), "passkey@example.com", h.account.AuthKey); code != http.StatusUnauthorized || out.Code != "bad_credentials" {
		t.Fatalf("a disabled account: %d %+v", code, out)
	}
	// A wrap of the wrong shape is refused before anything is spent.
	var out platformAnswer
	bad := base64.StdEncoding.EncodeToString(make([]byte, 61))
	if code := h.pagePost(t, "/v1/auth/platform/link", map[string]string{"ticket": ticket(), "email": "passkey@example.com", "auth_key": h.account.AuthKey, "platform_wrap": bad}, &out, "", nil); code != http.StatusBadRequest {
		t.Fatalf("a wrap with version 0: %d %+v", code, out)
	}
}

// Two id. accounts linking the same Wappie account at once: one wins, the
// other is told it is already linked, and nothing of the loser remains.
func TestPlatformConcurrentLinksOfOneAccount(t *testing.T) {
	h := newPlatformHarness(t, config.LocalLoginOn)
	tickets := make([]string, 2)
	for i := range tickets {
		_, a := h.signIn(t, newPerson(t, uuid.NewString()+"@example.com"), 1)
		tickets[i] = a.Ticket
	}
	codes := make([]int, 2)
	var wg sync.WaitGroup
	for i := range tickets {
		wg.Go(func() {
			var out platformAnswer
			codes[i] = h.pagePost(t, "/v1/auth/platform/link", map[string]string{"ticket": tickets[i], "email": "passkey@example.com",
				"auth_key": h.account.AuthKey, "platform_wrap": randomWrap(t)}, &out, "", nil)
		})
	}
	wg.Wait()
	if oneWonOneConflicted := codes[0] == http.StatusOK && codes[1] == http.StatusConflict || codes[0] == http.StatusConflict && codes[1] == http.StatusOK; !oneWonOneConflicted {
		t.Fatalf("codes %v", codes)
	}
	if n := h.count(t, `SELECT count(*) FROM platform_identities`); n != 1 {
		t.Fatalf("%d links", n)
	}
	if n := h.count(t, `SELECT count(*) FROM platform_wraps`); n != 1 {
		t.Fatalf("%d wraps", n)
	}
}

// An address already held by another account linked through the provider
// is not a link hint (that account is not a password account) and cannot
// be taken by a second account.
func TestPlatformNewAccountWithATakenAddress(t *testing.T) {
	h := newPlatformHarness(t, config.LocalLoginOn)
	_, a := h.signIn(t, newPerson(t, "fia@example.com"), 1)
	if code, _, _, _ := h.createAccount(t, a.Ticket); code != http.StatusOK {
		t.Fatalf("first: %d", code)
	}
	code, b := h.signIn(t, newPerson(t, "fia@example.com"), 1)
	if code != http.StatusOK || b.Kind != "new" {
		t.Fatalf("second sign-in: %d %+v", code, b)
	}
	if code, out, _, _ := h.createAccount(t, b.Ticket); code != http.StatusConflict || out.Code != "email_taken" {
		t.Fatalf("second account: %d %+v", code, out)
	}
}

// userinfo's address is the current verified one: an account created
// through the provider follows it; a linked legacy account keeps its own,
// which its legacy wrap is bound to, and the link records the new one.
func TestPlatformAddressFollowsTheProvider(t *testing.T) {
	h := newPlatformHarness(t, config.LocalLoginOn)
	p := newPerson(t, "gil@example.com")
	_, a := h.signIn(t, p, 1)
	if code, _, _, _ := h.createAccount(t, a.Ticket); code != http.StatusOK {
		t.Fatal(code)
	}
	p.email = "gil@new.example.com"
	if code, s := h.signIn(t, p, 1); code != http.StatusOK || s.User.Email != "gil@new.example.com" {
		t.Fatalf("after the address changed: %d %+v", code, s.User)
	}
	if n := h.count(t, `SELECT count(*) FROM platform_identities WHERE sub = $1 AND email = 'gil@new.example.com' AND email_changed_at IS NOT NULL`, p.sub); n != 1 {
		t.Fatal("the link did not record the new address")
	}

	q := newPerson(t, "passkey@example.com")
	_, b := h.signIn(t, q, 1)
	var linked platformAnswer
	if code := h.pagePost(t, "/v1/auth/platform/link", map[string]string{"ticket": b.Ticket, "email": "passkey@example.com", "auth_key": h.account.AuthKey, "platform_wrap": randomWrap(t)}, &linked, "", nil); code != http.StatusOK {
		t.Fatalf("link: %d %+v", code, linked)
	}
	q.email = "moved@example.com"
	if code, s := h.signIn(t, q, 1); code != http.StatusOK || s.User.Email != "passkey@example.com" {
		t.Fatalf("a linked account's address: %d %+v", code, s.User)
	}
}

// A provider epoch the account has no wrap for: the sign-in names the
// account, and a browser signed into it stores the new epoch's wrap.
func TestPlatformRewrapForANewEpoch(t *testing.T) {
	h := newPlatformHarness(t, config.LocalLoginOn)
	p := newPerson(t, "hugo@example.com")
	_, a := h.signIn(t, p, 1)
	_, created, pub, _ := h.createAccount(t, a.Ticket)

	code, r := h.signIn(t, p, 2)
	if code != http.StatusOK || r.Kind != "rewrap_required" || r.Ticket == "" || r.UserID != p.sub || r.PublicKey != pub || r.Pin.ProductKeyID != "wappie:2" || r.Token != "" {
		t.Fatalf("epoch 2: %d %+v", code, r)
	}
	wrap := randomWrap(t)
	if code := h.pagePost(t, "/v1/auth/platform/rewrap", map[string]string{"ticket": r.Ticket, "platform_wrap": wrap}, nil, "", nil); code != http.StatusUnauthorized {
		t.Fatalf("rewrap without a session: %d", code)
	}
	// Another account's session cannot store it.
	_, o := h.signIn(t, newPerson(t, "other@example.com"), 1)
	_, other, _, _ := h.createAccount(t, o.Ticket)
	var out platformAnswer
	if code := h.pagePost(t, "/v1/auth/platform/rewrap", map[string]string{"ticket": r.Ticket, "platform_wrap": wrap}, &out, other.Token, nil); code != http.StatusUnauthorized || out.Code != "ticket_invalid" {
		t.Fatalf("another account's rewrap: %d %+v", code, out)
	}
	// The refused attempt spent nothing: the account's own session stores it.
	if code := h.pagePost(t, "/v1/auth/platform/rewrap", map[string]string{"ticket": r.Ticket, "platform_wrap": wrap}, nil, created.Token, nil); code != http.StatusNoContent {
		t.Fatalf("rewrap: %d", code)
	}
	if code := h.pagePost(t, "/v1/auth/platform/rewrap", map[string]string{"ticket": r.Ticket, "platform_wrap": wrap}, &out, created.Token, nil); code != http.StatusUnauthorized || out.Code != "ticket_invalid" {
		t.Fatalf("a spent rewrap ticket: %d %+v", code, out)
	}
	if code, s := h.signIn(t, p, 2); code != http.StatusOK || s.Kind != "session" || s.PlatformWrap != wrap {
		t.Fatalf("epoch 2 after the rewrap: %d %+v", code, s)
	}
	if code, s := h.signIn(t, p, 1); code != http.StatusOK || s.Kind != "session" || s.PlatformWrap == wrap {
		t.Fatalf("epoch 1 still opens its own wrap: %d %+v", code, s)
	}
}

// WS_LOCAL_LOGIN on every password route: link_only keeps only what the
// link ceremony needs (the challenge; the ceremony proves a recovery code
// at link/prepare, never at /recover/open), off keeps none, and a service's
// registration stays.
func TestLocalLoginModes(t *testing.T) {
	routes := []struct {
		method, path string
		linkOnly     bool
	}{
		{"POST", "/v1/auth/challenge", true},
		{"POST", "/v1/auth/recover/open", false},
		{"POST", "/v1/auth/login", false},
		{"POST", "/v1/auth/signup", false},
		{"POST", "/v1/auth/signup/verification", false},
		{"POST", "/v1/auth/recover/finish", false},
		{"POST", "/v1/auth/password", false},
		{"POST", "/v1/auth/recovery", false},
		{"POST", "/v1/auth/rewrap", false},
		{"GET", "/v1/auth/passkeys", false},
		{"DELETE", "/v1/auth/passkeys/" + uuid.NewString(), false},
		{"POST", "/v1/auth/passkeys/register/options", false},
		{"POST", "/v1/auth/passkeys/register/finish", false},
		{"POST", "/v1/auth/passkeys/login/options", false},
		{"POST", "/v1/auth/passkeys/login/finish", false},
	}
	for _, mode := range []config.LocalLogin{config.LocalLoginOn, config.LocalLoginLinkOnly, config.LocalLoginOff} {
		t.Run(string(mode), func(t *testing.T) {
			h := newPlatformHarness(t, mode)
			for _, r := range routes {
				var out platformAnswer
				body := map[string]string{"email": "passkey@example.com"}
				if r.path == "/v1/auth/signup" {
					body = map[string]string{"email": "new@example.com", "auth_key": "k", "public_key": randomKey(t), "kdf_salt": randomKey(t)[:24], "wrapped_usk": randomKey(t)}
				}
				code := h.request(t, r.method, r.path, passkeyApp, h.signed.Token, body, &out)
				refused := code == http.StatusForbidden && out.Code == "local_login_disabled"
				want := mode == config.LocalLoginOff || mode == config.LocalLoginLinkOnly && !r.linkOnly
				if refused != want {
					t.Errorf("%s %s: %d %+v, refused %v want %v", r.method, r.path, code, out, refused, want)
				}
			}
			// A service registers in every mode: content consents depend on it.
			var service sessionReply
			if code := h.post(t, "/v1/auth/signup", map[string]string{"invite": h.invite(t, "service"), "name": "reader", "public_key": randomKey(t)}, &service, ""); code != http.StatusOK {
				t.Errorf("service registration: %d", code)
			}
			var cfg struct {
				Enabled bool `json:"enabled"`
			}
			if code := h.get(t, "/v1/auth/passkeys/config", &cfg, ""); code != http.StatusOK || cfg.Enabled != (mode == config.LocalLoginOn) {
				t.Errorf("passkeys config: %d %+v", code, cfg)
			}
			// The link needs local login on or link_only.
			_, a := h.signIn(t, newPerson(t, uuid.NewString()+"@example.com"), 1)
			var out platformAnswer
			code := h.pagePost(t, "/v1/auth/platform/link/prepare", map[string]string{"ticket": a.Ticket, "email": "passkey@example.com", "auth_key": h.account.AuthKey}, &out, "", nil)
			if (code == http.StatusForbidden && out.Code == "local_login_disabled") != (mode == config.LocalLoginOff) {
				t.Errorf("link/prepare: %d %+v", code, out)
			}
			// The verified owner of an unlinked password account's address:
			// offered the link while it is open, and told why there is no
			// way in, with no ticket, once it is closed.
			tickets := h.count(t, `SELECT count(*) FROM platform_login_tickets`)
			code, owner := h.signIn(t, newPerson(t, "passkey@example.com"), 1)
			if mode == config.LocalLoginOff {
				if code != http.StatusForbidden || owner.Code != "legacy_account_unlinked" || owner.Ticket != "" || h.count(t, `SELECT count(*) FROM platform_login_tickets`) != tickets {
					t.Errorf("the address of an unlinked password account: %d %+v", code, owner)
				}
			} else if code != http.StatusOK || owner.Kind != "link_required" || owner.Ticket == "" {
				t.Errorf("the address of an unlinked password account: %d %+v", code, owner)
			}
		})
	}
}

// A linked legacy account keeps its old address in the rollback window, so
// an invitation addressed to the provider's verified address is accepted
// by the link's address; one to a third address is still refused.
func TestPlatformLinkedAccountAcceptsAnInvitationToItsProviderAddress(t *testing.T) {
	h := newPlatformHarness(t, config.LocalLoginOn)
	ctx := context.Background()
	p := newPerson(t, "ana@id.example.com")
	_, answer := h.signIn(t, p, 1)
	var linked platformAnswer
	if code := h.pagePost(t, "/v1/auth/platform/link", map[string]string{"ticket": answer.Ticket, "email": "passkey@example.com",
		"auth_key": h.account.AuthKey, "platform_wrap": randomWrap(t)}, &linked, "", nil); code != http.StatusOK {
		t.Fatalf("link: %d %+v", code, linked)
	}
	var beta uuid.UUID
	if err := h.pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('beta') RETURNING id`).Scan(&beta); err != nil {
		t.Fatal(err)
	}
	other, err := h.users.CreateInvite(ctx, beta, "member", "someone@example.com", nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var out platformAnswer
	if code := h.post(t, "/v1/auth/workspaces/accept-invite", map[string]string{"invite": other}, &out, linked.Token); code != http.StatusForbidden || out.Code != "invite_email_mismatch" {
		t.Fatalf("an invitation to a third address: %d %+v", code, out)
	}
	mine, err := h.users.CreateInvite(ctx, beta, "member", "ana@id.example.com", nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var joined struct {
		TenantID string `json:"tenant_id"`
	}
	if code := h.post(t, "/v1/auth/workspaces/accept-invite", map[string]string{"invite": mine}, &joined, linked.Token); code != http.StatusOK || joined.TenantID != beta.String() {
		t.Fatalf("an invitation to the provider's address: %d %+v", code, joined)
	}
}

// The rules of the steps after a sign-in that the other tests do not reach:
// an expired "new" ticket, a member a route does not know, and a disabled
// linked account.
func TestPlatformStepRefusals(t *testing.T) {
	h := newPlatformHarness(t, config.LocalLoginOn)
	ctx := context.Background()

	// A "new" ticket a second past its five minutes creates nothing.
	late := newPerson(t, "late@example.com")
	_, a := h.signIn(t, late, 1)
	if _, err := h.pool.Exec(ctx, `UPDATE platform_login_tickets SET expires_at = now() - interval '1 second' WHERE used_at IS NULL`); err != nil {
		t.Fatal(err)
	}
	if code, out, _, _ := h.createAccount(t, a.Ticket); code != http.StatusUnauthorized || out.Code != "ticket_invalid" || out.Token != "" {
		t.Fatalf("an expired ticket: %d %+v", code, out)
	}
	if n := h.count(t, `SELECT count(*) FROM platform_identities WHERE sub = $1`, late.sub); n != 0 {
		t.Fatalf("an expired ticket linked %d accounts", n)
	}

	// No unknown member: refused before the token goes to userinfo, and
	// before a ticket is read.
	p := newPerson(t, "mia@example.com")
	before := h.id.requests.Load()
	var out platformAnswer
	if code := h.pagePost(t, "/v1/auth/platform/session", map[string]string{"access_token": h.id.issue(t, p.userinfo(t, 1)), "sub": p.sub}, &out, "", nil); code != http.StatusBadRequest || out.Code != "bad_request" || h.id.requests.Load() != before {
		t.Fatalf("an unknown member at session: %d %+v, userinfo %d", code, out, h.id.requests.Load()-before)
	}
	_, b := h.signIn(t, p, 1)
	if code := h.pagePost(t, "/v1/auth/platform/account", map[string]string{"ticket": b.Ticket, "public_key": randomKey(t), "platform_wrap": randomWrap(t), "role": "admin"}, &out, "", nil); code != http.StatusBadRequest || out.Code != "bad_request" {
		t.Fatalf("an unknown member at account: %d %+v", code, out)
	}

	// The ticket the refusal did not read still makes the account; then the
	// account is disabled, and its next sign-in is refused with no session.
	if code, _, _, _ := h.createAccount(t, b.Ticket); code != http.StatusOK {
		t.Fatalf("account: %d", code)
	}
	var home uuid.UUID
	if err := h.pool.QueryRow(ctx, `SELECT tenant_id FROM user_logins WHERE user_id = $1`, p.sub).Scan(&home); err != nil {
		t.Fatal(err)
	}
	if err := pg.InTenantTx(ctx, h.pool, home.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE users SET status = 'disabled' WHERE id = $1`, p.sub)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	sessions := h.count(t, `SELECT count(*) FROM sessions WHERE user_id = $1`, p.sub)
	if code, out := h.signIn(t, p, 1); code != http.StatusForbidden || out.Code != "account_disabled" || out.Token != "" || out.PlatformWrap != "" {
		t.Fatalf("a disabled account: %d %+v", code, out)
	}
	if n := h.count(t, `SELECT count(*) FROM sessions WHERE user_id = $1`, p.sub); n != sessions {
		t.Fatalf("a disabled account got a session: %d -> %d", sessions, n)
	}
}

// The link checks the proof again when it links: a password changed, or an
// account disabled, after link/prepare links nothing.
func TestPlatformLinkAfterTheAccountChanged(t *testing.T) {
	ctx := context.Background()
	for name, change := range map[string]func(h *platformHarness){
		"a new password": func(h *platformHarness) {
			if code := h.post(t, "/v1/auth/password", map[string]any{"auth_key": h.account.AuthKey, "new": fresh(t, "second", "w2", "", "")}, nil, h.signed.Token); code != http.StatusOK {
				t.Fatalf("password change: %d", code)
			}
		},
		"a disabled account": func(h *platformHarness) {
			var home uuid.UUID
			if err := h.pool.QueryRow(ctx, `SELECT tenant_id FROM user_logins WHERE user_id = $1`, h.signed.User.ID).Scan(&home); err != nil {
				t.Fatal(err)
			}
			if err := pg.InTenantTx(ctx, h.pool, home.String(), func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `UPDATE users SET status = 'disabled' WHERE id = $1`, h.signed.User.ID)
				return err
			}); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newPlatformHarness(t, config.LocalLoginOn)
			_, a := h.signIn(t, newPerson(t, "passkey@example.com"), 1)
			body := map[string]string{"ticket": a.Ticket, "email": "passkey@example.com", "auth_key": h.account.AuthKey}
			if code := h.pagePost(t, "/v1/auth/platform/link/prepare", body, nil, "", nil); code != http.StatusOK {
				t.Fatalf("prepare: %d", code)
			}
			change(h)
			body["platform_wrap"] = randomWrap(t)
			var out platformAnswer
			if code := h.pagePost(t, "/v1/auth/platform/link", body, &out, "", nil); code != http.StatusUnauthorized || out.Code != "bad_credentials" || out.Token != "" {
				t.Fatalf("link: %d %+v", code, out)
			}
			if n := h.count(t, `SELECT count(*) FROM platform_identities`); n != 0 {
				t.Fatalf("%d links", n)
			}
		})
	}
}

// The platform routes spend the address limit (session) and the address
// and account limits (link/prepare), beside the ticket's five attempts.
func TestPlatformRoutesAreRateLimited(t *testing.T) {
	h := newPlatformHarness(t, config.LocalLoginOn)
	p := newPerson(t, "nia@example.com")
	h.handler.Limits = &ratelimit.Auth{PerIP: ratelimit.New(1, 2)}
	for range 2 {
		if code, out := h.signIn(t, p, 1); code != http.StatusOK {
			t.Fatalf("within the limit: %d %+v", code, out)
		}
	}
	before := h.id.requests.Load()
	if code, out := h.signIn(t, p, 1); code != http.StatusTooManyRequests || out.Code != "rate_limited" || h.id.requests.Load() != before {
		t.Fatalf("past the address limit: %d %+v, userinfo %d", code, out, h.id.requests.Load()-before)
	}

	h.handler.Limits = &ratelimit.Auth{PerIP: ratelimit.New(60, 100), PerSubject: ratelimit.New(1, 2)}
	prepare := func(ticket string) (int, platformAnswer) {
		var out platformAnswer
		return h.pagePost(t, "/v1/auth/platform/link/prepare", map[string]string{"ticket": ticket, "email": "passkey@example.com", "auth_key": "wrong"}, &out, "", nil), out
	}
	_, a := h.signIn(t, newPerson(t, "oto@example.com"), 1)
	for range 2 {
		if code, out := prepare(a.Ticket); code != http.StatusUnauthorized || out.Code != "bad_credentials" {
			t.Fatalf("a wrong password within the limit: %d %+v", code, out)
		}
	}
	if code, out := prepare(a.Ticket); code != http.StatusTooManyRequests || out.Code != "rate_limited" {
		t.Fatalf("past the account limit: %d %+v", code, out)
	}
	// The account's limit holds across tickets, and a refusal by it costs
	// the ticket no attempt.
	_, b := h.signIn(t, newPerson(t, "pia@example.com"), 1)
	if code, out := prepare(b.Ticket); code != http.StatusTooManyRequests || out.Code != "rate_limited" {
		t.Fatalf("another ticket past the account limit: %d %+v", code, out)
	}
	if n := h.count(t, `SELECT max(attempts) FROM platform_login_tickets`); n != 2 {
		t.Fatalf("attempts %d", n)
	}
}
