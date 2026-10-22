package authapi_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"sync"
	"testing"

	"whatserver2/internal/authapi"
	"whatserver2/internal/store"
)

// The labels the consoles send are the fixture's, which the cloud console's
// test reads too: a source added on one side only is logged as "other".
func TestLogoutSourcesFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/logout-sources.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Header  string   `json:"header"`
		Sources []string `json:"sources"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Header != authapi.LogoutSourceHeader || !slices.Equal(fixture.Sources, authapi.LogoutSources) {
		t.Fatalf("fixture %+v, handler %s %v", fixture, authapi.LogoutSourceHeader, authapi.LogoutSources)
	}
	if slices.Contains(fixture.Sources, "other") {
		t.Fatal(`"other" is what an unknown source is logged as, never a source of its own`)
	}
}

// signedOut is one "signed out" line, as the handler logged it.
type signedOut struct {
	source     string
	allRelated bool
	revoked    int64
	user       string
}

// logLines keeps the "signed out" records a handler logs.
type logLines struct {
	mu    sync.Mutex
	lines []signedOut
}

func (l *logLines) Enabled(context.Context, slog.Level) bool { return true }
func (l *logLines) WithAttrs([]slog.Attr) slog.Handler       { return l }
func (l *logLines) WithGroup(string) slog.Handler            { return l }
func (l *logLines) Handle(_ context.Context, r slog.Record) error {
	if r.Message != "signed out" || r.Level != slog.LevelInfo {
		return nil
	}
	var line signedOut
	r.Attrs(func(a slog.Attr) bool {
		switch a.Key {
		case "source":
			line.source = a.Value.String()
		case "all_related":
			line.allRelated = a.Value.Bool()
		case "revoked":
			line.revoked = a.Value.Int64()
		case "user":
			line.user = a.Value.String()
		}
		return true
	})
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, line)
	return nil
}

// take returns the lines logged since the last take.
func (l *logLines) take() []signedOut {
	l.mu.Lock()
	defer l.mu.Unlock()
	lines := l.lines
	l.lines = nil
	return lines
}

// newLoggedHarness is newHarness with a handler that logs into the lines returned.
func newLoggedHarness(t *testing.T) (*harness, *logLines) {
	t.Helper()
	h := newHarness(t)
	logs := &logLines{}
	mux := http.NewServeMux()
	(&authapi.Handler{Users: h.users, Keys: h.keys, Devices: store.NewDevices(h.pool), Storage: store.NewStorage(h.pool), Log: slog.New(logs)}).Mount(mux)
	h.srv.Close()
	h.srv = httptest.NewServer(mux)
	t.Cleanup(h.srv.Close)
	return h, logs
}

// logout posts body to /v1/auth/logout with the given source headers (none for nil).
func logout(t *testing.T, h *harness, token string, body any, sources ...string) int {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, h.srv.URL+"/v1/auth/logout", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for _, source := range sources {
		req.Header.Add(authapi.LogoutSourceHeader, source)
	}
	return h.do(t, req, nil)
}

// A full sign-out says who asked: the console sends the button's label as a
// header, and the server logs it, checked against the list, with what the
// logout ended. Never from the body, which an older server would refuse.
func TestLogoutSaysWhoAsked(t *testing.T) {
	h, logs := newLoggedHarness(t)
	body, signed := browserAccount(t, h)
	login := func() string {
		t.Helper()
		var in sessionReply
		if code := h.post(t, "/v1/auth/login", map[string]string{"email": body.Email, "auth_key": body.AuthKey}, &in, ""); code != http.StatusOK {
			t.Fatalf("login: %d", code)
		}
		return in.Token
	}
	user := signed.User.ID
	logs.take()

	cases := map[string]struct {
		headers []string
		want    string
	}{
		"none":      {nil, "other"},
		"empty":     {[]string{""}, "other"},
		"unknown":   {[]string{"sidebar"}, "other"},
		"cased":     {[]string{"Chatlist"}, "other"},
		"listed":    {[]string{"chatlist, admin"}, "other"},
		"two":       {[]string{"chatlist", "chatlist"}, "other"},
		"the other": {[]string{"other"}, "other"},
	}
	for _, source := range authapi.LogoutSources {
		cases[source] = struct {
			headers []string
			want    string
		}{[]string{source}, source}
	}
	for name, c := range cases {
		if code := logout(t, h, login(), map[string]any{}, c.headers...); code != http.StatusNoContent {
			t.Fatalf("%s: logout %d", name, code)
		}
		want := []signedOut{{source: c.want, revoked: 1, user: user}}
		if got := logs.take(); !slices.Equal(got, want) {
			t.Fatalf("%s: logged %+v, want %+v", name, got, want)
		}
	}

	// The browser's family: the sign-in and the two workspace tokens it
	// minted, then nothing on a repeat.
	target := browserSecondWorkspace(t, h, signed.Token)
	first := browserSwitch(t, h, signed.Token, target)
	browserSwitch(t, h, first.Token, h.tenant)
	logs.take()
	if code := logout(t, h, signed.Token, map[string]bool{"all_related": true}, "chatlist"); code != http.StatusNoContent {
		t.Fatalf("family logout: %d", code)
	}
	if code := logout(t, h, signed.Token, map[string]bool{"all_related": true}, "chatlist"); code != http.StatusNoContent {
		t.Fatalf("repeated family logout: %d", code)
	}
	if got, want := logs.take(), []signedOut{{"chatlist", true, 3, user}, {"chatlist", true, 0, user}}; !slices.Equal(got, want) {
		t.Fatalf("family logouts logged %+v, want %+v", got, want)
	}

	// A token that names no session is still a 204, logged as nobody's.
	for _, token := range []string{"malformed", base64.RawURLEncoding.EncodeToString(make([]byte, 32))} {
		if code := logout(t, h, token, map[string]bool{"all_related": true}, "admin"); code != http.StatusNoContent {
			t.Fatalf("unknown token: %d", code)
		}
	}
	if got, want := logs.take(), []signedOut{{"admin", true, 0, ""}, {"admin", true, 0, ""}}; !slices.Equal(got, want) {
		t.Fatalf("unknown tokens logged %+v, want %+v", got, want)
	}

	// Without a bearer there is nothing to log; the source in the body is
	// still a malformed request, and its session is kept.
	if code := logout(t, h, "", map[string]bool{"all_related": true}, "chatlist"); code != http.StatusNoContent {
		t.Fatalf("bearer-less logout: %d", code)
	}
	kept := login()
	logs.take()
	if code := logout(t, h, kept, map[string]any{"all_related": true, "source": "chatlist"}, "chatlist"); code != http.StatusBadRequest {
		t.Fatalf("a body naming its source: %d, want 400", code)
	}
	if got := logs.take(); len(got) != 0 {
		t.Fatalf("logged %+v for a refused or bearer-less logout", got)
	}
	if _, err := h.users.Session(context.Background(), kept); err != nil {
		t.Fatalf("a refused logout ended the session: %v", err)
	}
}
