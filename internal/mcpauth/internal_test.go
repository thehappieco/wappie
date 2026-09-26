package mcpauth

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/store"
)

// The replay cache refuses a nonce it holds, forgets one once its timestamp
// could no longer pass, and fails closed when full of live nonces.
func TestReplayCache(t *testing.T) {
	now := time.Unix(1_790_300_000, 0)
	c := newReplayCache(2)
	if err := c.admit(DirectionToGo, "enclave", "a", now.Unix(), now); err != nil {
		t.Fatal(err)
	}
	if err := c.admit(DirectionToGo, "enclave", "a", now.Unix(), now); !errors.Is(err, errReplay) {
		t.Fatalf("same nonce: %v", err)
	}
	// The key includes direction and reader.
	if err := c.admit(DirectionToReader, "enclave", "a", now.Unix(), now); err != nil {
		t.Fatalf("other direction: %v", err)
	}
	if err := c.admit(DirectionToGo, "staging", "a", now.Unix(), now); !errors.Is(err, errReplayFull) {
		t.Fatalf("a third live nonce in a cache of two: %v", err)
	}
	// Sixty-one seconds on, every entry has lapsed and the sweep frees room.
	later := now.Add(61 * time.Second)
	if err := c.admit(DirectionToGo, "staging", "a", later.Unix(), later); err != nil {
		t.Fatalf("after the entries lapsed: %v", err)
	}
	if err := c.admit(DirectionToGo, "enclave", "a", later.Unix(), later); err != nil {
		t.Fatalf("a lapsed nonce is new again: %v", err)
	}
	if len(c.seen) != 2 {
		t.Fatalf("cache holds %d entries after the sweep", len(c.seen))
	}
}

// A full replay cache answers 503 to a request that is otherwise good.
func TestReplayCacheFullAnswers503(t *testing.T) {
	h := &Handler{
		Attested: []*AttestedReader{{ID: "enclave", Secrets: []string{"s"}, Peers: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}},
		Log:      slog.New(slog.DiscardHandler),
	}
	mux := http.NewServeMux()
	h.Mount(mux)
	h.replay = newReplayCache(1)
	send := func(nonce string) int {
		ts := time.Now().Unix()
		req := httptest.NewRequest(http.MethodPost, "/v1/mcp/enclave/connections/not-a-uuid/revoke", nil)
		req.RemoteAddr = "127.0.0.1:1"
		req.Header.Set(HeaderReader, "enclave")
		req.Header.Set(HeaderTimestamp, itoa(ts))
		req.Header.Set(HeaderNonce, nonce)
		req.Header.Set(HeaderSignature, Signature("s", DirectionToGo, "enclave", "POST", req.RequestURI, itoa(ts), nonce, nil))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code == http.StatusServiceUnavailable && !strings.Contains(w.Body.String(), `"replay_cache_full"`) {
			t.Fatalf("503 without its code: %s", w.Body)
		}
		return w.Code
	}
	// The first passes the guard and the route answers 404 for a bad id.
	if code := send(strings.Repeat("A", 22)); code != http.StatusNotFound {
		t.Fatalf("first: %d", code)
	}
	if code := send(strings.Repeat("B", 22)); code != http.StatusServiceUnavailable {
		t.Fatalf("second: %d", code)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// The request map expires entries, and when full forgets the one closest to
// expiry rather than refusing to learn a new request.
func TestRequestCacheBounds(t *testing.T) {
	c := newRequestCache()
	now := time.Now()
	c.put("old", requestEntry{reader: "hosted"}, now.Add(-requestTTL))
	if _, ok := c.get("old", now); ok {
		t.Fatal("an expired entry was returned")
	}
	for i := range requestCap {
		c.put(itoa(int64(i)), requestEntry{reader: "enclave"}, now.Add(time.Duration(i)*time.Millisecond))
	}
	c.put("new", requestEntry{reader: "enclave", prepared: true, kid: "k"}, now.Add(time.Hour))
	if len(c.entries) > requestCap {
		t.Fatalf("map grew to %d", len(c.entries))
	}
	if e, ok := c.get("new", now.Add(time.Hour)); !ok || !e.prepared || e.kid != "k" {
		t.Fatalf("new entry = %+v %v", e, ok)
	}
	if _, ok := c.entries["old"]; ok {
		t.Fatal("the expired entry survived a sweep")
	}
	if _, ok := c.entries["0"]; ok {
		t.Fatal("the entry closest to expiry survived a full map")
	}
}

// capture collects log records for the health test.
type capture struct {
	records []slog.Record
}

func (c *capture) Enabled(context.Context, slog.Level) bool { return true }
func (c *capture) Handle(_ context.Context, r slog.Record) error {
	c.records = append(c.records, r)
	return nil
}
func (c *capture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *capture) WithGroup(string) slog.Handler      { return c }

func (c *capture) last() (slog.Level, string, map[string]string) {
	r := c.records[len(c.records)-1]
	attrs := map[string]string{}
	r.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.String()
		return true
	})
	return r.Level, r.Message, attrs
}

// The health check logs fingerprints, never whole values it does not need,
// warns after three misses in a row and when the certificate is short.
func TestCheckReader(t *testing.T) {
	answer := `{}`
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		//nolint:errcheck // test server
		_, _ = w.Write([]byte(answer))
	}))
	t.Cleanup(srv.Close)
	logs := &capture{}
	h := &Handler{Log: slog.New(logs)}
	a := &AttestedReader{ID: "enclave", Relay: &SignedRelay{ReaderID: "enclave", BaseURL: srv.URL, Secret: "s", Client: srv.Client()}}
	ctx := context.Background()

	health := func(days int) string {
		b, err := json.Marshal(map[string]any{
			"ok": true, "reader_id": "enclave", "reader_version": "0.2.0", "boot_id": "0011223344556677", "state": "ready",
			"pcr0": strings.Repeat("ab", 48), "tls_spki_sha256": strings.Repeat("cd", 32), "policy_sha256": strings.Repeat("ef", 32),
			"cert_not_after": time.Now().Add(time.Duration(days)*24*time.Hour + time.Hour), "relay_secrets": 2,
		})
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	answer = health(60)
	if failures := h.checkReader(ctx, a, 0); failures != 0 {
		t.Fatalf("failures = %d", failures)
	}
	level, _, attrs := logs.last()
	if level != slog.LevelInfo || attrs["pcr0"] != strings.Repeat("ab", 6) || attrs["spki"] != strings.Repeat("cd", 6) ||
		attrs["policy"] != strings.Repeat("ef", 6) || attrs["cert_days_left"] != "60" || attrs["relay_secrets"] != "2" {
		t.Fatalf("health line = %v %v", level, attrs)
	}

	status, answer = http.StatusServiceUnavailable, `{"code":"starting"}`
	failures := 0
	for i := 1; i <= 3; i++ {
		failures = h.checkReader(ctx, a, failures)
		want := slog.LevelInfo
		if i == healthFailures {
			want = slog.LevelWarn
		}
		if level, _, _ := logs.last(); level != want {
			t.Fatalf("miss %d logged at %v, want %v", i, level, want)
		}
	}
	if failures != 3 {
		t.Fatalf("failures = %d", failures)
	}

	status, answer = http.StatusOK, health(10)
	if failures = h.checkReader(ctx, a, failures); failures != 0 {
		t.Fatalf("failures after recovery = %d", failures)
	}
	if level, msg, _ := logs.last(); level != slog.LevelWarn || !strings.Contains(msg, "expiry") {
		t.Fatalf("a ten-day certificate: %v %q", level, msg)
	}
}

// A connection's standing carries its expiry in UTC, for the hosted and the
// attested reply alike, whatever zone the database driver handed it in.
func TestStandingReplyExpiryIsUTC(t *testing.T) {
	zone := time.FixedZone("UTC+2", 2*60*60)
	at := time.Date(2026, 10, 26, 14, 30, 0, 0, zone)
	service := uuid.New()
	for name, attested := range map[string]bool{"hosted": false, "attested": true} {
		raw, err := json.Marshal(standingReply(store.StatusAnswer{Status: "active", ExpiresAt: at, Kind: "content", ServiceUserID: &service}, attested))
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]any
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatal(err)
		}
		if got["expires_at"] != "2026-10-26T12:30:00Z" {
			t.Fatalf("%s: expires_at = %v", name, got["expires_at"])
		}
		if _, carries := got["service_user_id"]; carries != attested {
			t.Fatalf("%s: reply = %s", name, raw)
		}
	}
}
