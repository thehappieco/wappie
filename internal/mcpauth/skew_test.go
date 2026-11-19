package mcpauth

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	clockLine     = "an attested reader's clock is off"
	clockLineFree = "an attested reader's clock is off (unauthenticated)"
	healthz401    = "an attested reader refused this server's signed health check; a clock skew beyond the limit is the likely cause"
)

// lines are the captured records with a message, with their attributes.
func (c *capture) lines(msg string) []capturedLine {
	var out []capturedLine
	for _, r := range c.records {
		if r.Message != msg {
			continue
		}
		attrs := map[string]string{}
		r.Attrs(func(a slog.Attr) bool {
			attrs[a.Key] = a.Value.String()
			return true
		})
		out = append(out, capturedLine{level: r.Level, attrs: attrs})
	}
	return out
}

type capturedLine struct {
	level slog.Level
	attrs map[string]string
}

// An authenticated gap inside ten seconds logs nothing, from ten a warning
// and from thirty an error, either way of this server's clock.
func TestReaderClockLevels(t *testing.T) {
	now := time.Unix(1_795_000_000, 0)
	for _, tc := range []struct {
		skew  int64
		level slog.Level
		logs  bool
	}{
		{0, 0, false},
		{-9, 0, false},
		{9, 0, false},
		{10, slog.LevelWarn, true},
		{-10, slog.LevelWarn, true},
		{29, slog.LevelWarn, true},
		{30, slog.LevelError, true},
		{-30, slog.LevelError, true},
		{65, slog.LevelError, true},
		{-65, slog.LevelError, true},
	} {
		logs := &capture{}
		h := &Handler{Log: slog.New(logs), clocks: newReaderClocks()}
		h.noteReaderClock(context.Background(), &AttestedReader{ID: "enclave"}, now.Unix()+tc.skew, now)
		got := logs.lines(clockLine)
		if !tc.logs {
			if len(logs.records) != 0 {
				t.Fatalf("skew %d s logged %d lines", tc.skew, len(logs.records))
			}
			continue
		}
		if len(got) != 1 || len(logs.records) != 1 {
			t.Fatalf("skew %d s: %d clock lines of %d", tc.skew, len(got), len(logs.records))
		}
		want := map[string]string{"reader": "enclave", "skew_s": strconv.FormatInt(tc.skew, 10), "authenticated": "true", "limit_s": "60"}
		if got[0].level != tc.level || !sameAttrs(got[0].attrs, want) {
			t.Fatalf("skew %d s: %v %v, want %v %v", tc.skew, got[0].level, got[0].attrs, tc.level, want)
		}
	}
}

func sameAttrs(got, want map[string]string) bool {
	if len(got) != len(want) {
		return false
	}
	for k, v := range want {
		if got[k] != v {
			return false
		}
	}
	return true
}

// One reader's clock is logged at most once in ten minutes per level, and
// separately for each reader and for signed and claimed gaps.
func TestReaderClockRateLimit(t *testing.T) {
	t0 := time.Unix(1_795_000_000, 0)
	logs := &capture{}
	h := &Handler{Log: slog.New(logs), clocks: newReaderClocks()}
	enclave, staging := &AttestedReader{ID: "enclave"}, &AttestedReader{ID: "staging"}
	ctx := context.Background()
	signed := func(a *AttestedReader, at time.Duration, skew int64) {
		now := t0.Add(at)
		h.noteReaderClock(ctx, a, now.Unix()+skew, now)
	}
	stale := func(a *AttestedReader, at time.Duration, skew int64) {
		now := t0.Add(at)
		header := http.Header{}
		header.Set(HeaderTimestamp, itoa(now.Unix()+skew))
		h.noteStaleClock(ctx, a, header, now)
	}
	count := func(msg string, level slog.Level, reader string) int {
		n := 0
		for _, l := range logs.lines(msg) {
			if l.level == level && l.attrs["reader"] == reader {
				n++
			}
		}
		return n
	}
	check := func(step string, msg string, level slog.Level, reader string, want int) {
		t.Helper()
		if got := count(msg, level, reader); got != want {
			t.Fatalf("%s: %d %v lines for %s, want %d", step, got, level, reader, want)
		}
	}

	signed(enclave, 0, 12)
	check("first warning", clockLine, slog.LevelWarn, "enclave", 1)
	signed(enclave, time.Minute, 12)
	signed(enclave, 9*time.Minute+59*time.Second, 15)
	check("within ten minutes", clockLine, slog.LevelWarn, "enclave", 1)
	signed(enclave, 2*time.Minute, 35)
	check("an error is its own level", clockLine, slog.LevelError, "enclave", 1)
	signed(enclave, 3*time.Minute, 40)
	check("the error within ten minutes", clockLine, slog.LevelError, "enclave", 1)
	signed(staging, time.Minute, 12)
	check("another reader", clockLine, slog.LevelWarn, "staging", 1)
	stale(enclave, 3*time.Minute, 65)
	check("a claimed gap is its own kind", clockLineFree, slog.LevelError, "enclave", 1)
	stale(enclave, 4*time.Minute, 66)
	check("the claimed gap within ten minutes", clockLineFree, slog.LevelError, "enclave", 1)
	signed(enclave, 10*time.Minute, 12)
	check("ten minutes on", clockLine, slog.LevelWarn, "enclave", 2)
	stale(enclave, 13*time.Minute, 70)
	check("the claimed gap ten minutes on", clockLineFree, slog.LevelError, "enclave", 2)
	if n := len(logs.records); n != 6 {
		t.Fatalf("%d lines in all, want 6", n)
	}
}

// signedRequest sends one request to the guard with the reader's timestamp
// at the given gap from now, signed with secret.
func signedRequest(t *testing.T, mux *http.ServeMux, secret string, skew time.Duration, nonce string) int {
	t.Helper()
	ts := itoa(time.Now().Add(skew).Unix())
	req := httptest.NewRequest(http.MethodPost, "/v1/mcp/enclave/connections/not-a-uuid/revoke", nil)
	req.RemoteAddr = "127.0.0.1:1"
	req.Header.Set(HeaderReader, "enclave")
	req.Header.Set(HeaderTimestamp, ts)
	req.Header.Set(HeaderNonce, nonce)
	req.Header.Set(HeaderSignature, Signature(secret, DirectionToGo, "enclave", "POST", req.RequestURI, ts, nonce, nil))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w.Code
}

// The guard reads the gap off a request only once its signature checks, and
// a stale request's claimed gap is logged as unauthenticated next to its 401.
func TestSignedGuardLogsReaderClock(t *testing.T) {
	logs := &capture{}
	h := &Handler{
		Attested: []*AttestedReader{{ID: "enclave", Secrets: []string{"s"}, Peers: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}},
		Log:      slog.New(logs),
	}
	mux := http.NewServeMux()
	h.Mount(mux)
	within := func(got string, lo, hi int64) bool {
		n, err := strconv.ParseInt(got, 10, 64)
		return err == nil && n >= lo && n <= hi
	}

	// Inside ten seconds: through the guard (the route answers 404 for a
	// bad id) and no clock line.
	if code := signedRequest(t, mux, "s", -5*time.Second, strings.Repeat("A", 22)); code != http.StatusNotFound {
		t.Fatalf("a request five seconds behind: %d", code)
	}
	if n := len(logs.lines(clockLine)); n != 0 {
		t.Fatalf("five seconds logged %d clock lines", n)
	}

	// A bad signature in the window says nothing about the clock.
	if code := signedRequest(t, mux, "not-the-secret", 35*time.Second, strings.Repeat("B", 22)); code != http.StatusUnauthorized {
		t.Fatalf("a bad signature: %d", code)
	}
	if n := len(logs.lines(clockLine)) + len(logs.lines(clockLineFree)); n != 0 {
		t.Fatalf("an unsigned gap logged %d clock lines", n)
	}

	// Signed, thirty-five seconds ahead: an error, authenticated.
	if code := signedRequest(t, mux, "s", 35*time.Second, strings.Repeat("C", 22)); code != http.StatusNotFound {
		t.Fatalf("a request thirty-five seconds ahead: %d", code)
	}
	got := logs.lines(clockLine)
	if len(got) != 1 || got[0].level != slog.LevelError || got[0].attrs["authenticated"] != "true" ||
		got[0].attrs["reader"] != "enclave" || !within(got[0].attrs["skew_s"], 34, 35) {
		t.Fatalf("clock lines = %+v", got)
	}

	// Sixty-five seconds ahead: refused, and the claim is logged as such.
	if code := signedRequest(t, mux, "s", 65*time.Second, strings.Repeat("D", 22)); code != http.StatusUnauthorized {
		t.Fatalf("a request sixty-five seconds ahead: %d", code)
	}
	refused := logs.lines("a signed reader request was refused")
	if len(refused) == 0 || refused[len(refused)-1].attrs["code"] != "hmac_stale" {
		t.Fatalf("refusals = %+v", refused)
	}
	free := logs.lines(clockLineFree)
	if len(free) != 1 || free[0].level != slog.LevelError || free[0].attrs["authenticated"] != "false" ||
		!within(free[0].attrs["skew_s"], 64, 65) || free[0].attrs["limit_s"] != "60" {
		t.Fatalf("unauthenticated lines = %+v", free)
	}
	// The latest reading is the claimed one, and says so.
	if r, ok := h.clocks.latest("enclave"); !ok || r.authenticated || r.seconds < 64 {
		t.Fatalf("latest reading = %+v %v", r, ok)
	}
}

// readerHealthJSON is a ready reader's health object.
func readerHealthJSON(t *testing.T) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"ok": true, "reader_id": "enclave", "reader_version": "0.6.0", "boot_id": "0011223344556677", "state": "ready",
		"pcr0": strings.Repeat("ab", 48), "tls_spki_sha256": strings.Repeat("cd", 32), "policy_sha256": strings.Repeat("ef", 32),
		"cert_not_after": time.Now().Add(60 * 24 * time.Hour), "relay_secrets": 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The health line carries the last reading and whether it was signed, and
// nothing about the clock before there is one.
func TestHealthLineCarriesReaderClock(t *testing.T) {
	answer := readerHealthJSON(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		//nolint:errcheck // test server
		_, _ = w.Write([]byte(answer))
	}))
	t.Cleanup(srv.Close)
	logs := &capture{}
	h := &Handler{Log: slog.New(logs), clocks: newReaderClocks()}
	a := &AttestedReader{ID: "enclave", Relay: &SignedRelay{ReaderID: "enclave", BaseURL: srv.URL, Secret: "s", Client: srv.Client()}}
	ctx := context.Background()

	h.checkReader(ctx, a, 0)
	level, msg, attrs := logs.last()
	if level != slog.LevelInfo || msg != "attested reader health" {
		t.Fatalf("health line = %v %q", level, msg)
	}
	for _, k := range []string{"clock_skew_s", "clock_skew_authenticated", "clock_skew_age_s"} {
		if _, ok := attrs[k]; ok {
			t.Fatalf("a reader never heard from has %s: %v", k, attrs)
		}
	}

	at := time.Now().Add(-30 * time.Second)
	h.clocks.note("enclave", skewReading{seconds: 7, authenticated: true, at: at})
	h.checkReader(ctx, a, 0)
	_, _, attrs = logs.last()
	age, err := strconv.Atoi(attrs["clock_skew_age_s"])
	if attrs["clock_skew_s"] != "7" || attrs["clock_skew_authenticated"] != "true" || err != nil || age < 30 || age > 40 {
		t.Fatalf("health line with a signed reading = %v", attrs)
	}

	h.clocks.note("enclave", skewReading{seconds: 65, authenticated: false, at: time.Now()})
	h.checkReader(ctx, a, 0)
	if _, _, attrs = logs.last(); attrs["clock_skew_s"] != "65" || attrs["clock_skew_authenticated"] != "false" {
		t.Fatalf("health line with a later claimed reading = %v", attrs)
	}
}

// A 401 to the health check names the clock as the likely cause, with what
// is known of it, at most once in ten minutes; another failure does not.
func TestHealthz401NamesTheClock(t *testing.T) {
	status := http.StatusUnauthorized
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		//nolint:errcheck // test server
		_, _ = w.Write([]byte(`{"code":"unauthorized"}`))
	}))
	t.Cleanup(srv.Close)
	logs := &capture{}
	h := &Handler{Log: slog.New(logs), clocks: newReaderClocks()}
	a := &AttestedReader{ID: "enclave", Relay: &SignedRelay{ReaderID: "enclave", BaseURL: srv.URL, Secret: "s", Client: srv.Client()}}
	ctx := context.Background()

	// Nothing known yet: the line names the cause and the limit only.
	failures := h.checkReader(ctx, a, 0)
	got := logs.lines(healthz401)
	if failures != 1 || len(got) != 1 || got[0].level != slog.LevelWarn ||
		!sameAttrs(got[0].attrs, map[string]string{"reader": "enclave", "limit_s": "60"}) {
		t.Fatalf("first 401: failures %d, lines %+v", failures, got)
	}
	// The miss itself is still logged as before.
	if misses := logs.lines("an attested reader missed a health check"); len(misses) != 1 {
		t.Fatalf("miss lines = %+v", misses)
	}

	// Within ten minutes: no second line.
	failures = h.checkReader(ctx, a, failures)
	if got := logs.lines(healthz401); len(got) != 1 {
		t.Fatalf("second 401 logged again: %+v", got)
	}

	// Ten minutes on, with a signed and a claimed reading.
	now := time.Now()
	h.clocks.note("enclave", skewReading{seconds: 58, authenticated: true, at: now.Add(-5 * time.Minute)})
	h.clocks.note("enclave", skewReading{seconds: 65, authenticated: false, at: now.Add(-time.Minute)})
	h.noteHealthzRefused(ctx, a, now.Add(10*time.Minute+time.Second))
	got = logs.lines(healthz401)
	if len(got) != 2 {
		t.Fatalf("ten minutes on: %+v", got)
	}
	if want := map[string]string{
		"reader": "enclave", "limit_s": "60", "last_authenticated_skew_s": "58", "last_authenticated_skew_age_s": "901",
		"last_unauthenticated_skew_s": "65", "last_unauthenticated_skew_age_s": "661",
	}; !sameAttrs(got[1].attrs, want) {
		t.Fatalf("line with readings = %v, want %v", got[1].attrs, want)
	}

	// A 503 is a reader that is starting or down, not a refusal.
	fresh := &capture{}
	h = &Handler{Log: slog.New(fresh), clocks: newReaderClocks()}
	status = http.StatusServiceUnavailable
	h.checkReader(ctx, a, 0)
	if got := fresh.lines(healthz401); len(got) != 0 {
		t.Fatalf("a 503 named the clock: %+v", got)
	}
}

// docs/mcp-enclave.md §4 and §5.1 name the clock lines, their thresholds
// and their rate limit as the code has them.
func TestReaderClockLinesMatchTheDocs(t *testing.T) {
	b, err := os.ReadFile("../../docs/mcp-enclave.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := strings.Join(strings.Fields(string(b)), " ")
	for _, s := range []string{
		"`" + clockLine + "`",
		"`" + clockLineFree + "`",
		"`" + healthz401 + "`",
		fmt.Sprintf("At |skew| ≥ %d s it logs WARN, at ≥ %d s ERROR", int(skewWarn/time.Second), int(skewError/time.Second)),
		fmt.Sprintf("at most once per %d minutes per reader, per level", int(skewLogEvery/time.Minute)),
		fmt.Sprintf("at most once per %d minutes per reader, the WARN", int(skewLogEvery/time.Minute)),
		fmt.Sprintf("`limit_s=%d`", skewLimitSeconds()),
	} {
		if !strings.Contains(doc, s) {
			t.Errorf("docs/mcp-enclave.md does not say %q", s)
		}
	}
}
