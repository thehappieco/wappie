package mcpauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// The three messages the health line goes out under. The release gate
// (scripts/reader_policy_gate.py in the cloud repo) matches them exactly.
const (
	healthLine    = "attested reader health"
	notReadyLine  = "an attested reader is not ready"
	certShortLine = "an attested reader's certificate is close to expiry"
)

// readerClockKeys are the health line's fields for the reader's own clock.
var readerClockKeys = []string{"clock_ok", "clock_unc_ms", "nsm_skew_ms", "go_skew_ms"}

// healthServer answers every health check with status and body, which the
// test may change between checks.
func healthServer(t *testing.T, status *int, body *string) *AttestedReader {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(*status)
		//nolint:errcheck // test server
		_, _ = w.Write([]byte(*body))
	}))
	t.Cleanup(srv.Close)
	return &AttestedReader{ID: "enclave", Relay: &SignedRelay{ReaderID: "enclave", BaseURL: srv.URL, Secret: "s", Client: srv.Client()}}
}

// readerHealthWith is a ready reader's health object with fields changed:
// a nil value removes the field.
func readerHealthWith(t *testing.T, fields map[string]any) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(readerHealthJSON(t)), &m); err != nil {
		t.Fatal(err)
	}
	for k, v := range fields {
		if v == nil {
			delete(m, k)
			continue
		}
		m[k] = v
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func ms(v int64) *int64 { return &v }

// Health reads the clock fields of a 0.6.1 reader, leaves them nil for an
// older reader, for null and for any shape it does not read, and never fails
// the answer over one of them.
func TestHealthReadsTheReaderClock(t *testing.T) {
	yes, no := true, false
	for _, tc := range []struct {
		name string
		raw  string
		ok   *bool
		unc  *int64
		nsm  *int64
		gos  *int64
	}{
		{name: "older reader", raw: ``},
		{name: "all", raw: `"clock_ok":true,"clock_unc_ms":42,"nsm_skew_ms":-3,"go_skew_ms":-1000`,
			ok: &yes, unc: ms(42), nsm: ms(-3), gos: ms(-1000)},
		{name: "not ok", raw: `"clock_ok":false,"clock_unc_ms":6001`, ok: &no, unc: ms(6001)},
		{name: "null", raw: `"clock_ok":null,"clock_unc_ms":null,"nsm_skew_ms":null,"go_skew_ms":null`},
		{name: "fractions round", raw: `"clock_unc_ms":1.5,"nsm_skew_ms":-0.4,"go_skew_ms":2.5e3`,
			unc: ms(2), nsm: ms(0), gos: ms(2500)},
		{name: "a day either way", raw: `"nsm_skew_ms":86400000,"go_skew_ms":-86400000`, nsm: ms(86_400_000), gos: ms(-86_400_000)},
		{name: "past a day", raw: `"nsm_skew_ms":86400001,"go_skew_ms":-1e300`},
		{name: "wrong shapes", raw: `"clock_ok":"true","clock_unc_ms":"42","nsm_skew_ms":true,"go_skew_ms":{"ms":1}`},
		{name: "a number for clock_ok", raw: `"clock_ok":1`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status := http.StatusOK
			body := readerHealthJSON(t)
			if tc.raw != "" {
				body = strings.TrimSuffix(body, "}") + "," + tc.raw + "}"
			}
			a := healthServer(t, &status, &body)
			health, err := a.Relay.Health(context.Background())
			if err != nil {
				t.Fatalf("health: %v", err)
			}
			if health.ReaderID != "enclave" || health.State != "ready" || health.PCR0 != strings.Repeat("ab", 48) {
				t.Fatalf("the rest of the answer = %+v", health)
			}
			if !sameBool(health.ClockOK, tc.ok) || !sameMS(health.ClockUncMS, tc.unc) ||
				!sameMS(health.NSMSkewMS, tc.nsm) || !sameMS(health.GoSkewMS, tc.gos) {
				t.Fatalf("clock = %s %s %s %s", show(health.ClockOK), show(health.ClockUncMS),
					show(health.NSMSkewMS), show(health.GoSkewMS))
			}
		})
	}
}

func sameBool(a, b *bool) bool { return a == nil && b == nil || a != nil && b != nil && *a == *b }
func sameMS(a, b *int64) bool  { return a == nil && b == nil || a != nil && b != nil && *a == *b }

// show prints a pointer's value, or nil.
func show[T any](v *T) string {
	if v == nil {
		return "nil"
	}
	return fmt.Sprint(*v)
}

// The health line carries the reader's clock fields when it sent them and
// none of them for an older reader; |go_skew_ms| from ten seconds makes it a
// warning under the same message, and nothing else about the clock does.
func TestHealthLineReaderClock(t *testing.T) {
	status, body := http.StatusOK, readerHealthJSON(t)
	a := healthServer(t, &status, &body)
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		fields map[string]any
		level  slog.Level
		msg    string
		attrs  map[string]string
	}{
		{name: "older reader", fields: map[string]any{}, level: slog.LevelInfo, msg: healthLine},
		{name: "ok", fields: map[string]any{"clock_ok": true, "clock_unc_ms": 12, "nsm_skew_ms": -3, "go_skew_ms": 0},
			level: slog.LevelInfo, msg: healthLine,
			attrs: map[string]string{"clock_ok": "true", "clock_unc_ms": "12", "nsm_skew_ms": "-3", "go_skew_ms": "0"}},
		{name: "only some", fields: map[string]any{"clock_ok": true, "go_skew_ms": 1000},
			level: slog.LevelInfo, msg: healthLine, attrs: map[string]string{"clock_ok": "true", "go_skew_ms": "1000"}},
		{name: "go skew under ten seconds", fields: map[string]any{"clock_ok": true, "go_skew_ms": 9999},
			level: slog.LevelInfo, msg: healthLine, attrs: map[string]string{"clock_ok": "true", "go_skew_ms": "9999"}},
		{name: "go skew ten seconds ahead", fields: map[string]any{"clock_ok": true, "go_skew_ms": 10000},
			level: slog.LevelWarn, msg: healthLine, attrs: map[string]string{"clock_ok": "true", "go_skew_ms": "10000"}},
		{name: "go skew ten seconds behind", fields: map[string]any{"clock_ok": true, "go_skew_ms": -10000},
			level: slog.LevelWarn, msg: healthLine, attrs: map[string]string{"clock_ok": "true", "go_skew_ms": "-10000"}},
		{name: "clock unknown", fields: map[string]any{"state": "clock_unknown", "clock_ok": false, "clock_unc_ms": 7000, "nsm_skew_ms": 6500},
			level: slog.LevelWarn, msg: notReadyLine,
			attrs: map[string]string{"state": "clock_unknown", "clock_ok": "false", "clock_unc_ms": "7000", "nsm_skew_ms": "6500"}},
		{name: "certificate short wins", fields: map[string]any{"cert_not_after": time.Now().Add(5 * 24 * time.Hour), "go_skew_ms": 60000},
			level: slog.LevelWarn, msg: certShortLine, attrs: map[string]string{"go_skew_ms": "60000"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := &capture{}
			h := &Handler{Log: slog.New(logs), clocks: newReaderClocks()}
			body = readerHealthWith(t, tc.fields)
			if failures := h.checkReader(ctx, a, 0); failures != 0 {
				t.Fatalf("failures = %d", failures)
			}
			level, msg, attrs := logs.last()
			if level != tc.level || msg != tc.msg || len(logs.records) != 1 {
				t.Fatalf("line = %v %q (of %d), want %v %q", level, msg, len(logs.records), tc.level, tc.msg)
			}
			for _, k := range readerClockKeys {
				want, ok := tc.attrs[k]
				if got, has := attrs[k]; has != ok || got != want {
					t.Fatalf("%s = %q (%v), want %q (%v); line %v", k, got, has, want, ok, attrs)
				}
			}
			if want, ok := tc.attrs["state"]; ok && attrs["state"] != want {
				t.Fatalf("state = %q", attrs["state"])
			}
			// The fingerprints the release gate reads are on every one.
			if attrs["reader"] != "enclave" || attrs["pcr0"] != strings.Repeat("ab", 6) || attrs["policy"] != strings.Repeat("ef", 6) {
				t.Fatalf("fingerprints = %v", attrs)
			}
		})
	}
}

// A 503 with a code is a typed error naming it, still ErrReaderUnavailable,
// and the miss lines carry the code; a body that is not a code adds none,
// and none of it is the 401 line.
func TestHealthzStatusCode(t *testing.T) {
	status, body := http.StatusServiceUnavailable, `{"code":"clock_unknown"}`
	a := healthServer(t, &status, &body)
	ctx := context.Background()

	_, err := a.Relay.Health(ctx)
	var se *HealthStatusError
	if !errors.As(err, &se) || se.Status != http.StatusServiceUnavailable || se.Code != ReaderCodeClockUnknown {
		t.Fatalf("503 clock_unknown: %#v", err)
	}
	if !errors.Is(err, ErrReaderUnavailable) || errors.Is(err, errHealthzUnauthorized) ||
		err.Error() != ErrReaderUnavailable.Error()+": healthz answered 503 clock_unknown" {
		t.Fatalf("503 clock_unknown: %v", err)
	}

	logs := &capture{}
	h := &Handler{Log: slog.New(logs), clocks: newReaderClocks()}
	failures := 0
	for range healthFailures {
		failures = h.checkReader(ctx, a, failures)
	}
	misses := logs.lines("an attested reader missed a health check")
	down := logs.lines("an attested reader is not answering its health check")
	if failures != healthFailures || len(misses) != healthFailures-1 || len(down) != 1 {
		t.Fatalf("failures %d, misses %d, down %d", failures, len(misses), len(down))
	}
	for _, l := range append(misses, down...) {
		if l.attrs["code"] != ReaderCodeClockUnknown || !strings.HasSuffix(l.attrs["error"], "healthz answered 503 clock_unknown") {
			t.Fatalf("miss line = %v", l.attrs)
		}
	}
	if got := logs.lines(healthz401); len(got) != 0 {
		t.Fatalf("a 503 named the signature: %+v", got)
	}

	// Anything that is not a code's shape is left out of the error and the
	// line; the status alone is still there.
	for _, tc := range []struct {
		status int
		body   string
		code   string
	}{
		{http.StatusServiceUnavailable, `{"code":"starting"}`, "starting"},
		{http.StatusBadGateway, `{"code":"kms_failed"}`, "kms_failed"},
		{http.StatusServiceUnavailable, `{"code":"Clock Unknown"}`, ""},
		{http.StatusServiceUnavailable, `{"code":"` + strings.Repeat("a", 41) + `"}`, ""},
		{http.StatusServiceUnavailable, `{"code":7}`, ""},
		{http.StatusServiceUnavailable, `<html>busy</html>`, ""},
		{http.StatusInternalServerError, ``, ""},
	} {
		status, body = tc.status, tc.body
		_, err := a.Relay.Health(ctx)
		want := ErrReaderUnavailable.Error() + ": healthz answered " + itoa(int64(tc.status))
		if tc.code != "" {
			want += " " + tc.code
		}
		if !errors.As(err, &se) || se.Status != tc.status || se.Code != tc.code || err.Error() != want {
			t.Fatalf("%d %s: %v", tc.status, tc.body, err)
		}
		logs := &capture{}
		h := &Handler{Log: slog.New(logs), clocks: newReaderClocks()}
		h.checkReader(ctx, a, 0)
		_, _, attrs := logs.last()
		if code, ok := attrs["code"]; code != tc.code || ok != (tc.code != "") {
			t.Fatalf("%d %s: line %v", tc.status, tc.body, attrs)
		}
	}

	// A 401 is the refusal it was, with no code and no typed status.
	status, body = http.StatusUnauthorized, `{"code":"clock_unknown"}`
	if _, err := a.Relay.Health(ctx); !errors.Is(err, errHealthzUnauthorized) || errors.As(err, &se) {
		t.Fatalf("401: %v", err)
	}
}

// docs/mcp-enclave.md §5.1 names the reader's clock fields, the 503 and the
// threshold as the code has them.
func TestReaderHealthClockMatchesTheDocs(t *testing.T) {
	b, err := os.ReadFile("../../docs/mcp-enclave.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := strings.Join(strings.Fields(string(b)), " ")
	for _, s := range []string{
		`"clock_ok":true|false|null`,
		`"go_skew_ms":<integer>|null`,
		"503 `" + ReaderCodeClockUnknown + "`",
		"`" + codePattern.String() + "`",
		"|go_skew_ms| ≥ " + itoa(skewWarn.Milliseconds()),
		"`" + healthLine + "`",
		"`" + notReadyLine + "`",
		"`" + certShortLine + "`",
	} {
		if !strings.Contains(doc, s) {
			t.Errorf("docs/mcp-enclave.md does not say %q", s)
		}
	}
}
