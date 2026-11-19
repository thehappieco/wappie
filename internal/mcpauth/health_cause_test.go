package mcpauth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

// Health reads the fields the clock alerts need when a 0.6.1 reader sends
// them, and leaves each nil when it is missing (0.6.0, or 0.6.1 before the
// fields), null or not a shape Go reads; a code Go does not know is never
// kept.
func TestHealthReadsTheClockCause(t *testing.T) {
	for _, tc := range []struct {
		name                                string
		raw                                 string
		code                                *string
		disagree, lo, hi, corrHour, corrDay *int64
	}{
		{name: "older reader", raw: ``},
		{name: "0.6.1 without the fields", raw: `"clock_ok":true,"clock_unc_ms":12`},
		{name: "all", raw: `"clock_code":"cap_exceeded","clock_disagree_kms":2,"kms_skew_lo_ms":-1500,"kms_skew_hi_ms":900,"clock_corr_hour_ms":3100,"clock_corr_day_ms":-4200`,
			code: str("cap_exceeded"), disagree: ms(2), lo: ms(-1500), hi: ms(900), corrHour: ms(3100), corrDay: ms(-4200)},
		{name: "every known code", raw: `"clock_code":"nsm_node_proof"`, code: str("nsm_node_proof")},
		{name: "the helper starting", raw: `"clock_code":"starting"`, code: str("starting")},
		{name: "null", raw: `"clock_code":null,"clock_disagree_kms":null,"kms_skew_lo_ms":null,"kms_skew_hi_ms":null,"clock_corr_hour_ms":null,"clock_corr_day_ms":null`},
		{name: "unknown code", raw: `"clock_code":"evil_word"`},
		{name: "code not a code's shape", raw: `"clock_code":"Cap Exceeded"`},
		{name: "code not a string", raw: `"clock_code":7`},
		{name: "count negative or a fraction", raw: `"clock_disagree_kms":-1`},
		{name: "count a fraction", raw: `"clock_disagree_kms":1.5`},
		{name: "count a string", raw: `"clock_disagree_kms":"1"`},
		{name: "past a day", raw: `"kms_skew_lo_ms":-86400001,"clock_corr_day_ms":1e300`},
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
			if !sameStr(health.ClockCode, tc.code) || !sameMS(health.ClockDisagreeKMS, tc.disagree) ||
				!sameMS(health.KMSSkewLoMS, tc.lo) || !sameMS(health.KMSSkewHiMS, tc.hi) ||
				!sameMS(health.ClockCorrHourMS, tc.corrHour) || !sameMS(health.ClockCorrDayMS, tc.corrDay) {
				t.Fatalf("cause = %s %s %s %s %s %s", show(health.ClockCode), show(health.ClockDisagreeKMS),
					show(health.KMSSkewLoMS), show(health.KMSSkewHiMS), show(health.ClockCorrHourMS), show(health.ClockCorrDayMS))
			}
		})
	}
}

// The 503 clock_unknown keeps the health object a 0.6.1 reader sends with
// it, and is the same typed error without it; a body that is another
// reader's or not ok is not kept, and no other status or code keeps one.
func TestHealthzStaleKeepsTheHealth(t *testing.T) {
	stale := func(t *testing.T, fields map[string]any) string {
		t.Helper()
		fields["code"] = ReaderCodeClockUnknown
		return readerHealthWith(t, fields)
	}
	for _, tc := range []struct {
		name   string
		status int
		body   func(t *testing.T) string
		kept   bool
	}{
		{name: "bare", status: http.StatusServiceUnavailable, body: func(*testing.T) string { return `{"code":"clock_unknown"}` }},
		{name: "with health", status: http.StatusServiceUnavailable, kept: true, body: func(t *testing.T) string {
			return stale(t, map[string]any{"state": "clock_unknown", "clock_ok": false, "clock_code": "cap_exceeded", "clock_unc_ms": 90000})
		}},
		{name: "another reader's", status: http.StatusServiceUnavailable, body: func(t *testing.T) string {
			return stale(t, map[string]any{"reader_id": "other", "clock_ok": false})
		}},
		{name: "not ok", status: http.StatusServiceUnavailable, body: func(t *testing.T) string {
			return stale(t, map[string]any{"ok": false, "clock_ok": false})
		}},
		{name: "another code", status: http.StatusServiceUnavailable, body: func(t *testing.T) string {
			return readerHealthWith(t, map[string]any{"code": "starting", "clock_ok": false})
		}},
		{name: "another status", status: http.StatusBadGateway, body: func(t *testing.T) string {
			return stale(t, map[string]any{"clock_ok": false})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, body := tc.status, tc.body(t)
			a := healthServer(t, &status, &body)
			_, err := a.Relay.Health(context.Background())
			var se *HealthStatusError
			if !errors.As(err, &se) || !errors.Is(err, ErrReaderUnavailable) {
				t.Fatalf("err = %v", err)
			}
			if (se.Health != nil) != tc.kept {
				t.Fatalf("health kept = %v, want %v", se.Health != nil, tc.kept)
			}
			if tc.kept {
				h := se.Health
				if h.BootID != "0011223344556677" || h.PCR0 != strings.Repeat("ab", 48) || h.ClockOK == nil || *h.ClockOK ||
					!sameStr(h.ClockCode, str("cap_exceeded")) || !sameMS(h.ClockUncMS, ms(90000)) {
					t.Fatalf("health = %+v", *h)
				}
				// The miss line carries the clock the 503 brought.
				logs := &capture{}
				hd := &Handler{Log: slog.New(logs), clocks: newReaderClocks()}
				hd.checkReader(context.Background(), a, 0)
				_, _, attrs := logs.last()
				if attrs["code"] != ReaderCodeClockUnknown || attrs["clock_code"] != "cap_exceeded" || attrs["clock_ok"] != "false" {
					t.Fatalf("miss line = %v", attrs)
				}
			}
		})
	}
}

func str(s string) *string { return &s }

func sameStr(a, b *string) bool { return a == nil && b == nil || a != nil && b != nil && *a == *b }
