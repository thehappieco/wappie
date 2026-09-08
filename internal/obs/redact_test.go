package obs

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestIdentifiersAreMaskedOnTheWayOut(t *testing.T) {
	cases := map[string]string{
		"5511999998888@s.whatsapp.net":                               "…8888@s.whatsapp.net",
		"123456789012345@lid":                                        "…2345@lid",
		"120363012345678901@g.us":                                    "…8901@g.us",
		"5511999998888-1600000000@g.us":                              "…0000@g.us",
		"resumed 5511999998888@s.whatsapp.net / 123456789012345@lid": "resumed …8888@s.whatsapp.net / …2345@lid",
		"felipe.restum@example.com":                                  "f…@example.com",
		"status@broadcast":                                           "status@broadcast",
		"no identifier here":                                         "no identifier here",
	}
	for in, want := range cases {
		if got := Redact(in); got != want {
			t.Errorf("Redact(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTheProcessLoggerRedactsEveryStringAttribute(t *testing.T) {
	var buf bytes.Buffer
	lg := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{ReplaceAttr: redactAttr}))
	lg.With("account", "ana@example.com").
		WithGroup("device").
		Info("resumed device 5511999998888@s.whatsapp.net", "chat", "5511777776666@s.whatsapp.net")
	out := buf.String()
	for _, secret := range []string{"5511999998888", "5511777776666", "ana@"} {
		if strings.Contains(out, secret) {
			t.Errorf("%q reached the log: %s", secret, out)
		}
	}
	if !strings.Contains(out, "…8888@s.whatsapp.net") || !strings.Contains(out, "a…@example.com") {
		t.Errorf("the masked forms are missing: %s", out)
	}
}
