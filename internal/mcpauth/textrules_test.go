package mcpauth

import (
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"testing"
)

// The shared vectors (docs/mcp-enclave.md §17.10): the same file the
// enclave's text rules read, so the two cannot drift apart.
func TestTextRuleVectors(t *testing.T) {
	raw, err := os.ReadFile("../../packages/mcp-http/enclave/test/send-text-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []struct {
			Name  string          `json:"name"`
			Text  json.RawMessage `json:"text"`
			Draft *string         `json:"draft"`
			Self  *string         `json:"self"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) < 40 {
		t.Fatalf("only %d vectors", len(file.Vectors))
	}
	want := func(why *string) string {
		if why == nil {
			return ""
		}
		return *why
	}
	for _, v := range file.Vectors {
		text, exact := jsonString(v.Text)
		draft, self := textControl, textControl
		if exact {
			draft, self = textRefusal(text, false, 0), textRefusal(text, true, selfTextMax)
		}
		if draft != want(v.Draft) || self != want(v.Self) {
			t.Errorf("%s: draft %q self %q, want %q and %q", v.Name, draft, self, want(v.Draft), want(v.Self))
		}
	}
}

// A lone surrogate escape, or a byte that is not UTF-8, is refused rather
// than read as U+FFFD, which encoding/json would do without a word; a pair,
// and every other escape, reads as encoding/json reads it.
func TestJSONStringIsExact(t *testing.T) {
	for raw, want := range map[string]string{
		`"plain"`:                   "plain",
		`"\ud83d\ude00"`:            "\U0001F600",
		`"\u00e9\n\t\"\\\/"`:        "\u00e9\n\t\"\\/",
		`"\uFFFD is a character"`:   "\uFFFD is a character",
		`"a\\ud800 is not escaped"`: `a\ud800 is not escaped`,
	} {
		got, ok := jsonString(json.RawMessage(raw))
		if !ok || got != want {
			t.Errorf("%s = %q %v", raw, got, ok)
		}
	}
	for _, raw := range []string{`"\ud800"`, `"\udc00"`, `"\ud83dA"`, `"\ud83d"`, `"x\ud83d\\"`, "\"\xff\"", `7`, `"unterminated`} {
		if got, ok := jsonString(json.RawMessage(raw)); ok {
			t.Errorf("%s read as %q", raw, got)
		}
	}
}

// An own-chat send is at most SELF_TEXT_MAX_CHARS UTF-16 code units, the
// reader's unit: an astral character counts two.
func TestTextLength(t *testing.T) {
	if why := textRefusal(strings.Repeat("a", selfTextMax), true, selfTextMax); why != "" {
		t.Fatalf("at the limit: %q", why)
	}
	if why := textRefusal(strings.Repeat("a", selfTextMax+1), true, selfTextMax); why != textTooLong {
		t.Fatalf("over the limit: %q", why)
	}
	if why := textRefusal(strings.Repeat("\U0001F600", selfTextMax/2)+"a", true, selfTextMax); why != textTooLong {
		t.Fatalf("astral characters counted once: %q", why)
	}
	// \r\n counts as the one \n it becomes.
	if why := textRefusal(strings.Repeat("\r\n", selfTextMax)+"a", true, selfTextMax); why != textTooLong {
		t.Fatalf("newlines: %q", why)
	}
	if why := textRefusal("a"+strings.Repeat("\r\n", selfTextMax-1), true, selfTextMax); why != "" {
		t.Fatalf("newlines at the limit: %q", why)
	}
}

// Refusals past a connection's cap are logged once per connection with
// their count, then forgotten; an hour with none logs nothing.
func TestDroppedRefusalsLogged(t *testing.T) {
	logs := &capture{}
	h := &Handler{Log: slog.New(logs), dropped: newRefusalDrops()}
	h.dropped.note("a")
	h.dropped.note("a")
	h.dropped.note("b")
	h.LogDroppedRefusals()
	counts := map[string]string{}
	for _, r := range logs.records {
		attrs := map[string]string{}
		r.Attrs(func(a slog.Attr) bool {
			attrs[a.Key] = a.Value.String()
			return true
		})
		if r.Message != "mcp_refusals_dropped" || r.Level != slog.LevelWarn {
			t.Fatalf("record = %v %q", r.Level, r.Message)
		}
		counts[attrs["connection"]] = attrs["count"]
	}
	if len(counts) != 2 || counts["a"] != "2" || counts["b"] != "1" {
		t.Fatalf("counts = %v", counts)
	}
	h.LogDroppedRefusals()
	if len(logs.records) != 2 {
		t.Fatalf("logged again: %d records", len(logs.records))
	}
}
