package mcpauth

import (
	"strings"
	"testing"
)

// The name rule of docs/mcp-enclave.md §19.6 step 3, on the cases the
// contract names: a bidi control, a zero-width character, a double space, a
// mixed script and an emoji with a zero-width joiner are refused; one script
// and the mixes UTS #39 allows pass.
func TestValidClientName(t *testing.T) {
	for _, name := range []string{
		"Claude", "Claude Code", "ChatGPT", "Example Agent", "Cursor on the laptop", "agent.example.com", "Zed", "VS Code",
		"Asistente de correo", "Ассистент", "助手", "Claude 日本語エージェント", "ひらがな カタカナ", "한국어 Agent 漢字", "注音 ㄅㄆㄇ Latin",
		"Agent 🚀", "Café", "naïve", strings.Repeat("a", 100), "x", "Léa", "A\u00a0B",
	} {
		if !validClientName(name) {
			t.Errorf("%q was refused", name)
		}
	}
	for name, s := range map[string]string{
		"empty":                    "",
		"too long":                 strings.Repeat("a", 101),
		"a leading space":          " Claude",
		"a trailing space":         "Claude ",
		"a double space":           "Claude  Code",
		"a tab and a space":        "Claude\t Code",
		"a bidi override":          "Claude\u202eedoC",
		"a bidi isolate":           "Claude\u2066x",
		"a zero-width space":       "Cla\u200bude",
		"a zero-width joiner":      "👩\u200d💻 Agent",
		"a byte order mark":        "\ufeffClaude",
		"a tag character":          "Claude\U000e0041",
		"a control":                "Claude\u0007",
		"a line separator":         "Claude\u2028Code",
		"a private use code point": "Claude\ue000",
		"Cyrillic in Latin":        "Сlaude",
		"Greek in Latin":           "Clαude",
		"Hangul with Kana":         "한국 カタカナ",
		"not NFC":                  "Cafe\u0301",
		"not UTF-8":                "Claude\xff",
	} {
		if validClientName(s) {
			t.Errorf("%s: %q passed", name, s)
		}
	}
	// A label is normalized first.
	if label, ok := normalName("Cafe\u0301 on the laptop"); !ok || label != "Café on the laptop" {
		t.Errorf("label = %q %v", label, ok)
	}
}
