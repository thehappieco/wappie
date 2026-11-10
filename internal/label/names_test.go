package label

import (
	"encoding/json"
	"io/fs"
	"strings"
	"testing"

	kc "github.com/thehappieco/kit/contract"
	kitvectors "github.com/thehappieco/kit/vectors"
)

// keyish is n base64url characters that mix letters and digits, with no
// run of seven digits. It is built at run time, so no key-shaped literal
// sits in the source.
func keyish(n int) string {
	const chars = "Zq7Xv2LpRk4TmWc8HdJf3BnGs5YhUe9a"
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteByte(chars[(i*7+3)%len(chars)])
	}
	return b.String()
}

// The key prefixes Name sets aside, each as a word.
var keyPrefixes = []string{"sk-", "sk-ant-api03-", "sk-proj-", "AIza", "xai-", "gsk_"}

type nameCase struct {
	name  string
	in    string
	avoid []string
	want  *string
}

func nameCases() []nameCase {
	p := func(s string) *string { return &s }
	cases := []nameCase{
		// What Clean does, and nothing more, for a plain name.
		{name: "a plain name", in: "Claude", want: p("Claude")},
		{name: "a long plain name", in: "Assistente de atendimento da loja", want: p("Assistente de atendimento da loja")},
		{name: "a long run of letters and hyphens", in: "Assistente-de-atendimento-da-loja-centro", want: p("Assistente-de-atendimento-da-loja-centro")},
		{name: "one long word", in: "Supercalifragilisticexpialidocious", want: p("Supercalifragilisticexpialidocious")},
		{name: "letters and digits in words of their own", in: "Loja 2024 atendimento 24h", want: p("Loja 2024 atendimento 24h")},
		{name: "a short hyphenated run with digits", in: "Loja-Centro-24h", want: p("Loja-Centro-24h")},
		{name: "SK-II is no key", in: "SK-II Atendimento", want: p("SK-II Atendimento")},
		{name: "sk- inside a word", in: "Risk-free bot", want: p("Risk-free bot")},
		{name: "Aiza is no key", in: "Atendimento Aizawa", want: p("Atendimento Aizawa")},
		{name: "a name that holds the host", in: "Bot de app.example.com", avoid: []string{"app.example.com"}, want: p("Bot de app.example.com")},
		{name: "an empty avoid", in: "Vendas", avoid: []string{"", "\u200b"}, want: p("Vendas")},
		{name: "an address", in: "vendas@loja.com.br", want: nil},
		{name: "an address inside a name", in: "Suporte (ana@loja.com.br)", want: nil},
		{name: "controls", in: "Ven\u0000da\u0007s\u202e", want: p("Vendas")},
		{name: "a run of 7 digits", in: "Ramal 1234567", want: p("Ramal …4567")},
		{name: "spaces", in: "  Suporte    24h ", want: p("Suporte 24h")},
		{name: "nothing", in: "", want: nil},
		{name: "spaces only", in: "   ", want: nil},
		{name: "hidden characters only", in: "\u200b\u200e", want: nil},
		{name: "101 code points", in: strings.Repeat("é", 101), want: p(strings.Repeat("é", MaxLabel))},
		{name: "101 code points, decomposed", in: strings.Repeat("e\u0301", 101), want: p(strings.Repeat("é", MaxLabel))},
		{name: "101 letters", in: strings.Repeat("z", 101), want: p(strings.Repeat("z", MaxLabel))},
		{name: "101 code points of words", in: strings.Repeat("Atendimento ", 9)[:101], want: p(strings.Repeat("Atendimento ", 6) + "Atendime")},
		{name: "a run of 23 that mixes letters and digits", in: keyish(23), want: p(keyish(23))},
		{name: "a run of 23 inside a name", in: "Bot " + keyish(23), want: p("Bot " + keyish(23))},

		// Opaque ids, as Contract sets them aside.
		{name: "a UUID", in: "0199a0c2-7b1e-7c3a-9d2e-4f5a6b7c8d9e", want: nil},
		{name: "a UUID in capitals, spaced and hidden", in: " \u200b0199A0C2-7B1E-7C3A-9D2E-4F5A6B7C8D9E ", want: nil},
		{name: "a UUID whose digits Clean masks", in: "01234567-89ab-4def-8123-456789abcdef", want: nil},
		{name: "24 hex characters", in: "0123456789abcdef01234567", want: nil},
		{name: "24 hex letters", in: "abcdefabcdefabcdefabcdef", want: nil},
		{name: "101 hex letters", in: strings.Repeat("a", 101), want: nil},
		{name: "an id inside a name", in: "Cliente 0199a0c2-7b1e-7c3a-9d2e-4f5a6b7c8d9e", want: nil},

		// Runs of base64url characters that mix letters and digits.
		{name: "a run of 24", in: keyish(24), want: nil},
		{name: "a run of 60", in: keyish(60), want: nil},
		{name: "a run inside a name", in: "Bot " + keyish(32) + " loja", want: nil},
		{name: "a run with - and _", in: keyish(10) + "-" + keyish(6) + "_" + keyish(8), want: nil},
		{name: "a run a hidden character splits", in: keyish(12) + "\u200b" + keyish(12), want: nil},
		{name: "a prefix a hidden character splits", in: "Chave g\u200bsk\u2060_x", want: nil},
		{name: "a run whose digits Clean masks", in: "abcdefghijkl1234567mnopqrstuvwx", want: nil},
		{name: "a run cut at 80", in: "Atendimento da loja do centro da cidade de São Paulo, filial número " + keyish(30), want: nil},

		// A name equal to the row's client id or redirect host.
		{name: "the client id", in: "https://claude.ai/oauth/mcp-oauth-client-metadata", avoid: []string{"https://claude.ai/oauth/mcp-oauth-client-metadata", "claude.ai"}, want: nil},
		{name: "the redirect host, another case", in: "CLAUDE.AI", avoid: []string{"https://claude.ai/oauth/mcp-oauth-client-metadata", "claude.ai"}, want: nil},
		{name: "the redirect host, spaced and hidden", in: " claude.ai\u200b ", avoid: []string{"claude.ai"}, want: nil},
		{name: "case folded beyond lower case", in: "STRASSE", avoid: []string{"straße"}, want: nil},
		{name: "a client id with a digit run", in: "cliente-1234567", avoid: []string{"cliente-1234567"}, want: nil},
		{name: "a client id, cleaned", in: "cliente-…4567", avoid: []string{"cliente-1234567"}, want: nil},
	}
	// A word that starts as a provider's key, alone, in a name, after
	// punctuation, and with a short tail.
	for _, prefix := range keyPrefixes {
		cases = append(cases,
			nameCase{name: prefix + " and a key's tail", in: prefix + keyish(40), want: nil},
			nameCase{name: prefix + " in a name", in: "Minha chave " + prefix + keyish(40), want: nil},
			nameCase{name: prefix + " after punctuation", in: "(" + prefix + keyish(20) + ")", want: nil},
			nameCase{name: prefix + " with a short tail", in: prefix + "x", want: nil},
		)
	}
	return cases
}

// TestName is G0's table (the plan's 4.1): what Clean leaves, set aside
// when it is an id, a key's shape or the row's own client id or host.
func TestName(t *testing.T) {
	for _, tc := range nameCases() {
		got := Name(tc.in, tc.avoid...)
		if !sameLabel(got, tc.want) {
			t.Errorf("%s: Name(%q, %q) = %s, want %s", tc.name, tc.in, tc.avoid, show(got), show(tc.want))
		}
		checkName(t, tc.name, tc.in, tc.avoid, got)
	}
}

// TestNameLabelVectors runs the contract's own labels (the kit's
// platform/contract-v1/labels.json) through Name: none is an id or a key,
// so Name gives what the contract's rule gives, and null for "".
func TestNameLabelVectors(t *testing.T) {
	var vectors struct {
		Format string `json:"format"`
		Kind   string `json:"kind"`
		Clean  []struct {
			Raw   string `json:"raw"`
			Clean string `json:"clean"`
		} `json:"clean"`
	}
	raw, err := fs.ReadFile(kitvectors.FS, "platform/contract-v1/labels.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.Format != "thehappie-contract/vectors" || vectors.Kind != "labels" || len(vectors.Clean) < 34 {
		t.Fatalf("not the labels vectors: %q %q, %d labels", vectors.Format, vectors.Kind, len(vectors.Clean))
	}
	for _, v := range vectors.Clean {
		var want *string
		if v.Clean != "" {
			want = &v.Clean
		}
		for _, in := range []string{v.Raw, v.Clean} {
			got := Name(in)
			if !sameLabel(got, want) {
				t.Errorf("Name(%q) = %s, want %s", in, show(got), show(want))
			}
			checkName(t, in, in, nil, got)
		}
	}
}

// FuzzName checks what Name gives against what may leave: the name
// cleaned, a valid label, never an id, a key's shape or the avoided name,
// and the same again through Name.
func FuzzName(f *testing.F) {
	for _, tc := range nameCases() {
		a := ""
		if len(tc.avoid) > 0 {
			a = tc.avoid[0]
		}
		f.Add(tc.in, a)
	}
	raw, err := fs.ReadFile(kitvectors.FS, "platform/contract-v1/labels.json")
	if err != nil {
		f.Fatal(err)
	}
	var vectors struct {
		Clean []struct {
			Raw string `json:"raw"`
		} `json:"clean"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		f.Fatal(err)
	}
	for _, v := range vectors.Clean {
		f.Add(v.Raw, v.Raw)
		f.Add(v.Raw, "")
	}
	f.Fuzz(func(t *testing.T, s, avoid string) {
		checkName(t, "fuzz", s, []string{avoid}, Name(s, avoid))
	})
}

// checkName is what Name's result must be, whatever the input.
func checkName(t *testing.T, name, in string, avoid []string, got *string) {
	t.Helper()
	if got == nil {
		return
	}
	if *got != Clean(in) {
		t.Errorf("%s: Name gave %q, not the name cleaned (%q)", name, *got, Clean(in))
	}
	if !kc.ValidLabel(*got) {
		t.Errorf("%s: the kit refuses %q", name, *got)
	}
	if again := Name(*got, avoid...); !sameLabel(again, got) {
		t.Errorf("%s: Name(%q) = %s, not the same again", name, *got, show(again))
	}
	if opaqueID.MatchString(*got) || keyPrefix.MatchString(*got) {
		t.Errorf("%s: %q is an id or starts a key", name, *got)
	}
	if run := mixedRun(*got); run >= 24 {
		t.Errorf("%s: %q holds a mixed run of %d", name, *got, run)
	}
	for _, a := range avoid {
		if f := fold(a); f != "" && f == fold(*got) {
			t.Errorf("%s: %q is the avoided %q", name, *got, a)
		}
	}
}

// mixedRun is the length of the longest run of base64url characters in s
// that holds both a letter and a digit, counted by hand.
func mixedRun(s string) int {
	longest := 0
	base64url := func(r rune) bool {
		return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_'
	}
	for _, run := range strings.FieldsFunc(s, func(r rune) bool { return !base64url(r) }) {
		if strings.ContainsAny(run, "0123456789") && strings.ContainsAny(run, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") && len(run) > longest {
			longest = len(run)
		}
	}
	return longest
}
