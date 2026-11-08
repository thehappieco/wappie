package label

import (
	"encoding/json"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	kc "github.com/thehappieco/kit/contract"
	kitvectors "github.com/thehappieco/kit/vectors"
)

// atSigns are "@" and the characters that read as one, as the contract's
// rule counts them: an address hides behind them too.
const atSigns = "@＠﹫"

// The hint the database takes (0050's CHECK on item_events.hint and
// device_notices.hint).
var hintShape = regexp.MustCompile(`^…[0-9]{4}$`)

// labelTable is Wappie's own table, testdata/contract-labels.json. A case's
// push name is the number's, which never stands in for its label (the
// platform's design of 2026-10-26, 10.27): it is there to show that.
type labelTable struct {
	Cases []struct {
		Name     string  `json:"name"`
		Label    string  `json:"label"`
		PushName string  `json:"push_name"`
		PN       string  `json:"pn"`
		DeviceID string  `json:"device_id"`
		Want     *string `json:"want"`
	} `json:"cases"`
}

// TestContractLabel runs Wappie's own table (the plan's test 41), whose
// labels the contract's vectors (TestContractLabelVectors) do not cover:
// placeholders, ids, the number itself, and a push name that never stands
// in. Every label Wappie keeps must pass the contract's rule, which the
// platform applies again on intake.
func TestContractLabel(t *testing.T) {
	var table labelTable
	readJSON(t, "testdata/contract-labels.json", &table)
	if len(table.Cases) == 0 {
		t.Fatal("no cases")
	}
	for _, tc := range table.Cases {
		got := Contract(tc.Label, tc.PN, tc.DeviceID)
		if !sameLabel(got, tc.Want) {
			t.Errorf("%s: Contract(%q, %q) with the push name %q = %s, want %s", tc.Name, tc.Label, tc.PN, tc.PushName, show(got), show(tc.Want))
		}
		checkKept(t, tc.Name, got)
	}

	// The cut, built here rather than counted by hand.
	long := strings.Repeat("A", MaxLabel) + "éééé"
	if got := Contract(long, "", ""); got == nil || *got != strings.Repeat("A", MaxLabel) {
		t.Errorf("cut: %s", show(got))
	}
	flag := strings.Repeat("A", MaxLabel-1) + "🇧🇷"
	if got := Contract(flag, "", ""); got == nil || *got != strings.Repeat("A", MaxLabel-1) {
		t.Errorf("half a flag: %s", show(got))
	}
	spaced := strings.Repeat("A", MaxLabel-1) + " B"
	if got := Contract(spaced, "", ""); got == nil || *got != strings.Repeat("A", MaxLabel-1) {
		t.Errorf("a cut ending in a space: %s", show(got))
	}
}

// FuzzContractNeverGivesThePushName is 10.27's property: whatever a
// number's push name, Contract never gives it, cleaned, as the number's
// label unless the label itself cleans to the same text. What it gives is
// the label, cleaned, or nothing. The seeds are the table's cases, and each
// of the contract's own labels as the push name of a number whose label is
// set aside or empty; go test runs them, and go test -fuzz looks further.
func FuzzContractNeverGivesThePushName(f *testing.F) {
	var table labelTable
	readJSON(f, "testdata/contract-labels.json", &table)
	for _, tc := range table.Cases {
		f.Add(tc.Label, tc.PushName, tc.PN, tc.DeviceID)
	}
	var vectors struct {
		Clean []struct {
			Raw string `json:"raw"`
		} `json:"clean"`
	}
	raw, err := fs.ReadFile(kitvectors.FS, "platform/contract-v1/labels.json")
	if err != nil {
		f.Fatal(err)
	}
	if err := json.Unmarshal(raw, &vectors); err != nil || len(vectors.Clean) == 0 {
		f.Fatalf("the kit's labels: %d, %v", len(vectors.Clean), err)
	}
	const pn, id = "5511912345678:12@s.whatsapp.net", "0199a0c2-7b1e-7c3a-9d2e-4f5a6b7c8d9e"
	for _, v := range vectors.Clean {
		for _, aside := range []string{"", "device", "Número do WhatsApp", "0199a0c2", "+55 11 91234-5678", "vendas@loja.com.br"} {
			f.Add(aside, v.Raw, pn, id)
		}
	}
	f.Fuzz(func(t *testing.T, label, pushName, pn, deviceID string) {
		got := Contract(label, pn, deviceID)
		if got == nil {
			return
		}
		if push := Clean(pushName); *got == push && Clean(label) != push {
			t.Fatalf("Contract(%q, %q, %q) = %q: the push name %q, cleaned", label, pn, deviceID, *got, pushName)
		}
		if *got != Clean(label) {
			t.Fatalf("Contract(%q, %q, %q) = %q, which is not the label cleaned (%q)", label, pn, deviceID, *got, Clean(label))
		}
	})
}

// TestContractLabelVectors is TB3 of release B's plan, in place of the
// copy test 41 read: the contract's own label vectors, as the kit go.mod
// requires embeds them (vectors.FS, platform/contract-v1/labels.json, byte
// for byte the platform's). Every clean case goes through Clean and, as the
// label of a number whose phone it does not hold, through Contract; every
// hint is checked against the kit's ValidHint, and the number-shaped ones
// against what HintFromPN makes and what the database's CHECK takes.
func TestContractLabelVectors(t *testing.T) {
	var vectors struct {
		Format string `json:"format"`
		Kind   string `json:"kind"`
		Clean  []struct {
			Raw   string `json:"raw"`
			Clean string `json:"clean"`
		} `json:"clean"`
		Hints []struct {
			Hint  string `json:"hint"`
			Valid bool   `json:"valid"`
		} `json:"hints"`
	}
	raw, err := fs.ReadFile(kitvectors.FS, "platform/contract-v1/labels.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	// labels.json is frozen at 34 labels and 14 hints: fewer means another
	// file, or a kit that lost cases.
	if vectors.Format != "thehappie-contract/vectors" || vectors.Kind != "labels" || len(vectors.Clean) < 34 || len(vectors.Hints) < 14 {
		t.Fatalf("not the labels vectors: %q %q, %d labels, %d hints", vectors.Format, vectors.Kind, len(vectors.Clean), len(vectors.Hints))
	}
	for _, v := range vectors.Clean {
		if got := Clean(v.Raw); got != v.Clean {
			t.Errorf("Clean(%q) = %q, want %q", v.Raw, got, v.Clean)
		}
		if got := Clean(v.Clean); got != v.Clean {
			t.Errorf("cleaning a clean label changed it: %q became %q", v.Clean, got)
		}
		if v.Clean != "" && !kc.ValidLabel(v.Clean) {
			t.Errorf("%q: the kit refuses the label it cleaned", v.Clean)
		}
		var want *string
		if v.Clean != "" {
			want = &v.Clean
		}
		got := Contract(v.Raw, "5521900000000@s.whatsapp.net", "")
		if !sameLabel(got, want) {
			t.Errorf("Contract(%q) = %s, want %s", v.Raw, show(got), show(want))
		}
		checkKept(t, v.Raw, got)
	}
	for _, h := range vectors.Hints {
		if kc.ValidHint(h.Hint) != h.Valid {
			t.Errorf("kit ValidHint(%q) should be %v", h.Hint, h.Valid)
		}
		// Wappie's hints are only ever a number's: "…" and four ASCII digits.
		if strings.Contains(h.Hint, "@") {
			continue
		}
		if hintShape.MatchString(h.Hint) != h.Valid {
			t.Errorf("hint %q: the database's shape says %v, the contract %v", h.Hint, !h.Valid, h.Valid)
		}
		if digits, ok := strings.CutPrefix(h.Hint, kc.Ellipsis); ok && h.Valid {
			got := HintFromPN("55119012" + digits + ":7@s.whatsapp.net")
			if got == nil || *got != h.Hint {
				t.Errorf("HintFromPN for the hint %q gave %s", h.Hint, show(got))
			}
		}
	}
}

// TestHintNeverFromLID is the plan's test 42: the hint comes from the phone
// number's user part only, the companion's ":NN" never counts, and a number
// with only a LID has none.
func TestHintNeverFromLID(t *testing.T) {
	for _, tc := range []struct{ pn, want string }{
		{"5511912345678@s.whatsapp.net", "…5678"},
		{"5511912345678:12@s.whatsapp.net", "…5678"},
		{"5511912345678:9@s.whatsapp.net", "…5678"},
		{"5511912345678", "…5678"},
		{"123@s.whatsapp.net", ""},
		{"", ""},
	} {
		got := HintFromPN(tc.pn)
		if (got == nil) != (tc.want == "") || got != nil && *got != tc.want {
			t.Errorf("HintFromPN(%q) = %v, want %q", tc.pn, show(got), tc.want)
		}
		if got != nil && (!hintShape.MatchString(*got) || !kc.ValidHint(*got)) {
			t.Errorf("HintFromPN(%q) = %q, which the database or the contract refuses", tc.pn, *got)
		}
	}
	// A LID-only number has no phone number to give a hint: the stored pn
	// is empty, and nothing reads the LID.
	if got := HintFromPN(""); got != nil {
		t.Errorf("a LID-only number got the hint %q", *got)
	}
}

func readJSON(t testing.TB, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

// checkKept is what the database's CHECK and the contract ask of a kept
// label: 1 to 80 code points, nothing an address could hide behind, and
// clean already.
func checkKept(t *testing.T, name string, got *string) {
	t.Helper()
	if got == nil {
		return
	}
	if n := utf8.RuneCountInString(*got); n < 1 || n > MaxLabel {
		t.Errorf("%s: %d code points", name, n)
	}
	if strings.ContainsAny(*got, atSigns) || Clean(*got) != *got {
		t.Errorf("%s: %q is not a clean label", name, *got)
	}
}

func sameLabel(a, b *string) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}

func show(s *string) string {
	if s == nil {
		return "null"
	}
	return `"` + *s + `"`
}

// Classify is the class of what Contract does with a number's label, for
// the snapshot's counts (the plan's 4.8): named exactly when Contract gives
// a label, else why the label was set aside. A push name never counts, so a
// label set aside is never named (10.27).
func TestClassify(t *testing.T) {
	const pn = "5511912345678:12@s.whatsapp.net"
	const id = "0199e000-0000-7000-8000-000000000004"
	for _, c := range []struct {
		name, label, pn string
		want            Class
	}{
		{"a name", "Vendas", pn, ClassNamed},
		{"the console's placeholder, which no push name names", "Número do WhatsApp", pn, ClassPlaceholder},
		{"a placeholder", "WhatsApp number", pn, ClassPlaceholder},
		{"the number", "+55 11 91234-5678", pn, ClassPhone},
		{"the number, spaced", "11 91234 5678", pn, ClassPhone},
		{"an opaque id", "0199e0000000700080000000000000ab", pn, ClassLegacyID},
		{"the start of its own id", "0199e000", pn, ClassLegacyID},
		{"an address, which the rule drops", "vendas@acme.test", pn, ClassEmpty},
		{"nothing", "", pn, ClassEmpty},
		{"hidden characters only", "\u200b\u200e", pn, ClassEmpty},
		{"the server's placeholder, with no phone number", "device", "", ClassPlaceholder},
		{"the server's placeholder", "device", pn, ClassPlaceholder},
	} {
		got := Classify(c.label, c.pn, id)
		if got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
		if (got == ClassNamed) != (Contract(c.label, c.pn, id) != nil) {
			t.Errorf("%s: %s, but Contract gives %s", c.name, got, show(Contract(c.label, c.pn, id)))
		}
	}
	if n := len(Classes()); n != 5 {
		t.Fatalf("%d classes", n)
	}
}
