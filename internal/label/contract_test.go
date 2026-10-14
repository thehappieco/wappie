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

// TestContractLabel runs Wappie's own table (the plan's test 41), whose
// labels the contract's vectors (TestContractLabelVectors) do not cover:
// placeholders, ids, the number itself and the push name. Every label
// Wappie keeps must pass the contract's rule, which the platform applies
// again on intake.
func TestContractLabel(t *testing.T) {
	var table struct {
		Cases []struct {
			Name     string  `json:"name"`
			Label    string  `json:"label"`
			PushName string  `json:"push_name"`
			PN       string  `json:"pn"`
			DeviceID string  `json:"device_id"`
			Want     *string `json:"want"`
		} `json:"cases"`
	}
	readJSON(t, "testdata/contract-labels.json", &table)
	if len(table.Cases) == 0 {
		t.Fatal("no cases")
	}
	for _, tc := range table.Cases {
		got := Contract(tc.Label, tc.PushName, tc.PN, tc.DeviceID)
		if !sameLabel(got, tc.Want) {
			t.Errorf("%s: Contract(%q, %q, %q) = %s, want %s", tc.Name, tc.Label, tc.PushName, tc.PN, show(got), show(tc.Want))
		}
		checkKept(t, tc.Name, got)
	}

	// The cut, built here rather than counted by hand.
	long := strings.Repeat("A", MaxLabel) + "éééé"
	if got := Contract(long, "", "", ""); got == nil || *got != strings.Repeat("A", MaxLabel) {
		t.Errorf("cut: %s", show(got))
	}
	flag := strings.Repeat("A", MaxLabel-1) + "🇧🇷"
	if got := Contract(flag, "", "", ""); got == nil || *got != strings.Repeat("A", MaxLabel-1) {
		t.Errorf("half a flag: %s", show(got))
	}
	spaced := strings.Repeat("A", MaxLabel-1) + " B"
	if got := Contract(spaced, "", "", ""); got == nil || *got != strings.Repeat("A", MaxLabel-1) {
		t.Errorf("a cut ending in a space: %s", show(got))
	}
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
		got := Contract(v.Raw, "", "5521900000000@s.whatsapp.net", "")
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

func readJSON(t *testing.T, path string, v any) {
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
