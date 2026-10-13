package label

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

// The hint the database takes (0050's CHECK on item_events.hint and
// device_notices.hint).
var hintShape = regexp.MustCompile(`^…[0-9]{4}$`)

// TestContractLabel runs Wappie's own table (the plan's test 41) and the
// platform contract's label vectors, which every label Wappie keeps must
// pass: an app's labels are the contract's CleanLabel, and the platform
// cleans them again on intake.
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

// TestContractVectors runs the contract's own vectors (v1 labels.json, at
// platform 463f320): every clean case through Contract, as a label of a
// number whose phone it does not hold, and the number-shaped hints.
func TestContractVectors(t *testing.T) {
	var vectors struct {
		Kind  string `json:"kind"`
		Clean []struct {
			Raw   string `json:"raw"`
			Clean string `json:"clean"`
		} `json:"clean"`
		Hints []struct {
			Hint  string `json:"hint"`
			Valid bool   `json:"valid"`
		} `json:"hints"`
	}
	readJSON(t, "testdata/contract-v1-labels.json", &vectors)
	if vectors.Kind != "labels" || len(vectors.Clean) == 0 {
		t.Fatalf("not the labels vectors: %q, %d cases", vectors.Kind, len(vectors.Clean))
	}
	for _, v := range vectors.Clean {
		if got := Clean(v.Raw); got != v.Clean {
			t.Errorf("Clean(%q) = %q, want %q", v.Raw, got, v.Clean)
		}
		if got := Clean(v.Clean); got != v.Clean {
			t.Errorf("cleaning a clean label changed it: %q became %q", v.Clean, got)
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
	// Wappie's hints are only ever a number's: "…" and four ASCII digits.
	for _, h := range vectors.Hints {
		if strings.Contains(h.Hint, "@") {
			continue
		}
		if hintShape.MatchString(h.Hint) != h.Valid {
			t.Errorf("hint %q: the database's shape says %v, the contract %v", h.Hint, !h.Valid, h.Valid)
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
		if got != nil && !hintShape.MatchString(*got) {
			t.Errorf("HintFromPN(%q) = %q, which the database refuses", tc.pn, *got)
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
