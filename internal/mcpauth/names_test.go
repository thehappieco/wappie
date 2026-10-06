package mcpauth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The name rule of docs/mcp-enclave.md §19.6 step 3 on the vectors the
// reader's suite runs too (packages/mcp-http/test/vectors/client-names.json):
// Go accepts every name the reader keeps, and refuses a bidi control, a
// zero-width character, a doubled or edge space, a control and the rest by
// their shape; scripts are the reader's to judge.
func TestValidClientName(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "packages", "mcp-http", "test", "vectors", "client-names.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Schema string `json:"schema"`
		Names  []struct {
			Name   string `json:"name"`
			Reader bool   `json:"reader"`
			Go     bool   `json:"go"`
			Why    string `json:"why"`
		} `json:"names"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil || vectors.Schema != "wappie-client-names/v1" || len(vectors.Names) < 30 {
		t.Fatalf("vectors: %v %q %d", err, vectors.Schema, len(vectors.Names))
	}
	for _, v := range vectors.Names {
		if v.Reader && !v.Go {
			t.Errorf("%s: the reader keeps a name Go refuses", v.Why)
		}
		if got := validClientName(v.Name); got != v.Go {
			t.Errorf("%s: %q = %v, want %v", v.Why, v.Name, got, v.Go)
		}
	}
	// What JSON cannot carry, or the vectors keep in NFC.
	for name, s := range map[string]string{"not NFC": "Café", "not UTF-8": "Claude\xff", "too long": strings.Repeat("é", 101)} {
		if validClientName(s) {
			t.Errorf("%s: %q passed", name, s)
		}
	}
	// A label is normalized first.
	if label, ok := normalName("Café on the laptop"); !ok || label != "Café on the laptop" {
		t.Errorf("label = %q %v", label, ok)
	}
}
