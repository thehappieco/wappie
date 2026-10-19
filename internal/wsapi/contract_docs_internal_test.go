package wsapi

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"whatserver2/internal/membership/membershiptest"
)

// TestHotPathTimingsMatchTheDocs: docs/contract.md's bounds on the
// socket's background checks (its "hot path" rows and its freshness
// prose) are this package's.
func TestHotPathTimingsMatchTheDocs(t *testing.T) {
	rows := membershiptest.Timings(t, "../../docs/contract.md")
	for name, want := range map[string]string{
		"hot path":       membershiptest.Spoken(atActEvery),
		"hot path bound": membershiptest.Spoken(atActBound),
	} {
		if got := rows[name]; got != want {
			t.Errorf("docs/contract.md's timing %q is %q, the code's is %q", name, got, want)
		}
	}
	b, err := os.ReadFile("../../docs/contract.md")
	if err != nil {
		t.Fatal(err)
	}
	if s := fmt.Sprintf("at most %d at once per process", atActsInFlight); !strings.Contains(strings.Join(strings.Fields(string(b)), " "), s) {
		t.Errorf("docs/contract.md does not say %q", s)
	}
}
