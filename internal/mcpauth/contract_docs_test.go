package mcpauth

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"whatserver2/internal/membership/membershiptest"
)

// TestSendCheckTimingsMatchTheDocs: mcp.send's background check is bound
// as docs/contract.md's "hot path" rows and its freshness prose say, the
// socket's sends' twin.
func TestSendCheckTimingsMatchTheDocs(t *testing.T) {
	rows := membershiptest.Timings(t, "../../docs/contract.md")
	for name, want := range map[string]string{
		"hot path":       membershiptest.Spoken(sendCheckEvery),
		"hot path bound": membershiptest.Spoken(sendCheckBound),
	} {
		if got := rows[name]; got != want {
			t.Errorf("docs/contract.md's timing %q is %q, the code's is %q", name, got, want)
		}
	}
	b, err := os.ReadFile("../../docs/contract.md")
	if err != nil {
		t.Fatal(err)
	}
	if s := fmt.Sprintf("and %d at once for `mcp.send`", sendChecksInFlight); !strings.Contains(strings.Join(strings.Fields(string(b)), " "), s) {
		t.Errorf("docs/contract.md does not say %q", s)
	}
}
