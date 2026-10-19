package membership

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"whatserver2/internal/membership/membershiptest"
)

var spoken = membershiptest.Spoken

// timingsElsewhere are the rows of docs/contract.md's Timings table that
// other packages set and check: cmd/whatserverd's TestContractDocsMatchTheCode
// (its own timings, the store's and the kit's), and wsapi's and mcpauth's
// docs tests (the hot paths). Every other row must be this package's.
var timingsElsewhere = []string{
	"fresh", "backup fresh", "clock skew", "orphan", "heartbeat", "long-poll", "snapshot not found", "event not found",
	"event expiry", "call timeout", "feed grace", "check feed", "check snapshot", "check published", "check errors",
	"check round", "check parked", "check events", "hot path", "hot path bound",
}

// docs/contract.md's timings and limits that this package sets (the rest
// are the packages' of timingsElsewhere): each row must be the code's, and
// every row is checked by one package or another.
func TestContractTimingsMatchTheDocs(t *testing.T) {
	b, err := os.ReadFile("../../docs/contract.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	rows := membershiptest.Timings(t, "../../docs/contract.md")
	span := func(least, most time.Duration) string { return spoken(least) + " to " + spoken(most) }
	ours := map[string]string{
		"call bound":       spoken(callBound),
		"mode cache":       spoken(stateFor),
		"pace":             spoken(roundPace),
		"sweep":            spoken(sweepEvery),
		"round":            spoken(roundEvery),
		"leader retry":     spoken(leaderRetry),
		"peer checks":      spoken(peerRetry),
		"feed backoff":     span(feedBackoffMin, feedBackoffMax),
		"feed silent":      spoken(feedSilentAfter),
		"warn":             spoken(warnEvery),
		"round failing":    spoken(roundIncompleteAfter),
		"debounce":         spoken(snapshotDebounce),
		"snapshot":         spoken(snapshotEvery),
		"snapshot backoff": span(snapshotBackoffMin, snapshotBackoffMax),
		"labels":           spoken(labelsEvery),
		"event backoff":    span(eventBackoffMin, eventBackoffMax),
		"event scan":       spoken(eventsScanEvery),
		"load retry":       spoken(loadRetry),
		"load retry for":   spoken(loadRetryFor),
		"load retry late":  spoken(loadRetryLate),
	}
	for name, want := range ours {
		if got := rows[name]; got != want {
			t.Errorf("docs/contract.md's timing %q is %q, the code's is %q", name, got, want)
		}
		if slices.Contains(timingsElsewhere, name) {
			t.Errorf("the timing %q is this package's and another's", name)
		}
	}
	for name := range rows {
		if _, mine := ours[name]; !mine && !slices.Contains(timingsElsewhere, name) {
			t.Errorf("docs/contract.md's timing %q is checked by no test", name)
		}
	}
	for _, name := range timingsElsewhere {
		if _, ok := rows[name]; !ok {
			t.Errorf("docs/contract.md has no timing %q", name)
		}
	}

	flat := strings.Join(strings.Fields(doc), " ")
	for _, s := range []string{
		fmt.Sprintf("the process's budget (%d a second, bursts of %d)", hookPerSecond, hookBurst),
		fmt.Sprintf("its workspace's (%d a second, bursts of %d)", tenantPerSecond, tenantBurst),
		fmt.Sprintf("at most %d in flight", hookCalls),
		fmt.Sprintf("a %d MiB body", snapshotBodyLimit>>20),
		fmt.Sprintf("%d calls a second", int(time.Second/roundPace)),
	} {
		if !strings.Contains(flat, s) {
			t.Errorf("docs/contract.md does not say %q", s)
		}
	}
	events, err := os.ReadFile("../../docs/contract-events.md")
	if err != nil {
		t.Fatal(err)
	}
	if s := fmt.Sprintf("under %d KiB encoded", eventsBodyLimit>>10); !strings.Contains(strings.Join(strings.Fields(string(events)), " "), s) {
		t.Errorf("docs/contract-events.md does not say %q", s)
	}
}

// TestProbeBusyLinesMatchTheDocs: the lines a probe prints for a busy
// platform, which the installer reads as "try again", are those of
// docs/contract.md's row for their exit status.
func TestProbeBusyLinesMatchTheDocs(t *testing.T) {
	b, err := os.ReadFile("../../docs/contract.md")
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(b), "\n### Checking the secret: contract check\n")
	if !ok {
		t.Fatal("docs/contract.md has no contract check")
	}
	row := ""
	for _, line := range strings.Split(section, "\n") {
		if strings.HasPrefix(line, fmt.Sprintf("| `%d` |", ProbeNoAnswer)) {
			row = line
		}
	}
	secret := membershiptest.Secret(t)
	for _, status := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		c := clientOn(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
		}, nil)
		if err := c.Use(secret, ""); err != nil {
			t.Fatal(err)
		}
		res := c.Probe(context.Background(), ProbeBoth)
		if res.Code != ProbeNoAnswer || !strings.Contains(row, "`"+res.Line+"`") {
			t.Errorf("an unsigned %d: %d %q; docs/contract.md's row for exit %d: %q", status, res.Code, res.Line, ProbeNoAnswer, row)
		}
	}
}
