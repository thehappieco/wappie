package membership

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// docs/contract.md's timings and limits that this package sets (the rest
// are cmd/whatserverd's TestContractDocsMatchTheCode's): each row must be
// the code's, and the code's each row.
func TestContractTimingsMatchTheDocs(t *testing.T) {
	b, err := os.ReadFile("../../docs/contract.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	_, section, ok := strings.Cut(doc, "\n## Timings\n")
	if !ok {
		t.Fatal("docs/contract.md has no timings")
	}
	rows := map[string]string{}
	for _, line := range strings.Split(section, "\n") {
		if strings.HasPrefix(line, "#") {
			break
		}
		if cells := strings.Split(line, "|"); len(cells) >= 4 {
			rows[strings.TrimSpace(cells[1])] = strings.TrimSpace(cells[2])
		}
	}
	span := func(least, most time.Duration) string { return spoken(least) + " to " + spoken(most) }
	for name, want := range map[string]string{
		"call bound":       spoken(callBound),
		"mode cache":       spoken(stateFor),
		"pace":             spoken(roundPace),
		"sweep":            spoken(sweepEvery),
		"round":            spoken(roundEvery),
		"leader retry":     spoken(leaderRetry),
		"feed backoff":     span(feedBackoffMin, feedBackoffMax),
		"feed silent":      spoken(feedSilentAfter),
		"round failing":    spoken(roundIncompleteAfter),
		"debounce":         spoken(snapshotDebounce),
		"snapshot":         spoken(snapshotEvery),
		"snapshot backoff": span(snapshotBackoffMin, snapshotBackoffMax),
		"event backoff":    span(eventBackoffMin, eventBackoffMax),
		"event scan":       spoken(eventsScanEvery),
		"load retry":       spoken(loadRetry),
		"load retry for":   spoken(loadRetryFor),
		"load retry late":  spoken(loadRetryLate),
	} {
		if got := rows[name]; got != want {
			t.Errorf("docs/contract.md's timing %q is %q, the code's is %q", name, got, want)
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

// spoken is a duration as the docs write it: "1 hour", "55 minutes",
// "29 days", "100 milliseconds" (cmd/whatserverd's test has its twin).
func spoken(d time.Duration) string {
	unit := func(n int64, one string) string {
		if n == 1 {
			return "1 " + one
		}
		return fmt.Sprintf("%d %ss", n, one)
	}
	day := 24 * time.Hour
	switch {
	case d > day && d%day == 0:
		return unit(int64(d/day), "day")
	case d%time.Hour == 0:
		return unit(int64(d/time.Hour), "hour")
	case d%time.Minute == 0:
		return unit(int64(d/time.Minute), "minute")
	case d%time.Second == 0:
		return unit(int64(d/time.Second), "second")
	}
	return unit(int64(d/time.Millisecond), "millisecond")
}
