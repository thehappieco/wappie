package membershiptest

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// Timings reads docs/contract.md's Timings table from the file at path:
// each row's name and its value. Each package that sets a timing checks
// its own rows against it (membership's TestContractTimingsMatchTheDocs
// and its twins in cmd/whatserverd, wsapi and mcpauth).
func Timings(tb testing.TB, path string) map[string]string {
	tb.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // G304: the test names the doc
	if err != nil {
		tb.Fatal(err)
	}
	_, section, ok := strings.Cut(string(b), "\n## Timings\n")
	if !ok {
		tb.Fatalf("%s has no timings", path)
	}
	rows := map[string]string{}
	for _, line := range strings.Split(section, "\n") {
		if strings.HasPrefix(line, "#") {
			break
		}
		cells := strings.Split(line, "|")
		if len(cells) < 4 || strings.HasPrefix(strings.TrimSpace(cells[1]), "---") || strings.TrimSpace(cells[1]) == "Timing" {
			continue
		}
		name := strings.TrimSpace(cells[1])
		if _, twice := rows[name]; twice {
			tb.Fatalf("%s's timing %q is there twice", path, name)
		}
		rows[name] = strings.TrimSpace(cells[2])
	}
	return rows
}

// Spoken is a duration as the docs write it: "1 hour", "55 minutes",
// "29 days", "100 milliseconds".
func Spoken(d time.Duration) string {
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
