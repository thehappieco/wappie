package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"whatserver2/internal/config"
)

func writeEnv(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadDotEnv(t *testing.T) {
	path := writeEnv(t, `
# a comment
WS_FOO=bar

  WS_SPACED  =  padded
export WS_EXPORTED=yes
WS_QUOTED="has spaces"
WS_SINGLE='single quoted'
WS_EMPTY=
WS_EQUALS=a=b=c
`)
	for _, k := range []string{"WS_FOO", "WS_SPACED", "WS_EXPORTED", "WS_QUOTED", "WS_SINGLE", "WS_EMPTY", "WS_EQUALS"} {
		t.Setenv(k, "")
		if err := os.Unsetenv(k); err != nil {
			t.Fatal(err)
		}
	}
	if err := config.LoadDotEnv(path); err != nil {
		t.Fatalf("LoadDotEnv: %v", err)
	}
	for k, want := range map[string]string{
		"WS_FOO":      "bar",
		"WS_SPACED":   "padded",
		"WS_EXPORTED": "yes",
		"WS_QUOTED":   "has spaces",
		"WS_SINGLE":   "single quoted",
		"WS_EMPTY":    "",
		"WS_EQUALS":   "a=b=c", // only the first = separates
	} {
		if got := os.Getenv(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}

// The real environment always wins. A stale .env on a laptop must never be able
// to redirect a deployment that passed its own configuration in.
func TestRealEnvironmentBeatsDotEnv(t *testing.T) {
	path := writeEnv(t, "WS_PRECEDENCE=from_file\n")
	t.Setenv("WS_PRECEDENCE", "from_environment")

	if err := config.LoadDotEnv(path); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("WS_PRECEDENCE"); got != "from_environment" {
		t.Fatalf("WS_PRECEDENCE = %q; the file overrode the real environment", got)
	}
}

// Most deployments have no .env at all, so its absence is not an error.
func TestMissingFileIsFine(t *testing.T) {
	if err := config.LoadDotEnv(filepath.Join(t.TempDir(), "nope.env")); err != nil {
		t.Fatalf("a missing file should not be an error: %v", err)
	}
}

func TestMalformedLineIsReportedWithItsNumber(t *testing.T) {
	path := writeEnv(t, "WS_OK=1\nthis is not an assignment\n")
	err := config.LoadDotEnv(path)
	if err == nil {
		t.Fatal("expected an error")
	}
	if got := err.Error(); !contains(got, "line 2") {
		t.Errorf("error should name the line: %v", err)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
