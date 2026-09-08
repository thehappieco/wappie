package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// LoadDotEnv reads KEY=VALUE pairs from a file into the process environment.
//
// Variables already set in the real environment always win. A .env file is a
// convenience for local development, and it must never be able to override what
// a deployment explicitly passed in — that is how a stale file on a laptop ends
// up pointing at the wrong database.
//
// A missing file is not an error: most deployments have no .env at all.
func LoadDotEnv(path string) (err error) {
	// The path comes from the program itself, not from user input: callers
	// pass a literal ".env". Nothing external chooses this file.
	//nolint:gosec // G304: caller-supplied constant path
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("config: open %s: %w", path, err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("config: close %s: %w", path, cerr)
		}
	}()

	scanner := bufio.NewScanner(f)
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		// Tolerate the "export FOO=bar" form, since people paste these files
		// from shell scripts and back again.
		text = strings.TrimPrefix(text, "export ")

		key, value, ok := strings.Cut(text, "=")
		if !ok {
			return fmt.Errorf("config: %s line %d: expected KEY=VALUE, got %q", path, line, text)
		}
		key = strings.TrimSpace(key)
		if key == "" {
			return fmt.Errorf("config: %s line %d: empty key", path, line)
		}
		if _, present := os.LookupEnv(key); present {
			continue
		}
		if err := os.Setenv(key, unquote(strings.TrimSpace(value))); err != nil {
			return fmt.Errorf("config: %s line %d: %w", path, line, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("config: read %s: %w", path, err)
	}
	return nil
}

// unquote strips one matching pair of surrounding quotes.
func unquote(v string) string {
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
			return v[1 : len(v)-1]
		}
	}
	return v
}
