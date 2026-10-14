package config

import (
	"bufio"
	"fmt"
	"io"
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

	pairs, err := parseDotEnv(f)
	if err != nil {
		return fmt.Errorf("config: %s %w", path, err)
	}
	for _, p := range pairs {
		if _, present := os.LookupEnv(p.key); present {
			continue
		}
		if err := os.Setenv(p.key, p.value); err != nil {
			return fmt.Errorf("config: %s line %d: %w", path, p.line, err)
		}
	}
	return nil
}

// ParseDotEnv reads the keys named from KEY=VALUE pairs, in LoadDotEnv's
// syntax, without touching the process environment. It exists for the root
// commands that need two settings of a file holding many secrets
// (contract-secret seal reads runtime.env for its KMS key alone): the map
// holds what they name and nothing else of the file.
//
// A named key assigned twice is refused: LoadDotEnv keeps a repeated key's
// first value and systemd's EnvironmentFile= its last, so the root step and
// the service the unit runs would each take a different one. An error names
// keys and lines, never a line's text, which may hold a secret.
func ParseDotEnv(r io.Reader, keys ...string) (map[string]string, error) {
	pairs, err := parseDotEnv(r)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	named := make(map[string]bool, len(keys))
	for _, k := range keys {
		named[k] = true
	}
	out := make(map[string]string, len(keys))
	lines := make(map[string]int, len(keys))
	for _, p := range pairs {
		if !named[p.key] {
			continue
		}
		if first, seen := lines[p.key]; seen {
			return nil, fmt.Errorf("config: %s is assigned twice, lines %d and %d: keep one "+
				"(LoadDotEnv would take the first, systemd's EnvironmentFile= the last)", p.key, first, p.line)
		}
		lines[p.key] = p.line
		out[p.key] = p.value
	}
	return out, nil
}

// dotEnvPair is one assignment of a .env file, with its line for errors.
type dotEnvPair struct {
	key, value string
	line       int
}

func parseDotEnv(r io.Reader) ([]dotEnvPair, error) {
	var pairs []dotEnvPair
	scanner := bufio.NewScanner(r)
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
			// The line is not echoed: a runtime.env holds secrets, and a
			// value pasted without its key is still one.
			return nil, fmt.Errorf("line %d: expected KEY=VALUE", line)
		}
		key = strings.TrimSpace(key)
		if key == "" {
			return nil, fmt.Errorf("line %d: empty key", line)
		}
		pairs = append(pairs, dotEnvPair{key: key, value: unquote(strings.TrimSpace(value)), line: line})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	return pairs, nil
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
