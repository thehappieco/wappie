// Command pslgen turns publicsuffix.org's public_suffix_list.dat into the
// snapshot internal/netguard embeds (docs/mcp-enclave.md §19.5):
//
//	go run ./internal/netguard/pslgen -date 2026-02-06 -revision <git sha> \
//	    < public_suffix_list.dat > internal/netguard/psl/psl-2026-02-06.json
//
// The snapshot is a JSON object with the list's date and git revision and
// two arrays of rules, the ICANN section's and the private section's, each in
// ASCII (an internationalized rule in its xn-- form, lower case), deduplicated
// and sorted by byte, one rule per line, with the List's own "*." and "!"
// prefixes. The same bytes are committed at packages/mcp-http/psl/ for the
// enclave; both test suites pin the file's SHA-256, so a refresh is the two
// copies and the two pins in one change.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/net/idna"
)

// Snapshot is the file's shape.
type Snapshot struct {
	ListDate     string   `json:"list_date"`
	ListRevision string   `json:"list_revision"`
	ICANN        []string `json:"icann"`
	Private      []string `json:"private"`
}

// Format names the shape, for a reader that wants to refuse another one.
const Format = "wappie-psl/v1"

var (
	datePattern     = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	revisionPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	rulePattern     = regexp.MustCompile(`^(\*\.|!)?[a-z0-9-]+(\.[a-z0-9-]+)*$`)
)

func main() {
	date := flag.String("date", "", "the list's date, YYYY-MM-DD")
	revision := flag.String("revision", "", "the list's git revision, 40 hex characters")
	flag.Parse()
	if !datePattern.MatchString(*date) || !revisionPattern.MatchString(*revision) {
		fmt.Fprintln(os.Stderr, "pslgen: -date YYYY-MM-DD and -revision <40 hex> are required")
		os.Exit(2)
	}
	s, err := Parse(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pslgen:", err)
		os.Exit(1)
	}
	s.ListDate, s.ListRevision = *date, *revision
	if _, err := os.Stdout.Write(Encode(s)); err != nil {
		fmt.Fprintln(os.Stderr, "pslgen:", err)
		os.Exit(1)
	}
}

// Parse reads the List: the rules between its ICANN markers go to ICANN,
// the rules between its private markers to Private, and a rule outside both
// is an error, as is a rule that is not a domain once in ASCII.
func Parse(r io.Reader) (Snapshot, error) {
	const (
		outside = iota
		icann
		private
	)
	section := outside
	seen := map[string]bool{}
	var s Snapshot
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.Contains(line, "===BEGIN ICANN DOMAINS==="):
			section = icann
			continue
		case strings.Contains(line, "===BEGIN PRIVATE DOMAINS==="):
			section = private
			continue
		case strings.Contains(line, "===END ICANN DOMAINS==="), strings.Contains(line, "===END PRIVATE DOMAINS==="):
			section = outside
			continue
		case line == "" || strings.HasPrefix(line, "//"):
			continue
		}
		// A rule ends at the first white space; the rest of the line is not
		// part of it.
		rule, err := ascii(strings.Fields(line)[0])
		if err != nil {
			return Snapshot{}, fmt.Errorf("%q: %w", line, err)
		}
		if section == outside {
			return Snapshot{}, fmt.Errorf("%q is outside both sections", line)
		}
		if seen[rule] {
			continue
		}
		seen[rule] = true
		if section == icann {
			s.ICANN = append(s.ICANN, rule)
		} else {
			s.Private = append(s.Private, rule)
		}
	}
	if err := scanner.Err(); err != nil {
		return Snapshot{}, err
	}
	if len(s.ICANN) == 0 || len(s.Private) == 0 {
		return Snapshot{}, errors.New("a section is empty; this is not the List")
	}
	slices.Sort(s.ICANN)
	slices.Sort(s.Private)
	return s, nil
}

// ascii is a rule in its lower-case ASCII form, its prefix kept.
func ascii(rule string) (string, error) {
	prefix := ""
	for _, p := range []string{"*.", "!"} {
		if rest, ok := strings.CutPrefix(rule, p); ok {
			prefix, rule = p, rest
			break
		}
	}
	name, err := idna.Lookup.ToASCII(rule)
	if err != nil {
		return "", err
	}
	out := prefix + strings.ToLower(name)
	if !rulePattern.MatchString(out) {
		return "", errors.New("not a rule")
	}
	return out, nil
}

// Encode writes the snapshot with one rule per line, so that a refresh
// reads as a diff of rules.
func Encode(s Snapshot) []byte {
	var b strings.Builder
	field := func(name string, v any) {
		raw, err := json.Marshal(v)
		if err != nil {
			panic(err) // strings never fail to marshal
		}
		fmt.Fprintf(&b, "%q: %s,\n", name, raw)
	}
	list := func(name string, rules []string, last bool) {
		fmt.Fprintf(&b, "%q: [\n", name)
		for i, rule := range rules {
			raw, err := json.Marshal(rule)
			if err != nil {
				panic(err)
			}
			b.Write(raw)
			if i < len(rules)-1 {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
		}
		b.WriteString("]")
		if !last {
			b.WriteByte(',')
		}
		b.WriteByte('\n')
	}
	b.WriteString("{\n")
	field("format", Format)
	field("list_date", s.ListDate)
	field("list_revision", s.ListRevision)
	list("icann", s.ICANN, false)
	list("private", s.Private, true)
	b.WriteString("}\n")
	return []byte(b.String())
}
