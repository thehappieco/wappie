package netguard

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

// The Public Suffix List snapshot (docs/mcp-enclave.md §19.5): the List at a
// pinned date, in the shape internal/netguard/pslgen writes, committed byte
// for byte here and at packages/mcp-http/psl/ for the enclave. No other
// source is used (not golang.org/x/net/publicsuffix), so the enclave, the
// egress proxy and the consent check compute the same registrable domain for
// every host. It is refreshed with each reader release.
//
//go:embed psl/psl-2026-02-06.json
var pslSnapshot []byte

// PSLFile is the embedded snapshot's name, for the tests that pin it.
const PSLFile = "psl/psl-2026-02-06.json"

// section is where a rule comes from in the List.
type section uint8

const (
	sectionICANN section = iota + 1
	sectionPrivate
)

// suffixList is the snapshot's rules by kind, keyed by the name they cover:
// a plain rule by itself, a wildcard rule ("*.ck") by its parent ("ck"), an
// exception rule ("!www.ck") by its name ("www.ck").
type suffixList struct {
	rules, wildcards, exceptions map[string]section
}

var loadList = sync.OnceValues(func() (*suffixList, error) {
	var raw struct {
		Format  string   `json:"format"`
		ICANN   []string `json:"icann"`
		Private []string `json:"private"`
	}
	if err := json.Unmarshal(pslSnapshot, &raw); err != nil {
		return nil, fmt.Errorf("netguard: the suffix list snapshot does not parse: %w", err)
	}
	if raw.Format != "wappie-psl/v1" || len(raw.ICANN) == 0 || len(raw.Private) == 0 {
		return nil, fmt.Errorf("netguard: the suffix list snapshot is not a wappie-psl/v1 list")
	}
	l := &suffixList{rules: map[string]section{}, wildcards: map[string]section{}, exceptions: map[string]section{}}
	for _, part := range []struct {
		rules []string
		s     section
	}{{raw.ICANN, sectionICANN}, {raw.Private, sectionPrivate}} {
		for _, rule := range part.rules {
			switch {
			case strings.HasPrefix(rule, "*."):
				l.wildcards[rule[2:]] = part.s
			case strings.HasPrefix(rule, "!"):
				l.exceptions[rule[1:]] = part.s
			default:
				l.rules[rule] = part.s
			}
		}
	}
	return l, nil
})

// list is the snapshot. It is embedded and checked by the tests, so a
// failure here is a broken build, not a condition to handle.
func list() *suffixList {
	l, err := loadList()
	if err != nil {
		panic(err)
	}
	return l
}

// suffix finds a host's public suffix by the List's algorithm: an exception
// rule that matches prevails and gives up its leftmost label; otherwise the
// matching rule with the most labels; otherwise the implicit "*", the last
// label. It returns how many of the host's labels the suffix spans and,
// when the prevailing rule is in the List, its section (0 for "*").
func (l *suffixList) suffix(labels []string) (int, section) {
	n := len(labels)
	for k := n; k >= 1; k-- {
		if s, ok := l.exceptions[strings.Join(labels[n-k:], ".")]; ok {
			return k - 1, s
		}
	}
	best, bestSection := 1, section(0)
	for k := 1; k <= n; k++ {
		if s, ok := l.rules[strings.Join(labels[n-k:], ".")]; ok && k >= best {
			best, bestSection = k, s
		}
		if k >= 2 {
			if s, ok := l.wildcards[strings.Join(labels[n-k+1:], ".")]; ok && k >= best {
				best, bestSection = k, s
			}
		}
	}
	return best, bestSection
}

// Registrable is a host's registrable domain (its public suffix and one
// label more) and, when that suffix comes from the List's private section,
// the suffix itself: "github.io" for "team.github.io". ok is false when the
// host is itself a public suffix, or shorter. The host must already be a
// lower-case ASCII name with no empty label; CheckHost makes sure of it.
func Registrable(host string) (registrable, sharedSuffix string, ok bool) {
	labels := strings.Split(host, ".")
	k, s := list().suffix(labels)
	if k >= len(labels) {
		return "", "", false
	}
	registrable = strings.Join(labels[len(labels)-k-1:], ".")
	if s == sectionPrivate {
		sharedSuffix = strings.Join(labels[len(labels)-k:], ".")
	}
	return registrable, sharedSuffix, true
}
