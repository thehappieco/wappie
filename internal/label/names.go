package label

import (
	"regexp"
	"strings"
)

// Name is what of a row's name may leave Wappie in a contract section (an
// MCP connection's name and what its client calls itself, an API key's
// name, an AI key's label, an installation's name), or nil when nothing
// may (decision DS36). It is Clean, NFC first, and nil when that leaves
// nothing or when the name is set aside:
//   - an opaque id, as Contract sets one aside: a UUID, or 24 or more hex
//     characters;
//   - a provider key's shape: a word starting sk- (sk-ant-, sk-proj-),
//     AIza, xai- or gsk_, or a run of 24 or more base64url characters that
//     mixes letters and digits (a run of letters alone is a long name);
//   - a name equal, case folded, to one of avoid (the row's client id, its
//     redirect host), or to one of them cleaned.
//
// The name is checked as stored and as cleaned, so a key that a hidden
// character splits, or whose digits Clean masks, is still set aside, and
// what is left never holds one. Name of what Name gave is the same.
//
// The gate is at render: stored names stay, and Wappie's own screens show
// them as they are.
func Name(s string, avoid ...string) *string {
	out := Clean(s)
	if out == "" {
		return nil
	}
	avoided := map[string]bool{}
	for _, a := range avoid {
		for _, f := range []string{fold(a), fold(Clean(a))} {
			if f != "" {
				avoided[f] = true
			}
		}
	}
	if nameAside(s, avoided) || nameAside(out, avoided) {
		return nil
	}
	return &out
}

var (
	// keyPrefix is a word that starts as a provider's API key does:
	// OpenAI's and Anthropic's sk- (with sk-proj- and sk-ant-), Google's
	// AIza, xAI's xai- and Groq's gsk_. Case counts, as in the keys, so
	// "SK-II" stays a name.
	keyPrefix = regexp.MustCompile(`\b(?:sk-|AIza|xai-|gsk_)`)
	// keyRun is a run of base64url characters long enough to be a key;
	// an AI key's label may hold 60 characters, a whole key.
	keyRun = regexp.MustCompile(`[A-Za-z0-9_-]{24,}`)
)

// nameAside reports a name that is an opaque id, holds a key's shape, or
// is one of the avoided names (folded).
func nameAside(s string, avoided map[string]bool) bool {
	trimmed := strings.TrimSpace(stripHidden(s))
	if opaqueID.MatchString(trimmed) || keyPrefix.MatchString(trimmed) || avoided[fold(s)] {
		return true
	}
	for _, run := range keyRun.FindAllString(trimmed, -1) {
		if strings.ContainsAny(run, "0123456789") && strings.ContainsFunc(run, asciiLetter) {
			return true
		}
	}
	return false
}

func asciiLetter(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
}
