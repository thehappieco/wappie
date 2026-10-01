package mcpauth

import (
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// The name rule of docs/mcp-enclave.md §19.6 step 3, which a 0.6.0 reader
// applies to the name a client document or a registration declares (a name
// that fails is dropped there, not fatal) and this server applies to the
// claimed name a version-2 descriptor carries and to a console token's
// label. A name is in Unicode normalization form C, 1 to 100 code points,
// with no white space at either end and no two white-space characters in a
// row, no code point of the categories Cc, Cf, Zl, Zp, Co or Cs (bidi
// controls, zero-width characters, U+FEFF, tag characters), and a mix of
// scripts that UTS #39 calls highly restrictive: one script, or Latin with
// Han, Hiragana and Katakana, or Latin with Han and Bopomofo, or Latin with
// Han and Hangul, with Common and Inherited allowed throughout. A code point
// unassigned in Go's tables has no category and no script and passes, as
// the reader leaves unassigned code points untested, so a Unicode version
// apart cannot split the two.

// maxNameRunes bounds a name, in code points.
const maxNameRunes = 100

// refusedCategories are the categories no name may carry.
var refusedCategories = []*unicode.RangeTable{unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp, unicode.Co, unicode.Cs}

// restrictiveSets are the script sets UTS #39's highly restrictive level
// admits beyond a single script.
var restrictiveSets = [][]string{
	{"Latin", "Han", "Hiragana", "Katakana"},
	{"Latin", "Han", "Bopomofo"},
	{"Latin", "Han", "Hangul"},
}

// validClientName reports whether s is a name by the rule, as given: a
// claimed name is compared with the form the reader attested, so it must
// already be in NFC.
func validClientName(s string) bool {
	if !utf8.ValidString(s) || !norm.NFC.IsNormalString(s) {
		return false
	}
	n := utf8.RuneCountInString(s)
	if n < 1 || n > maxNameRunes {
		return false
	}
	first, _ := utf8.DecodeRuneInString(s)
	last, _ := utf8.DecodeLastRuneInString(s)
	if unicode.IsSpace(first) || unicode.IsSpace(last) {
		return false
	}
	scripts := map[string]bool{}
	previousSpace := false
	for _, r := range s {
		space := unicode.IsSpace(r)
		if space && previousSpace {
			return false
		}
		previousSpace = space
		if unicode.In(r, refusedCategories...) {
			return false
		}
		if script := scriptOf(r); script != "" && script != "Common" && script != "Inherited" {
			scripts[script] = true
		}
	}
	if len(scripts) <= 1 {
		return true
	}
	for _, set := range restrictiveSets {
		if subset(scripts, set) {
			return true
		}
	}
	return false
}

// normalName is a token label as this server keeps it: the person's text in
// NFC, when that passes the rule.
func normalName(s string) (string, bool) {
	s = norm.NFC.String(s)
	return s, validClientName(s)
}

// scriptOf is the script property of a code point, "" when Go's tables have
// none for it.
func scriptOf(r rune) string {
	// The scripts a name is most likely in first; any other after.
	for _, name := range []string{"Latin", "Common", "Inherited", "Han", "Hiragana", "Katakana", "Hangul", "Cyrillic", "Greek", "Arabic"} {
		if unicode.Is(unicode.Scripts[name], r) {
			return name
		}
	}
	for name, table := range unicode.Scripts {
		if unicode.Is(table, r) {
			return name
		}
	}
	return ""
}

func subset(scripts map[string]bool, set []string) bool {
	for script := range scripts {
		found := false
		for _, s := range set {
			if s == script {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
