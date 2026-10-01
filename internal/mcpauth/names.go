package mcpauth

import (
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// The name rule of docs/mcp-enclave.md §19.6 step 3, as this server applies
// it to the claimed name a version-2 descriptor carries, to a tested
// client's display name and to a console token's label: a name is in Unicode
// normalization form C, 1 to 100 code points, with no white space at either
// end and no two white-space characters in a row, and no code point of the
// categories Cc, Cf, Zl, Zp, Co or Cs (bidi controls, zero-width characters,
// U+FEFF, tag characters). The reader also requires the name's scripts to be
// highly restrictive in UTS #39's sense, over Script_Extensions; this server
// does not judge scripts. A claimed name reaches it only once the attested
// reader kept it, and Go's tables have the Script property alone, under
// which a name the reader rightly keeps ("ޅކ ١٢", Thaana with Arabic-Indic
// digits) would read as two scripts and fail a consent the contract admits.
// A code point unassigned in Go's tables has no category and passes, as the
// reader leaves unassigned code points untested, so a Unicode version apart
// cannot split the two. Both suites run the shared vectors,
// packages/mcp-http/test/vectors/client-names.json.

// maxNameRunes bounds a name, in code points.
const maxNameRunes = 100

// refusedCategories are the categories no name may carry.
var refusedCategories = []*unicode.RangeTable{unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp, unicode.Co, unicode.Cs}

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
	}
	return true
}

// normalName is a token label as this server keeps it: the person's text in
// NFC, when that passes the rule.
func normalName(s string) (string, bool) {
	s = norm.NFC.String(s)
	return s, validClientName(s)
}
