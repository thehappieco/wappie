package mcpauth

import (
	"encoding/json"
	"regexp"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// The text rules of docs/mcp-enclave.md §17.10, which the enclave applies to
// every draft and send before anything is sealed or sent, applied here again
// to every text this server sends for a connection. Same table, same
// vectors: packages/mcp-http/enclave/test/send-text-vectors.json, which the
// enclave's textrules.mjs reads too.
//
// A text is refused, in this order, for control characters (C0 but tab and
// newline, DEL, C1, and lone surrogates), for the bidi embeddings, overrides
// and isolates, for being empty once white space is trimmed as JavaScript's
// trim() trims it, and, where links are refused, for a link. Every other
// character is kept, the invisible ones included: the console marks them for
// the person, which is what they are for.

// Why a text was refused, in the words the reader's guidance uses.
const (
	textEmpty     = "empty"
	textControl   = "control characters"
	textDirection = "text-direction controls"
	textLinks     = "links"
	textTooLong   = "length"
)

// linkPattern is the image's: anything that starts a web address.
var linkPattern = regexp.MustCompile(`(?i)(?:https?://|www\.)`)

// normalizeNewlines turns \r\n and \r into \n, as the enclave does before it
// checks or seals a text.
func normalizeNewlines(text string) string {
	return strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\r", "\n")
}

// textRefusal says why a text is refused, or "" when it passes. links refuses
// a web address too; maxUnits bounds its length in UTF-16 code units, the
// reader's unit, and 0 leaves it unbounded.
func textRefusal(text string, links bool, maxUnits int) string {
	text = normalizeNewlines(text)
	if maxUnits > 0 && len(utf16.Encode([]rune(text))) > maxUnits {
		return textTooLong
	}
	if !utf8.ValidString(text) || strings.ContainsFunc(text, controlChar) {
		return textControl
	}
	if strings.ContainsFunc(text, directionControl) {
		return textDirection
	}
	// trimName trims what trim() does once the controls are gone: Go's white
	// space adds only NEL, a C1 control, refused above.
	if trimName(text) == "" {
		return textEmpty
	}
	if links && linkPattern.MatchString(text) {
		return textLinks
	}
	return ""
}

// controlChar is a character no sent text may carry: the C0 controls but tab
// and newline, DEL, the C1 controls, and a surrogate on its own.
func controlChar(r rune) bool {
	return r < 0x20 && r != '\t' && r != '\n' || r >= 0x7F && r <= 0x9F || r >= 0xD800 && r <= 0xDFFF
}

// directionControl is a bidi embedding, override or isolate: what makes a
// text read differently from the order it is sent in.
func directionControl(r rune) bool {
	return r >= 0x202A && r <= 0x202E || r >= 0x2066 && r <= 0x2069
}

// jsonString decodes a JSON string exactly. encoding/json turns a lone
// surrogate escape (\ud800) and invalid UTF-8 into U+FFFD without a word,
// which would let a text the rules refuse pass as another; here either one
// is refused.
func jsonString(raw json.RawMessage) (string, bool) {
	var s string
	if !utf8.Valid(raw) || json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		if i+1 >= len(raw) {
			return "", false
		}
		if raw[i+1] != 'u' {
			i++
			continue
		}
		high, ok := hex4(raw, i+2)
		if !ok {
			return "", false
		}
		switch {
		case high >= 0xDC00 && high <= 0xDFFF:
			return "", false
		case high >= 0xD800 && high <= 0xDBFF:
			if i+11 >= len(raw) || raw[i+6] != '\\' || raw[i+7] != 'u' {
				return "", false
			}
			low, ok := hex4(raw, i+8)
			if !ok || low < 0xDC00 || low > 0xDFFF {
				return "", false
			}
			i += 11
		default:
			i += 5
		}
	}
	return s, true
}

// hex4 reads the four hex digits of a \u escape at raw[at:].
func hex4(raw []byte, at int) (rune, bool) {
	if at+4 > len(raw) {
		return 0, false
	}
	var v rune
	for _, c := range raw[at : at+4] {
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= rune(c - '0')
		case c >= 'a' && c <= 'f':
			v |= rune(c-'a') + 10
		case c >= 'A' && c <= 'F':
			v |= rune(c-'A') + 10
		default:
			return 0, false
		}
	}
	return v, true
}
