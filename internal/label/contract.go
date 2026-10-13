// Package label names a number to people who may no longer see it: the
// snapshot a notice and an event row keep of a deleted number, so they can
// say which one it was after the number itself is gone (decision 0038).
//
// Nothing here ever reads a LID, and nothing here returns a phone number.
package label

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// MaxLabel is the longest label, in code points: the contract's limit, and
// the CHECK on item_events.label and device_notices.label (0050).
const MaxLabel = 80

// ellipsis starts a masked run of digits and a hint: U+2026, never dots.
const ellipsis = "…"

// digitRun is how many digits make a run that could be a phone number.
const digitRun = 7

// placeholders are the names Wappie gives a number nobody named: the
// server's own default (wsapi's pair handler), the console's "Número do
// WhatsApp" and "Número sem nome", each in its five languages. A placeholder
// says nothing about which number it was, so it is no label.
var placeholders = func() map[string]bool {
	out := map[string]bool{}
	for _, p := range []string{
		"device",
		"Número do WhatsApp", "WhatsApp number", "Número de WhatsApp", "Numéro WhatsApp", "WhatsApp-Nummer",
		"Número sem nome", "Unnamed number", "Número sin nombre", "Numéro sans nom", "Unbenannte Nummer",
	} {
		out[fold(p)] = true
	}
	return out
}()

// fold is how a candidate is compared with a placeholder: NFC, case folded,
// with its controls gone and its whitespace collapsed. A Caser keeps state,
// so each call has its own.
func fold(s string) string {
	return cases.Fold().String(strings.Join(strings.FieldsFunc(stripHidden(norm.NFC.String(s)), unicode.IsSpace), " "))
}

// The console's rules for a name that is really an id (ui/deviceLabel.ts):
// a UUID or 24 or more hex digits, or a legacy label that was the start of
// the device's own id.
var (
	opaqueID     = regexp.MustCompile(`(?i)^(?:[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}|[0-9a-f]{24,})$`)
	legacyPrefix = regexp.MustCompile(`(?i)^[0-9a-f]{6,}$`)
)

// Contract is the label a notice and an event row keep of a number (the
// plan's contractLabel, D15): the platform contract's rule for a name a
// person gave an item (docs/contract/v1, 8.1, contract.CleanLabel), applied
// to the number's label, else its WhatsApp push name. Nil when neither
// leaves anything.
//
// First, as the contract asks of the app, a candidate is set aside when it
// is a placeholder, an opaque or legacy id, or the number itself: its digits
// hold the last seven of the phone number's. Then, after NFC, anything with
// an "@" (or a character that reads as one) goes, since it may be an
// address; control and format characters go; whitespace collapses; every
// run of seven or more digits, with the separators people type between
// them, becomes "…" and its last four digits; and it is cut at 80 code
// points, never leaving half a flag.
//
// The console never computes this: notices render the server's snapshot.
func Contract(label, pushName, pn, deviceID string) *string {
	last7 := ""
	if digits := asciiDigits(userPart(pn)); len(digits) >= digitRun {
		last7 = digits[len(digits)-digitRun:]
	}
	for _, candidate := range []string{label, pushName} {
		if setAside(candidate, last7, deviceID) {
			continue
		}
		if out := Clean(candidate); out != "" {
			return &out
		}
	}
	return nil
}

// setAside reports a candidate that names no number: empty, a placeholder,
// an id, or the number itself.
func setAside(candidate, last7, deviceID string) bool {
	trimmed := strings.TrimSpace(stripHidden(candidate))
	switch {
	case trimmed == "", placeholders[fold(trimmed)], opaqueID.MatchString(trimmed):
		return true
	case legacyPrefix.MatchString(trimmed) && deviceID != "" && strings.HasPrefix(strings.ToLower(deviceID), strings.ToLower(trimmed)):
		return true
	}
	return last7 != "" && strings.Contains(asciiDigits(candidate), last7)
}

// Clean is the contract's CleanLabel over NFC text: what of a name may
// leave Wappie, or "" when nothing does. Cleaning a clean label changes
// nothing.
func Clean(raw string) string {
	s := clean(norm.NFC.String(raw))
	if !norm.NFC.IsNormalString(s) {
		// Taking hidden characters out can bring marks together that NFC
		// composes: compose them, and clean what that left.
		s = clean(norm.NFC.String(s))
	}
	return s
}

// atSigns are "@" and the characters that read as one: an address hides
// behind them too.
const atSigns = "@＠﹫"

func clean(raw string) string {
	if !utf8.ValidString(raw) || strings.ContainsAny(raw, atSigns) {
		return ""
	}
	// Whitespace after the hidden characters, so a run of digits a no-break
	// space split is seen whole.
	s := strings.Join(strings.FieldsFunc(stripHidden(raw), unicode.IsSpace), " ")
	return cut(maskDigitRuns(s), MaxLabel)
}

// hidden reports the characters a label never carries: C0 and C1 controls,
// and every format character (bidirectional controls, zero-width
// characters, the soft hyphen, the word joiner), with the combining grapheme
// joiner, which could hide, split or reorder what a reader sees.
func hidden(r rune) bool {
	return r < 0x20 || r >= 0x7f && r <= 0x9f || r == 0x034f || unicode.Is(unicode.Cf, r)
}

func stripHidden(s string) string {
	return strings.Map(func(r rune) rune {
		if hidden(r) {
			return -1
		}
		return r
	}, s)
}

// separator reports the characters that may sit between the digits of a
// number someone typed: "+55 (11) 91234-5678", "11.91234.5678",
// "11/91234/5678", "55_11_91234_5678", "119·1234·5678", any dash, and the
// minus sign, which reads as one.
func separator(r rune) bool {
	switch r {
	case ' ', '.', ',', '/', '_', '(', ')', '+', '-', '·', '•', '*', '#', '−':
		return true
	}
	return unicode.Is(unicode.Pd, r)
}

// maskDigitRuns replaces every run of seven or more digits, of any script,
// with separators between them, by "…" and the run's last four digits. The
// separators inside a run go with it, and so does a "+" or "(" just before
// it; the rest around it stays.
func maskDigitRuns(s string) string {
	rs := []rune(s)
	var out []rune
	for i := 0; i < len(rs); {
		if !unicode.IsDigit(rs[i]) {
			out = append(out, rs[i])
			i++
			continue
		}
		last, digits := i, []rune{}
		for j := i; j < len(rs); j++ {
			if unicode.IsDigit(rs[j]) {
				digits = append(digits, rs[j])
				last = j
				continue
			}
			if !separator(rs[j]) {
				break
			}
		}
		end := last + 1
		if len(digits) >= digitRun {
			for len(out) > 0 && (out[len(out)-1] == '+' || out[len(out)-1] == '(') {
				out = out[:len(out)-1]
			}
			out = append(out, []rune(ellipsis)...)
			out = append(out, digits[len(digits)-4:]...)
		} else {
			out = append(out, rs[i:end]...)
		}
		i = end
	}
	return string(out)
}

// cut keeps max code points, never leaving a lone regional indicator (half
// a flag).
func cut(s string, max int) string {
	rs := []rune(s)
	if len(rs) <= max {
		return s
	}
	rs = rs[:max]
	n := 0
	for i := len(rs) - 1; i >= 0 && rs[i] >= 0x1f1e6 && rs[i] <= 0x1f1ff; i-- {
		n++
	}
	if n%2 == 1 {
		rs = rs[:len(rs)-1]
	}
	return strings.TrimSpace(string(rs))
}

// asciiDigits is the decimal digits of s, of any script, as ASCII.
func asciiDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsDigit(r) {
			b.WriteByte("0123456789"[digitValue(r)])
		}
	}
	return b.String()
}

// digitValue is a decimal digit's value. Unicode's decimal digits come in
// sets of ten, zero first, some of them back to back, so the value is the
// rune's place in its run of digits, modulo ten.
func digitValue(r rune) int {
	if r >= '0' && r <= '9' {
		return int(r - '0')
	}
	n := 0
	for n < 100 && unicode.IsDigit(r-rune(n)-1) {
		n++
	}
	return n % 10
}

// userPart is the user part of a stored JID: before ":" (the companion
// device) and "@".
func userPart(jid string) string {
	user, _, _ := strings.Cut(jid, "@")
	user, _, _ = strings.Cut(user, ":")
	return user
}

// HintFromPN is "…" and the last four digits of the user part of a stored
// phone-number JID ("5511912345678:12@s.whatsapp.net" gives "…5678"), or nil
// when fewer than four digits are left. The rest of the number never leaves
// it, and a LID-only number has no hint at all: it is never given a LID.
func HintFromPN(pn string) *string {
	var digits []byte
	user := userPart(pn)
	for i := 0; i < len(user); i++ {
		if c := user[i]; c >= '0' && c <= '9' {
			digits = append(digits, c)
		}
	}
	if len(digits) < 4 {
		return nil
	}
	hint := ellipsis + string(digits[len(digits)-4:])
	return &hint
}
