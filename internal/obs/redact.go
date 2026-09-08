package obs

import (
	"log/slog"
	"regexp"
)

// Redaction of identifiers in log output.
//
// The archive seals content and leaves routing in the clear, and the README
// says so. What it did not say is that the same routing reached the logs:
// phone numbers at INFO every boot, chat and contact JIDs on every error path,
// the account's email on every line of a session. A log aggregator then held
// the social graph the database holds — without the row-level security, and
// with whatever retention the aggregator has.
//
// So the logger masks them on the way out, at every level. A JID keeps its
// server and last four digits, which is enough to match a line to a row for
// somebody who has the database, and not enough to name anyone for somebody
// who has only the logs. An email keeps its first letter and its domain.
//
// Applied to every string attribute and to the message, not to a list of
// known keys: the list would drift the first time somebody logged a JID under
// a new name.

var (
	// tokenRE matches anything shaped like user@host: a WhatsApp identifier
	// or an email. Which it is decides how it is masked; one pass, so the
	// masked form of one cannot be re-read as the other. The colon is for
	// the device suffix a JID may carry (…:26@lid).
	tokenRE = regexp.MustCompile(`[A-Za-z0-9._%+:-]+@[A-Za-z0-9.-]+`)
	// jidRE is the WhatsApp shape: digits (a group adds a hyphen and more
	// digits), an optional device suffix, at one of the servers whatsmeow
	// routes to.
	jidRE = regexp.MustCompile(`^(\d[\d-]*?)(\d{4})(:\d+)?@(s\.whatsapp\.net|lid|g\.us|c\.us|newsletter|hosted|bot)$`)
	// emailRE is an address with a real domain.
	emailRE = regexp.MustCompile(`^([A-Za-z0-9])[A-Za-z0-9._%+-]*(@[A-Za-z0-9.-]+\.[A-Za-z]{2,})$`)
	// phoneRE is a bare number: ten to fifteen digits standing alone, the
	// way Identity.String() prints one in parentheses. A shorter run is a
	// count or a sequence; a longer one is not a phone number.
	phoneRE = regexp.MustCompile(`(^|[^0-9A-Za-z@:.-])\+?(\d{6,11})(\d{4})($|[^0-9A-Za-z@:.-])`)
)

// Redact masks the identifiers in s.
func Redact(s string) string {
	s = tokenRE.ReplaceAllStringFunc(s, func(token string) string {
		if m := jidRE.FindStringSubmatch(token); m != nil {
			return "…" + m[2] + m[3] + "@" + m[4]
		}
		if m := emailRE.FindStringSubmatch(token); m != nil {
			return m[1] + "…" + m[2]
		}
		return token
	})
	return phoneRE.ReplaceAllString(s, "$1…$3$4")
}

// redactAttr is the slog ReplaceAttr hook. Groups are irrelevant: a JID is a
// JID wherever it is nested.
func redactAttr(_ []string, a slog.Attr) slog.Attr {
	if a.Value.Kind() == slog.KindString {
		return slog.String(a.Key, Redact(a.Value.String()))
	}
	return a
}
