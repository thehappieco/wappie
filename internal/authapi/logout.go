package authapi

import (
	"net/http"
	"slices"

	"github.com/google/uuid"

	"whatserver2/internal/store"
)

// logoutSourceHeader names who asked for a full sign-out: which of the
// console's buttons or cards. It is a label for the log line, so that a
// sign-out nobody remembers asking for can be traced to the control that
// sent it; it authorizes nothing and changes nothing the logout does. A
// header rather than a body field: the body is decoded strictly, and a
// newer console's field would make an older server answer 400 and keep the
// session. The console sends it to its own origin only, where no preflight
// stands in the way (the browser origin policy does not list it).
const logoutSourceHeader = "X-Wappie-Logout-Source"

// logoutSources are the labels a console sends. testdata/logout-sources.json
// holds the same list, which the cloud console's test reads too.
var logoutSources = []string{
	"chatlist", "admin", "shell-back", "error-card", "account-section", "switcher", "assistant-page", "draft-link", "message-link",
}

// logoutSource is the request's label: its one header value when the list
// has it, else "other" (none, an unknown or empty one, or more than one).
func logoutSource(r *http.Request) string {
	values := r.Header.Values(logoutSourceHeader)
	if len(values) == 1 && slices.Contains(logoutSources, values[0]) {
		return values[0]
	}
	return "other"
}

// logSignOut writes the one line a logout leaves: who asked, whether it
// ended the browser's whole family, and how many sessions were still live
// (a repeat ends none). Without a bearer there is nothing to log.
func (h *Handler) logSignOut(r *http.Request, allRelated bool, ended store.EndedSessions) {
	attrs := []any{"source", logoutSource(r), "all_related", allRelated, "revoked", ended.Revoked}
	if ended.User != uuid.Nil {
		attrs = append(attrs, "user", ended.User)
	}
	h.log().Info("signed out", attrs...)
}
