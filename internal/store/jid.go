package store

import "go.mau.fi/whatsmeow/types"

// parseJID converts a stored string back to a JID, returning the empty JID for
// blank or malformed input.
func parseJID(s string) types.JID {
	if s == "" {
		return types.EmptyJID
	}
	jid, err := types.ParseJID(s)
	if err != nil {
		return types.EmptyJID
	}
	return jid
}
