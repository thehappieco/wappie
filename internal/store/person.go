package store

import (
	"strings"

	"go.mau.fi/whatsmeow/types"
)

// One person, several phones.
//
// A receipt is stored exactly as WhatsApp addressed it, device suffix and all —
// 224437861388494:12@lid is a particular phone, not a particular person. That is
// the right thing to keep: it is how "delivered at 14:02 and again at 19:40"
// turns out to be a laptop and a handset rather than a mystery. It is the wrong
// thing to count. A group of eight where three people carry two devices each
// would show eleven readers, and a tick that waits for everyone would wait for
// a denominator that does not exist.
//
// So the folding happens in the projection and never on disk. Nothing here
// rewrites a stored identifier.

// PersonKey is the identity a reader is counted under.
//
// LID first, matching the rule everywhere else: WhatsApp routes over LID now,
// LID exists precisely so a phone number never has to appear, and a known half
// is never replaced by an empty one.
//
// A key that does not parse comes back unchanged rather than collapsing to
// something. types.ParseJID accepts a string with no "@" at all and hands back a
// user on the default server, so folding on a parse failure would file every
// malformed key under one person — and that person would appear to have read
// everything.
func PersonKey(key, lid string) string {
	if p, ok := nonAD(lid); ok {
		return p
	}
	if p, ok := nonAD(key); ok {
		return p
	}
	return key
}

// nonAD strips the device suffix, reporting whether the value was usable.
func nonAD(raw string) (string, bool) {
	if raw == "" || !strings.Contains(raw, "@") {
		return "", false
	}
	jid, err := types.ParseJID(raw)
	if err != nil || jid.IsEmpty() || jid.User == "" {
		return "", false
	}
	return jid.ToNonAD().String(), true
}

// aliases folds the identifiers that name the same person into one.
//
// A receipt row carries up to three: the key it was addressed by, and either
// half of the identity beside it. Different rows for the same person can arrive
// addressed differently — that is the whole reason receipts are keyed on the
// message id and never on the chat — so counting on any single column splits
// one reader into two, and a tick waiting for everyone waits forever.
//
// Deliberately keyed on the WHOLE identifier and not on the user part. A LID
// whose digits happen to match somebody's phone number is a different person,
// and the client's own directory documents the same trap.
type aliases struct{ parent map[string]string }

func newAliases() *aliases { return &aliases{parent: map[string]string{}} }

func (a *aliases) find(x string) string {
	root, ok := a.parent[x]
	if !ok {
		a.parent[x] = x
		return x
	}
	if root == x {
		return x
	}
	top := a.find(root)
	a.parent[x] = top
	return top
}

func (a *aliases) union(xs ...string) {
	var first string
	for _, x := range xs {
		if x == "" {
			continue
		}
		if first == "" {
			first = a.find(x)
			continue
		}
		other := a.find(x)
		if other != first {
			a.parent[other] = first
		}
	}
}

// link records that these identifiers belong to one person, and returns the
// name that person is counted under.
func (a *aliases) link(row ReceiptRow) string {
	key, lid, pn := row.ReaderKey, row.ReaderLID, row.ReaderPN
	if p, ok := nonAD(key); ok {
		key = p
	}
	if p, ok := nonAD(lid); ok {
		lid = p
	}
	if p, ok := nonAD(pn); ok {
		pn = p
	}
	a.union(PersonKey(key, lid), key, lid, pn)
	return a.find(PersonKey(key, lid))
}
