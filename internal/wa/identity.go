package wa

import (
	"sync/atomic"

	"go.mau.fi/whatsmeow/types"
)

// Identity is a device's WhatsApp identity: a LID, optionally a phone number,
// and the push name.
//
// LID is primary. WhatsApp routes direct messages over LID now, and LID exists
// specifically to withhold the phone number, so PN may legitimately be absent
// forever. The v1 server rewrote every LID to a phone number on ingest and
// backfilled old rows on each reconnect; that is no longer possible, let alone
// correct. Both identifiers are carried, neither is rewritten.
//
// Identity values are immutable. Updating one means swapping the whole struct
// through the atomic pointer below, never mutating a field in place.
type Identity struct {
	LID types.JID
	PN  types.JID
	// PushName is the display name this device presents. It is our own name,
	// set from events.PushNameSetting — not events.PushName, which reports a
	// *contact's* name changing and has nothing to do with this device.
	PushName string
	// BusinessName is the verified business name, when the account has one.
	// Distinct from PushName: a business account has both, and they differ.
	BusinessName string
}

// Known reports whether the device has any usable identity yet. It is false
// between creating a device and completing pairing.
func (i Identity) Known() bool {
	return !i.LID.IsEmpty() || !i.PN.IsEmpty()
}

// Primary returns the identifier to key on: LID when present, phone number
// otherwise.
func (i Identity) Primary() types.JID {
	if !i.LID.IsEmpty() {
		return i.LID
	}
	return i.PN
}

// String renders the identity for logs.
func (i Identity) String() string {
	switch {
	case !i.LID.IsEmpty() && !i.PN.IsEmpty():
		return i.LID.String() + " (" + i.PN.User + ")"
	case !i.LID.IsEmpty():
		return i.LID.String()
	case !i.PN.IsEmpty():
		return i.PN.String()
	default:
		return "<unpaired>"
	}
}

// identityHolder stores an Identity behind an atomic pointer.
//
// This replaces the v1 server's plain struct field, which was written by the
// whatsmeow event handler goroutine on PairSuccess and read concurrently by
// every HTTP and websocket handler with no synchronisation at all. Swapping an
// immutable value means a reader always observes a complete, self-consistent
// identity rather than a half-updated one.
type identityHolder struct {
	v atomic.Pointer[Identity]
}

func (h *identityHolder) get() Identity {
	if p := h.v.Load(); p != nil {
		return *p
	}
	return Identity{}
}

// merge applies only the non-empty fields of next, so a later event that
// carries just a push name cannot erase a LID learned earlier.
func (h *identityHolder) merge(next Identity) Identity {
	for {
		old := h.v.Load()
		merged := Identity{}
		if old != nil {
			merged = *old
		}
		if !next.LID.IsEmpty() {
			merged.LID = next.LID
		}
		if !next.PN.IsEmpty() {
			merged.PN = next.PN
		}
		// The same rule the v1 store learned the hard way: never overwrite a
		// good name with an empty string.
		if next.PushName != "" {
			merged.PushName = next.PushName
		}
		if next.BusinessName != "" {
			merged.BusinessName = next.BusinessName
		}
		if h.v.CompareAndSwap(old, &merged) {
			return merged
		}
	}
}
