package relink

import (
	"context"
	"time"

	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// Facts are what a relink's checks before any QR judge a number on: its
// row, what the process sees of it, and the reads of its key and its
// account. Check reads them, with the side effect of releasing a stale
// hold; the numbers section reads them with none (its can_relink), so the
// two give one answer from one table (Judge).
type Facts struct {
	Status     wa.Status
	PauseCause string
	// Pairing: this process pairs the number now, since PairingSince.
	Pairing      bool
	PairingSince time.Time
	// Held: this process holds the number, and the hold is not a stale
	// one Check could release (a deletion's logout, a start).
	Held bool
	// PN and LID are the number's identity, non-AD, a missing half filled
	// from whatsmeow's map where it knows one (FillIdentity).
	PN, LID types.JID
	Epoch   int
	// KeyHeld: a person holds the number's key at its current epoch
	// (Devices.KeyHeld). HeldElsewhere: another live number of the
	// workspace holds the account (Devices.HeldElsewhere).
	KeyHeld, HeldElsewhere bool
	// Now is the clock item_busy's wait is counted on; zero is time.Now.
	Now time.Time
}

// Judge is the table of a relink's checks before any QR, in spec 14.13's
// order: item_busy (a pairing of the number, then a move's pause) before
// state_changed (not logged out), then item_busy for a hold that is not
// stale, read_only (no full identity), no_reader (no key or nobody holds
// it) and number_held. Nil when the number may be linked again now.
func Judge(f Facts) *Refusal {
	if r := judgeEntry(f); r != nil {
		return r
	}
	switch {
	case f.Held:
		return busy(busyElsewhere, "entry")
	case !FullIdentity(f.PN, f.LID):
		return refuse(CodeReadOnly, "entry")
	case f.Epoch < 1, !f.KeyHeld:
		return refuse(CodeNoReader, "entry")
	case f.HeldElsewhere:
		return refuse(CodeNumberHeld, "entry")
	}
	return nil
}

// judgeEntry is Judge's first three checks, which a stale hold's release
// waits for: a pairing of the number, a move's pause, not logged out.
func judgeEntry(f Facts) *Refusal {
	now := f.Now
	if now.IsZero() {
		now = time.Now()
	}
	switch {
	case f.Pairing:
		return busy(min(busyElsewhere, f.PairingSince.Add(wa.RelinkWindow).Sub(now)), "entry")
	case f.PauseCause == store.PauseForMove:
		return busy(busyElsewhere, "entry")
	case f.Status != wa.StatusLoggedOut:
		return refuse(CodeStateChanged, "entry")
	}
	return nil
}

// FullIdentity reports whether pn and lid are both halves of an account:
// a phone number and a LID, each with its user.
func FullIdentity(pn, lid types.JID) bool {
	return pn.Server == types.DefaultUserServer && pn.User != "" && lid.Server == types.HiddenUserServer && lid.User != ""
}

// FillIdentity is a number's identity non-AD, with a missing half filled
// from whatsmeow's map of LIDs and phone numbers when book knows it (nil
// fills nothing); fromMap says a half came from the map. Check and the
// numbers section's can_relink fill it alike.
func FillIdentity(ctx context.Context, book PhoneBook, pn, lid types.JID) (types.JID, types.JID, bool) {
	pn, lid = pn.ToNonAD(), lid.ToNonAD()
	fromMap := false
	if book == nil {
		return pn, lid, false
	}
	if pn.IsEmpty() && !lid.IsEmpty() {
		if found, ok := book.PhoneFor(ctx, lid); ok {
			pn, fromMap = found.ToNonAD(), true
		}
	}
	if lid.IsEmpty() && !pn.IsEmpty() {
		if found, ok := book.LIDFor(ctx, pn); ok {
			lid, fromMap = found.ToNonAD(), true
		}
	}
	return pn, lid, fromMap
}
