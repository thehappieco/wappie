package membership

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/store"
)

// The numbers section (the spec's 14.3; the kit's NumbersSettings): what
// Wappie's own tables say of one platform workspace's numbers, in the
// console's terms. A row carries no label (a number's label lives in the
// snapshot), no byte count (null until the privacy text names it), and no
// move_out preview (null while accepts lacks item.move_out).

// NumberLooks is what the leader's process knows of a registration that
// is not in the database: whether a pairing of it runs now, and whether
// the process holds it at all (running, pairing, reserved or stopped and
// not yet released). The registry (*wa.Registry) is one; nil means none
// runs and none may be retried.
type NumberLooks interface {
	PairingSince(id string) (time.Time, bool)
	Holds(id string) bool
}

// runs are the kinds this binary runs per section in the mode on: the
// numbers kinds, item.sync_now among them since the socket's frame asks a
// person's Read too, as its runner does (the platform's answer 4, DS13),
// the three flags kinds (step 12b, DS46: listed from the release that
// carries them, with no switch), and the person's two. Never item.relink
// or a kind of kit v0.11.0 (the whole document would be refused).
var runs = map[string][]string{
	kc.SectionNumbers: {kc.OpItemRename, kc.OpItemSyncStop, kc.OpItemSyncResume, kc.OpItemSyncNow, kc.OpItemRegistrationDelete,
		kc.OpItemFlagsRaise, kc.OpItemFlagsDrop, kc.OpItemAccessRemove},
	kc.SectionPerson: {kc.OpPersonNoticesDismiss, kc.OpPersonSignOutEverywhere},
}

// accepts are the kinds the settings mode lets this binary run for
// section (kc.SectionPerson for a person's document): none while it only
// reads, never null.
func accepts(mode, section string) []string {
	if mode != store.SettingsOn {
		return []string{}
	}
	return append([]string{}, runs[section]...)
}

// pendingOf is a registration's row as the leader's process sees it: a
// pairing under way, and whether the retry act may start one, by the
// retry's own rules (the socket's device.pair with resume): no pairing
// held here, and a key to keep.
func pendingOf(p store.ContractPending, looks NumberLooks) kc.PendingRegistration {
	row := kc.PendingRegistration{ID: p.ID.String(), CreatedAt: kc.T(p.CreatedAt)}
	if looks == nil {
		return row
	}
	_, row.Pairing = looks.PairingSince(row.ID)
	row.CanRetry = !row.Pairing && !looks.Holds(row.ID) && p.Epoch > 0
	return row
}

// numberRow is one number's row. read_only is the spec's (logged out or
// banned), a deleted number's (the platform's commitment), and a number
// with no identity stored (it connected for a pairing that never linked,
// or, rarely, Wappie failed to save the identity of one that did): Wappie
// holds no session it could start for it from what it stored, which the
// spec's read_only code names ("no session to the number"). Its sync now
// is not_linked, and a pause of it could not be lifted from the console
// (can_resume false, the resume state_changed), so the console holds both
// back, as on a logged-out number. In Wappie its start, its pairing retry
// (it connected) and its relink (no identity to compare) all refuse it:
// an owner deletes it and links the phone as a new number.
func numberRow(n store.ContractNumber) kc.NumberRow {
	loggedOut := n.Status == "logged_out"
	banned := n.Status == "banned"
	row := kc.NumberRow{ID: n.ID.String(), Connection: connectionOf(n), Capture: "on", RecoveryOpen: n.RecoveryOpen,
		ReadOnly: loggedOut || banned || n.Deleted || !n.Known}
	if n.LastConnectedAt != nil {
		at := kc.T(*n.LastConnectedAt)
		row.LastConnectedAt = &at
	}
	// A deleted number captures nothing whatever its pause says: no
	// console button shows before the platform's own guard (the platform's
	// answers, Wappie's commitment).
	if n.Paused || n.Deleted {
		row.Capture = "paused"
		row.PausedBy = pausedBy(n)
	}
	row.CanResume = n.Paused && !n.Deleted && n.Known && !loggedOut && !banned
	if n.Epoch > 0 {
		epoch := int64(n.Epoch)
		row.KeyEpoch = &epoch
	}
	return row
}

// connectionOf is a number's connection code.
func connectionOf(n store.ContractNumber) string {
	switch {
	case n.Deleted && n.Status == "banned":
		return "banned"
	case n.Deleted:
		return "logged_out_deletion"
	case n.Status == "logged_out" && n.LogoutCause == "deletion":
		return "logged_out_deletion"
	case n.Status == "logged_out":
		return "logged_out_phone"
	case n.Status == "banned", n.Status == "pairing", n.Status == "online":
		return n.Status
	}
	return "offline"
}

// pausedBy is who paused a number, or null when its time or its actor is
// not known (DS7): the kit refuses a paused_by with no time, and one such
// row would refuse the whole section.
func pausedBy(n store.ContractNumber) *kc.PausedBy {
	if !n.Paused || n.PausedAt == nil || n.PausedByKind == "" {
		return nil
	}
	p := &kc.PausedBy{Kind: n.PausedByKind, At: kc.T(*n.PausedAt)}
	if n.PausedByKind != kc.ActorApp && n.PausedBySub != nil {
		sub := n.PausedBySub.String()
		p.Sub = &sub
	}
	return p
}

// numbersDoc is the numbers section of read, as the settings mode lets it
// be sent: its accepts the mode's, a list over its bound sent empty with
// truncated (never cut), and the data encoded with no HTML escaping. A
// workspace Wappie has no workspace for gets an empty section.
func numbersDoc(read store.ContractNumbers, mode string, looks NumberLooks) (kc.SettingsDoc, error) {
	data := kc.NumbersSettings{CanLink: read.CanLink, StoragePaused: read.StoragePaused,
		Pending: []kc.PendingRegistration{}, Items: []kc.NumberRow{}}
	if !read.PendingOver {
		for _, p := range read.Pending {
			data.Pending = append(data.Pending, pendingOf(p, looks))
		}
	}
	if !read.ItemsOver {
		for _, n := range read.Items {
			data.Items = append(data.Items, numberRow(n))
		}
	}
	raw, err := encodeData(data)
	if err != nil {
		return kc.SettingsDoc{}, err
	}
	snapshotSeq := read.SnapshotSeq
	return kc.SettingsDoc{V: kc.SettingsV, Type: kc.SettingsType, App: App, Section: kc.SectionNumbers, Producer: kc.ProducerWappie,
		WorkspaceID: read.Workspace.String(), StateSeq: read.Seq, SnapshotSeq: &snapshotSeq, MeasuredAt: kc.T(read.MeasuredAt),
		Truncated: read.Over(), Accepts: accepts(mode, kc.SectionNumbers), Data: raw}, nil
}

// numbersSection is read's numbers section as Wappie sends it, checked as
// the platform reads it (sectionRule). A row the wire refuses is left out,
// and the section goes truncated (the spec's 14.2, "A row the wire
// refuses": every row sent is whole and true); dropped names those rows.
// No database row makes one: only a bug of Wappie's does, which the sender
// logs at ERROR. why and rule say why a section is still not sent: one
// that fails with no row at all, or for a rule no row breaks alone (an
// item twice), or over the call's limit.
func numbersSection(read store.ContractNumbers, mode string, looks NumberLooks) (doc kc.SettingsDoc, dropped []uuid.UUID,
	why string, rule error) {
	doc, err := numbersDoc(read, mode, looks)
	why, rule = "encode", err
	if err == nil {
		if why, rule = sectionRule(doc); why == "" || why == "too_large" {
			return doc, nil, why, rule
		}
	}
	// Each row in a section with no other row: one the section refuses with
	// no row at all puts no row to blame.
	alone := read
	alone.Pending, alone.Items, alone.PendingOver, alone.ItemsOver = nil, nil, false, false
	passes := func(one store.ContractNumbers) bool {
		d, err := numbersDoc(one, mode, looks)
		return err == nil && d.Validate() == nil
	}
	if !passes(alone) {
		return doc, nil, why, rule
	}
	kept := read
	kept.Pending, kept.Items = []store.ContractPending{}, []store.ContractNumber{}
	if !read.PendingOver {
		for _, p := range read.Pending {
			one := alone
			one.Pending = []store.ContractPending{p}
			if passes(one) {
				kept.Pending = append(kept.Pending, p)
			} else {
				dropped = append(dropped, p.ID)
			}
		}
	}
	if !read.ItemsOver {
		for _, n := range read.Items {
			one := alone
			one.Items = []store.ContractNumber{n}
			if passes(one) {
				kept.Items = append(kept.Items, n)
			} else {
				dropped = append(dropped, n.ID)
			}
		}
	}
	if len(dropped) == 0 {
		return doc, nil, why, rule
	}
	if doc, err = numbersDoc(kept, mode, looks); err != nil {
		return kc.SettingsDoc{}, dropped, "encode", err
	}
	doc.Truncated = true
	why, rule = sectionRule(doc)
	return doc, dropped, why, rule
}

// encodeData is a document's data as the kit sends a body (its
// marshalPlain): no HTML escaping, so an & or a < in a name is one byte, not
// six, and no newline after it. A nil list is the caller's to make [].
func encodeData(v any) (json.RawMessage, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// pendingSent is a workspace's registrations as its last numbers section
// sent them: the pairing look compares what the process sees now with it.
type pendingSent map[uuid.UUID]pendingRow

// pendingRow is one registration's epoch as read, and its pairing and
// retry as sent.
type pendingRow struct {
	epoch             int
	pairing, canRetry bool
}
