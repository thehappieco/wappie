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

// runs are the kinds this binary runs per section in the mode on: none in
// the read release, so a section's accepts is [] in every mode.
var runs = map[string][]string{}

// accepts are the kinds the settings mode lets this binary run for
// section: none while it only reads, never null.
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

// numberRow is one number's row.
func numberRow(n store.ContractNumber) kc.NumberRow {
	loggedOut := n.Status == "logged_out"
	banned := n.Status == "banned"
	row := kc.NumberRow{ID: n.ID.String(), Connection: connectionOf(n), Capture: "on", RecoveryOpen: n.RecoveryOpen,
		ReadOnly: loggedOut || banned || n.Deleted}
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
