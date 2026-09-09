package store

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/domain"
	"whatserver2/internal/pg"
)

// maxThreadHops bounds the walk from a control row up to the message it
// ultimately acts on.
//
// An edit targets a message and a revoke targets either, so one hop is the
// real-world case and two is the deepest legitimate chain. The bound exists
// because target ids arrive from the network: a crafted pair of rows pointing
// at each other would otherwise loop forever.
const maxThreadHops = 8

// MessageHistory is the whole life of one message.
//
// This is the projection the product exists for. An ordinary client shows the
// current text of a message and, once it is deleted, nothing at all. Here the
// original and every revision are separate rows that were never overwritten,
// the deletion is a row rather than the absence of one, and the receipts say
// who had which revision on screen.
//
// Nothing in it is decrypted. Every body travels sealed exactly as it sits on
// disk; what this assembles is the structure around them, which is built
// entirely from routing columns the server can read.
type MessageHistory struct {
	DeviceID uuid.UUID
	ChatKey  string
	// WAID is the root — the message everything else acts on. Asking for the
	// history of an edit returns the history of what it edited.
	WAID string

	// Versions are the original and each revision, oldest first. A message
	// that was never edited has exactly one.
	Versions []Version

	// Deletion is the revoke, if one arrived. The content it removed is still
	// in Versions, which is the point.
	Deletion *Deletion

	Reactions []Reaction

	// Readers is one entry per party that acknowledged anything, with the
	// revision each of them most plausibly saw.
	Readers []Reader
}

// Version is one state of a message.
type Version struct {
	// Revision is 0 for the original and increments per edit.
	Revision int
	// Row carries this version's sealed body. The client opens it; the server
	// never can.
	Row Row
	// From is when this version became current, and Until when it stopped.
	// Until is nil on the newest one. Both come from the sender's clock and
	// are display values — ordering is by the row's sequence number.
	From  *time.Time
	Until *time.Time
}

// Deletion records a revoke.
type Deletion struct {
	Row Row
	// ByAuthor distinguishes an author deleting their own message from a group
	// admin deleting someone else's. WhatsApp shows different text for each
	// and the difference matters to anyone reading the archive later.
	ByAuthor bool
	// ByAdmin requires evidence of a different sender in a group. If neither
	// attribution is known, clients should display a neutral deletion label.
	ByAdmin bool
	At      *time.Time
}

// Reaction is one reaction row and what later became of it.
//
// The emoji is sealed, so this cannot say *what* the reaction was — and
// deliberately does not try. It says which reaction rows exist, who sent each,
// and which are still standing. A client that opens the bodies has everything
// it needs; a server that could group by emoji would be a server that can read
// its users' reactions.
//
// That is also why a withdrawal is not flagged here. WhatsApp removes a
// reaction by sending one with an empty emoji, and empty is a property of the
// sealed body. The client sees a superseding row and finds it empty.
type Reaction struct {
	Row Row
	// Superseded is set when the same party sent a later reaction to the same
	// message. WhatsApp allows one reaction per party, so only the newest
	// stands.
	Superseded bool
	// Revoked is set when a delete row targets this reaction specifically —
	// the case the stored target_rel exists to make unambiguous.
	Revoked   bool
	RevokedAt *time.Time
}

// Reader is one party's acknowledgements of a message.
type Reader struct {
	Key      string
	LID      string
	PN       string
	IsFromMe bool

	Delivered *time.Time
	Read      *time.Time
	Played    *time.Time

	// SawRevision is the revision this party most plausibly had on screen when
	// they read. Zero when they never read.
	SawRevision int
	// ConfirmedRevision is the newest revision this party's own device
	// acknowledged receiving before the read. It is a floor, not a guess.
	ConfirmedRevision int
	// Confirmed reports whether the two agree. When they do not, SawRevision
	// is inferred from two clocks that were never synchronised with each
	// other and the reader may still have been looking at the older text.
	Confirmed bool

	// ReadDevice names which of this person's devices produced the read the
	// three revision fields above describe. Empty when they never read.
	//
	// Present because those fields belong to a device rather than to a person.
	// The revision somebody had on screen is decided by what THAT handset had
	// received, and a person reading on a phone whose laptop is three edits
	// behind is an ordinary situation, not a puzzle.
	ReadDevice string

	// Devices is each of this person's devices and what it acknowledged.
	//
	// The reason the top-level fields are the EARLIEST across devices rather
	// than a merge: "received at 14:02 and again at 19:40" is one person with
	// two phones, and the moment they got it is the first one. The rest is
	// here rather than discarded, because the second timestamp is the only
	// evidence a second device exists at all.
	Devices []ReaderDevice

	// Revisions is the same acknowledgements, told per version: earliest
	// across this person's devices, revision by revision.
	//
	// The flat fields above answer "did this reach them, and did they read
	// it". These answer "did they get THIS text, and were they looking at it"
	// — which on a message that was corrected is a different question, and the
	// only one worth asking about a particular revision.
	//
	// Where the two can disagree, and which one to believe: this list is folded
	// across every one of the person's devices, while SawRevision and the two
	// fields beside it describe only the device that read EARLIEST. So somebody
	// whose phone read the original and whose laptop later read the correction
	// has both reads here and a SawRevision naming only the first. That is not
	// a contradiction — they answer different questions — but a reader asking
	// about a version must use this list, because the flat fields will say the
	// correction was never read.
	Revisions []ReaderRevision
}

// ReaderDevice is one handset's acknowledgements.
type ReaderDevice struct {
	// Key is the identifier as stored, device suffix and all.
	Key string
	// Agent and Device are WhatsApp's two-part device axis. Both, because a
	// JID prints as user.agent:device@server and ordering on the device number
	// alone shuffles between reloads.
	Agent  uint8
	Device uint16

	Delivered *time.Time
	Read      *time.Time
	Played    *time.Time

	SawRevision       int
	ConfirmedRevision int
	Confirmed         bool

	// Revisions is the same acknowledgements, told per version.
	Revisions []ReaderRevision
}

// ReaderRevision is what one party acknowledged about ONE version of a message.
//
// The distinction the flat fields above cannot make. Delivered there is the
// earliest across every version — which on a message edited twice answers "when
// did this reach them at all", and is silent on the question somebody opening
// a revision is actually asking: did they get THIS text.
//
// The two halves have different evidential weight, and it is not a nicety:
//
//   - Delivered is exact. Every version is a stanza with a WhatsApp id of its
//     own and collects its own delivery receipts, so a receipt naming this
//     version's id is the reader's own device stating that this text arrived.
//     That is the whole reason edits are stored as rows rather than folded into
//     the original.
//
//   - Read and Played are usually exact too, and for a reason that is easy to
//     miss: editing a message makes it unread again on the recipient's phone,
//     and reading it afresh sends a read receipt naming the EDIT's own stanza.
//     So a read receipt does not merely say somebody was looking at the
//     conversation around then — it names the revision they read.
//
//     They fall back to inference in one case, and it is our own: this client
//     folds every version into one line and marks it read under the ORIGINAL's
//     id, whatever text is on screen. Our other devices therefore say nothing
//     about revisions by their ids, and are attributed from what they had been
//     delivered instead. Confirmed distinguishes the two.
//
// A read is placed on exactly one revision. A party who read twice — before and
// after a correction — appears on two, which is the situation this type exists
// for and is exactly what the unread-again behaviour produces: two receipts
// naming two stanzas, which the receipts table keeps as two rows because it is
// keyed on (device, wa_id, reader, kind).
//
// One place none of this works: in a newsletter, whatsmeow reuses the
// original's id for the edit stanza (its send.go overrides req.ID when the
// server is NewsletterServer), so there are no per-version ids for receipts to
// arrive under. Newsletters do not report per-reader receipts anyway.
type ReaderRevision struct {
	Revision int

	// Delivered is when this party first confirmed receiving this version.
	// Exact, per the above.
	Delivered *time.Time

	// Read and Played are set only on the revision they were attributed to.
	Read   *time.Time
	Played *time.Time

	// Confirmed reports whether the attribution above is proof: the device
	// acknowledged receiving this exact version before it reported reading.
	// False means it was inferred by comparing clocks, and a UI that renders
	// it as fact is claiming somebody read a correction they may never have
	// been shown.
	Confirmed bool
}

// History assembles everything known about one message.
func (m *Messages) History(ctx context.Context, tenant, device uuid.UUID,
	chatKey, waID string, receipts *Receipts) (MessageHistory, error) {
	out := MessageHistory{DeviceID: device, ChatKey: chatKey}

	root, rows, err := m.thread(ctx, tenant, device, chatKey, waID)
	if err != nil {
		return MessageHistory{}, err
	}
	out.WAID = root

	byTarget := map[string][]Row{}
	var rootRow *Row
	for i := range rows {
		if rows[i].WAID == root && !rows[i].Kind.IsControl() {
			rootRow = &rows[i]
			continue
		}
		if t := rows[i].TargetWAID; t != "" {
			byTarget[t] = append(byTarget[t], rows[i])
		}
	}
	if rootRow == nil {
		// Every control row that acts on it is stored, but the message itself
		// never arrived — normal during a backfill, and the reason target
		// resolution is allowed to stay open.
		return MessageHistory{}, pgx.ErrNoRows
	}

	out.Versions = versionsOf(*rootRow, byTarget[root])
	out.Deletion = deletionOf(*rootRow, byTarget[root])
	out.Reactions = reactionsOf(byTarget)

	if receipts != nil {
		ids := make([]string, 0, len(out.Versions))
		for _, v := range out.Versions {
			ids = append(ids, v.Row.WAID)
		}
		acks, err := receipts.ForMessages(ctx, tenant, device, ids)
		if err != nil {
			return MessageHistory{}, err
		}
		out.Readers = readersOf(out.Versions, acks)
	}
	return out, nil
}

// thread returns the root message id and every row in its thread.
//
// One recursive query rather than four: the root, the rows that target it, and
// the rows that target those. The last level is not padding — a revoke of a
// reaction targets the reaction, so without it a withdrawn thumbs-up is
// indistinguishable from a standing one.
func (m *Messages) thread(ctx context.Context, tenant, device uuid.UUID,
	chatKey, waID string) (string, []Row, error) {
	var root string
	var out []Row

	err := pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		var err error
		root, err = rootOf(ctx, tx, device, chatKey, waID)
		if err != nil {
			return err
		}

		rows, err := tx.Query(ctx, `
			WITH RECURSIVE thread AS (
				SELECT * FROM messages
				 WHERE device_id = $1 AND chat_key = $2 AND wa_id = $3
			  UNION
				SELECT c.* FROM messages c JOIN thread t
				  ON c.device_id = t.device_id
				 AND c.chat_key  = t.chat_key
				 AND c.target_wa_id = t.wa_id
			)
			SELECT `+rowColumns+`
			  FROM thread m LEFT JOIN media md ON md.message_uid = m.uid
			 ORDER BY m.seq`, device, chatKey, root)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanRow(rows)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return "", nil, fmt.Errorf("store: read thread for %s: %w", waID, err)
	}
	return root, out, nil
}

// rootOf walks from any row in a thread up to the message it acts on.
//
// Asking for the history of an edit should return the history of what was
// edited, not a thread of one row. The loop is bounded because the ids it
// follows came off the wire.
func rootOf(ctx context.Context, tx pgx.Tx, device uuid.UUID, chatKey, waID string) (string, error) {
	current := waID
	for hop := 0; hop < maxThreadHops; hop++ {
		var target *string
		err := tx.QueryRow(ctx, `
			SELECT target_wa_id FROM messages
			 WHERE device_id = $1 AND chat_key = $2 AND wa_id = $3`,
			device, chatKey, current).Scan(&target)
		if err != nil {
			// A row we have never stored is its own root: the control rows
			// that target it are still worth returning.
			if errors.Is(err, pgx.ErrNoRows) {
				return current, nil
			}
			return "", err
		}
		if target == nil || *target == "" || *target == current {
			return current, nil
		}
		current = *target
	}
	return current, nil
}

// versionsOf builds the revision chain.
//
// Edits are ordered by sequence, not by the timestamp on them. The sequence is
// this server's own allocation order; the timestamp is the sender's clock,
// which an edited message can perfectly well carry backwards.
func versionsOf(root Row, children []Row) []Version {
	versions := []Version{{Revision: 0, Row: root, From: root.TS}}

	edits := make([]Row, 0, len(children))
	for _, c := range children {
		if c.Kind == domain.KindEdit {
			edits = append(edits, c)
		}
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].Seq < edits[j].Seq })

	for i, e := range edits {
		versions = append(versions, Version{Revision: i + 1, Row: e, From: e.TS})
	}
	for i := 0; i < len(versions)-1; i++ {
		versions[i].Until = versions[i+1].From
	}
	return versions
}

// deletionOf returns the revoke of the message itself, if any.
//
// Only rows whose target relation resolved to the message count. A delete
// whose target turned out to be a reaction is a withdrawn reaction, and
// reporting it here is precisely the bug that made v1 show "message deleted"
// where someone had taken back a thumbs-up.
func deletionOf(root Row, children []Row) *Deletion {
	var found *Row
	for i := range children {
		c := children[i]
		if c.Kind != domain.KindDelete || c.TargetRel == domain.TargetReaction {
			continue
		}
		if found == nil || c.Seq < found.Seq {
			found = &children[i]
		}
	}
	if found == nil {
		return nil
	}
	author, admin := deletionAttribution(root, *found)
	return &Deletion{Row: *found, ByAuthor: author, ByAdmin: admin, At: found.TS}
}

func deletionAttribution(root, revoke Row) (author, admin bool) {
	if !root.IsGroup {
		return true, false
	}
	if root.IsFromMe && revoke.IsFromMe {
		return true, false
	}
	ids := func(row Row) []types.JID {
		var out []types.JID
		for _, raw := range []string{row.SenderKey, row.SenderLID, row.SenderPN} {
			if jid, err := types.ParseJID(raw); err == nil && jid.User != "" && jid.Server != "" {
				out = append(out, jid.ToNonAD())
			}
		}
		return out
	}
	left, right := ids(root), ids(revoke)
	for _, a := range left {
		for _, b := range right {
			if a == b {
				return true, false
			}
		}
	}
	if root.IsFromMe != revoke.IsFromMe && len(left) > 0 && len(right) > 0 {
		return false, true
	}
	for _, a := range left {
		for _, b := range right {
			if a.Server == b.Server {
				return false, true
			}
		}
	}
	return false, false
}

// reactionsOf collects the reactions and works out which still stand.
func reactionsOf(byTarget map[string][]Row) []Reaction {
	var out []Reaction
	for _, children := range byTarget {
		for _, c := range children {
			if c.Kind != domain.KindReaction {
				continue
			}
			r := Reaction{Row: c}
			for _, d := range byTarget[c.WAID] {
				if d.Kind == domain.KindDelete {
					r.Revoked = true
					r.RevokedAt = d.TS
					break
				}
			}
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Row.Seq < out[j].Row.Seq })

	// WhatsApp allows one reaction per party per message, so a later one from
	// the same party replaces whatever it sent before. Marking the earlier
	// rows rather than dropping them keeps the history of a changed mind,
	// which is the same reason edits are kept.
	newest := map[string]int{}
	for i, r := range out {
		newest[r.Row.SenderKey] = i
	}
	for i := range out {
		if newest[out[i].Row.SenderKey] != i {
			out[i].Superseded = true
		}
	}
	return out
}

// readersOf turns raw acknowledgements into one entry per PERSON, each carrying
// what each of their devices did.
//
// Two passes, and the order is the whole correctness argument.
//
// The first pass is per device, exactly as this always worked: one
// deliveredPer map and one AttributeRead call per handset. That is what
// separates proof from inference. An edit is a stanza with an id of its own, so
// a delivery receipt naming it is that specific device stating that specific
// text arrived — a floor nothing can argue with. Merging the deliveries of a
// person's devices BEFORE attributing would let a delivery to their laptop
// confirm a read on their phone, and the answer would come back Confirmed with
// nothing on the wire saying so. It is the one mistake here that produces a
// stronger claim rather than a weaker one.
//
// The second pass folds devices into people, and copies the revision fields
// from the device whose read became the person's — never recomputes them.
func readersOf(versions []Version, acks []ReceiptRow) []Reader {
	type agg struct {
		ReaderDevice
		lid, pn  string
		isFromMe bool
		// deliveredPer records, per version id, when this device confirmed
		// receiving that exact version.
		deliveredPer map[string]time.Time
		// reads and plays are every such receipt from this device, not only
		// the earliest, and each keeps the id it named. Somebody who read
		// before a correction and again after it sent two, and collapsing them
		// to one leaves the correction looking unread by a person who is
		// looking straight at it.
		reads, plays []ack
	}
	byKey := map[string]*agg{}
	order := []string{}
	link := newAliases()

	for _, a := range acks {
		g, ok := byKey[a.ReaderKey]
		if !ok {
			agent, dev := deviceAxis(a.ReaderKey)
			g = &agg{
				ReaderDevice: ReaderDevice{Key: a.ReaderKey, Agent: agent, Device: dev},
				lid:          a.ReaderLID, pn: a.ReaderPN, isFromMe: a.IsFromMe,
				deliveredPer: map[string]time.Time{},
			}
			byKey[a.ReaderKey] = g
			order = append(order, a.ReaderKey)
		}
		link.link(a)
		ts := a.TS
		switch a.Kind {
		case domain.ReceiptDelivered:
			if prev, ok := g.deliveredPer[a.WAID]; !ok || ts.Before(prev) {
				g.deliveredPer[a.WAID] = ts
			}
			g.Delivered = earliest(g.Delivered, ts)
		case domain.ReceiptRead:
			g.Read = earliest(g.Read, ts)
			g.reads = append(g.reads, ack{WAID: a.WAID, TS: ts})
		case domain.ReceiptPlayed:
			g.Played = earliest(g.Played, ts)
			g.plays = append(g.plays, ack{WAID: a.WAID, TS: ts})
		}
	}

	// Pass one: attribute per device, against that device's own deliveries.
	times := versionTimes(versions)
	for _, k := range order {
		g := byKey[k]
		if g.Read != nil {
			g.SawRevision, g.ConfirmedRevision, g.Confirmed =
				AttributeRead(times, g.deliveredPer, *g.Read)
		} else {
			g.Confirmed = true
		}
		// Our own devices are the exception: this client marks a whole line
		// read under the original's id, whatever version is on screen, so its
		// ids carry no revision at all.
		g.Revisions = perRevision(times, g.deliveredPer, g.reads, g.plays, !g.isFromMe)
	}

	// Pass two: fold devices into people.
	people := map[string]*Reader{}
	peopleOrder := []string{}
	for _, k := range order {
		g := byKey[k]
		person := link.find(PersonKey(k, g.lid))
		r, ok := people[person]
		if !ok {
			r = &Reader{Key: person, IsFromMe: g.isFromMe, Confirmed: true}
			people[person] = r
			peopleOrder = append(peopleOrder, person)
		}
		// Never overwrite a known half of an identity with an empty one.
		if r.LID == "" {
			if v, ok := nonAD(g.lid); ok {
				r.LID = v
			}
		}
		if r.PN == "" {
			if v, ok := nonAD(g.pn); ok {
				r.PN = v
			}
		}
		r.IsFromMe = r.IsFromMe || g.isFromMe
		r.Delivered = earlier(r.Delivered, g.Delivered)
		r.Played = earlier(r.Played, g.Played)
		r.Revisions = foldRevisions(r.Revisions, g.Revisions)
		// The read, and the revision claims that belong to it, move together.
		// Splitting them would attach one device's certainty to another
		// device's moment.
		if g.Read != nil && (r.Read == nil || g.Read.Before(*r.Read)) {
			r.Read = g.Read
			r.SawRevision, r.ConfirmedRevision, r.Confirmed =
				g.SawRevision, g.ConfirmedRevision, g.Confirmed
			r.ReadDevice = g.Key
		}
		r.Devices = append(r.Devices, g.ReaderDevice)
	}

	out := make([]Reader, 0, len(peopleOrder))
	for _, k := range peopleOrder {
		r := people[k]
		// Stable across reloads. A JID prints as user.agent:device@server, so
		// the axis is the pair; ordering on the device number alone shuffles
		// two devices of one person between one page and the next.
		sort.Slice(r.Devices, func(i, j int) bool {
			a, b := r.Devices[i], r.Devices[j]
			if a.Agent != b.Agent {
				return a.Agent < b.Agent
			}
			if a.Device != b.Device {
				return a.Device < b.Device
			}
			return a.Key < b.Key
		})
		out = append(out, *r)
	}
	return out
}

// deviceAxis pulls WhatsApp's two-part device identity out of a stored key.
func deviceAxis(key string) (uint8, uint16) {
	jid, err := types.ParseJID(key)
	if err != nil {
		return 0, 0
	}
	return jid.RawAgent, jid.Device
}

// earlier keeps the first of two moments, either of which may be absent.
func earlier(a, b *time.Time) *time.Time {
	switch {
	case b == nil:
		return a
	case a == nil:
		return b
	case b.Before(*a):
		return b
	}
	return a
}

// VersionTime is what receipt attribution needs from a version.
type VersionTime struct {
	Revision int
	WAID     string
	// TS is when this version was sent. Zero when the row carried no plausible
	// timestamp, in which case the version is never selected on time alone.
	TS *time.Time
}

func versionTimes(versions []Version) []VersionTime {
	out := make([]VersionTime, 0, len(versions))
	for _, v := range versions {
		out = append(out, VersionTime{Revision: v.Revision, WAID: v.Row.WAID, TS: v.From})
	}
	return out
}

// AttributeRead decides which revision of a message a reader had on screen.
//
// Two sources of evidence, and the difference between them is the whole point
// of returning three values instead of one.
//
// The floor is proof. Every version — the original and each edit — is a
// separate stanza with an id of its own, so a delivery receipt naming an edit's
// id is the reader's own device stating that that exact text arrived. The
// newest such version acknowledged at or before the read is a revision the
// reader certainly had.
//
// The ceiling is inference. It is the newest version sent at or before the
// read according to the timestamps — but those timestamps come from two
// different clocks, ours and WhatsApp's, and an edit sent a second before a
// read may not have reached the reader's screen at all.
//
// When the two agree there is nothing to caveat. When they do not, the caller
// gets both numbers and a false, rather than a confident answer to a question
// the data cannot settle. Reporting the inference alone would be a UI stating
// that someone read a correction they may never have seen.
func AttributeRead(versions []VersionTime, deliveredPer map[string]time.Time,
	readAt time.Time) (saw, confirmed int, certain bool) {
	for _, v := range versions {
		if d, ok := deliveredPer[v.WAID]; ok && !d.After(readAt) && v.Revision > confirmed {
			confirmed = v.Revision
		}
	}
	for _, v := range versions {
		if v.TS == nil || v.TS.IsZero() {
			continue
		}
		if !v.TS.After(readAt) && v.Revision > saw {
			saw = v.Revision
		}
	}
	// Proof outranks a clock comparison. A delivery receipt for revision two
	// before the read settles it even if revision two carries a timestamp
	// after the read, which happens whenever the sender's clock runs fast.
	if confirmed > saw {
		saw = confirmed
	}
	return saw, confirmed, saw == confirmed
}

func earliest(cur *time.Time, next time.Time) *time.Time {
	if cur == nil || next.Before(*cur) {
		t := next
		return &t
	}
	return cur
}

// perRevision tells one device's acknowledgements version by version.
//
// Delivery is copied straight across: a delivery receipt names the version's
// own stanza id, so it is that device stating that exact text arrived.
//
// Reads and plays are placed by the id they name, and that is the strongest
// evidence in this whole projection. Editing a message makes it unread again on
// the recipient's phone; reading it afresh sends a read receipt naming the
// EDIT's stanza. So a read receipt is not a vague "they were looking at the
// conversation around then" — it names the revision, and the revision it names
// is the one they read.
//
// AttributeRead survives as the fallback, for a receipt whose id belongs to no
// version here. That is not a hypothetical: this client's OWN reads always name
// the original, because the browser folds every version into one line and marks
// that line's id read. Our other devices therefore say nothing about revisions
// by their ids, and get the older treatment — the revision worked out from what
// that device had been delivered, reported as inferred.
//
// Each receipt is placed separately rather than only the earliest, because
// somebody who read before a correction and again after it belongs on two
// revisions. Whether one device produces two read rows depends on the peer:
// the receipts table is keyed on (device, wa_id, reader, kind), so a second
// read is a second row exactly when it names a different stanza — which, per
// the rule above, is what an edit causes.
//
// One place it cannot work at all: in a newsletter, whatsmeow reuses the
// original's id for the edit stanza, so there are no per-version ids for
// receipts to arrive under.
func perRevision(versions []VersionTime, delivered map[string]time.Time,
	reads, plays []ack, named bool) []ReaderRevision {
	if len(versions) == 0 {
		return nil
	}
	out := make([]ReaderRevision, 0, len(versions))
	index := map[int]int{}
	revisionOf := map[string]int{}
	for _, v := range versions {
		revisionOf[v.WAID] = v.Revision
		index[v.Revision] = len(out)
		// Confirmed starts false here, unlike the flat field, which starts
		// true to mean "nothing was claimed". This one qualifies a Read, and a
		// true sitting next to an absent read is a value a template can render
		// as "confirmado" for a version nobody looked at.
		rev := ReaderRevision{Revision: v.Revision}
		if d, ok := delivered[v.WAID]; ok {
			t := d
			rev.Delivered = &t
		}
		out = append(out, rev)
	}

	place := func(a ack) (int, bool, bool) {
		if named {
			if rev, ok := revisionOf[a.WAID]; ok {
				// The receipt names this stanza. Nothing beats that.
				i, ok := index[rev]
				return i, true, ok
			}
		}
		saw, _, certain := AttributeRead(versions, delivered, a.TS)
		i, ok := index[saw]
		return i, certain, ok
	}

	for _, a := range reads {
		i, certain, ok := place(a)
		if !ok {
			continue
		}
		// The earliest read on a revision is the one shown, and its certainty
		// travels with it: a later, better-evidenced read must not lend its
		// confidence to an earlier moment.
		if out[i].Read == nil || a.TS.Before(*out[i].Read) {
			t := a.TS
			out[i].Read = &t
			out[i].Confirmed = certain
		}
	}

	for _, a := range plays {
		i, _, ok := place(a)
		if !ok {
			continue
		}
		if out[i].Played == nil || a.TS.Before(*out[i].Played) {
			t := a.TS
			out[i].Played = &t
		}
	}
	return out
}

// ack is one acknowledgement, kept with the id it named.
//
// The id is the point. A read receipt names the stanza that was read, and an
// edit is a stanza of its own — so for anybody but ourselves the id says which
// revision, with no inference in the middle.
type ack struct {
	WAID string
	TS   time.Time
}

// foldRevisions merges one device's per-version record into the person's.
//
// Earliest wins, per revision and per field, for the same reason the flat
// fields are the earliest across devices: "received at 14:02 and again at
// 19:40" is one person with two phones, and when they got it is the first one.
//
// Read and Confirmed move together. Splitting them would attach one device's
// certainty to another device's moment — which is the failure
// TestOneDevicesDeliveryIsNotProofAboutAnother exists to catch, and it fails
// loud and confident rather than safe.
func foldRevisions(into, from []ReaderRevision) []ReaderRevision {
	if len(into) == 0 {
		return append([]ReaderRevision(nil), from...)
	}
	at := map[int]int{}
	for i, r := range into {
		at[r.Revision] = i
	}
	for _, r := range from {
		i, ok := at[r.Revision]
		if !ok {
			into = append(into, r)
			at[r.Revision] = len(into) - 1
			continue
		}
		into[i].Delivered = earlier(into[i].Delivered, r.Delivered)
		into[i].Played = earlier(into[i].Played, r.Played)
		if r.Read != nil && (into[i].Read == nil || r.Read.Before(*into[i].Read)) {
			into[i].Read = r.Read
			into[i].Confirmed = r.Confirmed
		}
	}
	return into
}
