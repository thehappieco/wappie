package store

import (
	"testing"
	"time"

	"whatserver2/internal/domain"
)

// One person, several phones — and the one mistake here that makes the archive
// claim MORE than it knows.
//
// The revision fields belong to a device, not to a person. Which text somebody
// had on screen when they read is decided by what THAT handset had received,
// and a person reading on a phone whose laptop is three edits ahead is
// ordinary. The obvious simplification — merge a person's deliveries, then
// attribute once — turns a delivery to the laptop into proof about the phone,
// and the answer comes back Confirmed with nothing on the wire saying so.
//
// Everything else in this file fails safe. This one fails loud and confident,
// which is exactly the failure the whole edit-history projection exists to
// avoid: telling somebody a correction was read when it may never have been
// delivered.

func at(min int) time.Time {
	return time.Date(2026, 9, 3, 10, min, 0, 0, time.UTC)
}

func tp(min int) *time.Time { t := at(min); return &t }

// versions: the original at 10:00, an edit at 10:10, each a stanza of its own.
func editedTwice() []Version {
	return []Version{
		{Revision: 0, Row: Row{WAID: "ORIG"}, From: tp(0), Until: tp(10)},
		{Revision: 1, Row: Row{WAID: "EDIT"}, From: tp(10)},
	}
}

func TestOneDevicesDeliveryIsNotProofAboutAnother(t *testing.T) {
	const phone = "224437861388494:12@lid"
	const laptop = "224437861388494:31@lid"

	acks := []ReceiptRow{
		// The laptop received the correction.
		{ReaderKey: laptop, ReaderLID: laptop, WAID: "EDIT",
			Kind: domain.ReceiptDelivered, TS: at(11)},
		// The phone only ever received the original...
		{ReaderKey: phone, ReaderLID: phone, WAID: "ORIG",
			Kind: domain.ReceiptDelivered, TS: at(1)},
		// ...and it is the phone that reported reading, after the edit was sent.
		{ReaderKey: phone, ReaderLID: phone, WAID: "ORIG",
			Kind: domain.ReceiptRead, TS: at(12)},
	}

	readers := readersOf(editedTwice(), acks)
	if len(readers) != 1 {
		t.Fatalf("readers = %d, want one person with two devices", len(readers))
	}
	r := readers[0]
	if len(r.Devices) != 2 {
		t.Fatalf("devices = %d, want 2", len(r.Devices))
	}

	// The read came from the phone, so the claims about it must come from the
	// phone too.
	if r.ReadDevice != phone {
		t.Errorf("ReadDevice = %q, want the phone %q", r.ReadDevice, phone)
	}
	if r.ConfirmedRevision != 0 {
		t.Errorf("ConfirmedRevision = %d, want 0 — the phone never acknowledged the edit; "+
			"a 1 here means the laptop's delivery was folded in before attribution",
			r.ConfirmedRevision)
	}
	if !r.Confirmed || r.SawRevision != 0 {
		t.Errorf("confirmed=%v revision=%d, want only the original named by the phone's receipt", r.Confirmed, r.SawRevision)
	}
	if r.Revisions[1].Read != nil {
		t.Fatal("the laptop's delivery invented a read of the correction")
	}
}

// The person's own moments are the EARLIEST across their devices.
//
// "Received at 14:02 and again at 19:40" is one person with two phones, and
// when they got it is the first one. The second is kept per device rather than
// discarded, because it is the only evidence the second device exists.
func TestAPersonGotItWhenTheirFirstDeviceDid(t *testing.T) {
	const phone = "224437861388494:12@lid"
	const laptop = "224437861388494:31@lid"

	readers := readersOf(editedTwice(), []ReceiptRow{
		{ReaderKey: laptop, ReaderLID: laptop, WAID: "ORIG",
			Kind: domain.ReceiptDelivered, TS: at(40)},
		{ReaderKey: phone, ReaderLID: phone, WAID: "ORIG",
			Kind: domain.ReceiptDelivered, TS: at(2)},
	})
	if len(readers) != 1 {
		t.Fatalf("readers = %d, want 1", len(readers))
	}
	if readers[0].Delivered == nil || !readers[0].Delivered.Equal(at(2)) {
		t.Errorf("delivered = %v, want the earlier %v", readers[0].Delivered, at(2))
	}
	if len(readers[0].Devices) != 2 {
		t.Fatalf("devices = %d, want both kept", len(readers[0].Devices))
	}
	// Ordered on the (agent, device) pair, so the list does not shuffle between
	// one reload and the next.
	if readers[0].Devices[0].Device != 12 || readers[0].Devices[1].Device != 31 {
		t.Errorf("devices out of order: %d then %d",
			readers[0].Devices[0].Device, readers[0].Devices[1].Device)
	}
}

// Two strangers stay two strangers.
//
// Folding on the user part alone would merge a LID whose digits happen to match
// somebody's phone number — the client's directory documents the same trap. In
// a group that shows one reader where there are two, and a tick waiting for
// everyone turns a person early.
func TestTwoIdentifiersThatMerelyShareDigitsAreTwoPeople(t *testing.T) {
	readers := readersOf(editedTwice(), []ReceiptRow{
		{ReaderKey: "5511988887777@lid", ReaderLID: "5511988887777@lid",
			WAID: "ORIG", Kind: domain.ReceiptDelivered, TS: at(1)},
		{ReaderKey: "5511988887777@s.whatsapp.net", ReaderPN: "5511988887777@s.whatsapp.net",
			WAID: "ORIG", Kind: domain.ReceiptDelivered, TS: at(2)},
	})
	if len(readers) != 2 {
		t.Fatalf("readers = %d, want 2 — a LID is not the phone number it resembles", len(readers))
	}
}

// Per version, which is the question somebody opening a revision is asking.
//
// The flat Delivered is the earliest across every version — "when did this
// reach them at all". On a message that was corrected that is a different
// question from "did they get this text", and presenting the first as an answer
// to the second is what made a revision's panel show a delivery for a
// correction the person never received.

func TestARevisionReportsItsOwnDeliveryNotTheMessagesFirst(t *testing.T) {
	const phone = "224437861388494:12@lid"

	readers := readersOf(editedTwice(), []ReceiptRow{
		// The original arrived. The correction never did.
		{ReaderKey: phone, ReaderLID: phone, WAID: "ORIG",
			Kind: domain.ReceiptDelivered, TS: at(1)},
	})
	if len(readers) != 1 {
		t.Fatalf("readers = %d, want 1", len(readers))
	}
	revs := readers[0].Revisions
	if len(revs) != 2 {
		t.Fatalf("revisions = %d, want one per version", len(revs))
	}
	if revs[0].Delivered == nil || !revs[0].Delivered.Equal(at(1)) {
		t.Errorf("revision 0 delivered = %v, want %v", revs[0].Delivered, at(1))
	}
	if revs[1].Delivered != nil {
		t.Errorf("revision 1 reports delivery at %v. Nothing acknowledged the "+
			"correction; this is the message's first delivery being shown as "+
			"the correction's, which is the whole defect.", revs[1].Delivered)
	}
}

func TestReadingTwiceLandsOnBothRevisions(t *testing.T) {
	// Read the original, then read again after the correction arrived. Two
	// receipts, two revisions. Keeping only the earliest leaves the correction
	// looking unread by somebody who had just looked at it.
	//
	// Two rows, because the receipts table is keyed on (device, wa_id, reader,
	// kind) and the two reads name different stanzas — which is precisely what
	// an edit causes: the message goes unread again and is acknowledged afresh
	// under the edit's own id.
	const phone = "224437861388494:12@lid"

	readers := readersOf(editedTwice(), []ReceiptRow{
		{ReaderKey: phone, ReaderLID: phone, WAID: "ORIG",
			Kind: domain.ReceiptDelivered, TS: at(1)},
		{ReaderKey: phone, ReaderLID: phone, WAID: "ORIG",
			Kind: domain.ReceiptRead, TS: at(5)},
		{ReaderKey: phone, ReaderLID: phone, WAID: "EDIT",
			Kind: domain.ReceiptDelivered, TS: at(11)},
		// The second read names the edit's stanza, and that id is exactly what
		// places it on revision 1. Editing a message makes it unread again;
		// reading it afresh acknowledges the edit's own stanza.
		{ReaderKey: phone, ReaderLID: phone, WAID: "EDIT",
			Kind: domain.ReceiptRead, TS: at(15)},
	})
	revs := readers[0].Revisions
	if revs[0].Read == nil || !revs[0].Read.Equal(at(5)) {
		t.Errorf("revision 0 read = %v, want %v", revs[0].Read, at(5))
	}
	if revs[1].Read == nil || !revs[1].Read.Equal(at(15)) {
		t.Errorf("revision 1 read = %v, want %v — the second read was dropped",
			revs[1].Read, at(15))
	}
	if !revs[1].Confirmed {
		t.Error("the read of revision 1 is reported as inferred, but the device " +
			"acknowledged receiving that exact version before reading it")
	}
}

func TestARevisionNobodyCouldHaveSeenIsNotMarkedRead(t *testing.T) {
	// The read happened before the correction was even sent. Attributing it to
	// the newest revision would state, as a fact about the archive, that
	// somebody read a text that did not exist yet.
	const phone = "224437861388494:12@lid"

	readers := readersOf(editedTwice(), []ReceiptRow{
		{ReaderKey: phone, ReaderLID: phone, WAID: "ORIG",
			Kind: domain.ReceiptDelivered, TS: at(1)},
		{ReaderKey: phone, ReaderLID: phone, WAID: "ORIG",
			Kind: domain.ReceiptRead, TS: at(5)},
	})
	revs := readers[0].Revisions
	if revs[1].Read != nil {
		t.Errorf("revision 1 read at %v, but it was only sent at %v",
			revs[1].Read, at(10))
	}
	if revs[0].Read == nil {
		t.Error("the read landed on no revision at all")
	}
}

func TestAPersonsRevisionIsTheEarliestAcrossTheirDevices(t *testing.T) {
	const phone = "224437861388494:12@lid"
	const laptop = "224437861388494:31@lid"

	readers := readersOf(editedTwice(), []ReceiptRow{
		{ReaderKey: laptop, ReaderLID: laptop, WAID: "EDIT",
			Kind: domain.ReceiptDelivered, TS: at(40)},
		{ReaderKey: phone, ReaderLID: phone, WAID: "EDIT",
			Kind: domain.ReceiptDelivered, TS: at(11)},
	})
	if len(readers) != 1 {
		t.Fatalf("readers = %d, want one person with two devices", len(readers))
	}
	revs := readers[0].Revisions
	if revs[1].Delivered == nil || !revs[1].Delivered.Equal(at(11)) {
		t.Errorf("revision 1 delivered = %v, want the earlier %v", revs[1].Delivered, at(11))
	}
	// And each device keeps its own, because the second timestamp is the only
	// evidence the second device exists.
	for _, d := range readers[0].Devices {
		if len(d.Revisions) != 2 {
			t.Fatalf("device %s has %d revisions, want 2", d.Key, len(d.Revisions))
		}
	}
}

func TestAReadOfTheOriginalIsNotAReadOfTheCorrection(t *testing.T) {
	// The read names ORIG, at a moment when the correction was already out.
	//
	// The old projection inferred from the clock that the correction must have
	// been what they were looking at, and reported revision 1 as read —
	// hedged as "inferred", but read. That inference was wrong, and WhatsApp's
	// own behaviour is why: editing a message makes it unread again, and
	// reading it afresh sends a receipt naming the EDIT's stanza. A receipt
	// naming ORIG is therefore somebody reading the original, whatever the
	// clock says was current.
	//
	// The laptop is here to keep the older trap covered too: it received the
	// correction, and its delivery must not vouch for what the phone read.
	const phone = "224437861388494:12@lid"
	const laptop = "224437861388494:31@lid"

	readers := readersOf(editedTwice(), []ReceiptRow{
		{ReaderKey: laptop, ReaderLID: laptop, WAID: "EDIT",
			Kind: domain.ReceiptDelivered, TS: at(11)},
		{ReaderKey: phone, ReaderLID: phone, WAID: "ORIG",
			Kind: domain.ReceiptDelivered, TS: at(1)},
		{ReaderKey: phone, ReaderLID: phone, WAID: "ORIG",
			Kind: domain.ReceiptRead, TS: at(12)},
	})
	revs := readers[0].Revisions
	if revs[0].Read == nil || !revs[0].Read.Equal(at(12)) {
		t.Errorf("revision 0 read = %v, want %v — the receipt named ORIG",
			revs[0].Read, at(12))
	}
	if !revs[0].Confirmed {
		t.Error("revision 0 is hedged as inferred. The receipt names that exact " +
			"stanza; there is nothing left to infer.")
	}
	if revs[1].Read != nil {
		t.Errorf("revision 1 read at %v. Nobody said they read the correction — "+
			"reading it would have sent a receipt naming the edit's stanza, and "+
			"the phone that read never even received it.", revs[1].Read)
	}
}

func TestOurOwnDevicesIdsSayNothingAboutRevisions(t *testing.T) {
	// The one reader whose ids cannot be trusted is us. This client folds every
	// version into one line and marks that line read under the ORIGINAL's id,
	// whatever text is on screen — so our own receipts always name ORIG, and
	// reading them as "you read the original" would be reading our own
	// simplification back as a fact about what somebody looked at.
	//
	// Preserve the message-level read, without assigning it to a version by time.
	const mine = "224437861388494:9@lid"

	readers := readersOf(editedTwice(), []ReceiptRow{
		{ReaderKey: mine, ReaderLID: mine, IsFromMe: true, WAID: "ORIG",
			Kind: domain.ReceiptDelivered, TS: at(1)},
		{ReaderKey: mine, ReaderLID: mine, IsFromMe: true, WAID: "EDIT",
			Kind: domain.ReceiptDelivered, TS: at(11)},
		{ReaderKey: mine, ReaderLID: mine, IsFromMe: true, WAID: "ORIG",
			Kind: domain.ReceiptRead, TS: at(12)},
	})
	revs := readers[0].Revisions
	if revs[0].Read != nil {
		t.Errorf("our own read was placed on revision 0 at %v because the id said "+
			"ORIG — but this client always says ORIG", revs[0].Read)
	}
	if revs[1].Read != nil {
		t.Fatal("delivery of the correction does not establish that it was read")
	}
	if readers[0].Read == nil || readers[0].Confirmed || revs[1].Confirmed {
		t.Error("keep the real read receipt without claiming a confirmed version")
	}
}

func TestUnknownReceiptStanzaNeverMarksAnyVersionReadOrPlayed(t *testing.T) {
	got := perRevision(versionTimes(editedTwice()), map[string]time.Time{"EDIT": at(11)},
		[]ack{{WAID: "UNRELATED", TS: at(12)}}, []ack{{WAID: "UNRELATED", TS: at(13)}}, true)
	for _, revision := range got {
		if revision.Read != nil || revision.Played != nil || revision.Confirmed || revision.PlayedConfirmed {
			t.Fatalf("unknown receipt invented evidence: %+v", revision)
		}
	}
}

func TestDeliveryAndPlaybackAreNotReadReceipts(t *testing.T) {
	readers := readersOf(editedTwice(), []ReceiptRow{
		{ReaderKey: "111@lid", WAID: "EDIT", Kind: domain.ReceiptDelivered, TS: at(11)},
		{ReaderKey: "222@lid", WAID: "EDIT", Kind: domain.ReceiptPlayed, TS: at(12)},
	})
	if len(readers) != 2 {
		t.Fatalf("readers=%d, want two different people", len(readers))
	}
	for _, reader := range readers {
		if reader.Read != nil || reader.Confirmed {
			t.Fatalf("non-read receipt became a read: %+v", reader)
		}
		for _, revision := range reader.Revisions {
			if revision.Read != nil || revision.Confirmed {
				t.Fatalf("non-read receipt became a version read: %+v", revision)
			}
		}
	}
	if !readers[1].Revisions[1].PlayedConfirmed || readers[1].Revisions[1].Played == nil {
		t.Fatal("the explicit playback receipt was lost")
	}
}

func TestAGroupIdentifierAndRetryCannotBecomeReaders(t *testing.T) {
	readers := readersOf(editedTwice(), []ReceiptRow{
		{ReaderKey: "123@g.us", WAID: "ORIG", Kind: domain.ReceiptRead, TS: at(1)},
		{ReaderKey: "111@lid", WAID: "ORIG", Kind: domain.ReceiptRetry, TS: at(1)},
	})
	if len(readers) != 0 {
		t.Fatalf("invalid reader evidence survived: %+v", readers)
	}
}

func TestARevisionWithNoReadIsNotConfirmedAnything(t *testing.T) {
	// Confirmed qualifies a read. A true sitting next to an absent read is a
	// value a template renders as "confirmado" for a version nobody looked at.
	const phone = "224437861388494:12@lid"

	readers := readersOf(editedTwice(), []ReceiptRow{
		{ReaderKey: phone, ReaderLID: phone, WAID: "ORIG",
			Kind: domain.ReceiptDelivered, TS: at(1)},
	})
	for _, r := range readers[0].Revisions {
		if r.Read == nil && r.Confirmed {
			t.Errorf("revision %d has no read and claims to be confirmed", r.Revision)
		}
	}
}
