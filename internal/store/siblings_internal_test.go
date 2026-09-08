package store

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func chatAt(key, lid, pn string, at *time.Time, unread int32) ChatRow {
	return ChatRow{ChatKey: key, ChatLID: lid, ChatPN: pn, LastTS: at, Unread: unread}
}

func when(day int) *time.Time {
	t := time.Date(2026, 9, day, 12, 0, 0, 0, time.UTC)
	return &t
}

// One person, two conversations, one row on screen.
//
// WhatsApp addressed the same contact by phone number for years and by LID
// since, so a conversation spanning the change is stored under both keys. On
// the archive this was written against: 47 people, 94 conversations, 38 of them
// with messages on both sides — two rows with the same name, one of them
// looking abandoned.
//
// The rows stay as they are. They record how WhatsApp actually addressed each
// message, which is a fact about what happened and the reason a receipt can be
// matched to a message at all. This is a projection, like folding a person's
// several devices into one reader.
func TestTwoConversationsWithOnePersonBecomeOne(t *testing.T) {
	const lid = "91938170638392@lid"
	const pn = "5511959446861@s.whatsapp.net"

	// The older row predates LIDs and has none: the backfill fills a phone
	// number from a LID and never the other way, because inventing a LID would
	// rewrite the key the row is stored under.
	old := chatAt(pn, "", pn, when(1), 2)
	old.NameSealed, old.NameKeyID, old.UID = []byte("selado"), 7, ChatUID(uuid.Nil, pn)
	recent := chatAt(lid, lid, pn, when(2), 3)

	out := foldChats([]ChatRow{old, recent})
	if len(out) != 1 {
		t.Fatalf("folded to %d rows, want 1", len(out))
	}
	got := out[0]

	if len(got.Keys) != 2 {
		t.Fatalf("keys = %v, want both", got.Keys)
	}
	// Identity: a known half is never replaced by an empty one, which is what
	// lets the older row contribute its number and the newer one its LID.
	if got.ChatLID != lid || got.ChatPN != pn {
		t.Errorf("identity = (%q, %q), want both halves", got.ChatLID, got.ChatPN)
	}
	// The badge counts messages, and the messages are all the person's.
	if got.Unread != 5 {
		t.Errorf("unread = %d, want 5", got.Unread)
	}
	// The preview follows the newest message, wherever it was addressed.
	if got.LastTS == nil || !got.LastTS.Equal(*when(2)) {
		t.Errorf("lastTS = %v, want the newer", got.LastTS)
	}
	// And the name stays with the row its uid belongs to. A sealed name binds
	// to that uid; taking the name from one row and the identity from another
	// opens as tampered with the correct key in hand, which reads as an attack.
	if got.ChatKey != pn || got.NameKeyID != 7 {
		t.Errorf("the name was taken from %q with key %d, but the identity from "+
			"elsewhere — the sealed value will not open", got.ChatKey, got.NameKeyID)
	}
}

// Groups never fold, and neither do two people who merely lack a number.
//
// A group id is not a person, and two conversations with no phone number
// between them are not evidence of anything. Folding on a missing value is how
// every unnamed stranger becomes one contact.
func TestFoldingNeverMergesWhatItCannotIdentify(t *testing.T) {
	out := foldChats([]ChatRow{
		{ChatKey: "120363000000000001@g.us", IsGroup: true},
		{ChatKey: "120363000000000002@g.us", IsGroup: true},
		{ChatKey: "111@lid", ChatLID: "111@lid"},
		{ChatKey: "222@lid", ChatLID: "222@lid"},
	})
	if len(out) != 4 {
		t.Fatalf("folded to %d rows, want 4 — nothing here identifies anything", len(out))
	}
}

// Archived only when every side is.
//
// A conversation the reader archived under one identifier and went on using
// under the other is one they have not finished with, and hiding it because
// half of it is archived loses the half that is not.
func TestArchivedOnlyWhenBothAre(t *testing.T) {
	const pn = "5511900000000@s.whatsapp.net"
	one := chatAt(pn, "", pn, when(1), 0)
	one.Archived = true
	two := chatAt("999@lid", "999@lid", pn, when(2), 0)

	out := foldChats([]ChatRow{one, two})
	if len(out) != 1 {
		t.Fatalf("folded to %d", len(out))
	}
	if out[0].Archived {
		t.Error("the conversation was hidden because one of its two halves was archived")
	}
}
