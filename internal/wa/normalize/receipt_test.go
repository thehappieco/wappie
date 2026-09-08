package normalize_test

import (
	"errors"
	"testing"
	"time"

	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"

	"whatserver2/internal/domain"
	"whatserver2/internal/wa/normalize"
)

var (
	peer  = types.JID{User: "5511999999999", Server: types.DefaultUserServer}
	group = types.JID{User: "120363000000000000", Server: types.GroupServer}
)

func receipt(kind types.ReceiptType, ids ...string) *events.Receipt {
	return &events.Receipt{
		MessageSource: types.MessageSource{Chat: peer, Sender: peer},
		MessageIDs:    ids,
		Timestamp:     time.Now().Truncate(time.Second),
		Type:          kind,
	}
}

// TestReceiptTypesCollapseToFiveFacts pins the mapping down.
//
// Upstream has eleven receipt types and they are not eleven different things.
// "inactive" is a delivery to a client that was not in the foreground; "sender"
// is a delivery to one of our own devices; "read-self" is a read that happened
// somewhere else we are signed in. Keeping the wire spelling would push that
// bookkeeping into every reader of the archive.
func TestReceiptTypesCollapseToFiveFacts(t *testing.T) {
	cases := []struct {
		wire   types.ReceiptType
		kind   domain.ReceiptKind
		fromMe bool
	}{
		{types.ReceiptTypeDelivered, domain.ReceiptDelivered, false},
		{types.ReceiptTypeInactive, domain.ReceiptDelivered, false},
		{types.ReceiptTypeSender, domain.ReceiptDelivered, true},
		{types.ReceiptTypeRead, domain.ReceiptRead, false},
		{types.ReceiptTypeReadSelf, domain.ReceiptRead, true},
		{types.ReceiptTypePlayed, domain.ReceiptPlayed, false},
		{types.ReceiptTypePlayedSelf, domain.ReceiptPlayed, true},
		{types.ReceiptTypeRetry, domain.ReceiptRetry, false},
		{types.ReceiptTypeServerError, domain.ReceiptError, false},
	}
	for _, c := range cases {
		got, err := normalize.ReceiptFrom(receipt(c.wire, "A1"), normalize.Options{})
		if err != nil {
			t.Fatalf("%q: %v", c.wire, err)
		}
		if got.Kind != c.kind {
			t.Errorf("%q became %q, want %q", c.wire, got.Kind, c.kind)
		}
		if got.IsFromMe != c.fromMe {
			t.Errorf("%q reports is-from-me %v, want %v", c.wire, got.IsFromMe, c.fromMe)
		}
		if !got.Kind.Valid() {
			t.Errorf("%q produced an unknown kind %q, which the schema will refuse", c.wire, got.Kind)
		}
	}
}

// TestHousekeepingReceiptsAreNotArchived. peer_msg and hist_sync are our own
// devices synchronising with each other, not anybody acknowledging anything.
func TestHousekeepingReceiptsAreNotArchived(t *testing.T) {
	for _, wire := range []types.ReceiptType{types.ReceiptTypePeerMsg, types.ReceiptTypeHistorySync} {
		_, err := normalize.ReceiptFrom(receipt(wire, "A1"), normalize.Options{})
		if !errors.Is(err, normalize.ErrNotArchived) {
			t.Errorf("%q returned %v, want ErrNotArchived", wire, err)
		}
	}
}

// TestAReceiptNamingNothingIsNotStored. A batch with no ids acknowledges
// nothing, and storing it would take a sequence number and publish an event
// that tells a client to redraw nothing.
func TestAReceiptNamingNothingIsNotStored(t *testing.T) {
	if _, err := normalize.ReceiptFrom(receipt(types.ReceiptTypeRead), normalize.Options{}); !errors.Is(err, normalize.ErrNotArchived) {
		t.Fatalf("got %v, want ErrNotArchived", err)
	}
	empty := receipt(types.ReceiptTypeRead, "", "")
	if _, err := normalize.ReceiptFrom(empty, normalize.Options{}); !errors.Is(err, normalize.ErrNotArchived) {
		t.Fatalf("ids that are all empty strings gave %v, want ErrNotArchived", err)
	}
}

// TestAGroupReceiptKeepsTheParticipantAsTheReader.
//
// In a group the chat and the reader are different parties, and conflating them
// would attribute every participant's read to the group itself — which is the
// one thing "who read this" must not do.
func TestAGroupReceiptKeepsTheParticipantAsTheReader(t *testing.T) {
	evt := &events.Receipt{
		MessageSource: types.MessageSource{Chat: group, Sender: peer, IsGroup: true},
		MessageIDs:    []string{"A1"},
		Timestamp:     time.Now(),
		Type:          types.ReceiptTypeRead,
	}
	got, err := normalize.ReceiptFrom(evt, normalize.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Chat.Primary().String() != group.String() {
		t.Fatalf("chat is %s, want the group", got.Chat)
	}
	if got.Reader.Primary().String() != peer.String() {
		t.Fatalf("reader is %s, want the participant who read", got.Reader)
	}
}

// TestAReceiptWithNoSenderFallsBackToTheChat. Direct chats sometimes omit the
// sender because it can only be the peer; dropping the acknowledgement would
// lose a real fact over a field WhatsApp considered redundant.
func TestAReceiptWithNoSenderFallsBackToTheChat(t *testing.T) {
	evt := &events.Receipt{
		MessageSource: types.MessageSource{Chat: peer},
		MessageIDs:    []string{"A1"},
		Timestamp:     time.Now(),
		Type:          types.ReceiptTypeRead,
	}
	got, err := normalize.ReceiptFrom(evt, normalize.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Reader.Primary().String() != peer.String() {
		t.Fatalf("reader is %s, want the chat peer", got.Reader)
	}
}

// TestAnImplausibleReceiptTimestampIsRefused. The timestamp drives version
// attribution, so a value from the year 20000 would place a read after every
// edit that will ever exist.
func TestAnImplausibleReceiptTimestampIsRefused(t *testing.T) {
	evt := receipt(types.ReceiptTypeRead, "A1")
	evt.Timestamp = time.Date(20000, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := normalize.ReceiptFrom(evt, normalize.Options{}); err == nil {
		t.Fatal("a timestamp in the year 20000 was accepted")
	}

	evt.Timestamp = time.Time{}
	if _, err := normalize.ReceiptFrom(evt, normalize.Options{}); err == nil {
		t.Fatal("a zero timestamp was accepted")
	}
}
