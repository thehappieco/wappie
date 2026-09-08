package wa_test

import (
	"context"
	"crypto/sha256"
	"log/slog"
	"testing"

	"go.mau.fi/whatsmeow/proto/waCommon"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"google.golang.org/protobuf/proto"

	"whatserver2/internal/wa"
	"whatserver2/internal/wa/fakewa"
	"whatserver2/internal/wa/normalize"
)

// A poll vote is encrypted a second time, like an edit and like a reaction in
// an announcement group. Unlike those two, the plaintext has nowhere to go: a
// PollUpdateMessage's Vote field is a PollEncValue and stays one, so the opened
// selection has to travel beside the protobuf rather than inside it.
//
// These tests are about that pairing arriving intact, because the failure it
// guards against is quiet. A vote that stores without its selection looks
// exactly like a vote that was cast: the row is there, it names the poll, and
// every poll in the archive shows nobody having chosen anything.

func pollVote(pollID string) *waE2E.Message {
	return &waE2E.Message{
		PollUpdateMessage: &waE2E.PollUpdateMessage{
			PollCreationMessageKey: &waCommon.MessageKey{ID: proto.String(pollID)},
			Vote: &waE2E.PollEncValue{
				EncPayload: []byte{1, 2, 3},
				EncIV:      []byte{4, 5, 6},
			},
		},
	}
}

// deliverAny is deliver, without the assumption that what comes out the far end
// is an *events.Message. It is exactly that assumption this feature breaks.
func deliverAny(t *testing.T, id string, msg *waE2E.Message, votes map[string]*waE2E.PollVoteMessage) any {
	t.Helper()
	fake := fakewa.New()
	fake.Votes = votes

	var seen any
	sunk := make(chan struct{}, 1)
	dev, err := wa.NewDevice(wa.DeviceConfig{
		ID:       "11111111-1111-1111-1111-111111111111",
		TenantID: "22222222-2222-2222-2222-222222222222",
		Client:   fake,
		Store:    noopStore{},
		Policy:   wa.ReceiptPolicy{Mode: wa.ModePassive},
		Log:      slog.New(slog.DiscardHandler),
		Sink: wa.SinkFunc(func(_ context.Context, _ string, evt any) {
			switch evt.(type) {
			case *events.Message, *normalize.OpenedPollVote:
				seen = evt
				select {
				case sunk <- struct{}{}:
				default:
				}
			}
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := dev.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dev.Stop(context.Background()) })

	fake.Emit(&events.Message{
		Info: types.MessageInfo{
			MessageSource: types.MessageSource{Chat: secretChat, Sender: secretChat},
			ID:            id,
		},
		Message: msg,
	})
	<-sunk
	return seen
}

func TestAPollVoteArrivesWithItsSelection(t *testing.T) {
	chosen := sha256.Sum256([]byte("Sexta"))
	got := deliverAny(t, "VOTE-1", pollVote("POLL-1"), map[string]*waE2E.PollVoteMessage{
		"VOTE-1": {SelectedOptions: [][]byte{chosen[:]}},
	})

	opened, ok := got.(*normalize.OpenedPollVote)
	if !ok {
		t.Fatalf("the vote reached the archive still sealed: %T", got)
	}
	if len(opened.Selected) != 1 || string(opened.Selected[0]) != string(chosen[:]) {
		t.Fatalf("selection = %x, want the hash of the chosen option", opened.Selected)
	}
	// The protobuf must survive alongside it. It names the poll being answered,
	// and nothing else does.
	if opened.Message.Message.GetPollUpdateMessage().GetPollCreationMessageKey().GetID() != "POLL-1" {
		t.Error("the vote lost the poll it answers")
	}
}

func TestAVoteThatCannotBeOpenedIsStillArchived(t *testing.T) {
	// No secret for this id. The row must still reach the archive naming the
	// poll: it simply does not say what was chosen, which is the truth about
	// it. Dropping it would understate how many people answered.
	got := deliverAny(t, "VOTE-2", pollVote("POLL-2"), nil)

	msg, ok := got.(*events.Message)
	if !ok {
		t.Fatalf("an unopened vote was dressed up as an opened one: %T", got)
	}
	if msg.Message.GetPollUpdateMessage().GetPollCreationMessageKey().GetID() != "POLL-2" {
		t.Fatal("the vote was dropped rather than archived unopened")
	}
}

func TestAWithdrawnVoteIsOpenedRatherThanUnreadable(t *testing.T) {
	// Somebody taking their vote back. WhatsApp sends it as a vote with no
	// selections, and it must arrive as an opened vote that chose nothing —
	// not as one nobody could read. The two look identical in the row and mean
	// opposite things: a change of mind, versus an answer this archive missed.
	got := deliverAny(t, "VOTE-3", pollVote("POLL-3"), map[string]*waE2E.PollVoteMessage{
		"VOTE-3": {SelectedOptions: nil},
	})

	opened, ok := got.(*normalize.OpenedPollVote)
	if !ok {
		t.Fatalf("a withdrawal was reported as a vote nobody could open: %T", got)
	}
	if len(opened.Selected) != 0 {
		t.Errorf("selection = %x, want nothing chosen", opened.Selected)
	}
}

func TestAPollCreationIsNotMistakenForAVote(t *testing.T) {
	// Only an update carries a vote. Sending a poll through the decryption path
	// would fail on every poll anybody ever asks, and the warning would be
	// about a message that was never encrypted twice in the first place.
	poll := &waE2E.Message{PollCreationMessageV3: &waE2E.PollCreationMessage{
		Name: proto.String("Que dia?"),
		Options: []*waE2E.PollCreationMessage_Option{
			{OptionName: proto.String("Sexta")},
		},
	}}
	if got := deliverAny(t, "POLL-4", poll, nil); !isPlain(got) {
		t.Fatalf("a poll was routed as if it were an answer to one: %T", got)
	}
}

func isPlain(evt any) bool {
	_, ok := evt.(*events.Message)
	return ok
}
