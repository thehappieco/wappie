package send_test

import (
	"context"
	"go.mau.fi/whatsmeow/types"
	"strings"
	"testing"
	"whatserver2/internal/wa/fakewa"
	"whatserver2/internal/wa/send"
)

func TestPollCreationRetainsVoteSecretAndDisappearingTimer(t *testing.T) {
	for _, seconds := range []uint32{0, 86400} {
		fake := fakewa.New()
		poll, err := send.ValidatePoll("  Lunch? ", []string{"Pizza", "Salad"}, 1)
		if err != nil {
			t.Fatal(err)
		}
		sent, err := send.SendPoll(context.Background(), fake, types.NewJID("120363123", types.GroupServer), "POLL-TEST", poll, send.Options{Expiration: seconds})
		if err != nil {
			t.Fatal(err)
		}
		messages := fake.Sent()
		if len(messages) != 1 {
			t.Fatalf("sent %d messages", len(messages))
		}
		msg := messages[0].Message
		if len(msg.GetMessageContextInfo().GetMessageSecret()) != 32 {
			t.Fatal("poll would not decrypt later votes")
		}
		if seconds > 0 {
			msg = msg.GetEphemeralMessage().GetMessage()
		}
		if msg.GetPollCreationMessage().GetContextInfo().GetExpiration() != seconds {
			t.Fatal("poll ignored chat timer")
		}
		if msg.GetPollCreationMessage().GetName() != "Lunch?" || msg.GetPollCreationMessage().GetSelectableOptionsCount() != 1 {
			t.Fatal("wire poll differs from requested poll")
		}
		if sent.Envelope.Content.Poll.Question != "Lunch?" || len(sent.Envelope.Content.Poll.Options) != 2 || sent.ID != "POLL-TEST" {
			t.Fatalf("wrong archive: %+v", sent)
		}
	}
}
func TestPollValidationDoesNotSendInvalidOrAmbiguousOptions(t *testing.T) {
	for _, c := range []struct {
		question string
		options  []string
		count    int
	}{
		{"", []string{"a", "b"}, 0}, {"q", []string{"a"}, 0}, {"q", []string{" A ", "a"}, 0}, {"q", []string{"a", "  "}, 0},
		{strings.Repeat("q", 256), []string{"a", "b"}, 0}, {"q", []string{"a", strings.Repeat("b", 101)}, 0}, {"q", []string{"a", "b"}, 2},
	} {
		if _, err := send.ValidatePoll(c.question, c.options, c.count); err == nil {
			t.Fatalf("accepted invalid poll %+v", c)
		}
	}
	if poll, err := send.ValidatePoll("q", []string{"a", "b"}, 0); err != nil || poll.SelectableCount != 0 {
		t.Fatal("multiple answers rejected")
	}
}
