package fakewa_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	waLog "go.mau.fi/whatsmeow/util/log"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	"whatserver2/internal/wa/fakewa"
)

// A fake is only worth having if it behaves like the thing it replaces. These
// tests run the same call against the real whatsmeow client and against the
// fake, then compare the protobuf that comes out. Without them the fake could
// drift into testing a message shape that does not exist, and every test built
// on it would be worthless while still passing.
//
// Timestamps are ignored: both sides stamp time.Now(), so that one field is
// guaranteed to differ and says nothing about fidelity.

func bothClients(t *testing.T) (*whatsmeow.Client, *fakewa.Client) {
	t.Helper()
	// A bare device is enough. The Build helpers only read the client's own
	// identity, and an empty identity is exactly the "sending as myself" case.
	return whatsmeow.NewClient(&store.Device{}, waLog.Noop), fakewa.New()
}

func assertSame(t *testing.T, real, fake proto.Message) {
	t.Helper()
	d := cmp.Diff(real, fake,
		protocmp.Transform(),
		protocmp.IgnoreFields(&waE2E.ProtocolMessage{}, "timestampMS"),
		protocmp.IgnoreFields(&waE2E.ReactionMessage{}, "senderTimestampMS"),
	)
	if d != "" {
		t.Errorf("the fake diverges from the real client (-real +fake):\n%s", d)
	}
}

var (
	dmChat = types.JID{User: "5511999999999", Server: types.DefaultUserServer}
	group  = types.JID{User: "120363000000000000", Server: types.GroupServer}
	other  = types.JID{User: "5511888888888", Server: types.DefaultUserServer}
	msgID  = types.MessageID("3EB0ABCDEF1234567890")
)

func TestBuildRevokeMatchesReal(t *testing.T) {
	real, fake := bothClients(t)
	for name, sender := range map[string]types.JID{
		"revoking my own message":    types.EmptyJID,
		"group admin revoking anoth": other,
	} {
		t.Run(name, func(t *testing.T) {
			assertSame(t, real.BuildRevoke(dmChat, sender, msgID), fake.BuildRevoke(dmChat, sender, msgID))
		})
	}
}

// Participant is populated for groups and omitted for direct messages. Getting
// this wrong is not cosmetic: it is the same class of bug the v1 server hit,
// where a missing Participant made quoted replies render truncated on the
// recipient's phone.
func TestBuildRevokeGroupCarriesParticipant(t *testing.T) {
	real, fake := bothClients(t)
	assertSame(t, real.BuildRevoke(group, other, msgID), fake.BuildRevoke(group, other, msgID))

	if got := fake.BuildRevoke(group, other, msgID); got.GetProtocolMessage().GetKey().GetParticipant() == "" {
		t.Error("a group revoke must carry Participant")
	}
	if got := fake.BuildRevoke(dmChat, other, msgID); got.GetProtocolMessage().GetKey().GetParticipant() != "" {
		t.Error("a direct-message revoke must not carry Participant")
	}
}

func TestBuildReactionMatchesReal(t *testing.T) {
	real, fake := bothClients(t)
	// The empty string is not a no-op: it is how a reaction is removed, and it
	// is what turns a reaction row into a delete row in the projection.
	for _, emoji := range []string{"\U0001F44D", "❤️", ""} {
		assertSame(t,
			real.BuildReaction(dmChat, other, msgID, emoji),
			fake.BuildReaction(dmChat, other, msgID, emoji))
	}
}

func TestBuildEditMatchesReal(t *testing.T) {
	real, fake := bothClients(t)
	content := &waE2E.Message{Conversation: proto.String("corrected text")}
	assertSame(t, real.BuildEdit(dmChat, msgID, content), fake.BuildEdit(dmChat, msgID, content))
}

func TestBuildUnavailableMessageRequestMatchesReal(t *testing.T) {
	real, fake := bothClients(t)
	assertSame(t,
		real.BuildUnavailableMessageRequest(dmChat, other, msgID),
		fake.BuildUnavailableMessageRequest(dmChat, other, msgID))
}

func TestBuildHistorySyncRequestMatchesReal(t *testing.T) {
	real, fake := bothClients(t)
	info := &types.MessageInfo{
		ID:            msgID,
		MessageSource: types.MessageSource{Chat: dmChat, IsFromMe: false},
	}
	assertSame(t, real.BuildHistorySyncRequest(info, 50), fake.BuildHistorySyncRequest(info, 50))
}
