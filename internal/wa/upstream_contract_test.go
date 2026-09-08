// Package wa wraps whatsmeow. This file is not a unit test of our code — it is
// a contract test against the upstream library.
//
// whatsmeow tracks a protocol Meta changes without notice and ships breaking
// changes freely: between the version this project was designed against
// (2026-04-27) and the version it pins (2026-08-21) there were 95 commits
// touching 87 files, including signature changes in the exact receipt path the
// incognito mode depends on.
//
// Every assertion below encodes a design decision documented in the plan. When
// an upgrade breaks one of these, that is the intended outcome: it means a
// decision needs re-examining, not that the test should be updated to match.
package wa

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	waLog "go.mau.fi/whatsmeow/util/log"
)

// Method expressions: these fail to compile if a signature changes, without
// needing a live Client.
var (
	_ func(*whatsmeow.Client, context.Context, types.JID, *waE2E.Message, ...whatsmeow.SendRequestExtra) (whatsmeow.SendResponse, error) = (*whatsmeow.Client).SendMessage
	_ func(*whatsmeow.Client, context.Context, *waE2E.Message) (whatsmeow.SendResponse, error)                                           = (*whatsmeow.Client).SendPeerMessage

	// Control messages. BuildEdit and BuildRevoke are the whole "edited /
	// deleted history" feature; BuildReaction feeds ResolveReactRow.
	_ func(*whatsmeow.Client, types.JID, types.MessageID, *waE2E.Message) *waE2E.Message    = (*whatsmeow.Client).BuildEdit
	_ func(*whatsmeow.Client, types.JID, types.JID, types.MessageID) *waE2E.Message         = (*whatsmeow.Client).BuildRevoke
	_ func(*whatsmeow.Client, types.JID, types.JID, types.MessageID, string) *waE2E.Message = (*whatsmeow.Client).BuildReaction
	_ func(*whatsmeow.Client, *types.MessageInfo, int) *waE2E.Message                       = (*whatsmeow.Client).BuildHistorySyncRequest

	// The three calls the incognito ReceiptPolicy gates. If any signature
	// moves, the policy has to be revisited rather than silently adapted.
	_ func(*whatsmeow.Client, context.Context, []types.MessageID, time.Time, types.JID, types.JID, ...types.ReceiptType) error = (*whatsmeow.Client).MarkRead
	_ func(*whatsmeow.Client, context.Context, types.Presence) error                                                           = (*whatsmeow.Client).SendPresence
	_ func(*whatsmeow.Client, bool)                                                                                            = (*whatsmeow.Client).SetForceActiveDeliveryReceipts

	_ func(*whatsmeow.Client, context.Context, types.JID, types.ChatPresence, types.ChatPresenceMedia) error = (*whatsmeow.Client).SendChatPresence

	// Polls. BuildPollVote hashes the option text and encrypts the result
	// under the poll's secret; DecryptPollVote gives back the hashes and
	// nothing else. Both are pinned because the whole client-side tally rests
	// on the answer being SHA-256 of the option string and staying that way —
	// if upstream changed the digest, the archive would keep storing votes
	// that no client could ever match to an option.
	_ func(*whatsmeow.Client, context.Context, *types.MessageInfo, []string) (*waE2E.Message, error) = (*whatsmeow.Client).BuildPollVote
	_ func(*whatsmeow.Client, context.Context, *events.Message) (*waE2E.PollVoteMessage, error)      = (*whatsmeow.Client).DecryptPollVote
	_ func([]string) [][]byte                                                                        = whatsmeow.HashPollOptions

	// Accepting a group invitation. Pinned because the argument order is the
	// only thing separating "join the group you were invited to" from "join
	// some other group", and both compile: jid and inviter are the same type.
	_ func(*whatsmeow.Client, context.Context, types.JID, types.JID, string, int64) error = (*whatsmeow.Client).JoinGroupWithInvite

	// Listing groups. The only way to find a group that was already there when
	// the device was paired and has said nothing since.
	_ func(*whatsmeow.Client, context.Context) ([]*types.GroupInfo, error)                = (*whatsmeow.Client).GetJoinedGroups
	_ func(*whatsmeow.Client, context.Context, types.JID, time.Duration, time.Time) error = (*whatsmeow.Client).SetDisappearingTimer
	// Profile pictures come back as a plain URL: WhatsApp does not encrypt
	// them, which is why the archive has to seal them itself.
	_ func(*whatsmeow.Client, context.Context, types.JID, *whatsmeow.GetProfilePictureParams) (*types.ProfilePictureInfo, error) = (*whatsmeow.Client).GetProfilePictureInfo
	_ func(*whatsmeow.Client, context.Context, []byte, whatsmeow.MediaType) (whatsmeow.UploadResponse, error)                    = (*whatsmeow.Client).Upload
	_ func(*whatsmeow.Client, context.Context, *types.MessageInfo, []byte) error                                                 = (*whatsmeow.Client).SendMediaRetryReceipt

	// Pairing by 8-character code, no QR. Better UX on mobile than a QR the
	// user has to photograph from their own screen.
	_ func(*whatsmeow.Client, context.Context, string, bool, whatsmeow.PairClientType, string) (string, error) = (*whatsmeow.Client).PairPhone

	// LID migration. WhatsApp now routes DMs over LID by default, so identity
	// is a (lid, pn) pair and PN may never be known. See TestLIDIsFirstClass.
	_ func(*whatsmeow.Client, context.Context, types.JID, types.JID) = (*whatsmeow.Client).StoreLIDPNMapping

	_ func(context.Context, string, string, waLog.Logger) (*sqlstore.Container, error) = sqlstore.New
)

// TestEditWindow pins the 20-minute limit. The API rejects an edit past this
// window client-side rather than sending a stanza that is already doomed, so
// the constant leaks into user-visible behaviour.
func TestEditWindow(t *testing.T) {
	if whatsmeow.EditWindow != 20*time.Minute {
		t.Fatalf("EditWindow = %v, want 20m — the edit precheck and its error message need updating",
			whatsmeow.EditWindow)
	}
}

// TestInactiveReceiptExists guards the no-fork incognito story.
//
// There is still no upstream flag to suppress delivery receipts:
// sendMessageReceipt is called unconditionally from handleDecryptedMessage.
// What we rely on instead is that when sendActiveReceipts is 0 — which is the
// default, and stays 0 as long as we never send presence "available" — the
// receipt goes out typed "inactive", which official clients receive but do not
// render as delivered.
//
// If this constant disappears, the fork becomes mandatory rather than optional.
func TestInactiveReceiptExists(t *testing.T) {
	if types.ReceiptTypeInactive != "inactive" {
		t.Fatalf("ReceiptTypeInactive = %q, want \"inactive\" — incognito without a fork may no longer work",
			types.ReceiptTypeInactive)
	}
	// Presence "available" is the switch that turns inactive receipts into
	// real delivery receipts. Never send it while incognito is on.
	if types.PresenceAvailable != "available" || types.PresenceUnavailable != "unavailable" {
		t.Fatal("presence constants changed; ReceiptPolicy.OnConnect needs review")
	}
}

// TestProtocolMessageTypes pins the enum values the control-row pipeline keys
// off. Edits and revokes both arrive as ProtocolMessage, and revokes from other
// people arrive as a plain events.Message because handleProtocolMessage returns
// early when the message is not from us — so we dispatch on these ourselves.
func TestProtocolMessageTypes(t *testing.T) {
	if waE2E.ProtocolMessage_REVOKE != 0 {
		t.Errorf("REVOKE = %d, want 0", waE2E.ProtocolMessage_REVOKE)
	}
	if waE2E.ProtocolMessage_MESSAGE_EDIT != 14 {
		t.Errorf("MESSAGE_EDIT = %d, want 14", waE2E.ProtocolMessage_MESSAGE_EDIT)
	}
}

// TestEditAttributes pins the stanza attribute values used to tell an author's
// own delete apart from a group admin deleting someone else's message. The
// history panel shows different text for each, so conflating them is a
// user-visible bug.
func TestEditAttributes(t *testing.T) {
	for _, tc := range []struct{ got, want string }{
		{string(types.EditAttributeMessageEdit), "1"},
		{string(types.EditAttributeSenderRevoke), "7"},
		{string(types.EditAttributeAdminRevoke), "8"},
	} {
		if tc.got != tc.want {
			t.Errorf("edit attribute = %q, want %q", tc.got, tc.want)
		}
	}
}

// TestForwardedFieldsExist pins the ContextInfo fields behind "send as
// forwarded". whatsmeow has no BuildForward helper — we populate ContextInfo
// ourselves, and Conversation has no ContextInfo at all, which is why outbound
// text always goes as ExtendedTextMessage.
func TestForwardedFieldsExist(t *testing.T) {
	ci := &waE2E.ContextInfo{
		IsForwarded:     new(true),
		ForwardingScore: new(uint32(5)),
		Expiration:      new(uint32(86400)),
	}
	if !ci.GetIsForwarded() || ci.GetForwardingScore() != 5 || ci.GetExpiration() != 86400 {
		t.Fatal("ContextInfo forwarding/expiration accessors changed")
	}
	// ExtendedTextMessage must keep carrying ContextInfo; Conversation is a
	// bare string and cannot.
	var ext waE2E.ExtendedTextMessage
	ext.ContextInfo = ci
	if ext.GetContextInfo().GetForwardingScore() != 5 {
		t.Fatal("ExtendedTextMessage.ContextInfo changed")
	}
}

// TestMediaTypesMatchOurInfoStrings ties whatsmeow's MediaType values to the
// HKDF info strings implemented in internal/crypto/wamedia. They must agree or
// stored blobs become undecryptable.
func TestMediaTypesMatchOurInfoStrings(t *testing.T) {
	for _, tc := range []struct {
		got  whatsmeow.MediaType
		want string
	}{
		{whatsmeow.MediaImage, "WhatsApp Image Keys"},
		{whatsmeow.MediaVideo, "WhatsApp Video Keys"},
		{whatsmeow.MediaAudio, "WhatsApp Audio Keys"},
		{whatsmeow.MediaDocument, "WhatsApp Document Keys"},
	} {
		if string(tc.got) != tc.want {
			t.Errorf("MediaType = %q, want %q — internal/crypto/wamedia must match", tc.got, tc.want)
		}
	}
}

// TestPTTFieldsExist pins the three fields that make a voice note render as a
// voice note rather than a plain audio attachment.
func TestPTTFieldsExist(t *testing.T) {
	audio := &waE2E.AudioMessage{
		PTT:      new(true),
		Seconds:  new(uint32(7)),
		Waveform: make([]byte, 64),
	}
	if !audio.GetPTT() || audio.GetSeconds() != 7 || len(audio.GetWaveform()) != 64 {
		t.Fatal("AudioMessage PTT fields changed")
	}
}

// TestLIDIsFirstClass documents the identity model correction.
//
// The v1 server rewrote every @lid JID to a phone number on ingest. Upstream
// has since made LID the primary identifier for DMs ("always use LID for DMs"),
// and LID exists precisely to withhold the phone number — so for some contacts
// a PN will never be available. Identity is therefore a (lid, pn) pair with LID
// primary, and the database never rewrites a key.
func TestLIDIsFirstClass(t *testing.T) {
	if types.HiddenUserServer != "lid" {
		t.Fatalf("HiddenUserServer = %q, want \"lid\"", types.HiddenUserServer)
	}
	if types.DefaultUserServer != "s.whatsapp.net" {
		t.Fatalf("DefaultUserServer = %q", types.DefaultUserServer)
	}
	lid := types.JID{User: "123456789", Server: types.HiddenUserServer}
	if lid.Server == types.DefaultUserServer {
		t.Fatal("a LID JID must not compare equal to a phone-number JID")
	}
}

// TestEventsWeDispatchOn compile-asserts the event types the ingest pipeline
// handles. The v1 server ended its handler with `_ = v // ignore the rest for
// MVP` and silently dropped roughly forty event types; the replacement switch
// is exhaustive, so every type here must keep existing.
func TestEventsWeDispatchOn(t *testing.T) {
	var (
		_ events.Message              // inbound messages, edits and third-party revokes
		_ events.Receipt              // delivered / read / played
		_ events.UndecryptableMessage // v1 dropped these entirely
		_ events.HistorySync
		_ events.MediaRetry
		_ events.MediaRetryError
		_ events.Connected
		_ events.Disconnected
		_ events.LoggedOut
		_ events.PairSuccess
		_ events.PairError
		_ events.QR
		_ events.TemporaryBan
		_ events.StreamReplaced
		_ events.ChatPresence
		_ events.Presence
		_ events.GroupInfo
		_ events.JoinedGroup
		_ events.IdentityChange
		_ events.OfflineSyncCompleted
		_ events.OfflineSyncPreview

		// App state. Without these the contacts table stays empty, which is
		// exactly what happened in v1.
		_ events.Contact
		_ events.PushName
		_ events.Pin
		_ events.Star
		_ events.Mute
		_ events.Archive
		_ events.MarkChatAsRead
		_ events.DeleteForMe // "delete for me" is NOT a revoke; the UI differs
		_ events.DeleteChat
		_ events.ClearChat
	)
}

// TestPollOptionsAreHashedWithSHA256 pins the one fact the poll tally rests on.
//
// The archive stores a vote as the hashes WhatsApp sends and cannot resolve
// them: the poll's options are sealed content this server has never been able
// to read. The client does the matching, by hashing each option it opens and
// looking for it among the selections — which works only while the digest is
// SHA-256 of the raw option string, with no salt, no prefix and no truncation.
//
// If upstream ever changed that, every vote would keep storing and no vote
// would ever match an option again. The failure would be silent: polls would
// simply show nobody having answered them.
func TestPollOptionsAreHashedWithSHA256(t *testing.T) {
	const option = "Sim, pode ser na sexta"
	want := sha256.Sum256([]byte(option))

	got := whatsmeow.HashPollOptions([]string{option})
	if len(got) != 1 {
		t.Fatalf("hashed one option into %d values", len(got))
	}
	if !bytes.Equal(got[0], want[:]) {
		t.Fatalf("poll option hash is no longer plain SHA-256 of the text:\n got %x\nwant %x", got[0], want)
	}
}
