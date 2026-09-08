// Package wa wraps whatsmeow: device lifecycle, pairing, sending and the
// receipt policy that implements incognito.
//
// The package deliberately exposes a narrow interface (see Client) rather than
// passing *whatsmeow.Client around. upstream_contract_test.go pins the parts of
// the upstream API this design depends on, so a library upgrade that changes
// one of them fails the build with a message naming the decision to revisit.
package wa

import (
	"context"
	"io"
	"time"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
)

// Client is the slice of whatsmeow this server actually uses.
//
// Two things make this worth having. It documents the real coupling surface —
// a couple of dozen methods out of several hundred — and it makes the whole
// pipeline testable, because *whatsmeow.Client satisfies it as written, with no
// adapter in between. Adding a wrapper would defeat the point: the fake would
// then be exercising the wrapper rather than the shape of the real library.
//
// The testability matters most for one specific thing. Incognito is defined by
// calls that must NOT happen, and you cannot assert the absence of a network
// call against a live client. Against a fake you can, and fakewa's counters are
// what stop someone reintroducing the unconditional SendPresence(available)
// that v1 issued on every connect.
type Client interface {
	// Connection lifecycle.
	Connect() error
	Disconnect()
	IsConnected() bool
	IsLoggedIn() bool
	Logout(ctx context.Context) error

	AddEventHandler(handler whatsmeow.EventHandler) uint32
	RemoveEventHandler(id uint32) bool

	// Pairing. GetQRChannel must be called before Connect; PairPhone must be
	// called immediately after, because the server closes the login socket once
	// the QR codes run out, roughly 160 seconds in.
	GetQRChannel(ctx context.Context) (<-chan whatsmeow.QRChannelItem, error)
	PairPhone(ctx context.Context, phone string, showPushNotification bool,
		clientType whatsmeow.PairClientType, clientDisplayName string) (string, error)

	// Sending. Text always goes out as ExtendedTextMessage rather than
	// Conversation, because Conversation carries no ContextInfo and therefore
	// cannot express a reply, a mention, an expiry or the forwarded flag.
	SendMessage(ctx context.Context, to types.JID, message *waE2E.Message,
		extra ...whatsmeow.SendRequestExtra) (whatsmeow.SendResponse, error)
	SendPeerMessage(ctx context.Context, message *waE2E.Message) (whatsmeow.SendResponse, error)

	// Control messages. These three are the edit and delete history feature.
	BuildEdit(chat types.JID, id types.MessageID, newContent *waE2E.Message) *waE2E.Message
	BuildRevoke(chat, sender types.JID, id types.MessageID) *waE2E.Message
	BuildReaction(chat, sender types.JID, id types.MessageID, reaction string) *waE2E.Message

	// History. BuildHistorySyncRequest fetches older messages on demand;
	// BuildUnavailableMessageRequest re-requests one that failed to decrypt,
	// which v1 never did, so undecryptable messages simply vanished there.
	BuildHistorySyncRequest(lastKnownMessageInfo *types.MessageInfo, count int) *waE2E.Message
	BuildUnavailableMessageRequest(chat, sender types.JID, id string) *waE2E.Message

	// Receipts and presence: everything the incognito policy gates.
	MarkRead(ctx context.Context, ids []types.MessageID, timestamp time.Time,
		chat, sender types.JID, receiptTypeExtra ...types.ReceiptType) error
	SendPresence(ctx context.Context, state types.Presence) error
	SendChatPresence(ctx context.Context, jid types.JID, state types.ChatPresence,
		media types.ChatPresenceMedia) error
	SetForceActiveDeliveryReceipts(active bool)

	// Media.
	Upload(ctx context.Context, plaintext []byte, appInfo whatsmeow.MediaType) (whatsmeow.UploadResponse, error)
	UploadReader(ctx context.Context, plaintext io.Reader, tempFile io.ReadWriteSeeker,
		appInfo whatsmeow.MediaType) (whatsmeow.UploadResponse, error)
	SendMediaRetryReceipt(ctx context.Context, message *types.MessageInfo, mediaKey []byte) error

	// Contacts and profile pictures. Profile pictures are served over plain
	// HTTP and are not encrypted, unlike message media — so the URL is all
	// this returns, and whatever fetches it must seal the bytes itself.
	GetProfilePictureInfo(ctx context.Context, jid types.JID,
		params *whatsmeow.GetProfilePictureParams) (*types.ProfilePictureInfo, error)
	GetGroupInfo(ctx context.Context, jid types.JID) (*types.GroupInfo, error)

	// GetJoinedGroups is every group this account is in, with names.
	//
	// The archive learns a group's name from a history sync or from the event
	// that fires when we join. Neither reaches a group that was already there
	// when the device was paired and has said nothing since — and a group with
	// no message has no conversation row at all, so it is not merely nameless,
	// it is absent. This is the one call that can find them.
	GetJoinedGroups(ctx context.Context) ([]*types.GroupInfo, error)

	// JoinGroupWithInvite accepts an invitation that arrived as a message.
	//
	// Outward facing and not undoable from here: it makes this account a
	// member, visible to everyone already in the group. Nothing on the ingest
	// path may call it — it exists for a person who has read the invitation and
	// pressed a button.
	//
	// The code cannot come from this server's own archive. It is sealed, as a
	// capability should be, so the client opens it and passes it in for the one
	// exchange — the same shape media retry uses for a media key.
	JoinGroupWithInvite(ctx context.Context, jid, inviter types.JID, code string, expiration int64) error

	// Chat settings.
	SetDisappearingTimer(ctx context.Context, chat types.JID, timer time.Duration, settingTS time.Time) error

	// Secret-encrypted payloads. Reactions in announcement groups and poll
	// votes arrive wrapped and need the message secret to open.
	DecryptReaction(ctx context.Context, reaction *events.Message) (*waE2E.ReactionMessage, error)

	// And so do edits, from clients that send them this way: the new text is
	// encrypted under a secret derived from the message being corrected, so
	// nothing can read it without having seen the original. An edit that is not
	// opened here reaches the archive as an unreadable blob of a type nobody
	// recognises — which is exactly what it did.
	DecryptSecretEncryptedMessage(ctx context.Context, evt *events.Message) (*waE2E.Message, error)

	// And so do poll votes. What comes back is a list of SHA-256 hashes of the
	// option text — WhatsApp never transmits the choice in the clear, and this
	// server could not resolve the hashes even if it wanted to, because the
	// poll's options are sealed content it has never been able to read.
	DecryptPollVote(ctx context.Context, vote *events.Message) (*waE2E.PollVoteMessage, error)

	// BuildPollVote hashes the chosen options and encrypts them under the
	// poll's secret. It only builds the message; sending it is SendMessage's
	// job, on the same path as any other outbound message.
	BuildPollVote(ctx context.Context, pollInfo *types.MessageInfo, optionNames []string) (*waE2E.Message, error)

	// Identity. LID and phone number are two names for the same account and
	// either may be absent; see the comment on migration 0001.
	StoreLIDPNMapping(ctx context.Context, first, second types.JID)
}

// The real client satisfies the interface directly. If an upstream signature
// changes, this line fails to compile and names the method.
var _ Client = (*whatsmeow.Client)(nil)
