// Package fakewa is an in-memory stand-in for whatsmeow's Client.
//
// It exists for one thing above all: asserting that a call did NOT happen.
//
// Incognito is defined entirely by absence. Not marking read, not announcing
// presence, not forcing active delivery receipts. Against a live client those
// are unobservable — you would have to look at the other person's phone. Here
// they are counters, so a test can state the requirement directly:
//
//	if fake.MarkReadCalls() != 0 { ... }
//
// That assertion is the guard against the v1 mistake, which sent
// SendPresence(available) unconditionally on every connect and so turned every
// delivery receipt from "inactive" into a real one, visible to the sender.
package fakewa

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"sync"
	"time"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waCommon"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"google.golang.org/protobuf/proto"

	"whatserver2/internal/wa"
)

// SentMessage records one outbound send.
type SentMessage struct {
	To      types.JID
	Message *waE2E.Message
	Extra   []whatsmeow.SendRequestExtra
}

// ReadReceipt records one MarkRead call.
type ReadReceipt struct {
	IDs       []types.MessageID
	Timestamp time.Time
	Chat      types.JID
	Sender    types.JID
	Types     []types.ReceiptType
}

// Client is a fake whatsmeow client. The zero value is ready to use and every
// method is safe to call from multiple goroutines, because event handlers run
// on their own.
type Client struct {
	mu sync.Mutex

	connected bool
	loggedIn  bool

	handlers   map[uint32]whatsmeow.EventHandler
	nextHandle uint32

	qrCh chan whatsmeow.QRChannelItem

	sent         []SentMessage
	peerSent     []*waE2E.Message
	readReceipts []ReadReceipt
	presences    []types.Presence
	chatPresence []types.ChatPresence
	forceActive  bool
	uploads      int
	disconnects  int

	// Joins are the group invitations this client was asked to accept.
	// Recorded because joining is outward facing and a test has to be able to
	// assert that the ingest path never does it.
	Joins []Joined

	// ProfilePicture and GroupInfo let a test supply answers. Nil means the
	// same thing a real account says about most contacts: nothing.
	ProfilePicture func(types.JID) (*types.ProfilePictureInfo, error)
	GroupInfo      func(types.JID) (*types.GroupInfo, error)

	// JoinedGroups is what GetJoinedGroups answers. Nil is what a device with
	// no groups says, which is an ordinary answer.
	JoinedGroups []*types.GroupInfo

	// Secrets is what a secret-encrypted message opens to, by message id. A
	// test sets it instead of doing real key derivation, which is whatsmeow's
	// job and not what any test here is about.
	Secrets map[string]*waE2E.Message

	// Votes is what a poll vote opens to, by the voter's message id, for the
	// same reason.
	Votes map[string]*waE2E.PollVoteMessage

	// PollVotes are the answers this client was asked to build. Recorded
	// because voting is outward facing, like joining a group.
	PollVotes []PollVote

	// Identity. BuildMessageKey decides FromMe by comparing the sender
	// against the client's own identifiers, so the fake needs them to
	// reproduce that logic rather than approximate it.
	OwnID  types.JID
	OwnLID types.JID

	CreateGroupFunc        func(whatsmeow.ReqCreateGroup) (*types.GroupInfo, error)
	UpdateParticipantsFunc func(types.JID, []types.JID, whatsmeow.ParticipantChange) ([]types.GroupParticipant, error)
	LeaveGroupFunc         func(types.JID) error
	CheckPhoneFunc         func([]string) ([]types.IsOnWhatsAppResponse, error)
	// Injectable behaviour.
	JoinErr      error
	PollVoteErr  error
	ConnectErr   error
	SendErr      error
	PairCode     string
	PairErr      error
	UploadResult whatsmeow.UploadResponse
}

// New returns a fake ready for use.
func New() *Client {
	return &Client{
		handlers: map[uint32]whatsmeow.EventHandler{},
		PairCode: "ABCD1234",
	}
}

// Compile-time proof the fake and the real client are interchangeable. Without
// this the fake could drift into testing a shape that does not exist.
var _ wa.Client = (*Client)(nil)

// ---------------------------------------------------------------------------
// Assertions. These are the point of the package.
// ---------------------------------------------------------------------------

// MarkReadCalls returns how many times MarkRead was called. Must be zero for a
// device in incognito that was never explicitly told to mark anything read.
func (c *Client) MarkReadCalls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.readReceipts)
}

// SendPresenceCalls returns how many presence updates were sent. Must be zero
// in incognito: sending presence "available" is what promotes delivery receipts
// from "inactive", which official clients ignore, to real ones they render.
func (c *Client) SendPresenceCalls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.presences)
}

// ForceActiveReceipts reports whether SetForceActiveDeliveryReceipts(true) was
// ever called. Must be false in incognito.
func (c *Client) ForceActiveReceipts() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.forceActive
}

// Sent returns a copy of every outbound message.
func (c *Client) Sent() []SentMessage {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]SentMessage(nil), c.sent...)
}

// LastSent returns the most recent outbound message, or nil.
func (c *Client) LastSent() *SentMessage {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.sent) == 0 {
		return nil
	}
	last := c.sent[len(c.sent)-1]
	return &last
}

// ReadReceipts returns a copy of every MarkRead call.
func (c *Client) ReadReceipts() []ReadReceipt {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]ReadReceipt(nil), c.readReceipts...)
}

// Presences returns every presence state sent.
func (c *Client) Presences() []types.Presence {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]types.Presence(nil), c.presences...)
}

// Disconnects returns how many times Disconnect was called.
func (c *Client) Disconnects() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.disconnects
}

// ---------------------------------------------------------------------------
// Driving the fake from a test.
// ---------------------------------------------------------------------------

// Emit delivers an event to every registered handler, synchronously, so a test
// does not have to wait for anything.
func (c *Client) Emit(evt any) {
	c.mu.Lock()
	hs := make([]whatsmeow.EventHandler, 0, len(c.handlers))
	for _, h := range c.handlers {
		hs = append(hs, h)
	}
	c.mu.Unlock()
	for _, h := range hs {
		h(evt)
	}
}

// PushQR sends an item down the QR channel opened by GetQRChannel.
func (c *Client) PushQR(item whatsmeow.QRChannelItem) {
	c.mu.Lock()
	ch := c.qrCh
	c.mu.Unlock()
	if ch != nil {
		ch <- item
	}
}

// CloseQR closes the QR channel, which is what the real client does when the
// login socket goes away.
func (c *Client) CloseQR() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.qrCh != nil {
		close(c.qrCh)
		c.qrCh = nil
	}
}

// SetLoggedIn adjusts the reported login state.
func (c *Client) SetLoggedIn(v bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loggedIn = v
}

// ---------------------------------------------------------------------------
// wa.Client
// ---------------------------------------------------------------------------

func (c *Client) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ConnectErr != nil {
		return c.ConnectErr
	}
	c.connected = true
	return nil
}

func (c *Client) Disconnect() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.connected = false
	c.disconnects++
}

func (c *Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

func (c *Client) IsLoggedIn() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.loggedIn
}

func (c *Client) Logout(context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.connected, c.loggedIn = false, false
	return nil
}

func (c *Client) AddEventHandler(h whatsmeow.EventHandler) uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.handlers == nil {
		c.handlers = map[uint32]whatsmeow.EventHandler{}
	}
	c.nextHandle++
	c.handlers[c.nextHandle] = h
	return c.nextHandle
}

func (c *Client) RemoveEventHandler(id uint32) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.handlers[id]
	delete(c.handlers, id)
	return ok
}

func (c *Client) GetQRChannel(context.Context) (<-chan whatsmeow.QRChannelItem, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.loggedIn {
		return nil, whatsmeow.ErrQRStoreContainsID
	}
	c.qrCh = make(chan whatsmeow.QRChannelItem, 8)
	return c.qrCh, nil
}

func (c *Client) PairPhone(_ context.Context, phone string, _ bool,
	_ whatsmeow.PairClientType, _ string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.PairErr != nil {
		return "", c.PairErr
	}
	if phone == "" {
		return "", errors.New("fakewa: empty phone number")
	}
	return c.PairCode, nil
}

func (c *Client) SendMessage(_ context.Context, to types.JID, msg *waE2E.Message,
	extra ...whatsmeow.SendRequestExtra) (whatsmeow.SendResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.SendErr != nil {
		return whatsmeow.SendResponse{}, c.SendErr
	}
	c.sent = append(c.sent, SentMessage{To: to, Message: msg, Extra: extra})
	id := "FAKE" + time.Now().Format("150405.000000")
	if len(extra) > 0 && extra[0].ID != "" {
		id = extra[0].ID
	}
	return whatsmeow.SendResponse{ID: id, Timestamp: time.Now()}, nil
}

func (c *Client) SendPeerMessage(_ context.Context, msg *waE2E.Message) (whatsmeow.SendResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.peerSent = append(c.peerSent, msg)
	return whatsmeow.SendResponse{ID: "FAKEPEER", Timestamp: time.Now()}, nil
}

// The Build* helpers mirror upstream literally, including BuildMessageKey's
// FromMe logic. Approximating them here would let the fake and reality disagree
// about the very structures the ingest pipeline parses, which is the one place
// a fake must not diverge.

// buildMessageKey mirrors whatsmeow's Client.BuildMessageKey.
func (c *Client) buildMessageKey(chat, sender types.JID, id types.MessageID) *waCommon.MessageKey {
	key := &waCommon.MessageKey{
		FromMe:    new(true),
		ID:        new(id),
		RemoteJID: new(chat.String()),
	}
	if !sender.IsEmpty() && sender.User != c.OwnID.User && sender.User != c.OwnLID.User {
		key.FromMe = new(false)
		// Participant is only set for group chats: in a direct message the
		// remote JID already identifies the other party.
		if chat.Server != types.DefaultUserServer &&
			chat.Server != types.HiddenUserServer &&
			chat.Server != types.MessengerServer {
			key.Participant = new(sender.ToNonAD().String())
		}
	}
	return key
}

func (c *Client) BuildEdit(chat types.JID, id types.MessageID, newContent *waE2E.Message) *waE2E.Message {
	return &waE2E.Message{EditedMessage: &waE2E.FutureProofMessage{
		Message: &waE2E.Message{ProtocolMessage: &waE2E.ProtocolMessage{
			Key: &waCommon.MessageKey{
				FromMe:    new(true),
				ID:        new(id),
				RemoteJID: new(chat.String()),
			},
			Type:          waE2E.ProtocolMessage_MESSAGE_EDIT.Enum(),
			EditedMessage: newContent,
			TimestampMS:   new(time.Now().UnixMilli()),
		}},
	}}
}

func (c *Client) BuildRevoke(chat, sender types.JID, id types.MessageID) *waE2E.Message {
	return &waE2E.Message{ProtocolMessage: &waE2E.ProtocolMessage{
		Type: waE2E.ProtocolMessage_REVOKE.Enum(),
		Key:  c.buildMessageKey(chat, sender, id),
	}}
}

func (c *Client) BuildReaction(chat, sender types.JID, id types.MessageID, reaction string) *waE2E.Message {
	return &waE2E.Message{ReactionMessage: &waE2E.ReactionMessage{
		Key:               c.buildMessageKey(chat, sender, id),
		Text:              new(reaction),
		SenderTimestampMS: new(time.Now().UnixMilli()),
	}}
}

func (c *Client) BuildHistorySyncRequest(last *types.MessageInfo, count int) *waE2E.Message {
	req := &waE2E.PeerDataOperationRequestMessage_HistorySyncOnDemandRequest{
		// Not clamped, because upstream does not clamp either and the fake
		// must produce a byte-identical protobuf. See fidelity_test.go.
		//nolint:gosec // G115: mirrors whatsmeow's own conversion
		OnDemandMsgCount: new(int32(count)),
	}
	if last != nil {
		req.ChatJID = new(last.Chat.String())
		req.OldestMsgID = new(last.ID)
		req.OldestMsgFromMe = new(last.IsFromMe)
		// Named "MS" but carries seconds; upstream notes the same thing.
		req.OldestMsgTimestampMS = new(last.Timestamp.Unix())
	}
	return &waE2E.Message{ProtocolMessage: &waE2E.ProtocolMessage{
		Type: waE2E.ProtocolMessage_PEER_DATA_OPERATION_REQUEST_MESSAGE.Enum(),
		PeerDataOperationRequestMessage: &waE2E.PeerDataOperationRequestMessage{
			PeerDataOperationRequestType: waE2E.PeerDataOperationRequestType_HISTORY_SYNC_ON_DEMAND.Enum(),
			HistorySyncOnDemandRequest:   req,
		},
	}}
}

func (c *Client) BuildUnavailableMessageRequest(chat, sender types.JID, id string) *waE2E.Message {
	return &waE2E.Message{ProtocolMessage: &waE2E.ProtocolMessage{
		Type: waE2E.ProtocolMessage_PEER_DATA_OPERATION_REQUEST_MESSAGE.Enum(),
		PeerDataOperationRequestMessage: &waE2E.PeerDataOperationRequestMessage{
			PeerDataOperationRequestType: waE2E.PeerDataOperationRequestType_PLACEHOLDER_MESSAGE_RESEND.Enum(),
			PlaceholderMessageResendRequest: []*waE2E.PeerDataOperationRequestMessage_PlaceholderMessageResendRequest{{
				MessageKey: c.buildMessageKey(chat, sender, id),
			}},
		},
	}}
}

func (c *Client) MarkRead(_ context.Context, ids []types.MessageID, ts time.Time,
	chat, sender types.JID, extra ...types.ReceiptType) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readReceipts = append(c.readReceipts, ReadReceipt{
		IDs: ids, Timestamp: ts, Chat: chat, Sender: sender, Types: extra,
	})
	return nil
}

func (c *Client) SendPresence(_ context.Context, state types.Presence) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.presences = append(c.presences, state)
	return nil
}

// SubscribePresence observes a contact without announcing our own presence.
func (c *Client) SubscribePresence(_ context.Context, _ types.JID) error { return nil }

func (c *Client) SendChatPresence(_ context.Context, _ types.JID,
	state types.ChatPresence, _ types.ChatPresenceMedia) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.chatPresence = append(c.chatPresence, state)
	return nil
}

// ChatPresences is every typing notification this client was asked to send.
//
// Counted because the quiet posture is defined by calls that must NOT happen,
// and you cannot assert the absence of a network call against a live client.
// Typing is the sharpest case: it names a conversation somebody has open, right
// now, several times a minute.
func (c *Client) ChatPresences() []types.ChatPresence {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]types.ChatPresence(nil), c.chatPresence...)
}

func (c *Client) SetForceActiveDeliveryReceipts(active bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if active {
		c.forceActive = true
	}
}

func (c *Client) Upload(context.Context, []byte, whatsmeow.MediaType) (whatsmeow.UploadResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.uploads++
	return c.UploadResult, nil
}

func (c *Client) UploadReader(context.Context, io.Reader, io.ReadWriteSeeker,
	whatsmeow.MediaType) (whatsmeow.UploadResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.uploads++
	return c.UploadResult, nil
}

func (c *Client) SendMediaRetryReceipt(context.Context, *types.MessageInfo, []byte) error {
	return nil
}

// GetProfilePictureInfo answers with nothing by default. Tests that care set
// ProfilePicture; the rest get the same answer as a contact with no picture,
// which is the common case in a real account too.
func (c *Client) GetProfilePictureInfo(_ context.Context, jid types.JID,
	_ *whatsmeow.GetProfilePictureParams) (*types.ProfilePictureInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ProfilePicture == nil {
		return nil, nil
	}
	return c.ProfilePicture(jid)
}

// GetGroupInfo answers with nothing by default.
func (c *Client) GetGroupInfo(_ context.Context, jid types.JID) (*types.GroupInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.GroupInfo == nil {
		return nil, nil
	}
	return c.GroupInfo(jid)
}

// PollVote is one answer this client was asked to build.
type PollVote struct {
	Poll    string
	Chat    types.JID
	Options []string
}

// Joined records every invitation this fake was asked to accept.
//
// Counted rather than merely allowed, because joining a group is outward
// facing: it makes the account a member, visible to everyone already there. A
// test that asserts the ingest path never joins anything needs the absence of a
// call to be observable, which is the same reason the receipt counters exist.
type Joined struct {
	Group      types.JID
	Inviter    types.JID
	Code       string
	Expiration int64
}

// GetJoinedGroups answers with whatever JoinedGroups holds.
func (c *Client) GetJoinedGroups(context.Context) ([]*types.GroupInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.JoinedGroups, nil
}

// JoinGroupWithInvite records the acceptance and reports whatever JoinErr says.
func (c *Client) JoinGroupWithInvite(_ context.Context, jid, inviter types.JID,
	code string, expiration int64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Joins = append(c.Joins, Joined{
		Group: jid, Inviter: inviter, Code: code, Expiration: expiration,
	})
	return c.JoinErr
}

// JoinsMade returns the invitations accepted so far.
func (c *Client) JoinsMade() []Joined {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Joined(nil), c.Joins...)
}

func (c *Client) SetDisappearingTimer(context.Context, types.JID, time.Duration, time.Time) error {
	return nil
}

func (c *Client) DecryptReaction(_ context.Context, evt *events.Message) (*waE2E.ReactionMessage, error) {
	if evt == nil || evt.Message == nil {
		return nil, errors.New("fakewa: no reaction to decrypt")
	}
	return evt.Message.GetReactionMessage(), nil
}

// DecryptSecretEncryptedMessage returns whatever the test put inside the
// wrapper, so a caller can exercise the unwrapping without a message secret.
//
// Secrets is consulted first when a test wants to control the answer; failing
// that, the payload is read straight out of the wrapper's ciphertext field,
// which lets a test build one without any encryption at all.
func (c *Client) DecryptSecretEncryptedMessage(_ context.Context, evt *events.Message) (*waE2E.Message, error) {
	if evt == nil || evt.Message == nil || evt.Message.GetSecretEncryptedMessage() == nil {
		return nil, errors.New("fakewa: not a secret encrypted message")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Secrets == nil {
		return nil, errors.New("fakewa: no secret payload was set")
	}
	msg, ok := c.Secrets[evt.Info.ID]
	if !ok {
		return nil, errors.New("fakewa: no secret payload for " + evt.Info.ID)
	}
	return msg, nil
}

// DecryptPollVote returns whatever a test registered under the voter's message
// id, so the ingest path can be exercised without a poll secret.
//
// An unregistered id is an error rather than an empty selection, and the
// distinction matters: a vote nobody could open must reach the archive naming
// the poll and saying nothing about the choice, and a test that could not tell
// those apart would pass against a build that silently dropped every answer.
func (c *Client) DecryptPollVote(_ context.Context, evt *events.Message) (*waE2E.PollVoteMessage, error) {
	if evt == nil || evt.Message.GetPollUpdateMessage() == nil {
		return nil, errors.New("fakewa: not a poll update message")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	vote, ok := c.Votes[evt.Info.ID]
	if !ok {
		return nil, errors.New("fakewa: no poll vote for " + evt.Info.ID)
	}
	return vote, nil
}

// BuildPollVote hashes the options the same way whatsmeow does, so a test can
// check the wire form without reaching for the real client.
func (c *Client) BuildPollVote(_ context.Context, info *types.MessageInfo, options []string) (*waE2E.Message, error) {
	if info == nil {
		return nil, errors.New("fakewa: no poll to answer")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.PollVotes = append(c.PollVotes, PollVote{Poll: info.ID, Chat: info.Chat, Options: options})
	if c.PollVoteErr != nil {
		return nil, c.PollVoteErr
	}
	hashes := make([][]byte, 0, len(options))
	for _, opt := range options {
		sum := sha256.Sum256([]byte(opt))
		hashes = append(hashes, sum[:])
	}
	return &waE2E.Message{PollUpdateMessage: &waE2E.PollUpdateMessage{
		PollCreationMessageKey: &waCommon.MessageKey{
			ID:        proto.String(info.ID),
			RemoteJID: proto.String(info.Chat.String()),
			FromMe:    proto.Bool(info.IsFromMe),
		},
		Vote: &waE2E.PollEncValue{EncPayload: bytes.Join(hashes, nil)},
	}}, nil
}

// PollVotesMade returns the answers built so far.
func (c *Client) PollVotesMade() []PollVote {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]PollVote(nil), c.PollVotes...)
}

func (c *Client) StoreLIDPNMapping(context.Context, types.JID, types.JID) {}

func (c *Client) CreateGroup(_ context.Context, req whatsmeow.ReqCreateGroup) (*types.GroupInfo, error) {
	if c.CreateGroupFunc != nil {
		return c.CreateGroupFunc(req)
	}
	return nil, errors.New("fake: no group creation response configured")
}
func (c *Client) UpdateGroupParticipants(_ context.Context, jid types.JID, participants []types.JID, action whatsmeow.ParticipantChange) ([]types.GroupParticipant, error) {
	if c.UpdateParticipantsFunc != nil {
		return c.UpdateParticipantsFunc(jid, participants, action)
	}
	return nil, errors.New("fake: no participant response configured")
}
func (c *Client) LeaveGroup(_ context.Context, jid types.JID) error {
	if c.LeaveGroupFunc != nil {
		return c.LeaveGroupFunc(jid)
	}
	return errors.New("fake: no leave response configured")
}
func (c *Client) IsOnWhatsApp(_ context.Context, phones []string) ([]types.IsOnWhatsAppResponse, error) {
	if c.CheckPhoneFunc != nil {
		return c.CheckPhoneFunc(phones)
	}
	return nil, errors.New("fake: no phone response configured")
}
func (c *Client) BuildPollCreation(name string, options []string, count int) *waE2E.Message {
	// The upstream builder is pure; exercise its actual message secret format.
	return (*whatsmeow.Client)(nil).BuildPollCreation(name, options, count)
}
