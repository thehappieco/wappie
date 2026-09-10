// Package wsapi is the websocket protocol clients speak.
//
// One transport, deliberately. The v1 server ran server-sent events for the
// browser and a bespoke msgpack-over-TCP protocol for backend consumers, and
// the two rendering paths drifted apart until they disagreed about the shape of
// an edited message. The performance difference never justified maintaining
// both.
package wsapi

import (
	"encoding/json"
	"time"
)

// Version is the protocol version. A client announcing a different major
// version is refused rather than served something it may misread.
const Version = 1

// Frame is the envelope for every message in both directions.
type Frame struct {
	// Type selects the payload. Namespaced with dots by subject.
	Type string `json:"t"`
	// ReqID correlates a response with the request that caused it. Empty on
	// unsolicited server pushes such as device.status.
	ReqID string `json:"r,omitempty"`
	// Payload is the type-specific body.
	Payload json.RawMessage `json:"p,omitempty"`
}

// Client-to-server frame types.
const (
	TypeHello         = "hello"
	TypePair          = "pair"
	TypePairCancel    = "pair.cancel"
	TypeDevicesList   = "devices.list"
	TypeUsersList     = "users.list"
	TypeSubscribe     = "subscribe"
	TypeChatsList     = "chats.list"
	TypeContacts      = "contacts.list"
	TypeResolve       = "contacts.resolve"
	TypeAvatar        = "contacts.avatar"
	TypeChatPage      = "chat.page"
	TypeHistory       = "message.history"
	TypeMessageGet    = "message.get"
	TypeKeysGet       = "keys.get"
	TypeSend          = "message.send"
	TypeSendMedia     = "message.send.media"
	TypeEdit          = "message.edit"
	TypeRevoke        = "message.revoke"
	TypeReact         = "message.react"
	TypeMarkRead      = "message.read"
	TypePollVote      = "message.poll.vote"
	TypeChatTimer     = "chat.timer"
	TypeGroupJoin     = "group.join"
	TypeGroupGet      = "group.info"
	TypeChatTyping    = "chat.presence"
	TypePresenceWatch = "presence.subscribe"
	TypeDeviceMode    = "device.mode"
	TypeReprojectGet  = "reproject.list"
	TypeReprojectPut  = "reproject.apply"
	TypeMediaRetry    = "media.retry"
	TypeMediaExpired  = "media.expired"
	TypeBackfill      = "history.backfill"
	TypeDeviceStop    = "device.stop"
	TypeDeviceStart   = "device.start"
	TypeDeviceRename  = "device.rename"
	TypeDevicesStats  = "devices.stats"
	TypeDeviceInfo    = "device.info"
	TypeDeviceDelete  = "device.delete"
	TypeKeysList      = "apikeys.list"
	TypeKeyCreate     = "apikeys.create"
	TypeKeyRevoke     = "apikeys.revoke"
	TypeGrantAdd      = "grant.add"
	TypeGrantRevoke   = "grant.revoke"
	TypeGrantsList    = "grants.list"
	TypeGrants        = "grants"
	TypePing          = "ping"
)

// Server-to-client frame types.
const (
	TypeWelcome      = "welcome"
	TypePairQR       = "pair.qr"
	TypePairCode     = "pair.code"
	TypePairSuccess  = "pair.success"
	TypePairTimeout  = "pair.timeout"
	TypeDeviceStatus = "device.status"
	TypeDevices      = "devices"
	TypeUsers        = "users"
	TypeReplayBegin  = "replay.begin"
	TypeReplayEnd    = "replay.end"
	TypeMessage      = "message"
	TypeLag          = "lag"
	TypeChats        = "chats"
	TypeContactList  = "contacts"
	TypeAvatarFrame  = "avatar"
	TypePage         = "page"
	TypeHistoryFrame = "history"
	TypeMessageFrame = "message.one"
	TypeReceipt      = "receipt"
	TypeKeys         = "keys"
	TypeSendResult   = "message.sent"
	TypeChatTimerSet = "chat.timer.set"
	TypeGroupJoined  = "group.joined"
	TypeGroupFrame   = "group"
	TypePresence     = "presence"
	TypeChatUpdate   = "chat.update"
	TypeUnsupported  = "reproject.rows"
	TypeReprojected  = "reproject.done"
	TypeRetryQueued  = "media.retry.queued"
	TypeBackfillSent = "history.backfill.sent"
	TypeExpiredList  = "media.expired.list"
	TypeDeviceStats  = "devices.stats.result"
	TypeDeviceDetail = "device.detail"
	TypeDeviceGone   = "device.deleted"
	TypeAPIKeys      = "apikeys"
	TypeAPIKeyNew    = "apikeys.created"
	TypeAPIKeyGone   = "apikeys.revoked"
	TypeReaders      = "device.readers"
	TypeError        = "error"
	TypePong         = "pong"
)

// Hello authenticates the connection. It must be the first frame.
//
// Two ways in, for two kinds of caller. An API key belongs to a program and
// lives until revoked; a session belongs to a person, expires, and is what a
// browser gets from signing in. Exactly one of them is expected.
type Hello struct {
	APIKey  string `json:"api_key,omitempty"`
	Session string `json:"session,omitempty"`
	Version int    `json:"version"`
	// ClientID is free-form and appears in server logs. Useful when several
	// consumers share one key.
	ClientID string `json:"client_id,omitempty"`
}

// Welcome confirms authentication.
type Welcome struct {
	Version  int      `json:"version"`
	TenantID string   `json:"tenant_id"`
	Features []string `json:"features"`
	// Account and Role identify the person who signed in, and are empty for an
	// API key. A client uses them to decide what to offer rather than to decide
	// what to allow — the server refuses regardless of what the client drew.
	Account string `json:"account,omitempty"`
	Role    string `json:"role,omitempty"`
	// Scope is what an API key may do, and empty for a person. A client
	// uses it to hide what would be refused, not to decide what to allow.
	Scope    string `json:"scope,omitempty"`
	ServerTS int64  `json:"server_ts"`
}

// PairRequest starts linking a device.
type PairRequest struct {
	Label string `json:"label,omitempty"`
	// Method is "qr" or "code". Code pairing is far better over a terminal:
	// the alternative is photographing your own screen.
	Method string `json:"method"`
	// Phone is required for code pairing, in full international form.
	Phone string `json:"phone,omitempty"`
	// DisplayName shows under "Linked devices" on the phone. WhatsApp
	// validates the format, so it must look like "Browser (OS)".
	DisplayName string `json:"display_name,omitempty"`
	// ReceiptMode is "passive" (the default, and what incognito means) or
	// "active".
	ReceiptMode string `json:"receipt_mode,omitempty"`

	// DeviceID is chosen by the caller, not by the database.
	//
	// It has to be: a key grant binds to the device, so the grants have to be
	// sealed before the row exists. Asking the server for an id first would
	// leave a device that exists with no key for however long the round trip
	// took, and the first message can arrive inside that window.
	DeviceID string `json:"device_id,omitempty"`
	// Resume retries an existing unpaired device without replacing its archive key.
	Resume bool `json:"resume,omitempty"`

	// ArchivePublicKey is this device's archive key, generated by the caller.
	//
	// Required, and it has to arrive here rather than a moment later: the first
	// message can land seconds after the phone accepts, and a device with no key
	// cannot seal — ingest refuses rather than storing plaintext. Only the
	// public half exists in this struct, so no code path could carry a private
	// one by mistake.
	ArchivePublicKey []byte `json:"archive_public_key"`

	// Grants are the device's private archive key, sealed once per account that
	// should be able to read it. The caller produced them; this server stores
	// ciphertext it cannot open.
	//
	// Empty means nobody can read this device yet, which is a real choice — the
	// caller kept the key — and a loud one, because it is how an archive gets
	// lost. So empty is refused unless Orphan says the caller meant it.
	Grants []KeyGrant `json:"grants,omitempty"`
	// Orphan is the caller saying "no grants, and I know what that means".
	Orphan bool `json:"orphan,omitempty"`
}

// KeyGrant is one account's copy of a device archive key.
type KeyGrant struct {
	UserID    string `json:"user_id"`
	SealedDSK []byte `json:"sealed_dsk"`
}

// UsersRequest asks who can be granted access.
type UsersRequest struct{}

// UserSummary is one account, with the public key a grant is sealed to.
type UserSummary struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	PublicKey []byte `json:"public_key"`
}

// Users is the response to users.list.
type Users struct {
	Users []UserSummary `json:"users"`
}

// PairCode carries the eight-character linking code.
type PairCode struct {
	DeviceID string    `json:"device_id"`
	Code     string    `json:"code"`
	Expires  time.Time `json:"expires"`
}

// PairQR carries one QR payload. Codes rotate roughly every twenty seconds
// until the pairing window closes.
type PairQR struct {
	DeviceID string    `json:"device_id"`
	Code     string    `json:"code"`
	Expires  time.Time `json:"expires"`
}

// PairResult reports the outcome of a pairing attempt.
type PairResult struct {
	DeviceID string `json:"device_id"`
}

// DeviceStatus is pushed whenever a device changes state.
type DeviceStatus struct {
	DeviceID string `json:"device_id"`
	Status   string `json:"status"`
	Reason   string `json:"reason,omitempty"`
}

// DeviceInfo describes one device.
//
// LID and PN are both reported and either may be empty. LID is the primary
// identifier; a phone number is not always knowable, because withholding it is
// what LID is for.
type DeviceInfo struct {
	ID           string `json:"id"`
	Label        string `json:"label"`
	LID          string `json:"lid,omitempty"`
	PN           string `json:"pn,omitempty"`
	PushName     string `json:"push_name,omitempty"`
	Status       string `json:"status"`
	StatusReason string `json:"status_reason,omitempty"`
	ReceiptMode  string `json:"receipt_mode"`
	Running      bool   `json:"running"`
	Paused       bool   `json:"paused"`
	CanManage    bool   `json:"can_manage"`
	CanSend      bool   `json:"can_send"`
	ProfileKey   string `json:"profile_key,omitempty"`
	// CreatedAt is when the row was made, LastConnectedAt when the device last
	// reached "online" — not when it went offline. A device that is running now
	// has been up since then; one that is not was last seen then.
	CreatedAt       time.Time  `json:"created_at"`
	LastConnectedAt *time.Time `json:"last_connected_at,omitempty"`
	// Deliberately no "readable" flag. Whether a client can open a device is
	// decided by whether a grant actually opens in its browser, and a server
	// field claiming the same thing would be a second source of truth that
	// nobody can verify — pleasant right up to the moment the two disagree.
}

// Devices is the response to devices.list.
type Devices struct {
	Devices []DeviceInfo `json:"devices"`
}

// DeviceStat is how much one device has archived.
//
// Answered separately from devices.list because counting rows is the one query
// here whose cost grows with the size of the archive, and devices.list runs on
// every reconnect of every client. This runs when a person opens the console
// and asks.
type DeviceStat struct {
	DeviceID   string     `json:"device_id"`
	Chats      int64      `json:"chats"`
	Messages   int64      `json:"messages"`
	Media      int64      `json:"media"`
	MediaBytes int64      `json:"media_bytes"`
	LastAt     *time.Time `json:"last_at,omitempty"`
}

// DeviceStats is the response to devices.stats.
type DeviceStats struct {
	Stats []DeviceStat `json:"stats"`
}

// KeyHolder is one account that can open a device's archive.
//
// Reported so an operator can see the access control list rather than be told
// it was handled. Removing somebody from it stops them obtaining the key again
// and does not reach into a browser where they already have it, which is a
// distinction a UI has to be able to state.
type KeyHolder struct {
	UserID    string    `json:"user_id"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	Epoch     int       `json:"epoch"`
	GrantedAt time.Time `json:"granted_at"`
	GrantedBy string    `json:"granted_by,omitempty"`
}

// DeviceDetail is one device in full: identity, lifetime, counters and who can
// read what it archived.
type DeviceDetail struct {
	Device  DeviceInfo  `json:"device"`
	Stats   DeviceStat  `json:"stats"`
	Readers []KeyHolder `json:"readers"`
	// Epoch is the archive key generation this device seals under. Zero means
	// it has no key, which stops ingest rather than storing plaintext.
	Epoch int `json:"epoch"`
}

// DeleteRequest asks for a device and everything it archived to be removed.
//
// Confirm must repeat the device id. Not ceremony: this is the one call in the
// protocol that destroys an archive, the reply cannot be undone by anything on
// this server, and a mis-click in a device list is otherwise indistinguishable
// from an intention.
type DeleteRequest struct {
	DeviceID string `json:"device_id"`
	Confirm  string `json:"confirm"`
	// Unlink asks WhatsApp to drop the linked device as well, which is what
	// makes it disappear from the phone. Best effort: it needs the device to be
	// connected, and a device that is already logged out cannot be unlinked.
	Unlink bool `json:"unlink"`
}

// DeviceDeleted reports what a delete removed.
type DeviceDeleted struct {
	DeviceID string `json:"device_id"`
	Chats    int64  `json:"chats"`
	Messages int64  `json:"messages"`
	Media    int64  `json:"media"`
	// Unlinked is true when WhatsApp accepted the logout, so the device is gone
	// from the phone's list too. False means the row is gone here and the
	// entry on the phone has to be removed by hand.
	Unlinked bool `json:"unlinked"`
	// Note carries what went wrong with the parts that are best effort.
	Note string `json:"note,omitempty"`
}

// APIKeyInfo is one key as an operator sees it: everything except the key.
type APIKeyInfo struct {
	Prefix string `json:"prefix"`
	Name   string `json:"name"`
	// Scope is read, send or full. See store.KeyScope.
	Scope string `json:"scope"`
	// ActsAs is the service account the key carries, by name; empty for none.
	ActsAs     string     `json:"acts_as,omitempty"`
	CreatedBy  string     `json:"created_by,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

// APIKeys is the response to apikeys.list.
type APIKeys struct {
	Keys []APIKeyInfo `json:"keys"`
}

// APIKeyRequest asks for a new key.
//
// Scope is required. A default would be either too wide — a leaked key that
// can send as the paired number — or too narrow to notice until the job it
// was issued for fails, and whoever mints a key knows which they want.
//
// ActsAs names a service account. A key acting as one carries that account's
// grants — the sealed device keys the system opens with its own private key
// — and reaches only the devices it was granted, like a member.
type APIKeyRequest struct {
	Name   string `json:"name"`
	Scope  string `json:"scope"`
	ActsAs string `json:"acts_as,omitempty"`
}

// GrantsRequest asks for the grants of the account this connection acts as.
type GrantsRequest struct{}

// GrantEntry is one device this account may open: its key, sealed to the
// account's public key. Ciphertext here, and opened only by whoever holds
// the account's private key.
type GrantEntry struct {
	DeviceID  string `json:"device_id"`
	Label     string `json:"label,omitempty"`
	Epoch     int    `json:"epoch"`
	SealedDSK []byte `json:"sealed_dsk"`
}

// Grants answers grants.list.
type Grants struct {
	UserID string       `json:"user_id"`
	Grants []GrantEntry `json:"grants"`
}

// APIKeyCreated carries the new key, once.
//
// The plaintext exists in this frame and nowhere else, ever again: only a hash
// is stored. A client that does not show it to somebody has lost it.
type APIKeyCreated struct {
	Key  string     `json:"key"`
	Info APIKeyInfo `json:"info"`
}

// APIKeyRef names a key by its prefix, which is a selector and not a secret.
type APIKeyRef struct {
	Prefix string `json:"prefix"`
}

// GrantRequest hands one account the key to one device.
//
// The ciphertext was produced by a client that already had the device key,
// because only such a client can produce it: this server has never held the
// private half and cannot seal anything to anybody.
//
// Which means the honest description of the rule below is narrow. Requiring an
// admin controls what gets *recorded here*. It cannot stop somebody who already
// holds a key from passing it on by other means — no arrangement can, once a
// key is in a person's browser.
type GrantRequest struct {
	DeviceID  string `json:"device_id"`
	UserID    string `json:"user_id"`
	Epoch     int    `json:"epoch"`
	SealedDSK []byte `json:"sealed_dsk"`
}

// GrantRevoke takes it back, for whatever that is worth.
//
// Level 1 revocation: the account can no longer obtain the key. It says nothing
// about a copy already unlocked in a browser. Only an epoch rotation with a
// re-seal is retroactive, and this server cannot do one — it cannot open what
// it would have to re-seal.
type GrantRevoke struct {
	DeviceID string `json:"device_id"`
	UserID   string `json:"user_id"`
}

// Readers is the access control list after a change.
type Readers struct {
	DeviceID string      `json:"device_id"`
	Readers  []KeyHolder `json:"readers"`
}

// Subscribe asks for everything since a cursor, then live traffic.
type Subscribe struct {
	// SinceSeq is the last sequence this client already has. Zero means start
	// from the beginning; omit the field entirely to receive only live traffic.
	SinceSeq int64 `json:"since_seq"`
	// Live only, skipping replay. For a client that has no local store.
	LiveOnly bool `json:"live_only,omitempty"`
	// Devices limits delivery. Empty means every device of the tenant.
	Devices []string `json:"devices,omitempty"`
}

// ReplayBegin announces the watermark the replay will run to.
type ReplayBegin struct {
	ThroughSeq int64 `json:"through_seq"`
}

// ReplayEnd reports where the replay actually stopped. Live traffic follows.
type ReplayEnd struct {
	LastSeq int64 `json:"last_seq"`
	Count   int   `json:"count"`
}

// Lag tells a client its stream was not continuous and where to resume from.
//
// Sent instead of closing the connection. The v1 server dropped a slow
// consumer, which turned a phone on a bad connection into a lost session; here
// the client refetches from the sequence below and carries on.
type Lag struct {
	FromSeq int64 `json:"from_seq"`
	Dropped int   `json:"dropped"`
}

// SealedMedia is an attachment as it leaves the server.
type SealedMedia struct {
	MediaType     string `json:"media_type"`
	MimeType      string `json:"mimetype,omitempty"`
	FileLength    int64  `json:"file_length,omitempty"`
	FileEncSHA256 []byte `json:"file_enc_sha256,omitempty"`
	Width         int32  `json:"width,omitempty"`
	Height        int32  `json:"height,omitempty"`
	Seconds       int32  `json:"seconds,omitempty"`
	// Waveform is the 64-byte amplitude sketch behind a voice note. Not
	// sealed: it is envelope shape, carries no speech, and the client needs it
	// to draw the placeholder before fetching the audio.
	Waveform []byte `json:"waveform,omitempty"`
	IsGIF    bool   `json:"is_gif,omitempty"`

	// Sealed. The file name is content, not metadata.
	MediaKeySealed []byte `json:"media_key_sealed,omitempty"`
	ThumbSealed    []byte `json:"thumb_sealed,omitempty"`
	FileNameSealed []byte `json:"filename_sealed,omitempty"`

	DownloadStatus string `json:"download_status"`
}

// SealedMessage is one archived message on the wire.
//
// Routing travels readable so a client can order and group without unwrapping
// anything; content travels exactly as it sits on disk. The server is not a
// participant in the encryption, only a courier.
type SealedMessage struct {
	UID string `json:"uid"`
	Seq int64  `json:"seq"`

	DeviceID  string `json:"device_id"`
	WAID      string `json:"wa_id"`
	ChatKey   string `json:"chat_key"`
	SenderKey string `json:"sender_key,omitempty"`
	SenderLID string `json:"sender_lid,omitempty"`
	SenderPN  string `json:"sender_pn,omitempty"`

	TS       *time.Time `json:"ts,omitempty"`
	IsFromMe bool       `json:"is_from_me"`
	IsGroup  bool       `json:"is_group,omitempty"`

	Kind string `json:"kind"`
	Type string `json:"type"`
	// Unsupported names the protobuf field this build did not understand, on a
	// message whose type is "unsupported". A reader shows it instead of a bare
	// label, so somebody can say what to implement next.
	Unsupported string `json:"unsupported,omitempty"`

	// TargetRel says whether a control row acts on a message or on a reaction.
	// Resolved once during ingest, so no client has to work it out — the
	// question v1 answered in two places that disagreed.
	TargetWAID string `json:"target_wa_id,omitempty"`
	TargetUID  string `json:"target_uid,omitempty"`
	TargetRel  string `json:"target_rel,omitempty"`
	ReplyTo    string `json:"reply_to,omitempty"`

	IsForwarded     bool  `json:"is_forwarded,omitempty"`
	ForwardingScore int32 `json:"forwarding_score,omitempty"`

	Expiration int32      `json:"expiration,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	ViewOnce   bool       `json:"view_once,omitempty"`
	Ephemeral  bool       `json:"ephemeral,omitempty"`

	Source string `json:"source"`

	ContentKeyID uint32 `json:"content_key_id,omitempty"`
	BodySealed   []byte `json:"body_sealed,omitempty"`
	// PayloadSealed is the structured content — location, poll, contact cards,
	// event, link preview, mentions — as sealed JSON. Opens with the same
	// content key as the body; decode it with domain.ParsePayload.
	PayloadSealed []byte `json:"payload_sealed,omitempty"`

	Media *SealedMedia `json:"media,omitempty"`
}

// SendRequest sends a text message.
//
// The body arrives in plaintext because the server has to hand it to the Signal
// session. That is the one place content necessarily passes through here, and
// it is why the README says outbound text is not covered by the sealed-archive
// guarantee. It is sealed the moment it is archived.
type SendRequest struct {
	DeviceID string `json:"device_id"`
	// Chat is the JID to send to.
	Chat string `json:"chat"`
	Body string `json:"body"`

	// ID makes a retry idempotent: the same id twice is one message.
	ID string `json:"id,omitempty"`

	// ReplyTo quotes an earlier message. ReplyBody must accompany it: the
	// archive is sealed, so the server cannot look up what was said, and the
	// quote has to be reconstructed from what the client already holds.
	ReplyTo     string `json:"reply_to,omitempty"`
	ReplySender string `json:"reply_sender,omitempty"`
	ReplyBody   string `json:"reply_body,omitempty"`

	// Forwarded marks the message as forwarded. A score of five or more is
	// what WhatsApp renders as "forwarded many times".
	Forwarded       bool   `json:"forwarded,omitempty"`
	ForwardingScore uint32 `json:"forwarding_score,omitempty"`

	// Expiration overrides the chat's disappearing timer for this message.
	//
	// Normally left empty. Disappearing messages are a property of the chat,
	// so the server reads the chat's timer and applies it — including the
	// envelope the message has to travel in, which is the part that actually
	// makes it vanish. Setting a value here that does not match the chat's
	// setting produces a message clients disagree about.
	Expiration uint32 `json:"expiration,omitempty"`
	// Ephemeral forces the disappearing envelope. Also normally left empty:
	// it follows from the chat's timer.
	Ephemeral bool     `json:"ephemeral,omitempty"`
	ViewOnce  bool     `json:"view_once,omitempty"`
	Mentions  []string `json:"mentions,omitempty"`

	// Preview is the link card, described by the client.
	//
	// The server never builds one. Doing so would mean fetching the URL: it
	// would learn every link its users send, which contradicts the sealed
	// archive, and it would issue requests to addresses chosen by whoever is
	// messaging. The client has already loaded the page; it can describe it.
	Preview *LinkPreviewRequest `json:"preview,omitempty"`
}

// LinkPreviewRequest is a link card supplied with an outbound message.
type LinkPreviewRequest struct {
	// URL must appear verbatim in the body. WhatsApp matches the card to the
	// text, and one that does not match silently fails to render.
	URL         string `json:"url"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Thumbnail   []byte `json:"thumbnail,omitempty"`
}

// UploadRef is what POST /v1/upload gave back.
//
// The bytes are already on WhatsApp's servers by the time this is filled in; a
// message referencing them is a small protobuf, which is why the same upload
// can be sent to several chats without transferring anything again.
type UploadRef struct {
	// Type is the attachment kind the upload encrypted for, echoed back by the
	// endpoint. Left empty by an older client, in which case nothing is
	// checked; when present it must agree with the send's own type.
	Type          string `json:"type,omitempty"`
	URL           string `json:"url"`
	DirectPath    string `json:"direct_path"`
	MediaKey      []byte `json:"media_key"`
	FileSHA256    []byte `json:"file_sha256"`
	FileEncSHA256 []byte `json:"file_enc_sha256"`
	FileLength    uint64 `json:"file_length"`
}

// SendMediaRequest sends an attachment that has already been uploaded.
//
// Two steps rather than one: the file goes to POST /v1/upload, and this frame
// references the result. Framing a video down the websocket would stall every
// other frame behind it and would need the whole thing in memory on both ends.
type SendMediaRequest struct {
	DeviceID string `json:"device_id"`
	Chat     string `json:"chat"`
	// Type is image, video, ptv, audio, ptt, document or sticker.
	Type   string    `json:"type"`
	Upload UploadRef `json:"upload"`
	// MimeType is how the recipient decides to render it, so it is required.
	MimeType string `json:"mimetype"`

	ID string `json:"id,omitempty"`

	// Caption is the text under an image, video or document. Audio has none —
	// WhatsApp has no field for it — and passing one is refused rather than
	// dropped, because a caption that vanishes looks like a delivery failure.
	Caption string `json:"caption,omitempty"`
	// FileName is required for a document and is what the download is called.
	FileName string `json:"filename,omitempty"`

	Width   uint32 `json:"width,omitempty"`
	Height  uint32 `json:"height,omitempty"`
	Seconds uint32 `json:"seconds,omitempty"`

	// Waveform and Thumbnail come from the client. Computing either means
	// decoding the media, and the thing that already decoded it is whatever
	// recorded or displayed it.
	Waveform  []byte `json:"waveform,omitempty"`
	Thumbnail []byte `json:"thumbnail,omitempty"`
	// Sidecar carries per-chunk MACs so a video plays before it has finished
	// downloading.
	Sidecar []byte `json:"sidecar,omitempty"`

	// IsGIF makes a video loop silently, which is how WhatsApp does GIFs: it
	// has no GIF type, only a video flagged this way.
	IsGIF      bool `json:"is_gif,omitempty"`
	IsAnimated bool `json:"is_animated,omitempty"`

	ReplyTo     string `json:"reply_to,omitempty"`
	ReplySender string `json:"reply_sender,omitempty"`
	ReplyBody   string `json:"reply_body,omitempty"`

	Forwarded       bool   `json:"forwarded,omitempty"`
	ForwardingScore uint32 `json:"forwarding_score,omitempty"`

	Expiration uint32 `json:"expiration,omitempty"`
	// ViewOnce finally means something here. It is a media feature; the same
	// flag on text renders as "sent from an older version of WhatsApp".
	ViewOnce  bool     `json:"view_once,omitempty"`
	Ephemeral bool     `json:"ephemeral,omitempty"`
	Mentions  []string `json:"mentions,omitempty"`
}

// EditRequest replaces the text of a message already sent.
type EditRequest struct {
	DeviceID string `json:"device_id"`
	Chat     string `json:"chat"`
	// TargetID is the message being replaced.
	TargetID string `json:"target_id"`
	Body     string `json:"body"`
	// SentAt lets the server refuse an edit past the twenty-minute window
	// before spending a round trip on a stanza that would be rejected.
	SentAt *time.Time `json:"sent_at,omitempty"`
}

// RevokeRequest deletes a message for everyone. The archive keeps it.
type RevokeRequest struct {
	DeviceID string `json:"device_id"`
	Chat     string `json:"chat"`
	TargetID string `json:"target_id"`
	// Sender is the original author, for a group admin deleting someone
	// else's message. Empty deletes our own.
	Sender string `json:"sender,omitempty"`
}

// ReactRequest adds or removes a reaction. An empty emoji removes.
type ReactRequest struct {
	DeviceID string `json:"device_id"`
	Chat     string `json:"chat"`
	TargetID string `json:"target_id"`
	Sender   string `json:"sender,omitempty"`
	Emoji    string `json:"emoji"`
}

// MarkReadRequest sends a read receipt.
//
// Always explicit. Nothing on the ingest path sends one, which is what
// incognito means here.
type MarkReadRequest struct {
	DeviceID string   `json:"device_id"`
	Chat     string   `json:"chat"`
	Sender   string   `json:"sender,omitempty"`
	IDs      []string `json:"ids"`
	// Played marks voice notes and view-once media as played, a separate
	// signal from read on the sender's screen.
	Played bool `json:"played,omitempty"`
}

// ChatTimerRequest turns disappearing messages on or off for one chat.
//
// It is a chat setting, not a message option, because that is all WhatsApp has:
// there is no way to make one message vanish and leave the next one alone.
// Every message sent into such a chat then carries the timer, and this server
// applies it automatically — a caller does not pass an expiry per send.
//
// The change is announced in the conversation by WhatsApp itself, to everyone
// in it. It is not a quiet setting.
type ChatTimerRequest struct {
	DeviceID string `json:"device_id"`
	Chat     string `json:"chat"`
	// Seconds is the timer. Zero turns disappearing messages off. WhatsApp's
	// own presets are 86400 (24 hours), 604800 (7 days) and 7776000 (90 days);
	// other values are accepted by the protocol and may render oddly in
	// official clients.
	Seconds uint32 `json:"seconds"`
}

// ChatTimerResult confirms the setting that is now in force.
type ChatTimerResult struct {
	Chat    string `json:"chat"`
	Seconds uint32 `json:"seconds"`
}

// GroupJoinRequest accepts an invitation that arrived as a message.
//
// The code has to come from the client, and that is not an inconvenience to
// work around later. An invite code is a capability — whoever holds it can walk
// into the group — so it is sealed with the rest of the message payload, and
// this server cannot read its own archive. The client opens the payload and
// passes the code in for the one exchange, exactly as MediaRetryRequest passes
// a media key.
//
// Explicit, and never inferred. Joining makes this account a member, visible to
// everyone already in the group, and there is no undo on this side. Nothing on
// the ingest path may reach this — it exists for somebody who read the
// invitation and pressed a button.
type GroupJoinRequest struct {
	DeviceID string `json:"device_id"`
	// GroupJID is the group being joined, and Inviter whoever sent the
	// invitation. Both are needed: WhatsApp validates the code against the
	// pair.
	GroupJID string `json:"group_jid"`
	Inviter  string `json:"inviter"`
	Code     string `json:"code"`
	// Expiration is the code's own expiry, in Unix seconds, echoed back from
	// the message. WhatsApp refuses a stale one.
	Expiration int64 `json:"expiration,omitempty"`
}

// PollVoteRequest answers a poll.
//
// The options arrive as text, from the client, and that is the only place they
// could come from: a poll's options are sealed content, so this server cannot
// read the question it is helping to answer. It hashes what it is given and
// encrypts the result under the poll's secret — which is all WhatsApp's own
// clients do.
//
// A vote replaces the voter's previous answer rather than adding to it, which
// is WhatsApp's rule and not this server's: sending an empty Options list is
// how a person withdraws their vote, and it is a legitimate request, not an
// empty one to be rejected.
type PollVoteRequest struct {
	DeviceID string `json:"device_id"`
	Chat     string `json:"chat"`
	// PollID identifies the poll being answered, and Sender who created it.
	// Both are needed: the vote's key is derived from the original message,
	// and the sender is part of that derivation.
	PollID     string `json:"poll_id"`
	PollSender string `json:"poll_sender"`
	// PollFromMe says the poll is one of ours, which the key derivation also
	// needs and which no amount of comparing strings here can settle as
	// reliably as the client, which has the row in front of it.
	PollFromMe bool `json:"poll_from_me,omitempty"`
	// Options are the choices, as the exact text of the poll's own options.
	// Empty withdraws the vote.
	Options []string `json:"options"`
}

// GroupRequest asks who is in a group and what has happened to it.
//
// Refreshes the composition from WhatsApp on the way, when the device is
// connected: a membership list a week old, presented without saying so, is a
// worse answer than a round trip.
type GroupRequest struct {
	DeviceID string `json:"device_id"`
	Chat     string `json:"chat"`
	// Refresh asks WhatsApp rather than answering from the archive alone.
	Refresh bool `json:"refresh,omitempty"`
}

// GroupMember is one participant, as the wire carries them.
//
// The identifiers are readable, exactly as sender_key and reader_key already
// are; the NAME is not here at all, because a name is content and lives sealed
// in contacts. A client resolves it there, the same way it resolves the author
// of any message.
type GroupMember struct {
	Key          string `json:"key"`
	LID          string `json:"lid,omitempty"`
	PN           string `json:"pn,omitempty"`
	IsAdmin      bool   `json:"is_admin,omitempty"`
	IsSuperAdmin bool   `json:"is_super_admin,omitempty"`
}

// GroupChange is one thing that happened to a group.
type GroupChange struct {
	TS         time.Time `json:"ts"`
	Action     string    `json:"action"`
	ActorKey   string    `json:"actor_key,omitempty"`
	ActorLID   string    `json:"actor_lid,omitempty"`
	ActorPN    string    `json:"actor_pn,omitempty"`
	SubjectKey string    `json:"subject_key,omitempty"`
	SubjectLID string    `json:"subject_lid,omitempty"`
	SubjectPN  string    `json:"subject_pn,omitempty"`
	Detail     string    `json:"detail,omitempty"`
}

// Group is who is in a conversation and what has happened to it.
type Group struct {
	PermissionsKnown bool          `json:"permissions_known"`
	CanManage        bool          `json:"can_manage"`
	IsMember         bool          `json:"is_member"`
	ChatKey          string        `json:"chat_key"`
	Members          []GroupMember `json:"members"`
	Changes          []GroupChange `json:"changes,omitempty"`
	// Since is when this archive's record of the group begins. Before it,
	// nothing is known and nothing is claimed: WhatsApp does not deliver a
	// group's past, so an empty history is not a peaceful one and a reader has
	// to be told which it is looking at.
	Since *time.Time `json:"since,omitempty"`
	// Refreshed reports whether the composition was just re-read from
	// WhatsApp, so a client can say "as of now" or "as last seen".
	Refreshed bool `json:"refreshed,omitempty"`
}

// GroupJoined confirms the account is now a member.
type GroupJoined struct {
	GroupJID string `json:"group_jid"`
}

// ReprojectRequest asks which stored messages this build might now understand,
// and then hands back what one of them turned out to be.
//
// Classification happens once, on the way in, so a message that arrived before
// its type was supported stays "unsupported" for good. The protobuf that
// produced it was sealed and kept precisely so a later build can look again —
// but this server cannot open its own archive, which is the premise the whole
// design rests on.
//
// So the browser does the opening and the server does the classifying. The
// archive key never leaves the tab: the client opens raw_sealed, sends back the
// protobuf, and this server runs the SAME normaliser the ingest path runs and
// re-seals the result with the public half, which is all sealing needs.
//
// The cost is stated rather than hidden: for the rows an operator explicitly
// asks to reproject, the message passes through this server in the clear. That
// is the same exposure outbound text already carries, bounded to a deliberate
// action, and strictly smaller than the alternative — which was handing the
// archive key to a command line, where it would sit in a shell history forever.
type ReprojectRequest struct {
	DeviceID string `json:"device_id"`
	// Limit bounds a listing, and BeforeSeq pages it.
	//
	// A cursor rather than an offset because most rows stay unsupported —
	// they are types this build still does not understand and they come back
	// on every pass — so an offset-free second request returns the same
	// unconvertible page for ever and nothing past it is ever reached.
	Limit     int   `json:"limit,omitempty"`
	BeforeSeq int64 `json:"before_seq,omitempty"`
	// UID and Raw carry one opened message back. Empty on a listing.
	UID string `json:"uid,omitempty"`
	Raw []byte `json:"raw,omitempty"`
}

// UnsupportedRow is one stored message a later build might understand.
type UnsupportedRow struct {
	UID  string `json:"uid"`
	Seq  int64  `json:"seq"`
	WAID string `json:"wa_id"`
	// Field is the protobuf field name this build could not classify, which is
	// the only clue there is about what to implement next.
	Field        string `json:"field,omitempty"`
	ContentKeyID uint32 `json:"content_key_id,omitempty"`
	RawSealed    []byte `json:"raw_sealed,omitempty"`
}

// Unsupported is the response to reproject.list.
type Unsupported struct {
	DeviceID string           `json:"device_id"`
	Rows     []UnsupportedRow `json:"rows"`
}

// Reprojected reports what one message turned out to be.
type Reprojected struct {
	UID string `json:"uid"`
	// Type is the new classification. Still "unsupported" is the ordinary
	// answer: most rows are types this build does not know either, and the
	// field name is kept so somebody can decide what to build next.
	Type string `json:"type"`
	// Changed is false when the row was left exactly as it was.
	Changed bool `json:"changed"`
	// Note explains a row that could have changed and deliberately was not.
	Note string `json:"note,omitempty"`
	// Machinery says the row is protocol traffic rather than a message: key
	// distribution and the like, which an older build stored and the current
	// one skips on the way in. Not a failure and not a type waiting to be
	// implemented.
	Machinery bool `json:"machinery,omitempty"`
}

// ChatPresenceRequest says we are typing in a conversation, or have stopped.
//
// The most continuous signal this account can emit: it names a conversation
// somebody has open, at this exact moment, several times a minute. Which is why
// it goes through the same policy as every receipt and is simply not sent in
// the quiet posture — there is no upstream flag for silence, and silence is
// what happens when nothing is sent.
type ChatPresenceRequest struct {
	DeviceID string `json:"device_id"`
	Chat     string `json:"chat"`
	// State is "composing" or "paused".
	State string `json:"state"`
	// Media is "audio" while recording a voice note, empty while typing.
	Media string `json:"media,omitempty"`
}

// PresenceEvent is somebody else typing, pushed as it happens.
//
// It carries no sequence number and is never replayed, because it is true for a
// few seconds and then it is not. A client that was not connected missed
// nothing worth having.
type PresenceEvent struct {
	DeviceID  string     `json:"device_id"`
	ChatKey   string     `json:"chat_key"`
	SenderKey string     `json:"sender_key,omitempty"`
	SenderLID string     `json:"sender_lid,omitempty"`
	SenderPN  string     `json:"sender_pn,omitempty"`
	State     string     `json:"state"`
	Media     string     `json:"media,omitempty"`
	LastSeen  *time.Time `json:"last_seen,omitempty"`
}

type PresenceSubscribeRequest struct {
	DeviceID string `json:"device_id"`
	Chat     string `json:"chat"`
}

type PresenceSubscription struct {
	DeviceID   string `json:"device_id"`
	Chat       string `json:"chat"`
	Subscribed bool   `json:"subscribed"`
	Reason     string `json:"reason,omitempty"`
}

// ChatUpdateEvent is a change to a conversation itself, pushed as it happens.
//
// It exists because two numbers were being computed correctly and never said.
// An unread badge and a disappearing timer both live on the chat row, and the
// only frame that ever carried either was the reply to a chats.list request —
// so a badge moved when the sidebar happened to be refetched and at no other
// moment, and a timer the other side changed stayed invisible until a reload.
//
// A patch, not a snapshot, and every field is a pointer for that reason: an
// event about a badge says nothing about the timer, and a client treating an
// absent field as zero would clear one whenever the other moved. In JSON that
// means a client must distinguish "key absent" from "key present and zero" —
// zero is a real value for both fields, which is precisely why turning a timer
// off could never be expressed before.
type ChatUpdateEvent struct {
	DeviceID string `json:"device_id"`
	ChatKey  string `json:"chat_key"`
	Unread   *int32 `json:"unread,omitempty"`
	// Ephemeral is the timer in seconds. Zero means off — and note that
	// omitempty does not drop it, because it is a pointer: a pointer to zero
	// marshals as 0, which is the whole point.
	Ephemeral *int32 `json:"ephemeral,omitempty"`
}

// DeviceModeRequest changes what a device tells the other side, while it runs.
//
// The mode was fixed at pairing, which made "go quiet" something you could only
// decide before you had anything to be quiet about. It is also the switch the
// whole incognito posture hangs off: read receipts, played receipts and typing
// notifications are all suppressed by it, and delivery receipts leave typed
// "inactive", which official clients receive and do not render.
type DeviceModeRequest struct {
	DeviceID string `json:"device_id"`
	// ReceiptMode is "passive" (quiet, and what incognito means) or "active".
	ReceiptMode string `json:"receipt_mode"`
}

// MediaRetryRequest asks a sender to upload an attachment again.
//
// WhatsApp signs media URLs with an expiry and puts the same signature on the
// direct path, so once it passes there is no address left that works. A history
// sync replays months-old messages with the URL minted back then, which is why
// a bootstrap can land with most of its attachments already unreachable.
//
// The media key has to come from the client. It is needed both to authenticate
// the request and to read the answer, and this server cannot open the sealed
// copy it holds. It is kept in memory for the exchange and never written down —
// a real exposure, accepted deliberately, for attachments the owner asked to
// recover.
type MediaRetryRequest struct {
	DeviceID string `json:"device_id"`
	// UID is the message whose attachment is missing.
	UID string `json:"uid"`
	// MediaKey is the 32 bytes from the message's sealed media key, opened by
	// the client.
	MediaKey []byte `json:"media_key"`
}

// BackfillRequest asks WhatsApp for messages older than the archive has.
//
// A history sync covers what the phone still holds and stops; anything earlier
// has to be asked for one chat at a time. The request is anchored on the oldest
// message already stored, so the answer is what came *before* it — asking with
// the newest would return what is already here.
//
// The answer is not immediate and does not come back on this connection. It
// arrives minutes later as an ON_DEMAND history sync, is ingested like any
// other, and shows up as new messages on the subscription.
type BackfillRequest struct {
	DeviceID string `json:"device_id"`
	Chat     string `json:"chat"`
	// Count is how many messages to ask for. WhatsApp decides what it will
	// actually send, and sends nothing at all once the phone has no more.
	Count int `json:"count,omitempty"`
}

// BackfillSent confirms the request left, and names the anchor it was made
// against so a caller can tell whether progress was made when it asks again.
type BackfillSent struct {
	Chat string `json:"chat"`
	// AnchorID is the oldest message the archive held when this was asked.
	AnchorID string `json:"anchor_id"`
	Count    int    `json:"count"`
}

// ExpiredMediaRequest asks which attachments have an expired url.
//
// Separate from the download queue because these are not retryable by
// downloading: nothing about them changes until the sender re-uploads.
type ExpiredMediaRequest struct {
	DeviceID string `json:"device_id"`
	Limit    int    `json:"limit,omitempty"`
}

// ExpiredMedia lists the message uids whose attachments are unreachable.
type ExpiredMedia struct {
	UIDs []string `json:"uids"`
}

// MediaRetryQueued confirms the request left. The answer, if the sender is
// reachable and still has the file, arrives later and the attachment is
// downloaded then.
type MediaRetryQueued struct {
	UID string `json:"uid"`
}

// SendResult reports what was sent.
type SendResult struct {
	ID        string    `json:"id"`
	UID       string    `json:"uid,omitempty"`
	Seq       int64     `json:"seq,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// KeysRequest asks for sealed content keys by id.
//
// Scoped to a device, because content keys are: each is sealed to that
// device's archive key, and ids are counted per device rather than per tenant,
// so id 7 names a different key on every account.
type KeysRequest struct {
	DeviceID string   `json:"device_id"`
	IDs      []uint32 `json:"ids"`
}

// SealedKey is one content key, still sealed to a device's archive key.
//
// The server hands these out freely to an authenticated client because it
// cannot open them: they are ciphertext under a public key whose private half
// never reached this process. A client without the matching device key gets
// bytes and nothing else.
type SealedKey struct {
	ID     uint32 `json:"id"`
	Sealed []byte `json:"sealed"`
}

// Keys is the response to keys.get. The device is echoed back because the
// sealed values bind to it, and a client opening them has to know which.
type Keys struct {
	DeviceID string      `json:"device_id"`
	Keys     []SealedKey `json:"keys"`
}

// ContactSummary is one contact as it leaves the server.
//
// Three names rather than one, because they are three different claims: what
// someone calls themselves, what this account saved them as, and what WhatsApp
// verified about a business. Which to show is the client's decision — it
// depends on what the client is for — so the server hands over all three rather
// than picking.
//
// All of them are sealed. A name is content by the same definition that seals a
// message body: a database dump that revealed who the identifiers belong to
// would hand over most of what a social graph is.
type ContactSummary struct {
	// UID is what the sealed values are bound to.
	UID        string `json:"uid"`
	ContactKey string `json:"contact_key"`
	ContactLID string `json:"contact_lid,omitempty"`
	ContactPN  string `json:"contact_pn,omitempty"`
	IsGroup    bool   `json:"is_group,omitempty"`

	ContentKeyID       uint32 `json:"content_key_id,omitempty"`
	PushNameSealed     []byte `json:"push_name_sealed,omitempty"`
	FullNameSealed     []byte `json:"full_name_sealed,omitempty"`
	BusinessNameSealed []byte `json:"business_name_sealed,omitempty"`

	// HasAvatar says a picture is stored without sending it. A thousand
	// contacts with a picture each is tens of megabytes, and a chat list needs
	// the names now and the faces as it draws them.
	HasAvatar   bool   `json:"has_avatar,omitempty"`
	AvatarID    string `json:"avatar_id,omitempty"`
	AvatarKeyID uint32 `json:"avatar_key_id,omitempty"`
}

// Contacts is the response to contacts.list.
type Contacts struct {
	DeviceID string           `json:"device_id"`
	Contacts []ContactSummary `json:"contacts"`
}

// ContactsResolveRequest asks who particular identifiers belong to.
//
// Distinct from contacts.list, which pages the whole device once. A client
// keeps its directory from that list and then meets identifiers the list did
// not have: a conversation started after it loaded, a group participant who has
// never sent anything here. Reloading five thousand rows to learn one name is
// the wrong shape, and drawing a LID at somebody is the wrong answer.
//
// Best effort by design. The reply carries whatever is stored for the keys
// asked about, having first looked in whatsmeow's own contact cache for the
// ones this archive has nothing for, and having asked the picture worker to
// look at them ahead of its ordinary sweep. A key that nothing knows about
// simply comes back absent.
type ContactsResolveRequest struct {
	DeviceID string `json:"device_id"`
	// Keys are contact keys as they appear on messages and chats. Anything
	// past resolveLimit is dropped rather than refused: a client redrawing a
	// long list asks about what it can see, and the rest come with the next
	// draw.
	Keys []string `json:"contact_keys"`
}

// AvatarRequest asks for one profile picture.
type AvatarRequest struct {
	DeviceID   string `json:"device_id"`
	ContactKey string `json:"contact_key"`
}

// Avatar is one sealed profile picture. The device is echoed because content
// keys are per device and a client needs it to ask for the right one.
//
// Sealed by this server rather than stored as received: WhatsApp serves profile
// pictures over plain HTTP with no encryption, unlike message media where the
// CDN hands over ciphertext that is kept verbatim. There was nothing to
// preserve, so the bytes were sealed on the way in.
type Avatar struct {
	DeviceID   string `json:"device_id"`
	ContactKey string `json:"contact_key"`
	UID        string `json:"uid"`
	KeyID      uint32 `json:"key_id,omitempty"`
	Sealed     []byte `json:"sealed,omitempty"`
}

// ChatSummary is one entry in the chat list.
type ChatSummary struct {
	// UID is what the sealed name is bound to. Sent rather than derived on the
	// client, so nothing has to reimplement the derivation to open a name.
	UID     string     `json:"uid"`
	ChatKey string     `json:"chat_key"`
	ChatLID string     `json:"chat_lid,omitempty"`
	ChatPN  string     `json:"chat_pn,omitempty"`
	IsGroup bool       `json:"is_group,omitempty"`
	LastSeq int64      `json:"last_seq"`
	LastTS  *time.Time `json:"last_ts,omitempty"`
	// CreatedAt is when this archive wrote the row: the last-resort sort key.
	// GroupCreatedAt is when the group itself was made, which is what orders a
	// conversation nobody has spoken in — a group created yesterday belongs
	// where yesterday belongs, not below every conversation last spoken in
	// years ago.
	CreatedAt      time.Time  `json:"created_at"`
	GroupCreatedAt *time.Time `json:"group_created_at,omitempty"`
	LastKind       string     `json:"last_kind,omitempty"`
	LastType       string     `json:"last_type,omitempty"`
	Unread         int32      `json:"unread,omitempty"`
	Archived       bool       `json:"archived,omitempty"`
	Pinned         bool       `json:"pinned,omitempty"`

	NameSealed []byte `json:"name_sealed,omitempty"`
	NameKeyID  uint32 `json:"name_key_id,omitempty"`

	// Keys is every conversation folded into this one, usually just its own.
	//
	// Sent because live traffic arrives addressed by whichever key WhatsApp
	// used, and a client holding one row has to recognise a message that names
	// the other half of the same person.
	Keys []string `json:"keys,omitempty"`

	// Audience is how many people are in the group, including us: the
	// denominator behind "everyone received it". Absent for a direct
	// conversation, where it is one, and absent for a group WhatsApp has not
	// been asked about — where a tick must not be promoted past one grey,
	// because "everyone" on the strength of a number nobody has is the claim
	// this field exists to prevent.
	Audience int32 `json:"audience,omitempty"`

	// Ephemeral is the disappearing-message timer on the conversation, in
	// seconds. Zero is off. A chat setting rather than a message option
	// because that is all WhatsApp has, and every message sent into the
	// conversation picks it up.
	Ephemeral int32 `json:"ephemeral,omitempty"`

	// The newest message in the conversation, so a list can show a preview
	// without a request per row. Sealed like any other body and bound to
	// LastUID, not to the chat — opening it against the chat uid fails.
	//
	// Absent when the newest row carries no text: a deletion has none, and a
	// photograph without a caption has none either. LastType says which.
	LastUID        string `json:"last_uid,omitempty"`
	LastBodySealed []byte `json:"last_body_sealed,omitempty"`
	LastBodyKeyID  uint32 `json:"last_body_key_id,omitempty"`
}

// Chats is the response to chats.list.
type Chats struct {
	DeviceID string        `json:"device_id"`
	Chats    []ChatSummary `json:"chats"`
}

// ChatPageRequest asks for a page of one conversation.
//
// The cursor is a pair, and both halves are required to page backwards. A
// conversation is ordered by when each message was sent; WhatsApp timestamps
// are whole seconds, so a burst inside one second needs seq to break the tie.
// A cursor on time alone would skip messages or repeat them at every page
// boundary, depending on which way the comparison leaned.
type ChatPageRequest struct {
	DeviceID string `json:"device_id"`
	ChatKey  string `json:"chat_key"`
	// BeforeTS and BeforeSeq page backwards, taken from the oldest message of
	// the page already held. An empty BeforeTS means the latest page.
	BeforeTS  *time.Time `json:"before_ts,omitempty"`
	BeforeSeq int64      `json:"before_seq,omitempty"`
	Limit     int        `json:"limit,omitempty"`
}

// MessageAcks is one message's ticks, as counts of PEOPLE.
//
// Not rows and not devices: one reader with a phone and a laptop is one person
// who received it, and a tick that waits for everyone must not be waiting for a
// device count nobody can name.
//
// Our own acknowledgements are excluded from the counts and reported in
// ReadByUs. ReceiptTypeSender is our own phone confirming it received a message
// WE sent; counting it draws two grey ticks the instant our own handset
// acknowledges, with the recipient having received nothing.
//
// Retrying and Failed are apart and no tick rule reads them. A message stuck in
// retry looks delivered and is not.
type MessageAcks struct {
	WAID      string `json:"wa_id"`
	Delivered int    `json:"delivered,omitempty"`
	Read      int    `json:"read,omitempty"`
	Played    int    `json:"played,omitempty"`

	DeliveredAt *time.Time `json:"delivered_at,omitempty"`
	ReadAt      *time.Time `json:"read_at,omitempty"`
	PlayedAt    *time.Time `json:"played_at,omitempty"`

	ReadByUs bool `json:"read_by_us,omitempty"`
	Retrying bool `json:"retrying,omitempty"`
	Failed   bool `json:"failed,omitempty"`
}

// Page is a page of one conversation, oldest first.
type Page struct {
	ChatKey  string          `json:"chat_key"`
	Messages []SealedMessage `json:"messages"`
	// Receipts covers the messages above, so ticks survive a reload.
	//
	// Without it a client only knows what crossed its own connection, so a
	// conversation opened cold shows a single grey tick on everything —
	// including messages read months ago — and looks like a client that has
	// stopped updating.
	//
	// Keyed on the ROOT message id, never on an edit's. A bubble is keyed on
	// the root, so acks for an edit would be looked up by nobody; and folding
	// them into the parent would count twice anybody who acknowledged both
	// versions. Which version each reader actually saw stays in
	// message.history, where the distinction between proof and inference is
	// already reported.
	Receipts []MessageAcks `json:"receipts,omitempty"`
	// NextTS and NextSeq are the cursor for the page before this one. Sent
	// rather than derived by the client, so both sides agree about what
	// "oldest" means when a page ends on a second boundary.
	NextTS  *time.Time `json:"next_ts,omitempty"`
	NextSeq int64      `json:"next_seq,omitempty"`
	// HasMore is true when an older page exists.
	HasMore bool `json:"has_more"`
}

// MessageGetRequest asks for one message by uid.
//
// Distinct from a page: a client that already has a uid — from a send result,
// from a receipt, from a link — should not have to page a conversation to find
// the row again.
type MessageGetRequest struct {
	UID string `json:"uid"`
}

// HistoryRequest asks for the whole life of one message.
//
// Either identifier works. UID is what a client already holds from a message
// frame; chat_key with wa_id is what a human has when reading a log. Asking for
// an edit or a reaction returns the history of the message it acts on, because
// that is invariably what was meant.
type HistoryRequest struct {
	DeviceID string `json:"device_id"`
	UID      string `json:"uid,omitempty"`
	ChatKey  string `json:"chat_key,omitempty"`
	WAID     string `json:"wa_id,omitempty"`
}

// MessageVersion is one state of a message.
type MessageVersion struct {
	// Revision is 0 for the original and increments per edit.
	Revision int `json:"revision"`
	// Message carries this version's sealed body, in the same shape any other
	// message frame uses — so a client opens it with the code it already has.
	Message SealedMessage `json:"message"`
	// From and Until bracket the time this version was the current one. Both
	// are the sender's clock and are for display; the ordering is Revision.
	From  *time.Time `json:"from,omitempty"`
	Until *time.Time `json:"until,omitempty"`
}

// MessageDeletion reports that a message was revoked. Its content is still in
// the versions above, which is the entire point of the archive.
type MessageDeletion struct {
	Message SealedMessage `json:"message"`
	// ByAuthor separates an author deleting their own message from a group
	// admin removing someone else's.
	ByAuthor bool       `json:"by_author"`
	ByAdmin  bool       `json:"by_admin,omitempty"`
	At       *time.Time `json:"at,omitempty"`
}

// MessageReaction is one reaction and what became of it.
//
// There is no emoji field and no grouping by emoji. The emoji is sealed, so the
// server cannot see it — a client opens the sealed body like any other. What
// the server can say is structural: who reacted, in what order, and which rows
// were later replaced or revoked.
type MessageReaction struct {
	Message    SealedMessage `json:"message"`
	Superseded bool          `json:"superseded,omitempty"`
	Revoked    bool          `json:"revoked,omitempty"`
	RevokedAt  *time.Time    `json:"revoked_at,omitempty"`
}

// MessageReader is one party's acknowledgements, and which revision they saw.
type MessageReader struct {
	Key      string `json:"key"`
	LID      string `json:"lid,omitempty"`
	PN       string `json:"pn,omitempty"`
	IsFromMe bool   `json:"is_from_me,omitempty"`

	Delivered *time.Time `json:"delivered,omitempty"`
	Read      *time.Time `json:"read,omitempty"`
	Played    *time.Time `json:"played,omitempty"`

	// Revision fields identify the stanza named by the earliest read receipt.
	// They are meaningful only when Confirmed is true; no clock estimate is sent.
	SawRevision       int  `json:"saw_revision"`
	ConfirmedRevision int  `json:"confirmed_revision"`
	Confirmed         bool `json:"confirmed"`

	// ReadDevice names which of this person's devices produced the read the
	// three fields above describe, and Devices lists each device with what it
	// acknowledged.
	//
	// Present because those three belong to a DEVICE. Which text somebody had
	// on screen is decided by what that handset had received, and a person
	// reading on a phone whose laptop is three edits ahead is ordinary. Folding
	// a person's deliveries together before attributing would let the laptop
	// vouch for the phone and return Confirmed with nothing behind it.
	//
	// The top-level times are the EARLIEST across devices: "received at 14:02
	// and again at 19:40" is one person with two phones, and when they got it
	// is the first one.
	ReadDevice string         `json:"read_device,omitempty"`
	Devices    []ReaderDevice `json:"devices,omitempty"`

	// Revisions is the same acknowledgements told per version, which is what a
	// panel opened on a particular revision has to show.
	//
	// Without it the only honest thing that panel could draw was the read
	// list, because the flat Delivered above is the earliest across every
	// version — the answer to "did this reach them at all". Rendering that
	// under a revision heading says the correction was delivered on the
	// strength of the original having been.
	Revisions []ReaderRevision `json:"revisions,omitempty"`
}

// ReaderRevision contains receipts naming one version's stanza. Confirmed and
// PlayedConfirmed qualify Read and Played independently. Neither is inferred
// from delivery or timestamps; ambiguous receipts remain at message level.
type ReaderRevision struct {
	Revision        int        `json:"revision"`
	Delivered       *time.Time `json:"delivered,omitempty"`
	Read            *time.Time `json:"read,omitempty"`
	Played          *time.Time `json:"played,omitempty"`
	Confirmed       bool       `json:"confirmed,omitempty"`
	PlayedConfirmed bool       `json:"played_confirmed,omitempty"`
}

// ReaderDevice is one handset's acknowledgements.
type ReaderDevice struct {
	// Key is the identifier as stored, device suffix and all.
	Key string `json:"key"`
	// Agent and Device are WhatsApp's two-part device axis. Both, because a
	// JID prints as user.agent:device@server and ordering on the device number
	// alone shuffles a person's devices between reloads.
	Agent  uint8  `json:"agent,omitempty"`
	Device uint16 `json:"device,omitempty"`

	Delivered *time.Time `json:"delivered,omitempty"`
	Read      *time.Time `json:"read,omitempty"`
	Played    *time.Time `json:"played,omitempty"`

	SawRevision       int  `json:"saw_revision"`
	ConfirmedRevision int  `json:"confirmed_revision"`
	Confirmed         bool `json:"confirmed"`

	// Revisions is this one device's record, version by version. Kept per
	// device because the second timestamp is the only evidence a second device
	// exists at all.
	Revisions []ReaderRevision `json:"revisions,omitempty"`
}

// History is the response to message.history.
type History struct {
	DeviceID  string            `json:"device_id"`
	ChatKey   string            `json:"chat_key"`
	WAID      string            `json:"wa_id"`
	Versions  []MessageVersion  `json:"versions"`
	Deletion  *MessageDeletion  `json:"deletion,omitempty"`
	Reactions []MessageReaction `json:"reactions,omitempty"`
	Readers   []MessageReader   `json:"readers,omitempty"`
}

// ReceiptEvent is one acknowledgement, pushed live and replayed on resume.
//
// It shares the tenant sequence with messages, so a client keeps one cursor for
// both. One frame per acknowledgement event rather than per message id: that is
// the shape WhatsApp sends, and a read in a group would otherwise become one
// frame per message per participant.
type ReceiptEvent struct {
	Seq      int64    `json:"seq"`
	DeviceID string   `json:"device_id"`
	ChatKey  string   `json:"chat_key"`
	WAIDs    []string `json:"wa_ids"`

	// ReaderKey is the identifier exactly as WhatsApp addressed it, device
	// suffix and all — which is what makes "received at 14:02 and again at
	// 19:40" legible as a laptop and a handset.
	ReaderKey string `json:"reader_key"`
	// ReaderPerson is the same reader folded to a person, and it is what a
	// count must be keyed on. A group of eight where three people carry two
	// devices each has eleven acknowledgements and eight readers, and a tick
	// waiting for everyone would wait on a number that does not exist.
	ReaderPerson string `json:"reader_person"`
	ReaderLID    string `json:"reader_lid,omitempty"`
	ReaderPN     string `json:"reader_pn,omitempty"`
	IsFromMe     bool   `json:"is_from_me,omitempty"`

	Kind string    `json:"kind"`
	TS   time.Time `json:"ts"`
}

// DeviceRef names a device in a request.
type DeviceRef struct {
	DeviceID string `json:"device_id"`
}

// Error codes. Stable strings so clients can branch on them.
const (
	ErrCodeUnauthorized  = "unauthorized"
	ErrCodeBadRequest    = "bad_request"
	ErrCodeVersion       = "version_mismatch"
	ErrCodeNotFound      = "not_found"
	ErrCodeConflict      = "conflict"
	ErrCodeInternal      = "internal"
	ErrCodeRateLimited   = "rate_limited"
	ErrCodeNotAuthorized = "not_authorized"
)

// Error is the failure payload.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// encode builds a frame with a JSON payload.
func encode(frameType, reqID string, payload any) (Frame, error) {
	f := Frame{Type: frameType, ReqID: reqID}
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return Frame{}, err
		}
		f.Payload = b
	}
	return f, nil
}

// DeviceRename changes only the internal device name.
type DeviceRename struct {
	DeviceID string `json:"device_id"`
	Label    string `json:"label"`
}

// UnmarshalJSON defaults deletion to unlinking from WhatsApp. Older API clients
// can explicitly pass false, but omission has the ordinary removal semantics.
func (r *DeleteRequest) UnmarshalJSON(data []byte) error {
	type plain DeleteRequest
	value := plain{Unlink: true}
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*r = DeleteRequest(value)
	return nil
}

// Conversation creation and explicit group management.
const (
	TypeChatStart         = "chat.start"
	TypeChatStarted       = "chat.started"
	TypeGroupCreate       = "group.create"
	TypeGroupParticipants = "group.participants.update"
	TypeGroupLeave        = "group.leave"
	TypeGroupChanged      = "group.changed"
	TypePollCreate        = "message.poll.create"
)

type ChatStartRequest struct {
	DeviceID string `json:"device_id"`
	Phone    string `json:"phone"`
}
type ChatStarted struct {
	Chat string `json:"chat"`
}
type GroupCreateRequest struct {
	DeviceID     string   `json:"device_id"`
	Name         string   `json:"name"`
	Participants []string `json:"participants"`
}
type GroupParticipantsRequest struct {
	DeviceID     string   `json:"device_id"`
	Chat         string   `json:"chat"`
	Action       string   `json:"action"`
	Participants []string `json:"participants"`
}
type GroupLeaveRequest struct {
	DeviceID string `json:"device_id"`
	Chat     string `json:"chat"`
}
type ParticipantResult struct {
	JID   string `json:"jid"`
	Error int    `json:"error,omitempty"`
}
type GroupChanged struct {
	Chat         string              `json:"chat"`
	Action       string              `json:"action"`
	Participants []ParticipantResult `json:"participants,omitempty"`
	Refreshed    bool                `json:"refreshed"`
}
type PollCreateRequest struct {
	DeviceID        string   `json:"device_id"`
	Chat            string   `json:"chat"`
	ID              string   `json:"id,omitempty"`
	Question        string   `json:"question"`
	Options         []string `json:"options"`
	SelectableCount int      `json:"selectable_count"`
}
