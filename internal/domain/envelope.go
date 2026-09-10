// Package domain holds the canonical shape of a WhatsApp event.
//
// Everything that enters the system becomes an Envelope before anything else
// looks at it. Live events and history sync both normalise into this one form,
// which is the correction to the central structural failure of the v1 server:
// there, the live path and the history path each did their own type dispatch,
// each built their own event body, and each detected reaction chains their own
// way. Four pairs of near-identical logic, and all four had already drifted
// apart by the time the project was abandoned.
//
// This package depends on whatsmeow's types package for JID, and on nothing
// else. types.JID is a value object with no ties to the client, so the coupling
// is to a data shape rather than to a library's behaviour. Storing JIDs as bare
// strings to avoid that would trade a stable dependency for constant reparsing
// and a whole class of "which half of the JID is this" bugs.
package domain

import (
	"encoding/json"
	"time"

	"go.mau.fi/whatsmeow/types"
)

// Kind distinguishes a message from the control rows that act on one.
//
// Edits, deletions and reactions are stored as rows in their own right, not as
// columns on the message they affect. That is what makes the product's central
// feature possible: showing the full history of an edited message, and the
// content of a deleted one. A schema that overwrote the text on edit, or set a
// deleted flag, would have destroyed exactly the information worth keeping.
type Kind string

const (
	KindMessage  Kind = "message"
	KindEdit     Kind = "edit"
	KindDelete   Kind = "delete"
	KindReaction Kind = "reaction"
)

// Valid reports whether k is a known kind.
func (k Kind) Valid() bool {
	switch k {
	case KindMessage, KindEdit, KindDelete, KindReaction:
		return true
	}
	return false
}

// IsControl reports whether k acts on another row rather than standing alone.
func (k Kind) IsControl() bool { return k != KindMessage }

// TargetRel says what a control row's target points at.
//
// Resolved once, during ingest, and stored. The v1 server instead recomputed it
// at render time — in two separate places, which then disagreed. The question
// it answers is real: a revoke can target a reaction rather than a message, and
// a reader that cannot tell the difference renders a deleted message where a
// withdrawn thumbs-up belongs.
type TargetRel string

const (
	TargetNone     TargetRel = ""
	TargetMessage  TargetRel = "message"
	TargetReaction TargetRel = "reaction"
)

// Type is the content type of a message.
type Type string

const (
	TypeText         Type = "text"
	TypeImage        Type = "image"
	TypeVideo        Type = "video"
	TypePTV          Type = "ptv" // round video note
	TypeAudio        Type = "audio"
	TypePTT          Type = "ptt" // voice note
	TypeDocument     Type = "document"
	TypeSticker      Type = "sticker"
	TypeLocation     Type = "location"
	TypeLiveLocation Type = "live_location"
	TypeContact      Type = "contact"
	TypeContactArray Type = "contact_array"
	TypePoll         Type = "poll"
	TypePollVote     Type = "poll_vote"
	TypeEvent        Type = "event"
	TypeGroupInvite  Type = "group_invite"
	TypeAlbum        Type = "album"
	TypeTemplate     Type = "template"
	// The business message formats. All the same shape once opened — some
	// text and the labels of what was offered — and all of them used to land
	// as unsupported, a few every day, for as long as the account talked to
	// any business at all.
	TypeInteractive Type = "interactive"  // native flow, carousel
	TypeButtons     Type = "buttons"      // the older buttons format
	TypeList        Type = "list"         // a list of options
	TypeButtonReply Type = "button_reply" // somebody pressed one of those
	// Placeholder is a message this device will never have. The phone masked
	// its content from linked devices — WhatsApp's PlaceholderMessage with
	// MASK_LINKED_DEVICES — so the message exists on the handset and here
	// there is a slot where it should be. Named as its own type rather than
	// filed as unsupported, because there is nothing a later build could do
	// about it and an archive that promises completeness owes the reader the
	// hole, not a mystery.
	TypePlaceholder Type = "placeholder"
	TypeReaction    Type = "reaction"
	TypeProtocol    Type = "protocol"

	// TypeUnsupported is a message whose kind this build does not understand.
	//
	// Kept rather than dropped. WhatsApp adds message types continuously, and
	// the v1 server discarded anything it did not recognise, leaving silent
	// holes in conversations that nobody could explain later. An unsupported
	// row preserves the routing metadata and the raw payload, so the same
	// message becomes readable after an upgrade.
	TypeUnsupported Type = "unsupported"

	// TypeUndecryptable is a message WhatsApp itself could not decrypt.
	// Distinct from unsupported: the remedy is a resend request, not a code
	// change, and the UI has to say something different.
	TypeUndecryptable Type = "undecryptable"
)

// KeyClass is the family of keys an attachment's bytes are encrypted under.
//
// Several types deliberately share one: a sticker rides on the image keys, a
// round video note on video, a voice note on audio. That is WhatsApp's scheme
// rather than an approximation made here — the class picks the HKDF label the
// media key is derived from.
//
// It has a name of its own because the class is chosen once, when the bytes are
// uploaded, and the type is declared again when the message that points at them
// is sent. Nothing links the two calls, so nothing but a comparison stops bytes
// sealed under the image label from being described as a document. That send
// succeeds, the archive stores it, and the attachment then opens for nobody —
// not the recipient and not us.
//
// Empty for anything that is not an attachment.
func KeyClass(t Type) string {
	switch t {
	case TypeImage, TypeSticker:
		return "image"
	case TypeVideo, TypePTV:
		return "video"
	case TypeAudio, TypePTT:
		return "audio"
	case TypeDocument:
		return "document"
	default:
		return ""
	}
}

// HasMedia reports whether this type carries a media attachment.
func (t Type) HasMedia() bool {
	switch t {
	case TypeImage, TypeVideo, TypePTV, TypeAudio, TypePTT, TypeDocument, TypeSticker:
		return true
	}
	return false
}

// Source records where an envelope came from.
//
// Live and history are not interchangeable. History arrives out of order and in
// bulk, may contain messages already known, and carries less context — so
// ingest treats it differently even though the envelope shape is identical.
type Source string

const (
	SourceLive    Source = "live"
	SourceHistory Source = "history"
	SourceOutbox  Source = "outbox" // sent by us, recorded on the way out
)

// Address is one party's identity.
//
// Both halves are carried and either may be empty. LID is primary: WhatsApp
// routes direct messages over it, and it exists precisely to withhold the phone
// number, so for many contacts a phone number is never revealed. The v1 server
// rewrote every LID to a phone number on ingest and backfilled old rows on each
// reconnect; that is no longer possible, and pretending otherwise loses the
// ability to address the contact at all.
type Address struct {
	LID types.JID
	PN  types.JID
}

// AddressOf builds an Address from whichever JID is available, putting it in
// the right half.
func AddressOf(jid types.JID) Address {
	if jid.IsEmpty() {
		return Address{}
	}
	if jid.Server == types.HiddenUserServer {
		return Address{LID: jid}
	}
	return Address{PN: jid}
}

// Primary returns the identifier to key on.
func (a Address) Primary() types.JID {
	if !a.LID.IsEmpty() {
		return a.LID
	}
	return a.PN
}

// Empty reports whether neither half is set.
func (a Address) Empty() bool { return a.LID.IsEmpty() && a.PN.IsEmpty() }

// Merge fills in halves that are missing from a using values from b.
func (a Address) Merge(b Address) Address {
	if a.LID.IsEmpty() {
		a.LID = b.LID
	}
	if a.PN.IsEmpty() {
		a.PN = b.PN
	}
	return a
}

// String renders the address for logs.
func (a Address) String() string {
	switch {
	case !a.LID.IsEmpty() && !a.PN.IsEmpty():
		return a.LID.String() + " (" + a.PN.User + ")"
	case !a.LID.IsEmpty():
		return a.LID.String()
	case !a.PN.IsEmpty():
		return a.PN.String()
	default:
		return "<empty>"
	}
}

// Envelope is one normalised event.
//
// The split between routing and content is deliberate and load-bearing. The
// fields above Content stay readable so the server can order, paginate and fan
// out; Content is sealed to the tenant's public key on the way in and the
// server can never reopen it. Which side of that line a field falls on is a
// privacy decision, so each one is called out in the comments below.
type Envelope struct {
	// --- Routing. Stays readable. ---

	TenantID string
	DeviceID string

	// MessageID is WhatsApp's identifier, unique per chat.
	MessageID string

	Chat   Address
	Sender Address

	// Timestamp is when WhatsApp says the message was sent, not when it was
	// received. Ordering uses the sequence number assigned at insert; this is
	// for display.
	Timestamp time.Time

	IsFromMe bool
	IsGroup  bool

	Kind Kind
	Type Type

	// TargetID is the message or reaction this row acts on. Empty for a plain
	// message.
	TargetID  string
	TargetRel TargetRel

	// ReplyTo is the quoted message, if any. Distinct from TargetID: a reply
	// is a new message that references another, while a control row modifies
	// one.
	ReplyTo string

	// IsForwarded and ForwardingScore drive the "forwarded" and "forwarded
	// many times" badges. A score of five or more is what WhatsApp treats as
	// the stronger label.
	IsForwarded     bool
	ForwardingScore uint32

	// Expiration is the disappearing-message timer in seconds, zero when off.
	Expiration uint32
	ViewOnce   bool
	Ephemeral  bool

	Source Source

	// --- Content. Sealed. ---

	Content Content
}

// Content is everything the server must not be able to read back.
type Content struct {
	// Body is the message text, or a media caption, or the emoji of a
	// reaction.
	Body string

	// Media describes an attachment. The bytes themselves live in object
	// storage, still in WhatsApp's own encrypted form; only MediaKey needs
	// sealing, and without it the stored blob is inert.
	Media *Media

	// Location, Contacts, Poll, Event and LinkPreview carry the structured
	// payloads. They are sealed together as one Payload rather than each
	// getting a column; see Payload for why.
	Location    *Location
	Contacts    []Contact
	Poll        *Poll
	Event       *Event
	GroupInvite *GroupInvite
	Album       *Album
	Buttons     []string
	PollVote    *PollVote
	LinkPreview *LinkPreview

	// Mentions are the JIDs tagged in the text. Content, not routing.
	Mentions []string

	// Unsupported names the protobuf field this build did not understand, for
	// a message that reached TypeUnsupported.
	//
	// Unsealed, and it belongs unsealed: every readable Type value in this
	// schema is already a waE2E field name translated -- "image" is
	// imageMessage, "ptt" is audioMessage with the PTT flag. Recording
	// "albumMessage" when the switch matched nothing records the same fact at
	// the same granularity, from a vocabulary bounded by the compiled protobuf
	// rather than by the sender.
	//
	// Without it, "unsupported" is a dead end: the payload is sealed, so
	// nobody can find out what to implement next without guessing.
	Unsupported string

	// Raw is the original protobuf.
	//
	// The v1 server stored this in the clear, in a column beside everything
	// else, which made it the single worst leak in that schema: it contained
	// the full message including fields the code never even surfaced. Kept
	// here because it is the only way to recover a message whose type this
	// build did not understand, but sealed like everything else.
	Raw []byte
}

// Empty reports whether there is nothing worth sealing.
func (c Content) Empty() bool {
	return c.Body == "" && c.Media == nil && len(c.Raw) == 0 && c.Payload().Empty()
}

// Payload gathers the structured content into the form that gets sealed.
func (c Content) Payload() Payload {
	return Payload{
		Mentions:    c.Mentions,
		Location:    c.Location,
		Contacts:    c.Contacts,
		Poll:        c.Poll,
		Event:       c.Event,
		GroupInvite: c.GroupInvite,
		Album:       c.Album,
		Buttons:     c.Buttons,
		PollVote:    c.PollVote,
		LinkPreview: c.LinkPreview,
	}
}

// Media describes an attachment.
type Media struct {
	// MimeType, FileLength and the hashes stay readable: the client needs to
	// know what an attachment is before it can decide to fetch and open it,
	// and the hashes are of ciphertext, so they reveal nothing about content.
	MimeType      string
	FileLength    uint64
	FileSHA256    []byte
	FileEncSHA256 []byte

	// DirectPath and URL locate the blob on WhatsApp's CDN. They are
	// capability URLs and useless without the key.
	DirectPath string
	URL        string

	// MediaKey is the one field that matters. Thirty-two bytes, sealed. The
	// stored ciphertext is WhatsApp's own AES-256-CBC with an encrypt-then-MAC
	// HMAC; without this key it is noise. The v1 server stored the blob
	// encrypted and then wrote this key in the clear in the column next to it.
	MediaKey []byte

	// Sidecar carries per-chunk MACs for streaming video.
	Sidecar []byte

	Width  uint32
	Height uint32

	// Seconds is duration for audio and video.
	Seconds uint32

	// Waveform is the 64-byte amplitude sketch drawn behind a voice note.
	Waveform []byte

	// Thumbnail is a small preview, sealed: it is a legible picture of the
	// content.
	Thumbnail []byte

	FileName string
	IsGIF    bool

	// Downloaded reports whether the blob has been fetched into our storage.
	Downloaded bool
	ObjectKey  string
}

// Location is a shared position.
type Location struct {
	Latitude  float64 `json:"lat"`
	Longitude float64 `json:"lon"`
	Name      string  `json:"name,omitempty"`
	Address   string  `json:"address,omitempty"`
	// AccuracyMeters may accompany either a fixed or live location.
	AccuracyMeters uint32  `json:"accuracy_m,omitempty"`
	Speed          float32 `json:"speed,omitempty"`
	// SequenceNumber orders updates within one live-location session.
	SequenceNumber int64 `json:"seq,omitempty"`
}

// Contact is a shared contact card.
type Contact struct {
	DisplayName string `json:"display_name,omitempty"`
	VCard       string `json:"vcard,omitempty"`
}

// Poll is a poll message.
type Poll struct {
	Question string   `json:"question,omitempty"`
	Options  []string `json:"options,omitempty"`
	// SelectableCount is how many options a voter may pick.
	//
	// One means a single-answer poll, which is what the field is for and is
	// the one reading whatsmeow's own documentation states.
	//
	// Zero is read here as "the poll stated no limit", which is what "allow
	// multiple answers" produces. That reading is an inference, not something
	// upstream establishes: the protobuf carries no default and no comment,
	// whatsmeow never reads the field on the way in, and the only signal is
	// that its BuildPollCreation normalises an out-of-range count to zero. It
	// is believed because the alternative is worse in a way that was observed
	// — reading zero as one refuses the second tick on every multiple-choice
	// poll while a phone accepts it — and because zero cannot be a literal
	// maximum without making the poll unanswerable.
	//
	// Being wrong the other way is possible and is worth naming: a genuinely
	// single-answer poll arriving with zero would let somebody tick several
	// here. Nothing in this repository rules that out.
	//
	// The getter above collapses an absent field to zero before this struct is
	// built, so this value cannot distinguish the two — and neither can
	// omitempty, downstream. The raw protobuf keeps the difference, because
	// the field has explicit presence, but nothing can currently reach it: a
	// poll row is never unsupported, and reprojection only reopens rows that
	// are. If the reading above ever needs settling from the archive rather
	// than from argument, that is the thread to pull.
	SelectableCount uint32 `json:"selectable_count,omitempty"`
}

// GroupInvite is an invitation to join a group, sent into a conversation.
//
// The whole thing is sealed with the rest of the payload, and the invite code
// is why that is not merely tidy. The code is a capability: anybody holding it
// can join the group, without the sender being asked again. Leaving it in a
// readable column would put "join any group my users were invited to" in a
// database dump, beside the group's name and the face of whoever runs it.
//
// Which also decides where accepting happens. This server cannot read the code,
// so it cannot act on an invitation by itself — the client opens the payload
// and passes the code back for one exchange, the same shape media retry uses
// for a media key.
type GroupInvite struct {
	// GroupJID is the group being offered.
	GroupJID string `json:"group_jid,omitempty"`
	// Code is the capability. Sealed.
	Code string `json:"code,omitempty"`
	// Expiration is when the code stops working, in Unix seconds. WhatsApp
	// mints these with a lifetime measured in days.
	Expiration int64 `json:"expiration,omitempty"`
	// Name is the group's name as it was when the invitation was sent, which
	// is the only name a reader has for a group they are not in.
	Name    string `json:"name,omitempty"`
	Caption string `json:"caption,omitempty"`
	// Thumbnail is the group picture, as a small JPEG carried in the message.
	Thumbnail []byte `json:"thumbnail,omitempty"`
}

// PollVote is somebody's answer to a poll.
//
// The selections are SHA-256 hashes of the option text, which is what WhatsApp
// transmits and what this archive can therefore hold. It cannot resolve them:
// the poll's options are sealed content, and the server has never been able to
// read them.
//
// So the tally is computed by the client, which opens the poll, hashes each
// option and matches. That is not a workaround — it is the only arrangement in
// which a sealed archive can show poll results at all, and it keeps the
// property that a database dump reveals neither the question nor the answers.
// The presence of this struct means the vote was opened. An empty Selected is
// a withdrawal — WhatsApp replaces a voter's previous answer rather than adding
// to it, so choosing nothing is how a person takes their vote back — and it is
// a different fact from a vote nobody could decrypt, which has no PollVote at
// all. A reader that could not tell them apart would report a poll as having
// gone half-unread when in truth somebody changed their mind.
type PollVote struct {
	// Selected are the hashes of the chosen options' text.
	Selected [][]byte `json:"selected,omitempty"`
}

// Album is the header WhatsApp sends before a run of photographs.
//
// A header and nothing else: it declares how many pictures and videos follow
// and carries none of them. The images arrive as ordinary messages of their
// own, and the protobuf has no field linking a child back to this — so the
// archive records what the message actually says and no more. Guessing which
// of the next few attachments belong to it would be inventing a relation
// WhatsApp did not state.
type Album struct {
	Images int `json:"images,omitempty"`
	Videos int `json:"videos,omitempty"`
}

// Event is a scheduled event message.
type Event struct {
	Name        string    `json:"name,omitempty"`
	Description string    `json:"description,omitempty"`
	Location    *Location `json:"location,omitempty"`
	JoinLink    string    `json:"join_link,omitempty"`
	StartTime   time.Time `json:"start_time,omitzero"`
	EndTime     time.Time `json:"end_time,omitzero"`
	// IsCanceled is set when the organiser called the event off. The message
	// is still an event, so this is a field rather than a separate type.
	IsCanceled         bool `json:"is_canceled,omitempty"`
	ExtraGuestsAllowed bool `json:"extra_guests_allowed,omitempty"`
}

// LinkPreview is the card WhatsApp renders under a message containing a URL.
//
// Every field of it is produced by the *sender's* client, which is why it can
// be carried here at all. This server never fetches a URL to build one: doing
// so would tell the server which links pass through it, contradicting the
// sealed archive, and would turn it into a machine that issues requests to
// addresses chosen by whoever is messaging you.
type LinkPreview struct {
	// URL is the link as it appeared in the message body.
	//
	// WhatsApp carries only this one, not a resolved canonical form: the card
	// is built by the sender's client from whatever it fetched, and the
	// address it settled on is not transmitted. Nothing here is going to
	// resolve it either, for the reason above.
	URL         string `json:"url,omitempty"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	// Thumbnail is a small JPEG, inline. Sealed with the rest of the payload:
	// a preview image of a page somebody visited is content.
	Thumbnail []byte `json:"thumbnail,omitempty"`
}

// Payload is the structured content of a message, in the form it is sealed.
//
// One sealed value rather than a column per type. The alternative was
// latitude, longitude, poll_options, vcard, event_start and the rest spreading
// across the message table — each one a decision about what stays readable,
// made under pressure, for a field nobody had thought about yet. Here the
// answer is uniform: structured content is content.
//
// It is also what keeps the browser client from needing WhatsApp's protobuf
// definitions. Everything below is recoverable from the sealed raw protobuf,
// but only by something that can parse waE2E — which is a heavy thing to ship
// to a web page just to draw a map pin.
type Payload struct {
	// Mentions are the JIDs tagged in the text.
	//
	// Sealed rather than left readable. A mention list is the social graph
	// inside a message: who tags whom, how often. Keeping it readable would
	// have let the server count mentions without opening anything, which is
	// convenient for a notification badge and is exactly the kind of
	// convenience this archive exists to refuse.
	Mentions []string `json:"mentions,omitempty"`

	Location    *Location    `json:"location,omitempty"`
	Contacts    []Contact    `json:"contacts,omitempty"`
	Poll        *Poll        `json:"poll,omitempty"`
	Event       *Event       `json:"event,omitempty"`
	GroupInvite *GroupInvite `json:"group_invite,omitempty"`
	Album       *Album       `json:"album,omitempty"`
	// Buttons are the labels a business template offered. Content: they are
	// text somebody wrote and a reader needs them to understand the message.
	Buttons     []string     `json:"buttons,omitempty"`
	PollVote    *PollVote    `json:"poll_vote,omitempty"`
	LinkPreview *LinkPreview `json:"link_preview,omitempty"`
}

// Empty reports whether there is nothing structured to seal.
func (p Payload) Empty() bool {
	return len(p.Mentions) == 0 && p.Location == nil && len(p.Contacts) == 0 &&
		p.Poll == nil && p.Event == nil && p.LinkPreview == nil && p.GroupInvite == nil &&
		p.Album == nil && len(p.Buttons) == 0 && p.PollVote == nil
}

// Marshal renders the payload for sealing.
func (p Payload) Marshal() ([]byte, error) { return json.Marshal(p) }

// ParsePayload reads a payload back after it has been opened.
func ParsePayload(b []byte) (Payload, error) {
	var p Payload
	if len(b) == 0 {
		return p, nil
	}
	err := json.Unmarshal(b, &p)
	return p, err
}
