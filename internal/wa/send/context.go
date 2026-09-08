// Package send builds and dispatches outbound messages.
//
// Everything that leaves this server goes through one ContextInfo builder.
// Reply, forwarding, disappearing timers and view-once are all expressed in
// that one struct, and building it in each send path separately is how a
// feature ends up working for text and silently missing for images.
package send

import (
	"errors"
	"fmt"
	"strings"

	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
)

// Options are the parts of an outbound message that are not its content.
type Options struct {
	// ReplyTo quotes an earlier message.
	ReplyTo string
	// ReplySender is who sent the quoted message. Required in groups; see
	// buildContext.
	ReplySender types.JID
	// ReplyContent is the quoted message itself, and it is optional.
	//
	// StanzaID and ReplyContent do different jobs and are not alternatives.
	// StanzaID is the link: it is what lets the recipient tap the quote and
	// jump to the original. ReplyContent is the preview text, used when the
	// recipient's own copy is missing — they deleted it, or joined on a new
	// device, or it predates their history.
	//
	// So a recipient who still has the message renders from their own copy and
	// ignores this, which makes it look redundant. It is not: without it, a
	// recipient who does not have the original sees a quote with nothing in it.
	//
	// The caller supplies it because the server cannot: the archive is sealed,
	// and only a client holding the private key can read what was said.
	ReplyContent *waE2E.Message

	// Forwarded marks the message as forwarded.
	Forwarded bool
	// ForwardingScore drives which label the recipient sees. Five or more is
	// what WhatsApp renders as "forwarded many times".
	ForwardingScore uint32

	// Expiration is the disappearing-message timer in seconds.
	Expiration uint32
	// ViewOnce wraps the message so it can be opened once.
	//
	// Media only. See Text.
	ViewOnce bool
	// Ephemeral wraps the message in the disappearing-message envelope.
	Ephemeral bool

	// Mentions are the JIDs tagged in the text.
	Mentions []types.JID

	// Preview is the link card shown under the message.
	//
	// Supplied by the caller, never built here. Generating one means fetching
	// the URL, and a server that fetches the links its users send is a server
	// that learns them — which contradicts the sealed archive — and one that
	// can be pointed at an address of a stranger's choosing. The client has
	// already loaded the page it is linking to; it can describe it.
	Preview *Preview
}

// Preview is a link card for an outbound message.
type Preview struct {
	// URL must appear in the message body. WhatsApp matches the card to the
	// text, and a card describing a link that is not there does not render.
	URL         string
	Title       string
	Description string
	// Thumbnail is a small JPEG shown on the card.
	Thumbnail []byte
}

// buildContext assembles the ContextInfo for one outbound message.
//
// Returns nil when there is nothing to say, so a plain message is not padded
// with an empty struct.
func buildContext(chat types.JID, opts Options) *waE2E.ContextInfo {
	ci := &waE2E.ContextInfo{}
	used := false

	if opts.ReplyTo != "" {
		ci.StanzaID = &opts.ReplyTo
		ci.QuotedMessage = opts.ReplyContent
		used = true

		// Participant identifies who wrote the quoted message. In a group it
		// is required: without it the recipient's client renders the quote
		// stripped of its author, which is a visible defect the v1 server hit
		// and had to patch. In a direct chat the remote JID already says who
		// the other party is, and sending it anyway is wrong.
		if !opts.ReplySender.IsEmpty() {
			participant := opts.ReplySender.ToNonAD().String()
			ci.Participant = &participant
		} else if chat.Server == types.GroupServer {
			// A group reply with no known author still quotes, but the label
			// will be missing. Better than refusing to send.
			ci.Participant = nil
		}
	}

	if opts.Forwarded {
		ci.IsForwarded = new(true)
		score := opts.ForwardingScore
		if score == 0 {
			// A forwarded message with a score of zero shows no badge at all
			// on the recipient's phone, which makes the flag pointless. One is
			// the minimum that renders. The v1 server learned this the same
			// way.
			score = 1
		}
		ci.ForwardingScore = &score
		used = true
	}

	if opts.Expiration > 0 {
		ci.Expiration = &opts.Expiration
		used = true
	}

	if len(opts.Mentions) > 0 {
		ci.MentionedJID = make([]string, 0, len(opts.Mentions))
		for _, jid := range opts.Mentions {
			ci.MentionedJID = append(ci.MentionedJID, jid.ToNonAD().String())
		}
		used = true
	}

	if !used {
		return nil
	}
	return ci
}

// wrap applies the envelope wrappers a message needs.
//
// Order matters and is not arbitrary: view-once sits inside the ephemeral
// wrapper, matching how whatsmeow's UnwrapRaw peels them on the way in. Getting
// it backwards produces a message that official clients silently ignore.
func wrap(msg *waE2E.Message, opts Options) *waE2E.Message {
	if opts.ViewOnce {
		msg = &waE2E.Message{ViewOnceMessageV2: &waE2E.FutureProofMessage{Message: msg}}
	}
	// An expiration implies the envelope, always.
	//
	// The two are not independent settings even though they look like it. A
	// message that carries a timer but is not wrapped in the disappearing
	// envelope is one every client reads the timer from and then keeps
	// forever — which is precisely what "-expires 3600 and it is still there
	// an hour later" turned out to be. Making the rule live here rather than
	// in a caller means no caller can get it wrong.
	if opts.disappearing() {
		msg = &waE2E.Message{EphemeralMessage: &waE2E.FutureProofMessage{Message: msg}}
	}
	return msg
}

// disappearing reports whether the message travels in the disappearing
// envelope.
//
// One function, used both by wrap and by the archived envelope, for the same
// reason forwardingScore is: the row has to record what actually went on the
// wire. Deriving it twice is how an archive ends up saying a message was
// ordinary when the recipient's client made it vanish.
func (o Options) disappearing() bool { return o.Ephemeral || o.Expiration > 0 }

// ErrViewOnceText means view-once was asked for on a text message.
//
// View-once is a media feature. WhatsApp clients render it for images, videos
// and voice notes, and for anything else they show the "this message will not
// disappear, sent from an older version of WhatsApp" fallback — which is what a
// client does with an envelope it cannot interpret.
//
// The protobuf does carry a ViewOnce field on ExtendedTextMessage, but the
// generated types come from Meta's own definitions and contain plenty that no
// client acts on. Sending a message that renders as a version warning is worse
// than refusing, so this refuses.
var ErrViewOnceText = errors.New("send: view once is a media feature and does not work on text")

// Text builds an outbound text message.
//
// Always ExtendedTextMessage, never Conversation. Conversation is a bare string
// field with nowhere to attach ContextInfo, so a plain-string message cannot
// express a reply, a mention, an expiry or the forwarded flag. Sending one and
// then discovering the flag was dropped is a confusing bug; using the richer
// form unconditionally means there is nothing to discover.
func Text(chat types.JID, body string, opts Options) (*waE2E.Message, error) {
	if body == "" {
		return nil, fmt.Errorf("send: refusing to send an empty message")
	}
	if opts.ViewOnce {
		return nil, ErrViewOnceText
	}
	ext := &waE2E.ExtendedTextMessage{
		Text:        &body,
		ContextInfo: buildContext(chat, opts),
	}
	if p := opts.Preview; p != nil {
		if !strings.Contains(body, p.URL) {
			// WhatsApp matches the card to the text by this exact substring.
			// A card for a link that is not in the body silently does not
			// render, which is worse than being told.
			return nil, fmt.Errorf(
				"send: the preview url %q does not appear in the message body, "+
					"so WhatsApp will not attach the card", p.URL)
		}
		ext.MatchedText = &p.URL
		if p.Title != "" {
			ext.Title = &p.Title
		}
		if p.Description != "" {
			ext.Description = &p.Description
		}
		ext.JPEGThumbnail = p.Thumbnail
	}
	return wrap(&waE2E.Message{ExtendedTextMessage: ext}, opts), nil
}
