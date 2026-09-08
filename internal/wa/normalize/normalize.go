// Package normalize turns whatsmeow events into domain envelopes.
//
// There is exactly one classifier. Live events and history sync both build the
// same input shape and hand it to classify, so a new message type is taught to
// the system once. The v1 server dispatched separately on each path, with a
// comment admitting the duplication was deliberate; the two had already
// diverged by the time it was abandoned, and history-synced messages rendered
// differently from the same message seen live.
//
// # The asymmetry this package exists to absorb
//
// whatsmeow's UnwrapRaw peels the outer wrappers — ephemeral, view-once,
// edited, document-with-caption — and sets a flag for each. After it runs, an
// edit is a Message whose ProtocolMessage is still intact, which is exactly
// what we want: the target id and the new content are both reachable.
//
// ParseWebMessage, used for history sync, calls UnwrapRaw and then goes one
// step further: for an edit it overwrites Info.ID with the *target's* id and
// replaces Message with the edited content. That is convenient for a client
// that only wants the final text, and destructive for an archive that wants the
// edit history — after it runs, there is no way to tell an edit from an
// ordinary message.
//
// So history does not go through ParseWebMessage. FromHistory below rebuilds
// the message info itself and stops at UnwrapRaw, producing the same shape the
// live path produces.
package normalize

import (
	"errors"
	"fmt"
	"reflect"
	"time"

	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/proto/waWeb"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"

	"whatserver2/internal/domain"
)

// ErrSkip means the event carries nothing to store.
//
// Not an error condition: protocol housekeeping like key distribution and
// history-sync notifications flows through the same channel as real messages.
// Callers check for it and move on.
var ErrSkip = errors.New("normalize: nothing to store")

// Options carries what the classifier cannot derive from the event alone.
type Options struct {
	TenantID string
	DeviceID string
	// Own is this device's identity, used to decide IsFromMe for history
	// messages, where the sender is often implied rather than stated.
	Own domain.Address

	// PollVote is the selection a caller managed to decrypt.
	//
	// It arrives here rather than being read out of the protobuf because it
	// is not in the protobuf: a vote travels under a key derived from the
	// poll, and what the message carries is ciphertext. Only the device has
	// the message secret, so only the device can open it — this package
	// classifies, it does not decrypt.
	//
	// A pointer, not a slice, because "opened, and they chose nothing" and
	// "nobody could open this" are different facts that a slice would render
	// identically. The first is a withdrawal — WhatsApp's way of taking a vote
	// back — and reporting it as unreadable would understate how many people
	// answered while overstating how much this archive failed to read.
	PollVote *OpenedVote
}

// OpenedVote is a poll answer somebody decrypted, as SHA-256 hashes of the
// option text. Empty is a withdrawal.
type OpenedVote struct {
	Selected [][]byte
}

// OpenedPollVote is a poll answer whose selection somebody has decrypted.
//
// The pairing exists because the plaintext has no home in the protobuf. A
// PollUpdateMessage's Vote field is a PollEncValue and stays one; there is no
// field to write the answer back into. So the two travel side by side from the
// device that could open it to the pipeline that stores it, and the wrapper is
// the smallest thing that says so honestly.
//
// A vote that could not be opened is published as a plain *events.Message. It
// still stores, still names the poll it answers, and simply does not say what
// was chosen — which is the truth about it.
type OpenedPollVote struct {
	*events.Message

	// Selected are hashes of the chosen options' text. Empty is a withdrawal.
	Selected [][]byte
}

// flags mirror the wrapper flags UnwrapRaw sets.
type flags struct {
	IsEdit                bool
	IsEphemeral           bool
	IsViewOnce            bool
	IsDocumentWithCaption bool
	IsLottieSticker       bool
}

// input is the one shape both entry points produce.
type input struct {
	Info    types.MessageInfo
	Message *waE2E.Message
	Raw     *waE2E.Message
	Flags   flags
	Source  domain.Source

	// PollVote is Options.PollVote, carried in so that content() can reach it.
	PollVote *OpenedVote
}

// FromLive normalises a live message event.
func FromLive(evt *events.Message, opts Options) (domain.Envelope, error) {
	if evt == nil || evt.Message == nil {
		return domain.Envelope{}, ErrSkip
	}
	return classify(input{
		Info:    evt.Info,
		Message: evt.Message,
		Raw:     evt.RawMessage,
		Source:  domain.SourceLive,
		Flags: flags{
			IsEdit:                evt.IsEdit,
			IsEphemeral:           evt.IsEphemeral,
			IsViewOnce:            evt.IsViewOnce,
			IsDocumentWithCaption: evt.IsDocumentWithCaption,
			IsLottieSticker:       evt.IsLottieSticker,
		},
	}, opts)
}

// FromRaw normalises a message from the protobuf the archive stored.
//
// The third entry point, and it exists so that a row filed as unsupported can
// be looked at again by a later build without a second classifier being written
// to do it. raw_sealed holds the message exactly as it arrived, wrappers and
// all, which is what makes reclassification possible at all — and reusing this
// path is what makes it trustworthy. A reprojection that disagreed with the
// ingest path about what a message is would be worse than no reprojection: the
// archive would hold two kinds of row for one kind of message, and only the
// date would say which classifier had produced it.
//
// The info is rebuilt by the caller from the stored routing columns, which are
// readable precisely so this is possible.
func FromRaw(info types.MessageInfo, raw *waE2E.Message, opts Options) (domain.Envelope, error) {
	if raw == nil {
		return domain.Envelope{}, ErrSkip
	}
	// Same unwrapping as the history path, and for the same reason: the list
	// of wrappers grows, and a private copy would silently fall behind.
	evt := (&events.Message{RawMessage: raw, Info: info}).UnwrapRaw()
	return classify(input{
		Info:    evt.Info,
		Message: evt.Message,
		Raw:     evt.RawMessage,
		Source:  domain.SourceHistory,
		Flags: flags{
			IsEdit:                evt.IsEdit,
			IsEphemeral:           evt.IsEphemeral,
			IsViewOnce:            evt.IsViewOnce,
			IsDocumentWithCaption: evt.IsDocumentWithCaption,
			IsLottieSticker:       evt.IsLottieSticker,
		},
	}, opts)
}

// FromHistory normalises one message out of a history sync.
//
// It deliberately does not call Client.ParseWebMessage; see the package
// comment. The message info is rebuilt here so that the result stops at
// UnwrapRaw and keeps edits recognisable as edits.
func FromHistory(chat types.JID, webMsg *waWeb.WebMessageInfo, opts Options) (domain.Envelope, error) {
	if webMsg.GetMessage() == nil {
		return domain.Envelope{}, ErrSkip
	}
	info, err := historyInfo(chat, webMsg, opts)
	if err != nil {
		return domain.Envelope{}, err
	}

	// Reuse whatsmeow's own unwrapping rather than reimplementing the wrapper
	// chain: the list of wrappers grows, and a private copy would silently
	// fall behind.
	evt := (&events.Message{RawMessage: webMsg.GetMessage(), Info: info}).UnwrapRaw()

	return classify(input{
		Info:    evt.Info,
		Message: evt.Message,
		Raw:     evt.RawMessage,
		Source:  domain.SourceHistory,
		Flags: flags{
			IsEdit:                evt.IsEdit,
			IsEphemeral:           evt.IsEphemeral,
			IsViewOnce:            evt.IsViewOnce,
			IsDocumentWithCaption: evt.IsDocumentWithCaption,
			IsLottieSticker:       evt.IsLottieSticker,
		},
	}, opts)
}

// historyInfo rebuilds types.MessageInfo from a stored web message. It mirrors
// the first half of whatsmeow's ParseWebMessage, and stops short of the edit
// rewrite that the second half performs.
func historyInfo(chat types.JID, webMsg *waWeb.WebMessageInfo, opts Options) (types.MessageInfo, error) {
	var err error
	if chat.IsEmpty() {
		chat, err = types.ParseJID(webMsg.GetKey().GetRemoteJID())
		if err != nil {
			return types.MessageInfo{}, fmt.Errorf("normalize: chat jid: %w", err)
		}
	}
	info := types.MessageInfo{
		MessageSource: types.MessageSource{
			Chat:     chat,
			IsFromMe: webMsg.GetKey().GetFromMe(),
			// Broadcast counts, matching whatsmeow's own rule for the live
			// path (message.go parseMessageSource). The two disagreed, so the
			// same status post was is_group=true when it arrived live and
			// false when it came back in a history sync -- and a reader that
			// labels the author only for groups then named the sender on some
			// posts and not others, in a feed where every post is by somebody
			// different.
			IsGroup: chat.Server == types.GroupServer || chat.Server == types.BroadcastServer,
		},
		ID:        webMsg.GetKey().GetID(),
		PushName:  webMsg.GetPushName(),
		Timestamp: unixSeconds(webMsg.GetMessageTimestamp()),
	}

	switch {
	case info.IsFromMe:
		if s := webMsg.GetOriginalSelfAuthorUserJIDString(); s != "" {
			info.Sender, err = types.ParseJID(s)
		} else {
			// Our own identity. Unlike whatsmeow we do not fail when it is
			// unknown: a history message that we sent is still worth keeping
			// with an empty sender, and refusing it would drop part of the
			// backfill for no gain.
			info.Sender = opts.Own.Primary().ToNonAD()
		}
	case chat.Server == types.DefaultUserServer ||
		chat.Server == types.HiddenUserServer ||
		chat.Server == types.NewsletterServer:
		// In a direct chat the chat identifies the other party.
		info.Sender = chat
	case webMsg.GetParticipant() != "":
		info.Sender, err = types.ParseJID(webMsg.GetParticipant())
	case webMsg.GetKey().GetParticipant() != "":
		info.Sender, err = types.ParseJID(webMsg.GetKey().GetParticipant())
	}
	if err != nil {
		return types.MessageInfo{}, fmt.Errorf("normalize: sender of %s: %w", info.ID, err)
	}
	return info, nil
}

// maxPlausibleTimestamp is the year 2200 in Unix seconds. History blobs are
// attacker-adjacent data: they arrive from the network, and a corrupt or
// hostile one could carry a value that wraps to a negative time when narrowed
// to int64. A message dated in the distant past sorts to the top of every
// conversation and is a cheap way to vandalise an archive.
const maxPlausibleTimestamp = 7_258_118_400

// unixSeconds converts a reported timestamp, refusing implausible values.
//
// Zero is returned rather than a wrapped date. The row is still stored; it just
// carries no usable time, which is honest about what was received.
func unixSeconds(secs uint64) time.Time {
	if secs == 0 || secs > maxPlausibleTimestamp {
		return time.Time{}
	}
	return time.Unix(int64(secs), 0)
}

// validTimestamp applies the same plausibility bound to a time that arrived
// already parsed, which is how whatsmeow hands over receipt timestamps.
func validTimestamp(t time.Time) bool {
	return !t.IsZero() && t.Unix() > 0 && t.Unix() <= maxPlausibleTimestamp
}

// classify is the single dispatch point.
func classify(in input, opts Options) (domain.Envelope, error) {
	if in.Message == nil {
		return domain.Envelope{}, ErrSkip
	}
	in.PollVote = opts.PollVote

	env := domain.Envelope{
		TenantID:  opts.TenantID,
		DeviceID:  opts.DeviceID,
		MessageID: in.Info.ID,
		Chat:      addressFor(in.Info.Chat, in.Info.SenderAlt, false),
		Sender:    addressFor(in.Info.Sender, in.Info.SenderAlt, true),
		Timestamp: in.Info.Timestamp,
		IsFromMe:  in.Info.IsFromMe,
		IsGroup:   in.Info.IsGroup,
		Source:    in.Source,
		ViewOnce:  in.Flags.IsViewOnce,
		Ephemeral: in.Flags.IsEphemeral,
	}
	if in.Raw != nil {
		env.Content.Raw = marshalRaw(in.Raw)
	}

	// Control rows first. A protocol message is never also a content message,
	// and a reaction is never text.
	if pm := in.Message.GetProtocolMessage(); pm != nil {
		return control(env, pm)
	}
	if react := in.Message.GetReactionMessage(); react != nil {
		return reaction(env, react)
	}

	env.Kind = domain.KindMessage
	applyContext(&env, contextInfoOf(in.Message))
	out, err := content(env, in)
	if err != nil || out.Type != domain.TypeUnsupported {
		return out, err
	}

	// Nothing matched. Before giving up, look inside: WhatsApp wraps ordinary
	// messages in envelopes — group mentions, status mentions, spoilers, bot
	// forwards, and more every few months — and whatsmeow's UnwrapRaw peels
	// exactly nine of them, in one fixed-order pass. Anything else, or anything
	// nested in an order that pass did not anticipate, arrives here as a
	// message whose only set field is the wrapper.
	//
	// That is how a perfectly ordinary text or sticker becomes "unsupported":
	// 998 rows in one real archive, none of which carried a body, because the
	// classifier never saw the message inside.
	//
	// Only on this path, so the cost falls on messages that were already going
	// to be recorded as unreadable rather than on every message.
	for depth := 0; depth < maxWrapperDepth; depth++ {
		inner := insideWrapper(in.Message)
		if inner == nil {
			return out, nil
		}
		in.Message = inner

		// A wrapped edit or revocation is a control row, not content, and has
		// to be recognised as one — otherwise the edit is filed as an ordinary
		// message and the original never gets its new text.
		if pm := inner.GetProtocolMessage(); pm != nil {
			return control(env, pm)
		}
		if react := inner.GetReactionMessage(); react != nil {
			return reaction(env, react)
		}
		applyContext(&env, contextInfoOf(inner))
		out, err = content(env, in)
		if err != nil || out.Type != domain.TypeUnsupported {
			return out, err
		}
	}
	return out, nil
}

// maxWrapperDepth bounds the descent. Real messages nest two or three deep; the
// limit is there so a malformed or hostile message cannot spin.
const maxWrapperDepth = 8

// insideWrapper returns the message inside a FutureProofMessage envelope, or
// nil if this message is not one.
//
// By reflection rather than a list of accessors, deliberately. waE2E.Message
// has dozens of these fields and gains more with every protocol revision; a
// hand-written list is a copy that silently falls behind, which is the same
// reasoning that made FromLive reuse whatsmeow's UnwrapRaw instead of
// reimplementing it. Whatever the field is called, if it holds a
// FutureProofMessage then the real message is inside it.
func insideWrapper(m *waE2E.Message) *waE2E.Message {
	if m == nil {
		return nil
	}
	v := reflect.ValueOf(m).Elem()
	for i := range v.NumField() {
		f := v.Field(i)
		if f.Kind() != reflect.Ptr || f.IsNil() || f.Type() != futureProof {
			continue
		}
		//nolint:forcetypeassert // guarded by the type comparison above
		if inner := f.Interface().(*waE2E.FutureProofMessage).GetMessage(); inner != nil {
			return inner
		}
	}
	return nil
}

var futureProof = reflect.TypeOf((*waE2E.FutureProofMessage)(nil))

// control handles protocol messages: edits, revocations and housekeeping.
func control(env domain.Envelope, pm *waE2E.ProtocolMessage) (domain.Envelope, error) {
	target := pm.GetKey().GetID()

	switch pm.GetType() {
	case waE2E.ProtocolMessage_MESSAGE_EDIT:
		if target == "" {
			return domain.Envelope{}, errors.New("normalize: edit with no target")
		}
		env.Kind = domain.KindEdit
		env.Type = domain.TypeText
		env.TargetID = target
		// An edit always targets a real message, never a reaction: WhatsApp
		// has no notion of editing a reaction, only of replacing one.
		env.TargetRel = domain.TargetMessage

		inner := pm.GetEditedMessage()
		if inner == nil {
			return domain.Envelope{}, errors.New("normalize: edit with no new content")
		}
		env.Content.Body = textOf(inner)
		applyContext(&env, contextInfoOf(inner))
		return env, nil

	case waE2E.ProtocolMessage_REVOKE:
		if target == "" {
			return domain.Envelope{}, errors.New("normalize: revoke with no target")
		}
		env.Kind = domain.KindDelete
		env.Type = domain.TypeText
		env.TargetID = target
		// Left unresolved on purpose. Whether this deletes a message or
		// withdraws a reaction depends on what the target actually is, which
		// only the store knows. Ingest resolves it once and records the
		// answer; the v1 server recomputed it at render time, in two places
		// that then disagreed.
		env.TargetRel = domain.TargetNone
		return env, nil

	default:
		// Key distribution, history-sync notifications, ephemeral settings and
		// the rest. Real protocol traffic, handled elsewhere or not at all,
		// but never a row in the archive.
		return domain.Envelope{}, ErrSkip
	}
}

// reaction handles both a reaction and its removal.
func reaction(env domain.Envelope, r *waE2E.ReactionMessage) (domain.Envelope, error) {
	target := r.GetKey().GetID()
	if target == "" {
		return domain.Envelope{}, errors.New("normalize: reaction with no target")
	}
	env.Kind = domain.KindReaction
	env.Type = domain.TypeReaction
	env.TargetID = target
	env.TargetRel = domain.TargetMessage
	// An empty emoji is a removal, not an empty reaction, and it is stored as
	// an ordinary reaction row whose sealed body happens to be empty.
	//
	// Nothing here flags it, deliberately. Emptiness is a property of the
	// content, and the content is sealed — a server-side "this was a removal"
	// boolean would be the server reporting something about a body it is not
	// supposed to be able to read. The history projection returns the reaction
	// rows per party in order and marks the older ones superseded; the client,
	// which can open them, sees that the newest is empty.
	env.Content.Body = r.GetText()
	if ts := r.GetSenderTimestampMS(); ts != 0 {
		env.Timestamp = time.UnixMilli(ts)
	}
	return env, nil
}

// addressFor builds an Address, using the alternate JID whatsmeow supplies to
// fill in the other half when it can.
//
// WhatsApp reports one identifier as primary and sometimes the other alongside
// it. Capturing both is what lets a contact stay addressable when a chat
// migrates from a phone number to a LID, which is now the default direction.
func addressFor(primary, alt types.JID, useAlt bool) domain.Address {
	addr := domain.AddressOf(primary)
	if useAlt && !alt.IsEmpty() {
		addr = addr.Merge(domain.AddressOf(alt))
	}
	return addr
}

// applyContext copies the parts of ContextInfo that belong on the envelope.
func applyContext(env *domain.Envelope, ci *waE2E.ContextInfo) {
	if ci == nil {
		return
	}
	env.ReplyTo = ci.GetStanzaID()
	env.IsForwarded = ci.GetIsForwarded()
	env.ForwardingScore = ci.GetForwardingScore()
	env.Expiration = ci.GetExpiration()
	// Mentions land in Content, not beside the fields above, because they are
	// content: who was tagged is the social graph inside the message.
	if m := ci.GetMentionedJID(); len(m) > 0 {
		env.Content.Mentions = m
	}
}
