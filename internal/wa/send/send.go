package send

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/domain"
	"whatserver2/internal/emoji"
)

// Client is the slice of whatsmeow this package needs.
type Client interface {
	SendMessage(ctx context.Context, to types.JID, message *waE2E.Message,
		extra ...whatsmeow.SendRequestExtra) (whatsmeow.SendResponse, error)
	BuildEdit(chat types.JID, id types.MessageID, newContent *waE2E.Message) *waE2E.Message
	BuildRevoke(chat, sender types.JID, id types.MessageID) *waE2E.Message
	BuildReaction(chat, sender types.JID, id types.MessageID, reaction string) *waE2E.Message
	BuildPollVote(ctx context.Context, poll *types.MessageInfo, options []string) (*waE2E.Message, error)
}

// ErrEditWindowExpired means the message is too old to edit.
//
// WhatsApp allows twenty minutes. Checking locally turns a stanza that the
// server would reject into an error the caller can show, and saves a round trip
// that was never going to work.
var ErrEditWindowExpired = errors.New("send: the twenty-minute edit window has passed")

// ErrInvalidReaction rejects text or multiple emoji before reaching WhatsApp.
var ErrInvalidReaction = errors.New("send: a reaction must be one complete emoji, or empty to remove it")

// Sent describes what left.
type Sent struct {
	ID        string
	Timestamp time.Time
	// Envelope is the outbound message as it will be archived, so the caller
	// stores exactly what was sent rather than reconstructing it.
	Envelope domain.Envelope
}

// Request is one outbound message.
type Request struct {
	Chat types.JID
	Body string
	Opts Options

	// ID lets a caller supply its own message id, making a retry idempotent:
	// the same id sent twice is the same message, not two.
	ID string
}

// SendText sends a text message and returns what to archive.
func SendText(ctx context.Context, c Client, req Request) (Sent, error) {
	msg, err := Text(req.Chat, req.Body, req.Opts)
	if err != nil {
		return Sent{}, err
	}

	var extra []whatsmeow.SendRequestExtra
	if req.ID != "" {
		extra = append(extra, whatsmeow.SendRequestExtra{ID: req.ID})
	}
	resp, err := c.SendMessage(ctx, req.Chat, msg, extra...)
	if err != nil {
		return Sent{}, fmt.Errorf("send: %w", err)
	}

	return Sent{
		ID:        resp.ID,
		Timestamp: resp.Timestamp,
		Envelope:  outboundEnvelope(req.Chat, resp, domain.KindMessage, domain.TypeText, req.Body, req.Opts),
	}, nil
}

// EditRequest replaces the text of a message already sent.
type EditRequest struct {
	Chat types.JID
	// TargetID is the message being replaced.
	TargetID string
	// SentAt is when the original was sent, for the window check. Zero skips
	// the check and lets the server decide.
	SentAt time.Time
	Body   string
	Opts   Options
}

// SendEdit edits a message.
func SendEdit(ctx context.Context, c Client, req EditRequest) (Sent, error) {
	if req.TargetID == "" {
		return Sent{}, errors.New("send: an edit needs a target")
	}
	if !req.SentAt.IsZero() && time.Since(req.SentAt) > whatsmeow.EditWindow {
		return Sent{}, fmt.Errorf("%w (sent %s ago)", ErrEditWindowExpired,
			time.Since(req.SentAt).Round(time.Minute))
	}

	content, err := Text(req.Chat, req.Body, req.Opts)
	if err != nil {
		return Sent{}, err
	}
	resp, err := c.SendMessage(ctx, req.Chat,
		c.BuildEdit(req.Chat, req.TargetID, content))
	if err != nil {
		return Sent{}, fmt.Errorf("send: edit: %w", err)
	}

	env := outboundEnvelope(req.Chat, resp, domain.KindEdit, domain.TypeText, req.Body, req.Opts)
	env.TargetID = req.TargetID
	// An edit always targets a real message: WhatsApp has no notion of editing
	// a reaction, only of replacing one.
	env.TargetRel = domain.TargetMessage
	return Sent{ID: resp.ID, Timestamp: resp.Timestamp, Envelope: env}, nil
}

// RevokeRequest deletes a message for everyone.
type RevokeRequest struct {
	Chat types.JID
	// TargetID is the message being deleted.
	TargetID string
	// Sender is the original author. Empty deletes our own message; set, it is
	// a group admin deleting someone else's.
	Sender types.JID
}

// SendRevoke deletes a message for everyone.
//
// The archive keeps the original. That is the product: a deleted message is
// still there, marked as deleted, with its content intact for whoever holds the
// key.
func SendRevoke(ctx context.Context, c Client, req RevokeRequest) (Sent, error) {
	if req.TargetID == "" {
		return Sent{}, errors.New("send: a revoke needs a target")
	}
	resp, err := c.SendMessage(ctx, req.Chat,
		c.BuildRevoke(req.Chat, req.Sender, req.TargetID))
	if err != nil {
		return Sent{}, fmt.Errorf("send: revoke: %w", err)
	}

	env := outboundEnvelope(req.Chat, resp, domain.KindDelete, domain.TypeText, "", Options{})
	env.TargetID = req.TargetID
	// Left unresolved: whether this deletes a message or withdraws a reaction
	// depends on what the target is, and ingest answers that once by looking.
	env.TargetRel = domain.TargetNone
	return Sent{ID: resp.ID, Timestamp: resp.Timestamp, Envelope: env}, nil
}

// ReactRequest adds or removes a reaction.
type ReactRequest struct {
	Chat types.JID
	// TargetID is the message being reacted to.
	TargetID string
	// Sender is the author of the target message.
	Sender types.JID
	// Emoji is the reaction. An empty string removes it — not an empty
	// reaction, a withdrawal.
	Emoji string
}

// PollVoteRequest answers a poll.
type PollVoteRequest struct {
	Chat types.JID
	// Poll identifies the message being answered: its id, its author, and
	// whether it is ours. All three feed the key derivation, which is why the
	// caller passes them rather than this package guessing.
	PollID     string
	PollSender types.JID
	PollFromMe bool
	// Options are the choices, in the poll's own wording. Empty withdraws.
	Options []string
}

// SendPollVote answers a poll.
//
// The options arrive as text and are hashed by whatsmeow, because a vote on the
// wire is a list of SHA-256 digests of the option strings and nothing else.
// That is also why this server can neither read nor tally a poll on its own:
// the question and its options are sealed, and the only place both halves exist
// together is a client that has opened the payload.
//
// An empty Options list is a withdrawal, not a mistake. WhatsApp treats a vote
// as replacing the voter's previous answer, so an empty selection is how a
// person takes theirs back — refusing it here would leave no way to.
func SendPollVote(ctx context.Context, c Client, req PollVoteRequest) (Sent, error) {
	if req.PollID == "" {
		return Sent{}, errors.New("send: a vote needs the poll it answers")
	}
	msg, err := c.BuildPollVote(ctx, &types.MessageInfo{
		ID: req.PollID,
		MessageSource: types.MessageSource{
			Chat:     req.Chat,
			Sender:   req.PollSender,
			IsFromMe: req.PollFromMe,
			IsGroup:  req.Chat.Server == types.GroupServer,
		},
	}, req.Options)
	if err != nil {
		return Sent{}, fmt.Errorf("send: build vote: %w", err)
	}
	resp, err := c.SendMessage(ctx, req.Chat, msg)
	if err != nil {
		return Sent{}, fmt.Errorf("send: vote: %w", err)
	}

	env := outboundEnvelope(req.Chat, resp, domain.KindMessage, domain.TypePollVote, "", Options{})
	env.TargetID = req.PollID
	env.TargetRel = domain.TargetMessage
	// Our own vote, hashed the same way the wire form is, so that the client
	// tallying the poll finds this row exactly as it finds everybody else's.
	// Recording the plain text here instead would put the poll's options in
	// the one row of the poll that was not sealed.
	env.Content.PollVote = &domain.PollVote{Selected: whatsmeow.HashPollOptions(req.Options)}
	return Sent{ID: resp.ID, Timestamp: resp.Timestamp, Envelope: env}, nil
}

func SendReaction(ctx context.Context, c Client, req ReactRequest) (Sent, error) {
	if req.TargetID == "" {
		return Sent{}, errors.New("send: a reaction needs a target")
	}
	canonical, valid := emoji.Normalize(req.Emoji)
	if !valid {
		return Sent{}, ErrInvalidReaction
	}
	req.Emoji = canonical
	resp, err := c.SendMessage(ctx, req.Chat,
		c.BuildReaction(req.Chat, req.Sender, req.TargetID, req.Emoji))
	if err != nil {
		return Sent{}, fmt.Errorf("send: reaction: %w", err)
	}

	env := outboundEnvelope(req.Chat, resp, domain.KindReaction, domain.TypeReaction, req.Emoji, Options{})
	env.TargetID = req.TargetID
	env.TargetRel = domain.TargetMessage
	return Sent{ID: resp.ID, Timestamp: resp.Timestamp, Envelope: env}, nil
}

// outboundEnvelope builds the archive row for something we sent.
//
// Recording our own messages through the same envelope the inbound path
// produces means one storage path and one rendering, so a message we sent looks
// the same as one we received. The source marks where it came from.
func outboundEnvelope(chat types.JID, resp whatsmeow.SendResponse,
	kind domain.Kind, typ domain.Type, body string, opts Options) domain.Envelope {
	return domain.Envelope{
		MessageID:       resp.ID,
		Chat:            domain.AddressOf(chat),
		Timestamp:       resp.Timestamp,
		IsFromMe:        true,
		IsGroup:         chat.Server == types.GroupServer,
		Kind:            kind,
		Type:            typ,
		ReplyTo:         opts.ReplyTo,
		IsForwarded:     opts.Forwarded,
		ForwardingScore: forwardingScore(opts),
		Expiration:      opts.Expiration,
		ViewOnce:        opts.ViewOnce,
		Ephemeral:       opts.disappearing(),
		Source:          domain.SourceOutbox,
		Content:         outboundContent(body, opts),
	}
}

// outboundContent records what actually went out, beyond the text.
//
// Mentions and the link card reached the recipient — buildContext put both on
// the wire — and used to reach the archive as nothing, so our own copy of a
// message was strictly poorer than the copy anyone else received. Both are
// content and both are sealed with the body, exactly as the inbound path does.
func outboundContent(body string, opts Options) domain.Content {
	c := domain.Content{Body: body}
	for _, jid := range opts.Mentions {
		c.Mentions = append(c.Mentions, jid.ToNonAD().String())
	}
	if p := opts.Preview; p != nil {
		c.LinkPreview = &domain.LinkPreview{
			URL:         p.URL,
			Title:       p.Title,
			Description: p.Description,
			Thumbnail:   p.Thumbnail,
		}
	}
	return c
}

// forwardingScore mirrors what buildContext actually put on the wire, so the
// archive records what the recipient saw rather than what was asked for.
func forwardingScore(opts Options) uint32 {
	if !opts.Forwarded {
		return 0
	}
	if opts.ForwardingScore == 0 {
		return 1
	}
	return opts.ForwardingScore
}
