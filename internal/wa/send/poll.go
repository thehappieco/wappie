package send

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf8"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
	"whatserver2/internal/domain"
)

func ValidatePoll(question string, options []string, count int) (domain.Poll, error) {
	poll := domain.Poll{Question: strings.TrimSpace(question)}
	if poll.Question == "" || utf8.RuneCountInString(poll.Question) > 255 {
		return poll, fmt.Errorf("poll question must contain 1 to 255 characters")
	}
	if len(options) < 2 || len(options) > 12 {
		return poll, fmt.Errorf("poll needs 2 to 12 options")
	}
	if count != 0 && count != 1 {
		return poll, fmt.Errorf("selectable_count must be 0 (multiple answers) or 1 (single answer)")
	}
	seen := map[string]bool{}
	for _, value := range options {
		value = strings.TrimSpace(value)
		if value == "" || utf8.RuneCountInString(value) > 100 {
			return poll, fmt.Errorf("poll options must contain 1 to 100 characters")
		}
		folded := strings.ToLower(value)
		if seen[folded] {
			return poll, fmt.Errorf("poll options must be distinct")
		}
		seen[folded] = true
		poll.Options = append(poll.Options, value)
	}
	if count == 1 {
		poll.SelectableCount = 1
	}
	return poll, nil
}

type pollClient interface {
	Client
	BuildPollCreation(name string, options []string, count int) *waE2E.Message
}

func SendPoll(ctx context.Context, c pollClient, chat types.JID, id string, poll domain.Poll, opts Options) (Sent, error) {
	msg := c.BuildPollCreation(poll.Question, poll.Options, int(poll.SelectableCount))
	msg.PollCreationMessage.ContextInfo = buildContext(chat, opts)
	// Keep MessageContextInfo on the outer message: whatsmeow stores this secret
	// for decrypting subsequent votes, including for a disappearing poll.
	secret := msg.MessageContextInfo
	msg = wrap(msg, opts)
	msg.MessageContextInfo = secret
	var extra []whatsmeow.SendRequestExtra
	if id != "" {
		extra = append(extra, whatsmeow.SendRequestExtra{ID: id})
	}
	resp, err := c.SendMessage(ctx, chat, msg, extra...)
	if err != nil {
		return Sent{}, fmt.Errorf("send poll: %w", err)
	}
	env := outboundEnvelope(chat, resp, domain.KindMessage, domain.TypePoll, poll.Question, opts)
	env.Content.Poll = &poll
	return Sent{ID: resp.ID, Timestamp: resp.Timestamp, Envelope: env}, nil
}
