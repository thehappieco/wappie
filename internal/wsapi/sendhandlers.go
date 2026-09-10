package wsapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"whatserver2/internal/store"

	"github.com/google/uuid"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
	"google.golang.org/protobuf/proto"

	"whatserver2/internal/domain"
	"whatserver2/internal/ingest"
	"whatserver2/internal/wa"
	"whatserver2/internal/wa/send"
)

// sendTarget is what every outbound handler needs to resolve first.
type sendTarget struct {
	tenant uuid.UUID
	device *wa.Device
	// deviceID is the resolved uuid. The Device carries its id as a string and
	// the caller may have typed a prefix, so this is the one to key on.
	deviceID uuid.UUID
	chat     types.JID
}

// resolveSend validates the device and chat for an outbound request.
func (s *session) resolveSend(ctx context.Context, f Frame, deviceID, chat string) (sendTarget, bool) {
	// Everything that goes through here reaches WhatsApp as this number. A
	// key issued to read the archive does not get to speak for it.
	if !s.requireScope(f.ReqID, store.ScopeSend) {
		return sendTarget{}, false
	}
	tenant, resolved, ok := s.resolveDevice(ctx, f, deviceID)
	if !ok {
		return sendTarget{}, false
	}
	// The registry is keyed by the full id, so use what resolveDevice found
	// rather than what the caller typed, which may have been a prefix.
	dev, running := s.srv.cfg.Registry.Get(resolved.String())
	if !running {
		s.replyError(f.ReqID, ErrCodeConflict,
			"that device is not connected right now; nothing can be sent from it")
		return sendTarget{}, false
	}
	if chat == "" {
		s.replyError(f.ReqID, ErrCodeBadRequest, "chat is required")
		return sendTarget{}, false
	}
	jid, err := types.ParseJID(chat)
	if err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, fmt.Sprintf("chat %q is not a JID", chat))
		return sendTarget{}, false
	}
	return sendTarget{tenant: tenant, device: dev, deviceID: resolved, chat: jid}, true
}

// archive stores an outbound message and reports the result.
//
// A send that reaches WhatsApp but fails to archive is still a send: the
// message is on the recipient's phone either way. Reporting success with the
// archiving error logged is honest about what happened; failing the call would
// invite a retry that duplicates the message.
func (s *session) archive(ctx context.Context, t sendTarget, sent send.Sent, f Frame) {
	result := SendResult{ID: sent.ID, Timestamp: sent.Timestamp}

	if s.srv.cfg.Router != nil {
		res, err := s.srv.cfg.Router.IngestOutbound(ctx, t.tenant, t.device.ID(), sent.Envelope)
		if err != nil {
			s.log.Error("a message was sent but could not be archived",
				"message", sent.ID, "error", err)
		} else {
			result.UID, result.Seq = res.UID.String(), res.Seq
		}
	}
	s.reply(TypeSendResult, f.ReqID, result)
}

func (s *session) handleSend(ctx context.Context, f Frame) {
	var req SendRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	t, ok := s.resolveSend(ctx, f, req.DeviceID, req.Chat)
	if !ok {
		return
	}

	opts := send.Options{
		ReplyTo:         req.ReplyTo,
		Forwarded:       req.Forwarded,
		ForwardingScore: req.ForwardingScore,
		Expiration:      req.Expiration,
		ViewOnce:        req.ViewOnce,
		Ephemeral:       req.Ephemeral,
	}
	if req.ReplyTo != "" {
		// The quoted content comes from the client because the archive is
		// sealed: this server cannot read what was said, so it cannot rebuild
		// the quote. Without it the recipient sees a reply pointing at
		// nothing.
		if req.ReplyBody != "" {
			opts.ReplyContent = &waE2E.Message{Conversation: proto.String(req.ReplyBody)}
		}
		if req.ReplySender != "" {
			jid, err := types.ParseJID(req.ReplySender)
			if err != nil {
				s.replyError(f.ReqID, ErrCodeBadRequest, "reply_sender is not a JID")
				return
			}
			opts.ReplySender = jid
		}
	}
	for _, m := range req.Mentions {
		jid, err := types.ParseJID(m)
		if err != nil {
			s.replyError(f.ReqID, ErrCodeBadRequest, fmt.Sprintf("mention %q is not a JID", m))
			return
		}
		opts.Mentions = append(opts.Mentions, jid)
	}

	if p := req.Preview; p != nil {
		if p.URL == "" {
			s.replyError(f.ReqID, ErrCodeBadRequest, "preview.url is required")
			return
		}
		opts.Preview = &send.Preview{
			URL: p.URL, Title: p.Title, Description: p.Description, Thumbnail: p.Thumbnail,
		}
	}

	s.applyChatTimer(ctx, t, &opts)

	sent, err := send.SendText(ctx, t.device.Client(), send.Request{
		Chat: t.chat, Body: req.Body, Opts: opts, ID: req.ID,
	})
	if errors.Is(err, send.ErrViewOnceText) {
		// The caller asked for something WhatsApp does not do, not something
		// that failed. Retrying will never help.
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	if err != nil {
		s.replyError(f.ReqID, ErrCodeInternal, err.Error())
		return
	}
	s.archive(ctx, t, sent, f)
}

// handleSendMedia sends an attachment already uploaded to WhatsApp.
func (s *session) handleSendMedia(ctx context.Context, f Frame) {
	var req SendMediaRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	// The request is checked against itself before anything is looked up. Both
	// of these are wrong no matter which device they were aimed at, and saying
	// "that device is not connected" to somebody whose frame could never have
	// worked sends them looking in the wrong place.
	if req.Upload.URL == "" || req.Upload.DirectPath == "" || len(req.Upload.MediaKey) == 0 {
		s.replyError(f.ReqID, ErrCodeBadRequest,
			"upload is required: post the file to /v1/upload first and pass what it returns")
		return
	}
	// The upload chose the HKDF label from its own ?type=, and this frame names
	// a type again. Nothing links the two calls, so this comparison is the only
	// thing standing between "sent as a document, sealed as an image" and an
	// attachment that answers 200 at every step and then opens for nobody —
	// not the recipient, and not this archive either.
	if req.Upload.Type != "" &&
		domain.KeyClass(domain.Type(req.Upload.Type)) != domain.KeyClass(domain.Type(req.Type)) {
		s.replyError(f.ReqID, ErrCodeBadRequest, fmt.Sprintf(
			"the file was uploaded as %q and is being sent as %q; those use different "+
				"encryption keys, so the attachment would never open. Upload it again as %q.",
			req.Upload.Type, req.Type, req.Type))
		return
	}
	if err := send.ValidateVideo(send.Attachment{
		Type: domain.Type(req.Type), MimeType: req.MimeType,
		Caption: req.Caption, Seconds: req.Seconds, IsGIF: req.IsGIF,
	}); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}

	t, ok := s.resolveSend(ctx, f, req.DeviceID, req.Chat)
	if !ok {
		return
	}

	opts, ok := s.sendOptions(ctx, f, sendCommon{
		ReplyTo: req.ReplyTo, ReplySender: req.ReplySender, ReplyBody: req.ReplyBody,
		Forwarded: req.Forwarded, ForwardingScore: req.ForwardingScore,
		Expiration: req.Expiration, ViewOnce: req.ViewOnce, Ephemeral: req.Ephemeral,
		Mentions: req.Mentions,
	})
	if !ok {
		return
	}

	s.applyChatTimer(ctx, t, &opts)

	sent, err := send.SendMedia(ctx, t.device.Client(), send.MediaRequest{
		Chat: t.chat, ID: req.ID, Opts: opts,
		Attachment: send.Attachment{
			Type:     domain.Type(req.Type),
			MimeType: req.MimeType,
			URL:      req.Upload.URL, DirectPath: req.Upload.DirectPath,
			MediaKey:   req.Upload.MediaKey,
			FileSHA256: req.Upload.FileSHA256, FileEncSHA256: req.Upload.FileEncSHA256,
			FileLength: req.Upload.FileLength,
			Caption:    req.Caption, FileName: req.FileName,
			Width: req.Width, Height: req.Height, Seconds: req.Seconds,
			Waveform: req.Waveform, Thumbnail: req.Thumbnail, Sidecar: req.Sidecar,
			IsGIF: req.IsGIF, IsAnimated: req.IsAnimated,
		},
	})
	if errors.Is(err, send.ErrNoAttachment) || errors.Is(err, send.ErrCaptionOnAudio) || errors.Is(err, send.ErrInvalidVideo) {
		// The caller asked for something WhatsApp does not do. Retrying never
		// helps, so this is a bad request rather than an internal failure.
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	if err != nil {
		s.replyError(f.ReqID, ErrCodeInternal, err.Error())
		return
	}
	s.archive(ctx, t, sent, f)
}

// handleChatTimer turns disappearing messages on or off for a chat.
func (s *session) handleChatTimer(ctx context.Context, f Frame) {
	var req ChatTimerRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	t, ok := s.resolveSend(ctx, f, req.DeviceID, req.Chat)
	if !ok {
		return
	}
	// A timer beyond a year is not something WhatsApp offers and is far more
	// likely to be milliseconds passed by mistake.
	const maxTimer = 400 * 24 * 60 * 60
	if req.Seconds > maxTimer {
		s.replyError(f.ReqID, ErrCodeBadRequest,
			"that timer is longer than a year; WhatsApp's longest preset is 7776000 (90 days)")
		return
	}

	if err := t.device.Client().SetDisappearingTimer(ctx, t.chat,
		time.Duration(req.Seconds)*time.Second, time.Now()); err != nil {
		s.replyError(f.ReqID, ErrCodeInternal, err.Error())
		return
	}
	// Recorded only after WhatsApp accepted it, so the row says what the other
	// side will actually do rather than what was asked for.
	//nolint:gosec // G115: bounded above, and the column is a plain integer
	if err := s.srv.cfg.Messages.SetChatTimer(ctx, t.tenant, t.deviceID,
		t.chat.String(), int32(req.Seconds)); err != nil {
		s.log.Error("the timer was set on WhatsApp but not recorded here",
			"chat", t.chat, "error", err)
	}
	s.reply(TypeChatTimerSet, f.ReqID, ChatTimerResult{
		Chat: t.chat.String(), Seconds: req.Seconds,
	})
}

// applyChatTimer fills in the disappearing-message settings for an outbound
// message.
//
// This is what was missing when -expires appeared to do nothing. WhatsApp has
// no per-message expiry: a message vanishes because the *chat* has a timer, and
// a message sent into such a chat has to both declare the timer and travel
// inside the disappearing envelope. Setting only the first, which is what the
// flag used to do, produces a message every client treats as ordinary.
//
// So the caller does not pass an expiry at all in the normal case; the chat's
// setting is read here and applied.
func (s *session) applyChatTimer(ctx context.Context, t sendTarget, opts *send.Options) {
	if opts.Expiration == 0 {
		seconds, err := s.srv.cfg.Messages.ChatTimer(ctx, t.tenant, t.deviceID, t.chat.String())
		if err != nil {
			s.log.Warn("could not read a chat's disappearing timer",
				"chat", t.chat, "error", err)
			return
		}
		if seconds <= 0 {
			return
		}
		// The envelope follows from the expiration inside send.wrap, so
		// nothing here has to remember to set it.
		//nolint:gosec // G115: a timer in seconds, bounded when it was set
		opts.Expiration = uint32(seconds)
	}
}

// sendCommon are the options every outbound message shares.
type sendCommon struct {
	ReplyTo         string
	ReplySender     string
	ReplyBody       string
	Forwarded       bool
	ForwardingScore uint32
	Expiration      uint32
	ViewOnce        bool
	Ephemeral       bool
	Mentions        []string
}

// sendOptions builds the shared options, validating the JIDs in them.
//
// Shared between text and media so the two cannot drift: a reply that works on
// a text message and not on a photograph would be exactly the kind of quiet
// divergence this codebase exists to avoid.
func (s *session) sendOptions(_ context.Context, f Frame, in sendCommon) (send.Options, bool) {
	opts := send.Options{
		ReplyTo:         in.ReplyTo,
		Forwarded:       in.Forwarded,
		ForwardingScore: in.ForwardingScore,
		Expiration:      in.Expiration,
		ViewOnce:        in.ViewOnce,
		Ephemeral:       in.Ephemeral,
	}
	if in.ReplyTo != "" {
		// The quoted content comes from the client because the archive is
		// sealed: this server cannot read what was said, so it cannot rebuild
		// the quote.
		if in.ReplyBody != "" {
			opts.ReplyContent = &waE2E.Message{Conversation: proto.String(in.ReplyBody)}
		}
		if in.ReplySender != "" {
			jid, err := types.ParseJID(in.ReplySender)
			if err != nil {
				s.replyError(f.ReqID, ErrCodeBadRequest, "reply_sender is not a JID")
				return send.Options{}, false
			}
			opts.ReplySender = jid
		}
	}
	for _, m := range in.Mentions {
		jid, err := types.ParseJID(m)
		if err != nil {
			s.replyError(f.ReqID, ErrCodeBadRequest, fmt.Sprintf("mention %q is not a JID", m))
			return send.Options{}, false
		}
		opts.Mentions = append(opts.Mentions, jid)
	}
	return opts, true
}

func (s *session) handleEdit(ctx context.Context, f Frame) {
	var req EditRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	t, ok := s.resolveSend(ctx, f, req.DeviceID, req.Chat)
	if !ok {
		return
	}

	er := send.EditRequest{Chat: t.chat, TargetID: req.TargetID, Body: req.Body}
	if req.SentAt != nil {
		er.SentAt = *req.SentAt
	}
	sent, err := send.SendEdit(ctx, t.device.Client(), er)
	if errors.Is(err, send.ErrEditWindowExpired) {
		// A distinct code, because a client should show this rather than
		// retry: no amount of retrying makes a message younger.
		s.replyError(f.ReqID, ErrCodeConflict, err.Error())
		return
	}
	if err != nil {
		s.replyError(f.ReqID, ErrCodeInternal, err.Error())
		return
	}
	s.archive(ctx, t, sent, f)
}

func (s *session) handleRevoke(ctx context.Context, f Frame) {
	var req RevokeRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	t, ok := s.resolveSend(ctx, f, req.DeviceID, req.Chat)
	if !ok {
		return
	}
	var sender types.JID
	if req.Sender != "" {
		jid, err := types.ParseJID(req.Sender)
		if err != nil {
			s.replyError(f.ReqID, ErrCodeBadRequest, "sender is not a JID")
			return
		}
		sender = jid
	}
	sent, err := send.SendRevoke(ctx, t.device.Client(), send.RevokeRequest{
		Chat: t.chat, TargetID: req.TargetID, Sender: sender,
	})
	if err != nil {
		s.replyError(f.ReqID, ErrCodeInternal, err.Error())
		return
	}
	s.archive(ctx, t, sent, f)
}

// handlePollVote answers a poll.
//
// The option text comes from the client and is not checked against the poll,
// because it cannot be: the poll's options are sealed content and this server
// has never been able to read them. What it can check is that a poll was named
// and that its author parses, and it does — a vote for a poll nobody identified
// is not a vote, and WhatsApp would reject it after a round trip anyway.
//
// Nothing about a wrong option is recoverable here. If the client sends text
// that is not one of the poll's options, the hash matches nothing, and every
// client tallying that poll sees a vote for no option at all. That is a real
// failure mode of this design and the reason the client sends the exact strings
// it rendered rather than anything a person typed.
func (s *session) handlePollVote(ctx context.Context, f Frame) {
	var req PollVoteRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	if req.PollID == "" {
		s.replyError(f.ReqID, ErrCodeBadRequest, "a vote needs the poll it answers")
		return
	}
	t, ok := s.resolveSend(ctx, f, req.DeviceID, req.Chat)
	if !ok {
		return
	}
	sender, err := types.ParseJID(req.PollSender)
	if err != nil || sender.User == "" {
		s.replyError(f.ReqID, ErrCodeBadRequest, "the poll's sender is required and must be a JID")
		return
	}

	sent, err := send.SendPollVote(ctx, t.device.Client(), send.PollVoteRequest{
		Chat:       t.chat,
		PollID:     req.PollID,
		PollSender: sender,
		PollFromMe: req.PollFromMe,
		Options:    req.Options,
	})
	if err != nil {
		s.replyError(f.ReqID, ErrCodeInternal, err.Error())
		return
	}
	s.archive(ctx, t, sent, f)
}

func (s *session) handleReact(ctx context.Context, f Frame) {
	var req ReactRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	t, ok := s.resolveSend(ctx, f, req.DeviceID, req.Chat)
	if !ok {
		return
	}
	var sender types.JID
	if req.Sender != "" {
		jid, err := types.ParseJID(req.Sender)
		if err != nil {
			s.replyError(f.ReqID, ErrCodeBadRequest, "sender is not a JID")
			return
		}
		sender = jid
	}
	sent, err := send.SendReaction(ctx, t.device.Client(), send.ReactRequest{
		Chat: t.chat, TargetID: req.TargetID, Sender: sender, Emoji: req.Emoji,
	})
	if err != nil {
		s.replyError(f.ReqID, ErrCodeInternal, err.Error())
		return
	}
	s.archive(ctx, t, sent, f)
}

// handleMarkRead sends a read receipt, always explicitly.
//
// This is the only path that produces one. Nothing on the ingest side marks
// anything read, which is what makes the default posture incognito: a device
// receives without telling anyone it did.
func (s *session) handleMarkRead(ctx context.Context, f Frame) {
	var req MarkReadRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	t, ok := s.resolveSend(ctx, f, req.DeviceID, req.Chat)
	if !ok {
		return
	}
	if len(req.IDs) == 0 {
		s.replyError(f.ReqID, ErrCodeBadRequest, "ids is required")
		return
	}
	var sender types.JID
	if req.Sender != "" {
		jid, err := types.ParseJID(req.Sender)
		if err != nil {
			s.replyError(f.ReqID, ErrCodeBadRequest, "sender is not a JID")
			return
		}
		sender = jid
	}
	// types.MessageID is an alias for string, so the request ids are already
	// the right type.
	ids := req.IDs

	// The badge first, and unconditionally. It is a fact about this reader,
	// not about what was reported to the other side — and the two were tangled
	// together: the only thing that used to clear a badge was our own read
	// receipt coming back through ingest, so a device in the default discreet
	// mode, which sends no read receipts at all, could never clear one. Marking
	// a conversation read did nothing visible, forever.
	if s.srv.cfg.Unread != nil {
		if err := s.srv.cfg.Unread.MarkReadThrough(ctx, t.tenant, t.deviceID, ids); err != nil {
			s.log.Error("could not clear a badge", "chat", t.chat, "error", err)
		} else {
			s.announceUnread(ctx, t)
		}
	}

	if err := t.device.Policy().MarkRead(ctx, t.device.Client(), t.chat, sender, ids, req.Played); err != nil {
		s.replyError(f.ReqID, ErrCodeInternal, err.Error())
		return
	}
	s.reply(TypeSendResult, f.ReqID, SendResult{ID: req.IDs[0]})
}

// announceUnread pushes a conversation's recounted badge to every client.
//
// Through the bus rather than as a reply, because the reader is rarely alone:
// a second tab, and this account's other browsers, are showing the same badge
// and have no other way to learn it moved. The tab that asked receives it too,
// which is one assignment it would otherwise have had to guess at.
func (s *session) announceUnread(ctx context.Context, t sendTarget) {
	if s.srv.cfg.Unread == nil || s.srv.cfg.Bus == nil {
		return
	}
	chat := t.chat.String()
	n, err := s.srv.cfg.Unread.Count(ctx, t.tenant, t.deviceID, chat)
	if err != nil {
		s.log.Debug("could not read a badge back", "chat", chat, "error", err)
		return
	}
	s.srv.cfg.Bus.Publish(t.tenant, ingest.Event{
		Class: ingest.ClassChat, TenantID: t.tenant, DeviceID: t.deviceID,
		ChatKey: chat, Ephemeral: true,
		Chat: &ingest.ChatUpdate{ChatKey: chat, Unread: &n},
	})
}
