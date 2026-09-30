package wsapi

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/store"
	"whatserver2/internal/wa/send"
)

// Assistant connections that send (docs/mcp-enclave.md §17): a person's
// confirmation of a draft, over this socket, and the own-chat note the MCP
// send route hands to SendText. Both go through the same text send as any
// frame, timer and archive included.

// draftSendTimeout bounds a confirmed draft's send and its record once the
// draft is taken: they run to their end even if the socket closes, so the
// ledger never keeps a draft sending that left.
const draftSendTimeout = 60 * time.Second

// handleDraftSend sends an assistant's draft for the person who consented
// to its connection (§17.7a). The frame is checked as any send is, device,
// permission and chat, before the draft is taken; the draft is then taken
// in one transaction under its lock, so a second frame naming it finds it
// gone and nothing is sent twice. The text and the quote are the frame's:
// this server cannot open the draft, and mcp_edited is the console's word.
// A confirmation does not count toward the connection's limits: a person
// sends it.
func (s *session) handleDraftSend(ctx context.Context, f Frame, req SendRequest) {
	who := s.actor()
	if !who.person {
		// An API key, the connection's own included, never confirms a draft.
		s.replyError(f.ReqID, ErrCodeNotAuthorized, "only the person who consented to the connection may send its draft")
		return
	}
	draft, err := uuid.Parse(req.MCPDraft)
	if err != nil || draft == uuid.Nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, "mcp_draft is not a draft id")
		return
	}
	if s.srv.cfg.MCP == nil {
		s.replyError(f.ReqID, ErrCodeSendNotAllowed, "this server does not hold assistant drafts")
		return
	}
	if req.ViewOnce {
		// Refused before the draft is taken: WhatsApp has no view-once text.
		s.replyError(f.ReqID, ErrCodeBadRequest, send.ErrViewOnceText.Error())
		return
	}
	t, ok := s.resolveSend(ctx, f, req.DeviceID, req.Chat)
	if !ok {
		return
	}
	opts, ok := s.sendOptions(ctx, f, sendCommon{
		ReplyTo: req.ReplyTo, ReplySender: req.ReplySender, ReplyBody: req.ReplyBody,
		Forwarded: req.Forwarded, ForwardingScore: req.ForwardingScore,
		Expiration: req.Expiration, Ephemeral: req.Ephemeral, Mentions: req.Mentions,
	})
	if !ok {
		return
	}
	if p := req.Preview; p != nil {
		if p.URL == "" {
			s.replyError(f.ReqID, ErrCodeBadRequest, "preview.url is required")
			return
		}
		opts.Preview = &send.Preview{URL: p.URL, Title: p.Title, Description: p.Description, Thumbnail: p.Thumbnail}
	}

	claimed, err := s.srv.cfg.MCP.ClaimDraft(ctx, t.tenant, who.userID, draft, t.deviceID, req.Chat, s.srv.cfg.MCPSendAllowed)
	switch {
	case errors.Is(err, store.ErrOutboundNotFound), errors.Is(err, store.ErrMembershipForbidden):
		s.replyError(f.ReqID, ErrCodeNotAuthorized, "this draft is not one this account may send")
		return
	case errors.Is(err, store.ErrDraftState):
		s.replyError(f.ReqID, ErrCodeDraftState, "this draft is no longer waiting: sent, discarded, expired or ended with its connection")
		return
	case errors.Is(err, store.ErrSendNotAllowed):
		s.replyError(f.ReqID, ErrCodeSendNotAllowed, "this draft's connection may not send right now")
		return
	case errors.Is(err, store.ErrDraftMismatch):
		s.replyError(f.ReqID, ErrCodeBadRequest, "device_id and chat must be the draft's")
		return
	case err != nil:
		s.log.Error("could not take a draft", "draft", draft, "error", err)
		s.replyError(f.ReqID, ErrCodeInternal, "could not take the draft")
		return
	}

	sendCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), draftSendTimeout)
	defer cancel()
	sent, err := s.srv.sendText(sendCtx, s.log, t, req.Body, opts, req.ID)
	if err != nil {
		// Taken and not known to have left: uncertain, for the person to
		// check. Nothing retries it.
		s.finishDraft(sendCtx, t, claimed, store.DraftOutcome{Status: store.OutboundUncertain, Edited: req.MCPEdited, At: time.Now()})
		s.replyError(f.ReqID, ErrCodeInternal, err.Error())
		return
	}
	result := s.srv.archiveSent(sendCtx, s.log, t, sent)
	outcome := store.DraftOutcome{Status: store.OutboundSent, WAID: sent.ID, Edited: req.MCPEdited, At: sent.Timestamp}
	if uid, err := uuid.Parse(result.UID); err == nil {
		outcome.MessageUID = &uid
	}
	if outcome.At.IsZero() {
		outcome.At = time.Now()
	}
	s.finishDraft(sendCtx, t, claimed, outcome)
	s.reply(TypeSendResult, f.ReqID, result)
}

// finishDraft records how a confirmed draft's send ended.
func (s *session) finishDraft(ctx context.Context, t sendTarget, claimed store.ClaimedDraft, out store.DraftOutcome) {
	if err := s.srv.cfg.MCP.FinishDraft(ctx, t.tenant, claimed.ID, out); err != nil {
		s.log.Error("could not record how a draft's send ended", "draft", claimed.ID, "connection", claimed.ConnectionID, "error", err)
	}
	s.log.Info("mcp_draft_decided", "connection", claimed.ConnectionID, "draft", claimed.ID, "device", t.deviceID,
		"status", out.Status, "edited", out.Edited, "archived", out.MessageUID != nil)
}

// Text is one text for SendText.
type Text struct {
	Tenant, Device uuid.UUID
	// Chat is the JID it goes to.
	Chat string
	Body string
}

// TextSent is a text that left: WhatsApp's id and time, and the archived
// message's uid, nil when archiving failed.
type TextSent struct {
	WAID      string
	Timestamp time.Time
	UID       *uuid.UUID
}

var (
	// ErrNotSent is SendText refusing before anything reached WhatsApp.
	ErrNotSent = errors.New("wsapi: nothing was sent")
	// ErrDeviceOffline is a number that is not connected right now.
	ErrDeviceOffline = fmt.Errorf("%w: the number is not connected", ErrNotSent)
	// ErrCapturePaused is a workspace whose archive capture is paused: a
	// send it could not archive is not made, as for a frame.
	ErrCapturePaused = fmt.Errorf("%w: archive capture is paused", ErrNotSent)
)

// SendText sends a text as a number for a path that is not a frame: an
// assistant connection's own-chat note, which the MCP send route has checked
// (docs/mcp-enclave.md §17.7). It is the frame's send with nothing a frame
// may add: the chat's timer, and no preview, mention, forwarding, view-once,
// quote or chosen id. The message is archived as any outbound one; a failure
// to archive leaves TextSent.UID nil, and the message has left all the same.
// An error that is not ErrNotSent is a send that may or may not have left.
func (s *Server) SendText(ctx context.Context, in Text) (TextSent, error) {
	if s.cfg.Storage != nil {
		if err := s.cfg.Storage.Check(ctx, in.Tenant); errors.Is(err, store.ErrStoragePaused) {
			return TextSent{}, ErrCapturePaused
		} else if err != nil {
			return TextSent{}, fmt.Errorf("%w: %w", ErrNotSent, err)
		}
	}
	dev, running := s.device(in.Device.String())
	if !running {
		return TextSent{}, ErrDeviceOffline
	}
	chat, err := types.ParseJID(in.Chat)
	if err != nil {
		return TextSent{}, fmt.Errorf("%w: %w", ErrNotSent, err)
	}
	t := sendTarget{tenant: in.Tenant, device: dev, deviceID: in.Device, chat: chat}
	sent, err := s.sendText(ctx, s.log, t, in.Body, send.Options{}, "")
	if err != nil {
		return TextSent{}, err
	}
	out := TextSent{WAID: sent.ID, Timestamp: sent.Timestamp}
	if uid, err := uuid.Parse(s.archiveSent(ctx, s.log, t, sent).UID); err == nil {
		out.UID = &uid
	}
	return out, nil
}
