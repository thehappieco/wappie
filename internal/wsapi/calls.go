package wsapi

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/calling"
	"whatserver2/internal/store"
)

const (
	TypeCallsList        = "calls.list"
	TypeCallStart        = "call.start"
	TypeCallAnswer       = "call.answer"
	TypeCallReject       = "call.reject"
	TypeCallHangup       = "call.hangup"
	TypeCallMedia        = "call.media"
	TypeCallInvite       = "call.invite"
	TypeCallsListResult  = "calls.list.result"
	TypeCallResult       = "call.result"
	TypeCallMediaResult  = "call.media.result"
	TypeCallInviteResult = "call.invite.result"
)

type CallsListRequest struct {
	DeviceID string `json:"device_id"`
}

type CallStartRequest struct {
	DeviceID string `json:"device_id"`
	Chat     string `json:"chat"`
	Video    bool   `json:"video"`
}

type CallRequest struct {
	DeviceID string `json:"device_id"`
	CallID   string `json:"call_id"`
}

type CallInviteRequest struct {
	DeviceID     string   `json:"device_id"`
	CallID       string   `json:"call_id"`
	Participants []string `json:"participants"`
}

type CallsListResult struct {
	Calls     []calling.Snapshot `json:"calls"`
	Available bool               `json:"available"`
}

type CallMediaResult struct {
	Ticket string `json:"ticket"`
	Path   string `json:"path"`
}

// A connection owns its calls; client_id and login credentials can be shared
// between tabs and must never let one tab take another tab's media channel.
func (s *session) initCallOwner() string {
	s.callMu.Lock()
	defer s.callMu.Unlock()
	if s.callsReleased {
		return ""
	}
	if s.callOwner == "" {
		s.callOwner = uuid.NewString()
		if s.srv.cfg.Calls != nil {
			s.srv.cfg.Calls.RegisterOwner(s.callOwner)
		}
	}
	return s.callOwner
}

func (s *session) releaseCallOwner() {
	s.callMu.Lock()
	defer s.callMu.Unlock()
	if s.callsReleased {
		return
	}
	s.callsReleased = true
	owner := s.callOwner
	if owner != "" && s.srv.cfg.Calls != nil {
		s.srv.cfg.Calls.ReleaseOwner(owner)
	}
}

// Even listing incoming calls requires send permission: a read-only archive
// token must not learn about or gain control over a live conversation.
func (s *session) resolveCallDevice(ctx context.Context, f Frame, deviceID string) (string, string, string, bool) {
	if !s.requireScope(f.ReqID, store.ScopeSend) {
		return "", "", "", false
	}
	if s.srv.cfg.Devices == nil {
		s.replyError(f.ReqID, ErrCodeInternal, "devices are not configured")
		return "", "", "", false
	}
	tenant, device, ok := s.resolveDevice(ctx, f, deviceID)
	if !ok {
		return "", "", "", false
	}
	owner := s.initCallOwner()
	if owner == "" || ctx.Err() != nil {
		return "", "", "", false
	}
	return tenant.String(), device.String(), owner, true
}

func (s *session) handleCallsList(ctx context.Context, f Frame) {
	var req CallsListRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, "invalid calls request")
		return
	}
	tenant, device, owner, ok := s.resolveCallDevice(ctx, f, req.DeviceID)
	if !ok {
		return
	}
	result := CallsListResult{Calls: []calling.Snapshot{}}
	if s.srv.cfg.Calls != nil {
		result.Available = s.srv.cfg.Calls.Attached(tenant, device)
		result.Calls = s.srv.cfg.Calls.List(tenant, device, owner)
		if result.Calls == nil {
			result.Calls = []calling.Snapshot{}
		}
	}
	s.reply(TypeCallsListResult, f.ReqID, result)
}

func callPeer(raw string) (string, error) {
	jid, err := types.ParseJID(strings.TrimSpace(raw))
	if err != nil || jid.User == "" || len(jid.User) > 20 || (jid.Server != types.DefaultUserServer && jid.Server != types.HiddenUserServer) {
		return "", calling.ErrInvalid
	}
	for _, digit := range jid.User {
		if digit < '0' || digit > '9' {
			return "", calling.ErrInvalid
		}
	}
	return jid.ToNonAD().String(), nil
}

func (s *session) handleCallStart(ctx context.Context, f Frame) {
	var req CallStartRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, "invalid call request")
		return
	}
	peer, err := callPeer(req.Chat)
	if err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, "calls are available only for individual WhatsApp accounts")
		return
	}
	tenant, device, owner, ok := s.resolveCallDevice(ctx, f, req.DeviceID)
	if !ok || !s.requireCalling(f.ReqID) {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	result, err := s.srv.cfg.Calls.Start(ctx, tenant, device, owner, peer, req.Video)
	if err != nil {
		s.replyCallError(f.ReqID, err)
		return
	}
	s.reply(TypeCallResult, f.ReqID, result)
}

func (s *session) handleCallInvite(ctx context.Context, f Frame) {
	var req CallInviteRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil || req.CallID == "" || strings.TrimSpace(req.CallID) != req.CallID || len(req.CallID) > 256 || len(req.Participants) < 1 || len(req.Participants) > 7 {
		s.replyError(f.ReqID, ErrCodeBadRequest, "a valid call_id and one to seven individual participants are required")
		return
	}
	// Validate the entire batch before any invitation can reach WhatsApp.
	for i, raw := range req.Participants {
		peer, err := callPeer(raw)
		if err != nil {
			s.replyError(f.ReqID, ErrCodeBadRequest, "calls are available only for individual WhatsApp accounts")
			return
		}
		req.Participants[i] = peer
	}
	tenant, device, owner, ok := s.resolveCallDevice(ctx, f, req.DeviceID)
	if !ok || !s.requireCalling(f.ReqID) {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	result, err := s.srv.cfg.Calls.Invite(ctx, tenant, device, owner, req.CallID, req.Participants)
	if err != nil {
		s.replyCallError(f.ReqID, err)
		return
	}
	s.reply(TypeCallInviteResult, f.ReqID, result)
}

func (s *session) handleCallAction(ctx context.Context, f Frame) {
	var req CallRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, "invalid call request")
		return
	}
	if req.CallID == "" || strings.TrimSpace(req.CallID) != req.CallID || len(req.CallID) > 256 {
		s.replyError(f.ReqID, ErrCodeBadRequest, "a valid call_id is required")
		return
	}
	tenant, device, owner, ok := s.resolveCallDevice(ctx, f, req.DeviceID)
	if !ok || !s.requireCalling(f.ReqID) {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var result any
	var err error
	switch f.Type {
	case TypeCallAnswer:
		result, err = s.srv.cfg.Calls.Answer(ctx, tenant, device, owner, req.CallID)
	case TypeCallReject:
		err = s.srv.cfg.Calls.Reject(ctx, tenant, device, owner, req.CallID)
	case TypeCallHangup:
		err = s.srv.cfg.Calls.Hangup(ctx, tenant, device, owner, req.CallID)
	case TypeCallMedia:
		var ticket string
		ticket, err = s.srv.cfg.Calls.MediaTicket(tenant, device, owner, req.CallID)
		result = CallMediaResult{Ticket: ticket, Path: "/v1/calls/media"}
	default:
		err = calling.ErrInvalid
	}
	if err != nil {
		s.replyCallError(f.ReqID, err)
		return
	}
	if f.Type == TypeCallMedia {
		s.reply(TypeCallMediaResult, f.ReqID, result)
		return
	}
	s.reply(TypeCallResult, f.ReqID, result)
}

func (s *session) requireCalling(reqID string) bool {
	if s.srv.cfg.Calls != nil {
		return true
	}
	s.replyCallError(reqID, calling.ErrUnavailable)
	return false
}

func (s *session) replyCallError(reqID string, err error) {
	switch {
	case errors.Is(err, calling.ErrInvalid):
		s.replyError(reqID, ErrCodeBadRequest, "invalid call request")
	case errors.Is(err, calling.ErrNotFound):
		s.replyError(reqID, ErrCodeNotFound, "this call no longer exists")
	case errors.Is(err, calling.ErrUnavailable):
		s.replyError(reqID, ErrCodeConflict, "WhatsApp calling is unavailable for this device")
	case errors.Is(err, calling.ErrConflict):
		s.replyError(reqID, ErrCodeConflict, "this call is already in use or its state has changed")
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		s.replyError(reqID, ErrCodeConflict, "the call operation was interrupted")
	default:
		s.log.Warn("WhatsApp call operation failed", "error", err)
		s.replyError(reqID, ErrCodeInternal, "could not complete the call operation")
	}
}
