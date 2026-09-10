package wsapi

import (
	"context"
	"encoding/json"
	"time"

	"go.mau.fi/whatsmeow/types"
	"whatserver2/internal/wa/send"
)

func (s *session) handleEventCreate(ctx context.Context, f Frame) {
	var req EventCreateRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, "invalid event request; dates need RFC3339 timestamps with a time zone")
		return
	}
	event, err := send.ValidateEvent(send.EventDraft{
		Name: req.Name, Description: req.Description, StartTime: req.StartTime, EndTime: req.EndTime,
		LocationName: req.LocationName, JoinLink: req.JoinLink,
	}, time.Now())
	if err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	target, ok := s.resolveSend(ctx, f, req.DeviceID, req.Chat)
	if !ok {
		return
	}
	if target.chat.User == "" || (target.chat.Server != types.GroupServer && target.chat.Server != types.DefaultUserServer && target.chat.Server != types.HiddenUserServer) {
		s.replyError(f.ReqID, ErrCodeBadRequest, "events need an individual chat or a group")
		return
	}
	opts := send.Options{}
	s.applyChatTimer(ctx, target, &opts)
	sent, err := send.SendEvent(ctx, target.device.Client(), target.chat, req.ID, event, opts)
	if err != nil {
		s.replyError(f.ReqID, ErrCodeConflict, err.Error())
		return
	}
	s.archive(ctx, target, sent, f)
}
