package wsapi

import (
	"context"
	"encoding/json"

	"go.mau.fi/whatsmeow/types"
	"whatserver2/internal/domain"
	"whatserver2/internal/wa/send"
)

func (s *session) handleLocationSend(ctx context.Context, f Frame) {
	var req LocationSendRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil || req.Latitude == nil || req.Longitude == nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, "a location needs numeric lat and lon coordinates")
		return
	}
	location, err := send.ValidateLocation(domain.Location{Latitude: *req.Latitude, Longitude: *req.Longitude, Name: req.Name, Address: req.Address, AccuracyMeters: req.AccuracyMeters})
	if err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	target, ok := s.resolveSend(ctx, f, req.DeviceID, req.Chat)
	if !ok {
		return
	}
	if target.chat.Server != types.GroupServer && target.chat.Server != types.DefaultUserServer && target.chat.Server != types.HiddenUserServer {
		s.replyError(f.ReqID, ErrCodeBadRequest, "locations need an individual chat or a group")
		return
	}
	opts := send.Options{}
	s.applyChatTimer(ctx, target, &opts)
	sent, err := send.SendLocation(ctx, target.device.Client(), target.chat, req.ID, location, opts)
	if err != nil {
		s.replyError(f.ReqID, ErrCodeConflict, err.Error())
		return
	}
	s.archive(ctx, target, sent, f)
}
