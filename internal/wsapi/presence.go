package wsapi

import (
	"context"
	"encoding/json"

	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/wa"
)

// handleChatPresence tells a conversation we are typing, or have stopped.
//
// Answered with nothing but the absence of an error. There is no receipt for a
// typing notification and nothing to report about one: it is true for a moment
// and the moment passes.
func (s *session) handleChatPresence(ctx context.Context, f Frame) {
	var req ChatPresenceRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	t, ok := s.resolveSend(ctx, f, req.DeviceID, req.Chat)
	if !ok {
		return
	}
	state := types.ChatPresence(req.State)
	if state != types.ChatPresenceComposing && state != types.ChatPresencePaused {
		s.replyError(f.ReqID, ErrCodeBadRequest,
			`state must be "composing" or "paused"`)
		return
	}
	media := types.ChatPresenceMedia(req.Media)
	if media != "" && media != types.ChatPresenceMediaAudio {
		s.replyError(f.ReqID, ErrCodeBadRequest, `media must be "audio" or empty`)
		return
	}

	// Through the policy, like every other outbound signal. In the quiet
	// posture this sends nothing and says so to the metrics, which is the only
	// place the absence of a network call is visible.
	if err := t.device.Policy().ChatPresence(ctx, t.device.Client(), t.chat, state, media); err != nil {
		s.log.Debug("could not send a typing notification", "error", err)
		s.replyError(f.ReqID, ErrCodeConflict, err.Error())
		return
	}
	s.reply(TypeSendResult, f.ReqID, SendResult{ID: req.State})
}

// handleDeviceMode changes what a device tells the other side, while it runs.
//
// Persisted and applied in one call. Persisted because the mode is applied on
// connect and a device that came back loud because nobody wrote the switch down
// would be a surprising way to stop being invisible; applied because the point
// of a switch is that it takes effect when it is flipped.
func (s *session) handleDeviceMode(ctx context.Context, f Frame) {
	var req DeviceModeRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	mode, err := wa.ParseReceiptMode(req.ReceiptMode)
	if err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	tenant, device, ok := s.resolveDevice(ctx, f, req.DeviceID)
	if !ok {
		return
	}

	if err := s.srv.cfg.Devices.SetReceiptMode(ctx, tenant.String(), device.String(), mode); err != nil {
		s.log.Error("could not record a receipt mode", "error", err)
		s.replyError(f.ReqID, ErrCodeInternal, "could not record the mode")
		return
	}
	// A device that is not running has nothing to tell WhatsApp yet; the mode
	// is what its next connect will apply.
	if dev, running := s.srv.cfg.Registry.Get(device.String()); running {
		if err := dev.SetReceiptMode(ctx, mode); err != nil {
			s.log.Warn("could not apply a receipt mode", "error", err)
		}
	}
	// Answered with the device as it now is, so the client draws from the
	// server's view of the switch rather than from its own optimism.
	dev, err := s.srv.cfg.Devices.Get(ctx, tenant.String(), device.String())
	if err != nil {
		s.replyError(f.ReqID, ErrCodeNotFound, "no such device")
		return
	}
	s.reply(TypeDeviceDetail, f.ReqID, DeviceDetail{
		Device: s.toDeviceInfo(dev), Epoch: dev.Epoch,
	})
}
