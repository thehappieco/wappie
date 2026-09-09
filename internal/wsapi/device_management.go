package wsapi

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"whatserver2/internal/wa"
)

func (s *session) handleDeviceRename(ctx context.Context, f Frame) {
	var req DeviceRename
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, "invalid device name")
		return
	}
	_, resolved, ok := s.resolveDevice(ctx, f, req.DeviceID)
	if !ok {
		return
	}
	req.DeviceID = resolved.String()
	req.Label = strings.TrimSpace(req.Label)
	if req.Label == "" || len([]rune(req.Label)) > 100 {
		s.replyError(f.ReqID, ErrCodeBadRequest, "device name must contain 1 to 100 characters")
		return
	}
	if err := s.srv.cfg.Devices.Rename(ctx, s.tenantID(), req.DeviceID, req.Label); err != nil {
		s.replyError(f.ReqID, ErrCodeInternal, "could not rename the device")
		return
	}
	s.handleDeviceInfo(ctx, f)
}

func (s *session) handleDeviceStart(ctx context.Context, f Frame) {
	var ref DeviceRef
	if err := json.Unmarshal(f.Payload, &ref); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, "invalid device")
		return
	}
	_, resolved, ok := s.resolveDevice(ctx, f, ref.DeviceID)
	if !ok {
		return
	}
	ref.DeviceID = resolved.String()
	tenant := s.tenantID()
	dev, err := s.srv.cfg.Devices.Get(ctx, tenant, ref.DeviceID)
	if err != nil {
		s.replyError(f.ReqID, ErrCodeNotFound, "no such device")
		return
	}
	if !dev.Identity.Known() {
		s.replyError(f.ReqID, ErrCodeConflict, "this number must be linked first")
		return
	}
	if s.srv.cfg.Registry == nil {
		s.replyError(f.ReqID, ErrCodeInternal, "WhatsApp connection is unavailable")
		return
	}
	if dev.Status == wa.StatusLoggedOut || dev.Status == wa.StatusBanned {
		s.replyError(f.ReqID, ErrCodeConflict, "the WhatsApp session is no longer available")
		return
	}
	if err = s.srv.cfg.Devices.SetPaused(ctx, tenant, ref.DeviceID, false); err != nil {
		s.replyError(f.ReqID, ErrCodeInternal, "could not resume the device")
		return
	}
	_, err = s.srv.cfg.Registry.StartExisting(ctx, tenant, dev.ID, wa.ReceiptPolicy{Mode: dev.ReceiptMode, Recorder: s.recordReceipt}, dev.Identity.PN, dev.Identity.LID)
	if err != nil && !errors.Is(err, wa.ErrAlreadyRunning) {
		restoreCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if pauseErr := s.srv.cfg.Devices.SetPaused(restoreCtx, tenant, dev.ID, true); pauseErr != nil {
			s.log.Error("could not preserve pause after failed resume", "device", dev.ID, "error", pauseErr)
		}
		if errors.Is(err, wa.ErrNoSession) {
			if statusErr := s.srv.cfg.Devices.SetStatus(restoreCtx, tenant, dev.ID, wa.StatusLoggedOut, "session missing"); statusErr != nil {
				s.log.Error("could not record missing WhatsApp session", "device", dev.ID, "error", statusErr)
			}
		}
		s.replyError(f.ReqID, ErrCodeConflict, "could not resume this connection: "+err.Error())
		return
	}
	// Report the persisted state; connection may still be completing.
	current, err := s.srv.cfg.Devices.Get(ctx, tenant, dev.ID)
	if err != nil || current.Paused {
		s.srv.cfg.Registry.Stop(context.WithoutCancel(ctx), dev.ID)
		s.replyError(f.ReqID, ErrCodeConflict, "this connection was paused or removed while resuming")
		return
	}
	s.reply(TypeDeviceStatus, f.ReqID, DeviceStatus{DeviceID: dev.ID, Status: string(current.Status)})
}
