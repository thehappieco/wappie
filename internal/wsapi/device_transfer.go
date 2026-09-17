package wsapi

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"time"
	"whatserver2/internal/store"
)

const (
	TypeDeviceTransferPreview = "device.transfer.preview"
	TypeDeviceTransfer        = "device.transfer"
	TypeDeviceTransferred     = "device.transferred"
)

type DeviceTransferRequest struct {
	DeviceID          string `json:"device_id"`
	Confirm           string `json:"confirm"`
	TargetWorkspaceID string `json:"target_workspace_id"`
}

func (s *session) handleDeviceTransferPreview(ctx context.Context, f Frame) {
	who, ok := s.requireAdmin(f.ReqID)
	if !ok {
		return
	}
	var req DeviceRef
	if json.Unmarshal(f.Payload, &req) != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, "Número inválido.")
		return
	}
	device, err := uuid.Parse(req.DeviceID)
	if err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, "Número inválido.")
		return
	}
	out, err := s.srv.cfg.Devices.PreviewPersonalTransfer(ctx, uuid.MustParse(s.tenantID()), who.userID, device)
	if err != nil {
		s.transferError(f.ReqID, err)
		return
	}
	s.reply(TypeDeviceTransferPreview, f.ReqID, out)
}

func (s *session) handleDeviceTransfer(ctx context.Context, f Frame) {
	who, ok := s.requireAdmin(f.ReqID)
	if !ok {
		return
	}
	var req DeviceTransferRequest
	if json.Unmarshal(f.Payload, &req) != nil || req.Confirm != req.DeviceID {
		s.replyError(f.ReqID, ErrCodeBadRequest, "Confirme o número que deseja mover.")
		return
	}
	device, err := uuid.Parse(req.DeviceID)
	if err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, "Número inválido.")
		return
	}
	target, err := uuid.Parse(req.TargetWorkspaceID)
	if err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, "Destino inválido.")
		return
	}
	source := uuid.MustParse(s.tenantID())
	out, err := s.srv.cfg.Devices.PreviewPersonalTransfer(ctx, source, who.userID, device)
	if err != nil {
		s.transferError(f.ReqID, err)
		return
	}
	if !out.Eligible || out.TargetWorkspaceID != target.String() {
		s.replyError(f.ReqID, ErrCodeConflict, out.Reason)
		return
	}
	if err = s.srv.cfg.Devices.SetPaused(ctx, source.String(), device.String(), true); err != nil {
		s.transferError(f.ReqID, err)
		return
	}
	s.srv.cancelDevicePairing(source.String(), device.String())
	if s.srv.cfg.Registry != nil {
		s.srv.cfg.Registry.Stop(ctx, device.String())
	}
	// The store fences stale workers by current device ownership. Cached crypto
	// pipelines must be rebuilt with the destination's storage scope on resume.
	if s.srv.cfg.Router != nil {
		s.srv.cfg.Router.Forget(device)
	}
	moveCtx, cancel := context.WithTimeout(ctx, 115*time.Second)
	defer cancel()
	out, err = s.srv.cfg.Devices.TransferPersonal(moveCtx, source, who.userID, device, target)
	if err != nil {
		s.transferError(f.ReqID, err)
		return
	}
	if s.srv.cfg.Router != nil {
		s.srv.cfg.Router.Forget(device)
	}
	s.log.Info("device moved to Personal", "device", device, "source", source, "destination", target, "by", who.userID)
	s.reply(TypeDeviceTransferred, f.ReqID, out)
	s.srv.RevalidateAccess()
}
func (s *session) transferError(reqID string, err error) {
	var denied *store.TransferDenied
	switch {
	case errors.As(err, &denied):
		s.replyError(reqID, ErrCodeConflict, denied.Reason)
	case errors.Is(err, store.ErrNotFound):
		s.replyError(reqID, ErrCodeNotFound, "Este número não está neste workspace. Atualize a lista.")
	default:
		s.log.Error("device transfer failed", "error", err)
		s.replyError(reqID, ErrCodeConflict, "Não foi possível mover o número. Ele permanece no workspace de origem. Atualize a lista e tente novamente.")
	}
}
