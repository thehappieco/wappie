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

// handleDeviceTransfer moves a Team's number to its owner's Personal, only
// when nobody else has access to it (decision 0040): the preview's refusal
// answers others_have_access with who still has it, before anything is
// paused, and the store decides it again under its locks. Any error after
// the handler paused the number (that refusal from inside the move, a
// timeout, a deadlock) rolls the move back, so the handler undoes its own
// pause and the supervisor resumes the number. No platform call runs inside
// the move's transaction (the plan's D13): a later release asks for a fresh
// membership document before it, never inside.
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
		s.transferError(f.ReqID, &store.TransferDenied{Reason: out.Reason, Code: out.ReasonCode, Others: out.Others})
		return
	}
	dev, err := s.srv.cfg.Devices.Get(ctx, source.String(), device.String())
	if err != nil {
		s.transferError(f.ReqID, err)
		return
	}
	// The sessions that see the number now, the Team's owners and admins
	// who manage it by role, are told it is gone once it moved; nobody else
	// can be reading it.
	viewers := s.srv.viewersOf(ctx, source, device)
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
	out, err = s.srv.transfer(moveCtx, source, who.userID, device, target)
	if err != nil {
		if !dev.Paused {
			s.undoTransferPause(ctx, source, device)
		}
		s.transferError(f.ReqID, err)
		return
	}
	if s.srv.cfg.Router != nil {
		s.srv.cfg.Router.Forget(device)
	}
	s.log.Info("device moved to Personal", "device", device, "source", source, "destination", target, "by", who.userID,
		"assistants_ended", len(out.AssistantsEnded), "keys_narrowed", len(out.KeysNarrowed))
	s.reply(TypeDeviceTransferred, f.ReqID, out)
	s.srv.RevalidateAccess()
	for _, viewer := range viewers {
		if viewer != s {
			viewer.reply(TypeDeviceRemoved, "", DeviceRemoved{DeviceID: device.String(), Reason: DeviceRemovedMoved})
		}
	}
}

// transfer is the move itself: the store's, or a test's stand-in.
func (s *Server) transfer(ctx context.Context, source, actor, device, target uuid.UUID) (store.PersonalTransferPreview, error) {
	if s.cfg.transferHook != nil {
		return s.cfg.transferHook(ctx, source, actor, device, target)
	}
	return s.cfg.Devices.TransferPersonal(ctx, source, actor, device, target)
}

// undoTransferPause takes back the pause this handler made before a move
// that did not happen, on a context of its own: a closing socket must not
// leave the number's sync silently off. A move whose commit went through
// and only its answer was lost has left the workspace, so the row is not
// found here, and the number stays paused in Personal, as a move leaves it.
func (s *session) undoTransferPause(ctx context.Context, source, device uuid.UUID) {
	undoCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	err := s.srv.cfg.Devices.SetPaused(undoCtx, source.String(), device.String(), false)
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.log.Warn("a transfer failed after its commit; the number stays paused in Personal", "device", device)
	case err != nil:
		s.log.Error("could not undo a failed transfer's pause", "device", device, "error", err)
	}
}

func (s *session) transferError(reqID string, err error) {
	var denied *store.TransferDenied
	switch {
	case errors.As(err, &denied) && denied.Code == store.ReasonOthersHaveAccess:
		s.reply(TypeError, reqID, Error{Code: ErrCodeOthersHaveAccess, Message: denied.Reason, Others: denied.Others})
	case errors.As(err, &denied):
		s.replyError(reqID, ErrCodeConflict, denied.Reason)
	case errors.Is(err, store.ErrNotFound):
		s.replyError(reqID, ErrCodeNotFound, "Este número não está neste workspace. Atualize a lista.")
	default:
		s.log.Error("device transfer failed", "error", err)
		s.replyError(reqID, ErrCodeConflict, "Não foi possível mover o número. Ele permanece no workspace de origem. Atualize a lista e tente novamente.")
	}
}
