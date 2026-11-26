package wsapi

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/membership"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
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
	// The preview reads the stored freshness only; the move itself asks
	// for a fresh document (handleDeviceTransfer).
	if !s.fresh(ctx, f.ReqID, TypeDeviceTransferPreview, person(who, membership.Stored)) {
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
// pause, unless someone paused the number meanwhile, and the supervisor
// resumes it. No platform call runs inside the move's transaction (the
// plan's D13): once the preview finds the move possible, and before
// anything changes, the mover's document is asked for, always with a fresh
// GET (README 7.1), and must list them as the team's only owner (decision
// 0043; freshness.go).
//
// The move holds its workspace from before its pause to its end
// (store.HoldMove): a relink meanwhile is workspace_busy, in any process
// (DS56). A number a relink pairs is not moved: item_busy with the seconds
// left in WhatsApp's window, before anything is paused and with the relink
// left running (relinkPairing). The hold comes first, so a relink that
// starts after the look sees the hold and ends itself.
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
	// Only a move the preview, a read, finds possible asks the platform:
	// a frame for a number that is missing or cannot move costs no call.
	// The move decides it again under its locks.
	if !s.freshMover(ctx, f.ReqID, source, who.userID) {
		return
	}
	// The sessions that see the number now, the Team's owners and admins
	// who manage it by role, are told it is gone once it moved; nobody else
	// can be reading it.
	viewers := s.srv.viewersOf(ctx, source, device)
	releaseHold, err := s.srv.cfg.Devices.HoldMove(ctx, source, device)
	if err != nil {
		s.transferError(f.ReqID, err)
		return
	}
	// Each answer below goes once the hold is gone (release is idempotent),
	// so a client that reads it finds the workspace free; the defer is for
	// a panic.
	defer releaseHold()
	if wait, pairing, err := s.srv.relinkPairing(ctx, source, device); err != nil || pairing {
		releaseHold()
		if err != nil {
			s.transferError(f.ReqID, err)
			return
		}
		s.reply(TypeError, f.ReqID, Error{Code: ErrCodeItemBusy, RetryAfter: int(math.Ceil(wait.Seconds())),
			Message: "Este número está sendo vinculado de novo. Tente mover quando o vínculo terminar."})
		return
	}
	pause, err := s.srv.cfg.Devices.PauseForMove(ctx, source, device)
	if err != nil {
		releaseHold()
		s.transferError(f.ReqID, err)
		return
	}
	// Past the look, no relink pairs the number: one that starts now sees
	// the hold and ends itself workspace_busy. What this still cancels is
	// a new number's pairing, and a relink caught between its own hold
	// and its look at the move's, whose end is workspace_busy as well.
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
	// On every path, the move's or not: a pipeline an outbound send rebuilt
	// meanwhile carries the source's scope.
	if s.srv.cfg.Router != nil {
		s.srv.cfg.Router.Forget(device)
	}
	if err != nil {
		gone, moved := s.settleFailedTransfer(ctx, source, target, device, pause)
		releaseHold()
		if gone {
			if moved {
				// The move committed and only its answer was lost.
				s.srv.exportLedger(context.WithoutCancel(ctx), source)
				s.srv.RevalidateAccess()
				s.tellMoved(viewers, device)
			}
			s.transferError(f.ReqID, store.ErrNotFound)
			return
		}
		s.transferError(f.ReqID, err)
		return
	}
	s.log.Info("device moved to Personal", "device", device, "source", source, "destination", target, "by", who.userID,
		"assistants_ended", len(out.AssistantsEnded), "keys_narrowed", len(out.KeysNarrowed))
	// The move's moved_out line, so a restore from before it never puts
	// the number back in its team.
	s.srv.exportLedger(context.WithoutCancel(ctx), source)
	releaseHold()
	s.reply(TypeDeviceTransferred, f.ReqID, out)
	s.srv.RevalidateAccess()
	s.tellMoved(viewers, device)
}

// relinkPairing reports whether a relink pairs a logged-out number now,
// and the wait it leaves: in this process, any pairing of the number in
// the registry (the sheet's relink), with the seconds left in WhatsApp's
// window, or a console relink (Relinks); in any process, the relink's own
// hold (store.RelinkLook), WhatsApp's whole window. A device lock alone
// is no relink: a process keeps one for a number logged out while it held
// it, until something stops that client, and the move then meets it in
// the store (TransferDenied). A number that is not logged out is paired by
// no relink: a new number's pairing is cancelled, as before.
func (s *Server) relinkPairing(ctx context.Context, tenant, device uuid.UUID) (time.Duration, bool, error) {
	loggedOut, relinking, err := s.cfg.Devices.RelinkLook(ctx, tenant, device)
	if err != nil || !loggedOut {
		return 0, false, err
	}
	if since, ok := s.cfg.Registry.PairingSince(device.String()); ok {
		return max(time.Second, min(wa.PairWindow, time.Until(since.Add(wa.RelinkWindow)))), true, nil
	}
	if s.cfg.Relinks.Has(device) || relinking {
		return wa.PairWindow, true, nil
	}
	return 0, false, nil
}

// tellMoved tells the other sessions that saw the number that it moved.
func (s *session) tellMoved(viewers []*session, device uuid.UUID) {
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

// settleFailedTransfer takes back the pause this handler made before a move
// that did not happen, on a context of its own: a closing socket must not
// leave the number's sync silently off. The store leaves the number paused
// when someone paused it since (a stop that came during the move found it
// paused and changed nothing else). It reports whether the number is no
// longer in the workspace, and whether that is because the move had in fact
// committed and only its answer was lost: the number is then in the
// destination, where it stays paused, as a move leaves it.
func (s *session) settleFailedTransfer(ctx context.Context, source, target, device uuid.UUID, pause store.MovePause) (gone, moved bool) {
	undoCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	undone, err := s.srv.cfg.Devices.UndoMovePause(undoCtx, source, device, pause)
	if err == nil && !pause.Changed {
		// Paused before the move: nothing to undo, but the move may still
		// have committed.
		_, err = s.srv.cfg.Devices.Get(undoCtx, source.String(), device.String())
	}
	switch {
	case errors.Is(err, store.ErrNotFound):
		if _, err := s.srv.cfg.Devices.Get(undoCtx, target.String(), device.String()); err == nil {
			s.log.Warn("a transfer failed after its commit; the number stays paused in Personal", "device", device)
			return true, true
		}
		return true, false
	case err != nil:
		s.log.Error("could not undo a failed transfer's pause", "device", device, "error", err)
	case pause.Changed && !undone:
		s.log.Info("a failed transfer left its pause alone: the number was paused or resumed meanwhile", "device", device)
	}
	return false, false
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
