package wsapi

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"

	"whatserver2/internal/relink"
	"whatserver2/internal/store"
)

// Authorize before contacting WhatsApp. Transactional archive guards also cover
// capture, direct clients and concurrent writes after this initial check.
func (s *session) allowStorageOperation(ctx context.Context, f Frame) bool {
	switch f.Type {
	case TypePair, TypeSendMedia, TypeSend, TypeEdit, TypeRevoke, TypeReact,
		TypePollVote, TypeMediaRetry, TypeBackfill, TypeChatTimer, TypeGroupJoin,
		TypeChatStart, TypeGroupCreate, TypeGroupParticipants, TypeGroupLeave,
		TypePollCreate, TypeLocationSend, TypeEventCreate, TypeReprojectPut,
		TypeDeviceStart, TypeCallStart, TypeCallInvite, TypeCallAnswer:
	default:
		return true
	}
	if s.srv.cfg.Storage == nil {
		return true
	}
	tenant, err := uuid.Parse(s.tenantID())
	if err == nil {
		err = s.srv.cfg.Storage.Check(ctx, tenant)
	}
	if err == nil {
		return true
	}
	if errors.Is(err, store.ErrStoragePaused) {
		if s.relinkDuringMove(ctx, f, tenant) {
			return false
		}
		s.replyError(f.ReqID, ErrCodeStoragePaused, "Archive sync is paused. Free storage or increase capacity, then explicitly resume sync.")
	} else {
		s.replyError(f.ReqID, ErrCodeInternal, "Could not verify storage capacity")
	}
	return false
}

// relinkDuringMove answers a relink's pair frame workspace_busy, and
// reports whether it did, while a move out of the workspace runs: the spec
// judges it before the storage pause (DS56), which this gate answers
// before the relink's own checks.
func (s *session) relinkDuringMove(ctx context.Context, f Frame, tenant uuid.UUID) bool {
	var req PairRequest
	if f.Type != TypePair || s.srv.cfg.Devices == nil || json.Unmarshal(f.Payload, &req) != nil || !req.Relink {
		return false
	}
	running, err := s.srv.cfg.Devices.MoveRunning(ctx, tenant)
	if err != nil || !running {
		return false
	}
	return s.relinkRefused(f.ReqID, relink.MoveBusy())
}
