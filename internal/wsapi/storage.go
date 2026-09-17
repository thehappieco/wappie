package wsapi

import (
	"context"
	"errors"
	"github.com/google/uuid"
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
		s.replyError(f.ReqID, "storage_paused", "Archive capture is paused. Free storage or increase capacity, then explicitly resume capture.")
	} else {
		s.replyError(f.ReqID, ErrCodeInternal, "Could not verify storage capacity")
	}
	return false
}
