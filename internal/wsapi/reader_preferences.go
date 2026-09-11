package wsapi

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"whatserver2/internal/wa"
)

// readerPolicy gates actions from people without changing the shared device
// policy. Legacy service/CLI actions retain their explicit transport setting.
func (s *session) readerPolicy(ctx context.Context, f Frame, device *wa.Device) (wa.ReceiptPolicy, bool) {
	policy := device.Policy()
	if !s.actor().person {
		return policy, true
	}
	policy.Mode = wa.ModePassive
	accounts := s.accountStore()
	if accounts == nil {
		s.replyError(f.ReqID, ErrCodeInternal, "reader preferences are unavailable")
		return policy, false
	}
	mode, err := accounts.ReaderMode(ctx, uuid.MustParse(s.tenantID()), s.actor().userID, uuid.MustParse(device.ID()))
	if err != nil {
		s.replyError(f.ReqID, ErrCodeInternal, "could not read your reading preference")
		return policy, false
	}
	policy.Mode = mode
	return policy, true
}

func (s *session) handleReaderMode(ctx context.Context, f Frame) {
	if !s.actor().person || s.accountStore() == nil {
		s.replyError(f.ReqID, ErrCodeNotAuthorized, "a personal reading preference requires a user session")
		return
	}
	var req ReaderModeRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, "invalid reading preference")
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
	if err := s.accountStore().SetReaderMode(ctx, tenant, s.actor().userID, device, mode); err != nil {
		s.replyError(f.ReqID, ErrCodeNotAuthorized, "this reading preference requires active read access")
		return
	}
	result := ReaderModeRequest{DeviceID: device.String(), ReceiptMode: string(mode)}
	s.reply(TypeReaderMode, f.ReqID, result)
	// Keep the same person's other tabs consistent, without broadcasting their
	// personal choice to other workspace members.
	who := s.actor()
	s.srv.mu.RLock()
	others := make([]*session, 0, len(s.srv.sessions))
	for other := range s.srv.sessions {
		others = append(others, other)
	}
	s.srv.mu.RUnlock()
	for _, other := range others {
		actor := other.actor()
		if other != s && actor.person && actor.tenant == who.tenant && actor.userID == who.userID {
			other.reply(TypeReaderMode, "", result)
		}
	}
}
