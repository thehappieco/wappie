package wsapi

import (
	"context"
	"errors"
	"math"

	"github.com/google/uuid"

	"whatserver2/internal/relink"
	"whatserver2/internal/store"
)

// handleRelink is the pair frame's relink branch: a logged-out number
// linked again with a new QR into the same device (decision 0057), kept
// only for the number's own WhatsApp account.
//
// The request is {"device_id", "relink": true, "method": "qr"}; method may
// be left out. The answers on the request's id are pair.qr for each QR,
// then pair.success once the number names the new link, or one error with
// a code of the contract's 14.9 (relink.Code*), a fixed English message,
// and retry_after with item_busy. A relink never sends pair.code or
// pair.timeout.
func (s *session) handleRelink(ctx context.Context, f Frame, req PairRequest) {
	switch {
	case req.Method != "" && req.Method != "qr":
		s.replyError(f.ReqID, ErrCodeBadRequest, "a relink pairs by QR only")
		return
	case req.Resume || req.Phone != "" || req.DisplayName != "" || req.Label != "" || req.ReceiptMode != "" ||
		len(req.ArchivePublicKey) > 0 || len(req.Grants) > 0 || req.Orphan:
		s.replyError(f.ReqID, ErrCodeBadRequest, "a relink keeps the number as it is: send device_id, relink and method only")
		return
	}
	device, err := uuid.Parse(req.DeviceID)
	if err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, "device_id is not a device id")
		return
	}

	// Who: a signed-in person first, before anything a key could pass; an
	// owner or admin; a recent sign-in; fresh memberships in a team.
	who := s.actor()
	if !who.person {
		s.replyError(f.ReqID, ErrCodeNotAuthorized, "linking a number again needs a signed-in owner or admin")
		return
	}
	if _, ok := s.requireAdmin(f.ReqID); !ok {
		return
	}
	if !s.stepUpRecent(ctx, f.ReqID, who) {
		return
	}
	if !s.freshPairing(ctx, f.ReqID, nil) {
		return
	}

	svc := s.srv.cfg.Relink
	if svc == nil {
		s.replyError(f.ReqID, ErrCodeInternal, "WhatsApp connection is unavailable")
		return
	}
	tenant, err := uuid.Parse(s.tenantID())
	if err != nil {
		s.replyError(f.ReqID, ErrCodeInternal, "bad tenant")
		return
	}
	target, err := svc.Check(ctx, tenant, device)
	if s.relinkRefused(f.ReqID, err) {
		return
	}
	sess, err := svc.Start(ctx, target, relink.Actor{Kind: "person", ID: who.userID})
	if s.relinkRefused(f.ReqID, err) {
		return
	}

	id := device.String()
	s.pairMu.Lock()
	s.pairings[id] = sess
	s.pairMu.Unlock()
	defer func() {
		s.pairMu.Lock()
		if s.pairings[id] == sess {
			delete(s.pairings, id)
		}
		s.pairMu.Unlock()
	}()

	for evt := range sess.Events() {
		s.reply(TypePairQR, f.ReqID, PairQR{DeviceID: id, Code: evt.Code, Expires: evt.Expires})
	}
	if s.relinkRefused(f.ReqID, sess.Result()) {
		return
	}
	s.reply(TypePairSuccess, f.ReqID, PairResult{DeviceID: id})
}

// relinkRefused answers a relink's error, if there is one, and reports
// whether it did. A refusal goes with its code and fixed message; nothing
// of the account, the JIDs or the QR ever reaches the frame.
func (s *session) relinkRefused(reqID string, err error) bool {
	if err == nil {
		return false
	}
	var r *relink.Refusal
	switch {
	case errors.As(err, &r):
		e := Error{Code: r.Code, Message: r.Message}
		if r.RetryAfter > 0 {
			e.RetryAfter = int(math.Ceil(r.RetryAfter.Seconds()))
		}
		s.reply(TypeError, reqID, e)
	case errors.Is(err, store.ErrNotFound):
		s.replyError(reqID, ErrCodeNotFound, "no such device")
	default:
		s.log.Error("a relink failed", "error", err)
		s.replyError(reqID, ErrCodeInternal, "could not link the number again")
	}
	return true
}
