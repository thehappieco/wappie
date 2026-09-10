package wsapi

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/media"
	"whatserver2/internal/store"
)

// handleHistory answers message.history: the whole life of one message.
//
// This is the read the product exists for. Everything it returns is still
// sealed — the versions, the deleted text, the reaction emoji — and the server
// assembles only the structure around them, which it builds from routing
// columns it can read. A client opens the bodies with keys this process has
// never held.
func (s *session) handleHistory(ctx context.Context, f Frame) {
	var req HistoryRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	if s.srv.cfg.Receipts == nil {
		s.replyError(f.ReqID, ErrCodeInternal, "receipts are not configured on this server")
		return
	}

	tenant, device, chatKey, waID, ok := s.locateMessage(ctx, f, req)
	if !ok {
		return
	}

	h, err := s.srv.cfg.Messages.History(ctx, tenant, device, chatKey, waID, s.srv.cfg.Receipts)
	if errors.Is(err, pgx.ErrNoRows) {
		s.replyError(f.ReqID, ErrCodeNotFound,
			"no message "+waID+" in "+chatKey+". Control rows may exist for it, but the "+
				"message itself was never stored — usual while a backfill is still running")
		return
	}
	if err != nil {
		s.log.Error("could not assemble a message history",
			"chat", chatKey, "message", waID, "error", err)
		s.replyError(f.ReqID, ErrCodeInternal, "could not read the history")
		return
	}
	s.reply(TypeHistoryFrame, f.ReqID, historyFrame(h))
}

// locateMessage resolves a request to a device, a chat and a message id.
//
// Two ways in. A uid is self-describing — the row names its own device and chat
// — so a client that already holds a message frame passes only that. A human
// reading a log has a chat and a WhatsApp id instead, and then the device has
// to be named because the same id can exist under two paired devices.
func (s *session) locateMessage(ctx context.Context, f Frame, req HistoryRequest) (
	tenant, device uuid.UUID, chatKey, waID string, ok bool) {
	if req.UID != "" {
		tenant, err := uuid.Parse(s.tenantID())
		if err != nil {
			s.replyError(f.ReqID, ErrCodeInternal, "bad tenant")
			return uuid.Nil, uuid.Nil, "", "", false
		}
		uid, err := uuid.Parse(req.UID)
		if err != nil {
			s.replyError(f.ReqID, ErrCodeBadRequest, "uid is not an id: "+err.Error())
			return uuid.Nil, uuid.Nil, "", "", false
		}
		row, err := s.srv.cfg.Messages.Get(ctx, tenant, uid)
		if err != nil {
			// Row-level security answers a cross-tenant lookup with no rows,
			// so this is both "unknown" and "not yours" and should stay
			// indistinguishable.
			s.replyError(f.ReqID, ErrCodeNotFound, "no message with uid "+req.UID)
			return uuid.Nil, uuid.Nil, "", "", false
		}
		if !s.authorizeDevice(ctx, f, row.DeviceID, store.ActionRead) {
			return uuid.Nil, uuid.Nil, "", "", false
		}
		return tenant, row.DeviceID, row.ChatKey, row.WAID, true
	}

	if req.ChatKey == "" || req.WAID == "" {
		s.replyError(f.ReqID, ErrCodeBadRequest,
			"give either uid, or chat_key with wa_id and device_id")
		return uuid.Nil, uuid.Nil, "", "", false
	}
	tenant, device, ok = s.resolveDevice(ctx, f, req.DeviceID)
	if !ok {
		return uuid.Nil, uuid.Nil, "", "", false
	}
	return tenant, device, req.ChatKey, req.WAID, true
}

// handleMessageGet returns one message by uid.
func (s *session) handleMessageGet(ctx context.Context, f Frame) {
	var req MessageGetRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	tenant, err := uuid.Parse(s.tenantID())
	if err != nil {
		s.replyError(f.ReqID, ErrCodeInternal, "bad tenant")
		return
	}
	uid, err := uuid.Parse(req.UID)
	if err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, "uid is not an id: "+err.Error())
		return
	}
	row, err := s.srv.cfg.Messages.Get(ctx, tenant, uid)
	if err != nil {
		// Row level security answers a cross-tenant lookup with no rows, so
		// "unknown" and "not yours" are the same answer and should stay that
		// way.
		s.replyError(f.ReqID, ErrCodeNotFound, "no message with uid "+req.UID)
		return
	}
	if !s.authorizeDevice(ctx, f, row.DeviceID, store.ActionRead) {
		return
	}
	s.reply(TypeMessageFrame, f.ReqID, sealedMessage(row))
}

func historyFrame(h store.MessageHistory) History {
	out := History{
		DeviceID: h.DeviceID.String(),
		ChatKey:  h.ChatKey,
		WAID:     h.WAID,
		Versions: make([]MessageVersion, 0, len(h.Versions)),
	}
	for _, v := range h.Versions {
		out.Versions = append(out.Versions, MessageVersion{
			Revision: v.Revision,
			Message:  sealedMessage(v.Row),
			From:     v.From,
			Until:    v.Until,
		})
	}
	if h.Deletion != nil {
		out.Deletion = &MessageDeletion{
			Message:  sealedMessage(h.Deletion.Row),
			ByAuthor: h.Deletion.ByAuthor,
			ByAdmin:  h.Deletion.ByAdmin,
			At:       h.Deletion.At,
		}
	}
	for _, r := range h.Reactions {
		out.Reactions = append(out.Reactions, MessageReaction{
			Message:    sealedMessage(r.Row),
			Superseded: r.Superseded,
			Revoked:    r.Revoked,
			RevokedAt:  r.RevokedAt,
		})
	}
	for _, r := range h.Readers {
		devices := make([]ReaderDevice, 0, len(r.Devices))
		for _, d := range r.Devices {
			devices = append(devices, ReaderDevice{
				Key: d.Key, Agent: d.Agent, Device: d.Device,
				Delivered: d.Delivered, Read: d.Read, Played: d.Played,
				SawRevision:       d.SawRevision,
				ConfirmedRevision: d.ConfirmedRevision,
				Confirmed:         d.Confirmed,
				Revisions:         readerRevisions(d.Revisions),
			})
		}
		out.Readers = append(out.Readers, MessageReader{
			Key: r.Key, LID: r.LID, PN: r.PN, IsFromMe: r.IsFromMe,
			Delivered: r.Delivered, Read: r.Read, Played: r.Played,
			SawRevision:       r.SawRevision,
			ConfirmedRevision: r.ConfirmedRevision,
			Confirmed:         r.Confirmed,
			ReadDevice:        r.ReadDevice,
			Devices:           devices,
			Revisions:         readerRevisions(r.Revisions),
		})
	}
	return out
}

func readerRevisions(in []store.ReaderRevision) []ReaderRevision {
	if len(in) == 0 {
		return nil
	}
	out := make([]ReaderRevision, 0, len(in))
	for _, r := range in {
		out = append(out, ReaderRevision{
			Revision: r.Revision, Delivered: r.Delivered,
			Read: r.Read, Played: r.Played, Confirmed: r.Confirmed,
			PlayedConfirmed: r.PlayedConfirmed,
		})
	}
	return out
}

// receiptEvent is the one place a stored acknowledgement becomes a frame.
//
// One place on purpose: the live path and the replay path both come through
// here, so the person a receipt is counted under cannot be derived differently
// by the two and leave a client counting the same reader twice depending on
// whether it was connected at the time.
func receiptEvent(b store.ReceiptBatch) ReceiptEvent {
	return ReceiptEvent{
		ReaderPerson: store.PersonKey(b.ReaderKey, b.ReaderLID),
		Seq:          b.Seq,
		DeviceID:     b.DeviceID.String(),
		ChatKey:      b.ChatKey,
		WAIDs:        b.WAIDs,

		ReaderKey: b.ReaderKey,
		ReaderLID: b.ReaderLID,
		ReaderPN:  b.ReaderPN,
		IsFromMe:  b.IsFromMe,

		Kind: string(b.Kind),
		TS:   b.TS,
	}
}

// receiptsSince reads a page of acknowledgements, tolerating a server with no
// receipt store wired.
func (s *session) receiptsSince(ctx context.Context, tenant uuid.UUID, since int64, limit int) (
	[]store.ReceiptBatch, bool, error) {
	if s.srv.cfg.Receipts == nil {
		return nil, false, nil
	}
	return s.srv.cfg.Receipts.Since(ctx, tenant, since, limit)
}

// handleMediaRetry asks a sender to upload an attachment again.
func (s *session) handleMediaRetry(ctx context.Context, f Frame) {
	var req MediaRetryRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	if s.srv.cfg.Retrier == nil {
		s.replyError(f.ReqID, ErrCodeInternal, "media retries are not configured on this server")
		return
	}
	tenant, device, ok := s.resolveDevice(ctx, f, req.DeviceID)
	if !ok {
		return
	}
	uid, err := uuid.Parse(req.UID)
	if err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, "uid is not an id: "+err.Error())
		return
	}
	if len(req.MediaKey) != 32 {
		s.replyError(f.ReqID, ErrCodeBadRequest,
			"media_key must be the 32 bytes from the message's sealed media key, "+
				"opened by you: this server cannot open its own copy")
		return
	}

	if err := s.srv.cfg.Retrier.Request(ctx, tenant, device, uid, req.MediaKey); err != nil {
		if errors.Is(err, media.ErrTooManyPending) {
			s.replyError(f.ReqID, ErrCodeRateLimited, err.Error())
			return
		}
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	s.reply(TypeRetryQueued, f.ReqID, MediaRetryQueued{UID: req.UID})
}

// handleExpiredMedia lists attachments whose url signature ran out.
func (s *session) handleExpiredMedia(ctx context.Context, f Frame) {
	var req ExpiredMediaRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	if s.srv.cfg.Media == nil {
		s.replyError(f.ReqID, ErrCodeInternal, "media is not configured on this server")
		return
	}
	tenant, device, ok := s.resolveDevice(ctx, f, req.DeviceID)
	if !ok {
		return
	}
	if req.Limit <= 0 || req.Limit > 1000 {
		req.Limit = 100
	}
	uids, err := s.srv.cfg.Media.Expired(ctx, tenant, device, req.Limit)
	if err != nil {
		s.log.Error("could not list expired media", "error", err)
		s.replyError(f.ReqID, ErrCodeInternal, "could not list expired attachments")
		return
	}
	out := make([]string, 0, len(uids))
	for _, id := range uids {
		out = append(out, id.String())
	}
	s.reply(TypeExpiredList, f.ReqID, ExpiredMedia{UIDs: out})
}

// handleBackfill asks WhatsApp for messages older than the archive holds.
//
// The answer does not come back on this connection. WhatsApp replies minutes
// later with an ON_DEMAND history sync, which is ingested exactly like a
// bootstrap and appears as new messages on the subscription — so this returns
// as soon as the request has left, and says what it anchored on rather than
// pretending to report a result it cannot have.
func (s *session) handleBackfill(ctx context.Context, f Frame) {
	var req BackfillRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	// Asks the phone to hand over more of its history: a change to what this
	// server holds, not a message, so it is above the send scope.
	if !s.requireScope(f.ReqID, store.ScopeFull) {
		return
	}
	t, ok := s.resolveSend(ctx, f, req.DeviceID, req.Chat)
	if !ok {
		return
	}
	if req.Count <= 0 || req.Count > 500 {
		req.Count = 50
	}

	oldest, err := s.srv.cfg.Messages.Oldest(ctx, t.tenant, t.deviceID, t.chat.String())
	if err != nil {
		s.replyError(f.ReqID, ErrCodeNotFound,
			"nothing is stored for that chat yet, so there is no point to anchor a "+
				"backfill on. Wait for a message, or re-pair to bring the sync")
		return
	}

	info := &types.MessageInfo{
		ID: oldest.WAID,
		MessageSource: types.MessageSource{
			Chat: t.chat, IsFromMe: oldest.IsFromMe, IsGroup: oldest.IsGroup,
		},
	}
	if oldest.TS != nil {
		info.Timestamp = *oldest.TS
	}
	if oldest.SenderKey != "" {
		if sender, err := types.ParseJID(oldest.SenderKey); err == nil {
			info.Sender = sender
		}
	}

	msg := t.device.Client().BuildHistorySyncRequest(info, req.Count)
	if msg == nil {
		s.replyError(f.ReqID, ErrCodeInternal, "could not build a history request")
		return
	}
	// A peer message: it goes to our own other devices, not into the chat.
	// Nobody on the other side sees anything.
	if _, err := t.device.Client().SendPeerMessage(ctx, msg); err != nil {
		s.replyError(f.ReqID, ErrCodeInternal, err.Error())
		return
	}
	s.reply(TypeBackfillSent, f.ReqID, BackfillSent{
		Chat: t.chat.String(), AnchorID: oldest.WAID, Count: req.Count,
	})
}
