package wsapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"whatserver2/internal/bus"
	"whatserver2/internal/ingest"
	"whatserver2/internal/store"
)

// replayPage is how many rows one replay query fetches.
//
// Bounded so a client resuming from a long absence does not pull a hundred
// thousand rows into memory on either side; the loop below pages until it
// reaches the watermark.
const replayPage = 500

// handleSubscribe streams the archive: everything since a cursor, then live.
//
// The ordering here is the whole point and it is easy to get wrong. Subscribing
// first and reading history second delivers the overlap twice; the reverse
// loses whatever arrives in between. The subscription therefore starts in
// replay mode — registered, capturing, but withholding — and only hands over
// once the history read has reached a watermark it can name.
func (s *session) handleSubscribe(ctx context.Context, f Frame) {
	var req Subscribe
	if len(f.Payload) > 0 {
		if err := json.Unmarshal(f.Payload, &req); err != nil {
			s.replyError(f.ReqID, ErrCodeBadRequest, "malformed subscribe: "+err.Error())
			return
		}
	}
	tenant, err := uuid.Parse(s.tenantID())
	if err != nil {
		s.replyError(f.ReqID, ErrCodeInternal, "bad tenant")
		return
	}

	filter := bus.Filter{}
	allowed, err := s.grantDevices(ctx)
	if err != nil {
		s.replyError(f.ReqID, ErrCodeInternal, "could not check device access")
		return
	}
	if allowed != nil {
		if len(allowed) == 0 {
			s.replyError(f.ReqID, ErrCodeNotAuthorized, "no devices have been granted to this account")
			return
		}
		filter.Devices = allowed
	}
	if len(req.Devices) > 0 {
		filter.Devices = make(map[uuid.UUID]struct{}, len(req.Devices))
		for _, d := range req.Devices {
			id, err := uuid.Parse(d)
			if err != nil {
				s.replyError(f.ReqID, ErrCodeBadRequest, fmt.Sprintf("device %q is not an id", d))
				return
			}
			filter.Devices[id] = struct{}{}
			if allowed != nil {
				if _, ok := allowed[id]; !ok {
					s.replyError(f.ReqID, ErrCodeNotAuthorized, "this device has not been granted to your account")
					return
				}
			}
		}
	}

	s.subMu.Lock()
	if s.sub != nil {
		s.subMu.Unlock()
		s.replyError(f.ReqID, ErrCodeConflict, "this connection is already subscribed")
		return
	}
	sub := s.srv.cfg.Bus.Subscribe(tenant, filter)
	s.sub = sub
	s.subMu.Unlock()

	// The watermark is read before any row is sent. Sequences are allocated
	// under a row lock held to commit, so everything at or below it is already
	// visible — which is what makes it safe to discard buffered events up to
	// this number without losing one still in flight.
	watermark, err := s.srv.cfg.Messages.MaxSeq(ctx, tenant)
	if err != nil {
		s.log.Error("could not read the cursor", "error", err)
		sub.EndReplay(0)
		s.replyError(f.ReqID, ErrCodeInternal, "could not start the stream")
		return
	}

	if req.LiveOnly {
		sub.EndReplay(watermark)
		s.reply(TypeReplayEnd, f.ReqID, ReplayEnd{LastSeq: watermark})
		go s.pump(ctx, sub, f.ReqID)
		return
	}

	s.reply(TypeReplayBegin, f.ReqID, ReplayBegin{ThroughSeq: watermark})

	sent, last := 0, req.SinceSeq
	for last < watermark {
		rows, err := s.srv.cfg.Messages.Since(ctx, tenant, last, replayPage)
		if err != nil {
			s.log.Error("replay read failed", "since", last, "error", err)
			break
		}
		acks, truncated, err := s.receiptsSince(ctx, tenant, last, replayPage)
		if err != nil {
			s.log.Error("receipt replay read failed", "since", last, "error", err)
			break
		}
		if len(rows) == 0 && len(acks) == 0 {
			break
		}

		// Messages and acknowledgements share one sequence, so replay is a
		// merge of two streams the client must receive in order. The horizon is
		// how far this round can be trusted: a full page of either stream means
		// higher sequences exist that were not fetched, and emitting the other
		// stream past that point would deliver events out of order.
		horizon := watermark
		if len(rows) == replayPage {
			horizon = min(horizon, rows[len(rows)-1].Seq)
		}
		if truncated && len(acks) > 0 {
			horizon = min(horizon, acks[len(acks)-1].Seq)
		}

		mergeReplay(rows, acks, horizon,
			func(r store.Row) {
				if len(filter.Devices) > 0 {
					if _, ok := filter.Devices[r.DeviceID]; !ok {
						return
					}
				}
				s.reply(TypeMessage, f.ReqID, sealedMessage(r))
				sent++
			},
			func(b store.ReceiptBatch) {
				if len(filter.Devices) > 0 {
					if _, ok := filter.Devices[b.DeviceID]; !ok {
						return
					}
				}
				s.reply(TypeReceipt, f.ReqID, receiptEvent(b))
				sent++
			})

		if horizon <= last {
			break
		}
		last = horizon
	}

	// Hand over under the bus's lock: buffered events at or below the
	// watermark are dropped as already sent, the rest are released in order.
	sub.EndReplay(last)
	s.reply(TypeReplayEnd, f.ReqID, ReplayEnd{LastSeq: last, Count: sent})

	go s.pump(ctx, sub, f.ReqID)
}

// mergeReplay emits two sequence-ordered streams as one, stopping at horizon.
//
// Messages and acknowledgements share the tenant cursor, so a client must
// receive them interleaved in sequence order — a receipt delivered before the
// message it acknowledges is a client drawing a tick on a message it has not
// been told about.
//
// horizon is how far this round may be trusted. Either read can have been cut
// short by its page limit, and emitting the other stream past that point would
// deliver a sequence the client then treats as covered when it is not.
//
// Pulled out of the loop above so the ordering can be tested without a
// database, a websocket and a thousand rows to reach the paging boundary.
func mergeReplay(rows []store.Row, acks []store.ReceiptBatch, horizon int64,
	onMessage func(store.Row), onReceipt func(store.ReceiptBatch)) int {
	sent, i, j := 0, 0, 0
	for i < len(rows) || j < len(acks) {
		nextIsMessage := j >= len(acks) || (i < len(rows) && rows[i].Seq < acks[j].Seq)
		if nextIsMessage {
			if rows[i].Seq > horizon {
				i = len(rows)
				continue
			}
			onMessage(rows[i])
			sent++
			i++
			continue
		}
		if acks[j].Seq > horizon {
			j = len(acks)
			continue
		}
		onReceipt(acks[j])
		sent++
		j++
	}
	return sent
}

// pump forwards live events until the subscription or the connection ends.
func (s *session) pump(ctx context.Context, sub *bus.Subscription, reqID string) {
	tenant, err := uuid.Parse(s.tenantID())
	if err != nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-sub.Events():
			if !ok {
				return
			}
			// A lagged subscription means the client's view is no longer
			// continuous. Telling it where to resume is better than closing
			// the connection, which is what v1 did to a slow reader.
			if lagged, from, dropped := sub.Lagged(); lagged {
				sub.ClearLag()
				s.reply(TypeLag, reqID, Lag{FromSeq: from, Dropped: dropped})
			}
			s.deliver(ctx, tenant, reqID, ev)
		}
	}
}

// deliver loads the stored row and sends it.
//
// Reading back what was just written, rather than rendering from the event,
// is deliberate. It costs one indexed lookup and it guarantees a live message
// and a replayed one are byte-identical, because they come from the same query.
// v1 rendered separately on each path and the two drifted until an edited
// message looked different depending on how it arrived.
func (s *session) deliver(ctx context.Context, tenant uuid.UUID, reqID string, ev ingest.Event) {
	// Presence has no row to read back, and that is what makes it different
	// from everything else here. Every other class is delivered by fetching
	// what was stored, so the live frame and the replayed frame are byte for
	// byte the same; this one carries its own content because there is nothing
	// on disk and never will be — it is true for a few seconds and then it is
	// not.
	if ev.Class == ingest.ClassPresence {
		if ev.Presence == nil {
			return
		}
		s.reply(TypePresence, reqID, PresenceEvent{
			DeviceID:  ev.DeviceID.String(),
			ChatKey:   ev.Presence.ChatKey,
			SenderKey: ev.Presence.SenderKey,
			SenderLID: ev.Presence.SenderLID,
			SenderPN:  ev.Presence.SenderPN,
			State:     ev.Presence.State,
			Media:     ev.Presence.Media,
		})
		return
	}

	// A change to the conversation rather than to anything in it. Like
	// presence, it carries its own content: there is no row to read back that
	// would say what changed, only a chat row whose current state says nothing
	// about which field moved.
	if ev.Class == ingest.ClassChat {
		if ev.Chat == nil {
			return
		}
		s.reply(TypeChatUpdate, reqID, ChatUpdateEvent{
			DeviceID:  ev.DeviceID.String(),
			ChatKey:   ev.Chat.ChatKey,
			Unread:    ev.Chat.Unread,
			Ephemeral: ev.Chat.Ephemeral,
		})
		return
	}

	if ev.Class == ingest.ClassReceipt {
		if s.srv.cfg.Receipts == nil {
			return
		}
		batch, err := s.srv.cfg.Receipts.Batch(ctx, tenant, ev.Seq)
		if err != nil {
			s.log.Error("could not load a published receipt", "seq", ev.Seq, "error", err)
			return
		}
		s.reply(TypeReceipt, reqID, receiptEvent(batch))
		return
	}

	row, err := s.srv.cfg.Messages.Get(ctx, tenant, ev.UID)
	if err != nil {
		s.log.Error("could not load a published message", "uid", ev.UID, "error", err)
		return
	}
	s.reply(TypeMessage, reqID, sealedMessage(row))
}

func sealedMessage(r store.Row) SealedMessage {
	m := SealedMessage{
		UID: r.UID.String(), Seq: r.Seq,
		DeviceID: r.DeviceID.String(),
		WAID:     r.WAID, ChatKey: r.ChatKey,
		SenderKey: r.SenderKey, SenderLID: r.SenderLID, SenderPN: r.SenderPN,
		TS: r.TS, IsFromMe: r.IsFromMe, IsGroup: r.IsGroup,
		Kind: string(r.Kind), Type: string(r.Type), Unsupported: r.Unsupported,
		TargetWAID: r.TargetWAID, TargetRel: string(r.TargetRel), ReplyTo: r.ReplyTo,
		IsForwarded: r.IsForwarded, ForwardingScore: r.ForwardingScore,
		Expiration: r.Expiration, ExpiresAt: r.ExpiresAt,
		ViewOnce: r.ViewOnce, Ephemeral: r.Ephemeral,
		Source:        string(r.Source),
		ContentKeyID:  r.ContentKeyID,
		BodySealed:    r.BodySealed,
		PayloadSealed: r.PayloadSealed,
	}
	if r.TargetUID != nil {
		m.TargetUID = r.TargetUID.String()
	}
	if r.Media != nil {
		m.Media = &SealedMedia{
			MediaType: r.Media.MediaType, MimeType: r.Media.MimeType,
			FileLength: r.Media.FileLength, FileEncSHA256: r.Media.FileEncSHA256,
			Width: r.Media.Width, Height: r.Media.Height, Seconds: r.Media.Seconds,
			Waveform: r.Media.Waveform, IsGIF: r.Media.IsGIF,
			MediaKeySealed: r.Media.MediaKeySealed,
			ThumbSealed:    r.Media.ThumbSealed,
			FileNameSealed: r.Media.FileNameSealed,
			DownloadStatus: r.Media.DownloadStatus,
		}
	}
	return m
}

// handleKeysGet returns sealed content keys.
//
// Safe to serve to any authenticated client of the tenant precisely because the
// server cannot open them. Withholding them would protect nothing and would
// make the archive unreadable to its owner.
func (s *session) handleKeysGet(ctx context.Context, f Frame) {
	var req KeysRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	if len(req.IDs) == 0 || len(req.IDs) > 500 {
		s.replyError(f.ReqID, ErrCodeBadRequest, "ask for between 1 and 500 keys")
		return
	}
	tenant, device, ok := s.resolveDevice(ctx, f, req.DeviceID)
	if !ok {
		return
	}

	out := make([]SealedKey, 0, len(req.IDs))
	for _, id := range req.IDs {
		sealed, err := s.srv.cfg.Keys2.SealedContentKey(ctx, tenant, device, id)
		if err != nil {
			// A missing key is not fatal to the batch: a client asking for a
			// key that was retired by a rotation should get the rest.
			s.log.Debug("content key unavailable", "id", id, "error", err)
			continue
		}
		out = append(out, SealedKey{ID: id, Sealed: sealed})
	}
	s.reply(TypeKeys, f.ReqID, Keys{DeviceID: device.String(), Keys: out})
}

// chatListLimit is how many conversations one listing carries.
//
// Raised from 500 after a group somebody had just joined turned out to be
// invisible. A conversation exists from the moment the account is in the group,
// with no message and therefore no timestamp, so every one of them sorts behind
// every conversation that has ever been spoken in — on the archive this was
// found on, 1029 of them behind 592. The cut fell in between, and the answer
// to "where is the group I joined" was that it had been listed off the end.
//
// Sized against what that archive actually holds: 1621 conversations whose
// sealed names come to 44 kB, well inside the 1 MiB frame limit. It is a
// ceiling, not a design — an account with several thousand conversations needs
// this paged, and that is a different shape from the one listing this is.
const chatListLimit = 3000

func (s *session) handleChatsList(ctx context.Context, f Frame) {
	var ref DeviceRef
	if err := json.Unmarshal(f.Payload, &ref); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	tenant, device, ok := s.resolveDevice(ctx, f, ref.DeviceID)
	if !ok {
		return
	}
	rows, err := s.srv.cfg.Messages.Chats(ctx, tenant, device, chatListLimit)
	if err != nil {
		s.log.Error("could not list chats", "error", err)
		s.replyError(f.ReqID, ErrCodeInternal, "could not list chats")
		return
	}
	out := make([]ChatSummary, 0, len(rows))
	for _, c := range rows {
		out = append(out, ChatSummary{
			UID:     c.UID.String(),
			ChatKey: c.ChatKey, ChatLID: c.ChatLID, ChatPN: c.ChatPN, IsGroup: c.IsGroup,
			LastSeq: c.LastSeq, LastTS: c.LastTS,
			CreatedAt: c.CreatedAt, GroupCreatedAt: c.GroupCreatedAt,
			LastKind: c.LastKind, LastType: c.LastType,
			Unread: c.Unread, Archived: c.Archived, Pinned: c.Pinned,
			NameSealed: c.NameSealed, NameKeyID: c.NameKeyID, Keys: c.Keys,
			Audience: audience(c), Ephemeral: c.Ephemeral,
			LastUID: lastUID(c), LastBodySealed: c.LastBodySealed,
			LastBodyKeyID: c.LastBodyKeyID,
		})
	}
	s.reply(TypeChats, f.ReqID, Chats{DeviceID: device.String(), Chats: out})
}

// lastUID renders the preview row's identity, and nothing when there is none.
// A zero uuid on the wire would look like a real row a client could ask for.
func lastUID(c store.ChatRow) string {
	if c.LastUID == uuid.Nil {
		return ""
	}
	return c.LastUID.String()
}

func (s *session) handleChatPage(ctx context.Context, f Frame) {
	var req ChatPageRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	if req.ChatKey == "" {
		s.replyError(f.ReqID, ErrCodeBadRequest, "chat_key is required")
		return
	}
	if req.Limit <= 0 || req.Limit > 200 {
		req.Limit = 50
	}
	tenant, device, ok := s.resolveDevice(ctx, f, req.DeviceID)
	if !ok {
		return
	}

	before := store.Cursor{Seq: req.BeforeSeq}
	if req.BeforeTS != nil {
		before.TS = *req.BeforeTS
	}

	// Every key that names this conversation, not only the one clicked. The
	// same contact addressed by phone number for years and by LID since is
	// stored under both, and paging one of them silently hides the other half
	// of what was said.
	keys, err := s.srv.cfg.Messages.SiblingKeys(ctx, tenant, device, req.ChatKey)
	if err != nil {
		s.log.Warn("could not resolve sibling chat keys", "error", err)
		keys = []string{req.ChatKey}
	}

	// One extra row, to answer "is there more" without a second query.
	rows, err := s.srv.cfg.Messages.Page(ctx, tenant, device, keys, before, req.Limit+1)
	if err != nil {
		s.log.Error("could not page a chat", "error", err)
		s.replyError(f.ReqID, ErrCodeInternal, "could not read the conversation")
		return
	}
	hasMore := len(rows) > req.Limit
	if hasMore {
		rows = rows[len(rows)-req.Limit:]
	}
	msgs := make([]SealedMessage, 0, len(rows))
	for _, r := range rows {
		msgs = append(msgs, sealedMessage(r))
	}
	page := Page{ChatKey: req.ChatKey, Messages: msgs, HasMore: hasMore}
	page.Receipts = s.acksFor(ctx, tenant, device, rows)
	// The cursor comes from the page as trimmed, not from the extra row that
	// only answered "is there more" -- otherwise the next page would start one
	// message too far back and repeat it.
	if next := store.Before(rows); !next.TS.IsZero() {
		at := next.TS
		page.NextTS, page.NextSeq = &at, next.Seq
	}
	s.reply(TypePage, f.ReqID, page)
}

// deviceNotFoundHint explains a device lookup failure in terms of what this
// API key can reach.
func (s *session) deviceNotFoundHint(ctx context.Context, tenant uuid.UUID, deviceID string) string {
	devices, err := s.srv.cfg.Devices.List(ctx, tenant.String())
	if err != nil || len(devices) == 0 {
		return fmt.Sprintf("no device %s. This API key belongs to tenant %s, which has no "+
			"devices at all — it is probably a key for the wrong tenant. "+
			"Run \"whatserverd tenants\" to see which one has your devices.", deviceID, tenant)
	}
	allowed, err := s.actionDevices(ctx, store.ActionView)
	if err != nil {
		return "device unavailable"
	}
	ids := make([]string, 0, len(devices))
	for _, d := range devices {
		if _, ok := allowed[uuid.MustParse(d.ID)]; ok {
			ids = append(ids, d.ID)
		}
	}
	return fmt.Sprintf("no device %s. This API key reaches tenant %s, whose devices are: %s",
		deviceID, tenant, strings.Join(ids, ", "))
}

// resolveDevice validates that a device belongs to this session's tenant.
//
// Row-level security answers a cross-tenant lookup with "not found", so this
// authorises and validates in one step.
func (s *session) resolveDevice(ctx context.Context, f Frame, deviceID string) (uuid.UUID, uuid.UUID, bool) {
	tenant, err := uuid.Parse(s.tenantID())
	if err != nil {
		s.replyError(f.ReqID, ErrCodeInternal, "bad tenant")
		return uuid.Nil, uuid.Nil, false
	}
	if deviceID == "" {
		s.replyError(f.ReqID, ErrCodeBadRequest, "device_id is required")
		return uuid.Nil, uuid.Nil, false
	}
	// A unique prefix is accepted, because the listing shows a short form and
	// an identifier you cannot type back is a trap.
	dev, err := s.srv.cfg.Devices.Resolve(ctx, tenant.String(), deviceID)
	if err != nil {
		if errors.Is(err, store.ErrAmbiguous) {
			s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
			return uuid.Nil, uuid.Nil, false
		}
		// Row-level security cannot distinguish "does not exist" from
		// "belongs to another tenant", and it should not. But a key issued for
		// the wrong tenant is by far the likeliest cause, so the message says
		// what this key *can* see rather than leaving the caller to guess.
		s.replyError(f.ReqID, ErrCodeNotFound, s.deviceNotFoundHint(ctx, tenant, deviceID))
		return uuid.Nil, uuid.Nil, false
	}
	device, err := uuid.Parse(dev.ID)
	if err != nil {
		s.replyError(f.ReqID, ErrCodeInternal, "stored device id is unusable")
		return uuid.Nil, uuid.Nil, false
	}
	if !s.authorizeDevice(ctx, f, device, frameAction(f.Type)) {
		return uuid.Nil, uuid.Nil, false
	}
	return tenant, device, true
}

// acksFor folds the acknowledgements for the messages of one page.
//
// Only the message rows, never the control ones. A bubble is keyed on the root
// message id, so acks attached to an edit or a reaction would be looked up by
// nobody — and anybody who "fixed" that by folding them into the parent would
// count twice every reader who acknowledged both versions.
//
// Degrades rather than fails. A history frame without its readers is not the
// thing that was asked for and errors; a page without ticks is still a page,
// and refusing to draw a conversation because the receipt table was slow would
// be a worse answer than drawing it with one grey tick.
func (s *session) acksFor(ctx context.Context, tenant, device uuid.UUID,
	rows []store.Row) []MessageAcks {
	if s.srv.cfg.Receipts == nil || len(rows) == 0 {
		return nil
	}
	ids := make([]string, 0, len(rows))
	for _, r := range rows {
		if r.Kind.IsControl() {
			continue
		}
		ids = append(ids, r.WAID)
	}
	folded, err := s.srv.cfg.Receipts.AcksForPage(ctx, tenant, device, ids)
	if err != nil {
		s.log.Warn("could not read receipts for a page", "error", err)
		return nil
	}
	out := make([]MessageAcks, 0, len(folded))
	for _, r := range rows {
		a, ok := folded[r.WAID]
		if !ok {
			continue
		}
		out = append(out, MessageAcks{
			WAID:      r.WAID,
			Delivered: a.Delivered, Read: a.Read, Played: a.Played,
			DeliveredAt: a.DeliveredAt, ReadAt: a.ReadAt, PlayedAt: a.PlayedAt,
			ReadByUs: a.ReadByUs, Retrying: a.Retrying, Failed: a.Failed,
		})
	}
	return out
}

// audience is the denominator a tick needs, or zero for "unknown".
func audience(c store.ChatRow) int32 {
	if c.ParticipantCount == nil {
		return 0
	}
	return *c.ParticipantCount
}
