package ingest

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.mau.fi/whatsmeow/proto/waHistorySync"
	"go.mau.fi/whatsmeow/proto/waWeb"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/domain"
	"whatserver2/internal/store"
	"whatserver2/internal/wa/normalize"
)

// historyQueueDepth is how many sync chunks may wait to be ingested.
//
// A chunk is a pointer to a protobuf already in memory, so queueing is cheap
// and the depth is about how far ingest may fall behind rather than about
// bytes. WhatsApp delivers a bootstrap in tens of chunks over minutes, so this
// is comfortable headroom.
const historyQueueDepth = 64

// historyChunk is one sync payload waiting to be stored.
type historyChunk struct {
	deviceID string
	info     DeviceInfo
	data     *waHistorySync.HistorySync
}

// handleHistorySync accepts a chunk and returns immediately.
//
// Returning immediately is the whole point. whatsmeow calls the event handler
// synchronously on the goroutine that reads the socket, so ingesting a
// ten-thousand message bootstrap inline would stop that device receiving
// anything — live messages, receipts, connection events — for as long as it
// took. The v1 server did exactly this and its authors concluded that history
// sync "made the client hang".
func (r *Router) handleHistorySync(ctx context.Context, deviceID string, evt *events.HistorySync, name string) {
	info, ok := r.cfg.Lookup(deviceID)
	if !ok {
		r.log.Warn("history sync for a device this process does not supervise", "device", deviceID)
		r.failed(name, "unknown_device")
		return
	}
	data := evt.Data
	if data == nil {
		r.ignored(name)
		return
	}

	syncType := data.GetSyncType()
	if !carriesMessages(syncType) && len(data.GetStatusV3Messages()) == 0 && !pushNameChunk(data) {
		// NON_BLOCKING_DATA is settings, and nothing else here carries
		// anything the archive keeps.
		r.ignored(fmt.Sprintf("%s/%s", name, syncType))
		return
	}

	chunk := historyChunk{deviceID: deviceID, info: info, data: data}
	select {
	case r.history <- chunk:
	case <-ctx.Done():
		return
	default:
		// The queue is full, which means ingest is genuinely behind rather
		// than momentarily busy. Blocking here stalls the device's event
		// stream, and dropping loses history that WhatsApp delivers once —
		// so it blocks, with a warning, because a delayed receipt is
		// recoverable and a lost conversation is not.
		r.log.Warn("the history queue is full; the device's events will wait",
			"device", deviceID, "depth", historyQueueDepth)
		select {
		case r.history <- chunk:
		case <-ctx.Done():
		}
	}
}

// RunHistory ingests queued sync chunks until the context ends.
//
// One worker, deliberately. Chunks of the same conversation arrive in order and
// ingesting them concurrently would have several transactions contending for
// the tenant's sequence counter, which serialises anyway — so the parallelism
// would buy contention rather than throughput.
func (r *Router) RunHistory(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case chunk := <-r.history:
			r.ingestChunk(ctx, chunk)
		}
	}
}

// ingestChunk stores one sync payload.
func (r *Router) ingestChunk(ctx context.Context, chunk historyChunk) {
	deviceUUID, err := uuid.Parse(chunk.deviceID)
	if err != nil {
		r.failed("HistorySync", "bad_device")
		return
	}
	pipe, err := r.pipelineFor(ctx, chunk.info.TenantID, deviceUUID)
	if err != nil {
		r.log.Error("cannot ingest history for this device",
			"tenant", chunk.info.TenantID, "device", chunk.deviceID, "error", err)
		r.failed("HistorySync", "no_pipeline")
		return
	}

	var stored, duplicate, skipped, failed int
	started := time.Now()

	// The names arrive in bulk here: a bootstrap names most of the people an
	// account has ever spoken to, in one payload. Without it a re-paired
	// archive shows hundreds of conversations as bare phone numbers.
	named := r.ingestPushNames(ctx, chunk)

	// Status updates arrive in their own field rather than as a conversation.
	//
	// Ingesting them keeps the two paths agreeing: a status broadcast received
	// live is stored as an ordinary message, so one arriving in a sync must be
	// too. Skipping them here would mean the same broadcast is in the archive
	// or not depending on whether this device happened to be connected when it
	// was posted — which is the class of divergence this pipeline exists to
	// prevent.
	if msgs := chunk.data.GetStatusV3Messages(); len(msgs) > 0 {
		s, d, k, e := r.ingestMessages(ctx, pipe, chunk, statusBroadcast, msgs)
		stored, duplicate, skipped, failed = stored+s, duplicate+d, skipped+k, failed+e
	}

	for _, conv := range chunk.data.GetConversations() {
		if ctx.Err() != nil {
			return
		}
		chat, err := types.ParseJID(conv.GetID())
		if err != nil {
			r.log.Warn("history conversation has an unusable id",
				"id", conv.GetID(), "error", err)
			failed++
			continue
		}

		r.storeChatMeta(ctx, pipe, chunk, deviceUUID, chat, conv)

		msgs := make([]*waWeb.WebMessageInfo, 0, len(conv.GetMessages()))
		for _, hm := range conv.GetMessages() {
			if web := hm.GetMessage(); web != nil {
				msgs = append(msgs, web)
			}
		}
		s, d, k, e := r.ingestMessages(ctx, pipe, chunk, chat, msgs)
		stored, duplicate, skipped, failed = stored+s, duplicate+d, skipped+k, failed+e
	}

	r.log.Info("history sync chunk ingested",
		"device", chunk.deviceID,
		"type", chunk.data.GetSyncType().String(),
		"chunk", chunk.data.GetChunkOrder(),
		"progress", chunk.data.GetProgress(),
		"conversations", len(chunk.data.GetConversations()),
		"stored", stored, "duplicate", duplicate, "skipped", skipped, "failed", failed,
		"names", named,
		"took", time.Since(started).Round(time.Millisecond))
	r.handled("HistorySync")
}

// statusBroadcast is the pseudo-chat status updates belong to.
var statusBroadcast = types.JID{User: "status", Server: types.BroadcastServer}

// ingestMessages normalises and stores a run of history messages.
func (r *Router) ingestMessages(ctx context.Context, pipe *Pipeline, chunk historyChunk,
	chat types.JID, msgs []*waWeb.WebMessageInfo) (stored, duplicate, skipped, failed int) {
	for _, web := range msgs {
		if ctx.Err() != nil {
			return
		}
		env, err := normalize.FromHistory(chat, web, normalize.Options{
			TenantID: chunk.info.TenantID.String(),
			DeviceID: chunk.deviceID,
			Own:      chunk.info.Own,
		})
		if errors.Is(err, normalize.ErrSkip) {
			skipped++
			continue
		}
		if err != nil {
			r.log.Debug("could not normalise a history message",
				"chat", chat, "error", err)
			failed++
			continue
		}

		res, err := pipe.Ingest(ctx, env)
		if err != nil {
			r.log.Error("could not store a history message",
				"chat", chat, "message", env.MessageID, "error", err)
			failed++
			continue
		}
		if res.Duplicate {
			duplicate++
			continue
		}
		stored++
		if r.cfg.Metrics != nil {
			r.cfg.Metrics.HistoryMessages.Inc()
		}
	}
	return stored, duplicate, skipped, failed
}

// storeChatMeta records what the sync says about a conversation.
//
// This is where chat names come from. Until now a group showed as a numeric id
// — the ugly state v1 was abandoned in — because nothing on the live path
// carries a name. The history sync does, and it is sealed like any other piece
// of content: for a direct chat it is a person's name.
func (r *Router) storeChatMeta(ctx context.Context, pipe *Pipeline, chunk historyChunk,
	device uuid.UUID, chat types.JID, conv *waHistorySync.Conversation) {
	addr := domain.AddressOf(chat)
	meta := store.ChatMeta{
		TenantID: chunk.info.TenantID,
		DeviceID: device,
		ChatKey:  chat.String(),
		ChatLID:  jidString(addr.LID),
		ChatPN:   jidString(addr.PN),
		IsGroup:  chat.Server == types.GroupServer,
	}

	if name := conv.GetName(); name != "" {
		sealed, keyID, err := pipe.SealChatName(ctx, store.ChatUID(device, chat.String()), name)
		if err != nil {
			// The messages matter more than the label. Losing the whole
			// conversation because its name could not be sealed would be the
			// wrong trade.
			r.log.Error("could not seal a chat name", "chat", chat, "error", err)
		} else {
			meta.NameSealed, meta.NameKeyID = sealed, keyID
		}
	}
	if v := conv.GetEphemeralExpiration(); v > 0 {
		//nolint:gosec // G115: a timer in seconds
		seconds := int32(min(v, 1<<31-1))
		meta.EphemeralExpiration = &seconds
	}
	// Present, not non-zero. A sync reporting zero is the phone saying the
	// conversation has been read, and treating that as "said nothing" leaves a
	// badge nothing can ever lower — which is most of why the number was
	// wrong.
	if conv.UnreadCount != nil {
		v := conv.GetUnreadCount()
		//nolint:gosec // G115: a count of unread messages
		unread := int32(min(v, 1<<31-1))
		meta.Unread = &unread
	}
	if conv.Archived != nil {
		archived := conv.GetArchived()
		meta.Archived = &archived
	}
	if conv.Pinned != nil {
		pinned := conv.GetPinned() > 0
		meta.Pinned = &pinned
	}
	if v := conv.GetMuteEndTime(); v > 0 && v < 1<<62 {
		//nolint:gosec // G115: bounded immediately above
		until := time.Unix(int64(v), 0)
		meta.MuteUntil = &until
	}

	if err := r.cfg.Messages.UpsertChatMeta(ctx, meta); err != nil {
		r.log.Error("could not record chat metadata", "chat", chat, "error", err)
	}
	r.ensureIdentity(ctx, chunk.info.TenantID, device, chat)
}

// ensureIdentity makes sure a chat has a row in contacts.
//
// Groups never get one otherwise: the contact cache whatsmeow keeps is people,
// and a group's name lives on the chat. But a group has a profile picture like
// anyone else, and the picture belongs with the identity rather than with the
// conversation — so the row exists to hang it on, carrying no name of its own.
func (r *Router) ensureIdentity(ctx context.Context, tenant, device uuid.UUID, chat types.JID) {
	if chat.Server != types.GroupServer {
		return
	}
	r.EnsureIdentity(ctx, tenant, device, chat)
}

// EnsureIdentity gives one identifier a contacts row, carrying no name.
//
// The row is what the picture worker walks, so an identifier with no row never
// gets a face however long it waits. Groups need it because whatsmeow's contact
// cache is people; a person needs it when they have only ever appeared as a LID
// on a message, which is exactly the case a reader hits when a conversation it
// cannot name appears in the sidebar.
//
// Deliberately not called during a bulk import. Writing a row for every
// identifier anything ever mentioned would fill the table with keys and no
// information; writing one for a key a reader explicitly asked about is the
// opposite — somebody is looking at it right now.
func (r *Router) EnsureIdentity(ctx context.Context, tenant, device uuid.UUID, jid types.JID) {
	if r.cfg.Contacts == nil || jid.IsEmpty() {
		return
	}
	key := jid.ToNonAD()
	addr := domain.AddressOf(key)
	if err := r.cfg.Contacts.Upsert(ctx, store.ContactName{
		TenantID: tenant, DeviceID: device,
		ContactKey: key.String(),
		ContactLID: jidString(addr.LID),
		ContactPN:  jidString(addr.PN),
		IsGroup:    key.Server == types.GroupServer,
	}); err != nil {
		r.log.Debug("could not record an identity", "contact", key, "error", err)
	}
}

// SeedGroupIdentities gives every group chat a contacts row, so the avatar
// worker reaches it.
//
// Runs at boot and is idempotent. Groups stored before this existed have no
// identity row and would otherwise never get a picture.
func (r *Router) SeedGroupIdentities(ctx context.Context, tenant, device uuid.UUID,
	chats []store.ChatRow) int {
	var n int
	for _, c := range chats {
		if !c.IsGroup {
			continue
		}
		jid, err := types.ParseJID(c.ChatKey)
		if err != nil {
			continue
		}
		r.ensureIdentity(ctx, tenant, device, jid)
		n++
	}
	return n
}

// carriesMessages reports whether a sync type contains archive content.
func carriesMessages(t waHistorySync.HistorySync_HistorySyncType) bool {
	switch t {
	case waHistorySync.HistorySync_INITIAL_BOOTSTRAP,
		waHistorySync.HistorySync_FULL,
		waHistorySync.HistorySync_RECENT,
		waHistorySync.HistorySync_ON_DEMAND:
		return true
	default:
		return false
	}
}

// SealChatName seals a conversation's display name.
func (p *Pipeline) SealChatName(ctx context.Context, chatUID uuid.UUID, name string) ([]byte, uint32, error) {
	sealed, keyID, err := p.sealer.SealAll(ctx, chatUID,
		map[seal.Kind][]byte{seal.KindContactName: []byte(name)})
	if err != nil {
		return nil, 0, fmt.Errorf("ingest: seal chat name: %w", err)
	}
	return sealed[seal.KindContactName], keyID, nil
}
