package ingest

import (
	"context"
	"time"

	"github.com/google/uuid"
	"go.mau.fi/whatsmeow/types/events"

	"whatserver2/internal/domain"
)

// The badge clears from three places and none of them knows about the others.
//
// A reader marks messages read from the browser; one of our own other devices
// reports a read, which comes back as an ordinary receipt with is_from_me set;
// and the phone replays its own "mark as read" through app state. All three end
// at the same watermark, which is why they can all be applied blindly.

// handleMarkChatAsRead applies the phone's own read state.
//
// Two branches, and only one of them filters replays. Registry turns on
// EmitAppStateEventsOnFullSync, so a re-pair delivers the whole of app state
// again: replaying "read" is free, because a watermark never moves backwards,
// while replaying "unread" would relight every conversation the phone has ever
// had marked unread — months of them, at once, on the first boot after pairing.
func (r *Router) handleMarkChatAsRead(ctx context.Context, deviceID string, evt *events.MarkChatAsRead) {
	if r.cfg.Unread == nil || evt == nil || evt.Action == nil || evt.JID.IsEmpty() {
		return
	}
	info, ok := r.cfg.Lookup(deviceID)
	if !ok {
		return
	}
	device, err := uuid.Parse(deviceID)
	if err != nil {
		return
	}
	chat := evt.JID.ToNonAD().String()

	if !evt.Action.GetRead() {
		if evt.FromFullSync {
			return
		}
		if err := r.cfg.Unread.MarkChatUnread(ctx, info.TenantID, device, chat); err != nil {
			r.log.Debug("could not mark a chat unread", "chat", chat, "error", err)
		}
		return
	}

	var at *time.Time
	if ts := evt.Action.GetMessageRange().GetLastMessageTimestamp(); ts > 0 {
		when := time.Unix(ts, 0)
		at = &when
	}
	if err := r.cfg.Unread.MarkChatReadAt(ctx, info.TenantID, device, chat, at); err != nil {
		r.log.Debug("could not clear a chat badge", "chat", chat, "error", err)
	}
}

// clearOnOwnRead applies a read our own other device reported.
//
// Gated on the kind, not only on is_from_me, and that gate is the whole of it.
// types.ReceiptTypeSender also arrives with is_from_me set and normalises to a
// DELIVERY — our own phone confirming it received something we sent. Clearing
// on that would empty the badge because a message reached one of our devices,
// which nobody has read.
func (r *Router) clearOnOwnRead(ctx context.Context, tenant uuid.UUID, deviceID string,
	rec domain.Receipt) {
	if r.cfg.Unread == nil || !rec.IsFromMe {
		return
	}
	if rec.Kind != domain.ReceiptRead && rec.Kind != domain.ReceiptPlayed {
		return
	}
	device, err := uuid.Parse(deviceID)
	if err != nil {
		return
	}
	if err := r.cfg.Unread.MarkReadThrough(ctx, tenant, device, rec.MessageIDs); err != nil {
		r.log.Debug("could not clear a badge from our own read", "error", err)
	}
}
