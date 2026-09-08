package ingest

import (
	"context"

	"github.com/google/uuid"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types/events"
)

// applyEphemeralSetting records a disappearing timer the other side changed.
//
// This is how a one-to-one conversation's timer arrives: as a ProtocolMessage
// of type EPHEMERAL_SETTING inside an ordinary message event, carrying the new
// expiration and the moment it was set. whatsmeow does not consume it — its
// handleProtocolMessage has no branch for it — so it reaches this server as a
// plain *events.Message and was, until now, classified as housekeeping and
// dropped.
//
// Dropping it left two visible failures. Turning a timer ON was eventually
// noticed anyway, because every message in a disappearing chat carries the
// timer in its context info and upsertChat ratchets the chat row up from it —
// so the setting appeared minutes late, whenever the other side next spoke.
// Turning one OFF was never noticed at all: that ratchet only ever raises, by
// design, and the explicit path that can lower it was reachable only from our
// own outbound handler. A conversation the other side took out of disappearing
// mode went on being drawn as temporary indefinitely.
//
// Applied here rather than in the classifier because it is not a row. Nothing
// about it belongs in the archive as a message — it is a fact about the chat,
// and the chat table is where facts about chats live. normalize goes on
// skipping it, which is why this runs before normalize is called rather than
// depending on what it returns.
func (r *Router) applyEphemeralSetting(ctx context.Context, info DeviceInfo,
	deviceID string, evt *events.Message) {
	if evt == nil || evt.Message == nil {
		return
	}
	pm := evt.Message.GetProtocolMessage()
	if pm == nil {
		return
	}
	switch pm.GetType() {
	case waE2E.ProtocolMessage_EPHEMERAL_SETTING, waE2E.ProtocolMessage_EPHEMERAL_SYNC_RESPONSE:
	default:
		return
	}
	// A group's timer arrives as events.GroupInfo instead, with an author and
	// a place in the group's history. Taking it from here as well would write
	// the same change twice and leave the group panel with two entries for one
	// act.
	if evt.Info.IsGroup {
		return
	}

	dev, err := uuid.Parse(deviceID)
	if err != nil {
		return
	}
	//nolint:gosec // G115: an expiration is bounded by WhatsApp's own presets
	seconds := int32(min(pm.GetEphemeralExpiration(), 1<<31-1))
	chat := evt.Info.Chat.ToNonAD().String()

	if err := r.cfg.Messages.SetChatTimer(ctx, info.TenantID, dev, chat, seconds); err != nil {
		r.log.Error("could not record a disappearing timer the other side changed",
			"chat", chat, "seconds", seconds, "error", err)
		return
	}
	r.log.Info("the other side changed the disappearing timer",
		"chat", chat, "seconds", seconds)
	r.announceTimer(info.TenantID, dev, chat, seconds)
}

// announceTimer tells connected clients a conversation's timer moved.
//
// Without it the change lands in the database and nowhere else: the only frame
// that ever carried a timer was the reply to a chats.list request, so the
// header went on showing the old value until something refetched the sidebar.
func (r *Router) announceTimer(tenant, device uuid.UUID, chat string, seconds int32) {
	if r.cfg.Bus == nil {
		return
	}
	at := seconds
	r.cfg.Bus.Publish(tenant, Event{
		Class: ClassChat, TenantID: tenant, DeviceID: device,
		ChatKey: chat, Ephemeral: true,
		Chat: &ChatUpdate{ChatKey: chat, Ephemeral: &at},
	})
}
