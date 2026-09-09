package ingest

import (
	"context"
	"time"

	"github.com/google/uuid"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"

	"whatserver2/internal/domain"
)

// handlePresence relays a contact's reported online state, never recording it
// in the archive. Missing events are not evidence that someone is offline.
func (r *Router) handlePresence(ctx context.Context, deviceID string, evt *events.Presence) {
	if r.cfg.Bus == nil || evt == nil || evt.From.IsEmpty() {
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
	peer := domain.AddressOf(evt.From.ToNonAD())
	if peer.Primary().Server != types.DefaultUserServer && peer.Primary().Server != types.HiddenUserServer {
		return
	}
	if r.cfg.Phones != nil && !peer.LID.IsEmpty() {
		if pn, found := r.cfg.Phones.PhoneFor(ctx, peer.LID); found {
			peer = peer.Merge(domain.AddressOf(pn))
		}
	}
	status := "available"
	if evt.Unavailable {
		status = "unavailable"
	}
	var lastSeen *time.Time
	if evt.Unavailable && !evt.LastSeen.IsZero() {
		lastSeen = &evt.LastSeen
	}
	r.cfg.Bus.Publish(info.TenantID, Event{
		Class: ClassPresence, TenantID: info.TenantID, DeviceID: device,
		ChatKey: peer.Primary().String(), Ephemeral: true,
		Presence: &Presence{ChatKey: peer.Primary().String(), SenderKey: peer.Primary().String(),
			SenderLID: jidString(peer.LID), SenderPN: jidString(peer.PN), State: status, LastSeen: lastSeen},
	})
}

// handleChatPresence forwards "somebody is typing" and stores nothing.
//
// Nothing to store: it is true for a few seconds and then it is not, and a row
// recording it would be a fact that had stopped being one before anybody could
// read it. It is also the only event in this pipeline with no sequence number,
// which is what Event.Ephemeral exists to say — see the comment there for what
// the bus must not do with one.
//
// Worth stating where this sits relative to incognito: these arrive only while
// the account is announced as online, and announcing presence is exactly what
// incognito refuses to do. So a device in the quiet posture never sees them,
// which is a property of the protocol rather than a limitation here.
func (r *Router) handleChatPresence(ctx context.Context, deviceID string, evt *events.ChatPresence) {
	_ = ctx
	if r.cfg.Bus == nil || evt == nil {
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

	chat := addressOf(evt.Chat, evt.RecipientAlt)
	if chat.Empty() {
		return
	}
	sender := addressOf(evt.Sender, evt.SenderAlt)
	if sender.Empty() {
		// A direct chat sometimes omits the sender because it can only be the
		// peer. Falling back keeps the event usable rather than dropping it.
		sender = chat
	}

	r.cfg.Bus.Publish(info.TenantID, Event{
		Class:     ClassPresence,
		TenantID:  info.TenantID,
		DeviceID:  device,
		ChatKey:   chat.Primary().String(),
		Ephemeral: true,
		Presence: &Presence{
			ChatKey:   chat.Primary().String(),
			SenderKey: sender.Primary().String(),
			SenderLID: jidString(sender.LID),
			SenderPN:  jidString(sender.PN),
			State:     string(evt.State),
			Media:     string(evt.Media),
		},
	})
}

// addressOf merges the two halves of an identity the way the rest of the
// pipeline does: neither is rewritten and a known one is never lost.
func addressOf(primary, alt types.JID) domain.Address {
	addr := domain.AddressOf(primary)
	if !alt.IsEmpty() {
		addr = addr.Merge(domain.AddressOf(alt))
	}
	return addr
}
