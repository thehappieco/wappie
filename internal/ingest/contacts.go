package ingest

import (
	"context"

	"github.com/google/uuid"
	"go.mau.fi/whatsmeow/proto/waHistorySync"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/domain"
	"whatserver2/internal/store"
)

// Names reach this archive from four places and no two agree.
//
//   - A push name is what a contact calls themselves. It arrives on any message
//     they send, so it is the one name almost everybody has.
//   - The address book name is what this account saved them as. Better, when it
//     exists, and it exists only for people actually saved.
//   - A business name is verified by WhatsApp and belongs to a company.
//   - A conversation name comes with the history sync and names groups.
//
// All four are stored, sealed, and none overwrites another with nothing. Which
// to display is the client's decision, because it depends on what the client is
// for: an archive reader wants the saved name, an operator triaging an inbox
// often wants the one the sender chose.

// SealFor seals one value for a device, binding it to a row.
//
// Exposed so workers outside this package — the avatar fetcher, which fetches
// over plain HTTP and has nothing else to do with ingest — can seal without
// each of them holding a sealer of its own.
func (r *Router) SealFor(ctx context.Context, tenant, device, uid uuid.UUID,
	kind seal.Kind, value []byte) ([]byte, uint32, error) {
	pipe, err := r.pipelineFor(ctx, tenant, device)
	if err != nil {
		return nil, 0, err
	}
	sealed, keyID, err := pipe.sealer.SealAll(ctx, uid, map[seal.Kind][]byte{kind: value})
	if err != nil {
		return nil, 0, err
	}
	return sealed[kind], keyID, nil
}

// recordName stores one contact name, sealed.
func (r *Router) recordName(ctx context.Context, deviceID string, jid, alt types.JID,
	which seal.Kind, name string) {
	if name == "" || r.cfg.Contacts == nil {
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
	addr := domain.AddressOf(jid)
	if !alt.IsEmpty() {
		addr = addr.Merge(domain.AddressOf(alt))
	}
	key := addr.Primary()
	if key.IsEmpty() {
		return
	}
	contactKey := key.ToNonAD().String()

	sealed, keyID, err := r.SealFor(ctx, info.TenantID, device,
		store.ContactUID(device, contactKey), which, []byte(name))
	if err != nil {
		r.log.Error("could not seal a contact name", "contact", contactKey, "error", err)
		return
	}

	in := store.ContactName{
		TenantID: info.TenantID, DeviceID: device,
		ContactKey:   contactKey,
		ContactLID:   jidString(addr.LID),
		ContactPN:    jidString(addr.PN),
		IsGroup:      key.Server == types.GroupServer,
		ContentKeyID: keyID,
	}
	switch which {
	case seal.KindPushName:
		in.PushNameSealed = sealed
	case seal.KindFullName:
		in.FullNameSealed = sealed
	case seal.KindBusinessName:
		in.BusinessNameSealed = sealed
	default:
		return
	}
	if err := r.cfg.Contacts.Upsert(ctx, in); err != nil {
		r.log.Error("could not record a contact name", "contact", contactKey, "error", err)
	}
}

// handlePushName records the name a contact chose for themselves.
//
// Note this is events.PushName and not events.PushNameSetting: the latter is
// *our own* display name, and an earlier version of this server confused the
// two and wrote a stranger's name into the device's identity.
func (r *Router) handlePushName(ctx context.Context, deviceID string, evt *events.PushName) {
	r.recordName(ctx, deviceID, evt.JID, evt.JIDAlt, seal.KindPushName, evt.NewPushName)
}

// handleBusinessName records a verified business name.
func (r *Router) handleBusinessName(ctx context.Context, deviceID string, evt *events.BusinessName) {
	r.recordName(ctx, deviceID, evt.JID, types.EmptyJID, seal.KindBusinessName, evt.NewBusinessName)
}

// handleContact records the name this account saved a contact under.
//
// The address book name, which is the best one when it exists — and exists only
// for people actually saved, which on a busy account is a minority.
func (r *Router) handleContact(ctx context.Context, deviceID string, evt *events.Contact) {
	action := evt.Action
	if action == nil {
		return
	}
	name := action.GetFullName()
	if name == "" {
		name = action.GetFirstName()
	}
	r.recordName(ctx, deviceID, evt.JID, types.EmptyJID, seal.KindFullName, name)
}

// handlePicture records that a profile picture changed.
//
// The bytes are not fetched here. This runs on whatsmeow's event goroutine, and
// a plain HTTP download of a face on that goroutine stops the device receiving
// anything for as long as it takes — the same reason history sync is ingested
// off it. Clearing the check time hands the work to the picture worker, which
// is paced and already knows how to seal what it fetches.
//
// A removal is recorded the same way. WhatsApp says the picture is gone; the
// worker asks, is told there is none, and records that — one path for "look
// again" rather than a second that decides what "gone" means.
func (r *Router) handlePicture(ctx context.Context, deviceID string, evt *events.Picture) {
	if r.cfg.Contacts == nil || evt == nil || evt.JID.IsEmpty() {
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
	key := evt.JID.ToNonAD().String()
	if err := r.cfg.Contacts.InvalidateAvatar(ctx, info.TenantID, device, key); err != nil {
		r.log.Debug("could not mark a profile picture for refetching",
			"contact", key, "error", err)
	}
}

// ingestPushNames records the names carried by a PUSH_NAME sync chunk.
//
// This is where the bulk arrives: a bootstrap names most of the people an
// account has ever spoken to, in one payload, and without it a re-paired
// archive shows hundreds of conversations as bare phone numbers.
func (r *Router) ingestPushNames(ctx context.Context, chunk historyChunk) int {
	names := chunk.data.GetPushnames()
	if len(names) == 0 || r.cfg.Contacts == nil {
		return 0
	}
	var stored int
	for _, pn := range names {
		if ctx.Err() != nil {
			return stored
		}
		jid, err := types.ParseJID(pn.GetID())
		if err != nil || pn.GetPushname() == "" {
			continue
		}
		r.recordName(ctx, chunk.deviceID, jid, types.EmptyJID,
			seal.KindPushName, pn.GetPushname())
		stored++
	}
	return stored
}

// pushNameChunk reports whether a sync payload carries contact names.
func pushNameChunk(data *waHistorySync.HistorySync) bool {
	return len(data.GetPushnames()) > 0
}

// ImportContacts copies whatsmeow's cached contact names into the archive.
//
// The bulk of the names arrive in a single PUSH_NAME chunk during a history
// sync, and whatsmeow puts them straight into its own store. An archive that
// only listened for events would wait for each of those people to send
// something before learning who they are — which for a five thousand contact
// account means most of them, forever.
//
// Idempotent, so it can run at every boot: names are upserted and none
// overwrites another with nothing.
func (r *Router) ImportContacts(ctx context.Context, deviceID string,
	contacts map[types.JID]types.ContactInfo) (int, error) {
	if r.cfg.Contacts == nil || len(contacts) == 0 {
		return 0, nil
	}
	info, ok := r.cfg.Lookup(deviceID)
	if !ok {
		return 0, nil
	}
	device, err := uuid.Parse(deviceID)
	if err != nil {
		return 0, err
	}

	var imported int
	for jid, contact := range contacts {
		if ctx.Err() != nil {
			return imported, ctx.Err()
		}
		key := jid.ToNonAD().String()
		uid := store.ContactUID(device, key)

		in := store.ContactName{
			TenantID: info.TenantID, DeviceID: device,
			ContactKey: key,
			ContactLID: jidString(domain.AddressOf(jid).LID),
			ContactPN:  jidString(domain.AddressOf(jid).PN),
			IsGroup:    jid.Server == types.GroupServer,
		}

		// The address book name is the better one when it exists, and the
		// first name is what WhatsApp falls back to when a contact was saved
		// with only that.
		fullName := contact.FullName
		if fullName == "" {
			fullName = contact.FirstName
		}
		var any bool
		for _, candidate := range []struct {
			kind seal.Kind
			text string
			into *[]byte
		}{
			{seal.KindPushName, contact.PushName, &in.PushNameSealed},
			{seal.KindFullName, fullName, &in.FullNameSealed},
			{seal.KindBusinessName, contact.BusinessName, &in.BusinessNameSealed},
		} {
			if candidate.text == "" {
				continue
			}
			sealed, keyID, err := r.SealFor(ctx, info.TenantID, device, uid, candidate.kind,
				[]byte(candidate.text))
			if err != nil {
				return imported, err
			}
			*candidate.into = sealed
			in.ContentKeyID = keyID
			any = true
		}
		if !any {
			// A row whatsmeow knows nothing about. Storing it would fill the
			// table with identifiers and no information.
			continue
		}
		if err := r.cfg.Contacts.Upsert(ctx, in); err != nil {
			return imported, err
		}
		imported++
	}
	return imported, nil
}
