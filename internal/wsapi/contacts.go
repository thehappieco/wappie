package wsapi

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/google/uuid"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/store"
)

// handleContactsList returns who the identifiers belong to.
func (s *session) handleContactsList(ctx context.Context, f Frame) {
	var ref DeviceRef
	if err := json.Unmarshal(f.Payload, &ref); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	if s.srv.cfg.Contacts == nil {
		s.replyError(f.ReqID, ErrCodeInternal, "contacts are not configured on this server")
		return
	}
	tenant, device, ok := s.resolveDevice(ctx, f, ref.DeviceID)
	if !ok {
		return
	}
	rows, err := s.srv.cfg.Contacts.List(ctx, tenant, device, 5000)
	if err != nil {
		s.log.Error("could not list contacts", "error", err)
		s.replyError(f.ReqID, ErrCodeInternal, "could not list contacts")
		return
	}
	out := make([]ContactSummary, 0, len(rows))
	for _, c := range rows {
		out = append(out, contactSummary(c))
	}
	// The resolved id, not what was asked for: callers accept a unique prefix,
	// and a client that echoed one back could not use it as a key.
	s.reply(TypeContactList, f.ReqID, Contacts{DeviceID: device.String(), Contacts: out})
}

// handleAvatar returns one sealed profile picture.
//
// Fetched one at a time rather than with the list: pictures are tens of
// kilobytes each and a client needs the names before it needs any of the faces.
func (s *session) handleAvatar(ctx context.Context, f Frame) {
	var req AvatarRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	if s.srv.cfg.Contacts == nil {
		s.replyError(f.ReqID, ErrCodeInternal, "contacts are not configured on this server")
		return
	}
	if req.ContactKey == "" {
		s.replyError(f.ReqID, ErrCodeBadRequest, "contact_key is required")
		return
	}
	tenant, device, ok := s.resolveDevice(ctx, f, req.DeviceID)
	if !ok {
		return
	}
	sealed, keyID, uid, err := s.srv.cfg.Contacts.Avatar(ctx, tenant, device, req.ContactKey)
	if err != nil {
		s.replyError(f.ReqID, ErrCodeNotFound, "no such contact")
		return
	}
	s.reply(TypeAvatarFrame, f.ReqID, Avatar{
		DeviceID: device.String(), ContactKey: req.ContactKey,
		UID: uid.String(), KeyID: keyID, Sealed: sealed,
	})
}

func contactSummary(c store.ContactRow) ContactSummary {
	return ContactSummary{
		UID:        c.UID.String(),
		ContactKey: c.ContactKey, ContactLID: c.ContactLID, ContactPN: c.ContactPN,
		IsGroup:            c.IsGroup,
		ContentKeyID:       c.ContentKeyID,
		PushNameSealed:     c.PushNameSealed,
		FullNameSealed:     c.FullNameSealed,
		BusinessNameSealed: c.BusinessNameSealed,
		HasAvatar:          c.HasAvatar,
		AvatarID:           c.AvatarID,
		AvatarKeyID:        c.AvatarKeyID,
	}
}

// resolveLimit bounds one contacts.resolve request.
//
// A client asks about what it is drawing, so this is comfortably above a
// screenful of chats. Anything past it is dropped rather than refused: the next
// draw asks again, and refusing would leave the caller with nothing at all.
const resolveLimit = 200

// handleContactsResolve answers "who are these identifiers".
//
// Three sources, cheapest first. What the archive already has; then whatsmeow's
// own contact cache, for keys the archive has no name for at all — that cache
// is local and free, and it is where a push name lands before anything asks for
// it; then the picture worker, nudged so a face that a person is looking at
// right now does not wait for a paced sweep of five thousand contacts.
//
// Nothing here fails the request. Every step is an enrichment, and a client
// that gets back less than it hoped draws the fallback it was already drawing.
func (s *session) handleContactsResolve(ctx context.Context, f Frame) {
	var req ContactsResolveRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	if s.srv.cfg.Contacts == nil {
		s.replyError(f.ReqID, ErrCodeInternal, "contacts are not configured on this server")
		return
	}
	tenant, device, ok := s.resolveDevice(ctx, f, req.DeviceID)
	if !ok {
		return
	}

	keys := contactKeys(req.Keys)
	if len(keys) == 0 {
		s.reply(TypeContactList, f.ReqID, Contacts{DeviceID: device.String()})
		return
	}

	rows, err := s.srv.cfg.Contacts.Some(ctx, tenant, device, keys)
	if err != nil {
		s.log.Error("could not read contacts", "error", err)
		s.replyError(f.ReqID, ErrCodeInternal, "could not read contacts")
		return
	}

	learned := s.importCached(ctx, tenant, device, keys, rows)
	// A key with no row at all gets one, carrying no name. The picture worker
	// walks contact rows, so without this an identifier nobody can name also
	// never gets a face — which is the pair of blanks this whole frame exists
	// to fill.
	if s.ensureRows(ctx, tenant, device, keys, rows) {
		learned = true
	}
	if learned {
		// Rows are stale now. Re-reading is one query and keeps a single shape
		// for the reply.
		if again, err := s.srv.cfg.Contacts.Some(ctx, tenant, device, keys); err == nil {
			rows = again
		}
	}
	s.nudgeAvatars(tenant, device, rows)

	out := make([]ContactSummary, 0, len(rows))
	for _, c := range rows {
		out = append(out, contactSummary(c))
	}
	s.reply(TypeContactList, f.ReqID, Contacts{DeviceID: device.String(), Contacts: out})
}

// contactKeys normalises what a client asked about.
//
// ToNonAD because a contact is a person, not one of their devices: a sender key
// carrying a device suffix names the same contact as one without, and asking
// with the suffix would find no row. Deduplicated because a client redrawing a
// conversation asks about the same sender once per message.
//
// The validation is stricter than types.ParseJID, deliberately. ParseJID
// accepts a string with no "@" at all and returns it as a user on the default
// server, so "not a jid" parses cleanly into "not a jid@s.whatsapp.net". That
// is harmless where the input came from WhatsApp and is not harmless here: this
// list reaches EnsureIdentity, and a caller could otherwise fill the contacts
// table with rows named whatever it liked.
func contactKeys(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, min(len(in), resolveLimit))
	for _, raw := range in {
		if len(out) >= resolveLimit {
			break
		}
		key, ok := contactKey(raw)
		if !ok {
			continue
		}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	return out
}

// contactKey validates one identifier and returns it in its canonical form.
func contactKey(raw string) (string, bool) {
	if !strings.Contains(raw, "@") {
		return "", false
	}
	jid, err := types.ParseJID(raw)
	if err != nil || jid.IsEmpty() || jid.User == "" {
		return "", false
	}
	switch jid.Server {
	case types.DefaultUserServer, types.HiddenUserServer,
		types.GroupServer, types.BroadcastServer:
	default:
		// Newsletters and anything a later upstream adds. Not refused loudly:
		// a client asking about one gets no row, which is the truth.
		return "", false
	}
	return jid.ToNonAD().String(), true
}

// importCached copies whatsmeow's cached names for keys the archive cannot name.
//
// Reports whether anything was stored. Only for keys with no name at all: a
// contact this archive already names does not need re-importing, and the cache
// has nothing better to offer than what the ordinary event path already wrote.
func (s *session) importCached(ctx context.Context, tenant, device uuid.UUID,
	keys []string, have []store.ContactRow) bool {
	if s.srv.cfg.Router == nil || s.srv.cfg.Registry == nil {
		return false
	}
	named := make(map[string]struct{}, len(have))
	for _, row := range have {
		if len(row.PushNameSealed) > 0 || len(row.FullNameSealed) > 0 ||
			len(row.BusinessNameSealed) > 0 {
			named[row.ContactKey] = struct{}{}
		}
	}
	dev, running := s.srv.cfg.Registry.Get(device.String())
	if !running {
		// Not connected, so there is no cache to read. Not an error: the rows
		// already read are still the answer.
		return false
	}

	cached := map[types.JID]types.ContactInfo{}
	for _, key := range keys {
		if _, ok := named[key]; ok {
			continue
		}
		jid, err := types.ParseJID(key)
		if err != nil {
			continue
		}
		info, err := dev.Contact(ctx, jid)
		if err != nil || (info.PushName == "" && info.FullName == "" &&
			info.FirstName == "" && info.BusinessName == "") {
			continue
		}
		cached[jid] = info
	}
	if len(cached) == 0 {
		return false
	}
	// ImportContacts is the boot-time bulk path, used here for a handful. One
	// implementation of "a cached contact becomes a sealed row" rather than a
	// second that could seal under a different kind or forget a field.
	n, err := s.srv.cfg.Router.ImportContacts(ctx, device.String(), cached)
	if err != nil {
		s.log.Debug("could not import cached contact names", "error", err)
	}
	return n > 0
}

// nudgeAvatars asks the picture worker to look at faces a reader is drawing now.
func (s *session) nudgeAvatars(tenant, device uuid.UUID, rows []store.ContactRow) {
	if s.srv.cfg.Avatars == nil {
		return
	}
	var want []string
	for _, row := range rows {
		if row.HasAvatar || row.AvatarChecked != nil {
			continue
		}
		want = append(want, row.ContactKey)
	}
	s.srv.cfg.Avatars.Nudge(tenant, device, want)
}

// ensureRows gives a contacts row to every key that has none.
//
// Reports whether anything was written. Bounded by the caller's key list, which
// is already capped: this is a row per identifier a person is looking at, not a
// row per identifier that has ever appeared.
func (s *session) ensureRows(ctx context.Context, tenant, device uuid.UUID,
	keys []string, have []store.ContactRow) bool {
	if s.srv.cfg.Router == nil {
		return false
	}
	known := make(map[string]struct{}, len(have))
	for _, row := range have {
		known[row.ContactKey] = struct{}{}
	}
	var wrote bool
	for _, key := range keys {
		if _, ok := known[key]; ok {
			continue
		}
		jid, err := types.ParseJID(key)
		if err != nil {
			continue
		}
		s.srv.cfg.Router.EnsureIdentity(ctx, tenant, device, jid)
		wrote = true
	}
	return wrote
}
