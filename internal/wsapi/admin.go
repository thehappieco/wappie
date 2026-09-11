package wsapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/access"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// The tenant console: what a person managing this installation can see and do.
//
// Three of these operations are refused to API keys outright — minting a key,
// revoking one, and deleting a device. The rule is in requireAdmin and the
// reason is there too: a leaked key that can mint its own successors survives
// the revocation of the key that leaked.
//
// Reading is not restricted the same way. Counters and identities are envelope,
// not content, and a monitoring script with a key has a legitimate reason to
// ask how many messages a device has archived.

// handleDevicesStats counts what each device has archived.
func (s *session) handleDevicesStats(ctx context.Context, f Frame) {
	allowed, err := s.actionDevices(ctx, store.ActionView)
	if err != nil {
		s.replyError(f.ReqID, ErrCodeInternal, "could not check device permissions")
		return
	}
	rows, err := s.srv.cfg.Devices.Stats(ctx, s.tenantID())
	if err != nil {
		s.log.Error("device stats failed", "error", err)
		s.replyError(f.ReqID, ErrCodeInternal, "could not count the archive")
		return
	}
	out := make([]DeviceStat, 0, len(rows))
	for _, r := range rows {
		id, err := uuid.Parse(r.DeviceID)
		if err != nil {
			continue
		}
		if _, ok := allowed[id]; !ok {
			continue
		}
		out = append(out, toStat(r))
	}
	s.reply(TypeDeviceStats, f.ReqID, DeviceStats{Stats: out})
}

func toStat(r store.DeviceStat) DeviceStat {
	stat := DeviceStat{
		DeviceID: r.DeviceID, Chats: r.Chats, Messages: r.Messages,
		Media: r.Media, MediaBytes: r.MediaBytes,
	}
	if !r.LastMessageAt.IsZero() {
		at := r.LastMessageAt
		stat.LastAt = &at
	}
	return stat
}

// handleDeviceInfo describes one device, including who can read it.
func (s *session) handleDeviceInfo(ctx context.Context, f Frame) {
	var ref DeviceRef
	if err := json.Unmarshal(f.Payload, &ref); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	tenant := s.tenantID()
	dev, err := s.srv.cfg.Devices.Resolve(ctx, tenant, ref.DeviceID)
	if err != nil {
		// Row-level security answers a cross-tenant lookup with "not found",
		// so this both authorises and validates in one step.
		s.replyError(f.ReqID, ErrCodeNotFound, "no such device")
		return
	}

	detail := DeviceDetail{Device: s.toDeviceInfo(ctx, dev), Epoch: dev.Epoch}

	tenantUUID, err := uuid.Parse(tenant)
	if err != nil {
		s.replyError(f.ReqID, ErrCodeInternal, "bad tenant")
		return
	}
	deviceUUID, err := uuid.Parse(dev.ID)
	if err != nil {
		s.replyError(f.ReqID, ErrCodeInternal, "bad device id")
		return
	}
	if !s.authorizeDevice(ctx, f, deviceUUID, store.ActionView) {
		return
	}

	// Who can read a device — emails, roles, who granted whom — is tenant
	// configuration. The rest of the detail is what any reader of the device
	// may see; this part is for those who administer it.
	if s.srv.cfg.Keys2 != nil && s.actor().admin() {
		holders, err := s.srv.cfg.Keys2.Readers(ctx, tenantUUID, deviceUUID)
		if err != nil {
			s.log.Error("listing readers failed", "error", err)
			s.replyError(f.ReqID, ErrCodeInternal, "could not list who can read this device")
			return
		}
		detail.Readers = make([]KeyHolder, 0, len(holders))
		for _, h := range holders {
			detail.Readers = append(detail.Readers, KeyHolder{
				UserID: h.UserID.String(), Email: h.Email, Role: h.Role,
				Epoch: int(h.Epoch), GrantedAt: h.GrantedAt, GrantedBy: h.GrantedBy,
			})
		}
	}

	// Counters for this one device, from the same query the list uses. Cheaper
	// paths exist; none of them are worth a second definition of "how many
	// messages does this device have" that could drift from the first.
	stats, err := s.srv.cfg.Devices.Stats(ctx, tenant)
	if err == nil {
		for _, st := range stats {
			if st.DeviceID == dev.ID {
				detail.Stats = toStat(st)
				break
			}
		}
	}
	detail.Stats.DeviceID = dev.ID

	s.reply(TypeDeviceDetail, f.ReqID, detail)
}

// handleDeviceDelete removes a device and everything it archived.
//
// The only call in this protocol that destroys an archive. Four things happen,
// in an order chosen so a failure partway through leaves something an operator
// can still act on:
//
//  1. Unlink from WhatsApp, if asked and if the device is connected. First,
//     because it is the only step that needs a live session — doing it last
//     would mean the row is already gone when it fails.
//
//  2. Stop supervising it, so nothing tries to archive into a device that is
//     about to stop existing.
//
//  3. Delete the row. Chats, messages, media rows, content keys, the archive
//     key and every grant cascade from it.
//
//  4. Report what went, including what did not.
//
//  5. Remove the attachment bytes from object storage, best effort, after
//     the rows are gone. Only the objects nothing else in the tenant still
//     names: a forwarded attachment is one object under several rows. A
//     failure here is logged and the reply says so; the bytes are ciphertext
//     whose keys step 3 destroyed, so an untidy bucket is a cost, not a leak.
func (s *session) handleDeviceDelete(ctx context.Context, f Frame) {
	who, ok := s.requireAdmin(f.ReqID)
	if !ok {
		return
	}
	var req DeleteRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	tenant := s.tenantID()
	dev, err := s.srv.cfg.Devices.Get(ctx, tenant, req.DeviceID)
	if err != nil {
		s.replyError(f.ReqID, ErrCodeNotFound, "no such device")
		return
	}
	if req.Confirm != dev.ID {
		s.replyError(f.ReqID, ErrCodeBadRequest,
			"deleting a device needs its id repeated in confirm; nothing was removed")
		return
	}

	// Counted before, because after the delete there is nothing left to count
	// and "removed a device" without a number is not a report.
	var before DeviceStat
	if stats, err := s.srv.cfg.Devices.Stats(ctx, tenant); err == nil {
		for _, st := range stats {
			if st.DeviceID == dev.ID {
				before = toStat(st)
				break
			}
		}
	}

	out := DeviceDeleted{
		DeviceID: dev.ID, Chats: before.Chats,
		Messages: before.Messages, Media: before.Media,
	}
	var notes []string

	// Persist the pause before stopping or reconnecting for logout, so the
	// background supervisor cannot claim a device being removed.
	if err := s.srv.cfg.Devices.SetPaused(ctx, tenant, dev.ID, true); err != nil {
		s.replyError(f.ReqID, ErrCodeInternal, "could not prepare the device for removal")
		return
	}
	s.srv.cancelDevicePairing(tenant, dev.ID)
	if req.Unlink && s.srv.cfg.Registry != nil && dev.Identity.Known() {
		unlinkCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
		running, held := s.srv.cfg.Registry.Get(dev.ID)
		if !held {
			// A paused number still has a WhatsApp session. Reconnect briefly to
			// remove that session on the phone instead of silently leaving it linked.
			running, err = s.srv.cfg.Registry.StartExisting(unlinkCtx, tenant, dev.ID,
				wa.ReceiptPolicy{Mode: wa.ModePassive}, dev.Identity.PN, dev.Identity.LID)
		}
		if running != nil && err == nil {
			if logoutErr := running.Client().Logout(unlinkCtx); logoutErr == nil {
				out.Unlinked = true
			} else {
				s.log.Warn("WhatsApp logout was not acknowledged", "device", dev.ID, "error", logoutErr)
			}
		}
		cancel()
		if !out.Unlinked {
			notes = append(notes, "WhatsApp could not confirm disconnection; remove this session under Linked devices on the phone")
		}
	}

	if s.srv.cfg.Registry != nil {
		s.srv.cfg.Registry.Stop(ctx, dev.ID)
	}

	// Collected before the rows go, because afterwards there is nothing to
	// ask.
	var objects []string
	tenantUUID, deviceUUID, _ := s.ids(f.ReqID, tenant, dev.ID)
	if s.srv.cfg.Pool != nil && s.srv.cfg.Blob.Configured() {
		if keys, err := store.ObjectKeysForDevice(ctx, s.srv.cfg.Pool, tenantUUID, deviceUUID); err == nil {
			objects = keys
		} else {
			s.log.Warn("could not list a device's attachments before deleting it", "error", err)
		}
	}

	if err := s.srv.cfg.Devices.Delete(ctx, tenant, dev.ID); err != nil {
		s.log.Error("deleting device failed", "device", dev.ID, "error", err)
		s.replyError(f.ReqID, ErrCodeInternal, "could not delete the device: "+err.Error())
		return
	}

	// Loud on purpose. This is the one operation here with no way back, and the
	// log line is the only trace left once the rows are gone.
	s.log.Warn("device deleted",
		"device", dev.ID, "label", dev.Label, "by", who.email,
		"messages", out.Messages, "chats", out.Chats, "media", out.Media)

	if len(objects) > 0 {
		removed, failed := s.removeObjects(ctx, tenantUUID, objects)
		if failed > 0 {
			notes = append(notes, fmt.Sprintf(
				"%d attachment object(s) could not be removed from storage and remain as ciphertext",
				failed))
		}
		s.log.Info("attachment objects removed", "device", dev.ID, "removed", removed, "failed", failed)
	}

	out.Note = strings.Join(notes, "; ")
	s.reply(TypeDeviceGone, f.ReqID, out)
	s.srv.BroadcastDeviceStatus(tenant, dev.ID, string(wa.StatusOffline), "deleted")
}

// removeObjects deletes the objects no media row still references.
func (s *session) removeObjects(ctx context.Context, tenant uuid.UUID, keys []string) (removed, failed int) {
	orphans, err := store.Unreferenced(ctx, s.srv.cfg.Pool, tenant, keys)
	if err != nil {
		s.log.Warn("could not tell which attachment objects are unreferenced", "error", err)
		return 0, len(keys)
	}
	for _, key := range orphans {
		if err := s.srv.cfg.Blob.Delete(context.WithoutCancel(ctx), key); err != nil {
			s.log.Warn("could not remove an attachment object", "key", key, "error", err)
			failed++
			continue
		}
		removed++
	}
	return removed, failed
}

// handleAPIKeysList reports the tenant's machine credentials.
func (s *session) handleAPIKeysList(ctx context.Context, f Frame) {
	if _, ok := s.requireAdmin(f.ReqID); !ok {
		return
	}
	rows, err := s.srv.cfg.Keys.List(ctx, s.tenantID())
	if err != nil {
		s.log.Error("listing api keys failed", "error", err)
		s.replyError(f.ReqID, ErrCodeInternal, "could not list the keys")
		return
	}
	out := make([]APIKeyInfo, 0, len(rows))
	for _, k := range rows {
		info := APIKeyInfo{
			Prefix: k.Prefix, Name: k.Name, Scope: string(k.Scope), ActsAs: k.ActsAs,
			CreatedBy: k.CreatedBy, CreatedAt: k.CreatedAt,
		}
		if !k.LastUsedAt.IsZero() {
			at := k.LastUsedAt
			info.LastUsedAt = &at
		}
		if !k.RevokedAt.IsZero() {
			at := k.RevokedAt
			info.RevokedAt = &at
		}
		out = append(out, info)
	}
	s.reply(TypeAPIKeys, f.ReqID, APIKeys{Keys: out})
}

// handleAPIKeyCreate mints a key and returns it once.
//
// What a key can do is worth being clear about, because it is not what an
// account can do. A key reaches the archive as ciphertext: it can list devices,
// subscribe to traffic and fetch sealed rows, and it holds no grant, so none of
// it opens. Reading is an account with a grant, and stays that way.
func (s *session) handleAPIKeyCreate(ctx context.Context, f Frame) {
	who, ok := s.requireAdmin(f.ReqID)
	if !ok {
		return
	}
	var req APIKeyRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		s.replyError(f.ReqID, ErrCodeBadRequest,
			"a key needs a name saying what will use it; six keys called \"key\" "+
				"is how a leaked one goes unnoticed")
		return
	}
	if len(name) > 120 {
		s.replyError(f.ReqID, ErrCodeBadRequest, "that name is too long")
		return
	}
	if strings.TrimSpace(req.Scope) == "" {
		s.replyError(f.ReqID, ErrCodeBadRequest,
			"a key needs a scope: read (the archive as ciphertext), send (plus "+
				"outbound messages) or full (plus pairing, stopping and backfill)")
		return
	}
	scope, err := store.ParseKeyScope(req.Scope)
	if err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}

	tenant := s.tenantID()
	var actsAs *uuid.UUID
	actsAsName := ""
	if req.ActsAs != "" {
		id, err := uuid.Parse(req.ActsAs)
		if err != nil {
			s.replyError(f.ReqID, ErrCodeBadRequest, "acts_as is not an account id")
			return
		}
		tenantUUID, err := uuid.Parse(tenant)
		if err != nil {
			s.replyError(f.ReqID, ErrCodeInternal, "bad tenant")
			return
		}
		account, err := s.srv.cfg.Accounts.Get(ctx, tenantUUID, id)
		if err != nil {
			s.replyError(f.ReqID, ErrCodeNotFound, "no such account in this tenant")
			return
		}
		if account.Role != store.RoleService {
			// A key that acted as a person would carry a person's grants
			// with none of the person's password behind them.
			s.replyError(f.ReqID, ErrCodeBadRequest,
				"a key can act as a service account only; "+account.Email+" is a person")
			return
		}
		actsAs, actsAsName = &id, store.ServiceName(account)
	}
	author := who.userID
	key, err := s.srv.cfg.Keys.IssueActingAs(ctx, tenant, name, scope, &author, actsAs)
	if err != nil {
		s.log.Error("issuing an api key failed", "error", err)
		s.replyError(f.ReqID, ErrCodeInternal, "could not issue the key")
		return
	}
	prefix, _, _ := strings.Cut(key, ".")
	s.log.Info("api key issued", "prefix", prefix, "name", name, "scope", scope,
		"acts_as", actsAsName, "by", who.email)

	// Looked up rather than assembled, so the timestamps a client shows are the
	// ones the database recorded.
	info := APIKeyInfo{Prefix: prefix, Name: name, Scope: string(scope),
		ActsAs: actsAsName, CreatedBy: who.email}
	if rows, err := s.srv.cfg.Keys.List(ctx, tenant); err == nil {
		for _, k := range rows {
			if k.Prefix == prefix {
				info.CreatedAt = k.CreatedAt
				break
			}
		}
	}
	s.reply(TypeAPIKeyNew, f.ReqID, APIKeyCreated{Key: key, Info: info})
}

// handleAPIKeyRevoke disables one key.
func (s *session) handleAPIKeyRevoke(ctx context.Context, f Frame) {
	who, ok := s.requireAdmin(f.ReqID)
	if !ok {
		return
	}
	var ref APIKeyRef
	if err := json.Unmarshal(f.Payload, &ref); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	err := s.srv.cfg.Keys.Revoke(ctx, s.tenantID(), ref.Prefix)
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.replyError(f.ReqID, ErrCodeNotFound, "no active key with that prefix")
		return
	case err != nil:
		s.log.Error("revoking an api key failed", "error", err)
		s.replyError(f.ReqID, ErrCodeInternal, "could not revoke the key")
		return
	}
	s.log.Info("api key revoked", "prefix", ref.Prefix, "by", who.email)

	// Close local sockets now; per-frame and periodic revalidation also covers
	// connections on other processes.
	s.reply(TypeAPIKeyGone, f.ReqID, APIKeyRef{Prefix: ref.Prefix})
	s.srv.disconnectKey(ref.Prefix)
}

// handleGrantAdd records one account's copy of a device key.
//
// The server is a filing cabinet here. It cannot produce this ciphertext, cannot
// verify that it opens to the right key, and cannot read it — a client that
// already had the device key made it. What is checked is what can be: that the
// device exists in this tenant, that the account does, and that the epoch is the
// one the device is actually sealing under.
//
// A grant recorded against the wrong epoch would be worse than a refusal: it
// would sit in the list looking like access, and fail to open on the one day
// somebody needed it.
func (s *session) handleGrantAdd(ctx context.Context, f Frame) {
	who, ok := s.requireAdmin(f.ReqID)
	if !ok {
		return
	}
	var req GrantRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	if len(req.SealedDSK) == 0 {
		s.replyError(f.ReqID, ErrCodeBadRequest, "a grant with no sealed key is not a grant")
		return
	}

	tenant := s.tenantID()
	dev, err := s.srv.cfg.Devices.Get(ctx, tenant, req.DeviceID)
	if err != nil {
		s.replyError(f.ReqID, ErrCodeNotFound, "no such device")
		return
	}
	tenantUUID, deviceUUID, ok := s.ids(f.ReqID, tenant, dev.ID)
	if !ok {
		return
	}
	user, err := uuid.Parse(req.UserID)
	if err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, "that is not an account id")
		return
	}
	if _, err := s.srv.cfg.Accounts.Get(ctx, tenantUUID, user); err != nil {
		s.replyError(f.ReqID, ErrCodeNotFound, "no such account in this tenant")
		return
	}

	_, epoch, err := s.srv.cfg.Keys2.ArchiveKey(ctx, tenantUUID, deviceUUID)
	if errors.Is(err, store.ErrNoArchiveKey) {
		s.replyError(f.ReqID, ErrCodeConflict,
			"this device has no archive key, so there is nothing to grant")
		return
	}
	if err != nil {
		s.log.Error("reading the archive key failed", "device", dev.ID, "error", err)
		s.replyError(f.ReqID, ErrCodeInternal, "could not read the device key")
		return
	}
	if req.Epoch != int(epoch) {
		s.replyError(f.ReqID, ErrCodeConflict, fmt.Sprintf(
			"this device seals under generation %d and the grant is for %d; "+
				"it would be recorded as access and fail to open", epoch, req.Epoch))
		return
	}

	author := who.userID
	if err := s.srv.cfg.Keys2.PutGrant(ctx, store.Grant{
		TenantID: tenantUUID, DeviceID: deviceUUID, UserID: user,
		Epoch: epoch, SealedDSK: req.SealedDSK,
	}, &author); err != nil {
		s.log.Error("recording a grant failed", "device", dev.ID, "error", err)
		s.replyError(f.ReqID, ErrCodeInternal, "could not record the grant")
		return
	}
	s.log.Info("device key granted",
		"device", dev.ID, "to", req.UserID, "by", who.email, "epoch", epoch)
	s.replyReaders(ctx, f.ReqID, tenantUUID, deviceUUID, dev.ID)
}

// handleGrantRevoke removes one account's access, for what that is worth.
func (s *session) handleGrantRevoke(ctx context.Context, f Frame) {
	who, ok := s.requireAdmin(f.ReqID)
	if !ok {
		return
	}
	var req GrantRevoke
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	tenant := s.tenantID()
	dev, err := s.srv.cfg.Devices.Get(ctx, tenant, req.DeviceID)
	if err != nil {
		s.replyError(f.ReqID, ErrCodeNotFound, "no such device")
		return
	}
	tenantUUID, deviceUUID, ok := s.ids(f.ReqID, tenant, dev.ID)
	if !ok {
		return
	}
	user, err := uuid.Parse(req.UserID)
	if err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, "that is not an account id")
		return
	}
	if err := s.srv.cfg.Keys2.RevokeGrant(ctx, tenantUUID, deviceUUID, user); err != nil {
		if errors.Is(err, store.ErrLastDeviceReader) {
			s.replyError(f.ReqID, ErrCodeLastDeviceReader, "give another active member read access to this number before removing its last reader")
			return
		}
		s.log.Error("revoking a grant failed", "device", dev.ID, "error", err)
		s.replyError(f.ReqID, ErrCodeInternal, "could not revoke the grant")
		return
	}
	s.log.Info("device key grant revoked",
		"device", dev.ID, "from", req.UserID, "by", who.email)
	s.srv.RevalidateAccess()
	s.replyReaders(ctx, f.ReqID, tenantUUID, deviceUUID, dev.ID)
}

// handleGrantsList returns the grants of the account this connection acts
// as: a person's, or a service account's through the key that acts as it.
//
// Ciphertext, freely given: each entry opens only to the account's private
// key, and the server has never held one.
func (s *session) handleGrantsList(ctx context.Context, f Frame) {
	who := s.actor()
	if !who.person && !who.service {
		s.replyError(f.ReqID, ErrCodeNotAuthorized,
			"this key acts as no account, so it holds no grants; issue one that acts as a service account")
		return
	}
	if s.srv.cfg.Keys2 == nil {
		s.replyError(f.ReqID, ErrCodeInternal, "grants are not configured on this server")
		return
	}
	tenant, err := uuid.Parse(s.tenantID())
	if err != nil {
		s.replyError(f.ReqID, ErrCodeInternal, "bad tenant")
		return
	}
	grants, err := s.srv.cfg.Keys2.GrantsFor(ctx, tenant, who.userID)
	if err != nil {
		s.log.Error("listing grants failed", "error", err)
		s.replyError(f.ReqID, ErrCodeInternal, "could not list the grants")
		return
	}
	labels := map[string]string{}
	if devices, err := s.srv.cfg.Devices.List(ctx, tenant.String()); err == nil {
		for _, d := range devices {
			labels[d.ID] = d.Label
		}
	}
	out := Grants{UserID: who.userID.String(), Grants: make([]GrantEntry, 0, len(grants))}
	for _, g := range grants {
		out.Grants = append(out.Grants, GrantEntry{
			DeviceID: g.DeviceID.String(), Label: labels[g.DeviceID.String()],
			Epoch: int(g.Epoch), SealedDSK: g.SealedDSK,
		})
	}
	s.reply(TypeGrants, f.ReqID, out)
}

// ids parses the two identifiers every grant handler needs.
func (s *session) ids(reqID, tenant, device string) (uuid.UUID, uuid.UUID, bool) {
	tenantUUID, err := uuid.Parse(tenant)
	if err != nil {
		s.replyError(reqID, ErrCodeInternal, "bad tenant")
		return uuid.Nil, uuid.Nil, false
	}
	deviceUUID, err := uuid.Parse(device)
	if err != nil {
		s.replyError(reqID, ErrCodeInternal, "bad device id")
		return uuid.Nil, uuid.Nil, false
	}
	return tenantUUID, deviceUUID, true
}

// replyReaders answers a grant change with the list as it now stands, so a
// client never has to guess what its own change produced.
func (s *session) replyReaders(ctx context.Context, reqID string,
	tenant, device uuid.UUID, deviceID string) {
	holders, err := s.srv.cfg.Keys2.Readers(ctx, tenant, device)
	if err != nil {
		s.log.Error("listing readers failed", "error", err)
		s.replyError(reqID, ErrCodeInternal, "the change was made, but the list could not be read")
		return
	}
	out := make([]KeyHolder, 0, len(holders))
	for _, h := range holders {
		out = append(out, KeyHolder{
			UserID: h.UserID.String(), Email: h.Email, Role: h.Role,
			Epoch: int(h.Epoch), GrantedAt: h.GrantedAt, GrantedBy: h.GrantedBy,
		})
	}
	s.reply(TypeReaders, reqID, Readers{DeviceID: deviceID, Readers: out})
}

// toDeviceInfo converts a row for the wire, filling in what only this process
// knows: whether the device is actually running here.
func (s *session) toDeviceInfo(ctx context.Context, d store.Device) DeviceInfo {
	info := DeviceInfo{
		ID: d.ID, Label: d.Label, PushName: d.Identity.PushName,
		Status: string(d.Status), StatusReason: d.StatusReason,
		ReceiptMode: string(d.ReceiptMode), CreatedAt: d.CreatedAt, Paused: d.Paused,
	}
	if d.Identity.Known() {
		info.ProfileKey = d.Identity.Primary().ToNonAD().String()
	}
	if !d.Identity.LID.IsEmpty() {
		info.LID = d.Identity.LID.String()
	}
	if !d.Identity.PN.IsEmpty() {
		info.PN = d.Identity.PN.String()
	}
	if !d.LastConnectedAt.IsZero() {
		at := d.LastConnectedAt
		info.LastConnectedAt = &at
	}
	who := s.actor()
	if tenant, err := uuid.Parse(d.TenantID); err == nil {
		if device, err := uuid.Parse(d.ID); err == nil {
			if who.person {
				info.ReaderReceiptMode = string(wa.ModePassive)
				if accounts := s.accountStore(); accounts != nil {
					if mode, err := accounts.ReaderMode(ctx, tenant, who.userID, device); err == nil {
						info.ReaderReceiptMode = string(mode)
					}
				}
			}
			allowed, err := access.Allows(ctx, access.Actor{Tenant: tenant, User: who.userID, Key: who.keyID, Scope: who.scope, Role: who.role}, device, store.ActionManage, s.srv.cfg.Keys, s.accountStore())
			if err != nil {
				s.log.Warn("could not load device management permission", "device", d.ID, "error", err)
			} else {
				info.CanManage = allowed
			}
			allowed, err = access.Allows(ctx, access.Actor{Tenant: tenant, User: who.userID, Key: who.keyID, Scope: who.scope, Role: who.role}, device, store.ActionSend, s.srv.cfg.Keys, s.accountStore())
			if err == nil {
				info.CanSend = allowed
			}
		}
	}
	// A terminal device keeps its registry reservation until explicit teardown.
	// That reservation is not an active WhatsApp connection after phone unlink.
	if live, held := s.srv.cfg.Registry.Get(d.ID); held {
		info.Running = d.Status == wa.StatusOnline && !d.Paused && live.IsConnected()
	}
	return info
}

// running reports whether this process is supervising a device.
//
// A server built without a registry supervises nothing — a read-only
// deployment, or a test — and should say so rather than dereference nil.
func (s *session) running(deviceID string) bool {
	if s.srv.cfg.Registry == nil {
		return false
	}
	_, ok := s.srv.cfg.Registry.Get(deviceID)
	return ok
}

// Cancel a pending pairing even when another browser initiated it.
func (s *Server) cancelDevicePairing(tenant, device string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for sess := range s.sessions {
		if sess.tenantID() != tenant {
			continue
		}
		sess.pairMu.Lock()
		pair := sess.pairings[device]
		sess.pairMu.Unlock()
		if pair != nil {
			pair.Cancel()
		}
	}
}
