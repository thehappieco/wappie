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
	"whatserver2/internal/membership"
	"whatserver2/internal/stepup"
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
		ArchiveBytes: r.ArchiveBytes, ObjectBytes: r.ObjectBytes, UsedBytes: r.UsedBytes,
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
		out = append(out, apiKeyInfo(k))
	}
	s.reply(TypeAPIKeys, f.ReqID, APIKeys{Keys: out})
}

func apiKeyInfo(k store.APIKeyInfo) APIKeyInfo {
	info := APIKeyInfo{
		Prefix: k.Prefix, Name: k.Name, Scope: string(k.Scope), ActsAs: k.ActsAs,
		CreatedBy: k.CreatedBy, CreatedAt: k.CreatedAt,
		DevicesRestricted: k.DevicesRestricted, DeviceIDs: append([]string{}, k.DeviceIDs...),
	}
	if k.ActsAsID != nil {
		info.ActsAsID = k.ActsAsID.String()
	}
	if !k.LastUsedAt.IsZero() {
		at := k.LastUsedAt
		info.LastUsedAt = &at
	}
	if !k.RevokedAt.IsZero() {
		at := k.RevokedAt
		info.RevokedAt = &at
	}
	if k.ExpiresAt != nil {
		at := *k.ExpiresAt
		info.ExpiresAt = &at
	}
	return info
}

// maxKeyLifetime caps how far out a key's deadline may be set; the store
// enforces the same bound.
const maxKeyLifetime = 365 * 24 * time.Hour

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
	// JSON null is supplied input, not omission. Never turn it into an
	// unrestricted credential just because a nil slice also means "absent".
	if req.DeviceIDs == nil {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(f.Payload, &fields); err != nil {
			s.replyError(f.ReqID, ErrCodeBadRequest, "invalid API key request")
			return
		}
		if _, supplied := fields["device_ids"]; supplied {
			s.replyError(f.ReqID, ErrCodeBadRequest, "device_ids must be a nonempty array")
			return
		}
	}
	var deviceIDs []uuid.UUID
	if req.DeviceIDs != nil {
		deviceIDs = make([]uuid.UUID, 0, len(req.DeviceIDs))
		for _, raw := range req.DeviceIDs {
			id, err := uuid.Parse(raw)
			if err != nil || len(raw) != 36 || id == uuid.Nil {
				s.replyError(f.ReqID, ErrCodeBadRequest, "device_ids must contain complete, nonzero UUIDs")
				return
			}
			deviceIDs = append(deviceIDs, id)
		}
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
	var expiresAt *time.Time
	if strings.TrimSpace(req.ExpiresAt) != "" {
		at, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			s.replyError(f.ReqID, ErrCodeBadRequest, "expires_at must be an RFC 3339 timestamp")
			return
		}
		// The store checks again, inside the transaction; this is the
		// message a person reads.
		if now := time.Now(); !at.After(now) || at.After(now.Add(maxKeyLifetime)) {
			s.replyError(f.ReqID, ErrCodeBadRequest, "expires_at must be in the future and at most a year out")
			return
		}
		at = at.UTC()
		expiresAt = &at
	}
	// Creating an API key waits for the person's fresh memberships in a
	// team (README 7.1), before the key exists.
	if !s.fresh(ctx, f.ReqID, TypeKeyCreate, person(who, membership.IfStale)) {
		return
	}
	author := who.userID
	key, err := s.srv.cfg.Keys.IssueActingAsForDevices(ctx, tenant, name, scope, &author, actsAs, deviceIDs, expiresAt)
	if errors.Is(err, store.ErrInvalidKeyDevices) {
		s.replyError(f.ReqID, ErrCodeBadRequest, "device_ids must select distinct devices in this workspace")
		return
	}
	if errors.Is(err, store.ErrInvalidExpiry) {
		s.replyError(f.ReqID, ErrCodeBadRequest, "expires_at must be in the future and at most a year out")
		return
	}
	if errors.Is(err, store.ErrMembershipForbidden) {
		s.replyError(f.ReqID, ErrCodeNotAuthorized, "workspace or service account access changed")
		return
	}
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
		ActsAs: actsAsName, CreatedBy: who.email, DevicesRestricted: deviceIDs != nil, DeviceIDs: []string{}}
	if actsAs != nil {
		info.ActsAsID = actsAs.String()
	}
	for _, id := range deviceIDs {
		info.DeviceIDs = append(info.DeviceIDs, id.String())
	}
	if rows, err := s.srv.cfg.Keys.List(ctx, tenant); err == nil {
		for _, k := range rows {
			if k.Prefix == prefix {
				info = apiKeyInfo(k)
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
	// Every grant hands the number's key on, to a person, a standing service
	// account or an assistant's reader alike: it waits for the person's fresh
	// step-up, as a connection does (internal/stepup).
	if !s.stepUpRecent(ctx, f.ReqID, who) {
		return
	}
	// Sharing a key (README 7.1): the person IfStale and the recipient
	// always with a fresh GET; a service account is no party (the hook
	// leaves it out), and a person's grant to themselves shares nothing.
	parties := []membership.Party{person(who, membership.IfStale)}
	if user != who.userID {
		parties = append(parties, membership.Party{User: user, How: membership.Always})
	}
	if !s.fresh(ctx, f.ReqID, TypeGrantAdd, parties...) {
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
		if errors.Is(err, store.ErrNumberGone) {
			// It moved to Personal while the grant waited for the
			// workspace's lock (decision 0040's transfer).
			s.replyError(f.ReqID, ErrCodeNotFound, "this number is no longer in this workspace")
			return
		}
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
	// It narrows who holds the number's key: the remaining holders count
	// as backups only on a fresh document (README 7.1, the minute rule),
	// asked for before the revocation's transaction.
	if !s.freshBackups(ctx, f.ReqID, TypeGrantRevoke, tenantUUID, deviceUUID, user) {
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
	allowed, err := s.actionDevices(ctx, store.ActionRead)
	if err != nil {
		s.replyError(f.ReqID, ErrCodeInternal, "could not check grant permissions")
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
		if _, ok := allowed[g.DeviceID]; !ok {
			continue
		}
		out.Grants = append(out.Grants, GrantEntry{
			ArchiveTenantID: g.ArchiveTenantID.String(), DeviceID: g.DeviceID.String(), Label: labels[g.DeviceID.String()],
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
	info := DeviceFromRow(d)
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

// stepUpRecent refuses a person whose session has not proved itself within
// the step-up window (internal/stepup), with step_up_required: the console
// asks and tries again. A grant asks it, because whoever receives one, it is
// a copy of a number's key, and a browser left open must not be enough to
// make one; a deletion, because its WhatsApp logout cannot be undone; and a
// recovery, because it switches every key copy of the number back on.
func (s *session) stepUpRecent(ctx context.Context, reqID string, who actor) bool {
	checker := s.srv.cfg.StepUp
	if checker == nil && s.srv.cfg.Sessions != nil {
		checker = stepup.Recent(s.srv.cfg.Sessions)
	}
	fresh := false
	if checker != nil && who.person {
		var err error
		if fresh, err = checker.Fresh(ctx, who.sessionID); err != nil {
			s.log.Error("reading a session's step-up failed", "error", err)
			s.replyError(reqID, ErrCodeInternal, "could not check your confirmation")
			return false
		}
	}
	if !fresh {
		s.replyError(reqID, ErrCodeStepUpRequired, stepup.Message)
		return false
	}
	return true
}
