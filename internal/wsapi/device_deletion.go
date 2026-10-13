package wsapi

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/access"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// Deleting a number (decision 0038, as amended by 0039 and 0040). Only an
// owner deletes, in every workspace, a personal one included; the number is
// kept 30 days, readable by nobody, in which an owner can recover it; then
// the janitor purges it. A registration that never linked is still removed
// at once, by an owner or an admin.
//
// The order is what makes the WhatsApp logout safe: it cannot be undone, so
// it runs only after the owner check, the step-up, the readers'
// acknowledgement and the commit have all succeeded, and only while the row
// is still excluded. A refused deletion never leaves a live number logged
// out.
//
// No platform call runs inside the deletion's or the recovery's store
// transaction (the plan's D13): when a later release waits for a fresh
// membership document, it asks before the transaction, never inside it.

// Unlinker logs a deleted number out of WhatsApp: on the client this process
// holds, or on one of its own (wa.Registry.Unlink). BeginUnlink marks the
// number from before the deletion commits until the logout is done, so
// neither the supervisor nor the deletion's own notification stops its
// client in between. Unlink calls record with the device lock still held,
// once WhatsApp was asked or the session turned out to be gone, so the
// logout is recorded before a recovery can take the lock.
type Unlinker interface {
	BeginUnlink(deviceID string) (end func())
	Unlink(ctx context.Context, tenantID, deviceID string, jid types.JID,
		recheck func(context.Context) error, record func(context.Context, error)) error
}

// unlinker is the configured Unlinker, the registry by default, or nil.
func (s *Server) unlinker() Unlinker {
	if s.cfg.Unlinker != nil {
		return s.cfg.Unlinker
	}
	if s.cfg.Registry != nil {
		return s.cfg.Registry
	}
	return nil
}

// unlinkTimeout bounds the logout; afterwards the janitor retries it.
const unlinkTimeout = 12 * time.Second

// requireOwner refuses anyone but a person whose role is owner, with
// owner_only. The store checks the live role again, under the workspace
// lock; this is only the fast path.
func (s *session) requireOwner(reqID string) (actor, bool) {
	who := s.actor()
	if !who.person || who.role != "owner" {
		s.replyError(reqID, ErrCodeOwnerOnly, "only an owner of this workspace may delete or recover a number")
		return actor{}, false
	}
	return who, true
}

// ownerError answers the store's refusals that every owner frame shares.
func (s *session) ownerError(reqID string, err error, what string) {
	switch {
	case errors.Is(err, store.ErrOwnerOnly):
		s.replyError(reqID, ErrCodeOwnerOnly, "only an owner of this workspace may delete or recover a number")
	case errors.Is(err, store.ErrNotFound):
		s.replyError(reqID, ErrCodeNotFound, "no such device")
	default:
		s.log.Error(what+" failed", "error", err)
		s.replyError(reqID, ErrCodeInternal, "could not "+what)
	}
}

// deviceRef parses a request naming one device by its full id.
func (s *session) deviceRef(f Frame) (uuid.UUID, bool) {
	var ref DeviceRef
	if err := json.Unmarshal(f.Payload, &ref); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return uuid.Nil, false
	}
	device, err := uuid.Parse(ref.DeviceID)
	if err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, "device_id must be a device id")
		return uuid.Nil, false
	}
	return device, true
}

// handleDeviceDeleteCheck is a deletion's preflight, for an owner, on a live
// number. It changes nothing and needs no step-up.
func (s *session) handleDeviceDeleteCheck(ctx context.Context, f Frame) {
	who, ok := s.requireOwner(f.ReqID)
	if !ok {
		return
	}
	device, ok := s.deviceRef(f)
	if !ok {
		return
	}
	check, err := s.srv.cfg.Devices.DeleteCheck(ctx, uuid.MustParse(who.tenant), who.userID, device)
	if err != nil {
		s.ownerError(f.ReqID, err, "check the deletion")
		return
	}
	s.reply(TypeDeviceDeleteChecked, f.ReqID, DeviceDeleteChecked{
		DeviceID: device.String(), Readers: check.Readers, ServiceAccounts: nonNil(check.ServiceAccounts),
		Assistants: nonNil(check.Assistants), Keys: nonNil(check.Keys), AllNumberKeys: nonNil(check.AllNumberKeys),
		Bytes: check.Bytes, CanUnlink: check.Session && s.srv.unlinker() != nil,
		CheckedAt: check.CheckedAt, RecoverableUntilPreview: check.RecoverableUntilPreview,
	})
}

func nonNil[T any](v []T) []T {
	if v == nil {
		return []T{}
	}
	return v
}

// handleDeviceDelete deletes a number, in this order:
//
//  1. A person, and confirm repeating the id.
//  2. A registration that never linked is removed at once (owner or admin).
//  3. Authorization before any lookup of a deleted number: anyone but an
//     owner learns nothing about one, not even that it exists, and an owner
//     retrying gets the stored state (already). For a live linked number:
//     owner_only, then unlink:false refused, then the step-up.
//  4. Devices.Quarantine, the one transaction (store/device_deletion.go).
//  5. After the commit, on a context of its own (a socket closing must not
//     cancel the logout): the number dropped from this process's
//     subscriptions, the logout and its RecordUnlink under the device lock,
//     then the stop, which releases it.
//  6. The reply, then device.removed to the sessions that could see it.
func (s *session) handleDeviceDelete(ctx context.Context, f Frame) {
	who := s.actor()
	if !who.person {
		s.replyError(f.ReqID, ErrCodeNotAuthorized,
			"this needs a signed-in account; an API key cannot delete a number")
		return
	}
	var req DeleteRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	device, err := uuid.Parse(req.DeviceID)
	if err != nil {
		s.replyError(f.ReqID, ErrCodeNotFound, "no such device")
		return
	}
	if req.Confirm != req.DeviceID {
		s.replyError(f.ReqID, ErrCodeBadRequest,
			"deleting a number needs its id repeated in confirm; nothing was removed")
		return
	}
	tenant := uuid.MustParse(who.tenant)
	dev, err := s.srv.cfg.Devices.Get(ctx, tenant.String(), device.String())
	switch {
	case err == nil && !dev.Identity.Known() && dev.LastConnectedAt.IsZero():
		s.deletePending(ctx, f.ReqID, dev)
		return
	case errors.Is(err, store.ErrNotFound):
		s.replyDeletedAlready(ctx, f.ReqID, who, tenant, device)
		return
	case err != nil:
		s.log.Error("reading a number to delete failed", "device", device, "error", err)
		s.replyError(f.ReqID, ErrCodeInternal, "could not delete the number")
		return
	}
	if _, ok := s.requireOwner(f.ReqID); !ok {
		return
	}
	if !req.Unlink {
		s.replyError(f.ReqID, ErrCodeBadRequest, "a deletion always disconnects the number from WhatsApp; nothing was removed")
		return
	}
	if !s.stepUpRecent(ctx, f.ReqID, who) {
		return
	}
	acknowledged := make([]uuid.UUID, 0, len(req.AcknowledgedReaders))
	for _, raw := range req.AcknowledgedReaders {
		id, err := uuid.Parse(raw)
		if err != nil {
			s.replyError(f.ReqID, ErrCodeBadRequest, "acknowledged_readers must be account ids")
			return
		}
		acknowledged = append(acknowledged, id)
	}

	// Counted, and its viewers found, while the number is still visible.
	var counts *DeviceStat
	if stats, err := s.srv.cfg.Devices.Stats(ctx, tenant.String()); err == nil {
		for _, st := range stats {
			if st.DeviceID == dev.ID {
				stat := toStat(st)
				counts = &stat
			}
		}
		if counts == nil {
			counts = &DeviceStat{}
		}
	}
	viewers := s.srv.viewersOf(ctx, tenant, device)
	unlinker := s.srv.unlinker()
	endMark := func() {}
	if unlinker != nil {
		endMark = unlinker.BeginUnlink(dev.ID)
	}
	defer func() { endMark() }()

	q, err := s.srv.cfg.Devices.Quarantine(ctx, tenant, who.userID, device, acknowledged)
	var unacknowledged *store.ErrDeviceHasReaders
	switch {
	case errors.As(err, &unacknowledged):
		s.reply(TypeError, f.ReqID, Error{Code: ErrCodeDeviceHasReaders,
			Message: "people still read this number; confirm them and try again", Readers: unacknowledged.Readers})
		return
	case err != nil:
		s.ownerError(f.ReqID, err, "delete the number")
		return
	case q.Already:
		s.reply(TypeDeviceGone, f.ReqID, alreadyDeleted(dev.ID, q.DeletedAt, q.PurgeAfter, q.Unlinked, q.NoteCode))
		return
	}

	// Committed. Nothing below may be cancelled by the socket closing.
	bg := context.WithoutCancel(ctx)
	if s.srv.cfg.Bus != nil {
		s.srv.cfg.Bus.DropDevice(tenant, device)
	}
	s.srv.cancelDevicePairing(tenant.String(), dev.ID)

	// The record runs inside Unlink, with the device lock still held, so a
	// recovery never lands between a logout and its record; RecordUnlink
	// checks that an acknowledged session is really gone.
	var record store.UnlinkRecord
	var recordErr error
	recorded := false
	write := func(logoutErr error) {
		recordCtx, cancel := context.WithTimeout(bg, 10*time.Second)
		defer cancel()
		acknowledged := logoutErr == nil || errors.Is(logoutErr, wa.ErrNoSession)
		record, recordErr = s.srv.cfg.Devices.RecordUnlink(recordCtx, tenant, device, q.DeletedAt, acknowledged)
		recorded = true
	}
	if q.Session != nil && unlinker != nil {
		jid, err := types.ParseJID(q.Session.JID)
		if err == nil {
			unlinkCtx, cancel := context.WithTimeout(bg, unlinkTimeout)
			deletedAt := q.DeletedAt
			err = unlinker.Unlink(unlinkCtx, tenant.String(), dev.ID, jid, func(ctx context.Context) error {
				still, err := s.srv.cfg.Devices.StillExcluded(ctx, tenant, device, deletedAt, nil)
				if err == nil && !still {
					err = errNoLongerExcluded
				}
				return err
			}, func(_ context.Context, logoutErr error) { write(logoutErr) })
			cancel()
		}
		switch {
		case errors.Is(err, errNoLongerExcluded):
			// Recovered before the logout: WhatsApp was not asked, and the
			// row is the owner's again, so nothing is recorded on it.
			record, recorded = store.UnlinkRecord{NoteCode: store.NoteUnlinkUnconfirmed}, true
		case err != nil && !errors.Is(err, wa.ErrNoSession):
			// A session already gone from the store is nothing to warn of.
			s.log.Warn("WhatsApp logout of a deleted number was not acknowledged", "device", dev.ID, "error", err)
		}
	}
	if !recorded {
		// Nothing was asked: no session (the stored outcome is read back),
		// no unlinker, or the logout could not start (one more attempt).
		write(errLogoutNotAsked)
	}
	// After the record: on the running client, this releases the lock.
	if s.srv.cfg.Registry != nil {
		s.srv.cfg.Registry.Stop(bg, dev.ID)
	}
	if s.srv.cfg.Router != nil {
		s.srv.cfg.Router.Forget(device)
	}
	endMark()

	if recordErr != nil {
		// The fingerprint is in the commit: the janitor retries the logout,
		// and the purge removes the session by it.
		s.log.Error("recording a deleted number's logout failed", "device", dev.ID, "error", recordErr)
		record = store.UnlinkRecord{NoteCode: store.NoteUnlinkUnconfirmed}
		if q.Session == nil {
			record = store.UnlinkRecord{Unlinked: true, NoteCode: store.NoteAlreadyDisconnected}
		}
	}

	// Loud on purpose: this is what an operator reads afterwards.
	s.log.Warn("number excluded (recoverable)", "device", dev.ID, "by", who.userID, "purge_after", q.PurgeAfter,
		"unlinked", record.Unlinked, "assistants_ended", len(q.AssistantsEnded), "keys_narrowed", len(q.KeysNarrowed))

	out := alreadyDeleted(dev.ID, q.DeletedAt, q.PurgeAfter, record.Unlinked, record.NoteCode)
	out.Already = false
	out.AssistantsEnded, out.KeysNarrowed = q.AssistantsEnded, q.KeysNarrowed
	if counts != nil {
		out.Chats, out.Messages, out.Media = &counts.Chats, &counts.Messages, &counts.Media
	}
	s.reply(TypeDeviceGone, f.ReqID, out)
	for _, viewer := range viewers {
		viewer.reply(TypeDeviceRemoved, "", DeviceRemoved{DeviceID: dev.ID})
	}
	s.srv.RevalidateAccess()
}

// errNoLongerExcluded aborts a logout whose number was recovered, or deleted
// again, since: WhatsApp is never asked.
var errNoLongerExcluded = errors.New("the number is no longer excluded by this deletion")

// errLogoutNotAsked records a deletion whose logout never reached WhatsApp.
var errLogoutNotAsked = errors.New("the logout was not asked")

// alreadyDeleted is device.deleted from a number's stored state.
func alreadyDeleted(device string, deletedAt, purgeAfter time.Time, unlinked bool, note string) DeviceDeleted {
	out := DeviceDeleted{DeviceID: device, Already: true, DeletedAt: &deletedAt, RecoverableUntil: &purgeAfter,
		Unlinked: unlinked, NoteCode: note}
	switch note {
	case store.NoteUnlinkUnconfirmed:
		out.Note = "WhatsApp could not confirm the disconnection; remove this session under Linked devices on the phone"
	case store.NoteAlreadyDisconnected:
		out.Note = "WhatsApp had already disconnected this number"
	}
	return out
}

// replyDeletedAlready answers a deletion of a number that is not live: an
// owner retrying after a lost reply gets the stored state, and anyone else
// not_found, so nobody learns by probing an id that a number is deleted, nor
// until when.
func (s *session) replyDeletedAlready(ctx context.Context, reqID string, who actor, tenant, device uuid.UUID) {
	if who.role != "owner" {
		s.replyError(reqID, ErrCodeNotFound, "no such device")
		return
	}
	excluded, err := s.srv.cfg.Devices.GetExcluded(ctx, tenant, who.userID, device)
	if err != nil {
		s.ownerError(reqID, err, "delete the number")
		return
	}
	s.reply(TypeDeviceGone, reqID, alreadyDeleted(device.String(), excluded.DeletedAt, excluded.PurgeAfter, excluded.Unlinked, excluded.NoteCode))
}

// deletePending removes a registration that never linked: no identity, no
// data, nothing to recover, so no 30 days, no event and no notice.
func (s *session) deletePending(ctx context.Context, reqID string, dev store.Device) {
	if _, ok := s.requireAdmin(reqID); !ok {
		return
	}
	s.srv.cancelDevicePairing(dev.TenantID, dev.ID)
	if s.srv.cfg.Registry != nil {
		s.srv.cfg.Registry.Stop(ctx, dev.ID)
	}
	if err := s.srv.cfg.Devices.DeleteUnpaired(ctx, dev.TenantID, dev.ID); err != nil {
		s.log.Error("removing a registration failed", "device", dev.ID, "error", err)
		s.replyError(reqID, ErrCodeInternal, "could not remove the registration")
		return
	}
	if _, err := s.srv.cfg.Devices.Get(ctx, dev.TenantID, dev.ID); err == nil {
		s.replyError(reqID, ErrCodeConflict, "this number has just linked; open it again before deleting it")
		return
	}
	s.reply(TypeDeviceGone, reqID, DeviceDeleted{DeviceID: dev.ID, Pending: true})
}

// viewersOf is every session of this process that may see the number now,
// found before it is excluded, for the device.removed push.
func (s *Server) viewersOf(ctx context.Context, tenant, device uuid.UUID) []*session {
	s.mu.RLock()
	var candidates []*session
	for sess := range s.sessions {
		if sess.tenantID() == tenant.String() {
			candidates = append(candidates, sess)
		}
	}
	s.mu.RUnlock()
	var out []*session
	for _, sess := range candidates {
		who := sess.actor()
		allowed, err := access.Allows(ctx, access.Actor{Tenant: tenant, User: who.userID, Key: who.keyID, Scope: who.scope, Role: who.role},
			device, store.ActionView, s.cfg.Keys, sess.accountStore())
		if err == nil && allowed {
			out = append(out, sess)
		}
	}
	return out
}

// handleDevicesDeleted lists the workspace's deleted numbers, for owners.
func (s *session) handleDevicesDeleted(ctx context.Context, f Frame) {
	who, ok := s.requireOwner(f.ReqID)
	if !ok {
		return
	}
	numbers, err := s.srv.cfg.Devices.ListDeleted(ctx, uuid.MustParse(who.tenant), who.userID)
	if err != nil {
		s.ownerError(f.ReqID, err, "list the deleted numbers")
		return
	}
	out := DeletedNumbers{Numbers: make([]DeletedNumber, 0, len(numbers))}
	for _, n := range numbers {
		out.Numbers = append(out.Numbers, DeletedNumber{
			DeviceID: n.DeviceID.String(), Label: n.Label, PushName: n.PushName, PN: n.PN,
			DeletedAt: n.DeletedAt, DeletedByName: n.DeletedByName, RecoverableUntil: n.RecoverableUntil,
			Recoverable: n.Recoverable, Purging: n.Purging, Bytes: n.Bytes, Unlinked: n.Unlinked, NoteCode: n.NoteCode,
			RecoveryStatus: recoveryStatus(n.RecoveryState),
		})
	}
	s.reply(TypeDeletedNumbers, f.ReqID, out)
}

func recoveryStatus(r store.RecoveryState) RecoveryStatus {
	return RecoveryStatus{Status: string(r.Status), StatusReason: r.StatusReason, LoggedOut: r.LoggedOut,
		CanResume: r.CanResume, KeyHolders: r.KeyHolders}
}

// handleDeviceRecoverCheck is a recovery's preflight: read-only, owners
// only, no step-up.
func (s *session) handleDeviceRecoverCheck(ctx context.Context, f Frame) {
	who, ok := s.requireOwner(f.ReqID)
	if !ok {
		return
	}
	device, ok := s.deviceRef(f)
	if !ok {
		return
	}
	check, err := s.srv.cfg.Devices.RecoverCheck(ctx, uuid.MustParse(who.tenant), who.userID, device)
	if err != nil {
		s.ownerError(f.ReqID, err, "check the recovery")
		return
	}
	s.reply(TypeDeviceRecoverChecked, f.ReqID, DeviceRecoverChecked{
		DeviceID: device.String(), Readers: check.Readers, ServiceAccounts: nonNil(check.ServiceAccounts), Others: nonNil(check.Others),
		AllNumberKeys: nonNil(check.AllNumberKeys), Recoverable: check.Recoverable, RecoveryStatus: recoveryStatus(check.RecoveryState),
	})
}

// handleDeviceRecover brings a deleted number back, paused: an owner, then
// the step-up, since a recovery switches every key copy of the number back
// on.
func (s *session) handleDeviceRecover(ctx context.Context, f Frame) {
	who, ok := s.requireOwner(f.ReqID)
	if !ok {
		return
	}
	var req RecoverRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	device, err := uuid.Parse(req.DeviceID)
	if err != nil {
		s.replyError(f.ReqID, ErrCodeNotFound, "no such device")
		return
	}
	if req.Confirm != req.DeviceID {
		s.replyError(f.ReqID, ErrCodeBadRequest, "recovering a number needs its id repeated in confirm")
		return
	}
	if !s.stepUpRecent(ctx, f.ReqID, who) {
		return
	}
	tenant := uuid.MustParse(who.tenant)
	recovered, err := s.srv.cfg.Devices.Recover(ctx, tenant, who.userID, device)
	switch {
	case errors.Is(err, store.ErrRecoveryClosed):
		s.replyError(f.ReqID, ErrCodeRecoveryClosed, "this number can no longer be recovered")
		return
	case errors.Is(err, store.ErrDeviceBusy):
		s.replyError(f.ReqID, ErrCodeDeviceBusy, "this number is still being disconnected from WhatsApp; try again in a few seconds")
		return
	case errors.Is(err, store.ErrCapacity):
		s.replyError(f.ReqID, ErrCodeCapacityReached, "the plan has no free slot for this number; delete another number or change the plan")
		return
	case errors.Is(err, store.ErrIdentityInUse):
		s.replyError(f.ReqID, ErrCodeIdentityInUse, "this phone is linked again as another number")
		return
	case err != nil:
		s.ownerError(f.ReqID, err, "recover the number")
		return
	}
	dev, err := s.srv.cfg.Devices.Get(ctx, tenant.String(), device.String())
	if err != nil {
		s.log.Error("reading a recovered number failed", "device", device, "error", err)
		s.replyError(f.ReqID, ErrCodeInternal, "the number was recovered, but could not be read back; reload the list")
		return
	}
	if !recovered.Already {
		s.log.Warn("number recovered", "device", device, "by", who.userID, "status", recovered.Status)
	}
	s.reply(TypeDeviceRecovered, f.ReqID, DeviceRecovered{Device: s.toDeviceInfo(ctx, dev), Already: recovered.Already,
		RecoveryStatus: recoveryStatus(recovered.RecoveryState)})
	s.srv.RevalidateAccess()
}

// handleDeviceNoticeSeen acknowledges a person's own notices.
func (s *session) handleDeviceNoticeSeen(ctx context.Context, f Frame) {
	who := s.actor()
	if !who.person {
		s.replyError(f.ReqID, ErrCodeNotAuthorized, "notices are a person's")
		return
	}
	var req DeviceNoticeSeen
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	if len(req.NoticeIDs) == 0 || len(req.NoticeIDs) > 500 {
		s.replyError(f.ReqID, ErrCodeBadRequest, "name between 1 and 500 notices")
		return
	}
	left, err := s.srv.cfg.Devices.SeeNotices(ctx, uuid.MustParse(who.tenant), who.userID, req.NoticeIDs)
	if err != nil {
		s.log.Error("acknowledging notices failed", "error", err)
		s.replyError(f.ReqID, ErrCodeInternal, "could not acknowledge the notices")
		return
	}
	s.reply(TypeDeviceNotices, f.ReqID, DeviceNotices{Notices: wireNotices(left)})
}

func wireNotices(notices []store.DeviceNotice) []DeviceNotice {
	out := make([]DeviceNotice, 0, len(notices))
	for _, n := range notices {
		out = append(out, DeviceNotice{
			ID: n.ID, DeviceID: n.DeviceID.String(), Kind: n.Kind, Label: n.Label, Hint: n.Hint,
			RaisedAt: n.RaisedAt, LastRaisedAt: n.LastRaisedAt, Pauses: n.Pauses, SeveralActors: n.SeveralActors,
			RaisedByName: n.RaisedByName, RaisedByKind: n.RaisedByKind, Until: n.Until, ResumedAt: n.ResumedAt, PurgedAt: n.PurgedAt,
		})
	}
	return out
}

var _ Unlinker = (*wa.Registry)(nil)
