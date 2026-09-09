package wsapi

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// handlePair creates a device row and starts a pairing attempt, streaming
// codes back to the client until the phone accepts or the window closes.
func (s *session) handlePair(ctx context.Context, f Frame) {
	// Pairing links a phone number to this tenant and decides who can read
	// it. That is an operator's act: the command line with a full key, or an
	// owner or admin in the browser.
	var req PairRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, "malformed pair request: "+err.Error())
		return
	}

	if !req.Resume {
		if _, ok := s.requireOperator(f.ReqID); !ok {
			return
		}
	}
	mode := wa.ModePassive
	if req.ReceiptMode != "" {
		parsed, err := wa.ParseReceiptMode(req.ReceiptMode)
		if err != nil {
			s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
			return
		}
		mode = parsed
	}

	opts := wa.PairOptions{
		Method:      wa.PairMethod(req.Method),
		Phone:       req.Phone,
		DisplayName: req.DisplayName,
	}
	// Validated before the row is created, so a typo does not leave an
	// orphaned device behind.
	if err := opts.Validate(); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}

	tenant := s.tenantID()
	var dev store.Device
	var err error
	if req.Resume {
		dev, err = s.srv.cfg.Devices.Get(ctx, tenant, req.DeviceID)
		if err != nil {
			s.replyError(f.ReqID, ErrCodeNotFound, "no such device")
			return
		}
		if !s.authorizeDevice(ctx, f, uuid.MustParse(dev.ID), store.ActionManage) {
			return
		}
		if s.running(dev.ID) {
			s.replyError(f.ReqID, ErrCodeConflict, "pairing is already in progress for this device")
			return
		}
		if dev.Identity.Known() || !dev.LastConnectedAt.IsZero() {
			s.replyError(f.ReqID, ErrCodeConflict, "this device is already linked; resume its connection instead")
			return
		}
		// The original grants remain the sole source of access. A retry cannot
		// silently replace the key and make existing history unreadable.
		if dev.Epoch == 0 {
			s.replyError(f.ReqID, ErrCodeConflict, "this incomplete device has no encryption key; delete it and connect a new number")
			return
		}
		if len(req.ArchivePublicKey) > 0 || len(req.Grants) > 0 || req.Orphan {
			s.replyError(f.ReqID, ErrCodeBadRequest, "retry pairing must preserve existing keys and grants")
			return
		}
		mode = dev.ReceiptMode
	} else {
		// The archive key has to exist before the device does anything, because the
		// first message can arrive seconds after the phone accepts and a device
		// with no key cannot seal. Refusing here is the difference between a clear
		// error now and a stream of ingest failures later.
		pub, err := seal.ParsePublicKey(req.ArchivePublicKey)
		if err != nil {
			s.replyError(f.ReqID, ErrCodeBadRequest,
				"pairing needs this device's archive public key: "+err.Error())
			return
		}
		if len(req.Grants) == 0 && !req.Orphan {
			// Refused rather than warned. A device with no grant is an archive
			// only whoever kept the generated key can read, and that is how the
			// first archive of this project was lost. The caller has to say it
			// meant that.
			s.replyError(f.ReqID, ErrCodeBadRequest,
				"no grants: nobody could read this device. Seal its key to at least one "+
					"account, or set orphan to pair anyway and keep the key yourself")
			return
		}

		tenantUUID, err := uuid.Parse(tenant)
		if err != nil {
			s.replyError(f.ReqID, ErrCodeInternal, "bad tenant")
			return
		}
		label := req.Label
		if label == "" {
			label = "device"
		}
		dev, err = s.srv.cfg.Devices.CreateWithID(ctx, tenant, req.DeviceID, label, mode)
		if err != nil {
			if strings.Contains(err.Error(), "workspace device capacity reached") {
				s.replyError(f.ReqID, ErrCodeBadRequest, "workspace device capacity reached; remove a device or increase capacity in the console")
				return
			}
			s.log.Error("creating a device row failed", "error", err)
			s.replyError(f.ReqID, ErrCodeInternal, "could not create the device")
			return
		}
		deviceUUID := uuid.MustParse(dev.ID)

		if err := s.srv.cfg.Keys2.CreateArchiveKey(ctx, tenantUUID, deviceUUID, 1, pub); err != nil {
			s.log.Error("could not record the archive key", "device", dev.ID, "error", err)
			s.cleanupFailedPairing(ctx, tenant, dev.ID)
			s.replyError(f.ReqID, ErrCodeInternal, "could not record the archive key")
			return
		}
		// Grants next, and failures are fatal to the pairing rather than tolerated:
		// a device paired with no way to read it is an archive nobody can open, and
		// finding that out later means throwing the messages away.
		for _, g := range req.Grants {
			user, err := uuid.Parse(g.UserID)
			if err != nil {
				s.cleanupFailedPairing(ctx, tenant, dev.ID)
				s.replyError(f.ReqID, ErrCodeBadRequest, "a grant names an account id that is not a uuid")
				return
			}
			if err := s.srv.cfg.Keys2.PutGrant(ctx, store.Grant{
				TenantID: tenantUUID, DeviceID: deviceUUID, UserID: user,
				Epoch: 1, SealedDSK: g.SealedDSK,
			}, nil); err != nil {
				s.log.Error("could not record a key grant", "device", dev.ID, "error", err)
				s.cleanupFailedPairing(ctx, tenant, dev.ID)
				s.replyError(f.ReqID, ErrCodeInternal, "could not record a key grant")
				return
			}
		}
		if len(req.Grants) == 0 {
			s.log.Warn("a device was paired with no key grants; only whoever holds the "+
				"generated key can read it", "device", dev.ID)
		}

	}
	if s.srv.cfg.Registry == nil {
		if !req.Resume {
			s.cleanupFailedPairing(ctx, tenant, dev.ID)
		}
		s.replyError(f.ReqID, ErrCodeInternal, "WhatsApp connection is unavailable")
		return
	}

	if req.Resume {
		if err := s.srv.cfg.Devices.SetPaused(ctx, tenant, dev.ID, false); err != nil {
			s.replyError(f.ReqID, ErrCodeInternal, "could not resume pairing")
			return
		}
	}
	pair, err := s.srv.cfg.Registry.StartPairing(ctx, tenant, dev.ID,
		wa.ReceiptPolicy{Mode: mode, Recorder: s.recordReceipt}, opts)
	if err != nil {
		// The row is removed on failure: an unpaired device that never even
		// started is noise, not history.
		if delErr := func() error {
			if req.Resume {
				return nil
			}
			return s.srv.cfg.Devices.DeleteUnpaired(context.WithoutCancel(ctx), tenant, dev.ID)
		}(); delErr != nil {
			s.log.Warn("could not clean up an abandoned device row", "device", dev.ID, "error", delErr)
		}
		code := ErrCodeInternal
		if errors.Is(err, wa.ErrAlreadyRunning) {
			code = ErrCodeConflict
		}
		s.replyError(f.ReqID, code, err.Error())
		return
	}

	s.pairMu.Lock()
	s.pairings[dev.ID] = pair
	s.pairMu.Unlock()
	// Once published, a concurrent pause/delete can cancel this attempt.
	// Recheck the interval before it was published as well.
	if current, err := s.srv.cfg.Devices.Get(ctx, tenant, dev.ID); err != nil || current.Paused {
		pair.Cancel()
	}

	defer func() {
		s.pairMu.Lock()
		delete(s.pairings, dev.ID)
		s.pairMu.Unlock()
	}()

	completed := false
	terminal := false
	defer func() {
		if !completed {
			s.cleanupFailedPairing(ctx, tenant, dev.ID)
		}
	}()
	for evt := range pair.Events() {
		switch evt.Kind {
		case wa.PairEventCode:
			s.reply(TypePairCode, f.ReqID, PairCode{
				DeviceID: dev.ID, Code: evt.Code, Expires: evt.Expires,
			})
		case wa.PairEventQR:
			s.reply(TypePairQR, f.ReqID, PairQR{
				DeviceID: dev.ID, Code: evt.Code, Expires: evt.Expires,
			})
		case wa.PairEventSuccess:
			completed = true
			s.reply(TypePairSuccess, f.ReqID, PairResult{DeviceID: dev.ID})
		case wa.PairEventTimeout:
			terminal = true
			s.cleanupFailedPairing(ctx, tenant, dev.ID)
			s.reply(TypePairTimeout, f.ReqID, PairResult{DeviceID: dev.ID})
		case wa.PairEventError:
			terminal = true
			s.cleanupFailedPairing(ctx, tenant, dev.ID)
			s.replyError(f.ReqID, ErrCodeInternal, evt.Err.Error())
		}
	}
	if !completed && !terminal {
		s.reply(TypePairTimeout, f.ReqID, PairResult{DeviceID: dev.ID})
	}
}

// cleanupFailedPairing removes the device row for an attempt that never
// completed. Leaving it would accumulate rows in status "new" that no operator
// can account for.
func (s *session) cleanupFailedPairing(ctx context.Context, tenant, deviceID string) {
	if err := s.srv.cfg.Devices.DeleteUnpaired(context.WithoutCancel(ctx), tenant, deviceID); err != nil &&
		!errors.Is(err, store.ErrNotFound) {
		s.log.Warn("could not clean up a failed pairing", "device", deviceID, "error", err)
	}
}

func (s *session) handlePairCancel(f Frame) {
	var ref DeviceRef
	if err := json.Unmarshal(f.Payload, &ref); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	s.pairMu.Lock()
	pair, ok := s.pairings[ref.DeviceID]
	s.pairMu.Unlock()
	if !ok {
		s.replyError(f.ReqID, ErrCodeNotFound, "no pairing in progress for that device")
		return
	}
	pair.Cancel()
}

func (s *session) handleDevicesList(ctx context.Context, f Frame) {
	tenant := s.tenantID()
	allowed, err := s.actionDevices(ctx, store.ActionView)
	if err != nil {
		s.replyError(f.ReqID, ErrCodeInternal, "could not check device access")
		return
	}
	rows, err := s.srv.cfg.Devices.List(ctx, tenant)
	if err != nil {
		s.log.Error("listing devices failed", "error", err)
		s.replyError(f.ReqID, ErrCodeInternal, "could not list devices")
		return
	}
	out := make([]DeviceInfo, 0, len(rows))
	for _, d := range rows {
		if allowed != nil {
			if _, ok := allowed[uuid.MustParse(d.ID)]; !ok {
				continue
			}
		}
		out = append(out, s.toDeviceInfo(ctx, d))
	}
	s.reply(TypeDevices, f.ReqID, Devices{Devices: out})
}

// handleUsersList reports the accounts a device key can be granted to.
//
// Public keys only. It is what a pairing client needs in order to seal a grant
// per account, and it is the whole reason the server holds a public key at all.
func (s *session) handleUsersList(ctx context.Context, f Frame) {
	// Who has an account here is tenant configuration, and the reason to ask
	// is to seal a grant, which is an operator's act.
	if _, ok := s.requireOperator(f.ReqID); !ok {
		return
	}
	if s.srv.cfg.Accounts == nil {
		s.replyError(f.ReqID, ErrCodeInternal, "accounts are not configured on this server")
		return
	}
	tenant, err := uuid.Parse(s.tenantID())
	if err != nil {
		s.replyError(f.ReqID, ErrCodeInternal, "bad tenant")
		return
	}
	rows, err := s.srv.cfg.Accounts.List(ctx, tenant)
	if err != nil {
		s.log.Error("listing accounts failed", "error", err)
		s.replyError(f.ReqID, ErrCodeInternal, "could not list accounts")
		return
	}
	out := make([]UserSummary, 0, len(rows))
	for _, u := range rows {
		out = append(out, UserSummary{
			ID: u.ID.String(), Email: store.ServiceName(u), Role: u.Role, PublicKey: u.PublicKey,
		})
	}
	s.reply(TypeUsers, f.ReqID, Users{Users: out})
}

func (s *session) handleDeviceStop(ctx context.Context, f Frame) {
	var ref DeviceRef
	if err := json.Unmarshal(f.Payload, &ref); err != nil {
		s.replyError(f.ReqID, ErrCodeBadRequest, err.Error())
		return
	}
	// Stopping a device stops the archive for every reader of it. A key
	// that was issued to read or to send does not get to do that.
	_, resolved, ok := s.resolveDevice(ctx, f, ref.DeviceID)
	if !ok {
		return
	}
	ref.DeviceID = resolved.String()
	tenant := s.tenantID()
	// Confirm ownership before acting. Row-level security answers a
	// cross-tenant lookup with "not found", so this both authorises and
	// validates in one step.
	if _, err := s.srv.cfg.Devices.Get(ctx, tenant, ref.DeviceID); err != nil {
		s.replyError(f.ReqID, ErrCodeNotFound, "no such device")
		return
	}
	if err := s.srv.cfg.Devices.SetPaused(ctx, tenant, ref.DeviceID, true); err != nil {
		s.replyError(f.ReqID, ErrCodeInternal, "could not pause the device")
		return
	}
	s.srv.cancelDevicePairing(tenant, ref.DeviceID)
	if s.srv.cfg.Registry != nil {
		s.srv.cfg.Registry.Stop(ctx, ref.DeviceID)
	}
	statusCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := s.srv.cfg.Devices.SetStatus(statusCtx, tenant, ref.DeviceID, wa.StatusOffline, "paused by request"); err != nil {
		// The durable pause already succeeded and supervision has stopped.
		s.log.Warn("device paused but display status could not be updated", "device", ref.DeviceID, "error", err)
	}
	s.srv.BroadcastDeviceStatus(tenant, ref.DeviceID, string(wa.StatusOffline), "paused by request")
	s.reply(TypeDeviceStatus, f.ReqID, DeviceStatus{
		DeviceID: ref.DeviceID, Status: string(wa.StatusOffline), Reason: "paused by request",
	})
}

// recordReceipt funnels receipt decisions into the metrics counter. In passive
// mode the suppressed series should be the only one moving.
func (s *session) recordReceipt(kind, decision string) {
	if s.srv.cfg.Metrics != nil {
		s.srv.cfg.Metrics.ReceiptDecisions.WithLabelValues(kind, decision).Inc()
	}
}
