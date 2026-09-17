package calling

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/purpshell/meowcaller"
	"go.mau.fi/whatsmeow/types"
)

const ParticipantLimit = 8
const participantHistoryLimit = 32

type Participant struct {
	ID    string `json:"id"`
	PN    string `json:"pn,omitempty"`
	Self  bool   `json:"self"`
	State string `json:"state"`
}
type InviteParticipantResult struct {
	Peer  string `json:"peer"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}
type InviteResult struct {
	Call    Snapshot                  `json:"call"`
	Results []InviteParticipantResult `json:"results"`
}
type groupCall interface {
	AddParticipant(context.Context, string) error
	OnParticipantVideoFrame(func(meowcaller.ParticipantVideoFrame))
}
type groupResolver interface {
	resolve(context.Context, types.JID) (types.JID, types.JID, error)
}
type participantRecord struct {
	Participant
	selected     map[types.JID]uint32
	order        uint64
	pendingUntil time.Time
	localPending bool
}

// initParticipants runs under s.mu. Preserve the initial phone alias after the
// native caller resolves the peer to a LID.
func (s *Service) initParticipants(r *record, original types.JID) {
	r.participants = make(map[string]*participantRecord)
	var self, selfPN types.JID
	for _, jid := range r.device.engine.self() {
		jid = jid.ToNonAD()
		if jid.IsEmpty() {
			continue
		}
		if self.IsEmpty() || jid.Server == types.HiddenUserServer {
			self = jid
		}
		if jid.Server == types.DefaultUserServer {
			selfPN = jid
		}
	}
	if !self.IsEmpty() {
		p := s.putParticipant(r, self.String(), selfPN.String())
		p.Self = true
		p.State = "connected"
	}
	peer, err := individualJID(r.snapshot.Peer)
	if err != nil {
		return
	}
	pn := ""
	if original.Server == types.DefaultUserServer {
		pn = original.String()
	}
	if !peer.IsEmpty() {
		p := s.putParticipant(r, peer.String(), pn)
		p.State = "invited"
	}
}
func (s *Service) putParticipant(r *record, id, pn string) *participantRecord {
	if p := s.findParticipant(r, id, pn); p != nil {
		// A later authoritative LID supersedes a known phone ID without adding a row.
		if jid, err := individualJID(id); err == nil && jid.Server == types.HiddenUserServer && p.ID != id {
			delete(r.participants, p.ID)
			p.ID = id
			r.participants[id] = p
		}
		if pn != "" {
			p.PN = pn
		}
		return p
	}
	if len(r.participants) >= participantHistoryLimit {
		var oldest *participantRecord
		for _, p := range r.participants {
			if !p.Self && (p.State == "left" || p.State == "failed") && (oldest == nil || p.order < oldest.order) {
				oldest = p
			}
		}
		if oldest != nil {
			delete(r.participants, oldest.ID)
		}
	}
	r.participantOrder++
	p := &participantRecord{Participant: Participant{ID: id, PN: pn, State: "invited"}, order: r.participantOrder}
	r.participants[id] = p
	return p
}
func (s *Service) findParticipant(r *record, id, pn string) *participantRecord {
	for _, p := range r.participants {
		if p.ID == id || p.PN == id || (pn != "" && (p.ID == pn || p.PN == pn)) {
			return p
		}
	}
	return nil
}
func (s *Service) participantCount(r *record) int {
	count := 0
	for _, p := range r.participants {
		if p.Self || p.State == "connected" || p.State == "invited" {
			count++
		}
	}
	return count
}
func (s *Service) inviteAllowed(r *record, owner string) bool {
	_, native := r.call.(groupCall)
	return native && s.ownerAlive(owner) && r.owner == owner && r.snapshot.Direction == "outgoing" && r.snapshot.State == "active" && s.devices[r.device.key] == r.device && r.bridge.groupCapable()
}
func (s *Service) snapshotLocked(r *record, owner string) Snapshot {
	s.expireInvites(r)
	snap := r.snapshot
	snap.Owned = r.owner == owner && owner != ""
	snap.ParticipantLimit = ParticipantLimit
	snap.CanInvite = s.inviteAllowed(r, owner) && s.participantCount(r) < ParticipantLimit
	snap.Participants = make([]Participant, 0, len(r.participants))
	for _, p := range r.participants {
		snap.Participants = append(snap.Participants, p.Participant)
	}
	sort.Slice(snap.Participants, func(i, j int) bool {
		a, b := snap.Participants[i], snap.Participants[j]
		if a.Self != b.Self {
			return a.Self
		}
		return a.ID < b.ID
	})
	return snap
}

// Invite serializes signaling and reserves each slot before native conversion.
// The context is also canceled by local teardown, including owner revocation.
func (s *Service) Invite(ctx context.Context, tenantID, deviceID, owner, callID string, targets []string) (InviteResult, error) {
	if s == nil {
		return InviteResult{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return InviteResult{}, err
	}
	if len(targets) == 0 || len(targets) >= ParticipantLimit {
		return InviteResult{}, ErrInvalid
	}
	parsed := make([]types.JID, len(targets))
	for i, target := range targets {
		jid, err := individualJID(target)
		if err != nil {
			return InviteResult{}, ErrInvalid
		}
		parsed[i] = jid
	}
	s.mu.Lock()
	r, err := s.lookup(tenantID, deviceID, owner, callID, false)
	s.mu.Unlock()
	if err != nil {
		return InviteResult{}, err
	}
	r.op.Lock()
	defer r.op.Unlock()
	s.mu.Lock()
	_, err = s.lookup(tenantID, deviceID, owner, callID, false)
	if err == nil && (r.snapshot.Direction != "outgoing" || r.snapshot.State != "active") {
		err = ErrConflict
	}
	if err == nil && !s.inviteAllowed(r, owner) {
		err = ErrUnavailable
	}
	if err != nil {
		s.mu.Unlock()
		return InviteResult{}, err
	}
	opCtx, cancel := context.WithCancel(ctx)
	r.inviteCancel = cancel
	s.mu.Unlock()
	defer func() { cancel(); s.mu.Lock(); r.inviteCancel = nil; s.mu.Unlock() }()
	result := InviteResult{Results: make([]InviteParticipantResult, len(targets))}
	attempted := make(map[string]bool)
	for i, target := range parsed {
		item := InviteParticipantResult{Peer: target.String()}
		result.Results[i] = item
		s.mu.Lock()
		allowed := s.inviteAllowed(r, owner)
		s.mu.Unlock()
		if opCtx.Err() != nil || !allowed {
			result.Results[i].Error = "interrupted"
			continue
		}
		// Check known aliases before network lookup; reject self and current members
		// even when user-info lookup is unavailable.
		s.mu.Lock()
		s.expireInvites(r)
		code := s.inviteIdentityError(r, target.String(), "")
		if code == "" && attempted[target.String()] {
			code = "duplicate"
		}
		s.mu.Unlock()
		if code != "" {
			result.Results[i].Error = code
			continue
		}
		resolver, ok := r.device.engine.(groupResolver)
		if !ok {
			result.Results[i].Error = "unavailable"
			continue
		}
		id, pn, resolveErr := resolver.resolve(opCtx, target)
		if resolveErr != nil {
			result.Results[i].Error = "unavailable"
			if opCtx.Err() != nil {
				result.Results[i].Error = "interrupted"
			}
			continue
		}
		validID, parseErr := individualJID(id.String())
		if parseErr != nil {
			result.Results[i].Error = "unavailable"
			continue
		}
		id = validID
		pnString := ""
		if !pn.IsEmpty() {
			if pn.Server != types.DefaultUserServer {
				result.Results[i].Error = "unavailable"
				continue
			}
			validPN, e := individualJID(pn.String())
			if e != nil {
				result.Results[i].Error = "unavailable"
				continue
			}
			pnString = validPN.String()
		}
		if target.Server == types.DefaultUserServer {
			pnString = target.String()
		}
		s.mu.Lock()
		code = s.inviteIdentityError(r, id.String(), pnString)
		if code == "" && (attempted[id.String()] || (pnString != "" && attempted[pnString])) {
			code = "duplicate"
		}
		if opCtx.Err() != nil || !s.inviteAllowed(r, owner) {
			code = "interrupted"
		}
		if code == "" && s.participantCount(r) >= ParticipantLimit {
			code = "limit"
		}
		var p *participantRecord
		if code == "" {
			p = s.putParticipant(r, id.String(), pnString)
			p.State = "invited"
			p.selected = nil
			p.pendingUntil = s.now().Add(ringTimeout)
			p.localPending = true
			attempted[target.String()] = true
			attempted[id.String()] = true
			if pnString != "" {
				attempted[pnString] = true
			}
		}
		s.mu.Unlock()
		if code != "" {
			result.Results[i].Error = code
			continue
		}
		nativeErr := s.signalInvite(opCtx, r, id, pnString)
		s.mu.Lock()
		interrupted := opCtx.Err() != nil || !s.inviteAllowed(r, owner)
		if nativeErr != nil || interrupted {
			code = "unavailable"
			if interrupted || errors.Is(nativeErr, context.Canceled) || errors.Is(nativeErr, context.DeadlineExceeded) {
				code = "interrupted"
			}
			// A synchronous authoritative callback can replace the roster and
			// already report connection. Update the current row, never the old copy.
			p = s.findParticipant(r, id.String(), pnString)
			if p != nil && p.State == "invited" {
				p.State = "failed"
				p.localPending = false
			}
			result.Results[i].Error = code
		} else {
			result.Results[i].OK = true
		}
		s.mu.Unlock()
	}
	result.Call = s.snapshot(r, owner)
	return result, nil
}
func (s *Service) inviteIdentityError(r *record, id, pn string) string {
	for _, own := range r.device.engine.self() {
		own = own.ToNonAD()
		if !own.IsEmpty() && (own.String() == id || own.String() == pn) {
			return "self"
		}
	}
	if p := s.findParticipant(r, id, pn); p != nil {
		if p.Self {
			return "self"
		}
		if p.State == "connected" || p.State == "invited" {
			return "duplicate"
		}
	}
	return ""
}

// expireInvites runs under s.mu. An unanswered invitation releases its slot;
// another invitation requires a new explicit action.
func (s *Service) expireInvites(r *record) {
	now := s.now()
	for _, p := range r.participants {
		if p.State == "invited" && !p.pendingUntil.IsZero() && !now.Before(p.pendingUntil) {
			p.State = "failed"
			p.localPending = false
			p.selected = nil
		}
	}
}
func (s *Service) signalInvite(ctx context.Context, r *record, id types.JID, pn string) error {
	if state, ok := r.call.GroupState(); ok && state.TransactionID != 0 {
		for _, p := range state.Participants {
			if p.JID.ToNonAD() == id || (!p.PN.IsEmpty() && (p.PN.ToNonAD() == id || p.PN.ToNonAD().String() == pn)) || p.JID.ToNonAD().String() == pn {
				if ring, ok := r.call.(interface {
					RingParticipant(context.Context, string) error
				}); ok {
					return ring.RingParticipant(ctx, id.String())
				}
				return ErrUnavailable
			}
		}
	}
	group, ok := r.call.(groupCall)
	if !ok {
		return ErrUnavailable
	}
	return group.AddParticipant(ctx, id.String())
}
func (s *Service) groupState(r *record, state meowcaller.GroupCallState) {
	s.mu.Lock()
	if r.snapshot.State == "ended" {
		s.mu.Unlock()
		return
	}
	if r.snapshot.Direction != "outgoing" || !s.ownerAlive(r.owner) || !r.bridge.groupCapable() {
		s.mu.Unlock()
		s.end(r, "group_unsupported", true)
		return
	}
	if state.TransactionID != 0 && r.groupTransaction != 0 && state.TransactionID <= r.groupTransaction {
		s.mu.Unlock()
		return
	}
	if state.TransactionID == 0 && r.groupTransaction != 0 {
		s.mu.Unlock()
		return
	}
	s.expireInvites(r)
	// Build the next roster separately so departures release slots before joins,
	// and readers never observe a partially applied or over-capacity roster.
	next := &record{device: r.device, participants: make(map[string]*participantRecord), participantOrder: r.participantOrder}
	now := s.now()
	for id, p := range r.participants {
		clone := *p
		clone.selected = nil
		if !clone.Self {
			if state.TransactionID == 0 && clone.State == "connected" {
				clone.State = "invited"
				clone.pendingUntil = now.Add(ringTimeout)
			}
			if state.TransactionID != 0 && !clone.localPending && (clone.State == "connected" || clone.State == "invited") {
				clone.State = "left"
			}
		}
		next.participants[id] = &clone
	}
	for _, entry := range state.Participants {
		jid, err := individualJID(entry.JID.ToNonAD().String())
		if err != nil {
			continue
		}
		pn := ""
		if entry.PN.Server == types.DefaultUserServer {
			if valid, e := individualJID(entry.PN.ToNonAD().String()); e == nil {
				pn = valid.String()
			}
		}
		p := s.putParticipant(next, jid.String(), pn)
		p.selected = nil
		p.localPending = false
		for _, own := range r.device.engine.self() {
			if !own.IsEmpty() && (own.ToNonAD() == jid || own.ToNonAD().String() == pn) {
				p.Self = true
			}
		}
		p.State = "invited"
		if state.TransactionID != 0 {
			switch entry.State {
			case "connected":
				// Native rosters normally contain one chosen device. A deterministic
				// single choice also prevents two device streams sharing a decoder/SSRC.
				var selected *meowcaller.GroupCallDevice
				for i := range entry.Devices {
					dev := &entry.Devices[i]
					if dev.HasPID && !dev.JID.IsEmpty() && (dev.JID.ToNonAD() == jid || dev.JID.ToNonAD().String() == pn) && (selected == nil || dev.JID.String() < selected.JID.String()) {
						selected = dev
					}
				}
				if selected != nil {
					p.State = "connected"
					p.selected = map[types.JID]uint32{selected.JID: selected.PID}
				}
			case "left", "disconnected", "removed", "rejected", "ended":
				p.State = "left"
			case "failed":
				p.State = "failed"
			}
		}
		if p.Self {
			p.State = "connected"
		}
		if p.State == "invited" {
			if p.pendingUntil.IsZero() {
				p.pendingUntil = now.Add(ringTimeout)
			}
			if !now.Before(p.pendingUntil) {
				p.State = "failed"
			}
		}
		if p.State == "connected" {
			p.pendingUntil = time.Time{}
		}
	}
	if s.participantCount(next) > ParticipantLimit {
		s.mu.Unlock()
		s.end(r, "group_limit", true)
		return
	}
	r.participants = next.participants
	r.participantOrder = next.participantOrder
	r.snapshot.Group = true
	r.bridge.enableGroup()
	connected := make([]string, 0, ParticipantLimit-1)
	for _, p := range r.participants {
		if !p.Self && p.State == "connected" {
			connected = append(connected, p.ID)
		}
	}
	sort.Strings(connected)
	r.bridge.syncGroupParticipants(connected)
	if state.TransactionID != 0 {
		r.groupTransaction = state.TransactionID
	}
	s.mu.Unlock()
}
func (s *Service) participantVideo(r *record, frame meowcaller.ParticipantVideoFrame) {
	// Native group notifications are queued, but authenticated video callbacks
	// run directly on the receive loop. Consult the already updated native cache
	// so the first IDR is not lost while an older notification is still running.
	if latest, ok := r.call.GroupState(); ok {
		s.mu.Lock()
		newer := r.snapshot.State != "ended" && (!r.snapshot.Group || latest.TransactionID > r.groupTransaction)
		s.mu.Unlock()
		if newer {
			s.groupState(r, latest)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !r.snapshot.Group || r.snapshot.State != "active" || !s.ownerAlive(r.owner) || !frame.HasPID || frame.Device.IsEmpty() {
		return
	}
	sender, err := individualJID(frame.Sender.ToNonAD().String())
	if err != nil {
		return
	}
	p := s.findParticipant(r, sender.String(), "")
	if p == nil || p.Self || p.State != "connected" {
		return
	}
	pid, selected := p.selected[frame.Device]
	if !selected || pid != frame.PID {
		return
	}
	// A sender identity must agree with the selected device, including known PN aliases.
	deviceUser := frame.Device.ToNonAD().String()
	if deviceUser != p.ID && deviceUser != p.PN {
		return
	}
	orientation := byte(0)
	if frame.Orientation >= 0 && frame.Orientation <= 3 {
		orientation = byte(frame.Orientation)
	}
	r.bridge.writeParticipantVideo(videoFrame{data: frame.AccessUnit, duration: 33333 * time.Microsecond, orientation: orientation, participant: p.ID, ssrc: frame.SSRC})
}

func (e *nativeEngine) resolve(ctx context.Context, jid types.JID) (types.JID, types.JID, error) {
	if e.client == nil || e.client.Store == nil || e.client.Store.LIDs == nil {
		return types.EmptyJID, types.EmptyJID, ErrUnavailable
	}
	if jid.Server == types.HiddenUserServer {
		pn, err := e.client.Store.LIDs.GetPNForLID(ctx, jid)
		if err != nil {
			return types.EmptyJID, types.EmptyJID, err
		}
		return jid, pn.ToNonAD(), nil
	}
	lid, err := e.client.Store.LIDs.GetLIDForPN(ctx, jid)
	if err != nil {
		return types.EmptyJID, types.EmptyJID, err
	}
	if !lid.IsEmpty() {
		return lid.ToNonAD(), jid, nil
	}
	info, err := e.client.GetUserInfo(ctx, []types.JID{jid})
	if err != nil {
		return types.EmptyJID, types.EmptyJID, err
	}
	if ui, ok := info[jid]; ok && !ui.LID.IsEmpty() {
		return ui.LID.ToNonAD(), jid, nil
	}
	lid, err = e.client.Store.LIDs.GetLIDForPN(ctx, jid)
	if err != nil || lid.IsEmpty() {
		return types.EmptyJID, types.EmptyJID, ErrUnavailable
	}
	return lid.ToNonAD(), jid, nil
}
