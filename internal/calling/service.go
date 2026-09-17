// Package calling bridges WhatsApp calls to authenticated browser sessions.
// Call and media state are ephemeral; audio and video are never persisted.
package calling

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
	"whatserver2/internal/browserorigin"

	"github.com/purpshell/meowcaller"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
)

var (
	ErrUnavailable = errors.New("WhatsApp calling unavailable")
	ErrConflict    = errors.New("call is busy or owned by another session")
	ErrNotFound    = errors.New("call not found")
	ErrInvalid     = errors.New("invalid call request")
)

const (
	ringTimeout      = 60 * time.Second
	ticketLifetime   = 30 * time.Second
	terminalLifetime = 30 * time.Second
)

type Snapshot struct {
	ID               string        `json:"id"`
	DeviceID         string        `json:"device_id"`
	Peer             string        `json:"peer"`
	Direction        string        `json:"direction"`
	State            string        `json:"state"`
	Video            bool          `json:"video"`
	Owned            bool          `json:"owned"`
	Reason           string        `json:"reason,omitempty"`
	Group            bool          `json:"group"`
	CanInvite        bool          `json:"can_invite"`
	ParticipantLimit int           `json:"participant_limit"`
	Participants     []Participant `json:"participants"`
}

type engine interface {
	call(context.Context, string, bool) (liveCall, error)
	online() bool
	self() []types.JID
	incoming(func(liveCall))
}

type liveCall interface {
	ID() string
	Peer() types.JID
	State() meowcaller.CallPhase
	IsVideo() bool
	GroupState() (meowcaller.GroupCallState, bool)
	Answer() error
	Reject() error
	Hangup() error
	Play(meowcaller.AudioSource) *meowcaller.Player
	Receive(meowcaller.AudioSink)
	ReceiveVideo(meowcaller.VideoSink)
	SendVideoWithDuration([]byte, time.Duration) error
	OnStateChange(func(meowcaller.CallPhase))
	OnEnd(func(string))
	OnGroupState(func(meowcaller.GroupCallState))
	OnPeerAccept(func())
	OnVideoState(func(meowcaller.VideoState))
}

type deviceKey struct{ tenant, device string }
type device struct {
	key     deviceKey
	client  *whatsmeow.Client
	engine  engine
	active  *record
	cleanup func()
}

type record struct {
	device           *device
	call             liveCall
	snapshot         Snapshot
	owner            string
	pending          bool
	mediaActive      bool
	peerAccepted     bool
	bridge           *mediaBridge
	ring             *time.Timer
	mediaWait        *time.Timer
	cancel           context.CancelFunc
	inviteCancel     context.CancelFunc
	participants     map[string]*participantRecord
	participantOrder uint64
	groupTransaction uint32
	// Serialize local signaling so Answer cannot resurrect a locally ended call.
	op sync.Mutex
}

type ticket struct {
	record  *record
	owner   string
	expires time.Time
}

// Service owns all attached devices and ephemeral, session-scoped calls.
type Service struct {
	// BrowserOrigins is configured before serving requests.
	BrowserOrigins browserorigin.Policy
	mu             sync.Mutex
	attachMu       sync.Mutex
	devices        map[deviceKey]*device
	calls          map[*record]struct{}
	owners         map[string]struct{}
	tickets        map[string]ticket
	now            func() time.Time
}

func New() *Service {
	return &Service{devices: make(map[deviceKey]*device), calls: make(map[*record]struct{}), owners: make(map[string]struct{}), tickets: make(map[string]ticket), now: time.Now}
}

// RegisterOwner starts the lifetime of an authenticated control websocket session.
func (s *Service) RegisterOwner(owner string) {
	if owner == "" {
		return
	}
	s.mu.Lock()
	s.owners[owner] = struct{}{}
	s.mu.Unlock()
}

// Attach must run before client.Connect. Repeated attachment of the same live
// client is harmless. A cleanup for a replaced client never detaches its successor.
func (s *Service) Attach(tenantID, deviceID string, client *whatsmeow.Client) func() {
	if client == nil || client.Store == nil || tenantID == "" || deviceID == "" {
		return func() {}
	}
	s.attachMu.Lock()
	defer s.attachMu.Unlock()
	key := deviceKey{tenantID, deviceID}
	s.mu.Lock()
	old := s.devices[key]
	if old != nil && old.client == client {
		cleanup := old.cleanup
		s.mu.Unlock()
		return cleanup
	}
	s.mu.Unlock()
	// Installing the raw WhatsApp call handler on a running client is unsafe.
	if client.IsConnected() {
		return func() {}
	}
	if old != nil {
		s.detach(old)
	}
	d := &device{key: key, client: client}
	d.engine = &nativeEngine{client: client, calls: meowcaller.NewClient(client, meowcaller.WithLogger(s.failureLogger(d)))}
	var once sync.Once
	handlerID := client.AddEventHandler(func(evt any) {
		switch evt.(type) {
		case *events.Disconnected, *events.LoggedOut:
			s.mu.Lock()
			r := d.active
			s.mu.Unlock()
			if r != nil {
				s.end(r, "disconnected", true)
			}
		}
	})
	d.cleanup = func() {
		once.Do(func() {
			s.detach(d)
			// Event callbacks hold whatsmeow's event-handler read lock.
			go client.RemoveEventHandler(handlerID)
		})
	}
	s.mu.Lock()
	s.devices[key] = d
	s.mu.Unlock()
	d.engine.incoming(func(c liveCall) { s.incoming(d, c) })
	return d.cleanup
}

func (s *Service) detach(d *device) {
	s.mu.Lock()
	if s.devices[d.key] == d {
		delete(s.devices, d.key)
	}
	r := d.active
	s.mu.Unlock()
	if r != nil {
		s.end(r, "disconnected", true)
	}
}

func (s *Service) Attached(tenantID, deviceID string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.devices[deviceKey{tenantID, deviceID}] != nil
}

func (s *Service) List(tenantID, deviceID, owner string) []Snapshot {
	out := []Snapshot{}
	if s == nil {
		return out
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.ownerAlive(owner) {
		return out
	}
	for r := range s.calls {
		if r.device.key != (deviceKey{tenantID, deviceID}) || r.snapshot.ID == "" {
			continue
		}
		snap := s.snapshotLocked(r, owner)
		out = append(out, snap)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *Service) Start(ctx context.Context, tenantID, deviceID, owner, target string, video bool) (Snapshot, error) {
	if s == nil {
		return Snapshot{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	jid, err := individualJID(target)
	if err != nil {
		return Snapshot{}, err
	}
	s.mu.Lock()
	d := s.devices[deviceKey{tenantID, deviceID}]
	if !s.ownerAlive(owner) {
		s.mu.Unlock()
		return Snapshot{}, ErrUnavailable
	}
	if d == nil || !d.engine.online() {
		s.mu.Unlock()
		return Snapshot{}, ErrUnavailable
	}
	for _, self := range d.engine.self() {
		if !self.IsEmpty() && self.ToNonAD() == jid {
			s.mu.Unlock()
			return Snapshot{}, fmt.Errorf("%w: cannot call yourself", ErrInvalid)
		}
	}
	if d.active != nil {
		s.mu.Unlock()
		return Snapshot{}, ErrConflict
	}
	callCtx, cancel := context.WithCancel(ctx)
	r := &record{device: d, owner: owner, pending: true, bridge: newMediaBridge(), cancel: cancel, snapshot: Snapshot{DeviceID: deviceID, Peer: jid.String(), Direction: "outgoing", State: "ringing", Video: video}}
	d.active = r
	s.calls[r] = struct{}{}
	r.ring = time.AfterFunc(ringTimeout, func() { s.end(r, "timeout", true) })
	s.mu.Unlock()
	c, err := d.engine.call(callCtx, jid.String(), video)
	cancel()
	s.mu.Lock()
	r.pending = false
	alive := s.devices[d.key] == d && s.ownerAlive(owner) && r.snapshot.State != "ended" && ctx.Err() == nil
	if alive && err == nil && c != nil {
		r.call = c
		r.snapshot.ID = c.ID()
		r.snapshot.Peer = c.Peer().ToNonAD().String()
		s.initParticipants(r, jid)
		r.mediaWait = time.AfterFunc(ticketLifetime, func() { s.expireMedia(r) })
	}
	if !alive && d.active == r {
		d.active = nil
	}
	s.mu.Unlock()
	if err != nil || c == nil {
		s.end(r, "failed", false)
		if err == nil {
			err = ErrUnavailable
		}
		return Snapshot{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if !alive {
		s.end(r, "failed", false)
		go c.Hangup() //nolint:errcheck // best-effort remote notification after local call rejection
		return Snapshot{}, ErrUnavailable
	}
	s.configure(r)
	return s.snapshot(r, owner), nil
}

func (s *Service) incoming(d *device, c liveCall) {
	if c == nil {
		return
	}
	_, group := c.GroupState()
	jid, err := individualJID(c.Peer().ToNonAD().String())
	// Unsupported conference offers remain available in the WhatsApp phone app.
	if group || err != nil {
		return
	}
	video := c.IsVideo()
	s.mu.Lock()
	if s.devices[d.key] != d || d.active != nil {
		s.mu.Unlock()
		// Do not block whatsmeow event dispatch on signaling I/O.
		go c.Reject() //nolint:errcheck // best-effort remote rejection; no local call was accepted
		return
	}
	r := &record{device: d, call: c, bridge: newMediaBridge(), snapshot: Snapshot{ID: c.ID(), DeviceID: d.key.device, Peer: jid.String(), Direction: "incoming", State: "ringing", Video: video}}
	s.initParticipants(r, jid)
	d.active = r
	s.calls[r] = struct{}{}
	r.ring = time.AfterFunc(ringTimeout, func() { s.end(r, "timeout", true) })
	s.mu.Unlock()
	s.configure(r)
}

func (s *Service) configure(r *record) {
	r.op.Lock()
	defer r.op.Unlock()
	s.mu.Lock()
	ended := r.snapshot.State == "ended"
	c := r.call
	s.mu.Unlock()
	if ended || c == nil {
		return
	}
	c.Play(r.bridge)
	c.Receive(r.bridge)
	if r.snapshot.Video {
		c.OnVideoState(r.bridge.setVideoState)
		c.ReceiveVideo(r.bridge)
	}
	c.OnEnd(func(reason string) { s.end(r, safeReason(reason), false) })
	if gc, ok := c.(groupCall); ok {
		gc.OnParticipantVideoFrame(func(frame meowcaller.ParticipantVideoFrame) { s.participantVideo(r, frame) })
	}
	c.OnGroupState(func(state meowcaller.GroupCallState) { s.groupState(r, state) })
	c.OnStateChange(func(phase meowcaller.CallPhase) { s.phase(r, phase) })
	c.OnPeerAccept(func() {
		s.mu.Lock()
		allowed := r.snapshot.Direction == "outgoing" && s.ownerAlive(r.owner) && r.snapshot.State != "ended"
		if allowed {
			r.peerAccepted = true
		}
		s.mu.Unlock()
		if !allowed {
			return
		}
		r.bridge.allowAudio()
		s.phase(r, c.State())
	})
	s.phase(r, c.State())
}

func (s *Service) phase(r *record, phase meowcaller.CallPhase) {
	// OnEnd preserves the remote reason; State() covers calls that ended before
	// callback installation.
	if phase == meowcaller.CallPhaseEnded {
		s.end(r, "ended", false)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.snapshot.State == "ended" {
		return
	}
	if phase == meowcaller.CallPhaseActive {
		r.mediaActive = true
	}
	// Relay preparation is eager in meowcaller: Connecting/Active does not
	// imply the user or remote peer accepted the invitation.
	if (r.snapshot.Direction == "incoming" && r.owner == "") || (r.snapshot.Direction == "outgoing" && !r.peerAccepted) {
		return
	}
	if r.mediaActive {
		r.snapshot.State = "active"
		if !r.snapshot.Group {
			for _, p := range r.participants {
				p.State = "connected"
			}
		}
		if r.ring != nil {
			r.ring.Stop()
			r.ring = nil
		}
	} else if phase == meowcaller.CallPhaseConnecting || r.peerAccepted {
		r.snapshot.State = "connecting"
	}

}

func (s *Service) snapshot(r *record, owner string) Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshotLocked(r, owner)
}

func (s *Service) Answer(ctx context.Context, tenantID, deviceID, owner, callID string) (Snapshot, error) {
	if s == nil {
		return Snapshot{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	s.mu.Lock()
	r, err := s.lookup(tenantID, deviceID, owner, callID, true)
	if err == nil && (r.snapshot.Direction != "incoming" || r.snapshot.State != "ringing") {
		err = ErrConflict
	}
	if err == nil {
		r.owner = owner
		r.snapshot.State = "connecting"
		r.mediaWait = time.AfterFunc(ticketLifetime, func() { s.expireMedia(r) })
	}
	s.mu.Unlock()
	if err != nil {
		return Snapshot{}, err
	}
	r.op.Lock()
	s.mu.Lock()
	alive := s.ownerAlive(owner) && r.snapshot.State != "ended"
	s.mu.Unlock()
	if !alive {
		r.op.Unlock()
		return Snapshot{}, ErrUnavailable
	}
	err = r.call.Answer()
	r.op.Unlock()
	if err != nil {
		s.end(r, "failed", true)
		return Snapshot{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	r.bridge.allowAudio()
	return s.snapshot(r, owner), nil
}

func (s *Service) Reject(ctx context.Context, tenantID, deviceID, owner, callID string) error {
	if s == nil {
		return ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	r, err := s.lookup(tenantID, deviceID, owner, callID, true)
	if err == nil && (r.snapshot.Direction != "incoming" || r.snapshot.State != "ringing") {
		err = ErrConflict
	}
	if err == nil {
		r.owner = owner
	}
	s.mu.Unlock()
	if err != nil {
		return err
	}
	s.end(r, "rejected", true)
	return nil
}

func (s *Service) Hangup(ctx context.Context, tenantID, deviceID, owner, callID string) error {
	if s == nil {
		return ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	r, err := s.lookup(tenantID, deviceID, owner, callID, false)
	s.mu.Unlock()
	if err != nil {
		return err
	}
	s.end(r, "hangup", true)
	return nil
}

// Caller holds s.mu. Unclaimed incoming calls may only be claimed by Answer or Reject.
func (s *Service) lookup(tenantID, deviceID, owner, callID string, claim bool) (*record, error) {
	if !s.ownerAlive(owner) {
		return nil, ErrUnavailable
	}
	for r := range s.calls {
		if r.device.key != (deviceKey{tenantID, deviceID}) || r.snapshot.ID != callID || callID == "" {
			continue
		}
		if r.snapshot.State == "ended" {
			return nil, ErrNotFound
		}
		if r.owner != owner && (!claim || r.owner != "") {
			return nil, ErrConflict
		}
		return r, nil
	}
	return nil, ErrNotFound
}

func (s *Service) ownerAlive(owner string) bool { _, ok := s.owners[owner]; return owner != "" && ok }

// ReleaseOwner invalidates the session before stopping media, so late commands
// and in-flight outgoing call setup cannot create an orphaned microphone stream.
func (s *Service) ReleaseOwner(owner string) {
	if s == nil || owner == "" {
		return
	}
	s.mu.Lock()
	delete(s.owners, owner)
	var owned []*record
	for r := range s.calls {
		if r.owner == owner {
			owned = append(owned, r)
		}
	}
	for token, t := range s.tickets {
		if t.owner == owner {
			delete(s.tickets, token)
		}
	}
	s.mu.Unlock()
	for _, r := range owned {
		s.end(r, "session_closed", true)
	}
}

func (s *Service) end(r *record, reason string, signal bool) {
	s.mu.Lock()
	if r.snapshot.State == "ended" {
		if r.snapshot.Reason == "ended" && reason != "ended" {
			r.snapshot.Reason = reason
		}
		s.mu.Unlock()
		return
	}
	reject := r.snapshot.Direction == "incoming" && r.snapshot.State == "ringing"
	r.snapshot.State = "ended"
	r.snapshot.Reason = reason
	if r.ring != nil {
		r.ring.Stop()
		r.ring = nil
	}
	if r.mediaWait != nil {
		r.mediaWait.Stop()
		r.mediaWait = nil
	}
	if r.inviteCancel != nil {
		r.inviteCancel()
	}
	if r.cancel != nil {
		r.cancel()
	}
	if r.device.active == r && !r.pending {
		r.device.active = nil
	}
	for token, t := range s.tickets {
		if t.record == r {
			delete(s.tickets, token)
		}
	}
	c := r.call
	s.mu.Unlock()
	_ = r.bridge.Close() //nolint:errcheck // local teardown completes even if the peer socket already closed
	time.AfterFunc(terminalLifetime, func() { s.mu.Lock(); delete(s.calls, r); s.mu.Unlock() })
	if signal && c != nil {
		// The library lacks context-aware Answer/Hangup. Local teardown is immediate;
		// peer notification is serialized outside the control and event callbacks.
		go func() {
			r.op.Lock()
			defer r.op.Unlock()
			if reject {
				_ = c.Reject() //nolint:errcheck // best-effort peer notification after authoritative local teardown
			} else {
				_ = c.Hangup() //nolint:errcheck // best-effort peer notification after authoritative local teardown
			}
		}()
	}
}

func (s *Service) expireMedia(r *record) {
	if !r.bridge.connected() {
		s.end(r, "media_timeout", true)
	}
}

func (s *Service) MediaTicket(tenantID, deviceID, owner, callID string) (string, error) {
	if s == nil {
		return "", ErrUnavailable
	}
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.lookup(tenantID, deviceID, owner, callID, false)
	if err != nil {
		return "", err
	}
	if r.bridge.connected() {
		return "", ErrConflict
	}
	now := s.now()
	for previous, t := range s.tickets {
		if t.record == r || !now.Before(t.expires) {
			delete(s.tickets, previous)
		}
	}
	s.tickets[token] = ticket{record: r, owner: owner, expires: now.Add(ticketLifetime)}
	return token, nil
}

func (s *Service) consumeTicket(token string) (*record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tickets[token]
	delete(s.tickets, token)
	if !ok || !s.now().Before(t.expires) || !s.ownerAlive(t.owner) || t.record.owner != t.owner || t.record.snapshot.State == "ended" || s.devices[t.record.device.key] != t.record.device {
		return nil, ErrNotFound
	}
	return t.record, nil
}

func individualJID(raw string) (types.JID, error) {
	raw = strings.TrimSpace(raw)
	if len(raw) > 100 || raw == "" {
		return types.EmptyJID, ErrInvalid
	}
	if !strings.ContainsRune(raw, '@') {
		raw = strings.TrimPrefix(raw, "+") + "@" + types.DefaultUserServer
	}
	jid, err := types.ParseJID(raw)
	if err != nil || (jid.Server != types.DefaultUserServer && jid.Server != types.HiddenUserServer) || jid.User == "" || jid.Device != 0 || jid.RawAgent != 0 {
		return types.EmptyJID, fmt.Errorf("%w: individual phone or LID required", ErrInvalid)
	}
	for _, c := range jid.User {
		if c < '0' || c > '9' {
			return types.EmptyJID, ErrInvalid
		}
	}
	return jid.ToNonAD(), nil
}

func randomToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
func safeReason(reason string) string {
	switch reason {
	case "busy", "rejected", "timeout", "hangup", "unavailable", "canceled", "cancelled":
		return reason
	}
	return "ended"
}

type nativeEngine struct {
	client *whatsmeow.Client
	calls  *meowcaller.Client
}

func (e *nativeEngine) call(ctx context.Context, target string, video bool) (liveCall, error) {
	return e.calls.CallWithOptions(ctx, target, meowcaller.CallOptions{Video: video})
}
func (e *nativeEngine) online() bool { return e.client.IsConnected() && e.client.IsLoggedIn() }
func (e *nativeEngine) self() []types.JID {
	return []types.JID{e.client.Store.GetJID(), e.client.Store.GetLID()}
}
func (e *nativeEngine) incoming(fn func(liveCall)) {
	e.calls.OnIncomingCall(func(c *meowcaller.Call) { fn(c) })
}
