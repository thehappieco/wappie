// Package relink links a logged-out number again into the number Wappie
// already holds (decision 0057, spec 14.13): a new QR, the same row, key,
// epoch, grants, readers and receipt mode, kept only when the account that
// scans is the number's own.
//
// One path for Wappie's own sheet now and for the console's command later.
// Each caller makes its own checks of who asks; this package makes the
// checks of the number, starts the pairing and names its end with a code of
// the contract's 14.9, so the console's runner maps them one to one.
package relink

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// The codes of a relink's refusals, as the contract's 14.9 names them.
const (
	CodeOtherAccount  = "other_account"
	CodeLinkTimeout   = "link_timeout"
	CodeConnectFailed = "connect_failed"
	CodeNumberHeld    = "number_held"
	CodeReadOnly      = "read_only"
	CodeNoReader      = "no_reader"
	// CodeCapacityReached is never answered today: the logged-out number
	// keeps its place, and the attach is an UPDATE, which the capacity
	// triggers do not check. It is named so a caller can map it.
	CodeCapacityReached = "capacity_reached"
	CodeStoragePaused   = "storage_paused"
	CodeItemBusy        = "item_busy"
	CodeStateChanged    = "state_changed"
)

// Refusal is a relink's end other than linked: a code, a fixed English
// message that names no account, and for item_busy the time to wait.
type Refusal struct {
	Code       string
	Message    string
	RetryAfter time.Duration
	// Stage and Half are for the log: where it was decided (entry, start,
	// scan, attach or end), and for a scan which half of the account
	// differed.
	Stage, Half string
}

func (r *Refusal) Error() string { return "relink: " + r.Code + ": " + r.Message }

var messages = map[string]string{
	CodeOtherAccount:    "the QR code was scanned by another WhatsApp account, or by this account under another phone number; nothing was stored",
	CodeLinkTimeout:     "the QR code was not scanned in time",
	CodeConnectFailed:   "the link did not start or did not finish",
	CodeNumberHeld:      "this WhatsApp account is already linked here as another number",
	CodeReadOnly:        "Wappie does not hold this number's full WhatsApp identity to compare the scan with",
	CodeNoReader:        "nobody holds this number's key",
	CodeCapacityReached: "there is no free place for this number to sync",
	CodeStoragePaused:   "the workspace's storage is paused",
	CodeItemBusy:        "this number is being linked or moved already",
	CodeStateChanged:    "this number is no longer one to link again, or it changed meanwhile",
}

func refuse(code, stage string) *Refusal {
	return &Refusal{Code: code, Message: messages[code], Stage: stage}
}

// busyElsewhere is item_busy's wait when the number's lock is held
// somewhere this process cannot date: WhatsApp's whole window.
const busyElsewhere = wa.PairWindow

func busy(wait time.Duration, stage string) *Refusal {
	r := refuse(CodeItemBusy, stage)
	r.RetryAfter = max(time.Second, wait)
	return r
}

// Pairer is what a relink needs of the registry: *wa.Registry through
// FromRegistry, a fake in a test.
type Pairer interface {
	PairingSince(deviceID string) (time.Time, bool)
	Holds(deviceID string) bool
	ReleaseStale(ctx context.Context, deviceID string) bool
	StartPairing(ctx context.Context, tenantID, deviceID string, policy wa.ReceiptPolicy, opts wa.PairOptions) (Pairing, error)
}

// Pairing is a pairing in progress.
type Pairing interface {
	Events() <-chan wa.PairEvent
	Cancel()
}

// FromRegistry is the registry as a Pairer.
func FromRegistry(r *wa.Registry) Pairer { return registryPairer{r} }

type registryPairer struct{ *wa.Registry }

func (p registryPairer) StartPairing(ctx context.Context, tenantID, deviceID string, policy wa.ReceiptPolicy, opts wa.PairOptions) (Pairing, error) {
	s, err := p.Registry.StartPairing(ctx, tenantID, deviceID, policy, opts)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// PhoneBook is whatsmeow's shared map of LIDs and phone numbers, which may
// fill a half of the identity a number's row lacks.
type PhoneBook interface {
	PhoneFor(ctx context.Context, lid types.JID) (types.JID, bool)
	LIDFor(ctx context.Context, pn types.JID) (types.JID, bool)
}

// Service links numbers again.
type Service struct {
	Devices *store.Devices
	Pairer  Pairer
	// LIDs fills a missing half of a row's identity. Nil fills nothing.
	LIDs PhoneBook
	// Receipts records the receipt policy's decisions.
	Receipts func(kind, decision string)
	Log      *slog.Logger
}

// Target is a number that passed the checks before the pairing.
type Target struct {
	Tenant, Device uuid.UUID
	// Expect is the number's account, non-AD: the halves the scan must
	// match.
	Expect wa.Identity
	// FromMap says a half came from whatsmeow's map, not the row.
	FromMap     bool
	Seen        store.RelinkSeen
	Paused      bool
	ReceiptMode wa.ReceiptMode
}

// Actor is who asked, for the log only.
type Actor struct {
	Kind string
	ID   uuid.UUID
}

func (s *Service) log() *slog.Logger {
	if s.Log == nil {
		return slog.Default()
	}
	return s.Log
}

// Check makes the checks of the number before any QR, in the order of spec
// 14.13: item_busy before state_changed, then read_only, no_reader and
// number_held. A number with no live row is store.ErrNotFound, the caller's
// not_found. A refusal is a *Refusal.
func (s *Service) Check(ctx context.Context, tenant, device uuid.UUID) (Target, error) {
	row, err := s.Devices.RelinkRow(ctx, tenant, device)
	if err != nil {
		return Target{}, err
	}
	id := device.String()
	t := Target{Tenant: tenant, Device: device, Seen: store.RelinkSeen{PauseSeq: row.PauseSeq},
		Paused: row.Paused, ReceiptMode: row.ReceiptMode}
	refused := func(r *Refusal) (Target, error) {
		s.logRefused(t, Actor{}, r)
		return Target{}, r
	}

	if since, ok := s.Pairer.PairingSince(id); ok {
		return refused(busy(min(busyElsewhere, time.Until(since.Add(wa.RelinkWindow))), "entry"))
	}
	if row.PauseCause == store.PauseForMove {
		return refused(busy(busyElsewhere, "entry"))
	}
	if row.Status != wa.StatusLoggedOut {
		return refused(refuse(CodeStateChanged, "entry"))
	}
	// A number logged out while this process held it keeps a stopped
	// entry and its lock until something releases them. Any other hold of
	// a logged-out number (a deletion's logout, a start) is busy.
	if s.Pairer.Holds(id) && !s.Pairer.ReleaseStale(ctx, id) {
		return refused(busy(busyElsewhere, "entry"))
	}

	pn, lid := row.Identity.PN.ToNonAD(), row.Identity.LID.ToNonAD()
	if pn.IsEmpty() && !lid.IsEmpty() && s.LIDs != nil {
		if found, ok := s.LIDs.PhoneFor(ctx, lid); ok {
			pn, t.FromMap = found.ToNonAD(), true
		}
	}
	if lid.IsEmpty() && !pn.IsEmpty() && s.LIDs != nil {
		if found, ok := s.LIDs.LIDFor(ctx, pn); ok {
			lid, t.FromMap = found.ToNonAD(), true
		}
	}
	if pn.Server != types.DefaultUserServer || pn.User == "" || lid.Server != types.HiddenUserServer || lid.User == "" {
		return refused(refuse(CodeReadOnly, "entry"))
	}
	t.Expect = wa.Identity{PN: pn, LID: lid}

	if row.Epoch < 1 {
		return refused(refuse(CodeNoReader, "entry"))
	}
	held, err := s.Devices.KeyHeld(ctx, tenant, device)
	if err != nil {
		return Target{}, err
	}
	if !held {
		return refused(refuse(CodeNoReader, "entry"))
	}
	elsewhere, err := s.Devices.HeldElsewhere(ctx, tenant, device, t.Expect)
	if err != nil {
		return Target{}, err
	}
	if elsewhere {
		return refused(refuse(CodeNumberHeld, "entry"))
	}
	return t, nil
}

// Session is a relink in progress.
type Session struct {
	svc    *Service
	target Target
	actor  Actor
	pair   Pairing
	events chan wa.PairEvent
	// cause is set before a cancel this package makes, to name the end.
	cause  chan error
	result error
}

// Events yields the pairing's QR events until it ends, then closes. They
// carry a link code: never log one.
func (s *Session) Events() <-chan wa.PairEvent { return s.events }

// Cancel ends the pairing. A cancel that finds the number changed is
// state_changed; else connect_failed.
func (s *Session) Cancel() { s.pair.Cancel() }

// Result is nil once the number names the new link, else a *Refusal. Only
// valid after Events closed.
func (s *Session) Result() error { return s.result }

// Start starts the pairing of a number Check passed. Its error is a
// *Refusal; the end comes through Session.Result.
func (s *Service) Start(ctx context.Context, t Target, who Actor) (*Session, error) {
	s.log().Info("relink started", "device", t.Device, "tenant", t.Tenant, "actor_kind", who.Kind, "actor", who.ID,
		"paused", t.Paused, "identity_from_map", t.FromMap)
	rl := &wa.Relink{
		Expect: t.Expect,
		Recheck: func(ctx context.Context) error {
			return s.Devices.RelinkRecheck(ctx, t.Tenant, t.Device, t.Seen, t.Expect)
		},
		Attach: func(ctx context.Context, linked wa.Identity) error {
			a, err := s.Devices.AttachRelink(ctx, t.Tenant, t.Device, t.Seen, linked)
			if err == nil {
				s.log().Info("relink attached", "device", t.Device, "tenant", t.Tenant, "actor", who.ID,
					"resumed_pause", a.ResumedPause, "old_session_left", a.OldSessionLeft)
			}
			return err
		},
		Discarded: func(ctx context.Context, jid types.JID) {
			if err := s.Devices.ForgetDiscardedSession(ctx, t.Tenant, jid.String()); err != nil {
				s.log().Warn("relink could not forget a refused link's tokens", "device", t.Device, "error", err)
			}
		},
	}
	pair, err := s.Pairer.StartPairing(ctx, t.Tenant.String(), t.Device.String(),
		wa.ReceiptPolicy{Mode: t.ReceiptMode, Recorder: s.Receipts}, wa.PairOptions{Method: wa.PairByQR, Relink: rl})
	if err != nil {
		var r *Refusal
		switch {
		case errors.Is(err, wa.ErrAlreadyRunning):
			r = busy(busyElsewhere, "start")
		case errors.Is(err, store.ErrStoragePaused):
			r = refuse(CodeStoragePaused, "start")
		default:
			r = refuse(CodeConnectFailed, "start")
			s.log().Warn("relink could not start", "device", t.Device, "error", err)
		}
		s.logRefused(t, who, r)
		return nil, r
	}
	sess := &Session{svc: s, target: t, actor: who, pair: pair, events: make(chan wa.PairEvent, 8), cause: make(chan error, 1)}
	// The check above ran before the device lock: read once more now that
	// the pairing holds it, as a new number's pairing does.
	if err := s.Devices.RelinkRecheck(ctx, t.Tenant, t.Device, t.Seen, t.Expect); err != nil {
		sess.cause <- err
		pair.Cancel()
	}
	go sess.run(context.WithoutCancel(ctx))
	return sess, nil
}

func (s *Session) run(ctx context.Context) {
	defer close(s.events)
	var end error
	for e := range s.pair.Events() {
		switch e.Kind {
		case wa.PairEventQR:
			select {
			case s.events <- e:
			default:
				// A reader that does not keep up misses a rotation, never
				// the pairing.
			}
		case wa.PairEventSuccess:
			s.result = nil
			return
		case wa.PairEventError, wa.PairEventTimeout:
			end = e.Err
			if end == nil {
				end = wa.ErrLinkTimeout
			}
		}
	}
	select {
	case cause := <-s.cause:
		end = cause
	default:
	}
	if end == nil {
		end = wa.ErrLinkFailed
	}
	r := s.svc.classify(ctx, s.target, end)
	s.svc.logRefused(s.target, s.actor, r)
	s.result = r
}

// classify names a pairing's end. A window that closed, or a link that
// failed, is first set against the number as it is now: a cancel by a
// pause, a deletion, a move or a storage stop is its cause.
func (s *Service) classify(ctx context.Context, t Target, err error) *Refusal {
	var other *wa.OtherAccount
	switch {
	case errors.As(err, &other):
		r := refuse(CodeOtherAccount, "scan")
		r.Half = other.Half
		return r
	case errors.Is(err, wa.ErrOtherAccount):
		return refuse(CodeOtherAccount, "scan")
	case errors.Is(err, store.ErrRelinkNumberHeld):
		return refuse(CodeNumberHeld, "attach")
	case errors.Is(err, store.ErrRelinkStateChanged):
		return refuse(CodeStateChanged, "attach")
	case errors.Is(err, store.ErrStoragePaused):
		return refuse(CodeStoragePaused, "attach")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	switch now := s.Devices.RelinkState(ctx, t.Tenant, t.Device, t.Seen); {
	case errors.Is(now, store.ErrRelinkStateChanged):
		return refuse(CodeStateChanged, "end")
	case errors.Is(now, store.ErrStoragePaused):
		return refuse(CodeStoragePaused, "end")
	}
	if errors.Is(err, wa.ErrLinkTimeout) {
		return refuse(CodeLinkTimeout, "end")
	}
	s.log().Info("relink did not finish", "device", t.Device, "error", err)
	return refuse(CodeConnectFailed, "end")
}

func (s *Service) logRefused(t Target, who Actor, r *Refusal) {
	args := []any{"device", t.Device, "tenant", t.Tenant, "code", r.Code, "stage", r.Stage}
	if who.ID != uuid.Nil {
		args = append(args, "actor", who.ID)
	}
	if r.Half != "" {
		args = append(args, "half", r.Half)
	}
	s.log().Info("relink refused", args...)
}

// String is a refusal's code, for a log line.
func (r *Refusal) String() string { return fmt.Sprintf("%s (%s)", r.Code, r.Stage) }
