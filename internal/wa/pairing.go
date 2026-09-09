package wa

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"go.mau.fi/whatsmeow"
)

// PairWindow is the hard deadline on a pairing attempt.
//
// whatsmeow issues a fresh QR code every twenty seconds and the server closes
// the login socket once the sequence runs out, roughly 160 seconds in. Nothing
// can extend it; a session that misses the window has to start over.
const PairWindow = 160 * time.Second

// PairMethod selects how the phone is linked.
type PairMethod string

const (
	// PairByQR shows QR codes to be scanned with the phone's camera.
	PairByQR PairMethod = "qr"

	// PairByCode asks WhatsApp for an eight-character code that the user types
	// into their phone. Far better over a terminal, where the alternative is
	// photographing your own screen.
	PairByCode PairMethod = "code"
)

// PairEventKind labels an update from a pairing session.
type PairEventKind string

const (
	PairEventQR      PairEventKind = "qr"      // a new QR code to display
	PairEventCode    PairEventKind = "code"    // the eight-character linking code
	PairEventSuccess PairEventKind = "success" // the phone accepted the link
	PairEventTimeout PairEventKind = "timeout" // the window closed unused
	PairEventError   PairEventKind = "error"
)

// PairEvent is one update from a pairing session.
type PairEvent struct {
	Kind PairEventKind
	// Code carries the QR payload for PairEventQR and the linking code for
	// PairEventCode.
	Code string
	// Expires is when this particular code stops working. QR codes rotate
	// roughly every twenty seconds.
	Expires time.Time
	Err     error
}

// PairOptions configures a pairing attempt.
type PairOptions struct {
	Method PairMethod

	// Phone is required for PairByCode: full international format, no leading
	// zero, no punctuation (punctuation is stripped for you).
	Phone string

	// DisplayName is what shows up under "Linked devices" on the phone.
	//
	// WhatsApp validates the format server-side and rejects anything it does
	// not recognise with a 400, so this must look like "Browser (OS)" using a
	// real browser and OS name. It is not free text.
	DisplayName string
}

// defaultDisplayName is a combination WhatsApp accepts.
const defaultDisplayName = "Chrome (Linux)"

// displayNameRE enforces the "Browser (OS)" shape before the request is sent.
// Catching it here turns an opaque server-side 400 into a message that says
// what is wrong.
var displayNameRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9 .]* \([A-Za-z][A-Za-z0-9 .]*\)$`)

var nonDigits = regexp.MustCompile(`\D`)

// Validate checks the options and fills in defaults.
func (o *PairOptions) Validate() error {
	switch o.Method {
	case PairByQR:
	case PairByCode:
		digits := nonDigits.ReplaceAllString(o.Phone, "")
		switch {
		case digits == "":
			return errors.New("wa: pairing by code needs a phone number")
		case len(digits) <= 6:
			return fmt.Errorf("wa: %q is too short for a phone number", o.Phone)
		case strings.HasPrefix(digits, "0"):
			return fmt.Errorf("wa: %q starts with a zero; use the full international "+
				"form with the country code, for example 5511999999999", o.Phone)
		}
		o.Phone = digits
	case "":
		return errors.New("wa: pairing method is required")
	default:
		return fmt.Errorf("wa: unknown pairing method %q", o.Method)
	}

	if o.DisplayName == "" {
		o.DisplayName = defaultDisplayName
	}
	if !displayNameRE.MatchString(o.DisplayName) {
		return fmt.Errorf("wa: display name %q must look like \"Browser (OS)\" — "+
			"WhatsApp validates this and rejects anything else", o.DisplayName)
	}
	return nil
}

// PairSession is one pairing attempt in progress.
type PairSession struct {
	events chan PairEvent
	cancel context.CancelFunc
	device *Device
}

// Events yields pairing updates until the session ends. The channel is closed
// when it does, so ranging over it terminates on its own.
func (s *PairSession) Events() <-chan PairEvent { return s.events }

// Device returns the supervised device behind this session.
func (s *PairSession) Device() *Device { return s.device }

// Cancel abandons the attempt.
func (s *PairSession) Cancel() { s.cancel() }

// StartPairing begins linking a new device.
//
// The call order below is fixed by whatsmeow and getting it wrong produces
// confusing failures rather than errors:
//
//  1. GetQRChannel BEFORE Connect. Afterwards it returns ErrQRStoreContainsID,
//     because by then the store either has an identity or the login socket has
//     already moved on.
//  2. Connect.
//  3. For code pairing, PairPhone immediately. The 160-second window starts at
//     connect, not at the request, so any delay here is deducted from the time
//     the user gets to type the code.
func (r *Registry) StartPairing(ctx context.Context, tenantID, deviceID string,
	policy ReceiptPolicy, opts PairOptions) (*PairSession, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}

	// Detached from the caller so the session survives the request that
	// started it, but bounded so an abandoned attempt cannot linger.
	sessionCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), PairWindow)

	client := whatsmeow.NewClient(r.cfg.Container.NewDevice(), r.waLogger("pair/"+shortID(deviceID)))
	applyClientPolicy(client)

	// Step 1, before connecting.
	qrCh, err := client.GetQRChannel(sessionCtx)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("wa: open pairing channel: %w", err)
	}

	dev, err := r.adopt(sessionCtx, tenantID, deviceID, policy, client)
	if err != nil {
		cancel()
		return nil, err
	}

	// Step 2.
	if err := dev.Start(sessionCtx); err != nil {
		cancel()
		r.Stop(context.WithoutCancel(ctx), deviceID)
		return nil, fmt.Errorf("wa: connect for pairing: %w", err)
	}

	s := &PairSession{events: make(chan PairEvent, 8), cancel: cancel, device: dev}
	go r.runPairing(sessionCtx, s, client, qrCh, opts, deviceID)
	return s, nil
}

func (r *Registry) runPairing(ctx context.Context, s *PairSession, client *whatsmeow.Client,
	qrCh <-chan whatsmeow.QRChannelItem, opts PairOptions, deviceID string) {
	defer close(s.events)

	emit := func(e PairEvent) {
		select {
		case s.events <- e:
		case <-ctx.Done():
		}
	}

	// Step 3. Requested immediately, because the window is already running.
	if opts.Method == PairByCode {
		code, err := client.PairPhone(ctx, opts.Phone, true, whatsmeow.PairClientChrome, opts.DisplayName)
		if err != nil {
			emit(PairEvent{Kind: PairEventError, Err: fmt.Errorf("wa: request linking code: %w", err)})
			r.abandon(ctx, deviceID)
			return
		}
		emit(PairEvent{Kind: PairEventCode, Code: code, Expires: time.Now().Add(PairWindow)})
	}

	for {
		select {
		case <-ctx.Done():
			// Deliberate cleanup. Without it an abandoned attempt leaves a
			// connected client and a half-created whatsmeow device behind,
			// which is how the v1 server accumulated orphans.
			r.abandon(ctx, deviceID)
			emit(PairEvent{Kind: PairEventTimeout})
			return

		case item, open := <-qrCh:
			if !open {
				return
			}
			switch item.Event {
			case "code":
				// Only meaningful when the user is looking at a QR. During
				// code pairing these still arrive and are simply noise.
				if opts.Method == PairByQR {
					emit(PairEvent{
						Kind:    PairEventQR,
						Code:    item.Code,
						Expires: time.Now().Add(item.Timeout),
					})
				}

			case "success":
				emit(PairEvent{Kind: PairEventSuccess})
				return

			case "timeout":
				r.abandon(ctx, deviceID)
				emit(PairEvent{Kind: PairEventTimeout})
				return

			default:
				err := item.Error
				if err == nil {
					err = fmt.Errorf("pairing failed: %s", item.Event)
				}
				r.abandon(ctx, deviceID)
				emit(PairEvent{Kind: PairEventError, Err: err})
				return
			}
		}
	}
}

// abandon tears down a pairing attempt that will not complete.
func (r *Registry) abandon(ctx context.Context, deviceID string) {
	r.Stop(context.WithoutCancel(ctx), deviceID)
}

// adopt registers an already-constructed client under a device id. It shares
// the bookkeeping in start without creating a second whatsmeow client, which
// matters here because the pairing flow must build the client itself in order
// to call GetQRChannel before Connect.
func (r *Registry) adopt(ctx context.Context, tenantID, deviceID string,
	policy ReceiptPolicy, client Client) (*Device, error) {
	r.mu.Lock()
	if _, running := r.devices[deviceID]; running {
		r.mu.Unlock()
		return nil, ErrAlreadyRunning
	}
	r.devices[deviceID] = &entry{}
	r.mu.Unlock()

	fail := func(err error) (*Device, error) {
		r.mu.Lock()
		delete(r.devices, deviceID)
		r.mu.Unlock()
		return nil, err
	}

	var release func()
	if r.cfg.Locker != nil {
		rel, ok, err := r.cfg.Locker.TryLock(ctx, "device:"+deviceID)
		if err != nil {
			return fail(fmt.Errorf("wa: lock device: %w", err))
		}
		if !ok {
			return fail(ErrAlreadyRunning)
		}
		release = rel
	}

	dev, err := NewDevice(DeviceConfig{
		ID: deviceID, TenantID: tenantID,
		Client: client, Store: r.cfg.Store, Sink: r.cfg.Sink,
		Contacts: contactSourceOf(client),
		Policy:   policy, Log: r.log, OnStatus: r.cfg.OnStatus,
	})
	if err != nil {
		if release != nil {
			release()
		}
		return fail(err)
	}

	// Existing sessions already know their own profile. Waiting for a later
	// PushNameSetting event would leave the console unnamed after every restart.
	if real, ok := client.(*whatsmeow.Client); ok && real.Store != nil {
		identity := Identity{LID: real.Store.GetLID(), PushName: real.Store.PushName}
		if real.Store.ID != nil {
			identity.PN = *real.Store.ID
		}
		dev.identity.merge(identity)
	}
	r.mu.Lock()
	r.devices[deviceID] = &entry{device: dev, release: release}
	r.mu.Unlock()
	return dev, nil
}

// contactSourceOf reaches whatsmeow's own contact cache, when there is one.
//
// A type assertion rather than a method on the Client interface, because the
// cache belongs to whatsmeow's session store and not to the protocol surface
// this server models. Adding it to the interface would mean the contract test
// could no longer assert that *whatsmeow.Client satisfies it directly, which is
// the thing that makes an upstream signature change fail to compile.
//
// A fake client has no cache and gets nil, which every caller tolerates.
func contactSourceOf(client Client) ContactSource {
	real, ok := client.(*whatsmeow.Client)
	if !ok || real.Store == nil || real.Store.Contacts == nil {
		return nil
	}
	return real.Store.Contacts
}
