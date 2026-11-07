package wa

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
)

// PairWindow is the hard deadline on a pairing attempt.
//
// whatsmeow issues a fresh QR code every twenty seconds and the server closes
// the login socket once the sequence runs out, roughly 160 seconds in. Nothing
// can extend it; a session that misses the window has to start over.
const PairWindow = 160 * time.Second

// RelinkWindow is a relink's deadline. whatsmeow's codes run PairWindow
// from the first QR, which comes after the connect; the slack lets
// whatsmeow's own timeout end the window, so the last QR shown stays
// good until it expires.
const RelinkWindow = PairWindow + 15*time.Second

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

	// DisplayName is the browser descriptor for the code-pairing request.
	// The installation name in Linked devices comes from RegistryConfig.
	//
	// WhatsApp validates the format server-side and rejects anything it does
	// not recognise with a 400, so this must look like "Browser (OS)" using a
	// real browser and OS name. It is not free text.
	DisplayName string

	// Relink links a number Wappie already holds again, by QR only, and
	// keeps the link only for the number's own account (relink.go).
	Relink *Relink
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
	if o.Relink != nil {
		if o.Method != PairByQR {
			return errors.New("wa: a relink pairs by QR only")
		}
		if o.Relink.Expect.PN.User == "" || o.Relink.Expect.LID.User == "" {
			return errors.New("wa: a relink needs both halves of the number's identity")
		}
	}
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
	window := PairWindow
	if opts.Relink != nil {
		window = RelinkWindow
	}
	sessionCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), window)

	ds := r.newPairingDevice()
	client := r.newPairingClient(ds, "pair/"+shortID(deviceID))
	var guard *relinkContainer
	if opts.Relink != nil {
		guard = armRelink(ds, client, opts.Relink)
	}

	// Step 1, before connecting.
	qrCh, err := client.GetQRChannel(sessionCtx)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("wa: open pairing channel: %w", err)
	}

	dev, err := r.adopt(sessionCtx, tenantID, deviceID, policy, client, adoptOptions{pairing: true, relink: guard != nil})
	if err != nil {
		cancel()
		return nil, err
	}

	// Step 2.
	if err := dev.Start(sessionCtx); err != nil {
		cancel()
		r.stopIf(context.WithoutCancel(ctx), deviceID, dev)
		return nil, fmt.Errorf("wa: connect for pairing: %w", err)
	}

	s := &PairSession{events: make(chan PairEvent, 8), cancel: cancel, device: dev}
	go r.runPairing(sessionCtx, s, pairRun{
		client: client, ds: ds, dev: dev, qrCh: qrCh, opts: opts, deviceID: deviceID, guard: guard,
	})
	return s, nil
}

// newPairingDevice is a fresh whatsmeow device with no JID: new noise,
// identity and ADV keys.
func (r *Registry) newPairingDevice() *store.Device {
	if r.cfg.NewPairingDevice != nil {
		return r.cfg.NewPairingDevice()
	}
	return r.cfg.Container.NewDevice()
}

// newPairingClient builds a pairing's client on its device.
func (r *Registry) newPairingClient(ds *store.Device, module string) Client {
	log := r.pairLogger(module)
	if r.cfg.NewPairingClient != nil {
		return r.cfg.NewPairingClient(ds, log)
	}
	client := whatsmeow.NewClient(ds, log)
	applyClientPolicy(client)
	return client
}

// pairRun is one pairing's parts, for runPairing.
type pairRun struct {
	client   Client
	ds       *store.Device
	dev      *Device
	qrCh     <-chan whatsmeow.QRChannelItem
	opts     PairOptions
	deviceID string
	guard    *relinkContainer // a relink's account check; nil otherwise
}

const (
	// finalEmitWait bounds the send of a pairing's last event, which must
	// not be lost to a window that closed meanwhile.
	finalEmitWait = 5 * time.Second
	// relinkFinish bounds a relink's steps after WhatsApp confirmed the
	// link: the attach, the reconnect, or the logout of a refused link. Its
	// own context, so a scan in the window's last second still attaches.
	relinkFinish = 30 * time.Second
	// relinkLoginWait is how long a relink waits for the pairing's 515
	// before it reconnects anyway.
	relinkLoginWait = 15 * time.Second
	// relinkSettleWait bounds the wait for whatsmeow's own end of a scan
	// that passed the account check, when the window ended first.
	relinkSettleWait = 30 * time.Second
)

func (r *Registry) runPairing(ctx context.Context, s *PairSession, p pairRun) {
	defer close(s.events)
	if p.guard != nil {
		// In the background: a handler that runs now, such as the Device's
		// after the attach, holds whatsmeow's handler lock.
		defer func() { go p.client.RemoveEventHandler(p.guard.handler) }()
	}

	emit := func(e PairEvent) {
		select {
		case s.events <- e:
		case <-ctx.Done():
		}
	}
	final := func(e PairEvent) {
		select {
		case s.events <- e:
		case <-time.After(finalEmitWait):
			r.log.Warn("a pairing's last event found nobody listening", "device", p.deviceID, "kind", e.Kind)
		}
	}
	relink := p.opts.Relink != nil
	// endRelink ends a relink that did not link, with its reason. A scan
	// that passed the account check first gets whatsmeow's own end: a
	// cancel or the window's end may land after whatsmeow stored the link
	// and sent pair-device-sign, and such a link is attached as on success.
	endRelink := func(timedOut bool, cause error) {
		if r.settleRelink(p) {
			r.finishRelink(ctx, p, final)
			return
		}
		err := relinkEnd(&p.guard.verdict, timedOut, cause)
		r.abandon(ctx, p)
		final(PairEvent{Kind: PairEventError, Err: err})
	}

	// Step 3. Requested immediately, because the window is already running.
	if p.opts.Method == PairByCode {
		code, err := p.client.PairPhone(ctx, p.opts.Phone, true, whatsmeow.PairClientChrome, p.opts.DisplayName)
		if err != nil {
			emit(PairEvent{Kind: PairEventError, Err: fmt.Errorf("wa: request linking code: %w", err)})
			r.abandon(ctx, p)
			return
		}
		emit(PairEvent{Kind: PairEventCode, Code: code, Expires: time.Now().Add(PairWindow)})
	}

	var lastExpires time.Time
	loggedQR := false
	for {
		select {
		case <-ctx.Done():
			if relink {
				endRelink(errors.Is(ctx.Err(), context.DeadlineExceeded), ctx.Err())
				return
			}
			// Deliberate cleanup. Without it an abandoned attempt leaves a
			// connected client and a half-created whatsmeow device behind,
			// which is how the v1 server accumulated orphans.
			r.abandon(ctx, p)
			emit(PairEvent{Kind: PairEventTimeout})
			return

		case item, open := <-p.qrCh:
			if !open {
				if relink {
					endRelink(false, errors.New("the pairing channel closed"))
				}
				return
			}
			switch item.Event {
			case "code":
				// The platform's measure of a real QR's size: its length,
				// once per pairing, never its text.
				if !loggedQR {
					loggedQR = true
					r.log.Info("pairing QR", "device", p.deviceID, "qr_length", len(item.Code))
				}
				// Only meaningful when the user is looking at a QR. During
				// code pairing these still arrive and are simply noise.
				if p.opts.Method == PairByQR {
					lastExpires = time.Now().Add(item.Timeout)
					emit(PairEvent{
						Kind:    PairEventQR,
						Code:    item.Code,
						Expires: lastExpires,
					})
				}

			case "success":
				if relink {
					r.finishRelink(ctx, p, final)
					return
				}
				r.endPairing(p.deviceID, p.dev)
				emit(PairEvent{Kind: PairEventSuccess})
				return

			case "timeout":
				if relink {
					// whatsmeow sends timeout when its codes run out, and
					// also when the socket drops mid-window.
					endRelink(!lastExpires.IsZero() && !time.Now().Before(lastExpires.Add(-time.Second)),
						errors.New("the socket closed during the window"))
					return
				}
				r.abandon(ctx, p)
				emit(PairEvent{Kind: PairEventTimeout})
				return

			default:
				err := item.Error
				if err == nil {
					err = fmt.Errorf("pairing failed: %s", item.Event)
				}
				if relink {
					endRelink(false, err)
					return
				}
				r.abandon(ctx, p)
				emit(PairEvent{Kind: PairEventError, Err: err})
				return
			}
		}
	}
}

// finishRelink keeps or drops a relink's new link once WhatsApp confirmed
// it. The account already passed the check before the link. Attach writes
// the link into the number; until it commits, the Device is gated and the
// client has not reconnected, so nothing of the link reached the archive.
// A refused attach logs the link out again.
func (r *Registry) finishRelink(ctx context.Context, p pairRun, final func(PairEvent)) {
	post, cancel := context.WithTimeout(context.WithoutCancel(ctx), relinkFinish)
	defer cancel()
	if p.ds.ID == nil {
		r.abandon(post, p)
		final(PairEvent{Kind: PairEventError, Err: fmt.Errorf("%w: no phone number in the new link", ErrLinkFailed)})
		return
	}
	linked := Identity{PN: *p.ds.ID, LID: p.ds.LID, BusinessName: p.ds.BusinessName}
	if err := p.opts.Relink.Attach(post, linked); err != nil {
		r.discardLink(post, p, linked.PN)
		final(PairEvent{Kind: PairEventError, Err: err})
		return
	}
	// A pause, a storage stop or a deletion that stopped the number since
	// keeps it stopped: its row names the new link, and the supervisor
	// picks it up when it may.
	if r.endPairing(p.deviceID, p.dev) {
		p.dev.OpenGate()
		select {
		case <-p.dev.LoginRestarted():
		case <-time.After(relinkLoginWait):
		case <-post.Done():
		}
		p.client.Disconnect()
		if err := p.dev.reconnectAfterPair(post); err != nil {
			r.log.Warn("relink reconnect left to the supervisor", "device", p.deviceID, "error", err)
			r.stopIf(post, p.deviceID, p.dev)
		}
	}
	final(PairEvent{Kind: PairEventSuccess})
}

// discardLink logs out a relink's new link whose attach was refused. The
// account is the number's own, so the link exists on WhatsApp. The gate
// stays closed and no OnClient handler exists, so the connection captures
// nothing. Logout comes first, while connected: it disconnects and deletes
// the session itself, and a disconnect first would leave the link on the
// phone.
func (r *Registry) discardLink(ctx context.Context, p pairRun, jid types.JID) {
	p.client.Disconnect()
	confirmed := false
	if err := p.client.Connect(); err == nil || errors.Is(err, whatsmeow.ErrAlreadyConnected) {
		confirmed = logoutOn(ctx, p.client, nil, nil) == nil
	}
	if !confirmed {
		// The phone may keep the entry under Linked devices; the session
		// goes anyway.
		p.client.Disconnect()
		if err := p.ds.Delete(ctx); err != nil {
			r.log.Warn("relink could not delete a refused link's session", "device", p.deviceID, "error", err)
		}
	}
	if p.opts.Relink.Discarded != nil {
		p.opts.Relink.Discarded(ctx, jid)
	}
	r.abandon(ctx, p)
	r.log.Info("relink new link logged out", "device", p.deviceID, "confirmed", confirmed)
}

// settleRelink reports whether a relink whose window ended, or whose QR
// channel ended without a success, linked anyway. Only a scan that passed
// the account check can have: whatsmeow then stores the link and sends
// pair-device-sign on its own goroutine. Its PairSuccess or PairError
// settles it; until then the client stays connected, so the sign is not
// cut off halfway.
func (r *Registry) settleRelink(p pairRun) bool {
	if !p.guard.verdict.isAccepted() {
		return false
	}
	select {
	case <-p.guard.verdict.settled:
	case <-time.After(relinkSettleWait):
		r.log.Warn("a relink's accepted scan did not settle", "device", p.deviceID)
		return false
	}
	return p.guard.verdict.isLinked()
}

// abandon tears down a pairing attempt that will not complete. Only its
// own entry: a later pairing or start of the number keeps running.
func (r *Registry) abandon(ctx context.Context, p pairRun) {
	stop := context.WithoutCancel(ctx)
	if !r.stopIf(stop, p.deviceID, p.dev) {
		p.client.Disconnect()
	}
}

// adopt registers an already-constructed client under a device id. It shares
// the bookkeeping in start without creating a second whatsmeow client, which
// matters here because the pairing flow must build the client itself in order
// to call GetQRChannel before Connect.
func (r *Registry) adopt(ctx context.Context, tenantID, deviceID string,
	policy ReceiptPolicy, client Client, o adoptOptions) (*Device, error) {
	if r.cfg.CheckStart != nil {
		if err := r.cfg.CheckStart(ctx, tenantID); err != nil {
			return nil, err
		}
	}
	r.mu.Lock()
	if _, running := r.devices[deviceID]; running {
		r.mu.Unlock()
		return nil, ErrAlreadyRunning
	}
	reserved := &entry{}
	r.devices[deviceID] = reserved
	r.mu.Unlock()

	fail := func(err error) (*Device, error) {
		r.mu.Lock()
		if r.devices[deviceID] == reserved {
			delete(r.devices, deviceID)
		}
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
		Contacts:   contactSourceOf(client),
		CheckStart: r.cfg.CheckStart,
		Policy:     policy, Log: r.log, OnStatus: r.cfg.OnStatus,
		Gated: o.relink,
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
	var stopClient func()
	var deferred func() func()
	if real, ok := client.(*whatsmeow.Client); ok && r.cfg.OnClient != nil {
		if o.relink {
			// Not before the attach: no call offer reaches a link Wappie
			// has not kept.
			deferred = func() func() { return r.cfg.OnClient(tenantID, deviceID, real) }
		} else {
			stopClient = r.cfg.OnClient(tenantID, deviceID, real)
		}
	}
	if real, ok := client.(*whatsmeow.Client); ok {
		installConnectionPolicy(real, tenantID, r.cfg.CheckStart)
	}
	r.mu.Lock()
	if r.devices[deviceID] != reserved {
		r.mu.Unlock()
		if stopClient != nil {
			stopClient()
		}
		dev.Stop(context.WithoutCancel(ctx))
		if release != nil {
			release()
		}
		return nil, fmt.Errorf("wa: device start was cancelled: %w", context.Canceled)
	}
	e := &entry{device: dev, release: release, stopClient: stopClient, pairing: o.pairing, relink: o.relink, deferredOnClient: deferred}
	if o.pairing {
		e.pairingSince = time.Now()
	}
	r.devices[deviceID] = e
	r.mu.Unlock()
	return dev, nil
}

// adoptOptions says what kind of entry adopt makes.
type adoptOptions struct {
	// pairing is a pairing's entry until it links: Held reports it and
	// PairingSince dates it.
	pairing bool
	// relink gates the Device until the attach (DeviceConfig.Gated) and
	// defers OnClient to it.
	relink bool
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
