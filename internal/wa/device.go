package wa

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"

	"whatserver2/internal/wa/normalize"
)

// Status is a device's lifecycle state. It mirrors the CHECK constraint on
// devices.status in migration 0001.
type Status string

const (
	StatusNew       Status = "new"        // created, never paired
	StatusPairing   Status = "pairing"    // a pairing attempt is in flight
	StatusOnline    Status = "online"     // connected and authenticated
	StatusOffline   Status = "offline"    // paired, currently disconnected
	StatusLoggedOut Status = "logged_out" // unlinked from the phone; needs re-pairing
	StatusBanned    Status = "banned"     // temporarily banned by WhatsApp
)

// Terminal reports whether a status needs human intervention. whatsmeow will
// not reconnect out of these on its own, and neither should the supervisor:
// retrying a logged-out or banned device just burns connection attempts against
// a server that has already said no.
func (s Status) Terminal() bool {
	return s == StatusLoggedOut || s == StatusBanned
}

// Store persists device state.
//
// An interface rather than a concrete Postgres type so the supervisor can be
// tested against the fake client with no database at all. Every method takes
// the tenant explicitly, because the implementation scopes its transaction with
// it and row-level security refuses the write otherwise.
type Store interface {
	SetStatus(ctx context.Context, tenantID, deviceID string, status Status, reason string) error
	SetIdentity(ctx context.Context, tenantID, deviceID string, id Identity) error
}

// Sink receives whatsmeow events that the supervisor does not consume itself.
// In phase 2 this becomes the ingest pipeline; until then it is whatever the
// caller supplies, and nil means discard.
type Sink interface {
	Handle(ctx context.Context, deviceID string, evt any)
}

// SinkFunc adapts a function to Sink.
type SinkFunc func(ctx context.Context, deviceID string, evt any)

func (f SinkFunc) Handle(ctx context.Context, deviceID string, evt any) { f(ctx, deviceID, evt) }

// DeviceConfig configures a supervised device.
type DeviceConfig struct {
	ID       string // our uuid, stable across re-pairings
	TenantID string
	Client   Client
	Store    Store
	// Contacts is whatsmeow's own cached contact list for this device.
	//
	// A narrow seam rather than exposing the whole session store. It exists
	// because a history sync fills that cache with thousands of push names in
	// one payload, and an archive that only listened for the events would wait
	// for each of those people to send something before learning who they are.
	Contacts ContactSource
	Sink     Sink
	Policy   ReceiptPolicy
	Log      *slog.Logger

	// OnStatus is called after every status change, for the websocket layer to
	// push to subscribers. The tenant is included because the layer above fans
	// out per tenant and cannot recover it from the device id alone. Optional.
	OnStatus func(tenantID, deviceID string, status Status, reason string)
}

// ContactSource is whatsmeow's cached contact list.
//
// Both shapes are here because the archive needs both. The bulk import at boot
// wants everything at once; answering "who is this chat I have never seen
// before" wants exactly one row, and asking for five thousand to find it would
// be absurd.
type ContactSource interface {
	GetAllContacts(ctx context.Context) (map[types.JID]types.ContactInfo, error)
	GetContact(ctx context.Context, user types.JID) (types.ContactInfo, error)
}

// Contacts returns what whatsmeow has cached about this device's contacts.
func (d *Device) Contacts(ctx context.Context) (map[types.JID]types.ContactInfo, error) {
	if d.cfg.Contacts == nil {
		return nil, nil
	}
	return d.cfg.Contacts.GetAllContacts(ctx)
}

// Contact returns what whatsmeow has cached about one contact.
//
// The zero value and a nil error mean "nothing known", which is an ordinary
// answer rather than a failure: a LID that has only ever appeared as a chat key
// may genuinely have no name attached to it yet.
func (d *Device) Contact(ctx context.Context, jid types.JID) (types.ContactInfo, error) {
	if d.cfg.Contacts == nil {
		return types.ContactInfo{}, nil
	}
	return d.cfg.Contacts.GetContact(ctx, jid.ToNonAD())
}

// Device supervises one WhatsApp connection.
type Device struct {
	cfg      DeviceConfig
	log      *slog.Logger
	identity identityHolder

	mu       sync.Mutex
	status   Status
	handleID uint32
	running  bool
	stop     context.CancelFunc
	done     chan struct{}
}

// NewDevice builds a supervisor. It does not connect; call Start.
func NewDevice(cfg DeviceConfig) (*Device, error) {
	if cfg.ID == "" || cfg.TenantID == "" {
		return nil, errors.New("wa: device needs both an id and a tenant")
	}
	if cfg.Client == nil {
		return nil, errors.New("wa: device needs a client")
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Device{
		cfg:    cfg,
		log:    cfg.Log.With("device", cfg.ID, "tenant", cfg.TenantID),
		status: StatusNew,
	}, nil
}

// Identity returns the current identity. Safe from any goroutine.
func (d *Device) Identity() Identity { return d.identity.get() }

// Status returns the current status.
func (d *Device) Status() Status {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.status
}

// ID returns the device's stable identifier.
func (d *Device) ID() string { return d.cfg.ID }

// TenantID returns the tenant this device belongs to.
func (d *Device) TenantID() string { return d.cfg.TenantID }

// Client exposes the underlying whatsmeow client for the send path.
//
// Returned as the narrow interface rather than *whatsmeow.Client, so callers
// stay testable against the fake and cannot reach past the surface this design
// actually depends on.
func (d *Device) Client() Client { return d.cfg.Client }

// Policy returns the device's receipt policy.
func (d *Device) Policy() ReceiptPolicy {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cfg.Policy
}

// SetReceiptMode changes what this device tells the other side, while it runs.
//
// The mode used to be fixed at pairing, which made "go quiet" a thing you could
// only decide before you had anything to be quiet about. Changing it here means
// the switch is one call rather than a re-pair.
//
// The order of the two upstream calls is not interchangeable, and the asymmetry
// is upstream's. SetForceActiveDeliveryReceipts(true) stores 2 and presence
// "unavailable" only moves 1 to 0 — so going quiet needs the setter explicitly,
// or a device that had ever been forced active would keep sending real delivery
// receipts while reporting itself silent. Going loud needs the presence
// announcement, because that is also what makes WhatsApp send us other people's
// typing notifications at all.
func (d *Device) SetReceiptMode(ctx context.Context, mode ReceiptMode) error {
	d.mu.Lock()
	if d.cfg.Policy.Mode == mode {
		d.mu.Unlock()
		return nil
	}
	d.cfg.Policy.Mode = mode
	client := d.cfg.Client
	running := d.running
	policy := d.cfg.Policy
	d.mu.Unlock()

	if !running {
		// Nothing to tell WhatsApp yet. The mode is what the next connect
		// will apply, which is what OnConnect is for.
		return nil
	}
	if mode == ModeActive {
		return policy.OnConnect(ctx, client)
	}
	client.SetForceActiveDeliveryReceipts(false)
	return policy.OnDisconnect(ctx, client)
}

// Start registers the event handler and connects, retrying transient failures
// with a jittered backoff. It returns once a connection is established;
// supervision then continues in the background until Stop.
//
// Two contexts are in play and the distinction matters. The caller's ctx bounds
// the initial connect, so a caller with a deadline gets an answer within it.
// Supervision runs on a context derived with WithoutCancel, because it has to
// outlive the Start call — otherwise returning from Start would immediately
// tear down the handler it just installed.
func (d *Device) Start(ctx context.Context) error {
	d.mu.Lock()
	if d.running {
		d.mu.Unlock()
		return errors.New("wa: device is already running")
	}
	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	d.stop, d.running, d.done = cancel, true, make(chan struct{})
	d.handleID = d.cfg.Client.AddEventHandler(func(evt any) {
		d.handleEvent(runCtx, evt)
	})
	d.mu.Unlock()

	if err := d.connectWithBackoff(ctx); err != nil {
		d.Stop(ctx)
		return err
	}
	return nil
}

// Stop disconnects and unregisters. It is safe to call more than once.
//
// The context bounds teardown only. It is stripped of cancellation first,
// because Stop is usually reached *because* a context was cancelled, and a
// dead context would make the final presence update a no-op.
func (d *Device) Stop(ctx context.Context) {
	d.mu.Lock()
	if !d.running {
		d.mu.Unlock()
		return
	}
	d.running = false
	stop, handle, done := d.stop, d.handleID, d.done
	d.mu.Unlock()

	stop()
	d.cfg.Client.RemoveEventHandler(handle)

	teardown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	if err := d.cfg.Policy.OnDisconnect(teardown, d.cfg.Client); err != nil {
		d.log.Debug("withdrawing presence on shutdown failed", "error", err)
	}
	cancel()

	d.cfg.Client.Disconnect()
	close(done)
}

// Done is closed once Stop has completed.
func (d *Device) Done() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.done
}

// backoff schedule for the initial connect. whatsmeow handles reconnection
// once a session is established; this covers the cold start, where the network
// or the server may simply not be there yet.
const (
	backoffBase = 500 * time.Millisecond
	backoffMax  = 30 * time.Second
	maxAttempts = 8
)

func (d *Device) connectWithBackoff(ctx context.Context) error {
	var lastErr error
	for attempt := range maxAttempts {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := d.cfg.Client.Connect(); err == nil {
			return nil
		} else if errors.Is(err, whatsmeow.ErrAlreadyConnected) {
			return nil
		} else {
			lastErr = err
		}

		delay := jitteredBackoff(attempt)
		d.log.Warn("connect failed, retrying",
			"attempt", attempt+1, "of", maxAttempts, "in", delay, "error", lastErr)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
	return fmt.Errorf("wa: connect failed after %d attempts: %w", maxAttempts, lastErr)
}

// jitteredBackoff returns an exponential delay with full jitter.
//
// Full jitter rather than a fixed schedule because every device in the fleet
// reconnects at once after a network partition heals. Without jitter they would
// retry in lockstep and hammer the server in synchronised waves.
//
//nolint:gosec // G404: scheduling jitter, not a security decision
func jitteredBackoff(attempt int) time.Duration {
	d := backoffBase << attempt
	if d > backoffMax || d <= 0 {
		d = backoffMax
	}
	return time.Duration(rand.Int64N(int64(d)) + int64(backoffBase))
}

// handleEvent maps upstream events onto device state, then forwards everything
// to the sink.
//
// The supervisor consumes only the events that describe the connection itself.
// Message traffic is not interpreted here; that belongs to the ingest pipeline,
// and keeping the split clean is what stops this file growing into the v1
// server's handler, where connection handling, message dispatch, media
// downloads and event publishing all shared one function.
func (d *Device) handleEvent(ctx context.Context, evt any) {
	switch v := evt.(type) {
	case *events.PairSuccess:
		// BusinessName is the verified business name, not a push name. Our own
		// push name arrives later, via events.PushNameSetting.
		d.identity.merge(Identity{LID: v.LID, PN: v.ID, BusinessName: v.BusinessName})
		d.persistIdentity(ctx)
		d.setStatus(ctx, StatusPairing, "paired, connecting")

	case *events.Connected:
		// Identity is only fully known after the post-pairing reconnect.
		d.persistIdentity(ctx)
		d.setStatus(ctx, StatusOnline, "")
		// The one call that decides whether this device is visible. In passive
		// mode it does nothing, deliberately.
		if err := d.cfg.Policy.OnConnect(ctx, d.cfg.Client); err != nil {
			d.log.Warn("receipt policy failed on connect", "error", err)
		}

	case *events.Disconnected:
		// Transient. whatsmeow reconnects on its own; recording offline keeps
		// the UI honest in the meantime.
		d.setStatus(ctx, StatusOffline, "")

	case *events.LoggedOut:
		d.setStatus(ctx, StatusLoggedOut, fmt.Sprintf("unlinked (%s)", v.Reason))

	case *events.TemporaryBan:
		// Expire is a duration from now, not an instant.
		d.setStatus(ctx, StatusBanned, fmt.Sprintf("%s, lifts in %s", v.Code, v.Expire))

	case *events.StreamReplaced:
		// Another client connected with the same credentials. Reconnecting
		// would start a fight neither side wins.
		d.setStatus(ctx, StatusOffline, "replaced by another session")

	case *events.ClientOutdated:
		d.setStatus(ctx, StatusOffline, "client version rejected by the server")

	case *events.PushNameSetting:
		// Our own display name. Note this is PushNameSetting, not PushName:
		// the latter fires when a *contact* changes their name and would
		// otherwise overwrite this device's identity with a stranger's.
		if name := v.Action.GetName(); name != "" {
			d.identity.merge(Identity{PushName: name})
			d.persistIdentity(ctx)
		}
	}

	if msg, ok := evt.(*events.Message); ok {
		evt = d.openSecrets(ctx, msg)
	}

	if d.cfg.Sink != nil {
		d.cfg.Sink.Handle(ctx, d.cfg.ID, evt)
	}
}

// openSecrets decrypts the payloads WhatsApp encrypts a second time.
//
// Some content travels under a key derived from the message it refers to, so
// that only somebody who received the original can read it: an edit sent by a
// current client, and a reaction in an announcement group. whatsmeow decrypts
// the outer Signal layer and stops there — opening these needs the message
// secret it stored when the original arrived, and it leaves that call to the
// application.
//
// Nothing called it, so an edit reached the archive as a blob of a type nobody
// recognised. It looked exactly like a WhatsApp feature this build did not
// support, and it was a correction to a message sitting two lines above it.
//
// Done here rather than in the ingest pipeline because it needs the client, and
// this package is the only one that has one. It is decryption, not
// interpretation: the same job UnwrapRaw does one layer out.
// Returns what should be published: the same event, with its secret payload
// opened in place, except for a poll vote — whose plaintext has nowhere to live
// in the protobuf and so comes back paired with it.
func (d *Device) openSecrets(ctx context.Context, evt *events.Message) any {
	if evt.Message == nil {
		return evt
	}

	if enc := evt.Message.GetSecretEncryptedMessage(); enc != nil {
		inner, err := d.cfg.Client.DecryptSecretEncryptedMessage(ctx, evt)
		if err != nil {
			// Reported and left alone. The row still stores, still names the
			// field it could not open, and the raw protobuf is kept — so a
			// later build with the secret can still make sense of it.
			d.log.Warn("could not open a secret-encrypted message",
				"message", evt.Info.ID, "kind", enc.GetSecretEncType().String(), "error", err)
			return evt
		}
		evt.Message = asEdit(inner, enc)
		return evt
	}

	if evt.Message.GetPollUpdateMessage().GetVote() != nil {
		vote, err := d.cfg.Client.DecryptPollVote(ctx, evt)
		if err != nil {
			// Left alone on purpose. The row still stores and still names the
			// poll it answers; it simply does not say what was chosen, which
			// is the truth about a vote nobody here could open.
			d.log.Warn("could not open a poll vote",
				"message", evt.Info.ID, "error", err)
			return evt
		}
		return &normalize.OpenedPollVote{Message: evt, Selected: vote.GetSelectedOptions()}
	}

	if evt.Message.GetEncReactionMessage() != nil {
		reaction, err := d.cfg.Client.DecryptReaction(ctx, evt)
		if err != nil {
			d.log.Warn("could not open an encrypted reaction",
				"message", evt.Info.ID, "error", err)
			return evt
		}
		evt.Message = &waE2E.Message{
			ReactionMessage:    reaction,
			MessageContextInfo: evt.Message.GetMessageContextInfo(),
		}
	}
	return evt
}

// asEdit makes sure a decrypted correction still looks like one.
//
// The wrapper says what it is and which message it corrects, and the payload
// inside may or may not repeat that: some clients put a protocol message in
// there, others just the new content. Taking the answer from the wrapper when
// the payload does not carry one means the classifier sees an edit either way,
// rather than a stray line of text that happens to repeat something.
func asEdit(inner *waE2E.Message, enc *waE2E.SecretEncryptedMessage) *waE2E.Message {
	if inner == nil {
		return inner
	}
	if inner.GetProtocolMessage() != nil {
		return inner
	}
	if enc.GetSecretEncType() != waE2E.SecretEncryptedMessage_MESSAGE_EDIT {
		return inner
	}
	target := enc.GetTargetMessageKey()
	if target.GetID() == "" {
		return inner
	}
	return &waE2E.Message{
		ProtocolMessage: &waE2E.ProtocolMessage{
			Type:          waE2E.ProtocolMessage_MESSAGE_EDIT.Enum(),
			Key:           target,
			EditedMessage: inner,
		},
		MessageContextInfo: inner.GetMessageContextInfo(),
	}
}

func (d *Device) setStatus(ctx context.Context, s Status, reason string) {
	d.mu.Lock()
	if d.status == s {
		d.mu.Unlock()
		return
	}
	prev := d.status
	d.status = s
	d.mu.Unlock()

	d.log.Info("device status", "from", prev, "to", s, "reason", reason)
	if d.cfg.Store != nil {
		if err := d.cfg.Store.SetStatus(ctx, d.cfg.TenantID, d.cfg.ID, s, reason); err != nil {
			// Logged rather than dropped: the v1 server discarded persistence
			// errors with `_ = ...` and a failed write became a silent success.
			d.log.Error("persisting device status failed", "status", s, "error", err)
		}
	}
	if d.cfg.OnStatus != nil {
		d.cfg.OnStatus(d.cfg.TenantID, d.cfg.ID, s, reason)
	}
	if s.Terminal() {
		d.log.Warn("device reached a terminal state; supervision stops", "status", s, "reason", reason)
		// In its own goroutine because this runs inside the event handler, and
		// Stop unregisters that very handler.
		go d.Stop(context.WithoutCancel(ctx))
	}
}

func (d *Device) persistIdentity(ctx context.Context) {
	id := d.identity.get()
	if !id.Known() || d.cfg.Store == nil {
		return
	}
	if err := d.cfg.Store.SetIdentity(ctx, d.cfg.TenantID, d.cfg.ID, id); err != nil {
		d.log.Error("persisting device identity failed", "identity", id.String(), "error", err)
	}
}

// LearnIdentity records a LID/phone-number pairing observed at runtime, both
// locally and in whatsmeow's own mapping store.
func (d *Device) LearnIdentity(ctx context.Context, lid, pn types.JID) {
	if lid.IsEmpty() || pn.IsEmpty() {
		return
	}
	d.cfg.Client.StoreLIDPNMapping(ctx, lid, pn)
}
