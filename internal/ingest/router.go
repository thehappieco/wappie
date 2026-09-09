package ingest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/google/uuid"
	"go.mau.fi/whatsmeow/types/events"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/domain"
	"whatserver2/internal/obs"
	"whatserver2/internal/store"
	"whatserver2/internal/wa/normalize"
)

// DeviceInfo is what routing an event needs to know about its device.
type DeviceInfo struct {
	TenantID uuid.UUID
	// Own is the device's own identity, used to decide whether a history
	// message was sent by us when the stored copy only implies it.
	Own domain.Address
}

// DeviceLookup resolves a device id. Supplied by the registry, which is the
// only thing that knows which devices are running here.
type DeviceLookup func(deviceID string) (DeviceInfo, bool)

// ArchiveKeys supplies a device's public key.
type ArchiveKeys interface {
	ArchiveKey(ctx context.Context, tenant, device uuid.UUID) (seal.PublicKey, uint16, error)
}

// RouterConfig wires a router.
type RouterConfig struct {
	Lookup   DeviceLookup
	Keys     ArchiveKeys
	KeyStore seal.KeyStore
	Messages *store.Messages
	// Receipts archives acknowledgements. Optional: a deployment that only
	// wants the message archive can leave it out, and receipt events are then
	// counted as ignored rather than failing.
	Receipts *store.Receipts
	// Contacts records who the identifiers belong to. Optional: without it
	// names are counted as ignored and conversations stay identified by
	// number.
	Contacts *store.Contacts
	// Unread moves the read watermark. Optional: without it the badge only
	// ever grows, which is what it did before it existed.
	Unread *store.Unread
	// Groups records who is in a group and what has happened to it. Optional:
	// without it group events are counted as ignored, which is what they were.
	Groups *store.Groups
	// Retries handles WhatsApp's answer when a sender re-uploads an
	// attachment whose URL signature had expired. Optional.
	Retries MediaRetries
	Bus     Publisher
	Media   MediaQueue
	Metrics *obs.Metrics
	// Phones resolves a group participant's LID to the number behind it.
	// Optional: without it, group senders addressed by LID stay unmatched
	// against a contact list that is keyed by phone number.
	Phones PhoneBook
	Log    *slog.Logger
}

// MediaRetries handles the answer to a re-upload request.
type MediaRetries interface {
	Handle(ctx context.Context, evt *events.MediaRetry)
}

// Router turns whatsmeow events into archive rows.
//
// It is the single subscriber to every device's event stream, and the only
// place that decides what is stored and what is not. The v1 server ended its
// handler with a bare default case that discarded roughly forty event types
// without a trace; here every type is named, and the ones deliberately skipped
// increment a counter so they are visible on a dashboard rather than invisible
// in a switch.
type Router struct {
	cfg RouterConfig
	log *slog.Logger

	mu        sync.Mutex
	pipelines map[uuid.UUID]*Pipeline

	// history buffers sync chunks for the background worker. See
	// handleHistorySync for why they cannot be ingested inline.
	history chan historyChunk
}

// NewRouter builds a router.
func NewRouter(cfg RouterConfig) (*Router, error) {
	switch {
	case cfg.Lookup == nil:
		return nil, errors.New("ingest: router needs a device lookup")
	case cfg.Keys == nil || cfg.KeyStore == nil:
		return nil, errors.New("ingest: router needs a key source")
	case cfg.Messages == nil:
		return nil, errors.New("ingest: router needs a message store")
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Router{
		cfg: cfg, log: cfg.Log,
		pipelines: map[uuid.UUID]*Pipeline{},
		history:   make(chan historyChunk, historyQueueDepth),
	}, nil
}

// Handle receives one whatsmeow event. It satisfies wa.Sink.
func (r *Router) Handle(ctx context.Context, deviceID string, evt any) {
	name := eventName(evt)

	switch v := evt.(type) {
	case *events.Message:
		r.handleMessage(ctx, deviceID, v, name, nil)

	case *normalize.OpenedPollVote:
		// A poll answer the device managed to decrypt. The selection travels
		// beside the protobuf rather than inside it, because the protobuf has
		// no field to put it in.
		r.handleMessage(ctx, deviceID, v.Message, name, &normalize.OpenedVote{Selected: v.Selected})

	case *events.Receipt:
		r.handleReceipt(ctx, deviceID, v, name)

	case *events.HistorySync:
		r.handleHistorySync(ctx, deviceID, v, name)

	case *events.PushName:
		r.handlePushName(ctx, deviceID, v)
		r.handled(name)

	case *events.BusinessName:
		r.handleBusinessName(ctx, deviceID, v)
		r.handled(name)

	case *events.Contact:
		r.handleContact(ctx, deviceID, v)
		r.handled(name)

	case *events.Picture:
		r.handlePicture(ctx, deviceID, v)
		r.handled(name)

	case *events.MarkChatAsRead:
		r.handleMarkChatAsRead(ctx, deviceID, v)
		r.handled(name)

	case *events.JoinedGroup:
		r.handleJoinedGroup(ctx, deviceID, v)
		r.handled(name)

	case *events.ChatPresence:
		r.handleChatPresence(ctx, deviceID, v)
	case *events.Presence:
		r.handlePresence(ctx, deviceID, v)
		r.handled(name)

	case *events.GroupInfo:
		r.handleGroupInfo(ctx, deviceID, v)
		r.handled(name)

	case *events.MediaRetry:
		// A sender re-uploaded an attachment this archive could not fetch.
		// Reading the answer needs the media key, which is sealed — so the
		// retrier holds one only for the exchange it was given for.
		if r.cfg.Retries == nil {
			r.ignored(name)
			return
		}
		r.cfg.Retries.Handle(ctx, v)
		r.handled(name)

	// Handled by the device supervisor, which owns connection state. Counted
	// as handled rather than ignored: something does act on them.
	case *events.Connected, *events.Disconnected, *events.LoggedOut,
		*events.PairSuccess, *events.PairError, *events.QR,
		*events.TemporaryBan, *events.StreamReplaced, *events.ClientOutdated,
		*events.PushNameSetting:
		r.handled(name)

	default:
		// Everything not yet implemented. Presence, app state, groups, calls
		// and media retries all land here for now, and the counter is what
		// makes that visible: a series climbing steadily is a feature nobody
		// has built yet, not a mystery.
		r.ignored(name)
	}
}

// handleReceipt archives one acknowledgement.
//
// Worth stating where it sits relative to incognito: this server suppresses the
// receipts it *sends*, and that has no bearing on the ones it receives. Staying
// quiet does not make the other side stop telling us when they read something,
// so the edit-history projection works in passive mode — which is the only mode
// this product is really about.
func (r *Router) handleReceipt(ctx context.Context, deviceID string, evt *events.Receipt, name string) {
	info, ok := r.cfg.Lookup(deviceID)
	if !ok {
		r.log.Warn("receipt for a device this process does not supervise", "device", deviceID)
		r.failed(name, "unknown_device")
		return
	}
	if r.cfg.Receipts == nil {
		r.ignored(name)
		return
	}

	rec, err := normalize.ReceiptFrom(evt, normalize.Options{
		TenantID: info.TenantID.String(),
		DeviceID: deviceID,
		Own:      info.Own,
	})
	if errors.Is(err, normalize.ErrNotArchived) {
		// peer_msg and hist_sync: our own devices synchronising with each
		// other, not anybody acknowledging anything.
		r.ignored(name + "/housekeeping")
		return
	}
	if err != nil {
		r.log.Error("could not normalise a receipt", "device", deviceID, "error", err)
		r.failed(name, "normalize")
		return
	}

	if err := r.ingestReceipt(ctx, info.TenantID, rec); err != nil {
		r.log.Error("could not archive a receipt",
			"device", deviceID, "kind", rec.Kind, "error", err)
		r.failed(name, "ingest")
		return
	}
	r.handled(name)
}

func (r *Router) handleMessage(ctx context.Context, deviceID string, evt *events.Message, name string, pollVote *normalize.OpenedVote) {
	info, ok := r.cfg.Lookup(deviceID)
	if !ok {
		r.log.Warn("event for a device this process does not supervise", "device", deviceID)
		r.failed(name, "unknown_device")
		return
	}

	// A disappearing-timer change, before classification and deliberately not
	// as a row. See applyEphemeralSetting.
	r.applyEphemeralSetting(ctx, info, deviceID, evt)

	env, err := normalize.FromLive(evt, normalize.Options{
		TenantID: info.TenantID.String(),
		DeviceID: deviceID,
		Own:      info.Own,
		PollVote: pollVote,
	})
	if errors.Is(err, normalize.ErrSkip) {
		// Protocol housekeeping — key distribution, sync notifications. Real
		// traffic, but not archive content.
		r.ignored(name + "/housekeeping")
		return
	}
	if err != nil {
		r.log.Error("could not normalise a message", "device", deviceID, "error", err)
		r.failed(name, "normalize")
		return
	}

	device, err := uuid.Parse(deviceID)
	if err != nil {
		r.log.Error("device id is not a uuid", "device", deviceID, "error", err)
		r.failed(name, "bad_device")
		return
	}
	pipe, err := r.pipelineFor(ctx, info.TenantID, device)
	if err != nil {
		// Notably includes a device with no archive key. Ingest stops rather
		// than storing content unsealed, which would be a silent failure of
		// the one guarantee this system makes.
		r.log.Error("cannot ingest for this device",
			"tenant", info.TenantID, "device", deviceID, "error", err)
		r.failed(name, "no_pipeline")
		return
	}

	if _, err := pipe.Ingest(ctx, env); err != nil {
		r.log.Error("ingest failed",
			"device", deviceID, "message", env.MessageID, "kind", env.Kind, "error", err)
		r.failed(name, "ingest")
		return
	}
	r.handled(name)
}

// pipelineFor returns the device's pipeline, building it on first use.
//
// One per device rather than one per tenant, because the archive key is per
// device now: two devices of the same tenant seal under different keys, so they
// cannot share a sealer.
//
// Built lazily because it needs the device's archive public key, which may not
// exist when the process starts: a device paired before its key was generated
// is a normal state, and it fails here with a clear message rather than at boot
// with an obscure one.
func (r *Router) pipelineFor(ctx context.Context, tenant, device uuid.UUID) (*Pipeline, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if p, ok := r.pipelines[device]; ok {
		return p, nil
	}

	pub, epoch, err := r.cfg.Keys.ArchiveKey(ctx, tenant, device)
	if err != nil {
		return nil, fmt.Errorf("ingest: archive key for device %s: %w", device, err)
	}
	sealer, err := seal.NewSealer(tenant, device, pub, epoch, r.cfg.KeyStore)
	if err != nil {
		return nil, err
	}
	p, err := New(Config{
		Tenant: tenant, Sealer: sealer, Messages: r.cfg.Messages,
		Bus: r.cfg.Bus, Media: r.cfg.Media, Metrics: r.cfg.Metrics,
		Phones: r.cfg.Phones, Log: r.log,
	})
	if err != nil {
		return nil, err
	}
	r.pipelines[device] = p
	return p, nil
}

// IngestOutbound archives a message this server sent.
//
// Outbound goes through the same pipeline as inbound, so a message we sent is
// stored and rendered exactly like one we received — same sealing, same
// projection, same event. Only the source differs. A separate write path for
// our own messages is how v1 ended up with subtly different rows depending on
// direction.
func (r *Router) IngestOutbound(ctx context.Context, tenant uuid.UUID, deviceID string,
	env domain.Envelope) (Result, error) {
	device, err := uuid.Parse(deviceID)
	if err != nil {
		return Result{}, fmt.Errorf("ingest: %q is not a device id: %w", deviceID, err)
	}
	pipe, err := r.pipelineFor(ctx, tenant, device)
	if err != nil {
		return Result{}, err
	}
	env.TenantID = tenant.String()
	env.DeviceID = deviceID
	env.Source = domain.SourceOutbox
	// A message we sent has a sender: us. The send path cannot fill it — it
	// holds a whatsmeow client, not this device's identity — and the row went
	// in with sender_key NULL, so our own messages were the only ones in the
	// archive that could not say who wrote them. The lookup already carries
	// the identity for exactly this class of question.
	if env.Sender.Empty() {
		if info, ok := r.cfg.Lookup(deviceID); ok {
			env.Sender = info.Own
		}
	}
	return pipe.Ingest(ctx, env)
}

// Forget drops a device's cached pipeline, so the next event rebuilds it.
// Used after a key rotation, where the epoch and public key both change.
func (r *Router) Forget(device uuid.UUID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.pipelines, device)
}

func (r *Router) handled(name string) {
	if r.cfg.Metrics != nil {
		r.cfg.Metrics.EventsHandled.WithLabelValues(name).Inc()
	}
}

func (r *Router) ignored(name string) {
	if r.cfg.Metrics != nil {
		r.cfg.Metrics.EventsIgnored.WithLabelValues(name).Inc()
	}
}

func (r *Router) failed(name, reason string) {
	if r.cfg.Metrics != nil {
		r.cfg.Metrics.EventsFailed.WithLabelValues(name, reason).Inc()
	}
}

// eventName renders a whatsmeow event type for metric labels.
//
// Written out rather than derived by reflection so the label set is bounded:
// a metric label taken from a type name is a cardinality bomb waiting for
// upstream to add a type.
func eventName(evt any) string {
	switch evt.(type) {
	case *events.Message, *normalize.OpenedPollVote:
		// One label. A vote whose selection could not be opened arrives as a
		// plain Message and is stored the same way, so counting them apart
		// would split one kind of traffic across two series for a reason
		// nobody reading the metric would guess.
		return "Message"
	case *events.Receipt:
		return "Receipt"
	case *events.UndecryptableMessage:
		return "UndecryptableMessage"
	case *events.HistorySync:
		return "HistorySync"
	case *events.MediaRetry:
		return "MediaRetry"
	case *events.MediaRetryError:
		return "MediaRetryError"
	case *events.Connected:
		return "Connected"
	case *events.Disconnected:
		return "Disconnected"
	case *events.LoggedOut:
		return "LoggedOut"
	case *events.PairSuccess:
		return "PairSuccess"
	case *events.PairError:
		return "PairError"
	case *events.QR:
		return "QR"
	case *events.TemporaryBan:
		return "TemporaryBan"
	case *events.StreamReplaced:
		return "StreamReplaced"
	case *events.ClientOutdated:
		return "ClientOutdated"
	case *events.ChatPresence:
		return "ChatPresence"
	case *events.Presence:
		return "Presence"
	case *events.GroupInfo:
		return "GroupInfo"
	case *events.JoinedGroup:
		return "JoinedGroup"
	case *events.IdentityChange:
		return "IdentityChange"
	case *events.OfflineSyncPreview:
		return "OfflineSyncPreview"
	case *events.OfflineSyncCompleted:
		return "OfflineSyncCompleted"
	case *events.Contact:
		return "Contact"
	case *events.Picture:
		return "Picture"
	case *events.PushName:
		return "PushName"
	case *events.PushNameSetting:
		return "PushNameSetting"
	case *events.Pin:
		return "Pin"
	case *events.Star:
		return "Star"
	case *events.Mute:
		return "Mute"
	case *events.Archive:
		return "Archive"
	case *events.MarkChatAsRead:
		return "MarkChatAsRead"
	case *events.DeleteForMe:
		return "DeleteForMe"
	case *events.DeleteChat:
		return "DeleteChat"
	case *events.ClearChat:
		return "ClearChat"
	case *events.AppStateSyncComplete:
		return "AppStateSyncComplete"
	case *events.CallOffer:
		return "CallOffer"
	case *events.CallTerminate:
		return "CallTerminate"
	default:
		return "other"
	}
}
