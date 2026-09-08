package media

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"

	"whatserver2/internal/store"
)

// pendingTTL is how long a retry keeps its media key in memory.
//
// WhatsApp answers a retry receipt in seconds when the sender is reachable and
// never when they are not, so this is generous rather than tuned. It exists to
// bound how long key material sits in this process, which is the whole reason
// the map is swept at all.
const pendingTTL = 10 * time.Minute

// maxPending bounds outstanding retries, so a caller cannot grow this map
// without limit by asking for retries nobody will ever answer.
const maxPending = 4096

// ErrNotAvailable reports that the sender no longer has the file.
var ErrNotAvailable = errors.New("media: the sender's device no longer has this attachment")

// ErrTooManyPending reports the retry table being full.
var ErrTooManyPending = errors.New("media: too many retries are already outstanding")

// Retrier asks senders to re-upload attachments whose URLs have expired.
//
// WhatsApp signs media URLs with an expiry, and the direct path carries the
// same signature — so once it passes there is no second address to try and no
// header that helps. A history sync replays messages from months ago with the
// URL that was minted then, which is why a bootstrap can arrive with most of
// its attachments already unreachable.
//
// The recovery is to ask the sender's device to upload the file again. It
// needs the media key, both to authenticate the request and to read the reply
// — and the key is sealed, so this server cannot supply it. The client opens
// it and passes it in for the duration of one exchange. That is a real
// exposure and it is deliberate: the key is held in memory, for minutes, for
// attachments the owner explicitly asked to recover, and never written down.
type Retrier struct {
	Messages *store.Messages
	Media    *store.Media
	Devices  DeviceClients
	// Queue is nudged when an attachment becomes downloadable again.
	Queue interface {
		Enqueue(ctx context.Context, tenant, messageUID uuid.UUID) error
	}
	Log *slog.Logger

	mu      sync.Mutex
	pending map[types.MessageID]pendingRetry
}

type pendingRetry struct {
	tenant     uuid.UUID
	messageUID uuid.UUID
	key        []byte
	expires    time.Time
}

// RetryClient is the part of a device a retry needs.
type RetryClient interface {
	SendMediaRetryReceipt(ctx context.Context, message *types.MessageInfo, mediaKey []byte) error
}

// DeviceClients resolves a device to something that can send a retry receipt.
type DeviceClients func(ctx context.Context, tenant uuid.UUID, deviceID string) (RetryClient, error)

// Request asks the sender to re-upload one attachment.
func (r *Retrier) Request(ctx context.Context, tenant, device, messageUID uuid.UUID,
	mediaKey []byte) error {
	if len(mediaKey) != 32 {
		return errors.New("media: a media key is 32 bytes; open the sealed one first")
	}
	row, err := r.Messages.Get(ctx, tenant, messageUID)
	if err != nil {
		return fmt.Errorf("media: no such message: %w", err)
	}
	if row.Media == nil {
		return store.ErrNoMedia
	}

	chat, err := types.ParseJID(row.ChatKey)
	if err != nil {
		return fmt.Errorf("media: chat %q is not a JID: %w", row.ChatKey, err)
	}
	sender := chat
	if row.SenderKey != "" {
		if sender, err = types.ParseJID(row.SenderKey); err != nil {
			return fmt.Errorf("media: sender %q is not a JID: %w", row.SenderKey, err)
		}
	}

	client, err := r.Devices(ctx, tenant, device.String())
	if err != nil {
		return fmt.Errorf("media: %w", err)
	}

	if err := r.remember(row.WAID, pendingRetry{
		tenant: tenant, messageUID: messageUID,
		key: mediaKey, expires: time.Now().Add(pendingTTL),
	}); err != nil {
		return err
	}

	info := &types.MessageInfo{
		ID: row.WAID,
		MessageSource: types.MessageSource{
			Chat: chat, Sender: sender,
			IsFromMe: row.IsFromMe, IsGroup: row.IsGroup,
		},
	}
	if err := client.SendMediaRetryReceipt(ctx, info, mediaKey); err != nil {
		r.forget(row.WAID)
		return fmt.Errorf("media: send retry receipt: %w", err)
	}
	return nil
}

// Handle processes WhatsApp's answer to a retry.
func (r *Retrier) Handle(ctx context.Context, evt *events.MediaRetry) {
	log := r.Log
	if log == nil {
		log = slog.Default()
	}

	entry, ok := r.take(evt.MessageID)
	if !ok {
		// Either the retry was asked for by another process, or it took longer
		// than the key was held. Neither is worth an error: the attachment is
		// simply still missing, and asking again is cheap.
		log.Debug("a media retry arrived with no key held for it", "message", evt.MessageID)
		return
	}

	notif, err := whatsmeow.DecryptMediaRetryNotification(evt, entry.key)
	if err != nil {
		if errors.Is(err, whatsmeow.ErrMediaNotAvailableOnPhone) {
			// The sender's device no longer has the file. Nothing recovers
			// this, and it is the expected answer for anything old.
			log.Info("the sender no longer has this attachment", "message", evt.MessageID)
			return
		}
		log.Warn("could not read a media retry answer", "message", evt.MessageID, "error", err)
		return
	}
	if notif.GetDirectPath() == "" {
		log.Info("a media retry came back with no new path", "message", evt.MessageID)
		return
	}

	if err := r.Media.Refresh(ctx, entry.tenant, entry.messageUID, notif.GetDirectPath()); err != nil {
		log.Error("could not record a refreshed media path",
			"message", evt.MessageID, "error", err)
		return
	}
	if r.Queue != nil {
		if err := r.Queue.Enqueue(ctx, entry.tenant, entry.messageUID); err != nil {
			log.Debug("could not nudge the media queue", "error", err)
		}
	}
	log.Info("an attachment was re-uploaded and is queued again", "message", evt.MessageID)
}

// Pending reports how many retries are outstanding.
func (r *Retrier) Pending() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pending)
}

func (r *Retrier) remember(id types.MessageID, entry pendingRetry) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending == nil {
		r.pending = map[types.MessageID]pendingRetry{}
	}
	r.sweepLocked()
	if len(r.pending) >= maxPending {
		return ErrTooManyPending
	}
	r.pending[id] = entry
	return nil
}

func (r *Retrier) take(id types.MessageID) (pendingRetry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.pending[id]
	delete(r.pending, id)
	r.sweepLocked()
	if !ok || time.Now().After(entry.expires) {
		return pendingRetry{}, false
	}
	return entry, true
}

func (r *Retrier) forget(id types.MessageID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.pending, id)
}

// sweepLocked drops expired entries. Key material must not outlive its use, and
// there is no other moment that reliably arrives — a retry nobody answers
// produces no event to clean up after.
func (r *Retrier) sweepLocked() {
	now := time.Now()
	for id, entry := range r.pending {
		if now.After(entry.expires) {
			delete(r.pending, id)
		}
	}
}
