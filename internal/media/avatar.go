package media

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/store"
)

// maxAvatarBytes bounds one profile picture.
//
// WhatsApp's are tens of kilobytes; this is far above that and exists because
// the URL is fetched over plain HTTP from a host that could answer with
// anything.
const maxAvatarBytes = 4 << 20

// AvatarClient is the part of a device the avatar worker needs.
type AvatarClient interface {
	GetProfilePictureInfo(ctx context.Context, jid types.JID,
		params *whatsmeow.GetProfilePictureParams) (*types.ProfilePictureInfo, error)
}

// Sealer seals a value for one device, bound to a row.
//
// The device is part of it because the archive key is: two devices of the same
// tenant seal under different keys, so a picture sealed for one is not readable
// with the other's.
type Sealer interface {
	SealFor(ctx context.Context, tenant, device, uid uuid.UUID,
		kind seal.Kind, value []byte) ([]byte, uint32, error)
}

// AvatarConfig wires the avatar worker.
type AvatarConfig struct {
	Contacts *store.Contacts
	Devices  *store.Devices
	Tenants  TenantLister
	Clients  func(ctx context.Context, tenant uuid.UUID, deviceID string) (AvatarClient, error)
	Sealer   Sealer
	Log      *slog.Logger

	// Batch is how many contacts one pass asks about, and Pace how long it
	// waits between them.
	//
	// Both matter. Each question is a query over the same socket that carries
	// messages, and a thousand of them as fast as they will go is a good way
	// to be rate limited — or to make the device look like something other
	// than a chat client.
	Batch    int
	Pace     time.Duration
	Interval time.Duration
	// StaleAfter is how long a picture is trusted before being asked about
	// again. People change them rarely.
	StaleAfter time.Duration
	// Origins is where a picture may be fetched from. The URL comes back
	// from a query over the device socket, and a server that answers with
	// an address of its choosing gets the same treatment as a sender who
	// picks an attachment URL: refused. Zero means WhatsApp's own hosts.
	Origins *Origins
}

// AvatarWorker keeps profile pictures.
//
// Unlike message media there is no ciphertext to preserve: WhatsApp serves
// profile pictures over plain HTTP, unencrypted, to anyone with the URL. So the
// bytes are sealed here on the way in, like a message body — a face is content
// — and the archive holds something the server cannot read even though it could
// read it for the moment it passed through.
//
// That asymmetry is worth naming rather than smoothing over. Inbound message
// media is never decrypted here; a profile picture necessarily is, because it
// never arrives encrypted at all.
type AvatarWorker struct {
	cfg     AvatarConfig
	log     *slog.Logger
	origins Origins
	http    *http.Client

	// nudges carries "look at these contacts now" from a reader that just met
	// an identifier it cannot draw. See Nudge.
	nudges chan avatarNudge
}

// avatarNudge asks for particular contacts ahead of the ordinary sweep.
type avatarNudge struct {
	tenant uuid.UUID
	device uuid.UUID
	keys   []string
}

// nudgeDepth bounds how many jumps of the queue may wait.
//
// Small on purpose. A dropped nudge costs a wait — the ordinary pass finds the
// same row — and an unbounded one would let a client that scrolls a thousand
// unknown chats schedule a thousand queries over the device socket.
const nudgeDepth = 64

// nudgeBatch bounds one nudge, for the same reason.
const nudgeBatch = 16

// NewAvatarWorker builds the worker.
func NewAvatarWorker(cfg AvatarConfig) (*AvatarWorker, error) {
	switch {
	case cfg.Contacts == nil:
		return nil, errors.New("media: the avatar worker needs a contact store")
	case cfg.Devices == nil || cfg.Tenants == nil || cfg.Clients == nil:
		return nil, errors.New("media: the avatar worker needs devices to ask through")
	case cfg.Sealer == nil:
		// Refusing rather than storing a picture in the clear. A silent
		// downgrade here would be the same failure as storing a message body
		// unsealed.
		return nil, errors.New("media: refusing to store profile pictures unsealed")
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Batch <= 0 {
		cfg.Batch = 20
	}
	if cfg.Pace <= 0 {
		cfg.Pace = 400 * time.Millisecond
	}
	if cfg.Interval <= 0 {
		cfg.Interval = time.Minute
	}
	if cfg.StaleAfter <= 0 {
		cfg.StaleAfter = 7 * 24 * time.Hour
	}
	origins := WhatsAppOrigins()
	if cfg.Origins != nil {
		origins = *cfg.Origins
	}
	return &AvatarWorker{
		cfg: cfg, log: cfg.Log,
		origins: origins,
		http:    origins.Client(2*time.Minute, 3),
		nudges:  make(chan avatarNudge, nudgeDepth),
	}, nil
}

// Nudge asks for these contacts' pictures ahead of the ordinary sweep.
//
// The sweep is paced deliberately — each question is a query over the socket
// that carries messages — which is right for five thousand contacts and wrong
// for the one conversation a person just opened and is looking at. This is the
// jump-the-queue path for that case.
//
// Never blocks and never reports failure. A dropped nudge costs a wait, not a
// picture: the row is still in the durable queue and the next pass finds it.
func (w *AvatarWorker) Nudge(tenant, device uuid.UUID, keys []string) {
	if w == nil || len(keys) == 0 {
		return
	}
	if len(keys) > nudgeBatch {
		keys = keys[:nudgeBatch]
	}
	select {
	case w.nudges <- avatarNudge{tenant: tenant, device: device, keys: keys}:
	default:
	}
}

// Run keeps profile pictures up to date until the context ends.
func (w *AvatarWorker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.cfg.Interval)
	defer ticker.Stop()
	// The first sweep runs before the first tick, and a nudge must not trigger
	// one: answering "who is this" for four contacts would otherwise walk every
	// contact of every device first.
	w.pass(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.pass(ctx)
		case n := <-w.nudges:
			w.urgent(ctx, n)
		}
	}
}

// urgent answers one nudge: the named contacts, now, at the usual pace.
//
// Still paced. The point of jumping the queue is being asked about first, not
// being asked about faster — the rate limit does not care which contact a
// question was about.
func (w *AvatarWorker) urgent(ctx context.Context, n avatarNudge) {
	client, err := w.cfg.Clients(ctx, n.tenant, n.device.String())
	if err != nil {
		return
	}
	rows, err := w.cfg.Contacts.Some(ctx, n.tenant, n.device, n.keys)
	if err != nil {
		w.log.Debug("could not read contacts for a picture nudge", "error", err)
		return
	}
	for _, contact := range rows {
		if ctx.Err() != nil {
			return
		}
		// Already looked at recently. Asking again because a client drew the
		// row would defeat the whole point of recording the check.
		if contact.AvatarChecked != nil &&
			time.Since(*contact.AvatarChecked) < w.cfg.StaleAfter {
			continue
		}
		w.one(ctx, n.tenant, n.device, client, contact)
		select {
		case <-ctx.Done():
			return
		case <-time.After(w.cfg.Pace):
		}
	}
}

func (w *AvatarWorker) pass(ctx context.Context) {
	tenants, err := w.cfg.Tenants(ctx)
	if err != nil {
		w.log.Error("could not list tenants for profile pictures", "error", err)
		return
	}
	for _, tenant := range tenants {
		devices, err := w.cfg.Devices.List(ctx, tenant.String())
		if err != nil {
			w.log.Error("could not list devices", "tenant", tenant, "error", err)
			continue
		}
		for _, dev := range devices {
			if ctx.Err() != nil {
				return
			}
			w.drainDevice(ctx, tenant, dev.ID)
		}
	}
}

func (w *AvatarWorker) drainDevice(ctx context.Context, tenant uuid.UUID, deviceID string) {
	device, err := uuid.Parse(deviceID)
	if err != nil {
		return
	}
	client, err := w.cfg.Clients(ctx, tenant, deviceID)
	if err != nil {
		// Not connected. Nothing to report: the queue is durable and the next
		// pass finds the same rows.
		return
	}
	pending, err := w.cfg.Contacts.NeedAvatar(ctx, tenant, device, w.cfg.StaleAfter, w.cfg.Batch)
	if err != nil {
		w.log.Error("could not list contacts needing pictures", "error", err)
		return
	}

	var fetched, unchanged, none int
	for _, contact := range pending {
		if ctx.Err() != nil {
			return
		}
		switch w.one(ctx, tenant, device, client, contact) {
		case resultFetched:
			fetched++
		case resultUnchanged:
			unchanged++
		case resultNone:
			none++
		}
		// Paced deliberately. Each question is a query over the socket that
		// carries messages.
		select {
		case <-ctx.Done():
			return
		case <-time.After(w.cfg.Pace):
		}
	}
	if fetched > 0 {
		w.log.Info("profile pictures updated",
			"device", deviceID, "fetched", fetched, "unchanged", unchanged, "none", none)
	}
}

type avatarResult int

const (
	resultNone avatarResult = iota
	resultUnchanged
	resultFetched
	resultFailed
)

// one updates a single contact's picture.
func (w *AvatarWorker) one(ctx context.Context, tenant, device uuid.UUID,
	client AvatarClient, contact store.ContactRow) avatarResult {
	jid, err := types.ParseJID(contact.ContactKey)
	if err != nil {
		return resultFailed
	}

	info, err := client.GetProfilePictureInfo(ctx, jid, &whatsmeow.GetProfilePictureParams{
		ExistingID: contact.AvatarID,
	})
	if err != nil {
		// A contact whose privacy settings hide their picture answers with an
		// error, and so does one who has none. Both mean "nothing to fetch",
		// and both must be recorded or every pass asks again and the contacts
		// that have never been asked never get a turn.
		w.touch(ctx, tenant, device, contact.ContactKey)
		return resultNone
	}
	if info == nil {
		// Unchanged: whatsmeow answers nil when ExistingID still matches.
		w.touch(ctx, tenant, device, contact.ContactKey)
		return resultUnchanged
	}
	if info.URL == "" {
		w.touch(ctx, tenant, device, contact.ContactKey)
		return resultNone
	}

	picture, err := w.fetch(ctx, info.URL)
	if err != nil {
		w.log.Debug("could not fetch a profile picture",
			"contact", contact.ContactKey, "error", err)
		w.touch(ctx, tenant, device, contact.ContactKey)
		return resultFailed
	}

	sealed, keyID, err := w.cfg.Sealer.SealFor(ctx, tenant, device,
		store.ContactUID(device, contact.ContactKey), seal.KindAvatar, picture)
	if err != nil {
		w.log.Error("could not seal a profile picture",
			"contact", contact.ContactKey, "error", err)
		return resultFailed
	}
	if err := w.cfg.Contacts.SetAvatar(ctx, tenant, device,
		contact.ContactKey, info.ID, sealed, keyID); err != nil {
		w.log.Error("could not store a profile picture",
			"contact", contact.ContactKey, "error", err)
		return resultFailed
	}
	return resultFetched
}

// fetch downloads a profile picture.
//
// Plain HTTP with no authentication, because that is how WhatsApp serves them.
// Bounded, because the response comes from a host that could answer with
// anything and the bytes go straight into a database row.
func (w *AvatarWorker) fetch(ctx context.Context, url string) ([]byte, error) {
	if err := w.origins.Check(url); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := w.http.Do(req)
	if err != nil {
		return nil, err
	}
	//nolint:errcheck // the body is fully read or being discarded
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAvatarBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxAvatarBytes {
		return nil, fmt.Errorf("profile picture is over %d bytes", maxAvatarBytes)
	}
	if len(body) == 0 {
		return nil, errors.New("empty profile picture")
	}
	return body, nil
}

func (w *AvatarWorker) touch(ctx context.Context, tenant, device uuid.UUID, contactKey string) {
	if err := w.cfg.Contacts.TouchAvatar(ctx, tenant, device, contactKey); err != nil {
		w.log.Debug("could not record a profile picture check", "error", err)
	}
}
