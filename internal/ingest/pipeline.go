// Package ingest is the single path everything entering the archive follows.
//
// Normalise, resolve, seal, persist, publish — in that order, for every event,
// from every source. The v1 server had four pairs of parallel implementations
// of parts of this, and all four had drifted by the time it was abandoned. One
// pipeline is the correction.
//
// Sealing happens as late as possible and as close to persistence as it can be,
// so plaintext has the shortest life it can in this process. That is a real but
// limited protection: a server executing attacker code sees content in flight
// regardless, which is why the README says at-rest sealing protects a stolen
// disk and a leaked backup rather than a live compromise.
package ingest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/domain"
	"whatserver2/internal/obs"
	"whatserver2/internal/store"
)

// Publisher receives events for live delivery to connected clients.
type Publisher interface {
	Publish(tenantID uuid.UUID, ev Event)
}

// Event is what a connected client is told about.
//
// Deliberately free of content: it carries identifiers and the sequence number,
// and a client fetches the sealed row and opens it. Putting sealed bytes on the
// bus would mean the same payload rendered twice, once for live and once for
// replay, which is how v1 ended up with two renderers that disagreed.
type Event struct {
	// Class says which store holds the thing this event announces. It exists
	// because the delivery path reads the row back before sending it, and the
	// row for an acknowledgement lives in a different table from the row for a
	// message. Spelled out rather than left to a zero value, so adding a third
	// class in a later phase cannot silently inherit the wrong one.
	Class Class

	Seq      int64
	TenantID uuid.UUID
	DeviceID uuid.UUID
	ChatKey  string

	// Kind, Type and UID describe a message and are empty on a receipt.
	Kind domain.Kind
	Type domain.Type
	UID  uuid.UUID

	// Ephemeral marks an event that has no row behind it and no sequence
	// number: somebody is typing, and in a moment they will not be.
	//
	// It changes two things about how the bus may treat it, and both are the
	// difference between a nicety and a data-loss bug. Such an event carries
	// Seq 0, so the replay handover would discard it — harmless, since stale
	// presence is worthless — but an overflow would record 0 as the sequence
	// the client must resume from, and the client would refetch the archive
	// from the beginning. And a dropped "typing" is worth nothing, so it must
	// never mark a subscription lagged at all.
	Ephemeral bool

	// Presence carries what an ephemeral event says. Empty otherwise.
	Presence *Presence

	// Chat carries a change to the conversation itself rather than to
	// anything in it: a badge that went up, a disappearing timer somebody
	// altered.
	//
	// It exists because the server had no way to say either. Both numbers were
	// computed correctly and written correctly, and the only frame that ever
	// carried them was the reply to a chats.list request — so a badge moved
	// when the sidebar was refetched and at no other moment, and a timer the
	// other side changed was invisible until a reload.
	Chat *ChatUpdate
}

// ChatUpdate is a change to a conversation's own state.
//
// Every field is a pointer because this is a patch, not a snapshot: an event
// about a badge says nothing about the timer, and a client that treated a
// missing field as zero would clear one every time the other moved.
type ChatUpdate struct {
	ChatKey string
	// Unread is the badge, recomputed by the server.
	Unread *int32
	// Ephemeral is the disappearing timer in seconds; zero means off, which is
	// why it has to be a pointer to be sayable at all.
	Ephemeral *int32
}

// Presence is somebody typing or recording, right now.
//
// Nothing about it is stored. It is true for a few seconds and then it is not,
// and an archive that kept it would be recording a fact that had already
// stopped being one by the time anybody read the row.
type Presence struct {
	ChatKey   string
	SenderKey string
	SenderLID string
	SenderPN  string
	// State is "available", "unavailable", "composing" or "paused"; Media is "audio" while recording a
	// voice note and empty while typing.
	State    string
	Media    string
	LastSeen *time.Time
}

// Class distinguishes what an event announces.
type Class string

const (
	// ClassMessage announces a row in messages: a message, an edit, a
	// deletion or a reaction.
	ClassMessage Class = "message"

	// ClassPresence announces that somebody is typing. There is no row and no
	// sequence: see Event.Ephemeral.
	ClassPresence Class = "presence"

	// ClassChat announces a change to a conversation rather than to anything
	// in it. Ephemeral, like presence, and for the same reason: there is no
	// row behind it and no sequence number, so it must never move a client's
	// replay cursor or mark a subscription lagged. A dropped one leaves a
	// stale badge until the next listing, which is exactly what every badge
	// did before this existed.
	ClassChat Class = "chat"

	// ClassReceipt announces a row in receipts: somebody acknowledged
	// something. Carried on the same sequence as messages so a client keeps
	// one cursor.
	ClassReceipt Class = "receipt"
)

// MediaQueue receives attachments that still need downloading.
type MediaQueue interface {
	Enqueue(ctx context.Context, tenantID, messageUID uuid.UUID) error
}

// Pipeline ingests envelopes for one tenant.
type Pipeline struct {
	tenant   uuid.UUID
	sealer   *seal.Sealer
	messages *store.Messages
	bus      Publisher
	media    MediaQueue
	metrics  *obs.Metrics
	phones   PhoneBook
	log      *slog.Logger
}

// Config wires a pipeline.
type Config struct {
	Tenant   uuid.UUID
	Sealer   *seal.Sealer
	Messages *store.Messages
	Bus      Publisher
	Media    MediaQueue
	Metrics  *obs.Metrics
	// Phones resolves a group participant's LID to the number behind it, so a
	// sender can be matched against a contact list keyed by phone number.
	// Optional: without it, LID-only senders stay LID-only.
	Phones PhoneBook
	Log    *slog.Logger
}

// PhoneBook answers "whose number is this LID".
//
// An interface rather than the concrete map so this package keeps not importing
// whatsmeow, and so a test can answer without a session store.
type PhoneBook interface {
	PhoneFor(ctx context.Context, lid types.JID) (types.JID, bool)
}

// New builds a pipeline.
func New(cfg Config) (*Pipeline, error) {
	if cfg.Sealer == nil {
		// Refusing here rather than falling back to storing plaintext. A
		// silent downgrade would be the worst possible failure of the one
		// guarantee this system makes.
		return nil, errors.New("ingest: a sealer is required; refusing to store content unsealed")
	}
	if cfg.Messages == nil {
		return nil, errors.New("ingest: a message store is required")
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Pipeline{
		tenant: cfg.Tenant, sealer: cfg.Sealer, messages: cfg.Messages,
		bus: cfg.Bus, media: cfg.Media, metrics: cfg.Metrics,
		phones: cfg.Phones, log: cfg.Log,
	}, nil
}

// Result reports what one ingest did.
type Result struct {
	UID       uuid.UUID
	Seq       int64
	Duplicate bool
}

// Ingest stores one envelope.
func (p *Pipeline) Ingest(ctx context.Context, env domain.Envelope) (Result, error) {
	if err := validate(env); err != nil {
		return Result{}, err
	}
	p.resolvePhones(ctx, &env)

	// The row identity is chosen here because the sealed fields bind to it.
	// UUIDv7 so the primary key stays roughly time-ordered on disk.
	uid, err := uuid.NewV7()
	if err != nil {
		return Result{}, fmt.Errorf("ingest: new uid: %w", err)
	}

	deviceID, err := uuid.Parse(env.DeviceID)
	if err != nil {
		return Result{}, fmt.Errorf("ingest: device id %q: %w", env.DeviceID, err)
	}

	sealed, keyID, err := p.seal(ctx, uid, env)
	if err != nil {
		return Result{}, err
	}

	in := store.InsertMessage{
		UID:      uid,
		TenantID: p.tenant,
		DeviceID: deviceID,

		WAID:    env.MessageID,
		ChatKey: env.Chat.Primary().String(),
		ChatLID: jidString(env.Chat.LID),
		ChatPN:  jidString(env.Chat.PN),
		IsGroup: env.IsGroup,

		SenderKey: jidString(env.Sender.Primary()),
		SenderLID: jidString(env.Sender.LID),
		SenderPN:  jidString(env.Sender.PN),

		TS:       env.Timestamp,
		IsFromMe: env.IsFromMe,

		Kind: env.Kind,
		Type: env.Type,
		// Carried through so an unsupported row can say what it was. The
		// payload is sealed; without this the answer is unreachable.
		Unsupported: env.Content.Unsupported,

		TargetWAID: env.TargetID,
		ReplyTo:    env.ReplyTo,

		IsForwarded:     env.IsForwarded,
		ForwardingScore: int32(min(env.ForwardingScore, 1<<31-1)),

		Expiration: int32(min(env.Expiration, 1<<31-1)),
		ViewOnce:   env.ViewOnce,
		Ephemeral:  env.Ephemeral,

		Source: env.Source,

		ContentKeyID:  keyID,
		BodySealed:    sealed[seal.KindBody],
		RawSealed:     sealed[seal.KindRawProto],
		PayloadSealed: sealed[seal.KindPayload],
	}
	if env.Content.Media != nil {
		in.Media = mediaRow(env.Type, env.Content.Media, sealed)
	}

	res, err := p.messages.Insert(ctx, in)
	if err != nil {
		p.failed(string(env.Kind), "insert")
		return Result{}, err
	}
	out := Result{UID: res.UID, Seq: res.Seq, Duplicate: res.Duplicate}

	if res.Duplicate {
		// Routine, not exceptional: history sync redelivers what has been seen
		// and the event stream is at-least-once. Nothing is republished, or a
		// client would see the same message twice on every backfill.
		p.handled(string(env.Kind), "duplicate")
		return out, nil
	}
	p.handled(string(env.Kind), "stored")

	if in.Media != nil && p.media != nil {
		if err := p.media.Enqueue(ctx, p.tenant, res.UID); err != nil {
			// The message is already stored; the attachment can be fetched
			// later. Failing the ingest here would lose the message over a
			// queue hiccup.
			p.log.Warn("could not queue a media download",
				"message", res.UID, "error", err)
		}
	}

	if p.bus != nil {
		p.bus.Publish(p.tenant, Event{
			Class: ClassMessage,
			Seq:   res.Seq, TenantID: p.tenant, DeviceID: deviceID,
			ChatKey: in.ChatKey, Kind: env.Kind, Type: env.Type, UID: res.UID,
		})
		// And the badge, which the store just recomputed and which nothing
		// else will ever mention. Sent even when the count did not move: the
		// alternative is remembering what each subscriber last saw, and a
		// number repeated costs a client one assignment.
		if res.CountsUnread {
			unread := res.Unread
			p.bus.Publish(p.tenant, Event{
				Class: ClassChat, TenantID: p.tenant, DeviceID: deviceID,
				ChatKey: in.ChatKey, Ephemeral: true,
				Chat: &ChatUpdate{ChatKey: in.ChatKey, Unread: &unread},
			})
		}
	}
	return out, nil
}

// seal encrypts every content field of one message under a single content key.
//
// One key per row, not per field: a reader unwraps once and opens four values,
// rather than doing four asymmetric operations. Each value keeps its own kind,
// so a thumbnail still cannot be presented where a body is expected.
func (p *Pipeline) seal(ctx context.Context, uid uuid.UUID, env domain.Envelope) (map[seal.Kind][]byte, uint32, error) {
	values := map[seal.Kind][]byte{}
	if env.Content.Body != "" {
		values[seal.KindBody] = []byte(env.Content.Body)
	}
	if len(env.Content.Raw) > 0 {
		values[seal.KindRawProto] = env.Content.Raw
	}
	// The structured content: a location, a poll, contact cards, an event, a
	// link preview, the mention list. Sealed as one value under the same key
	// as the body, so a client that opens the body has already done the
	// asymmetric work needed to open this too.
	if pl := env.Content.Payload(); !pl.Empty() {
		b, err := pl.Marshal()
		if err != nil {
			return nil, 0, fmt.Errorf("ingest: encode payload: %w", err)
		}
		values[seal.KindPayload] = b
	}
	if m := env.Content.Media; m != nil {
		if len(m.MediaKey) > 0 {
			values[seal.KindMediaKey] = m.MediaKey
		}
		if len(m.Thumbnail) > 0 {
			values[seal.KindThumbnail] = m.Thumbnail
		}
		if m.FileName != "" {
			// A file name is content, not metadata: "acordo-divorcio.pdf"
			// says more than most message bodies.
			values[seal.KindContactName] = []byte(m.FileName)
		}
	}
	if len(values) == 0 {
		return nil, 0, nil
	}

	sealed, keyID, err := p.sealer.SealAll(ctx, uid, values)
	if err != nil {
		return nil, 0, fmt.Errorf("ingest: seal content: %w", err)
	}
	if p.metrics != nil {
		for kind := range values {
			p.metrics.Sealed.WithLabelValues(kind.String()).Inc()
		}
	}
	return sealed, keyID, nil
}

func mediaRow(typ domain.Type, m *domain.Media, sealed map[seal.Kind][]byte) *store.InsertMedia {
	return &store.InsertMedia{
		MediaType:     string(typ),
		MimeType:      m.MimeType,
		FileLength:    int64(min(m.FileLength, 1<<62)),
		FileSHA256:    m.FileSHA256,
		FileEncSHA256: m.FileEncSHA256,
		DirectPath:    m.DirectPath,
		URL:           m.URL,
		Width:         int32(min(m.Width, 1<<31-1)),
		Height:        int32(min(m.Height, 1<<31-1)),
		Seconds:       int32(min(m.Seconds, 1<<31-1)),
		Waveform:      m.Waveform,
		Sidecar:       m.Sidecar,
		IsGIF:         m.IsGIF,

		MediaKeySealed: sealed[seal.KindMediaKey],
		ThumbSealed:    sealed[seal.KindThumbnail],
		FileNameSealed: sealed[seal.KindContactName],
	}
}

func validate(env domain.Envelope) error {
	switch {
	case env.MessageID == "":
		return errors.New("ingest: envelope has no message id")
	case env.DeviceID == "":
		return errors.New("ingest: envelope has no device")
	case !env.Kind.Valid():
		return fmt.Errorf("ingest: unknown kind %q", env.Kind)
	case env.Type == "":
		return errors.New("ingest: envelope has no type")
	case env.Chat.Empty():
		return errors.New("ingest: envelope has no chat")
	case env.Kind.IsControl() && env.TargetID == "":
		return fmt.Errorf("ingest: a %s row must name a target", env.Kind)
	}
	return nil
}

func (p *Pipeline) handled(kind, outcome string) {
	if p.metrics != nil {
		p.metrics.EventsHandled.WithLabelValues(kind + ":" + outcome).Inc()
	}
}

func (p *Pipeline) failed(kind, reason string) {
	if p.metrics != nil {
		p.metrics.EventsFailed.WithLabelValues(kind, reason).Inc()
	}
}

func jidString(j jidLike) string {
	if j.IsEmpty() {
		return ""
	}
	return j.String()
}

// jidLike is the slice of types.JID this package uses, so the signature does
// not drag the whole type in.
type jidLike interface {
	IsEmpty() bool
	String() string
}

// resolvePhones fills in a phone number the addressing hid.
//
// WhatsApp addresses group participants by LID, and the contact list a phone
// syncs is keyed by phone number, so a group sender matches no contact and
// shows up unnamed. On one real account that was 860 of 883 senders -- not
// missing names, just names filed under an identifier nobody looked up.
//
// Here rather than in normalize, because this is the one point live traffic,
// history and outbound all pass through, and history is where it matters: the
// history importer rebuilds MessageInfo itself and never sets SenderAlt, so
// 15040 of 15041 LID-only senders came from a sync. Fixing only the live path
// would have repaired about a hundred rows out of fifteen thousand.
//
// One direction, and only one: a missing PN is filled from a LID, never the
// reverse. Primary() prefers the LID, so inventing one would change chat_key
// and sender_key -- the archive's storage identity -- and every row would
// arrive again under a different name.
func (p *Pipeline) resolvePhones(ctx context.Context, env *domain.Envelope) {
	if p.phones == nil {
		return
	}
	fill := func(a domain.Address) domain.Address {
		if !a.PN.IsEmpty() || a.LID.IsEmpty() {
			return a
		}
		if pn, ok := p.phones.PhoneFor(ctx, a.LID); ok {
			a.PN = pn
		}
		return a
	}
	env.Sender = fill(env.Sender)
	env.Chat = fill(env.Chat)
}
