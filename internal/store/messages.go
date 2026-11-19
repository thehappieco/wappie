package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/domain"
	"whatserver2/internal/pg"
)

// Messages persists the archive.
type Messages struct{ pool *pgxpool.Pool }

// NewMessages returns a message store.
func NewMessages(pool *pgxpool.Pool) *Messages { return &Messages{pool: pool} }

// InsertMedia describes an attachment being recorded alongside a message.
type InsertMedia struct {
	MediaType     string
	MimeType      string
	FileLength    int64
	FileSHA256    []byte
	FileEncSHA256 []byte
	DirectPath    string
	URL           string
	Width         int32
	Height        int32
	Seconds       int32
	Waveform      []byte
	Sidecar       []byte
	IsGIF         bool

	MediaKeySealed []byte
	ThumbSealed    []byte
	FileNameSealed []byte
}

// InsertMessage is one row to store, with its content already sealed.
//
// The sealed fields arrive as opaque bytes. Nothing in this package can open
// them, which is the point: persistence has no access to content even in
// principle.
type InsertMessage struct {
	// UID is chosen by the caller rather than by the database.
	//
	// The sealed fields are bound to it through the associated data, so it has
	// to exist before anything can be sealed. Letting Postgres default it
	// would mean sealing against an id nobody knows yet.
	UID uuid.UUID

	TenantID uuid.UUID
	DeviceID uuid.UUID

	WAID    string
	ChatKey string
	ChatLID string
	ChatPN  string
	IsGroup bool
	// ProbeKeys are the other keys a direct message may already be stored
	// under: the chat's other half, LID or phone number. A copy under one of
	// them is a duplicate. Groups have none.
	ProbeKeys []string

	SenderKey string
	SenderLID string
	SenderPN  string

	TS       time.Time
	IsFromMe bool

	Kind domain.Kind
	Type domain.Type
	// Unsupported names the protobuf field this build did not understand.
	// Empty for every message it did.
	Unsupported string

	TargetWAID string
	ReplyTo    string

	IsForwarded     bool
	ForwardingScore int32

	Expiration int32
	ViewOnce   bool
	Ephemeral  bool

	Source domain.Source

	ContentKeyID  uint32
	BodySealed    []byte
	RawSealed     []byte
	PayloadSealed []byte
	// ArchiveKey is the archive public key ContentKeyID was sealed to.
	// Ingest sets it. Insert then stores the row only while that content
	// key is stored under that key, and refuses it with
	// ErrArchiveKeyChanged after a reset (contentKeyIsTx, DS49). nil
	// checks nothing.
	ArchiveKey []byte

	// FillsPlaceholder is set when the message was sealed again to the
	// uid a PlaceholderError named. Insert then only fills that
	// placeholder. If no row holds the message any more, it writes
	// nothing and returns ErrPlaceholderGone, so a uid never names a
	// second row (DS51).
	FillsPlaceholder bool

	Media *InsertMedia
}

// InsertResult reports what happened.
type InsertResult struct {
	UID uuid.UUID
	Seq int64
	// Duplicate is true when the message was already stored. History sync
	// redelivers what has been seen, and the event stream is at-least-once, so
	// this is the common case rather than an error.
	Duplicate bool
	// TargetRel is what the control row's target turned out to be. Resolved
	// here, once, and stored.
	TargetRel domain.TargetRel

	// CountsUnread is whether this row belongs in a chat badge, and Unread the
	// chat's count after it landed.
	//
	// Both come back from the write rather than from a query after it. A read
	// afterwards would be a second transaction seeing a number that a
	// concurrent insert had already moved, and the value is pushed straight to
	// connected clients — so "the count as of this message" has to be the count
	// this statement produced.
	CountsUnread bool
	Unread       int32

	// Filled is true when the message filled an empty placeholder
	// (fillStub). The row keeps the placeholder's uid and sequence, so
	// Duplicate is true too, and now holds this message and its
	// attachment.
	Filled bool
}

// PlaceholderError is Insert's answer to a message that would fill an
// empty placeholder (fillStub) but was sealed to another uid. The row
// keeps the placeholder's uid, and a sealed value opens only under the
// uid it was sealed to. Nothing was written. The caller seals the
// message again to UID and inserts it again (DS51).
type PlaceholderError struct{ UID uuid.UUID }

func (e *PlaceholderError) Error() string {
	return fmt.Sprintf("store: the message fills placeholder %s and must be sealed to its uid", e.UID)
}

// ErrPlaceholderGone is Insert's answer to a message sealed to a
// placeholder's uid (InsertMessage.FillsPlaceholder) when no row holds the
// message any more: a purge or an erasure deleted the placeholder in
// between. Nothing was written. The caller seals the message to a fresh
// uid and inserts it again (DS51).
var ErrPlaceholderGone = errors.New("store: the placeholder this message was sealed for is gone")

// Insert stores one message and everything that follows from it, atomically.
//
// One transaction covers the sequence allocation, the row, its media, the chat
// projection and the journal entry. A partial write would leave a message a
// client can never be told about, or a cursor pointing at nothing.
func (m *Messages) Insert(ctx context.Context, in InsertMessage) (InsertResult, error) {
	var res InsertResult
	err := pg.InTenantTx(ctx, m.pool, in.TenantID.String(), func(tx pgx.Tx) error {
		// Idempotency first, and cheaply: history sync redelivers in bulk, so
		// the duplicate path is hot. Checking before allocating a sequence
		// number also stops a backfill of known messages from tearing a
		// tenant's cursor forward by thousands.
		//
		// A direct conversation may be stored under both its LID and its
		// phone number (siblings.go), and a history sync after a relink sends
		// it again under either: the same wa_id under a sibling key is the
		// same message. Groups never fold.
		keys, err := chatKeys(ctx, tx, in)
		if err != nil {
			return err
		}
		var existingUID uuid.UUID
		var existingSeq int64
		var existingRel *string
		var existingKey string
		err = tx.QueryRow(ctx, `
			SELECT uid, seq, target_rel, chat_key FROM messages
			 WHERE device_id = $1 AND chat_key = ANY($2) AND wa_id = $3
			 ORDER BY chat_key = $4 DESC LIMIT 1`,
			in.DeviceID, keys, in.WAID, in.ChatKey).Scan(&existingUID, &existingSeq, &existingRel, &existingKey)
		switch {
		case err == nil:
			res = InsertResult{UID: existingUID, Seq: existingSeq, Duplicate: true}
			if existingRel != nil {
				res.TargetRel = domain.TargetRel(*existingRel)
			}
			if existingKey != in.ChatKey {
				// A copy under the conversation's other key: nothing more.
				return nil
			}
			// Unless what is already there is an empty placeholder and this is
			// the real message. That happens because a group message carrying a
			// Signal sender key used to arrive twice under one id, the key
			// first, and the key took the row.
			return fillStub(ctx, tx, in, existingUID, &res)
		case !errors.Is(err, pgx.ErrNoRows):
			return fmt.Errorf("store: check for an existing message: %w", err)
		}
		if in.FillsPlaceholder {
			// Sealed to a placeholder's uid, and the placeholder is gone. A
			// new row under that uid would give a deleted row's uid to
			// another row.
			return ErrPlaceholderGone
		}

		rel, targetUID, err := resolveTarget(ctx, tx, in, keys)
		if err != nil {
			return err
		}
		res.TargetRel = rel

		seq, err := nextSeq(ctx, tx, in.TenantID)
		if err != nil {
			return err
		}
		res.Seq = seq
		// After nextSeq, which holds the workspace's row: a reset is
		// wholly before this or wholly after the commit.
		if err := contentKeyIsTx(ctx, tx, in.DeviceID, in.ContentKeyID, in.ArchiveKey); err != nil {
			return err
		}

		if err := insertMessageRow(ctx, tx, in, seq, rel, targetUID, &res); err != nil {
			return err
		}
		if res.Duplicate {
			// Lost a race with a concurrent insert of the same message. The
			// unique constraint held, which is what it is for.
			return nil
		}
		if in.Media != nil {
			if err := insertMediaRow(ctx, tx, in, res.UID); err != nil {
				return err
			}
		}
		if err := upsertChat(ctx, tx, in, seq, &res); err != nil {
			return err
		}
		return insertEvent(ctx, tx, in, seq, res.UID)
	})
	if err != nil {
		return InsertResult{}, err
	}
	return res, nil
}

// chatKeys is the message's own chat key, then the other keys its
// conversation may be stored under: the probe keys the pipeline found, and
// when it found none for a conversation keyed by phone number, every chat of
// the device with that phone number (the rare case where whatsmeow's map
// does not know the LID). A group has its own key only.
func chatKeys(ctx context.Context, tx pgx.Tx, in InsertMessage) ([]string, error) {
	keys := []string{in.ChatKey}
	if in.IsGroup {
		return keys, nil
	}
	for _, k := range in.ProbeKeys {
		if k != "" && !slices.Contains(keys, k) {
			keys = append(keys, k)
		}
	}
	if len(keys) > 1 || in.ChatPN == "" || in.ChatKey != in.ChatPN || !strings.HasSuffix(in.ChatPN, "@s.whatsapp.net") {
		return keys, nil
	}
	rows, err := tx.Query(ctx, `SELECT chat_key FROM chats
		WHERE device_id = $1 AND chat_pn = $2 AND NOT is_group AND chat_key <> $3`, in.DeviceID, in.ChatPN, in.ChatKey)
	if err != nil {
		return nil, fmt.Errorf("store: sibling chat keys: %w", err)
	}
	siblings, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("store: sibling chat keys: %w", err)
	}
	return append(keys, siblings...), nil
}

// nextSeq allocates the tenant's next cursor value.
//
// UPDATE ... RETURNING serialises concurrent inserts for one tenant, which is
// exactly what a monotonic counter requires. It is the one point of contention
// per tenant, and it is cheap: a single row update on a primary key.
//
// The serialisation carries a second property that the replay handover in
// internal/bus depends on, and that is worth stating because it is not
// obvious: this UPDATE takes a row lock held until commit, so a transaction
// cannot allocate a sequence until the previous holder has committed.
// Allocation order therefore equals commit order, which means a reader that
// can see sequence N can also see every sequence below it.
//
// Without that, a client resuming would lose messages. A history read that saw
// N but not N-1 would set its watermark at N, and N-1 — published moments later
// by a transaction that committed out of order — would be discarded as already
// covered. Replacing this with a Postgres sequence, which allocates without
// blocking and therefore commits out of order, would reintroduce exactly that.
func nextSeq(ctx context.Context, tx pgx.Tx, tenant uuid.UUID) (int64, error) {
	var seq int64
	if err := tx.QueryRow(ctx,
		`UPDATE tenants SET last_seq = last_seq + 1 WHERE id = $1 RETURNING last_seq`,
		tenant).Scan(&seq); err != nil {
		return 0, fmt.Errorf("store: allocate sequence: %w", err)
	}
	return seq, nil
}

// resolveTarget decides what a control row acts on.
//
// This is the question v1 answered at render time, in two places that
// disagreed. Removing a reaction produces a delete whose target is the
// reaction, not the message; a reader that cannot tell the difference shows a
// deleted message where a withdrawn reaction belongs. Answering it once, here,
// and storing the answer means no reader ever has to work it out.
//
// An unresolvable target is not an error. Messages arrive out of order — a
// reaction can land before the message it reacts to, especially during a
// backfill — so the row is stored with the target unresolved and reconciled
// when the other half arrives.
//
// The target is looked for under the conversation's sibling keys too,
// preferring its own: a reaction filed under the LID finds a message filed
// under the phone number.
func resolveTarget(ctx context.Context, tx pgx.Tx, in InsertMessage, keys []string) (domain.TargetRel, *uuid.UUID, error) {
	if in.TargetWAID == "" {
		return domain.TargetNone, nil, nil
	}

	var uid uuid.UUID
	var kind string
	err := tx.QueryRow(ctx, `
		SELECT uid, kind FROM messages
		 WHERE device_id = $1 AND chat_key = ANY($2) AND wa_id = $3
		 ORDER BY chat_key = $4 DESC LIMIT 1`,
		in.DeviceID, keys, in.TargetWAID, in.ChatKey).Scan(&uid, &kind)
	if errors.Is(err, pgx.ErrNoRows) {
		// Target not seen yet. For a reaction the relation is known from the
		// message type regardless; for a delete it genuinely depends on what
		// the target is, so it stays open.
		if in.Kind == domain.KindReaction {
			return domain.TargetMessage, nil, nil
		}
		return domain.TargetNone, nil, nil
	}
	if err != nil {
		return domain.TargetNone, nil, fmt.Errorf("store: resolve target: %w", err)
	}

	if domain.Kind(kind) == domain.KindReaction {
		return domain.TargetReaction, &uid, nil
	}
	return domain.TargetMessage, &uid, nil
}

func insertMessageRow(ctx context.Context, tx pgx.Tx, in InsertMessage, seq int64,
	rel domain.TargetRel, targetUID *uuid.UUID, res *InsertResult) error {
	var relArg *string
	if rel != domain.TargetNone {
		s := string(rel)
		relArg = &s
	}

	err := tx.QueryRow(ctx, `
		INSERT INTO messages (
			uid, tenant_id, device_id, seq, wa_id, chat_key,
			sender_key, sender_lid, sender_pn, ts, is_from_me, is_group,
			kind, type, target_wa_id, target_uid, target_rel, reply_to,
			is_forwarded, forwarding_score, expiration, expires_at,
			view_once, ephemeral, source,
			content_key_id, body_sealed, raw_sealed, payload_sealed,
			unsupported_field)
		VALUES ($1,$2,$3,$4,$5,$6,
		        $7,$8,$9,$10,$11,$12,
		        $13,$14,$15,$16,$17,$18,
		        $19,$20,$21,$22,
		        $23,$24,$25,
		        $26,$27,$28,$29,
		        $30)
		ON CONFLICT (device_id, chat_key, wa_id) DO NOTHING
		RETURNING uid, counts_unread`,
		in.UID, in.TenantID, in.DeviceID, seq, in.WAID, in.ChatKey,
		nullable(in.SenderKey), nullable(in.SenderLID), nullable(in.SenderPN),
		nullableTime(in.TS), in.IsFromMe, in.IsGroup,
		string(in.Kind), string(in.Type), nullable(in.TargetWAID), targetUID, relArg,
		nullable(in.ReplyTo),
		in.IsForwarded, in.ForwardingScore, in.Expiration, expiresAt(in),
		in.ViewOnce, in.Ephemeral, string(in.Source),
		nullableKeyID(in.ContentKeyID), in.BodySealed, in.RawSealed, in.PayloadSealed,
		nullable(in.Unsupported),
	).Scan(&res.UID, &res.CountsUnread)

	if errors.Is(err, pgx.ErrNoRows) {
		res.Duplicate = true
		if err := tx.QueryRow(ctx, `
			SELECT uid, seq FROM messages
			 WHERE device_id = $1 AND chat_key = $2 AND wa_id = $3`,
			in.DeviceID, in.ChatKey, in.WAID).Scan(&res.UID, &res.Seq); err != nil {
			return err
		}
		return fillStub(ctx, tx, in, res.UID, res)
	}
	if err != nil {
		return fmt.Errorf("store: insert message: %w", err)
	}
	return nil
}

// fillStub replaces an empty placeholder with the real message.
//
// It exists because of one specific accident. A group message that also carried
// a Signal sender key was dispatched twice under the same message id: the key
// arrived first, was classified as "unsupported", and took the row -- so the
// real message that followed was rejected here as a duplicate of a stub. 661
// group messages on one installation were replaced by empty rows that way.
//
// The classifier no longer stores those keys, but the stubs are already
// written, and while they hold the (device, chat, wa_id) slot no history sync
// can ever put the real message back. So a row that carries nothing gives way
// to one that carries something.
//
// Narrow on purpose. It only fires when the stored row is an empty placeholder
// from the same sender (fillable), and only for an incoming row that actually
// has content. A real message is never overwritten by anything, including
// another copy of itself.
//
// The row keeps the placeholder's uid, and every sealed value binds to the
// uid it was sealed to. So the message must be sealed to the placeholder's
// uid. One sealed to another uid fills nothing: it gets a PlaceholderError,
// and the caller seals it again (DS51). The attachment's row and the chat
// list's type are written with the fill.
func fillStub(ctx context.Context, tx pgx.Tx, in InsertMessage, uid uuid.UUID, res *InsertResult) error {
	if in.Type == domain.TypeUnsupported || in.Kind != domain.KindMessage {
		return nil
	}
	if len(in.BodySealed) == 0 && len(in.PayloadSealed) == 0 && in.Media == nil {
		return nil
	}
	guard := []any{uid, in.IsFromMe, nullable(in.SenderKey), nullable(in.SenderLID), nullable(in.SenderPN)}

	if in.UID != uid {
		var stub bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM messages WHERE uid = $1 AND `+fillable+`)`,
			guard...).Scan(&stub); err != nil {
			return fmt.Errorf("store: check placeholder: %w", err)
		}
		if stub {
			return &PlaceholderError{UID: uid}
		}
		return nil
	}

	// The update's statement trigger (storage_lock) takes the workspace's
	// row before the update locks the message's, the same order as Insert.
	tag, err := tx.Exec(ctx, `
		UPDATE messages SET
			kind = $6, type = $7, unsupported_field = NULL,
			content_key_id = $8, body_sealed = $9, raw_sealed = $10, payload_sealed = $11,
			reply_to = $12, is_forwarded = $13, forwarding_score = $14,
			view_once = $15, ephemeral = $16
		 WHERE uid = $1 AND `+fillable,
		append(guard, string(in.Kind), string(in.Type),
			nullableKeyID(in.ContentKeyID), in.BodySealed, in.RawSealed, in.PayloadSealed,
			nullable(in.ReplyTo), in.IsForwarded, in.ForwardingScore,
			in.ViewOnce, in.Ephemeral)...)
	if err != nil {
		return fmt.Errorf("store: fill placeholder: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil
	}
	// The transaction holds the workspace's row; it rolls back unless the
	// content key is still there.
	if err := contentKeyIsTx(ctx, tx, in.DeviceID, in.ContentKeyID, in.ArchiveKey); err != nil {
		return err
	}
	if in.Media != nil {
		// The placeholder had none: the update's guard says so.
		if err := insertMediaRow(ctx, tx, in, uid); err != nil {
			return err
		}
	}
	// The chat list says "unsupported" while the placeholder is its newest
	// message. Newest by timestamp, as upsertChat picks it. MarkProtocol
	// leaves last_type alone, so a protocol placeholder shows as
	// "unsupported" there too.
	if _, err := tx.Exec(ctx, `
		UPDATE chats SET last_type = $3
		 WHERE device_id = $1 AND chat_key = $2 AND last_type = 'unsupported'
		   AND last_ts IS NOT DISTINCT FROM (SELECT ts FROM messages WHERE uid = $4)`,
		in.DeviceID, in.ChatKey, string(in.Type), uid); err != nil {
		return fmt.Errorf("store: fill placeholder's chat: %w", err)
	}
	res.Filled = true
	return nil
}

// fillable is the WHERE clause of a row fillStub may fill. One text for
// the check and the update. $1 is the row's uid, $2 the message's
// is_from_me, and $3, $4 and $5 its sender's key, LID and phone number.
//
// An empty placeholder: unsupported, or retyped protocol by MarkProtocol
// (the browser's reproject does that to a sender key's placeholder, the
// very row this exists for), with no body, no payload and no attachment.
// Length rather than IS NULL: an empty bytea and a null both mean
// "carries nothing", and which one was written depends on the driver
// rather than on anything meaningful.
//
// From the same sender. A fill used to read as tampered, so another
// sender's content in the row showed as broken. Now it opens cleanly, so
// the row must not take content from anyone but its sender. is_from_me
// must agree: a contact reusing the id of my message does not fill it.
// For my own messages that is enough, since only my devices send them,
// and their sender is often not stored. Anyone else must match on a
// half both sides know (key, LID or phone number). A null half matches
// nothing, so someone else's placeholder with no sender stored is never
// filled.
const fillable = `type IN ('unsupported', 'protocol')
		   AND coalesce(length(body_sealed), 0) = 0
		   AND coalesce(length(payload_sealed), 0) = 0
		   AND NOT EXISTS (SELECT 1 FROM media WHERE message_uid = $1)
		   AND is_from_me = $2
		   AND (is_from_me
		        OR sender_key IN ($3, $4, $5)
		        OR sender_lid = $4
		        OR sender_pn = $5)`

// expiresAt computes when the sender intended the message to vanish.
//
// Computed here rather than as a generated column: timestamptz arithmetic is
// only STABLE, not IMMUTABLE, so Postgres refuses it in a generated expression.
// The archive keeps the message either way; this records the intent so a reader
// can be told the message was meant to be ephemeral, instead of the archive
// quietly presenting it as an ordinary one.
func expiresAt(in InsertMessage) *time.Time {
	if in.Expiration <= 0 || in.TS.IsZero() {
		return nil
	}
	t := in.TS.Add(time.Duration(in.Expiration) * time.Second)
	return &t
}

func insertMediaRow(ctx context.Context, tx pgx.Tx, in InsertMessage, uid uuid.UUID) error {
	m := in.Media
	_, err := tx.Exec(ctx, `
		INSERT INTO media (
			message_uid, tenant_id, media_type, mimetype, file_length,
			file_sha256, file_enc_sha256, direct_path, url,
			width, height, seconds, waveform, sidecar, is_gif,
			content_key_id, media_key_sealed, thumb_sealed, filename_sealed)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
		uid, in.TenantID, m.MediaType, m.MimeType, m.FileLength,
		m.FileSHA256, m.FileEncSHA256, nullable(m.DirectPath), nullable(m.URL),
		m.Width, m.Height, m.Seconds, m.Waveform, m.Sidecar, m.IsGIF,
		nullableKeyID(in.ContentKeyID), m.MediaKeySealed, m.ThumbSealed, m.FileNameSealed)
	if err != nil {
		return fmt.Errorf("store: insert media: %w", err)
	}
	return nil
}

// upsertChat maintains the chat list projection.
//
// Written on every message so the sidebar is an index-only scan. v1 computed
// the equivalent with a triple join and two aggregate subqueries on every load,
// over the whole message table.
//
// Control rows advance the projection too — an edit or a reaction is activity —
// but a message arriving out of order during a backfill must not drag the
// "latest" pointer backwards, hence the GREATEST and the conditional update.
// upsertChat projects the newest message onto its conversation, and moves the
// unread badge.
//
// The badge is incremented HERE, inside the same statement and the same
// transaction as the projection, and that placement is the whole guarantee. A
// separate Exec would sit one refactor away from being hoisted above the
// duplicate check at the top of Insert, and a history sync redelivering
// nineteen thousand known messages would then add nineteen thousand to a
// number the phone had just told us was three. As written it is unreachable for
// a duplicate: Insert returns before this on the idempotency path and on the
// lost-race path.
func upsertChat(ctx context.Context, tx pgx.Tx, in InsertMessage, seq int64, res *InsertResult) error {
	unread := 0
	if res.CountsUnread {
		unread = 1
	}
	err := tx.QueryRow(ctx, `
		INSERT INTO chats (tenant_id, device_id, chat_key, chat_lid, chat_pn,
		                   is_group, last_seq, last_ts, last_kind, last_type,
		                   ephemeral_expiration, unread)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT (device_id, chat_key) DO UPDATE SET
			-- Never overwrite a known identifier with nothing: either half may
			-- be absent from any single message.
			chat_lid  = COALESCE(EXCLUDED.chat_lid, chats.chat_lid),
			chat_pn   = COALESCE(EXCLUDED.chat_pn,  chats.chat_pn),
			is_group  = chats.is_group OR EXCLUDED.is_group,
			last_seq  = GREATEST(chats.last_seq, EXCLUDED.last_seq),
			-- "Latest" by when it was sent, not by when it was stored. seq
			-- rises on every insert, so keying these off it meant a backfilled
			-- message from last year overwrote the projection with its own
			-- timestamp and preview -- and the chat list is ordered by exactly
			-- this. GREATEST ignores nulls, which is what a message with no
			-- timestamp should do here: nothing.
			last_ts   = GREATEST(chats.last_ts, EXCLUDED.last_ts),
			last_kind = CASE WHEN chats.last_ts IS NULL OR EXCLUDED.last_ts > chats.last_ts
			                 THEN EXCLUDED.last_kind ELSE chats.last_kind END,
			last_type = CASE WHEN chats.last_ts IS NULL OR EXCLUDED.last_ts > chats.last_ts
			                 THEN EXCLUDED.last_type ELSE chats.last_type END,
			-- Learned from the messages themselves. Every message in a chat
			-- with disappearing messages on carries the timer, which is how a
			-- linked device finds out about a setting changed on the phone.
			--
			-- Only a non-zero value updates it. A message with no expiration
			-- is the ordinary case and says nothing about the setting; letting
			-- it write zero would clear a live timer on the first message that
			-- happened to arrive without one. Turning the timer off goes
			-- through SetChatTimer, which is explicit.
			ephemeral_expiration = CASE WHEN EXCLUDED.ephemeral_expiration > 0
			                            THEN EXCLUDED.ephemeral_expiration
			                            ELSE chats.ephemeral_expiration END,
			-- Above the reader's watermark, or it is not new to them.
			--
			-- Unreachable today and kept deliberately. Sequence allocation
			-- order equals commit order, and every watermark is set from a
			-- sequence that already exists, so nothing Insert writes can land
			-- below one. It costs a comparison and it is the only thing here
			-- that would survive a writer that did not hold that property.
			--
			-- It is NOT what protects the badge from an on-demand backfill.
			-- A backfill arrives as an ON_DEMAND history sync, so its rows are
			-- source='history' and counts_unread is already false for them --
			-- which matters, because a backfilled row is old by timestamp and
			-- NEW by sequence, and a guard on seq alone would let every one of
			-- them through.
			unread = chats.unread + CASE
			             WHEN EXCLUDED.last_seq > chats.read_through_seq
			             THEN EXCLUDED.unread ELSE 0 END
		RETURNING unread`,
		in.TenantID, in.DeviceID, in.ChatKey, nullable(in.ChatLID), nullable(in.ChatPN),
		in.IsGroup, seq, nullableTime(in.TS), string(in.Kind), string(in.Type),
		in.Expiration, unread).Scan(&res.Unread)
	if err != nil {
		return fmt.Errorf("store: upsert chat: %w", err)
	}
	return nil
}

func insertEvent(ctx context.Context, tx pgx.Tx, in InsertMessage, seq int64, uid uuid.UUID) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO events (seq, tenant_id, device_id, kind, chat_key, message_uid)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		seq, in.TenantID, in.DeviceID, string(in.Kind), in.ChatKey, uid)
	if err != nil {
		return fmt.Errorf("store: insert event: %w", err)
	}
	return nil
}

// ResolvePendingTargets links control rows whose target has since arrived.
//
// Messages arrive out of order: a reaction can land before the message it
// reacts to, which is routine during a backfill. Those rows are stored with an
// unresolved target and reconciled here.
func (m *Messages) ResolvePendingTargets(ctx context.Context, tenant, device uuid.UUID, limit int) (int, error) {
	var n int
	err := pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE messages c SET
				target_uid = t.uid,
				target_rel = CASE WHEN t.kind = 'reaction' THEN 'reaction' ELSE 'message' END
			  FROM messages t
			 WHERE c.uid IN (
			     SELECT uid FROM messages
			      WHERE device_id = $1 AND target_wa_id IS NOT NULL AND target_uid IS NULL
			      LIMIT $2)
			   AND t.device_id = c.device_id
			   AND t.chat_key  = c.chat_key
			   AND t.wa_id     = c.target_wa_id`, device, limit)
		if err != nil {
			return fmt.Errorf("store: resolve pending targets: %w", err)
		}
		n = int(tag.RowsAffected())
		return nil
	})
	return n, err
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func nullableTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// nullableKeyID renders a content key id for the column, treating zero as
// absent: a row with no sealed content has no key.
func nullableKeyID(id uint32) *int32 {
	if id == 0 {
		return nil
	}
	col, err := toColumnID(id)
	if err != nil {
		return nil
	}
	return &col
}
