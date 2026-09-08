package store

import (
	"context"
	"errors"
	"fmt"
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
}

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
		var existingUID uuid.UUID
		var existingSeq int64
		var existingRel *string
		err := tx.QueryRow(ctx, `
			SELECT uid, seq, target_rel FROM messages
			 WHERE device_id = $1 AND chat_key = $2 AND wa_id = $3`,
			in.DeviceID, in.ChatKey, in.WAID).Scan(&existingUID, &existingSeq, &existingRel)
		switch {
		case err == nil:
			res = InsertResult{UID: existingUID, Seq: existingSeq, Duplicate: true}
			if existingRel != nil {
				res.TargetRel = domain.TargetRel(*existingRel)
			}
			// Unless what is already there is an empty placeholder and this is
			// the real message. That happens because a group message carrying a
			// Signal sender key used to arrive twice under one id, the key
			// first, and the key took the row.
			return fillStub(ctx, tx, in, existingUID)
		case !errors.Is(err, pgx.ErrNoRows):
			return fmt.Errorf("store: check for an existing message: %w", err)
		}

		rel, targetUID, err := resolveTarget(ctx, tx, in)
		if err != nil {
			return err
		}
		res.TargetRel = rel

		seq, err := nextSeq(ctx, tx, in.TenantID)
		if err != nil {
			return err
		}
		res.Seq = seq

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
func resolveTarget(ctx context.Context, tx pgx.Tx, in InsertMessage) (domain.TargetRel, *uuid.UUID, error) {
	if in.TargetWAID == "" {
		return domain.TargetNone, nil, nil
	}

	var uid uuid.UUID
	var kind string
	err := tx.QueryRow(ctx, `
		SELECT uid, kind FROM messages
		 WHERE device_id = $1 AND chat_key = $2 AND wa_id = $3`,
		in.DeviceID, in.ChatKey, in.TargetWAID).Scan(&uid, &kind)
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
		return fillStub(ctx, tx, in, res.UID)
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
// Narrow on purpose. It only fires when the stored row is an unsupported
// placeholder with no body, no payload and no attachment, and only for an
// incoming row that actually has content. A real message is never overwritten
// by anything, including another copy of itself.
func fillStub(ctx context.Context, tx pgx.Tx, in InsertMessage, uid uuid.UUID) error {
	if in.Type == domain.TypeUnsupported || in.Kind != domain.KindMessage {
		return nil
	}
	if len(in.BodySealed) == 0 && len(in.PayloadSealed) == 0 && in.Media == nil {
		return nil
	}

	_, err := tx.Exec(ctx, `
		UPDATE messages SET
			kind = $2, type = $3, unsupported_field = NULL,
			content_key_id = $4, body_sealed = $5, raw_sealed = $6, payload_sealed = $7,
			reply_to = $8, is_forwarded = $9, forwarding_score = $10,
			view_once = $11, ephemeral = $12
		 WHERE uid = $1
		   AND type = 'unsupported'
		   -- Length rather than IS NULL: an empty bytea and a null both mean
		   -- "carries nothing", and which one was written depends on the
		   -- driver rather than on anything meaningful.
		   AND coalesce(length(body_sealed), 0) = 0
		   AND coalesce(length(payload_sealed), 0) = 0
		   AND NOT EXISTS (SELECT 1 FROM media WHERE message_uid = $1)`,
		uid, string(in.Kind), string(in.Type),
		nullableKeyID(in.ContentKeyID), in.BodySealed, in.RawSealed, in.PayloadSealed,
		nullable(in.ReplyTo), in.IsForwarded, in.ForwardingScore,
		in.ViewOnce, in.Ephemeral)
	if err != nil {
		return fmt.Errorf("store: fill placeholder: %w", err)
	}
	return nil
}

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
