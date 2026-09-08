package store

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/domain"
	"whatserver2/internal/pg"
)

// Row is one archived message as it leaves the server.
//
// The sealed fields travel as opaque bytes. This server cannot open them and
// neither can anything between here and the client, which is the point: the
// wire carries the same ciphertext the disk does.
type Row struct {
	UID uuid.UUID
	Seq int64

	// DeviceID travels with the row. It used to be filled in only on the live
	// delivery path, from the publishing event, which left every replayed and
	// paged message carrying an empty one — so a client grouping by device saw
	// nothing until the next live message arrived.
	DeviceID uuid.UUID

	WAID      string
	ChatKey   string
	SenderKey string
	SenderLID string
	SenderPN  string

	TS       *time.Time
	IsFromMe bool
	IsGroup  bool

	Kind domain.Kind
	Type domain.Type

	TargetWAID string
	TargetUID  *uuid.UUID
	TargetRel  domain.TargetRel
	ReplyTo    string

	IsForwarded     bool
	ForwardingScore int32

	Expiration int32
	// ExpiresAt is when the sender intended the message to vanish. The archive
	// keeps it regardless; this is what lets a reader be told plainly that it
	// was meant to be ephemeral, rather than being shown an ordinary message.
	ExpiresAt *time.Time
	ViewOnce  bool
	Ephemeral bool

	Source domain.Source

	ContentKeyID uint32
	BodySealed   []byte
	RawSealed    []byte
	// PayloadSealed carries the structured content — a location, a poll,
	// contact cards, an event, a link preview, the mention list — as sealed
	// JSON. Empty for an ordinary text message.
	PayloadSealed []byte

	// Unsupported names the protobuf field this build did not understand, for
	// a row whose type is "unsupported". Empty otherwise. Unsealed, like Type.
	Unsupported string

	Media *MediaRow
}

// MediaRow describes an attachment.
type MediaRow struct {
	MediaType     string
	MimeType      string
	FileLength    int64
	FileSHA256    []byte
	FileEncSHA256 []byte
	Width         int32
	Height        int32
	Seconds       int32
	Waveform      []byte
	IsGIF         bool

	MediaKeySealed []byte
	ThumbSealed    []byte
	FileNameSealed []byte

	DownloadStatus string
	ObjectKey      string
}

// ChatRow is one entry in the chat list.
type ChatRow struct {
	// UID is the chat's stable identity, which its sealed name is bound to.
	// Derived, so a client could compute it — but it is sent, so no client has
	// to know the derivation.
	UID     uuid.UUID
	ChatKey string
	ChatLID string
	ChatPN  string
	IsGroup bool
	LastSeq int64
	LastTS  *time.Time
	// CreatedAt is when THIS ARCHIVE wrote the row. The last-resort sort key,
	// and deliberately not the first: six hundred groups found by one boot
	// sync share a single instant, so ordering on it is ordering on nothing.
	CreatedAt time.Time
	// GroupCreatedAt is when the group itself was made, per WhatsApp. It is
	// what orders a conversation nobody has spoken in — a group created
	// yesterday belongs where yesterday belongs.
	GroupCreatedAt *time.Time
	// ParticipantCount is how many people are in the group, including us. The
	// denominator behind "everyone received it". Nil means unknown, and a tick
	// must not be promoted on an unknown denominator.
	ParticipantCount *int32
	// Ephemeral is the disappearing-message timer in seconds. Zero is off.
	Ephemeral int32
	LastKind  string
	LastType  string
	Unread    int32
	Archived  bool
	Pinned    bool

	NameSealed []byte
	NameKeyID  uint32

	// Keys is every conversation folded into this one. Usually just its own.
	//
	// The same contact addressed by phone number for years and by LID since is
	// stored under both, and the rows stay as they are — they record how
	// WhatsApp actually addressed each message. This is the projection that
	// presents them as the one conversation they are.
	Keys []string

	// The newest row in the conversation, for the list preview.
	//
	// Carried here rather than left to the client because the alternative is
	// one request per chat to render a list — five hundred round trips to draw
	// a sidebar. The body is sealed like any other, bound to LastUID, and a
	// deletion or a reaction has none, which is why the kind travels beside it.
	LastUID        uuid.UUID
	LastBodySealed []byte
	LastBodyKeyID  uint32
}

const rowColumns = `
	m.uid, m.seq, m.device_id, m.wa_id, m.chat_key,
	coalesce(m.sender_key,''), coalesce(m.sender_lid,''), coalesce(m.sender_pn,''),
	m.ts, m.is_from_me, m.is_group, m.kind, m.type,
	coalesce(m.target_wa_id,''), m.target_uid, coalesce(m.target_rel,''), coalesce(m.reply_to,''),
	m.is_forwarded, m.forwarding_score, m.expiration, m.expires_at,
	m.view_once, m.ephemeral, m.source,
	coalesce(m.content_key_id,0), m.body_sealed, m.raw_sealed, m.payload_sealed,
	coalesce(m.unsupported_field,''),
	md.media_type, md.mimetype, md.file_length, md.file_sha256, md.file_enc_sha256,
	md.width, md.height, md.seconds, md.waveform, md.is_gif,
	md.media_key_sealed, md.thumb_sealed, md.filename_sealed,
	md.download_status, md.object_key`

func scanRow(rows pgx.Rows) (Row, error) {
	var r Row
	var rel string
	var keyID int32
	// Media columns are null when the message has no attachment, so every one
	// scans into a pointer and the row is assembled only if the type is there.
	var (
		mType, mMime, mStatus, mObject        *string
		mLength                               *int64
		mSHA, mEncSHA, mWaveform              []byte
		mWidth, mHeight, mSeconds             *int32
		mIsGIF                                *bool
		mKeySealed, mThumbSealed, mNameSealed []byte
	)
	if err := rows.Scan(
		&r.UID, &r.Seq, &r.DeviceID, &r.WAID, &r.ChatKey,
		&r.SenderKey, &r.SenderLID, &r.SenderPN,
		&r.TS, &r.IsFromMe, &r.IsGroup, &r.Kind, &r.Type,
		&r.TargetWAID, &r.TargetUID, &rel, &r.ReplyTo,
		&r.IsForwarded, &r.ForwardingScore, &r.Expiration, &r.ExpiresAt,
		&r.ViewOnce, &r.Ephemeral, &r.Source,
		&keyID, &r.BodySealed, &r.RawSealed, &r.PayloadSealed,
		&r.Unsupported,
		&mType, &mMime, &mLength, &mSHA, &mEncSHA,
		&mWidth, &mHeight, &mSeconds, &mWaveform, &mIsGIF,
		&mKeySealed, &mThumbSealed, &mNameSealed,
		&mStatus, &mObject,
	); err != nil {
		return Row{}, err
	}
	r.TargetRel = domain.TargetRel(rel)
	if keyID > 0 {
		r.ContentKeyID = uint32(keyID)
	}
	if mType != nil {
		r.Media = &MediaRow{
			MediaType: *mType, MimeType: deref(mMime), FileLength: derefInt64(mLength),
			FileSHA256: mSHA, FileEncSHA256: mEncSHA,
			Width: derefInt32(mWidth), Height: derefInt32(mHeight), Seconds: derefInt32(mSeconds),
			Waveform: mWaveform, IsGIF: derefBool(mIsGIF),
			MediaKeySealed: mKeySealed, ThumbSealed: mThumbSealed, FileNameSealed: mNameSealed,
			DownloadStatus: deref(mStatus), ObjectKey: deref(mObject),
		}
	}
	return r, nil
}

// Since returns rows after a cursor, in sequence order.
//
// This is the replay read. It is deliberately the same query shape the live
// path's rows come from, so a client cannot tell a replayed message from a live
// one — which is what stops the two paths drifting into different renderings,
// as they did in v1.
func (m *Messages) Since(ctx context.Context, tenant uuid.UUID, sinceSeq int64, limit int) ([]Row, error) {
	var out []Row
	err := pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT `+rowColumns+`
			  FROM messages m LEFT JOIN media md ON md.message_uid = m.uid
			 WHERE m.tenant_id = $1 AND m.seq > $2
			 ORDER BY m.seq
			 LIMIT $3`, tenant, sinceSeq, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanRow(rows)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("store: read since %d: %w", sinceSeq, err)
	}
	return out, nil
}

// Cursor points at one position in a conversation, in display order.
//
// Two fields because one is not enough. WhatsApp timestamps are whole seconds
// and a burst inside one second is ordinary, so a cursor on time alone would
// either skip messages or repeat them at every page boundary. Seq breaks the
// tie and is unique per tenant.
type Cursor struct {
	TS  time.Time
	Seq int64
}

// Before returns the cursor for paging further back from a page.
//
// The oldest row of the page, which is the first one: a page comes back oldest
// first. A row with no timestamp cannot be a cursor -- it would compare as the
// far past and end the paging early -- so this reports the zero cursor, and the
// caller stops rather than silently truncating the conversation.
func Before(rows []Row) Cursor {
	if len(rows) == 0 || rows[0].TS == nil {
		return Cursor{}
	}
	return Cursor{TS: *rows[0].TS, Seq: rows[0].Seq}
}

// Page returns the newest messages in one chat, oldest first within the page.
//
// Ordered by when each message was SENT, with seq only as a tie-break. That
// distinction is the whole point: seq is allocated when a row is written, and
// history sync writes last year's messages with today's numbers -- in reverse,
// because WhatsApp delivers each chunk newest-first. Ordering a conversation by
// seq therefore shows the backfill upside down and drops it wherever it
// happened to land.
//
// A zero cursor means the latest page. Control rows are included: an edit or a
// deletion is part of the history, and hiding them here is what would make the
// archive indistinguishable from an ordinary client.
// Page reads one page of a conversation.
//
// Takes several chat keys, because one conversation can be stored under more
// than one. WhatsApp addressed the same contact by phone number for years and
// by LID since, so a conversation that spans the change lives under both keys —
// and paging only the one the reader clicked would silently hide the other
// half. On the archive this was written against that was 226 messages of 709.
//
// The two-part cursor already does the right thing across keys: ordering is by
// when a message was SENT with the sequence breaking ties, and both are
// properties of the message rather than of the key it was filed under.
func (m *Messages) Page(ctx context.Context, tenant, device uuid.UUID,
	chatKeys []string, before Cursor, limit int) ([]Row, error) {
	if len(chatKeys) == 0 {
		return nil, nil
	}
	// The far future, so the first page needs no separate query. Postgres has
	// 'infinity' for exactly this.
	ts := before.TS
	seq := before.Seq
	latest := ts.IsZero()

	var out []Row
	err := pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT `+rowColumns+`
			  FROM messages m LEFT JOIN media md ON md.message_uid = m.uid
			 WHERE m.device_id = $1 AND m.chat_key = ANY($2::text[])
			   AND ($3::boolean
			        OR (coalesce(m.ts, m.created_at), m.seq) < ($4::timestamptz, $5::bigint))
			 ORDER BY coalesce(m.ts, m.created_at) DESC, m.seq DESC
			 LIMIT $6`, device, chatKeys, latest, ts, seq, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanRow(rows)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("store: page chat %v: %w", chatKeys, err)
	}
	// Reversed here rather than in a wrapping query: the page is bounded by
	// limit, so this is at most a couple of hundred rows, and the alternative
	// is a derived table whose column names collide.
	slices.Reverse(out)
	return out, nil
}

// Get returns one message by uid.
func (m *Messages) Get(ctx context.Context, tenant, uid uuid.UUID) (Row, error) {
	var out Row
	err := pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT `+rowColumns+`
			  FROM messages m LEFT JOIN media md ON md.message_uid = m.uid
			 WHERE m.uid = $1`, uid)
		if err != nil {
			return err
		}
		defer rows.Close()
		if !rows.Next() {
			if err := rows.Err(); err != nil {
				return err
			}
			return pgx.ErrNoRows
		}
		out, err = scanRow(rows)
		return err
	})
	if err != nil {
		return Row{}, fmt.Errorf("store: get message: %w", err)
	}
	return out, nil
}

// Chats returns the chat list for one device, most recent first.
func (m *Messages) Chats(ctx context.Context, tenant, device uuid.UUID, limit int) ([]ChatRow, error) {
	var out []ChatRow
	err := pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT coalesce(c.uid, '00000000-0000-0000-0000-000000000000'::uuid),
			       c.chat_key, coalesce(c.chat_lid,''), coalesce(c.chat_pn,''), c.is_group,
			       c.last_seq, c.last_ts, c.created_at, c.group_created_at,
			       c.participant_count, c.ephemeral_expiration,
			       coalesce(c.last_kind,''), coalesce(c.last_type,''),
			       c.unread, c.archived, c.pinned, c.name_sealed, coalesce(c.name_key_id,0),
			       coalesce(m.uid, '00000000-0000-0000-0000-000000000000'::uuid),
			       m.body_sealed, coalesce(m.content_key_id, 0)
			  FROM chats c
			  -- The newest row of each conversation, for the list preview. A
			  -- lateral rather than a join on last_seq: last_seq is what the
			  -- history sync last reported and can lag a live insert, and a
			  -- preview showing the second-newest message looks like a bug.
			  -- messages_by_chat covers this, so it is an index hit per chat.
			  LEFT JOIN LATERAL (
			      SELECT uid, body_sealed, content_key_id
			        FROM messages
			       WHERE device_id = c.device_id AND chat_key = c.chat_key
			       ORDER BY coalesce(ts, created_at) DESC, seq DESC
			       LIMIT 1
			  ) m ON true
			 WHERE c.device_id = $1
			 -- By when the newest message was sent. Ordering by last_seq put a
			 -- conversation at the top because a backfill had just written some
			 -- of its history, which is not what "recent" means to a reader.
			 -- One key, not two buckets. A group is a conversation from the
			 -- moment the account is in it, and the date that means something
			 -- about it is when it was MADE — so a group created yesterday
			 -- belongs where yesterday belongs, not below every conversation
			 -- last spoken in in 2024. Bucketing them put a group somebody had
			 -- just joined a thousand rows down.
			 --
			 -- created_at is the last resort and is deliberately not folded
			 -- into the coalesce above: it is when THIS ARCHIVE wrote the row,
			 -- which for six hundred groups found by one boot sync is a single
			 -- instant, and promoting that to a sort key would put all of them
			 -- at the top of the sidebar at once.
			 ORDER BY coalesce(c.last_ts, c.group_created_at) DESC NULLS LAST,
			          c.created_at DESC, c.last_seq DESC
			 LIMIT $2`, device, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c ChatRow
			var keyID, lastKeyID int32
			if err := rows.Scan(&c.UID, &c.ChatKey, &c.ChatLID, &c.ChatPN, &c.IsGroup,
				&c.LastSeq, &c.LastTS, &c.CreatedAt, &c.GroupCreatedAt,
				&c.ParticipantCount, &c.Ephemeral, &c.LastKind, &c.LastType,
				&c.Unread, &c.Archived, &c.Pinned, &c.NameSealed, &keyID,
				&c.LastUID, &c.LastBodySealed, &lastKeyID); err != nil {
				return err
			}
			if keyID > 0 {
				c.NameKeyID = uint32(keyID)
			}
			if lastKeyID > 0 {
				c.LastBodyKeyID = uint32(lastKeyID)
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("store: list chats: %w", err)
	}
	// Folded after reading, not in SQL. The rule is "same person", and the
	// pieces it needs — a known half never replaced by an empty one, a sealed
	// name staying with the row its uid belongs to — are the same rules the
	// rest of this package states in Go. A window function would state them a
	// second time, in another language, where the two could drift.
	return foldChats(out), nil
}

// MaxSeq returns the tenant's current cursor high-water mark.
//
// Read before the replay handover: it is the watermark passed to EndReplay, and
// it is safe to use because sequences are allocated under a row lock held to
// commit, so anything below it is already visible. See nextSeq.
func (m *Messages) MaxSeq(ctx context.Context, tenant uuid.UUID) (int64, error) {
	var seq int64
	err := pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT last_seq FROM tenants WHERE id = $1`, tenant).Scan(&seq)
	})
	if err != nil {
		return 0, fmt.Errorf("store: read cursor: %w", err)
	}
	return seq, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func derefInt64(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}

func derefInt32(v *int32) int32 {
	if v == nil {
		return 0
	}
	return *v
}

func derefBool(v *bool) bool {
	if v == nil {
		return false
	}
	return *v
}

// ChatTimer returns a chat's disappearing-message timer in seconds, zero when
// off.
//
// WhatsApp has no per-message expiry: disappearing messages are a property of
// the conversation, and every message sent into one carries the timer so that
// clients agree about it. So an outbound message needs to know the chat's
// setting, and this is where it comes from.
//
// Read across the whole conversation, not one row, and that is the fix for a
// message that went out permanent into a disappearing chat. One person can hold
// two chat rows — a LID one and a phone-number one — and the sidebar advertises
// whichever of them carries the name. Live traffic lands on whichever half
// WhatsApp addressed, so the timer can be learned on the row that is NOT the
// advertised one; a single-row read by the advertised key then answers zero,
// the envelope is skipped, and the composer has meanwhile been promising the
// reader "como a conversa: 24 horas".
//
// max() rather than a preference between the rows, because the two states a
// row can be in are "no timer" and "this timer", and any row that knows one
// knows the conversation's. Turning the timer off writes zero to every sibling
// (see SetChatTimer), so max() answers zero then too — which is the case a
// first-non-zero rule would get wrong.
func (m *Messages) ChatTimer(ctx context.Context, tenant, device uuid.UUID, chatKey string) (int32, error) {
	var seconds int32
	err := pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			SELECT coalesce(max(c.ephemeral_expiration), 0) FROM chats c
			 WHERE c.device_id = $1
			   AND (c.chat_key = $2 OR (
			         NOT c.is_group AND c.chat_pn IS NOT NULL
			         AND c.chat_pn = (SELECT chat_pn FROM chats
			                           WHERE device_id = $1 AND chat_key = $2
			                             AND NOT is_group)))`,
			device, chatKey).Scan(&seconds)
		// No ErrNoRows branch: an aggregate over no rows still returns a row,
		// and coalesce turns its NULL into zero. A chat nothing has been
		// received in yet therefore answers "no timer known", which is not the
		// same as knowing there is none — but it is the only honest answer
		// available, and it is what the caller has always got.
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("store: read chat timer: %w", err)
	}
	return seconds, nil
}

// SetChatTimer records a disappearing-message timer, including turning it off.
//
// Called after WhatsApp has accepted the change, so the row reflects what the
// other side will actually do rather than what was asked for.
//
// Written to every row this conversation is spread across, which is the point.
// A person can hold a LID row and a phone-number row; the timer is one fact
// about one conversation, and storing it on only the row the caller happened to
// name leaves the other half disagreeing. The sidebar folds the two and takes
// the first non-zero, so a timer turned OFF on one row is resurrected from the
// other and the setting appears to revert on its own — which is exactly what it
// looked like from outside.
func (m *Messages) SetChatTimer(ctx context.Context, tenant, device uuid.UUID,
	chatKey string, seconds int32) error {
	keys, err := m.SiblingKeys(ctx, tenant, device, chatKey)
	if err != nil {
		// Not fatal. A conversation with no siblings is the common case, and
		// failing to look for them is not a reason to refuse to record a
		// setting WhatsApp has already accepted.
		keys = []string{chatKey}
	}
	err = pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		for _, key := range keys {
			// Insert only for the key the caller named. A sibling that does
			// not exist is not a conversation this timer belongs to, and
			// creating a row for it would invent one.
			if key != chatKey {
				if _, err := tx.Exec(ctx, `
					UPDATE chats SET ephemeral_expiration = $3
					 WHERE device_id = $1 AND chat_key = $2`,
					device, key, seconds); err != nil {
					return err
				}
				continue
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO chats (tenant_id, device_id, chat_key, ephemeral_expiration)
				VALUES ($1,$2,$3,$4)
				ON CONFLICT (device_id, chat_key)
				DO UPDATE SET ephemeral_expiration = EXCLUDED.ephemeral_expiration`,
				tenant, device, key, seconds); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("store: set chat timer: %w", err)
	}
	return nil
}

// Oldest returns the earliest message stored in one chat.
//
// The anchor for an on-demand backfill: WhatsApp is asked for what came before
// a message it can identify, so the request needs the oldest one already held
// rather than the newest. Ordering is by sequence, not timestamp — a phone with
// a wrong clock would otherwise nominate an anchor from the middle of the
// conversation and the answer would repeat what is already stored.
func (m *Messages) Oldest(ctx context.Context, tenant, device uuid.UUID, chatKey string) (Row, error) {
	var out Row
	err := pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT `+rowColumns+`
			  FROM messages m LEFT JOIN media md ON md.message_uid = m.uid
			 WHERE m.device_id = $1 AND m.chat_key = $2
			 ORDER BY m.seq
			 LIMIT 1`, device, chatKey)
		if err != nil {
			return err
		}
		defer rows.Close()
		if !rows.Next() {
			if err := rows.Err(); err != nil {
				return err
			}
			return pgx.ErrNoRows
		}
		out, err = scanRow(rows)
		return err
	})
	if err != nil {
		return Row{}, fmt.Errorf("store: oldest message in %s: %w", chatKey, err)
	}
	return out, nil
}
