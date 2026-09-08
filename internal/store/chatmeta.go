package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/pg"
)

// chatNamespace is the uuid namespace chat identities are derived in.
//
// An arbitrary but fixed uuid. It only has to be distinct from any other
// namespace this project derives identities in, so that two different kinds of
// thing cannot collide onto the same identifier.
var chatNamespace = uuid.MustParse("6f0e4c9a-2b7d-4f31-9a55-8f4e6d2c1b03")

// ChatUID is a chat's stable identity.
//
// Sealed values are bound to the row they belong to, so a chat's name needs an
// identifier to bind to. Deriving it from the device and the chat key rather
// than generating one means both sides can compute it without asking, and it
// survives a re-import unchanged. It is predictable, which is fine: associated
// data is a binding, not a secret. What it prevents is a sealed name opening
// against a different chat.
func ChatUID(device uuid.UUID, chatKey string) uuid.UUID {
	return uuid.NewSHA1(chatNamespace, append([]byte(device.String()+"\x00"), chatKey...))
}

// ChatMeta is what a history sync knows about a conversation beyond its
// messages.
//
// Every field is optional. A sync chunk may describe a chat without repeating
// everything about it, and a zero here means "not stated" rather than "zero",
// which is why they are pointers.
type ChatMeta struct {
	TenantID uuid.UUID
	DeviceID uuid.UUID
	ChatKey  string
	ChatLID  string
	ChatPN   string
	IsGroup  bool

	// NameSealed is the display name. Sealed: for a direct chat it is a
	// person's name, which is content rather than routing.
	NameSealed []byte
	NameKeyID  uint32

	EphemeralExpiration *int32
	Unread              *int32
	Archived            *bool
	Pinned              *bool
	MuteUntil           *time.Time

	// GroupCreatedAt is when the group itself was made, per WhatsApp. Distinct
	// from created_at, which is when this archive first recorded the row — for
	// six hundred groups found by one boot sync that is a single instant, and
	// ordering on it is ordering on nothing.
	GroupCreatedAt *time.Time
	// ParticipantCount is how many people are in the group, including us. The
	// denominator behind "everyone received it".
	ParticipantCount *int32
}

// UpsertChatMeta records what a history sync said about a conversation.
//
// Nothing known is overwritten with nothing. A later chunk that mentions a chat
// in passing must not erase a name an earlier one carried, which is the same
// rule the identifier columns already follow.
func (m *Messages) UpsertChatMeta(ctx context.Context, meta ChatMeta) error {
	err := pg.InTenantTx(ctx, m.pool, meta.TenantID.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO chats (tenant_id, device_id, chat_key, uid, chat_lid, chat_pn,
			                   is_group, name_sealed, name_key_id,
			                   ephemeral_expiration, unread, archived, pinned, muted_until,
			                   group_created_at, participant_count)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,
			        coalesce($10, 0), coalesce($11, 0),
			        coalesce($12, false), coalesce($13, false), $14, $15, $16)
			ON CONFLICT (device_id, chat_key) DO UPDATE SET
				uid       = COALESCE(chats.uid, EXCLUDED.uid),
				chat_lid  = COALESCE(EXCLUDED.chat_lid, chats.chat_lid),
				chat_pn   = COALESCE(EXCLUDED.chat_pn,  chats.chat_pn),
				is_group  = chats.is_group OR EXCLUDED.is_group,
				name_sealed = COALESCE(EXCLUDED.name_sealed, chats.name_sealed),
				name_key_id = COALESCE(EXCLUDED.name_key_id, chats.name_key_id),
				ephemeral_expiration = COALESCE($10, chats.ephemeral_expiration),
				unread      = COALESCE($11, chats.unread),
				archived    = COALESCE($12, chats.archived),
				pinned      = COALESCE($13, chats.pinned),
				muted_until = COALESCE($14, chats.muted_until),
				-- Never replaced once known. WhatsApp answers with the group's
				-- creation time only when it feels like it, and a pass that
				-- came back without one must not blank the ordering key of
				-- every quiet conversation.
				group_created_at = COALESCE(EXCLUDED.group_created_at, chats.group_created_at),
				-- Never replaced by nothing. A pass that could not ask leaves
				-- the last known count, because a tick with no denominator
				-- cannot be promoted at all — losing it would un-tick every
				-- message in the group.
				participant_count = COALESCE(EXCLUDED.participant_count, chats.participant_count)`,
			meta.TenantID, meta.DeviceID, meta.ChatKey,
			ChatUID(meta.DeviceID, meta.ChatKey),
			nullable(meta.ChatLID), nullable(meta.ChatPN), meta.IsGroup,
			meta.NameSealed, nullableKeyID(meta.NameKeyID),
			meta.EphemeralExpiration, meta.Unread, meta.Archived, meta.Pinned,
			meta.MuteUntil, meta.GroupCreatedAt, meta.ParticipantCount)
		return err
	})
	if err != nil {
		return fmt.Errorf("store: upsert chat metadata: %w", err)
	}
	return nil
}

// BackfillChatUIDs gives an identity to chats created before there was one.
//
// Runs once at boot and is a no-op afterwards. Doing it in a migration would
// have meant reimplementing the derivation in SQL, where a mismatch with the Go
// version would be silent and would only surface as names that will not open.
func (m *Messages) BackfillChatUIDs(ctx context.Context, tenant uuid.UUID) (int, error) {
	var n int
	err := pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT device_id, chat_key FROM chats WHERE uid IS NULL`)
		if err != nil {
			return err
		}
		type ref struct {
			device uuid.UUID
			key    string
		}
		var pending []ref
		for rows.Next() {
			var r ref
			if err := rows.Scan(&r.device, &r.key); err != nil {
				rows.Close()
				return err
			}
			pending = append(pending, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		for _, r := range pending {
			if _, err := tx.Exec(ctx,
				`UPDATE chats SET uid = $3 WHERE device_id = $1 AND chat_key = $2`,
				r.device, r.key, ChatUID(r.device, r.key)); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("store: backfill chat identities: %w", err)
	}
	return n, nil
}
