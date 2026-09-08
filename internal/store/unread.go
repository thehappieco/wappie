package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/pg"
)

// Unread moves the read watermark and recounts the badge behind it.
//
// A watermark rather than a counter, and that is the whole design. Three
// independent things clear a badge — an explicit mark from a reader, a read
// receipt arriving from one of our own other devices, and an app-state event
// the phone replays — and none of them knows what the others have already done.
// Decrementing a counter would need exactly that knowledge: the same fact
// arriving twice would subtract twice. Moving a position forward is idempotent
// by construction, and a position that has already passed moves nothing.
type Unread struct{ pool *pgxpool.Pool }

// NewUnread returns the badge store.
func NewUnread(pool *pgxpool.Pool) *Unread { return &Unread{pool: pool} }

// lockChats takes a row lock on the conversations about to be recounted.
//
// A separate statement, before the update, and the separation is load-bearing.
// Under READ COMMITTED an UPDATE that blocks on a row lock re-evaluates its SET
// expressions against the new row version — but a subquery inside them keeps
// the ORIGINAL statement snapshot. So the recount would not see a message that
// committed while this statement was waiting, and would write a count that was
// already stale at the moment it was written. Worse, it is permanent: the next
// arrival increments from the wrong base. Locking first means the UPDATE that
// follows takes a fresh snapshot with the lock already held.
func lockChats(ctx context.Context, tx pgx.Tx, device uuid.UUID, chatKeys []string) error {
	if len(chatKeys) == 0 {
		return nil
	}
	_, err := tx.Exec(ctx, `
		SELECT 1 FROM chats
		 WHERE device_id = $1 AND chat_key = ANY($2::text[])
		 ORDER BY chat_key
		 FOR UPDATE`, device, chatKeys)
	return err
}

// recount sets a chat's badge to what is actually above the watermark.
//
// Counted rather than adjusted, for the same reason the watermark exists: a
// count derived from the rows is right however many times it runs, and however
// many of the three clearing paths have already run.
const recount = `
	UPDATE chats SET
		read_through_seq = GREATEST(read_through_seq, $3),
		unread = (
			SELECT count(*) FROM messages
			 WHERE device_id = chats.device_id
			   AND chat_key = chats.chat_key
			   AND counts_unread
			   AND seq > GREATEST(chats.read_through_seq, $3))
	 WHERE device_id = $1 AND chat_key = $2`

// MarkReadThrough clears everything at or below the newest of these messages.
//
// The conversation is found FROM THE IDS, never from a chat key the caller
// supplied. That is the same rule receipts follow, and for the same reason it
// was written down: a message sent to a phone number is stored under
// 5511999999999@s.whatsapp.net and its receipt comes back addressed
// 224437861388494@lid. Same conversation, same id, two different chat keys.
//
// By position, not by set: reading a message clears everything under it. That
// is what WhatsApp does, and it is what makes the badge mean "how much is left
// at the end of this conversation" rather than "how many individual rows remain
// unticked".
func (u *Unread) MarkReadThrough(ctx context.Context, tenant, device uuid.UUID,
	waIDs []string) error {
	if len(waIDs) == 0 {
		return nil
	}
	err := pg.InTenantTx(ctx, u.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT chat_key, max(seq) FROM messages
			 WHERE device_id = $1 AND wa_id = ANY($2::text[])
			 GROUP BY chat_key`, device, waIDs)
		if err != nil {
			return err
		}
		type mark struct {
			chat string
			seq  int64
		}
		var marks []mark
		for rows.Next() {
			var m mark
			if err := rows.Scan(&m.chat, &m.seq); err != nil {
				rows.Close()
				return err
			}
			marks = append(marks, m)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if len(marks) == 0 {
			// Acknowledging messages this archive has never stored. Ordinary:
			// a receipt can arrive for a message that was never ingested.
			return nil
		}

		keys := make([]string, 0, len(marks))
		for _, m := range marks {
			keys = append(keys, m.chat)
		}
		if err := lockChats(ctx, tx, device, keys); err != nil {
			return err
		}
		for _, m := range marks {
			if _, err := tx.Exec(ctx, recount, device, m.chat, m.seq); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("store: mark read through: %w", err)
	}
	return nil
}

// MarkChatReadAt clears a whole conversation, optionally only as far as a time.
//
// A nil time means all of it. A time means "as far as the phone had got", which
// is what an app-state event carries.
//
// The anchor is restricted to rows that can count, and that restriction is not
// cosmetic. Sequence numbers rise on insert and timestamps say when a message
// was sent, so a backfilled row from 2019 carries an old timestamp and a high
// sequence — the reason conversations are ordered by time and not by sequence
// at all. Anchoring on max(seq) of everything at or before a timestamp would
// pick that row and silently mark live messages nobody has read.
func (u *Unread) MarkChatReadAt(ctx context.Context, tenant, device uuid.UUID,
	chatKey string, at *time.Time) error {
	err := pg.InTenantTx(ctx, u.pool, tenant.String(), func(tx pgx.Tx) error {
		// Either half of the identity may name the chat: an app-state event
		// can address the conversation by the number where the row is keyed on
		// the LID.
		var resolved string
		err := tx.QueryRow(ctx, `
			SELECT chat_key FROM chats
			 WHERE device_id = $1 AND ($2 IN (chat_key, chat_lid, chat_pn))
			 LIMIT 1`, device, chatKey).Scan(&resolved)
		if err != nil {
			if err == pgx.ErrNoRows {
				return nil
			}
			return err
		}

		var anchor int64
		if at == nil {
			err = tx.QueryRow(ctx, `
				SELECT coalesce(max(seq), 0) FROM messages
				 WHERE device_id = $1 AND chat_key = $2`, device, resolved).Scan(&anchor)
		} else {
			err = tx.QueryRow(ctx, `
				SELECT coalesce(max(seq), 0) FROM messages
				 WHERE device_id = $1 AND chat_key = $2
				   AND counts_unread AND ts <= $3`, device, resolved, *at).Scan(&anchor)
		}
		if err != nil {
			return err
		}
		if err := lockChats(ctx, tx, device, []string{resolved}); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, recount, device, resolved, anchor)
		return err
	})
	if err != nil {
		return fmt.Errorf("store: mark chat read: %w", err)
	}
	return nil
}

// MarkChatUnread puts a badge back, because somebody asked for one.
//
// Deliberately not a recount. "Mark as unread" is a reminder a person set on
// their phone, not a claim about how many messages are outstanding — and the
// honest count is usually zero, which would render as no badge at all and lose
// the reminder entirely. One is what WhatsApp shows.
func (u *Unread) MarkChatUnread(ctx context.Context, tenant, device uuid.UUID, chatKey string) error {
	err := pg.InTenantTx(ctx, u.pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE chats SET unread = GREATEST(unread, 1)
			 WHERE device_id = $1 AND ($2 IN (chat_key, chat_lid, chat_pn))`, device, chatKey)
		return err
	})
	if err != nil {
		return fmt.Errorf("store: mark chat unread: %w", err)
	}
	return nil
}

// Count reads a chat's badge. For tests and for pushing the number after a
// change, so the value a client receives is the one the write produced.
func (u *Unread) Count(ctx context.Context, tenant, device uuid.UUID, chatKey string) (int32, error) {
	var n int32
	err := pg.InTenantTx(ctx, u.pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT coalesce(sum(c.unread), 0)::int FROM chats c
			 WHERE c.device_id = $1
			   AND (c.chat_key = $2 OR (
			         NOT c.is_group AND c.chat_pn IS NOT NULL
			         AND c.chat_pn = (SELECT chat_pn FROM chats
			                           WHERE device_id = $1 AND chat_key = $2
			                             AND NOT is_group)))`,
			device, chatKey).Scan(&n)
	})
	if err != nil {
		return 0, fmt.Errorf("store: read unread: %w", err)
	}
	return n, nil
}
