package store

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/pg"
)

// One person, two conversations.
//
// WhatsApp addressed the same contact by phone number for years and now
// addresses them by LID, and a conversation that spans the change is stored
// under both — 226 messages under one key, 483 under the other, the same person
// on the other end. Measured on the archive this was written against: 47 people,
// 94 conversations, 38 of them with messages on both sides.
//
// Nothing is merged on disk. The rows record how WhatsApp actually addressed
// each message, which is a fact about what happened and the reason receipts can
// be matched at all; rewriting a chat_key would destroy it and could not be
// undone. So the folding is a projection, the same shape as folding a person's
// several devices into one reader.
//
// The join is the phone number. The older row predates LIDs and has none — the
// backfill fills a phone number from a LID and never the other way, because
// inventing a LID would rewrite the key it is stored under.

// personOf is the identity a direct conversation is counted under.
//
// The phone number first, because it is the half both rows carry: the LID-keyed
// row knows the number, and the number-keyed row has no LID at all. Keying on
// the LID would leave the older conversation on its own, which is the state
// this exists to fix.
//
// Groups never fold. A group id is not a person and two groups that happen to
// share digits are two groups.
func personOf(c ChatRow) string {
	if c.IsGroup || c.ChatPN == "" {
		return c.ChatKey
	}
	return c.ChatPN
}

// foldChats collapses conversations that name the same person into one.
//
// The representative is the row that carries a name, and failing that the one
// with the newest activity — because the sealed name is bound to that row's own
// uid, so taking the name from one row and the identity from another produces a
// value that reports tampering with the correct key in hand.
func foldChats(rows []ChatRow) []ChatRow {
	byPerson := map[string]*ChatRow{}
	order := []string{}

	for i := range rows {
		row := rows[i]
		person := personOf(row)
		head, ok := byPerson[person]
		if !ok {
			row.Keys = []string{row.ChatKey}
			byPerson[person] = &row
			order = append(order, person)
			continue
		}
		head.Keys = append(head.Keys, row.ChatKey)
		mergeInto(head, row)
	}

	out := make([]ChatRow, 0, len(order))
	for _, p := range order {
		head := byPerson[p]
		sort.Strings(head.Keys)
		out = append(out, *head)
	}
	return out
}

// mergeInto folds one conversation into another.
func mergeInto(head *ChatRow, other ChatRow) {
	// Identity: a known half is never replaced by an empty one, which is the
	// rule everywhere else and is what lets the older row contribute its
	// number and the newer one its LID.
	if head.ChatLID == "" {
		head.ChatLID = other.ChatLID
	}
	if head.ChatPN == "" {
		head.ChatPN = other.ChatPN
	}

	// The name, and the identity it is bound to, move together. A sealed name
	// binds to its own row's uid; taking the name from one row and the uid
	// from another opens as tampered with the right key in hand, which reads
	// as an attack rather than a mistake.
	if len(head.NameSealed) == 0 && len(other.NameSealed) > 0 {
		head.UID, head.NameSealed, head.NameKeyID = other.UID, other.NameSealed, other.NameKeyID
		head.ChatKey = other.ChatKey
	}

	// Badges add up: they count messages, and the messages are all the
	// person's.
	head.Unread += other.Unread
	// Pinned if either is. Archived only if both are — a conversation the
	// reader archived under one identifier and not the other is one they have
	// not finished with.
	head.Pinned = head.Pinned || other.Pinned
	head.Archived = head.Archived && other.Archived

	// The preview follows the newest message, wherever it was addressed.
	if newer(other.LastTS, head.LastTS) {
		head.LastTS, head.LastSeq = other.LastTS, other.LastSeq
		head.LastKind, head.LastType = other.LastKind, other.LastType
		head.LastUID, head.LastBodySealed, head.LastBodyKeyID =
			other.LastUID, other.LastBodySealed, other.LastBodyKeyID
	} else if other.LastSeq > head.LastSeq && head.LastTS == nil {
		head.LastSeq = other.LastSeq
	}
	if head.Ephemeral == 0 {
		head.Ephemeral = other.Ephemeral
	}
	if other.ParticipantCount != nil && head.ParticipantCount == nil {
		head.ParticipantCount = other.ParticipantCount
	}
	if other.GroupCreatedAt != nil && head.GroupCreatedAt == nil {
		head.GroupCreatedAt = other.GroupCreatedAt
	}
	if other.CreatedAt.Before(head.CreatedAt) {
		head.CreatedAt = other.CreatedAt
	}
}

// newer reports whether a is later than b, treating absent as earliest.
func newer(a, b *time.Time) bool {
	switch {
	case a == nil:
		return false
	case b == nil:
		return true
	}
	return a.After(*b)
}

// SiblingKeys returns every key that names the same conversation as this one.
//
// Always includes the key it was given, so a caller can use the result
// unconditionally and a conversation with no sibling costs one query and
// behaves exactly as it did before.
//
// The lookup is by phone number because that is the half both rows carry. A
// group returns only itself: a group id is not a person.
func (m *Messages) SiblingKeys(ctx context.Context, tenant, device uuid.UUID,
	chatKey string) ([]string, error) {
	keys := []string{chatKey}
	err := pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT other.chat_key
			  FROM chats self
			  JOIN chats other
			    ON other.device_id = self.device_id
			   AND other.chat_pn = self.chat_pn
			   AND other.chat_key <> self.chat_key
			   AND NOT other.is_group
			 WHERE self.device_id = $1 AND self.chat_key = $2
			   AND NOT self.is_group AND self.chat_pn IS NOT NULL`, device, chatKey)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var k string
			if err := rows.Scan(&k); err != nil {
				return err
			}
			keys = append(keys, k)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("store: sibling chat keys: %w", err)
	}
	sort.Strings(keys)
	return keys, nil
}
