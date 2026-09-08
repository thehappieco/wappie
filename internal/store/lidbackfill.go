package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/pg"
)

// LinkCounts reports what one linking pass filled in.
type LinkCounts struct {
	Messages int64
	Chats    int64
	Contacts int64
}

// LinkPhoneNumbers fills in the phone number behind a LID, everywhere it is
// already known and missing.
//
// The ingest path resolves this for new traffic, but the archive was written
// before it did: on one real account, 860 of 883 group senders had a LID and no
// number, so they matched no contact and showed up with no name. The names were
// never missing -- they were filed under an identifier nobody looked up.
//
// The join comes from whatsmeow's own table. Every group query it makes records
// the LID/phone pairs it learns, and they have been accumulating in
// whatsmeow_lid_map since the first sync. Reading it here rather than asking
// WhatsApp again costs nothing and works for devices this process is not even
// supervising.
//
// One direction only, and this is the part that would be easy to get wrong: a
// missing phone number is filled from a LID, never the reverse. chat_key and
// sender_key are derived from whichever identifier is primary, and the LID is
// primary -- so inventing a LID for a row that has only a number would rewrite
// the archive's storage identity, and every conversation would fork in two.
//
// Idempotent, so it can run at every boot: a row that already has a number is
// left alone by the WHERE clause.
func LinkPhoneNumbers(ctx context.Context, pool *pgxpool.Pool, tenant uuid.UUID) (LinkCounts, error) {
	var out LinkCounts
	err := pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		// whatsmeow owns this table and creates it with its own migrations when
		// the session store opens. On an installation that has never paired
		// anything it may not be there yet, and a boot pass must not fail for
		// want of a join it has nothing to join.
		var present bool
		if err := tx.QueryRow(ctx,
			`SELECT to_regclass('whatsmeow_lid_map') IS NOT NULL`).Scan(&present); err != nil {
			return fmt.Errorf("store: look for the lid map: %w", err)
		}
		if !present {
			return nil
		}

		// The map holds bare user parts with no server, and a stored LID may
		// carry a device suffix, so both sides are cut down to the user before
		// they meet. The result is rebuilt as a plain phone JID: keeping the
		// suffix would produce 5511971446866:5@s.whatsapp.net, which matches no
		// contact and no chat.
		steps := []struct {
			name  string
			sql   string
			count *int64
		}{
			{"messages", `
				UPDATE messages m
				   SET sender_pn = l.pn || '@s.whatsapp.net'
				  FROM whatsmeow_lid_map l
				 WHERE m.sender_pn IS NULL
				   AND m.sender_lid IS NOT NULL
				   AND l.lid = split_part(split_part(m.sender_lid, '@', 1), ':', 1)`,
				&out.Messages},

			{"chats", `
				UPDATE chats c
				   SET chat_pn = l.pn || '@s.whatsapp.net'
				  FROM whatsmeow_lid_map l
				 WHERE c.chat_pn IS NULL
				   AND c.chat_lid IS NOT NULL
				   AND l.lid = split_part(split_part(c.chat_lid, '@', 1), ':', 1)`,
				&out.Chats},

			// And the other half of the same problem: a contact learned by phone
			// number has no LID, so a group message addressed by LID finds
			// nothing. Filling contact_lid is safe where filling a message's LID
			// would not be -- contact_key stays exactly as it was, so nothing
			// re-keys; the row simply gains a second way to be found.
			{"contacts", `
				UPDATE contacts c
				   SET contact_lid = l.lid || '@lid'
				  FROM whatsmeow_lid_map l
				 WHERE c.contact_lid IS NULL
				   AND c.contact_pn IS NOT NULL
				   AND l.pn = split_part(split_part(c.contact_pn, '@', 1), ':', 1)`,
				&out.Contacts},
		}

		for _, step := range steps {
			tag, err := tx.Exec(ctx, step.sql)
			if err != nil {
				return fmt.Errorf("store: link %s: %w", step.name, err)
			}
			*step.count = tag.RowsAffected()
		}
		return nil
	})
	if err != nil {
		return LinkCounts{}, err
	}
	return out, nil
}
