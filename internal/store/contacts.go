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

// Contacts persists who the identifiers belong to.
type Contacts struct{ pool *pgxpool.Pool }

// NewContacts returns a contact store.
func NewContacts(pool *pgxpool.Pool) *Contacts { return &Contacts{pool: pool} }

// contactNamespace is the uuid namespace contact identities are derived in.
// Distinct from the chat one so a chat and a contact with the same key cannot
// collide onto the same identifier.
var contactNamespace = uuid.MustParse("b1c3e5a7-9d24-4f68-8e0b-3a7c5d1f9042")

// ContactUID is a contact's stable identity, for binding sealed values to.
//
// Derived rather than generated, for the same reasons as ChatUID: both sides
// compute it without asking, and it survives a re-import. Predictability is
// fine — associated data is a binding, not a secret.
func ContactUID(device uuid.UUID, contactKey string) uuid.UUID {
	return uuid.NewSHA1(contactNamespace, append([]byte(device.String()+"\x00"), contactKey...))
}

// ContactName is one name to record.
//
// Each is optional and nil means "not stated", which is not the same as empty.
// A push-name update says nothing about the address book, and letting it clear
// a saved name would lose the better of the two.
type ContactName struct {
	TenantID uuid.UUID
	DeviceID uuid.UUID

	ContactKey string
	ContactLID string
	ContactPN  string
	IsGroup    bool

	ContentKeyID       uint32
	PushNameSealed     []byte
	FullNameSealed     []byte
	BusinessNameSealed []byte
}

// ContactRow is a contact as it leaves the server.
type ContactRow struct {
	UID        uuid.UUID
	ContactKey string
	ContactLID string
	ContactPN  string
	IsGroup    bool

	ContentKeyID       uint32
	PushNameSealed     []byte
	FullNameSealed     []byte
	BusinessNameSealed []byte

	AvatarID      string
	AvatarKeyID   uint32
	HasAvatar     bool
	AvatarChecked *time.Time
}

// Upsert records what is known about a contact.
func (c *Contacts) Upsert(ctx context.Context, in ContactName) error {
	err := pg.InTenantTx(ctx, c.pool, in.TenantID.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO contacts (tenant_id, device_id, contact_key, contact_lid, contact_pn,
			                      is_group, uid, content_key_id,
			                      push_name_sealed, full_name_sealed, business_name_sealed)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
			ON CONFLICT (device_id, contact_key) DO UPDATE SET
				contact_lid = COALESCE(EXCLUDED.contact_lid, contacts.contact_lid),
				contact_pn  = COALESCE(EXCLUDED.contact_pn,  contacts.contact_pn),
				is_group    = contacts.is_group OR EXCLUDED.is_group,
				-- A name that was not stated must not erase one that was. A
				-- push name arriving on a message says nothing about the
				-- address book, and the address book is the better name.
				content_key_id       = COALESCE(EXCLUDED.content_key_id, contacts.content_key_id),
				push_name_sealed     = COALESCE(EXCLUDED.push_name_sealed, contacts.push_name_sealed),
				full_name_sealed     = COALESCE(EXCLUDED.full_name_sealed, contacts.full_name_sealed),
				business_name_sealed = COALESCE(EXCLUDED.business_name_sealed, contacts.business_name_sealed)`,
			in.TenantID, in.DeviceID, in.ContactKey,
			nullable(in.ContactLID), nullable(in.ContactPN), in.IsGroup,
			ContactUID(in.DeviceID, in.ContactKey), nullableKeyID(in.ContentKeyID),
			nullableBytes(in.PushNameSealed), nullableBytes(in.FullNameSealed),
			nullableBytes(in.BusinessNameSealed))
		return err
	})
	if err != nil {
		return fmt.Errorf("store: upsert contact: %w", err)
	}
	return nil
}

// SetAvatar records a sealed profile picture.
//
// avatarID is WhatsApp's identifier for the image; it changes when the picture
// does, and is what lets the fetcher skip a contact whose picture it already
// has. An empty sealed value with a set checked time means "asked, and there
// is no picture" — which has to be recorded, or every pass asks again.
func (c *Contacts) SetAvatar(ctx context.Context, tenant, device uuid.UUID,
	contactKey, avatarID string, sealed []byte, keyID uint32) error {
	err := pg.InTenantTx(ctx, c.pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO contacts (tenant_id, device_id, contact_key, uid,
			                      avatar_id, avatar_sealed, avatar_key_id, avatar_checked_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,now())
			ON CONFLICT (device_id, contact_key) DO UPDATE SET
				avatar_id         = EXCLUDED.avatar_id,
				avatar_sealed     = EXCLUDED.avatar_sealed,
				avatar_key_id     = EXCLUDED.avatar_key_id,
				avatar_checked_at = now()`,
			tenant, device, contactKey, ContactUID(device, contactKey),
			nullable(avatarID), nullableBytes(sealed), nullableKeyID(keyID))
		return err
	})
	if err != nil {
		return fmt.Errorf("store: set avatar: %w", err)
	}
	return nil
}

const contactColumns = `uid, contact_key, coalesce(contact_lid,''), coalesce(contact_pn,''),
	is_group, coalesce(content_key_id,0), push_name_sealed, full_name_sealed,
	business_name_sealed, coalesce(avatar_id,''), coalesce(avatar_key_id,0),
	avatar_sealed IS NOT NULL, avatar_checked_at`

func scanContact(rows pgx.Rows) (ContactRow, error) {
	var c ContactRow
	var keyID, avatarKeyID int32
	if err := rows.Scan(&c.UID, &c.ContactKey, &c.ContactLID, &c.ContactPN, &c.IsGroup,
		&keyID, &c.PushNameSealed, &c.FullNameSealed, &c.BusinessNameSealed,
		&c.AvatarID, &avatarKeyID, &c.HasAvatar, &c.AvatarChecked); err != nil {
		return ContactRow{}, err
	}
	if keyID > 0 {
		c.ContentKeyID = uint32(keyID)
	}
	if avatarKeyID > 0 {
		c.AvatarKeyID = uint32(avatarKeyID)
	}
	return c, nil
}

// List returns the contacts of one device.
//
// The avatar bytes are deliberately not included: a thousand contacts with a
// picture each is tens of megabytes, and a chat list needs the names now and
// the faces as it draws them. Avatar fetches one.
func (c *Contacts) List(ctx context.Context, tenant, device uuid.UUID, limit int) ([]ContactRow, error) {
	var out []ContactRow
	err := pg.InTenantTx(ctx, c.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT `+contactColumns+`
			  FROM contacts WHERE device_id = $1
			 ORDER BY contact_key LIMIT $2`, device, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			row, err := scanContact(rows)
			if err != nil {
				return err
			}
			out = append(out, row)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("store: list contacts: %w", err)
	}
	return out, nil
}

// Some returns the contacts named by key, in whatever order they come back.
//
// Distinct from List, which pages the whole device: this answers "who are these
// particular identifiers", which is what a client asks when a conversation it
// has never seen appears and the sidebar is about to draw a LID. Keys that name
// no row are simply absent from the result — a caller cannot tell an unknown
// contact from one with nothing recorded, and does not need to.
func (c *Contacts) Some(ctx context.Context, tenant, device uuid.UUID, keys []string) ([]ContactRow, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	var out []ContactRow
	err := pg.InTenantTx(ctx, c.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT `+contactColumns+`
			  FROM contacts WHERE device_id = $1 AND contact_key = ANY($2)`, device, keys)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			row, err := scanContact(rows)
			if err != nil {
				return err
			}
			out = append(out, row)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("store: read contacts: %w", err)
	}
	return out, nil
}

// Avatar returns one contact's sealed profile picture.
func (c *Contacts) Avatar(ctx context.Context, tenant, device uuid.UUID, contactKey string) (
	sealed []byte, keyID uint32, uid uuid.UUID, err error) {
	var raw int32
	err = pg.InTenantTx(ctx, c.pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT avatar_sealed, coalesce(avatar_key_id,0), uid FROM contacts
			 WHERE device_id = $1 AND contact_key = $2`, device, contactKey).
			Scan(&sealed, &raw, &uid)
	})
	if err != nil {
		return nil, 0, uuid.Nil, fmt.Errorf("store: read avatar: %w", err)
	}
	if raw > 0 {
		keyID = uint32(raw)
	}
	return sealed, keyID, uid, nil
}

// NeedAvatar lists contacts whose picture has not been looked at recently.
//
// Ordered oldest-checked first, so a pass makes progress rather than asking
// about the same few every time. Never-checked rows sort first.
func (c *Contacts) NeedAvatar(ctx context.Context, tenant, device uuid.UUID,
	staleAfter time.Duration, limit int) ([]ContactRow, error) {
	var out []ContactRow
	err := pg.InTenantTx(ctx, c.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT `+contactColumns+`
			  FROM contacts
			 WHERE device_id = $1
			   AND (avatar_checked_at IS NULL OR avatar_checked_at < now() - $2::interval)
			 ORDER BY avatar_checked_at NULLS FIRST
			 LIMIT $3`, device, staleAfter.String(), limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			row, err := scanContact(rows)
			if err != nil {
				return err
			}
			out = append(out, row)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("store: list contacts needing avatars: %w", err)
	}
	return out, nil
}

// TouchAvatar records that a contact was asked about and nothing came back.
//
// Without it a contact with no picture is asked about on every pass forever,
// and the ones that have never been asked never get a turn.
func (c *Contacts) TouchAvatar(ctx context.Context, tenant, device uuid.UUID, contactKey string) error {
	err := pg.InTenantTx(ctx, c.pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE contacts SET avatar_checked_at = now()
			 WHERE device_id = $1 AND contact_key = $2`, device, contactKey)
		return err
	})
	if err != nil {
		return fmt.Errorf("store: touch avatar: %w", err)
	}
	return nil
}

// InvalidateAvatar marks a contact's picture as worth asking about again.
//
// Clearing the check time rather than the picture itself: the stored face is
// still the one that was current a moment ago, and blanking it would put a
// placeholder on screen for however long the refetch takes. The row simply
// sorts to the front of the worker's queue, and avatar_id then tells WhatsApp
// which picture we already have — so an unchanged one costs a question and no
// download.
func (c *Contacts) InvalidateAvatar(ctx context.Context, tenant, device uuid.UUID, contactKey string) error {
	err := pg.InTenantTx(ctx, c.pool, tenant.String(), func(tx pgx.Tx) error {
		// Matched on any of the three identifiers, not on contact_key alone.
		// contact_key is whichever half Address.Primary picked when the row was
		// written — the LID when both are known — and events.Picture can name
		// the other one. A mismatch updates zero rows, which pgx reports as
		// success and nothing logs, so the one event that can make a changed
		// face appear inside the seven-day staleness window would go missing
		// with no trace at all.
		_, err := tx.Exec(ctx, `
			UPDATE contacts SET avatar_checked_at = NULL
			 WHERE device_id = $1
			   AND (contact_key = $2 OR contact_lid = $2 OR contact_pn = $2)`, device, contactKey)
		return err
	})
	if err != nil {
		return fmt.Errorf("store: invalidate avatar: %w", err)
	}
	return nil
}

// nullableBytes keeps an absent value distinguishable from an empty one, so a
// COALESCE upsert does not treat "not stated" as "cleared".
func nullableBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}
