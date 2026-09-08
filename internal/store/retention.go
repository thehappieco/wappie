package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/pg"
)

// Retention: what the archive stops holding, and when.
//
// Three operations, all destructive and all deliberate. A purge applies a
// tenant's retention window; an erasure removes one person from a tenant's
// archive; and the housekeeping pass forgets sessions and invites that have
// been dead long enough to be of no use to an audit. None of them run by
// themselves without a setting that says so.

// PurgeCounts reports what a purge or an erasure removed.
type PurgeCounts struct {
	Messages     int64
	Receipts     int64
	Media        int64
	Contacts     int64
	Participants int64
	Changes      int64
	// ObjectKeys are the attachments whose bytes may now be removed from
	// object storage: their rows went and nothing else references the key.
	ObjectKeys []string
}

// RetentionTenant is one tenant with a retention window set.
type RetentionTenant struct {
	ID   uuid.UUID
	Days int
}

// TenantsWithRetention lists the tenants that asked for a window.
func TenantsWithRetention(ctx context.Context, pool *pgxpool.Pool) ([]RetentionTenant, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, retention_days FROM tenants WHERE retention_days IS NOT NULL AND status = 'active'`)
	if err != nil {
		return nil, fmt.Errorf("store: tenants with retention: %w", err)
	}
	defer rows.Close()
	var out []RetentionTenant
	for rows.Next() {
		var t RetentionTenant
		if err := rows.Scan(&t.ID, &t.Days); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// SetRetention records a window in days, or forever with 0.
func SetRetention(ctx context.Context, pool *pgxpool.Pool, tenant uuid.UUID, days int) error {
	var value *int
	if days > 0 {
		value = &days
	}
	tag, err := pool.Exec(ctx,
		`UPDATE tenants SET retention_days = $2, updated_at = now() WHERE id = $1`, tenant, value)
	if err != nil {
		return fmt.Errorf("store: set retention: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Purge removes everything in a tenant's archive older than before.
//
// Messages carry their media by cascade; receipts and group changes are
// separate rows keyed by time. Chats and contacts stay: a conversation that
// is empty is still a conversation, and the name a contact was saved under
// is not a message.
func Purge(ctx context.Context, pool *pgxpool.Pool, tenant uuid.UUID, before time.Time) (PurgeCounts, error) {
	var out PurgeCounts
	err := pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		keys, err := objectKeysWhere(ctx, tx,
			`SELECT m.object_key FROM media m JOIN messages msg ON msg.uid = m.message_uid
			  WHERE m.object_key IS NOT NULL AND msg.ts < $1`, before)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM messages WHERE ts < $1`, before)
		if err != nil {
			return fmt.Errorf("store: purge messages: %w", err)
		}
		out.Messages = tag.RowsAffected()
		tag, err = tx.Exec(ctx, `DELETE FROM receipts WHERE ts < $1`, before)
		if err != nil {
			return fmt.Errorf("store: purge receipts: %w", err)
		}
		out.Receipts = tag.RowsAffected()
		tag, err = tx.Exec(ctx, `DELETE FROM group_changes WHERE ts < $1`, before)
		if err != nil {
			return fmt.Errorf("store: purge group changes: %w", err)
		}
		out.Changes = tag.RowsAffected()
		out.ObjectKeys, err = unreferenced(ctx, tx, keys)
		out.Media = int64(len(keys))
		return err
	})
	if err != nil {
		return PurgeCounts{}, err
	}
	return out, nil
}

// Erase removes one person from a tenant's archive: every message they sent
// or that was sent to them directly, every receipt they produced, the group
// membership rows that name them, and the contact row that names them.
//
// A right-to-erasure request arrives with an identifier, not a device, so this
// runs across every device of the tenant. Messages in a group that quote or
// mention the person are somebody else's messages and stay.
func Erase(ctx context.Context, pool *pgxpool.Pool, tenant uuid.UUID, keys []string) (PurgeCounts, error) {
	if len(keys) == 0 {
		return PurgeCounts{}, errors.New("store: erase needs at least one identifier")
	}
	var out PurgeCounts
	err := pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		objects, err := objectKeysWhere(ctx, tx,
			`SELECT m.object_key FROM media m JOIN messages msg ON msg.uid = m.message_uid
			  WHERE m.object_key IS NOT NULL
			    AND (msg.chat_key = ANY($1) OR msg.sender_key = ANY($1)
			         OR msg.sender_lid = ANY($1) OR msg.sender_pn = ANY($1))`, keys)
		if err != nil {
			return err
		}
		steps := []struct {
			name string
			sql  string
			into *int64
		}{
			{"messages", `DELETE FROM messages
				WHERE chat_key = ANY($1) OR sender_key = ANY($1)
				   OR sender_lid = ANY($1) OR sender_pn = ANY($1)`, &out.Messages},
			{"receipts", `DELETE FROM receipts
				WHERE chat_key = ANY($1) OR reader_key = ANY($1)
				   OR reader_lid = ANY($1) OR reader_pn = ANY($1)`, &out.Receipts},
			{"chats", `DELETE FROM chats WHERE chat_key = ANY($1) OR chat_lid = ANY($1) OR chat_pn = ANY($1)`, nil},
			{"contacts", `DELETE FROM contacts
				WHERE contact_key = ANY($1) OR contact_lid = ANY($1) OR contact_pn = ANY($1)`, &out.Contacts},
			{"group participants", `DELETE FROM group_participants
				WHERE participant_key = ANY($1) OR participant_lid = ANY($1) OR participant_pn = ANY($1)`, &out.Participants},
			{"group changes", `DELETE FROM group_changes
				WHERE actor_key = ANY($1) OR actor_lid = ANY($1) OR actor_pn = ANY($1)
				   OR subject_key = ANY($1) OR subject_lid = ANY($1) OR subject_pn = ANY($1)`, &out.Changes},
		}
		for _, step := range steps {
			tag, err := tx.Exec(ctx, step.sql, keys)
			if err != nil {
				return fmt.Errorf("store: erase %s: %w", step.name, err)
			}
			if step.into != nil {
				*step.into = tag.RowsAffected()
			}
		}
		out.ObjectKeys, err = unreferenced(ctx, tx, objects)
		out.Media = int64(len(objects))
		return err
	})
	if err != nil {
		return PurgeCounts{}, err
	}
	return out, nil
}

// ObjectKeysForDevice lists the attachment objects a device's archive holds,
// for a caller about to delete the device and wanting the bytes gone too.
func ObjectKeysForDevice(ctx context.Context, pool *pgxpool.Pool, tenant, device uuid.UUID) ([]string, error) {
	var out []string
	err := pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		var err error
		out, err = objectKeysWhere(ctx, tx,
			`SELECT m.object_key FROM media m JOIN messages msg ON msg.uid = m.message_uid
			  WHERE m.object_key IS NOT NULL AND msg.device_id = $1`, device)
		return err
	})
	return out, err
}

// ObjectKeysForTenant lists every attachment object a tenant holds.
func ObjectKeysForTenant(ctx context.Context, pool *pgxpool.Pool, tenant uuid.UUID) ([]string, error) {
	var out []string
	err := pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		var err error
		out, err = objectKeysWhere(ctx, tx, `SELECT object_key FROM media WHERE object_key IS NOT NULL`)
		return err
	})
	return out, err
}

// Unreferenced filters keys down to those no media row of the tenant still
// names. Objects are content-addressed per tenant, so a forwarded attachment
// is one object under several rows, and the last row to go is the one that
// frees it.
func Unreferenced(ctx context.Context, pool *pgxpool.Pool, tenant uuid.UUID, keys []string) ([]string, error) {
	var out []string
	err := pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		var err error
		out, err = unreferenced(ctx, tx, keys)
		return err
	})
	return out, err
}

func unreferenced(ctx context.Context, tx pgx.Tx, keys []string) ([]string, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `
		SELECT k FROM unnest($1::text[]) AS k
		 WHERE NOT EXISTS (SELECT 1 FROM media WHERE object_key = k)`, keys)
	if err != nil {
		return nil, fmt.Errorf("store: unreferenced objects: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func objectKeysWhere(ctx context.Context, tx pgx.Tx, sql string, args ...any) ([]string, error) {
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("store: object keys: %w", err)
	}
	defer rows.Close()
	seen := map[string]bool{}
	var out []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	return out, rows.Err()
}

// Housekeeping forgets sessions and invites that have been dead for a while.
//
// A revoked or expired session is kept for a grace period so "who was signed
// in last week" can still be answered, then goes: it holds a user agent and a
// last-seen time, which is tracking data with no further use.
func Housekeeping(ctx context.Context, pool *pgxpool.Pool, grace time.Duration) (sessions, invites int64, err error) {
	cutoff := time.Now().Add(-grace)
	tag, err := pool.Exec(ctx, `
		DELETE FROM sessions
		 WHERE coalesce(revoked_at, expires_at) < $1`, cutoff)
	if err != nil {
		return 0, 0, fmt.Errorf("store: housekeeping sessions: %w", err)
	}
	sessions = tag.RowsAffected()
	tag, err = pool.Exec(ctx, `
		DELETE FROM invites
		 WHERE coalesce(completed_at, expires_at) < $1`, cutoff)
	if err != nil {
		return sessions, 0, fmt.Errorf("store: housekeeping invites: %w", err)
	}
	return sessions, tag.RowsAffected(), nil
}
