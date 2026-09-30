package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"whatserver2/internal/pg"
)

// The keychain (docs/mcp-enclave.md §18.6): a person's API keys, sealed in
// their browser under a key only their account's private key derives. This
// server stores an opaque envelope with the provider, a label and the key's
// last four characters beside it, and can neither open nor make one.

const (
	// AIKeychainMax is how many live items a person may hold in one
	// workspace.
	AIKeychainMax = 20
	// aiEnvelopeMax bounds an envelope, as its column does.
	aiEnvelopeMax = 4096
	// aiEnvelopeMin is the magic, the IV and the AES-GCM tag: the shortest
	// envelope that could open.
	aiEnvelopeMin = 4 + 12 + 16
	// aiKeychainRetention is how long a deleted item's row is kept.
	aiKeychainRetention = 30 * 24 * time.Hour
)

// aiEnvelopeMagic starts every keychain envelope.
var aiEnvelopeMagic = []byte("WKC1")

// ValidAIEnvelope is an envelope of the keychain's format and size: "WKC1",
// then at least an IV and a tag, at most 4 KiB in all.
func ValidAIEnvelope(envelope []byte) bool {
	return len(envelope) >= aiEnvelopeMin && len(envelope) <= aiEnvelopeMax && bytes.HasPrefix(envelope, aiEnvelopeMagic)
}

// AIKeychainItem is one keychain item.
type AIKeychainItem struct {
	ID        uuid.UUID
	Provider  string
	Label     string
	Suffix    string
	Envelope  []byte
	CreatedAt time.Time
}

// Keychain lists a person's live items in a workspace, oldest first.
func (a *AI) Keychain(ctx context.Context, tenant, user uuid.UUID) ([]AIKeychainItem, error) {
	out := []AIKeychainItem{}
	err := pg.InTenantTx(ctx, a.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, provider, label, suffix, envelope, created_at FROM ai_keychain
			WHERE tenant_id=$1 AND user_id=$2 AND deleted_at IS NULL ORDER BY created_at, id`, tenant, user)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item AIKeychainItem
			if err := rows.Scan(&item.ID, &item.Provider, &item.Label, &item.Suffix, &item.Envelope, &item.CreatedAt); err != nil {
				return err
			}
			out = append(out, item)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("store: list the keychain: %w", err)
	}
	return out, nil
}

// AddKeychainItem stores a person's sealed item under the id the browser
// chose and bound in the envelope. A person holds at most AIKeychainMax live
// items per workspace (ErrAIKeychainFull); an id already taken, by anyone,
// is ErrAIKeychainExists.
func (a *AI) AddKeychainItem(ctx context.Context, tenant, user uuid.UUID, item AIKeychainItem) (AIKeychainItem, error) {
	switch {
	case item.ID == uuid.Nil, !slices.Contains(AIProviders, item.Provider), !ValidAILabel(item.Label),
		!ValidAISuffix(item.Suffix), !ValidAIEnvelope(item.Envelope):
		// The handler checks the body; this is the backstop.
		return AIKeychainItem{}, errors.New("store: a keychain item needs an id, a provider, a label, a suffix and an envelope")
	}
	err := pg.InTenantTx(ctx, a.pool, tenant.String(), func(tx pgx.Tx) error {
		// The workspace's row serializes two adds of one person, so the
		// count holds.
		if _, err := activeRoleTx(ctx, tx, tenant, user); err != nil {
			return err
		}
		var live int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM ai_keychain WHERE tenant_id=$1 AND user_id=$2 AND deleted_at IS NULL`,
			tenant, user).Scan(&live); err != nil {
			return err
		}
		if live >= AIKeychainMax {
			return ErrAIKeychainFull
		}
		err := tx.QueryRow(ctx, `INSERT INTO ai_keychain (id, tenant_id, user_id, provider, label, suffix, envelope)
			VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING created_at`,
			item.ID, tenant, user, item.Provider, item.Label, item.Suffix, item.Envelope).Scan(&item.CreatedAt)
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrAIKeychainExists
		}
		return err
	})
	if err != nil {
		return AIKeychainItem{}, err
	}
	return item, nil
}

// EndedConnection is a connection a change ended: the one to tell its
// reader about.
type EndedConnection struct {
	ID     string
	Reader string
}

// DeleteKeychainItem deletes one of a person's live items: its envelope is
// emptied and it is marked deleted, and every live AI authorization whose
// configuration names it ends with ReasonAIKeyDeleted, in the same
// transaction. Another person's item, or one already deleted, is
// ErrAINotFound. The ended authorizations come back for their reader to be
// told.
func (a *AI) DeleteKeychainItem(ctx context.Context, tenant, user, id uuid.UUID) ([]EndedConnection, error) {
	var ended []EndedConnection
	err := pg.InTenantTx(ctx, a.pool, tenant.String(), func(tx pgx.Tx) error {
		if err := lockWorkspaceAccess(ctx, tx, tenant); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE ai_keychain SET envelope='\x', deleted_at=now()
			WHERE id=$1 AND tenant_id=$2 AND user_id=$3 AND deleted_at IS NULL`, id, tenant, user)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrAINotFound
		}
		rows, err := tx.Query(ctx, `SELECT id::text, reader FROM mcp_connections
			WHERE tenant_id=$1 AND kind='ai' AND status IN ('pending','active','reseal')
			  AND EXISTS (SELECT 1 FROM jsonb_each(ai_config->'keys') k WHERE k.value->>'keychain_id' = $2)
			ORDER BY id`, tenant, id.String())
		if err != nil {
			return err
		}
		for rows.Next() {
			var e EndedConnection
			if err := rows.Scan(&e.ID, &e.Reader); err != nil {
				rows.Close()
				return err
			}
			ended = append(ended, e)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, e := range ended {
			if _, err := endMCPConnectionTx(ctx, tx, tenant, e.ID, statusRevoked, ReasonAIKeyDeleted); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ended, nil
}
