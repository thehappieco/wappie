package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/pg"
)

// ResetCounts reports what a reset removed.
type ResetCounts struct {
	Messages int64
	Chats    int64
	Contacts int64
	Media    int64
	Devices  int64
}

// ResetArchive removes everything sealed for one tenant.
//
// It exists because a change to the key scheme cannot be applied to data
// already sealed: re-sealing means opening, and this server has never been able
// to open its own archive. The only way past one is to discard and start again,
// which is a decision an operator makes deliberately — never a migration.
//
// Object storage is left alone. What is in it is ciphertext addressed by a
// content hash and inert without keys that this removes; deleting it is a long
// remote operation that can half-finish, and a half-finished delete is worse
// than an untidy bucket.
func ResetArchive(ctx context.Context, pool *pgxpool.Pool, tenant uuid.UUID,
	keepDevices bool) (ResetCounts, error) {
	var out ResetCounts
	err := pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		// Order matters only for readability: every one of these cascades from
		// devices, and the counts would be zero if devices went first.
		for _, step := range []struct {
			table string
			into  *int64
		}{
			{"media", &out.Media},
			{"messages", &out.Messages},
			{"chats", &out.Chats},
			{"contacts", &out.Contacts},
			{"content_keys", nil},
			{"device_key_grants", nil},
			{"device_archive_keys", nil},
		} {
			tag, err := tx.Exec(ctx, "DELETE FROM "+step.table)
			if err != nil {
				return fmt.Errorf("store: reset %s: %w", step.table, err)
			}
			if step.into != nil {
				*step.into = tag.RowsAffected()
			}
		}

		if !keepDevices {
			tag, err := tx.Exec(ctx, `DELETE FROM devices`)
			if err != nil {
				return fmt.Errorf("store: reset devices: %w", err)
			}
			out.Devices = tag.RowsAffected()
		} else {
			// A device with no key cannot seal, and ingest refuses rather than
			// storing plaintext. Saying so here beats discovering it as a
			// stream of errors on the next message.
			if _, err := tx.Exec(ctx, `UPDATE devices SET current_epoch = 0`); err != nil {
				return fmt.Errorf("store: clear device epochs: %w", err)
			}
		}

		// The tenant sequence goes back to zero with the rows it numbered. A
		// client resuming from an old cursor would otherwise wait forever for
		// sequences that will never be issued again.
		if _, err := tx.Exec(ctx,
			`UPDATE tenants SET last_seq = 0 WHERE id = $1`, tenant); err != nil {
			return fmt.Errorf("store: reset sequence: %w", err)
		}
		return nil
	})
	if err != nil {
		return ResetCounts{}, err
	}
	return out, nil
}
