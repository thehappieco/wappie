package store

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/pg"
)

// Keys persists archive keys, content keys and key grants.
//
// Only public and sealed material passes through here. A device's private
// archive key is generated on a client and never transmitted, which is what
// makes the server unable to read what it stores. There is no parameter on any
// function below that could carry one.
type Keys struct{ pool *pgxpool.Pool }

// NewKeys returns a key store.
func NewKeys(pool *pgxpool.Pool) *Keys { return &Keys{pool: pool} }

var _ seal.KeyStore = (*Keys)(nil)

// ErrNoArchiveKey means a device has no archive key yet, so nothing can be
// stored for it. Deliberately fatal to ingest rather than a reason to fall back
// to plaintext, which would be a silent failure of the one guarantee this
// system makes.
var ErrNoArchiveKey = errors.New("store: device has no archive key")

// ArchiveKey returns a device's current archive public key and epoch.
func (k *Keys) ArchiveKey(ctx context.Context, tenant, device uuid.UUID) (seal.PublicKey, uint16, error) {
	var raw []byte
	var epoch int32
	err := pg.InTenantTx(ctx, k.pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT k.public_key, k.epoch
			  FROM device_archive_keys k
			  JOIN devices d ON d.id = k.device_id AND d.current_epoch = k.epoch
			 WHERE k.device_id = $1 AND k.retired_at IS NULL`, device).Scan(&raw, &epoch)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return seal.PublicKey{}, 0, fmt.Errorf("%w: %s", ErrNoArchiveKey, device)
	}
	if err != nil {
		return seal.PublicKey{}, 0, fmt.Errorf("store: load archive key: %w", err)
	}
	pub, err := seal.ParsePublicKey(raw)
	if err != nil {
		return seal.PublicKey{}, 0, err
	}
	if epoch < 1 || epoch > maxEpoch {
		return seal.PublicKey{}, 0, fmt.Errorf("store: epoch %d is out of range for device %s", epoch, device)
	}
	return pub, uint16(epoch), nil
}

// The envelope header carries the epoch as a uint16 and content key ids as a
// uint32, while both columns are Postgres integers. Neither range is reachable
// in practice — an epoch counts key rotations and an id counts content keys,
// which rotate every thousand seals — but a value past the boundary would wrap
// to a negative number and silently address the wrong row, so it is checked
// rather than assumed.
const (
	maxEpoch = 1<<16 - 1
	maxKeyID = 1<<31 - 1
)

// toColumnID narrows a content key id to the column's integer type.
func toColumnID(id uint32) (int32, error) {
	if id < 1 || id > maxKeyID {
		return 0, fmt.Errorf("store: content key id %d is out of range", id)
	}
	return int32(id), nil
}

// CreateArchiveKey records a device's archive public key for an epoch.
//
// Only the public half is accepted, by construction: there is no parameter for
// a private key, so no code path exists that could store one by mistake.
func (k *Keys) CreateArchiveKey(ctx context.Context, tenant, device uuid.UUID,
	epoch uint16, pub seal.PublicKey) error {
	if !pub.Valid() {
		return errors.New("store: archive key is not a valid public key")
	}
	if epoch < 1 {
		return fmt.Errorf("store: epoch must be at least 1, got %d", epoch)
	}
	return pg.InTenantTx(ctx, k.pool, tenant.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO device_archive_keys (tenant_id, device_id, epoch, public_key, suite)
			VALUES ($1, $2, $3, $4, $5)`,
			tenant, device, int32(epoch), pub.Bytes(), int16(seal.SuiteV1)); err != nil {
			return fmt.Errorf("store: insert archive key: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`UPDATE devices SET current_epoch = $2 WHERE id = $1 AND tenant_id = $3`,
			device, int32(epoch), tenant); err != nil {
			return fmt.Errorf("store: set current epoch: %w", err)
		}
		return nil
	})
}

// HasArchiveKey reports whether a device can seal yet.
func (k *Keys) HasArchiveKey(ctx context.Context, tenant, device uuid.UUID) (bool, error) {
	_, _, err := k.ArchiveKey(ctx, tenant, device)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, ErrNoArchiveKey):
		return false, nil
	default:
		return false, err
	}
}

// CreateContentKey allocates the next per-device id and stores the key sealed
// against it, in one transaction.
//
// The id is a per-device counter rather than a global sequence, so it does not
// leak system-wide volume to clients. Allocating it means reading the current
// maximum, which two concurrent rotations would otherwise both read — hence the
// advisory lock, held for the transaction and released on commit.
func (k *Keys) CreateContentKey(ctx context.Context, tenant, device uuid.UUID, epoch uint16,
	sealFn func(id uint32) ([]byte, error)) (uint32, error) {
	var id uint32
	err := pg.InTenantTx(ctx, k.pool, tenant.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, contentKeyLock(device)); err != nil {
			return fmt.Errorf("store: lock content key counter: %w", err)
		}

		var next int32
		if err := tx.QueryRow(ctx, `
			SELECT coalesce(max(id), 0) + 1 FROM content_keys WHERE device_id = $1`,
			device).Scan(&next); err != nil {
			return fmt.Errorf("store: allocate content key id: %w", err)
		}
		if next < 1 || next > maxKeyID {
			return fmt.Errorf("store: content key counter is out of range: %d", next)
		}
		id = uint32(next)

		sealed, err := sealFn(id)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO content_keys (tenant_id, device_id, id, epoch, sealed_key)
			VALUES ($1, $2, $3, $4, $5)`,
			tenant, device, next, int32(epoch), sealed); err != nil {
			return fmt.Errorf("store: insert content key: %w", err)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return id, nil
}

// SealedContentKey returns a stored content key, for a client to unwrap.
func (k *Keys) SealedContentKey(ctx context.Context, tenant, device uuid.UUID, id uint32) ([]byte, error) {
	col, err := toColumnID(id)
	if err != nil {
		return nil, err
	}
	var sealed []byte
	err = pg.InTenantTx(ctx, k.pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT sealed_key FROM content_keys WHERE device_id = $1 AND id = $2`,
			device, col).Scan(&sealed)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: content key %d", ErrNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("store: load content key: %w", err)
	}
	return sealed, nil
}

// CountSeal records additional uses of a content key.
//
// Operational visibility only: the authoritative count lives in the sealer's
// memory, and rotation never waits on this.
func (k *Keys) CountSeal(ctx context.Context, tenant, device uuid.UUID, id uint32, n int) error {
	col, err := toColumnID(id)
	if err != nil {
		return err
	}
	return pg.InTenantTx(ctx, k.pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE content_keys SET sealed_count = sealed_count + $3
			 WHERE device_id = $1 AND id = $2`, device, col, n)
		return err
	})
}

// CloseContentKey marks a key as no longer accepting new values.
func (k *Keys) CloseContentKey(ctx context.Context, tenant, device uuid.UUID, id uint32) error {
	col, err := toColumnID(id)
	if err != nil {
		return err
	}
	return pg.InTenantTx(ctx, k.pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE content_keys SET closed_at = now()
			 WHERE device_id = $1 AND id = $2 AND closed_at IS NULL`, device, col)
		return err
	})
}

// ---------------------------------------------------------------------------
// Key grants
// ---------------------------------------------------------------------------

// Grant is one device's private archive key sealed to one person's public key.
//
// This is the archive access control list. Removing a row stops the person
// obtaining the key again; it guarantees nothing about a copy they already
// unlocked, because the key was in their browser. Only an epoch rotation plus a
// re-seal is retroactive.
type Grant struct {
	TenantID  uuid.UUID
	DeviceID  uuid.UUID
	UserID    uuid.UUID
	Epoch     uint16
	SealedDSK []byte
}

// PutGrant records a sealed device key for one user.
func (k *Keys) PutGrant(ctx context.Context, g Grant, grantedBy *uuid.UUID) error {
	if len(g.SealedDSK) == 0 {
		return errors.New("store: a grant with no sealed key is not a grant")
	}
	return pg.InTenantTx(ctx, k.pool, g.TenantID.String(), func(tx pgx.Tx) error {
		var member uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT m.user_id FROM workspace_memberships m JOIN users u ON u.id=m.user_id
			WHERE m.tenant_id=$1 AND m.user_id=$2 AND m.status='active' AND u.status='active' FOR SHARE OF m`, g.TenantID, g.UserID).Scan(&member); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO device_key_grants
			       (tenant_id, device_id, user_id, epoch, sealed_dsk, granted_by)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (user_id, device_id, epoch) DO UPDATE
			   SET sealed_dsk = EXCLUDED.sealed_dsk`,
			g.TenantID, g.DeviceID, g.UserID, int32(g.Epoch), g.SealedDSK, grantedBy)
		return err
	})
}

// GrantsFor returns every device key one user may open.
//
// The reply is what a browser turns into a set of readable accounts: no grant,
// no key, and the archive stays closed however the server behaves.
func (k *Keys) GrantsFor(ctx context.Context, tenant, user uuid.UUID) ([]Grant, error) {
	var out []Grant
	err := pg.InTenantTx(ctx, k.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT g.device_id, g.epoch, g.sealed_dsk
			  FROM device_key_grants g
			  JOIN devices d ON d.id = g.device_id AND d.current_epoch = g.epoch
			 WHERE g.user_id = $1
			 ORDER BY d.created_at`, user)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			g := Grant{TenantID: tenant, UserID: user}
			var epoch int32
			if err := rows.Scan(&g.DeviceID, &epoch, &g.SealedDSK); err != nil {
				return err
			}
			if epoch < 1 || epoch > maxEpoch {
				return fmt.Errorf("store: grant epoch %d is out of range", epoch)
			}
			g.Epoch = uint16(epoch)
			out = append(out, g)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("store: list grants: %w", err)
	}
	return out, nil
}

// HasGrant reports whether an account holds this device's key for the
// current epoch — that is, whether the device is readable to them at all.
func (k *Keys) HasGrant(ctx context.Context, tenant, device, user uuid.UUID) (bool, error) {
	var has bool
	err := pg.InTenantTx(ctx, k.pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM device_key_grants g
				  JOIN devices d ON d.id = g.device_id AND d.current_epoch = g.epoch
				 WHERE g.device_id = $1 AND g.user_id = $2)`, device, user).Scan(&has)
	})
	if err != nil {
		return false, fmt.Errorf("store: has grant: %w", err)
	}
	return has, nil
}

// RevokeGrant removes one user's access to one device.
func (k *Keys) RevokeGrant(ctx context.Context, tenant, device, user uuid.UUID) error {
	return pg.InTenantTx(ctx, k.pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`DELETE FROM device_key_grants WHERE device_id = $1 AND user_id = $2`, device, user)
		return err
	})
}

// KeyHolder is one account that can open a device's archive.
//
// Named apart from Reader, which in this package means somebody who read a
// message. The two words are the same in English and nothing alike here.
//
// This is the access control list, read back. It is worth showing plainly
// because the guarantee it describes is unusual: removing somebody from this
// list stops them OBTAINING the key again. It does not reach into a browser
// where they already unlocked one. An operator deciding whether that is enough
// needs to see who is on the list, not be told it was handled.
type KeyHolder struct {
	UserID    uuid.UUID
	Email     string
	Role      string
	Epoch     uint16
	GrantedAt time.Time
	// GrantedBy is the address of whoever sealed it, empty when it was sealed
	// by a command-line tool or by an account since deleted.
	GrantedBy string
}

// Readers lists the accounts holding a grant for one device.
func (k *Keys) Readers(ctx context.Context, tenant, device uuid.UUID) ([]KeyHolder, error) {
	var out []KeyHolder
	err := pg.InTenantTx(ctx, k.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT u.id, u.email, m.role, g.epoch, g.created_at,
			       coalesce(b.email, '')
			  FROM device_key_grants g
			  JOIN users u ON u.id = g.user_id
			  JOIN workspace_memberships m ON m.user_id=g.user_id AND m.tenant_id=g.tenant_id
			  LEFT JOIN users b ON b.id = g.granted_by
			 WHERE g.device_id = $1
			 ORDER BY u.email`, device)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r KeyHolder
			var epoch int32
			if err := rows.Scan(&r.UserID, &r.Email, &r.Role, &epoch,
				&r.GrantedAt, &r.GrantedBy); err != nil {
				return err
			}
			if epoch < 1 || epoch > maxEpoch {
				return fmt.Errorf("store: grant epoch %d is out of range", epoch)
			}
			r.Epoch = uint16(epoch)
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("store: list readers: %w", err)
	}
	return out, nil
}

// contentKeyLock derives an advisory lock key scoped to one device's counter.
func contentKeyLock(device uuid.UUID) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("content_key_counter:"))
	_, _ = h.Write(device[:])
	// Reinterpreting bits rather than narrowing a value: advisory lock keys are
	// an opaque 64-bit space and a negative key is as valid as a positive one.
	//nolint:gosec // G115: intentional bit reinterpretation
	return int64(h.Sum64())
}
