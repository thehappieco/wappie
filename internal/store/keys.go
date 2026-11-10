package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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

// ArchiveTenant returns the immutable cryptographic namespace after authorizing
// the device under its current workspace. It grants no access to that old workspace.
func (k *Keys) ArchiveTenant(ctx context.Context, tenant, device uuid.UUID) (uuid.UUID, error) {
	var archive uuid.UUID
	err := pg.InTenantTx(ctx, k.pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT archive_tenant_id FROM devices WHERE id=$1 AND tenant_id=$2`, device, tenant).Scan(&archive)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrNotFound
	}
	return archive, err
}

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
//
// It tells every process at its commit (ArchiveKeyChannel): after a reset
// the new key may take the old one's epoch, and a running server would
// otherwise keep sealing to the old key (DS49).
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
		return notifyArchiveKeyTx(ctx, tx, tenant, &device)
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
//
// It checks nothing of the key sealFn seals to. Ingest uses
// CreateContentKeyFor.
func (k *Keys) CreateContentKey(ctx context.Context, tenant, device uuid.UUID, epoch uint16,
	sealFn func(id uint32) ([]byte, error)) (uint32, error) {
	return k.createContentKey(ctx, tenant, device, epoch, nil, sealFn)
}

// ErrArchiveKeyChanged means a number's archive key is not the one a write
// was made for. It was deleted (reset-archive), or replaced at the same
// epoch (device-key after reset-archive -keep-devices). A content key
// sealed to the old key, or a grant of it, would be filed as the new key's
// and open nothing (DS49).
var ErrArchiveKeyChanged = errors.New("store: the number's archive key changed")

// CreateContentKeyFor is CreateContentKey for a sealer that seals to pub. It
// makes the content key only while pub is still the number's current
// archive key at epoch, read in the same transaction, else
// ErrArchiveKeyChanged.
//
// The transaction takes the workspace's tenants row (FOR KEY SHARE, which
// the content key's own foreign key takes anyway) before it reads the key.
// A reset holds that row (FOR UPDATE) from before its deletes to its
// commit, so the read sees the key either before the reset or after it.
// Without it a reset and a device-key could commit between the read and
// the insert, and the insert's foreign key would find the new key's row.
func (k *Keys) CreateContentKeyFor(ctx context.Context, tenant, device uuid.UUID, epoch uint16,
	pub seal.PublicKey, sealFn func(id uint32) ([]byte, error)) (uint32, error) {
	if !pub.Valid() {
		return 0, errors.New("store: a content key needs the archive key it is sealed to")
	}
	return k.createContentKey(ctx, tenant, device, epoch, pub.Bytes(), sealFn)
}

// createContentKey is CreateContentKey, with pub's check when pub is set.
func (k *Keys) createContentKey(ctx context.Context, tenant, device uuid.UUID, epoch uint16,
	pub []byte, sealFn func(id uint32) ([]byte, error)) (uint32, error) {
	var id uint32
	err := pg.InTenantTx(ctx, k.pool, tenant.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, contentKeyLock(device)); err != nil {
			return fmt.Errorf("store: lock content key counter: %w", err)
		}
		if pub != nil {
			if err := currentArchiveKeyIsTx(ctx, tx, tenant, device, epoch, pub); err != nil {
				return err
			}
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

// currentArchiveKeyIsTx returns ErrArchiveKeyChanged unless pub at epoch
// is device's current archive key, not retired. It takes the tenants row
// first (FOR KEY SHARE), so a reset is wholly before it or wholly after.
func currentArchiveKeyIsTx(ctx context.Context, tx pgx.Tx, tenant, device uuid.UUID, epoch uint16, pub []byte) error {
	var id uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM tenants WHERE id = $1 FOR KEY SHARE`, tenant).Scan(&id); err != nil {
		return fmt.Errorf("store: lock the workspace for a content key: %w", err)
	}
	var stored []byte
	err := tx.QueryRow(ctx, `
		SELECT k.public_key
		  FROM device_archive_keys k
		  JOIN devices d ON d.id = k.device_id AND d.current_epoch = k.epoch
		 WHERE k.device_id = $1 AND k.epoch = $2 AND k.retired_at IS NULL`, device, int32(epoch)).Scan(&stored)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: device %s has no current key at epoch %d", ErrArchiveKeyChanged, device, epoch)
	}
	if err != nil {
		return fmt.Errorf("store: read the archive key: %w", err)
	}
	if !bytes.Equal(stored, pub) {
		return fmt.Errorf("%w: device %s has another key at epoch %d", ErrArchiveKeyChanged, device, epoch)
	}
	return nil
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
	ArchiveTenantID uuid.UUID
	TenantID        uuid.UUID
	DeviceID        uuid.UUID
	UserID          uuid.UUID
	Epoch           uint16
	SealedDSK       []byte
	// Fingerprint names the archive key SealedDSK is (ArchiveKeyFingerprint).
	// PutGrant requires it, and GrantsFor gives the stored key's (DS49).
	Fingerprint string
}

// ErrGrantFingerprint is a grant that names no archive key fingerprint, or
// one not in ArchiveKeyFingerprint's form.
var ErrGrantFingerprint = errors.New("store: a grant must name its archive key's fingerprint")

// PutGrant records a sealed device key for one user. A live connection's
// own account takes only a number its key names and its person reads
// (ErrConnectionAccountGrant, DS48): grant.add, a pairing's grants and the
// command line's device-key alike.
//
// The grant names the archive key it was sealed for (g.Fingerprint), and
// PutGrant compares it with the number's key at g.Epoch in the same
// transaction: ErrArchiveKeyChanged for another key or none (DS49). The
// epoch alone cannot say: after reset-archive -keep-devices, device-key
// gives the number a new key at epoch 1 again, and a grant sealed with
// the old key would be recorded as Read and open nothing. The transaction
// holds the workspace's tenants row from before the comparison to its
// commit, and a reset takes that row before its deletes, so a reset is
// wholly before the comparison or wholly after the grant.
func (k *Keys) PutGrant(ctx context.Context, g Grant, grantedBy *uuid.UUID) error {
	if len(g.SealedDSK) == 0 {
		return errors.New("store: a grant with no sealed key is not a grant")
	}
	if !ValidArchiveKeyFingerprint(g.Fingerprint) {
		return ErrGrantFingerprint
	}
	return pg.InTenantTx(ctx, k.pool, g.TenantID.String(), func(tx pgx.Tx) error {
		if err := lockWorkspaceAccess(ctx, tx, g.TenantID); err != nil {
			return err
		}
		if err := grantableTx(ctx, tx, g.TenantID, g.DeviceID, g.UserID); err != nil {
			return err
		}
		if err := grantKeyIsTx(ctx, tx, g.DeviceID, g.Epoch, g.Fingerprint); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO device_key_grants
			       (tenant_id, device_id, user_id, epoch, sealed_dsk, granted_by)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (user_id, device_id, epoch) DO UPDATE
			   SET sealed_dsk = EXCLUDED.sealed_dsk`,
			g.TenantID, g.DeviceID, g.UserID, int32(g.Epoch), g.SealedDSK, grantedBy)
		return numberGone(err)
	})
}

// CheckGrant runs PutGrant's checks of user on device and writes nothing:
// ErrNotFound for an account that is not an active, unexpired member, and
// ErrConnectionAccountGrant for a live connection's own account on a
// number its consent does not cover. device-key asks it of every account
// before it makes the number's key, so a refusal leaves no key that
// nobody holds. PutGrant asks again under the workspace's lock.
func (k *Keys) CheckGrant(ctx context.Context, tenant, device, user uuid.UUID) error {
	return pg.InTenantTx(ctx, k.pool, tenant.String(), func(tx pgx.Tx) error {
		return grantableTx(ctx, tx, tenant, device, user)
	})
}

// grantKeyIsTx returns ErrArchiveKeyChanged unless device's archive key
// at epoch, not retired, has fingerprint. A number this workspace no
// longer sees (moved to Personal, or deleted) is ErrNumberGone, as the
// insert's ownership trigger would answer.
func grantKeyIsTx(ctx context.Context, tx pgx.Tx, device uuid.UUID, epoch uint16, fingerprint string) error {
	var stored []byte
	err := tx.QueryRow(ctx, `SELECT public_key FROM device_archive_keys
		WHERE device_id = $1 AND epoch = $2 AND retired_at IS NULL`, device, int32(epoch)).Scan(&stored)
	if errors.Is(err, pgx.ErrNoRows) {
		var here bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM devices WHERE id = $1)`, device).Scan(&here); err != nil {
			return fmt.Errorf("store: read the number: %w", err)
		}
		if !here {
			return ErrNumberGone
		}
		return fmt.Errorf("%w: device %s has no key at epoch %d", ErrArchiveKeyChanged, device, epoch)
	}
	if err != nil {
		return fmt.Errorf("store: read the archive key: %w", err)
	}
	if ArchiveKeyFingerprint(stored) != fingerprint {
		return fmt.Errorf("%w: the grant is for another key than device %s's at epoch %d", ErrArchiveKeyChanged, device, epoch)
	}
	return nil
}

// ArchiveKeyFingerprintAt returns the fingerprint of device's archive key
// at epoch, not retired, or ErrNoArchiveKey: what a grant sealed for that
// key names. For a tool or a test that grants a key it did not make.
func (k *Keys) ArchiveKeyFingerprintAt(ctx context.Context, tenant, device uuid.UUID, epoch uint16) (string, error) {
	var stored []byte
	err := pg.InTenantTx(ctx, k.pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT public_key FROM device_archive_keys
			WHERE device_id = $1 AND epoch = $2 AND retired_at IS NULL`, device, int32(epoch)).Scan(&stored)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("%w: %s at epoch %d", ErrNoArchiveKey, device, epoch)
	}
	if err != nil {
		return "", fmt.Errorf("store: read the archive key: %w", err)
	}
	return ArchiveKeyFingerprint(stored), nil
}

// grantableTx is PutGrant's checks of user on device.
func grantableTx(ctx context.Context, tx pgx.Tx, tenant, device, user uuid.UUID) error {
	var member uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT m.user_id FROM workspace_memberships m JOIN users u ON u.id=m.user_id
		WHERE m.tenant_id=$1 AND m.user_id=$2 AND m.status='active' AND u.status='active' AND (m.expires_at IS NULL OR m.expires_at > now()) FOR SHARE OF m`, tenant, user).Scan(&member); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	return connectionAccountTakesTx(ctx, tx, tenant, user, device)
}

// ErrNumberGone is a write for a number that left the workspace while it
// waited for the workspace's lock: moved to Personal (0036's ownership
// trigger raises WS002), or deleted.
var ErrNumberGone = errors.New("store: this number is no longer in this workspace")

// numberGone turns the ownership trigger's WS002 into ErrNumberGone.
func numberGone(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "WS002" {
		return ErrNumberGone
	}
	return err
}

// GrantsFor returns every device key one user may open.
//
// The reply is what a browser turns into a set of readable accounts: no grant,
// no key, and the archive stays closed however the server behaves. Each
// grant carries its key's fingerprint, which a client echoes when it seals
// the key to someone else (grant.add, DS49).
func (k *Keys) GrantsFor(ctx context.Context, tenant, user uuid.UUID) ([]Grant, error) {
	var out []Grant
	err := pg.InTenantTx(ctx, k.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT g.device_id, g.epoch, g.sealed_dsk, d.archive_tenant_id, k.public_key
			  FROM device_key_grants g
			  JOIN devices d ON d.id = g.device_id AND d.current_epoch = g.epoch AND d.deleted_at IS NULL
			  JOIN device_archive_keys k ON k.device_id = g.device_id AND k.epoch = g.epoch
			 WHERE g.user_id = $1
			 ORDER BY d.created_at`, user)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			g := Grant{TenantID: tenant, UserID: user}
			var epoch int32
			var pub []byte
			if err := rows.Scan(&g.DeviceID, &epoch, &g.SealedDSK, &g.ArchiveTenantID, &pub); err != nil {
				return err
			}
			g.Fingerprint = ArchiveKeyFingerprint(pub)
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
				  JOIN devices d ON d.id = g.device_id AND d.current_epoch = g.epoch AND d.deleted_at IS NULL
				 WHERE g.device_id = $1 AND g.user_id = $2)`, device, user).Scan(&has)
	})
	if err != nil {
		return false, fmt.Errorf("store: has grant: %w", err)
	}
	return has, nil
}

// RevokeGrant is RevokeGrantEnded without the list. It may end
// connections, and nobody tells their readers but the 30-second re-tell.
// Code that serves a person's act calls RevokeGrantEnded and tells them,
// as the socket's grant.revoke does.
func (k *Keys) RevokeGrant(ctx context.Context, tenant, actor, device, user uuid.UUID) error {
	_, err := k.RevokeGrantEnded(ctx, tenant, actor, device, user)
	return err
}

// RevokeGrantEnded is the socket's grant.revoke: actor removes user's
// grants on device, at every epoch, so a revoke that deleted one leaves
// none at the number's current epoch. It returns the connections it ended,
// for their readers to be told after the commit.
//
// Who: actor's role is read again under the tenants row
// (lockWorkspaceManager), since a session's role can be stale: an owner or
// an admin, active, in an active workspace, else ErrMembershipForbidden.
// Only an owner changes an owner's access (DS18, the platform's 0060): an
// admin whose target ownerTargetTx reads as an owner, fail-closed, is
// refused with ErrOwnerTarget before anything else is checked or deleted,
// a live grant or a dormant one alike.
//
// What ends (DS48), in the same transaction, whole and access_lost:
//   - when user has the Read flag, the revoke takes their Read though the
//     flag stays, and ends their own connections and integrations that held
//     the number (grantTakenTx, the platform's 0061);
//   - when user is a connection's own account (its service_user_id), that
//     connection, which the revoke would otherwise narrow.
//
// A revoke that finds no grant, or deletes a dormant one (no Read flag) of
// a person, ends nothing; a refusal (ErrLastDeviceReader) changes nothing.
func (k *Keys) RevokeGrantEnded(ctx context.Context, tenant, actor, device, user uuid.UUID) ([]EndedConnection, error) {
	var ended []EndedConnection
	err := pg.InTenantTx(ctx, k.pool, tenant.String(), func(tx pgx.Tx) error {
		role, err := lockWorkspaceManager(ctx, tx, tenant, actor)
		if err != nil {
			return err
		}
		if role != "owner" {
			owner, err := ownerTargetTx(ctx, tx, tenant, user)
			if err != nil {
				return err
			}
			if owner {
				return ErrOwnerTarget
			}
		}
		if err := requireRemainingReader(ctx, tx, tenant, user, &device); err != nil {
			return err
		}
		// A connection's own account: its connection is locked before its
		// rows are touched (the tenants row, then the connection, then its
		// own rows; reader_safety.go).
		named, err := namedConnectionTx(ctx, tx, tenant, user)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx,
			`DELETE FROM device_key_grants WHERE device_id = $1 AND user_id = $2`, device, user)
		if err != nil || tag.RowsAffected() == 0 {
			return err
		}
		for _, c := range named {
			if _, err := endMCPConnectionTx(ctx, tx, tenant, c.ID, statusRevoked, ReasonAccessLost); err != nil {
				return err
			}
		}
		own, err := grantTakenTx(ctx, tx, tenant, user, device)
		ended = append(named, own...)
		return err
	})
	if err != nil {
		return nil, err
	}
	return ended, nil
}

// namedConnectionTx locks the live connection that names user as its own
// account (service_user_id, unique), if there is one. The caller holds the
// tenants row lock.
func namedConnectionTx(ctx context.Context, tx pgx.Tx, tenant, user uuid.UUID) ([]EndedConnection, error) {
	rows, err := tx.Query(ctx, `SELECT id::text, reader FROM mcp_connections
		WHERE tenant_id = $1 AND service_user_id = $2 AND status IN ('pending', 'active', 'reseal')
		ORDER BY id FOR UPDATE`, tenant, user)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (EndedConnection, error) {
		var c EndedConnection
		err := row.Scan(&c.ID, &c.Reader)
		return c, err
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
			       coalesce(former.email, b.email, '')
			  FROM device_key_grants g
			  JOIN users u ON u.id = g.user_id
			  JOIN workspace_memberships m ON m.user_id=g.user_id AND m.tenant_id=g.tenant_id
			  LEFT JOIN users b ON b.id = g.granted_by
			  LEFT JOIN workspace_member_history former ON former.tenant_id=g.tenant_id AND former.user_id=g.granted_by
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
