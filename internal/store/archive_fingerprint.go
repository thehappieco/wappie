package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ArchiveKeyFingerprintLen is the length of an archive key's fingerprint.
const ArchiveKeyFingerprintLen = 2 * sha256.Size

// ArchiveKeyFingerprint names one archive public key: the lowercase hex
// SHA-256 of the key's stored bytes (device_archive_keys.public_key, the
// 32 raw X25519 bytes). It is 64 characters, with no prefix.
//
// A grant names the key it was sealed for by this, because an epoch does
// not name a key: after reset-archive -keep-devices, device-key gives the
// number a new key at epoch 1 again (DS49). This is the one definition.
// Every grant write, every grant context and token.grant use it.
func ArchiveKeyFingerprint(publicKey []byte) string {
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:])
}

// ValidArchiveKeyFingerprint reports whether s has ArchiveKeyFingerprint's
// form: 64 lowercase hex characters.
func ValidArchiveKeyFingerprint(s string) bool {
	if len(s) != ArchiveKeyFingerprintLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// ErrArchiveKeyChanged means a number's archive key is not the one a write
// was made for. It was deleted (reset-archive), or replaced at the same
// epoch (device-key after reset-archive -keep-devices). A content key
// sealed to the old key, a value sealed under one, or a grant of it, would
// be filed as the new key's and open nothing (DS49).
var ErrArchiveKeyChanged = errors.New("store: the number's archive key changed")

// archiveKeyIsTx is every grant write's check (PutGrant, and step 7's
// token grant): device's archive key at epoch, not retired, has the
// fingerprint fp. Another key is ErrArchiveKeyChanged. No key at all is
// both ErrArchiveKeyChanged and ErrNoArchiveKey, so either test finds it.
// A number this workspace no longer sees (moved to Personal, or deleted)
// is ErrNumberGone, as the insert's ownership trigger would answer.
//
// The caller holds the workspace's row (lockWorkspaceAccess). Every write
// to device_archive_keys takes that row too (0036's archive_owner_lock),
// and a reset takes it first, so the key read here is still the key when
// the grant's insert meets it.
func archiveKeyIsTx(ctx context.Context, tx pgx.Tx, device uuid.UUID, epoch uint16, fp string) error {
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
		return fmt.Errorf("%w: %w: device %s at epoch %d", ErrArchiveKeyChanged, ErrNoArchiveKey, device, epoch)
	}
	if err != nil {
		return fmt.Errorf("store: read the archive key: %w", err)
	}
	if ArchiveKeyFingerprint(stored) != fp {
		return fmt.Errorf("%w: the grant is for another key than device %s's at epoch %d", ErrArchiveKeyChanged, device, epoch)
	}
	return nil
}
