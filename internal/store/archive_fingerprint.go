package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// A number's archive key, named by its fingerprint (the platform's answer of
// 2026-11-10, W46 7929b4a). After reset-archive -keep-devices and
// device-key, a number's new archive key takes epoch 1 again. So the epoch
// number alone cannot tell a grant sealed to the old key from one sealed to
// the new: a grant must also name the key, and the write compares it with
// the stored key in its own transaction.

// ArchiveKeyFingerprintLen is the length of an archive key's fingerprint.
const ArchiveKeyFingerprintLen = 2 * sha256.Size

// ArchiveKeyFingerprint is the fingerprint of a number's archive public key:
// the lowercase hex of the SHA-256 of its stored bytes (64 characters).
func ArchiveKeyFingerprint(pub []byte) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// ValidArchiveKeyFingerprint reports whether s has a fingerprint's shape:
// 64 lowercase hex characters.
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

// ErrArchiveKeyChanged is a grant whose fingerprint is not that of the
// number's archive key at the grant's epoch: it was sealed to another key,
// such as the key an archive reset deleted.
var ErrArchiveKeyChanged = errors.New("store: this grant was sealed for another archive key of the number")

// archiveKeyIsTx checks that device's archive key at epoch, not retired, has
// the fingerprint fp. It answers ErrNoArchiveKey when there is no such key,
// and ErrArchiveKeyChanged when the key is another.
//
// The caller holds the workspace's row (lockWorkspaceAccess). Every write to
// device_archive_keys takes that row too (0036's archive_owner_lock), so the
// key read here is still the key when the grant's foreign key meets it at
// the insert.
func archiveKeyIsTx(ctx context.Context, tx pgx.Tx, device uuid.UUID, epoch uint16, fp string) error {
	var pub []byte
	err := tx.QueryRow(ctx, `SELECT public_key FROM device_archive_keys WHERE device_id = $1 AND epoch = $2 AND retired_at IS NULL`,
		device, int32(epoch)).Scan(&pub)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNoArchiveKey
	}
	if err != nil {
		return err
	}
	if ArchiveKeyFingerprint(pub) != fp {
		return ErrArchiveKeyChanged
	}
	return nil
}
