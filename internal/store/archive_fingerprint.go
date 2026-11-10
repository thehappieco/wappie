package store

import (
	"crypto/sha256"
	"encoding/hex"
)

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
	if len(s) != 2*sha256.Size {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
