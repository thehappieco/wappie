package seal

import (
	"github.com/google/uuid"
	kit "github.com/thehappieco/kit/seal"
)

// Rotation limits for a content key.
const (
	// MaxSealsPerKey bounds how many values one content key covers. Chosen so
	// that losing a key to a memory-disclosure bug exposes a bounded window,
	// while keeping the asymmetric work a client does on open negligible: a
	// hundred thousand messages come out to roughly a hundred unwraps.
	MaxSealsPerKey = kit.MaxSealsPerKey

	// MaxKeyAge bounds the same window in time, for a quiet tenant where the
	// count alone would keep one key alive for weeks.
	MaxKeyAge = kit.MaxKeyAge
)

// KeyStore persists sealed content keys (internal/store's Keys).
//
// An interface so this package stays free of any database dependency, and so
// the rotation logic can be tested without one. CreateContentKey takes a
// callback because a content key's sealed form binds to its own id, which is
// only known once the store has allocated it: the store allocates inside its
// transaction, asks the caller to seal, and commits both together.
type KeyStore = kit.KeyStore

// Sealer seals content for one device.
//
// One per device rather than one per tenant, because the archive key is per
// device: the whole point is that a reader holding one device's key cannot open
// another's. Rotation happens under the same lock as sealing, so a key can
// never be used past its limit by a racing caller.
type Sealer = kit.Sealer[Kind]

// NewSealer builds a sealer for one device at one epoch.
func NewSealer(tenant, device uuid.UUID, pub PublicKey, epoch uint16, store KeyStore) (*Sealer, error) {
	return NewSealerWithArchiveTenant(tenant, tenant, device, pub, epoch, store)
}

// NewSealerWithArchiveTenant separates current storage authorization from the
// immutable cryptographic namespace, preserving ciphertext after a workspace move.
func NewSealerWithArchiveTenant(tenant, archiveTenant, device uuid.UUID, pub PublicKey, epoch uint16, store KeyStore) (*Sealer, error) {
	return kit.NewSealer[Kind](store, tenant, archiveTenant, device, pub, epoch)
}
