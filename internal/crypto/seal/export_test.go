package seal

import (
	"time"

	"github.com/google/uuid"
	kit "github.com/thehappieco/kit/seal"
)

// NewSealerWithClockForTest builds a sealer whose clock the test controls, so
// age-based rotation can be tested without waiting fifteen minutes.
// Test-only: defined in a _test file so it is not part of the package's API.
func NewSealerWithClockForTest(tenant, device uuid.UUID, pub PublicKey, epoch uint16, store KeyStore, now func() time.Time) (*Sealer, error) {
	return kit.NewSealer[Kind](store, tenant, tenant, device, pub, epoch, kit.WithClock(now))
}
