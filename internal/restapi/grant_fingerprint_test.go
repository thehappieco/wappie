package restapi_test

import (
	"testing"

	"github.com/google/uuid"

	"whatserver2/internal/store"
)

// grantFingerprint is the fingerprint of the number's archive key at
// epoch, which every grant names (DS49).
func grantFingerprint(t testing.TB, keys *store.Keys, tenant, device uuid.UUID, epoch uint16) string {
	t.Helper()
	fp, err := keys.ArchiveKeyFingerprintAt(t.Context(), tenant, device, epoch)
	if err != nil {
		t.Fatal(err)
	}
	return fp
}
