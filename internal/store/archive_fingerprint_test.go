package store_test

import (
	"strings"
	"testing"

	"whatserver2/internal/store"
)

// TestArchiveKeyFingerprint pins the fingerprint's format (DS49): the
// lowercase hex SHA-256 of the stored public key bytes, 64 characters, no
// prefix. Clients echo what the server gives, and step 7's token.grant uses
// the same helper, so a change here is a change of the wire.
func TestArchiveKeyFingerprint(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	for _, c := range []struct {
		key  []byte
		want string
	}{
		{make([]byte, 32), "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"},
		{key, "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd"},
	} {
		got := store.ArchiveKeyFingerprint(c.key)
		if got != c.want {
			t.Fatalf("fingerprint %s, want %s", got, c.want)
		}
		if !store.ValidArchiveKeyFingerprint(got) {
			t.Fatalf("%s is not valid", got)
		}
	}
	for _, bad := range []string{"", strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("A", 64),
		"sha256:" + strings.Repeat("a", 57), strings.Repeat("g", 64)} {
		if store.ValidArchiveKeyFingerprint(bad) {
			t.Fatalf("%q is valid", bad)
		}
	}
}
