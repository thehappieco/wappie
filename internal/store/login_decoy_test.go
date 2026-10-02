package store_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"

	"github.com/google/uuid"

	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
)

// The challenge answers an address with no password with a made-up salt. If
// anybody could compute that salt from the address, comparing it with the
// server's answer would say whether the address has an account: a match means
// none. So the decoy is keyed with a server secret, stays put for one server,
// and differs between two servers with different secrets.
func TestTheLoginDecoyIsKeyedByTheServer(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	tenant := uuid.MustParse(newTenant(t, pool, "acme"))

	service, err := store.NewUsers(pool).CreateService(ctx, tenant, "erp", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	salt := bytes.Repeat([]byte{7}, 16)
	if _, err := store.NewUsers(pool).Create(ctx, store.NewUser{
		TenantID: tenant, Email: "known@example.com", Role: "owner", AuthKey: "k",
		KDFSalt: salt, KDFParams: store.DefaultKDFParams(),
		PublicKey: make([]byte, 32), WrappedUSK: []byte("wrapped"),
	}); err != nil {
		t.Fatal(err)
	}

	// Two servers over the same database, each with its own secret.
	one, two := store.NewUsers(pool), store.NewUsers(pool)
	if err := one.SetLoginDecoyKey(bytes.Repeat([]byte{1}, 32)); err != nil {
		t.Fatal(err)
	}
	if err := two.SetLoginDecoyKey(bytes.Repeat([]byte{2}, 32)); err != nil {
		t.Fatal(err)
	}
	challenge := func(u *store.Users, email string) []byte {
		t.Helper()
		got, params, err := u.Challenge(ctx, email)
		if err != nil {
			t.Fatal(err)
		}
		if params != store.DefaultKDFParams() {
			t.Fatalf("%s: params %+v, want the defaults", email, params)
		}
		return got
	}

	// A missing address and a service account are both answered with a decoy.
	for _, email := range []string{"ghost@example.com", service.Email} {
		unkeyed := sha256.Sum256([]byte("whatserver2/login-decoy/" + email))
		first := challenge(one, email)
		switch {
		case len(first) != 16:
			t.Errorf("%s: a decoy of %d bytes, want 16 like a real salt", email, len(first))
		case bytes.Equal(first, unkeyed[:16]):
			t.Errorf("%s: the decoy is the unkeyed hash of the address, which anybody can compute", email)
		case !bytes.Equal(first, challenge(one, email)):
			t.Errorf("%s: the decoy changes between requests to one server", email)
		case bytes.Equal(first, challenge(two, email)):
			t.Errorf("%s: two servers with different secrets give the same decoy", email)
		}
	}

	// A Users nobody gave a key still keys its decoys, just not across restarts.
	unkeyed := sha256.Sum256([]byte("whatserver2/login-decoy/ghost@example.com"))
	if bytes.Equal(challenge(store.NewUsers(pool), "ghost@example.com"), unkeyed[:16]) {
		t.Error("without a configured key the decoy falls back to the unkeyed hash")
	}

	// A real account's salt is its own whatever the key.
	if got := challenge(one, "known@example.com"); !bytes.Equal(got, salt) {
		t.Errorf("a real account's challenge returned %x, want its salt", got)
	}
	if got := challenge(two, "known@example.com"); !bytes.Equal(got, salt) {
		t.Errorf("a real account's challenge depends on the decoy key: %x", got)
	}

	for _, size := range []int{1, 16, 31, 33, 64} {
		if err := one.SetLoginDecoyKey(make([]byte, size)); err == nil {
			t.Errorf("accepted a %d-byte decoy key", size)
		}
	}
}
