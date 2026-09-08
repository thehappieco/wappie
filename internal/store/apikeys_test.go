package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
)

func TestIssueAndVerify(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	keys := store.NewAPIKeys(pool)
	ctx := context.Background()
	tenant := newTenant(t, pool, "acme")

	key, err := keys.Issue(ctx, tenant, "ci")
	if err != nil {
		t.Fatal(err)
	}
	got, err := keys.Verify(ctx, key)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got != tenant {
		t.Errorf("tenant = %q, want %q", got, tenant)
	}
}

// The plaintext key exists exactly once, at issue. Only its hash is stored, so
// a database dump does not hand over working credentials.
func TestPlaintextKeyIsNotStored(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	keys := store.NewAPIKeys(pool)
	ctx := context.Background()
	tenant := newTenant(t, pool, "acme")

	key, err := keys.Issue(ctx, tenant, "ci")
	if err != nil {
		t.Fatal(err)
	}
	_, secret, _ := strings.Cut(key, ".")

	var stored string
	if err := pool.QueryRow(ctx, `SELECT key_hash FROM api_keys LIMIT 1`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, secret) {
		t.Fatal("the stored hash contains the secret")
	}
	if !strings.HasPrefix(stored, "$argon2id$") {
		t.Errorf("stored value is not an argon2id hash: %q", stored)
	}
}

// Every failure mode returns the same error. Distinguishing "unknown prefix"
// from "wrong secret" would let an attacker enumerate valid prefixes.
func TestEveryFailureLooksTheSame(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	keys := store.NewAPIKeys(pool)
	ctx := context.Background()
	tenant := newTenant(t, pool, "acme")

	valid, err := keys.Issue(ctx, tenant, "ci")
	if err != nil {
		t.Fatal(err)
	}
	prefix, _, _ := strings.Cut(valid, ".")

	for name, presented := range map[string]string{
		"empty":                      "",
		"no separator":               "abcdef0123456789",
		"unknown prefix":             "0000000a.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"right prefix, wrong secret": prefix + ".wrongwrongwrongwrongwrongwrongwrongwrong",
		"empty secret":               prefix + ".",
		"short prefix":               "abc.def",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := keys.Verify(ctx, presented); !errors.Is(err, store.ErrInvalidKey) {
				t.Fatalf("err = %v, want ErrInvalidKey", err)
			}
		})
	}
}

func TestRevokedKeyStopsWorking(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	keys := store.NewAPIKeys(pool)
	ctx := context.Background()
	tenant := newTenant(t, pool, "acme")

	key, err := keys.Issue(ctx, tenant, "ci")
	if err != nil {
		t.Fatal(err)
	}
	prefix, _, _ := strings.Cut(key, ".")

	if _, err := keys.Verify(ctx, key); err != nil {
		t.Fatal(err)
	}
	if err := keys.Revoke(ctx, tenant, prefix); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.Verify(ctx, key); !errors.Is(err, store.ErrInvalidKey) {
		t.Fatalf("a revoked key still authenticates: %v", err)
	}
	// Revoking twice is not an error worth hiding, but it is not a success.
	if err := keys.Revoke(ctx, tenant, prefix); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("second revoke: err = %v", err)
	}
}

// One tenant must not be able to revoke another's key.
func TestRevokeIsScopedToTheTenant(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	keys := store.NewAPIKeys(pool)
	ctx := context.Background()
	acme := newTenant(t, pool, "acme")
	globex := newTenant(t, pool, "globex")

	key, err := keys.Issue(ctx, acme, "ci")
	if err != nil {
		t.Fatal(err)
	}
	prefix, _, _ := strings.Cut(key, ".")

	if err := keys.Revoke(ctx, globex, prefix); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("globex revoked acme's key: %v", err)
	}
	if _, err := keys.Verify(ctx, key); err != nil {
		t.Fatalf("acme's key stopped working: %v", err)
	}
}

func TestKeysAreDistinct(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	keys := store.NewAPIKeys(pool)
	ctx := context.Background()
	tenant := newTenant(t, pool, "acme")

	seen := map[string]bool{}
	for range 5 {
		key, err := keys.Issue(ctx, tenant, "k")
		if err != nil {
			t.Fatal(err)
		}
		if seen[key] {
			t.Fatal("Issue returned a duplicate key")
		}
		seen[key] = true
	}
}
