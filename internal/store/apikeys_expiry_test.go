package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
)

// A key with a deadline is refused by the same lookup that refuses a revoked
// one, and takes the same path on a miss, so the response time says nothing
// about why.
func TestVerifyScopedRefusesExpired(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	keys := store.NewAPIKeys(pool)
	ctx := context.Background()
	tenant := newTenant(t, pool, "acme")

	in := time.Now().Add(time.Hour)
	key, err := keys.IssueActingAsForDevices(ctx, tenant, "hosted", store.ScopeRead, nil, nil, nil, &in)
	if err != nil {
		t.Fatal(err)
	}
	forever, err := keys.Issue(ctx, tenant, "ci")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keys.VerifyScoped(ctx, key); err != nil {
		t.Fatalf("a key an hour from its deadline was refused: %v", err)
	}
	prefix, _, _ := strings.Cut(key, ".")
	if _, err := pool.Exec(ctx, `UPDATE api_keys SET expires_at = now() - interval '1 second' WHERE prefix = $1`, prefix); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.VerifyScoped(ctx, key); !errors.Is(err, store.ErrInvalidKey) {
		t.Fatalf("an expired key still authenticates: %v", err)
	}
	if _, err := keys.Verify(ctx, forever); err != nil {
		t.Fatalf("a key with no deadline was refused: %v", err)
	}
	listed, err := keys.List(ctx, tenant)
	if err != nil || len(listed) != 2 {
		t.Fatalf("list = %+v %v", listed, err)
	}
	for _, k := range listed {
		if (k.Prefix == prefix) != (k.ExpiresAt != nil) {
			t.Errorf("%s: expires_at = %v", k.Prefix, k.ExpiresAt)
		}
	}
}

// A live socket revalidates its key without the secret; the deadline applies
// there too, or an expired key would keep an open connection alive.
func TestConnectionKeyRefusesExpired(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	keys := store.NewAPIKeys(pool)
	ctx := context.Background()
	tenant := newTenant(t, pool, "acme")

	in := time.Now().Add(time.Hour)
	key, err := keys.IssueActingAsForDevices(ctx, tenant, "hosted", store.ScopeRead, nil, nil, nil, &in)
	if err != nil {
		t.Fatal(err)
	}
	v, err := keys.VerifyScoped(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.ConnectionKey(ctx, v.ID, tenant, v.Scope, uuid.Nil, v.AccessVersion); err != nil {
		t.Fatalf("live key refused: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE api_keys SET expires_at = now() - interval '1 second' WHERE id = $1`, v.ID); err != nil {
		t.Fatal(err)
	}
	if err := keys.ConnectionKey(ctx, v.ID, tenant, v.Scope, uuid.Nil, v.AccessVersion); !errors.Is(err, store.ErrInvalidKey) {
		t.Fatalf("an expired key kept its socket: %v", err)
	}
}

func TestIssueRejectsFarExpiry(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	keys := store.NewAPIKeys(pool)
	ctx := context.Background()
	tenant := newTenant(t, pool, "acme")

	for name, at := range map[string]time.Time{
		"past":     time.Now().Add(-time.Second),
		"now":      time.Now(),
		"366 days": time.Now().Add(366 * 24 * time.Hour),
	} {
		t.Run(name, func(t *testing.T) {
			at := at
			if _, err := keys.IssueActingAsForDevices(ctx, tenant, name, store.ScopeRead, nil, nil, nil, &at); !errors.Is(err, store.ErrInvalidExpiry) {
				t.Fatalf("err = %v, want ErrInvalidExpiry", err)
			}
		})
	}
	edge := time.Now().Add(365*24*time.Hour - time.Minute)
	if _, err := keys.IssueActingAsForDevices(ctx, tenant, "a year", store.ScopeRead, nil, nil, nil, &edge); err != nil {
		t.Fatalf("a deadline just inside the cap was refused: %v", err)
	}
	listed, err := keys.List(ctx, tenant)
	if err != nil || len(listed) != 1 {
		t.Fatalf("refused deadlines left keys behind: %+v %v", listed, err)
	}
}

// A consent promotes a key's deadline and never shortens it. The store does
// this inside Create, so that is the door it is tested through.
func TestExtendExpiryOnlyForward(t *testing.T) {
	f := newMCPFixture(t)
	ctx := context.Background()

	_, prefix := f.provisionalKey(ctx, t, "forward")
	in := consent(prefix)
	in.ExpiresAt = time.Now().Add(30 * 24 * time.Hour)
	if _, err := f.conns.Create(ctx, f.tenant, f.owner, in); err != nil {
		t.Fatal(err)
	}
	keys, err := f.keys.List(ctx, f.tenant.String())
	if err != nil || len(keys) != 1 || keys[0].ExpiresAt == nil || keys[0].ExpiresAt.Sub(in.ExpiresAt) > time.Second {
		t.Fatalf("keys = %+v %v", keys, err)
	}

	// A key whose deadline is already past the consent has nothing to extend:
	// the consent is refused and leaves no row. The key is still a
	// provisional one — a longer deadline would be refused as unsuitable
	// before the extension is even tried — so the consent is the short side.
	far := time.Now().Add(25 * time.Minute)
	key, err := f.keys.IssueActingAsForDevices(ctx, f.tenant.String(), "already long", store.ScopeRead, &f.owner, nil, []uuid.UUID{f.device}, &far)
	if err != nil {
		t.Fatal(err)
	}
	prefix, _, _ = strings.Cut(key, ".")
	shorter := consent(prefix)
	shorter.ExpiresAt = time.Now().Add(10 * time.Minute)
	if _, err := f.conns.Create(ctx, f.tenant, f.owner, shorter); !errors.Is(err, store.ErrInvalidKey) {
		t.Fatalf("a deadline was shortened: %v", err)
	}
	if listed, err := f.conns.List(ctx, f.tenant); err != nil || len(listed) != 1 {
		t.Fatalf("refused consent left a row: %+v %v", listed, err)
	}
	keys, _ = f.keys.List(ctx, f.tenant.String())
	for _, k := range keys {
		if k.Prefix == prefix && (k.ExpiresAt == nil || k.ExpiresAt.Sub(far) > time.Second || far.Sub(*k.ExpiresAt) > time.Second) {
			t.Fatalf("the long deadline moved: %v", k.ExpiresAt)
		}
	}
}
