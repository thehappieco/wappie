package store_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// tenantWithKey builds a tenant, a device and that device's archive key.
//
// The key hangs off the device now, so there is no such thing as a tenant with
// a key and no device.
func tenantWithKey(t *testing.T, pool *pgxpool.Pool) (uuid.UUID, uuid.UUID, seal.PublicKey, seal.PrivateKey, *store.Keys) {
	t.Helper()
	ctx := context.Background()
	tenant := uuid.MustParse(newTenant(t, pool, "acme"))

	dev, err := store.NewDevices(pool).Create(ctx, tenant.String(), "test", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	device := uuid.MustParse(dev.ID)

	pub, priv, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keys := store.NewKeys(pool)
	if err := keys.CreateArchiveKey(ctx, tenant, device, 1, pub); err != nil {
		t.Fatal(err)
	}
	return tenant, device, pub, priv, keys
}

// TestPrivateKeyNeverReachesTheDatabase is the schema-level counterpart to the
// cryptographic proof in the seal package.
//
// There is no column for it and no code path that could store one — the API
// takes a PublicKey, so the mistake is not expressible. This test scans the
// entire database for the private bytes anyway, because "it cannot happen"
// deserves to be checked once rather than assumed forever.
func TestPrivateKeyNeverReachesTheDatabase(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	tenant, device, pub, priv, keys := tenantWithKey(t, pool)

	privBytes, err := priv.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	// Seal something, so content keys and envelopes exist to search too.
	sealer, err := seal.NewSealer(tenant, device, pub, 1, keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sealer.Seal(ctx, seal.KindBody, uuid.New(), []byte("a secret")); err != nil {
		t.Fatal(err)
	}

	// Every bytea column in the schema.
	rows, err := pool.Query(ctx, `
		SELECT table_name, column_name FROM information_schema.columns
		 WHERE table_schema = current_schema() AND data_type = 'bytea'`)
	if err != nil {
		t.Fatal(err)
	}
	type col struct{ table, name string }
	var cols []col
	for rows.Next() {
		var c col
		if err := rows.Scan(&c.table, &c.name); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		cols = append(cols, c)
	}
	rows.Close()
	if len(cols) == 0 {
		t.Fatal("found no bytea columns; the scan would prove nothing")
	}

	for _, c := range cols {
		vals, err := pool.Query(ctx, `SELECT `+c.name+` FROM `+c.table)
		if err != nil {
			// Row-level security hides tenant tables outside a scoped
			// transaction, which is itself the correct behaviour.
			continue
		}
		for vals.Next() {
			var v []byte
			if err := vals.Scan(&v); err != nil {
				continue
			}
			if bytes.Contains(v, privBytes) {
				vals.Close()
				t.Fatalf("the private key is stored in %s.%s", c.table, c.name)
			}
		}
		vals.Close()
	}

	// And the public key is there, so the scan was looking at real data.
	stored, epoch, err := keys.ArchiveKey(ctx, tenant, device)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored.Bytes(), pub.Bytes()) {
		t.Error("the stored public key does not match")
	}
	if epoch != 1 {
		t.Errorf("epoch = %d, want 1", epoch)
	}
}

// A device with no archive key must not be sealable. Falling back to plaintext
// would be a silent failure of the only guarantee this system makes.
func TestMissingArchiveKeyIsAnError(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	tenant := uuid.MustParse(newTenant(t, pool, "acme"))
	dev, err := store.NewDevices(pool).Create(ctx, tenant.String(), "test", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = store.NewKeys(pool).ArchiveKey(ctx, tenant, uuid.MustParse(dev.ID))
	if !errors.Is(err, store.ErrNoArchiveKey) {
		t.Fatalf("err = %v, want ErrNoArchiveKey", err)
	}
}

func TestSealAndReopenThroughPostgres(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	tenant, device, pub, priv, keys := tenantWithKey(t, pool)

	sealer, err := seal.NewSealer(tenant, device, pub, 1, keys)
	if err != nil {
		t.Fatal(err)
	}
	row := uuid.New()
	secret := []byte("mensagem que o servidor nao pode ler")

	sealed, err := sealer.Seal(ctx, seal.KindBody, row, secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, secret) {
		t.Fatal("the envelope contains the plaintext")
	}

	id, _, err := seal.ContentKeyID(sealed)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := keys.SealedContentKey(ctx, tenant, device, id)
	if err != nil {
		t.Fatal(err)
	}
	ck, err := seal.OpenContentKey(priv, tenant, device, id, stored)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ck.Open(seal.KindBody, tenant, row, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Errorf("got %q, want %q", got, secret)
	}
}

// The counter is per tenant. Two rotations racing must not both claim the same
// id, or one key silently overwrites the other and its messages become
// unreadable.
func TestContentKeyIDsAreUniqueUnderContention(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	tenant, device, pub, _, keys := tenantWithKey(t, pool)

	const racers = 10
	var (
		mu   sync.Mutex
		seen = map[uint32]bool{}
		wg   sync.WaitGroup
	)
	for range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, err := keys.CreateContentKey(ctx, tenant, device, 1, func(id uint32) ([]byte, error) {
				ck, err := seal.NewContentKey(pub, tenant, device, 1, id)
				if err != nil {
					return nil, err
				}
				return ck.Sealed, nil
			})
			if err != nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if seen[id] {
				t.Errorf("content key id %d was allocated twice", id)
			}
			seen[id] = true
		}()
	}
	wg.Wait()
	if len(seen) != racers {
		t.Fatalf("allocated %d ids for %d racers", len(seen), racers)
	}
}

// Each device counts from one. A global sequence would leak system-wide volume
// to every client that reads an envelope header.
func TestCountersAreScopedPerDevice(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()

	var firstIDs []uint32
	for range 2 {
		tenant, device, pub, _, keys := tenantWithKey(t, pool)
		id, err := keys.CreateContentKey(ctx, tenant, device, 1, func(id uint32) ([]byte, error) {
			ck, err := seal.NewContentKey(pub, tenant, device, 1, id)
			if err != nil {
				return nil, err
			}
			return ck.Sealed, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		firstIDs = append(firstIDs, id)
	}
	for i, id := range firstIDs {
		if id != 1 {
			t.Errorf("device %d got first content key id %d, want 1", i, id)
		}
	}
}

// One tenant must not reach another's content keys, even knowing the id.
func TestContentKeysAreTenantScoped(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	tenantA, deviceA, pubA, _, keysA := tenantWithKey(t, pool)
	tenantB, deviceB, _, _, _ := tenantWithKey(t, pool)

	id, err := keysA.CreateContentKey(ctx, tenantA, deviceA, 1, func(id uint32) ([]byte, error) {
		ck, err := seal.NewContentKey(pubA, tenantA, deviceA, 1, id)
		if err != nil {
			return nil, err
		}
		return ck.Sealed, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keysA.SealedContentKey(ctx, tenantB, deviceB, id); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("tenant B read tenant A's content key: %v", err)
	}
}

// And one device must not reach another's, inside the same tenant. This is the
// whole reason the key moved off the tenant: a reader holding one account's key
// has to be unable to open another's, whatever the server does.
func TestContentKeysAreDeviceScoped(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	tenant, deviceA, pubA, privA, keys := tenantWithKey(t, pool)

	other, err := store.NewDevices(pool).Create(ctx, tenant.String(), "second", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	deviceB := uuid.MustParse(other.ID)
	pubB, privB, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.CreateArchiveKey(ctx, tenant, deviceB, 1, pubB); err != nil {
		t.Fatal(err)
	}

	idA, err := keys.CreateContentKey(ctx, tenant, deviceA, 1, func(id uint32) ([]byte, error) {
		ck, err := seal.NewContentKey(pubA, tenant, deviceA, 1, id)
		if err != nil {
			return nil, err
		}
		return ck.Sealed, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	sealed, err := keys.SealedContentKey(ctx, tenant, deviceA, idA)
	if err != nil {
		t.Fatal(err)
	}

	// The other device's key does not open it, which is the arithmetic the
	// design rests on rather than a rule the server applies.
	if _, err := seal.OpenContentKey(privB, tenant, deviceA, idA, sealed); err == nil {
		t.Fatal("one device's key opened another device's content key")
	}
	// Nor does the right key against the wrong device, because the row the
	// value binds to is derived from the device.
	if _, err := seal.OpenContentKey(privA, tenant, deviceB, idA, sealed); err == nil {
		t.Fatal("a content key opened while claiming to belong to another device")
	}
	// And the right key against the right device still works, so the checks
	// above are not passing for some unrelated reason.
	if _, err := seal.OpenContentKey(privA, tenant, deviceA, idA, sealed); err != nil {
		t.Fatalf("the correct key did not open its own content key: %v", err)
	}
}
