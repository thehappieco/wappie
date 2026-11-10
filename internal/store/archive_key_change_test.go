package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// keyWorld is one workspace with one number and its archive key.
type keyWorld struct {
	pool     *pgxpool.Pool
	backends *pgtest.Backends
	keys     *store.Keys
	tenant   uuid.UUID
	device   uuid.UUID
	pub      seal.PublicKey
}

func newKeyWorld(t *testing.T) *keyWorld {
	t.Helper()
	backends := &pgtest.Backends{}
	pool := pgtest.FreshWith(t, migrate.Run, backends.Configure)
	ctx := context.Background()
	var tenant uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('keys') RETURNING id`).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	dev, err := store.NewDevices(pool).Create(ctx, tenant.String(), "number", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	w := &keyWorld{pool: pool, backends: backends, keys: store.NewKeys(pool), tenant: tenant, device: uuid.MustParse(dev.ID)}
	w.pub = w.newKey(t)
	return w
}

// newKey gives the number a new archive key at epoch 1, as device-key
// does after a reset.
func (w *keyWorld) newKey(t *testing.T) seal.PublicKey {
	t.Helper()
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := w.keys.CreateArchiveKey(context.Background(), w.tenant, w.device, 1, pub); err != nil {
		t.Fatal(err)
	}
	return pub
}

// contentKey makes a content key for pub, sealed to pub as a sealer would.
func (w *keyWorld) contentKey(ctx context.Context, pub seal.PublicKey) error {
	_, err := w.keys.CreateContentKeyFor(ctx, w.tenant, w.device, 1, pub, func(id uint32) ([]byte, error) {
		ck, err := seal.NewContentKey(pub, w.tenant, w.device, 1, id)
		if err != nil {
			return nil, err
		}
		return ck.Sealed, nil
	})
	return err
}

// TestCreateContentKeyForChecksTheKey: a content key is made only for the
// number's current archive key (DS49). After reset-archive -keep-devices
// the number has none; after device-key it has another at the same epoch,
// so the epoch alone would let a sealer built before the reset file a
// content key sealed to the old key under the new one.
func TestCreateContentKeyForChecksTheKey(t *testing.T) {
	w := newKeyWorld(t)
	ctx := context.Background()
	if err := w.contentKey(ctx, w.pub); err != nil {
		t.Fatalf("the current key: %v", err)
	}
	other, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := w.contentKey(ctx, other); !errors.Is(err, store.ErrArchiveKeyChanged) {
		t.Fatalf("another key: %v, want ErrArchiveKeyChanged", err)
	}
	if _, err := store.ResetArchive(ctx, w.pool, w.tenant, true); err != nil {
		t.Fatal(err)
	}
	if err := w.contentKey(ctx, w.pub); !errors.Is(err, store.ErrArchiveKeyChanged) {
		t.Fatalf("after the reset: %v, want ErrArchiveKeyChanged", err)
	}
	fresh := w.newKey(t)
	if err := w.contentKey(ctx, w.pub); !errors.Is(err, store.ErrArchiveKeyChanged) {
		t.Fatalf("the old key after device-key: %v, want ErrArchiveKeyChanged", err)
	}
	if err := w.contentKey(ctx, fresh); err != nil {
		t.Fatalf("the new key: %v", err)
	}
}

// TestCreateContentKeyForRacingReset: a reset and a new key that commit
// while a content key is being made. The content key's transaction takes
// the tenants row before it reads the key, so it reads the key after the
// reset's commit and is refused. Reading first, it would pass the old key,
// and the insert's foreign key would find the new key's row at epoch 1.
func TestCreateContentKeyForRacingReset(t *testing.T) {
	w := newKeyWorld(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	made := make(chan error, 1)
	fresh, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	err = pg.InTenantTx(ctx, w.pool, w.tenant.String(), func(tx pgx.Tx) error {
		// What the reset holds first.
		if _, err := tx.Exec(ctx, `SELECT id FROM tenants WHERE id = $1 FOR UPDATE`, w.tenant); err != nil {
			return err
		}
		go func() { made <- w.contentKey(ctx, w.pub) }()
		for {
			waiting, err := w.backends.Waiting(ctx, w.pool)
			if err != nil {
				return err
			}
			if waiting {
				break
			}
			select {
			case err := <-made:
				t.Fatalf("the content key did not wait for the reset: %v", err)
			case <-time.After(10 * time.Millisecond):
			}
		}
		// The reset's deletes and device-key's new key, at epoch 1 again.
		if _, err := tx.Exec(ctx, `DELETE FROM device_archive_keys WHERE device_id = $1`, w.device); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO device_archive_keys (tenant_id, device_id, epoch, public_key, suite)
			VALUES ($1, $2, 1, $3, 1)`, w.tenant, w.device, fresh.Bytes()); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-made; !errors.Is(err, store.ErrArchiveKeyChanged) {
		t.Fatalf("a content key for the old key after a racing reset: %v, want ErrArchiveKeyChanged", err)
	}
	var n int
	if err := pg.InTenantTx(ctx, w.pool, w.tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM content_keys WHERE device_id = $1`, w.device).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("%d content keys filed for the new key, sealed to the old one", n)
	}
}

// TestArchiveKeyNotices: a reset and a new archive key each tell every
// process at their commit (ArchiveKeyChannel, DS49), the reset for the
// whole workspace and the key for its number, so a running server drops
// what ingest built from the old key.
func TestArchiveKeyNotices(t *testing.T) {
	w := newKeyWorld(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	listener, err := w.pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Release()
	if _, err := listener.Exec(ctx, `LISTEN `+store.ArchiveKeyChannel); err != nil {
		t.Fatal(err)
	}
	heard := func(what, payload string) {
		t.Helper()
		if err := w.backends.Notice(ctx, listener.Conn(), store.ArchiveKeyChannel, payload); err != nil {
			t.Fatalf("%s sent no notice %q: %v", what, payload, err)
		}
		tenant, device, err := store.ParseArchiveKeyNotice(payload)
		if err != nil || tenant != w.tenant || (device != uuid.Nil && device != w.device) {
			t.Fatalf("%s's notice %q reads as %s, %s, %v", what, payload, tenant, device, err)
		}
	}
	if _, err := store.ResetArchive(ctx, w.pool, w.tenant, true); err != nil {
		t.Fatal(err)
	}
	heard("the reset", w.tenant.String())
	w.newKey(t)
	heard("device-key", w.tenant.String()+":"+w.device.String())
}

// TestParseArchiveKeyNotice reads a workspace's and a number's notice and
// refuses anything else.
func TestParseArchiveKeyNotice(t *testing.T) {
	tenant, device := uuid.New(), uuid.New()
	if gotT, gotD, err := store.ParseArchiveKeyNotice(tenant.String()); err != nil || gotT != tenant || gotD != uuid.Nil {
		t.Fatalf("a workspace's notice: %s %s %v", gotT, gotD, err)
	}
	if gotT, gotD, err := store.ParseArchiveKeyNotice(tenant.String() + ":" + device.String()); err != nil || gotT != tenant || gotD != device {
		t.Fatalf("a number's notice: %s %s %v", gotT, gotD, err)
	}
	for _, bad := range []string{"", "x", uuid.Nil.String(), tenant.String() + ":", tenant.String() + ":" + uuid.Nil.String(),
		tenant.String() + ":x", "urn:uuid:" + tenant.String(), "{" + tenant.String() + "}"} {
		if _, _, err := store.ParseArchiveKeyNotice(bad); err == nil {
			t.Fatalf("%q read as a notice", bad)
		}
	}
}
