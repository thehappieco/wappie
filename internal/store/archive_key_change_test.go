package store_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/domain"
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

// TestCreateContentKeyForTwoNumbers: two numbers of one workspace make a
// content key at the same moment. Both are made. The check's lock on the
// workspace's row is FOR UPDATE, the lock the insert's trigger takes. A
// weaker one (FOR KEY SHARE) let both transactions hold it, and each then
// waited for the other at the trigger: a deadlock, and a lost message.
func TestCreateContentKeyForTwoNumbers(t *testing.T) {
	w := newKeyWorld(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dev, err := store.NewDevices(w.pool).Create(ctx, w.tenant.String(), "second number", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	other := uuid.MustParse(dev.ID)
	otherPub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := w.keys.CreateArchiveKey(ctx, w.tenant, other, 1, otherPub); err != nil {
		t.Fatal(err)
	}
	// Each sealFn waits, a little, for the other to be inside its own
	// transaction too: with the old lock both held it here.
	both := make(chan struct{})
	var arrived sync.WaitGroup
	arrived.Add(2)
	go func() { arrived.Wait(); close(both) }()
	made := make(chan error, 2)
	for _, n := range []struct {
		device uuid.UUID
		pub    seal.PublicKey
	}{{w.device, w.pub}, {other, otherPub}} {
		go func() {
			_, err := w.keys.CreateContentKeyFor(ctx, w.tenant, n.device, 1, n.pub, func(id uint32) ([]byte, error) {
				arrived.Done()
				select {
				case <-both:
				case <-time.After(time.Second):
				}
				ck, err := seal.NewContentKey(n.pub, w.tenant, n.device, 1, id)
				if err != nil {
					return nil, err
				}
				return ck.Sealed, nil
			})
			made <- err
		}()
	}
	for range 2 {
		if err := <-made; err != nil {
			t.Fatalf("two numbers' content keys at once: %v", err)
		}
	}
}

// TestSealedWritesNameTheirKey: every write of what ingest sealed names
// the archive key its content key was sealed to, and the store takes it
// only while that content key is stored under that key (DS49): a message,
// a placeholder it fills, a reprojection, a chat's name, a contact's name
// and a picture. After a reset the content key is gone, and after
// device-key the same id may be another key's. A write that names no key
// (a tool, a test) is not checked.
func TestSealedWritesNameTheirKey(t *testing.T) {
	w := newKeyWorld(t)
	ctx := context.Background()
	if err := w.contentKey(ctx, w.pub); err != nil {
		t.Fatal(err)
	}
	other, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	messages := store.NewMessages(w.pool)
	contacts := store.NewContacts(w.pool)
	const chat = "5511999990000@s.whatsapp.net"
	n := 0
	next := func() string { n++; return fmt.Sprintf("W%d", n) }
	rowAs := func(uid uuid.UUID, waID string, typ domain.Type, id uint32, key []byte) (uuid.UUID, error) {
		in := store.InsertMessage{UID: uid, TenantID: w.tenant, DeviceID: w.device,
			WAID: waID, ChatKey: chat, ChatPN: chat, SenderKey: chat, SenderPN: chat,
			TS: time.Now(), Kind: domain.KindMessage, Type: typ,
			Source: domain.SourceLive, ContentKeyID: id, ArchiveKey: key}
		if typ == domain.TypeUnsupported {
			in.Unsupported = "senderKeyDistributionMessage"
		} else {
			in.BodySealed = []byte("sealed")
		}
		res, err := messages.Insert(ctx, in)
		return res.UID, err
	}
	row := func(waID string, typ domain.Type, id uint32, key []byte) (uuid.UUID, error) {
		return rowAs(uuid.New(), waID, typ, id, key)
	}
	for _, c := range []struct {
		name  string
		write func(id uint32, key []byte) error
	}{
		{"message", func(id uint32, key []byte) error {
			_, err := row(next(), domain.TypeText, id, key)
			return err
		}},
		{"placeholder filled", func(id uint32, key []byte) error {
			waID := next()
			uid, err := row(waID, domain.TypeUnsupported, 0, nil)
			if err != nil {
				return err
			}
			// Sealed to the placeholder's uid, as ingest seals it (DS51).
			_, err = rowAs(uid, waID, domain.TypeText, id, key)
			return err
		}},
		{"reprojection", func(id uint32, key []byte) error {
			uid, err := row(next(), domain.TypeUnsupported, 0, nil)
			if err != nil {
				return err
			}
			return messages.Reproject(ctx, w.tenant, w.device, uid, domain.TypeText, id, key,
				[]byte("sealed"), nil, []byte("sealed raw"), nil)
		}},
		{"chat name", func(id uint32, key []byte) error {
			return messages.UpsertChatMeta(ctx, store.ChatMeta{TenantID: w.tenant, DeviceID: w.device,
				ChatKey: next() + "@g.us", IsGroup: true, NameSealed: []byte("sealed"), NameKeyID: id, NameArchiveKey: key})
		}},
		{"contact name", func(id uint32, key []byte) error {
			return contacts.Upsert(ctx, store.ContactName{TenantID: w.tenant, DeviceID: w.device,
				ContactKey: next() + "@s.whatsapp.net", PushNameSealed: []byte("sealed"), ContentKeyID: id, ArchiveKey: key})
		}},
		{"picture", func(id uint32, key []byte) error {
			return contacts.SetAvatar(ctx, w.tenant, w.device, next()+"@s.whatsapp.net", "pic", []byte("sealed"), id, key)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if err := c.write(1, w.pub.Bytes()); err != nil {
				t.Fatalf("content key 1 under its own key: %v", err)
			}
			if err := c.write(1, other.Bytes()); !errors.Is(err, store.ErrArchiveKeyChanged) {
				t.Fatalf("content key 1 named with another archive key: %v, want ErrArchiveKeyChanged", err)
			}
			if err := c.write(2, w.pub.Bytes()); !errors.Is(err, store.ErrArchiveKeyChanged) {
				t.Fatalf("a content key that is not stored: %v, want ErrArchiveKeyChanged", err)
			}
			if err := c.write(2, nil); err != nil {
				t.Fatalf("a write that names no archive key: %v", err)
			}
		})
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

// member is an active member of the workspace, who may hold a grant.
func (w *keyWorld) member(t *testing.T, role string) uuid.UUID {
	t.Helper()
	u, err := store.NewUsers(w.pool).Create(context.Background(), store.NewUser{TenantID: w.tenant,
		Email: role + "-" + uuid.NewString()[:8] + "@acme.test", Role: role, AuthKey: "test", KDFSalt: make([]byte, 16),
		KDFParams: store.DefaultKDFParams(), PublicKey: make([]byte, 32), WrappedUSK: []byte("wrapped")})
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}

// grant writes user's grant of the number at epoch 1, naming fingerprint.
func (w *keyWorld) grant(ctx context.Context, user uuid.UUID, fingerprint string) error {
	return w.keys.PutGrant(ctx, store.Grant{TenantID: w.tenant, DeviceID: w.device, UserID: user, Epoch: 1,
		SealedDSK: []byte("sealed for " + fingerprint), Fingerprint: fingerprint}, nil)
}

// TestPutGrantNamesItsKey: every grant names the archive key it was sealed
// for, and PutGrant compares it with the number's key in its own
// transaction (DS49). The epoch is reused after a reset, so a grant sealed
// with the old key at epoch 1 is refused once device-key gave the number
// a new key at epoch 1, and so is one between the reset and device-key.
// Each grant the context lists gives the fingerprint to echo.
func TestPutGrantNamesItsKey(t *testing.T) {
	w := newKeyWorld(t)
	ctx := context.Background()
	owner, member := w.member(t, "owner"), w.member(t, "member")
	old := store.ArchiveKeyFingerprint(w.pub.Bytes())
	for _, bad := range []string{"", "x", strings.ToUpper(old)} {
		if err := w.grant(ctx, owner, bad); !errors.Is(err, store.ErrGrantFingerprint) {
			t.Fatalf("a grant naming %q: %v, want ErrGrantFingerprint", bad, err)
		}
	}
	if err := w.grant(ctx, owner, old); err != nil {
		t.Fatal(err)
	}
	if fp, err := w.keys.ArchiveKeyFingerprintAt(ctx, w.tenant, w.device, 1); err != nil || fp != old {
		t.Fatalf("the key's fingerprint: %s %v", fp, err)
	}

	if _, err := store.ResetArchive(ctx, w.pool, w.tenant, true); err != nil {
		t.Fatal(err)
	}
	// No key at all: both errors, so grant.add and step 7's token grant,
	// which test them in different orders, both answer conflict.
	if err := w.grant(ctx, member, old); !errors.Is(err, store.ErrArchiveKeyChanged) || !errors.Is(err, store.ErrNoArchiveKey) {
		t.Fatalf("the old key after the reset: %v, want ErrArchiveKeyChanged and ErrNoArchiveKey", err)
	}
	fresh := store.ArchiveKeyFingerprint(w.newKey(t).Bytes())
	if err := w.grant(ctx, member, old); !errors.Is(err, store.ErrArchiveKeyChanged) || errors.Is(err, store.ErrNoArchiveKey) {
		t.Fatalf("the old key at the reused epoch: %v, want ErrArchiveKeyChanged only", err)
	}
	if err := w.grant(ctx, member, fresh); err != nil {
		t.Fatalf("the new key: %v", err)
	}
	grants, err := w.keys.GrantsFor(ctx, w.tenant, member)
	if err != nil || len(grants) != 1 || grants[0].Fingerprint != fresh {
		t.Fatalf("the grant context: %+v %v, want the new key's fingerprint", grants, err)
	}
}

// TestPutGrantRacingReset: a grant whose context was read before a reset
// and device-key, written while they commit. The comparison is in the
// grant's transaction, after the workspace's lock, so it reads the new key
// and refuses the old one. Read before the lock, it would pass, and the
// grant's foreign key would find the new key's row at epoch 1.
func TestPutGrantRacingReset(t *testing.T) {
	w := newKeyWorld(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	owner := w.member(t, "owner")
	old := store.ArchiveKeyFingerprint(w.pub.Bytes())
	fresh, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	granted := make(chan error, 1)
	err = pg.InTenantTx(ctx, w.pool, w.tenant.String(), func(tx pgx.Tx) error {
		// What the reset holds first.
		if _, err := tx.Exec(ctx, `SELECT id FROM tenants WHERE id = $1 FOR UPDATE`, w.tenant); err != nil {
			return err
		}
		go func() { granted <- w.grant(ctx, owner, old) }()
		for {
			waiting, err := w.backends.Waiting(ctx, w.pool)
			if err != nil {
				return err
			}
			if waiting {
				break
			}
			select {
			case err := <-granted:
				t.Fatalf("the grant did not wait for the reset: %v", err)
			case <-time.After(10 * time.Millisecond):
			}
		}
		if _, err := tx.Exec(ctx, `DELETE FROM device_archive_keys WHERE device_id = $1`, w.device); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO device_archive_keys (tenant_id, device_id, epoch, public_key, suite)
			VALUES ($1, $2, 1, $3, 1)`, w.tenant, w.device, fresh.Bytes())
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-granted; !errors.Is(err, store.ErrArchiveKeyChanged) {
		t.Fatalf("a grant of the old key after a racing reset: %v, want ErrArchiveKeyChanged", err)
	}
	if ok, err := w.keys.HasGrant(ctx, w.tenant, w.device, owner); err != nil || ok {
		t.Fatalf("a grant sealed with the old key is recorded at epoch 1: %v %v", ok, err)
	}
}
