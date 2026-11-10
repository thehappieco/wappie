package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/domain"
	"whatserver2/internal/ingest"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// keyServe is serve's ingest over one number, and its listener for
// archive key changes when a test starts it.
type keyServe struct {
	pool   *pgxpool.Pool
	keys   *store.Keys
	tenant uuid.UUID
	device uuid.UUID
	priv   seal.PrivateKey
	app    *app
	now    time.Time
	mu     sync.Mutex
	heard  chan [2]uuid.UUID
	n      int
}

func newKeyServe(t *testing.T) *keyServe {
	t.Helper()
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	var tenant uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('reset') RETURNING id`).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	dev, err := store.NewDevices(pool).Create(ctx, tenant.String(), "number", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	w := &keyServe{pool: pool, keys: store.NewKeys(pool), tenant: tenant, device: uuid.MustParse(dev.ID),
		now: time.Now(), heard: make(chan [2]uuid.UUID, 16)}
	w.priv = w.deviceKey(t)
	router, err := ingest.NewRouter(ingest.RouterConfig{
		Lookup: func(string) (ingest.DeviceInfo, bool) { return ingest.DeviceInfo{TenantID: tenant}, true },
		Keys:   w.keys, KeyStore: w.keys, Now: w.clock,
		Messages: store.NewMessages(pool), Log: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	w.app = &app{log: slog.New(slog.DiscardHandler), router: router}
	return w
}

func (w *keyServe) clock() time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.now
}

// due moves the sealers' clock past a content key's age limit.
func (w *keyServe) due() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.now = w.now.Add(seal.MaxKeyAge)
}

// listen starts serve's listener for archive key changes (onArchiveKey),
// and returns once it listens. Every notice for this workspace, and the
// one for everything when it starts, is also sent on heard.
func (w *keyServe) listen(t *testing.T, ctx context.Context) {
	t.Helper()
	listening := make(chan struct{})
	go func() {
		_ = listenArchiveKeyChanged(ctx, w.pool, func(tenant, device uuid.UUID) {
			w.app.onArchiveKey(tenant, device)
			if tenant == w.tenant || tenant == uuid.Nil {
				w.heard <- [2]uuid.UUID{tenant, device}
			}
		}, func() { close(listening) })
	}()
	select {
	case <-listening:
	case <-time.After(10 * time.Second):
		t.Fatal("the listener never listened")
	}
	w.wait(t, uuid.Nil, uuid.Nil)
}

// wait returns once the listener has handled the notice for tenant and
// device.
func (w *keyServe) wait(t *testing.T, tenant, device uuid.UUID) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case got := <-w.heard:
			if got == [2]uuid.UUID{tenant, device} {
				return
			}
		case <-deadline:
			t.Fatalf("no notice for %s %s", tenant, device)
		}
	}
}

// deviceKey gives the number a new archive key at epoch 1, as device-key
// does after reset-archive -keep-devices.
func (w *keyServe) deviceKey(t *testing.T) seal.PrivateKey {
	t.Helper()
	pub, priv, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := w.keys.CreateArchiveKey(context.Background(), w.tenant, w.device, 1, pub); err != nil {
		t.Fatal(err)
	}
	return priv
}

func (w *keyServe) reset(t *testing.T) {
	t.Helper()
	if _, err := store.ResetArchive(context.Background(), w.pool, w.tenant, true); err != nil {
		t.Fatal(err)
	}
}

// message is one ingested message and its body.
type message struct {
	uid  uuid.UUID
	body string
}

// send ingests one message with a body, as a message the number sent.
func (w *keyServe) send() (message, error) {
	w.n++
	body := fmt.Sprintf("message %d", w.n)
	res, err := w.app.router.IngestOutbound(context.Background(), w.tenant, w.device.String(), domain.Envelope{
		MessageID: fmt.Sprintf("M%d", w.n), Timestamp: time.Now(), IsFromMe: true,
		Chat: domain.AddressOf(types.JID{User: "5511999999999", Server: types.DefaultUserServer}),
		Kind: domain.KindMessage, Type: domain.TypeText, Content: domain.Content{Body: body},
	})
	return message{res.UID, body}, err
}

// opens fails unless m opens with priv.
func (w *keyServe) opens(t *testing.T, priv seal.PrivateKey, m message) {
	t.Helper()
	ctx := context.Background()
	var sealed []byte
	var keyID int32
	if err := pg.InTenantTx(ctx, w.pool, w.tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT body_sealed, content_key_id FROM messages WHERE uid = $1`, m.uid).Scan(&sealed, &keyID)
	}); err != nil {
		t.Fatal(err)
	}
	blob, err := w.keys.SealedContentKey(ctx, w.tenant, w.device, uint32(keyID))
	if err != nil {
		t.Fatalf("%q names content key %d: %v", m.body, keyID, err)
	}
	ck, err := seal.OpenContentKey(priv, w.tenant, w.device, uint32(keyID), blob)
	if err != nil {
		t.Fatalf("the content key of %q does not open with the number's key: %v", m.body, err)
	}
	if got, err := ck.Open(seal.KindBody, w.tenant, m.uid, sealed); err != nil || string(got) != m.body {
		t.Fatalf("%q opened to %q, %v", m.body, got, err)
	}
}

// keysOpen fails unless every content key of the number opens with priv
// and every message names a content key that exists.
func (w *keyServe) keysOpen(t *testing.T, priv seal.PrivateKey) {
	t.Helper()
	ctx := context.Background()
	var ids []int32
	var orphans int
	if err := pg.InTenantTx(ctx, w.pool, w.tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id FROM content_keys WHERE device_id = $1`, w.device)
		if err != nil {
			return err
		}
		if ids, err = pgx.CollectRows(rows, pgx.RowTo[int32]); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM messages m WHERE m.device_id = $1 AND NOT EXISTS
			(SELECT 1 FROM content_keys k WHERE k.device_id = m.device_id AND k.id = m.content_key_id)`, w.device).Scan(&orphans)
	}); err != nil {
		t.Fatal(err)
	}
	if orphans != 0 {
		t.Fatalf("%d messages name a content key that is gone", orphans)
	}
	for _, id := range ids {
		blob, err := w.keys.SealedContentKey(ctx, w.tenant, w.device, uint32(id))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := seal.OpenContentKey(priv, w.tenant, w.device, uint32(id), blob); err != nil {
			t.Fatalf("content key %d is sealed to another key: %v", id, err)
		}
	}
}

// TestResetThenDeviceKeyWhileServing: reset-archive -keep-devices, then
// device-key, while serve runs, and every later message opens with the
// number's new key (DS49). No restart.
//
// Listening, the reset's notice drops the number's pipeline at once: a
// message before device-key is refused, as the number has no key, rather
// than stored under the content key the reset deleted. device-key's
// notice drops it again, and the next message seals to the new key.
//
// Not listening (the notice lost, or a binary without it), a pipeline
// built with the old key keeps it, and seals under its content key until
// that is due (lost, the first case, which the notice ends). The check
// before each content key then refuses a key sealed to the old one and
// filed at epoch 1 (the third case), and the next message seals to the new
// key.
//
// A notice sent while the process was not listening is lost, so when it
// listens again every pipeline goes.
func TestResetThenDeviceKeyWhileServing(t *testing.T) {
	t.Run("listening", func(t *testing.T) {
		w := newKeyServe(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		w.listen(t, ctx)
		m, err := w.send()
		if err != nil {
			t.Fatal(err)
		}
		w.opens(t, w.priv, m)

		w.reset(t)
		w.wait(t, w.tenant, uuid.Nil)
		if _, err := w.send(); !errors.Is(err, store.ErrNoArchiveKey) {
			t.Fatalf("a message between the reset and device-key: %v, want ErrNoArchiveKey", err)
		}
		fresh := w.deviceKey(t)
		w.wait(t, w.tenant, w.device)
		for range 3 {
			m, err := w.send()
			if err != nil {
				t.Fatal(err)
			}
			w.opens(t, fresh, m)
		}
		w.keysOpen(t, fresh)
	})

	t.Run("not listening", func(t *testing.T) {
		w := newKeyServe(t)
		if _, err := w.send(); err != nil {
			t.Fatal(err)
		}
		w.reset(t)
		fresh := w.deviceKey(t)
		w.due()
		if _, err := w.send(); !errors.Is(err, store.ErrArchiveKeyChanged) {
			t.Fatalf("a content key sealed to the old key: %v, want ErrArchiveKeyChanged", err)
		}
		for range 3 {
			m, err := w.send()
			if err != nil {
				t.Fatal(err)
			}
			w.opens(t, fresh, m)
		}
		var ids []int32
		if err := pg.InTenantTx(context.Background(), w.pool, w.tenant.String(), func(tx pgx.Tx) error {
			rows, err := tx.Query(context.Background(), `SELECT id FROM content_keys WHERE device_id = $1`, w.device)
			if err != nil {
				return err
			}
			ids, err = pgx.CollectRows(rows, pgx.RowTo[int32])
			return err
		}); err != nil {
			t.Fatal(err)
		}
		for _, id := range ids {
			blob, err := w.keys.SealedContentKey(context.Background(), w.tenant, w.device, uint32(id))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := seal.OpenContentKey(fresh, w.tenant, w.device, uint32(id), blob); err != nil {
				t.Fatalf("content key %d is sealed to the old key: %v", id, err)
			}
		}
	})

	t.Run("missed while not listening", func(t *testing.T) {
		w := newKeyServe(t)
		if _, err := w.send(); err != nil {
			t.Fatal(err)
		}
		w.reset(t)
		fresh := w.deviceKey(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		w.listen(t, ctx)
		m, err := w.send()
		if err != nil {
			t.Fatal(err)
		}
		w.opens(t, fresh, m)
		w.keysOpen(t, fresh)
	})
}

// TestServeListensForArchiveKeys: serve starts the listener, the
// command line's setup does not, and the listener's failure line says
// what still holds.
func TestServeListensForArchiveKeys(t *testing.T) {
	src := rawCode(t, ".")
	if !strings.Contains(funcBody(t, src, "serve"), "go a.listenArchiveKeys(ctx)") {
		t.Fatal("serve does not listen for archive key changes")
	}
	if strings.Contains(funcBody(t, src, "setupWith"), "listenArchiveKeys") {
		t.Fatal("setupWith listens for archive key changes")
	}
	_, listen, ok := strings.Cut(src, "\nfunc (a *app) listenArchiveKeys(")
	if !ok {
		t.Fatal("no listenArchiveKeys")
	}
	listen, _, _ = strings.Cut(listen, "\n}\n")
	inOrder(t, "the listener", listen, "a.keepListening(ctx,",
		"each new content key is still checked against the number's key", "listenArchiveKeyChanged(ctx, a.pools.API, a.onArchiveKey, ready)")
}

// TestDeviceKeyGrantsNameTheKey: device-key's grants, and the demo seed's,
// name the key the command just made (DS49), as every grant does.
func TestDeviceKeyGrantsNameTheKey(t *testing.T) {
	inOrder(t, "device-key", funcBody(t, rawCode(t, "."), "deviceKey"), "keys.CreateArchiveKey(ctx, tenant, deviceID, epoch, pub)",
		"keys.PutGrant(", "Fingerprint: store.ArchiveKeyFingerprint(pub.Bytes())")
	inOrder(t, "the demo seed", rawCode(t, "../seeddemo"), "keys.CreateArchiveKey(ctx, tenant, deviceID, epoch, pub)",
		"keys.PutGrant(", "Fingerprint: store.ArchiveKeyFingerprint(pub.Bytes())")
}
