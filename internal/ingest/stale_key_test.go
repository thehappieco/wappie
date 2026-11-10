package ingest_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/domain"
	"whatserver2/internal/ingest"
	"whatserver2/internal/store"
)

// clock is a sealer clock a test moves.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// staleWorld is a router over one number, with no listener for the key's
// notices: only the check before each content key is left.
type staleWorld struct {
	*fixture
	router *ingest.Router
	clock  *clock
	n      int
}

func newStaleWorld(t *testing.T) *staleWorld {
	t.Helper()
	f := newFixture(t)
	c := &clock{now: time.Now()}
	r, err := ingest.NewRouter(ingest.RouterConfig{
		Lookup: func(string) (ingest.DeviceInfo, bool) { return ingest.DeviceInfo{TenantID: f.tenant}, true },
		Keys:   f.keys, KeyStore: f.keys, Now: c.Now,
		Messages: store.NewMessages(f.pool), Log: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &staleWorld{fixture: f, router: r, clock: c}
}

// send ingests one message with a body.
func (w *staleWorld) send(ctx context.Context) (ingest.Result, string, error) {
	w.n++
	body := fmt.Sprintf("message %d", w.n)
	res, err := w.router.IngestOutbound(ctx, w.tenant, w.device.String(), domain.Envelope{
		MessageID: fmt.Sprintf("M%d", w.n), Chat: domain.AddressOf(chatJID), Timestamp: time.Now(),
		IsFromMe: true, Kind: domain.KindMessage, Type: domain.TypeText, Content: domain.Content{Body: body},
	})
	return res, body, err
}

// opens fails unless the stored message uid opens with priv to body.
func (w *staleWorld) opens(t *testing.T, priv seal.PrivateKey, uid uuid.UUID, body string) {
	t.Helper()
	ctx := context.Background()
	var sealed []byte
	var keyID int32
	if err := withTenant(ctx, w.pool, w.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT body_sealed, content_key_id FROM messages WHERE uid = $1`, uid).Scan(&sealed, &keyID)
	}); err != nil {
		t.Fatal(err)
	}
	blob, err := w.keys.SealedContentKey(ctx, w.tenant, w.device, uint32(keyID))
	if err != nil {
		t.Fatalf("message %s names content key %d: %v", uid, keyID, err)
	}
	ck, err := seal.OpenContentKey(priv, w.tenant, w.device, uint32(keyID), blob)
	if err != nil {
		t.Fatalf("content key %d of message %s does not open with the number's key: %v", keyID, uid, err)
	}
	got, err := ck.Open(seal.KindBody, w.tenant, uid, sealed)
	if err != nil || string(got) != body {
		t.Fatalf("message %s opened to %q, %v; want %q", uid, got, err, body)
	}
}

// contentKeysOpen fails unless every content key of the number opens with
// priv: none is sealed to a key the number no longer has.
func (w *staleWorld) contentKeysOpen(t *testing.T, priv seal.PrivateKey) {
	t.Helper()
	ctx := context.Background()
	var ids []int32
	if err := withTenant(ctx, w.pool, w.tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id FROM content_keys WHERE device_id = $1`, w.device)
		if err != nil {
			return err
		}
		ids, err = pgx.CollectRows(rows, pgx.RowTo[int32])
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(ids) == 0 {
		t.Fatal("no content key")
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

// deviceKey gives the number a new archive key at epoch 1, as device-key
// does after reset-archive -keep-devices.
func (w *staleWorld) deviceKey(t *testing.T) seal.PrivateKey {
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

// TestStaleSealerAfterNewKey is the stale sealer's third case (DS49), with
// no notice heard: a pipeline built with the old key, after reset-archive
// -keep-devices and device-key, which gives the number a new key at epoch
// 1. When its content key is due, the new one would be sealed to the old
// key and filed at epoch 1, so every message after it would be unreadable.
// The check before each content key refuses it, the refusal drops the
// pipeline, and the next message seals to the new key.
func TestStaleSealerAfterNewKey(t *testing.T) {
	w := newStaleWorld(t)
	ctx := context.Background()
	res, body, err := w.send(ctx)
	if err != nil {
		t.Fatal(err)
	}
	w.opens(t, w.priv, res.UID, body)

	if _, err := store.ResetArchive(ctx, w.pool, w.tenant, true); err != nil {
		t.Fatal(err)
	}
	fresh := w.deviceKey(t)
	w.clock.advance(seal.MaxKeyAge)

	if _, _, err := w.send(ctx); !errors.Is(err, store.ErrArchiveKeyChanged) {
		t.Fatalf("the stale sealer's next content key: %v, want ErrArchiveKeyChanged", err)
	}
	for range 2 {
		res, body, err := w.send(ctx)
		if err != nil {
			t.Fatalf("the message after the refusal: %v", err)
		}
		w.opens(t, fresh, res.UID, body)
	}
	w.contentKeysOpen(t, fresh)
}

// TestStaleSealerAfterReset is its second case: after the reset and before
// device-key the number has no key. A due content key is refused, not
// filed for a key that is gone, and the pipeline is dropped, so once
// device-key ran the next message seals to the new key.
func TestStaleSealerAfterReset(t *testing.T) {
	w := newStaleWorld(t)
	ctx := context.Background()
	if _, _, err := w.send(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ResetArchive(ctx, w.pool, w.tenant, true); err != nil {
		t.Fatal(err)
	}
	w.clock.advance(seal.MaxKeyAge)
	if _, _, err := w.send(ctx); !errors.Is(err, store.ErrArchiveKeyChanged) {
		t.Fatalf("a content key with no archive key: %v, want ErrArchiveKeyChanged", err)
	}
	if _, _, err := w.send(ctx); !errors.Is(err, store.ErrNoArchiveKey) {
		t.Fatalf("a message with no archive key: %v, want ErrNoArchiveKey", err)
	}
	fresh := w.deviceKey(t)
	res, body, err := w.send(ctx)
	if err != nil {
		t.Fatal(err)
	}
	w.opens(t, fresh, res.UID, body)
	w.contentKeysOpen(t, fresh)
}

// TestRouterForget: a notice drops the pipelines it names, and the next
// message builds them again from the key as it is now. Forget drops one
// number's, ForgetWorkspace a workspace's, ForgetAll every one.
func TestRouterForget(t *testing.T) {
	for _, c := range []struct {
		name   string
		forget func(w *staleWorld)
	}{
		{"number", func(w *staleWorld) { w.router.Forget(w.device) }},
		{"workspace", func(w *staleWorld) { w.router.ForgetWorkspace(w.tenant) }},
		{"all", func(w *staleWorld) { w.router.ForgetAll() }},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := newStaleWorld(t)
			ctx := context.Background()
			if _, _, err := w.send(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := store.ResetArchive(ctx, w.pool, w.tenant, true); err != nil {
				t.Fatal(err)
			}
			fresh := w.deviceKey(t)
			c.forget(w)
			res, body, err := w.send(ctx)
			if err != nil {
				t.Fatal(err)
			}
			w.opens(t, fresh, res.UID, body)
		})
	}
	t.Run("another workspace", func(t *testing.T) {
		w := newStaleWorld(t)
		ctx := context.Background()
		if _, _, err := w.send(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ResetArchive(ctx, w.pool, w.tenant, true); err != nil {
			t.Fatal(err)
		}
		w.deviceKey(t)
		w.router.ForgetWorkspace(uuid.New())
		// Still the old pipeline: its content key, not due, is the one
		// the reset deleted (the first case, which the notice ends).
		res, _, err := w.send(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.keys.SealedContentKey(ctx, w.tenant, w.device, contentKeyOf(t, w, res.UID)); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("another workspace's notice dropped this one's pipeline: %v", err)
		}
	})
}

// contentKeyOf reads a message's content key id.
func contentKeyOf(t *testing.T, w *staleWorld, uid uuid.UUID) uint32 {
	t.Helper()
	ctx := context.Background()
	var id int32
	if err := withTenant(ctx, w.pool, w.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT content_key_id FROM messages WHERE uid = $1`, uid).Scan(&id)
	}); err != nil {
		t.Fatal(err)
	}
	return uint32(id)
}
