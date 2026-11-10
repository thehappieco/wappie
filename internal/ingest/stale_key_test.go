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
	"go.mau.fi/whatsmeow/proto/waHistorySync"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/domain"
	"whatserver2/internal/ingest"
	"whatserver2/internal/pgtest"
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
// notices: only the checks before each content key and at each write are
// left.
type staleWorld struct {
	*fixture
	backends *pgtest.Backends
	router   *ingest.Router
	clock    *clock
	n        int
}

func newStaleWorld(t *testing.T) *staleWorld {
	t.Helper()
	backends := &pgtest.Backends{}
	f := newFixtureWith(t, backends.Configure)
	c := &clock{now: time.Now()}
	r, err := ingest.NewRouter(ingest.RouterConfig{
		Lookup: func(string) (ingest.DeviceInfo, bool) { return ingest.DeviceInfo{TenantID: f.tenant}, true },
		Keys:   f.keys, KeyStore: f.keys, Now: c.Now,
		Messages: store.NewMessages(f.pool), Log: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &staleWorld{fixture: f, backends: backends, router: r, clock: c}
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
	_, priv := w.deviceKeyPair(t)
	return priv
}

// deviceKeyPair is deviceKey, with the new public key too.
func (w *staleWorld) deviceKeyPair(t *testing.T) (seal.PublicKey, seal.PrivateKey) {
	t.Helper()
	pub, priv, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := w.keys.CreateArchiveKey(context.Background(), w.tenant, w.device, 1, pub); err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// reset is reset-archive -keep-devices.
func (w *staleWorld) reset(t *testing.T) {
	t.Helper()
	if _, err := store.ResetArchive(context.Background(), w.pool, w.tenant, true); err != nil {
		t.Fatal(err)
	}
}

// messages counts the number's stored messages.
func (w *staleWorld) messages(t *testing.T) int {
	t.Helper()
	ctx := context.Background()
	var n int
	if err := withTenant(ctx, w.pool, w.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM messages WHERE device_id = $1`, w.device).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestStaleSealerAfterNewKey is the stale sealer's third case (DS49), with
// no notice heard: a pipeline built with the old key, after reset-archive
// -keep-devices and device-key, which gives the number a new key at epoch
// 1. When its content key is due, the new one would be sealed to the old
// key and filed at epoch 1, so every message after it would be unreadable.
// The check before each content key refuses it, the router builds the
// pipeline again, and the message seals to the new key. No content key is
// left sealed to the old key.
func TestStaleSealerAfterNewKey(t *testing.T) {
	w := newStaleWorld(t)
	ctx := context.Background()
	res, body, err := w.send(ctx)
	if err != nil {
		t.Fatal(err)
	}
	w.opens(t, w.priv, res.UID, body)

	w.reset(t)
	fresh := w.deviceKey(t)
	w.clock.advance(seal.MaxKeyAge)

	for range 2 {
		res, body, err := w.send(ctx)
		if err != nil {
			t.Fatalf("a message after the reset and device-key: %v", err)
		}
		w.opens(t, fresh, res.UID, body)
	}
	w.contentKeysOpen(t, fresh)
}

// TestStaleSealerAfterReset is its second case: after the reset and before
// device-key the number has no key. A due content key is refused, not
// filed for a key that is gone, and the router builds the pipeline again,
// which fails: the message is not stored. Once device-key ran the next
// message seals to the new key.
func TestStaleSealerAfterReset(t *testing.T) {
	w := newStaleWorld(t)
	ctx := context.Background()
	if _, _, err := w.send(ctx); err != nil {
		t.Fatal(err)
	}
	w.reset(t)
	w.clock.advance(seal.MaxKeyAge)
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

// TestStaleSealerBeforeItsKeyIsDue is the first case, with no notice
// heard: the pipeline's content key, not due, is one the reset deleted.
// Each write names the archive key its content key was sealed to, and the
// store refuses one whose content key is gone, so nothing is stored under
// a deleted key. Before device-key the message is refused. After it the
// router builds the pipeline again and the message seals to the new key.
func TestStaleSealerBeforeItsKeyIsDue(t *testing.T) {
	t.Run("before device-key", func(t *testing.T) {
		w := newStaleWorld(t)
		ctx := context.Background()
		if _, _, err := w.send(ctx); err != nil {
			t.Fatal(err)
		}
		w.reset(t)
		if _, _, err := w.send(ctx); !errors.Is(err, store.ErrNoArchiveKey) {
			t.Fatalf("a message after the reset: %v, want ErrNoArchiveKey", err)
		}
		if n := w.messages(t); n != 0 {
			t.Fatalf("%d messages stored under a content key the reset deleted", n)
		}
		fresh := w.deviceKey(t)
		res, body, err := w.send(ctx)
		if err != nil {
			t.Fatal(err)
		}
		w.opens(t, fresh, res.UID, body)
	})
	t.Run("after device-key", func(t *testing.T) {
		w := newStaleWorld(t)
		ctx := context.Background()
		if _, _, err := w.send(ctx); err != nil {
			t.Fatal(err)
		}
		w.reset(t)
		fresh := w.deviceKey(t)
		res, body, err := w.send(ctx)
		if err != nil {
			t.Fatal(err)
		}
		w.opens(t, fresh, res.UID, body)
	})
}

// TestStaleSealerAfterAnotherContentKey: with no notice heard, after the
// reset and device-key, another process made the new key's first content
// key, at the id the stale pipeline's deleted one had. The write names the
// archive key too, so the store tells the two apart: it refuses the stale
// one, and the message seals to the new key. An id alone would pass it.
func TestStaleSealerAfterAnotherContentKey(t *testing.T) {
	w := newStaleWorld(t)
	ctx := context.Background()
	res, _, err := w.send(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stale := contentKeyOf(t, w, res.UID)
	w.reset(t)
	pub, fresh := w.deviceKeyPair(t)
	id, err := w.keys.CreateContentKeyFor(ctx, w.tenant, w.device, 1, pub, func(id uint32) ([]byte, error) {
		ck, err := seal.NewContentKey(pub, w.tenant, w.device, 1, id)
		if err != nil {
			return nil, err
		}
		return ck.Sealed, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if id != stale {
		t.Fatalf("the new content key is %d, the stale one %d: the test needs them equal", id, stale)
	}
	res, body, err := w.send(ctx)
	if err != nil {
		t.Fatal(err)
	}
	w.opens(t, fresh, res.UID, body)
}

// TestMessageSealedDuringReset: a message sealed before a reset's commit,
// whose write waits for the reset's lock on the workspace. Its write runs
// after the commit, names a content key the reset deleted, and is refused
// rather than stored in the new archive as a row nobody can open. The
// router builds the pipeline again, which fails until device-key.
func TestMessageSealedDuringReset(t *testing.T) {
	w := newStaleWorld(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, _, err := w.send(ctx); err != nil {
		t.Fatal(err)
	}
	sent := make(chan error, 1)
	err := withTenant(ctx, w.pool, w.tenant, func(tx pgx.Tx) error {
		// What the reset holds first.
		if _, err := tx.Exec(ctx, `SELECT id FROM tenants WHERE id = $1 FOR UPDATE`, w.tenant); err != nil {
			return err
		}
		go func() {
			_, _, err := w.send(ctx)
			sent <- err
		}()
		for {
			waiting, err := w.backends.Waiting(ctx, w.pool)
			if err != nil {
				return err
			}
			if waiting {
				break
			}
			select {
			case err := <-sent:
				t.Fatalf("the message did not wait for the reset: %v", err)
			case <-time.After(10 * time.Millisecond):
			}
		}
		// The reset's deletes.
		for _, q := range []string{`DELETE FROM messages`, `DELETE FROM chats`, `DELETE FROM events`,
			`DELETE FROM content_keys`, `DELETE FROM device_key_grants`, `DELETE FROM device_archive_keys`,
			`UPDATE devices SET current_epoch = 0`} {
			if _, err := tx.Exec(ctx, q); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-sent; !errors.Is(err, store.ErrNoArchiveKey) {
		t.Fatalf("a message sealed during the reset: %v, want ErrNoArchiveKey", err)
	}
	if n := w.messages(t); n != 0 {
		t.Fatalf("%d messages stored after the reset under a content key it deleted", n)
	}
	fresh := w.deviceKey(t)
	res, body, err := w.send(ctx)
	if err != nil {
		t.Fatal(err)
	}
	w.opens(t, fresh, res.UID, body)
}

// TestRouterForget: a notice drops the pipelines it names, and the next
// message builds them again: a new pipeline, with a content key of its
// own. Forget drops one number's, ForgetWorkspace a workspace's,
// ForgetAll every one. Another workspace's notice drops nothing here.
func TestRouterForget(t *testing.T) {
	for _, c := range []struct {
		name    string
		forget  func(w *staleWorld)
		dropped bool
	}{
		{"number", func(w *staleWorld) { w.router.Forget(w.device) }, true},
		{"workspace", func(w *staleWorld) { w.router.ForgetWorkspace(w.tenant) }, true},
		{"all", func(w *staleWorld) { w.router.ForgetAll() }, true},
		{"another number", func(w *staleWorld) { w.router.Forget(uuid.New()) }, false},
		{"another workspace", func(w *staleWorld) { w.router.ForgetWorkspace(uuid.New()) }, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := newStaleWorld(t)
			ctx := context.Background()
			first, _, err := w.send(ctx)
			if err != nil {
				t.Fatal(err)
			}
			c.forget(w)
			res, body, err := w.send(ctx)
			if err != nil {
				t.Fatal(err)
			}
			w.opens(t, w.priv, res.UID, body)
			if dropped := contentKeyOf(t, w, res.UID) != contentKeyOf(t, w, first.UID); dropped != c.dropped {
				t.Fatalf("pipeline dropped: %v, want %v", dropped, c.dropped)
			}
		})
	}
}

// resetBus runs do at the first message published: in the middle of a
// history chunk, when the worker already holds the number's pipeline.
type resetBus struct {
	once sync.Once
	do   func()
}

func (b *resetBus) Publish(_ uuid.UUID, ev ingest.Event) {
	if ev.Class == ingest.ClassMessage {
		b.once.Do(b.do)
	}
}

// TestHistoryChunkAcrossReset: a reset and device-key in the middle of a
// history chunk. Each message of the chunk fetches the number's pipeline
// again, and one the notice dropped seals nothing more, so the rest of the
// chunk seals to the new key. Without the notice, the stale pipeline's
// next write is refused (its content key is gone) and the pipeline is
// built again. Either way every message stored after the reset opens with
// the new key, and the chat's name too.
func TestHistoryChunkAcrossReset(t *testing.T) {
	for _, heard := range []bool{true, false} {
		t.Run(map[bool]string{true: "notice heard", false: "no notice"}[heard], func(t *testing.T) {
			w := newStaleWorld(t)
			ctx := context.Background()
			var fresh seal.PrivateKey
			bus := &resetBus{}
			// On the history worker's goroutine: t.Error, never t.Fatal.
			bus.do = func() {
				if _, err := store.ResetArchive(ctx, w.pool, w.tenant, true); err != nil {
					t.Error(err)
					return
				}
				pub, priv, err := seal.GenerateKeyPair()
				if err != nil {
					t.Error(err)
					return
				}
				if err := w.keys.CreateArchiveKey(ctx, w.tenant, w.device, 1, pub); err != nil {
					t.Error(err)
					return
				}
				fresh = priv
				if heard {
					w.router.ForgetWorkspace(w.tenant)
				}
			}
			r, err := ingest.NewRouter(ingest.RouterConfig{
				Lookup: func(string) (ingest.DeviceInfo, bool) { return ingest.DeviceInfo{TenantID: w.tenant}, true },
				Keys:   w.keys, KeyStore: w.keys,
				Messages: store.NewMessages(w.pool), Bus: bus,
				Log: slog.New(slog.DiscardHandler),
			})
			if err != nil {
				t.Fatal(err)
			}
			w.router = r
			named := conversation(
				historyMsg("H1", text("um"), false),
				historyMsg("H2", text("dois"), false),
				historyMsg("H3", text("três"), false),
			)
			named.Name = ptr("a conversa")
			second := &waHistorySync.Conversation{ID: ptr(otherChat.String()), Name: ptr("outra conversa"),
				Messages: []*waHistorySync.HistorySyncMsg{historyMsg("H4", text("quatro"), false)}}
			second.Messages[0].Message.Key.RemoteJID = ptr(otherChat.String())
			hctx, stop := context.WithTimeout(ctx, 20*time.Second)
			defer stop()
			go r.RunHistory(hctx)
			r.Handle(hctx, w.device.String(), &events.HistorySync{Data: bootstrap(named, second)})
			waitFor(t, func() bool { return w.messages(t) == 3 })

			// H1, stored before the reset, went with it.
			for _, c := range []struct{ chat, waID, body string }{
				{chatJID.String(), "H2", "dois"}, {chatJID.String(), "H3", "três"}, {otherChat.String(), "H4", "quatro"},
			} {
				uid, chat := messageUID(t, w, c.waID)
				if chat != c.chat {
					t.Fatalf("%s is filed under %s", c.waID, chat)
				}
				w.opens(t, fresh, uid, c.body)
			}
			nameOpens(t, w, fresh, otherChat.String(), "outra conversa")
		})
	}
}

// otherChat is a second conversation of the chunk, after the reset.
var otherChat = types.NewJID("5511988887777", types.DefaultUserServer)

func ptr(s string) *string { return &s }

// waitFor polls cond for up to 15 seconds.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatal("gave up waiting")
}

// messageUID finds a stored message by its WhatsApp id.
func messageUID(t *testing.T, w *staleWorld, waID string) (uuid.UUID, string) {
	t.Helper()
	ctx := context.Background()
	var uid uuid.UUID
	var chat string
	if err := withTenant(ctx, w.pool, w.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT uid, chat_key FROM messages WHERE wa_id = $1`, waID).Scan(&uid, &chat)
	}); err != nil {
		t.Fatalf("message %s: %v", waID, err)
	}
	return uid, chat
}

// nameOpens fails unless the chat's sealed name opens with priv to name.
func nameOpens(t *testing.T, w *staleWorld, priv seal.PrivateKey, chat, name string) {
	t.Helper()
	ctx := context.Background()
	var sealed []byte
	var keyID int32
	if err := withTenant(ctx, w.pool, w.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT name_sealed, name_key_id FROM chats WHERE device_id = $1 AND chat_key = $2`,
			w.device, chat).Scan(&sealed, &keyID)
	}); err != nil {
		t.Fatal(err)
	}
	blob, err := w.keys.SealedContentKey(ctx, w.tenant, w.device, uint32(keyID))
	if err != nil {
		t.Fatalf("the name of %s names content key %d: %v", chat, keyID, err)
	}
	ck, err := seal.OpenContentKey(priv, w.tenant, w.device, uint32(keyID), blob)
	if err != nil {
		t.Fatalf("content key %d of the name of %s: %v", keyID, chat, err)
	}
	got, err := ck.Open(seal.KindContactName, w.tenant, store.ChatUID(w.device, chat), sealed)
	if err != nil || string(got) != name {
		t.Fatalf("the name of %s opened to %q, %v; want %q", chat, got, err, name)
	}
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
