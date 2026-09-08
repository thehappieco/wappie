package seal_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/crypto/seal"
)

// memKeys is an in-memory KeyStore.
type memKeys struct {
	mu     sync.Mutex
	next   uint32
	stored map[uint32][]byte
	closed map[uint32]bool
	fail   error
}

func newMemKeys() *memKeys {
	return &memKeys{stored: map[uint32][]byte{}, closed: map[uint32]bool{}}
}

func (m *memKeys) CreateContentKey(_ context.Context, _, _ uuid.UUID, _ uint16,
	sealFn func(uint32) ([]byte, error)) (uint32, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return 0, m.fail
	}
	m.next++
	sealed, err := sealFn(m.next)
	if err != nil {
		m.next-- // the allocation did not happen
		return 0, err
	}
	m.stored[m.next] = sealed
	return m.next, nil
}

func (m *memKeys) CountSeal(context.Context, uuid.UUID, uuid.UUID, uint32, int) error {
	return nil
}

func (m *memKeys) CloseContentKey(_ context.Context, _, _ uuid.UUID, id uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed[id] = true
	return nil
}

func (m *memKeys) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.stored)
}

func newSealer(t *testing.T) (*seal.Sealer, *memKeys, seal.PrivateKey) {
	t.Helper()
	pub, priv := keys(t)
	store := newMemKeys()
	s, err := seal.NewSealer(tenant, testDevice, pub, 1, store)
	if err != nil {
		t.Fatal(err)
	}
	return s, store, priv
}

func TestSealerCreatesKeyLazily(t *testing.T) {
	s, store, _ := newSealer(t)
	if store.count() != 0 {
		t.Fatal("a content key was created before anything needed sealing")
	}
	if _, err := s.Seal(context.Background(), seal.KindBody, rowA, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if store.count() != 1 {
		t.Fatalf("stored %d keys, want 1", store.count())
	}
}

// Many values share one key: that is the entire reason content keys exist. One
// asymmetric operation per message is what makes a phone take half a minute to
// open a conversation.
func TestManySealsShareOneKey(t *testing.T) {
	s, store, _ := newSealer(t)
	ctx := context.Background()
	for range seal.MaxSealsPerKey {
		if _, err := s.Seal(ctx, seal.KindBody, rowA, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if store.count() != 1 {
		t.Fatalf("stored %d keys for %d seals, want 1", store.count(), seal.MaxSealsPerKey)
	}
	// One past the limit rotates.
	if _, err := s.Seal(ctx, seal.KindBody, rowA, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if store.count() != 2 {
		t.Fatalf("stored %d keys after exceeding the limit, want 2", store.count())
	}
}

func TestRotationClosesThePreviousKey(t *testing.T) {
	s, store, _ := newSealer(t)
	ctx := context.Background()
	if _, err := s.Seal(ctx, seal.KindBody, rowA, []byte("x")); err != nil {
		t.Fatal(err)
	}
	first := s.CurrentKeyID()
	if err := s.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Seal(ctx, seal.KindBody, rowA, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if s.CurrentKeyID() == first {
		t.Fatal("Rotate did not produce a new key")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if !store.closed[first] {
		t.Error("the previous key was not closed")
	}
}

// A quiet tenant would otherwise keep one key alive for weeks. The age limit
// bounds the exposure window in time as well as in count.
func TestKeyRotatesOnAge(t *testing.T) {
	pub, _ := keys(t)
	store := newMemKeys()
	s, err := seal.NewSealer(tenant, testDevice, pub, 1, store)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	seal.SetClockForTest(s, func() time.Time { return now })

	ctx := context.Background()
	if _, err := s.Seal(ctx, seal.KindBody, rowA, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if store.count() != 1 {
		t.Fatal("expected one key")
	}

	// Just under the limit: still the same key.
	now = now.Add(seal.MaxKeyAge - time.Second)
	if _, err := s.Seal(ctx, seal.KindBody, rowA, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if store.count() != 1 {
		t.Fatalf("rotated early: %d keys", store.count())
	}

	now = now.Add(2 * time.Second)
	if _, err := s.Seal(ctx, seal.KindBody, rowA, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if store.count() != 2 {
		t.Fatalf("did not rotate on age: %d keys", store.count())
	}
}

// One message's fields share a key so a reader unwraps once rather than four
// times, but each keeps its own kind so none can be substituted for another.
func TestSealAllSharesOneKeyButNotOneKind(t *testing.T) {
	s, store, priv := newSealer(t)
	ctx := context.Background()

	values := map[seal.Kind][]byte{
		seal.KindBody:      []byte("uma legenda"),
		seal.KindMediaKey:  make([]byte, 32),
		seal.KindThumbnail: []byte("thumb bytes"),
		seal.KindRawProto:  []byte("protobuf bytes"),
	}
	sealed, keyID, err := s.SealAll(ctx, rowA, values)
	if err != nil {
		t.Fatal(err)
	}
	if store.count() != 1 {
		t.Fatalf("stored %d keys for one message, want 1", store.count())
	}

	store.mu.Lock()
	blob := store.stored[keyID]
	store.mu.Unlock()
	ck, err := seal.OpenContentKey(priv, tenant, testDevice, keyID, blob)
	if err != nil {
		t.Fatal(err)
	}

	for kind, want := range values {
		got, err := ck.Open(kind, tenant, rowA, sealed[kind])
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if string(got) != string(want) {
			t.Errorf("%s: round trip mismatch", kind)
		}
	}

	// The thumbnail cannot be presented as the body, even sharing a key.
	if _, err := ck.Open(seal.KindBody, tenant, rowA, sealed[seal.KindThumbnail]); err == nil {
		t.Error("a thumbnail opened as a message body")
	}
}

// Ingest runs a goroutine per device and they share a tenant's sealer.
// Rotation must happen under the same lock as sealing, or a key gets used past
// its limit.
func TestConcurrentSealing(t *testing.T) {
	s, store, _ := newSealer(t)
	ctx := context.Background()

	const workers, each = 8, 400
	var wg sync.WaitGroup
	errs := make([]error, workers)
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range each {
				if _, err := s.Seal(ctx, seal.KindBody, rowA, []byte("x")); err != nil {
					errs[i] = err
					return
				}
			}
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("worker %d: %v", i, err)
		}
	}

	// 3200 seals at 1000 per key: at least three keys, and never one.
	if got := store.count(); got < 3 {
		t.Errorf("stored %d keys for %d seals, want at least 3", got, workers*each)
	}
}

// A tenant with no archive key must not be sealable. Falling back to plaintext
// would be the worst possible failure mode: silent, and exactly what this
// system exists to prevent.
func TestSealerRefusesWithoutAnArchiveKey(t *testing.T) {
	_, err := seal.NewSealer(tenant, testDevice, seal.PublicKey{}, 1, newMemKeys())
	if err == nil {
		t.Fatal("a sealer was built without an archive key")
	}
}

// A store failure must surface, not silently produce unsealed output.
func TestStoreFailurePropagates(t *testing.T) {
	pub, _ := keys(t)
	store := newMemKeys()
	store.fail = errors.New("database is down")
	s, err := seal.NewSealer(tenant, testDevice, pub, 1, store)
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.Seal(context.Background(), seal.KindBody, rowA, []byte("secret"))
	if err == nil {
		t.Fatal("sealing succeeded despite the store failing")
	}
	if out != nil {
		t.Fatal("output was returned alongside an error")
	}
}
