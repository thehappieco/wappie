package seal

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Rotation limits for a content key.
const (
	// MaxSealsPerKey bounds how many values one content key covers. Chosen so
	// that losing a key to a memory-disclosure bug exposes a bounded window,
	// while keeping the asymmetric work a client does on open negligible: a
	// hundred thousand messages come out to roughly a hundred unwraps.
	MaxSealsPerKey = 1000

	// MaxKeyAge bounds the same window in time, for a quiet tenant where the
	// count alone would keep one key alive for weeks.
	MaxKeyAge = 15 * time.Minute

	// hardSealLimit is the cryptographic ceiling rather than a policy one. GCM
	// nonces here are 96 random bits, and collision probability climbs with the
	// square of the number of messages; 2^20 keeps it far below anything that
	// matters. Reaching it means the policy limits above were bypassed, so it
	// fails rather than rotating.
	hardSealLimit = 1 << 20
)

// KeyStore persists sealed content keys.
//
// An interface so this package stays free of any database dependency, and so
// the rotation logic can be tested without one.
type KeyStore interface {
	// CreateContentKey allocates the next per-device id and stores the key
	// sealed against it, atomically.
	//
	// The callback exists because of an ordering constraint: a content key's
	// sealed form binds to its own id, and the id is only known once the store
	// has allocated it. Doing this in two calls would mean either sealing
	// against a placeholder and re-sealing, or leaving gaps in a counter that
	// operators read. The store allocates inside its transaction, asks the
	// caller to seal, and commits both together.
	CreateContentKey(ctx context.Context, tenant, device uuid.UUID, epoch uint16,
		seal func(id uint32) ([]byte, error)) (uint32, error)

	// CountSeal records that one more value was sealed under a key. Best
	// effort bookkeeping for operators; the authoritative count is in memory.
	CountSeal(ctx context.Context, tenant, device uuid.UUID, id uint32, n int) error

	// CloseContentKey marks a key as no longer accepting new values.
	CloseContentKey(ctx context.Context, tenant, device uuid.UUID, id uint32) error
}

// Sealer seals content for one device.
//
// One per device rather than one per tenant, because the archive key is per
// device: the whole point is that a reader holding one device's key cannot open
// another's. Rotation happens under the same lock as sealing, so a key can
// never be used past its limit by a racing caller.
type Sealer struct {
	tenant uuid.UUID
	device uuid.UUID
	pub    PublicKey
	epoch  uint16
	store  KeyStore

	// now is injectable so the age-based rotation can be tested without
	// waiting fifteen minutes.
	now func() time.Time

	mu      sync.Mutex
	current *ContentKey
	seals   int
	born    time.Time
}

// NewSealer builds a sealer for one device at one epoch.
func NewSealer(tenant, device uuid.UUID, pub PublicKey, epoch uint16, store KeyStore) (*Sealer, error) {
	if !pub.Valid() {
		return nil, fmt.Errorf("seal: device %s has no archive key; it must be created before anything can be stored", device)
	}
	if store == nil {
		return nil, fmt.Errorf("seal: sealer needs a key store")
	}
	return &Sealer{tenant: tenant, device: device, pub: pub, epoch: epoch, store: store, now: time.Now}, nil
}

// Tenant returns the tenant this sealer belongs to.
func (s *Sealer) Tenant() uuid.UUID { return s.tenant }

// Device returns the device whose archive key this sealer holds.
func (s *Sealer) Device() uuid.UUID { return s.device }

// Epoch returns the archive epoch being sealed to.
func (s *Sealer) Epoch() uint16 { return s.epoch }

// Seal encrypts one value, rotating the content key when it is due.
//
// The returned envelope carries the content key id, so a reader can find the
// key without being told which one was used.
func (s *Sealer) Seal(ctx context.Context, kind Kind, row uuid.UUID, plaintext []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key, err := s.keyLocked(ctx)
	if err != nil {
		return nil, err
	}
	sealed, err := key.Seal(kind, s.tenant, row, plaintext)
	if err != nil {
		return nil, err
	}
	s.seals++
	return sealed, nil
}

// SealAll seals several values under the same content key.
//
// Used for one message's fields — body, media key, thumbnail, raw protobuf —
// so they share a key and a reader unwraps once rather than four times. The
// values keep their own kinds, so none can be substituted for another.
func (s *Sealer) SealAll(ctx context.Context, row uuid.UUID, values map[Kind][]byte) (map[Kind][]byte, uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key, err := s.keyLocked(ctx)
	if err != nil {
		return nil, 0, err
	}
	out := make(map[Kind][]byte, len(values))
	for kind, plaintext := range values {
		sealed, err := key.Seal(kind, s.tenant, row, plaintext)
		if err != nil {
			return nil, 0, err
		}
		out[kind] = sealed
		s.seals++
	}
	return out, key.ID, nil
}

// Rotate forces a fresh content key on the next seal.
//
// History sync gets its own key: a backfill seals tens of thousands of values
// in a burst, and letting it share a key with live traffic would blow through
// the rotation limit in one go and tie unrelated conversations together.
func (s *Sealer) Rotate(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rotateLocked(ctx)
}

// CurrentKeyID reports the content key in use, or zero when none has been
// created yet. For diagnostics.
func (s *Sealer) CurrentKeyID() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current == nil {
		return 0
	}
	return s.current.ID
}

// keyLocked returns a usable content key, rotating if the current one is spent.
func (s *Sealer) keyLocked(ctx context.Context) (*ContentKey, error) {
	if s.current != nil && !s.dueLocked() {
		return s.current, nil
	}
	if err := s.rotateLocked(ctx); err != nil {
		return nil, err
	}
	return s.current, nil
}

// dueLocked reports whether the current key has reached a rotation limit.
func (s *Sealer) dueLocked() bool {
	return s.seals >= MaxSealsPerKey || s.now().Sub(s.born) >= MaxKeyAge
}

func (s *Sealer) rotateLocked(ctx context.Context) error {
	if s.seals >= hardSealLimit {
		// Unreachable through the policy limits above. If it is ever reached,
		// something bypassed them, and continuing would weaken the nonce
		// guarantee rather than merely being untidy.
		return fmt.Errorf("seal: content key exceeded the hard limit of %d seals", hardSealLimit)
	}

	previous := s.current

	// The key material is generated here, and sealed inside the store's
	// transaction once an id exists to bind it to.
	var fresh *ContentKey
	id, err := s.store.CreateContentKey(ctx, s.tenant, s.device, s.epoch, func(id uint32) ([]byte, error) {
		ck, err := NewContentKey(s.pub, s.tenant, s.device, s.epoch, id)
		if err != nil {
			return nil, err
		}
		fresh = ck
		return ck.Sealed, nil
	})
	if err != nil {
		return fmt.Errorf("seal: create content key: %w", err)
	}
	if fresh == nil || fresh.ID != id {
		return fmt.Errorf("seal: store allocated id %d but the key was not sealed against it", id)
	}

	s.current, s.seals, s.born = fresh, 0, s.now()

	if previous != nil {
		// Bookkeeping only, and deliberately not propagated: the key is
		// already out of use in memory, and failing the rotation here would
		// stop ingest over a stale closed_at timestamp.
		//nolint:errcheck // marking the old key closed is advisory
		_ = s.store.CloseContentKey(ctx, s.tenant, s.device, previous.ID)
	}
	return nil
}
