package pg

import (
	"context"
	"fmt"
	"hash/fnv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Locker takes Postgres advisory locks, so that only one process supervises a
// given device at a time.
//
// Two instances driving the same WhatsApp session is not a theoretical problem:
// both would connect with the same credentials, and WhatsApp responds by
// emitting StreamReplaced and dropping one of them, repeatedly. During a rolling
// deploy the old and new pods overlap by design, so without this the fleet would
// fight itself on every release.
type Locker struct {
	pool *pgxpool.Pool
}

// NewLocker returns a Locker backed by pool.
func NewLocker(pool *pgxpool.Pool) *Locker { return &Locker{pool: pool} }

// TryLock takes a session-scoped advisory lock, returning ok=false when another
// session already holds it.
//
// The lock is bound to a connection checked out of the pool and held for the
// lifetime of the lock. That is what makes it crash-safe: if the process dies,
// the connection drops and Postgres releases the lock without anyone needing to
// clean up. It is also why the lock must not be taken on the general-purpose
// pool during a request — it removes a connection from circulation until
// released.
//
// One consequence worth knowing: a pool cannot be closed while a lock taken
// from it is still held. Close blocks waiting for the connection to come back,
// and only release returns it. Always release before shutting a pool down.
func (l *Locker) TryLock(ctx context.Context, key string) (release func(), ok bool, err error) {
	conn, err := l.pool.Acquire(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("pg: acquire for advisory lock: %w", err)
	}

	var acquired bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, lockKey(key)).Scan(&acquired); err != nil {
		conn.Release()
		return nil, false, fmt.Errorf("pg: try advisory lock %q: %w", key, err)
	}
	if !acquired {
		conn.Release()
		return nil, false, nil
	}

	var once sync.Once
	return func() {
		once.Do(func() {
			// Detached from the caller's context: release must happen even
			// when the reason for releasing is that the context was cancelled.
			unlockCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			// Nothing useful to do on failure: the lock is released anyway
			// when this connection closes, which is the crash-safety property
			// this design relies on.
			//nolint:errcheck // advisory locks free themselves on disconnect
			_, _ = conn.Exec(unlockCtx, `SELECT pg_advisory_unlock($1)`, lockKey(key))
			conn.Release()
		})
	}, true, nil
}

// lockKey hashes a name into the int64 advisory lock space.
//
// Collisions are possible in principle and harmless in practice: the worst case
// is that two unrelated keys serialise against each other, which costs a little
// concurrency and never corrupts anything.
func lockKey(name string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(name))
	// Reinterpreting the bits rather than narrowing a value: advisory lock
	// keys are an opaque 64-bit space, and a negative key is as valid as a
	// positive one.
	//nolint:gosec // G115: intentional bit reinterpretation, not a numeric conversion
	return int64(h.Sum64())
}
