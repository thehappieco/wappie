package pg

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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

// HoldHeartbeat is how often a held lock's connection is asked whether it
// still holds the lock, when Hold is given no interval of its own: a holder
// whose lock went quietly is stopped within it, and one whose link went
// silent within twice it.
const HoldHeartbeat = 10 * time.Second

// ErrLockLost is the cause of a Held's context once its lock is gone: its
// connection failed or closed, or the server no longer lists the lock.
var ErrLockLost = errors.New("pg: the advisory lock is no longer held")

// Held is a session advisory lock held for as long as its holder works under
// it, on a connection of its own (opened with the pool's configuration but
// outside it, so it never takes a request's slot). Its Context ends the
// moment the lock may no longer be held: the connection's loss (a crash of
// the server process, pg_terminate_backend, a closed link) is seen at once,
// since the connection always waits on the server; a lock that went
// quietly within the heartbeat, which runs every interval however many
// notices arrive, and a link that went silent within twice it. Work done under the lock runs under
// that context, so it stops when the lock goes; and every write it makes to
// state other holders share must still be compare-and-set, since a commit
// already sent may land after the lock is gone.
//
// The connection also LISTENs on the channels Hold is given, and
// Notifications delivers what arrives: a listener that is the holder's own
// loses its notices exactly when it loses the lock.
type Held struct {
	ctx     context.Context
	cancel  context.CancelCauseFunc
	notes   chan *pgconn.Notification
	stopped chan struct{}
}

// Hold takes the session advisory lock key on a connection of its own and
// keeps it until Release or ctx's end, returning ok=false when another
// session holds it. every is the heartbeat (HoldHeartbeat when zero); the
// connection LISTENs on each of listen.
func (l *Locker) Hold(ctx context.Context, key string, every time.Duration, listen ...string) (*Held, bool, error) {
	if every <= 0 {
		every = HoldHeartbeat
	}
	conn, err := pgx.ConnectConfig(ctx, l.pool.Config().ConnConfig.Copy())
	if err != nil {
		return nil, false, fmt.Errorf("pg: connect for advisory lock: %w", err)
	}
	closeConn := func() {
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		//nolint:errcheck // closing frees the lock whatever the error
		_ = conn.Close(closeCtx)
	}
	k := lockKey(key)
	var acquired bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, k).Scan(&acquired); err != nil {
		closeConn()
		return nil, false, fmt.Errorf("pg: try advisory lock %q: %w", key, err)
	}
	if !acquired {
		closeConn()
		return nil, false, nil
	}
	for _, channel := range listen {
		if _, err := conn.Exec(ctx, "LISTEN "+pgx.Identifier{channel}.Sanitize()); err != nil {
			closeConn()
			return nil, false, fmt.Errorf("pg: listen on %q: %w", channel, err)
		}
	}
	hctx, cancel := context.WithCancelCause(ctx)
	h := &Held{ctx: hctx, cancel: cancel, notes: make(chan *pgconn.Notification, 64), stopped: make(chan struct{})}
	go h.watch(conn, k, every, closeConn) //nolint:contextcheck // the watcher runs under h.ctx, which ctx's end ends
	return h, true, nil
}

// Context is the holder's: it ends when the lock may no longer be held, with
// ErrLockLost as its cause, or when Release or the parent context ends it.
func (h *Held) Context() context.Context { return h.ctx }

// Notifications are the notices of the channels Hold listens on, in the
// order they arrived, until the lock goes. Nothing is delivered after the
// context ends.
func (h *Held) Notifications() <-chan *pgconn.Notification { return h.notes }

// Release lets the lock go and closes its connection, and returns once both
// are done. It is idempotent.
func (h *Held) Release() {
	h.cancel(context.Canceled)
	<-h.stopped
}

// watch waits on the connection for notices, which it delivers, and asks
// every interval, notices or none, whether the lock is still held, waiting
// for the answer at most that interval (and at least a second: a busy
// server is not a lost lock). So a connection that went silent (a
// half-open link, which the server's statement_timeout cannot end) fails
// within twice the interval rather than when TCP gives up. Any failure of the
// connection, or a lock the server no longer lists, ends the holder's
// context. On the way out the lock is released, unless it is already lost,
// and the connection closed.
func (h *Held) watch(conn *pgx.Conn, key int64, every time.Duration, closeConn func()) {
	defer close(h.stopped)
	defer func() {
		if !conn.IsClosed() && !errors.Is(context.Cause(h.ctx), ErrLockLost) {
			unlockCtx, cancel := context.WithTimeout(context.WithoutCancel(h.ctx), 5*time.Second)
			//nolint:errcheck // closing the connection frees the lock anyway
			_, _ = conn.Exec(unlockCtx, `SELECT pg_advisory_unlock($1)`, key)
			cancel()
		}
		closeConn()
	}()
	// pg_locks lists a bigint key as its high and low 32 bits.
	//nolint:gosec // G115: the key's bits, split as pg_locks shows them
	hi, lo := int64(uint32(uint64(key)>>32)), int64(uint32(uint64(key)))
	beat := time.Now()
	for {
		if left := every - time.Since(beat); left > 0 {
			wait, cancel := context.WithTimeout(h.ctx, left)
			n, err := conn.WaitForNotification(wait)
			cancel()
			if h.ctx.Err() != nil {
				return
			}
			switch {
			case err == nil:
				select {
				case h.notes <- n:
				case <-h.ctx.Done():
					return
				}
				continue
			case !errors.Is(err, context.DeadlineExceeded) || conn.IsClosed():
				h.cancel(fmt.Errorf("%w: %w", ErrLockLost, err))
				return
			}
		}
		ask, cancel := context.WithTimeout(h.ctx, max(every, time.Second))
		var held bool
		err := conn.QueryRow(ask, `SELECT EXISTS (SELECT 1 FROM pg_locks WHERE pid = pg_backend_pid()
			AND locktype = 'advisory' AND granted AND classid = $1::bigint::oid AND objid = $2::bigint::oid AND objsubid = 1)`,
			hi, lo).Scan(&held)
		cancel()
		switch {
		case h.ctx.Err() != nil:
			return
		case err != nil:
			h.cancel(fmt.Errorf("%w: the heartbeat failed: %w", ErrLockLost, err))
			return
		case !held:
			h.cancel(fmt.Errorf("%w: the server no longer lists it", ErrLockLost))
			return
		}
		beat = time.Now()
	}
}

// LockKey is the advisory lock key a name hashes to, as pg_locks shows it
// (classid the high 32 bits, objid the low): tests find a holder's backend
// by it.
func LockKey(name string) int64 { return lockKey(name) }

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

// TryLockTx uses the same namespace as running WhatsApp supervisors, but the
// database releases it with the caller's transaction even after a crash.
func TryLockTx(ctx context.Context, tx interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, key string) (bool, error) {
	var ok bool
	err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, lockKey(key)).Scan(&ok)
	return ok, err
}
