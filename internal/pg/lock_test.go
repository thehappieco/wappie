package pg_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
)

// Two instances driving the same WhatsApp session would connect with identical
// credentials, and WhatsApp answers that by dropping one with StreamReplaced,
// over and over. Rolling deploys overlap old and new pods by design, so this
// lock is what stops the fleet fighting itself on every release.
func TestAdvisoryLockIsExclusive(t *testing.T) {
	pool := pgtest.Connect(t)
	ctx := context.Background()
	locker := pg.NewLocker(pool)

	release, ok, err := locker.TryLock(ctx, "device:lock-exclusive-abc")
	if err != nil || !ok {
		t.Fatalf("first lock: ok=%v err=%v", ok, err)
	}

	// A second attempt from a different connection must be refused, not block.
	other, err := pgxpool.New(ctx, pgtest.DSN())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()

	_, ok2, err := pg.NewLocker(other).TryLock(ctx, "device:lock-exclusive-abc")
	if err != nil {
		t.Fatal(err)
	}
	if ok2 {
		t.Fatal("two sessions hold the same device lock at once")
	}

	// A different device is unaffected.
	releaseOther, ok3, err := pg.NewLocker(other).TryLock(ctx, "device:lock-exclusive-xyz")
	if err != nil || !ok3 {
		t.Fatalf("an unrelated key should be lockable: ok=%v err=%v", ok3, err)
	}
	releaseOther()

	release()

	// After release the lock is available again.
	release2, ok4, err := pg.NewLocker(other).TryLock(ctx, "device:lock-exclusive-abc")
	if err != nil || !ok4 {
		t.Fatalf("lock not available after release: ok=%v err=%v", ok4, err)
	}
	release2()
}

func TestReleaseIsIdempotent(t *testing.T) {
	pool := pgtest.Connect(t)
	release, ok, err := pg.NewLocker(pool).TryLock(context.Background(), "device:lock-idempotent")
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	release()
	release() // must not double-release the pooled connection
	release()
}

// Exactly one caller wins.
//
// Each racer keeps its pool open until after the lock is released. That is not
// tidiness: TryLock holds a connection checked out of the pool for as long as
// the lock is held, so closing the pool first blocks forever waiting for a
// connection that is only returned by release.
func TestConcurrentLockAttempts(t *testing.T) {
	pgtest.Connect(t) // skip early when Postgres is unreachable
	ctx := context.Background()

	const racers = 8
	type result struct {
		release func()
		pool    *pgxpool.Pool
	}
	var (
		mu    sync.Mutex
		won   []result
		pools []*pgxpool.Pool
		wg    sync.WaitGroup
	)
	for range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, err := pgxpool.New(ctx, pgtest.DSN())
			if err != nil {
				return
			}
			mu.Lock()
			pools = append(pools, p)
			mu.Unlock()

			release, ok, err := pg.NewLocker(p).TryLock(ctx, "device:lock-race")
			if err != nil || !ok {
				return
			}
			mu.Lock()
			won = append(won, result{release: release, pool: p})
			mu.Unlock()
		}()
	}
	wg.Wait()

	for _, r := range won {
		r.release()
	}
	for _, p := range pools {
		p.Close()
	}

	if len(won) != 1 {
		t.Fatalf("%d of %d racers took the same lock, want exactly 1", len(won), racers)
	}
}

// holderPID is the backend that holds the advisory lock name, or 0.
func holderPID(t *testing.T, pool *pgxpool.Pool, name string) int32 {
	t.Helper()
	key := pg.LockKey(name)
	//nolint:gosec // G115: the key's bits, split as pg_locks shows them
	hi, lo := int64(uint32(uint64(key)>>32)), int64(uint32(uint64(key)))
	var pid int32
	err := pool.QueryRow(context.Background(), `SELECT coalesce(max(pid), 0) FROM pg_locks WHERE locktype = 'advisory' AND granted
		AND classid = $1::bigint::oid AND objid = $2::bigint::oid AND objsubid = 1`, hi, lo).Scan(&pid)
	if err != nil {
		t.Fatal(err)
	}
	return pid
}

func lockName(t *testing.T) string { return "hold:" + t.Name() + ":" + uuid.NewString() }

// A held lock is exclusive, and its release lets the next holder in.
func TestHoldIsExclusive(t *testing.T) {
	pool := pgtest.Connect(t)
	ctx := context.Background()
	name := lockName(t)
	locker := pg.NewLocker(pool)
	held, ok, err := locker.Hold(ctx, name, 0)
	if err != nil || !ok {
		t.Fatalf("the first hold: ok=%v err=%v", ok, err)
	}
	if holderPID(t, pool, name) == 0 {
		t.Fatal("pg_locks lists no holder of a held lock")
	}
	if _, ok, err := locker.Hold(ctx, name, 0); err != nil || ok {
		t.Fatalf("a second hold of a held lock: ok=%v err=%v", ok, err)
	}
	if _, ok, err := locker.TryLock(ctx, name); err != nil || ok {
		t.Fatalf("TryLock of a held lock: ok=%v err=%v", ok, err)
	}
	held.Release()
	held.Release() // idempotent
	if held.Context().Err() == nil {
		t.Fatal("a released hold's context is still alive")
	}
	if holderPID(t, pool, name) != 0 {
		t.Fatal("a released lock is still held")
	}
	again, ok, err := locker.Hold(ctx, name, 0)
	if err != nil || !ok {
		t.Fatalf("a hold after the release: ok=%v err=%v", ok, err)
	}
	again.Release()
}

// The holder learns at once that its lock's connection is gone, and its
// heartbeat, run many times, keeps a lock that is still held.
func TestHoldEndsWithItsConnection(t *testing.T) {
	pool := pgtest.Connect(t)
	ctx := context.Background()
	name := lockName(t)
	held, ok, err := pg.NewLocker(pool).Hold(ctx, name, 20*time.Millisecond)
	if err != nil || !ok {
		t.Fatalf("hold: ok=%v err=%v", ok, err)
	}
	defer held.Release()
	// Many heartbeats: a heartbeat that asked the wrong question would end
	// the hold of a lock still held.
	time.Sleep(300 * time.Millisecond)
	if err := held.Context().Err(); err != nil {
		t.Fatalf("the heartbeat ended a lock that is held: %v", context.Cause(held.Context()))
	}
	pid := holderPID(t, pool, name)
	if _, err := pool.Exec(ctx, `SELECT pg_terminate_backend($1)`, pid); err != nil {
		t.Fatal(err)
	}
	select {
	case <-held.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the holder did not see its connection go")
	}
	if cause := context.Cause(held.Context()); !errors.Is(cause, pg.ErrLockLost) {
		t.Fatalf("the cause is %v, want ErrLockLost", cause)
	}
	next, ok, err := pg.NewLocker(pool).Hold(ctx, name, 0)
	if err != nil || !ok {
		t.Fatalf("the lock was not free after its connection went: ok=%v err=%v", ok, err)
	}
	next.Release()
}

// The holder's connection delivers the notices of its channels, and the
// parent context's end ends the hold and frees the lock.
func TestHoldListens(t *testing.T) {
	pool := pgtest.Connect(t)
	name := lockName(t)
	channel := "hold_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	ctx, cancel := context.WithCancel(context.Background())
	held, ok, err := pg.NewLocker(pool).Hold(ctx, name, 20*time.Millisecond, channel)
	if err != nil || !ok {
		t.Fatalf("hold: ok=%v err=%v", ok, err)
	}
	for _, payload := range []string{"one", "two"} {
		if _, err := pool.Exec(context.Background(), `SELECT pg_notify($1, $2)`, channel, payload); err != nil {
			t.Fatal(err)
		}
		select {
		case n := <-held.Notifications():
			if n.Channel != channel || n.Payload != payload {
				t.Fatalf("got %q on %q, want %q", n.Payload, n.Channel, payload)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no notice %q", payload)
		}
	}
	cancel()
	held.Release()
	if holderPID(t, pool, name) != 0 {
		t.Fatal("the lock outlived its holder's context")
	}
}
