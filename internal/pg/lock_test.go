package pg_test

import (
	"context"
	"sync"
	"testing"

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
