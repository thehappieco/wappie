package pg_test

import (
	"context"
	"errors"
	"net"
	"strconv"
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

// The heartbeat runs every interval however many notices arrive: a steady
// stream of them never postpones it (DB7: a holder whose lock went
// quietly stops within the heartbeat). The holder's backend shows the
// heartbeat as its latest query while notices keep coming.
func TestHoldBeatsThroughNotices(t *testing.T) {
	pool := pgtest.Connect(t)
	name := lockName(t)
	channel := "hold_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	held, ok, err := pg.NewLocker(pool).Hold(context.Background(), name, 100*time.Millisecond, channel)
	if err != nil || !ok {
		t.Fatalf("hold: ok=%v err=%v", ok, err)
	}
	defer held.Release()
	pid := holderPID(t, pool, name)
	latest := func() string {
		t.Helper()
		var q string
		if err := pool.QueryRow(context.Background(), `SELECT query FROM pg_stat_activity WHERE pid = $1`, pid).Scan(&q); err != nil {
			t.Fatal(err)
		}
		return q
	}
	if q := latest(); !strings.HasPrefix(q, "LISTEN") {
		t.Fatalf("the holder's latest query before any heartbeat: %q", q)
	}
	// A notice every 10 ms, each delivered, for a second.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			case <-held.Notifications():
			}
		}
	})
	for end := time.Now().Add(time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if _, err := pool.Exec(context.Background(), `SELECT pg_notify($1, 'x')`, channel); err != nil {
			t.Fatal(err)
		}
	}
	q := latest()
	close(stop)
	wg.Wait()
	if !strings.Contains(q, "pg_locks") {
		t.Fatalf("no heartbeat in a second of notices every 10 ms: the holder's latest query is %q", q)
	}
	if err := held.Context().Err(); err != nil {
		t.Fatalf("the hold ended: %v", context.Cause(held.Context()))
	}
}

// relay forwards TCP connections to the database until frozen: then it
// reads and drops whatever either side sends, keeping every connection
// open, as a half-open link does.
type relay struct {
	ln     net.Listener
	mu     sync.Mutex
	frozen bool
	conns  []net.Conn
}

func newRelay(t *testing.T, to string) *relay {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &relay{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", to)
			if err != nil {
				_ = c.Close()
				continue
			}
			r.mu.Lock()
			r.conns = append(r.conns, c, up)
			r.mu.Unlock()
			go r.pipe(c, up)
			go r.pipe(up, c)
		}
	}()
	t.Cleanup(r.kill)
	return r
}

func (r *relay) pipe(from, to net.Conn) {
	buf := make([]byte, 32<<10)
	for {
		n, err := from.Read(buf)
		if err != nil {
			_ = to.Close()
			return
		}
		r.mu.Lock()
		frozen := r.frozen
		r.mu.Unlock()
		if frozen {
			continue
		}
		if _, err := to.Write(buf[:n]); err != nil {
			return
		}
	}
}

func (r *relay) freeze() { r.mu.Lock(); r.frozen = true; r.mu.Unlock() }

// kill closes the relay and every connection through it.
func (r *relay) kill() {
	_ = r.ln.Close()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.conns {
		_ = c.Close()
	}
}

// A lock whose link goes silent (nothing answers, nothing closes) is lost
// within twice the heartbeat's interval and its floor of a second, not
// when TCP gives up: the heartbeat's own wait is bounded.
func TestHoldStopsOnASilentLink(t *testing.T) {
	direct := pgtest.Connect(t)
	cfg := direct.Config().Copy()
	r := newRelay(t, net.JoinHostPort(cfg.ConnConfig.Host, strconv.Itoa(int(cfg.ConnConfig.Port))))
	port, err := strconv.Atoi(strings.TrimPrefix(r.ln.Addr().String(), "127.0.0.1:"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Host, cfg.ConnConfig.Port, cfg.ConnConfig.Fallbacks = "127.0.0.1", uint16(port), nil
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	held, ok, err := pg.NewLocker(pool).Hold(context.Background(), lockName(t), 200*time.Millisecond)
	if err != nil || !ok {
		t.Fatalf("hold: ok=%v err=%v", ok, err)
	}
	time.Sleep(500 * time.Millisecond)
	if err := held.Context().Err(); err != nil {
		t.Fatalf("the hold ended on a live link: %v", context.Cause(held.Context()))
	}
	r.freeze()
	frozen := time.Now()
	select {
	case <-held.Context().Done():
	case <-time.After(5 * time.Second):
		r.kill()
		held.Release()
		t.Fatal("the holder did not stop within 5 s of its link going silent")
	}
	if took := time.Since(frozen); took > 2*time.Second {
		t.Fatalf("the holder stopped %v after its link went silent, want within 200 ms and a second", took)
	}
	if cause := context.Cause(held.Context()); !errors.Is(cause, pg.ErrLockLost) {
		t.Fatalf("the cause is %v, want ErrLockLost", cause)
	}
	r.kill()
	held.Release()
}
