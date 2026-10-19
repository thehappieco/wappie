package pgtest

import (
	"context"
	"slices"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Backends records the server process of every connection a pool opens, so
// a test can tell its own sessions from other tests'. Each test has a schema
// of its own, but every test shares the database: a NOTIFY reaches every
// session listening on its channel, and pg_stat_activity lists every
// session, whichever package's test opened it. Give Configure to FreshWith.
type Backends struct {
	mu   sync.Mutex
	pids map[uint32]bool
}

// Configure records each connection the pool opens, after any AfterConnect
// already set.
func (b *Backends) Configure(cfg *pgxpool.Config) {
	next := cfg.AfterConnect
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		b.mu.Lock()
		if b.pids == nil {
			b.pids = map[uint32]bool{}
		}
		b.pids[c.PgConn().PID()] = true
		b.mu.Unlock()
		if next != nil {
			return next(ctx, c)
		}
		return nil
	}
}

// Has reports whether pid is one of the pool's backends.
func (b *Backends) Has(pid uint32) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.pids[pid]
}

// PIDs lists the pool's backends, for a query's pid = ANY ($1).
func (b *Backends) PIDs() []int32 {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]int32, 0, len(b.pids))
	for pid := range b.pids {
		out = append(out, int32(pid)) //nolint:gosec // G115: a backend's pid is a Postgres int4
	}
	slices.Sort(out)
	return out
}

// Notice waits on conn, which LISTENs on channel, for a notification with
// payload sent by one of the pool's backends, and skips every other: one
// another test sent, or one of the pool's with another payload. It returns
// the context's error when none comes.
func (b *Backends) Notice(ctx context.Context, conn *pgx.Conn, channel, payload string) error {
	for {
		n, err := conn.WaitForNotification(ctx)
		if err != nil {
			return err
		}
		if n.Channel == channel && n.Payload == payload && b.Has(n.PID) {
			return nil
		}
	}
}

// Waiting reports whether one of the pool's backends is waiting on a lock
// now: a test that proves a race waits on this, never on a sleep.
func (b *Backends) Waiting(ctx context.Context, pool *pgxpool.Pool) (bool, error) {
	var waiting bool
	err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity
		WHERE pid = ANY ($1) AND wait_event_type = 'Lock')`, b.PIDs()).Scan(&waiting)
	return waiting, err
}
