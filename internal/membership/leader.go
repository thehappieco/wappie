package membership

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/pg"
	"whatserver2/internal/store"
)

// The leader (the plan's DB7 and 4.7): of every process on one database,
// only the one that holds the contract's advisory lock follows the feed,
// runs the round and the sweep and sends the snapshots (and, from P5, the
// events), so none of them ever runs twice, even while a restart overlaps
// two processes. The lock is held through pg.Locker.Hold, whose
// context ends the moment its connection goes; every write the leader
// makes to the shared state is compare-and-set besides, so a late commit
// of a leader that lost its lock changes nothing.
//
// Its gaps are bounded well under the platform's contract_feed_silent alert
// (10 minutes without a read, the plan's 18): a long-poll answers within
// its wait (25 s); a process that does not lead tries the lock every
// Retry (30 s); a leader whose connection goes stops at once, one whose
// lock went quietly within the heartbeat (10 s), one whose link went
// silent within twice it; after a failure the feed
// is asked again within BackoffMax (60 s); and the round, the sweep and
// the snapshots run beside the feed, never in its way. Likewise every
// recorded workspace's snapshot goes at the leader's start, within the
// debounce of a change, and 55 minutes after its last accepted one, well
// under the 90 minutes after which the platform counts it stale
// (contract_snapshots_stale, the plan's 18).

// The leader's defaults.
const (
	// LockName is the advisory lock's name.
	LockName = "contract"
	// leaderRetry is how often a process that does not lead tries the
	// lock (DB7).
	leaderRetry = 30 * time.Second
	// modeCheck is how often the leader reads the mode, besides the
	// notices: a switch to off stops it within it (4.4).
	modeCheck = stateFor
	// feedBackoffMin and feedBackoffMax bound the wait after a feed call
	// that got no page (4.7), and the round's after a pass that left subs.
	feedBackoffMin = 2 * time.Second
	feedBackoffMax = time.Minute
	// feedSilentAfter is how long without a page before one ERROR.
	feedSilentAfter = 15 * time.Minute
	// roundIncompleteAfter is how long the round's passes may leave held
	// subs with no document (their PUTs failing) before one ERROR, and
	// before contract status --check reports them.
	roundIncompleteAfter = 15 * time.Minute
	// sweepEvery is how often the sweep runs, at most OrphanAfter apart:
	// an orphan is unfollowed within OrphanAfter and this of its last PUT,
	// well inside the 90 minutes after which the platform counts its
	// workspaces' snapshots stale.
	sweepEvery = 5 * time.Minute
	// roundEvery is how often a round that is done is asked again: a
	// person linked since whose sign-in PUT failed is subscribed within it.
	roundEvery = time.Minute
	// warnEvery spaces the follower's WARNs.
	warnEvery = time.Minute
)

// Leader runs the contract's background work in the process that holds
// the lock, while the contract is on and a secret is loaded.
type Leader struct {
	// Members calls the platform and stores what it answers.
	Members *Members
	// Pool is the database: the lock and the listening connection are
	// opened with its configuration, outside it.
	Pool *pgxpool.Pool
	Log  *slog.Logger
	// Key is the advisory lock's name (LockName when empty; tests make
	// their own, since every test schema shares one database's locks).
	Key string
	// The timings, the defaults above when zero (tests shorten them).
	Retry, Heartbeat, ModeCheck time.Duration
	// Wait is the long-poll's, in seconds (kc.MaxWait when zero).
	Wait                         int
	BackoffMin, BackoffMax       time.Duration
	SilentAfter, IncompleteAfter time.Duration
	SweepEvery, RoundEvery       time.Duration
	// The snapshots' timings (snapshots.go): the next after one accepted,
	// the debounce after a change, and the backoff after a failure.
	SnapshotEvery, SnapshotDebounce        time.Duration
	SnapshotBackoffMin, SnapshotBackoffMax time.Duration
}

func or[T comparable](v, def T) T {
	var zero T
	if v == zero {
		return def
	}
	return v
}

func (l *Leader) log() *slog.Logger {
	if l.Log != nil {
		return l.Log
	}
	return l.Members.log()
}

// Run leads whenever it can until ctx ends: while the contract is on and a
// secret is loaded it tries the lock, at once after a mode notice and
// every Retry otherwise; it leads until the mode is off, the lock goes or
// ctx ends. A leader that lost its lock waits twice Retry before it tries
// again, so a process that was waiting takes over first.
func (l *Leader) Run(ctx context.Context) {
	wake := make(chan string, 1)
	go l.listen(ctx, wake)
	locker := pg.NewLocker(l.Pool)
	key := or(l.Key, LockName)
	retry := or(l.Retry, leaderRetry)
	for ctx.Err() == nil {
		pause := retry
		if l.ready(ctx) {
			held, ok, err := locker.Hold(ctx, key, l.Heartbeat, store.ContractDirtyChannel, store.ContractModeChannel,
				store.ContractDueChannel)
			switch {
			case err != nil:
				l.log().Warn("contract: could not try the leader's lock", "error", err)
			case ok:
				lost := l.lead(held, wake) //nolint:contextcheck // the leader runs under held's context, which ctx's end ends
				held.Release()
				if !lost {
					continue
				}
				pause = 2 * retry
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-wake:
		case <-time.After(pause):
		}
	}
}

// ready reports whether this process may lead: the contract on, and the
// platform callable.
func (l *Leader) ready(ctx context.Context) bool {
	if !l.Members.connected() {
		return false
	}
	state, err := l.Members.Contract.State(ctx)
	if err != nil {
		if ctx.Err() == nil {
			l.log().Warn("contract: could not read the contract's state", "error", err)
		}
		return false
	}
	return state.On()
}

// listen delivers the mode channel's notices (a switch, a generation an
// answer did not match, a round to run) to wake, on a connection of its
// own, reconnecting with a backoff up to a minute, until ctx ends.
func (l *Leader) listen(ctx context.Context, wake chan<- string) {
	backoff := time.Second
	for ctx.Err() == nil {
		err := listenOn(ctx, l.Pool, store.ContractModeChannel, func(payload string) {
			select {
			case wake <- payload:
			default:
			}
		}, func() { backoff = time.Second })
		if ctx.Err() != nil {
			return
		}
		l.log().Warn("contract: listening for mode switches failed; the leader still tries every retry", "error", err, "retry_in", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, time.Minute)
	}
}

// listenOn LISTENs on channel on a connection of its own and calls notice
// for each notification until ctx ends or the connection fails; ready is
// called once it listens.
func listenOn(ctx context.Context, pool *pgxpool.Pool, channel string, notice func(string), ready func()) error {
	conn, err := pgx.ConnectConfig(ctx, pool.Config().ConnConfig.Copy())
	if err != nil {
		return err
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		//nolint:errcheck // closing a listener that is going away anyway
		_ = conn.Close(closeCtx)
	}()
	if _, err := conn.Exec(ctx, "LISTEN "+pgx.Identifier{channel}.Sanitize()); err != nil {
		return err
	}
	ready()
	for {
		n, err := conn.WaitForNotification(ctx)
		if err != nil {
			return err
		}
		notice(n.Payload)
	}
}

// lead runs the leader's loops under held's context until the mode is off,
// the lock goes, or the parent context ends, and reports whether it ended
// because the lock went.
func (l *Leader) lead(held *pg.Held, wake <-chan string) (lost bool) {
	ctx, stop := context.WithCancel(held.Context())
	defer stop()
	l.log().Info("contract: leading")
	f := &follower{l: l, round: make(chan struct{}, 1)}
	snaps := &snapshotSender{l: l, notices: newNotices(), logged: map[uuid.UUID]time.Time{}}
	var wg sync.WaitGroup
	wg.Go(func() { f.run(ctx) })
	wg.Go(func() { l.rounds(ctx, f.round) })
	wg.Go(func() { snaps.run(ctx) })
	wg.Go(func() { l.watchMode(ctx, stop, f, snaps.notices, held, wake) })
	wg.Wait()
	lost = errors.Is(context.Cause(held.Context()), pg.ErrLockLost)
	if lost {
		l.log().Warn("contract: the leader's lock is lost; stopping", "error", context.Cause(held.Context()))
	} else {
		l.log().Info("contract: no longer leading")
	}
	return lost
}

// watchMode stops the leader when the mode is off, read every ModeCheck
// and at each mode notice, and passes the other notices on, never waiting
// on their loops: a round to run now, a generation to look for at once
// (the long-poll in flight is cut), and to the snapshot sender the
// workspaces a change touched and the due times made sooner. It is the
// held connection's one reader.
func (l *Leader) watchMode(ctx context.Context, stop context.CancelFunc, f *follower, snaps *notices, held *pg.Held, wake <-chan string) {
	tick := time.NewTicker(or(l.ModeCheck, modeCheck))
	defer tick.Stop()
	check := func() {
		state, err := l.Members.Contract.State(ctx)
		if err != nil {
			return
		}
		if !state.On() {
			stop()
		}
	}
	notice := func(payload string) {
		switch payload {
		case "round":
			kick(f.round)
		case "generation":
			f.interrupt()
		default:
			check()
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			check()
		case payload := <-wake:
			notice(payload)
		case n, ok := <-held.Notifications():
			if !ok {
				return
			}
			switch n.Channel {
			case store.ContractModeChannel:
				notice(n.Payload)
			case store.ContractDirtyChannel:
				snaps.dirty(n.Payload)
			case store.ContractDueChannel:
				snaps.due()
			}
		}
	}
}

// kick wakes a loop that waits on c, without blocking.
func kick(c chan struct{}) {
	select {
	case c <- struct{}{}:
	default:
	}
}

// rounds runs the round and the sweep, one after the other (the plan's
// 4.6): the round at once, then again after a backoff while subs are left
// (within BackoffMax), every RoundEvery once it is done, and at once when
// kicked (a restart, a GET's not_found); the sweep at the leader's start
// and every SweepEvery. A run of passes whose PUTs keep failing logs one
// ERROR once it has lasted IncompleteAfter, and records it for contract
// status --check (DB24: someone is told when the contract fails).
func (l *Leader) rounds(ctx context.Context, kicked <-chan struct{}) {
	m := l.Members
	minBack, maxBack := or(l.BackoffMin, feedBackoffMin), or(l.BackoffMax, feedBackoffMax)
	backoff := minBack
	sweepAt := time.Now()
	var failingSince time.Time
	told := false
	for ctx.Err() == nil {
		done, err := m.Round(ctx)
		if err != nil && ctx.Err() == nil {
			l.log().Warn("contract: the round's pass failed", "error", err)
		}
		pause := or(l.RoundEvery, roundEvery)
		if done {
			backoff, failingSince, told = minBack, time.Time{}, false
		} else {
			pause, backoff = backoff, min(backoff*2, maxBack)
		}
		if !done && err == nil {
			// Every sub left was PUT in this pass, and some got no document.
			if failingSince.IsZero() {
				failingSince = time.Now()
			}
			if !told && time.Since(failingSince) >= or(l.IncompleteAfter, roundIncompleteAfter) {
				told = true
				l.incomplete(ctx, failingSince)
			}
		}
		if !time.Now().Before(sweepAt) {
			if n, err := m.Sweep(ctx); err != nil && ctx.Err() == nil {
				l.log().Warn("contract: the sweep's pass failed", "error", err)
			} else if n > 0 {
				l.log().Info("contract: the sweep unsubscribed orphans", "count", n)
			}
			sweepAt = time.Now().Add(or(l.SweepEvery, sweepEvery))
		}
		pause = min(pause, max(time.Until(sweepAt), 0))
		select {
		case <-ctx.Done():
			return
		case <-kicked:
		case <-time.After(pause):
		}
	}
}

// incomplete logs, and records for contract status --check, the round's
// ERROR: held subs whose PUTs have failed since since.
func (l *Leader) incomplete(ctx context.Context, since time.Time) {
	attrs := []any{"since", since.UTC().Format(time.RFC3339)}
	if state, err := l.Members.Contract.State(ctx); err == nil {
		attrs = append(attrs, "class", state.RoundError)
	}
	l.log().Error("contract: held subs still have no document of this generation; their PUTs fail", attrs...)
	if err := l.Members.Contract.RecordError(ctx, store.ContractErrorRoundIncomplete); err != nil && ctx.Err() == nil {
		l.log().Warn("contract: could not record an ERROR", "error", err)
	}
}

// wait is the long-poll's wait in seconds.
func (l *Leader) wait() int {
	if l.Wait > 0 {
		return min(l.Wait, kc.MaxWait)
	}
	return kc.MaxWait
}
