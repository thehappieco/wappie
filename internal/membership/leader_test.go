package membership

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	kc "github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/contract/contracttest"
	"github.com/thehappieco/kit/profiles/wappie"

	"whatserver2/internal/membership/membershiptest"
	"whatserver2/internal/pg"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// The leader and the follower on a real database and the fake platform
// (the plan's DB7, 4.6 to 4.8; TB20 to TB26).

// leader is a leader over w with the test's timings, its bounds in
// milliseconds, on a lock of the test's own (every test schema shares one
// database's advisory locks).
func (w *world) leader(m *Members, logs *membershiptest.Logs, key string) *Leader {
	return &Leader{Members: m, Pool: w.pool, Log: logs.Logger(), Key: key,
		Retry: 300 * time.Millisecond, Heartbeat: 100 * time.Millisecond, ModeCheck: 100 * time.Millisecond, Wait: 1,
		BackoffMin: 20 * time.Millisecond, BackoffMax: 200 * time.Millisecond, SweepEvery: time.Hour, RoundEvery: 200 * time.Millisecond}
}

// run starts l until the test ends or stop.
func run(t *testing.T, l *Leader) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		l.Run(ctx)
		close(done)
	}()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			<-done
		})
	}
	t.Cleanup(stop)
	return stop
}

func eventually(t *testing.T, within time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v: %s", within, what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (w *world) state(t *testing.T) store.ContractState {
	t.Helper()
	s, err := w.contract.State(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// version is sub's stored document's version, 0 for none.
func (w *world) version(t *testing.T, sub uuid.UUID) int64 {
	t.Helper()
	var v *int64
	err := w.pool.QueryRow(context.Background(), `SELECT (doc->>'version')::bigint FROM contract_accounts WHERE sub = $1`, sub).Scan(&v)
	if err != nil || v == nil {
		return 0
	}
	return *v
}

func lockKey(t *testing.T) string { return "contract:" + t.Name() + ":" + uuid.NewString() }

// lockHolder is the backend holding the advisory lock name, 0 for none.
func (w *world) lockHolder(t *testing.T, name string) int32 {
	t.Helper()
	key := pg.LockKey(name)
	//nolint:gosec // G115: the key's bits, split as pg_locks shows them
	hi, lo := int64(uint32(uint64(key)>>32)), int64(uint32(uint64(key)))
	var pid int32
	if err := w.pool.QueryRow(context.Background(), `SELECT coalesce(max(pid), 0) FROM pg_locks WHERE locktype = 'advisory'
		AND granted AND classid = $1::bigint::oid AND objid = $2::bigint::oid AND objsubid = 1`, hi, lo).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	return pid
}

// TestLeaderBounds pins the bounds the platform's alerts rest on with
// literals (the plan's 18): a test that reads a constant cannot pin it.
func TestLeaderBounds(t *testing.T) {
	for name, c := range map[string]struct{ got, want time.Duration }{
		"a non-leader's retry":      {leaderRetry, 30 * time.Second},
		"the lock's heartbeat":      {pg.HoldHeartbeat, 10 * time.Second},
		"the mode's check":          {modeCheck, 5 * time.Second},
		"the sign-ins' mode cache":  {stateFor, 5 * time.Second},
		"the feed's longest pause":  {feedBackoffMax, time.Minute},
		"the feed's first pause":    {feedBackoffMin, 2 * time.Second},
		"the silence's ERROR":       {feedSilentAfter, 15 * time.Minute},
		"the round's ERROR":         {roundIncompleteAfter, 15 * time.Minute},
		"the sweep's interval":      {sweepEvery, 5 * time.Minute},
		"an orphan's age":           {OrphanAfter, 15 * time.Minute},
		"a done round's next pass":  {roundEvery, time.Minute},
		"the long-poll, in seconds": {time.Duration((&Leader{}).wait()) * time.Second, 25 * time.Second},
	} {
		if c.got != c.want {
			t.Errorf("%s: %v, want %v", name, c.got, c.want)
		}
	}
	// The worst gap between two reads of the feed, by the bounds above: a
	// long-poll's wait and the kit's grace, a lost lock seen within twice
	// the heartbeat (a silent link) and taken over within a retry, and the
	// longest backoff.
	worst := 25*time.Second + kc.FeedGrace + 2*pg.HoldHeartbeat + leaderRetry + feedBackoffMax
	if worst >= 5*time.Minute {
		t.Errorf("the worst gap between reads is %v, not well under the platform's 10 minutes", worst)
	}
}

// TB20, the follower's part: a feed document newer than the stored one is
// stored, and refreshes nobody (only an answer does); while the platform's
// publisher is stuck, published_through stays at its oldest unpublished
// change and moves again once it publishes; and a page with more stores no
// published_through, the last page of the run does.
func TestFollowerNewerOnly(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	_, sub := w.held(t)
	logs := &membershiptest.Logs{}
	stop := run(t, w.leader(w.members, logs, lockKey(t)))
	// The platform follows the sub once it served the PUT, and the page may
	// store the document first: the PUT's answer, which sets fresh_at, is
	// waited for too.
	eventually(t, 10*time.Second, "the round's answer and a page", func() bool {
		s := w.state(t)
		_, _, at := w.row(context.Background(), t, sub)
		return w.following(sub) && at != nil && w.version(t, sub) > 0 && s.FeedCursor >= 1 && s.PublishedThrough != nil
	})
	_, _, answered := w.row(ctx, t, sub)
	if answered == nil {
		t.Fatal("the round's answer set no fresh_at")
	}
	team, err := w.fake.AddTeam("Equipe", sub.String())
	if err != nil {
		t.Fatal(err)
	}
	before := w.version(t, sub)
	eventually(t, 10*time.Second, "the team's document", func() bool { return w.version(t, sub) > before })
	if _, _, at := w.row(ctx, t, sub); at == nil || !at.Equal(*answered) {
		t.Fatalf("a feed document moved fresh_at from %v to %v", answered, at)
	}
	if _, ok, err := w.contract.Workspace(ctx, uuid.MustParse(team)); err != nil || !ok {
		t.Fatalf("the team was not recorded: %v %v", ok, err)
	}

	// A stuck publisher: published_through stays at the held change.
	if err := w.fake.HoldPublishing("wappie"); err != nil {
		t.Fatal(err)
	}
	changed := time.Now()
	if err := w.fake.RenameTeam(team, "Outra"); err != nil {
		t.Fatal(err)
	}
	reads := len(w.fake.Reads())
	eventually(t, 10*time.Second, "two long-polls after the held change", func() bool { return len(w.fake.Reads()) >= reads+2 })
	held := *w.state(t).PublishedThrough
	if held.After(changed.Add(time.Second)) {
		t.Fatalf("published_through %v ran past the change held at %v", held, changed)
	}
	reads = len(w.fake.Reads())
	eventually(t, 10*time.Second, "two more long-polls", func() bool { return len(w.fake.Reads()) >= reads+2 })
	if pt := w.state(t).PublishedThrough; !pt.Equal(held) {
		t.Fatalf("published_through moved from %v to %v while the publisher is stuck", held, pt)
	}
	if err := w.fake.Release("wappie"); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "published_through after the release", func() bool { return w.state(t).PublishedThrough.After(held) })

	// A run of pages: 201 documents of subscriptions made while no leader
	// ran, so the first page ends with more.
	stop()
	for range kc.MaxFeedItems + 1 {
		other := uuid.New()
		if _, err := w.fake.AddAccount(other.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := w.members.Client.Subscribe(ctx, other.String()); err != nil {
			t.Fatal(err)
		}
	}
	start := w.state(t)
	var seen atomic.Pointer[store.ContractState]
	w.fake.Before(contracttest.CallFeed, func(string) {
		if s, err := w.contract.State(ctx); err == nil && s.FeedCursor > start.FeedCursor && seen.Load() == nil {
			seen.Store(&s)
		}
	})
	run(t, w.leader(w.members, logs, lockKey(t)))
	eventually(t, 20*time.Second, "the run of pages", func() bool {
		s := w.state(t)
		return seen.Load() != nil && s.PublishedThrough.After(*start.PublishedThrough)
	})
	w.fake.Before(contracttest.CallFeed, nil)
	mid := seen.Load()
	if mid.FeedCursor-start.FeedCursor != kc.MaxFeedItems || !mid.PublishedThrough.Equal(*start.PublishedThrough) {
		t.Fatalf("after a page with more: cursor %d (from %d), published_through %v (was %v)",
			mid.FeedCursor, start.FeedCursor, mid.PublishedThrough, start.PublishedThrough)
	}
}

// TB21: every corruption of a signed answer, and every refusal but gone,
// moves no cursor and stores nothing, and the follower backs off; the
// answer after it is taken.
func TestFollowerIgnoresBadAnswers(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	_, sub := w.held(t)
	logs := &membershiptest.Logs{}
	l := w.leader(w.members, logs, lockKey(t))
	// The platform's long-poll: only a change, or a notice that cuts it,
	// ends one before 25 s.
	l.Wait, l.BackoffMin, l.BackoffMax = 25, 20*time.Millisecond, 100*time.Millisecond
	run(t, l)
	eventually(t, 10*time.Second, "the round and a page", func() bool { return w.following(sub) && w.state(t).FeedCursor >= 1 })
	team, err := w.fake.AddTeam("Equipe", sub.String())
	if err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "the team's document", func() bool {
		_, recorded, _ := w.contract.Workspace(ctx, uuid.MustParse(team))
		return recorded
	})
	// What each feed request finds stored, before it is served.
	type seen struct {
		cursor, version int64
		failed          string
		read            time.Time
	}
	var mu sync.Mutex
	var log []seen
	w.fake.Before(contracttest.CallFeed, func(string) {
		s, err := w.contract.State(ctx)
		if err != nil || s.FeedReadAt == nil {
			return
		}
		mu.Lock()
		log = append(log, seen{s.FeedCursor, w.version(t, sub), s.FeedError, *s.FeedReadAt}) //nolint:contextcheck // a test's read
		mu.Unlock()
	})
	defer w.fake.Before(contracttest.CallFeed, nil)
	names := 0
	rename := func() {
		t.Helper()
		names++
		if err := w.fake.RenameTeam(team, fmt.Sprintf("Equipe %d", names)); err != nil {
			t.Fatal(err)
		}
	}
	// A corruption spoils the next answer, the long-poll in flight, which
	// the change wakes: the request after it finds the state as it was
	// (no page committed, not even its read) and the failure recorded.
	for _, how := range []contracttest.Corruption{contracttest.Unsigned, contracttest.AnotherNonce, contracttest.AnotherBody,
		contracttest.AnotherSecret, contracttest.Stale} {
		if err := w.fake.Corrupt("wappie", contracttest.CallFeed, how); err != nil {
			t.Fatal(err)
		}
		// Read after the corruption is set: every answer since is the
		// corrupted one, which must change nothing.
		was := w.state(t)
		mu.Lock()
		from := len(log)
		mu.Unlock()
		version := w.version(t, sub)
		rename()
		eventually(t, 10*time.Second, "the document after the corruption", func() bool { return w.version(t, sub) > version })
		mu.Lock()
		after := slices.Clone(log[from:])
		mu.Unlock()
		if !slices.Contains(after, seen{was.FeedCursor, version, "unverified", *was.FeedReadAt}) {
			t.Fatalf("corruption %d: the requests after it saw %+v, want one from cursor %d, version %d, read at %v, after an unverified answer",
				how, after, was.FeedCursor, version, was.FeedReadAt)
		}
	}
	elsewhere := uuid.New()
	w.exec(ctx, t, `INSERT INTO contract_workspaces (workspace_id, kind) VALUES ($1, 'team')`, elsewhere)
	// A refusal, every time: the cursor stays and nothing is stored, at a
	// backoff, until the platform answers again.
	for _, code := range []string{kc.CodeUnauthenticated, kc.CodeStale, kc.CodeReplay, kc.CodeInvalid, kc.CodeNotFound,
		kc.CodeConflict, kc.CodeTooLarge, kc.CodeRateLimited, kc.CodeUnavailable} {
		w.fake.RefuseAlways(contracttest.CallFeed, code)
		// The long-poll in flight began before the refusals: a generation's
		// notice cuts it at once, and the next request is refused.
		w.exec(ctx, t, `SELECT pg_notify($1, 'generation')`, store.ContractModeChannel)
		eventually(t, 2*time.Second, code+": a refusal soon after the notice", func() bool { return w.state(t).FeedError != "" })
		cursor, version := w.state(t).FeedCursor, w.version(t, sub)
		calls := w.fake.Count(contracttest.CallFeed)
		rename()
		time.Sleep(400 * time.Millisecond)
		if s := w.state(t); s.FeedCursor != cursor || w.version(t, sub) != version || s.FeedError == "" || s.FeedErrorAt == nil {
			t.Fatalf("%s: cursor %d (was %d), version %d (was %d), error %q", code, s.FeedCursor, cursor, w.version(t, sub), version, s.FeedError)
		}
		// 20 ms doubling to 100: a handful in 400 ms (a signed replay or
		// unavailable is asked twice), never a busy loop.
		if n := w.fake.Count(contracttest.CallFeed) - calls; n < 2 || n > 30 {
			t.Fatalf("%s: %d feed calls in 400 ms", code, n)
		}
		// A workspace backing off meanwhile (a snapshot refused for the
		// same outage), which no document of the run names, is due at once
		// when the feed answers again.
		w.exec(ctx, t, `UPDATE contract_workspaces SET snapshot_tries = 3, snapshot_due_at = clock_timestamp() + interval '1 hour',
			snapshot_ok_at = clock_timestamp() WHERE workspace_id = $1`, elsewhere)
		w.fake.RefuseAlways(contracttest.CallFeed, "")
		eventually(t, 10*time.Second, code+": the document after the refusal", func() bool { return w.version(t, sub) > version })
		var due bool
		if err := w.pool.QueryRow(ctx, `SELECT snapshot_due_at <= clock_timestamp() AND snapshot_tries = 0 FROM contract_workspaces
			WHERE workspace_id = $1`, elsewhere).Scan(&due); err != nil || !due {
			t.Fatalf("%s: the backed-off workspace is not due after the recovery (%v)", code, err)
		}
		if s := w.state(t); s.FeedError != "" || s.FeedErrorAt != nil {
			t.Fatalf("%s: the feed's error stays after a page: %+v", code, s)
		}
	}
	if len(logs.Lines("contract: the feed got no page")) == 0 || len(logs.Lines("contract: the feed answers again")) == 0 {
		t.Fatalf("the follower said nothing of its failures:\n%s", logs.String())
	}
}

// TB22: a restore (a gone) and a new generation: the stored versions, the
// freshness and published_through are forgotten, the highest revocation
// times kept, every sub is PUT again, the feed read from 0, every
// workspace's snapshot due; a lower wversion of the new generation is
// applied; the confirmation is stored; and with no generation stored (the
// first observe), the first page adopts the platform's.
func TestGoneAndNewGeneration(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	_, one := w.held(t)
	_, two := w.held(t)
	logs := &membershiptest.Logs{}
	l := w.leader(w.members, logs, lockKey(t))
	l.RoundEvery = time.Hour // only the restart's kick runs the round again
	run(t, l)
	platformGen, _ := w.fake.Generation()
	eventually(t, 10*time.Second, "the first page adopts the generation", func() bool {
		s := w.state(t)
		return s.Generation != nil && s.Generation.String() == platformGen && s.FeedCursor >= 2 && s.RoundGeneration != nil
	})
	team, err := w.fake.AddTeam("Equipe", one.String())
	if err != nil {
		t.Fatal(err)
	}
	ws := uuid.MustParse(team)
	eventually(t, 10*time.Second, "the team recorded", func() bool { _, ok, _ := w.contract.Workspace(ctx, ws); return ok })
	disabled := dbNow(t, w.pool, "-2 hours")

	for _, how := range []string{"restore", "new generation"} {
		// What a restart must forget, and what it must keep.
		w.exec(ctx, t, `UPDATE contract_accounts SET disabled_at = $1, sessions_revoked_at = $1 WHERE sub = $2`, disabled, one)
		w.exec(ctx, t, `UPDATE contract_workspaces SET wversion = 99, status = 'open', snapshot_due_at = clock_timestamp() + interval '1 day',
			not_found_since = clock_timestamp()`)
		var gen string
		if how == "restore" {
			gen = w.fake.Restore()
		} else {
			gen = w.fake.NewGeneration()
		}
		eventually(t, 15*time.Second, how+": the restart and the round", func() bool {
			s := w.state(t)
			return s.Generation != nil && s.Generation.String() == gen && s.RoundGeneration != nil && *s.RoundGeneration == *s.Generation &&
				w.following(one) && w.following(two)
		})
		s := w.state(t)
		if s.GenerationConfirmed {
			t.Fatalf("%s: an unconfirmed generation stored as confirmed", how)
		}
		var kept int
		if err := w.pool.QueryRow(ctx, `SELECT count(*) FROM contract_accounts WHERE sub = $1 AND disabled_at = $2 AND sessions_revoked_at = $2
			AND version IS NOT NULL AND generation = $3`, one, disabled, gen).Scan(&kept); err != nil || kept != 1 {
			t.Fatalf("%s: the highest revocation times or the new version (%d, %v)", how, kept, err)
		}
		var due, parked int
		if err := w.pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE snapshot_due_at <= clock_timestamp()),
			count(*) FILTER (WHERE not_found_since IS NOT NULL) FROM contract_workspaces`).Scan(&due, &parked); err != nil || due != 3 || parked != 0 {
			t.Fatalf("%s: %d of 3 workspaces due, %d still not_found (%v)", how, due, parked, err)
		}
		// The restart made every wversion 0: the new generation's are taken.
		if err := w.fake.CloseTeam(team); err != nil {
			t.Fatal(err)
		}
		eventually(t, 10*time.Second, how+": a lower wversion's status", func() bool {
			rec, _, _ := w.contract.Workspace(ctx, ws)
			return rec.Status == "closed"
		})
		if err := w.fake.ReopenTeam(team); err != nil {
			t.Fatal(err)
		}
		eventually(t, 10*time.Second, how+": reopened", func() bool { rec, _, _ := w.contract.Workspace(ctx, ws); return rec.Status == "open" })
		if len(logs.Lines("contract: the platform's generation changed")) == 0 {
			t.Fatalf("%s: no WARN of the restart", how)
		}
	}
	w.fake.ConfirmGeneration()
	if err := w.fake.RenameTeam(team, "Confirmada"); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "the confirmation", func() bool { return w.state(t).GenerationConfirmed })
}

// dbNow is the database's clock moved by offset.
func dbNow(t *testing.T, pool *pgxpool.Pool, offset string) time.Time {
	t.Helper()
	var at time.Time
	if err := pool.QueryRow(context.Background(), `SELECT clock_timestamp() + $1::interval`, offset).Scan(&at); err != nil {
		t.Fatal(err)
	}
	return at
}

// counting counts a process's feed requests.
type counting struct {
	feed atomic.Int64
}

func (c *counting) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.HasSuffix(r.URL.Path, "/feed") {
		c.feed.Add(1)
	}
	return http.DefaultTransport.RoundTrip(r)
}

// TB23: two processes on one database: one long-poll at a time, one round;
// when the leader's lock connection is killed, it makes no feed call
// again, and the other takes over within its retry.
func TestOneLeader(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	var subs []uuid.UUID
	for range 3 {
		_, sub := w.held(t)
		subs = append(subs, sub)
	}
	key := lockKey(t)
	type process struct {
		count *counting
		logs  *membershiptest.Logs
	}
	var procs []process
	for range 2 {
		c := &counting{}
		client := NewClient(&http.Client{Transport: c}, w.fake.URL, nil)
		if err := client.Use(w.secret, ""); err != nil {
			t.Fatal(err)
		}
		logs := &membershiptest.Logs{}
		m := &Members{Client: client, Contract: w.contract, Log: logs.Logger(), ModeCache: -1, Pace: time.Millisecond}
		run(t, w.leader(m, logs, key))
		procs = append(procs, process{c, logs})
	}
	eventually(t, 10*time.Second, "one leader's round", func() bool {
		return w.following(subs[0]) && w.following(subs[1]) && w.following(subs[2]) && w.state(t).RoundGeneration != nil
	})
	time.Sleep(time.Second)
	if n := w.fake.Count(contracttest.CallSubscribe); n != 3 {
		t.Fatalf("%d PUTs for 3 subs: the round ran twice", n)
	}
	if n := w.fake.Most(contracttest.CallFeed); n != 1 {
		t.Fatalf("%d long-polls at once", n)
	}
	leading := -1
	for i, p := range procs {
		if p.count.feed.Load() > 0 {
			if leading >= 0 {
				t.Fatal("both processes read the feed")
			}
			leading = i
		}
	}
	if leading < 0 {
		t.Fatal("no process reads the feed")
	}
	old, other := procs[leading], procs[1-leading]
	pid := w.lockHolder(t, key)
	if pid == 0 {
		t.Fatal("no backend holds the lock")
	}
	if _, err := w.pool.Exec(ctx, `SELECT pg_terminate_backend($1)`, pid); err != nil {
		t.Fatal(err)
	}
	killed := time.Now()
	eventually(t, 5*time.Second, "the old leader stops", func() bool { return len(old.logs.Lines("contract: the leader's lock is lost")) > 0 })
	calls := old.count.feed.Load()
	eventually(t, 3*time.Second, "the other takes over", func() bool { return other.count.feed.Load() > 0 })
	if took := time.Since(killed); took > 2*time.Second {
		t.Fatalf("the takeover took %v with a retry of 300 ms", took)
	}
	time.Sleep(time.Second)
	if n := old.count.feed.Load(); n != calls {
		t.Fatalf("the old leader made %d feed calls after its lock went", n-calls)
	}
	if n := w.fake.Most(contracttest.CallFeed); n != 1 {
		t.Fatalf("%d long-polls at once across the takeover", n)
	}
}

// TestFeedNeverSilent: on the fake platform's clock, which runs twenty
// times faster than the test's (and the leader's timings twenty times
// shorter than their defaults), no gap between two reads of the feed comes
// near the platform's 10-minute contract_feed_silent alert, nor the
// 5-minute early warning of contract status: not while a leader follows,
// nor across a takeover after the lock's connection is killed, a restart
// of the leading process, or an outage of the platform after it answers
// again.
func TestFeedNeverSilent(t *testing.T) {
	const scale = 20
	// An hour behind the database's clock to start with, so that the
	// platform's published_through never runs past it within the test.
	origin := time.Now()
	clock := func() time.Time { return origin.Add(-time.Hour + time.Since(origin)*scale) }
	w := newWorldAt(t, clock)
	key := lockKey(t)
	_, sub := w.held(t)
	scaled := func(m *Members, logs *membershiptest.Logs) *Leader {
		return &Leader{Members: m, Pool: w.pool, Log: logs.Logger(), Key: key,
			Retry: leaderRetry / scale, Heartbeat: pg.HoldHeartbeat / scale, ModeCheck: modeCheck / scale, Wait: 1,
			BackoffMin: feedBackoffMin / scale, BackoffMax: feedBackoffMax / scale, SweepEvery: sweepEvery / scale, RoundEvery: roundEvery / scale}
	}
	second := func() *Members {
		client := NewClient(&http.Client{}, w.fake.URL, clock)
		if err := client.Use(w.secret, ""); err != nil {
			t.Fatal(err)
		}
		return &Members{Client: client, Contract: w.contract, Log: w.logs.Logger(), ModeCache: -1, Pace: time.Millisecond}
	}
	stopA := run(t, scaled(w.members, &membershiptest.Logs{}))
	run(t, scaled(second(), &membershiptest.Logs{}))
	eventually(t, 10*time.Second, "the follower", func() bool { return w.following(sub) && len(w.fake.Reads()) > 2 })
	time.Sleep(2 * time.Second)

	// A takeover: whoever holds the lock loses its connection.
	if _, err := w.pool.Exec(context.Background(), `SELECT pg_terminate_backend($1)`, w.lockHolder(t, key)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Second)
	// A restart of the first process (whichever leads, the other takes
	// over or it starts again).
	stopA()
	time.Sleep(2 * time.Second)
	run(t, scaled(second(), &membershiptest.Logs{}))
	time.Sleep(2 * time.Second)
	// An outage: the platform answers nothing for a platform-minute, then
	// answers again.
	w.fake.SetDown(true)
	down := clock()
	time.Sleep(3 * time.Second)
	w.fake.SetDown(false)
	up := clock()
	time.Sleep(2 * time.Second)

	reads := w.fake.Reads()
	worst, back := time.Duration(0), time.Duration(-1)
	for i := 1; i < len(reads); i++ {
		if reads[i-1].Before(up) && reads[i].After(down) {
			// The outage is the platform's own; what counts is how soon the
			// follower reads once it answers again.
			continue
		}
		worst = max(worst, reads[i].Sub(reads[i-1]))
	}
	for _, r := range reads {
		if r.After(up) {
			back = r.Sub(up)
			break
		}
	}
	if worst > 5*time.Minute || worst == 0 {
		t.Fatalf("the longest gap between reads is %v of the platform's clock (%d reads)", worst, len(reads))
	}
	if back < 0 || back > 2*time.Minute {
		t.Fatalf("after the outage the feed was read %v later on the platform's clock", back)
	}
	t.Logf("the longest gap %v, the read after the outage %v later, on the platform's clock", worst, back)
}

// TB24: across the platform's changes, observe stores and compares and
// changes nothing of Wappie's own: its people, memberships, sessions,
// keys, grants, permissions, workspaces and connections are as they were;
// each difference of the plan's 4.8 is logged, by ids only. The person is
// a legacy account linked to the platform, whose user id is not its sub,
// as the pilot's people who signed up before the platform's sign-in; what
// enforce would end counts only what began before the revocation times.
func TestObserveChangesNothing(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	user, sub := w.legacy(t)
	owner := uuid.New()
	if _, err := w.fake.AddAccount(owner.String()); err != nil {
		t.Fatal(err)
	}
	teams := map[string]uuid.UUID{}
	for _, name := range []string{"Equipe Dois", "Equipe Tres"} {
		id, err := w.fake.AddTeam(name, owner.String())
		if err != nil {
			t.Fatal(err)
		}
		teams[name] = uuid.MustParse(id)
	}
	two, three := teams["Equipe Dois"], teams["Equipe Tres"]
	// Wappie's own: the two teams with the platform's ids; the person an
	// admin of the first, a disabled member of the second; an unlinked
	// colleague in the first; a number of the first the person reads, with
	// a key; and, from an hour ago (before the revocation times below) and
	// from ten minutes ago (after them), a session, a key, an MCP
	// connection, an AI connection and a standing service account each.
	w.localTeam(t, two, "Equipe Dois", member{user, "admin", "active"})
	w.localTeam(t, three, "Equipe Tres", member{user, "member", "disabled"})
	colleague := w.localPerson(t)
	w.localTeam(t, two, "", member{colleague, "member", "active"})
	w.reader(t, two, user)
	for _, at := range []time.Time{dbNow(t, w.pool, "-1 hour"), dbNow(t, w.pool, "-10 minutes")} {
		w.credentials(t, two, user, at)
	}
	before := w.dump(t)

	logs := &membershiptest.Logs{}
	w.members.Log = logs.Logger()
	run(t, w.leader(w.members, logs, lockKey(t)))
	lines := func() int { return len(logs.Lines("contract observe: differences", "sub="+sub.String())) }
	eventually(t, 10*time.Second, "the round's document", func() bool { return lines() >= 1 })
	revoke := dbNow(t, w.pool, "-30 minutes")
	var four string
	steps := []struct {
		name string
		act  func() error
	}{
		{"AddTeam", func() (err error) { four, err = w.fake.AddTeam("Equipe Quatro", sub.String()); return err }},
		{"SetRole", func() error { return w.fake.SetRole(two.String(), sub.String(), "member") }},
		{"SetRole again", func() error { return w.fake.SetRole(three.String(), sub.String(), "member") }},
		{"RemoveMember", func() error { return w.fake.RemoveMember(two.String(), sub.String()) }},
		{"Disable", func() error { return w.fake.Disable(sub.String(), revoke) }},
		{"RevokeSessions", func() error { return w.fake.RevokeSessions(sub.String(), revoke.Add(time.Minute), true) }},
		{"CloseTeam", func() error { return w.fake.CloseTeam(three.String()) }},
		{"RenameTeam", func() error { return w.fake.RenameTeam(three.String(), "Outro nome") }},
		{"CloseTeam of its own", func() error { return w.fake.CloseTeam(four) }},
		{"CloseAccount", func() error { return w.fake.CloseAccount(sub.String()) }},
	}
	for _, s := range steps {
		n := lines()
		if err := s.act(); err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
		eventually(t, 10*time.Second, s.name+"'s document compared", func() bool { return lines() > n })
	}
	all := logs.String()
	if testing.Verbose() {
		for _, l := range logs.Lines("contract observe") {
			t.Log(l)
		}
	}
	for _, kind := range []string{store.DiffPersonalMismatch, store.DiffPlatformOnly, store.DiffRole, store.DiffNoSub, store.DiffMembershipStatus,
		store.DiffLocalOnly, store.DiffAccountStatus, store.DiffSessionsWouldEnd, store.DiffCredentialsWouldStop, store.DiffTeamClosed, store.DiffName} {
		if !strings.Contains(all, "kind="+kind+" ") {
			t.Errorf("no %s difference logged", kind)
		}
	}
	if !strings.Contains(all, "tenant_missing=true") || !strings.Contains(all, "platform=closed") {
		t.Error("platform_only's missing tenant or the closed account was not logged")
	}
	for _, line := range logs.Lines("contract observe: differences") {
		if strings.Contains(line, "@") || strings.Contains(line, "Equipe") || strings.Contains(line, "Outro") {
			t.Fatalf("a difference names a person or a team: %s", line)
		}
	}
	if after := w.dump(t); after != before {
		t.Fatalf("observe changed Wappie's tables:\nbefore %s\nafter  %s", before, after)
	}
	// The differences name the person's own user, not their sub.
	if user == sub || !strings.Contains(all, "user="+user.String()) {
		t.Fatalf("no difference names the person's user %s (sub %s)", user, sub)
	}
	diffs, compared, err := w.contract.DifferencesOf(ctx, sub)
	if err != nil || !compared {
		t.Fatalf("the closed document: %v %v", compared, err)
	}
	var sessions, credentials *store.ContractDifference
	for i, d := range diffs {
		switch d.Kind {
		case store.DiffSessionsWouldEnd:
			sessions = &diffs[i]
		case store.DiffCredentialsWouldStop:
			credentials = &diffs[i]
		}
		if d.Sub == sub && d.User != user {
			t.Fatalf("a difference of sub %s names user %s, not %s", sub, d.User, user)
		}
	}
	// Each counts what began before the revocation times only: of each
	// pair, the one from an hour ago.
	if sessions == nil || sessions.Count != 1 {
		t.Fatalf("sessions that would end: %+v", sessions)
	}
	if credentials == nil || credentials.Keys != 1 || credentials.Connections != 2 || credentials.Services != 1 {
		t.Fatalf("credentials that would stop: %+v, want 1 key, 2 connections (MCP and AI), 1 service", credentials)
	}
}

// legacy is a person Wappie holds who signed up before the platform's
// sign-in and linked their account later: their user id is not their sub,
// and their personal workspace is Wappie's own.
func (w *world) legacy(t *testing.T) (uuid.UUID, uuid.UUID) {
	t.Helper()
	user, sub := w.localPerson(t), uuid.New()
	if _, err := w.fake.AddAccount(sub.String()); err != nil {
		t.Fatal(err)
	}
	w.exec(context.Background(), t, `INSERT INTO platform_identities (sub, user_id, email, linked_from) VALUES ($1, $2, $3, 'legacy')`,
		sub, user, sub.String()[:8]+"@id.test")
	return user, sub
}

// reader makes a number of tenant that user reads: a permission and a
// grant at its archive key's epoch.
func (w *world) reader(t *testing.T, tenant, user uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	device, err := store.NewDevices(w.pool).Create(ctx, tenant.String(), "atendimento", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	if err := pg.InTenantTx(ctx, w.pool, tenant.String(), func(tx pgx.Tx) error {
		for _, q := range []string{
			`INSERT INTO device_archive_keys (tenant_id, device_id, epoch, public_key) VALUES ($1, $2, 1, decode(repeat('ab', 32), 'hex'))`,
			`INSERT INTO device_key_grants (tenant_id, device_id, user_id, epoch, sealed_dsk, granted_by) VALUES ($1, $2, $3, 1, '\x01', $3)`,
			`INSERT INTO device_permissions (tenant_id, device_id, user_id, can_read) VALUES ($1, $2, $3, true)
			 ON CONFLICT (tenant_id, device_id, user_id) DO UPDATE SET can_read = true`,
		} {
			args := []any{tenant, device.ID}
			if strings.Contains(q, "$3") {
				args = append(args, user)
			}
			if _, err := tx.Exec(ctx, q, args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// credentials makes, in tenant at at, what enforce stops at a recovery of
// user's account: a session, an API key, an MCP connection (with its own
// key), an AI connection (a keychain entry), and a standing service account
// user invited.
func (w *world) credentials(t *testing.T, tenant, user uuid.UUID, at time.Time) {
	t.Helper()
	ctx := context.Background()
	w.exec(ctx, t, `INSERT INTO sessions (user_id, tenant_id, token_hash, expires_at, created_at)
		VALUES ($1, $2, $3, clock_timestamp() + interval '1 day', $4)`, user, tenant, random(t, 32), at)
	key := func() uuid.UUID {
		var id uuid.UUID
		if err := w.pool.QueryRow(ctx, `INSERT INTO api_keys (tenant_id, prefix, key_hash, created_by, created_at)
			VALUES ($1, $2, 'x', $3, $4) RETURNING id`, tenant, uuid.NewString()[:8], user, at).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	key()
	service := uuid.New()
	if err := pg.InTenantTx(ctx, w.pool, tenant.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO mcp_connections (tenant_id, request_id, api_key_id, created_by, client_name, redirect_host,
			device_count, reader_kid, status, expires_at, created_at)
			VALUES ($1, $2, $3, $4, 'Claude', 'claude.ai', 1, '0123456789abcdef', 'active', clock_timestamp() + interval '1 day', $5)`,
			tenant, uuid.NewString(), key(), user, at); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO ai_keychain (id, tenant_id, user_id, provider, label, suffix, envelope, created_at)
			VALUES ($1, $2, $3, 'anthropic', 'Chave', 'abcd', '\x01', $4)`, uuid.New(), tenant, user, at); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO users (id, tenant_id, email, public_key, role) VALUES ($1, $2, $3, $4, 'service')`,
			service, tenant, service.String()[:8]+"@service.test", random(t, 32))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	w.exec(ctx, t, `INSERT INTO invites (invite_id, tenant_id, role, created_by, expires_at, claimed_by, claimed_at, completed_at, created_at)
		VALUES ($1, $2, 'service', $3, $4::timestamptz + interval '1 day', $5, $4, $4, $4)`, random(t, 32), tenant, user, at, service)
}

type member struct {
	user         uuid.UUID
	role, status string
}

// localTeam makes Wappie's own team of the id (unless name is empty: it
// exists already) with these members.
func (w *world) localTeam(t *testing.T, id uuid.UUID, name string, members ...member) {
	t.Helper()
	ctx := context.Background()
	if name != "" {
		w.exec(ctx, t, `INSERT INTO tenants (id, name) VALUES ($1, $2)`, id, name)
	}
	if err := pg.InTenantTx(ctx, w.pool, id.String(), func(tx pgx.Tx) error {
		for _, m := range members {
			if _, err := tx.Exec(ctx, `INSERT INTO workspace_memberships (tenant_id, user_id, role, status) VALUES ($1, $2, $3, $4)`,
				id, m.user, m.role, m.status); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// localPerson is a person of Wappie's own with no platform link.
func (w *world) localPerson(t *testing.T) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	user, home := uuid.New(), uuid.New()
	if err := pg.InTenantTx(ctx, w.pool, home.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO users (id, tenant_id, email, public_key, role, auth_source)
			VALUES ($1, $2, $3, $4, 'owner', 'platform')`, user, home, user.String()[:8]+"@example.com", random(t, 32))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return user
}

// dump is every row of the tables observe must not change, each table's
// rows in one order, every workspace's under its own row-level security.
func (w *world) dump(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	var b strings.Builder
	err := pgx.BeginTxFunc(ctx, w.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		agg := func(table string) error {
			var s string
			if err := tx.QueryRow(ctx, `SELECT coalesce(string_agg(to_jsonb(x)::text, E'\n' ORDER BY to_jsonb(x)::text), '') FROM `+table+` x`).Scan(&s); err != nil {
				return err
			}
			b.WriteString(table + ":\n" + s + "\n")
			return nil
		}
		for _, table := range []string{"tenants", "sessions", "api_keys", "mcp_connections"} {
			if err := agg(table); err != nil {
				return err
			}
		}
		rows, err := tx.Query(ctx, `SELECT id FROM tenants ORDER BY id`)
		if err != nil {
			return err
		}
		tenants, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			return err
		}
		for _, id := range tenants {
			if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, id.String()); err != nil {
				return err
			}
			b.WriteString("workspace " + id.String() + "\n")
			for _, table := range []string{"users", "workspace_memberships", "device_key_grants", "device_permissions"} {
				if err := agg(table); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// heldAtHome is a person Wappie holds who signed up once the contract was
// observed: their personal workspace has the platform's id.
func (w *world) heldAtHome(t *testing.T) (uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	sub := uuid.New()
	if _, err := w.fake.AddAccount(sub.String()); err != nil {
		t.Fatal(err)
	}
	key := random(t, 32)
	if _, _, err := store.NewPlatformPins(w.pool).InsertPin(ctx, sub.String(), "wappie:1", key); err != nil {
		t.Fatal(err)
	}
	ticket, err := w.users.CreatePlatformTicket(ctx, store.PlatformTicket{Kind: store.TicketNew, Sub: sub, ProductKeyID: "wappie:1", ProductKey: key,
		Email: sub.String()[:8] + "@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	s, err := w.members.SignUp(ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	wrap := random(t, wappie.PlatformWrapLen)
	wrap[0] = wappie.PlatformWrapHeader
	u, _, err := w.users.SignupPlatform(ctx, store.NewPlatformUser{Ticket: ticket, PublicKey: random(t, 32), Wrap: wrap, Home: s.Home, Doc: s.Doc})
	if err != nil {
		t.Fatal(err)
	}
	return u.ID, sub, s.Home
}

// TB25: the pilot's shape (the owner, at the platform's personal workspace
// and in TBFG, both of the platform's ids, beside Piloto A and Piloto B,
// which no document names) differs only by the two unnamed teams; a person
// whose personal workspace is Wappie's own (D6) differs by it, with its
// count of numbers; and --tenant keeps the differences that name it.
func TestContractDiff(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	user, sub, _ := w.heldAtHome(t)
	team, err := w.fake.AddTeam("TBFG", sub.String())
	if err != nil {
		t.Fatal(err)
	}
	tbfg := uuid.MustParse(team)
	w.localTeam(t, tbfg, "TBFG", member{user, "owner", "active"})
	pilotoA, pilotoB := uuid.New(), uuid.New()
	w.localTeam(t, pilotoA, "Piloto A", member{user, "owner", "active"})
	w.localTeam(t, pilotoB, "Piloto B", member{user, "owner", "active"})
	w.members.SignIn(ctx, sub)
	if _, ok, err := w.contract.Workspace(ctx, tbfg); err != nil || !ok {
		t.Fatalf("TBFG not recorded: %v %v", ok, err)
	}
	diffs, err := w.contract.Differences(ctx, uuid.Nil)
	if err != nil {
		t.Fatal(err)
	}
	var unnamed []uuid.UUID
	for _, d := range diffs {
		if d.Kind != store.DiffUnnamedTenant {
			t.Fatalf("the pilot's shape differs by %+v", d)
		}
		unnamed = append(unnamed, d.Workspace)
	}
	if len(unnamed) != 2 || !slices.Contains(unnamed, pilotoA) || !slices.Contains(unnamed, pilotoB) {
		t.Fatalf("unnamed teams %v, want Piloto A and B", unnamed)
	}

	// A person at a home of Wappie's own, with one number there.
	d6User, d6Sub := w.held(t)
	var home uuid.UUID
	if err := w.pool.QueryRow(ctx, `SELECT id FROM tenants WHERE personal_owner_id = $1`, d6User).Scan(&home); err != nil {
		t.Fatal(err)
	}
	if _, err := store.NewDevices(w.pool).Create(ctx, home.String(), "atendimento", wa.ModePassive); err != nil {
		t.Fatal(err)
	}
	w.members.SignIn(ctx, d6Sub)
	diffs, err = w.contract.Differences(ctx, home)
	if err != nil {
		t.Fatal(err)
	}
	if len(diffs) != 1 || diffs[0].Kind != store.DiffPersonalMismatch || diffs[0].Sub != d6Sub || diffs[0].LocalWorkspace != home ||
		diffs[0].Count != 1 || diffs[0].Workspace == uuid.Nil {
		t.Fatalf("the D6 person's differences: %+v", diffs)
	}
	if diffs, err := w.contract.Differences(ctx, pilotoA); err != nil || len(diffs) != 1 || diffs[0].Workspace != pilotoA {
		t.Fatalf("--tenant Piloto A: %+v %v", diffs, err)
	}
}

// TB26: the mode in the database: off stops the leader and the returning
// sign-ins' PUTs within their bounds (the mode cache and the leader's mode
// check are each 5 s, TestLeaderBounds; shortened here), and observe again
// starts it once more.
func TestModeSwitch(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	_, sub := w.held(t)
	logs := &membershiptest.Logs{}
	l := w.leader(w.members, logs, lockKey(t))
	l.ModeCheck = time.Hour // only the switch's notice stops it
	run(t, l)
	eventually(t, 10*time.Second, "the leader's round", func() bool { return w.following(sub) && w.state(t).FeedCursor >= 1 })
	signIns := &Members{Client: w.members.Client, Contract: w.contract, Log: logs.Logger(), ModeCache: 200 * time.Millisecond}
	signIns.SignIn(ctx, sub) // caches observe

	if _, err := w.contract.SetMode(ctx, store.ContractOff); err != nil {
		t.Fatal(err)
	}
	switched := time.Now()
	eventually(t, 5*time.Second, "the leader stops", func() bool { return len(logs.Lines("contract: no longer leading")) > 0 })
	if took := time.Since(switched); took > 2*time.Second {
		t.Fatalf("the leader stopped %v after the switch", took)
	}
	feeds := w.fake.Count(contracttest.CallFeed)
	time.Sleep(300 * time.Millisecond)
	puts := w.fake.Count(contracttest.CallSubscribe)
	signIns.SignIn(ctx, sub)
	if n := w.fake.Count(contracttest.CallSubscribe); n != puts {
		t.Fatalf("a returning sign-in PUT %d times past the mode cache, at off", n-puts)
	}
	time.Sleep(time.Second)
	if n := w.fake.Count(contracttest.CallFeed); n != feeds {
		t.Fatalf("%d feed calls at off", n-feeds)
	}
	if s := w.state(t); s.EventsPausedAt == nil || s.Mode != store.ContractOff {
		t.Fatalf("off: %+v", s)
	}

	if _, err := w.contract.SetMode(ctx, store.ContractObserve); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "the leader leads again", func() bool { return w.fake.Count(contracttest.CallFeed) > feeds })
	if s := w.state(t); len(s.EventsOff) != 1 || s.EventsPausedAt != nil {
		t.Fatalf("observe again: %+v", s)
	}
}

// The leader's sweep runs at its start: an orphan over OrphanAfter old is
// unfollowed within seconds of a leader's start.
func TestLeaderSweeps(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	orphan := uuid.New()
	if _, err := w.fake.AddAccount(orphan.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := w.contract.Intend(ctx, orphan); err != nil {
		t.Fatal(err)
	}
	if _, err := w.members.Client.Subscribe(ctx, orphan.String()); err != nil {
		t.Fatal(err)
	}
	w.age(ctx, t, orphan, 16*time.Minute)
	logs := &membershiptest.Logs{}
	run(t, w.leader(w.members, logs, lockKey(t)))
	// The platform unfollows on the DELETE, before the sweep's answer
	// removes the row: both are waited for.
	eventually(t, 10*time.Second, "the sweep, and the orphan's row removed", func() bool {
		exists, _, _ := w.row(ctx, t, orphan)
		return !w.following(orphan) && !exists
	})
}

// The follower's silence (the plan's 4.7): after SilentAfter without a
// page, one ERROR, recorded for contract status --check, however many
// calls fail after it; a page ends the run, and a new outage is told again.
func TestFollowerSilence(t *testing.T) {
	w := newWorld(t)
	_, sub := w.held(t)
	logs := &membershiptest.Logs{}
	l := w.leader(w.members, logs, lockKey(t))
	l.SilentAfter = 300 * time.Millisecond
	run(t, l)
	eventually(t, 10*time.Second, "the round and a page", func() bool { return w.following(sub) && w.state(t).FeedCursor >= 1 })
	silence := func() int { return len(logs.Lines("level=ERROR", "contract: no feed page for a long time")) }
	if n := silence(); n != 0 {
		t.Fatalf("%d silences while the feed answers", n)
	}
	outage := func() {
		t.Helper()
		w.fake.RefuseAlways(contracttest.CallFeed, kc.CodeUnavailable)
		// The long-poll in flight began before the refusals.
		w.exec(context.Background(), t, `SELECT pg_notify($1, 'generation')`, store.ContractModeChannel)
	}
	outage()
	eventually(t, 5*time.Second, "the silence's ERROR", func() bool { return silence() == 1 })
	calls := w.fake.Count(contracttest.CallFeed)
	// Many more failed calls, and the ERROR recorded meanwhile.
	time.Sleep(500 * time.Millisecond)
	if n := w.fake.Count(contracttest.CallFeed) - calls; n < 2 || silence() != 1 {
		t.Fatalf("%d silences over %d more failed calls, want one", silence(), n)
	}
	if s := w.state(t); s.ErrorClass != store.ContractErrorFeedSilent || s.ErrorAt == nil {
		t.Fatalf("the silence was not recorded: %+v", s)
	}
	w.fake.RefuseAlways(contracttest.CallFeed, "")
	eventually(t, 5*time.Second, "the feed answers again", func() bool { return len(logs.Lines("contract: the feed answers again")) > 0 })
	w.exec(context.Background(), t, `UPDATE contract_state SET error_class = NULL, error_at = NULL`)
	outage()
	// The ERROR is logged, then recorded.
	eventually(t, 5*time.Second, "the second outage's ERROR, recorded", func() bool {
		return silence() == 2 && w.state(t).ErrorClass == store.ContractErrorFeedSilent
	})
}

// The round's failures are told (DB24): a held sub whose PUT keeps
// failing (a signed not_found, which never means closed, README 6.1) has
// its class and the run's start recorded at once for contract status;
// once the run has lasted IncompleteAfter, one ERROR, recorded too,
// however many passes fail after it; the pass that subscribes it ends the
// run; and a new run is told again.
func TestRoundFailuresAreTold(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	_, sub := w.held(t)
	w.fake.RefuseAlways(contracttest.CallSubscribe, kc.CodeNotFound)
	logs := &membershiptest.Logs{}
	l := w.leader(w.members, logs, lockKey(t))
	l.IncompleteAfter = 300 * time.Millisecond
	run(t, l)
	told := func() int {
		return len(logs.Lines("level=ERROR", "contract: held subs still have no document of this generation", "class=refused:not_found"))
	}
	eventually(t, 5*time.Second, "the failing pass recorded", func() bool {
		s := w.state(t)
		return s.RoundError == "refused:not_found" && s.RoundErrorAt != nil
	})
	if told() != 0 {
		t.Fatal("the round's ERROR before its bound")
	}
	eventually(t, 5*time.Second, "the round's ERROR", func() bool { return told() == 1 })
	puts := w.fake.Count(contracttest.CallSubscribe)
	time.Sleep(500 * time.Millisecond)
	if n := w.fake.Count(contracttest.CallSubscribe) - puts; n < 2 || told() != 1 {
		t.Fatalf("%d ERRORs over %d more failed PUTs, want one", told(), n)
	}
	if s := w.state(t); s.ErrorClass != store.ContractErrorRoundIncomplete || s.ErrorAt == nil {
		t.Fatalf("the round's ERROR was not recorded: %+v", s)
	}
	w.fake.RefuseAlways(contracttest.CallSubscribe, "")
	eventually(t, 5*time.Second, "the round done", func() bool {
		s := w.state(t)
		return w.following(sub) && s.RoundGeneration != nil && s.RoundError == "" && s.RoundErrorAt == nil
	})
	// A GET's not_found forgets the sub's version again, and its PUTs fail.
	w.fake.RefuseAlways(contracttest.CallSubscribe, kc.CodeUnavailable)
	if err := w.contract.Unfollowed(ctx, sub); err != nil {
		t.Fatal(err)
	}
	if err := w.contract.Wake(ctx, "round"); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "the second run's ERROR", func() bool {
		return len(logs.Lines("level=ERROR", "contract: held subs still have no document of this generation")) == 2
	})
	if s := w.state(t); s.RoundError != "refused:unavailable" {
		t.Fatalf("the second run's class: %+v", s)
	}
}

// signedFeed is a client whose feed requests get page(after), signed with
// secret, and whose other calls go to the fake platform. It counts the
// feed requests.
func signedFeed(t *testing.T, fake *membershiptest.Fake, secret string, calls *atomic.Int64, page func(after int64) kc.Feed) *Client {
	t.Helper()
	platform, err := url.Parse(fake.URL)
	if err != nil {
		t.Fatal(err)
	}
	c := clientOn(func(r *http.Request) (*http.Response, error) {
		if !strings.HasSuffix(r.URL.Path, "/feed") {
			out := r.Clone(r.Context())
			out.URL.Scheme, out.URL.Host, out.Host = platform.Scheme, platform.Host, platform.Host
			return http.DefaultTransport.RoundTrip(out)
		}
		calls.Add(1)
		after, err := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
		if err != nil {
			return nil, err
		}
		body, err := json.Marshal(page(after))
		if err != nil {
			return nil, err
		}
		return signedAnswer(r, secret, http.StatusOK, body, time.Now()), nil
	}, nil)
	if err := c.Use(secret, ""); err != nil {
		t.Fatal(err)
	}
	return c
}

// A signed page that does not move the cursor as README 6.3 describes,
// which the kit does not check (more with no items, or ending at or before
// the cursor, or before its last item's seq; a next_after behind the
// cursor), is no page: nothing commits, and the follower backs off as for
// any answer it cannot take, never asking again at once in a loop.
func TestFollowerRefusesPagesThatDoNotMove(t *testing.T) {
	w := newWorld(t)
	_, sub := w.held(t)
	gen, _ := w.fake.Generation()
	const cursor = 10
	w.exec(context.Background(), t, `UPDATE contract_state SET generation = $1, feed_cursor = $2`, uuid.MustParse(gen), cursor)
	doc := func(seq int64) kc.FeedItem {
		return kc.FeedItem{Seq: seq, Doc: kc.AccountDoc{V: kc.DocV, Type: kc.DocType, App: App, Generation: gen, Sub: sub.String(),
			Version: seq, Status: kc.AccountActive, Workspaces: []kc.Workspace{}}}
	}
	page := func(after, next int64, more bool, items ...kc.FeedItem) kc.Feed {
		return kc.Feed{Generation: gen, Head: after + 5, PublishedThrough: kc.T(time.Now().Add(-time.Minute)),
			Items: append([]kc.FeedItem{}, items...), NextAfter: next, More: more}
	}
	for _, c := range []struct {
		name string
		page func(after int64) kc.Feed
	}{
		{"more with no items", func(after int64) kc.Feed { return page(after, after, true) }},
		{"more ending at the cursor", func(after int64) kc.Feed { return page(after, after, true, doc(after)) }},
		{"more ending before its last item", func(after int64) kc.Feed { return page(after, after+1, true, doc(after+1), doc(after+2)) }},
		{"next_after behind the cursor", func(after int64) kc.Feed { return page(after, after-1, false) }},
	} {
		logs := &membershiptest.Logs{}
		var calls atomic.Int64
		m := &Members{Client: signedFeed(t, w.fake, w.secret, &calls, c.page), Contract: w.contract, Log: logs.Logger(), ModeCache: -1,
			Pace: time.Millisecond}
		stop := run(t, w.leader(m, logs, lockKey(t)))
		eventually(t, 5*time.Second, c.name+": the round", func() bool { return w.following(sub) && calls.Load() > 0 })
		time.Sleep(time.Second)
		stop()
		// 20 ms doubling to 200 ms: a handful in a second, never a loop.
		if n := calls.Load(); n > 15 {
			t.Fatalf("%s: %d feed calls in about a second", c.name, n)
		}
		if s := w.state(t); s.FeedCursor != cursor || s.FeedReadAt != nil || s.FeedError != "unverified" {
			t.Fatalf("%s: the state %+v, want the cursor at %d, never read, unverified", c.name, s, cursor)
		}
	}
}

// A process whose secret is not loaded never takes the leader's lock (the
// plan's 4.7: only while the contract is on and a secret is loaded), so it
// never holds the feed up for the process that has one, which leads.
func TestLeaderNeedsASecret(t *testing.T) {
	w := newWorld(t)
	_, sub := w.held(t)
	key := lockKey(t)
	bare := &counting{}
	logs := &membershiptest.Logs{}
	m := &Members{Client: NewClient(&http.Client{Transport: bare}, w.fake.URL, nil), Contract: w.contract, Log: logs.Logger(),
		ModeCache: -1, Pace: time.Millisecond}
	run(t, w.leader(m, logs, key))
	// Past several of its retries (300 ms).
	time.Sleep(time.Second)
	if pid := w.lockHolder(t, key); pid != 0 || len(logs.Lines("contract: leading")) != 0 {
		t.Fatalf("a process with no secret leads (backend %d)", pid)
	}
	run(t, w.leader(w.members, &membershiptest.Logs{}, key))
	eventually(t, 5*time.Second, "the process with the secret leads", func() bool {
		return w.following(sub) && w.state(t).FeedCursor >= 1 && w.lockHolder(t, key) != 0
	})
	if n := bare.feed.Load(); n != 0 || len(logs.Lines("contract: leading")) != 0 {
		t.Fatalf("the process with no secret made %d feed calls", n)
	}
}
