package store_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/migrate"
	"whatserver2/internal/obs"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
)

// The contract's events in the store (the plan's 4.11 and DB23): the
// expiry and the housekeeping (TB35), and the lock order of the sender's
// transactions against a purge and against a document's release of
// parked rows (TB50).

var eventTimes = store.ContractEventTimes{BackoffMin: 5 * time.Second, BackoffMax: time.Hour}

// pastEvent writes an item_events row of kind in tenant, written and
// occurred ago before the database's clock, with set (an UPDATE's SET
// list) on it, and returns its event id.
func pastEvent(t *testing.T, pool *pgxpool.Pool, tenant uuid.UUID, kind, written, occurred, set string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	id := uuid.Must(uuid.NewV7())
	inTenantTx(ctx, t, pool, tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO item_events (event_id, tenant_id, type, item_id, dedupe_key, occurred_at, actor_kind,
			deleted_at, purge_after, ledgered_at, created_at)
			VALUES ($1, $2, $3, $4, $5, clock_timestamp() - $7::interval, 'person',
			CASE WHEN $3 IN ('deleted', 'recovered', 'purged') THEN clock_timestamp() - $7::interval END,
			CASE WHEN $3 IN ('deleted', 'purged') THEN clock_timestamp() + interval '1 day' END,
			clock_timestamp(), clock_timestamp() - $6::interval)`, id, tenant, kind, uuid.New(), id.String(), written, occurred); err != nil {
			return err
		}
		if set == "" {
			return nil
		}
		_, err := tx.Exec(ctx, `UPDATE item_events SET `+set+` WHERE event_id = $1`, id)
		return err
	})
	return id
}

// eventState is a row's delivery: gone, parked with its code, settled.
func eventState(t *testing.T, pool *pgxpool.Pool, tenant, id uuid.UUID) string {
	t.Helper()
	ctx := context.Background()
	var state string
	inTenantTx(ctx, t, pool, tenant, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT coalesce(outcome, reject_code, 'owed') FROM item_events WHERE event_id = $1`, id).Scan(&state)
		if errors.Is(err, pgx.ErrNoRows) {
			state, err = "gone", nil
		}
		return err
	})
	return state
}

// TB35 (but its self-hosted 90 days, P6c's): before the first observe, an
// unsent row goes at 30 days as release A's; once observed, an owed row is
// parked expired at 29 days since it occurred (a pause with the rows
// folded into it), and goes at 30 days since it was written; one written
// over 30 days ago that is still owed stays; a delivered row goes at 30
// days; and a row of a workspace no document named goes at 30 days.
func TestEventHousekeeping(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	c := store.NewContract(pool)
	team := uuid.MustParse(newTenant(t, pool, "Equipe"))
	unnamed := uuid.MustParse(newTenant(t, pool, "Piloto A"))
	housekeep := func(tenant uuid.UUID) store.DeletionHousekeepingCounts {
		t.Helper()
		counts, err := store.DeletionHousekeeping(ctx, pool, tenant)
		if err != nil {
			t.Fatal(err)
		}
		return counts
	}
	never := pastEvent(t, pool, team, "deleted", "30 days 1 minute", "30 days 1 minute", "")
	if counts := housekeep(team); counts.Events != 1 || len(counts.Expired) != 0 || eventState(t, pool, team, never) != "gone" {
		t.Fatalf("never observed: %+v", counts)
	}

	if _, err := c.SetMode(ctx, store.ContractObserve); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE contract_state SET events_from = clock_timestamp() - interval '40 days'`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO contract_workspaces (workspace_id, kind, named_at)
		VALUES ($1, 'team', clock_timestamp() - interval '40 days')`, team); err != nil {
		t.Fatal(err)
	}
	expired := pastEvent(t, pool, team, "deleted", "29 days 1 minute", "29 days 1 minute", "")
	young := pastEvent(t, pool, team, "deleted", "28 days 23 hours", "28 days 23 hours", "")
	head := pastEvent(t, pool, team, "sync_paused", "29 days 2 minutes", "29 days 2 minutes", "")
	folded := pastEvent(t, pool, team, "sync_paused", "28 days 23 hours", "28 days 23 hours", "coalesced_into = '"+head.String()+"'")
	late := pastEvent(t, pool, team, "deleted", "31 days", "1 day", "")
	settledOld := pastEvent(t, pool, team, "deleted", "30 days 1 minute", "30 days 1 minute",
		"settled_at = clock_timestamp(), outcome = 'accepted'")
	settledYoung := pastEvent(t, pool, team, "deleted", "29 days 23 hours", "29 days 23 hours",
		"settled_at = clock_timestamp(), outcome = 'accepted'")
	other := pastEvent(t, pool, unnamed, "deleted", "30 days 1 minute", "30 days 1 minute", "")

	counts := housekeep(team)
	slices.SortFunc(counts.Expired, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
	want := []uuid.UUID{expired, head, folded}
	slices.SortFunc(want, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
	if counts.Events != 1 || !slices.Equal(counts.Expired, want) {
		t.Fatalf("observed: %+v, want 1 row gone and %v expired", counts, want)
	}
	for id, state := range map[uuid.UUID]string{expired: "expired", head: "expired", folded: "expired", young: "owed", late: "owed",
		settledOld: "gone", settledYoung: "accepted"} {
		if got := eventState(t, pool, team, id); got != state {
			t.Errorf("event %s: %s, want %s", id, got, state)
		}
	}
	if counts := housekeep(unnamed); counts.Events != 1 || eventState(t, pool, unnamed, other) != "gone" {
		t.Fatalf("a workspace no document names: %+v", counts)
	}
	// Parked, it goes at 30 days since it was written.
	inTenantTx(ctx, t, pool, team, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE item_events SET created_at = clock_timestamp() - interval '30 days 1 minute'
			WHERE event_id = ANY ($1)`, []uuid.UUID{expired, head, folded})
		return err
	})
	if counts := housekeep(team); counts.Events != 3 || len(counts.Expired) != 0 {
		t.Fatalf("expired, 30 days on: %+v", counts)
	}
	for _, id := range []uuid.UUID{expired, head, folded} {
		if got := eventState(t, pool, team, id); got != "gone" {
			t.Errorf("event %s: %s, want gone", id, got)
		}
	}
	if got := eventState(t, pool, team, late); got != "owed" {
		t.Fatalf("a row still owed: %s", got)
	}
	// The sender meets an expired row first, with its own read: a pause
	// with the row folded into it too.
	sent := pastEvent(t, pool, team, "deleted", "0", "29 days 1 minute", "")
	pausedHead := pastEvent(t, pool, team, "sync_paused", "0", "29 days 2 minutes", "")
	pausedFold := pastEvent(t, pool, team, "sync_paused", "0", "28 days 23 hours", "coalesced_into = '"+pausedHead.String()+"'")
	batch, err := c.EventBatch(ctx, team, 100)
	if err != nil || len(batch.Expired) != 3 || len(batch.Events) != 2 || batch.Events[0].EventID != young || batch.Events[1].EventID != late {
		t.Fatalf("the sender's read: %+v %v", batch, err)
	}
	for _, id := range []uuid.UUID{sent, pausedHead, pausedFold} {
		if got := eventState(t, pool, team, id); got != "expired" {
			t.Errorf("event %s after the sender's read: %s", id, got)
		}
	}
}

// The queue's read (DB11, README 9): a pause folded into a delivered one
// of the hour, its own folded rows heading their events again; a row
// folded into one no longer owed heading its own; a pause nobody but its
// actor reads settled not_sent; and the limit.
func TestEventBatchFolds(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	c := store.NewContract(pool)
	team := uuid.MustParse(newTenant(t, pool, "Equipe"))
	if _, err := c.SetMode(ctx, store.ContractObserve); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO contract_workspaces (workspace_id, kind, named_at)
		VALUES ($1, 'team', clock_timestamp() - interval '1 minute')`, team); err != nil {
		t.Fatal(err)
	}
	actor, reader, item := uuid.New(), uuid.New(), uuid.New()
	pausing := func(occurred, set string) uuid.UUID {
		t.Helper()
		if set != "" {
			set = ", " + set
		}
		return pastEvent(t, pool, team, "sync_paused", "0", occurred, fmt.Sprintf(
			`item_id = '%s', actor_sub = '%s', reader_subs = ARRAY['%s', '%s']::uuid[]%s`, item, actor, actor, reader, set))
	}
	delivered := pausing("70 minutes", "settled_at = clock_timestamp(), outcome = 'accepted'")
	under := pausing("20 minutes", "")
	// Folded into under in an earlier read, and over an hour after the
	// delivered one: once under folds into it, it heads its own event.
	after := pausing("0", "coalesced_into = '"+under.String()+"'")
	orphan := pastEvent(t, pool, team, "deleted", "0", "0", "coalesced_into = '"+uuid.NewString()+"'")
	lonely := pastEvent(t, pool, team, "sync_paused", "0", "0", fmt.Sprintf(`actor_sub = '%s', reader_subs = ARRAY['%s']::uuid[]`, actor, actor))
	batch, err := c.EventBatch(ctx, team, 100)
	if err != nil {
		t.Fatal(err)
	}
	var heads []uuid.UUID
	for _, e := range batch.Events {
		heads = append(heads, e.EventID)
	}
	if !slices.Equal(heads, []uuid.UUID{after, orphan}) || batch.NotSent != 1 || batch.Coalesced != 1 || batch.More {
		t.Fatalf("the read: heads %v (want %v), %+v", heads, []uuid.UUID{after, orphan}, batch)
	}
	if got := eventState(t, pool, team, under); got != "coalesced" {
		t.Fatalf("a pause under an hour after a delivered one: %s", got)
	}
	if got := eventState(t, pool, team, lonely); got != "not_sent" {
		t.Fatalf("a pause nobody else reads: %s", got)
	}
	var into *uuid.UUID
	inTenantTx(ctx, t, pool, team, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT coalesced_into FROM item_events WHERE event_id = $1`, under).Scan(&into); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM item_events WHERE event_id = ANY ($1) AND coalesced_into IS NULL`,
			[]uuid.UUID{after, orphan}).Scan(&n); err != nil || n != 2 {
			return fmt.Errorf("the heads are still folded: %d %w", n, err)
		}
		return nil
	})
	if into == nil || *into != delivered {
		t.Fatalf("folded into %v, want the delivered pause %s", into, delivered)
	}
	// The limit: the first of them, and more.
	if batch, err := c.EventBatch(ctx, team, 1); err != nil || len(batch.Events) != 1 || batch.Events[0].EventID != after || !batch.More {
		t.Fatalf("a limit of 1: %+v %v", batch, err)
	}

	// The hour, and the actor's kind: a pause of another item, then the
	// same item's under the hour (folded, its readers joining), 61 minutes
	// on (its own), and by the actor's key (its own).
	other := uuid.New()
	pause := func(occurred, kind string, readers ...uuid.UUID) uuid.UUID {
		t.Helper()
		list := make([]string, len(readers))
		for i, r := range readers {
			list[i] = "'" + r.String() + "'"
		}
		return pastEvent(t, pool, team, "sync_paused", "0", occurred, fmt.Sprintf(
			`item_id = '%s', actor_kind = '%s', actor_sub = '%s', reader_subs = ARRAY[%s]::uuid[]`, other, kind, actor, strings.Join(list, ", ")))
	}
	third := uuid.New()
	first := pause("90 minutes", "person", actor, reader)
	joined := pause("31 minutes", "person", actor, third)
	later := pause("29 minutes", "person", actor, reader)
	keyed := pause("80 minutes", "key", actor, reader)
	batch, err = c.EventBatch(ctx, team, 100)
	if err != nil {
		t.Fatal(err)
	}
	heads = nil
	for _, e := range batch.Events {
		heads = append(heads, e.EventID)
		if e.EventID == first && (e.Folded != 1 || !slices.Equal(e.Readers, []uuid.UUID{actor, reader, third})) {
			t.Fatalf("the first pause: %d folded, readers %v", e.Folded, e.Readers)
		}
	}
	if want := []uuid.UUID{after, orphan, first, later, keyed}; !slices.Equal(heads, want) {
		t.Fatalf("heads %v, want %v (joined %s folded)", heads, want, joined)
	}
}

// TB50: the sender's settle against a purge of the same workspace, forced
// into the purge's order (the workspace's row, then, once the settle waits
// on it, the events' rows) and then raced with a real purge; and two
// documents naming the same teams in opposite orders, stored beside the
// sender's reads, both releasing the teams' parked rows. No deadlock, so
// no retry.
func TestMailerAndPurgeDoNotDeadlock(t *testing.T) {
	a := newExcludedArchive(t)
	ctx := context.Background()
	c := store.NewContract(a.pool)
	if _, err := c.SetMode(ctx, store.ContractObserve); err != nil {
		t.Fatal(err)
	}
	if _, err := a.pool.Exec(ctx, `INSERT INTO contract_workspaces (workspace_id, kind, named_at)
		VALUES ($1, 'team', clock_timestamp() - interval '1 minute')`, a.tenant); err != nil {
		t.Fatal(err)
	}
	a.quarantine(t, a.excluded)
	var log bytes.Buffer
	var logMu sync.Mutex
	logged := obs.WithLogger(ctx, slog.New(slog.NewTextHandler(writerFunc(func(p []byte) (int, error) {
		logMu.Lock()
		defer logMu.Unlock()
		return log.Write(p)
	}), nil)))
	deadlocked := func(what string) {
		t.Helper()
		logMu.Lock()
		defer logMu.Unlock()
		if strings.Contains(log.String(), "deadlocked") {
			t.Fatalf("%s deadlocked:\n%s", what, log.String())
		}
	}
	accept := func(batch store.ContractEventBatch) error {
		var rs []store.ContractEventResult
		for _, e := range batch.Events {
			rs = append(rs, store.ContractEventResult{EventID: e.EventID, Outcome: store.ContractEventAccepted})
		}
		if len(rs) == 0 {
			return nil
		}
		_, err := c.EventsSent(logged, a.tenant, batch.ReadAt, rs, eventTimes)
		return err
	}
	batch, err := c.EventBatch(logged, a.tenant, 100)
	if err != nil || len(batch.Events) != 1 || batch.Events[0].Type != "deleted" {
		t.Fatalf("the deletion's queue: %+v %v", batch, err)
	}

	// The purge's order, forced.
	purge, err := a.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer purge.Rollback(ctx) //nolint:errcheck // committed below
	if _, err := purge.Exec(ctx, `SELECT 1 FROM tenants WHERE id = $1 FOR UPDATE`, a.tenant); err != nil {
		t.Fatal(err)
	}
	settled := make(chan error, 1)
	go func() { settled <- accept(batch) }()
	waitBlockedOn(t, a.pool, int(purge.Conn().PgConn().PID()), 1)
	if _, err := purge.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, a.tenant.String()); err != nil {
		t.Fatal(err)
	}
	quick, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := purge.Exec(quick, `UPDATE item_events SET label = NULL, hint = NULL WHERE item_id = $1`, a.excluded); err != nil {
		t.Fatalf("the purge's write of the events' rows behind a settle: %v", err)
	}
	if err := purge.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-settled; err != nil {
		t.Fatal(err)
	}
	deadlocked("the forced settle")
	if got := eventState(t, a.pool, a.tenant, batch.Events[0].EventID); got != store.ContractEventAccepted {
		t.Fatalf("the deletion after the forced settle: %s", got)
	}

	// A real purge, beside the sender's reads and settles.
	makeDue(t, a.pool, a.tenant, a.excluded)
	purged := make(chan error, 1)
	go func() {
		_, err := store.PurgeDevice(logged, a.pool, a.tenant, a.excluded, nil, store.PurgeOptions{Batch: 1})
		purged <- err
	}()
	done := false
	for !done {
		select {
		case err := <-purged:
			if err != nil {
				t.Fatal(err)
			}
			done = true
		default:
		}
		batch, err := c.EventBatch(logged, a.tenant, 100)
		if err != nil {
			t.Fatal(err)
		}
		if err := accept(batch); err != nil {
			t.Fatal(err)
		}
	}
	if batch, err := c.EventBatch(logged, a.tenant, 100); err != nil || accept(batch) != nil {
		t.Fatalf("the purge's event: %v", err)
	}
	deadlocked("the sender and a purge")
	var purgedState string
	inTenantTx(ctx, t, a.pool, a.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT coalesce(outcome, 'owed') FROM item_events WHERE type = 'purged' AND item_id = $1`, a.excluded).Scan(&purgedState)
	})
	if purgedState != store.ContractEventAccepted {
		t.Fatalf("the purge's event: %s", purgedState)
	}

	// Two documents naming two teams in opposite orders, each team with
	// rows parked not_found, stored concurrently beside the sender's reads.
	_, sub1, home1 := heldPerson(t, a.pool)
	_, sub2, home2 := heldPerson(t, a.pool)
	gen := uuid.New()
	teams := []uuid.UUID{uuid.MustParse(newTenant(t, a.pool, "A")), uuid.MustParse(newTenant(t, a.pool, "B"))}
	team := func(id uuid.UUID) store.ContractDocWorkspace {
		return store.ContractDocWorkspace{ID: id, Role: "member", Status: "open", WVersion: 1}
	}
	storeDocs(t, c, store.ContractAnswer, contractDoc(sub1, gen, 1, "active", home1, team(teams[0]), team(teams[1])),
		contractDoc(sub2, gen, 1, "active", home2, team(teams[1]), team(teams[0])))
	for round := range 8 {
		for _, id := range teams {
			if _, err := a.pool.Exec(ctx, `UPDATE contract_workspaces SET events_not_found_since = clock_timestamp() - interval '2 days'
				WHERE workspace_id = $1`, id); err != nil {
				t.Fatal(err)
			}
			for range 3 {
				pastEvent(t, a.pool, id, "deleted", "0", "0", "parked_at = clock_timestamp(), reject_code = 'not_found'")
			}
			pastEvent(t, a.pool, id, "deleted", "0", "0", "")
		}
		var wg sync.WaitGroup
		errs := make(chan error, 4)
		for i, order := range [][]uuid.UUID{{teams[0], teams[1]}, {teams[1], teams[0]}} {
			sub, home := sub1, home1
			if i == 1 {
				sub, home = sub2, home2
			}
			v := int64(2 + round)
			wg.Go(func() {
				_, err := c.StoreDocuments(logged, store.ContractAnswer, contractDoc(sub, gen, v, "active", home, team(order[0]), team(order[1])))
				errs <- err
			})
		}
		for _, id := range teams {
			wg.Go(func() {
				batch, err := c.EventBatch(logged, id, 100)
				if err == nil && len(batch.Events) > 0 {
					rs := make([]store.ContractEventResult, len(batch.Events))
					for i, e := range batch.Events {
						rs[i] = store.ContractEventResult{EventID: e.EventID, Outcome: store.ContractEventAccepted}
					}
					_, err = c.EventsSent(logged, id, batch.ReadAt, rs, eventTimes)
				}
				errs <- err
			})
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("round %d: %v", round, err)
			}
		}
		for _, id := range teams {
			var parked int
			inTenantTx(ctx, t, a.pool, id, func(tx pgx.Tx) error {
				return tx.QueryRow(ctx, `SELECT count(*) FROM item_events WHERE reject_code = 'not_found'`).Scan(&parked)
			})
			if parked != 0 {
				t.Fatalf("round %d: %d rows still parked in %s after its naming", round, parked, id)
			}
		}
	}
	deadlocked("two documents in opposite orders and the sender")
}

// writerFunc is an io.Writer in a function.
type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// The queue's failures and answers (README 9): a failure backs off, 5 s
// doubled up to an hour, unless the queue was made due since the batch was
// read (a recovery, a name given again), which stands; an answer clears
// the backoff; a not_found starts the queue's own run, which the snapshot's
// not_found and park never touch, and an accepted event ends it, releasing
// the rows parked for it.
func TestEventQueueState(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	c := store.NewContract(pool)
	team := uuid.MustParse(newTenant(t, pool, "Equipe"))
	if _, err := c.SetMode(ctx, store.ContractObserve); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO contract_workspaces (workspace_id, kind, named_at)
		VALUES ($1, 'team', clock_timestamp() - interval '1 minute')`, team); err != nil {
		t.Fatal(err)
	}
	type qs struct {
		wait          time.Duration
		tries         int
		class         string
		notFound      bool
		snapshotNF    bool
		snapshotParks bool
	}
	read := func() qs {
		t.Helper()
		var q qs
		var secs float64
		if err := pool.QueryRow(ctx, `SELECT coalesce(extract(epoch FROM events_due_at - clock_timestamp()), 0), events_tries,
			coalesce(events_error, ''), events_not_found_since IS NOT NULL, not_found_since IS NOT NULL, parked_at IS NOT NULL
			FROM contract_workspaces WHERE workspace_id = $1`, team).Scan(&secs, &q.tries, &q.class, &q.notFound, &q.snapshotNF, &q.snapshotParks); err != nil {
			t.Fatal(err)
		}
		q.wait = time.Duration(secs * float64(time.Second))
		return q
	}
	row := pastEvent(t, pool, team, "deleted", "0", "0", "")
	at := dbClock(t, pool, "0")
	// The sender reads a batch only once its queue is due: the backoff's
	// end, played in SQL.
	due := func() {
		t.Helper()
		if _, err := pool.Exec(ctx, `UPDATE contract_workspaces SET events_due_at = clock_timestamp() - interval '1 second'
			WHERE workspace_id = $1 AND events_due_at IS NOT NULL`, team); err != nil {
			t.Fatal(err)
		}
	}
	for i, want := range []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second} {
		due()
		rec, err := c.EventsFailed(ctx, team, dbClock(t, pool, "0"), "unavailable:timeout", eventTimes)
		if err != nil || rec.Again || rec.Tries != i+1 {
			t.Fatalf("failure %d: %+v %v", i+1, rec, err)
		}
		if q := read(); q.tries != i+1 || q.wait < want-2*time.Second || q.wait > want || q.class != "unavailable:timeout" {
			t.Fatalf("failure %d: %+v, want a wait of %v", i+1, q, want)
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE contract_workspaces SET events_tries = 30 WHERE workspace_id = $1`, team); err != nil {
		t.Fatal(err)
	}
	due()
	if _, err := c.EventsFailed(ctx, team, dbClock(t, pool, "0"), "unavailable:timeout", eventTimes); err != nil {
		t.Fatal(err)
	}
	if q := read(); q.wait > time.Hour || q.wait < 59*time.Minute {
		t.Fatalf("the backoff's cap: %v", q.wait)
	}
	// A recovery since the read: its due time stands, no try counts.
	if _, err := c.Recovered(ctx); err != nil {
		t.Fatal(err)
	}
	rec, err := c.EventsFailed(ctx, team, at, "unverified", eventTimes)
	if q := read(); err != nil || !rec.Again || q.wait > 0 || q.tries != 0 {
		t.Fatalf("a failure read before a recovery: %+v %+v %v", rec, q, err)
	}
	// An answer: the backoff and the failure's class go.
	if _, err := c.EventsSent(ctx, team, dbClock(t, pool, "0"), []store.ContractEventResult{{EventID: row, Outcome: store.ContractEventAccepted}}, eventTimes); err != nil {
		t.Fatal(err)
	}
	if q := read(); q.wait != 0 || q.tries != 0 || q.class != "" {
		t.Fatalf("after an answer: %+v", q)
	}
	// A not_found: the queue's own run; the snapshot's columns untouched.
	refused := pastEvent(t, pool, team, "deleted", "0", "0", "")
	nf := []store.ContractEventResult{{EventID: refused, Outcome: store.ContractEventRejected, Code: store.EventParkedNotFound}}
	if rec, err := c.EventsSent(ctx, team, dbClock(t, pool, "0"), nf, eventTimes); err != nil || !rec.Refused || len(rec.NotFound) != 0 {
		t.Fatalf("a not_found: %+v %v", rec, err)
	}
	if q := read(); !q.notFound || q.snapshotNF || q.snapshotParks || q.tries != 1 || q.class != "refused:not_found" {
		t.Fatalf("after a not_found: %+v", q)
	}
	// 23 hours on, then 24: parked.
	if _, err := pool.Exec(ctx, `UPDATE contract_workspaces SET events_not_found_since = clock_timestamp() - interval '23 hours'`); err != nil {
		t.Fatal(err)
	}
	due()
	if rec, err := c.EventsSent(ctx, team, dbClock(t, pool, "0"), nf, eventTimes); err != nil || len(rec.NotFound) != 0 {
		t.Fatalf("23 hours of not_found: %+v %v", rec, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE contract_workspaces SET events_not_found_since = clock_timestamp() - interval '24 hours 1 minute'`); err != nil {
		t.Fatal(err)
	}
	rec, err = c.EventsSent(ctx, team, dbClock(t, pool, "0"), nf, eventTimes)
	if err != nil || !slices.Equal(rec.NotFound, []uuid.UUID{refused}) || eventState(t, pool, team, refused) != store.EventParkedNotFound {
		t.Fatalf("24 hours of not_found: %+v %v", rec, err)
	}
	if q := read(); !q.notFound || q.snapshotParks || q.tries != 0 || q.wait != 0 {
		t.Fatalf("after the park: %+v", q)
	}
	// An event of the workspace accepted: the run ends, its rows go again.
	other := pastEvent(t, pool, team, "deleted", "0", "0", "")
	rec, err = c.EventsSent(ctx, team, dbClock(t, pool, "0"), []store.ContractEventResult{{EventID: other, Outcome: store.ContractEventDuplicate}}, eventTimes)
	if err != nil || rec.Released != 1 || rec.Delivered != 1 || eventState(t, pool, team, refused) != "owed" {
		t.Fatalf("an event accepted after the park: %+v %v", rec, err)
	}
	if q := read(); q.notFound {
		t.Fatalf("the run after an acceptance: %+v", q)
	}
	// An outcome that is no verdict is no answer.
	if _, err := c.EventsSent(ctx, team, dbClock(t, pool, "0"), []store.ContractEventResult{{EventID: other, Outcome: "kept"}}, eventTimes); err == nil {
		t.Fatal("an unknown outcome was recorded")
	}
}
