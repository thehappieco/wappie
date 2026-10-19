package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/migrate"
	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// The snapshot sender's state on each recorded workspace (the plan's
// 4.10): when a snapshot is due, its snapshot_seq, the outcomes of README
// 8's intake, the debounce, and the notices that wake the sender.

// snapshotRow is a recorded workspace's snapshot columns.
type snapshotRow struct {
	Seq           int64
	OKAt, DueAt   *time.Time
	Tries         int
	Error         *string
	NotFoundSince *time.Time
	ParkedAt      *time.Time
	// DueIn is snapshot_due_at less the database's clock.
	DueIn time.Duration
}

func readSnapshotRow(t *testing.T, pool *pgxpool.Pool, ws uuid.UUID) snapshotRow {
	t.Helper()
	var r snapshotRow
	var due time.Time
	var now time.Time
	if err := pool.QueryRow(context.Background(), `SELECT snapshot_seq, snapshot_ok_at, snapshot_due_at, snapshot_tries,
		snapshot_error, not_found_since, parked_at, clock_timestamp() FROM contract_workspaces WHERE workspace_id = $1`, ws).
		Scan(&r.Seq, &r.OKAt, &due, &r.Tries, &r.Error, &r.NotFoundSince, &r.ParkedAt, &now); err != nil {
		t.Fatal(err)
	}
	r.DueAt, r.DueIn = &due, due.Sub(now)
	return r
}

func recordWorkspace(t *testing.T, pool *pgxpool.Pool, kind string) uuid.UUID {
	t.Helper()
	ws := uuid.New()
	if _, err := pool.Exec(context.Background(), `INSERT INTO contract_workspaces (workspace_id, kind) VALUES ($1, $2)`, ws, kind); err != nil {
		t.Fatal(err)
	}
	return ws
}

var snapshotTimes = store.ContractSnapshotTimes{Every: 55 * time.Minute, BackoffMin: 5 * time.Second, BackoffMax: time.Hour}

// The outcomes of a snapshot sent, by compare-and-set on its seq: an
// accepted one is due again Every later; a failure backs off, 5 s doubled
// up to an hour; a not_found keeps its first time and parks after a day;
// an invalid_request parks at once with no not_found_since, which no
// document releases; a seq another leader has passed records nothing; and a
// due time set after the measurement stands.
func TestContractSnapshotOutcomes(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	c := store.NewContract(pool)
	ws := recordWorkspace(t, pool, "team")
	next, ok, err := c.NextSnapshot(ctx)
	if err != nil || !ok || next.Workspace != ws || !next.Due || next.Seq != 0 {
		t.Fatalf("a new record is due at once: %+v %v %v", next, ok, err)
	}

	// The seq: the measurement's milliseconds, or one more than the last.
	measured := dbClock(t, pool, "0")
	seq, ok, err := c.SnapshotSeq(ctx, ws, measured)
	if err != nil || !ok || seq != measured.UnixMilli() {
		t.Fatalf("seq %d %v %v, want %d", seq, ok, err, measured.UnixMilli())
	}
	if again, _, _ := c.SnapshotSeq(ctx, ws, measured.Add(-time.Hour)); again != seq+1 {
		t.Fatalf("a clock stepped back gives %d, want %d", again, seq+1)
	}
	seq++

	sent := func(outcome store.ContractSnapshotOutcome, class string) store.ContractSnapshotRecord {
		t.Helper()
		// The sender measures a snapshot once it is due.
		if _, err := pool.Exec(ctx, `UPDATE contract_workspaces SET snapshot_due_at = least(snapshot_due_at, clock_timestamp())
			WHERE workspace_id = $1`, ws); err != nil {
			t.Fatal(err)
		}
		measured := dbClock(t, pool, "0") //nolint:contextcheck // the database's clock, read for the test
		rec, err := c.SnapshotSent(ctx, ws, seq, measured, outcome, class, snapshotTimes)
		if err != nil || !rec.Recorded {
			t.Fatalf("outcome %d: %+v %v", outcome, rec, err)
		}
		return rec
	}
	near := func(what string, got, want time.Duration) {
		t.Helper()
		if got < want-30*time.Second || got > want+time.Second {
			t.Fatalf("%s: due in %v, want %v", what, got, want)
		}
	}

	// Failures in a row: 5 s, 10 s, 20 s, ..., an hour at most.
	want := 5 * time.Second
	for i := 1; i <= 12; i++ {
		rec := sent(store.SnapshotFailed, "unavailable:timeout")
		r := readSnapshotRow(t, pool, ws)
		if rec.Tries != i || r.Tries != i || r.Error == nil || *r.Error != "unavailable:timeout" || r.OKAt != nil {
			t.Fatalf("failure %d: %+v %+v", i, rec, r)
		}
		// The run's class, as it was before this failure: none at its start.
		if before := map[bool]string{true: "", false: "unavailable:timeout"}[i == 1]; rec.Before != before {
			t.Fatalf("failure %d: the class before it %q, want %q", i, rec.Before, before)
		}
		near("failure", r.DueIn, min(want, time.Hour))
		want *= 2
	}
	// Accepted: the run ends, due again 55 minutes on.
	rec := sent(store.SnapshotAccepted, "")
	r := readSnapshotRow(t, pool, ws)
	if rec.Tries != 0 || r.Tries != 0 || r.Error != nil || r.OKAt == nil || r.NotFoundSince != nil {
		t.Fatalf("accepted: %+v %+v", rec, r)
	}
	near("accepted", r.DueIn, 55*time.Minute)

	// A stale leader's outcome, on a seq passed since, records nothing.
	if rec, err := c.SnapshotSent(ctx, ws, seq-1, dbClock(t, pool, "0"), store.SnapshotFailed, "x", snapshotTimes); err != nil || rec.Recorded {
		t.Fatalf("a stale seq's outcome: %+v %v", rec, err)
	}

	// not_found: its first time kept, backed off, then parked after a day.
	first := sent(store.SnapshotNotFound, "refused:not_found")
	if first.Parked || first.NotFoundSince == nil || first.Tries != 1 {
		t.Fatalf("a first not_found: %+v", first)
	}
	second := sent(store.SnapshotNotFound, "refused:not_found")
	if second.Parked || !second.NotFoundSince.Equal(*first.NotFoundSince) || second.Tries != 2 {
		t.Fatalf("a second not_found: %+v", second)
	}
	if _, err := pool.Exec(ctx, `UPDATE contract_workspaces SET not_found_since = not_found_since - interval '23 hours 59 minutes'
		WHERE workspace_id = $1`, ws); err != nil {
		t.Fatal(err)
	}
	if rec := sent(store.SnapshotNotFound, "refused:not_found"); rec.Parked {
		t.Fatalf("parked before a day: %+v", rec)
	}
	if _, err := pool.Exec(ctx, `UPDATE contract_workspaces SET not_found_since = not_found_since - interval '1 minute'
		WHERE workspace_id = $1`, ws); err != nil {
		t.Fatal(err)
	}
	if rec := sent(store.SnapshotNotFound, "refused:not_found"); !rec.Parked {
		t.Fatalf("not parked after a day: %+v", rec)
	}
	r = readSnapshotRow(t, pool, ws)
	if r.ParkedAt == nil || r.NotFoundSince == nil {
		t.Fatalf("a not_found park keeps its not_found_since: %+v", r)
	}
	if _, ok, err := c.NextSnapshot(ctx); err != nil || ok {
		t.Fatalf("a parked workspace is never due: %v %v", ok, err)
	}
	if _, ok, err := c.SnapshotSeq(ctx, ws, dbClock(t, pool, "0")); err != nil || ok {
		t.Fatalf("a parked workspace gets no seq: %v %v", ok, err)
	}

	// A leader's start tries a parked workspace once.
	if err := c.SnapshotsDue(ctx); err != nil {
		t.Fatal(err)
	}
	if r := readSnapshotRow(t, pool, ws); r.ParkedAt != nil || r.NotFoundSince == nil || r.DueIn > 0 {
		t.Fatalf("after a leader's start: %+v", r)
	}
	if seq, ok, err = c.SnapshotSeq(ctx, ws, dbClock(t, pool, "0")); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if rec := sent(store.SnapshotNotFound, "refused:not_found"); !rec.Parked {
		t.Fatalf("one more not_found after a day parks again at once: %+v", rec)
	}

	// invalid_request parks at once, with no not_found_since.
	if err := c.SnapshotsDue(ctx); err != nil {
		t.Fatal(err)
	}
	if seq, ok, err = c.SnapshotSeq(ctx, ws, dbClock(t, pool, "0")); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if rec := sent(store.SnapshotRefused, "refused:invalid_request"); !rec.Parked || rec.NotFoundSince != nil {
		t.Fatalf("invalid_request: %+v", rec)
	}
	if r := readSnapshotRow(t, pool, ws); r.ParkedAt == nil || r.NotFoundSince != nil || r.Error == nil || *r.Error != "refused:invalid_request" {
		t.Fatalf("an invalid_request park: %+v", r)
	}
	// Accepted after the leader's start's try: the park and the error end.
	if err := c.SnapshotsDue(ctx); err != nil {
		t.Fatal(err)
	}
	if seq, ok, err = c.SnapshotSeq(ctx, ws, dbClock(t, pool, "0")); err != nil || !ok {
		t.Fatal(ok, err)
	}
	sent(store.SnapshotAccepted, "")
	if r := readSnapshotRow(t, pool, ws); r.ParkedAt != nil || r.Error != nil || r.Tries != 0 {
		t.Fatalf("accepted after a park: %+v", r)
	}

	// Again: a due time set after the measurement (a document that changes
	// the members, a restart, a name given again) stands, whatever the
	// outcome, and a failure then counts no try.
	for _, outcome := range []store.ContractSnapshotOutcome{store.SnapshotAccepted, store.SnapshotFailed, store.SnapshotNotFound} {
		if seq, ok, err = c.SnapshotSeq(ctx, ws, dbClock(t, pool, "0")); err != nil || !ok {
			t.Fatal(ok, err)
		}
		measured := dbClock(t, pool, "0")
		if _, err := pool.Exec(ctx, `UPDATE contract_workspaces SET snapshot_due_at = clock_timestamp() WHERE workspace_id = $1`, ws); err != nil {
			t.Fatal(err)
		}
		before := readSnapshotRow(t, pool, ws)
		rec, err := c.SnapshotSent(ctx, ws, seq, measured, outcome, "x", snapshotTimes)
		after := readSnapshotRow(t, pool, ws)
		if err != nil || !rec.Recorded || !rec.Again || !after.DueAt.Equal(*before.DueAt) || after.Tries != before.Tries ||
			after.NotFoundSince != nil {
			t.Fatalf("outcome %d after a due time set since the measurement: %+v, %+v then %+v (%v)", outcome, rec, before, after, err)
		}
	}
}

// The debounce: a change a snapshot shows makes it due within 2 s,
// counted from the first change of a run; a workspace backing off keeps
// its backoff, a parked one its park; "all" reaches every one.
func TestContractSnapshotsDirty(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	c := store.NewContract(pool)
	quiet, backing, parked, other := recordWorkspace(t, pool, "team"), recordWorkspace(t, pool, "team"),
		recordWorkspace(t, pool, "personal"), recordWorkspace(t, pool, "personal")
	if _, err := pool.Exec(ctx, `UPDATE contract_workspaces SET snapshot_due_at = clock_timestamp() + interval '50 minutes'`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE contract_workspaces SET snapshot_tries = 4 WHERE workspace_id = $1`, backing); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE contract_workspaces SET parked_at = clock_timestamp() WHERE workspace_id = $1`, parked); err != nil {
		t.Fatal(err)
	}
	if err := c.SnapshotsDirty(ctx, []uuid.UUID{quiet, backing, parked}, false, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if r := readSnapshotRow(t, pool, quiet); r.DueIn > 2*time.Second || r.DueIn < time.Second {
		t.Fatalf("a change: due in %v", r.DueIn)
	}
	first := *readSnapshotRow(t, pool, quiet).DueAt
	time.Sleep(300 * time.Millisecond)
	if err := c.SnapshotsDirty(ctx, []uuid.UUID{quiet}, false, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if r := readSnapshotRow(t, pool, quiet); !r.DueAt.Equal(first) {
		t.Fatalf("a second change of the run moved the snapshot from %v to %v", first, r.DueAt)
	}
	if r := readSnapshotRow(t, pool, backing); r.DueIn < 49*time.Minute {
		t.Fatalf("a workspace backing off lost its backoff: due in %v", r.DueIn)
	}
	if r := readSnapshotRow(t, pool, parked); r.ParkedAt == nil || r.DueIn < 49*time.Minute {
		t.Fatalf("a parked workspace: %+v", r)
	}
	if r := readSnapshotRow(t, pool, other); r.DueIn < 49*time.Minute {
		t.Fatalf("a workspace no change named: due in %v", r.DueIn)
	}
	if err := c.SnapshotsDirty(ctx, nil, true, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if r := readSnapshotRow(t, pool, other); r.DueIn > 2*time.Second {
		t.Fatalf("all: due in %v", r.DueIn)
	}
	next, ok, err := c.NextSnapshot(ctx)
	if err != nil || !ok || next.Due || next.Wait > 2*time.Second || next.Workspace == parked || next.Workspace == backing {
		t.Fatalf("the next due: %+v %v %v", next, ok, err)
	}
}

// 0051's contract_mark_due: a new record, a due time made sooner or due
// now, and a park released each notify the workspace's id, from whichever
// process; the sender's own later due times notify nobody.
func TestContractDueNotify(t *testing.T) {
	backends := &pgtest.Backends{}
	pool := pgtest.FreshWith(t, migrate.Run, backends.Configure)
	ctx := context.Background()
	listener, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Release()
	if _, err := listener.Exec(ctx, `LISTEN `+store.ContractDueChannel); err != nil {
		t.Fatal(err)
	}
	ws := uuid.New()
	heard := func(what string, change string, args ...any) bool {
		t.Helper()
		if _, err := pool.Exec(ctx, change, args...); err != nil {
			t.Fatal(err)
		}
		fence := "fence:" + uuid.NewString()
		if _, err := pool.Exec(ctx, `SELECT pg_notify($1, $2)`, store.ContractDueChannel, fence); err != nil {
			t.Fatal(err)
		}
		wait, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		got := false
		for {
			n, err := listener.Conn().WaitForNotification(wait)
			if err != nil {
				t.Fatalf("%s: %v", what, err)
			}
			switch {
			case n.Payload == fence:
				return got
			case n.Payload == ws.String() && backends.Has(n.PID):
				got = true
			}
		}
	}
	for _, c := range []struct {
		what, sql string
		want      bool
	}{
		{"a new record", `INSERT INTO contract_workspaces (workspace_id, kind) VALUES ($1, 'team')`, true},
		{"its next an hour on", `UPDATE contract_workspaces SET snapshot_due_at = clock_timestamp() + interval '1 hour' WHERE workspace_id = $1`, false},
		{"due within 2 s", `UPDATE contract_workspaces SET snapshot_due_at = clock_timestamp() + interval '2 seconds' WHERE workspace_id = $1`, true},
		{"a backoff later", `UPDATE contract_workspaces SET snapshot_due_at = clock_timestamp() + interval '5 seconds' WHERE workspace_id = $1`, false},
		{"due now", `UPDATE contract_workspaces SET snapshot_due_at = clock_timestamp() WHERE workspace_id = $1`, true},
		{"the seq", `UPDATE contract_workspaces SET snapshot_seq = snapshot_seq + 1 WHERE workspace_id = $1`, false},
		{"parked", `UPDATE contract_workspaces SET parked_at = clock_timestamp(), snapshot_due_at = clock_timestamp() + interval '1 hour'
			WHERE workspace_id = $1`, false},
		{"released", `UPDATE contract_workspaces SET parked_at = NULL WHERE workspace_id = $1`, true},
	} {
		if got := heard(c.what, c.sql, ws); got != c.want {
			t.Errorf("%s: notified %v, want %v", c.what, got, c.want)
		}
	}
}

// A document stored while a snapshot is in flight, measured before it,
// which changes the workspace's members: the snapshot goes again at once
// (Again), not an hour later, though the workspace was due already when
// the document came. Likewise the late outcome of a leader that lost its
// lock without knowing it yet: another leader's start leaves the workspace
// due now, and its debounce of a change due within 2 s.
func TestContractSnapshotInFlight(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	c := store.NewContract(pool)
	sub, gen, personal, team := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	storeDocs(t, c, store.ContractAnswer, contractDoc(sub, gen, 1, "active", personal,
		store.ContractDocWorkspace{ID: team, Role: "member", Status: "open", WVersion: 1}))
	if _, err := pool.Exec(ctx, `UPDATE contract_workspaces SET snapshot_due_at = clock_timestamp() - interval '1 second'
		WHERE workspace_id = $1`, team); err != nil {
		t.Fatal(err)
	}
	measured := dbClock(t, pool, "0")
	seq, ok, err := c.SnapshotSeq(ctx, team, measured)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	storeDocs(t, c, store.ContractAnswer, contractDoc(sub, gen, 2, "active", personal,
		store.ContractDocWorkspace{ID: team, Role: "admin", Status: "open", WVersion: 1}))
	rec, err := c.SnapshotSent(ctx, team, seq, measured, store.SnapshotAccepted, "", snapshotTimes)
	if err != nil || !rec.Recorded || !rec.Again {
		t.Fatalf("the snapshot measured before the document: %+v %v", rec, err)
	}
	if r := readSnapshotRow(t, pool, team); r.DueIn > 0 || r.OKAt == nil {
		t.Fatalf("not due again after the document: %+v", r)
	}

	// L1 measures a workspace due now and sends it; L2 starts (SnapshotsDue);
	// then L1's accepted comes back.
	ws := recordWorkspace(t, pool, "team")
	measured = dbClock(t, pool, "0")
	if seq, ok, err = c.SnapshotSeq(ctx, ws, measured); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if err := c.SnapshotsDue(ctx); err != nil {
		t.Fatal(err)
	}
	if rec, err := c.SnapshotSent(ctx, ws, seq, measured, store.SnapshotAccepted, "", snapshotTimes); err != nil || !rec.Recorded || !rec.Again {
		t.Fatalf("a late outcome after another leader's start: %+v %v", rec, err)
	}
	if r := readSnapshotRow(t, pool, ws); r.DueIn > 0 || r.OKAt == nil {
		t.Fatalf("not due after another leader's start: %+v", r)
	}

	// L1 measures; L2 debounces a change committed since; then L1's outcome,
	// accepted or failed, comes back: still due within 2 s, and no try.
	for _, outcome := range []store.ContractSnapshotOutcome{store.SnapshotAccepted, store.SnapshotFailed} {
		if _, err := pool.Exec(ctx, `UPDATE contract_workspaces SET snapshot_due_at = clock_timestamp() + interval '50 minutes',
			snapshot_tries = 0 WHERE workspace_id = $1`, ws); err != nil {
			t.Fatal(err)
		}
		measured = dbClock(t, pool, "0")
		if seq, ok, err = c.SnapshotSeq(ctx, ws, measured); err != nil || !ok {
			t.Fatal(ok, err)
		}
		if err := c.SnapshotsDirty(ctx, []uuid.UUID{ws}, false, 2*time.Second); err != nil {
			t.Fatal(err)
		}
		rec, err := c.SnapshotSent(ctx, ws, seq, measured, outcome, "unavailable:timeout", snapshotTimes)
		if err != nil || !rec.Recorded || !rec.Again || rec.Tries != 0 {
			t.Fatalf("outcome %d after another leader's debounce: %+v %v", outcome, rec, err)
		}
		if r := readSnapshotRow(t, pool, ws); r.DueIn > 2*time.Second || r.DueIn < time.Second || r.Tries != 0 {
			t.Fatalf("outcome %d after another leader's debounce: due in %v, %+v", outcome, r.DueIn, r)
		}
	}
	// A debounce longer than the failure's backoff: the sooner stands.
	if _, err := pool.Exec(ctx, `UPDATE contract_workspaces SET snapshot_due_at = clock_timestamp() + interval '50 minutes'
		WHERE workspace_id = $1`, ws); err != nil {
		t.Fatal(err)
	}
	measured = dbClock(t, pool, "0")
	if seq, ok, err = c.SnapshotSeq(ctx, ws, measured); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if err := c.SnapshotsDirty(ctx, []uuid.UUID{ws}, false, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SnapshotSent(ctx, ws, seq, measured, store.SnapshotFailed, "unavailable:timeout", snapshotTimes); err != nil {
		t.Fatal(err)
	}
	if r := readSnapshotRow(t, pool, ws); r.DueIn > 5*time.Second || r.DueIn < 4*time.Second {
		t.Fatalf("a failure's backoff sooner than another leader's debounce: due in %v", r.DueIn)
	}
}

// A number's state as its workspace makes it (the plan's 4.10 and DB12):
// paused for quota exactly when the workspace's storage check refuses
// capture (Storage.Check's verdict, read in a transaction rolled back, as
// it records the stop it finds): a stop recorded, 105% of the limit, or
// the 72 hours of grace spent; and paused in error in a workspace that is
// not active.
func TestSnapshotTenantStates(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	c := store.NewContract(pool)
	var tenant uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('Equipe') RETURNING id`).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	d, err := store.NewDevices(pool).Create(ctx, tenant.String(), "Vendas", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	if err := pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE devices SET pn = '5511912345678@s.whatsapp.net', status = 'online' WHERE id = $1`, d.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	stateOf := func() (string, string) {
		t.Helper()
		s, err := c.Snapshot(ctx, tenant)
		if err != nil || len(s.Items) != 1 {
			t.Fatalf("the snapshot: %+v %v", s, err)
		}
		return s.Items[0].State, s.Items[0].Reason
	}
	refused := func() bool {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck // the check's stop is not kept
		if _, err := tx.Exec(ctx, `SELECT set_config($1, $2, true)`, pg.TenantGUC, tenant.String()); err != nil {
			t.Fatal(err)
		}
		u, err := store.StorageUsageTx(ctx, tx, tenant)
		if err != nil {
			t.Fatal(err)
		}
		return u.PausedAt != nil
	}
	const reset = `status = 'active', storage_limit_bytes = NULL, storage_archive_bytes = 0, storage_object_bytes = 0,
		storage_over_since = NULL, storage_paused_at = NULL`
	for _, x := range []struct {
		what, set     string
		quota         bool
		state, reason string
	}{
		{"capturing", `storage_limit_bytes = 1000, storage_archive_bytes = 900`, false, store.SnapshotActive, ""},
		{"a stop recorded", `storage_paused_at = clock_timestamp()`, true, store.SnapshotSyncPaused, store.SnapshotQuota},
		{"105% of the limit, no stop recorded", `storage_limit_bytes = 1000, storage_archive_bytes = 1000, storage_object_bytes = 50,
			storage_over_since = clock_timestamp()`, true, store.SnapshotSyncPaused, store.SnapshotQuota},
		{"104% of the limit", `storage_limit_bytes = 1000, storage_archive_bytes = 1000, storage_object_bytes = 40,
			storage_over_since = clock_timestamp()`, false, store.SnapshotActive, ""},
		{"over for 73 hours", `storage_limit_bytes = 1000, storage_archive_bytes = 1001,
			storage_over_since = clock_timestamp() - interval '73 hours'`, true, store.SnapshotSyncPaused, store.SnapshotQuota},
		{"over for 71 hours", `storage_limit_bytes = 1000, storage_archive_bytes = 1001,
			storage_over_since = clock_timestamp() - interval '71 hours'`, false, store.SnapshotActive, ""},
		{"over since 73 hours, no limit now", `storage_over_since = clock_timestamp() - interval '73 hours'`, false, store.SnapshotActive, ""},
		{"a suspended workspace", `status = 'suspended'`, false, store.SnapshotSyncPaused, store.SnapshotError},
	} {
		if _, err := pool.Exec(ctx, `UPDATE tenants SET `+reset+` WHERE id = $1`, tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `UPDATE tenants SET `+x.set+` WHERE id = $1`, tenant); err != nil {
			t.Fatalf("%s: %v", x.what, err)
		}
		state, reason := stateOf()
		if state != x.state || reason != x.reason {
			t.Errorf("%s: %s/%s, want %s/%s", x.what, state, reason, x.state, x.reason)
		}
		if got := refused(); got != x.quota {
			t.Errorf("%s: the storage check refuses capture %v, want %v", x.what, got, x.quota)
		}
	}
}

// A suspended sole holder stays protected (the plan's 19; Wappie's reply
// of 2026-10-14, which the platform's verdict follows): a person whose
// account is disabled, whose membership stands, and who holds a number's
// only key is in the snapshot's protected for it, and an owner's removal
// or disable of them is refused, with last_device_reader for a live
// number and last_reader_of_deleted for a deleted one. Only an active
// person is a backup: a second suspended holder changes nothing, and an
// active one with Read and the key lets the removal through, and is then
// the one protected.
func TestSuspendedSoleHolderProtected(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	c := store.NewContract(w.pool)
	holder, gone := w.person(t, "holder", "member"), w.person(t, "gone-holder", "member")
	holderSub, goneSub := linkSub(t, w.pool, holder), linkSub(t, w.pool, gone)
	live, deleted := w.number(t, "Vendas"), w.number(t, "Suporte")
	w.reads(t, holder, live)
	w.reads(t, gone, deleted)
	w.quarantine(t, deleted, gone)
	// A second holder of the live number, suspended too: no backup.
	suspendedBackup := w.person(t, "suspended-backup", "member")
	w.reads(t, suspendedBackup, live)
	for _, u := range []uuid.UUID{holder, gone, suspendedBackup} {
		w.disableAccount(t, u)
	}
	protectedOn := func(device uuid.UUID) []uuid.UUID {
		t.Helper()
		s, err := c.Snapshot(ctx, w.tenant)
		if err != nil {
			t.Fatal(err)
		}
		for _, it := range s.Items {
			if it.ID == device {
				return it.Protected
			}
		}
		t.Fatalf("%s is not in the snapshot", device)
		return nil
	}
	if got := protectedOn(live); !sameSubs(got, holderSub) {
		t.Fatalf("the live number protects %v, want the suspended sole holder %s", got, holderSub)
	}
	if got := protectedOn(deleted); !sameSubs(got, goneSub) {
		t.Fatalf("the deleted number protects %v, want the suspended sole holder %s", got, goneSub)
	}
	if err := w.users.RemoveMember(ctx, w.tenant, w.owner, holder); !errors.Is(err, store.ErrLastDeviceReader) {
		t.Fatalf("removing a live number's suspended sole holder: %v", err)
	}
	if err := w.users.UpdateMember(ctx, w.tenant, w.owner, holder, "member", "disabled"); !errors.Is(err, store.ErrLastDeviceReader) {
		t.Fatalf("disabling a live number's suspended sole holder: %v", err)
	}
	var refused *store.ErrLastReaderOfDeleted
	if err := w.users.RemoveMember(ctx, w.tenant, w.owner, gone); !errors.As(err, &refused) ||
		len(refused.Numbers) != 1 || refused.Numbers[0].DeviceID != deleted {
		t.Fatalf("removing a deleted number's suspended sole holder: %v", err)
	}

	// An active backup, linked, with Read and the key.
	backup := w.person(t, "backup", "member")
	backupSub := linkSub(t, w.pool, backup)
	w.reads(t, backup, live)
	if got := protectedOn(live); !sameSubs(got, backupSub) {
		t.Fatalf("with an active backup the live number protects %v, want only the backup %s", got, backupSub)
	}
	if err := w.users.RemoveMember(ctx, w.tenant, w.owner, holder); err != nil {
		t.Fatalf("removing a suspended holder with an active backup: %v", err)
	}
	if n := w.count(t, `SELECT count(*) FROM workspace_memberships WHERE tenant_id = $1 AND user_id = $2`, w.tenant, holder); n != 0 {
		t.Fatal("the suspended holder's membership is still there")
	}
}
