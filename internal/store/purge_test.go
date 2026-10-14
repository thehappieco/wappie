package store_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/domain"
	"whatserver2/internal/pg"
	"whatserver2/internal/store"
)

// The purge (decision 0038's plan, section 7, and its test 15): 30 days
// after its deletion a number goes for good, in short batches that each
// take the workspace's row first, and an object whose delete fails is left
// to the orphan pass, never holding the rest back.

// bucket is the object store, recording the keys it is asked to delete.
type bucket struct {
	mu      sync.Mutex
	removed []string
	fail    error
	hang    bool
}

func (b *bucket) remove(ctx context.Context, key string) error {
	if b.hang {
		<-ctx.Done()
		return ctx.Err()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.fail != nil {
		return b.fail
	}
	b.removed = append(b.removed, key)
	return nil
}

func (b *bucket) keys() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := slices.Clone(b.removed)
	slices.Sort(out)
	return out
}

// quarantine deletes a number of the archive as its owner does.
func (a *excludedArchive) quarantine(t *testing.T, device uuid.UUID, ack ...uuid.UUID) store.Quarantined {
	t.Helper()
	q, err := store.NewDevices(a.pool).Quarantine(context.Background(), a.tenant, a.owner, device, ack)
	if err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	return q
}

// makeDue backdates an excluded number's purge_after in SQL, with the scope
// on, as the deploy's documented operator step does.
func makeDue(t *testing.T, pool interface {
	Begin(context.Context) (pgx.Tx, error)
}, tenant, device uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // committed below
	if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenant.String()); err != nil {
		t.Fatal(err)
	}
	if err := store.WithQuarantineForTest(ctx, tx, func() error {
		tag, err := tx.Exec(ctx, `UPDATE devices SET purge_after = clock_timestamp() - interval '1 minute' WHERE id = $1 AND deleted_at IS NOT NULL`, device)
		if err == nil && tag.RowsAffected() != 1 {
			err = errors.New("no excluded number to make due")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func (a *excludedArchive) objectKeys(t *testing.T, device uuid.UUID) []string {
	t.Helper()
	keys, err := store.ObjectKeysForDevice(context.Background(), a.pool, a.tenant, device)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(keys)
	return keys
}

func (a *excludedArchive) left(t *testing.T, device uuid.UUID) map[string]int {
	t.Helper()
	ctx := context.Background()
	out := map[string]int{}
	inTenantTx(ctx, t, a.pool, a.tenant, func(tx pgx.Tx) error {
		for table, count := range archiveTables {
			var n int
			if err := tx.QueryRow(ctx, count, device).Scan(&n); err != nil {
				return err
			}
			if n > 0 {
				out[table] = n
			}
		}
		return nil
	})
	return out
}

func TestPurge(t *testing.T) {
	a := newExcludedArchive(t)
	ctx := context.Background()
	storage := store.NewStorage(a.pool)
	sessionStore(t, a.pool)
	pn := func(device uuid.UUID) string {
		var p string
		inTenantTx(ctx, t, a.pool, a.tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT pn FROM devices WHERE id = $1`, device).Scan(&p)
		})
		return p
	}
	excludedJID := pn(a.excluded)
	// The deleted number's session survived its logout; another phone
	// keeps its own privacy tokens.
	for _, sql := range []string{`INSERT INTO whatsmeow_device (jid, registration_id) VALUES ($1, 7)`,
		`INSERT INTO whatsmeow_privacy_tokens VALUES ($1, 'them@s.whatsapp.net', '\x01', 1), ('other@s.whatsapp.net', 'them@s.whatsapp.net', '\x01', 1)`} {
		if _, err := a.pool.Exec(ctx, sql, excludedJID); err != nil {
			t.Fatal(err)
		}
	}
	stored := a.storedBy(t, a.excluded)
	keys := a.objectKeys(t, a.excluded)
	if len(keys) == 0 {
		t.Fatal("the archive holds no object")
	}
	before, err := storage.Usage(ctx, a.tenant)
	if err != nil {
		t.Fatal(err)
	}
	q := a.quarantine(t, a.excluded)
	if q.Session == nil || q.Session.RegistrationID != 7 {
		t.Fatalf("the deletion kept no fingerprint: %+v", q)
	}
	// A suspended workspace's deleted numbers keep their date (18.8).
	if _, err := a.pool.Exec(ctx, `UPDATE tenants SET status = 'suspended' WHERE id = $1`, a.tenant); err != nil {
		t.Fatal(err)
	}

	// Not due: nothing happens, and nothing starts.
	if _, err := store.PurgeDevice(ctx, a.pool, a.tenant, a.excluded, nil, store.PurgeOptions{}); !errors.Is(err, store.ErrNotDue) {
		t.Fatalf("a purge before its date: %v", err)
	}
	makeDue(t, a.pool, a.tenant, a.excluded)
	b := &bucket{}
	var batches []int64
	res, err := store.PurgeDevice(ctx, a.pool, a.tenant, a.excluded, &store.ObjectDeletes{Storage: storage, Remove: b.remove},
		store.PurgeOptions{Batch: 2, AfterBatch: func(_ string, rows int64) { batches = append(batches, rows) }})
	if err != nil || !res.Done || !res.Final || !res.SessionRemoved {
		t.Fatalf("the purge: %+v %v", res, err)
	}
	// Each batch deleted at most its bound from one table, and the purge
	// took several.
	if len(batches) < 4 {
		t.Fatalf("%d batches", len(batches))
	}
	for _, n := range batches {
		if n > 2 {
			t.Fatalf("a batch deleted %d rows: %v", n, batches)
		}
	}
	if got := b.keys(); !slices.Equal(got, keys) || res.ObjectsRemoved != len(keys) || res.ObjectsFailed != 0 {
		t.Fatalf("the bucket deleted %q, the number held %q (%+v)", got, keys, res)
	}
	after, err := storage.Usage(ctx, a.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if before.ArchiveBytes-after.ArchiveBytes != stored.ArchiveBytes || before.ObjectBytes-after.ObjectBytes != stored.ObjectBytes {
		t.Fatalf("the workspace stores %+v, was %+v; the number stored %+v", after, before, stored)
	}
	if left := a.left(t, a.excluded); len(left) != 0 {
		t.Fatalf("the purge left %v", left)
	}
	var row int
	inTenantTx(ctx, t, a.pool, a.tenant, func(tx pgx.Tx) error {
		return store.WithQuarantineForTest(ctx, tx, func() error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM devices WHERE id = $1`, a.excluded).Scan(&row)
		})
	})
	if row != 0 {
		t.Fatal("the number's row is still there")
	}
	// The session went by its fingerprint, with its own privacy tokens.
	var sessions, tokens int
	if err := a.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM whatsmeow_device), (SELECT count(*) FROM whatsmeow_privacy_tokens WHERE our_jid = $1)`,
		excludedJID).Scan(&sessions, &tokens); err != nil || sessions != 0 || tokens != 0 {
		t.Fatalf("the session: %d rows, %d tokens left %v", sessions, tokens, err)
	}
	if err := a.pool.QueryRow(ctx, `SELECT count(*) FROM whatsmeow_privacy_tokens`).Scan(&tokens); err != nil || tokens != 1 {
		t.Fatalf("another phone's privacy tokens: %d %v", tokens, err)
	}
	// One purged row, from the app, with the deletion's dates; no label or
	// hint is left in any of the number's rows.
	rows := readEvents(t, a.pool, a.tenant, a.excluded)
	purged := 0
	for _, e := range rows {
		if e.Label != nil || e.Hint != nil {
			t.Fatalf("a %s row kept its label: %+v", e.Type, e)
		}
		if e.Type == "purged" {
			purged++
			if e.ActorKind != "app" || e.ActorSub != nil || e.ActorUserID != nil || len(e.ReaderSubs) != 0 ||
				!e.DeletedAt.Equal(q.DeletedAt) || e.Ledgered {
				t.Fatalf("the purged row: %+v", e)
			}
		}
	}
	if purged != 1 || len(rows) != 2 {
		t.Fatalf("the number's events: %+v", rows)
	}
	// A purge of a number that is gone finds nothing.
	if _, err := store.PurgeDevice(ctx, a.pool, a.tenant, a.excluded, nil, store.PurgeOptions{}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a second purge: %v", err)
	}
	// The other number keeps everything, and keeps archiving.
	if left := a.left(t, a.live); len(left) != len(archiveTables) {
		t.Fatalf("the live number lost rows: %v", left)
	}
	if _, err := a.pool.Exec(ctx, `UPDATE tenants SET status = 'active' WHERE id = $1`, a.tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := a.messages.Insert(ctx, store.InsertMessage{UID: uuid.New(), TenantID: a.tenant, DeviceID: a.live, WAID: "after",
		ChatKey: a.chatKeys[a.live], Kind: domain.KindMessage, Type: domain.TypeText, Source: domain.SourceLive,
		TS: time.Now(), BodySealed: []byte{1}}); err != nil {
		t.Fatalf("the live number after the purge: %v", err)
	}
}

// A session under the same JID with another registration id is a phone
// linked again: the purge never touches it.
func TestPurgeLeavesARelinkedSession(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	sessionStore(t, w.pool)
	device := w.number(t, "Vendas")
	jid := w.pn(ctx, t, device)
	if _, err := w.pool.Exec(ctx, `INSERT INTO whatsmeow_device VALUES ($1, 7)`, jid); err != nil {
		t.Fatal(err)
	}
	w.quarantine(t, device)
	for _, sql := range []string{`UPDATE whatsmeow_device SET registration_id = 8 WHERE jid = $1`,
		`INSERT INTO whatsmeow_privacy_tokens VALUES ($1, 'them@s.whatsapp.net', '\x01', 1)`} {
		if _, err := w.pool.Exec(ctx, sql, jid); err != nil {
			t.Fatal(err)
		}
	}
	makeDue(t, w.pool, w.tenant, device)
	res, err := store.PurgeDevice(ctx, w.pool, w.tenant, device, nil, store.PurgeOptions{})
	if err != nil || !res.Final || res.SessionRemoved {
		t.Fatalf("the purge: %+v %v", res, err)
	}
	var sessions, tokens int
	if err := w.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM whatsmeow_device WHERE registration_id = 8), (SELECT count(*) FROM whatsmeow_privacy_tokens)`).
		Scan(&sessions, &tokens); err != nil || sessions != 1 || tokens != 1 {
		t.Fatalf("the relinked session: %d, its tokens %d %v", sessions, tokens, err)
	}
}

// An object whose delete fails, or that a crash left before its delete,
// never holds the purge back: the number goes on schedule, and the object
// stays in storage_objects, unreferenced, until an orphan pass deletes it.
func TestPurgeLeavesFailedObjectsToTheOrphanPass(t *testing.T) {
	for _, crash := range []bool{false, true} {
		a := newExcludedArchive(t)
		ctx := context.Background()
		storage := store.NewStorage(a.pool)
		keys := a.objectKeys(t, a.excluded)
		a.quarantine(t, a.excluded)
		makeDue(t, a.pool, a.tenant, a.excluded)
		b := &bucket{fail: errors.New("bucket unreachable")}
		objects := &store.ObjectDeletes{Storage: storage, Remove: b.remove}
		if crash {
			objects = nil
		}
		res, err := store.PurgeDevice(ctx, a.pool, a.tenant, a.excluded, objects, store.PurgeOptions{})
		if err != nil || !res.Final || res.ObjectsRemoved != 0 {
			t.Fatalf("crash %v: the purge: %+v %v", crash, res, err)
		}
		if left := a.left(t, a.excluded); len(left) != 0 {
			t.Fatalf("crash %v: the purge left %v", crash, left)
		}
		if n := len(eventsOf(t, a.pool, a.tenant, a.excluded, "purged")); n != 1 {
			t.Fatalf("crash %v: %d purged rows", crash, n)
		}
		orphans, err := storage.UnreferencedObjects(ctx, a.tenant, 1000)
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range keys {
			if !slices.Contains(orphans, k) {
				t.Fatalf("crash %v: %s is no orphan the next pass would retry: %v", crash, k, orphans)
			}
		}
		b.fail = nil
		for _, k := range orphans {
			if err := storage.DeleteObject(ctx, a.tenant, k, b.remove); err != nil {
				t.Fatal(err)
			}
		}
		if got := b.keys(); !slices.Equal(got, keys) {
			t.Fatalf("crash %v: the orphan pass deleted %q, want %q", crash, got, keys)
		}
	}
}

// A number a client or a logout still holds is skipped by the start, and
// purged once let go; one not due is never started, unless an operator
// purges it now, which makes its record say so.
func TestPurgeWaitsForAHeldNumber(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	device := w.number(t, "Vendas")
	w.quarantine(t, device)
	makeDue(t, w.pool, w.tenant, device)
	release, ok, err := pg.NewLocker(w.pool).TryLock(ctx, "device:"+device.String())
	if err != nil || !ok {
		t.Fatalf("the device lock: %v %v", ok, err)
	}
	res, err := store.PurgeDevice(ctx, w.pool, w.tenant, device, nil, store.PurgeOptions{})
	if err != nil || !res.Busy || res.Done {
		t.Fatalf("a held number: %+v %v", res, err)
	}
	if n := w.count(t, `SELECT count(*) FROM devices WHERE id = $1 AND purge_started_at IS NULL`, device); n != 1 {
		t.Fatal("a skipped purge started")
	}
	release()
	if res, err := store.PurgeDevice(ctx, w.pool, w.tenant, device, nil, store.PurgeOptions{}); err != nil || !res.Final {
		t.Fatalf("after the lock: %+v %v", res, err)
	}

	early := w.number(t, "Cedo")
	q := w.quarantine(t, early)
	if _, err := store.PurgeDevice(ctx, w.pool, w.tenant, early, nil, store.PurgeOptions{}); !errors.Is(err, store.ErrNotDue) {
		t.Fatalf("a number not due: %v", err)
	}
	res, err = store.PurgeDevice(ctx, w.pool, w.tenant, early, nil, store.PurgeOptions{Now: true})
	if err != nil || !res.Final || !res.PurgeAfter.Before(q.PurgeAfter) || !res.DeletedAt.Equal(q.DeletedAt) {
		t.Fatalf("an operator's purge now: %+v %v (deleted %+v)", res, err, q)
	}
	if rows := eventsOf(t, w.pool, w.tenant, early, "purged"); len(rows) != 1 || !rows[0].PurgeAfter.Equal(res.PurgeAfter) {
		t.Fatalf("the early purge's row: %+v", rows)
	}
}

// Two purgers of one number (the janitor runs in every process) take turns
// batch by batch: one deletes the row and writes the one purged row.
func TestPurgersSerialize(t *testing.T) {
	a := newExcludedArchive(t)
	ctx := context.Background()
	a.quarantine(t, a.excluded)
	makeDue(t, a.pool, a.tenant, a.excluded)
	var wg sync.WaitGroup
	results := make([]store.PurgeResult, 2)
	errs := make([]error, 2)
	for i := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = store.PurgeDevice(ctx, a.pool, a.tenant, a.excluded, nil, store.PurgeOptions{Batch: 1})
		}()
	}
	wg.Wait()
	final := 0
	for i := range 2 {
		if errs[i] != nil && !errors.Is(errs[i], store.ErrNotFound) {
			t.Fatalf("purger %d: %v", i, errs[i])
		}
		if results[i].Final {
			final++
		}
	}
	if final != 1 {
		t.Fatalf("%d purgers deleted the row: %+v", final, results)
	}
	if n := len(eventsOf(t, a.pool, a.tenant, a.excluded, "purged")); n != 1 {
		t.Fatalf("%d purged rows", n)
	}
	if left := a.left(t, a.excluded); len(left) != 0 {
		t.Fatalf("the purgers left %v", left)
	}
}

// Every purge transaction takes the workspace's row before the number's,
// the order of every writer: while another transaction holds the workspace,
// a purge waiting on it holds no number row (test 12's blocker pattern).
func TestPurgeLocksTheWorkspaceFirst(t *testing.T) {
	a := newExcludedArchive(t)
	ctx := context.Background()
	a.quarantine(t, a.excluded)
	makeDue(t, a.pool, a.tenant, a.excluded)

	// blockWhile holds the workspace's row while go_on lets the purge run
	// into its next transaction, and checks, once the purge waits on it,
	// that the number's row is free.
	blockWhile := func(goOn func()) {
		t.Helper()
		ctx := context.Background()
		blocker, err := a.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer blocker.Rollback(ctx) //nolint:errcheck // released below
		if _, err := blocker.Exec(ctx, `SELECT 1 FROM tenants WHERE id = $1 FOR UPDATE`, a.tenant); err != nil {
			t.Fatal(err)
		}
		goOn()
		waitBlockedOn(t, a.pool, int(blocker.Conn().PgConn().PID()), 1)
		if err := pg.InTenantTx(ctx, a.pool, a.tenant.String(), func(tx pgx.Tx) error {
			return store.WithQuarantineForTest(ctx, tx, func() error {
				_, err := tx.Exec(ctx, `SELECT 1 FROM devices WHERE id = $1 FOR UPDATE NOWAIT`, a.excluded)
				return err
			})
		}); err != nil {
			t.Fatalf("a purge waiting on the workspace holds the number's row: %v", err)
		}
		if err := blocker.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
	}

	// The start, then a batch.
	afterFirst, resume := make(chan struct{}), make(chan struct{})
	var once sync.Once
	done := make(chan error, 1)
	blockWhile(func() {
		go func() {
			_, err := store.PurgeDevice(ctx, a.pool, a.tenant, a.excluded, nil, store.PurgeOptions{Batch: 1, AfterBatch: func(string, int64) {
				once.Do(func() {
					close(afterFirst)
					<-resume
				})
			}})
			done <- err
		}()
	})
	<-afterFirst
	blockWhile(func() { close(resume) })
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if n := len(eventsOf(t, a.pool, a.tenant, a.excluded, "purged")); n != 1 {
		t.Fatalf("%d purged rows", n)
	}
}

// The deleted number's notices outlive it with no name, and go by their
// own timers; its other notices go with it. Its event rows keep no name.
func TestPurgeNotices(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	device := w.number(t, "Vendas")
	reader := w.person(t, "ana", "member")
	other := w.person(t, "bia", "owner")
	w.reads(t, w.owner, device)
	w.reads(t, reader, device)
	w.pause(t, device, store.PauseActor{User: w.owner})
	w.quarantine(t, device, reader)
	for _, u := range []uuid.UUID{reader, other} {
		if n := w.notices(t, u); len(n) != 1 || n[0].Label == nil {
			t.Fatalf("%s's notice before the purge: %+v", u, n)
		}
	}
	makeDue(t, w.pool, w.tenant, device)
	if res, err := store.PurgeDevice(ctx, w.pool, w.tenant, device, nil, store.PurgeOptions{}); err != nil || !res.Final {
		t.Fatalf("the purge: %+v %v", res, err)
	}
	for _, u := range []uuid.UUID{reader, other} {
		n := w.notices(t, u)
		if len(n) != 1 || n[0].Kind != store.NoticeNumberDeleted || n[0].Label != nil || n[0].Hint != nil || n[0].PurgedAt == nil {
			t.Fatalf("%s's notice after the purge: %+v", u, n)
		}
	}
	for _, e := range readEvents(t, w.pool, w.tenant, device) {
		if e.Label != nil || e.Hint != nil {
			t.Fatalf("a %s row kept its name: %+v", e.Type, e)
		}
	}
	// Housekeeping keeps them until 30 days after the purge.
	housekeep := func() store.DeletionHousekeepingCounts {
		t.Helper()
		c, err := store.DeletionHousekeeping(ctx, w.pool, w.tenant)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	housekeep()
	if n := w.notices(t, reader); len(n) != 1 {
		t.Fatalf("housekeeping took a purged number's notice within its 30 days: %+v", n)
	}
	inTenantTx(ctx, t, w.pool, w.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE device_notices SET purged_at = clock_timestamp() - interval '31 days' WHERE user_id = $1`, reader)
		return err
	})
	if c := housekeep(); c.Notices != 1 || len(w.notices(t, reader)) != 0 || len(w.notices(t, other)) != 1 {
		t.Fatalf("30 days after the purge: %+v", c)
	}
}
