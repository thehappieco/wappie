package store_test

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/obs"
	"whatserver2/internal/pg"
	"whatserver2/internal/store"
)

// The local event log (0050's item_events) and the readers' pause notices
// (decision 0038's plan, sections 5 and 8): what each writer records, and
// who is told of a pause.

// eventRow is one item_events row as a test reads it.
type eventRow struct {
	Type, ActorKind, DedupeKey string
	ActorSub, ActorUserID      *uuid.UUID
	ReaderSubs                 []uuid.UUID
	Label, Hint                *string
	OccurredAt                 time.Time
	DeletedAt, PurgeAfter      *time.Time
	ToTenantID                 *uuid.UUID
	Ledgered                   bool
	Seq                        int64
}

func readEvents(t *testing.T, pool *pgxpool.Pool, tenant, device uuid.UUID) []eventRow {
	t.Helper()
	ctx := context.Background()
	var out []eventRow
	inTenantTx(ctx, t, pool, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT type, actor_kind, dedupe_key, actor_sub, actor_user_id, reader_subs, label, hint,
			occurred_at, deleted_at, purge_after, to_tenant_id, ledgered_at IS NOT NULL, seq
			FROM item_events WHERE item_id = $1 ORDER BY seq`, device)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (eventRow, error) {
			var e eventRow
			err := row.Scan(&e.Type, &e.ActorKind, &e.DedupeKey, &e.ActorSub, &e.ActorUserID, &e.ReaderSubs, &e.Label, &e.Hint,
				&e.OccurredAt, &e.DeletedAt, &e.PurgeAfter, &e.ToTenantID, &e.Ledgered, &e.Seq)
			return e, err
		})
		return err
	})
	return out
}

// eventsOf is readEvents for one type.
func eventsOf(t *testing.T, pool *pgxpool.Pool, tenant, device uuid.UUID, kind string) []eventRow {
	t.Helper()
	var out []eventRow
	for _, e := range readEvents(t, pool, tenant, device) {
		if e.Type == kind {
			out = append(out, e)
		}
	}
	return out
}

// linkSub links an account to the platform with a new sub, as id.'s sign-in
// does.
func linkSub(t *testing.T, pool *pgxpool.Pool, user uuid.UUID) uuid.UUID {
	t.Helper()
	sub := uuid.New()
	if _, err := pool.Exec(context.Background(), `INSERT INTO platform_identities (sub, user_id, email, linked_from)
		VALUES ($1, $2, $3, 'new')`, sub, user, sub.String()[:8]+"@id.test"); err != nil {
		t.Fatal(err)
	}
	return sub
}

func sameSubs(got []uuid.UUID, want ...uuid.UUID) bool {
	a, b := slices.Clone(got), slices.Clone(want)
	sortIDs := func(s []uuid.UUID) {
		slices.SortFunc(s, func(x, y uuid.UUID) int { return strings.Compare(x.String(), y.String()) })
	}
	sortIDs(a)
	sortIDs(b)
	return slices.Equal(a, b)
}

func (w *delWorld) pause(t *testing.T, device uuid.UUID, by store.PauseActor) store.Paused {
	t.Helper()
	p, err := w.devices.Pause(context.Background(), w.tenant, device, by)
	if err != nil {
		t.Fatalf("pause: %v", err)
	}
	return p
}

// resume is what device.start does to the store once the client runs.
func (w *delWorld) resume(t *testing.T, device uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	if err := w.devices.SetPaused(ctx, w.tenant.String(), device.String(), false); err != nil {
		t.Fatal(err)
	}
	if err := w.devices.MarkResumed(ctx, w.tenant, device); err != nil {
		t.Fatal(err)
	}
}

func (w *delWorld) notices(t *testing.T, user uuid.UUID) []store.DeviceNotice {
	t.Helper()
	n, err := w.devices.Notices(context.Background(), w.tenant, user)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// keyBy issues an Integrations key restricted to device, created by
// creator (nil: a key from the command line, with no creator).
func (w *delWorld) keyBy(t *testing.T, creator *uuid.UUID, device uuid.UUID) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	key, err := w.apiKeys.IssueActingAsForDevices(ctx, w.tenant.String(), "k-"+uuid.NewString()[:6], store.ScopeFull, creator, nil, []uuid.UUID{device}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return w.keyID(ctx, t, key)
}

// TestPauseNotices is the plan's test 14; its housekeeping cases are
// TestNoticeHousekeeping's.
func TestPauseNotices(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	device := w.number(t, "Vendas")
	// Only owners and admins create keys: A, who reads, is an admin.
	a, b := w.person(t, "ana", "admin"), w.person(t, "bia", "member")
	admin := w.person(t, "adm", "admin")
	for _, u := range []uuid.UUID{w.owner, a, b} {
		w.reads(t, u, device)
	}
	ownerSub, aSub, bSub := linkSub(t, w.pool, w.owner), linkSub(t, w.pool, a), linkSub(t, w.pool, b)
	linkSub(t, w.pool, admin)
	svc, err := w.users.CreateService(ctx, w.tenant, "erp", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	service := svc.ID
	w.reads(t, service, device)

	// A person: only the transition writes, and only the other readers are
	// told, never a service account.
	p := w.pause(t, device, store.PauseActor{User: w.owner})
	if !p.Changed || !p.Recorded || len(p.Notices) != 2 || p.ActorKind != "person" {
		t.Fatalf("the owner's pause: %+v", p)
	}
	if again := w.pause(t, device, store.PauseActor{User: w.owner}); again.Changed || again.Recorded || len(again.Notices) != 0 {
		t.Fatalf("a repeated stop: %+v", again)
	}
	for _, u := range []uuid.UUID{a, b} {
		n := w.notices(t, u)
		if len(n) != 1 || n[0].Kind != store.NoticeSyncPaused || n[0].RaisedByKind != "person" || n[0].RaisedByName == nil ||
			n[0].Label == nil || *n[0].Label != "Vendas" || n[0].Hint == nil || *n[0].Hint != "…5678" || n[0].Pauses != 1 {
			t.Fatalf("%s's notice: %+v", u, n)
		}
	}
	if len(w.notices(t, w.owner)) != 0 || w.count(t, `SELECT count(*) FROM device_notices WHERE user_id=$1`, service) != 0 {
		t.Fatal("the actor, or a service account, was told")
	}
	rows := eventsOf(t, w.pool, w.tenant, device, "sync_paused")
	if len(rows) != 1 || rows[0].ActorKind != "person" || rows[0].ActorSub == nil || *rows[0].ActorSub != ownerSub ||
		rows[0].ActorUserID == nil || *rows[0].ActorUserID != w.owner || !sameSubs(rows[0].ReaderSubs, ownerSub, aSub, bSub) ||
		!rows[0].Ledgered || rows[0].Label == nil || *rows[0].Label != "Vendas" {
		t.Fatalf("the sync_paused row: %+v", rows)
	}

	// A reader away between the pause and the resume still has it, resumed,
	// with both dates; a second pause folds into it, open again.
	w.resume(t, device)
	n := w.notices(t, a)
	if len(n) != 1 || n[0].ResumedAt == nil {
		t.Fatalf("after the resume: %+v", n)
	}
	w.pause(t, device, store.PauseActor{User: w.owner})
	n = w.notices(t, a)
	if len(n) != 1 || n[0].Pauses != 2 || n[0].ResumedAt != nil || n[0].LastRaisedAt == nil || !n[0].LastRaisedAt.After(n[0].RaisedAt) ||
		n[0].SeveralActors {
		t.Fatalf("pause, resume, pause: %+v", n)
	}
	first := w.notices(t, b)[0].RaisedAt
	// The seen mark is per viewer and per notice, and per version: a pause
	// notice keeps its id when a pause folds into it, so seeing the version
	// before the fold, or naming it by a bare id, leaves it unseen.
	shown := store.SeenNotice{ID: n[0].ID, Pauses: n[0].Pauses}
	if left, err := w.devices.SeeNotices(ctx, w.tenant, b, []store.SeenNotice{shown}); err != nil || len(left) != 1 {
		t.Fatalf("b acknowledged a's notice: %+v %v", left, err)
	}
	for _, stale := range []store.SeenNotice{{ID: n[0].ID, Pauses: 1}, {ID: n[0].ID}} {
		if left, err := w.devices.SeeNotices(ctx, w.tenant, a, []store.SeenNotice{stale}); err != nil || len(left) != 1 || left[0].Pauses != 2 {
			t.Fatalf("a's acknowledgement of %+v, the notice at 2 pauses: %+v %v", stale, left, err)
		}
	}
	if left, err := w.devices.SeeNotices(ctx, w.tenant, a, []store.SeenNotice{shown}); err != nil || len(left) != 0 {
		t.Fatalf("a's acknowledgement: %+v %v", left, err)
	}
	if len(w.notices(t, b)) != 1 {
		t.Fatal("b's notice went with a's")
	}

	// A key is its creator's act: A's key tells B, not A, and the row is A's.
	w.resume(t, device)
	aKey := w.keyBy(t, &a, device)
	p = w.pause(t, device, store.PauseActor{Key: aKey})
	if !p.Changed || p.ActorKind != "key" || p.ActorUser == nil || *p.ActorUser != a {
		t.Fatalf("a's key's pause: %+v", p)
	}
	if mine := w.notices(t, a); len(mine) != 0 {
		t.Fatalf("a key's creator was told of their own key's pause: %+v", mine)
	}
	bn := w.notices(t, b)
	if len(bn) != 1 || bn[0].RaisedByKind != "key" || bn[0].RaisedByName == nil || !strings.HasPrefix(*bn[0].RaisedByName, "ana") ||
		bn[0].Pauses != 3 || !bn[0].SeveralActors || !bn[0].RaisedAt.Equal(first) {
		t.Fatalf("b's notice after a's key: %+v", bn)
	}
	rows = eventsOf(t, w.pool, w.tenant, device, "sync_paused")
	last := rows[len(rows)-1]
	if len(rows) != 3 || last.ActorKind != "key" || last.ActorSub == nil || *last.ActorSub != aSub || last.ActorUserID == nil ||
		*last.ActorUserID != a || !sameSubs(last.ReaderSubs, ownerSub, aSub, bSub) {
		t.Fatalf("the key's row: %+v", rows)
	}
	// An admin's key, the admin reading nothing: every reader is told.
	w.resume(t, device)
	w.pause(t, device, store.PauseActor{Key: w.keyBy(t, &admin, device)})
	for _, u := range []uuid.UUID{w.owner, a, b} {
		if len(w.notices(t, u)) != 1 {
			t.Fatalf("%s was not told of the admin's key", u)
		}
	}
	// A key with no creator: every reader is told, and the row has no actor.
	w.resume(t, device)
	p = w.pause(t, device, store.PauseActor{Key: w.keyBy(t, nil, device)})
	if p.ActorUser != nil || len(p.Notices) != 3 {
		t.Fatalf("a key with no creator: %+v", p)
	}
	rows = eventsOf(t, w.pool, w.tenant, device, "sync_paused")
	if last := rows[len(rows)-1]; last.ActorKind != "key" || last.ActorSub != nil || last.ActorUserID != nil {
		t.Fatalf("the no-creator key's row: %+v", last)
	}
	for _, u := range []uuid.UUID{w.owner, a, b} {
		if n := w.notices(t, u); n[0].RaisedByName != nil || n[0].RaisedByKind != "key" {
			t.Fatalf("%s's notice names someone: %+v", u, n[0])
		}
	}

	// Its only reader's pause, and their key's, tell nobody and record
	// nothing.
	solo := w.number(t, "Solo")
	w.reads(t, a, solo)
	for _, by := range []store.PauseActor{{User: a}, {Key: w.keyBy(t, &a, solo)}} {
		p := w.pause(t, solo, by)
		if !p.Changed || p.Recorded || len(p.Notices) != 0 {
			t.Fatalf("the only reader's pause (%+v): %+v", by, p)
		}
		w.resume(t, solo)
	}
	if rows := eventsOf(t, w.pool, w.tenant, solo, "sync_paused"); len(rows) != 0 {
		t.Fatalf("a pause with nobody to tell was recorded: %+v", rows)
	}

	// Notices drop a pause notice once its viewer loses Read; a deletion
	// notice the same viewer holds for another number stays.
	other := w.number(t, "Outro")
	w.reads(t, b, other)
	w.quarantine(t, other, b)
	if err := w.users.SetDevicePermission(ctx, w.tenant, w.owner, store.DevicePermission{DeviceID: device, UserID: b}); err != nil {
		t.Fatal(err)
	}
	if n := w.notices(t, b); len(n) != 1 || n[0].Kind != store.NoticeNumberDeleted || n[0].DeviceID != other {
		t.Fatalf("b's notices after losing Read: %+v", n)
	}

	// A deletion replaces the pause notices with its own.
	w.quarantine(t, device, a)
	if n := w.notices(t, a); len(n) != 1 || n[0].Kind != store.NoticeNumberDeleted {
		t.Fatalf("a's notices after the deletion: %+v", n)
	}
	if left := w.count(t, `SELECT count(*) FROM device_notices WHERE device_id=$1 AND kind='sync_paused'`, device); left != 0 {
		t.Fatalf("%d pause notices outlived the deletion", left)
	}
}

// A pause that commits after a resume's checks, before it marks the
// notices resumed, leaves them open: the number is paused.
func TestResumeMarksNothingOnAPausedNumber(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	device := w.number(t, "Vendas")
	a := w.person(t, "ana", "member")
	for _, u := range []uuid.UUID{w.owner, a} {
		w.reads(t, u, device)
	}
	w.pause(t, device, store.PauseActor{User: w.owner})
	// device.start's own write, then a stop before it marks the notices.
	if err := w.devices.SetPaused(ctx, w.tenant.String(), device.String(), false); err != nil {
		t.Fatal(err)
	}
	w.pause(t, device, store.PauseActor{User: w.owner})
	if err := w.devices.MarkResumed(ctx, w.tenant, device); err != nil {
		t.Fatal(err)
	}
	if n := w.notices(t, a); len(n) != 1 || n[0].Pauses != 2 || n[0].ResumedAt != nil {
		t.Fatalf("a paused number's notice was marked resumed: %+v", n)
	}
	w.resume(t, device)
	if n := w.notices(t, a); len(n) != 1 || n[0].ResumedAt == nil {
		t.Fatalf("after the resume: %+v", n)
	}
}

// The same person pausing, then their own key: a fold says that more than
// one actor paused, since a key is an actor of its own kind.
func TestPauseFoldTellsAPersonFromTheirKey(t *testing.T) {
	w := newDelWorld(t)
	device := w.number(t, "Dupla")
	// Only owners and admins create keys.
	a, b := w.person(t, "ana", "admin"), w.person(t, "bia", "member")
	for _, u := range []uuid.UUID{a, b} {
		w.reads(t, u, device)
	}
	w.pause(t, device, store.PauseActor{User: a})
	w.resume(t, device)
	w.pause(t, device, store.PauseActor{Key: w.keyBy(t, &a, device)})
	n := w.notices(t, b)
	if len(n) != 1 || n[0].Pauses != 2 || n[0].RaisedByKind != "key" || n[0].RaisedByName == nil ||
		!strings.HasPrefix(*n[0].RaisedByName, "ana") || !n[0].SeveralActors {
		t.Fatalf("b's notice after a's pause and then a's key's: %+v", n)
	}
}

// TestPauseLoopsFold: a stop/start loop leaves each reader one unseen notice,
// and one event row per transition; a second actor folds in and is said.
func TestPauseLoopsFold(t *testing.T) {
	w := newDelWorld(t)
	device := w.number(t, "Loop")
	a := w.person(t, "ana", "member")
	for _, u := range []uuid.UUID{w.owner, a} {
		w.reads(t, u, device)
	}
	const cycles = 1000
	for range cycles {
		w.pause(t, device, store.PauseActor{User: w.owner})
		w.resume(t, device)
	}
	n := w.notices(t, a)
	if len(n) != 1 || n[0].Pauses != cycles || n[0].SeveralActors || n[0].ResumedAt == nil {
		t.Fatalf("after %d cycles: %+v", cycles, n)
	}
	if rows := w.count(t, `SELECT count(*) FROM item_events WHERE item_id=$1 AND type='sync_paused'`, device); rows != cycles {
		t.Fatalf("%d sync_paused rows for %d pauses", rows, cycles)
	}
	second := w.person(t, "bia", "member")
	w.reads(t, second, device)
	w.pause(t, device, store.PauseActor{User: second})
	n = w.notices(t, a)
	if len(n) != 1 || n[0].Pauses != cycles+1 || !n[0].SeveralActors || n[0].RaisedByName == nil || !strings.HasPrefix(*n[0].RaisedByName, "bia") {
		t.Fatalf("a second actor's pause: %+v", n)
	}
	rows := eventsOf(t, w.pool, w.tenant, device, "sync_paused")
	if len(rows) != cycles+1 || rows[len(rows)-1].ActorUserID == nil || *rows[len(rows)-1].ActorUserID != second {
		t.Fatalf("the second actor's row: %d rows, last %+v", len(rows), rows[len(rows)-1])
	}
}

// In a personal workspace a key's act is the owner's own: only a key with
// no creator tells the owner.
func TestPauseInPersonalWorkspace(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	var personal uuid.UUID
	if err := w.pool.QueryRow(ctx, `SELECT id FROM tenants WHERE personal_owner_id=$1`, w.owner).Scan(&personal); err != nil {
		t.Fatal(err)
	}
	ownerSub := linkSub(t, w.pool, w.owner)
	p := &delWorld{pool: w.pool, tenant: personal, devices: w.devices, users: w.users, keys: w.keys, apiKeys: w.apiKeys, owner: w.owner, pns: 50}
	device := p.number(t, "Meu")
	p.reads(t, w.owner, device)
	for _, by := range []store.PauseActor{{User: w.owner}, {Key: p.keyBy(t, &w.owner, device)}} {
		paused := p.pause(t, device, by)
		if !paused.Changed || paused.Recorded || len(paused.Notices) != 0 {
			t.Fatalf("the owner's own pause (%+v): %+v", by, paused)
		}
		p.resume(t, device)
	}
	paused := p.pause(t, device, store.PauseActor{Key: p.keyBy(t, nil, device)})
	if !paused.Recorded || len(paused.Notices) != 1 || paused.Notices[0].UserID != w.owner {
		t.Fatalf("a key with no creator: %+v", paused)
	}
	rows := eventsOf(t, w.pool, personal, device, "sync_paused")
	if len(rows) != 1 || rows[0].ActorKind != "key" || rows[0].ActorSub != nil || rows[0].ActorUserID != nil || !sameSubs(rows[0].ReaderSubs, ownerSub) {
		t.Fatalf("the personal workspace's rows: %+v", rows)
	}
	if n := p.notices(t, w.owner); len(n) != 1 || n[0].RaisedByKind != "key" || n[0].RaisedByName != nil {
		t.Fatalf("the owner's notice: %+v", n)
	}
}

// Pause and the move to Personal take the workspace's row before the
// device's, the order every writer of the event log keeps (Quarantine and
// Recover: TestRecoverAndDeleteLockTheWorkspaceFirst), so seq order is
// commit order.
func TestPauseLocksTheWorkspaceFirst(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	device, moving := w.number(t, "Lock"), w.number(t, "Move")
	w.reads(t, w.owner, moving)
	if err := w.devices.SetPaused(ctx, w.tenant.String(), moving.String(), true); err != nil {
		t.Fatal(err)
	}
	var personal uuid.UUID
	if err := w.pool.QueryRow(ctx, `SELECT id FROM tenants WHERE personal_owner_id=$1`, w.owner).Scan(&personal); err != nil {
		t.Fatal(err)
	}
	blocker, err := w.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Rollback(context.Background()) }()
	if _, err := blocker.Exec(ctx, `SELECT 1 FROM tenants WHERE id=$1 FOR UPDATE`, w.tenant); err != nil {
		t.Fatal(err)
	}
	done, moved := make(chan error, 1), make(chan error, 1)
	go func() {
		_, err := w.devices.Pause(ctx, w.tenant, device, store.PauseActor{User: w.owner})
		done <- err
	}()
	go func() {
		_, err := w.devices.TransferPersonal(ctx, w.tenant, w.owner, moving, personal)
		moved <- err
	}()
	waitBlocked(t, w, int(blocker.Conn().PgConn().PID()), 2)
	w.scoped(t, func(tx pgx.Tx) error {
		for _, id := range []uuid.UUID{device, moving} {
			if _, err := tx.Exec(ctx, `SELECT 1 FROM devices WHERE id=$1 FOR UPDATE NOWAIT`, id); err != nil {
				t.Errorf("a device was locked before the workspace: %v", err)
				return err
			}
		}
		return nil
	})
	if err := blocker.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := <-moved; err != nil {
		t.Fatal(err)
	}
}

// The pauses Wappie makes on its own record nothing: the transfer's and its
// undo, and the deletion's. The failed resume's goes through device.start
// (wsapi's TestResumeOverTheSocket).
func TestOwnPausesRecordNothing(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	device := w.number(t, "Own")
	a := w.person(t, "ana", "member")
	w.reads(t, a, device)
	p, err := w.devices.PauseForMove(ctx, w.tenant, device)
	if err != nil || !p.Changed {
		t.Fatalf("the transfer's pause: %+v %v", p, err)
	}
	if undone, err := w.devices.UndoMovePause(ctx, w.tenant, device, p); err != nil || !undone {
		t.Fatalf("its undo: %v %v", undone, err)
	}
	w.quarantine(t, device, a)
	if rows := eventsOf(t, w.pool, w.tenant, device, "sync_paused"); len(rows) != 0 {
		t.Fatalf("Wappie's own pauses were recorded: %+v", rows)
	}
	if n := w.count(t, `SELECT count(*) FROM device_notices WHERE device_id=$1 AND kind='sync_paused'`, device); n != 0 {
		t.Fatalf("%d pause notices from Wappie's own pauses", n)
	}
}

// TestItemEvents is the plan's test 16; its ledger and housekeeping cases
// are TestLedgerTakesTheFourTypes' and TestLedgerExportAtLeastOnce's.
func TestItemEvents(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	device := w.number(t, "Loja 11912345678")
	reader, unlinked := w.person(t, "ana", "member"), w.person(t, "local", "member")
	for _, u := range []uuid.UUID{w.owner, reader, unlinked} {
		w.reads(t, u, device)
	}
	ownerSub, readerSub := linkSub(t, w.pool, w.owner), linkSub(t, w.pool, reader)

	w.pause(t, device, store.PauseActor{User: reader})
	q := w.quarantine(t, device, reader, unlinked)
	w.recover(t, device)

	rows := readEvents(t, w.pool, w.tenant, device)
	if len(rows) != 3 || rows[0].Type != "sync_paused" || rows[1].Type != "deleted" || rows[2].Type != "recovered" {
		t.Fatalf("rows: %+v", rows)
	}
	for _, e := range rows {
		// Subs only, people without one left out, and no phone digits but the
		// hint's: the label masked the number written in it.
		if !sameSubs(e.ReaderSubs, ownerSub, readerSub) || e.Label == nil || *e.Label != "Loja …5678" || e.Hint == nil || *e.Hint != "…5678" {
			t.Fatalf("%s row: %+v", e.Type, e)
		}
		if !strings.HasPrefix(e.DedupeKey, e.Type+":"+device.String()+":") {
			t.Fatalf("%s dedupe key %q", e.Type, e.DedupeKey)
		}
	}
	paused, deleted, recovered := rows[0], rows[1], rows[2]
	if *paused.ActorSub != readerSub || *paused.ActorUserID != reader || !paused.Ledgered {
		t.Fatalf("sync_paused: %+v", paused)
	}
	if deleted.ActorKind != "person" || *deleted.ActorSub != ownerSub || *deleted.ActorUserID != w.owner || deleted.Ledgered ||
		!deleted.DeletedAt.Equal(q.DeletedAt) || !deleted.PurgeAfter.Equal(q.PurgeAfter) || !deleted.OccurredAt.Equal(q.DeletedAt) {
		t.Fatalf("deleted: %+v (deletion %+v)", deleted, q)
	}
	if recovered.ActorKind != "person" || *recovered.ActorSub != ownerSub || recovered.Ledgered || !recovered.DeletedAt.Equal(q.DeletedAt) ||
		recovered.PurgeAfter != nil {
		t.Fatalf("recovered: %+v", recovered)
	}
	// No column but actor_user_id holds a Wappie user id or a key id, and
	// no column holds the phone number or the LID.
	var leaks int
	pn := w.pn(ctx, t, device)
	inTenantTx(ctx, t, w.pool, w.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM item_events e,
			LATERAL (SELECT concat_ws('|', e.event_id, e.type, e.dedupe_key, e.actor_sub, e.reader_subs::text, e.label, e.hint, e.to_tenant_id)) AS c(text)
			WHERE e.item_id = $1 AND (c.text LIKE '%'||$2||'%' OR c.text LIKE '%'||$3||'%' OR c.text LIKE '%'||$4||'%'
			   OR c.text LIKE '%91234%' OR c.text LIKE '%'||$5||'%')`,
			device, w.owner.String(), reader.String(), unlinked.String(), strings.SplitN(pn, "@", 2)[0]).Scan(&leaks)
	})
	if leaks != 0 {
		t.Fatalf("%d rows carry a user id or a phone number outside actor_user_id", leaks)
	}

	// Dedupe: the same event again writes nothing.
	inTenantTx(ctx, t, w.pool, w.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO item_events (event_id, tenant_id, type, item_id, dedupe_key, occurred_at, actor_kind, deleted_at, purge_after)
			VALUES ($1, $2, 'deleted', $3, $4, now(), 'person', now(), now()) ON CONFLICT (tenant_id, dedupe_key) DO NOTHING`,
			uuid.New(), w.tenant, device, deleted.DedupeKey)
		return err
	})
	if n := len(eventsOf(t, w.pool, w.tenant, device, "deleted")); n != 1 {
		t.Fatalf("%d deleted rows after a duplicate", n)
	}

	// The CHECKs.
	for name, insert := range map[string]string{
		"an unknown type":                  `INSERT INTO item_events (event_id, tenant_id, type, item_id, dedupe_key, occurred_at, actor_kind) VALUES ($1,$2,'stranded',$3,$4,now(),'app')`,
		"moved_out with no target":         `INSERT INTO item_events (event_id, tenant_id, type, item_id, dedupe_key, occurred_at, actor_kind) VALUES ($1,$2,'moved_out',$3,$4,now(),'person')`,
		"deleted with no dates":            `INSERT INTO item_events (event_id, tenant_id, type, item_id, dedupe_key, occurred_at, actor_kind) VALUES ($1,$2,'deleted',$3,$4,now(),'person')`,
		"sync_paused not ledgered":         `INSERT INTO item_events (event_id, tenant_id, type, item_id, dedupe_key, occurred_at, actor_kind) VALUES ($1,$2,'sync_paused',$3,$4,now(),'person')`,
		"a target on another type":         `INSERT INTO item_events (event_id, tenant_id, type, item_id, dedupe_key, occurred_at, actor_kind, deleted_at, to_tenant_id) VALUES ($1,$2,'recovered',$3,$4,now(),'person',now(),$2)`,
		"a label that is too long":         `INSERT INTO item_events (event_id, tenant_id, type, item_id, dedupe_key, occurred_at, actor_kind, deleted_at, label) VALUES ($1,$2,'recovered',$3,$4,now(),'person',now(),repeat('a',81))`,
		"a hint that is not four digits":   `INSERT INTO item_events (event_id, tenant_id, type, item_id, dedupe_key, occurred_at, actor_kind, deleted_at, hint) VALUES ($1,$2,'recovered',$3,$4,now(),'person',now(),'…567')`,
		"an actor kind the contract lacks": `INSERT INTO item_events (event_id, tenant_id, type, item_id, dedupe_key, occurred_at, actor_kind, deleted_at) VALUES ($1,$2,'recovered',$3,$4,now(),'service',now())`,
	} {
		err := pg.InTenantTx(ctx, w.pool, w.tenant.String(), func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, insert, uuid.New(), w.tenant, device, uuid.NewString())
			return err
		})
		if sqlState(err) != "23514" {
			t.Errorf("%s: %v, want a CHECK violation", name, err)
		}
	}

	// Another workspace sees none of them, and they go with their workspace.
	other := uuid.MustParse(newTenant(t, w.pool, "other"))
	var seen int
	inTenantTx(ctx, t, w.pool, other, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM item_events`).Scan(&seen)
	})
	if seen != 0 {
		t.Fatalf("another workspace sees %d rows", seen)
	}
	gone := uuid.MustParse(newTenant(t, w.pool, "gone"))
	inTenantTx(ctx, t, w.pool, gone, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO item_events (event_id, tenant_id, type, item_id, dedupe_key, occurred_at, actor_kind, deleted_at)
			VALUES ($1, $2, 'recovered', $3, 'x', now(), 'person', now())`, uuid.New(), gone, uuid.New())
		return err
	})
	if _, err := w.pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, gone); err != nil {
		t.Fatal(err)
	}
	inTenantTx(ctx, t, w.pool, gone, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM item_events`).Scan(&seen)
	})
	if seen != 0 {
		t.Fatalf("%d rows outlived their workspace", seen)
	}
}

// Where people sign in through the platform, an actor with no sub is a
// fault: logged at ERROR, and the row keeps its actor kind with no sub.
func TestEventActorWithoutSub(t *testing.T) {
	w := newDelWorld(t)
	device := w.number(t, "Sem sub")
	reader := w.person(t, "ana", "member")
	w.reads(t, w.owner, device)
	w.reads(t, reader, device)
	readerSub := linkSub(t, w.pool, reader)
	var logged bytes.Buffer
	ctx := obs.WithLogger(context.Background(), slog.New(slog.NewTextHandler(&logged, nil)))
	if _, err := w.devices.Quarantine(ctx, w.tenant, w.owner, device, []uuid.UUID{reader}); err != nil {
		t.Fatal(err)
	}
	rows := eventsOf(t, w.pool, w.tenant, device, "deleted")
	if len(rows) != 1 || rows[0].ActorKind != "person" || rows[0].ActorSub != nil || rows[0].ActorUserID == nil ||
		!sameSubs(rows[0].ReaderSubs, readerSub) {
		t.Fatalf("the row of an actor with no sub: %+v", rows)
	}
	if !strings.Contains(logged.String(), "level=ERROR") || !strings.Contains(logged.String(), "no platform sub") {
		t.Fatalf("no ERROR for an actor with no sub: %q", logged.String())
	}

	// A self-hosted install links nobody, and says nothing.
	self := newDelWorld(t)
	selfDevice := self.number(t, "Local")
	logged.Reset()
	if _, err := self.devices.Quarantine(ctx, self.tenant, self.owner, selfDevice, nil); err != nil {
		t.Fatal(err)
	}
	if logged.Len() != 0 {
		t.Fatalf("a self-hosted deletion logged: %q", logged.String())
	}
}

// The one INSERT into item_events is recordEvent's.
func TestOneEventWriter(t *testing.T) {
	insert := regexp.MustCompile(`(?i)insert\s+into\s+item_events`)
	found := 0
	for _, root := range []string{"../../cmd", "../../internal"} {
		files, err := goFiles(root)
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range files {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			n := len(insert.FindAllIndex(b, -1))
			found += n
			if n != 0 && filepath.ToSlash(path) != "../../internal/store/item_events.go" {
				t.Errorf("%s writes item_events outside recordEvent", path)
			}
		}
	}
	if found != 1 {
		t.Fatalf("%d inserts into item_events, want recordEvent's one", found)
	}
}

// TestHintNeverFromLID's store half (the plan's test 42): a number with only
// a LID keeps no hint in its event or its notices, and its pn's ":NN" never
// counts.
func TestEventHintNeverFromLID(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	lidOnly := linkedNumber(t, w.pool, w.tenant, "Só LID", "", "300000000000001")
	reader := w.person(t, "ana", "member")
	w.keysFor(t, lidOnly)
	w.reads(t, reader, lidOnly)
	w.quarantine(t, lidOnly, reader)
	rows := eventsOf(t, w.pool, w.tenant, lidOnly, "deleted")
	if len(rows) != 1 || rows[0].Hint != nil {
		t.Fatalf("a LID-only number's row: %+v", rows)
	}
	if n := w.notices(t, reader); len(n) != 1 || n[0].Hint != nil || n[0].Label == nil || *n[0].Label != "Só LID" {
		t.Fatalf("a LID-only number's notice: %+v", n)
	}
	companion := w.number(t, "Comp")
	inTenantTx(ctx, t, w.pool, w.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE devices SET pn = '5511998764321:23@s.whatsapp.net' WHERE id=$1`, companion)
		return err
	})
	w.quarantine(t, companion)
	if rows := eventsOf(t, w.pool, w.tenant, companion, "deleted"); len(rows) != 1 || rows[0].Hint == nil || *rows[0].Hint != "…4321" {
		t.Fatalf("a companion JID's hint: %+v", rows)
	}
}

// keysFor gives a number made with linkedNumber its archive key, as
// pairing does.
func (w *delWorld) keysFor(t *testing.T, device uuid.UUID) {
	t.Helper()
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := w.keys.CreateArchiveKey(context.Background(), w.tenant, device, 1, pub); err != nil {
		t.Fatal(err)
	}
}

// TestOwnersToldOfDeletion is the plan's test 66, store half: the
// workspace's other owners are told of a deletion in Wappie whether or not
// they read the number, once each; a personal workspace's deletion tells
// nobody; a recovery takes the notices back.
func TestOwnersToldOfDeletion(t *testing.T) {
	w := newDelWorld(t)
	device := w.number(t, "Caixa")
	b, reading := w.person(t, "bia", "owner"), w.person(t, "rui", "owner")
	w.reads(t, w.owner, device)
	w.reads(t, reading, device)
	q := w.quarantine(t, device, reading)
	for _, u := range []uuid.UUID{b, reading} {
		n := w.notices(t, u)
		if len(n) != 1 || n[0].Kind != store.NoticeNumberDeleted || n[0].RaisedByName == nil || !strings.HasPrefix(*n[0].RaisedByName, "owner") ||
			n[0].Label == nil || *n[0].Label != "Caixa" || n[0].Hint == nil || n[0].Until == nil || !n[0].Until.Equal(q.PurgeAfter) {
			t.Fatalf("%s's notice: %+v", u, n)
		}
	}
	if len(w.notices(t, w.owner)) != 0 {
		t.Fatal("the owner who deleted was told")
	}
	w.recover(t, device)
	if len(w.notices(t, b)) != 0 {
		t.Fatal("a recovery left the owners' notice")
	}

	ctx := context.Background()
	var personal uuid.UUID
	if err := w.pool.QueryRow(ctx, `SELECT id FROM tenants WHERE personal_owner_id=$1`, w.owner).Scan(&personal); err != nil {
		t.Fatal(err)
	}
	p := &delWorld{pool: w.pool, tenant: personal, devices: w.devices, users: w.users, keys: w.keys, apiKeys: w.apiKeys, owner: w.owner, pns: 70}
	mine := p.number(t, "Meu")
	p.reads(t, w.owner, mine)
	p.quarantine(t, mine)
	if n := p.count(t, `SELECT count(*) FROM device_notices WHERE device_id=$1`, mine); n != 0 {
		t.Fatalf("a personal workspace's deletion left %d notices", n)
	}
}
