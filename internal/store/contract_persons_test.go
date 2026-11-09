package store_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/store"
)

// The person's document (0052's contract_persons; the plan's 2.7 and
// 6.6): its seq on the person's clock, its notices (the platform
// workspaces' only, the ones Wappie's own page lists), and its sender's
// state.

// follow stores an active document for sub, as the round leaves one.
func follow(t *testing.T, w *delWorld, sub uuid.UUID, status string) {
	t.Helper()
	if _, err := w.pool.Exec(context.Background(), `INSERT INTO contract_accounts (sub, generation, version, status, doc)
		VALUES ($1, uuidv7(), 1, $2, '{"v":1}') ON CONFLICT (sub) DO UPDATE SET status = excluded.status, doc = excluded.doc`, sub, status); err != nil {
		t.Fatal(err)
	}
}

// notice writes one notice for user, as its writers leave one.
func (w *delWorld) notice(t *testing.T, tenant, device, user uuid.UUID, kind string, by *uuid.UUID, extra string) int64 {
	t.Helper()
	ctx := context.Background()
	var id int64
	inTenantTx(ctx, t, w.pool, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `INSERT INTO device_notices (tenant_id, device_id, user_id, kind, label, hint, raised_by, raised_by_kind, until)
			VALUES ($1, $2, $3, $4, 'Vendas', '…5678', $5, 'person', CASE WHEN $4 = 'number_deleted' THEN clock_timestamp() + interval '30 days' END)
			RETURNING id`, tenant, device, user, kind, by).Scan(&id)
	})
	if extra != "" {
		inTenantTx(ctx, t, w.pool, tenant, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE device_notices SET `+extra+` WHERE id = $1`, id)
			return err
		})
	}
	return id
}

func TestPersonOf(t *testing.T) {
	ctx := context.Background()
	w := newDelWorld(t)
	c := store.NewContract(w.pool)
	w.recordLocal(t, c)
	sub := linkSub(t, w.pool, w.owner)
	follow(t, w, sub, "active")
	actor := w.person(t, "actor", "admin")
	actorSub := linkSub(t, w.pool, actor)
	unlinked := w.person(t, "unlinked", "admin")
	var personal uuid.UUID
	if err := w.pool.QueryRow(ctx, `SELECT id FROM tenants WHERE personal_owner_id = $1`, w.owner).Scan(&personal); err != nil {
		t.Fatal(err)
	}

	read, unread, deleted := w.number(t, "read"), w.number(t, "unread"), w.number(t, "deleted")
	w.reads(t, w.owner, read)
	w.reads(t, w.owner, deleted)
	paused := w.notice(t, w.tenant, read, w.owner, store.NoticeSyncPaused, &actor, "pauses = 2, last_raised_at = clock_timestamp(), several_actors = true")
	hidden := w.notice(t, w.tenant, unread, w.owner, store.NoticeSyncPaused, &actor, "")
	byUnlinked := w.notice(t, w.tenant, read, w.owner, store.NoticeNumberStranded, &unlinked, "")
	w.notice(t, w.tenant, read, w.owner, store.NoticeNumberMovedOut, &actor, "seen_at = clock_timestamp()")
	w.quarantine(t, deleted)
	gone := w.notice(t, w.tenant, deleted, w.owner, store.NoticeNumberDeleted, &actor, "")
	movedOut := w.notice(t, w.tenant, uuid.New(), w.owner, store.NoticeNumberMovedOut, nil, "")
	// The personal workspace is not recorded: Wappie's own page only.
	personalDevice := uuid.New()
	w.notice(t, personal, personalDevice, w.owner, store.NoticeNumberMovedOut, nil, "")

	p, ok, err := c.PersonOf(ctx, sub)
	if err != nil || !ok {
		t.Fatalf("the person: %v %v", ok, err)
	}
	if p.User == nil || *p.User != w.owner || p.Seq == 0 || p.MeasuredAt.IsZero() || p.LabelCutoverAt.IsZero() || p.SignedOutEverywhereAt != nil {
		t.Fatalf("the person: %+v", p)
	}
	var got []int64
	byID := map[int64]store.ContractNotice{}
	for i, n := range p.Notices {
		got = append(got, n.ID)
		byID[n.ID] = n
		if i > 0 && p.Notices[i-1].At().Before(n.At()) {
			t.Fatalf("the notices are not newest first: %+v", p.Notices)
		}
	}
	// Parity: the ids Wappie's own page lists for the workspace.
	own, err := w.devices.Notices(ctx, w.tenant, w.owner)
	if err != nil {
		t.Fatal(err)
	}
	var want []int64
	for _, n := range own {
		want = append(want, n.ID)
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) || slices.Contains(got, hidden) || len(got) != 4 {
		t.Fatalf("the person's notices %v, Wappie's own page %v (hidden %d)", got, want, hidden)
	}
	if n := byID[paused]; n.ActorSub == nil || *n.ActorSub != actorSub || n.ActorKind != "person" || n.Pauses != 2 || !n.SeveralActors ||
		n.Workspace != w.tenant || n.Device != read || n.DeviceLabel == nil || *n.DeviceLabel != "read" || n.Label == nil || n.Hint == nil {
		t.Fatalf("a pause notice: %+v", n)
	}
	if n := byID[byUnlinked]; n.ActorSub != nil {
		t.Fatalf("an actor with no sub: %+v", n)
	}
	if n := byID[gone]; n.DeviceLabel == nil || *n.DeviceLabel != "deleted" || n.DevicePN == nil || n.Until == nil {
		t.Fatalf("a deleted number's notice finds its number: %+v", n)
	}
	if n := byID[movedOut]; n.DeviceLabel != nil || n.DevicePN != nil {
		t.Fatalf("a number gone from the workspace: %+v", n)
	}

	// The person's clock: each read and act above the last; an act's seq
	// leaves the outcome of a document in flight recorded.
	p2, _, _ := c.PersonOf(ctx, sub)
	if p2.Seq <= p.Seq {
		t.Fatalf("the next read's seq %d after %d", p2.Seq, p.Seq)
	}
	if _, err := w.pool.Exec(ctx, `UPDATE contract_persons SET seq = seq + 100000 WHERE sub = $1`, sub); err != nil {
		t.Fatal(err)
	}
	rec, err := c.PersonSent(ctx, sub, p2.Seq, p2.MeasuredAt, store.SnapshotAccepted, "", snapshotTimes)
	if err != nil || !rec.Recorded {
		t.Fatalf("the outcome after an act's seq: %+v %v", rec, err)
	}
	if p3, _, _ := c.PersonOf(ctx, sub); p3.Seq <= p2.Seq+100000 {
		t.Fatalf("a read after an act: %d", p3.Seq)
	}
	if rec, err := c.PersonSent(ctx, sub, p2.Seq, p2.MeasuredAt, store.SnapshotAccepted, "", snapshotTimes); err != nil || rec.Recorded {
		t.Fatalf("an outcome another read passed: %+v %v", rec, err)
	}

	// Who gets a document: a followed sub with a document, not closed, its
	// row not parked.
	intent := uuid.New()
	if _, err := w.pool.Exec(ctx, `INSERT INTO contract_accounts (sub) VALUES ($1)`, intent); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := c.PersonOf(ctx, intent); err != nil || ok {
		t.Fatalf("an intent with no document: %v %v", ok, err)
	}
	if _, ok, err := c.PersonOf(ctx, uuid.New()); err != nil || ok {
		t.Fatalf("a sub not followed: %v %v", ok, err)
	}
	follow(t, w, actorSub, "closed")
	if _, ok, err := c.PersonOf(ctx, actorSub); err != nil || ok {
		t.Fatalf("a closed account: %v %v", ok, err)
	}
	if _, err := w.pool.Exec(ctx, `UPDATE contract_persons SET parked_at = clock_timestamp() WHERE sub = $1`, sub); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := c.PersonOf(ctx, sub); err != nil || ok {
		t.Fatalf("a parked person: %v %v", ok, err)
	}
	if d, ok, err := c.NextPerson(ctx); err != nil || ok {
		t.Fatalf("a person due while the only sendable one is parked: %+v %v %v", d, ok, err)
	}
	if err := c.PersonsDue(ctx); err != nil {
		t.Fatal(err)
	}
	if d, ok, err := c.NextPerson(ctx); err != nil || !ok || d.Sub != sub || !d.Due {
		t.Fatalf("after the leader's start: %+v %v %v", d, ok, err)
	}

	// A notice's user, or a workspace's pause notices, make the document due.
	if _, err := w.pool.Exec(ctx, `UPDATE contract_persons SET due_at = clock_timestamp() + interval '1 hour', tries = 0`); err != nil {
		t.Fatal(err)
	}
	if err := c.PersonsDirty(ctx, nil, []uuid.UUID{w.owner}, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if d, _, _ := c.NextPerson(ctx); d.Sub != sub || d.Wait > 2*time.Second {
		t.Fatalf("a dirty person: %+v", d)
	}
	subs, err := c.PersonsOfWorkspace(ctx, w.tenant)
	if err != nil || !slices.Equal(subs, []uuid.UUID{sub}) {
		t.Fatalf("the persons of the workspace: %v %v", subs, err)
	}
}

// A person with no local account (followed, never linked) gets a document
// with no notices.
func TestPersonOfUnlinked(t *testing.T) {
	ctx := context.Background()
	w := newDelWorld(t)
	c := store.NewContract(w.pool)
	sub := uuid.New()
	follow(t, w, sub, "active")
	p, ok, err := c.PersonOf(ctx, sub)
	if err != nil || !ok || p.User != nil || len(p.Notices) != 0 || p.Notices == nil {
		t.Fatalf("an unlinked person: %+v %v %v", p, ok, err)
	}
}
