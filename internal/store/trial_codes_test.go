package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kc "github.com/thehappieco/kit/contract"
	kitvectors "github.com/thehappieco/kit/vectors"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// Slice 19's store (0054): item.linked on a link and a move in, placed_at
// at a link, a recovery and a move in and never at a relink,
// item.identity_updated on an identity learned, a document's trial or
// codes_after and a recovery in a workspace on trial, the catch-up's
// predicate, and the rows settled not_sent.

// codesWorld is a team (delWorld) whose workspace a document names, under
// generation gen.
type codesWorld struct {
	*delWorld
	c   *store.Contract
	gen uuid.UUID
}

func newCodesWorld(t *testing.T) codesWorld {
	t.Helper()
	w := codesWorld{delWorld: newDelWorld(t), gen: uuid.New()}
	w.c = store.NewContract(w.pool)
	ctx := context.Background()
	if _, err := w.c.SetMode(ctx, store.ContractObserve); err != nil {
		t.Fatal(err)
	}
	if _, err := w.pool.Exec(ctx, `UPDATE contract_state SET generation = $1`, w.gen); err != nil {
		t.Fatal(err)
	}
	if _, err := w.pool.Exec(ctx, `INSERT INTO contract_workspaces (workspace_id, kind) VALUES ($1, 'team')`, w.tenant); err != nil {
		t.Fatal(err)
	}
	return w
}

// pending is a number whose pairing has not completed: no identity.
func (w codesWorld) pending(t *testing.T) uuid.UUID {
	t.Helper()
	d, err := w.devices.Create(context.Background(), w.tenant.String(), "Novo", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	return uuid.MustParse(d.ID)
}

// identity is a number's synthetic identity, n its index.
func identity(n int) wa.Identity {
	return wa.Identity{PN: types.JID{User: fmt.Sprintf("1555010%04d", n), Server: types.DefaultUserServer},
		LID: types.JID{User: fmt.Sprintf("10000000000%04d", n), Server: types.HiddenUserServer}}
}

// linked is a new number linked by the owner: RecordLinked as the pairing
// hook calls it.
func (w codesWorld) linked(t *testing.T, n int) uuid.UUID {
	t.Helper()
	device := w.pending(t)
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := w.keys.CreateArchiveKey(context.Background(), w.tenant, device, 1, pub); err != nil {
		t.Fatal(err)
	}
	if _, err := w.c.RecordLinked(context.Background(), w.tenant, device, &w.owner, identity(n)); err != nil {
		t.Fatal(err)
	}
	return device
}

func (w codesWorld) placedAt(t *testing.T, device uuid.UUID) *time.Time {
	t.Helper()
	var at *time.Time
	w.scoped(t, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT placed_at FROM devices WHERE id = $1`, device).Scan(&at)
	})
	return at
}

// apply commits d as the next page's one document.
func (w codesWorld) apply(t *testing.T, d kc.EntitlementsDoc) store.EntItemResult {
	t.Helper()
	ctx := context.Background()
	st, err := w.c.EntState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	doc := entDoc(t, d, false)
	res, err := w.c.CommitEntPage(ctx, store.EntPage{SeenGeneration: w.gen, After: st.FeedCursor, NextAfter: d.Version, More: true,
		Items: []store.EntPageItem{{Seq: d.Version, Doc: &doc}}})
	if err != nil || !res.Committed || len(res.Items) != 1 {
		t.Fatalf("the page: %+v %v", res, err)
	}
	return res.Items[0]
}

// trialDoc is a document of the world's workspace at version v, its trial
// ending at trial (nil: none), asking codes after codesAfter, listing items.
func (w codesWorld) trialDoc(v int64, trial, codesAfter *time.Time, items ...uuid.UUID) kc.EntitlementsDoc {
	d := entKitDoc(w.tenant, w.gen, v, kc.ModeObserve)
	if trial != nil {
		at := kc.T(*trial)
		d.State.TrialEndsAt = &at
	}
	if codesAfter != nil {
		at := kc.T(*codesAfter)
		d.Requests.CodesAfter = &at
	}
	for _, id := range items {
		d.Items = append(d.Items, kc.ItemTrial{ID: id.String(), Trial: kc.TrialRunning, TrialEndsAt: kc.T(time.Now().Add(time.Hour))})
	}
	return d
}

func count(rows []eventRow) int { return len(rows) }

func TestRecordLinkedAndPlacedAt(t *testing.T) {
	w := newCodesWorld(t)
	ctx := context.Background()
	sub := linkSub(t, w.pool, w.owner)
	device := w.pending(t)
	placed, err := w.c.RecordLinked(ctx, w.tenant, device, &w.owner, identity(1))
	if err != nil {
		t.Fatal(err)
	}
	if at := w.placedAt(t, device); at == nil || !at.Equal(placed) {
		t.Fatalf("placed_at %v, RecordLinked said %v", at, placed)
	}
	rows := eventsOf(t, w.pool, w.tenant, device, "linked")
	if len(rows) != 1 || rows[0].ActorKind != "person" || rows[0].ActorSub == nil || *rows[0].ActorSub != sub ||
		!rows[0].OccurredAt.Equal(placed) || !rows[0].Ledgered || len(rows[0].ReaderSubs) != 0 || rows[0].Hint == nil {
		t.Fatalf("item.linked: %+v", rows)
	}
	// The identity came with the link: PairSuccess's later write learns
	// nothing, and records nothing.
	if err := w.devices.SetIdentity(ctx, w.tenant.String(), device.String(), identity(1)); err != nil {
		t.Fatal(err)
	}
	if n := count(eventsOf(t, w.pool, w.tenant, device, "identity_updated")); n != 0 {
		t.Fatalf("%d item.identity_updated after a write that learned nothing", n)
	}
	// No phone digits in any column of the row but the hint's.
	if n := w.count(t, `SELECT count(*) FROM item_events WHERE item_id = $1 AND (coalesce(label, '') LIKE '%15550100%'
		OR dedupe_key LIKE '%15550100%')`, device); n != 0 {
		t.Fatalf("%d rows carry the phone number", n)
	}
}

// TestKeyPairingLinkedActorNull: a full key's pairing links with nobody
// behind it: item.linked as person with actor null, which the sender does
// not count as a fault.
func TestKeyPairingLinkedActorNull(t *testing.T) {
	w := newCodesWorld(t)
	device := w.pending(t)
	if _, err := w.c.RecordLinked(context.Background(), w.tenant, device, nil, identity(2)); err != nil {
		t.Fatal(err)
	}
	rows := eventsOf(t, w.pool, w.tenant, device, "linked")
	if len(rows) != 1 || rows[0].ActorKind != "person" || rows[0].ActorSub != nil || rows[0].ActorUserID != nil {
		t.Fatalf("item.linked of a key's pairing: %+v", rows)
	}
	e := store.ContractEvent{Type: "linked", ActorKind: "person"}
	if e.ActorUnknown() {
		t.Fatal("a key's link counts as an actor without a sub")
	}
	if (store.ContractEvent{Type: "deleted", ActorKind: "person"}).ActorUnknown() == false {
		t.Fatal("a person's deletion without a sub no longer counts as a fault")
	}
}

// TestIdentityUpdatedOnLIDLearned / OnPNLearned: SetIdentity with one
// half first and the other later, on a linked number: one
// item.identity_updated for the half learned after the link; none on a
// number never linked (a pairing's own PairSuccess).
func TestIdentityUpdatedOnLIDLearned(t *testing.T) {
	testIdentityLearned(t, true)
}

func TestIdentityUpdatedOnPNLearned(t *testing.T) {
	testIdentityLearned(t, false)
}

func testIdentityLearned(t *testing.T, pnFirst bool) {
	w := newCodesWorld(t)
	ctx := context.Background()
	full := identity(3)
	first, later := wa.Identity{PN: full.PN}, wa.Identity{LID: full.LID}
	if !pnFirst {
		first, later = later, first
	}
	device := w.pending(t)
	if _, err := w.c.RecordLinked(ctx, w.tenant, device, &w.owner, first); err != nil {
		t.Fatal(err)
	}
	if err := w.devices.SetIdentity(ctx, w.tenant.String(), device.String(), first); err != nil {
		t.Fatal(err)
	}
	if n := count(eventsOf(t, w.pool, w.tenant, device, "identity_updated")); n != 0 {
		t.Fatalf("%d item.identity_updated before a half was learned", n)
	}
	if err := w.devices.SetIdentity(ctx, w.tenant.String(), device.String(), later); err != nil {
		t.Fatal(err)
	}
	rows := eventsOf(t, w.pool, w.tenant, device, "identity_updated")
	if len(rows) != 1 || rows[0].ActorKind != "app" || !rows[0].Ledgered {
		t.Fatalf("item.identity_updated: %+v", rows)
	}
	// Learned again: nothing new.
	if err := w.devices.SetIdentity(ctx, w.tenant.String(), device.String(), full); err != nil {
		t.Fatal(err)
	}
	if n := count(eventsOf(t, w.pool, w.tenant, device, "identity_updated")); n != 1 {
		t.Fatalf("%d item.identity_updated after a write that learned nothing", n)
	}
	// A pairing's own identity, on a number not linked yet: none.
	other := identity(30)
	first, later = wa.Identity{PN: other.PN}, wa.Identity{LID: other.LID}
	if !pnFirst {
		first, later = later, first
	}
	fresh := w.pending(t)
	if err := w.devices.SetIdentity(ctx, w.tenant.String(), fresh.String(), first); err != nil {
		t.Fatal(err)
	}
	if err := w.devices.SetIdentity(ctx, w.tenant.String(), fresh.String(), later); err != nil {
		t.Fatal(err)
	}
	if rows := readEvents(t, w.pool, w.tenant, fresh); len(rows) != 0 {
		t.Fatalf("a number not linked yet: %+v", rows)
	}
}

// TestSetIdentityCommitsWhenEventFails: an item.identity_updated whose
// insert fails is rolled back to its savepoint; the identity's write
// commits, the ERROR is recorded, and the catch-up then owes the number.
func TestSetIdentityCommitsWhenEventFails(t *testing.T) {
	w := newCodesWorld(t)
	ctx := context.Background()
	device := w.pending(t)
	if _, err := w.c.RecordLinked(ctx, w.tenant, device, &w.owner, wa.Identity{PN: identity(4).PN}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.pool.Exec(ctx, `CREATE FUNCTION test_refuse_identity() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.type = 'identity_updated' THEN RAISE EXCEPTION 'refused by the test'; END IF; RETURN NEW; END $$;
		CREATE TRIGGER test_refuse_identity BEFORE INSERT ON item_events FOR EACH ROW EXECUTE FUNCTION test_refuse_identity()`); err != nil {
		t.Fatal(err)
	}
	if err := w.devices.SetIdentity(ctx, w.tenant.String(), device.String(), wa.Identity{LID: identity(4).LID}); err != nil {
		t.Fatalf("the identity's write failed with its event: %v", err)
	}
	d, err := w.devices.Get(ctx, w.tenant.String(), device.String())
	if err != nil || d.Identity.LID.IsEmpty() {
		t.Fatalf("the LID was not kept: %+v %v", d.Identity, err)
	}
	st, err := w.c.State(ctx)
	if err != nil || st.ErrorClass != store.ContractErrorEventRecord {
		t.Fatalf("the ERROR recorded: %q %v", st.ErrorClass, err)
	}
	if _, err := w.pool.Exec(ctx, `DROP TRIGGER test_refuse_identity ON item_events`); err != nil {
		t.Fatal(err)
	}
	// The number's item.linked was delivered with no code (no key then):
	// the catch-up owes it one now.
	w.settle(t, device, "not_sent")
	items, err := w.c.CodesCatchUp(ctx, time.Now().Add(-time.Hour))
	if err != nil || len(items) != 1 || items[0].Device != device || items[0].LID == "" {
		t.Fatalf("the catch-up: %+v %v", items, err)
	}
}

// settle settles every row of device's as outcome.
func (w codesWorld) settle(t *testing.T, device uuid.UUID, outcome string) {
	t.Helper()
	inTenantTx(context.Background(), t, w.pool, w.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `UPDATE item_events SET settled_at = clock_timestamp(), outcome = $2
			WHERE item_id = $1 AND settled_at IS NULL`, device, outcome)
		return err
	})
}

// TestCodesCatchUp: numbers linked with no key (their rows settled
// not_sent) and one linked before slice 19 (no row) are owed; one with a
// row still owed is not; a number delivered is owed again only under a key
// made after its row, and RecordCatchUp records each once.
func TestCodesCatchUp(t *testing.T) {
	w := newCodesWorld(t)
	ctx := context.Background()
	noKey, owed, delivered := w.linked(t, 5), w.linked(t, 6), w.linked(t, 7)
	w.settle(t, noKey, "not_sent")
	w.settle(t, delivered, "accepted")
	before := w.number(t, "Antes") // linked before slice 19: no row
	_ = w.pending(t)               // never linked: no identity
	keyMade := time.Now().Add(-time.Hour)
	items, err := w.c.CodesCatchUp(ctx, keyMade)
	if err != nil {
		t.Fatal(err)
	}
	var got []uuid.UUID
	for _, it := range items {
		got = append(got, it.Device)
	}
	want := []uuid.UUID{noKey, before}
	slices.SortFunc(want, func(a, b uuid.UUID) int { return compareUUIDs(a, b) })
	if !slices.Equal(got, want) {
		t.Fatalf("owed %v, want %v (owed %s, delivered %s)", got, want, owed, delivered)
	}
	for _, d := range want {
		if ok, err := w.c.RecordCatchUp(ctx, w.tenant, d, keyMade); err != nil || !ok {
			t.Fatalf("the catch-up of %s: %v %v", d, ok, err)
		}
		if ok, err := w.c.RecordCatchUp(ctx, w.tenant, d, keyMade); err != nil || ok {
			t.Fatalf("the catch-up of %s again: %v %v", d, ok, err)
		}
	}
	if items, err := w.c.CodesCatchUp(ctx, keyMade); err != nil || len(items) != 0 {
		t.Fatalf("a second pass: %+v %v", items, err)
	}
	// A key made after the delivery: the delivered number's codes again.
	if items, err := w.c.CodesCatchUp(ctx, time.Now().Add(time.Minute)); err != nil || len(items) != 1 || items[0].Device != delivered {
		t.Fatalf("under a new key: %+v %v", items, err)
	}
}

// dbNow is the database's clock: the catch-up compares the key's time
// with settled_at, which the database's clock writes.
func (w codesWorld) dbNow(t *testing.T) time.Time {
	t.Helper()
	var at time.Time
	if err := w.pool.QueryRow(context.Background(), `SELECT clock_timestamp()`).Scan(&at); err != nil {
		t.Fatal(err)
	}
	return at
}

// park parks device's open rows with code.
func (w codesWorld) park(t *testing.T, device uuid.UUID, code string) {
	t.Helper()
	inTenantTx(context.Background(), t, w.pool, w.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `UPDATE item_events SET parked_at = clock_timestamp(), reject_code = $2
			WHERE item_id = $1 AND settled_at IS NULL`, device, code)
		return err
	})
}

// TestCodesCatchUpRowsNeverOwed: a number whose newest row is never sent
// is owed the catch-up: one written before the workspace's naming, one in
// an off period (contract mode off), one parked expired. One delivered
// after the key was made (written before it) is not, nor one still owed,
// one parked not_found and still released by a release, or one parked for
// another refusal. While events are paused, nothing is owed: a row written
// then would never go.
func TestCodesCatchUpRowsNeverOwed(t *testing.T) {
	w := newCodesWorld(t)
	ctx := context.Background()
	beforeNaming := w.linked(t, 30)
	if _, err := w.pool.Exec(ctx, `UPDATE contract_workspaces SET named_at = clock_timestamp() WHERE workspace_id = $1`, w.tenant); err != nil {
		t.Fatal(err)
	}
	deliveredLate := w.linked(t, 31)
	keyMade := w.dbNow(t)
	w.settle(t, deliveredLate, "accepted")
	if _, err := w.c.SetMode(ctx, store.ContractOff); err != nil {
		t.Fatal(err)
	}
	offPeriod := w.linked(t, 32)
	if _, err := w.c.SetMode(ctx, store.ContractObserve); err != nil {
		t.Fatal(err)
	}
	owed := w.linked(t, 33)
	expired := w.linked(t, 34)
	w.park(t, expired, store.EventParkedExpired)
	notFound := w.linked(t, 35)
	w.park(t, notFound, store.EventParkedNotFound)
	invalid := w.linked(t, 36)
	w.park(t, invalid, store.EventParkedLocalInvalid)

	items, err := w.c.CodesCatchUp(ctx, keyMade)
	if err != nil {
		t.Fatal(err)
	}
	var got []uuid.UUID
	for _, it := range items {
		got = append(got, it.Device)
	}
	want := []uuid.UUID{beforeNaming, offPeriod, expired}
	slices.SortFunc(want, compareUUIDs)
	if !slices.Equal(got, want) {
		t.Fatalf("owed %v, want %v (delivered late %s, owed %s, not_found %s, invalid %s)",
			got, want, deliveredLate, owed, notFound, invalid)
	}
	// Each once: the catch-up's own row is owed, so a second pass has none.
	for _, d := range want {
		if ok, err := w.c.RecordCatchUp(ctx, w.tenant, d, keyMade); err != nil || !ok {
			t.Fatalf("the catch-up of %s: %v %v", d, ok, err)
		}
	}
	if items, err := w.c.CodesCatchUp(ctx, keyMade); err != nil || len(items) != 0 {
		t.Fatalf("a second pass: %+v %v", items, err)
	}
	// Paused: nothing owed, and nothing recorded.
	if _, err := w.c.SetMode(ctx, store.ContractOff); err != nil {
		t.Fatal(err)
	}
	w.settle(t, owed, "not_sent")
	if items, err := w.c.CodesCatchUp(ctx, keyMade); err != nil || len(items) != 0 {
		t.Fatalf("while paused: %+v %v", items, err)
	}
	if ok, err := w.c.RecordCatchUp(ctx, w.tenant, owed, keyMade); err != nil || ok {
		t.Fatalf("a catch-up while paused: %v %v", ok, err)
	}
}

// TestRecordLinkedRetryWritesOnce: a retry of a link already recorded (its
// commit's answer lost) writes no second item.linked and keeps placed_at.
func TestRecordLinkedRetryWritesOnce(t *testing.T) {
	w := newCodesWorld(t)
	ctx := context.Background()
	device := w.pending(t)
	first, err := w.c.RecordLinked(ctx, w.tenant, device, &w.owner, identity(37))
	if err != nil {
		t.Fatal(err)
	}
	again, err := w.c.RecordLinked(ctx, w.tenant, device, &w.owner, identity(37))
	if err != nil || !again.Equal(first) {
		t.Fatalf("the retry: %v (first %v) %v", again, first, err)
	}
	if n := count(eventsOf(t, w.pool, w.tenant, device, "linked")); n != 1 {
		t.Fatalf("%d item.linked after a retry", n)
	}
	if at := w.placedAt(t, device); at == nil || !at.Equal(first) {
		t.Fatalf("placed_at %v after a retry, was %v", at, first)
	}
}

// TestRelinkAttachEventFailureRecorded: a relink that learns a half of the
// identity whose item.identity_updated cannot be written still attaches,
// and the failure is recorded for contract status, as SetIdentity's.
func TestRelinkAttachEventFailureRecorded(t *testing.T) {
	ctx := context.Background()
	w := newCodesWorld(t)
	sessionStore(t, w.pool)
	device, id := w.loggedOutNumber(t, "Loja", "155501000538", "100000000000538")
	if _, err := w.c.RecordLinked(ctx, w.tenant, device, &w.owner, id); err != nil {
		t.Fatal(err)
	}
	w.scoped(t, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE devices SET lid = NULL WHERE id = $1`, device)
		return err
	})
	if _, err := w.pool.Exec(ctx, `CREATE FUNCTION test_refuse_relink_identity() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.type = 'identity_updated' THEN RAISE EXCEPTION 'refused by the test'; END IF; RETURN NEW; END $$;
		CREATE TRIGGER test_refuse_relink_identity BEFORE INSERT ON item_events FOR EACH ROW
		EXECUTE FUNCTION test_refuse_relink_identity()`); err != nil {
		t.Fatal(err)
	}
	linked := newLink(id)
	w.putSession(t, linked.PN.String())
	if _, err := w.devices.AttachRelink(ctx, w.tenant, device, w.seen(t, device), linked); err != nil {
		t.Fatalf("the attach failed with its event: %v", err)
	}
	st, err := w.c.State(ctx)
	if err != nil || st.ErrorClass != store.ContractErrorEventRecord {
		t.Fatalf("the ERROR recorded: %q %v", st.ErrorClass, err)
	}
}

// TestHousekeepingKeepsLiveNumbersNewestCodeRow: past 30 days, a live
// number's newest item.linked or item.identity_updated stays (the
// catch-up reads it) and its older one goes; a deleted number's goes too.
func TestHousekeepingKeepsLiveNumbersNewestCodeRow(t *testing.T) {
	w := newCodesWorld(t)
	ctx := context.Background()
	live, gone := w.linked(t, 39), w.linked(t, 40)
	if ok, err := w.c.RecordCatchUp(ctx, w.tenant, live, w.dbNow(t).Add(time.Hour)); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Fatal("a number with an owed row caught up")
	}
	w.settle(t, live, "accepted")
	if ok, err := w.c.RecordCatchUp(ctx, w.tenant, live, w.dbNow(t).Add(time.Hour)); err != nil || !ok {
		t.Fatalf("the catch-up under a newer key: %v %v", ok, err)
	}
	w.settle(t, live, "accepted")
	w.settle(t, gone, "accepted")
	w.scoped(t, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE item_events SET created_at = created_at - interval '31 days'
			WHERE item_id = ANY ($1)`, []uuid.UUID{live, gone}); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE devices SET deleted_at = clock_timestamp(), purge_after = clock_timestamp() + interval '30 days',
			paused = true WHERE id = $1`, gone)
		return err
	})
	if _, err := store.DeletionHousekeeping(ctx, w.pool, w.tenant); err != nil {
		t.Fatal(err)
	}
	if n := count(eventsOf(t, w.pool, w.tenant, live, "linked")); n != 0 {
		t.Fatalf("a live number's older item.linked kept: %d", n)
	}
	if n := count(eventsOf(t, w.pool, w.tenant, live, "identity_updated")); n != 1 {
		t.Fatalf("a live number's newest row: %d", n)
	}
	if n := count(eventsOf(t, w.pool, w.tenant, gone, "linked")); n != 0 {
		t.Fatalf("a deleted number's row kept: %d", n)
	}
}

func compareUUIDs(a, b uuid.UUID) int {
	for i := range a {
		if a[i] != b[i] {
			return int(a[i]) - int(b[i])
		}
	}
	return 0
}

// TestIdentityUpdatedOnTrialDocument: the first document with
// trial_ends_at, a document after one without it, the first after a reset,
// and a codes_after advanced each record one item.identity_updated per
// linked number its items do not list; a document that asks nothing, and
// the same codes_after again, record none.
func TestIdentityUpdatedOnTrialDocument(t *testing.T) {
	w := newCodesWorld(t)
	ctx := context.Background()
	listed, unlisted, pending := w.linked(t, 8), w.linked(t, 9), w.pending(t)
	_ = pending
	trial := time.Now().Add(240 * time.Hour).UTC().Truncate(time.Second)
	updated := func() (int, int) {
		return count(eventsOf(t, w.pool, w.tenant, listed, "identity_updated")),
			count(eventsOf(t, w.pool, w.tenant, unlisted, "identity_updated"))
	}
	step := func(name string, d kc.EntitlementsDoc, wantUnlisted int) {
		t.Helper()
		r := w.apply(t, d)
		if r.Action != store.EntApply {
			t.Fatalf("%s: %s", name, r.Action)
		}
		if l, u := updated(); l != 0 || u != wantUnlisted {
			t.Fatalf("%s: listed %d, unlisted %d, want 0 and %d", name, l, u, wantUnlisted)
		}
	}
	step("the first document, on trial", w.trialDoc(2, &trial, nil, listed), 1)
	step("on trial again", w.trialDoc(3, &trial, nil, listed), 1)
	step("no trial", w.trialDoc(4, nil, nil, listed), 1)
	step("a trial after none", w.trialDoc(5, &trial, nil, listed), 2)
	ca := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	step("codes_after", w.trialDoc(6, &trial, &ca, listed), 3)
	step("the same codes_after", w.trialDoc(7, &trial, &ca, listed), 3)
	ca2 := ca.Add(time.Second)
	step("a later codes_after", w.trialDoc(8, &trial, &ca2, listed), 4)
	// A reset: the first document after it asks again, and forgets the
	// codes_after answered.
	gen := uuid.New()
	if done, err := w.c.RestartFromEntitlements(ctx, w.gen, &gen); err != nil || !done {
		t.Fatalf("the reset: %v %v", done, err)
	}
	w.gen = gen
	r := w.apply(t, w.trialDoc(1, &trial, &ca2, listed))
	if r.Action != store.EntApply {
		t.Fatalf("after the reset: %s", r.Action)
	}
	// One row for both triggers: the trial and the forgotten codes_after.
	if l, u := updated(); l != 0 || u != 5 {
		t.Fatalf("after the reset: listed %d, unlisted %d", l, u)
	}
	if r.Codes != 1 {
		t.Fatalf("the result counts %d", r.Codes)
	}
}

// TestIdentityUpdatedOnLateApply: a document kept for a workspace no
// account document names asks nothing until a naming applies it, which
// then records item.identity_updated by its trial.
func TestIdentityUpdatedOnLateApply(t *testing.T) {
	w := newCodesWorld(t)
	ctx := context.Background()
	if _, err := w.pool.Exec(ctx, `DELETE FROM contract_workspaces`); err != nil {
		t.Fatal(err)
	}
	number := w.linked(t, 10)
	trial := time.Now().Add(240 * time.Hour).UTC().Truncate(time.Second)
	if r := w.apply(t, w.trialDoc(2, &trial, nil)); r.Action != store.EntKeep {
		t.Fatalf("a document of a workspace not named: %s", r.Action)
	}
	if n := count(eventsOf(t, w.pool, w.tenant, number, "identity_updated")); n != 0 {
		t.Fatalf("%d before the naming", n)
	}
	tx, err := w.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }() //nolint:errcheck // committed below
	if err := store.RecordWorkspacesForTest(ctx, tx, map[uuid.UUID]store.ContractDocWorkspace{w.tenant: {Kind: "team", WVersion: 1, Status: "open"}}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if n := count(eventsOf(t, w.pool, w.tenant, number, "identity_updated")); n != 1 {
		t.Fatalf("%d after the late apply, want 1", n)
	}
}

// TestIdentityUpdatedOnRecoveryAllUnlisted (P1's literal reading): a
// recovery into a workspace on trial records one item.identity_updated for
// every linked hosted number its document does not list, the recovered one
// included; a deleted one and a listed one get none; off trial, none.
func TestIdentityUpdatedOnRecoveryAllUnlisted(t *testing.T) {
	w := newCodesWorld(t)
	recovered, other, listed, deleted := w.linked(t, 11), w.linked(t, 12), w.linked(t, 13), w.linked(t, 14)
	for _, d := range []uuid.UUID{recovered, other, listed, deleted} {
		w.reads(t, w.owner, d)
	}
	trial := time.Now().Add(240 * time.Hour).UTC().Truncate(time.Second)
	w.apply(t, w.trialDoc(2, &trial, nil, listed))
	base := map[uuid.UUID]int{}
	for _, d := range []uuid.UUID{recovered, other, listed, deleted} {
		base[d] = count(eventsOf(t, w.pool, w.tenant, d, "identity_updated"))
	}
	w.quarantine(t, deleted)
	w.quarantine(t, recovered)
	r := w.recover(t, recovered)
	_ = r
	got := map[uuid.UUID]int{}
	for _, d := range []uuid.UUID{recovered, other, listed, deleted} {
		got[d] = count(eventsOf(t, w.pool, w.tenant, d, "identity_updated")) - base[d]
	}
	if got[recovered] != 1 || got[other] != 1 || got[listed] != 0 || got[deleted] != 0 {
		t.Fatalf("after the recovery: %v (recovered %s, other %s, listed %s, deleted %s)", got, recovered, other, listed, deleted)
	}
	rows := eventsOf(t, w.pool, w.tenant, other, "identity_updated")
	if last := rows[len(rows)-1]; last.ActorKind != "person" || last.ActorUserID == nil || *last.ActorUserID != w.owner {
		t.Fatalf("the recovery's row: %+v", last)
	}
}

// TestRecoverySetsPlacedAtNoLinked: a recovery moves placed_at to its time
// and records no item.linked.
func TestRecoverySetsPlacedAtNoLinked(t *testing.T) {
	w := newCodesWorld(t)
	device := w.linked(t, 15)
	w.reads(t, w.owner, device)
	w.quarantine(t, device)
	w.recover(t, device)
	rec := eventsOf(t, w.pool, w.tenant, device, "recovered")
	if at := w.placedAt(t, device); len(rec) != 1 || at == nil || !at.Equal(rec[0].OccurredAt) {
		t.Fatalf("placed_at %v, the recovery at %+v", at, rec)
	}
	if n := count(eventsOf(t, w.pool, w.tenant, device, "linked")); n != 1 {
		t.Fatalf("%d item.linked after a recovery, want the link's 1", n)
	}
}

// TestMoveLinkedInDestinationQueue: a move to Personal records moved_out in
// the source and item.linked in the destination, the mover its actor, with
// placed_at the move's completion.
func TestMoveLinkedInDestinationQueue(t *testing.T) {
	w := newCodesWorld(t)
	ctx := context.Background()
	sub := linkSub(t, w.pool, w.owner)
	device := w.linked(t, 16)
	w.reads(t, w.owner, device)
	if err := w.devices.SetPaused(ctx, w.tenant.String(), device.String(), true); err != nil {
		t.Fatal(err)
	}
	var personal uuid.UUID
	if err := w.pool.QueryRow(ctx, `SELECT id FROM tenants WHERE personal_owner_id=$1`, w.owner).Scan(&personal); err != nil {
		t.Fatal(err)
	}
	if _, err := w.devices.TransferPersonal(ctx, w.tenant, w.owner, device, personal); err != nil {
		t.Fatal(err)
	}
	out := eventsOf(t, w.pool, w.tenant, device, "moved_out")
	in := eventsOf(t, w.pool, personal, device, "linked")
	if len(out) != 1 || len(in) != 1 || in[0].ActorKind != "person" || in[0].ActorSub == nil || *in[0].ActorSub != sub ||
		!in[0].OccurredAt.Equal(out[0].OccurredAt) {
		t.Fatalf("moved_out %+v, linked %+v", out, in)
	}
	var placed *time.Time
	var completed time.Time
	inTenantTx(ctx, t, w.pool, personal, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT d.placed_at, x.completed_at FROM devices d JOIN device_transfers x ON x.device_id = d.id
			WHERE d.id = $1`, device).Scan(&placed, &completed)
	})
	if placed == nil || !placed.Equal(completed) {
		t.Fatalf("placed_at %v, completed %v", placed, completed)
	}
}

// TestRelinkNoLinkedNoPlacedAt: a relink is no link (spec 15.11): it
// records no item.linked and keeps placed_at.
func TestRelinkNoLinkedNoPlacedAt(t *testing.T) {
	ctx := context.Background()
	w := newCodesWorld(t)
	sessionStore(t, w.pool)
	device, id := w.loggedOutNumber(t, "Loja", "155501000501", "100000000000501")
	if _, err := w.c.RecordLinked(ctx, w.tenant, device, &w.owner, id); err != nil {
		t.Fatal(err)
	}
	before := w.placedAt(t, device)
	linked := newLink(id)
	w.putSession(t, linked.PN.String())
	if _, err := w.devices.AttachRelink(ctx, w.tenant, device, w.seen(t, device), linked); err != nil {
		t.Fatal(err)
	}
	if at := w.placedAt(t, device); at == nil || !at.Equal(*before) {
		t.Fatalf("placed_at %v after the relink, was %v", at, before)
	}
	if n := count(eventsOf(t, w.pool, w.tenant, device, "linked")); n != 1 {
		t.Fatalf("%d item.linked after a relink", n)
	}
}

// TestReplayedRecoveryPlacedAt: a replayed recovery places the number at
// the recovery's own time, never earlier than it was.
func TestReplayedRecoveryPlacedAt(t *testing.T) {
	w := newCodesWorld(t)
	ctx := context.Background()
	device := w.linked(t, 17)
	recoveredAt := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)
	w.scoped(t, func(tx pgx.Tx) error {
		return store.ReplayRecoveryPlacedForTest(ctx, tx, device, recoveredAt)
	})
	if at := w.placedAt(t, device); at == nil || !at.Equal(recoveredAt) {
		t.Fatalf("placed_at %v, the recovery at %v", at, recoveredAt)
	}
	w.scoped(t, func(tx pgx.Tx) error {
		return store.ReplayRecoveryPlacedForTest(ctx, tx, device, recoveredAt.Add(-48*time.Hour))
	})
	if at := w.placedAt(t, device); at == nil || !at.Equal(recoveredAt) {
		t.Fatalf("an older replayed recovery moved placed_at back to %v", at)
	}
}

// TestEventsNotSentSettles: rows of the two types named settle not_sent;
// another type is left alone.
func TestEventsNotSentSettles(t *testing.T) {
	w := newCodesWorld(t)
	ctx := context.Background()
	device := w.linked(t, 18)
	var linkedID uuid.UUID
	inTenantTx(ctx, t, w.pool, w.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT event_id FROM item_events WHERE item_id = $1 AND type = 'linked'`, device).Scan(&linkedID)
	})
	w.pause(t, device, store.PauseActor{User: w.owner})
	var paused uuid.UUID
	inTenantTx(ctx, t, w.pool, w.tenant, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT event_id FROM item_events WHERE item_id = $1 AND type = 'sync_paused'`, device).Scan(&paused)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	})
	n, err := w.c.EventsNotSent(ctx, w.tenant, []uuid.UUID{linkedID, paused})
	if err != nil || n != 1 {
		t.Fatalf("settled %d, %v", n, err)
	}
	var outcome string
	inTenantTx(ctx, t, w.pool, w.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT outcome FROM item_events WHERE event_id = $1`, linkedID).Scan(&outcome)
	})
	if outcome != "not_sent" {
		t.Fatalf("outcome %q", outcome)
	}
}

// TestTrialKeyStore: the envelope goes in once; the codes switch; the
// opens recorded; the link checks counted.
func TestTrialKeyStore(t *testing.T) {
	w := newCodesWorld(t)
	ctx := context.Background()
	if st, err := w.c.TrialKeyState(ctx); err != nil || st.Installed || st.Codes != store.TrialCodesOn {
		t.Fatalf("before init: %+v %v", st, err)
	}
	if err := w.c.InitTrialKey(ctx, []byte("envelope")); err != nil {
		t.Fatal(err)
	}
	if err := w.c.InitTrialKey(ctx, []byte("another")); !errors.Is(err, store.ErrTrialKeyExists) {
		t.Fatalf("a second init: %v", err)
	}
	env, _, ok, err := w.c.TrialKeyEnvelope(ctx)
	if err != nil || !ok || string(env) != "envelope" {
		t.Fatalf("the envelope: %q %v %v", env, ok, err)
	}
	if err := w.c.TrialKeyOpened(ctx, env); err != nil {
		t.Fatal(err)
	}
	st, err := w.c.TrialKeyState(ctx)
	if err != nil || !st.Installed || st.OpenedAt == nil || string(st.EnvelopeSHA256) != string(st.StoredSHA256) {
		t.Fatalf("after the open: %+v %v", st, err)
	}
	if changed, err := w.c.SetTrialCodes(ctx, store.TrialCodesSuspended); err != nil || !changed {
		t.Fatalf("suspend: %v %v", changed, err)
	}
	if changed, err := w.c.SetTrialCodes(ctx, store.TrialCodesSuspended); err != nil || changed {
		t.Fatalf("suspend again: %v %v", changed, err)
	}
	if err := w.c.TrialKeyOpenFailed(ctx, "decrypt"); err != nil {
		t.Fatal(err)
	}
	if st, err := w.c.TrialKeyState(ctx); err != nil || st.OpenError != "decrypt" || st.Codes != store.TrialCodesSuspended {
		t.Fatalf("after a failed open: %+v %v", st, err)
	}
	for _, c := range []struct {
		answered bool
		reason   string
	}{{true, ""}, {true, "new_links_off"}, {false, "no_document"}} {
		if err := w.c.RecordLinkCheck(ctx, w.tenant, store.LinkActLink, c.answered, c.reason); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := w.c.LinkChecks(ctx); err != nil || n != (store.LinkCheckCounts{Answered: 2, Failed: 1, WouldRefuse: 2}) {
		t.Fatalf("the link checks: %+v %v", n, err)
	}
}

// TestCodesAfterVectors: wire-entitlements.json's codes_after, through
// CodesAfterDue: send when set and later than the last answered.
func TestCodesAfterVectors(t *testing.T) {
	var v struct {
		CodesAfter []struct {
			Name         string   `json:"name"`
			LastAnswered *kc.Time `json:"last_answered"`
			CodesAfter   *kc.Time `json:"codes_after"`
			Action       string   `json:"action"`
		} `json:"codes_after"`
	}
	b, err := fs.ReadFile(kitvectors.FS, "platform/contract-v1/wire-entitlements.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &v); err != nil || len(v.CodesAfter) != 6 {
		t.Fatalf("the vectors: %d %v", len(v.CodesAfter), err)
	}
	at := func(t *kc.Time) *time.Time {
		if t == nil {
			return nil
		}
		return &t.Time
	}
	for _, c := range v.CodesAfter {
		got := "none"
		if store.CodesAfterDue(at(c.LastAnswered), at(c.CodesAfter)) {
			got = "send"
		}
		if got != c.Action {
			t.Errorf("%s: %s, want %s", c.Name, got, c.Action)
		}
	}
}

// TestPlacedAtVectors: wire-entitlements.json's placed_at, Wappie's cases
// through the store's own paths: a link (RecordLinked), a recovery and a
// move in set placed_at to the event's time; a relink keeps it. Wappie has
// no number import (the E0 design's section 0), so the import and its
// first pairing are not applicable; Mailie's are Mailie's.
func TestPlacedAtVectors(t *testing.T) {
	var v struct {
		PlacedAt []struct {
			Name   string `json:"name"`
			App    string `json:"app"`
			Event  string `json:"event"`
			Action string `json:"action"`
		} `json:"placed_at"`
	}
	b, err := fs.ReadFile(kitvectors.FS, "platform/contract-v1/wire-entitlements.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &v); err != nil || len(v.PlacedAt) != 9 {
		t.Fatalf("the vectors: %d %v", len(v.PlacedAt), err)
	}
	w := newCodesWorld(t)
	sessionStore(t, w.pool)
	for _, c := range v.PlacedAt {
		if c.App != "wappie" || !slices.Contains([]string{"link", "recovery", "move_in", "relink"}, c.Event) {
			t.Logf("%s: not Wappie's in E0 (%s, %s)", c.Name, c.App, c.Event)
			continue
		}
		before, after, at := placedAtEvent(t, w, c.Event)
		switch c.Action {
		case "set":
			if after == nil || !after.Equal(at) {
				t.Errorf("%s: placed_at %v, want the event's %v", c.Name, after, at)
			}
		case "keep":
			if before == nil || after == nil || !after.Equal(*before) {
				t.Errorf("%s: placed_at %v, was %v", c.Name, after, before)
			}
		default:
			t.Errorf("%s: action %q", c.Name, c.Action)
		}
	}
}

// placedAtEvent runs a placed_at vector's event on a number of w placed
// before it, through the store's own path, and returns its placed_at
// before and after, and the event's own time.
func placedAtEvent(t *testing.T, w codesWorld, event string) (before, after *time.Time, at time.Time) {
	t.Helper()
	switch event {
	case "link":
		device := w.pending(t)
		at, err := w.c.RecordLinked(context.Background(), w.tenant, device, &w.owner, identity(40))
		if err != nil {
			t.Fatal(err)
		}
		return nil, w.placedAt(t, device), at
	case "recovery":
		device := w.linked(t, 41)
		w.reads(t, w.owner, device)
		before := w.placedAt(t, device)
		w.quarantine(t, device)
		w.recover(t, device)
		rec := eventsOf(t, w.pool, w.tenant, device, "recovered")
		return before, w.placedAt(t, device), rec[len(rec)-1].OccurredAt
	case "move_in":
		device := w.linked(t, 42)
		w.reads(t, w.owner, device)
		before := w.placedAt(t, device)
		if err := w.devices.SetPaused(context.Background(), w.tenant.String(), device.String(), true); err != nil {
			t.Fatal(err)
		}
		var personal uuid.UUID
		if err := w.pool.QueryRow(context.Background(), `SELECT id FROM tenants WHERE personal_owner_id=$1`, w.owner).Scan(&personal); err != nil {
			t.Fatal(err)
		}
		if _, err := w.devices.TransferPersonal(context.Background(), w.tenant, w.owner, device, personal); err != nil {
			t.Fatal(err)
		}
		in := eventsOf(t, w.pool, personal, device, "linked")
		var after *time.Time
		inTenantTx(context.Background(), t, w.pool, personal, func(tx pgx.Tx) error {
			return tx.QueryRow(context.Background(), `SELECT placed_at FROM devices WHERE id = $1`, device).Scan(&after)
		})
		return before, after, in[0].OccurredAt
	default: // relink
		device, id := w.loggedOutNumber(t, "Loja", "155501000601", "100000000000601")
		if _, err := w.c.RecordLinked(context.Background(), w.tenant, device, &w.owner, id); err != nil {
			t.Fatal(err)
		}
		before := w.placedAt(t, device)
		linked := newLink(id)
		w.putSession(t, linked.PN.String())
		if _, err := w.devices.AttachRelink(context.Background(), w.tenant, device, w.seen(t, device), linked); err != nil {
			t.Fatal(err)
		}
		return before, w.placedAt(t, device), time.Now()
	}
}
