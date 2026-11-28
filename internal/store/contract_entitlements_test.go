package store_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/migrate"
	"whatserver2/internal/obs"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
)

// The entitlements part's store (0053; E0 slice 17): a page stored by
// compare-and-set, documents applied by version only, kept for a workspace
// no account document names, refusals and the freshness they hold, the
// GET's answers, the reset, and the lock order.

// entKitDoc is a valid document of ws in generation gen at version v.
func entKitDoc(ws, gen uuid.UUID, v int64, mode string) kc.EntitlementsDoc {
	at := kc.T(time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond))
	on := kc.SwitchOn
	return kc.EntitlementsDoc{V: kc.EntitlementsV, Type: kc.EntitlementsType, App: "wappie", Generation: gen.String(),
		WorkspaceID: ws.String(), Version: v, ComputedAt: at, Mode: mode,
		State:    kc.EntitlementsState{Name: kc.WorkspaceActive, Since: at},
		Plan:     kc.EntitlementsPlan{Source: kc.SourceNone},
		Places:   kc.EntitlementsPlaces{Kind: kc.ItemNumber},
		Switches: kc.Switches{API: on, NewLinks: on, Sync: on, Send: on},
		Timeline: []kc.TimelineStep{}, Items: []kc.ItemTrial{},
		Links: kc.EntitlementsLinks{Plan: "https://console.thehappie.co/p", Storage: "https://console.thehappie.co/s"}}
}

// entDoc is d as the store keeps it, from the feed or (fromGet) a GET.
func entDoc(t *testing.T, d kc.EntitlementsDoc, fromGet bool) store.EntDoc {
	t.Helper()
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	doc, ok := store.NewEntDoc(d, raw, fromGet)
	if !ok {
		t.Fatalf("the document's ids: %v", d)
	}
	return doc
}

// entWorld is a database whose account side holds generation gen, with the
// platform workspaces named recorded.
type entWorld struct {
	pool *pgxpool.Pool
	c    *store.Contract
	gen  uuid.UUID
}

func newEntWorld(t *testing.T, named ...uuid.UUID) entWorld {
	t.Helper()
	pool := pgtest.Fresh(t, migrate.Run)
	w := entWorld{pool: pool, c: store.NewContract(pool), gen: uuid.New()}
	if _, err := w.c.SetMode(context.Background(), store.ContractObserve); err != nil {
		t.Fatal(err)
	}
	w.exec(t, `UPDATE contract_state SET generation = $1`, w.gen)
	for _, ws := range named {
		w.exec(t, `INSERT INTO contract_workspaces (workspace_id, kind) VALUES ($1, 'team')`, ws)
	}
	return w
}

func (w entWorld) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := w.pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// page commits items as the page after the stored cursor, to next.
func (w entWorld) page(t *testing.T, next int64, more bool, items ...store.EntPageItem) store.EntPageResult {
	t.Helper()
	st, err := w.c.EntState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	res, err := w.c.CommitEntPage(context.Background(), store.EntPage{SeenGeneration: w.gen, After: st.FeedCursor, NextAfter: next,
		More: more, PublishedThrough: time.Now().Add(-time.Second), Items: items})
	if err != nil || !res.Committed {
		t.Fatalf("the page to %d: %+v %v", next, res, err)
	}
	return res
}

func docItem(t *testing.T, d kc.EntitlementsDoc) store.EntPageItem {
	doc := entDoc(t, d, false)
	return store.EntPageItem{Seq: d.Version, Doc: &doc}
}

func refusedItem(seq int64, ws *uuid.UUID, code string) store.EntPageItem {
	return store.EntPageItem{Seq: seq, Refused: &store.EntRefusal{Seq: seq, Workspace: ws, Code: code}}
}

func (w entWorld) row(t *testing.T, ws uuid.UUID) store.EntRow {
	t.Helper()
	r, ok, err := w.c.EntRow(context.Background(), ws)
	if err != nil || !ok {
		t.Fatalf("the row of %s: %v %v", ws, ok, err)
	}
	return r
}

func actions(res store.EntPageResult) []string {
	var out []string
	for _, it := range res.Items {
		out = append(out, it.Action)
	}
	return out
}

// A document is applied only above the version held, or where the version
// was forgotten; one of a workspace no account document names is kept.
func TestCommitEntPageHigherVersionOnly(t *testing.T) {
	ctx := context.Background()
	named, other := uuid.New(), uuid.New()
	w := newEntWorld(t, named)
	if got := actions(w.page(t, 5, false, docItem(t, entKitDoc(named, w.gen, 5, kc.ModeObserve)))); fmt.Sprint(got) != "[apply]" {
		t.Fatalf("the first document: %v", got)
	}
	for _, c := range []struct {
		v    int64
		want string
	}{{4, "ignore"}, {5, "ignore"}, {6, "apply"}} {
		d := entKitDoc(named, w.gen, c.v, kc.ModeObserve)
		st, _ := w.c.EntState(ctx)
		res, err := w.c.CommitEntPage(ctx, store.EntPage{SeenGeneration: w.gen, After: st.FeedCursor, NextAfter: st.FeedCursor + 1,
			PublishedThrough: time.Now(), Items: []store.EntPageItem{{Seq: st.FeedCursor + 1, Doc: ptr(entDoc(t, d, false))}}})
		if err != nil || len(res.Items) != 1 || res.Items[0].Action != c.want {
			t.Fatalf("version %d: %+v %v, want %s", c.v, res, err, c.want)
		}
	}
	if r := w.row(t, named); r.Version == nil || *r.Version != 6 || r.AppliedAt == nil || r.Mode != kc.ModeObserve {
		t.Fatalf("the row: %+v", r)
	}
	if got := actions(w.page(t, 20, false, docItem(t, entKitDoc(other, w.gen, 20, kc.ModeObserve)))); fmt.Sprint(got) != "[keep]" {
		t.Fatalf("a workspace not named: %v", got)
	}
	// A reset forgets the versions: a lower one of the next generation is
	// applied.
	next := uuid.New()
	if done, err := w.c.RestartFromEntitlements(ctx, w.gen, &next); err != nil || !done {
		t.Fatalf("the reset: %v %v", done, err)
	}
	w.gen = next
	if got := actions(w.page(t, 1, false, docItem(t, entKitDoc(named, next, 1, kc.ModeObserve)))); fmt.Sprint(got) != "[apply]" {
		t.Fatalf("after a reset: %v", got)
	}
}

// A page commits only from the generation and the cursor it was asked
// with: nothing of it is stored otherwise.
func TestCommitEntPageCompareAndSet(t *testing.T) {
	ctx := context.Background()
	named := uuid.New()
	w := newEntWorld(t, named)
	item := docItem(t, entKitDoc(named, w.gen, 3, kc.ModeObserve))
	for name, p := range map[string]store.EntPage{
		"another generation": {SeenGeneration: uuid.New(), After: 0, NextAfter: 3, Items: []store.EntPageItem{item}},
		"another cursor":     {SeenGeneration: w.gen, After: 2, NextAfter: 3, Items: []store.EntPageItem{item}},
	} {
		res, err := w.c.CommitEntPage(ctx, p)
		if err != nil || res.Committed {
			t.Fatalf("%s: %+v %v", name, res, err)
		}
	}
	if _, ok, err := w.c.EntRow(ctx, named); err != nil || ok {
		t.Fatalf("a page not committed stored a document: %v %v", ok, err)
	}
	st, err := w.c.EntState(ctx)
	if err != nil || st.FeedCursor != 0 || st.FirstReadAt != nil {
		t.Fatalf("a page not committed moved the state: %+v %v", st, err)
	}
	// published_through only from a page with more false.
	w.page(t, 3, true, item)
	if st, _ := w.c.EntState(ctx); st.FeedCursor != 3 || st.PublishedThrough != nil || st.FirstReadAt == nil {
		t.Fatalf("a page with more: %+v", st)
	}
	w.page(t, 3, false)
	if st, _ := w.c.EntState(ctx); st.PublishedThrough == nil {
		t.Fatalf("a page with more false: %+v", st)
	}
}

// A document of a workspace no account document names is kept, counted as
// applied in the acknowledgement, and applied once an account document
// names it; a workspace named with no document gets its GET due.
func TestCommitEntPageKeepsUnnamedWorkspace(t *testing.T) {
	ctx := context.Background()
	w := newEntWorld(t)
	sub, home, team := uuid.New(), uuid.New(), uuid.New()
	w.page(t, 4, false, docItem(t, entKitDoc(team, w.gen, 4, kc.ModeObserve)))
	if r := w.row(t, team); r.AppliedAt != nil || r.Named || r.Doc == nil {
		t.Fatalf("a document kept: %+v", r)
	}
	if a, ok, err := w.c.EntAckDue(ctx); err != nil || !ok || a.Through != 4 {
		t.Fatalf("the acknowledgement counts it: %+v %v %v", a, ok, err)
	}
	storeDocs(t, w.c, store.ContractAnswer, contractDoc(sub, w.gen, 1, "active", home,
		store.ContractDocWorkspace{ID: team, Role: "owner", Status: "open", WVersion: 1}))
	if r := w.row(t, team); r.AppliedAt == nil || !r.Named || r.GetDueAt != nil {
		t.Fatalf("a document kept, its workspace named: %+v", r)
	}
	if r := w.row(t, home); r.Doc != nil || r.GetDueAt == nil {
		t.Fatalf("a workspace named with no document: %+v", r)
	}
	due, err := w.c.EntGetsDue(ctx, 10)
	if err != nil || len(due) != 1 || due[0].Workspace != home {
		t.Fatalf("the GETs due: %+v %v", due, err)
	}
}

// A refusal holds its workspace's freshness at the published_through stored
// before it, never NULL, while later pages advance; a valid newer document
// or a GET gives it back. One whose workspace_id cannot be read holds
// every kept row and paces their GETs.
func TestEntFreshnessHeldBackByBadDocument(t *testing.T) {
	ctx := context.Background()
	a, b := uuid.New(), uuid.New()
	w := newEntWorld(t, a, b)
	w.page(t, 2, false, docItem(t, entKitDoc(a, w.gen, 1, kc.ModeObserve)), docItem(t, entKitDoc(b, w.gen, 2, kc.ModeObserve)))
	before, _ := w.c.EntState(ctx)
	res := w.page(t, 3, false, refusedItem(3, &a, kc.RefusedInvalidDocument))
	if !res.Urgent {
		t.Fatal("a refusal does not make the acknowledgement urgent")
	}
	time.Sleep(10 * time.Millisecond)
	w.page(t, 3, false)
	after, _ := w.c.EntState(ctx)
	ra, rb := w.row(t, a), w.row(t, b)
	if ra.Fresh == nil || !ra.Fresh.Equal(*before.PublishedThrough) || ra.GetDueAt == nil {
		t.Fatalf("the refused workspace's freshness %v, want %v held; GET due %v", ra.Fresh, before.PublishedThrough, ra.GetDueAt)
	}
	if rb.Fresh == nil || !rb.Fresh.Equal(*after.PublishedThrough) || !after.PublishedThrough.After(*before.PublishedThrough) {
		t.Fatalf("the other workspace's freshness %v, want %v", rb.Fresh, after.PublishedThrough)
	}
	// A newer valid document gives it back.
	w.page(t, 4, false, docItem(t, entKitDoc(a, w.gen, 4, kc.ModeObserve)))
	now, _ := w.c.EntState(ctx)
	if r := w.row(t, a); r.FeedHeldBack || r.Fresh == nil || !r.Fresh.Equal(*now.PublishedThrough) {
		t.Fatalf("after a newer document: %+v", r)
	}
	// An unreadable workspace_id holds every kept row, its GETs paced.
	w.page(t, 5, false, refusedItem(5, nil, kc.RefusedInvalidDocument))
	held, _ := w.c.EntState(ctx)
	for _, ws := range []uuid.UUID{a, b} {
		if r := w.row(t, ws); !r.FeedHeldBack || r.GetDueAt == nil || r.Fresh == nil || !r.Fresh.Equal(*now.PublishedThrough) {
			t.Fatalf("%s after an unreadable refusal: %+v", ws, r)
		}
	}
	if held.UnreadableGetNextAt == nil {
		t.Fatal("the unreadable refusal's GETs are not paced")
	}
	due, err := w.c.EntGetsDue(ctx, 10)
	if err != nil || len(due) != 2 || !due[0].Paced {
		t.Fatalf("the GETs due: %+v %v", due, err)
	}
	if ok, err := w.c.EntGetPaced(ctx, 10*time.Second); err != nil || !ok {
		t.Fatalf("the first paced GET: %v %v", ok, err)
	}
	if ok, err := w.c.EntGetPaced(ctx, 10*time.Second); err != nil || ok {
		t.Fatalf("a second within 10 s: %v %v", ok, err)
	}
	// The acknowledgement lists both refusals, then neither.
	ack, ok, err := w.c.EntAckDue(ctx)
	if err != nil || !ok || len(ack.Refused) != 2 || ack.Through != 5 {
		t.Fatalf("the acknowledgement: %+v %v %v", ack, ok, err)
	}
	if err := w.c.EntAcked(ctx, ack); err != nil {
		t.Fatal(err)
	}
	if ack, _, _ := w.c.EntAckDue(ctx); len(ack.Refused) != 0 {
		t.Fatalf("refusals listed twice: %+v", ack)
	}
	if st, _ := w.c.EntState(ctx); st.AckUrgent || st.AckedThrough == nil || *st.AckedThrough != 5 {
		t.Fatalf("the state after the acknowledgement: %+v", st)
	}
}

// A GET's answer of the version held gives freshness only: the feed's
// bytes stay and nothing is applied; a higher one is applied with its own
// bytes; a lower one gives nothing.
func TestEntGetSameVersionFreshOnly(t *testing.T) {
	ctx := context.Background()
	ws := uuid.New()
	w := newEntWorld(t, ws)
	d := entKitDoc(ws, w.gen, 7, kc.ModeObserve)
	item := docItem(t, d)
	// The feed's bytes, as the platform writes them: not json.Marshal's.
	item.Doc.Raw = append([]byte(" "), item.Doc.Raw...)
	w.page(t, 7, false, item)
	signed := time.Now().Add(time.Hour).Truncate(time.Microsecond)
	res, err := w.c.EntGotDoc(ctx, entDoc(t, d, true), signed)
	if err != nil || res.Action != store.EntFresh {
		t.Fatalf("the version held: %+v %v", res, err)
	}
	r := w.row(t, ws)
	if !bytes.Equal(r.Doc, item.Doc.Raw) || r.GetFreshAt == nil || !r.GetFreshAt.Equal(signed) || !r.Fresh.Equal(signed) {
		t.Fatalf("after the version held: doc kept %v, get fresh %v", bytes.Equal(r.Doc, item.Doc.Raw), r.GetFreshAt)
	}
	res, err = w.c.EntGotDoc(ctx, entDoc(t, entKitDoc(ws, w.gen, 6, kc.ModeObserve), true), signed.Add(time.Minute))
	if err != nil || res.Action != store.EntIgnore {
		t.Fatalf("a lower version: %+v %v", res, err)
	}
	if r := w.row(t, ws); !r.GetFreshAt.Equal(signed) {
		t.Fatalf("a lower version gave freshness: %v", r.GetFreshAt)
	}
	higher := entDoc(t, entKitDoc(ws, w.gen, 8, kc.ModeObserve), true)
	res, err = w.c.EntGotDoc(ctx, higher, signed.Add(2*time.Minute))
	if err != nil || res.Action != store.EntApply {
		t.Fatalf("a higher version: %+v %v", res, err)
	}
	if r := w.row(t, ws); *r.Version != 8 || !bytes.Equal(r.Doc, higher.Raw) {
		t.Fatalf("after a higher version: %+v", r)
	}
}

// A GET's document of another generation applies nothing: it is a reset,
// through RestartFromEntitlements.
func TestEntGetOtherGenerationResets(t *testing.T) {
	ctx := context.Background()
	ws := uuid.New()
	w := newEntWorld(t, ws)
	w.page(t, 3, false, docItem(t, entKitDoc(ws, w.gen, 3, kc.ModeObserve)))
	other := uuid.New()
	res, err := w.c.EntGotDoc(ctx, entDoc(t, entKitDoc(ws, other, 1, kc.ModeObserve), true), time.Now())
	if err != nil || res.Action != store.EntReset {
		t.Fatalf("another generation's document: %+v %v", res, err)
	}
	if r := w.row(t, ws); *r.Version != 3 {
		t.Fatalf("another generation's document was applied: %+v", r)
	}
	if done, err := w.c.RestartFromEntitlements(ctx, w.gen, &other); err != nil || !done {
		t.Fatalf("the reset: %v %v", done, err)
	}
	st, _ := w.c.EntState(ctx)
	if st.Generation == nil || *st.Generation != other || st.FeedCursor != 0 {
		t.Fatalf("after the reset: %+v", st)
	}
}

// A reset keeps each workspace's document, applied_at, ever_enforce_at and
// brake, and forgets its version, codes_after_answered, the cursor, the
// refusals, and every freshness: published_through, the held one and the
// GET's.
func TestEntRestartKeepsDocumentsForgetsVersions(t *testing.T) {
	ctx := context.Background()
	ws := uuid.New()
	w := newEntWorld(t, ws)
	w.page(t, 9, false, docItem(t, entKitDoc(ws, w.gen, 9, kc.ModeEnforce)), refusedItem(10, &ws, kc.RefusedAnotherApp))
	if _, err := w.c.EntGotDoc(ctx, entDoc(t, entKitDoc(ws, w.gen, 9, kc.ModeEnforce), true), time.Now()); err != nil {
		t.Fatal(err)
	}
	w.exec(t, `UPDATE contract_ent_docs SET codes_after_answered = clock_timestamp()`)
	before := w.row(t, ws)
	if before.BrakeKind != store.BrakeEnforceInE0 || before.EverEnforceAt == nil || before.GetFreshAt == nil {
		t.Fatalf("before the reset: %+v", before)
	}
	next := uuid.New()
	if done, err := w.c.RestartFromEntitlements(ctx, w.gen, &next); err != nil || !done {
		t.Fatalf("the reset: %v %v", done, err)
	}
	r := w.row(t, ws)
	var answered *time.Time
	var first bool
	var refusals int
	if err := w.pool.QueryRow(ctx, `SELECT codes_after_answered, first_after_reset, (SELECT count(*) FROM contract_ent_refusals)
		FROM contract_ent_docs WHERE workspace_id = $1`, ws).Scan(&answered, &first, &refusals); err != nil {
		t.Fatal(err)
	}
	switch {
	case !bytes.Equal(r.Doc, before.Doc), r.Mode != kc.ModeEnforce, r.AppliedAt == nil || !r.AppliedAt.Equal(*before.AppliedAt),
		r.EverEnforceAt == nil, r.BrakeKind != store.BrakeEnforceInE0:
		t.Fatalf("a reset lost what it keeps: %+v", r)
	case r.Version != nil, answered != nil, !first, refusals != 0, r.FeedHeldBack, r.FeedFreshAt != nil, r.GetFreshAt != nil,
		r.Fresh != nil, r.GetDueAt == nil:
		t.Fatalf("a reset kept what it forgets: %+v, answered %v, first %v, refusals %d", r, answered, first, refusals)
	}
	if st, _ := w.c.EntState(ctx); st.FeedCursor != 0 || st.PublishedThrough != nil || st.AckedThrough != nil {
		t.Fatalf("the state after the reset: %+v", st)
	}
}

// The lock order: two pages, an account page that names workspaces, a
// reset and the GET's store, each in its own transaction, run at once many
// times; none deadlocks (the server's 40P01 would be retried, and logged).
func TestCommitEntPageLockOrder(t *testing.T) {
	ctx := context.Background()
	var logs bytes.Buffer
	var mu sync.Mutex
	lctx := obs.WithLogger(ctx, slog.New(slog.NewTextHandler(&lockedWriter{w: &logs, mu: &mu}, nil)))
	ids := make([]uuid.UUID, 6)
	for i := range ids {
		ids[i] = uuid.MustParse(fmt.Sprintf("%d0000000-0000-4000-8000-000000000000", i+1))
	}
	w := newEntWorld(t, ids[:3]...)
	sub, home := uuid.New(), uuid.New()
	for round := range 8 {
		st, err := w.c.EntState(ctx)
		if err != nil || st.Generation == nil {
			t.Fatal(err)
		}
		gen := *st.Generation
		var items []store.EntPageItem
		for i, ws := range ids {
			doc := entDoc(t, entKitDoc(ws, gen, st.FeedCursor+int64(i)+1, kc.ModeObserve), false)
			items = append(items, store.EntPageItem{Seq: doc.Version, Doc: &doc})
		}
		page := store.EntPage{SeenGeneration: gen, After: st.FeedCursor, NextAfter: st.FeedCursor + int64(len(ids)),
			PublishedThrough: time.Now(), Items: items}
		// The reverse order of rows too: a page never locks out of order.
		rev := page
		rev.Items = append([]store.EntPageItem{refusedItem(st.FeedCursor+1, nil, kc.RefusedInvalidDocument)}, items[1:]...)
		var teams []store.ContractDocWorkspace
		for _, ws := range ids[2:] {
			teams = append(teams, store.ContractDocWorkspace{ID: ws, Role: "member", Status: "open", WVersion: int64(round + 1)})
		}
		var wg sync.WaitGroup
		errs := make(chan error, 8)
		run := func(f func() error) { wg.Go(func() { errs <- f() }) }
		run(func() error { _, err := w.c.CommitEntPage(lctx, page); return err })
		run(func() error { _, err := w.c.CommitEntPage(lctx, rev); return err })
		run(func() error {
			_, err := w.c.StoreDocuments(lctx, store.ContractAnswer, contractDoc(sub, gen, int64(round+1), "active", home, teams...))
			return err
		})
		run(func() error {
			_, err := w.c.EntGotDoc(lctx, entDoc(t, entKitDoc(ids[4], gen, 1000+int64(round), kc.ModeObserve), true), time.Now())
			return err
		})
		run(func() error { _, err := w.c.EntBrake(lctx, ids[1], round%2 == 0, false); return ignoreNoBrake(err) })
		if round%3 == 2 {
			next := uuid.New()
			run(func() error { _, err := w.c.RestartFromEntitlements(lctx, gen, &next); return err })
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("round %d: %v", round, err)
			}
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Contains(logs.String(), "deadlocked") {
		t.Fatalf("a transaction deadlocked: %s", logs.String())
	}
}

func ignoreNoBrake(err error) error {
	if errors.Is(err, store.ErrEntNoBrake) {
		return nil
	}
	return err
}

type lockedWriter struct {
	w  *bytes.Buffer
	mu *sync.Mutex
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// An enforce document holds its workspace at observe in its own
// transaction; its release is refused while the document says enforce,
// and an operator's hold is released.
func TestEntEnforceBrakeStore(t *testing.T) {
	ctx := context.Background()
	ws, op := uuid.New(), uuid.New()
	w := newEntWorld(t, ws, op)
	res := w.page(t, 2, false, docItem(t, entKitDoc(ws, w.gen, 2, kc.ModeEnforce)))
	if !res.Items[0].NewBrake || !res.Items[0].Braked || !res.Urgent {
		t.Fatalf("an enforce document: %+v", res.Items[0])
	}
	if _, err := w.c.EntBrake(ctx, ws, false, true); !errors.Is(err, store.ErrEntEnforceHeld) {
		t.Fatalf("releasing an enforce hold: %v", err)
	}
	if changed, err := w.c.EntBrake(ctx, ws, true, true); err != nil || !changed {
		t.Fatalf("telling the platform of it: %v %v", changed, err)
	}
	if r := w.row(t, ws); r.BrakeKind != store.BrakeEnforceInE0 || !r.BrakeTold {
		t.Fatalf("the hold told: %+v", r)
	}
	w.page(t, 3, false, docItem(t, entKitDoc(op, w.gen, 3, kc.ModeObserve)))
	if changed, err := w.c.EntBrake(ctx, op, true, false); err != nil || !changed {
		t.Fatalf("an operator's hold: %v %v", changed, err)
	}
	if changed, err := w.c.EntBrake(ctx, op, false, false); err != nil || !changed {
		t.Fatalf("an operator's release: %v %v", changed, err)
	}
	if _, err := w.c.EntBrake(ctx, op, false, false); !errors.Is(err, store.ErrEntNoBrake) {
		t.Fatalf("a release of nothing: %v", err)
	}
}

// The modes: observe needs the contract on, enforce is refused, and off
// after a first read needs the platform told.
func TestEntModes(t *testing.T) {
	ctx := context.Background()
	w := newEntWorld(t)
	if _, err := w.c.SetEntMode(ctx, store.EntEnforce, true); !errors.Is(err, store.ErrEntMode) {
		t.Fatalf("enforce: %v", err)
	}
	if _, err := w.c.SetMode(ctx, store.ContractOff); err != nil {
		t.Fatal(err)
	}
	if _, err := w.c.SetEntMode(ctx, store.EntObserve, false); !errors.Is(err, store.ErrEntContractOff) {
		t.Fatalf("observe with the contract off: %v", err)
	}
	if _, err := w.c.SetEntUsage(ctx, store.UsageOn); !errors.Is(err, store.ErrEntContractOff) {
		t.Fatalf("usage on with the contract off: %v", err)
	}
	if _, err := w.c.SetMode(ctx, store.ContractObserve); err != nil {
		t.Fatal(err)
	}
	if ch, err := w.c.SetEntMode(ctx, store.EntObserve, false); err != nil || !ch.Changed {
		t.Fatalf("observe: %+v %v", ch, err)
	}
	w.page(t, 0, false)
	if _, err := w.c.SetEntMode(ctx, store.EntOff, false); !errors.Is(err, store.ErrEntTellPlatform) {
		t.Fatalf("off after a read: %v", err)
	}
	if ch, err := w.c.SetEntMode(ctx, store.EntOff, true); err != nil || !ch.Changed || ch.FirstReadAt == nil {
		t.Fatalf("off, told: %+v %v", ch, err)
	}
}
