package store_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/migrate"
	"whatserver2/internal/obs"
	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
)

// The leader's writes (the plan's 4.4 and 4.7): pages, restarts, the
// recovery's due-now, the mode, and what contract status reads.

// heldPerson is a person Wappie holds: a local account linked to a sub.
func heldPerson(t *testing.T, pool *pgxpool.Pool) (user, sub, home uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	user, home = uuid.New(), uuid.New()
	if err := pg.InTenantTx(ctx, pool, home.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO users (id, tenant_id, email, public_key, role, auth_source)
			VALUES ($1, $2, $3, $4, 'owner', 'platform')`, user, home, user.String()[:8]+"@example.com", platformBytes(t, 32))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return user, linkSub(t, pool, user), home
}

func commit(ctx context.Context, t *testing.T, c *store.Contract, p store.ContractPage) store.ContractPageResult {
	t.Helper()
	res, err := c.CommitPage(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func workspaceStatus(t *testing.T, c *store.Contract, id uuid.UUID) (store.ContractWorkspace, bool) {
	t.Helper()
	w, ok, err := c.Workspace(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return w, ok
}

// TB20's and TB22's store part, and TB23's compare-and-set: a page adopts
// the generation while none is stored and stores its documents newer only,
// refreshing nobody; only a held sub's document records its workspaces; the
// cursor moves by compare-and-set, so a stale leader's page changes no row;
// published_through is stored only from a page with more false and never
// past the clock; a lower wversion changes no status; a page of another
// generation is a restart; and the first writer of a generation wins.
func TestContractPages(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	var logged bytes.Buffer
	ctx := obs.WithLogger(context.Background(), slog.New(slog.NewTextHandler(&logged, nil)))
	c := store.NewContract(pool)
	_, held, home := heldPerson(t, pool)
	unheld, unheldHome, team := uuid.New(), uuid.New(), uuid.New()
	gen := uuid.New()
	open3 := store.ContractDocWorkspace{ID: team, Role: "member", Status: "open", WVersion: 3}
	through := dbClock(t, pool, "-1 minute")

	res := commit(ctx, t, c, store.ContractPage{After: 0, Generation: gen, Confirmed: true, NextAfter: 2, PublishedThrough: through,
		Docs: []store.ContractDoc{contractDoc(held, gen, 1, "active", home, open3), contractDoc(unheld, gen, 2, "active", unheldHome)}})
	if !res.Committed || !res.Vouched || res.Ahead || res.Outcomes[0] != store.ContractDocStored || res.Outcomes[1] != store.ContractDocStored {
		t.Fatalf("the first page: %+v", res)
	}
	s, err := c.State(ctx)
	if err != nil || s.Generation == nil || *s.Generation != gen || !s.GenerationConfirmed || s.FeedCursor != 2 ||
		s.PublishedThrough == nil || !s.PublishedThrough.Equal(through) || s.FeedReadAt == nil || s.FeedError != "" {
		t.Fatalf("after the first page: %+v %v", s, err)
	}
	if a := readAccount(t, pool, held); a.Version == nil || *a.Version != 1 || a.FreshAt != nil {
		t.Fatalf("a page's document: %+v (a page refreshes nobody)", a)
	}
	if a := readAccount(t, pool, unheld); a.Version == nil || *a.Version != 2 {
		t.Fatalf("an unheld sub's document: %+v", a)
	}
	for id, want := range map[uuid.UUID]bool{home: true, team: true, unheldHome: false} {
		if _, ok := workspaceStatus(t, c, id); ok != want {
			t.Fatalf("workspace %s recorded %v, want %v (only a held sub's page records)", id, ok, want)
		}
	}

	// The same and a lower version: kept, the document unchanged.
	res = commit(ctx, t, c, store.ContractPage{After: 2, SeenGeneration: &gen, Generation: gen, NextAfter: 3, PublishedThrough: through,
		Docs: []store.ContractDoc{contractDoc(held, gen, 1, "disabled", home), contractDoc(unheld, gen, 1, "disabled", unheldHome)}})
	if !res.Committed || res.Outcomes[0] != store.ContractDocKept || res.Outcomes[1] != store.ContractDocKept {
		t.Fatalf("an equal and a lower version: %+v", res)
	}
	if a := readAccount(t, pool, held); *a.Status != "active" || *a.DocVersion != 1 || a.FreshAt != nil {
		t.Fatalf("a kept document: %+v", a)
	}

	// A stale leader's page, asked from the cursor before: nothing.
	stale := commit(ctx, t, c, store.ContractPage{After: 2, SeenGeneration: &gen, Generation: gen, NextAfter: 9, PublishedThrough: dbClock(t, pool, "0"),
		Docs: []store.ContractDoc{contractDoc(held, gen, 9, "disabled", home)}})
	if stale.Committed || stale.Outcomes != nil {
		t.Fatalf("a stale page committed: %+v", stale)
	}
	if s, _ := c.State(ctx); s.FeedCursor != 3 || !s.PublishedThrough.Equal(through) {
		t.Fatalf("a stale page moved the state: %+v", s)
	}
	if a := readAccount(t, pool, held); *a.Version != 1 {
		t.Fatalf("a stale page stored a document: %+v", a)
	}

	// more true: the cursor moves, published_through does not.
	later := dbClock(t, pool, "0")
	res = commit(ctx, t, c, store.ContractPage{After: 3, SeenGeneration: &gen, Generation: gen, NextAfter: 5, More: true, PublishedThrough: later,
		Docs: []store.ContractDoc{contractDoc(held, gen, 4, "active", home, store.ContractDocWorkspace{ID: team, Role: "owner", Status: "closed", WVersion: 2})}})
	if !res.Committed || res.Vouched {
		t.Fatalf("a page with more: %+v", res)
	}
	if s, _ := c.State(ctx); s.FeedCursor != 5 || !s.PublishedThrough.Equal(through) {
		t.Fatalf("a page with more stored published_through: %+v", s)
	}
	// A lower wversion: the document is newer, the workspace's status stays.
	if w, _ := workspaceStatus(t, c, team); w.Status != "open" || w.WVersion != 3 {
		t.Fatalf("a lower wversion moved the status: %+v", w)
	}
	if a := readAccount(t, pool, held); *a.Version != 4 {
		t.Fatalf("the newer document: %+v", a)
	}

	// A published_through past the clock: kept as it was, at ERROR.
	res = commit(ctx, t, c, store.ContractPage{After: 5, SeenGeneration: &gen, Generation: gen, NextAfter: 5, PublishedThrough: dbClock(t, pool, "10 minutes")})
	if !res.Committed || res.Vouched || !res.Ahead {
		t.Fatalf("a published_through ahead: %+v", res)
	}
	if s, _ := c.State(ctx); !s.PublishedThrough.Equal(through) || s.ErrorClass != store.ContractErrorPublishedAhead || s.ErrorAt == nil {
		t.Fatalf("after a published_through ahead: %+v", s)
	}
	if !strings.Contains(logged.String(), "level=ERROR msg=\"contract: published_through ahead of the clock") {
		t.Fatalf("no ERROR: %s", logged.String())
	}
	// more false: stored.
	now := dbClock(t, pool, "0")
	if res = commit(ctx, t, c, store.ContractPage{After: 5, SeenGeneration: &gen, Generation: gen, NextAfter: 5, PublishedThrough: now}); !res.Vouched {
		t.Fatalf("a page with more false: %+v", res)
	}
	if s, _ := c.State(ctx); !s.PublishedThrough.Equal(now) {
		t.Fatalf("published_through %v, want %v", s.PublishedThrough, now)
	}

	// Another generation is the restart's, never a page's.
	if _, err := c.CommitPage(ctx, store.ContractPage{After: 5, SeenGeneration: &gen, Generation: uuid.New(), NextAfter: 5}); !errors.Is(err, store.ErrPageGeneration) {
		t.Fatalf("a page of another generation: %v", err)
	}
	if _, err := c.CommitPage(ctx, store.ContractPage{After: 5, SeenGeneration: &gen, Generation: gen, NextAfter: 4}); err == nil {
		t.Fatal("a page whose next_after is behind its cursor")
	}

	// The first writer of a generation wins: an answer that adopted it
	// first makes a page asked with none fail its compare-and-set, and the
	// page asked again with it commits.
	fresh := pgtest.Fresh(t, migrate.Run)
	fc := store.NewContract(fresh)
	g := uuid.New()
	storeDocs(t, fc, store.ContractAnswer, contractDoc(uuid.New(), g, 1, "active", uuid.New()))
	if res := commit(ctx, t, fc, store.ContractPage{After: 0, Generation: g, NextAfter: 1, PublishedThrough: dbClock(t, fresh, "0")}); res.Committed {
		t.Fatalf("a page asked with no generation after an answer adopted one: %+v", res)
	}
	if res := commit(ctx, t, fc, store.ContractPage{After: 0, SeenGeneration: &g, Generation: g, NextAfter: 1, PublishedThrough: dbClock(t, fresh, "0")}); !res.Committed {
		t.Fatalf("the page asked again: %+v", res)
	}
}

// TB22's store part: the restart forgets the stored generation's versions,
// cursor and freshness, keeps every document and its highest revocation
// times, makes every workspace's wversion 0 and its snapshot and queue due
// now with nothing parked; it is compare-and-set; and after it a lower
// wversion is applied.
func TestContractRestart(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	c := store.NewContract(pool)
	_, sub, home := heldPerson(t, pool)
	gen, team := uuid.New(), uuid.New()
	disabled := dbClock(t, pool, "-2 hours")
	storeDocs(t, c, store.ContractAnswer, revoked(contractDoc(sub, gen, 7, "active", home,
		store.ContractDocWorkspace{ID: team, Role: "owner", Status: "open", WVersion: 9}), disabled))
	if _, err := pool.Exec(ctx, `UPDATE contract_state SET feed_cursor = 7, published_through = clock_timestamp(),
		round_generation = generation, generation_confirmed = true`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE contract_workspaces SET snapshot_due_at = clock_timestamp() + interval '1 day',
		snapshot_ok_at = clock_timestamp(), snapshot_tries = 3, events_due_at = clock_timestamp() + interval '1 day', events_tries = 2,
		not_found_since = clock_timestamp(), parked_at = clock_timestamp()`); err != nil {
		t.Fatal(err)
	}
	next := uuid.New()
	if done, err := c.Restart(ctx, &gen, 6, &next, false); err != nil || done {
		t.Fatalf("a restart from a state that moved: %v %v", done, err)
	}
	if done, err := c.Restart(ctx, &gen, 7, &next, false); err != nil || !done {
		t.Fatalf("the restart: %v %v", done, err)
	}
	s, err := c.State(ctx)
	if err != nil || s.Generation == nil || *s.Generation != next || s.GenerationConfirmed || s.FeedCursor != 0 ||
		s.PublishedThrough != nil || s.RoundGeneration != nil {
		t.Fatalf("the state after the restart: %+v %v", s, err)
	}
	a := readAccount(t, pool, sub)
	if a.Version != nil || a.Generation != nil || a.FreshAt != nil || a.DocVersion == nil || *a.DocVersion != 7 || !a.revokedAt(disabled) {
		t.Fatalf("the account after the restart: %+v", a)
	}
	var due, back, wv int
	if err := pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE snapshot_due_at <= clock_timestamp() AND events_due_at <= clock_timestamp()),
		count(*) FILTER (WHERE snapshot_tries = 0 AND events_tries = 0 AND not_found_since IS NULL AND parked_at IS NULL AND snapshot_ok_at IS NULL),
		count(*) FILTER (WHERE wversion = 0 AND status = 'open') FROM contract_workspaces`).Scan(&due, &back, &wv); err != nil || due != 2 || back != 2 || wv != 2 {
		t.Fatalf("the workspaces after the restart: due %d, unparked %d, wversion 0 %d (%v)", due, back, wv, err)
	}
	// The new generation's lower wversion is applied, and an older
	// revocation time undoes nothing.
	storeDocs(t, c, store.ContractAnswer, revoked(contractDoc(sub, next, 1, "active", home,
		store.ContractDocWorkspace{ID: team, Role: "owner", Status: "closed", WVersion: 2}), dbClock(t, pool, "-3 hours")))
	if w, _ := workspaceStatus(t, c, team); w.Status != "closed" || w.WVersion != 2 {
		t.Fatalf("a lower wversion after the restart: %+v", w)
	}
	if a := readAccount(t, pool, sub); !a.revokedAt(disabled) || *a.Version != 1 {
		t.Fatalf("the highest revocation times: %+v", a)
	}

	// A gone: no generation until the next answer adopts one.
	if done, err := c.Restart(ctx, &next, 0, nil, true); err != nil || !done {
		t.Fatalf("the restart after a gone: %v %v", done, err)
	}
	if s, _ := c.State(ctx); s.Generation != nil || s.GenerationConfirmed {
		t.Fatalf("after a gone: %+v", s)
	}
}

// The recovery's due-now: every workspace backing off is due now with its
// tries reset; the others are left as they are.
func TestContractRecovered(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	c := store.NewContract(pool)
	_, sub, home := heldPerson(t, pool)
	team := uuid.New()
	storeDocs(t, c, store.ContractAnswer, contractDoc(sub, uuid.New(), 1, "active", home,
		store.ContractDocWorkspace{ID: team, Role: "owner", Status: "open", WVersion: 1}))
	if _, err := pool.Exec(ctx, `UPDATE contract_workspaces SET snapshot_due_at = clock_timestamp() + interval '1 hour',
		snapshot_tries = CASE WHEN workspace_id = $1 THEN 5 ELSE 0 END,
		events_due_at = clock_timestamp() + interval '1 hour', events_tries = CASE WHEN workspace_id = $1 THEN 4 ELSE 0 END`, team); err != nil {
		t.Fatal(err)
	}
	if n, err := c.Recovered(ctx); err != nil || n != 1 {
		t.Fatalf("recovered %d (%v), want the one backing off", n, err)
	}
	var dueTeam, dueHome bool
	if err := pool.QueryRow(ctx, `SELECT
		bool_and(snapshot_due_at <= clock_timestamp() AND events_due_at <= clock_timestamp() AND snapshot_tries = 0 AND events_tries = 0) FILTER (WHERE workspace_id = $1),
		bool_and(snapshot_due_at <= clock_timestamp()) FILTER (WHERE workspace_id = $2) FROM contract_workspaces`, team, home).Scan(&dueTeam, &dueHome); err != nil {
		t.Fatal(err)
	}
	if !dueTeam || dueHome {
		t.Fatalf("due: the backing-off team %v, the personal workspace %v", dueTeam, dueHome)
	}
}

// TB26's store part: the first observe sets events_from once; off starts
// an off period; a switch to the mode it is in changes nothing; the return
// to observe adds the period to events_off, counts the events it will now
// send (a deletion from before the pause, and one from the period) and
// those it holds back for good (a pause from the period), and wakes every
// process.
func TestContractSetMode(t *testing.T) {
	backends := &pgtest.Backends{}
	pool := pgtest.FreshWith(t, migrate.Run, backends.Configure)
	ctx := context.Background()
	c := store.NewContract(pool)
	listen, err := pgx.ConnectConfig(ctx, pool.Config().ConnConfig.Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close(ctx) //nolint:errcheck // a test's listener
	if _, err := listen.Exec(ctx, "LISTEN "+store.ContractModeChannel); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetMode(ctx, "enforce"); !errors.Is(err, store.ErrContractMode) {
		t.Fatalf("an unknown mode: %v", err)
	}
	if ch, err := c.SetMode(ctx, store.ContractOff); err != nil || ch.Changed {
		t.Fatalf("off while off: %+v %v", ch, err)
	}
	ch, err := c.SetMode(ctx, store.ContractObserve)
	if err != nil || !ch.Changed || ch.From != store.ContractOff || ch.ToSend != 0 || ch.HeldBack != 0 {
		t.Fatalf("the first observe: %+v %v", ch, err)
	}
	wait, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := backends.Notice(wait, listen, store.ContractModeChannel, "mode"); err != nil {
		t.Fatalf("no notice of the switch: %v", err)
	}
	first, _ := c.State(ctx)
	if first.EventsFrom == nil || first.EventsPausedAt != nil || first.Mode != store.ContractObserve {
		t.Fatalf("after the first observe: %+v", first)
	}

	// A recorded team of Wappie's, with a deletion before the pause.
	tenant := uuid.MustParse(newTenant(t, pool, "Equipe"))
	_, sub, home := heldPerson(t, pool)
	storeDocs(t, c, store.ContractAnswer, contractDoc(sub, uuid.New(), 1, "active", home,
		store.ContractDocWorkspace{ID: tenant, Role: "owner", Status: "open", WVersion: 1}))
	event := func(kind string) {
		t.Helper()
		if err := pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO item_events (event_id, tenant_id, type, item_id, dedupe_key, occurred_at, actor_kind,
				deleted_at, purge_after, ledgered_at)
				VALUES ($1, $2, $3, $4, $5, clock_timestamp(), 'person',
				CASE WHEN $3 = 'deleted' THEN clock_timestamp() END, CASE WHEN $3 = 'deleted' THEN clock_timestamp() + interval '30 days' END,
				clock_timestamp())`, uuid.New(), tenant, kind, uuid.New(), uuid.NewString())
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	event("deleted")

	if ch, err = c.SetMode(ctx, store.ContractOff); err != nil || !ch.Changed {
		t.Fatalf("off: %+v %v", ch, err)
	}
	off, _ := c.State(ctx)
	if off.EventsPausedAt == nil || !off.EventsFrom.Equal(*first.EventsFrom) {
		t.Fatalf("off after observe: %+v", off)
	}
	if ch, err := c.SetMode(ctx, store.ContractOff); err != nil || ch.Changed {
		t.Fatalf("off again: %+v %v", ch, err)
	}
	if again, _ := c.State(ctx); !again.EventsPausedAt.Equal(*off.EventsPausedAt) || !again.ModeChangedAt.Equal(off.ModeChangedAt) {
		t.Fatalf("off again changed the state: %+v", again)
	}
	event("sync_paused")
	event("deleted")

	ch, err = c.SetMode(ctx, store.ContractObserve)
	if err != nil || !ch.Changed || ch.ToSend != 2 || ch.HeldBack != 1 {
		t.Fatalf("the return to observe: %+v %v (want 2 to send, 1 held back)", ch, err)
	}
	back, _ := c.State(ctx)
	if !back.EventsFrom.Equal(*first.EventsFrom) || back.EventsPausedAt != nil || len(back.EventsOff) != 1 ||
		!back.EventsOff[0].From.Equal(*off.EventsPausedAt) || back.RoundGeneration != nil {
		t.Fatalf("after the return: %+v", back)
	}
}

// Status reads the counts contract status prints: the subs held and
// followed, the subscriptions, and each workspace's events.
func TestContractStatusRead(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	c := store.NewContract(pool)
	_, sub, home := heldPerson(t, pool)
	heldPerson(t, pool)
	gen := uuid.New()
	storeDocs(t, c, store.ContractAnswer, contractDoc(sub, gen, 1, "active", home), contractDoc(uuid.New(), gen, 1, "active", uuid.New()))
	st, err := c.Status(ctx)
	if err != nil || st.Held != 2 || st.Followed != 1 || st.Accounts != 2 || len(st.Workspaces) != 2 || st.Now.IsZero() {
		t.Fatalf("status: %+v %v", st, err)
	}
	for _, w := range st.Workspaces {
		if w.ID == home && !w.Local {
			t.Fatalf("the held person's home is not local: %+v", w)
		}
	}
}
