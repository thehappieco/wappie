package store_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
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
// send (a deletion from before the pause, and a deletion, a recovery and a
// purge from the period, DB10) and those it holds back for good (a pause
// and a stranding from the period), makes the round due again, and wakes
// every process.
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
	event := func(kind string) { t.Helper(); contractEvent(t, pool, tenant, kind, "") }
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
	for _, kind := range []string{"sync_paused", "stranded", "deleted", "recovered", "purged"} {
		event(kind)
	}
	if _, err := pool.Exec(ctx, `UPDATE contract_state SET round_generation = generation`); err != nil {
		t.Fatal(err)
	}

	ch, err = c.SetMode(ctx, store.ContractObserve)
	if err != nil || !ch.Changed || ch.ToSend != 4 || ch.HeldBack != 2 {
		t.Fatalf("the return to observe: %+v %v (want 4 to send, 2 held back)", ch, err)
	}
	back, _ := c.State(ctx)
	if !back.EventsFrom.Equal(*first.EventsFrom) || back.EventsPausedAt != nil || len(back.EventsOff) != 1 ||
		!back.EventsOff[0].From.Equal(*off.EventsPausedAt) || back.RoundGeneration != nil {
		t.Fatalf("after the return: %+v", back)
	}
}

// Status reads the counts contract status prints: the subs held and
// followed, the subscriptions, and each workspace's events: those eligible
// and undelivered (DB10's predicate: not one from before the first
// observe), parked, and folded into another.
func TestContractStatusRead(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	c := store.NewContract(pool)
	_, sub, home := heldPerson(t, pool)
	heldPerson(t, pool)
	gen := uuid.New()
	// Rows of the held person's workspace before the first observe, and
	// after it: one to send, one parked, one folded, one delivered.
	contractEvent(t, pool, home, "deleted", "")
	if _, err := c.SetMode(ctx, store.ContractObserve); err != nil {
		t.Fatal(err)
	}
	storeDocs(t, c, store.ContractAnswer, contractDoc(sub, gen, 1, "active", home), contractDoc(uuid.New(), gen, 1, "active", uuid.New()))
	if _, err := pool.Exec(ctx, `UPDATE contract_workspaces SET named_at = clock_timestamp() - interval '1 hour'`); err != nil {
		t.Fatal(err)
	}
	contractEvent(t, pool, home, "deleted", "")
	contractEvent(t, pool, home, "sync_paused", `parked_at = clock_timestamp(), reject_code = 'invalid_request'`)
	contractEvent(t, pool, home, "sync_paused", `settled_at = clock_timestamp(), outcome = 'coalesced', coalesced_into = gen_random_uuid()`)
	contractEvent(t, pool, home, "recovered", `settled_at = clock_timestamp(), outcome = 'accepted'`)
	st, err := c.Status(ctx)
	if err != nil || st.Held != 2 || st.Followed != 1 || st.Accounts != 2 || len(st.Workspaces) != 2 || st.Now.IsZero() {
		t.Fatalf("status: %+v %v", st, err)
	}
	for _, w := range st.Workspaces {
		if w.ID != home {
			if w.Local || w.Pending+w.Parked+w.Coalesced != 0 {
				t.Fatalf("a workspace Wappie does not have: %+v", w)
			}
			continue
		}
		if !w.Local || w.Pending != 1 || w.Parked != 1 || w.Coalesced != 1 {
			t.Fatalf("the held person's home: %+v, want local, 1 pending, 1 parked, 1 coalesced", w)
		}
	}
}

// A page's document Wappie cannot hold (invalid: a \u0000 escape, a
// revocation time ahead; kind_changed; or one the follower could not read)
// commits with the page, is recorded at ERROR by class, and forgets its
// sub's version, so the page's published_through no longer vouches for the
// older document Wappie still holds, and the round PUTs the sub again.
func TestContractPageForgetsRefusedDocuments(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	c := store.NewContract(pool)
	gen, team := uuid.New(), uuid.New()
	type person struct{ sub, home uuid.UUID }
	var people []person
	var docs []store.ContractDoc
	for range 5 {
		_, sub, home := heldPerson(t, pool)
		people = append(people, person{sub, home})
		docs = append(docs, contractDoc(sub, gen, 1, "active", home, store.ContractDocWorkspace{ID: team, Role: "member", Status: "open", WVersion: 1}))
	}
	old := dbClock(t, pool, "-2 hours")
	commit(ctx, t, c, store.ContractPage{After: 0, Generation: gen, NextAfter: 5, PublishedThrough: old, Docs: docs})
	for _, p := range people {
		if v, err := c.Vouched(ctx, store.FreshFor, p.sub); err != nil || v {
			t.Fatalf("an old published_through vouches: %v %v", v, err)
		}
	}

	nul := contractDoc(people[0].sub, gen, 2, "active", people[0].home)
	nul.Raw = []byte(`{"sub":"x","note":"\u0000"}`)
	ahead := revoked(contractDoc(people[1].sub, gen, 2, "disabled", people[1].home), dbClock(t, pool, "30 minutes"))
	// The team named as a personal workspace.
	clash := contractDoc(people[2].sub, gen, 2, "active", team)
	steps := []struct {
		name  string
		doc   *store.ContractDoc
		read  bool // the follower could not read it
		sub   uuid.UUID
		class string
	}{
		{"a \\u0000 escape", &nul, false, people[0].sub, store.ContractErrorDocumentInvalid},
		{"disabled_at ahead", &ahead, false, people[1].sub, store.ContractErrorDocumentInvalid},
		{"a kind clash", &clash, false, people[2].sub, store.ContractErrorKindChanged},
		{"unreadable", nil, true, people[3].sub, store.ContractErrorDocumentInvalid},
	}
	for i, s := range steps {
		if _, err := pool.Exec(ctx, `UPDATE contract_state SET error_class = NULL, error_at = NULL`); err != nil {
			t.Fatal(err)
		}
		p := store.ContractPage{After: int64(5 + i), SeenGeneration: &gen, Generation: gen, NextAfter: int64(6 + i),
			PublishedThrough: dbClock(t, pool, "0")}
		if s.doc != nil {
			p.Docs = []store.ContractDoc{*s.doc}
		}
		if s.read {
			p.Unreadable = []uuid.UUID{s.sub}
		}
		res := commit(ctx, t, c, p)
		st, err := c.State(ctx)
		if err != nil || !res.Committed || !res.Vouched || st.FeedCursor != p.NextAfter || st.ErrorClass != s.class || st.ErrorAt == nil {
			t.Fatalf("%s: %+v, state %+v %v", s.name, res, st, err)
		}
		a := readAccount(t, pool, s.sub)
		if a.Version != nil || a.Generation != nil || a.DocVersion == nil || *a.DocVersion != 1 {
			t.Fatalf("%s: the account %+v, want its version forgotten and its document kept", s.name, a)
		}
		if v, err := c.Vouched(ctx, store.FreshFor, s.sub); err != nil || v {
			t.Fatalf("%s: published_through vouches for a document Wappie could not hold: %v %v", s.name, v, err)
		}
		if fresh, err := c.Fresh(ctx, store.FreshFor, s.sub); err != nil || fresh[s.sub] {
			t.Fatalf("%s: fresh: %v %v", s.name, fresh, err)
		}
		if subs, err := c.Unsubscribed(ctx, 10); err != nil || !slices.Contains(subs, s.sub) {
			t.Fatalf("%s: the round would not PUT it again: %v %v", s.name, subs, err)
		}
	}
	// The pages still vouch for the sub none of them refused.
	if v, err := c.Vouched(ctx, store.FreshFor, people[4].sub); err != nil || !v {
		t.Fatalf("a sub no page refused: %v %v", v, err)
	}
}

// contractEvent writes an item_events row of kind in tenant with the columns
// its type needs, then sets extra (an UPDATE's SET list) on it.
func contractEvent(t *testing.T, pool *pgxpool.Pool, tenant uuid.UUID, kind, extra string) {
	t.Helper()
	ctx := context.Background()
	if err := pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		id := uuid.New()
		if _, err := tx.Exec(ctx, `INSERT INTO item_events (event_id, tenant_id, type, item_id, dedupe_key, occurred_at, actor_kind,
			deleted_at, purge_after, ledgered_at, person_sub, cause)
			VALUES ($1, $2, $3, $4, $5, clock_timestamp(), 'person',
			CASE WHEN $3 IN ('deleted', 'recovered', 'purged') THEN clock_timestamp() END,
			CASE WHEN $3 IN ('deleted', 'purged') THEN clock_timestamp() + interval '30 days' END,
			clock_timestamp(), NULL, CASE WHEN $3 = 'stranded' THEN 'revoked' END)`,
			id, tenant, kind, uuid.New(), uuid.NewString()); err != nil {
			return err
		}
		if extra == "" {
			return nil
		}
		_, err := tx.Exec(ctx, `UPDATE item_events SET `+extra+` WHERE event_id = $1`, id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// The due-now on naming (the plan's 4.7, "Round 2, recovery"): a document,
// an answer or a held sub's page, that names a workspace the platform
// refused (not_found, parked for it or not) makes its snapshot and queue
// due now with their tries reset, and releases the not_found park; a park
// for another reason (invalid_request, a Wappie bug) stays; a workspace
// with an accepted snapshot and nothing refused is left as it is, unless
// the document changes its members (the sub's role there), which makes its
// snapshot due; and an unheld sub's page makes nothing due.
func TestContractNamingMakesDue(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	c := store.NewContract(pool)
	_, sub, home := heldPerson(t, pool)
	gen := uuid.New()
	refused, refusedParked, parked, parkedNever, accepted := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	team := func(id uuid.UUID, role string) store.ContractDocWorkspace {
		return store.ContractDocWorkspace{ID: id, Role: role, Status: "open", WVersion: 1}
	}
	doc := func(v int64, role string) store.ContractDoc {
		return contractDoc(sub, gen, v, "active", home, team(refused, "member"), team(refusedParked, "member"), team(parked, "member"),
			team(parkedNever, "member"), team(accepted, role))
	}
	storeDocs(t, c, store.ContractAnswer, doc(1, "member"))
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	reset := func() {
		t.Helper()
		exec(`UPDATE contract_workspaces SET snapshot_ok_at = clock_timestamp() - interval '10 minutes',
			snapshot_due_at = clock_timestamp() + interval '1 hour', snapshot_tries = 3,
			events_due_at = clock_timestamp() + interval '1 hour', events_tries = 2, not_found_since = NULL, parked_at = NULL`)
		exec(`UPDATE contract_workspaces SET not_found_since = clock_timestamp() - interval '1 hour' WHERE workspace_id = $1`, refused)
		exec(`UPDATE contract_workspaces SET not_found_since = clock_timestamp() - interval '2 days',
			parked_at = clock_timestamp() - interval '1 day' WHERE workspace_id = $1`, refusedParked)
		exec(`UPDATE contract_workspaces SET parked_at = clock_timestamp() - interval '1 day' WHERE workspace_id = $1`, parked)
		// Parked for invalid_request before any snapshot was accepted.
		exec(`UPDATE contract_workspaces SET parked_at = clock_timestamp() - interval '1 day', snapshot_ok_at = NULL
			WHERE workspace_id = $1`, parkedNever)
	}
	type row struct {
		due, eventsDue, notFound, parked bool
		tries, eventsTries               int
	}
	read := func(id uuid.UUID) row {
		t.Helper()
		var r row
		if err := pool.QueryRow(ctx, `SELECT snapshot_due_at <= clock_timestamp(), events_due_at <= clock_timestamp(),
			not_found_since IS NOT NULL, parked_at IS NOT NULL, snapshot_tries, events_tries
			FROM contract_workspaces WHERE workspace_id = $1`, id).Scan(&r.due, &r.eventsDue, &r.notFound, &r.parked, &r.tries, &r.eventsTries); err != nil {
			t.Fatal(err)
		}
		return r
	}
	back := row{due: true, eventsDue: true}
	untouched := row{notFound: false, tries: 3, eventsTries: 2}
	for _, from := range []store.ContractSource{store.ContractAnswer, store.ContractFeed} {
		reset()
		// The same version again: kept.
		if out := storeDocs(t, c, from, doc(1, "member")); out[0] != store.ContractDocKept {
			t.Fatalf("source %d: %v", from, out)
		}
		for id, want := range map[uuid.UUID]row{
			refused: back, refusedParked: back,
			parked:      {parked: true, tries: 3, eventsTries: 2},
			parkedNever: {due: true, eventsDue: true, parked: true},
			accepted:    untouched, home: untouched,
		} {
			if got := read(id); got != want {
				t.Fatalf("source %d, workspace %s: %+v, want %+v", from, id, got, want)
			}
		}
	}

	// The sub's role changes in one workspace: its snapshot is due, its
	// tries as they were (no refusal ended), the others untouched.
	reset()
	exec(`UPDATE contract_workspaces SET not_found_since = NULL, parked_at = NULL, snapshot_ok_at = clock_timestamp()`)
	storeDocs(t, c, store.ContractFeed, doc(2, "admin"))
	if got := read(accepted); !got.due || got.eventsDue || got.tries != 3 {
		t.Fatalf("a role change: %+v", got)
	}
	if got := read(home); got != untouched {
		t.Fatalf("a workspace the change leaves alone: %+v", got)
	}
	// An unchanged document leaves every snapshot where it is.
	reset()
	exec(`UPDATE contract_workspaces SET not_found_since = NULL, parked_at = NULL, snapshot_ok_at = clock_timestamp()`)
	storeDocs(t, c, store.ContractFeed, doc(3, "admin"))
	for _, id := range []uuid.UUID{refused, accepted, home} {
		if got := read(id); got != untouched {
			t.Fatalf("an unchanged document's workspace %s: %+v", id, got)
		}
	}

	// A page's document of a sub Wappie does not hold makes nothing due.
	reset()
	storeDocs(t, c, store.ContractFeed, contractDoc(uuid.New(), gen, 1, "active", uuid.New(), team(refused, "owner"), team(accepted, "owner")))
	if got := read(refused); got != (row{notFound: true, tries: 3, eventsTries: 2}) {
		t.Fatalf("an unheld sub's page made a refused workspace due: %+v", got)
	}
	if got := read(accepted); got != untouched {
		t.Fatalf("an unheld sub's page changed a workspace's members: %+v", got)
	}
}

// A held sub's document kept because Wappie stores a newer one records the
// stored one's workspaces: the page stored it while the sub was not held
// (a sign-up's PUT answered, then the feed carried a newer version before
// the account was committed with the older answer), and no later document
// need name them again.
func TestContractKeptDocumentRecordsItsWorkspaces(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	c := store.NewContract(pool)
	sub, home, team, clash := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	gen := uuid.New()
	newer := contractDoc(sub, gen, 6, "active", home, store.ContractDocWorkspace{ID: team, Role: "member", Status: "open", WVersion: 4},
		store.ContractDocWorkspace{ID: clash, Role: "member", Status: "open", WVersion: 4})
	if out := storeDocs(t, c, store.ContractFeed, newer); out[0] != store.ContractDocStored {
		t.Fatalf("the unheld sub's page: %v", out)
	}
	if _, ok := workspaceStatus(t, c, team); ok {
		t.Fatal("an unheld sub's page recorded its team")
	}
	// Meanwhile another document recorded one of its teams as personal.
	if _, err := pool.Exec(ctx, `INSERT INTO contract_workspaces (workspace_id, kind) VALUES ($1, 'personal')`, clash); err != nil {
		t.Fatal(err)
	}
	// The account is committed, with the PUT's older answer.
	user := uuid.New()
	if err := pg.InTenantTx(ctx, pool, home.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO users (id, tenant_id, email, public_key, role, auth_source)
			VALUES ($1, $2, $3, $4, 'owner', 'platform')`, user, home, user.String()[:8]+"@example.com", platformBytes(t, 32))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO platform_identities (sub, user_id, email, linked_from) VALUES ($1, $2, $3, 'new')`,
		sub, user, sub.String()[:8]+"@id.test"); err != nil {
		t.Fatal(err)
	}
	if out := storeDocs(t, c, store.ContractAnswer, contractDoc(sub, gen, 5, "active", home)); out[0] != store.ContractDocKept {
		t.Fatalf("the older answer: %v", out)
	}
	if a := readAccount(t, pool, sub); *a.Version != 6 || a.FreshAt == nil {
		t.Fatalf("the account: %+v", a)
	}
	w, ok := workspaceStatus(t, c, team)
	if !ok || w.Kind != "team" || w.WVersion != 4 || w.Status != "open" {
		t.Fatalf("the stored document's team: %+v recorded %v", w, ok)
	}
	if _, ok := workspaceStatus(t, c, home); !ok {
		t.Fatal("the answer's personal workspace was not recorded")
	}
	// The team whose kind clashes is not recorded over, and the clash is
	// an ERROR contract status reports.
	if w, _ := workspaceStatus(t, c, clash); w.Kind != "personal" || w.WVersion != 0 || w.Status != "" {
		t.Fatalf("a clashing workspace was recorded over: %+v", w)
	}
	if s, _ := c.State(ctx); s.ErrorClass != store.ContractErrorKindChanged {
		t.Fatalf("the clash was not recorded: %+v", s)
	}
	var due bool
	if err := pool.QueryRow(ctx, `SELECT snapshot_due_at <= clock_timestamp() FROM contract_workspaces WHERE workspace_id = $1`, team).Scan(&due); err != nil || !due {
		t.Fatalf("the team recorded is not due (%v)", err)
	}
}

// The round's failing passes: the first one starts the run and each
// keeps the latest class; the pass that leaves none ends it.
func TestContractRoundFailed(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	c := store.NewContract(pool)
	_, sub, home := heldPerson(t, pool)
	if err := c.RoundFailed(ctx, "unavailable"); err != nil {
		t.Fatal(err)
	}
	first, _ := c.State(ctx)
	if first.RoundError != "unavailable" || first.RoundErrorAt == nil {
		t.Fatalf("after a failing pass: %+v", first)
	}
	if err := c.RoundFailed(ctx, "refused:not_found"); err != nil {
		t.Fatal(err)
	}
	if s, _ := c.State(ctx); s.RoundError != "refused:not_found" || !s.RoundErrorAt.Equal(*first.RoundErrorAt) {
		t.Fatalf("a second failing pass: %+v", s)
	}
	gen := uuid.New()
	storeDocs(t, c, store.ContractAnswer, contractDoc(sub, gen, 1, "active", home))
	if done, err := c.RoundDone(ctx, gen); err != nil || !done {
		t.Fatalf("the round done: %v %v", done, err)
	}
	if s, _ := c.State(ctx); s.RoundError != "" || s.RoundErrorAt != nil {
		t.Fatalf("a done round keeps its failure: %+v", s)
	}
}
