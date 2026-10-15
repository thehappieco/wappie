package store_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/migrate"
	"whatserver2/internal/obs"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
)

// The contract's store (0051): its state, the documents stored per sub,
// the workspaces they name, the intent rows and freshness (the plan's 4.4
// to 4.9, DB8 and DB21).

// contractDoc is a document for sub of generation gen at version v, its
// personal workspace first, then teams, each {id, role, status, wversion}.
func contractDoc(sub, gen uuid.UUID, v int64, status string, personal uuid.UUID, teams ...store.ContractDocWorkspace) store.ContractDoc {
	d := store.ContractDoc{Sub: sub, Generation: gen, Version: v, Status: status,
		Workspaces: []store.ContractDocWorkspace{{ID: personal, Kind: "personal", Role: "owner", Status: "open", WVersion: 1}}}
	for _, w := range teams {
		w.Kind = "team"
		d.Workspaces = append(d.Workspaces, w)
	}
	type ws struct {
		ID       string `json:"id"`
		Kind     string `json:"kind"`
		Role     string `json:"role"`
		Status   string `json:"status"`
		WVersion int64  `json:"wversion"`
	}
	raw := struct {
		V          int    `json:"v"`
		Sub        string `json:"sub"`
		Generation string `json:"generation"`
		Version    int64  `json:"version"`
		Status     string `json:"status"`
		Workspaces []ws   `json:"workspaces"`
	}{1, sub.String(), gen.String(), v, status, nil}
	for _, w := range d.Workspaces {
		raw.Workspaces = append(raw.Workspaces, ws{w.ID.String(), w.Kind, w.Role, w.Status, w.WVersion})
	}
	d.Raw, _ = json.Marshal(raw)
	return d
}

func storeDocs(t *testing.T, c *store.Contract, from store.ContractSource, docs ...store.ContractDoc) []store.ContractDocOutcome {
	t.Helper()
	out, err := c.StoreDocuments(context.Background(), from, docs...)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// account is a contract_accounts row as a test reads it.
type account struct {
	Version     *int64
	Generation  *uuid.UUID
	Status      *string
	DocVersion  *int64
	Disabled    *time.Time
	Sessions    *time.Time
	Credentials *time.Time
	FreshAt     *time.Time
}

func readAccount(t *testing.T, pool *pgxpool.Pool, sub uuid.UUID) account {
	t.Helper()
	var a account
	if err := pool.QueryRow(context.Background(), `SELECT version, generation, status, (doc->>'version')::bigint, disabled_at,
		sessions_revoked_at, credentials_revoked_at, fresh_at FROM contract_accounts WHERE sub = $1`, sub).
		Scan(&a.Version, &a.Generation, &a.Status, &a.DocVersion, &a.Disabled, &a.Sessions, &a.Credentials, &a.FreshAt); err != nil {
		t.Fatal(err)
	}
	return a
}

// revoked gives d's three revocation times as at.
func revoked(d store.ContractDoc, at time.Time) store.ContractDoc {
	d.DisabledAt, d.SessionsRevokedAt, d.CredentialsRevokedAt = &at, &at, &at
	return d
}

// revokedAt reports whether a's three revocation times are all at.
func (a account) revokedAt(at time.Time) bool {
	for _, got := range []*time.Time{a.Disabled, a.Sessions, a.Credentials} {
		if got == nil || !got.Equal(at) {
			return false
		}
	}
	return true
}

// restart leaves the state as P3b's restart will, for a new generation it
// returns: the stored generation replaced, the cursor and published_through
// reset, and every row's version and freshness forgotten.
func restart(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	gen := uuid.New()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `UPDATE contract_state SET generation = $1, feed_cursor = 0, published_through = NULL`, gen); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE contract_accounts SET generation = NULL, version = NULL, fresh_at = NULL`); err != nil {
		t.Fatal(err)
	}
	return gen
}

// dbClock is the database's clock moved by offset, an interval.
func dbClock(t *testing.T, pool *pgxpool.Pool, offset string) time.Time {
	t.Helper()
	var at time.Time
	if err := pool.QueryRow(context.Background(), `SELECT clock_timestamp() + $1::interval`, offset).Scan(&at); err != nil {
		t.Fatal(err)
	}
	return at
}

func TestContractState(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	c := store.NewContract(pool)
	// The contract is on in every mode but off, the modes a later release
	// adds included: none of them gates as off.
	for mode, on := range map[string]bool{store.ContractOff: false, store.ContractObserve: true, "enforce": true} {
		if (store.ContractState{Mode: mode}).On() != on {
			t.Errorf("mode %s: on %v", mode, !on)
		}
	}
	s, err := c.State(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if s.Mode != store.ContractOff || s.Observed() || s.Generation != nil || s.EventsPausedAt != nil || len(s.EventsOff) != 0 ||
		s.FeedCursor != 0 || s.PublishedThrough != nil || s.MailFrom.IsZero() {
		t.Fatalf("a new installation's state: %+v", s)
	}
	// Observed, then off, then observed again: one off period.
	for _, q := range []string{
		`UPDATE contract_state SET mode='observe', events_from=clock_timestamp()`,
		`UPDATE contract_state SET mode='off', events_paused_at=clock_timestamp()`,
		`UPDATE contract_state SET mode='observe', events_off = events_off + tstzmultirange(tstzrange(events_paused_at, clock_timestamp())),
			events_paused_at=NULL`,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if s, err = c.State(ctx); err != nil {
		t.Fatal(err)
	}
	if s.Mode != store.ContractObserve || !s.Observed() || len(s.EventsOff) != 1 || !s.EventsOff[0].From.Before(s.EventsOff[0].To) ||
		s.EventsOff[0].From.Before(*s.EventsFrom) {
		t.Fatalf("after an off period: %+v", s)
	}
}

// TestContractDocuments stores answers as every PUT and GET does: the
// first adopts the generation, a newer version replaces the stored one,
// the same or a lower one is kept but still refreshes the sub (DB8),
// revocation times only rise, in any document and across a new
// generation, a workspace's status moves only with its wversion, and
// another generation stores nothing and wakes the contract loops.
func TestContractDocuments(t *testing.T) {
	backends := &pgtest.Backends{}
	pool := pgtest.FreshWith(t, migrate.Run, backends.Configure)
	ctx := context.Background()
	c := store.NewContract(pool)
	gen, sub, home, team := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	member := store.ContractDocWorkspace{ID: team, Role: "member", Status: "open", WVersion: 3}
	answer := func(d store.ContractDoc) store.ContractDocOutcome {
		t.Helper()
		return storeDocs(t, c, store.ContractAnswer, d)[0]
	}

	if got := answer(contractDoc(sub, gen, 5, "active", home, member)); got != store.ContractDocStored {
		t.Fatalf("the first document: %v", got)
	}
	s, err := c.State(ctx)
	if err != nil || s.Generation == nil || *s.Generation != gen || s.GenerationConfirmed {
		t.Fatalf("the first document's generation: %+v %v", s, err)
	}
	first := readAccount(t, pool, sub)
	if first.Version == nil || *first.Version != 5 || *first.Generation != gen || *first.Status != "active" || *first.DocVersion != 5 ||
		first.FreshAt == nil {
		t.Fatalf("the stored document: %+v", first)
	}
	for id, kind := range map[uuid.UUID]string{home: "personal", team: "team"} {
		w, ok, err := c.Workspace(ctx, id)
		if err != nil || !ok || w.Kind != kind || w.Status != "open" {
			t.Fatalf("the record of %s: %+v %v %v", kind, w, ok, err)
		}
	}
	if _, ok, err := c.Workspace(ctx, uuid.New()); ok || err != nil {
		t.Fatalf("a workspace no document named: %v %v", ok, err)
	}

	// The same version, and a lower one: kept, and fresh again.
	for _, v := range []int64{5, 4} {
		before := readAccount(t, pool, sub)
		lower := contractDoc(sub, gen, v, "disabled", home, store.ContractDocWorkspace{ID: team, Role: "owner", Status: "closed", WVersion: 4})
		if got := answer(lower); got != store.ContractDocKept {
			t.Fatalf("version %d: %v", v, got)
		}
		after := readAccount(t, pool, sub)
		if *after.Version != 5 || *after.Status != "active" || *after.DocVersion != 5 || !after.FreshAt.After(*before.FreshAt) {
			t.Fatalf("version %d over 5: %+v (before %+v)", v, after, before)
		}
	}
	// A kept document still names its workspaces: the team's status moved
	// with the higher wversion it carried.
	if w, _, _ := c.Workspace(ctx, team); w.Status != "closed" || w.WVersion != 4 {
		t.Fatalf("the team after a kept document with wversion 4: %+v", w)
	}

	// A newer one replaces it, with its three revocation times, and a lower
	// wversion moves no status.
	early, revokedAt, later, latest := dbClock(t, pool, "-3 hours"), dbClock(t, pool, "-2 hours"),
		dbClock(t, pool, "-1 hour"), dbClock(t, pool, "-30 minutes")
	newer := revoked(contractDoc(sub, gen, 9, "disabled", home, store.ContractDocWorkspace{ID: team, Role: "admin", Status: "open", WVersion: 2}), revokedAt)
	if got := answer(newer); got != store.ContractDocStored {
		t.Fatalf("version 9: %v", got)
	}
	if a := readAccount(t, pool, sub); *a.Version != 9 || !a.revokedAt(revokedAt) {
		t.Fatalf("version 9's revocation times: %+v", a)
	}
	// Then they only rise: not undone by a document without them, nor
	// lowered by a newer one with earlier ones.
	if got := answer(contractDoc(sub, gen, 10, "active", home, member)); got != store.ContractDocStored {
		t.Fatalf("version 10: %v", got)
	}
	if got := answer(revoked(contractDoc(sub, gen, 11, "active", home, member), early)); got != store.ContractDocStored {
		t.Fatalf("version 11: %v", got)
	}
	a := readAccount(t, pool, sub)
	if *a.Version != 11 || *a.Status != "active" || !a.revokedAt(revokedAt) {
		t.Fatalf("after versions 10 and 11, with no times and earlier ones: %+v", a)
	}
	if w, _, _ := c.Workspace(ctx, team); w.Status != "closed" || w.WVersion != 4 {
		t.Fatalf("the team after lower wversions: %+v", w)
	}
	// A later one raises them, from a newer document or a kept one.
	if got := answer(revoked(contractDoc(sub, gen, 12, "active", home, member), later)); got != store.ContractDocStored {
		t.Fatalf("version 12: %v", got)
	}
	if a := readAccount(t, pool, sub); !a.revokedAt(later) {
		t.Fatalf("version 12's later times: %+v", a)
	}
	if got := answer(revoked(contractDoc(sub, gen, 12, "active", home, member), latest)); got != store.ContractDocKept {
		t.Fatalf("version 12 again: %v", got)
	}
	if a := readAccount(t, pool, sub); *a.Version != 12 || !a.revokedAt(latest) {
		t.Fatalf("a kept document's later times: %+v", a)
	}

	// A new generation, adopted as the restart leaves the row (versions
	// and freshness forgotten): its first document is stored as new, and
	// earlier times undo nothing (README 7.4).
	restored := restart(t, pool)
	if got := answer(revoked(contractDoc(sub, restored, 1, "active", home, member), early)); got != store.ContractDocStored {
		t.Fatalf("the new generation's first document: %v", got)
	}
	if a := readAccount(t, pool, sub); *a.Version != 1 || *a.Generation != restored || a.FreshAt == nil || !a.revokedAt(latest) {
		t.Fatalf("after the new generation's first document: %+v", a)
	}

	// Another generation: nothing stored or refreshed, and the loops woken.
	listener, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Release()
	if _, err := listener.Exec(ctx, `LISTEN `+store.ContractModeChannel); err != nil {
		t.Fatal(err)
	}
	before := readAccount(t, pool, sub)
	if got := answer(contractDoc(sub, uuid.New(), 11, "closed", home)); got != store.ContractDocOtherGeneration {
		t.Fatalf("another generation: %v", got)
	}
	if after := readAccount(t, pool, sub); *after.Version != 1 || !after.FreshAt.Equal(*before.FreshAt) {
		t.Fatalf("another generation changed the row: %+v", after)
	}
	// Only this test's own notice counts: other packages' tests send it too.
	wait, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := backends.Notice(wait, listener.Conn(), store.ContractModeChannel, "generation"); err != nil {
		t.Fatalf("no wake for another generation: %v", err)
	}
}

// A feed page's documents are stored as an answer's are, but refresh
// nobody, newer or kept, on a new row or after a restart: a page vouches
// for its subs only through published_through (DB8; README 6.3), so a
// backlog a stalled publisher replays never makes a sub fresh.
func TestContractFeedDocuments(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	c := store.NewContract(pool)
	gen, sub, unseen, home := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	stale := func(step string, subs ...uuid.UUID) {
		t.Helper()
		got, err := c.Fresh(ctx, store.FreshFor, subs...)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range subs {
			if got[s] {
				t.Fatalf("%s: %s is fresh", step, s)
			}
		}
	}
	storeDocs(t, c, store.ContractAnswer, contractDoc(sub, gen, 1, "active", home))
	if _, err := pool.Exec(ctx, `UPDATE contract_accounts SET fresh_at = clock_timestamp() - interval '2 hours'`); err != nil {
		t.Fatal(err)
	}
	aged := readAccount(t, pool, sub).FreshAt

	if got := storeDocs(t, c, store.ContractFeed, contractDoc(sub, gen, 2, "active", home), contractDoc(unseen, gen, 7, "active", uuid.New())); !slices.Equal(got,
		[]store.ContractDocOutcome{store.ContractDocStored, store.ContractDocStored}) {
		t.Fatalf("a page: %v", got)
	}
	if a := readAccount(t, pool, sub); *a.Version != 2 || !a.FreshAt.Equal(*aged) {
		t.Fatalf("a page's newer document: %+v, fresh_at was %v", a, aged)
	}
	if a := readAccount(t, pool, unseen); *a.Version != 7 || a.FreshAt != nil {
		t.Fatalf("a page's document for a sub with no row: %+v", a)
	}
	if got := storeDocs(t, c, store.ContractFeed, contractDoc(sub, gen, 2, "active", home)); got[0] != store.ContractDocKept {
		t.Fatalf("a page's same version: %v", got)
	}
	if a := readAccount(t, pool, sub); !a.FreshAt.Equal(*aged) {
		t.Fatalf("a page's kept document: %+v, fresh_at was %v", a, aged)
	}
	stale("after pages", sub, unseen)

	// After a restart the first page's documents are not fresh until the
	// round's PUTs answer (the plan's 4.7).
	restored := restart(t, pool)
	if got := storeDocs(t, c, store.ContractFeed, contractDoc(sub, restored, 1, "active", home)); got[0] != store.ContractDocStored {
		t.Fatalf("the first page after a restart: %v", got)
	}
	if a := readAccount(t, pool, sub); *a.Version != 1 || a.FreshAt != nil {
		t.Fatalf("the first page's document after a restart: %+v", a)
	}
	stale("after the first page of a new generation", sub)
	storeDocs(t, c, store.ContractAnswer, contractDoc(sub, restored, 1, "active", home))
	if got, err := c.Fresh(ctx, store.FreshFor, sub); err != nil || !got[sub] {
		t.Fatalf("the round's answer: %v %v", got, err)
	}
	if _, err := c.StoreDocuments(ctx, 0, contractDoc(sub, restored, 2, "active", home)); err == nil {
		t.Fatal("documents of no source were stored")
	}
}

// A document the database would not hold as received, or one whose
// revocation times are past its clock, is refused alone, by sub at ERROR:
// the rest of its batch is stored, and a page is never stuck on it.
func TestContractDocumentInvalid(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	c := store.NewContract(pool)
	var logged bytes.Buffer
	ctx := obs.WithLogger(context.Background(), slog.New(slog.NewTextHandler(&logged, nil)))
	gen := uuid.New()
	for _, raw := range []struct{ name, json string }{
		{"a NUL escape", `{"v":1,"x":"a\u0000b"}`},
		{"a lone high surrogate", `{"v":1,"x":"\ud800"}`},
		{"a lone low surrogate", `{"v":1,"x":"\udc00"}`},
		{"a number past numeric", `{"v":1,"x":1e1000000}`},
		{"invalid UTF-8", "{\"v\":1,\"x\":\"\xff\xfe\"}"},
		{"an array", `[{"v":1}]`},
		{"not JSON", `{"v":1,`},
	} {
		logged.Reset()
		bad, good := contractDoc(uuid.New(), gen, 1, "active", uuid.New()), contractDoc(uuid.New(), gen, 1, "active", uuid.New())
		bad.Raw = []byte(raw.json)
		out, err := c.StoreDocuments(ctx, store.ContractFeed, bad, good)
		if err != nil || !slices.Equal(out, []store.ContractDocOutcome{store.ContractDocInvalid, store.ContractDocStored}) {
			t.Fatalf("%s: %v %v", raw.name, out, err)
		}
		var rows int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM contract_accounts WHERE sub = $1`, bad.Sub).Scan(&rows); err != nil || rows != 0 {
			t.Fatalf("%s: %d rows for the refused document (%v)", raw.name, rows, err)
		}
		if _, ok, _ := c.Workspace(ctx, bad.Workspaces[0].ID); ok {
			t.Fatalf("%s: a refused document recorded its workspace", raw.name)
		}
		if !strings.Contains(logged.String(), `level=ERROR msg="contract: a document cannot be stored" sub=`+bad.Sub.String()) ||
			!strings.Contains(logged.String(), "reason=json") {
			t.Fatalf("%s: the ERROR: %q", raw.name, logged.String())
		}
	}

	// Revocation times past the database's clock: they would be kept for
	// good. Within the skew they are taken.
	for _, field := range []string{"disabled_at", "sessions_revoked_at", "credentials_revoked_at"} {
		logged.Reset()
		ahead, near := contractDoc(uuid.New(), gen, 1, "disabled", uuid.New()), contractDoc(uuid.New(), gen, 1, "disabled", uuid.New())
		future, soon := dbClock(t, pool, "1 hour"), dbClock(t, pool, "1 minute")
		switch field {
		case "disabled_at":
			ahead.DisabledAt, near.DisabledAt = &future, &soon
		case "sessions_revoked_at":
			ahead.SessionsRevokedAt, near.SessionsRevokedAt = &future, &soon
		default:
			ahead.CredentialsRevokedAt, near.CredentialsRevokedAt = &future, &soon
		}
		out, err := c.StoreDocuments(ctx, store.ContractAnswer, ahead, near)
		if err != nil || !slices.Equal(out, []store.ContractDocOutcome{store.ContractDocInvalid, store.ContractDocStored}) {
			t.Fatalf("%s ahead of the clock: %v %v", field, out, err)
		}
		if got, err := c.Fresh(ctx, store.FreshFor, ahead.Sub, near.Sub); err != nil || got[ahead.Sub] || !got[near.Sub] {
			t.Fatalf("%s ahead of the clock: fresh %v %v", field, got, err)
		}
		if !strings.Contains(logged.String(), "sub="+ahead.Sub.String()) || !strings.Contains(logged.String(), "reason="+field+"_ahead") {
			t.Fatalf("%s ahead of the clock: the ERROR: %q", field, logged.String())
		}
	}
}

// A document stored while an Intend for its sub inserts the row (a sign-in
// beside the round, right after a re-up) waits for it instead of failing
// on its key.
func TestContractDocumentsBesideAnIntend(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	c := store.NewContract(pool)
	sub := uuid.New()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Intend's statement, not committed yet.
	if _, err := tx.Exec(ctx, `INSERT INTO contract_accounts (sub) VALUES ($1)
		ON CONFLICT (sub) DO UPDATE SET subscribed_at = clock_timestamp()`, sub); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := c.StoreDocuments(ctx, store.ContractAnswer, contractDoc(sub, uuid.New(), 1, "active", uuid.New()))
		done <- err
	}()
	// The store waits on the uncommitted row before it is let through.
	deadline := time.Now().Add(20 * time.Second)
	for {
		var waiting bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity
			WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE '%contract_accounts%')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the store never waited on the intent's row")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("a document stored beside an Intend: %v", err)
	}
	if a := readAccount(t, pool, sub); a.Version == nil || *a.Version != 1 || a.FreshAt == nil {
		t.Fatalf("the document stored beside an Intend: %+v", a)
	}
}

// A document that names a workspace with another kind than Wappie recorded
// for it, or than the local workspace of that id has, is not stored, and
// says so at ERROR, by ids only (README 6.2).
func TestContractDocumentKindChanged(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	c := store.NewContract(pool)
	var logged bytes.Buffer
	ctx := obs.WithLogger(context.Background(), slog.New(slog.NewTextHandler(&logged, nil)))
	gen, team := uuid.New(), uuid.New()
	local := uuid.MustParse(newTenant(t, pool, "Piloto A"))
	one, two, three := uuid.New(), uuid.New(), uuid.New()
	out, err := c.StoreDocuments(ctx, store.ContractAnswer, contractDoc(one, gen, 1, "active", uuid.New(), store.ContractDocWorkspace{ID: team, Role: "owner", Status: "open", WVersion: 1}))
	if err != nil || out[0] != store.ContractDocStored {
		t.Fatalf("the first document: %v %v", out, err)
	}
	// The team named as someone's personal workspace, and a local team
	// named as one.
	out, err = c.StoreDocuments(ctx, store.ContractAnswer, contractDoc(two, gen, 1, "active", team), contractDoc(three, gen, 1, "active", local))
	if err != nil || !slices.Equal(out, []store.ContractDocOutcome{store.ContractDocKindChanged, store.ContractDocKindChanged}) {
		t.Fatalf("documents with a kind changed: %v %v", out, err)
	}
	var stored int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM contract_accounts WHERE sub = ANY($1)`, []uuid.UUID{two, three}).Scan(&stored); err != nil || stored != 0 {
		t.Fatalf("%d documents with a kind changed were stored (%v)", stored, err)
	}
	if _, ok, _ := c.Workspace(ctx, local); ok {
		t.Fatal("a refused document recorded its workspace")
	}
	if n := strings.Count(logged.String(), "level=ERROR msg=\"contract: workspace kind changed"); n != 2 ||
		!strings.Contains(logged.String(), team.String()) || !strings.Contains(logged.String(), local.String()) {
		t.Fatalf("the ERRORs: %q", logged.String())
	}
	if strings.Contains(logged.String(), "Piloto") {
		t.Fatalf("a log line names a workspace: %q", logged.String())
	}

	// The workspaces Wappie holds, named with their own kinds, are the
	// usual case: a person's personal workspace and a local team, each with
	// the platform's id, as the pilot holds its owner's and TBFG.
	u, err := store.NewUsers(pool).Create(ctx, store.NewUser{TenantID: local, Email: "dono@example.test", Role: "owner", AuthKey: "test",
		KDFSalt: make([]byte, 16), KDFParams: store.DefaultKDFParams(), PublicKey: make([]byte, 32), WrappedUSK: []byte("wrapped")})
	if err != nil {
		t.Fatal(err)
	}
	var personal uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE personal_owner_id = $1`, u.ID).Scan(&personal); err != nil {
		t.Fatal(err)
	}
	logged.Reset()
	out, err = c.StoreDocuments(ctx, store.ContractAnswer, contractDoc(uuid.New(), gen, 1, "active", personal,
		store.ContractDocWorkspace{ID: local, Role: "owner", Status: "open", WVersion: 1}))
	if err != nil || !slices.Equal(out, []store.ContractDocOutcome{store.ContractDocStored}) {
		t.Fatalf("a document naming the workspaces Wappie holds: %v %v", out, err)
	}
	for id, kind := range map[uuid.UUID]string{personal: "personal", local: "team"} {
		if w, ok, err := c.Workspace(ctx, id); err != nil || !ok || w.Kind != kind {
			t.Fatalf("the record of the local %s: %+v %v %v", kind, w, ok, err)
		}
	}
	if strings.Contains(logged.String(), "level=ERROR") {
		t.Fatalf("a document naming the workspaces Wappie holds: %q", logged.String())
	}

	// Two documents of one batch that disagree on a new workspace: the one
	// first in sub order records it, the other is refused.
	shared := uuid.New()
	lo, hi := uuid.New(), uuid.New()
	if bytes.Compare(lo[:], hi[:]) > 0 {
		lo, hi = hi, lo
	}
	out, err = c.StoreDocuments(ctx, store.ContractAnswer, contractDoc(hi, gen, 1, "active", shared),
		contractDoc(lo, gen, 1, "active", uuid.New(), store.ContractDocWorkspace{ID: shared, Role: "member", Status: "open", WVersion: 1}))
	if err != nil || !slices.Equal(out, []store.ContractDocOutcome{store.ContractDocKindChanged, store.ContractDocStored}) {
		t.Fatalf("a batch that disagrees: %v %v", out, err)
	}
	if w, _, _ := c.Workspace(ctx, shared); w.Kind != "team" {
		t.Fatalf("the shared workspace: %+v", w)
	}
}

// TestContractFreshness is DB8's rule: a sub is fresh while its last
// validated document, or the last trusted published_through, is under the
// window old, the latter only for a sub the platform follows in the stored
// generation; an unknown sub never is.
func TestContractFreshness(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	c := store.NewContract(pool)
	gen, followed, unknown := uuid.New(), uuid.New(), uuid.New()
	storeDocs(t, c, store.ContractAnswer, contractDoc(followed, gen, 1, "active", uuid.New()))
	fresh := func(step string, want bool) {
		t.Helper()
		got, err := c.Fresh(ctx, store.FreshFor, followed, unknown)
		if err != nil {
			t.Fatal(err)
		}
		if got[followed] != want || got[unknown] {
			t.Fatalf("%s: %v, want the followed sub %v and the unknown one stale", step, got, want)
		}
	}
	fresh("a document just stored", true)
	if _, err := pool.Exec(ctx, `UPDATE contract_accounts SET fresh_at = clock_timestamp() - interval '2 hours'`); err != nil {
		t.Fatal(err)
	}
	fresh("a document two hours old", false)
	if _, err := pool.Exec(ctx, `UPDATE contract_state SET published_through = clock_timestamp()`); err != nil {
		t.Fatal(err)
	}
	fresh("a trusted page since", true)
	if got, err := c.Fresh(ctx, time.Minute, followed); err != nil || !got[followed] {
		t.Fatalf("within a minute of the page: %v %v", got, err)
	}
	// A published_through past the database's clock is a fault, and
	// vouches for nobody; within the skew it counts.
	if _, err := pool.Exec(ctx, `UPDATE contract_state SET published_through = clock_timestamp() + interval '1 hour'`); err != nil {
		t.Fatal(err)
	}
	fresh("a page from an hour ahead", false)
	if _, err := pool.Exec(ctx, `UPDATE contract_state SET published_through = clock_timestamp() + interval '1 minute'`); err != nil {
		t.Fatal(err)
	}
	fresh("a page from a minute ahead", true)
	// A GET's not_found: the platform follows the sub no more, so the page
	// says nothing of it.
	if err := c.Unfollowed(ctx, followed); err != nil {
		t.Fatal(err)
	}
	fresh("after a not_found", false)
	storeDocs(t, c, store.ContractAnswer, contractDoc(followed, gen, 1, "active", uuid.New()))
	fresh("its document again", true)
	// A page of another generation vouches for nobody of this one.
	if _, err := pool.Exec(ctx, `UPDATE contract_accounts SET fresh_at = clock_timestamp() - interval '2 hours';
		UPDATE contract_state SET generation = uuidv7()`); err != nil {
		t.Fatal(err)
	}
	fresh("a page of another generation", false)
}

// TestContractIntents is DB21's bookkeeping: an intent row before every
// PUT, renewed by the next, removed after a signed unsubscribe only while
// it is the one seen and its sub is still unlinked; the sweep's orphans;
// the round's work.
func TestContractIntents(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	c := store.NewContract(w.pool)
	orphan, held := uuid.New(), linkSub(t, w.pool, w.person(t, "ana", "member"))
	for _, sub := range []uuid.UUID{orphan, held} {
		if _, err := c.Intend(ctx, sub); err != nil {
			t.Fatal(err)
		}
	}
	subscribedAt := func(sub uuid.UUID) time.Time {
		t.Helper()
		var at time.Time
		if err := w.pool.QueryRow(ctx, `SELECT subscribed_at FROM contract_accounts WHERE sub = $1`, sub).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at
	}

	orphans := func() []uuid.UUID {
		t.Helper()
		list, err := c.Orphans(ctx, time.Hour, 10)
		if err != nil {
			t.Fatal(err)
		}
		var out []uuid.UUID
		for _, i := range list {
			out = append(out, i.Sub)
		}
		return out
	}
	if got := orphans(); len(got) != 0 {
		t.Fatalf("orphans within the hour: %v", got)
	}
	if _, err := w.pool.Exec(ctx, `UPDATE contract_accounts SET subscribed_at = subscribed_at - interval '2 hours'`); err != nil {
		t.Fatal(err)
	}
	if got := orphans(); !slices.Equal(got, []uuid.UUID{orphan}) {
		t.Fatalf("orphans after an hour: %v, want only the unlinked sub", got)
	}

	// The sweep's removal names the intent it saw. A PUT after the sweep
	// read it (a sign-in, a second tab) renews the intent, so the sweep
	// removes nothing and the sub stays subscribed.
	seen := subscribedAt(orphan)
	again, err := c.Intend(ctx, orphan)
	if err != nil || !again.After(seen.Add(time.Hour)) {
		t.Fatalf("a second intent did not renew the first: %v, the first %v (%v)", again, seen, err)
	}
	if got := orphans(); len(got) != 0 {
		t.Fatalf("orphans after a renewed intent: %v", got)
	}
	if removed, err := c.ForgetIntent(ctx, orphan, seen); err != nil || removed {
		t.Fatalf("an intent renewed since it was seen: removed %v %v", removed, err)
	}
	if got := subscribedAt(orphan); !got.Equal(again) {
		t.Fatalf("the renewed intent: %v, want %v", got, again)
	}
	if removed, err := c.ForgetIntent(ctx, held, subscribedAt(held)); err != nil || removed {
		t.Fatalf("a linked sub: removed %v %v", removed, err)
	}
	if removed, err := c.ForgetIntent(ctx, orphan, again); err != nil || !removed {
		t.Fatalf("the intent seen: removed %v %v", removed, err)
	}

	// The round subscribes every linked sub with no version of the stored
	// generation.
	round := func() []uuid.UUID {
		t.Helper()
		subs, err := c.Unsubscribed(ctx, 10)
		if err != nil {
			t.Fatal(err)
		}
		return subs
	}
	if got := round(); !slices.Equal(got, []uuid.UUID{held}) {
		t.Fatalf("the round before a document: %v", got)
	}
	storeDocs(t, c, store.ContractAnswer, contractDoc(held, uuid.New(), 1, "active", uuid.New()))
	if got := round(); len(got) != 0 {
		t.Fatalf("the round after its document: %v", got)
	}
	if err := c.Unfollowed(ctx, held); err != nil {
		t.Fatal(err)
	}
	if got := round(); !slices.Equal(got, []uuid.UUID{held}) {
		t.Fatalf("the round after a not_found: %v", got)
	}
}

// The round's work comes untried subs first, then by the oldest attempt:
// subs whose PUTs keep failing (README 6.1 retries a not_found on PUT)
// move behind the rest at each attempt, so a round that works in batches
// reaches every sub.
func TestContractRoundOrder(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	c := store.NewContract(w.pool)
	var subs []uuid.UUID
	for _, name := range []string{"ana", "bia", "caio"} {
		subs = append(subs, linkSub(t, w.pool, w.person(t, name, "member")))
	}
	slices.SortFunc(subs, func(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) })
	first, second, third := subs[0], subs[1], subs[2]
	round := func(limit int) []uuid.UUID {
		t.Helper()
		got, err := c.Unsubscribed(ctx, limit)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	// The first two were tried and failed, the first one earlier.
	for i, sub := range []uuid.UUID{first, second} {
		if _, err := c.Intend(ctx, sub); err != nil {
			t.Fatal(err)
		}
		if _, err := w.pool.Exec(ctx, `UPDATE contract_accounts SET subscribed_at = clock_timestamp() - $2::interval WHERE sub = $1`,
			sub, time.Duration(2-i)*time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	if got := round(2); !slices.Equal(got, []uuid.UUID{third, first}) {
		t.Fatalf("a batch of two after two failures: %v, want the untried sub, then the oldest attempt", got)
	}
	// The first is tried again, and fails again: it goes last.
	if _, err := c.Intend(ctx, first); err != nil {
		t.Fatal(err)
	}
	if got := round(3); !slices.Equal(got, []uuid.UUID{third, second, first}) {
		t.Fatalf("after the first one's second failure: %v", got)
	}
}

// Documents naming the same teams, stored at once in opposite orders, never
// deadlock: each batch takes contract_state first, then its accounts and
// workspaces in id order (DB23).
func TestContractDocumentsConcurrently(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	c := store.NewContract(pool)
	gen := uuid.New()
	teams := []store.ContractDocWorkspace{{ID: uuid.New(), Role: "owner", Status: "open", WVersion: 1},
		{ID: uuid.New(), Role: "member", Status: "open", WVersion: 1}}
	subs := []uuid.UUID{uuid.New(), uuid.New()}
	var wg sync.WaitGroup
	errs := make(chan error, 40)
	for i := range 40 {
		wg.Go(func() {
			first, second := subs[i%2], subs[1-i%2]
			ts := []store.ContractDocWorkspace{teams[i%2], teams[1-i%2]}
			_, err := c.StoreDocuments(context.Background(), store.ContractAnswer,
				contractDoc(first, gen, int64(i+1), "active", uuid.NewSHA1(uuid.Nil, first[:]), ts...),
				contractDoc(second, gen, int64(i+1), "active", uuid.NewSHA1(uuid.Nil, second[:]), ts...))
			if err != nil {
				errs <- fmt.Errorf("batch %d: %w", i, err)
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// 0051 widens security_events for the sign-up refused because the
// platform's workspace id for it is one Wappie holds already.
func TestHomeTakenSecurityEvent(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	sub := uuid.New()
	if err := store.NewUsers(pool).RecordSecurityEvent(ctx, "platform_home_taken", nil, sub, map[string]string{"workspace": uuid.NewString()}); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM security_events WHERE kind = 'platform_home_taken' AND sub = $1`, sub).Scan(&n); err != nil || n != 1 {
		t.Fatalf("the home-taken event: %d %v", n, err)
	}
}
