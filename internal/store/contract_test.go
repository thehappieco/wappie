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

func storeDocs(t *testing.T, c *store.Contract, docs ...store.ContractDoc) []store.ContractDocOutcome {
	t.Helper()
	out, err := c.StoreDocuments(context.Background(), docs...)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// account is a contract_accounts row as a test reads it.
type account struct {
	Version    *int64
	Generation *uuid.UUID
	Status     *string
	DocVersion *int64
	Disabled   *time.Time
	Sessions   *time.Time
	FreshAt    *time.Time
}

func readAccount(t *testing.T, pool *pgxpool.Pool, sub uuid.UUID) account {
	t.Helper()
	var a account
	if err := pool.QueryRow(context.Background(), `SELECT version, generation, status, (doc->>'version')::bigint, disabled_at,
		sessions_revoked_at, fresh_at FROM contract_accounts WHERE sub = $1`, sub).
		Scan(&a.Version, &a.Generation, &a.Status, &a.DocVersion, &a.Disabled, &a.Sessions, &a.FreshAt); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestContractState(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	c := store.NewContract(pool)
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

// TestContractDocuments stores documents as every path does: the first
// adopts the generation, a newer version replaces the stored one, the same
// or a lower one is kept but still refreshes the sub (DB8), revocation
// times only rise, a workspace's status moves only with its wversion, and
// another generation stores nothing and wakes the contract loops.
func TestContractDocuments(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	c := store.NewContract(pool)
	gen, sub, home, team := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	member := store.ContractDocWorkspace{ID: team, Role: "member", Status: "open", WVersion: 3}

	if got := storeDocs(t, c, contractDoc(sub, gen, 5, "active", home, member)); !slices.Equal(got, []store.ContractDocOutcome{store.ContractDocStored}) {
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
		if got := storeDocs(t, c, lower); !slices.Equal(got, []store.ContractDocOutcome{store.ContractDocKept}) {
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

	// A newer one replaces it; its revocation times only rise, and a lower
	// wversion moves no status.
	disabledAt := time.Now().Add(-time.Hour).UTC().Truncate(time.Microsecond)
	newer := contractDoc(sub, gen, 9, "disabled", home, store.ContractDocWorkspace{ID: team, Role: "admin", Status: "open", WVersion: 2})
	newer.DisabledAt, newer.SessionsRevokedAt = &disabledAt, &disabledAt
	if got := storeDocs(t, c, newer); !slices.Equal(got, []store.ContractDocOutcome{store.ContractDocStored}) {
		t.Fatalf("version 9: %v", got)
	}
	newest := contractDoc(sub, gen, 10, "active", home, member)
	if got := storeDocs(t, c, newest); !slices.Equal(got, []store.ContractDocOutcome{store.ContractDocStored}) {
		t.Fatalf("version 10: %v", got)
	}
	a := readAccount(t, pool, sub)
	if *a.Version != 10 || *a.Status != "active" || a.Disabled == nil || !a.Disabled.Equal(disabledAt) || a.Sessions == nil {
		t.Fatalf("after version 10, with no disable in it: %+v", a)
	}
	if w, _, _ := c.Workspace(ctx, team); w.Status != "closed" || w.WVersion != 4 {
		t.Fatalf("the team after lower wversions: %+v", w)
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
	if got := storeDocs(t, c, contractDoc(sub, uuid.New(), 11, "closed", home)); !slices.Equal(got, []store.ContractDocOutcome{store.ContractDocOtherGeneration}) {
		t.Fatalf("another generation: %v", got)
	}
	if after := readAccount(t, pool, sub); *after.Version != 10 || !after.FreshAt.Equal(*before.FreshAt) {
		t.Fatalf("another generation changed the row: %+v", after)
	}
	wait, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for {
		n, err := listener.Conn().WaitForNotification(wait)
		if err != nil {
			t.Fatalf("no wake for another generation: %v", err)
		}
		if n.Payload == "generation" {
			break
		}
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
	out, err := c.StoreDocuments(ctx, contractDoc(one, gen, 1, "active", uuid.New(), store.ContractDocWorkspace{ID: team, Role: "owner", Status: "open", WVersion: 1}))
	if err != nil || out[0] != store.ContractDocStored {
		t.Fatalf("the first document: %v %v", out, err)
	}
	// The team named as someone's personal workspace, and a local team
	// named as one.
	out, err = c.StoreDocuments(ctx, contractDoc(two, gen, 1, "active", team), contractDoc(three, gen, 1, "active", local))
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

	// Two documents of one batch that disagree on a new workspace: the one
	// first in sub order records it, the other is refused.
	shared := uuid.New()
	lo, hi := uuid.New(), uuid.New()
	if bytes.Compare(lo[:], hi[:]) > 0 {
		lo, hi = hi, lo
	}
	out, err = c.StoreDocuments(ctx, contractDoc(hi, gen, 1, "active", shared),
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
	storeDocs(t, c, contractDoc(followed, gen, 1, "active", uuid.New()))
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
	// A GET's not_found: the platform follows the sub no more, so the page
	// says nothing of it.
	if err := c.Unfollowed(ctx, followed); err != nil {
		t.Fatal(err)
	}
	fresh("after a not_found", false)
	storeDocs(t, c, contractDoc(followed, gen, 1, "active", uuid.New()))
	fresh("its document again", true)
	// A page of another generation vouches for nobody of this one.
	if _, err := pool.Exec(ctx, `UPDATE contract_accounts SET fresh_at = clock_timestamp() - interval '2 hours';
		UPDATE contract_state SET generation = uuidv7()`); err != nil {
		t.Fatal(err)
	}
	fresh("a page of another generation", false)
}

// TestContractIntents is DB21's bookkeeping: an intent row before every
// PUT, removed after a signed unsubscribe only while it is the one seen and
// its sub is still unlinked; the sweep's orphans; the round's work.
func TestContractIntents(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	c := store.NewContract(w.pool)
	orphan, held := uuid.New(), linkSub(t, w.pool, w.person(t, "ana", "member"))
	seen, err := c.Intend(ctx, orphan)
	if err != nil {
		t.Fatal(err)
	}
	again, err := c.Intend(ctx, orphan)
	if err != nil || again.Before(seen) {
		t.Fatalf("a second intent: %v before %v (%v)", again, seen, err)
	}
	if _, err := c.Intend(ctx, held); err != nil {
		t.Fatal(err)
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

	// The sweep's removal names the intent it saw.
	if removed, err := c.ForgetIntent(ctx, orphan, again); err != nil || removed {
		t.Fatalf("an intent moved since it was seen: removed %v %v", removed, err)
	}
	var at time.Time
	if err := w.pool.QueryRow(ctx, `SELECT subscribed_at FROM contract_accounts WHERE sub = $1`, held).Scan(&at); err != nil {
		t.Fatal(err)
	}
	if removed, err := c.ForgetIntent(ctx, held, at); err != nil || removed {
		t.Fatalf("a linked sub: removed %v %v", removed, err)
	}
	if err := w.pool.QueryRow(ctx, `SELECT subscribed_at FROM contract_accounts WHERE sub = $1`, orphan).Scan(&at); err != nil {
		t.Fatal(err)
	}
	if removed, err := c.ForgetIntent(ctx, orphan, at); err != nil || !removed {
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
	storeDocs(t, c, contractDoc(held, uuid.New(), 1, "active", uuid.New()))
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
			_, err := c.StoreDocuments(context.Background(),
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
