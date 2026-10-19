package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/pg"
	"whatserver2/internal/store"
)

// A new account's home from the platform's document (the plan's 4.5 and
// DB23), at the store: SignupPlatform's transaction.

func (f *platformFixture) countOf(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TB16's fault: a document the account's transaction cannot store (here,
// one that is not a JSON object) rolls the whole account back, so nothing
// is left but the intent row the PUT was sent after. The same account, with
// a storable document, has the platform's id as its personal workspace,
// made by the insertion trigger, and records every workspace it names.
func TestSignUpHomeRollsBack(t *testing.T) {
	f := newPlatformFixture(t)
	ctx := context.Background()
	c := store.NewContract(f.pool)
	sub, home, team, gen := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	secret := f.ticket(t, store.TicketNew, sub, "ivo@example.com", uuid.Nil)
	if _, err := c.Intend(ctx, sub); err != nil {
		t.Fatal(err)
	}
	doc := contractDoc(sub, gen, 3, "active", home, store.ContractDocWorkspace{ID: team, Role: "member", Status: "open", WVersion: 2})
	broken := doc
	broken.Raw = []byte(`[1]`)
	in := store.NewPlatformUser{Ticket: secret, PublicKey: platformBytes(t, 32), Wrap: platformWrap(t), Home: home, Doc: &broken}
	var docErr *store.ContractDocError
	if _, _, err := f.users.SignupPlatform(ctx, in); !errors.As(err, &docErr) || docErr.Outcome != store.ContractDocInvalid {
		t.Fatalf("a document that cannot be stored: %v", err)
	}
	for q, want := range map[string]int{
		`SELECT count(*) FROM users WHERE id = $1`:                                       0,
		`SELECT count(*) FROM tenants WHERE personal_owner_id = $1`:                      0,
		`SELECT count(*) FROM platform_identities WHERE sub = $1`:                        0,
		`SELECT count(*) FROM platform_wraps WHERE user_id = $1`:                         0,
		`SELECT count(*) FROM security_events WHERE sub = $1`:                            0,
		`SELECT count(*) FROM contract_accounts WHERE sub = $1 AND version IS NULL`:      1,
		`SELECT count(*) FROM platform_login_tickets WHERE sub = $1 AND used_at IS NULL`: 1,
	} {
		if n := f.countOf(t, q, sub); n != want {
			t.Fatalf("%s: %d, want %d", q, n, want)
		}
	}
	if n := f.countOf(t, `SELECT count(*) FROM contract_workspaces`); n != 0 {
		t.Fatalf("%d workspaces recorded by a rolled-back account", n)
	}
	var generation *uuid.UUID
	if err := f.pool.QueryRow(ctx, `SELECT generation FROM contract_state`).Scan(&generation); err != nil || generation != nil {
		t.Fatalf("a rolled-back account adopted a generation: %v %v", generation, err)
	}

	in.Doc = &doc
	user, _, err := f.users.SignupPlatform(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if user.TenantID != home {
		t.Fatalf("the home is %s, want %s", user.TenantID, home)
	}
	if n := f.countOf(t, `SELECT count(*) FROM tenants WHERE id = $1 AND kind = 'personal' AND personal_owner_id = $2`, home, sub); n != 1 {
		t.Fatal("the trigger did not make the platform's personal workspace")
	}
	a := readAccount(t, f.pool, sub)
	if a.Version == nil || *a.Version != 3 || a.FreshAt == nil {
		t.Fatalf("the document with the account: %+v", a)
	}
	for id, kind := range map[uuid.UUID]string{home: "personal", team: "team"} {
		if n := f.countOf(t, `SELECT count(*) FROM contract_workspaces WHERE workspace_id = $1 AND kind = $2`, id, kind); n != 1 {
			t.Fatalf("workspace %s not recorded as %s", id, kind)
		}
	}
	if err := f.pool.QueryRow(ctx, `SELECT generation FROM contract_state`).Scan(&generation); err != nil || generation == nil || *generation != gen {
		t.Fatalf("the generation: %v %v", generation, err)
	}
}

// A home a tenant has already, and a home that is not the document's: the
// first refused with ErrHomeTaken and its security event after the
// rollback, the second a caller's fault, neither creating anything.
func TestSignUpHomeRefusals(t *testing.T) {
	f := newPlatformFixture(t)
	ctx := context.Background()
	gen := uuid.New()

	sub := uuid.New()
	doc := contractDoc(sub, gen, 1, "active", f.tenant)
	in := store.NewPlatformUser{Ticket: f.ticket(t, store.TicketNew, sub, "lia@example.com", uuid.Nil), PublicKey: platformBytes(t, 32),
		Wrap: platformWrap(t), Home: f.tenant, Doc: &doc}
	if _, _, err := f.users.SignupPlatform(ctx, in); !errors.Is(err, store.ErrHomeTaken) {
		t.Fatalf("a taken home: %v", err)
	}
	if n := f.countOf(t, `SELECT count(*) FROM security_events WHERE kind = 'platform_home_taken' AND sub = $1 AND user_id IS NULL`, sub); n != 1 {
		t.Fatalf("%d home-taken events", n)
	}
	if n := f.countOf(t, `SELECT count(*) FROM users WHERE id = $1`, sub) + f.countOf(t, `SELECT count(*) FROM contract_accounts`); n != 0 {
		t.Fatal("a refused home created something")
	}
	if n := f.countOf(t, `SELECT count(*) FROM platform_login_tickets WHERE sub = $1 AND used_at IS NULL`, sub); n != 1 {
		t.Fatal("a refused home spent the ticket")
	}

	// The sub's own personal workspace, which a second tab's account made
	// between this one's link check and its home check (here, a person of
	// that id with no link yet): already linked, never a conflict, and no
	// security event.
	own, ownHome := uuid.New(), uuid.New()
	if err := pg.InTenantTx(ctx, f.pool, ownHome.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO users (id, tenant_id, email, public_key, role, auth_source)
			VALUES ($1, $2, 'tab@example.com', $3, 'owner', 'platform')`, own, ownHome, platformBytes(t, 32))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	ownDoc := contractDoc(own, gen, 1, "active", ownHome)
	in = store.NewPlatformUser{Ticket: f.ticket(t, store.TicketNew, own, "tab2@example.com", uuid.Nil), PublicKey: platformBytes(t, 32),
		Wrap: platformWrap(t), Home: ownHome, Doc: &ownDoc}
	if _, _, err := f.users.SignupPlatform(ctx, in); !errors.Is(err, store.ErrAlreadyLinked) {
		t.Fatalf("the sub's own personal workspace: %v", err)
	}
	if n := f.countOf(t, `SELECT count(*) FROM security_events WHERE kind = 'platform_home_taken' AND sub = $1`, own); n != 0 {
		t.Fatalf("the sub's own workspace recorded %d home-taken events", n)
	}

	// A tenant of the home's id committed after the home check: the
	// trigger's insert waits for it, and the account is refused as a home
	// taken, with its event, rather than failing as an insert.
	racer, racedHome := uuid.New(), uuid.New()
	racedDoc := contractDoc(racer, gen, 1, "active", racedHome)
	in = store.NewPlatformUser{Ticket: f.ticket(t, store.TicketNew, racer, "race@example.com", uuid.Nil), PublicKey: platformBytes(t, 32),
		Wrap: platformWrap(t), Home: racedHome, Doc: &racedDoc}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }() //nolint:errcheck // committed below; a failed test's rollback
	if _, err := tx.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, 'racing')`, racedHome); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := f.users.SignupPlatform(ctx, in)
		done <- err
	}()
	waitForLock(t, f, done)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, store.ErrHomeTaken) {
		t.Fatalf("a home committed meanwhile: %v", err)
	}
	if n := f.countOf(t, `SELECT count(*) FROM security_events WHERE kind = 'platform_home_taken' AND sub = $1`, racer); n != 1 {
		t.Fatalf("%d home-taken events for a home committed meanwhile", n)
	}
	if n := f.countOf(t, `SELECT count(*) FROM users WHERE id = $1`, racer); n != 0 {
		t.Fatal("the racing account was created")
	}

	// A home that is not the active document's personal workspace of the
	// ticket's sub: a caller's fault, never ErrHomeTaken nor a ticket's.
	for name, mutate := range map[string]func(*store.NewPlatformUser, *store.ContractDoc){
		"no document":   func(in *store.NewPlatformUser, _ *store.ContractDoc) { in.Doc = nil },
		"another sub":   func(_ *store.NewPlatformUser, d *store.ContractDoc) { d.Sub = uuid.New() },
		"another home":  func(in *store.NewPlatformUser, _ *store.ContractDoc) { in.Home = uuid.New() },
		"not active":    func(_ *store.NewPlatformUser, d *store.ContractDoc) { d.Status = "disabled" },
		"a team first":  func(_ *store.NewPlatformUser, d *store.ContractDoc) { d.Workspaces[0].Kind = "team" },
		"no workspaces": func(_ *store.NewPlatformUser, d *store.ContractDoc) { d.Workspaces = nil },
	} {
		other, home := uuid.New(), uuid.New()
		d := contractDoc(other, gen, 1, "active", home)
		in := store.NewPlatformUser{Ticket: f.ticket(t, store.TicketNew, other, "mia@example.com", uuid.Nil), PublicKey: platformBytes(t, 32),
			Wrap: platformWrap(t), Home: home, Doc: &d}
		mutate(&in, &d)
		if _, _, err := f.users.SignupPlatform(ctx, in); err == nil || errors.Is(err, store.ErrHomeTaken) || errors.Is(err, store.ErrTicketInvalid) {
			t.Fatalf("%s: %v", name, err)
		}
		if n := f.countOf(t, `SELECT count(*) FROM users WHERE id = $1`, other); n != 0 {
			t.Fatalf("%s: the account was created", name)
		}
	}
	// Check refuses the request's own faults before anything is asked.
	for name, in := range map[string]store.NewPlatformUser{
		"key":  {PublicKey: platformBytes(t, 31), Wrap: platformWrap(t)},
		"wrap": {PublicKey: platformBytes(t, 32), Wrap: platformBytes(t, 61)},
		"name": {PublicKey: platformBytes(t, 32), Wrap: platformWrap(t), Name: string(make([]byte, 81))},
	} {
		if err := in.Check(); err == nil {
			t.Errorf("Check passed a bad %s", name)
		}
	}
	if err := (store.NewPlatformUser{PublicKey: platformBytes(t, 32), Wrap: platformWrap(t), Name: "Ana"}).Check(); err != nil {
		t.Fatalf("Check: %v", err)
	}
}

// waitForLock returns once one of f's sessions waits on a lock, and fails
// the test when done, the call that should wait, returns first.
func waitForLock(t *testing.T, f *platformFixture, done chan error) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		waiting, err := f.backends.Waiting(context.Background(), f.pool)
		if err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		select {
		case err := <-done:
			t.Fatalf("returned without waiting: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("nothing waited on the lock")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Once the contract was observed, Wappie never chooses a new account's
// home itself (the plan's DB2), whoever calls SignupPlatform: an account
// with no home of the platform's is refused, and nothing is created. A
// sign-up that read the contract off races the first switch to observe on
// contract_state's row: the switch, uncommitted, makes it wait, and it is
// refused once the switch commits; an account created first is one the
// switch's round subscribes.
func TestSignUpHomeRequired(t *testing.T) {
	f := newPlatformFixture(t)
	ctx := context.Background()
	newAccount := func(sub uuid.UUID) store.NewPlatformUser {
		return store.NewPlatformUser{Ticket: f.ticket(t, store.TicketNew, sub, sub.String()[:8]+"@example.com", uuid.Nil),
			PublicKey: platformBytes(t, 32), Wrap: platformWrap(t)}
	}
	created := func(sub uuid.UUID) int {
		return f.countOf(t, `SELECT count(*) FROM users WHERE id = $1`, sub) + f.countOf(t, `SELECT count(*) FROM tenants WHERE personal_owner_id = $1`, sub)
	}

	// The switch commits while the sign-up waits on the row.
	sub := uuid.New()
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }() //nolint:errcheck // committed below; a failed test's rollback
	if _, err := tx.Exec(ctx, `UPDATE contract_state SET mode = 'observe', events_from = clock_timestamp()`); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	in := newAccount(sub)
	go func() {
		_, _, err := f.users.SignupPlatform(ctx, in)
		done <- err
	}()
	waitForLock(t, f, done)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, store.ErrHomeRequired) {
		t.Fatalf("a sign-up racing the first observe: %v", err)
	}
	if n := created(sub); n != 0 {
		t.Fatal("a sign-up racing the first observe was created")
	}
	if n := f.countOf(t, `SELECT count(*) FROM platform_login_tickets WHERE sub = $1 AND used_at IS NULL`, sub); n != 1 {
		t.Fatal("the refusal spent the ticket")
	}

	// Off after an observe, the same.
	if _, err := f.pool.Exec(ctx, `UPDATE contract_state SET mode = 'off', events_paused_at = clock_timestamp()`); err != nil {
		t.Fatal(err)
	}
	other := uuid.New()
	if _, _, err := f.users.SignupPlatform(ctx, newAccount(other)); !errors.Is(err, store.ErrHomeRequired) || created(other) != 0 {
		t.Fatalf("off after an observe: %v", err)
	}
}

// The contract's reads for sign-ins and freshness: who is held, their subs,
// whether published_through vouches for a sub, and the round's end.
func TestContractSignInReads(t *testing.T) {
	f := newPlatformFixture(t)
	ctx := context.Background()
	c := store.NewContract(f.pool)
	sub := uuid.New()
	user, _, err := f.users.SignupPlatform(ctx, store.NewPlatformUser{Ticket: f.ticket(t, store.TicketNew, sub, "noa@example.com", uuid.Nil),
		PublicKey: platformBytes(t, 32), Wrap: platformWrap(t)})
	if err != nil {
		t.Fatal(err)
	}
	stranger := uuid.New()
	if held, err := c.Held(ctx, sub); err != nil || !held {
		t.Fatalf("held: %v %v", held, err)
	}
	if held, err := c.Held(ctx, stranger); err != nil || held {
		t.Fatalf("a stranger held: %v %v", held, err)
	}
	subs, err := c.SubsOf(ctx, user.ID, stranger)
	if err != nil || len(subs) != 1 || subs[user.ID] != sub {
		t.Fatalf("subs: %v %v", subs, err)
	}

	// The round is not done while a held sub has no document of the
	// stored generation, and is once every one has.
	second := uuid.New()
	other, _, err := f.users.SignupPlatform(ctx, store.NewPlatformUser{Ticket: f.ticket(t, store.TicketNew, second, "ora@example.com", uuid.Nil),
		PublicKey: platformBytes(t, 32), Wrap: platformWrap(t)})
	if err != nil {
		t.Fatal(err)
	}
	gen := uuid.New()
	if done, err := c.RoundDone(ctx, gen); err != nil || done {
		t.Fatalf("a round done with no generation: %v %v", done, err)
	}
	storeDocs(t, c, store.ContractAnswer, contractDoc(sub, gen, 1, "active", user.TenantID))
	if done, err := c.RoundDone(ctx, gen); err != nil || done {
		t.Fatalf("a round done with a held sub unsubscribed: %v %v", done, err)
	}
	storeDocs(t, c, store.ContractAnswer, contractDoc(second, gen, 1, "active", other.TenantID))
	if done, err := c.RoundDone(ctx, uuid.New()); err != nil || done {
		t.Fatalf("a round done for another generation: %v %v", done, err)
	}
	if done, err := c.RoundDone(ctx, gen); err != nil || !done {
		t.Fatalf("the round: %v %v", done, err)
	}
	var round *uuid.UUID
	if err := f.pool.QueryRow(ctx, `SELECT round_generation FROM contract_state`).Scan(&round); err != nil || round == nil || *round != gen {
		t.Fatalf("round_generation %v %v", round, err)
	}

	// published_through vouches for a followed sub only, of the stored
	// generation, within the hour, and never past the clock's bound; and
	// Vouched and the freshness every act reads (Standing, here with the
	// sub's own answer two hours old) say the same, from one clause.
	if _, err := f.pool.Exec(ctx, `UPDATE contract_accounts SET fresh_at = clock_timestamp() - interval '2 hours' WHERE sub = $1`, sub); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		through  string
		follow   bool
		otherGen bool
		want     bool
	}{
		{"-30 minutes", true, false, true},
		{"+4 minutes", true, false, true},
		{"-61 minutes", true, false, false},
		{"+10 minutes", true, false, false},
		{"-30 minutes", true, true, false},
		{"-30 minutes", false, false, false},
	} {
		if _, err := f.pool.Exec(ctx, `UPDATE contract_state SET published_through = $1`, dbClock(t, f.pool, tc.through)); err != nil {
			t.Fatal(err)
		}
		if tc.otherGen {
			if _, err := f.pool.Exec(ctx, `UPDATE contract_state SET generation = $1`, uuid.New()); err != nil {
				t.Fatal(err)
			}
		}
		if !tc.follow {
			if err := c.Unfollowed(ctx, sub); err != nil {
				t.Fatal(err)
			}
		}
		if v, err := c.Vouched(ctx, store.FreshFor, sub); err != nil || v != tc.want {
			t.Fatalf("published_through %s (followed %v, another generation %v): vouched %v, want %v (%v)", tc.through, tc.follow, tc.otherGen, v, tc.want, err)
		}
		if fresh, err := c.Fresh(ctx, store.FreshFor, sub); err != nil || fresh[sub] != tc.want {
			t.Fatalf("published_through %s (followed %v, another generation %v): fresh %v, want %v (%v)", tc.through, tc.follow, tc.otherGen, fresh[sub], tc.want, err)
		}
		if tc.otherGen {
			if _, err := f.pool.Exec(ctx, `UPDATE contract_state SET generation = $1`, gen); err != nil {
				t.Fatal(err)
			}
		}
	}
	if v, err := c.Vouched(ctx, store.FreshFor, stranger); err != nil || v {
		t.Fatalf("a stranger vouched: %v %v", v, err)
	}
}
