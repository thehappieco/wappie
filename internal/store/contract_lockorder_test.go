package store_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/obs"
	"whatserver2/internal/store"
)

// The lock order of the contract's workspaces (the plan's DB23): every
// transaction that locks several of them locks them in id order, so the
// snapshot sender's, which take no contract_state lock, never cross a
// document's store.

// waitersOf counts the pool's backends waiting on a lock now.
func waitersOf(t *testing.T, f *platformFixture) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM pg_stat_activity
		WHERE pid = ANY ($1) AND wait_event_type = 'Lock'`, f.backends.PIDs()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func untilWaiters(t *testing.T, f *platformFixture, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for waitersOf(t, f) < n {
		if time.Now().After(deadline) {
			t.Fatalf("never %d lock waiters", n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A document whose sub left team A while staying in team B and in its
// personal workspace P (A < B < P by id) is stored while another
// transaction holds P: the store holds what it locked and waits on P. The
// leader's start (SnapshotsDue) and a debounce of "all" (SnapshotsDirty)
// then lock every row in id order: they must wait on the store's first
// row, never hold one the store still needs (A, which it writes as a
// workspace its sub left). No deadlock, so no retry.
func TestContractLockOrder(t *testing.T) {
	f := newPlatformFixture(t)
	c := store.NewContract(f.pool)
	gen := uuid.New()
	for i, sender := range []struct {
		name string
		call func(context.Context) error
	}{
		{"the leader's start", c.SnapshotsDue},
		{"a debounce of all", func(ctx context.Context) error { return c.SnapshotsDirty(ctx, nil, true, 2*time.Second) }},
	} {
		id := func(prefix string) uuid.UUID {
			return uuid.MustParse(fmt.Sprintf("%s0000-0000-4000-8000-%012x", prefix, i+1))
		}
		sub, a, b, p := uuid.New(), id("1000"), id("8000"), id("f000")
		team := func(id uuid.UUID) store.ContractDocWorkspace {
			return store.ContractDocWorkspace{ID: id, Role: "member", Status: "open", WVersion: 1}
		}
		storeDocs(t, c, store.ContractAnswer, contractDoc(sub, gen, 1, "active", p, team(a), team(b)))
		// Not due within the debounce, so that "all" reaches each of them.
		execAt(t, f, `UPDATE contract_workspaces SET snapshot_due_at = clock_timestamp() + interval '50 minutes', snapshot_tries = 0`)

		holder, err := f.pool.Begin(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := holder.Exec(context.Background(), `SELECT 1 FROM contract_workspaces WHERE workspace_id = $1 FOR UPDATE`, p); err != nil {
			t.Fatal(err)
		}
		var storeLog, senderLog bytes.Buffer
		stored := make(chan error, 1)
		go func() {
			ctx := obs.WithLogger(context.Background(), slog.New(slog.NewTextHandler(&storeLog, nil)))
			_, err := c.StoreDocuments(ctx, store.ContractAnswer, contractDoc(sub, gen, 2, "active", p, team(b)))
			stored <- err
		}()
		untilWaiters(t, f, 1)
		sent := make(chan error, 1)
		go func() {
			sent <- sender.call(obs.WithLogger(context.Background(), slog.New(slog.NewTextHandler(&senderLog, nil))))
		}()
		untilWaiters(t, f, 2)
		if err := holder.Rollback(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := <-stored; err != nil {
			t.Fatalf("%s: the store: %v", sender.name, err)
		}
		if err := <-sent; err != nil {
			t.Fatalf("%s: %v", sender.name, err)
		}
		if logged := storeLog.String() + senderLog.String(); strings.Contains(logged, "deadlocked") {
			t.Fatalf("%s and a document's store deadlocked:\n%s", sender.name, logged)
		}
		if n := f.countOf(t, `SELECT count(*) FROM contract_workspaces WHERE workspace_id = $1 AND snapshot_due_at <= clock_timestamp() + interval '2 seconds'`, a); n != 1 {
			t.Fatalf("%s: the team the sub left is not due", sender.name)
		}
	}
}

// A sign-up chosen as a deadlock's victim is tried again (DB23's 40P01
// retry): here another transaction holds contract_state, which the
// sign-up's store of its document waits on, then inserts a tenant of the
// sign-up's home, which waits on the sign-up's own.
func TestSignUpRetriesADeadlock(t *testing.T) {
	f := newPlatformFixture(t)
	ctx := context.Background()
	c := store.NewContract(f.pool)
	sub, home, gen := uuid.New(), uuid.New(), uuid.New()
	secret := f.ticket(t, store.TicketNew, sub, "ana@example.com", uuid.Nil)
	if _, err := c.Intend(ctx, sub); err != nil {
		t.Fatal(err)
	}
	doc := contractDoc(sub, gen, 1, "active", home)
	in := store.NewPlatformUser{Ticket: secret, PublicKey: platformBytes(t, 32), Wrap: platformWrap(t), Home: home, Doc: &doc}

	holder, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback(ctx) //nolint:errcheck // rolled back below; a no-op then
	if _, err := holder.Exec(ctx, `SELECT 1 FROM contract_state FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	var logged bytes.Buffer
	done := make(chan error, 1)
	go func() {
		_, _, err := f.users.SignupPlatform(obs.WithLogger(ctx, slog.New(slog.NewTextHandler(&logged, nil))), in)
		done <- err
	}()
	// The sign-up waits on contract_state first, so its deadlock check
	// runs first: it is the victim.
	untilWaiters(t, f, 1)
	inserted := make(chan error, 1)
	go func() {
		_, err := holder.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, 'elsewhere')`, home)
		inserted <- err
	}()
	if err := <-inserted; err != nil {
		t.Fatalf("the other insert: %v", err)
	}
	// Retried, the sign-up waits on the other insert of its home.
	deadline := time.Now().Add(10 * time.Second)
	for waitersOf(t, f) < 1 {
		select {
		case err := <-done:
			t.Fatalf("the sign-up that lost a deadlock: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("the sign-up, tried again, never waited on the other insert")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := holder.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("a sign-up that lost a deadlock: %v", err)
	}
	if !strings.Contains(logged.String(), "deadlocked; retrying") {
		t.Fatalf("no deadlock, so nothing proved:\n%s", logged.String())
	}
	if n := f.countOf(t, `SELECT count(*) FROM tenants WHERE id = $1 AND personal_owner_id = $2`, home, sub); n != 1 {
		t.Fatal("the sign-up's home was not made")
	}
}

func execAt(t *testing.T, f *platformFixture, sql string, args ...any) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatal(err)
	}
}

// DB25 (the lock order of the token part, core/docs/decisions.md): a token
// page's commit takes contract_token_state and never contract_state, so it
// never waits behind the account side (CommitPage, StoreDocuments, a
// sign-in's FOR SHARE, SetMode), nor they behind it; Restart takes both,
// contract_state first, so it waits for a token commit in flight and never
// deadlocks with one.
func TestATokenCommitNeverWaitsOnTheAccountSide(t *testing.T) {
	w := newTokenWorld(t)
	ctx := context.Background()
	id := uuid.New()
	w.page(false, w.record(id, 1))

	// The account side holds contract_state, as CommitPage does: a token
	// page commits all the same.
	holder, err := w.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := holder.Exec(ctx, `SELECT 1 FROM contract_state FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := w.tryPage(false, w.record(id, 2))
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a token commit beside the account side: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a token commit waited on contract_state")
	}
	if err := holder.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	// A token commit in flight holds contract_token_state: the account
	// side's writers and a sign-in's read go on; Restart waits for it.
	holder, err = w.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := holder.Exec(ctx, `SELECT 1 FROM contract_token_state FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	gen := w.gen
	for name, call := range map[string]func() error{
		"StoreDocuments": func() error {
			_, err := w.contract.StoreDocuments(ctx, store.ContractAnswer, contractDoc(w.ownerSub, gen, 2, "active", uuid.New()))
			return err
		},
		"SetMode": func() error { _, err := w.contract.SetMode(ctx, store.ContractObserve); return err },
		"a sign-in's read": func() error {
			_, err := w.pool.Exec(ctx, `SELECT 1 FROM contract_state FOR SHARE`)
			return err
		},
	} {
		done := make(chan error, 1)
		go func() { done <- call() }()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("%s beside a token commit: %v", name, err)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("%s waited on a token commit", name)
		}
	}
	restarted := make(chan error, 1)
	go func() {
		next := uuid.New()
		_, err := w.contract.RestartFromTokens(ctx, gen, &next, true)
		restarted <- err
	}()
	untilTokenWaiters(t, w, 1)
	if err := holder.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-restarted; err != nil {
		t.Fatalf("Restart after a token commit: %v", err)
	}
}

func untilTokenWaiters(t *testing.T, w *tokenWorld, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var waiting int
		if err := w.pool.QueryRow(context.Background(), `SELECT count(*) FROM pg_stat_activity
			WHERE pid = ANY ($1) AND wait_event_type = 'Lock'`, w.backends.PIDs()).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("never %d lock waiters", n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A token commit chosen as a deadlock's victim is tried again: another
// transaction holds the token's row, which the commit waits on under
// contract_token_state's lock, then asks for that lock. The commit waits
// first, so its deadlock check runs first and it is the victim; should the
// other's check win a slow race, the scenario runs again.
func TestATokenCommitRetriesADeadlock(t *testing.T) {
	w := newTokenWorld(t)
	ctx := context.Background()
	id := uuid.New()
	w.page(false, w.record(id, 1))
	for attempt, version := 1, int64(2); ; attempt, version = attempt+1, version+1 {
		holder, err := w.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := holder.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, w.tenant.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := holder.Exec(ctx, `SELECT 1 FROM contract_tokens WHERE id = $1 FOR UPDATE`, id); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			_, err := w.tryPage(false, w.record(id, version, func(r *kc.TokenRecord) { r.Name = "Retried" }))
			done <- err
		}()
		untilTokenWaiters(t, w, 1)
		_, lockErr := holder.Exec(ctx, `SELECT 1 FROM contract_token_state FOR UPDATE`)
		if err := holder.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatalf("a token commit beside a deadlock: %v", err)
		}
		if lockErr != nil && attempt < 3 {
			// The other transaction was the victim this time.
			continue
		}
		if lockErr != nil {
			t.Fatalf("the other transaction: %v", lockErr)
		}
		break
	}
	if !strings.Contains(w.logs.String(), "deadlocked; retrying") {
		t.Fatalf("no deadlock, so nothing proved:\n%s", w.logs.String())
	}
	if strings.Contains(w.logs.String(), store.TokenErrorApplyFailed) || strings.Contains(w.logs.String(), "one by one") {
		t.Fatalf("a deadlock was taken for a bad record:\n%s", w.logs.String())
	}
	if s := w.token(id); s.Name != "Retried" {
		t.Fatalf("the retried commit did not apply: %+v", s)
	}
}

// Numbers made at once in one workspace each get their own ordinal: the
// trigger takes the workspace's row first, which serializes them, and none
// deadlocks on it.
func TestConcurrentNumbersGetTheirOwnOrdinals(t *testing.T) {
	w := newTokenWorld(t)
	ctx := context.Background()
	const n = 12
	errs := make(chan error, n)
	for range n {
		go func() {
			_, err := w.devices.CreateWithID(ctx, w.tenant.String(), "", "n", "passive")
			errs <- err
		}()
	}
	for range n {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if got := w.count(`SELECT count(DISTINCT ordinal) FROM devices WHERE ordinal BETWEEN 1 AND $1`, n); got != n {
		t.Fatalf("%d distinct ordinals among %d numbers", got, n)
	}
}

// A number made in a workspace while a number moves into it (0053's
// devices_ordinal, DB25): the move holds both workspaces' rows, then waits
// on the number's; the insert waits on the target's row before it takes
// anything else, so once the number is free the move's ordinal trigger
// asks for nothing the insert holds. Neither fails, and each number has an
// ordinal of its own in the target.
func TestANumberMadeBesideAMoveIntoItsWorkspace(t *testing.T) {
	w := newTokenWorld(t)
	ctx := context.Background()
	var personal uuid.UUID
	if err := w.pool.QueryRow(ctx, `SELECT id FROM tenants WHERE personal_owner_id = $1`, w.owner).Scan(&personal); err != nil {
		t.Fatal(err)
	}
	dev, err := w.devices.CreateWithID(ctx, w.tenant.String(), "", "Vendas", "passive")
	if err != nil {
		t.Fatal(err)
	}
	moving := uuid.MustParse(dev.ID)
	if err := w.devices.SetPaused(ctx, w.tenant.String(), dev.ID, true); err != nil {
		t.Fatal(err)
	}
	holder, err := w.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback(ctx) //nolint:errcheck // rolled back below; a no-op then
	if _, err := holder.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, w.tenant.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := holder.Exec(ctx, `SELECT 1 FROM devices WHERE id = $1 FOR UPDATE`, moving); err != nil {
		t.Fatal(err)
	}
	moved := make(chan error, 1)
	go func() {
		_, err := w.devices.TransferPersonal(ctx, w.tenant, w.owner, moving, personal)
		moved <- err
	}()
	untilTokenWaiters(t, w, 1)
	made := make(chan error, 1)
	var other string
	go func() {
		d, err := w.devices.CreateWithID(ctx, personal.String(), "", "Novo", "passive")
		other = d.ID
		made <- err
	}()
	untilTokenWaiters(t, w, 2)
	if err := holder.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-moved; err != nil {
		t.Fatalf("the move beside an insert into its target: %v", err)
	}
	if err := <-made; err != nil {
		t.Fatalf("an insert beside a move into its workspace: %v", err)
	}
	var ordinals []int
	inTenantTx(ctx, t, w.pool, personal, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT ordinal FROM devices WHERE id IN ($1, $2::uuid) ORDER BY ordinal`, moving, other)
		if err != nil {
			return err
		}
		ordinals, err = pgx.CollectRows(rows, pgx.RowTo[int])
		return err
	})
	if len(ordinals) != 2 || ordinals[0] == ordinals[1] {
		t.Fatalf("the target's ordinals: %v", ordinals)
	}
}

// A token page's commit takes its workspace's row and the numbers its
// records name FOR KEY SHARE before any token row (DB25 step 3): what the
// foreign keys of the rows it inserts take anyway. So against a
// transaction that holds the workspace's row, or a number's, and then takes
// the token's perms (a quarantine or a move, which delete a number's
// perms; a number's own delete, whose perms cascade), the commit waits
// first and holds nothing that transaction needs: no deadlock, and no
// retry.
func TestATokenCommitTakesItsWorkspaceAndNumbersFirst(t *testing.T) {
	for _, c := range []struct {
		name string
		lock string
	}{
		{"the workspace's row", `SELECT 1 FROM tenants WHERE id = $1::uuid AND $2::uuid IS NOT NULL FOR UPDATE`},
		{"a number's row", `SELECT 1 FROM devices WHERE id = $2::uuid AND $1::uuid IS NOT NULL FOR UPDATE`},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := newTokenWorld(t)
			ctx := context.Background()
			device, id := w.number(uuid.Nil), uuid.New()
			w.page(false, w.record(id, 1, grants(device, w.ownerSub, w.now, kc.CanRead)))
			holder, err := w.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer holder.Rollback(ctx) //nolint:errcheck // rolled back below; a no-op then
			if _, err := holder.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, w.tenant.String()); err != nil {
				t.Fatal(err)
			}
			if _, err := holder.Exec(ctx, c.lock, w.tenant, device); err != nil {
				t.Fatal(err)
			}
			// A new token of the workspace, and a new perm on the number for
			// the held one: both inserts' foreign keys meet the holder.
			done := make(chan error, 1)
			go func() {
				_, err := w.tryPage(false, w.record(id, 2, grants(device, w.ownerSub, w.now, kc.CanRead, kc.CanSend)), w.record(uuid.New(), 1))
				done <- err
			}()
			untilTokenWaiters(t, w, 1)
			if _, err := holder.Exec(ctx, `SET LOCAL lock_timeout = '5s'`); err != nil {
				t.Fatal(err)
			}
			if _, err := holder.Exec(ctx, `SELECT 1 FROM contract_token_perms WHERE token_id = $1 ORDER BY token_id, device_id, perm FOR UPDATE`, id); err != nil {
				t.Fatalf("the token's perms, under %s: %v", c.name, err)
			}
			if err := holder.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatalf("the commit: %v", err)
			}
			if strings.Contains(w.logs.String(), "deadlocked") {
				t.Fatalf("the commit deadlocked against a holder of %s:\n%s", c.name, w.logs.String())
			}
			if p := w.perms(id); p[device.String()+"/send"] != "pending" {
				t.Fatalf("the commit did not apply: %v", p)
			}
		})
	}
}

// A token commit that deletes a token identity's grants takes the
// workspace's row first (DB25 step 3), before its token rows: so a writer
// that holds the workspace's row and then asks for the token's rows (the
// grant write, FOR SHARE), its perms or its grants (a deletion's or a
// move's), finishes first, and the commit after it. Taken the other way,
// each would wait on the other.
func TestATokenCommitWaitsForTheWorkspacesWriters(t *testing.T) {
	for _, then := range []struct {
		name string
		sql  func(token, identity, device uuid.UUID) string
	}{
		{"the grant write's token row", func(token, _, _ uuid.UUID) string {
			return `SELECT 1 FROM contract_tokens WHERE id = '` + token.String() + `' FOR SHARE`
		}},
		{"a deletion's perms", func(_, _, device uuid.UUID) string {
			return `SELECT 1 FROM contract_token_perms WHERE device_id = '` + device.String() + `' ORDER BY token_id, device_id, perm FOR UPDATE`
		}},
		{"a deletion's grants", func(_, identity, device uuid.UUID) string {
			return `DELETE FROM device_key_grants WHERE device_id = '` + device.String() + `' AND user_id = '` + identity.String() + `'`
		}},
	} {
		t.Run(then.name, func(t *testing.T) {
			w := newTokenWorld(t)
			ctx := context.Background()
			device := w.number(uuid.Nil)
			key := readingKey(t)
			token := w.readingToken(device, key)
			w.tokensOn()
			if err := w.seal(token, device, w.owner, 1); err != nil {
				t.Fatal(err)
			}
			identity, _ := w.identityOf(token)
			holder, err := w.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer holder.Rollback(ctx) //nolint:errcheck // committed below; a no-op then
			if _, err := holder.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true), set_config('lock_timeout', '5s', true)`, w.tenant.String()); err != nil {
				t.Fatal(err)
			}
			if _, err := holder.Exec(ctx, `SELECT 1 FROM tenants WHERE id = $1 FOR UPDATE`, w.tenant); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				_, err := w.tryPage(false, w.record(token, 2, revokedBy(kc.RevokedInConsole, w.now)))
				done <- err
			}()
			untilTokenWaiters(t, w, 1)
			if _, err := holder.Exec(ctx, then.sql(token, *identity, device)); err != nil {
				t.Fatalf("the writer, after the commit started: %v", err)
			}
			if err := holder.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatalf("the commit: %v", err)
			}
			if strings.Contains(w.logs.String(), "deadlock") {
				t.Fatalf("a deadlock:\n%s", w.logs.String())
			}
			if s := w.token(token); !s.Revoked || w.grantsOf(*identity) != 0 {
				t.Fatalf("after both: %+v, %d grants", s, w.grantsOf(*identity))
			}
		})
	}
}

// A token page's commit beside the real writers that hold a workspace's row
// (DB25 step 3) and then its number, its token rows or perms, or its grants:
// a number's deletion and move-out (which delete the number's perms with
// dropNumberTokensTx), the token grant write, and grant.add. The tokens are
// of each shape whose commit takes a lock under the workspace's row: a
// key-less token whose next version adds a perm on the number (the perm's
// foreign key on the number), a refused perm given again (a new instance's),
// and a Read token whose next version brings its first reading key (its
// identity: the token row's foreign key on the workspace). Each pair runs
// both ways round: the commit stalled on its token row, holding what it
// takes before it, while the writer starts; and the writer stalled on a row
// it takes under the workspace's, while the commit starts. Neither is ever
// a deadlock's victim, and the commit never retries.
func TestATokenCommitBesideTheWorkspacesRealWriters(t *testing.T) {
	type shape int
	const (
		keyless shape = iota
		refusedAgain
		firstKey
	)
	shapes := map[shape]string{keyless: "a key-less token's new perm", refusedAgain: "a refused perm given again", firstKey: "a first reading key"}
	type world struct {
		*tokenWorld
		device, token, member, personal uuid.UUID
		key                             *kc.ReadingKey
		archive                         string
	}
	type writer struct {
		name string
		// stall is the holder's lock that stops the writer under the
		// workspace's row; args are w's.
		stall string
		run   func(w world) error
	}
	writers := map[string]writer{
		"a deletion": {"a deletion", `SELECT 1 FROM devices WHERE id = $1 FOR UPDATE`, func(w world) error {
			_, err := w.devices.Quarantine(context.Background(), w.tenant, w.owner, w.device, nil)
			return err
		}},
		"a move-out": {"a move-out", `SELECT 1 FROM devices WHERE id = $1 FOR UPDATE`, func(w world) error {
			_, err := w.devices.TransferPersonal(context.Background(), w.tenant, w.owner, w.device, w.personal)
			return err
		}},
		"a token grant": {"a token grant", `SELECT 1 FROM contract_tokens WHERE id = $2 FOR UPDATE`, func(w world) error {
			return w.tokens.PutTokenGrant(context.Background(), store.TokenGrant{Workspace: w.tenant, Token: w.token, Device: w.device, Epoch: 1,
				ArchiveKeyFingerprint: w.archive, SealedDSK: []byte("sealed to the token"), Sealer: w.owner, Now: w.now})
		}},
		"grant.add": {"grant.add", `SELECT 1 FROM workspace_memberships WHERE user_id = $3 FOR UPDATE`, func(w world) error {
			return w.keys.PutGrant(context.Background(), store.Grant{TenantID: w.tenant, DeviceID: w.device, UserID: w.member, Epoch: 1,
				SealedDSK: []byte("grant")}, &w.owner)
		}},
	}
	// The pairs whose writer reaches the rows the commit takes: a move-out
	// only of a number no token holds (the refused perm), a token grant
	// only of a token that may get its identity.
	pairs := []struct {
		shape  shape
		writer string
	}{
		{keyless, "a deletion"}, {refusedAgain, "a deletion"}, {firstKey, "a deletion"},
		{refusedAgain, "a move-out"},
		{firstKey, "a token grant"},
		{keyless, "grant.add"}, {firstKey, "grant.add"},
	}
	for _, pair := range pairs {
		for _, commitFirst := range []bool{true, false} {
			order := "the writer first"
			if commitFirst {
				order = "the commit first"
			}
			wr := writers[pair.writer]
			t.Run(shapes[pair.shape]+", "+wr.name+", "+order, func(t *testing.T) {
				// A workspace id below every Personal's (uuidv7), so a move
				// locks the Team's row first.
				w := world{tokenWorld: newTokenWorldIn(t, uuid.MustParse("00000000-0000-4000-8000-"+strings.ReplaceAll(uuid.NewString(), "-", "")[:12]), uuid.Nil)}
				ctx := context.Background()
				w.device, w.token, w.key = w.number(uuid.Nil), uuid.New(), readingKey(t)
				w.archive = w.archiveKey(w.device, 1)
				w.member = w.linked("member", "member", uuid.New(), true)
				if err := w.pool.QueryRow(ctx, `SELECT id FROM tenants WHERE personal_owner_id = $1`, w.owner).Scan(&w.personal); err != nil {
					t.Fatal(err)
				}
				w.scoped(func(tx pgx.Tx) error {
					_, err := tx.Exec(ctx, `UPDATE devices SET pn = '5511912345678@s.whatsapp.net', last_connected_at = now() WHERE id = $1`, w.device)
					return err
				})
				if err := w.devices.SetPaused(ctx, w.tenant.String(), w.device.String(), true); err != nil {
					t.Fatal(err)
				}
				before := w.now.Add(-time.Hour)
				var next kc.TokenRecord
				switch pair.shape {
				case keyless:
					w.page(false, w.record(w.token, 1, grants(w.device, w.ownerSub, before, kc.CanSend)))
					next = w.record(w.token, 2, grants(w.device, w.ownerSub, before, kc.CanSend, kc.CanManage))
				case refusedAgain:
					stranger := uuid.New()
					w.page(false, w.record(w.token, 1, grants(w.device, stranger, before, kc.CanSend)))
					next = w.record(w.token, 2, grants(w.device, stranger, w.now, kc.CanSend))
				case firstKey:
					w.page(false, w.record(w.token, 1, grants(w.device, w.ownerSub, before, kc.CanRead)))
					next = w.record(w.token, 2, grants(w.device, w.ownerSub, before, kc.CanRead), func(r *kc.TokenRecord) { r.ReadingKey = w.key })
				}
				w.judge()
				w.tokensOn()
				w.fetched(w.token, w.now)

				holder, err := w.pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer holder.Rollback(ctx) //nolint:errcheck // rolled back below; a no-op then
				if _, err := holder.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, w.tenant.String()); err != nil {
					t.Fatal(err)
				}
				stall := `SELECT 1 FROM contract_tokens WHERE id = $2 AND $1::uuid IS NOT NULL AND $3::uuid IS NOT NULL FOR KEY SHARE`
				if !commitFirst {
					stall = `SELECT 1 FROM (` + wr.stall + `) s WHERE $1::uuid IS NOT NULL AND $2::uuid IS NOT NULL AND $3::uuid IS NOT NULL`
				}
				if _, err := holder.Exec(ctx, stall, w.device, w.token, w.member); err != nil {
					t.Fatal(err)
				}
				committed, wrote := make(chan error, 1), make(chan error, 1)
				commit := func() {
					_, err := w.tryPage(false, next)
					committed <- err
				}
				write := func() { wrote <- wr.run(w) }
				if commitFirst {
					go commit()
					untilTokenWaiters(t, w.tokenWorld, 1)
					go write()
				} else {
					go write()
					untilTokenWaiters(t, w.tokenWorld, 1)
					go commit()
				}
				untilTokenWaiters(t, w.tokenWorld, 2)
				if err := holder.Rollback(ctx); err != nil {
					t.Fatal(err)
				}
				if err := <-committed; err != nil {
					t.Fatalf("the commit: %v", err)
				}
				var pgErr *pgconn.PgError
				if err := <-wrote; errors.As(err, &pgErr) && pgErr.Code == "40P01" || err != nil && strings.Contains(err.Error(), "deadlock") {
					t.Fatalf("%s: %v", wr.name, err)
				}
				if strings.Contains(w.logs.String(), "deadlock") {
					t.Fatalf("the commit was a deadlock's victim:\n%s", w.logs.String())
				}
				if pair.writer == "a deletion" {
					if p := w.perms(w.token); len(p) != 0 {
						t.Fatalf("the deleted number is still the token's: %v", p)
					}
				}
			})
		}
	}
}

// A page that lists a token twice, its first record bringing the token's
// first reading key (so its identity is made) and its second revoking it
// (so that identity goes, and its grants' cascade locks the workspace's row
// FOR UPDATE, 0036), takes the workspace's row FOR UPDATE before any token
// row: against a transaction that holds the row FOR KEY SHARE (as any
// insert under the workspace does) and then takes the token's row, the
// commit waits first and holds nothing that transaction needs. Taken FOR
// KEY SHARE and upgraded under the token rows, the two would deadlock.
func TestATokenListedTwiceTakesItsWorkspaceFirst(t *testing.T) {
	w := newTokenWorld(t)
	ctx := context.Background()
	device, id := w.number(uuid.Nil), uuid.New()
	w.page(false, w.record(id, 1, grants(device, w.ownerSub, w.now, kc.CanRead)))
	w.judge()
	holder, err := w.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback(ctx) //nolint:errcheck // rolled back below; a no-op then
	if _, err := holder.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true), set_config('lock_timeout', '5s', true)`, w.tenant.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := holder.Exec(ctx, `SELECT 1 FROM tenants WHERE id = $1 FOR KEY SHARE`, w.tenant); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := w.tryPage(false,
			w.record(id, 2, grants(device, w.ownerSub, w.now, kc.CanRead), func(r *kc.TokenRecord) { r.ReadingKey = readingKey(t) }),
			w.record(id, 3, revokedBy(kc.RevokedInConsole, w.now)))
		done <- err
	}()
	untilTokenWaiters(t, w, 1)
	if _, err := holder.Exec(ctx, `SELECT 1 FROM contract_tokens WHERE id = $1 FOR UPDATE`, id); err != nil {
		t.Fatalf("the token's row, under the workspace's: %v", err)
	}
	if err := holder.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("the commit: %v", err)
	}
	if strings.Contains(w.logs.String(), "deadlock") {
		t.Fatalf("a deadlock:\n%s", w.logs.String())
	}
	identity, dropped := w.identityOf(id)
	if identity == nil || !dropped || w.count(`SELECT count(*) FROM users WHERE token_identity`) != 0 {
		t.Fatalf("the identity made and dropped in one page: %v dropped %v", identity, dropped)
	}
}

// The applier deletes token identities' grants in two workspaces in one
// page while both workspaces' snapshots are read in a loop, which reads
// them before the page starts and goes on until it has committed: the page
// commits, no snapshot fails, and no identity is left. It measures no
// time, and an overlap is likely, not forced.
func TestTheApplierAcrossTwoWorkspacesBesideSnapshots(t *testing.T) {
	w := newTokenWorld(t)
	ctx := context.Background()
	other := uuid.New()
	w.exec(`INSERT INTO tenants (id, name) VALUES ($1, 'second')`, other)
	second := *w
	second.tenant = other
	second.owner = second.linked("owner2", "owner", uuid.New(), true)
	// The second workspace's owner gives its token, made by them.
	ownerTwo := uuid.Nil
	if err := w.pool.QueryRow(ctx, `SELECT sub FROM platform_identities WHERE user_id = $1`, second.owner).Scan(&ownerTwo); err != nil {
		t.Fatal(err)
	}
	second.ownerSub = ownerTwo
	a, b := w.number(uuid.Nil), second.number(uuid.Nil)
	ta, tb := w.readingToken(a, readingKey(t)), second.readingToken(b, readingKey(t))
	w.tokensOn()
	if err := w.seal(ta, a, w.owner, 1); err != nil {
		t.Fatal(err)
	}
	if err := second.seal(tb, b, second.owner, 1); err != nil {
		t.Fatal(err)
	}
	// A first round of both before the page, rounds while it runs, and a
	// last whole round begun after it committed.
	stop, started := make(chan struct{}), make(chan struct{})
	reads := make(chan error, 1)
	go func() {
		for round := 0; ; round++ {
			if round == 1 {
				close(started)
			}
			var last bool
			select {
			case <-stop:
				last = true
			default:
			}
			for _, ws := range []uuid.UUID{w.tenant, other} {
				if _, err := w.contract.Snapshot(ctx, ws); err != nil {
					if round == 0 {
						close(started)
					}
					reads <- err
					return
				}
			}
			if last {
				reads <- nil
				return
			}
		}
	}()
	<-started
	w.page(false, w.record(ta, 2, revokedBy(kc.RevokedInConsole, w.now)), second.record(tb, 2, revokedBy(kc.RevokedInConsole, w.now)))
	close(stop)
	if err := <-reads; err != nil {
		t.Fatalf("a snapshot beside the page: %v", err)
	}
	if w.count(`SELECT count(*) FROM users WHERE token_identity`) != 0 || second.count(`SELECT count(*) FROM users WHERE token_identity`) != 0 {
		t.Fatal("an identity stayed")
	}
}
