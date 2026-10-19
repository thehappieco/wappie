package store_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

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
