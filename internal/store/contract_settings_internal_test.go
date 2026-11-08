package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/migrate"
	"whatserver2/internal/obs"
	"whatserver2/internal/pgtest"
)

// The settings part's transactions against each other (the plan's 3.4 and
// 3.5): the numbers read and an act on one clock, and one lock order for
// every 12a writer beside a reset.

// settingsWorld is a workspace recorded as a platform team, with a
// snapshot numbered and one live number.
type settingsWorld struct {
	pool   *pgxpool.Pool
	c      *Contract
	ws     uuid.UUID
	device uuid.UUID
}

func newSettingsWorld(t *testing.T) settingsWorld {
	t.Helper()
	ctx := context.Background()
	pool := pgtest.Fresh(t, migrate.Run)
	w := settingsWorld{pool: pool, c: NewContract(pool)}
	if err := pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('team') RETURNING id`).Scan(&w.ws); err != nil {
		t.Fatal(err)
	}
	if err := pgxTenantTx(ctx, pool, w.ws, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `INSERT INTO devices (tenant_id, label, pn) VALUES ($1, 'Vendas', '5511900000001@s.whatsapp.net') RETURNING id`,
			w.ws).Scan(&w.device)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO contract_workspaces (workspace_id, kind) VALUES ($1, 'team')`, w.ws); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.c.SnapshotSeq(ctx, w.ws, time.Now()); err != nil {
		t.Fatal(err)
	}
	return w
}

func pgxTenantTx(ctx context.Context, pool *pgxpool.Pool, tenant uuid.UUID, fn func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenant.String()); err != nil {
			return err
		}
		return fn(tx)
	})
}

// blocked reports whether the backend pid waits on a lock another holds.
func blocked(t *testing.T, pool *pgxpool.Pool, pid uint32) bool {
	t.Helper()
	var b bool
	if err := pool.QueryRow(context.Background(), `SELECT cardinality(pg_blocking_pids($1)) > 0`, int32(pid)).Scan(&b); err != nil {
		t.Fatal(err)
	}
	return b
}

func blocking(t *testing.T, pool *pgxpool.Pool, pid uint32) bool {
	t.Helper()
	var b bool
	if err := pool.QueryRow(context.Background(), `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1 = ANY (pg_blocking_pids(pid)))`,
		int32(pid)).Scan(&b); err != nil {
		t.Fatal(err)
	}
	return b
}

func until(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("waited 20 s for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestNumbersReadSerializesWithAct: an act holding the record makes the
// numbers read wait; once the act commits the read runs again and shows it
// at a higher seq. A read holding the record makes the act wait, and the
// act's seq comes above the read's.
func TestNumbersReadSerializesWithAct(t *testing.T) {
	ctx := context.Background()
	w := newSettingsWorld(t)

	act, err := w.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = act.Rollback(ctx) }()
	actSeq, err := actSeqTx(ctx, act, w.ws)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := act.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, w.ws.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := act.Exec(ctx, `UPDATE devices SET paused = true, pause_cause = 'person', pause_seq = pause_seq + 1 WHERE id = $1`, w.device); err != nil {
		t.Fatal(err)
	}
	type read struct {
		n   ContractNumbers
		ok  bool
		err error
	}
	done := make(chan read, 1)
	go func() {
		n, ok, err := w.c.NumbersOf(ctx, w.ws)
		done <- read{n, ok, err}
	}()
	until(t, "the read to wait on the act", func() bool { return blocking(t, w.pool, act.Conn().PgConn().PID()) })
	if err := act.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	r := <-done
	if r.err != nil || !r.ok || r.n.Seq <= actSeq || len(r.n.Items) != 1 || !r.n.Items[0].Paused {
		t.Fatalf("the read after the act at %d: %+v %v %v", actSeq, r.n, r.ok, r.err)
	}

	// The read holds the record; the act waits and takes a higher seq.
	taken, release := make(chan struct{}), make(chan struct{})
	numbersSeqTaken = func() {
		close(taken)
		<-release
	}
	defer func() { numbersSeqTaken = nil }()
	go func() {
		n, ok, err := w.c.NumbersOf(ctx, w.ws)
		done <- read{n, ok, err}
	}()
	<-taken
	numbersSeqTaken = nil
	conn, err := w.pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	pid := conn.Conn().PgConn().PID()
	acted := make(chan error, 1)
	var secondSeq int64
	go func() {
		acted <- pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			var err error
			secondSeq, err = actSeqTx(ctx, tx, w.ws)
			return err
		})
	}()
	until(t, "the act to wait on the read", func() bool { return blocked(t, w.pool, pid) })
	close(release)
	r = <-done
	if err := <-acted; err != nil || r.err != nil || !r.ok || secondSeq <= r.n.Seq {
		t.Fatalf("an act after a read at %d: %d %v %v", r.n.Seq, secondSeq, err, r.err)
	}
}

// TestSettingsLockOrder: Restart at the same time as an act, a take, a
// numbers read, a new sub's document store and a person read, round after
// round. Nothing deadlocks, each commits (or, for a take, finds the state
// moved), and an act's result of the generation before is dropped.
func TestSettingsLockOrder(t *testing.T) {
	ctx := context.Background()
	w := newSettingsWorld(t)
	if _, err := w.c.SetMode(ctx, ContractObserve); err != nil {
		t.Fatal(err)
	}
	gen := uuid.New()
	if _, err := w.pool.Exec(ctx, `UPDATE contract_state SET generation = $1`, gen); err != nil {
		t.Fatal(err)
	}
	var user uuid.UUID
	if err := pgxTenantTx(ctx, w.pool, w.ws, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `INSERT INTO users (tenant_id, email, public_key, role, auth_source)
			VALUES ($1, 'person@example.test', decode(repeat('ab', 32), 'hex'), 'owner', 'platform') RETURNING id`, w.ws).Scan(&user)
	}); err != nil {
		t.Fatal(err)
	}
	person := uuid.New()
	if _, err := w.pool.Exec(ctx, `INSERT INTO platform_identities (sub, user_id, email, linked_from) VALUES ($1, $2, 'p@id.test', 'new')`,
		person, user); err != nil {
		t.Fatal(err)
	}
	if _, err := w.pool.Exec(ctx, `INSERT INTO contract_accounts (sub, generation, version, status, doc) VALUES ($1, $2, 1, 'active', '{"v":1}')`,
		person, gen); err != nil {
		t.Fatal(err)
	}

	var logs bytes.Buffer
	var logMu sync.Mutex
	lctx := obs.WithLogger(ctx, slog.New(slog.NewTextHandler(&lockedWriter{&logs, &logMu}, nil)))
	for round := range 25 {
		var cur uuid.UUID
		if err := w.pool.QueryRow(ctx, `SELECT generation FROM contract_state`).Scan(&cur); err != nil {
			t.Fatal(err)
		}
		id := uuid.New()
		if _, err := w.pool.Exec(ctx, `INSERT INTO contract_commands (id, generation, cseq, workspace_id, wseq, kind, section, actor, issued_at,
				body, body_key, signed_at) VALUES ($1, $2, $3, $4, $3, 'item.rename', 'numbers', $5, clock_timestamp(), '{}', $6, clock_timestamp())`,
			id, cur, round+1, w.ws, person, make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
		next := uuid.New()
		calls := map[string]func() error{
			"a reset": func() error {
				_, err := w.c.RestartFromCommands(lctx, cur, &next)
				return err
			},
			"an act": func() error {
				return pgx.BeginFunc(lctx, w.pool, func(tx pgx.Tx) error {
					seq, err := actSeqTx(lctx, tx, w.ws)
					if err != nil {
						return err
					}
					if _, err := tx.Exec(lctx, `SELECT 1 FROM contract_commands WHERE id = $1 FOR UPDATE`, id); err != nil {
						return err
					}
					if _, err := tx.Exec(lctx, `SELECT set_config('app.tenant_id', $1, true)`, w.ws.String()); err != nil {
						return err
					}
					if _, err := tx.Exec(lctx, `SELECT 1 FROM tenants WHERE id = $1 FOR UPDATE`, w.ws); err != nil {
						return err
					}
					if _, err := tx.Exec(lctx, `UPDATE devices SET label = $2 WHERE id = $1`, w.device, fmt.Sprintf("Vendas %d", round)); err != nil {
						return err
					}
					if err := finishCommandTx(lctx, tx, id, CommandResult{Outcome: CommandRan, StateSeq: &seq}); err != nil {
						return err
					}
					if err := sectionsDueNowTx(lctx, tx, w.ws); err != nil {
						return err
					}
					return snapshotDueNowTx(lctx, tx, w.ws)
				})
			},
			"a take": func() error {
				st, err := w.c.SettingsState(lctx)
				if err != nil {
					return err
				}
				_, err = w.c.TakeCommands(lctx, ContractCommandPage{SeenGeneration: cur, After: st.FeedCursor, NextAfter: st.FeedCursor + 1,
					SignedAt: time.Now(), Unreadable: []ContractUnreadable{{Cseq: st.FeedCursor + 1, Why: "test"}}})
				return err
			},
			"a numbers read": func() error {
				_, _, err := w.c.NumbersOf(lctx, w.ws)
				return err
			},
			"a new sub's document": func() error {
				sub := uuid.New()
				doc := ContractDoc{Sub: sub, Generation: cur, Version: 1, Status: "active",
					Workspaces: []ContractDocWorkspace{{ID: w.ws, Kind: "team", Role: "member", Status: "open", WVersion: 1}}}
				doc.Raw, _ = json.Marshal(map[string]any{"v": 1, "sub": sub})
				_, err := w.c.StoreDocuments(lctx, ContractAnswer, doc)
				return err
			},
			"a person read": func() error {
				_, _, err := w.c.PersonOf(lctx, person)
				return err
			},
		}
		var wg sync.WaitGroup
		errs := make(chan error, len(calls))
		start := make(chan struct{})
		for name, call := range calls {
			wg.Go(func() {
				<-start
				if err := call(); err != nil {
					errs <- fmt.Errorf("round %d, %s: %w", round, name, err)
				}
			})
		}
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Error(err)
		}
		if t.Failed() {
			return
		}
		if _, err := w.c.UndeliveredResults(ctx, 100); err != nil {
			t.Fatal(err)
		}
		var stale int
		if err := w.pool.QueryRow(ctx, `SELECT count(*) FROM contract_commands c WHERE c.outcome IS NOT NULL
			AND c.generation IS DISTINCT FROM (SELECT generation FROM contract_state) AND c.delivery IS DISTINCT FROM 'dropped'`).Scan(&stale); err != nil {
			t.Fatal(err)
		}
		if stale != 0 {
			t.Fatalf("round %d: %d results of an old generation not dropped", round, stale)
		}
	}
	logMu.Lock()
	defer logMu.Unlock()
	if strings.Contains(logs.String(), "deadlocked") {
		t.Fatalf("a deadlock, retried:\n%s", logs.String())
	}
}

type lockedWriter struct {
	b  *bytes.Buffer
	mu *sync.Mutex
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
