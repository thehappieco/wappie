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

// TestSnapshotReadSerializesWithAct: the snapshot as the sender reads it
// is numbered in its measuring transaction, as the numbers read is. A
// rename holding the record makes it wait; once the rename commits the
// read runs again and shows the new label at a higher seq. A read holding
// the record makes the act wait, and the act's seq comes above the read's.
// A parked workspace's snapshot is not read.
func TestSnapshotReadSerializesWithAct(t *testing.T) {
	ctx := context.Background()
	w := newSettingsWorld(t)
	label := func(s ContractSnapshot) string {
		if len(s.Items) != 1 || s.Items[0].Label == nil {
			return ""
		}
		return *s.Items[0].Label
	}

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
	if _, err := act.Exec(ctx, `UPDATE devices SET label = 'Vendas SP' WHERE id = $1`, w.device); err != nil {
		t.Fatal(err)
	}
	type read struct {
		s   ContractSnapshot
		ok  bool
		err error
	}
	done := make(chan read, 1)
	go func() {
		s, ok, err := w.c.SnapshotNumbered(ctx, w.ws)
		done <- read{s, ok, err}
	}()
	until(t, "the snapshot to wait on the act", func() bool { return blocking(t, w.pool, act.Conn().PgConn().PID()) })
	if err := act.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	r := <-done
	if r.err != nil || !r.ok || r.s.Seq <= actSeq || label(r.s) != "Vendas SP" {
		t.Fatalf("the snapshot after the act at %d: %+v %v %v", actSeq, r.s, r.ok, r.err)
	}
	var stored int64
	if err := w.pool.QueryRow(ctx, `SELECT snapshot_seq FROM contract_workspaces WHERE workspace_id = $1`, w.ws).Scan(&stored); err != nil ||
		stored != r.s.Seq {
		t.Fatalf("the stored snapshot_seq %d, the snapshot's %d: %v", stored, r.s.Seq, err)
	}

	// The read holds the record; the act waits and takes a higher seq.
	taken, release := make(chan struct{}), make(chan struct{})
	snapshotSeqTaken = func() {
		close(taken)
		<-release
	}
	defer func() { snapshotSeqTaken = nil }()
	go func() {
		s, ok, err := w.c.SnapshotNumbered(ctx, w.ws)
		done <- read{s, ok, err}
	}()
	<-taken
	snapshotSeqTaken = nil
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
			if secondSeq, err = actSeqTx(ctx, tx, w.ws); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, w.ws.String()); err != nil {
				return err
			}
			_, err = tx.Exec(ctx, `UPDATE devices SET label = 'Vendas RJ' WHERE id = $1`, w.device)
			return err
		})
	}()
	until(t, "the act to wait on the snapshot", func() bool { return blocked(t, w.pool, pid) })
	close(release)
	r = <-done
	if err := <-acted; err != nil || r.err != nil || !r.ok || secondSeq <= r.s.Seq || label(r.s) != "Vendas SP" {
		t.Fatalf("an act after a snapshot at %d (%q): %d %v %v", r.s.Seq, label(r.s), secondSeq, err, r.err)
	}

	if _, err := w.pool.Exec(ctx, `UPDATE contract_workspaces SET parked_at = clock_timestamp() WHERE workspace_id = $1`, w.ws); err != nil {
		t.Fatal(err)
	}
	if s, ok, err := w.c.SnapshotNumbered(ctx, w.ws); err != nil || ok || s.Seq != 0 {
		t.Fatalf("a parked workspace's snapshot: %+v %v %v", s, ok, err)
	}
}

// TestSettingsLockOrder: Restart at the same time as an act, a take, a
// numbers read, a new sub's document store, a person read, a refusal, a
// failed run, a results post clearing results_error, a trim and a mode
// switch, round after round. Nothing deadlocks, each commits (or, for a
// take, finds the state moved), and an act's result of the generation
// before is dropped.
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
		id, refused, failing := uuid.New(), uuid.New(), uuid.New()
		for i, row := range []uuid.UUID{id, refused, failing} {
			if _, err := w.pool.Exec(ctx, `INSERT INTO contract_commands (id, generation, cseq, workspace_id, wseq, kind, section, actor, issued_at,
					body, body_key, signed_at) VALUES ($1, $2, $3, $4, $3, 'item.rename', 'numbers', $5, clock_timestamp(), '{}', $6, clock_timestamp())`,
				row, cur, 3*round+i+1, w.ws, person, make([]byte, 32)); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.c.ResultsFailed(ctx, "transport"); err != nil {
			t.Fatal(err)
		}
		mode := SettingsRead
		if round%2 == 1 {
			mode = SettingsOn
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
			"a refusal": func() error {
				return w.c.RefuseCommand(lctx, refused, CommandResult{Code: CommandKindNotAccepted})
			},
			"a failed run": func() error {
				_, err := w.c.CommandRunFailed(lctx, failing, "store")
				return err
			},
			"a results post": func() error {
				results, err := w.c.UndeliveredResults(lctx, 100)
				if err != nil {
					return err
				}
				answers := []ContractResultOutcome{{ID: refused, Answer: DeliveryAccepted}}
				for _, r := range results {
					answers = append(answers, ContractResultOutcome{ID: r.ID, Answer: DeliveryAccepted})
				}
				return w.c.ResultsPosted(lctx, answers)
			},
			"a trim": func() error {
				_, err := w.c.TrimCommands(lctx)
				return err
			},
			"a mode switch": func() error {
				_, err := w.c.SetSettingsMode(lctx, mode, true)
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
		// Left to post: a result of an old generation is dropped, unless a
		// post settled it before the reset.
		var stale int
		if err := w.pool.QueryRow(ctx, `SELECT count(*) FROM contract_commands c WHERE c.outcome IS NOT NULL
			AND c.generation IS DISTINCT FROM (SELECT generation FROM contract_state) AND c.delivery IS NULL`).Scan(&stale); err != nil {
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

// TestResultsPostedLockOrder: the results poster clearing results_error
// takes the settings row before the ledger rows, as a reset and a take do
// (the plan's 3.4). A third transaction holds the settings row so that the
// reset (or the take) is queued on it first; the poster then records an
// answer for a result that the reset drops (or that the take meets again).
// Nothing deadlocks.
func TestResultsPostedLockOrder(t *testing.T) {
	for _, against := range []string{"a reset", "a take"} {
		t.Run(against, func(t *testing.T) {
			ctx := context.Background()
			w := newSettingsWorld(t)
			if _, err := w.c.SetMode(ctx, ContractObserve); err != nil {
				t.Fatal(err)
			}
			gen := uuid.New()
			if _, err := w.pool.Exec(ctx, `UPDATE contract_state SET generation = $1`, gen); err != nil {
				t.Fatal(err)
			}
			x, key := uuid.New(), make([]byte, 32)
			if _, err := w.pool.Exec(ctx, `INSERT INTO contract_commands (id, generation, cseq, body, body_key, signed_at, outcome, code, result_at)
				VALUES ($1, $2, 1, '{}', $3, clock_timestamp(), 'refused', 'invalid_command', clock_timestamp())`, x, gen, key); err != nil {
				t.Fatal(err)
			}
			if err := w.c.ResultsFailed(ctx, "transport"); err != nil {
				t.Fatal(err)
			}
			hold, err := w.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = hold.Rollback(ctx) }()
			if _, err := hold.Exec(ctx, `SELECT 1 FROM contract_settings_state FOR UPDATE`); err != nil {
				t.Fatal(err)
			}
			holder := hold.Conn().PgConn().PID()
			var logs bytes.Buffer
			var mu sync.Mutex
			lctx := obs.WithLogger(ctx, slog.New(slog.NewTextHandler(&lockedWriter{&logs, &mu}, nil)))
			first := make(chan error, 1)
			go func() {
				if against == "a reset" {
					next := uuid.New()
					_, err := w.c.RestartFromCommands(lctx, gen, &next)
					first <- err
					return
				}
				_, err := w.c.TakeCommands(lctx, ContractCommandPage{SeenGeneration: gen, After: 0, NextAfter: 1, SignedAt: time.Now(),
					Items: []ContractCommandTake{{ID: x, Cseq: 1, Body: []byte("{}"), BodyKey: key, Verdict: CommandInvalid, Why: "test"}}})
				first <- err
			}()
			until(t, against+" to wait on the settings row", func() bool { return blocking(t, w.pool, holder) })
			posted := make(chan error, 1)
			go func() {
				posted <- w.c.ResultsPosted(lctx, []ContractResultOutcome{{ID: x, Answer: DeliveryAccepted}})
			}()
			// The poster is on its way to the settings row or the ledger row.
			time.Sleep(300 * time.Millisecond)
			if err := hold.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			firstErr, postErr := <-first, <-posted
			mu.Lock()
			log := logs.String()
			mu.Unlock()
			if firstErr != nil || postErr != nil || strings.Contains(log, "deadlocked") {
				t.Fatalf("%s: %v; the post: %v; log:\n%s", against, firstErr, postErr, log)
			}
		})
	}
}

// TestCommandRetentionInHours: a ledger row is kept 720 hours whatever the
// session's time zone (decision 0056: never less and never more). An
// interval of days would follow the calendar: in New York, where daylight
// saving time starts on 2026-03-08, '30 days' before 2026-03-20 12:00 UTC
// is 719 hours.
func TestCommandRetentionInHours(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Fresh(t, migrate.Run)
	at := time.Date(2026, 3, 20, 12, 0, 0, 0, time.UTC)
	for _, zone := range []string{"UTC", "America/New_York", "Europe/Berlin", "Australia/Sydney"} {
		var from time.Time
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SELECT set_config('TimeZone', $1, true)`, zone); err != nil {
				return err
			}
			return tx.QueryRow(ctx, `SELECT $1::timestamptz - `+commandRetentionSQL, at).Scan(&from)
		}); err != nil {
			t.Fatal(err)
		}
		if got := at.Sub(from); got != CommandRetention {
			t.Errorf("%s: the ledger keeps a row %v, want %v", zone, got, CommandRetention)
		}
	}
	if !strings.Contains(commandLive, commandRetentionSQL) {
		t.Error("commandLive does not use commandRetentionSQL")
	}
}
