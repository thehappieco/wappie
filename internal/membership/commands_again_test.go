package membership

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/membership/membershiptest"
	"whatserver2/internal/store"
)

// A tightening delivered again (after Wappie's own restore) is never
// answered with a retry, which the platform would take as a conflict and
// never issue again (the spec's 14.8): it waits until it runs. And a row
// the executor cannot read is answered invalid_command with its time
// stamped for --check.

// wait is a row's run state: its tries, class, and whether it waits.
func (w *world) wait(t *testing.T, id uuid.UUID) (tries int, class string, waiting bool) {
	t.Helper()
	if err := w.pool.QueryRow(context.Background(), `SELECT run_tries, coalesce(run_error, ''), run_after > clock_timestamp()
		FROM contract_commands WHERE id = $1`, id).Scan(&tries, &class, &waiting); err != nil {
		t.Fatal(err)
	}
	return tries, class, waiting
}

// due makes a waiting row due now.
func (w *world) due(t *testing.T, id uuid.UUID) {
	t.Helper()
	w.exec(context.Background(), t, `UPDATE contract_commands SET run_after = clock_timestamp() WHERE id = $1`, id)
}

// TestAgainNeverARetry: a person.sign_out_everywhere delivered again whose
// document Wappie has not applied yet (based_on one version ahead), or
// that comes while the mode does not run it (read), is not answered
// memberships_behind or kind_not_accepted: it waits, the session begun
// before it still live, and runs once the document is applied and the
// mode runs it, ending that session. One not delivered again is answered
// as before.
func TestAgainNeverARetry(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	logs := &membershiptest.Logs{}
	read, on := w.executorOf(t, store.SettingsRead, logs), w.executorOf(t, store.SettingsOn, logs)
	u, err := w.users.Get(ctx, w.home, w.owner)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := w.users.StartSession(ctx, u, "before")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	ahead := map[uuid.UUID]int64{w.sub: w.version(t, w.sub) + 1}
	signOut := row{kind: kc.OpPersonSignOutEverywhere, actor: w.sub, docs: ahead, again: true}

	// Not delivered again: answered memberships_behind, a retry.
	fresh := signOut
	fresh.again = false
	id := w.take(t, fresh)
	w.runNext(t, on)
	if got, _ := w.ledgerRow(t, id.String()); got.code != kc.CodeMembershipsBehind {
		t.Fatalf("a first delivery behind: %+v", got)
	}

	id = w.take(t, signOut)
	w.runNext(t, on)
	if got, _ := w.ledgerRow(t, id.String()); got.outcome != "" {
		t.Fatalf("delivered again behind: answered %+v", got)
	}
	if tries, class, waiting := w.wait(t, id); tries != 1 || class != "again_"+kc.CodeMembershipsBehind || !waiting {
		t.Fatalf("delivered again behind: tries %d, class %q, waiting %v", tries, class, waiting)
	}
	if _, _, err := w.users.ActiveSession(ctx, token); err != nil {
		t.Fatalf("the session before it, while it waits: %v", err)
	}

	// The document applied, but the mode read: it waits again.
	w.exec(ctx, t, `UPDATE contract_accounts SET version = version + 1 WHERE sub = $1`, w.sub)
	w.due(t, id)
	w.runNext(t, read)
	if got, _ := w.ledgerRow(t, id.String()); got.outcome != "" {
		t.Fatalf("delivered again in read: answered %+v", got)
	}
	if _, class, _ := w.wait(t, id); class != "again_"+kc.CodeKindNotAccepted {
		t.Fatalf("delivered again in read: class %q", class)
	}

	// In on, it runs.
	w.due(t, id)
	w.runNext(t, on)
	if got, _ := w.ledgerRow(t, id.String()); got.outcome != store.CommandRan {
		t.Fatalf("delivered again, its document applied, in on: %+v", got)
	}
	if _, _, err := w.users.ActiveSession(ctx, token); !errors.Is(err, store.ErrNoSession) {
		t.Fatalf("the session begun before it: %v", err)
	}
}

// TestAgainNeverRateLimited: a tightening delivered again whose run keeps
// failing with a store error waits on past the tries a stuck row is
// answered rate_limited at, with one ERROR recorded there, and runs once
// the error is gone.
func TestAgainNeverRateLimited(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	logs := &membershiptest.Logs{}
	on := w.executorOf(t, store.SettingsOn, logs)
	w.exec(ctx, t, `CREATE FUNCTION test_refuse_signout() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'the test refuses it' USING ERRCODE = '23514'; END $$`)
	w.exec(ctx, t, `CREATE TRIGGER test_refuse_signout BEFORE INSERT OR UPDATE ON contract_persons FOR EACH ROW EXECUTE FUNCTION test_refuse_signout()`)
	id := w.take(t, row{kind: kc.OpPersonSignOutEverywhere, actor: w.sub, docs: map[uuid.UUID]int64{w.sub: w.version(t, w.sub)}, again: true})
	for range store.CommandRunTries + 2 {
		w.due(t, id)
		w.runNext(t, on)
	}
	if got, _ := w.ledgerRow(t, id.String()); got.outcome != "" {
		t.Fatalf("delivered again, failing: answered %+v", got)
	}
	if tries, class, _ := w.wait(t, id); tries != store.CommandRunTries+2 || class != "sqlstate_23514" {
		t.Fatalf("delivered again, failing: tries %d, class %q", tries, class)
	}
	if n := len(logs.Lines("level=ERROR", "contract: a command delivered again keeps waiting")); n != 1 {
		t.Fatalf("%d ERRORs; the log:\n%s", n, logs.String())
	}
	if w.state(t).ErrorClass != store.ContractErrorCommandStuck {
		t.Fatalf("the ERROR recorded: %q", w.state(t).ErrorClass)
	}
	w.exec(ctx, t, `DROP TRIGGER test_refuse_signout ON contract_persons`)
	w.due(t, id)
	w.runNext(t, on)
	if got, _ := w.ledgerRow(t, id.String()); got.outcome != store.CommandRan {
		t.Fatalf("delivered again, once it no longer fails: %+v", got)
	}
}

// TestUnreadableStampsInvalid: a row the executor cannot read (a rename
// with no after) is answered invalid_command with no seq, an ERROR
// recorded, and the answer's time stamped, so --check reports it as it
// reports a take's.
func TestUnreadableStampsInvalid(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	logs := &membershiptest.Logs{}
	on := w.executorOf(t, store.SettingsOn, logs)
	before, err := w.contract.SettingsState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if before.InvalidAt != nil {
		t.Fatalf("an invalid_command before any: %v", before.InvalidAt)
	}
	id := w.take(t, row{kind: kc.OpItemRename, ws: &w.team, actor: w.sub, target: item(w.device), params: `{"before":{"label":"Vendas"}}`,
		docs: map[uuid.UUID]int64{w.sub: w.version(t, w.sub)}})
	w.runNext(t, on)
	if got, _ := w.ledgerRow(t, id.String()); got.code != kc.CodeInvalidCommand || got.stateSeq != nil {
		t.Fatalf("an unreadable row: %+v", got)
	}
	after, err := w.contract.SettingsState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after.InvalidAt == nil {
		t.Fatal("the executor's invalid_command left no time for --check")
	}
	if w.state(t).ErrorClass != store.ContractErrorCommandInvalid {
		t.Fatalf("the ERROR recorded: %q", w.state(t).ErrorClass)
	}
}
