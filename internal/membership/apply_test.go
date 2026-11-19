package membership

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"whatserver2/internal/store"
)

// Members' part of the apply at enforce (DS54): what it does around the
// store's apply, which refuses before enforce, so these tests stand a fake
// in for the store's (applier).

// fakeApplier is the store's apply, answering what a test sets, and
// recording the closings it was asked to confirm.
type fakeApplier struct {
	mu       sync.Mutex
	account  store.ApplyResult
	err      error
	confirms []store.ContractDoc
}

func (f *fakeApplier) EnsureTeams(context.Context, uuid.UUID) ([]uuid.UUID, error) { return nil, nil }

func (f *fakeApplier) PendingWorkspacesOf(context.Context, uuid.UUID) ([]uuid.UUID, error) {
	return nil, nil
}

func (f *fakeApplier) ApplyWorkspace(_ context.Context, id uuid.UUID) (store.ApplyResult, error) {
	return store.ApplyResult{Workspace: id}, nil
}

func (f *fakeApplier) ApplyAccount(context.Context, uuid.UUID) (store.ApplyResult, error) {
	return f.account, f.err
}

func (f *fakeApplier) ConfirmClosing(_ context.Context, _ uuid.UUID, fresh store.ContractDoc) (store.ClosingResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.confirms = append(f.confirms, fresh)
	switch fresh.Status {
	case "active":
		return store.ClosingResult{}, store.ErrClosingContradicted
	case "closed":
		return store.ClosingResult{Sub: fresh.Sub, Quarantined: 1}, nil
	}
	return store.ClosingResult{}, store.ErrClosingUnconfirmed
}

func (f *fakeApplier) asked() []store.ContractDoc {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.confirms)
}

type tellRecorder struct {
	mu    sync.Mutex
	told  []string
	waken int
}

func (r *tellRecorder) TellRevoked(_ context.Context, reader, id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.told = append(r.told, reader+"/"+id)
}

func (r *tellRecorder) RevalidateAccess() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.waken++
}

// An apply that ended connections tells each reader, wakes this process's
// sessions and logs what it did; one that failed is logged at ERROR and
// recorded for contract status --check.
func TestMembersApplyTellsEndedReaders(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	sub := uuid.New()
	rec := &tellRecorder{}
	fake := &fakeApplier{account: store.ApplyResult{Sub: sub, Version: 3,
		Actions: []store.ApplyAction{{Kind: store.ApplyMemberLost, Workspace: uuid.New()}},
		Ended:   []store.EndedConnection{{ID: "c1", Reader: "hosted"}, {ID: "c2", Reader: "enclave"}},
		Counts:  store.ApplyCounts{Lost: 1, Connections: 2}}}
	m := w.members
	m.applier, m.Readers, m.Sockets = fake, rec, rec
	if _, err := m.Apply(ctx, sub); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(rec.told, []string{"hosted/c1", "enclave/c2"}) || rec.waken != 1 {
		t.Fatalf("told %v, sessions woken %d times", rec.told, rec.waken)
	}
	if len(w.logs.Lines("contract apply: applied", "sub="+sub.String(), "lost=1")) != 1 {
		t.Fatalf("the log:\n%s", w.logs)
	}
	fake.err = errors.New("boom")
	if _, err := m.Apply(ctx, sub); err == nil {
		t.Fatal("a failed apply returned no error")
	}
	if len(w.logs.Lines("contract apply: failed", "class=other")) != 1 {
		t.Fatalf("the failure's log:\n%s", w.logs)
	}
	if state := w.state(t); state.ErrorClass != store.ContractErrorApplyFailed {
		t.Fatalf("the recorded ERROR: %q", state.ErrorClass)
	}
	// Refused before enforce: neither logged as a failure nor recorded.
	fake.err = store.ErrApplyNeedsEnforce
	before := len(w.logs.Lines("contract apply: failed"))
	if _, err := m.Apply(ctx, sub); !errors.Is(err, store.ErrApplyNeedsEnforce) {
		t.Fatalf("before enforce: %v", err)
	}
	if len(w.logs.Lines("contract apply: failed")) != before {
		t.Fatal("a refusal before enforce was logged as a failure")
	}
}

// Observe never applies: no file of the package but apply.go, and none of
// whatserverd's but contract_apply.go, calls an apply. E2 wires them.
func TestObserveNeverApplies(t *testing.T) {
	applies := []string{"Apply", "ApplyPending", "ApplyAccount", "ApplyWorkspace", "EnsureTeams", "ConfirmClosing",
		"ForgetClosed", "SweepOrphanServices", "applies"}
	for _, c := range []struct{ dir, allowed string }{{".", "apply.go"}, {"../../cmd/whatserverd", "contract_apply.go"}} {
		files, err := filepath.Glob(filepath.Join(c.dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range files {
			if strings.HasSuffix(path, "_test.go") || filepath.Base(path) == c.allowed {
				continue
			}
			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			f, err := parser.ParseFile(token.NewFileSet(), path, src, 0)
			if err != nil {
				t.Fatal(err)
			}
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && slices.Contains(applies, sel.Sel.Name) {
					t.Errorf("%s calls %s", path, sel.Sel.Name)
				}
				return true
			})
		}
	}
}

// A closing is confirmed only on a signed answer that says closed: no
// answer asks the store nothing, an active one is logged at ERROR and
// recorded (closing_contradicted), and a closed one is confirmed.
func TestConfirmClosingNeedsFreshClosedAnswer(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	fake := &fakeApplier{}
	m := w.members
	m.applier = fake
	sub := uuid.New()
	if _, err := w.fake.AddAccount(sub.String()); err != nil {
		t.Fatal(err)
	}

	w.fake.SetDown(true)
	m.confirmClosing(ctx, sub)
	w.fake.SetDown(false)
	if got := fake.asked(); len(got) != 0 {
		t.Fatalf("with no answer the store was asked: %+v", got)
	}
	m.confirmClosing(ctx, uuid.New())
	if got := fake.asked(); len(got) != 0 {
		t.Fatalf("with a not_found the store was asked: %+v", got)
	}

	m.confirmClosing(ctx, sub)
	if got := fake.asked(); len(got) != 1 || got[0].Status != "active" {
		t.Fatalf("an active answer: %+v", got)
	}
	if len(w.logs.Lines("contract apply: closing_contradicted", "sub="+sub.String())) != 1 {
		t.Fatalf("the log:\n%s", w.logs)
	}
	if state := w.state(t); state.ErrorClass != store.ContractErrorClosingContradicted {
		t.Fatalf("the recorded ERROR: %q", state.ErrorClass)
	}

	if err := w.fake.CloseAccount(sub.String()); err != nil {
		t.Fatal(err)
	}
	m.confirmClosing(ctx, sub)
	if got := fake.asked(); len(got) != 2 || got[1].Status != "closed" || got[1].Sub != sub {
		t.Fatalf("a closed answer: %+v", got)
	}
	if len(w.logs.Lines("contract apply: closing confirmed", "sub="+sub.String())) != 1 {
		t.Fatalf("the confirmation's log:\n%s", w.logs)
	}
}

// The apply's log lines carry ids, codes and counts only (DB22): no
// address, no name, no team name.
func TestApplyLogsIdsOnly(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	user, sub := w.held(t)
	var actions []store.ApplyAction
	for _, kind := range []string{store.ApplyTeamCreated, store.ApplyMemberAdded, store.ApplyRoleChanged, store.ApplyMemberEnabled,
		store.ApplyMemberLost, store.ApplyTeamRenamed, store.ApplyTeamClosed, store.ApplyTeamReopened, store.ApplyPersonalNamed,
		store.ApplyAccountSuspended, store.ApplySessionsEnded, store.ApplyCredentialsStopped, store.ApplyServiceKept} {
		actions = append(actions, store.ApplyAction{Kind: kind, Sub: sub, User: user, Workspace: uuid.New(), Local: "member", Platform: "admin", Count: 1})
	}
	fake := &fakeApplier{account: store.ApplyResult{Sub: sub, Version: 2, Actions: actions, Held: store.HeldStrandsUnconfirmed,
		OperatorDisable: true, Ended: []store.EndedConnection{{ID: uuid.NewString(), Reader: "hosted"}},
		Counts: store.ApplyCounts{Added: 1, Roles: 1, Lost: 1, Renamed: 1, Sessions: 2, Keys: 3}}}
	m := w.members
	m.applier = fake
	if _, err := m.Apply(ctx, sub); err != nil {
		t.Fatal(err)
	}
	fake.err = errors.New("a failure that names Vendas and ana@example.com")
	_, _ = m.Apply(ctx, sub)
	logs := w.logs.String()
	for _, line := range strings.Split(logs, "\n") {
		if !strings.Contains(line, "contract apply") {
			continue
		}
		if strings.Contains(line, "@") || strings.Contains(line, "Vendas") || strings.Contains(line, "example") {
			t.Errorf("a log line names someone: %s", line)
		}
	}
	for _, want := range []string{"contract apply: applied", "contract apply: held", "contract apply: operator disable stands", "contract apply: failed"} {
		if len(w.logs.Lines(want, "sub="+sub.String())) == 0 {
			t.Errorf("no %q line:\n%s", want, logs)
		}
	}
}
