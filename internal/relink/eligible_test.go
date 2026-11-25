package relink_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/relink"
	wstore "whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// Judge's table, one case per check, each set against a number that passes
// every check before it: the codes come in spec 14.13's order.
func TestJudgeTable(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	pass := relink.Facts{Status: wa.StatusLoggedOut, PN: types.NewJID(ownPN, types.DefaultUserServer),
		LID: types.NewJID(ownLID, types.HiddenUserServer), Epoch: 1, KeyHeld: true, Now: now}
	if r := relink.Judge(pass); r != nil {
		t.Fatalf("a number that passes = %+v", r)
	}
	for _, tc := range []struct {
		name   string
		change func(f *relink.Facts)
		want   string
		wait   time.Duration
	}{
		{"a pairing here", func(f *relink.Facts) { f.Pairing, f.PairingSince = true, now.Add(-100*time.Second) }, relink.CodeItemBusy, 75 * time.Second},
		{"a pairing at its end", func(f *relink.Facts) { f.Pairing, f.PairingSince = true, now.Add(-time.Hour) }, relink.CodeItemBusy, time.Second},
		{"a pairing just started", func(f *relink.Facts) { f.Pairing, f.PairingSince = true, now }, relink.CodeItemBusy, wa.PairWindow},
		{"a move running", func(f *relink.Facts) { f.MoveRunning = true }, relink.CodeWorkspaceBusy, wstore.MoveBusyRetry},
		{"online", func(f *relink.Facts) { f.Status = wa.StatusOnline }, relink.CodeStateChanged, 0},
		{"banned", func(f *relink.Facts) { f.Status = wa.StatusBanned }, relink.CodeStateChanged, 0},
		{"a hold that is not stale", func(f *relink.Facts) { f.Held = true }, relink.CodeItemBusy, wa.PairWindow},
		{"no LID", func(f *relink.Facts) { f.LID = types.JID{} }, relink.CodeReadOnly, 0},
		{"no phone number", func(f *relink.Facts) { f.PN = types.JID{} }, relink.CodeReadOnly, 0},
		{"halves swapped", func(f *relink.Facts) { f.PN, f.LID = f.LID, f.PN }, relink.CodeReadOnly, 0},
		{"no epoch", func(f *relink.Facts) { f.Epoch = 0 }, relink.CodeNoReader, 0},
		{"nobody holds the key", func(f *relink.Facts) { f.KeyHeld = false }, relink.CodeNoReader, 0},
		{"the account is another number", func(f *relink.Facts) { f.HeldElsewhere = true }, relink.CodeNumberHeld, 0},
		// The order: each check before the next.
		{"a pairing before a move", func(f *relink.Facts) {
			f.Pairing, f.PairingSince, f.MoveRunning = true, now, true
		}, relink.CodeItemBusy, wa.PairWindow},
		{"a move before not logged out", func(f *relink.Facts) { f.MoveRunning, f.Status = true, wa.StatusOnline }, relink.CodeWorkspaceBusy, wstore.MoveBusyRetry},
		{"a move before a hold", func(f *relink.Facts) { f.MoveRunning, f.Held = true, true }, relink.CodeWorkspaceBusy, wstore.MoveBusyRetry},
		{"not logged out before a hold", func(f *relink.Facts) { f.Status, f.Held = wa.StatusOnline, true }, relink.CodeStateChanged, 0},
		{"a hold before read_only", func(f *relink.Facts) { f.Held, f.LID = true, types.JID{} }, relink.CodeItemBusy, wa.PairWindow},
		{"read_only before no_reader", func(f *relink.Facts) { f.LID, f.KeyHeld = types.JID{}, false }, relink.CodeReadOnly, 0},
		{"no_reader before number_held", func(f *relink.Facts) { f.KeyHeld, f.HeldElsewhere = false, true }, relink.CodeNoReader, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := pass
			tc.change(&f)
			r := relink.Judge(f)
			if r == nil || r.Code != tc.want || r.RetryAfter != tc.wait || r.Message == "" {
				t.Fatalf("= %+v, want %s waiting %s", r, tc.want, tc.wait)
			}
		})
	}
}

// FillIdentity fills only a missing half, from the map, and says so.
func TestFillIdentity(t *testing.T) {
	ctx := context.Background()
	pn := types.JID{User: ownPN, Device: 3, Server: types.DefaultUserServer}
	lid := types.JID{User: ownLID, Device: 3, Server: types.HiddenUserServer}
	book := phoneBook{pn: types.NewJID(ownPN, types.DefaultUserServer), lid: types.NewJID(ownLID, types.HiddenUserServer)}
	if p, l, m := relink.FillIdentity(ctx, book, pn, lid); m || p != pn.ToNonAD() || l != lid.ToNonAD() {
		t.Errorf("both halves = %v %v %v", p, l, m)
	}
	if p, l, m := relink.FillIdentity(ctx, book, pn, types.JID{}); !m || !relink.FullIdentity(p, l) {
		t.Errorf("no LID = %v %v %v", p, l, m)
	}
	if p, l, m := relink.FillIdentity(ctx, book, types.JID{}, lid); !m || !relink.FullIdentity(p, l) {
		t.Errorf("no phone number = %v %v %v", p, l, m)
	}
	if _, _, m := relink.FillIdentity(ctx, nil, pn, types.JID{}); m {
		t.Error("no map filled a half")
	}
	if p, l, m := relink.FillIdentity(ctx, phoneBook{}, pn, types.JID{}); m || relink.FullIdentity(p, l) {
		t.Errorf("a map that knows nothing = %v %v %v", p, l, m)
	}
}

// Start attaches with the function it is given, and with the number's own
// AttachRelink when given none.
func TestStartUsesGivenAttach(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	pairer := &fakePairer{}
	svc := &relink.Service{Devices: w.devices, Pairer: pairer, Log: slog.New(slog.DiscardHandler)}
	device := w.number(t, ownPN, ownLID)
	target, err := svc.Check(ctx, w.tenant, device)
	if err != nil {
		t.Fatal(err)
	}
	linked := wa.Identity{PN: types.JID{User: ownPN, Device: 12, Server: types.DefaultUserServer},
		LID: types.JID{User: ownLID, Device: 12, Server: types.HiddenUserServer}}
	errMine := errors.New("the given attach")
	var got wa.Identity
	sess, err := svc.Start(ctx, target, relink.Actor{Kind: "person", ID: w.owner}, func(_ context.Context, l wa.Identity) (wstore.Attached, error) {
		got = l
		return wstore.Attached{}, errMine
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := pairer.opts[0].Relink.Attach(ctx, linked); !errors.Is(err, errMine) || got != linked {
		t.Fatalf("the given attach: %v, got %+v", err, got)
	}
	pairer.started[0].events <- wa.PairEvent{Kind: wa.PairEventError, Err: wa.ErrLinkFailed}
	close(pairer.started[0].events)
	for range sess.Events() {
	}

	// nil: the number's own AttachRelink, which finds no session stored
	// for the new link and changes nothing.
	sess, err = svc.Start(ctx, target, relink.Actor{Kind: "person", ID: w.owner}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := pairer.opts[1].Relink.Attach(ctx, linked); !errors.Is(err, wstore.ErrRelinkNoSession) {
		t.Fatalf("nil attach = %v", err)
	}
	pairer.started[1].events <- wa.PairEvent{Kind: wa.PairEventError, Err: wa.ErrLinkFailed}
	close(pairer.started[1].events)
	for range sess.Events() {
	}
}

// Running: one relink per number, removed only by its own session,
// cancelled one by one or all at once; a nil one is empty.
func TestRunning(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	pairer := &fakePairer{}
	svc := &relink.Service{Devices: w.devices, Pairer: pairer, Log: slog.New(slog.DiscardHandler)}
	a, b := w.number(t, ownPN, ownLID), w.number(t, "155501000904", "100000000000904")
	start := func(device uuid.UUID) *relink.Session {
		target, err := svc.Check(ctx, w.tenant, device)
		if err != nil {
			t.Fatal(err)
		}
		sess, err := svc.Start(ctx, target, relink.Actor{Kind: "person", ID: w.owner}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return sess
	}
	sa, sb := start(a), start(b)
	var r relink.Running
	cmdA := uuid.New()
	if !r.Add(a, cmdA, sa) || r.Add(a, uuid.New(), sb) || !r.Add(b, uuid.New(), sb) {
		t.Fatal("one relink per number")
	}
	if got, ok := r.Command(a); !ok || got != cmdA || !r.Has(a) || r.Has(uuid.New()) {
		t.Fatalf("command %v %v", got, ok)
	}
	r.Remove(a, sb)
	if !r.Has(a) {
		t.Fatal("another session removed a's relink")
	}
	if !r.Cancel(a) || r.Cancel(uuid.New()) {
		t.Fatal("cancel")
	}
	r.CancelAll()
	for i, p := range pairer.started {
		p.cancelMu.Lock()
		n := p.cancels
		p.cancelMu.Unlock()
		if want := map[int]int{0: 2, 1: 1}[i]; n != want {
			t.Errorf("pairing %d cancelled %d times, want %d", i, n, want)
		}
		close(p.events)
	}
	for range sa.Events() {
	}
	for range sb.Events() {
	}
	r.Remove(a, sa)
	if r.Has(a) {
		t.Fatal("a's relink was not removed")
	}
	var none *relink.Running
	if none.Has(a) || none.Cancel(a) {
		t.Fatal("a nil Running holds something")
	}
	none.CancelAll()
}
