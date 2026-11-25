package store_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// The console's item.relink in the ledger (kit v0.11.0): its judgement,
// its in_progress, the final result that replaces only an in_progress,
// the attach that writes ran in its own transaction, and the settle that
// never marks a later final result delivered. Fictional accounts only.

// relinkWorld is an act world with a logged-out number the owner reads and
// an admin who may relink it.
type relinkWorld struct {
	*actWorld
	item      uuid.UUID
	id        wa.Identity
	user, sub uuid.UUID
}

func newRelinkWorld(t *testing.T) *relinkWorld {
	t.Helper()
	w := &relinkWorld{actWorld: newActWorld(t)}
	sessionStore(t, w.pool)
	w.item, w.id = w.loggedOutNumber(t, "Loja", "155501000201", "100000000000201")
	w.user, w.sub = w.actor(t, "admin", "admin")
	return w
}

// inProgress takes an item.relink and writes its in_progress.
func (w *relinkWorld) inProgress(t *testing.T) (store.ContractRun, store.ContractAct) {
	t.Helper()
	run := w.command(t, kc.OpItemRelink, w.user, w.sub)
	act, err := w.c.StartRelinkCommand(context.Background(), run, w.item, w.seen(t, w.item), nil)
	if err != nil || act.Result.Outcome != store.CommandInProgress || act.Result.StateSeq == nil || *act.Result.StateSeq != act.Seq {
		t.Fatalf("in_progress: %+v %v", act, err)
	}
	return run, act
}

func (w *relinkWorld) delivery(t *testing.T, id uuid.UUID) (delivery string, tries int) {
	t.Helper()
	if err := w.pool.QueryRow(context.Background(), `SELECT coalesce(delivery, ''), post_tries FROM contract_commands WHERE id = $1`,
		id).Scan(&delivery, &tries); err != nil {
		t.Fatal(err)
	}
	return delivery, tries
}

func undelivered(t *testing.T, c *store.Contract, id uuid.UUID) (store.ContractResult, bool) {
	t.Helper()
	rows, err := c.UndeliveredResults(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.ID == id {
			return r, true
		}
	}
	return store.ContractResult{}, false
}

// TestJudgeRelink: the number live (a deleted one not_found), then
// item_busy while it pairs here, then workspace_busy while a move out of
// the workspace runs, both before the role, then owners and admins only;
// a finished move's pause holds nothing; a number that passes leaves the
// act open, with nothing written.
func TestJudgeRelink(t *testing.T) {
	ctx := context.Background()
	w := newRelinkWorld(t)
	gone := w.number(t, "Apagado")
	w.quarantine(t, gone)
	act, err := w.c.JudgeRelink(ctx, w.command(t, kc.OpItemRelink, w.user, w.sub), gone, nil)
	refusedWith(t, "a deleted number", act, err, kc.CodeNotFound)

	member, memberSub := w.actor(t, "member", "member")
	busy := func(uuid.UUID) (int, bool) { return 42, true }
	act, err = w.c.JudgeRelink(ctx, w.command(t, kc.OpItemRelink, member, memberSub), w.item, busy)
	refusedWith(t, "a pairing here, before the role", act, err, kc.CodeItemBusy)
	if act.Result.RetryAfter != 42 {
		t.Fatalf("item_busy's wait %d", act.Result.RetryAfter)
	}
	release, err := w.devices.HoldMove(ctx, w.tenant, w.item)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	act, err = w.c.JudgeRelink(ctx, w.command(t, kc.OpItemRelink, member, memberSub), w.item, busy)
	refusedWith(t, "a pairing here, before a move", act, err, kc.CodeItemBusy)
	act, err = w.c.JudgeRelink(ctx, w.command(t, kc.OpItemRelink, member, memberSub), w.item, nil)
	refusedWith(t, "a move running, before the role", act, err, kc.CodeWorkspaceBusy)
	if act.Result.RetryAfter != int(store.MoveBusyRetry/time.Second) {
		t.Fatalf("workspace_busy's wait %d", act.Result.RetryAfter)
	}
	release()
	// The move ended and left its pause: nothing holds the number.
	w.execOne(t, `UPDATE devices SET paused = true, pause_cause = 'move' WHERE id = $1`, w.item)
	act, err = w.c.JudgeRelink(ctx, w.command(t, kc.OpItemRelink, member, memberSub), w.item, nil)
	refusedWith(t, "a member", act, err, kc.CodeNotAuthorized)

	run := w.command(t, kc.OpItemRelink, w.user, w.sub)
	act, err = w.c.JudgeRelink(ctx, run, w.item, nil)
	if err != nil || !act.Open {
		t.Fatalf("an admin: %+v %v", act, err)
	}
	if l := w.ledger(t, run.ID); l.outcome != "" {
		t.Fatalf("a judgement wrote %+v", l)
	}
}

// TestStartRelinkCommand: in_progress at the act's seq, which counts as
// run for the workspace's order (the wseq memory) and makes the numbers
// section due; state_changed for a number paused since the Check, no
// longer logged out, or paused later than based_on; not_found once
// deleted; and a pause before based_on is no change.
func TestStartRelinkCommand(t *testing.T) {
	ctx := context.Background()
	w := newRelinkWorld(t)
	w.later(t)
	run, act := w.inProgress(t)
	if l := w.ledger(t, run.ID); l.outcome != store.CommandInProgress || l.code != "" || l.seq == nil || *l.seq != act.Seq {
		t.Fatalf("the ledger %+v", l)
	}
	if _, _, due, _ := w.clock(t); due > 0 {
		t.Fatalf("the numbers section is due in %v", due)
	}
	var wseq int64
	if err := w.pool.QueryRow(ctx, `SELECT wseq FROM contract_command_wseq WHERE workspace_id = $1`, w.tenant).Scan(&wseq); err != nil ||
		wseq != w.cseq {
		t.Fatalf("the wseq memory %d %v, want %d", wseq, err, w.cseq)
	}
	if _, ok, err := w.c.NextCommand(ctx); err != nil || ok {
		t.Fatalf("an in_progress row is open to the executor: %v %v", ok, err)
	}
	if _, err := w.c.StartRelinkCommand(ctx, run, w.item, w.seen(t, w.item), nil); !errors.Is(err, store.ErrCommandFinished) {
		t.Fatalf("a second start = %v", err)
	}

	seen := w.seen(t, w.item)
	if _, err := w.devices.Pause(ctx, w.tenant, w.item, store.PauseActor{User: w.owner}); err != nil {
		t.Fatal(err)
	}
	act, err := w.c.StartRelinkCommand(ctx, w.command(t, kc.OpItemRelink, w.user, w.sub), w.item, seen, nil)
	refusedWith(t, "paused since the Check", act, err, kc.CodeStateChanged)

	// Paused now, seen so: a pause before based_on is no change, one after
	// it is.
	seen = w.seen(t, w.item)
	var pausedAt int64
	w.scoped(t, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT floor(extract(epoch FROM paused_at) * 1000)::bigint FROM devices WHERE id = $1`,
			w.item).Scan(&pausedAt)
	})
	after, before := pausedAt, pausedAt-1
	act, err = w.c.StartRelinkCommand(ctx, w.command(t, kc.OpItemRelink, w.user, w.sub), w.item, seen, &before)
	refusedWith(t, "a pause later than based_on", act, err, kc.CodeStateChanged)
	act, err = w.c.StartRelinkCommand(ctx, w.command(t, kc.OpItemRelink, w.user, w.sub), w.item, seen, &after)
	if err != nil || act.Result.Outcome != store.CommandInProgress {
		t.Fatalf("a pause the console drew: %+v %v", act, err)
	}

	// A move that started since the Check and still runs: workspace_busy
	// (DS56), before the state_changed its pause's pause_seq would give.
	seen = w.seen(t, w.item)
	release, err := w.devices.HoldMove(ctx, w.tenant, w.item)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	w.execOne(t, `UPDATE devices SET pause_cause = 'move', pause_seq = pause_seq + 1 WHERE id = $1`, w.item)
	run = w.command(t, kc.OpItemRelink, w.user, w.sub)
	act, err = w.c.StartRelinkCommand(ctx, run, w.item, seen, nil)
	refusedWith(t, "a move running, its pause since the Check", act, err, kc.CodeWorkspaceBusy)
	wait := int(store.MoveBusyRetry / time.Second)
	if act.Result.RetryAfter != wait {
		t.Fatalf("workspace_busy's wait %d", act.Result.RetryAfter)
	}
	if l := w.ledger(t, run.ID); l.retryAfter == nil || *l.retryAfter != wait || l.seq == nil {
		t.Fatalf("workspace_busy's ledger %+v", l)
	}
	release()
	// Once it ended: its pause since the Check is a pause later than the
	// start, state_changed; the same pause seen at the Check, older than
	// based_on, is no change, and the attach lifts it.
	act, err = w.c.StartRelinkCommand(ctx, w.command(t, kc.OpItemRelink, w.user, w.sub), w.item, seen, nil)
	refusedWith(t, "a finished move's pause since the Check", act, err, kc.CodeStateChanged)
	w.scoped(t, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT floor(extract(epoch FROM paused_at) * 1000)::bigint FROM devices WHERE id = $1`,
			w.item).Scan(&pausedAt)
	})
	act, err = w.c.StartRelinkCommand(ctx, w.command(t, kc.OpItemRelink, w.user, w.sub), w.item, w.seen(t, w.item), &pausedAt)
	if err != nil || act.Result.Outcome != store.CommandInProgress {
		t.Fatalf("a finished move's pause the console drew: %+v %v", act, err)
	}
	w.execOne(t, `UPDATE devices SET pause_cause = 'person' WHERE id = $1`, w.item)

	online := w.number(t, "Online")
	act, err = w.c.StartRelinkCommand(ctx, w.command(t, kc.OpItemRelink, w.user, w.sub), online, w.seen(t, online), nil)
	refusedWith(t, "a number online", act, err, kc.CodeStateChanged)

	w.quarantine(t, w.item, w.owner)
	act, err = w.c.StartRelinkCommand(ctx, w.command(t, kc.OpItemRelink, w.user, w.sub), w.item, seen, nil)
	refusedWith(t, "a number deleted", act, err, kc.CodeNotFound)
}

// TestFinishInProgressOnly: a final result replaces an in_progress only:
// a second final is ErrCommandFinished, and so is one on a row that never
// had an in_progress; the final result is undelivered afresh, its post's
// tries and rejection gone; its state_seq the judged seq, none for
// expired.
func TestFinishInProgressOnly(t *testing.T) {
	ctx := context.Background()
	w := newRelinkWorld(t)
	run, _ := w.inProgress(t)
	got, ok := undelivered(t, w.c, run.ID)
	if !ok || got.Outcome != store.CommandInProgress {
		t.Fatalf("the in_progress to post: %+v %v", got, ok)
	}
	if err := w.c.ResultsPosted(ctx, []store.ContractResultOutcome{{ID: run.ID, Failed: "timeout", ResultAt: got.At}}); err != nil {
		t.Fatal(err)
	}
	if err := w.c.ResultsPosted(ctx, []store.ContractResultOutcome{{ID: run.ID, Answer: store.DeliveryRejected, Code: "conflict",
		ResultAt: got.At}}); err != nil {
		t.Fatal(err)
	}
	if d, tries := w.delivery(t, run.ID); d != store.DeliveryRejected || tries != 1 {
		t.Fatalf("the in_progress's delivery %q, tries %d", d, tries)
	}

	if err := w.c.FinishInProgress(ctx, run.ID, store.CommandResult{Code: kc.CodeLinkTimeout}); err != nil {
		t.Fatal(err)
	}
	l := w.ledger(t, run.ID)
	sections, snapshot, _, _ := w.clock(t)
	if l.outcome != store.CommandRefused || l.code != kc.CodeLinkTimeout || l.seq == nil || *l.seq != max(sections, snapshot) {
		t.Fatalf("the final result %+v, the clock %d/%d", l, sections, snapshot)
	}
	if d, tries := w.delivery(t, run.ID); d != "" || tries != 0 {
		t.Fatalf("the final result's delivery %q, tries %d", d, tries)
	}
	var reject, postError *string
	if err := w.pool.QueryRow(ctx, `SELECT reject_code, post_error FROM contract_commands WHERE id = $1`, run.ID).
		Scan(&reject, &postError); err != nil || reject != nil || postError != nil {
		t.Fatalf("reject_code %v, post_error %v, %v", reject, postError, err)
	}
	if err := w.c.FinishInProgress(ctx, run.ID, store.CommandResult{Code: kc.CodeConnectFailed}); !errors.Is(err, store.ErrCommandFinished) {
		t.Fatalf("a second final = %v", err)
	}
	open := w.command(t, kc.OpItemRelink, w.user, w.sub)
	if err := w.c.FinishInProgress(ctx, open.ID, store.CommandResult{Code: kc.CodeConnectFailed}); !errors.Is(err, store.ErrCommandFinished) {
		t.Fatalf("a final with no in_progress = %v", err)
	}

	run, _ = w.inProgress(t)
	if err := w.c.FinishInProgress(ctx, run.ID, store.CommandResult{Code: kc.CodeItemBusy, RetryAfter: 30}); err != nil {
		t.Fatal(err)
	}
	if l := w.ledger(t, run.ID); l.code != kc.CodeItemBusy || l.retryAfter == nil || *l.retryAfter != 30 || l.seq == nil {
		t.Fatalf("item_busy %+v", l)
	}
	run, _ = w.inProgress(t)
	if err := w.c.FinishInProgress(ctx, run.ID, store.CommandResult{Code: kc.CodeExpired}); err != nil {
		t.Fatal(err)
	}
	if l := w.ledger(t, run.ID); l.code != kc.CodeExpired || l.seq != nil {
		t.Fatalf("expired %+v", l)
	}
}

// TestResultsPostedKeepsALaterFinal: the in_progress is read and posted;
// meanwhile the final result replaces it; the in_progress's answer (and a
// failed post's, and a park's) settles nothing of the final one, which is
// posted in turn.
func TestResultsPostedKeepsALaterFinal(t *testing.T) {
	ctx := context.Background()
	w := newRelinkWorld(t)
	for name, settle := range map[string]func(r store.ContractResult) error{
		"accepted": func(r store.ContractResult) error {
			return w.c.ResultsPosted(ctx, []store.ContractResultOutcome{{ID: r.ID, Answer: store.DeliveryAccepted, ResultAt: r.At}})
		},
		"failed": func(r store.ContractResult) error {
			return w.c.ResultsPosted(ctx, []store.ContractResultOutcome{{ID: r.ID, Failed: "timeout", ResultAt: r.At}})
		},
		"parked": func(r store.ContractResult) error {
			return w.c.ResultsParked(ctx, []store.ContractResultRef{{ID: r.ID, At: r.At}}, "local_invalid:invalid")
		},
	} {
		t.Run(name, func(t *testing.T) {
			run, _ := w.inProgress(t)                 //nolint:contextcheck // the world's helpers run on a context of their own
			posted, ok := undelivered(t, w.c, run.ID) //nolint:contextcheck // the world's helpers run on a context of their own
			if !ok || posted.Outcome != store.CommandInProgress {
				t.Fatalf("the in_progress: %+v %v", posted, ok)
			}
			if err := w.c.FinishInProgress(ctx, run.ID, store.CommandResult{Code: kc.CodeOtherAccount}); err != nil {
				t.Fatal(err)
			}
			if err := settle(posted); err != nil {
				t.Fatal(err)
			}
			final, ok := undelivered(t, w.c, run.ID) //nolint:contextcheck // the world's helpers run on a context of their own
			if !ok || final.Outcome != store.CommandRefused || final.Code != kc.CodeOtherAccount || final.PostTries != 0 {
				t.Fatalf("the final result after the in_progress settled: %+v %v", final, ok)
			}
			// Its own answer settles it.
			if err := settle(final); err != nil {
				t.Fatal(err)
			}
			if d, _ := w.delivery(t, run.ID); name != "failed" && d == "" { //nolint:contextcheck // the world's helpers run on a context of their own
				t.Fatalf("the final result's own answer left it undelivered")
			}
		})
	}
}

// TestAttachRelinkCommand: the attach writes the new link and the
// command's ran at the act's seq, with the numbers section and the
// snapshot due now and the pause lifted; on a row no longer in_progress
// it attaches nothing; and it runs beside a pause and a sync stop of the
// number without a deadlock, in the record, command, wseq, tenants, device
// order.
func TestAttachRelinkCommand(t *testing.T) {
	ctx := context.Background()
	w := newRelinkWorld(t)
	if _, err := w.devices.Pause(ctx, w.tenant, w.item, store.PauseActor{User: w.owner}); err != nil {
		t.Fatal(err)
	}
	linked := newLink(w.id)
	w.putSession(t, linked.PN.String())

	run, _ := w.inProgress(t)
	w.later(t)
	seen := w.seen(t, w.item)
	act, att, err := w.c.AttachRelinkCommand(ctx, run, w.item, seen, linked)
	ranAct(t, "the attach", act, err)
	if !att.ResumedPause {
		t.Fatal("the attach lifted no pause")
	}
	sections, _, numbersDue, snapshotDue := w.clock(t)
	if l := w.ledger(t, run.ID); l.outcome != store.CommandRan || l.seq == nil || *l.seq != act.Seq || act.Seq != sections {
		t.Fatalf("the ledger %+v, the act's seq %d, the clock %d", l, act.Seq, sections)
	}
	if numbersDue > 0 || snapshotDue > 0 {
		t.Fatalf("after the attach the numbers section is due in %v, the snapshot in %v", numbersDue, snapshotDue)
	}
	d := w.device(t, w.item)
	if d.Status != wa.StatusOffline || d.Paused || d.Identity.PN != linked.PN || d.Identity.LID != linked.LID {
		t.Fatalf("the number after the attach %+v", d)
	}
	if _, _, err := w.c.AttachRelinkCommand(ctx, run, w.item, seen, linked); !errors.Is(err, store.ErrCommandFinished) {
		t.Fatalf("a second attach = %v", err)
	}

	// A row another end answered: nothing attached.
	other, otherID := w.loggedOutNumber(t, "Outro", "155501000202", "100000000000202")
	otherLink := newLink(otherID)
	w.putSession(t, otherLink.PN.String())
	run = w.command(t, kc.OpItemRelink, w.user, w.sub)
	if _, err := w.c.StartRelinkCommand(ctx, run, other, w.seen(t, other), nil); err != nil {
		t.Fatal(err)
	}
	if err := w.c.FinishInProgress(ctx, run.ID, store.CommandResult{Code: kc.CodeConnectFailed}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.c.AttachRelinkCommand(ctx, run, other, w.seen(t, other), otherLink); !errors.Is(err, store.ErrCommandFinished) {
		t.Fatalf("an attach of a finished row = %v", err)
	}
	if d := w.device(t, other); d.Status != wa.StatusLoggedOut || d.Identity.PN != otherID.PN {
		t.Fatalf("a finished row's attach changed the number: %+v", d)
	}

	// Beside a pause and a sync stop of the number, many times: each ends,
	// none deadlocks, and the attach either ran or found the number
	// changed.
	for i := range 6 {
		number, ident := w.loggedOutNumber(t, "Corrida", "1555010003"+string(rune('0'+i))+"0", "1000000000003"+string(rune('0'+i))+"0")
		link := newLink(ident)
		w.putSession(t, link.PN.String())
		run := w.command(t, kc.OpItemRelink, w.user, w.sub)
		if _, err := w.c.StartRelinkCommand(ctx, run, number, w.seen(t, number), nil); err != nil {
			t.Fatal(err)
		}
		stop := w.command(t, kc.OpItemSyncStop, w.user, w.sub)
		seen := w.seen(t, number)
		var wg sync.WaitGroup
		errs := make([]error, 3)
		wg.Go(func() { _, _, errs[0] = w.c.AttachRelinkCommand(ctx, run, number, seen, link) })
		wg.Go(func() { _, errs[1] = w.devices.Pause(ctx, w.tenant, number, store.PauseActor{User: w.owner}) })
		wg.Go(func() { _, _, errs[2] = w.c.RunSyncStop(ctx, stop, number) })
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Fatal("the attach, a pause and a sync stop did not all end")
		}
		if errs[0] != nil && !errors.Is(errs[0], store.ErrRelinkStateChanged) {
			t.Fatalf("round %d: the attach = %v", i, errs[0])
		}
		if errs[1] != nil || errs[2] != nil {
			t.Fatalf("round %d: the pause = %v, the stop = %v", i, errs[1], errs[2])
		}
	}
}

// TestInProgressRelinks lists the item.relink rows left in_progress, and
// no other.
func TestInProgressRelinks(t *testing.T) {
	ctx := context.Background()
	w := newRelinkWorld(t)
	run, _ := w.inProgress(t)
	w.command(t, kc.OpItemRelink, w.user, w.sub)
	done, _ := w.inProgress(t)
	if err := w.c.FinishInProgress(ctx, done.ID, store.CommandResult{Code: kc.CodeLinkTimeout}); err != nil {
		t.Fatal(err)
	}
	w.execOne(t, `UPDATE contract_commands SET target = jsonb_build_object('item', $2::text) WHERE id = $1`, run.ID, w.item.String())
	got, err := w.c.InProgressRelinks(ctx)
	if err != nil || len(got) != 1 || got[0] != (store.InProgressRelink{ID: run.ID, Workspace: w.tenant, Device: w.item}) {
		t.Fatalf("in progress %+v %v", got, err)
	}
}

// TestNumbersRelinkColumns: the numbers section reads each number's stored
// identity, and whether a person holds its key only for a live number
// logged out.
func TestNumbersRelinkColumns(t *testing.T) {
	ctx := context.Background()
	w := newRelinkWorld(t)
	online := w.number(t, "Online")
	w.reads(t, w.owner, online)
	keyless, _ := w.loggedOutNumber(t, "Sem chave", "155501000203", "100000000000203")
	w.execOne(t, `DELETE FROM device_key_grants WHERE device_id = $1`, keyless)
	gone, _ := w.loggedOutNumber(t, "Apagado", "155501000204", "100000000000204")
	w.quarantine(t, gone, w.owner)

	n := w.numbers(ctx, t, w.c)
	for _, tc := range []struct {
		device  uuid.UUID
		keyHeld bool
	}{{w.item, true}, {online, false}, {keyless, false}, {gone, false}} {
		it, ok := itemOf(n, tc.device)
		if !ok {
			t.Fatalf("%s is not listed", tc.device)
		}
		if it.KeyHeld != tc.keyHeld || it.PN == "" || it.LID == "" {
			t.Errorf("%s: KeyHeld %v, PN %q, LID %q, want KeyHeld %v", tc.device, it.KeyHeld, it.PN, it.LID, tc.keyHeld)
		}
	}
	it, _ := itemOf(n, w.item)
	if it.PN != w.id.PN.String() || it.LID != w.id.LID.String() {
		t.Errorf("the identity read %q %q, stored %s %s", it.PN, it.LID, w.id.PN, w.id.LID)
	}
	if !store.HoldsAccount(it.PN, "", wa.Identity{PN: w.id.PN.ToNonAD()}) || store.HoldsAccount("", it.LID, wa.Identity{PN: w.id.PN}) {
		t.Error("HoldsAccount compares by halves")
	}
	if it.MoveRunning {
		t.Error("a move with none running")
	}

	// A move out of the workspace that runs: every row says so (its
	// can_relink), until it ends.
	release, err := w.devices.HoldMove(ctx, w.tenant, w.item)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	n = w.numbers(ctx, t, w.c)
	for _, it := range n.Items {
		if !it.MoveRunning {
			t.Errorf("%s: no move running", it.ID)
		}
	}
	release()
	n = w.numbers(ctx, t, w.c)
	for _, it := range n.Items {
		if it.MoveRunning {
			t.Errorf("%s: a move running once it ended", it.ID)
		}
	}
}
