package numberacts

import (
	"cmp"
	"context"
	"errors"
	"math"
	"time"

	"github.com/google/uuid"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/relink"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// RelinkCmd is what an item.relink carries for its act: its expires_at
// (the pairing starts only before it, by this process's clock) and
// based_on.state_seq (a pause later than it ends the relink
// state_changed), nil when the command names none.
type RelinkCmd struct {
	ExpiresAt  time.Time
	BasedOnSeq *int64
}

// PairingAheadMax is how far ahead of this process's clock a QR's
// expires_at may be sent: the kit's 90 s (kc.MaxPairingAhead) less a
// margin for the platform's clock, which judges it (the platform's
// question 4's default). Each QR goes with its own expiry, capped.
const PairingAheadMax = kc.MaxPairingAhead - 5*time.Second

// Relink is item.relink (kit v0.11.0; the spec's 14.13): a logged-out
// number linked again with a new QR into the same row, the QR shown on the
// console's page. Every check comes before any QR, in this order: the
// number live (not_found), item_busy while this process pairs it,
// workspace_busy while a move out of the workspace runs (a move that has
// ended holds nothing: the relink lifts its pause), the actor an owner or
// admin (not_authorized; no step-up: the platform asked a sign-in at most
// 10 minutes old), expired past the command's expires_at (state_seq
// null), then the relink's own table (relink.Service.Check: item_busy,
// workspace_busy, state_changed, item_busy for a hold, read_only,
// no_reader, number_held), and last a move since, then a pause later than
// based_on or since the Check (workspace_busy, then state_changed). Then in_progress is written in the transaction that
// starts the act, at the act's seq, so the workspace's next command runs
// while the person scans, and the pairing starts; the act returns at once.
//
// A goroutine sends each QR to the pairing route as WhatsApp gives it,
// the first once the in_progress was posted (PutPairing, seq 1, 2, ...,
// each expires_at its own, capped at PairingAheadMax and the window's
// end), ends the pairing at a rotation that finds the number changed, and
// writes the final result when
// the pairing ends: ran in the attach's own transaction, else the end's
// code (other_account, link_timeout, connect_failed, number_held,
// storage_paused, state_changed for a stop, a deletion or a number moved
// away meanwhile, workspace_busy for a move that still runs)
// over the in_progress (store.Contract.FinishInProgress). A QR is never
// logged.
func (r *Runner) Relink(ctx context.Context, run Run, item uuid.UUID, cmd RelinkCmd) (store.ContractAct, error) {
	act, err := r.Store.JudgeRelink(ctx, run.contract(), item, r.busy)
	if err != nil || !act.Open {
		return act, err
	}
	refused := func(code string, wait time.Duration) (store.ContractAct, error) {
		res := store.CommandResult{Outcome: store.CommandRefused, Code: code}
		if code == kc.CodeItemBusy || code == kc.CodeWorkspaceBusy {
			res.RetryAfter = retrySeconds(wait)
		}
		return r.Store.FinishAct(ctx, run.contract(), res)
	}
	if r.now().After(cmd.ExpiresAt) {
		// Taken in time, not started by its expires_at: expired, no
		// state_seq (the kit's SPEC 11.19).
		res := store.CommandResult{Outcome: store.CommandRefused, Code: kc.CodeExpired}
		if err := r.Store.RefuseCommand(ctx, run.Command, res); err != nil {
			return store.ContractAct{}, err
		}
		return store.ContractAct{Result: res}, nil
	}
	if r.Relinker == nil {
		return refused(kc.CodeConnectFailed, 0)
	}
	target, err := r.Relinker.Check(ctx, run.Workspace, item)
	var refusal *relink.Refusal
	switch {
	case errors.Is(err, store.ErrNotFound):
		return refused(kc.CodeNotFound, 0)
	case errors.As(err, &refusal):
		return refused(refusal.Code, refusal.RetryAfter)
	case err != nil:
		return store.ContractAct{}, err
	}
	act, err = r.Store.StartRelinkCommand(ctx, run.contract(), item, target.Seen, cmd.BasedOnSeq)
	if err != nil || act.Result.Outcome != store.CommandInProgress {
		return act, err
	}

	// Started: a started relink is never run again (its row is
	// in_progress), and its pairing outlives this call, never the process.
	pairCtx := context.WithoutCancel(ctx)
	attach := func(ctx context.Context, linked wa.Identity) (store.Attached, error) {
		_, a, err := r.Store.AttachRelinkCommand(ctx, run.contract(), item, target.Seen, linked)
		return a, err
	}
	since := r.now()
	sess, err := r.Relinker.Start(pairCtx, target, relink.Actor{Kind: "person", ID: run.User}, attach)
	if err != nil {
		r.finish(pairCtx, run, err)
		return act, nil
	}
	if !r.Running.Add(item, run.Command, sess) {
		// The registry let only one pairing of the number start; this
		// is no state a run can reach, and the pump below still ends it.
		r.log().Warn("relink: a console relink of the number was running already", "device", item, "id", run.Command)
	}
	// The leader's hooks as they are now: a later leader's term sets its
	// own.
	recheck := func(ctx context.Context) error {
		return r.Relinker.Devices.RelinkState(ctx, target.Tenant, target.Device, target.Seen)
	}
	go r.pump(pairCtx, run, item, sess, since, r.PutPairing, r.Ended, recheck)
	return act, nil
}

// postedPoll is how often the QR pump asks whether the in_progress was
// posted while it holds a QR for it (Runner.PostedPoll when set).
const postedPoll = 250 * time.Millisecond

// finishTries and finishBackoff bound the writes of a relink's final
// result: a write that fails is tried again, doubling the wait, before the
// leader's sweep is left to answer the row (connect_failed, the real end
// lost).
const (
	finishTries   = 5
	finishBackoff = time.Second
)

// pump sends sess's QRs until its pairing ends, then writes its final
// result. Every event is drained, since the session drops a QR its reader
// does not keep up with.
//
// The first QR goes only once the in_progress was posted (the platform's
// question 5's default: the in_progress first, then the first PUT): until
// then the newest QR is held, polled every PostedPoll, and dropped when it
// goes stale; once a final result replaced the in_progress, no QR goes.
// Each QR first reads the number again (recheck): one paused, deleted,
// moved or whose storage stopped meanwhile, by any process, ends the
// pairing, whose end then names the code, so a stop handled by another
// process than the leader's still ends the leader's pairing within a
// rotation.
func (r *Runner) pump(ctx context.Context, run Run, item uuid.UUID, sess *relink.Session, since time.Time,
	put func(context.Context, uuid.UUID, kc.PairingQR) (bool, error), ended func(), recheck func(context.Context) error) {
	var seq int64
	sending := put != nil
	posted := false
	var held *kc.PairingQR
	var tick <-chan time.Time
	var ticker *time.Ticker
	stopTick := func() {
		if ticker != nil {
			ticker.Stop()
			ticker, tick = nil, nil
		}
	}
	defer stopTick()
	window := since.Add(wa.RelinkWindow)
	send := func(q kc.PairingQR) {
		_, err := put(ctx, run.Command, q)
		var ref *kc.Refusal
		switch {
		case errors.As(err, &ref) && ref.Code == kc.CodeNotFound:
			// The platform holds a final result already, or never carried
			// it: no more QRs, and the pairing waits on (the platform's
			// question 3's default).
			sending = false
			r.log().Info("relink: the platform takes no more QRs for the command", "id", run.Command, "seq", q.Seq)
		case err != nil:
			// accepted false is delivered; an error is tried again at the
			// next rotation, never resent.
			r.log().Warn("relink: a QR was not delivered", "id", run.Command, "seq", q.Seq, "error", err)
		}
	}
	events := sess.Events()
	for events != nil {
		select {
		case evt, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			if evt.Kind != wa.PairEventQR {
				continue
			}
			// seq rises with every QR, sent or not: a gap is allowed.
			seq++
			if recheck != nil && !r.stillRelinkable(ctx, run, recheck) {
				sess.Cancel()
				sending, held = false, nil
				stopTick()
			}
			if !sending {
				continue
			}
			q, fresh := r.qrOf(seq, evt, window)
			if !fresh {
				// Stale while it waited: never sent.
				continue
			}
			if !posted {
				held = &q
				if ticker == nil {
					ticker = time.NewTicker(cmp.Or(r.PostedPoll, postedPoll))
					tick = ticker.C
				}
				continue
			}
			send(q)
		case <-tick:
			pctx, cancel := detached(ctx)
			p, final, err := r.Store.RelinkPosted(pctx, run.Command)
			cancel()
			switch {
			case err != nil:
				continue
			case final:
				sending, held = false, nil
				stopTick()
				continue
			case !p:
				if held != nil && !held.ExpiresAt.After(r.now()) {
					// Stale while it waited: dropped, and the next QR
					// asks again.
					held = nil
					stopTick()
				}
				continue
			}
			posted = true
			stopTick()
			q := held
			held = nil
			if q != nil && q.ExpiresAt.After(r.now()) {
				send(*q)
			}
		}
	}
	r.finish(ctx, run, sess.Result())
	r.Running.Remove(item, sess)
	if ended != nil {
		ended()
	}
}

// qrOf is the QR seq of evt as it is sent: its own expiry capped at
// PairingAheadMax and at the window's end. fresh is false for one already
// past it.
func (r *Runner) qrOf(seq int64, evt wa.PairEvent, window time.Time) (kc.PairingQR, bool) {
	now := r.now()
	exp := evt.Expires
	if exp.IsZero() || exp.After(now.Add(PairingAheadMax)) {
		exp = now.Add(PairingAheadMax)
	}
	if exp.After(window) {
		exp = window
	}
	return kc.PairingQR{Seq: seq, QR: evt.Code, ExpiresAt: exp.UTC()}, exp.After(now)
}

// stillRelinkable reads the number again at a QR's rotation: false when it
// is no longer one to link (paused, deleted, moved or its storage stopped
// meanwhile), whichever process made the change. A read that fails passes:
// the attach's compare-and-set still judges the scan.
func (r *Runner) stillRelinkable(ctx context.Context, run Run, recheck func(context.Context) error) bool {
	rctx, cancel := detached(ctx)
	defer cancel()
	err := recheck(rctx)
	if errors.Is(err, store.ErrRelinkStateChanged) || errors.Is(err, store.ErrRelinkWorkspaceBusy) || errors.Is(err, store.ErrStoragePaused) {
		r.log().Info("relink: the number changed while it paired; the pairing ends", "id", run.Command)
		return false
	}
	return true
}

// finish writes a relink's final result over its in_progress, for an end
// other than linked (nil: the attach wrote ran in its own transaction).
// One another end answered first is left as it is. A write that fails is
// tried again finishTries times, the wait doubling from finishBackoff,
// before the leader's sweep is left to answer the row.
func (r *Runner) finish(ctx context.Context, run Run, end error) {
	if end == nil {
		r.log().Info("contract: a relink ran", "id", run.Command)
		return
	}
	res := store.CommandResult{Outcome: store.CommandRefused, Code: kc.CodeConnectFailed}
	var refusal *relink.Refusal
	if errors.As(end, &refusal) {
		res.Code = refusal.Code
		if refusal.Code == kc.CodeItemBusy || refusal.Code == kc.CodeWorkspaceBusy {
			res.RetryAfter = retrySeconds(refusal.RetryAfter)
		}
	}
	wait := cmp.Or(r.FinishBackoff, finishBackoff)
	for try := 1; ; try++ {
		fctx, cancel := detached(ctx)
		err := r.Store.FinishInProgress(fctx, run.Command, res)
		cancel()
		switch {
		case errors.Is(err, store.ErrCommandFinished):
			return
		case err == nil:
			r.log().Info("contract: a relink ended", "id", run.Command, "code", res.Code)
			return
		case try >= finishTries:
			// The leader's sweep answers the row once nothing pairs its
			// number: connect_failed, this end lost.
			r.log().Warn("contract: a relink's final result could not be written", "id", run.Command, "code", res.Code,
				"tries", try, "error", err)
			return
		}
		r.log().Warn("contract: a relink's final result could not be written; it is tried again", "id", run.Command,
			"code", res.Code, "try", try, "error", err)
		t := time.NewTimer(wait)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return
		}
		wait *= 2
	}
}

// retrySeconds is item_busy's and workspace_busy's retry_after: wait in
// whole seconds, 1 to kc.MaxRetryAfter.
func retrySeconds(wait time.Duration) int {
	return min(max(1, int(math.Ceil(wait.Seconds()))), kc.MaxRetryAfter)
}

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}
