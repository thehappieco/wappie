package numberacts

import (
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
// number live (not_found), item_busy while this process pairs it or a
// move holds it, the actor an owner or admin (not_authorized; no step-up:
// the platform asked a sign-in at most 10 minutes old), expired past the
// command's expires_at (state_seq null), then the relink's own table
// (relink.Service.Check: state_changed, item_busy, read_only, no_reader,
// number_held), and last a pause later than based_on or since the Check
// (state_changed). Then in_progress is written in the transaction that
// starts the act, at the act's seq, so the workspace's next command runs
// while the person scans, and the pairing starts; the act returns at once.
//
// A goroutine sends each QR to the pairing route as WhatsApp gives it
// (PutPairing, seq 1, 2, ..., each expires_at its own, capped at
// PairingAheadMax and the window's end), and writes the final result when
// the pairing ends: ran in the attach's own transaction, else the end's
// code (other_account, link_timeout, connect_failed, number_held,
// storage_paused, state_changed for a stop, a deletion or a transfer meanwhile)
// over the in_progress (store.Contract.FinishInProgress). A QR is never
// logged.
func (r *Runner) Relink(ctx context.Context, run Run, item uuid.UUID, cmd RelinkCmd) (store.ContractAct, error) {
	act, err := r.Store.JudgeRelink(ctx, run.contract(), item, r.busy)
	if err != nil || !act.Open {
		return act, err
	}
	refused := func(code string, wait time.Duration) (store.ContractAct, error) {
		res := store.CommandResult{Outcome: store.CommandRefused, Code: code}
		if code == kc.CodeItemBusy {
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
	go r.pump(pairCtx, run, item, sess, since, r.PutPairing, r.Ended)
	return act, nil
}

// pump sends sess's QRs until its pairing ends, then writes its final
// result. Every event is drained, since the session drops a QR its reader
// does not keep up with.
func (r *Runner) pump(ctx context.Context, run Run, item uuid.UUID, sess *relink.Session, since time.Time,
	put func(context.Context, uuid.UUID, kc.PairingQR) (bool, error), ended func()) {
	var seq int64
	sending := put != nil
	window := since.Add(wa.RelinkWindow)
	for evt := range sess.Events() {
		if evt.Kind != wa.PairEventQR {
			continue
		}
		// seq rises with every QR, sent or not: a gap is allowed.
		seq++
		if !sending {
			continue
		}
		now := r.now()
		exp := evt.Expires
		if exp.IsZero() || exp.After(now.Add(PairingAheadMax)) {
			exp = now.Add(PairingAheadMax)
		}
		if exp.After(window) {
			exp = window
		}
		if !exp.After(now) {
			// Stale while it waited: never sent.
			continue
		}
		_, err := put(ctx, run.Command, kc.PairingQR{Seq: seq, QR: evt.Code, ExpiresAt: exp.UTC()})
		var ref *kc.Refusal
		switch {
		case errors.As(err, &ref) && ref.Code == kc.CodeNotFound:
			// The platform holds a final result already, or never carried
			// it: no more QRs, and the pairing waits on (the platform's
			// question 3's default).
			sending = false
			r.log().Info("relink: the platform takes no more QRs for the command", "id", run.Command, "seq", seq)
		case err != nil:
			// accepted false is delivered; an error is tried again at the
			// next rotation, never resent.
			r.log().Warn("relink: a QR was not delivered", "id", run.Command, "seq", seq, "error", err)
		}
	}
	r.finish(ctx, run, sess.Result())
	r.Running.Remove(item, sess)
	if ended != nil {
		ended()
	}
}

// finish writes a relink's final result over its in_progress, for an end
// other than linked (nil: the attach wrote ran in its own transaction).
// One another end answered first is left as it is.
func (r *Runner) finish(ctx context.Context, run Run, end error) {
	if end == nil {
		r.log().Info("contract: a relink ran", "id", run.Command)
		return
	}
	res := store.CommandResult{Outcome: store.CommandRefused, Code: kc.CodeConnectFailed}
	var refusal *relink.Refusal
	if errors.As(end, &refusal) {
		res.Code = refusal.Code
		if refusal.Code == kc.CodeItemBusy {
			res.RetryAfter = retrySeconds(refusal.RetryAfter)
		}
	}
	fctx, cancel := detached(ctx)
	defer cancel()
	err := r.Store.FinishInProgress(fctx, run.Command, res)
	switch {
	case errors.Is(err, store.ErrCommandFinished):
	case err != nil:
		// The leader's sweep answers the row once nothing pairs its number.
		r.log().Warn("contract: a relink's final result could not be written", "id", run.Command, "code", res.Code, "error", err)
	default:
		r.log().Info("contract: a relink ended", "id", run.Command, "code", res.Code)
	}
}

// retrySeconds is item_busy's retry_after: wait in whole seconds, 1 to
// kc.MaxRetryAfter.
func retrySeconds(wait time.Duration) int {
	return min(max(1, int(math.Ceil(wait.Seconds()))), kc.MaxRetryAfter)
}

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}
