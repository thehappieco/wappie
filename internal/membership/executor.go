package membership

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"whatserver2/internal/store"
)

// The executor (the spec's 14.6; the plan's 3.2): one ledger row at a
// time, in take order, not cseq (a restored platform starts cseq again
// below the ones taken), one open row at a time per workspace and producer
// (store.NextCommand). A kind the settings mode does not let this binary
// run is answered at R0, kind_not_accepted, with the seq it was judged on:
// in read every one, and a wappie-cloud kind always; the others are judged
// and run by commands_run.go.
// A store error that is not a verdict backs the row off
// (store.CommandRunFailed), holding back only the later rows of its own
// workspace and producer; after store.CommandRunTries it is answered
// rate_limited. The executor also trims the ledger, every trimEvery.

// execute runs the ledger's open rows until ctx ends.
func (sw *settingsWork) execute(ctx context.Context) {
	l, c := sw.l, sw.l.Members.Contract
	minBack := or(l.BackoffMin, feedBackoffMin)
	idle := or(sw.cfg.Idle, settingsIdle)
	trimAt := time.Now()
	var warned time.Time
	for ctx.Err() == nil {
		if !time.Now().Before(trimAt) {
			if n, err := c.TrimCommands(ctx); err != nil && ctx.Err() == nil {
				l.log().Warn("contract: could not trim the command ledger", "error", err)
			} else if n > 0 {
				l.log().Info("contract: command ledger trimmed", "rows", n)
			}
			trimAt = time.Now().Add(or(sw.cfg.TrimEvery, trimEvery))
		}
		cmd, ok, err := c.NextCommand(ctx)
		switch {
		case err != nil:
			if ctx.Err() != nil {
				return
			}
			if time.Since(warned) >= warnEvery {
				warned = time.Now()
				l.log().Warn("contract: could not read the next command", "error", err)
			}
			if !pause(ctx, minBack, sw.executor) {
				return
			}
		case ok:
			if !sw.runRow(ctx, cmd) && !pause(ctx, minBack, nil) {
				// Its failure could not be recorded, so it is still open:
				// not again at once.
				return
			}
			kick(sw.results)
		default:
			wait := min(idle, max(time.Until(trimAt), 0))
			if at, now, waiting, err := c.NextCommandAt(ctx); err == nil && waiting {
				wait = min(wait, max(at.Sub(now), 0))
			}
			if !pause(ctx, wait, sw.executor) {
				return
			}
		}
	}
}

// runRow judges one row and writes its result (commands_run.go): R0 to R4
// here, the target and the roles in its act's transaction, the result
// with them. It reports false when neither a result nor a failed run could
// be recorded.
func (sw *settingsWork) runRow(ctx context.Context, cmd store.ContractCommand) bool {
	return sw.runCommand(ctx, cmd)
}

// runFailed records a run that failed with a store error that is not a
// verdict: the row backs off, WARN; at CommandRunTries it is answered
// rate_limited, retry_after 60, with one ERROR recorded for --check.
// Another leader's answer meanwhile (ErrCommandFinished) is no failure.
// It reports false when the failure could not be recorded.
func (sw *settingsWork) runFailed(ctx context.Context, cmd store.ContractCommand, err error) bool {
	l, c := sw.l, sw.l.Members.Contract
	if errors.Is(err, store.ErrCommandFinished) {
		return true
	}
	class := storeClass(err)
	tries, ferr := c.CommandRunFailed(ctx, cmd.ID, class)
	switch {
	case errors.Is(ferr, store.ErrCommandFinished):
		return true
	case ferr != nil:
		if ctx.Err() == nil {
			l.log().Warn("contract: could not record a command's failed run", "id", cmd.ID, "error", ferr)
		}
		return false
	}
	l.log().Warn("contract: a command's run failed; it waits and is tried again", "id", cmd.ID, "kind", cmd.Kind,
		"class", class, "tries", tries)
	if tries < store.CommandRunTries {
		return true
	}
	stuck := store.CommandResult{Outcome: store.CommandRefused, Code: store.CommandRateLimited, RetryAfter: store.CommandStuckRetryAfter}
	if err := c.RefuseCommand(ctx, cmd.ID, stuck); err != nil {
		if ctx.Err() == nil && !errors.Is(err, store.ErrCommandFinished) {
			// It waits out its backoff, and is answered at its next run.
			l.log().Warn("contract: could not answer a stuck command rate_limited", "id", cmd.ID, "error", err)
		}
		return true
	}
	l.log().Error("contract: a command was answered rate_limited after its runs kept failing", "id", cmd.ID, "kind", cmd.Kind,
		"class", class, "tries", tries)
	if err := c.RecordError(ctx, store.ContractErrorCommandStuck); err != nil && ctx.Err() == nil {
		l.log().Warn("contract: could not record an ERROR", "error", err)
	}
	return true
}

// storeClass is a store error's class, as the ledger keeps it: a
// database's SQLSTATE, else ErrorClass's word; never a message.
func storeClass(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return "sqlstate_" + pgErr.Code
	}
	return ErrorClass(err)
}
