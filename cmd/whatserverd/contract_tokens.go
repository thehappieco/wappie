package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/config"
	"whatserver2/internal/membership"
	"whatserver2/internal/store"
)

// whatserverd contract tokens on|off|status (step 7's plan, section 8): the
// token mode, the database's switch of the contract's token part. On turns
// on, together, token acceptance, the leader's token feed with its
// acknowledgement and usage report, and what the later parts of the release
// gate on it; off turns them off, and token auth refuses every token at
// once in every process, since it reads the mode in its own query.

// The token part's early warnings of contract status --check, while the
// contract and the token mode are on, each counted from the later of its own
// time and the token mode's switch.
const (
	// checkTokenFeed: the token follower's last page.
	checkTokenFeed = 5 * time.Minute
	// checkTokenPublished: the token feed's last trusted published_through;
	// past it a token's send and manage are refused (stale_feed).
	checkTokenPublished = time.Hour
	// checkTokenHeld: token auth held (caught_up_at unset) since the switch.
	checkTokenHeld = 5 * time.Minute
	// checkAcks and checkUsage: the acknowledgement's and the usage
	// report's failing runs.
	checkAcks  = 5 * time.Minute
	checkUsage = 15 * time.Minute
	// checkTokenCommit: how far back a page that took over a second to
	// commit is told.
	checkTokenCommit = time.Hour
)

// contractTokensCommand is contract tokens on|off|status.
func contractTokensCommand(args []string, out io.Writer) error {
	if len(args) != 1 || (args[0] != store.TokensOn && args[0] != store.TokensOff && args[0] != "status") {
		return usageError{arg: "contract tokens " + strings.Join(args, " ")}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	a, closeAll, err := setupCurrent(ctx)
	if err != nil {
		return err
	}
	defer closeAll()
	c := store.NewContract(a.pools.API)
	if args[0] == "status" {
		st, err := c.Status(ctx)
		if err != nil {
			return err
		}
		ts, err := c.Tokens().TokenStatus(ctx, st.Now.Add(-checkErrors))
		if err != nil {
			return err
		}
		w := &lines{w: out}
		tokenStatusLines(w, st.Now, ts)
		return w.err
	}
	ready := func() error { return readyFor("contract tokens on", a.cfg.Contract, running) }
	return contractTokens(ctx, c, args[0], ready, func(ctx context.Context) (kc.TokenFeed, error) {
		return probeTokens(ctx, a.cfg.Contract)
	}, out)
}

// probeTokens loads the contract's secrets as contract check does, as the
// service user from the files the server reads, publishing nothing (it is
// not the server), and asks the token feed once: GET
// /contract/v1/tokens?after=0&wait=0.
func probeTokens(ctx context.Context, cfg config.Contract) (kc.TokenFeed, error) {
	cfg.LoadedFile = ""
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	client := newContractClient(cfg, log)
	secrets := &membership.Secrets{Config: cfg, Client: client, OpenWrapper: openKMS}
	if err := secrets.Load(ctx); err != nil {
		return kc.TokenFeed{}, fmt.Errorf("the secrets did not load (step %s)", secrets.Last().Error)
	}
	return client.Tokens(ctx, 0, 0)
}

// contractTokens switches the token mode and says what the switch did. A
// switch to on asks, first and with nothing changed when one refuses (exit
// exitNotReady): the contract on, with a generation stored; ready (the
// transport and the server's loaded secret, as contract mode observe asks);
// and probe, a signed answer of the token feed with the stored generation,
// which proves the platform's token part (T1) is live. On clears
// caught_up_at, so no token is accepted until the leader commits a page with
// more false.
func contractTokens(ctx context.Context, c *store.Contract, mode string, ready func() error,
	probe func(context.Context) (kc.TokenFeed, error), out io.Writer) error {
	tokens := c.Tokens()
	notReady := func(format string, args ...any) error {
		return exitError{code: exitNotReady, err: fmt.Errorf("contract tokens on: not ready: "+format+"; nothing changed", args...)}
	}
	if mode == store.TokensOn {
		current, err := tokens.Mode(ctx)
		if err != nil {
			return err
		}
		if current != store.TokensOn {
			state, err := c.State(ctx)
			switch {
			case err != nil:
				return err
			case !state.On():
				return notReady("the contract is off: turn it to observe first")
			case state.Generation == nil:
				return notReady("Wappie holds no generation of the platform's yet: wait for the feed's first page")
			}
			if ready != nil {
				if err := ready(); err != nil {
					return exitError{code: exitNotReady, err: err}
				}
			}
			feed, err := probe(ctx)
			switch {
			case err != nil:
				return notReady("the platform's token feed did not answer (%s): are its token routes live?", tokenProbeClass(err))
			case feed.Generation != state.Generation.String():
				return notReady("the token feed answers generation %s, Wappie holds %s", feed.Generation, state.Generation)
			}
		}
	}
	change, err := tokens.SetMode(ctx, mode, time.Now())
	if errors.Is(err, store.ErrTokensNeedTheContract) {
		return notReady("the contract is off: turn it to observe first")
	}
	if err != nil {
		return err
	}
	w := &lines{w: out}
	if !change.Changed {
		w.f("contract tokens: already %s; nothing changed", change.To)
		return w.err
	}
	w.f("contract tokens: %s -> %s", change.From, change.To)
	if change.To == store.TokensOn {
		w.f("token auth holds until the leader commits the token feed's first page with more false; it follows the feed within 5 seconds")
	} else {
		w.f("every token is refused from now on; the leader stops the token feed within 5 seconds")
	}
	return w.err
}

// tokenProbeClass is a failed probe's class: the secrets', or the call's.
func tokenProbeClass(err error) string {
	if strings.HasPrefix(err.Error(), "the secrets did not load") {
		return err.Error()
	}
	return membership.CallClass(err)
}

// tokenStatusLines are contract status's lines of the token part, each
// starting with "tokens ", which no kit's prefix matches.
func tokenStatusLines(w *lines, now time.Time, ts store.TokenStatus) {
	w.f("tokens mode: %s (since %s)", ts.Mode, stamp(ts.ModeChangedAt))
	caught := ago(now, ts.CaughtUpAt)
	if ts.CaughtUpAt == nil {
		caught = "never (token auth holds)"
	}
	w.f("tokens feed: cursor %d, published_through %s, last page %s, caught up %s", ts.Cursor, ago(now, ts.PublishedThrough),
		ago(now, ts.ReadAt), caught)
	if ts.Error != "" {
		w.f("tokens feed: failing since %s (%s)", ago(now, ts.ErrorAt), ts.Error)
	}
	w.f("tokens ack: through %d, last accepted %s", ts.AckThrough, ago(now, ts.AckSentAt))
	if ts.AckError != "" {
		w.f("tokens ack: failing since %s (%s)", ago(now, ts.AckErrorAt), ts.AckError)
	}
	w.f("tokens usage: last accepted %s", ago(now, ts.UsageSentAt))
	if ts.UsageError != "" {
		w.f("tokens usage: failing since %s (%s)", ago(now, ts.UsageErrorAt), ts.UsageError)
	}
	switch {
	case ts.PassGeneration == nil:
	case ts.PassDoneAt != nil:
		w.f("tokens pass: generation %s done %s", ts.PassGeneration, ago(now, ts.PassDoneAt))
	default:
		w.f("tokens pass: generation %s pending", ts.PassGeneration)
	}
	w.f("tokens held: %d live, %d unlisted in the last day, %d with a changed reading key; stops: %d operator, %d apply_failed",
		ts.Live, ts.Unlisted, ts.KeyChanged, ts.Stopped, ts.ApplyFailed)
	if ts.SlowCommitAt != nil {
		w.f("tokens slowest commit: %d ms, %s", ts.SlowCommit.Milliseconds(), ago(now, ts.SlowCommitAt))
	}
}

// tokenFindings are --check's findings of the token part: only while the
// contract and the token mode are on, so a release shipped at tokens off is
// clean whatever its token state.
func tokenFindings(now time.Time, contractOn bool, ts store.TokenStatus) []string {
	if !contractOn || ts.Mode != store.TokensOn {
		return nil
	}
	var out []string
	since := func(at *time.Time) *time.Time {
		if at == nil || at.Before(ts.ModeChangedAt) {
			return &ts.ModeChangedAt
		}
		return at
	}
	older := func(at *time.Time, d time.Duration) bool { return at == nil || now.Sub(*at) > d }
	if older(since(ts.ReadAt), checkTokenFeed) {
		out = append(out, fmt.Sprintf("the token feed was last read %s", ago(now, ts.ReadAt)))
	}
	if older(since(ts.PublishedThrough), checkTokenPublished) {
		out = append(out, fmt.Sprintf("the token feed's published_through is %s: tokens' send and manage are refused", ago(now, ts.PublishedThrough)))
	}
	if ts.CaughtUpAt == nil && older(&ts.ModeChangedAt, checkTokenHeld) {
		out = append(out, fmt.Sprintf("token auth holds: no token page with more false has committed since the token mode's switch at %s",
			stamp(ts.ModeChangedAt)))
	}
	if ts.AckErrorAt != nil && older(since(ts.AckErrorAt), checkAcks) {
		out = append(out, fmt.Sprintf("the token acknowledgement has failed since %s (%s)", stamp(*ts.AckErrorAt), ts.AckError))
	}
	if ts.UsageErrorAt != nil && older(since(ts.UsageErrorAt), checkUsage) {
		out = append(out, fmt.Sprintf("the token usage report has failed since %s (%s)", stamp(*ts.UsageErrorAt), ts.UsageError))
	}
	if ts.Unlisted > 0 {
		out = append(out, fmt.Sprintf("%d tokens unlisted by a reset's pass in the last day: refused here for good", ts.Unlisted))
	}
	if ts.KeyChanged > 0 {
		out = append(out, fmt.Sprintf("%d tokens' reading key changed: their new grants are refused", ts.KeyChanged))
	}
	if ts.ApplyFailed > 0 {
		out = append(out, fmt.Sprintf("%d tokens stopped here: a record of theirs could not be applied (apply_failed)", ts.ApplyFailed))
	}
	if ts.SlowCommitAt != nil && !older(ts.SlowCommitAt, checkTokenCommit) {
		out = append(out, fmt.Sprintf("a token page took %d ms to commit at %s (over a second)", ts.SlowCommit.Milliseconds(), stamp(*ts.SlowCommitAt)))
	}
	return out
}
