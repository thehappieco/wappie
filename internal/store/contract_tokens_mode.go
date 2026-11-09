package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/pg"
)

// The token mode and what the leader and contract status read of the token
// feed (step 7's plan, 4.3 and section 8): contract_token_state's switch,
// the follower's own state and failures, and the counts the status prints.

// ContractErrorTokenFeedSilent is the class of the token follower's ERROR
// after a long run without a page, as RecordError keeps it.
//
//nolint:gosec // G101: a class, not a credential
const ContractErrorTokenFeedSilent = "token_feed_silent"

// ContractErrorTokenLookupInvalid is the class of the leader's ERROR when
// the platform answers a token lookup with a record Wappie cannot use
// (TokenLookupFailed), as RecordError keeps it.
//
//nolint:gosec // G101: a class, not a credential
const ContractErrorTokenLookupInvalid = "token_lookup_invalid"

// ContractErrorTokenResetLoop is the class of the token follower's ERROR
// when a reset it starts comes within a minute of the last one it or the
// command follower made, and waits the minute out: each resets the
// command state too, so a platform fault (a gone that lasts, two feeds on
// two generations) resets everything once a minute until it ends.
//
//nolint:gosec // G101: a class, not a credential
const ContractErrorTokenResetLoop = "token_reset_loop"

// ErrTokensNeedTheContract refuses tokens on while the contract is off:
// token auth refuses every token then, whatever the token mode says.
var ErrTokensNeedTheContract = errors.New("store: the contract is off; tokens follow it")

// ErrTokensMode is a token mode Wappie does not know.
var ErrTokensMode = errors.New("store: the token mode is off or on")

// TokenFeedState is what the token follower reads before each call: the
// token mode and cursor, its last page committed (Wappie's clock), and
// contract_state's generation, which every feed shares.
type TokenFeedState struct {
	Mode       string
	Cursor     int64
	ReadAt     *time.Time
	Generation *uuid.UUID
}

// FeedState reads the token follower's state.
func (t *Tokens) FeedState(ctx context.Context) (TokenFeedState, error) {
	var s TokenFeedState
	err := t.pool.QueryRow(ctx, `SELECT s.mode, s.feed_cursor, s.read_at, c.generation
		FROM contract_token_state s CROSS JOIN contract_state c`).Scan(&s.Mode, &s.Cursor, &s.ReadAt, &s.Generation)
	return s, err
}

// Mode reads the token mode.
func (t *Tokens) Mode(ctx context.Context) (string, error) {
	var mode string
	err := t.pool.QueryRow(ctx, `SELECT mode FROM contract_token_state`).Scan(&mode)
	return mode, err
}

// FeedFailed records that a token feed call got no page Wappie could take:
// its class (an outcome, a refusal's code, a transport's class; never a
// message), and, kept from the first failure of the run, since when. A
// page's commit clears both.
func (t *Tokens) FeedFailed(ctx context.Context, class string, at time.Time) error {
	_, err := t.pool.Exec(ctx, `UPDATE contract_token_state SET error = $1, error_at = coalesce(error_at, $2)`, class, at)
	return err
}

// CommitTook records a token page whose commit took longer than the
// design's second from its receipt (the follower measures it), for
// contract status --check.
func (t *Tokens) CommitTook(ctx context.Context, took time.Duration, at time.Time) error {
	_, err := t.pool.Exec(ctx, `UPDATE contract_token_state SET slow_commit_at = $1, slow_commit_ms = $2`, at, took.Milliseconds())
	return err
}

// TokenModeChange is what a switch of the token mode did.
type TokenModeChange struct {
	From, To string
	// Changed: the mode was another; a switch to the mode it is in changes
	// nothing.
	Changed bool
}

// SetMode switches the token mode (whatserverd contract tokens on|off) in
// one transaction, contract_state first (DB25 step 1, shared: a contract
// mode off waits for it), then contract_token_state. On needs the contract
// on, and clears caught_up_at: no token is accepted until a page with more
// false commits. Both make every recorded workspace's snapshot due, so the
// snapshots follow the gate (ordinal and tokens). The mode's trigger
// notifies every process: token auth reads the mode in its own query, so
// off refuses every token at once.
func (t *Tokens) SetMode(ctx context.Context, mode string, now time.Time) (TokenModeChange, error) {
	if mode != TokensOff && mode != TokensOn {
		return TokenModeChange{}, ErrTokensMode
	}
	var out TokenModeChange
	err := retryDeadlock(ctx, func() error {
		out = TokenModeChange{}
		return pg.InTx(ctx, t.pool, func(tx pgx.Tx) error {
			var contract string
			if err := tx.QueryRow(ctx, `SELECT mode FROM contract_state FOR SHARE`).Scan(&contract); err != nil {
				return err
			}
			if mode == TokensOn && contract == ContractOff {
				return ErrTokensNeedTheContract
			}
			var from string
			if err := tx.QueryRow(ctx, `SELECT mode FROM contract_token_state FOR UPDATE`).Scan(&from); err != nil {
				return err
			}
			out = TokenModeChange{From: from, To: mode, Changed: from != mode}
			if !out.Changed {
				return nil
			}
			if _, err := tx.Exec(ctx, `UPDATE contract_token_state SET mode = $1, mode_changed_at = $2,
				caught_up_at = CASE WHEN $1 = 'on' THEN NULL ELSE caught_up_at END`, mode, now); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `UPDATE contract_workspaces w SET snapshot_due_at = clock_timestamp(), parked_at = NULL
				FROM (`+lockWorkspacesSQL(`true`)+`) l WHERE w.workspace_id = l.workspace_id`)
			return err
		})
	})
	return out, err
}

// tokensOffTx turns the token mode off in tx, which holds contract_state's
// lock (a switch of the contract to off), and reports whether it was on.
func tokensOffTx(ctx context.Context, tx pgx.Tx) (bool, error) {
	tag, err := tx.Exec(ctx, `UPDATE contract_token_state SET mode = 'off', mode_changed_at = clock_timestamp() WHERE mode <> 'off'`)
	return tag.RowsAffected() == 1, err
}

// adoptGenerationTx stores gen, the first answer's, in tx, which holds
// contract_state's lock and found no generation stored (the first observe,
// or after a gone), and starts the token feed's pass of it: after a gone the
// reset could not name the generation its pass lists, and a pass that never
// starts never finishes, so a token the platform no longer has would never
// be refused. At the first observe Wappie holds no token, and the pass
// refuses none.
func adoptGenerationTx(ctx context.Context, tx pgx.Tx, gen uuid.UUID, confirmed bool) error {
	if _, err := tx.Exec(ctx, `UPDATE contract_state SET generation = $1, generation_confirmed = $2,
		updated_at = clock_timestamp() WHERE generation IS NULL`, gen, confirmed); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE contract_token_state SET pass_generation = $1
		WHERE pass_generation IS NULL AND pass_done_at IS NULL`, gen)
	return err
}

// TokenStatus is what contract status prints of the token part, and what
// --check finds in it: times on Wappie's clock (the follower's), counts and
// classes, never a token's name or record.
type TokenStatus struct {
	Mode          string
	ModeChangedAt time.Time
	Cursor        int64
	// PublishedThrough is the last trusted one; CaughtUpAt the last commit
	// of a page with more false (unset: token auth holds); ReadAt the last
	// page committed, and Error its failing run's class since ErrorAt.
	PublishedThrough, CaughtUpAt, ReadAt *time.Time
	Error                                string
	ErrorAt                              *time.Time
	// The acknowledgement: the last through accepted, when, and a failing
	// run; the usage report's likewise.
	AckThrough            int64
	AckSentAt, AckErrorAt *time.Time
	AckError              string
	UsageSentAt           *time.Time
	UsageError            string
	UsageErrorAt          *time.Time
	// The reset's pass: its generation, and when it finished.
	PassGeneration *uuid.UUID
	PassDoneAt     *time.Time
	// SlowCommitAt is the last page whose commit took over a second, and
	// SlowCommit how long.
	SlowCommitAt *time.Time
	SlowCommit   time.Duration
	// Live are the tokens Wappie holds that have not ended; Unlisted those
	// a reset's pass refused for good within the last day; KeyChanged the
	// live ones whose reading key changed.
	Live, Unlisted, KeyChanged int64
	// The open stops: the operator's, of any selector; and the live tokens
	// with one of Wappie's own (apply_failed), which only a later version
	// that applies cleanly lifts, so that of a token that ended, or that
	// Wappie never held, is left to tokens list.
	Stopped, ApplyFailed int64
}

// TokenStatus reads the token part's state and counts, in one REPEATABLE
// READ transaction, the tokens counted workspace by workspace under each
// one's app.tenant_id. since bounds the unlisted count.
func (t *Tokens) TokenStatus(ctx context.Context, since time.Time) (TokenStatus, error) {
	var s TokenStatus
	err := pgx.BeginTxFunc(ctx, t.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var slow *int64
		if err := tx.QueryRow(ctx, `SELECT mode, mode_changed_at, feed_cursor, published_through, caught_up_at, read_at,
				coalesce(error, ''), error_at, ack_through, ack_sent_at, coalesce(ack_error, ''), ack_error_at,
				usage_sent_at, coalesce(usage_error, ''), usage_error_at, pass_generation, pass_done_at, slow_commit_at, slow_commit_ms,
				(SELECT count(*) FROM contract_token_stops WHERE cause = 'operator' AND lifted_at IS NULL)
			FROM contract_token_state`).Scan(&s.Mode, &s.ModeChangedAt, &s.Cursor, &s.PublishedThrough, &s.CaughtUpAt, &s.ReadAt,
			&s.Error, &s.ErrorAt, &s.AckThrough, &s.AckSentAt, &s.AckError, &s.AckErrorAt,
			&s.UsageSentAt, &s.UsageError, &s.UsageErrorAt, &s.PassGeneration, &s.PassDoneAt, &s.SlowCommitAt, &slow,
			&s.Stopped); err != nil {
			return err
		}
		if slow != nil {
			s.SlowCommit = time.Duration(*slow) * time.Millisecond
		}
		workspaces, err := tokenWorkspacesTx(ctx, tx)
		if err != nil {
			return err
		}
		for _, ws := range workspaces {
			if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, ws.String()); err != nil {
				return err
			}
			var live, unlisted, changed, failed int64
			if err := tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE live),
					count(*) FILTER (WHERE unlisted_at >= $1),
					count(*) FILTER (WHERE live AND key_changed_at IS NOT NULL),
					count(*) FILTER (WHERE live AND EXISTS (SELECT 1 FROM contract_token_selectors s
						JOIN contract_token_stops x ON x.selector = s.selector AND x.cause = 'apply_failed' AND x.lifted_at IS NULL
						WHERE s.token_id = t.id))
				FROM (SELECT *, ended_at IS NULL AND revoked_at IS NULL AND unlisted_at IS NULL AS live FROM contract_tokens) t`, since).
				Scan(&live, &unlisted, &changed, &failed); err != nil {
				return err
			}
			s.Live, s.Unlisted, s.KeyChanged, s.ApplyFailed = s.Live+live, s.Unlisted+unlisted, s.KeyChanged+changed, s.ApplyFailed+failed
		}
		return nil
	})
	return s, err
}
