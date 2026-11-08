package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/pg"
)

// The command ledger (0052's contract_commands, the plan's 2.3 and 3.1 to
// 3.3): every command the follower takes, its result written in the act's
// transaction, and its delivery. A row is kept exactly CommandRetention from
// taken_at: every read ignores an older one, and TrimCommands deletes it.
// The follower decides each item's verdict before the commit (the kit's
// VerifyCommand and ValidateIn, and the expiry rules); this file stores the
// page in one transaction and keeps the wseq memory.

// The codes and outcomes the store writes or reads (the kit's
// contract.Code* and Outcome*).
const (
	CommandRan        = "ran"
	CommandRefused    = "refused"
	CommandInProgress = "in_progress"

	CommandInvalid         = "invalid_command"
	CommandExpired         = "expired"
	CommandNotHeld         = "not_held"
	CommandRateLimited     = "rate_limited"
	CommandKindNotAccepted = "kind_not_accepted"
)

// The producers of the ledger's rows (the kit's SectionProducer): the
// leader answers a row it could not read as Wappie's.
const (
	ProducerWappie      = "wappie"
	ProducerWappieCloud = "wappie-cloud"
)

// The deliveries of a result (S 14.9): accepted and duplicate settle it, a
// rejection parks it with its code, and a result of an old generation's
// command is dropped.
const (
	DeliveryAccepted  = "accepted"
	DeliveryDuplicate = "duplicate"
	DeliveryRejected  = "rejected"
	DeliveryDropped   = "dropped"

	// RejectLocalInvalid is Wappie's own refusal of a result it would not
	// post (it fails the kit's check): parked, never sent.
	RejectLocalInvalid = "local_invalid"
)

// CommandRetention is how long a ledger row is kept from taken_at, never
// less and never more (decision 0056).
const CommandRetention = 30 * 24 * time.Hour

// The executor's retries after a store error that is not a verdict (the
// plan's 3.2): the row waits CommandRunBackoffMin doubled with each try, up
// to CommandRunBackoffMax, and after CommandRunTries it is answered
// rate_limited with CommandStuckRetryAfter.
const (
	CommandRunTries        = 5
	CommandRunBackoffMin   = 5 * time.Second
	CommandRunBackoffMax   = time.Minute
	CommandStuckRetryAfter = 60
)

// commandLive is a ledger row within its CommandRetention.
const commandLive = `taken_at > clock_timestamp() - interval '30 days'`

// ErrCommandFinished is a row that has its result already (another leader
// answered it, or a copy with another body finished it): the act that
// tried to finish it rolls back.
var ErrCommandFinished = errors.New("store: the command has its result already")

// ContractCommandFields are the columns of a command that passed
// ValidateIn for its workspace's kind, built from the decoded, validated
// command.
type ContractCommandFields struct {
	// Producer is the kind's (ProducerWappie or ProducerWappieCloud).
	Producer string
	// Workspace and WSeq are nil exactly for a person's kind.
	Workspace *uuid.UUID
	WSeq      *int64
	Kind      string
	Section   string
	Actor     uuid.UUID
	// ActorRole is "" for a person's kind.
	ActorRole string
	// Target is the decoded ids, a JSON object; Params the command's
	// params as received, whatever they hold.
	Target      json.RawMessage
	Params      []byte
	BasedOnSeq  *int64
	BasedOnDocs json.RawMessage
	IssuedAt    time.Time
	// FirstIssuedAt is the intent's first issued_at; zero for none.
	FirstIssuedAt time.Time
	ExpiresAt     *time.Time
	RetryOf       *uuid.UUID
	Confirm       *string
}

// ContractCommandTake is one feed item as the follower decided it (the
// plan's 3.1, steps 1 to 6).
type ContractCommandTake struct {
	// ID is the command's id, from a generic decode when nothing else of
	// it could be read.
	ID   uuid.UUID
	Cseq int64
	// Body is the command as received, its mac included; BodyKey the
	// sha256 of its canonical form without generation, cseq, secret and
	// mac (of the raw bytes when it has none).
	Body    []byte
	BodyKey []byte
	Again   bool
	// Verdict is "" for a command to run, else CommandInvalid or
	// CommandExpired, decided at steps 1 to 6.
	Verdict string
	// Why names what the follower decided, for the log and the security
	// log: never a body or a person.
	Why string
	// Forged: the body names another app, or its MAC holds under none of
	// the secrets, or it is no one object (steps 1 and 2). A security
	// event is written, and such a copy never touches a row already taken.
	Forged bool
	// Decoded is nil unless ValidateIn passed: a command refused before
	// keeps no decoded column.
	Decoded *ContractCommandFields
}

// ContractUnreadable is a feed item whose id is not a UUID: it gets no
// row, only the log and, for a forged one, the security log.
type ContractUnreadable struct {
	Cseq   int64
	Why    string
	Forged bool
}

// ContractCommandPage is one signed command feed answer, as the follower
// commits it.
type ContractCommandPage struct {
	// SeenGeneration is contract_state.generation when the page was asked
	// for, and the page's own; After is the cursor it was asked from.
	SeenGeneration   uuid.UUID
	After, NextAfter int64
	// SignedAt is the answer's X-Happie-Timestamp: expiry is judged on it.
	SignedAt   time.Time
	Items      []ContractCommandTake
	Unreadable []ContractUnreadable
}

// ContractTakeResult is what committing a command page did.
type ContractTakeResult struct {
	// Committed: the cursor moved. False when the generation or the cursor
	// was no longer the one the page was asked from: nothing was written,
	// and the follower reads the state again.
	Committed bool
	// New rows to run, rows refused at take, replays, and copies with
	// another body.
	New, Refused, Replayed, OtherBody int
	// Invalid counts the invalid_command answered at take (a refused row,
	// or an open row a copy finished), for the follower's one ERROR.
	Invalid int
	// Security counts the security events written.
	Security int
}

// ErrPageBehind is a page whose next_after is behind its after: no page.
var ErrPageBehind = errors.New("store: a command page's next_after is behind its after")

// takenRow is a ledger row a take met.
type takenRow struct {
	key      []byte
	finished bool
}

// TakeCommands stores a command page in one transaction, in 3.4's order:
// contract_state FOR SHARE (a reset waits for it), the settings row, the
// ledger rows of the page's ids (id order), then the wseq memory. It
// commits only while contract_state.generation and the cursor are the ones
// the page was asked from. Per item (the plan's 3.1): a row already taken
// with the same body is a replay (a result is posted again; the row moves
// to this generation); another body from a copy whose MAC holds finishes
// an open row invalid_command, and a forged one only logs; with no row, a
// verdict is stored with its result, a command whose wseq the memory has
// overtaken (not delivered again) is refused invalid_command, and the rest
// is stored to run. Then the cursor moves to NextAfter, the feed's read
// times are set, its error cleared, and invalid_at stamped when an
// invalid_command was answered.
func (c *Contract) TakeCommands(ctx context.Context, p ContractCommandPage) (ContractTakeResult, error) {
	if p.NextAfter < p.After {
		return ContractTakeResult{}, ErrPageBehind
	}
	var out ContractTakeResult
	err := retryDeadlock(ctx, func() error {
		out = ContractTakeResult{}
		return pg.InTx(ctx, c.pool, func(tx pgx.Tx) error {
			var gen *uuid.UUID
			if err := tx.QueryRow(ctx, `SELECT generation FROM contract_state FOR SHARE`).Scan(&gen); err != nil {
				return err
			}
			if gen == nil || *gen != p.SeenGeneration {
				return nil
			}
			settings, err := lockSettingsTx(ctx, tx)
			if err != nil {
				return err
			}
			if settings.FeedCursor != p.After {
				return nil
			}
			ids := make([]uuid.UUID, 0, len(p.Items))
			for _, it := range p.Items {
				ids = append(ids, it.ID)
			}
			// A row past its 30 days is gone for every read: deleted here,
			// so a delivery of its id starts a new row.
			if _, err := tx.Exec(ctx, `DELETE FROM contract_commands WHERE id = ANY ($1) AND NOT (`+commandLive+`)`, ids); err != nil {
				return err
			}
			rows, err := tx.Query(ctx, `SELECT id, body_key, outcome IS NOT NULL AND outcome <> 'in_progress' FROM contract_commands
				WHERE id = ANY ($1) ORDER BY id FOR UPDATE`, ids)
			if err != nil {
				return err
			}
			taken := map[uuid.UUID]takenRow{}
			if err := forEachRow(rows, func(row pgx.Rows) error {
				var id uuid.UUID
				var r takenRow
				if err := row.Scan(&id, &r.key, &r.finished); err != nil {
					return err
				}
				taken[id] = r
				return nil
			}); err != nil {
				return err
			}
			for _, it := range p.Items {
				if err := takeOneTx(ctx, tx, p, it, taken, &out); err != nil {
					return err
				}
			}
			for _, u := range p.Unreadable {
				if !u.Forged {
					continue
				}
				if err := commandSecurityEventTx(ctx, tx, nil, u.Cseq, u.Why); err != nil {
					return err
				}
				out.Security++
			}
			if _, err := tx.Exec(ctx, `UPDATE contract_settings_state SET feed_cursor = $1, read_at = clock_timestamp(),
				first_read_at = coalesce(first_read_at, clock_timestamp()), feed_error = NULL, feed_error_at = NULL,
				invalid_at = CASE WHEN $2 THEN clock_timestamp() ELSE invalid_at END, updated_at = clock_timestamp()`,
				p.NextAfter, out.Invalid > 0); err != nil {
				return err
			}
			out.Committed = true
			return nil
		})
	})
	return out, err
}

// takeOneTx stores one item of a page (TakeCommands).
func takeOneTx(ctx context.Context, tx pgx.Tx, p ContractCommandPage, it ContractCommandTake, taken map[uuid.UUID]takenRow,
	out *ContractTakeResult) error {
	if r, ok := taken[it.ID]; ok {
		if !it.Forged && bytes.Equal(r.key, it.BodyKey) {
			// A replay: its result is posted again (the platform answers
			// duplicate), delivered again or not; no result yet, the
			// executor has it. In a new generation the row moves to it.
			out.Replayed++
			_, err := tx.Exec(ctx, `UPDATE contract_commands SET generation = $2, again = again OR $3,
				delivery = CASE WHEN outcome IS NULL THEN delivery END,
				delivered_at = CASE WHEN outcome IS NULL THEN delivered_at END,
				reject_code = CASE WHEN outcome IS NULL THEN reject_code END
				WHERE id = $1`, it.ID, p.SeenGeneration, it.Again)
			return err
		}
		// One id with two bodies, or a forged copy of a row taken: only
		// the platform's own signed body may touch a row.
		out.OtherBody++
		why := "other_body"
		if it.Forged {
			why = "taken_" + it.Why
		}
		if err := commandSecurityEventTx(ctx, tx, &it.ID, it.Cseq, why); err != nil {
			return err
		}
		out.Security++
		switch {
		case it.Forged:
			// Only the platform's own signed body may cancel a command.
			return nil
		case !r.finished:
			out.Invalid++
			taken[it.ID] = takenRow{key: r.key, finished: true}
			return finishCommandTx(ctx, tx, it.ID, CommandResult{Outcome: CommandRefused, Code: CommandInvalid})
		default:
			_, err := tx.Exec(ctx, `UPDATE contract_commands SET delivery = NULL, delivered_at = NULL, reject_code = NULL
				WHERE id = $1`, it.ID)
			return err
		}
	}

	verdict, d := it.Verdict, it.Decoded
	if d == nil && verdict != CommandInvalid {
		// A command to run, or an expired one, that was never decoded is
		// the follower's bug: refused invalid_command (a row with no kind
		// holds no other result), never run, and never a page that fails.
		verdict, it.Why = CommandInvalid, "undecoded"
	}
	if it.Forged {
		if err := commandSecurityEventTx(ctx, tx, &it.ID, it.Cseq, it.Why); err != nil {
			return err
		}
		out.Security++
	}
	if verdict == "" && !it.Again && d.Workspace != nil && d.WSeq != nil {
		// Step 7: a wseq this producer already passed there in this
		// generation, with another id.
		var seen int64
		var by uuid.UUID
		err := tx.QueryRow(ctx, `SELECT wseq, id FROM contract_command_wseq WHERE workspace_id = $1 AND producer = $2 AND generation = $3`,
			*d.Workspace, producerOf(d), p.SeenGeneration).Scan(&seen, &by)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err == nil && *d.WSeq <= seen && by != it.ID {
			verdict = CommandInvalid
		}
	}
	if err := insertCommandTx(ctx, tx, p, it, verdict); err != nil {
		return err
	}
	taken[it.ID] = takenRow{key: it.BodyKey, finished: verdict != ""}
	if verdict == "" {
		out.New++
		return nil
	}
	out.Refused++
	if verdict == CommandInvalid {
		out.Invalid++
	}
	if d != nil && d.Workspace != nil && d.WSeq != nil {
		return rememberWSeqTx(ctx, tx, *d.Workspace, producerOf(d), p.SeenGeneration, *d.WSeq, it.ID)
	}
	return nil
}

func producerOf(d *ContractCommandFields) string {
	if d == nil || d.Producer == "" {
		return ProducerWappie
	}
	return d.Producer
}

// insertCommandTx writes a new ledger row, with its result when verdict is
// set (state_seq NULL: expired and invalid_command carry none).
func insertCommandTx(ctx context.Context, tx pgx.Tx, p ContractCommandPage, it ContractCommandTake, verdict string) error {
	var (
		workspace, retryOf                *uuid.UUID
		wseq, basedOn                     *int64
		kind, section, actorRole, confirm *string
		actor                             *uuid.UUID
		target, docs                      any
		params                            []byte
		issued, firstIssued, expires      *time.Time
		outcome, code                     *string
		producer                          = ProducerWappie
	)
	if d := it.Decoded; d != nil {
		producer = producerOf(d)
		workspace, wseq, retryOf, basedOn, confirm, expires = d.Workspace, d.WSeq, d.RetryOf, d.BasedOnSeq, d.Confirm, d.ExpiresAt
		kind, section, actor = &d.Kind, &d.Section, &d.Actor
		if d.ActorRole != "" {
			actorRole = &d.ActorRole
		}
		target, docs, params = jsonOrNil(d.Target), jsonOrNil(d.BasedOnDocs), d.Params
		issued = &d.IssuedAt
		if !d.FirstIssuedAt.IsZero() {
			firstIssued = &d.FirstIssuedAt
		}
	}
	if verdict != "" {
		refused := CommandRefused
		outcome, code = &refused, &verdict
	}
	_, err := tx.Exec(ctx, `INSERT INTO contract_commands (id, producer, generation, cseq, workspace_id, wseq, kind, section, actor,
			actor_role, target, params, based_on_seq, based_on_docs, issued_at, first_issued_at, expires_at, retry_of, confirm,
			body, body_key, signed_at, again, outcome, code, result_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25,
			CASE WHEN $24::text IS NULL THEN NULL ELSE clock_timestamp() END)`,
		it.ID, producer, p.SeenGeneration, it.Cseq, workspace, wseq, kind, section, actor,
		actorRole, target, params, basedOn, docs, issued, firstIssued, expires, retryOf, confirm,
		it.Body, it.BodyKey, p.SignedAt, it.Again, outcome, code)
	return err
}

// jsonOrNil passes raw to a jsonb column, or NULL for none.
func jsonOrNil(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}
	return string(raw)
}

// commandSecurityEventTx writes a contract_command_invalid row: no person
// (user_id and sub NULL; the ledger keeps the actor 30 days only), never
// the body, only the command's id when it has one, its cseq and why.
func commandSecurityEventTx(ctx context.Context, tx pgx.Tx, id *uuid.UUID, cseq int64, why string) error {
	var text *string
	if id != nil {
		s := id.String()
		text = &s
	}
	_, err := tx.Exec(ctx, `INSERT INTO security_events (kind, detail)
		VALUES ('contract_command_invalid', jsonb_strip_nulls(jsonb_build_object('id', $1::text, 'cseq', $2::bigint, 'why', $3::text)))`,
		text, cseq, why)
	return err
}

// rememberWSeqTx keeps the highest wseq the producer finished in the
// workspace in generation gen, and the command that set it; a memory of
// another generation is replaced.
func rememberWSeqTx(ctx context.Context, tx pgx.Tx, workspace uuid.UUID, producer string, gen uuid.UUID, wseq int64, id uuid.UUID) error {
	_, err := tx.Exec(ctx, `INSERT INTO contract_command_wseq AS m (workspace_id, producer, generation, wseq, id)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (workspace_id, producer) DO UPDATE SET
		  id = CASE WHEN m.generation = excluded.generation AND m.wseq >= excluded.wseq THEN m.id ELSE excluded.id END,
		  wseq = CASE WHEN m.generation = excluded.generation THEN greatest(m.wseq, excluded.wseq) ELSE excluded.wseq END,
		  generation = excluded.generation`, workspace, producer, gen, wseq, id)
	return err
}

// CommandResult is a command's result as an act or a refusal writes it.
type CommandResult struct {
	// Outcome is CommandRan or CommandRefused; Code a refusal's.
	Outcome, Code string
	// RetryAfter is in seconds, 0 for none.
	RetryAfter int
	// StateSeq is the seq the result covers or was judged on; nil for
	// expired, invalid_command and a person's not_held (RefuseCommand
	// fills the judged one otherwise).
	StateSeq *int64
	// Detail is a JSON object, or nil.
	Detail json.RawMessage
}

// finishCommandTx writes id's result in tx, by compare-and-set on its
// having none (ErrCommandFinished otherwise, and the caller rolls back): a
// result of a command whose row is of another generation than the current
// one is dropped at once (a plain read of contract_state, 3.4), and the
// wseq memory is kept, refusals included, for a row of the current one.
func finishCommandTx(ctx context.Context, tx pgx.Tx, id uuid.UUID, r CommandResult) error {
	var retry *int
	if r.RetryAfter > 0 {
		retry = &r.RetryAfter
	}
	var code *string
	if r.Code != "" {
		code = &r.Code
	}
	var workspace *uuid.UUID
	var wseq *int64
	var producer string
	var gen uuid.UUID
	var current bool
	err := tx.QueryRow(ctx, `WITH now AS (SELECT clock_timestamp() AS t, (SELECT generation FROM contract_state) AS gen)
		UPDATE contract_commands c SET outcome = $2, code = $3, retry_after = $4, state_seq = $5, detail = $6,
			result_at = now.t, run_after = NULL,
			delivery = CASE WHEN c.generation IS DISTINCT FROM now.gen THEN 'dropped' END,
			delivered_at = CASE WHEN c.generation IS DISTINCT FROM now.gen THEN now.t END
		FROM now WHERE c.id = $1 AND c.outcome IS NULL AND c.`+commandLive+`
		RETURNING c.workspace_id, c.wseq, c.producer, c.generation, c.generation IS NOT DISTINCT FROM now.gen`,
		id, r.Outcome, code, retry, r.StateSeq, jsonOrNil(r.Detail)).Scan(&workspace, &wseq, &producer, &gen, &current)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrCommandFinished
	}
	if err != nil {
		return err
	}
	if workspace == nil || wseq == nil || !current {
		return nil
	}
	return rememberWSeqTx(ctx, tx, *workspace, producer, gen, *wseq, id)
}

// RefuseCommand answers id with a refusal in its own transaction, in 3.4's
// order: the workspace's record first, then the row. With no StateSeq the
// judged seq is filled (the plan's 3.2): max(sections_seq, snapshot_seq, 1)
// for a workspace kind, max(contract_persons.seq, 1) for a person's; never
// for expired, invalid_command or a person's not_held, which carry none.
func (c *Contract) RefuseCommand(ctx context.Context, id uuid.UUID, r CommandResult) error {
	r.Outcome = CommandRefused
	return retryDeadlock(ctx, func() error {
		return pg.InTx(ctx, c.pool, func(tx pgx.Tx) error {
			var workspace, actor *uuid.UUID
			var kind *string
			err := tx.QueryRow(ctx, `SELECT workspace_id, kind, actor FROM contract_commands WHERE id = $1`, id).Scan(&workspace, &kind, &actor)
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrCommandFinished
			}
			if err != nil {
				return err
			}
			judged := int64(1)
			switch {
			case workspace != nil:
				err = tx.QueryRow(ctx, `SELECT greatest(sections_seq, snapshot_seq, 1) FROM contract_workspaces
					WHERE workspace_id = $1 FOR UPDATE`, *workspace).Scan(&judged)
			case kind != nil && actor != nil:
				err = tx.QueryRow(ctx, `SELECT greatest(seq, 1) FROM contract_persons WHERE sub = $1`, *actor).Scan(&judged)
			}
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			person := workspace == nil
			if r.StateSeq == nil && kind != nil && r.Code != CommandExpired && r.Code != CommandInvalid &&
				(!person || r.Code != CommandNotHeld) {
				r.StateSeq = &judged
			}
			return finishCommandTx(ctx, tx, id, r)
		})
	})
}

// ContractCommand is a ledger row as the executor reads it.
type ContractCommand struct {
	ID         uuid.UUID
	TakeSeq    int64
	Generation uuid.UUID
	Cseq       int64
	ContractCommandFields
	Body     []byte
	SignedAt time.Time
	TakenAt  time.Time
	Again    bool
	RunTries int
	RunError string
}

const commandColumns = `c.id, c.take_seq, c.generation, c.cseq, c.producer, c.workspace_id, c.wseq, coalesce(c.kind, ''),
	coalesce(c.section, ''), c.actor, coalesce(c.actor_role, ''), c.target, c.params, c.based_on_seq, c.based_on_docs,
	c.issued_at, c.first_issued_at, c.expires_at, c.retry_of, c.confirm, c.body, c.signed_at, c.taken_at, c.again,
	c.run_tries, coalesce(c.run_error, '')`

func scanCommand(row pgx.Row) (ContractCommand, error) {
	var cmd ContractCommand
	var actor *uuid.UUID
	var target, docs []byte
	var issued, firstIssued *time.Time
	err := row.Scan(&cmd.ID, &cmd.TakeSeq, &cmd.Generation, &cmd.Cseq, &cmd.Producer, &cmd.Workspace, &cmd.WSeq, &cmd.Kind,
		&cmd.Section, &actor, &cmd.ActorRole, &target, &cmd.Params, &cmd.BasedOnSeq, &docs,
		&issued, &firstIssued, &cmd.ExpiresAt, &cmd.RetryOf, &cmd.Confirm, &cmd.Body, &cmd.SignedAt, &cmd.TakenAt, &cmd.Again,
		&cmd.RunTries, &cmd.RunError)
	if actor != nil {
		cmd.Actor = *actor
	}
	if issued != nil {
		cmd.IssuedAt = *issued
	}
	if firstIssued != nil {
		cmd.FirstIssuedAt = *firstIssued
	}
	cmd.Target, cmd.BasedOnDocs = target, docs
	return cmd, err
}

// openCommandSQL is a row the executor may run now: no result, within its
// 30 days, not waiting out a retry, and with no earlier open row of its
// workspace and producer (for a person's kind, of its actor), in take
// order: one at a time per (workspace, producer), in wseq order (S 14.6),
// an old generation's open rows included.
const openCommandSQL = `c.outcome IS NULL AND c.` + commandLive + `
	AND NOT EXISTS (SELECT 1 FROM contract_commands e WHERE e.outcome IS NULL AND e.take_seq < c.take_seq
	  AND e.` + commandLive + ` AND e.producer = c.producer
	  AND (e.workspace_id = c.workspace_id OR (c.workspace_id IS NULL AND e.workspace_id IS NULL AND e.actor = c.actor)))`

// NextCommand reads the first row the executor may run now, in take order;
// false when none is.
func (c *Contract) NextCommand(ctx context.Context) (ContractCommand, bool, error) {
	cmd, err := scanCommand(c.pool.QueryRow(ctx, `SELECT `+commandColumns+` FROM contract_commands c
		WHERE `+openCommandSQL+` AND (c.run_after IS NULL OR c.run_after <= clock_timestamp())
		ORDER BY c.take_seq LIMIT 1`))
	if errors.Is(err, pgx.ErrNoRows) {
		return ContractCommand{}, false, nil
	}
	return cmd, err == nil, err
}

// NextCommandAt is when the first open row waiting out a retry may run,
// on the database's clock, with that clock; false when none waits.
func (c *Contract) NextCommandAt(ctx context.Context) (at, now time.Time, ok bool, err error) {
	var next *time.Time
	err = c.pool.QueryRow(ctx, `SELECT min(c.run_after), clock_timestamp() FROM contract_commands c
		WHERE `+openCommandSQL+` AND c.run_after > clock_timestamp()`).Scan(&next, &now)
	if err != nil || next == nil {
		return time.Time{}, now, false, err
	}
	return *next, now, true, nil
}

// CommandRunFailed records a store error that is not a verdict on id's
// run: one more try, its class (never a message), and the wait before the
// next (CommandRunBackoffMin doubled with each try, up to
// CommandRunBackoffMax). Only later rows of its workspace and producer wait
// behind it. It returns the tries so far; at CommandRunTries the executor
// answers it rate_limited. ErrCommandFinished when it has its result.
func (c *Contract) CommandRunFailed(ctx context.Context, id uuid.UUID, class string) (int, error) {
	var tries int
	err := c.pool.QueryRow(ctx, `UPDATE contract_commands SET run_tries = run_tries + 1, run_error = $2,
		run_after = clock_timestamp() + least($3::interval * power(2, least(run_tries, 20)), $4::interval)
		WHERE id = $1 AND outcome IS NULL RETURNING run_tries`, id, class, CommandRunBackoffMin, CommandRunBackoffMax).Scan(&tries)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrCommandFinished
	}
	return tries, err
}

// restartCommandsTx is the command side of a reset (S 7.4; the plan's
// 3.3), in Restart's transaction after the account state, in 3.4's order:
// the settings row (the feed from 0), the ledger rows to drop (id order:
// every result not delivered of another generation than gen, which the
// platform no longer expects), the wseq memory (forgotten), then every
// section and person document due now, afresh, as the snapshots are.
func restartCommandsTx(ctx context.Context, tx pgx.Tx, gen *uuid.UUID) error {
	if _, err := lockSettingsTx(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE contract_settings_state SET feed_cursor = 0, updated_at = clock_timestamp()`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE contract_commands c SET delivery = 'dropped', delivered_at = clock_timestamp()
		FROM (SELECT id FROM contract_commands WHERE outcome IS NOT NULL AND delivery IS NULL AND generation IS DISTINCT FROM $1::uuid
		      ORDER BY id FOR UPDATE) l WHERE c.id = l.id`, gen); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM contract_command_wseq`); err != nil {
		return err
	}
	return documentsDueNowTx(ctx, tx, true)
}

// RestartFromCommands is a reset the command feed asks for (a gone, or a
// page of another generation than seen), through Restart, so the account
// and command state reset in one transaction. It reads contract_state and
// restarts from it while its generation is still seen: a cursor that moved
// under it is the account follower's page, so it tries again, at most
// three times. False when the generation moved (another reset came first)
// or the cursor kept moving.
func (c *Contract) RestartFromCommands(ctx context.Context, seen uuid.UUID, gen *uuid.UUID) (bool, error) {
	for range 3 {
		st, err := c.State(ctx)
		if err != nil {
			return false, err
		}
		if st.Generation == nil || *st.Generation != seen {
			return false, nil
		}
		done, err := c.Restart(ctx, st.Generation, st.FeedCursor, gen, false)
		if err != nil || done {
			return done, err
		}
	}
	return false, nil
}

// ContractResult is a result to post, as the results poster reads it.
type ContractResult struct {
	ID uuid.UUID
	// Kind is the command's, "" for a row refused before ValidateIn
	// passed (always invalid_command).
	Kind       string
	Outcome    string
	Code       string
	RetryAfter *int
	StateSeq   *int64
	Detail     json.RawMessage
	At         time.Time
	PostTries  int
}

// UndeliveredResults drops every result not delivered of a command whose
// row is of another generation than the current one (an act that read the
// old generation and committed after a reset leaves one), then reads up to
// limit results to post, oldest first.
func (c *Contract) UndeliveredResults(ctx context.Context, limit int) ([]ContractResult, error) {
	if _, err := c.pool.Exec(ctx, `UPDATE contract_commands c SET delivery = 'dropped', delivered_at = clock_timestamp()
		FROM (SELECT id FROM contract_commands WHERE outcome IS NOT NULL AND delivery IS NULL
		        AND generation IS DISTINCT FROM (SELECT generation FROM contract_state)
		      ORDER BY id FOR UPDATE) l WHERE c.id = l.id`); err != nil {
		return nil, err
	}
	rows, err := c.pool.Query(ctx, `SELECT id, coalesce(kind, ''), outcome, coalesce(code, ''), retry_after, state_seq, detail,
		result_at, post_tries FROM contract_commands
		WHERE outcome IS NOT NULL AND delivery IS NULL AND `+commandLive+`
		ORDER BY result_at, id LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (ContractResult, error) {
		var r ContractResult
		var detail []byte
		err := row.Scan(&r.ID, &r.Kind, &r.Outcome, &r.Code, &r.RetryAfter, &r.StateSeq, &detail, &r.At, &r.PostTries)
		r.Detail = detail
		return r, err
	})
}

// ContractResultOutcome is what became of one result posted: the
// platform's answer (Answer: accepted, duplicate or rejected with Code),
// or, with Failed, the class of a post that got no answer for it.
type ContractResultOutcome struct {
	ID     uuid.UUID
	Answer string
	Code   string
	Failed string
}

// ResultsPosted records the answers to results posted, each by
// compare-and-set on its being undelivered: accepted and duplicate settle
// it, a rejection parks it with its code (only invalid_request is
// Wappie's to look at; conflict and not_found are the platform's), and a
// failed post counts a try and keeps its class. An answered post clears
// results_error.
func (c *Contract) ResultsPosted(ctx context.Context, outcomes []ContractResultOutcome) error {
	if len(outcomes) == 0 {
		return nil
	}
	answered := false
	return pg.InTx(ctx, c.pool, func(tx pgx.Tx) error {
		sorted := slices.Clone(outcomes)
		slices.SortFunc(sorted, func(a, b ContractResultOutcome) int { return compareIDs(a.ID, b.ID) })
		for _, o := range sorted {
			if o.Failed != "" {
				if _, err := tx.Exec(ctx, `UPDATE contract_commands SET post_tries = post_tries + 1, post_error = $2
					WHERE id = $1 AND outcome IS NOT NULL AND delivery IS NULL`, o.ID, o.Failed); err != nil {
					return err
				}
				continue
			}
			var code *string
			switch o.Answer {
			case DeliveryAccepted, DeliveryDuplicate:
			case DeliveryRejected:
				if o.Code == "" {
					return fmt.Errorf("store: a rejection of %s with no code", o.ID)
				}
				code = &o.Code
			default:
				return fmt.Errorf("store: unknown answer %q to a result", o.Answer)
			}
			answered = true
			if _, err := tx.Exec(ctx, `UPDATE contract_commands SET delivery = $2, reject_code = $3, delivered_at = clock_timestamp(),
				post_error = NULL WHERE id = $1 AND outcome IS NOT NULL AND delivery IS NULL`, o.ID, o.Answer, code); err != nil {
				return err
			}
		}
		if !answered {
			return nil
		}
		_, err := tx.Exec(ctx, `UPDATE contract_settings_state SET results_error = NULL, results_error_at = NULL WHERE results_error IS NOT NULL`)
		return err
	})
}

// ResultsParked parks results Wappie would not post (they fail the kit's
// check: Wappie's bug): rejected with RejectLocalInvalid, why kept as
// post_error, never sent.
func (c *Contract) ResultsParked(ctx context.Context, ids []uuid.UUID, why string) error {
	_, err := c.pool.Exec(ctx, `UPDATE contract_commands c SET delivery = 'rejected', reject_code = 'local_invalid',
		delivered_at = clock_timestamp(), post_error = $2
		FROM (SELECT id FROM contract_commands WHERE id = ANY ($1) AND outcome IS NOT NULL AND delivery IS NULL ORDER BY id FOR UPDATE) l
		WHERE c.id = l.id`, ids, why)
	return err
}

// TrimCommands deletes the ledger rows past their 30 days, and the persons
// whose sub is no longer followed (no contract_accounts row), each in a
// statement of its own. It returns how many ledger rows went.
func (c *Contract) TrimCommands(ctx context.Context) (int64, error) {
	tag, err := c.pool.Exec(ctx, `DELETE FROM contract_commands WHERE NOT (`+commandLive+`)`)
	if err != nil {
		return 0, err
	}
	if _, err := c.pool.Exec(ctx, `DELETE FROM contract_persons p
		WHERE NOT EXISTS (SELECT 1 FROM contract_accounts a WHERE a.sub = p.sub)`); err != nil {
		return tag.RowsAffected(), err
	}
	return tag.RowsAffected(), nil
}

// ContractResultCount is how many results of one outcome and code the
// ledger holds.
type ContractResultCount struct {
	Outcome, Code string
	N             int64
}

// ContractSectionStatus is one section as contract settings status shows
// it.
type ContractSectionStatus struct {
	Workspace uuid.UUID
	Section   string
	// Status is the workspace's (open, closed, or "" before a document
	// set it).
	Status        string
	StateSeq      int64
	OKAt          *time.Time
	DueAt         time.Time
	Tries         int
	Error         string
	NotFoundSince *time.Time
	ParkedAt      *time.Time
}

// ContractPersonStatus is one person's document as contract settings
// status shows it: a sub Wappie sends for.
type ContractPersonStatus struct {
	Sub      uuid.UUID
	OKAt     *time.Time
	DueAt    time.Time
	Tries    int
	Error    string
	ParkedAt *time.Time
}

// ContractSettingsStatus is what contract settings status and --check
// read, in one snapshot of the database, with its clock.
type ContractSettingsStatus struct {
	State ContractSettingsState
	Now   time.Time
	// Results counts the ledger's results by outcome and code.
	Results []ContractResultCount
	// Open counts the rows with no result, OldestOpen the first taken.
	Open       int64
	OldestOpen *time.Time
	// Undelivered counts the results not delivered; OldestUndelivered is
	// the oldest's result time and UndeliveredError its last post's class.
	Undelivered       int64
	OldestUndelivered *time.Time
	UndeliveredError  string
	// Parked counts the results rejected invalid_request or local_invalid,
	// LastParked the latest.
	Parked     int64
	LastParked *time.Time
	// Retrying counts the open rows retrying after store errors; the
	// oldest was taken at OldestRetrying, its class RetryError.
	Retrying       int64
	OldestRetrying *time.Time
	RetryError     string
	// StuckAt is the latest rate_limited answered after CommandRunTries
	// failed runs.
	StuckAt  *time.Time
	Sections []ContractSectionStatus
	Persons  []ContractPersonStatus
}

// SettingsStatus reads the settings part's state, the ledger's counts, every
// section and every person Wappie sends for, in one REPEATABLE READ
// transaction; rows past their 30 days are left out.
func (c *Contract) SettingsStatus(ctx context.Context) (ContractSettingsStatus, error) {
	var out ContractSettingsStatus
	err := pgx.BeginTxFunc(ctx, c.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var err error
		if out.State, err = scanSettingsState(tx.QueryRow(ctx, `SELECT `+settingsStateColumns+` FROM contract_settings_state`)); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp(),
				count(*) FILTER (WHERE outcome IS NULL), min(taken_at) FILTER (WHERE outcome IS NULL),
				count(*) FILTER (WHERE outcome IS NOT NULL AND delivery IS NULL),
				min(result_at) FILTER (WHERE outcome IS NOT NULL AND delivery IS NULL),
				count(*) FILTER (WHERE reject_code IN ('invalid_request', 'local_invalid')),
				max(delivered_at) FILTER (WHERE reject_code IN ('invalid_request', 'local_invalid')),
				count(*) FILTER (WHERE outcome IS NULL AND run_tries > 0), min(taken_at) FILTER (WHERE outcome IS NULL AND run_tries > 0),
				max(result_at) FILTER (WHERE code = 'rate_limited' AND run_tries >= $1)
			FROM contract_commands WHERE `+commandLive, CommandRunTries).Scan(&out.Now, &out.Open, &out.OldestOpen,
			&out.Undelivered, &out.OldestUndelivered, &out.Parked, &out.LastParked, &out.Retrying, &out.OldestRetrying, &out.StuckAt); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT coalesce((SELECT post_error FROM contract_commands
				WHERE outcome IS NOT NULL AND delivery IS NULL AND `+commandLive+` ORDER BY result_at, id LIMIT 1), ''),
			coalesce((SELECT run_error FROM contract_commands WHERE outcome IS NULL AND run_tries > 0 AND `+commandLive+`
				ORDER BY taken_at, id LIMIT 1), '')`).Scan(&out.UndeliveredError, &out.RetryError); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT outcome, coalesce(code, ''), count(*) FROM contract_commands
			WHERE outcome IS NOT NULL AND `+commandLive+` GROUP BY 1, 2 ORDER BY 1, 2`)
		if err != nil {
			return err
		}
		if out.Results, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (ContractResultCount, error) {
			var r ContractResultCount
			err := row.Scan(&r.Outcome, &r.Code, &r.N)
			return r, err
		}); err != nil {
			return err
		}
		rows, err = tx.Query(ctx, `SELECT s.workspace_id, s.section, coalesce(w.status, ''), s.state_seq, s.ok_at, s.due_at, s.tries,
				coalesce(s.error, ''), s.not_found_since, s.parked_at
			FROM contract_sections s JOIN contract_workspaces w ON w.workspace_id = s.workspace_id
			ORDER BY w.named_at, s.workspace_id, s.section`)
		if err != nil {
			return err
		}
		if out.Sections, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (ContractSectionStatus, error) {
			var s ContractSectionStatus
			err := row.Scan(&s.Workspace, &s.Section, &s.Status, &s.StateSeq, &s.OKAt, &s.DueAt, &s.Tries, &s.Error, &s.NotFoundSince, &s.ParkedAt)
			return s, err
		}); err != nil {
			return err
		}
		rows, err = tx.Query(ctx, `SELECT p.sub, p.ok_at, p.due_at, p.tries, coalesce(p.error, ''), p.parked_at
			FROM contract_persons p JOIN contract_accounts a ON a.sub = p.sub
			WHERE `+personSendableSQL+` ORDER BY p.sub`)
		if err != nil {
			return err
		}
		out.Persons, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (ContractPersonStatus, error) {
			var p ContractPersonStatus
			err := row.Scan(&p.Sub, &p.OKAt, &p.DueAt, &p.Tries, &p.Error, &p.ParkedAt)
			return p, err
		})
		return err
	})
	return out, err
}
