package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/pg"
)

// The contract's settings part on Wappie's side (migration 0052, step 12a):
// its mode, the command feed's cursor, and what contract settings status
// and --check read of them. The ledger is contract_commands.go's, the
// sections' seqs and due times contract_sections.go's, the persons'
// contract_persons.go's. internal/membership speaks the contract and calls
// these; nothing here calls the platform.
//
// One lock order for every 12a writer (the plan's 3.4, DS14), Restart's:
// contract_state, contract_accounts, contract_workspaces (id order),
// contract_settings_state, contract_commands (id order),
// contract_command_wseq, tenants, devices, device_notices and sessions,
// contract_sections, contract_persons. An act takes its record first and
// reads contract_state and contract_accounts with no lock.

// The settings modes (contract_settings_state.mode, DS2).
const (
	// SettingsOff: nothing of the settings part runs.
	SettingsOff = "off"
	// SettingsRead: the sections go with accepts [], the command feed is
	// followed, and every command is answered kind_not_accepted.
	SettingsRead = "read"
	// SettingsOn: the kinds this binary runs.
	SettingsOn = "on"
)

// ContractSettingsChannel carries what the settings sender looks at
// (0052's triggers): a workspace's id when its numbers section changes,
// "c:" and the id for a connection that only flipped between online and
// offline, "u:" and a user's id for that person's notices, and "due" when
// a section or a person was made due sooner, is new, or its park was
// released.
const ContractSettingsChannel = "wappie_contract_settings"

// The classes of the settings part's ERRORs, kept by RecordError in
// contract_state.error_class, which --check reports for a day. RecordError
// is called after an act's transaction ends, never in it: it locks
// contract_state, which an act never asks for while it holds a record.
const (
	// ContractErrorCommandInvalid: a command answered invalid_command.
	ContractErrorCommandInvalid = "command_invalid"
	// ContractErrorCommandStuck: a command answered rate_limited after
	// CommandRunTries failed runs.
	ContractErrorCommandStuck = "command_stuck"
	// ContractErrorSectionInvalid: a section Wappie would not send.
	ContractErrorSectionInvalid = "section_invalid"
	// ContractErrorSectionParked: a section parked.
	ContractErrorSectionParked = "section_parked"
	// ContractErrorResultParked: a result parked (invalid_request, or
	// Wappie's own check refused it).
	ContractErrorResultParked = "result_parked"
	// ContractErrorPersonInvalid: a person's document Wappie would not
	// send whole.
	ContractErrorPersonInvalid = "person_invalid"
	// ContractErrorCommandResetLoop: a reset from the command feed within a
	// minute of the last one it or the token follower made (each resets the
	// command state), which waits the minute out: a platform fault (two
	// feeds on two generations, or a gone that lasts) resets everything
	// once a minute until it ends.
	ContractErrorCommandResetLoop = "command_reset_loop"
)

// ContractSettingsState is contract_settings_state's one row.
type ContractSettingsState struct {
	// Mode is off, read or on as stored; Effective reads it.
	Mode          string
	ModeChangedAt time.Time
	// FeedCursor is the next command feed request's after, under
	// contract_state.generation.
	FeedCursor int64
	// FirstReadAt is the first page committed, set once: the platform
	// watches the feed from then on. ReadAt is the last.
	FirstReadAt, ReadAt *time.Time
	// FeedError is the class of the feed calls' failure since FeedErrorAt
	// ("" once a page commits); ResultsError the results poster's.
	FeedError      string
	FeedErrorAt    *time.Time
	ResultsError   string
	ResultsErrorAt *time.Time
	// InvalidAt is the last invalid_command answered.
	InvalidAt *time.Time
	// LabelCutoverAt is 0052's migrate time: a notice's label stored
	// before it is sent only when today's rule gives the same.
	LabelCutoverAt time.Time
	UpdatedAt      time.Time
}

// Effective is the mode this binary acts on: one it does not know, which a
// later release may add, reads as read (DS2), never as off or on.
func (s ContractSettingsState) Effective() string {
	switch s.Mode {
	case SettingsOff, SettingsOn:
		return s.Mode
	}
	return SettingsRead
}

// Following reports whether the command feed is followed: every mode but
// off.
func (s ContractSettingsState) Following() bool { return s.Effective() != SettingsOff }

const settingsStateColumns = `mode, mode_changed_at, feed_cursor, first_read_at, read_at,
	coalesce(feed_error, ''), feed_error_at, coalesce(results_error, ''), results_error_at, invalid_at,
	label_cutover_at, updated_at`

func scanSettingsState(row pgx.Row) (ContractSettingsState, error) {
	var s ContractSettingsState
	err := row.Scan(&s.Mode, &s.ModeChangedAt, &s.FeedCursor, &s.FirstReadAt, &s.ReadAt, &s.FeedError, &s.FeedErrorAt,
		&s.ResultsError, &s.ResultsErrorAt, &s.InvalidAt, &s.LabelCutoverAt, &s.UpdatedAt)
	return s, err
}

// SettingsState reads contract_settings_state.
func (c *Contract) SettingsState(ctx context.Context) (ContractSettingsState, error) {
	return scanSettingsState(c.pool.QueryRow(ctx, `SELECT `+settingsStateColumns+` FROM contract_settings_state`))
}

// personSendableSQL is a sub Wappie sends a document for: one it follows
// with a document that is not closed (a contract_accounts row a).
const personSendableSQL = `a.doc IS NOT NULL AND a.status <> 'closed'`

// lockSettingsTx reads contract_settings_state under its row lock.
func lockSettingsTx(ctx context.Context, tx pgx.Tx) (ContractSettingsState, error) {
	return scanSettingsState(tx.QueryRow(ctx, `SELECT `+settingsStateColumns+` FROM contract_settings_state FOR UPDATE`))
}

// SettingsModeChange is what a switch of the settings mode did.
type SettingsModeChange struct {
	From, To string
	// Changed: the mode was another; a switch to the mode it is in changes
	// nothing.
	Changed bool
	// FirstReadAt is the first command feed page committed, nil before
	// one: from then on the platform watches the feed for good.
	FirstReadAt *time.Time
}

var (
	// ErrSettingsMode is a mode Wappie does not know.
	ErrSettingsMode = errors.New("store: the settings mode is off, read or on")
	// ErrSettingsContractOff refuses read and on while the contract is
	// off: the settings part rides on the contract's generation and
	// secrets.
	ErrSettingsContractOff = errors.New("store: the contract is off; settings follow it")
	// ErrSettingsTellPlatform refuses the first switch that follows the
	// command feed, and off once the feed was read, unless the operator
	// says the platform was told (DS16): from the first read the platform
	// watches the feed for good, and alerts when it goes silent.
	ErrSettingsTellPlatform = errors.New("store: tell the platform first")
)

// SetSettingsMode switches the settings mode in one transaction,
// contract_state first (3.4's order). It refuses read and on while the
// contract is off; the first switch to read or on (no feed read yet), and
// off after a first read, unless platformTold. On any change every section
// and person document is due now (their accepts change), and every
// process's contract loop is woken (ContractModeChannel, "settings").
func (c *Contract) SetSettingsMode(ctx context.Context, mode string, platformTold bool) (SettingsModeChange, error) {
	if mode != SettingsOff && mode != SettingsRead && mode != SettingsOn {
		return SettingsModeChange{}, ErrSettingsMode
	}
	var out SettingsModeChange
	err := retryDeadlock(ctx, func() error {
		return pg.InTx(ctx, c.pool, func(tx pgx.Tx) error {
			state, err := lockStateTx(ctx, tx)
			if err != nil {
				return err
			}
			settings, err := lockSettingsTx(ctx, tx)
			if err != nil {
				return err
			}
			out = SettingsModeChange{From: settings.Mode, To: mode, FirstReadAt: settings.FirstReadAt}
			if settings.Mode == mode {
				return nil
			}
			switch {
			case mode != SettingsOff && !state.On():
				return ErrSettingsContractOff
			case mode != SettingsOff && settings.Mode == SettingsOff && settings.FirstReadAt == nil && !platformTold:
				return ErrSettingsTellPlatform
			case mode == SettingsOff && settings.FirstReadAt != nil && !platformTold:
				return ErrSettingsTellPlatform
			}
			out.Changed = true
			if _, err := tx.Exec(ctx, `UPDATE contract_settings_state SET mode = $1, mode_changed_at = clock_timestamp(),
				updated_at = clock_timestamp()`, mode); err != nil {
				return err
			}
			if err := documentsDueNowTx(ctx, tx, false); err != nil {
				return err
			}
			_, err = tx.Exec(ctx, `SELECT pg_notify($1, 'settings')`, ContractModeChannel)
			return err
		})
	})
	return out, err
}

// settingsOffTx turns settings off with the contract (contract mode off,
// in SetMode's transaction, after its contract_state lock): the settings
// part rides on the contract. It reports whether they were on.
func settingsOffTx(ctx context.Context, tx pgx.Tx) (bool, error) {
	tag, err := tx.Exec(ctx, `UPDATE contract_settings_state SET mode = 'off', mode_changed_at = clock_timestamp(),
		updated_at = clock_timestamp() WHERE mode <> 'off'`)
	return tag.RowsAffected() == 1, err
}

// documentsDueNowTx makes every section and person document due now, in
// key order, after the settings row in 3.4's order. With reset, as after
// a new generation, each also starts afresh: no accepted document (the
// platform may hold none of it), no backoff, no not_found run and no park,
// as Restart leaves the snapshots.
func documentsDueNowTx(ctx context.Context, tx pgx.Tx, reset bool) error {
	set := `due_at = clock_timestamp()`
	if reset {
		set += `, ok_at = NULL, tries = 0, error = NULL, not_found_since = NULL, parked_at = NULL`
	}
	if _, err := tx.Exec(ctx, `UPDATE contract_sections s SET `+set+`
		FROM (SELECT workspace_id, section FROM contract_sections ORDER BY workspace_id, section FOR UPDATE) l
		WHERE s.workspace_id = l.workspace_id AND s.section = l.section`); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE contract_persons p SET `+set+`
		FROM (SELECT sub FROM contract_persons ORDER BY sub FOR UPDATE) l WHERE p.sub = l.sub`)
	return err
}

// CommandFeedFailed records that a command feed call got no signed page:
// its class (an outcome, a refusal's code, a transport's; never a
// message), and, kept from the first failure of the run, since when. A
// page's commit clears both.
func (c *Contract) CommandFeedFailed(ctx context.Context, class string) error {
	_, err := c.pool.Exec(ctx, `UPDATE contract_settings_state SET feed_error = $1,
		feed_error_at = coalesce(feed_error_at, clock_timestamp())`, class)
	return err
}

// ResultsFailed records that a results post got no signed answer, as
// CommandFeedFailed does for the feed. An answered post clears both
// (ResultsPosted).
func (c *Contract) ResultsFailed(ctx context.Context, class string) error {
	_, err := c.pool.Exec(ctx, `UPDATE contract_settings_state SET results_error = $1,
		results_error_at = coalesce(results_error_at, clock_timestamp())`, class)
	return err
}

// UserOfSub is the local account linked to sub, nil for none.
func (c *Contract) UserOfSub(ctx context.Context, sub uuid.UUID) (*uuid.UUID, error) {
	var user uuid.UUID
	err := c.pool.QueryRow(ctx, `SELECT user_id FROM platform_identities WHERE sub = $1`, sub).Scan(&user)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}
