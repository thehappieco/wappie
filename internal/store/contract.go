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
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/obs"
	"whatserver2/internal/pg"
)

// The platform contract's state on Wappie's side (migration 0051, decision
// 0040): the mode, the documents the platform answers for each sub Wappie
// subscribes, and the workspaces they name. internal/membership speaks the
// contract and fills these structs from the kit's; this file only stores
// and reads them, on the database's clock.
//
// The three tables carry no row-level security (0051). Every transaction
// that stores documents locks contract_state's one row first, so the first
// writer of a generation wins and documents are stored one batch at a time;
// within a batch, accounts and then workspaces are written in id order, so
// a transaction that also holds other rows never meets another in the
// opposite order (the plan's DB23), and a deadlock the server still reports
// is retried.

// Contract is the contract's state in the database.
type Contract struct{ pool *pgxpool.Pool }

// NewContract returns the contract store backed by pool.
func NewContract(pool *pgxpool.Pool) *Contract { return &Contract{pool: pool} }

// The contract's modes (contract_state.mode). Enforce widens them.
const (
	ContractOff     = "off"
	ContractObserve = "observe"
)

// The channels the contract's triggers and writers notify.
const (
	// ContractDirtyChannel carries a workspace's id, or "all", when a change
	// its access snapshot shows commits (0051's triggers).
	ContractDirtyChannel = "wappie_contract_dirty"
	// ContractModeChannel wakes every process's contract loop: a mode
	// switch, or an answer of a generation Wappie does not hold.
	ContractModeChannel = "wappie_contract_mode"
)

// FreshFor is how long a validated document, or a trusted
// published_through, keeps a sub fresh (README 7.1).
const FreshFor = time.Hour

// ContractPeriod is one stretch of time the contract was off after its
// first observe.
type ContractPeriod struct{ From, To time.Time }

// ContractState is contract_state's one row.
type ContractState struct {
	Mode          string
	ModeChangedAt time.Time
	// EventsFrom is the first switch to observe; nil until then.
	EventsFrom *time.Time
	// EventsPausedAt is the last switch from observe to off, while off.
	EventsPausedAt *time.Time
	// EventsOff are the off periods after EventsFrom.
	EventsOff []ContractPeriod
	MailFrom  time.Time
	// Generation is the platform database's identity the stored state
	// belongs to; nil before the first answer and after a gone.
	Generation          *uuid.UUID
	GenerationConfirmed bool
	FeedCursor          int64
	PublishedThrough    *time.Time
	RoundGeneration     *uuid.UUID
	UpdatedAt           time.Time
}

// Observed reports whether the contract was ever switched to observe: from
// then on Wappie never goes back to choosing a new account's personal
// workspace itself (the plan's DB2).
func (s ContractState) Observed() bool { return s.EventsFrom != nil }

const contractStateColumns = `mode, mode_changed_at, events_from, events_paused_at, events_off, mail_from,
	generation, generation_confirmed, feed_cursor, published_through, round_generation, updated_at`

func scanContractState(row pgx.Row) (ContractState, error) {
	var s ContractState
	var off pgtype.Multirange[pgtype.Range[pgtype.Timestamptz]]
	if err := row.Scan(&s.Mode, &s.ModeChangedAt, &s.EventsFrom, &s.EventsPausedAt, &off, &s.MailFrom,
		&s.Generation, &s.GenerationConfirmed, &s.FeedCursor, &s.PublishedThrough, &s.RoundGeneration, &s.UpdatedAt); err != nil {
		return ContractState{}, err
	}
	for _, r := range off {
		// The off periods are closed ranges of two known times: an
		// unbounded or empty one is a fault, not a period.
		if !r.Valid || !r.Lower.Valid || !r.Upper.Valid {
			return ContractState{}, errors.New("store: contract_state.events_off holds an unbounded period")
		}
		s.EventsOff = append(s.EventsOff, ContractPeriod{From: r.Lower.Time, To: r.Upper.Time})
	}
	return s, nil
}

// State reads contract_state.
func (c *Contract) State(ctx context.Context) (ContractState, error) {
	return scanContractState(c.pool.QueryRow(ctx, `SELECT `+contractStateColumns+` FROM contract_state`))
}

// lockStateTx reads contract_state under its row lock, which every
// transaction that stores documents or moves the feed takes first.
func lockStateTx(ctx context.Context, tx pgx.Tx) (ContractState, error) {
	return scanContractState(tx.QueryRow(ctx, `SELECT `+contractStateColumns+` FROM contract_state FOR UPDATE`))
}

// ContractDoc is one account's document as the platform answered it
// (README 6.2), validated by the caller; membership fills it from the
// kit's AccountDoc. It holds no email and no person's name.
type ContractDoc struct {
	Sub        uuid.UUID
	Generation uuid.UUID
	Version    int64
	// Status is active, disabled or closed.
	Status string
	// The latest disable, revocation of every session, and recovery.
	DisabledAt           *time.Time
	SessionsRevokedAt    *time.Time
	CredentialsRevokedAt *time.Time
	// Workspaces are the account's, the personal one first.
	Workspaces []ContractDocWorkspace
	// Raw is the document as received, a JSON object.
	Raw []byte
}

// ContractDocWorkspace is one workspace of a document.
type ContractDocWorkspace struct {
	ID uuid.UUID
	// Kind is personal or team; Role owner, admin or member; Status open
	// or closed.
	Kind, Role, Status string
	WVersion           int64
}

// ContractDocOutcome is what storing one document did.
type ContractDocOutcome string

const (
	// ContractDocStored: a newer version of the stored generation, stored,
	// and the sub is fresh.
	ContractDocStored ContractDocOutcome = "stored"
	// ContractDocKept: the version Wappie holds already, or a lower one:
	// the stored document stays, and the sub is fresh all the same (the
	// plan's DB8: only the document's columns are newer-only).
	ContractDocKept ContractDocOutcome = "kept"
	// ContractDocOtherGeneration: of a generation Wappie does not hold:
	// nothing stored or refreshed, and every contract loop is woken, so
	// the leader's next feed call finds the new generation or gone.
	ContractDocOtherGeneration ContractDocOutcome = "other_generation"
	// ContractDocKindChanged: it names a workspace with another kind than
	// Wappie recorded for it, or than the local workspace of that id has:
	// nothing stored or refreshed, logged at ERROR (README 6.2: an app
	// refuses, and alerts on, such a document).
	ContractDocKindChanged ContractDocOutcome = "kind_changed"
)

// StoreDocuments stores documents in one transaction, as the follower's
// page, the round, a sign-in's PUT and a GET each do (the plan's 4.5, 4.7
// and 4.8), and says for each, in order, what it did. While Wappie holds no
// generation (the first answer, and after a gone) the first document's
// generation is adopted. Each document of the stored generation refreshes
// its sub's fresh_at and records every workspace it names; its own columns
// are replaced only by a higher version, and its revocation times only
// rise. Nothing here applies a document: that is enforce's.
func (c *Contract) StoreDocuments(ctx context.Context, docs ...ContractDoc) ([]ContractDocOutcome, error) {
	var out []ContractDocOutcome
	err := retryDeadlock(ctx, func() error {
		return pg.InTx(ctx, c.pool, func(tx pgx.Tx) error {
			state, err := lockStateTx(ctx, tx)
			if err != nil {
				return err
			}
			out, err = storeDocsTx(ctx, tx, state, docs)
			return err
		})
	})
	return out, err
}

// storeDocsTx stores docs in tx, which holds contract_state's lock (state
// is what it read under it): accounts in sub order, then their workspaces
// in id order.
func storeDocsTx(ctx context.Context, tx pgx.Tx, state ContractState, docs []ContractDoc) ([]ContractDocOutcome, error) {
	out := make([]ContractDocOutcome, len(docs))
	if len(docs) == 0 {
		return out, nil
	}
	generation := state.Generation
	if generation == nil {
		g := docs[0].Generation
		if _, err := tx.Exec(ctx, `UPDATE contract_state SET generation = $1, generation_confirmed = false,
			updated_at = clock_timestamp() WHERE generation IS NULL`, g); err != nil {
			return nil, err
		}
		generation = &g
	}

	// The kinds Wappie knows of every workspace the documents name: the
	// record's, and the local workspace's of the same id.
	var ids []uuid.UUID
	for _, d := range docs {
		for _, w := range d.Workspaces {
			ids = append(ids, w.ID)
		}
	}
	type known struct{ recorded, local string }
	kinds := map[uuid.UUID]known{}
	rows, err := tx.Query(ctx, `SELECT w.id, coalesce(cw.kind, ''), coalesce(t.kind, '')
		FROM unnest($1::uuid[]) AS w(id)
		LEFT JOIN contract_workspaces cw ON cw.workspace_id = w.id
		LEFT JOIN tenants t ON t.id = w.id`, ids)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id uuid.UUID
		var k known
		if err := rows.Scan(&id, &k.recorded, &k.local); err != nil {
			rows.Close()
			return nil, err
		}
		kinds[id] = k
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	order := make([]int, len(docs))
	for i := range order {
		order[i] = i
	}
	slices.SortStableFunc(order, func(a, b int) int { return compareIDs(docs[a].Sub, docs[b].Sub) })
	named := map[uuid.UUID]ContractDocWorkspace{}
	other := false
next:
	for _, i := range order {
		d := docs[i]
		if d.Generation != *generation {
			out[i] = ContractDocOtherGeneration
			other = true
			continue
		}
		for _, w := range d.Workspaces {
			if k := kinds[w.ID]; (k.recorded != "" && k.recorded != w.Kind) || (k.local != "" && k.local != w.Kind) {
				obs.LoggerFrom(ctx).Error("contract: workspace kind changed: the document is not stored",
					"sub", d.Sub, "workspace", w.ID, "kind", w.Kind, "recorded", k.recorded, "local", k.local)
				out[i] = ContractDocKindChanged
				continue next
			}
		}
		stored, err := storeAccountTx(ctx, tx, d)
		if err != nil {
			return nil, err
		}
		out[i] = ContractDocKept
		if stored {
			out[i] = ContractDocStored
		}
		for _, w := range d.Workspaces {
			// A later document of this batch is held to the kind this one
			// recorded.
			if k := kinds[w.ID]; k.recorded == "" {
				k.recorded = w.Kind
				kinds[w.ID] = k
			}
			if n, ok := named[w.ID]; !ok || w.WVersion > n.WVersion {
				named[w.ID] = w
			}
		}
	}
	if err := recordWorkspacesTx(ctx, tx, named); err != nil {
		return nil, err
	}
	if other {
		if _, err := tx.Exec(ctx, `SELECT pg_notify($1, 'generation')`, ContractModeChannel); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// storeAccountTx writes one document of the stored generation: the row's
// document columns when its version is higher than the row's (or the row
// has none), the revocation times at the highest seen, and fresh_at in any
// case. It reports whether the document was the newer one.
func storeAccountTx(ctx context.Context, tx pgx.Tx, d ContractDoc) (bool, error) {
	if !json.Valid(d.Raw) {
		return false, fmt.Errorf("store: the document of %s is not JSON", d.Sub)
	}
	var generation *uuid.UUID
	var version *int64
	err := tx.QueryRow(ctx, `SELECT generation, version FROM contract_accounts WHERE sub = $1 FOR UPDATE`, d.Sub).Scan(&generation, &version)
	if errors.Is(err, pgx.ErrNoRows) {
		_, err = tx.Exec(ctx, `INSERT INTO contract_accounts (sub, generation, version, status, disabled_at, sessions_revoked_at,
			credentials_revoked_at, doc, applied_at, fresh_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, clock_timestamp(), clock_timestamp())`,
			d.Sub, d.Generation, d.Version, d.Status, d.DisabledAt, d.SessionsRevokedAt, d.CredentialsRevokedAt, d.Raw)
		return err == nil, err
	}
	if err != nil {
		return false, err
	}
	newer := version == nil || generation == nil || *generation != d.Generation || d.Version > *version
	_, err = tx.Exec(ctx, `UPDATE contract_accounts SET
		generation = CASE WHEN $2 THEN $3 ELSE generation END,
		version    = CASE WHEN $2 THEN $4 ELSE version END,
		status     = CASE WHEN $2 THEN $5 ELSE status END,
		doc        = CASE WHEN $2 THEN $6::jsonb ELSE doc END,
		applied_at = CASE WHEN $2 THEN clock_timestamp() ELSE applied_at END,
		disabled_at            = greatest(disabled_at, $7),
		sessions_revoked_at    = greatest(sessions_revoked_at, $8),
		credentials_revoked_at = greatest(credentials_revoked_at, $9),
		fresh_at   = clock_timestamp()
		WHERE sub = $1`,
		d.Sub, newer, d.Generation, d.Version, d.Status, d.Raw, d.DisabledAt, d.SessionsRevokedAt, d.CredentialsRevokedAt)
	return newer, err
}

// recordWorkspacesTx records every named workspace for good, in id order:
// a new one with its kind and the time it was first named, and its status
// only with a higher wversion (README 6.2).
func recordWorkspacesTx(ctx context.Context, tx pgx.Tx, named map[uuid.UUID]ContractDocWorkspace) error {
	ids := make([]uuid.UUID, 0, len(named))
	for id := range named {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, compareIDs)
	for _, id := range ids {
		w := named[id]
		if _, err := tx.Exec(ctx, `INSERT INTO contract_workspaces (workspace_id, kind, wversion, status)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (workspace_id) DO UPDATE SET wversion = excluded.wversion, status = excluded.status
			WHERE contract_workspaces.wversion < excluded.wversion`, id, w.Kind, w.WVersion, w.Status); err != nil {
			return err
		}
	}
	return nil
}

// ContractWorkspace is one recorded platform workspace.
type ContractWorkspace struct {
	ID       uuid.UUID
	Kind     string
	NamedAt  time.Time
	WVersion int64
	// Status is open or closed, or empty before a document with a wversion
	// above the record's set it.
	Status string
}

// Workspace reads the record of a platform workspace, and false when no
// document has named it.
func (c *Contract) Workspace(ctx context.Context, id uuid.UUID) (ContractWorkspace, bool, error) {
	w := ContractWorkspace{ID: id}
	err := c.pool.QueryRow(ctx, `SELECT kind, named_at, wversion, coalesce(status, '') FROM contract_workspaces
		WHERE workspace_id = $1`, id).Scan(&w.Kind, &w.NamedAt, &w.WVersion, &w.Status)
	if errors.Is(err, pgx.ErrNoRows) {
		return ContractWorkspace{}, false, nil
	}
	return w, err == nil, err
}

// Intend commits the intent row of a PUT for sub, in its own statement and
// before the PUT is sent (the plan's DB21), and returns its subscribed_at:
// every subscription Wappie makes then has a row the sweep can see, and
// the sweep's removal names the intent it saw.
func (c *Contract) Intend(ctx context.Context, sub uuid.UUID) (time.Time, error) {
	var at time.Time
	err := c.pool.QueryRow(ctx, `INSERT INTO contract_accounts (sub) VALUES ($1)
		ON CONFLICT (sub) DO UPDATE SET subscribed_at = clock_timestamp()
		RETURNING subscribed_at`, sub).Scan(&at)
	return at, err
}

// ForgetIntent removes sub's row after the platform's signed unsubscribe,
// only while it is the intent seen and the sub is still not linked; false
// when a newer PUT or a link came meanwhile, and the caller subscribes
// again.
func (c *Contract) ForgetIntent(ctx context.Context, sub uuid.UUID, seen time.Time) (bool, error) {
	tag, err := c.pool.Exec(ctx, `DELETE FROM contract_accounts WHERE sub = $1 AND subscribed_at = $2
		AND NOT EXISTS (SELECT 1 FROM platform_identities WHERE sub = $1)`, sub, seen)
	return tag.RowsAffected() == 1, err
}

// ContractIntent is a subscription's row as the sweep reads it.
type ContractIntent struct {
	Sub          uuid.UUID
	SubscribedAt time.Time
}

// Orphans lists, oldest first, the subscriptions of subs Wappie does not
// hold whose last PUT's intent is older than after: a sign-up refused after
// its PUT, a failed unsubscribe, a ticket abandoned. The sweep unsubscribes
// them (the plan's 4.6).
func (c *Contract) Orphans(ctx context.Context, after time.Duration, limit int) ([]ContractIntent, error) {
	rows, err := c.pool.Query(ctx, `SELECT a.sub, a.subscribed_at FROM contract_accounts a
		WHERE a.subscribed_at < clock_timestamp() - $1::interval
		  AND NOT EXISTS (SELECT 1 FROM platform_identities pi WHERE pi.sub = a.sub)
		ORDER BY a.subscribed_at, a.sub LIMIT $2`, after, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (ContractIntent, error) {
		var i ContractIntent
		err := row.Scan(&i.Sub, &i.SubscribedAt)
		return i, err
	})
}

// Unsubscribed lists the subs Wappie holds (people linked to the platform)
// whose row is missing or carries no version of the stored generation: the
// round's work (the plan's 4.6).
func (c *Contract) Unsubscribed(ctx context.Context, limit int) ([]uuid.UUID, error) {
	rows, err := c.pool.Query(ctx, `SELECT pi.sub FROM platform_identities pi
		CROSS JOIN contract_state s
		LEFT JOIN contract_accounts a ON a.sub = pi.sub
		WHERE a.version IS NULL OR a.generation IS DISTINCT FROM s.generation
		ORDER BY pi.sub LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

// Unfollowed forgets sub's stored version after a signed not_found on a GET
// for it: the platform follows it no more, so its document stops counting
// for freshness through published_through, and the round subscribes it
// again. Its document and fresh_at stay.
func (c *Contract) Unfollowed(ctx context.Context, sub uuid.UUID) error {
	_, err := c.pool.Exec(ctx, `UPDATE contract_accounts SET generation = NULL, version = NULL WHERE sub = $1`, sub)
	return err
}

// Fresh says, for each sub, whether it is fresh within d on the database's
// clock: the later of its last validated document and the last trusted
// published_through, the latter only for a sub the platform follows in the
// stored generation (README 7.1; the plan's DB8). An unknown sub is stale.
func (c *Contract) Fresh(ctx context.Context, d time.Duration, subs ...uuid.UUID) (map[uuid.UUID]bool, error) {
	out := make(map[uuid.UUID]bool, len(subs))
	if len(subs) == 0 {
		return out, nil
	}
	rows, err := c.pool.Query(ctx, `SELECT q.sub, coalesce(greatest(a.fresh_at,
			CASE WHEN a.version IS NOT NULL AND a.generation = s.generation THEN s.published_through END)
			> clock_timestamp() - $2::interval, false)
		FROM unnest($1::uuid[]) AS q(sub)
		CROSS JOIN contract_state s
		LEFT JOIN contract_accounts a ON a.sub = q.sub`, subs, d)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var sub uuid.UUID
		var fresh bool
		if err := rows.Scan(&sub, &fresh); err != nil {
			return nil, err
		}
		out[sub] = fresh
	}
	return out, rows.Err()
}

// compareIDs orders UUIDs as Postgres does, byte by byte.
func compareIDs(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) }

// retryDeadlock runs fn again, at most twice more, when the server aborted
// it as a deadlock (40P01): fn is one whole transaction, so nothing of the
// aborted attempt stands.
func retryDeadlock(ctx context.Context, fn func() error) error {
	var err error
	for range 3 {
		if err = fn(); !isDeadlock(err) {
			return err
		}
		obs.LoggerFrom(ctx).Warn("store: a contract transaction deadlocked; retrying")
	}
	return err
}

func isDeadlock(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "40P01"
}
