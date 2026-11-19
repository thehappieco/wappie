package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/pg"
)

// Applying the stored account documents at enforce (decision DS54; the
// enforce design of 2026-11-18, step E1). Observe stores each document and
// compares it with Wappie's tables (contract_observe.go); enforce makes the
// tables say what the document says, from the same stored documents, by
// sub and by workspace:
//
//   - the document decides memberships in every workspace it records: a
//     membership it lists is added, given its role or set active; a
//     person's membership in a recorded workspace it does not list is
//     removed with every effect of a removal (applyMembershipLossTx);
//   - a team it names that Wappie lacks is created with the platform's id
//     and name; a workspace's name and closure follow its wversion
//     (ApplyWorkspace);
//   - the account's status, disable, revocation of sessions and recovery
//     (credentials_revoked_at) apply to the person (contract_apply_account.go);
//   - a closed account leaves every team, and is forgotten once its
//     personal numbers are purged (contract_apply_closing.go);
//   - service users with no membership lose any key still acting as them
//     (contract_apply_orphans.go).
//
// Every apply refuses unless contract_state.mode is enforce
// (ErrApplyNeedsEnforce), read FOR SHARE in its own transaction, which
// 0051's CHECK cannot hold until E2 widens it: nothing here runs before E2.
// The plan (PlanAccount, PlanAll) is the same code with nothing written, in
// one REPEATABLE READ, read-only transaction, in any mode: whatserverd
// contract apply -dry-run.
//
// Each step compares the document with the tables under the locks, so a
// pass run again changes nothing; the applied_* markers (0055) only spare
// needless passes. One transaction per account, in DB23's order extended by
// DS14 and DB25: contract_state FOR SHARE, the account's row, the records
// (contract_workspaces) of every workspace touched in id order, their
// tenants rows in id order, the person's users row, then each workspace's
// connections and rows. The apply never takes contract_token_state, and
// writes no token row: the belt reads the stored document.

// ContractEnforce is the mode at which documents apply. 0051's CHECK holds
// it only once E2 widens it.
const ContractEnforce = "enforce"

// ContractErrorApplyFailed is contract_state.error_class for an apply
// that failed (logged at ERROR): contract status --check reports it.
const ContractErrorApplyFailed = "apply_failed"

// ErrApplyNeedsEnforce refuses an apply while the contract is not at
// enforce: nothing is written.
var ErrApplyNeedsEnforce = errors.New("store: applying the platform's documents needs the contract at enforce")

// The kinds of what an apply does, or a plan would do (ApplyAction.Kind).
const (
	ApplyTeamCreated        = "team_created"
	ApplyMemberAdded        = "member_added"
	ApplyRoleChanged        = "role_changed"
	ApplyMemberEnabled      = "member_enabled"
	ApplyMemberLost         = "member_lost"
	ApplyTeamRenamed        = "team_renamed"
	ApplyTeamClosed         = "team_closed"
	ApplyTeamReopened       = "team_reopened"
	ApplyPersonalNamed      = "personal_named"
	ApplyAccountSuspended   = "account_suspended"
	ApplyAccountEnabled     = "account_enabled"
	ApplyOperatorDisable    = "operator_disable"
	ApplySessionsEnded      = "sessions_ended"
	ApplyCredentialsStopped = "credentials_stopped"
	ApplyServiceKept        = "service_kept"
	ApplyClosingSeen        = "closing_seen"
	ApplyClosingConfirmed   = "closing_confirmed"
	ApplyForgotten          = "forgotten"
	ApplyOrphanKeysRevoked  = "orphan_keys_revoked"
	ApplyHeld               = "held"
)

// Why part of an account's document is left for a later pass
// (contract_accounts.apply_held).
const (
	// HeldStrandsUnconfirmed: a membership's loss would strand a number,
	// and the platform's generation is not confirmed yet.
	HeldStrandsUnconfirmed = "strands_unconfirmed"
	// HeldPersonalMismatch: the document's personal workspace is not the
	// person's local one; neither is ever moved or deleted.
	HeldPersonalMismatch = "personal_mismatch"
	// HeldClosingUnconfirmed: a closed account waits for a fresh signed
	// answer before its personal numbers are deleted.
	HeldClosingUnconfirmed = "closing_unconfirmed"
	// HeldNoTenant: a team the document lists has no workspace yet.
	HeldNoTenant = "no_tenant"
)

// heldOrder is which held reason an account records when several hold.
var heldOrder = []string{HeldStrandsUnconfirmed, HeldNoTenant, HeldPersonalMismatch, HeldClosingUnconfirmed}

// ApplyAction is one thing an apply did, or a plan would do, by ids and
// counts only (DB22). Only the fields its kind uses are set.
type ApplyAction struct {
	Kind      string
	Sub       uuid.UUID
	User      uuid.UUID
	Workspace uuid.UUID
	// Local and Platform are the two roles (role_changed), or a kept
	// service's reason (Local, service_kept).
	Local, Platform string
	Count           int64
	// Held is the reason of an action left for later (ApplyHeld).
	Held string
}

// ApplyCounts are an apply's counts, as its log line gives them.
type ApplyCounts struct {
	Added, Roles, Enabled, Lost                        int64
	TeamsCreated, Renamed, Closed, Reopened            int64
	Sessions, Keys, Connections, Keychain              int64
	ServicesRemoved, ServicesKept, OrphanKeys, Strands int64
	Invites                                            int64
}

// ApplyResult is what one account's or one workspace's apply did, or its
// plan would do.
type ApplyResult struct {
	Sub       uuid.UUID
	Workspace uuid.UUID
	// Version is the document's applied (or planned).
	Version int64
	Actions []ApplyAction
	// Ended are the connections ended, for their readers to be told.
	Ended []EndedConnection
	// Held is the reason recorded for what was left, "" for none.
	Held   string
	Counts ApplyCounts
	// OperatorDisable: an operator's disable stands over an active
	// document.
	OperatorDisable bool
}

// Absorb adds o's actions, ended connections and counts to r: a
// workspace's part to its account's, for one log line.
func (r *ApplyResult) Absorb(o ApplyResult) {
	r.Actions = append(r.Actions, o.Actions...)
	r.Ended = append(r.Ended, o.Ended...)
	c, d := &r.Counts, o.Counts
	c.Added += d.Added
	c.Roles += d.Roles
	c.Enabled += d.Enabled
	c.Lost += d.Lost
	c.TeamsCreated += d.TeamsCreated
	c.Renamed += d.Renamed
	c.Closed += d.Closed
	c.Reopened += d.Reopened
	c.Sessions += d.Sessions
	c.Keys += d.Keys
	c.Connections += d.Connections
	c.Keychain += d.Keychain
	c.ServicesRemoved += d.ServicesRemoved
	c.ServicesKept += d.ServicesKept
	c.OrphanKeys += d.OrphanKeys
	c.Strands += d.Strands
	c.Invites += d.Invites
}

// PendingWorkspacesOf lists the workspaces sub's stored document names
// whose wversion is ahead of what was applied, and that Wappie has, in id
// order: what membership's Apply runs ApplyWorkspace for before the
// account.
func (c *Contract) PendingWorkspacesOf(ctx context.Context, sub uuid.UUID) ([]uuid.UUID, error) {
	rows, err := c.pool.Query(ctx, `SELECT w.workspace_id FROM contract_workspaces w JOIN tenants t ON t.id = w.workspace_id
		WHERE w.wversion > coalesce(w.applied_wversion, -1) AND w.workspace_id IN (
			SELECT (x->>'id')::uuid FROM contract_accounts a CROSS JOIN LATERAL jsonb_array_elements(a.doc->'workspaces') x
			 WHERE a.sub = $1 AND a.doc IS NOT NULL)
		ORDER BY w.workspace_id`, sub)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

// Changed reports whether the result holds any action but a held one.
func (r ApplyResult) Changed() bool {
	for _, a := range r.Actions {
		if a.Kind != ApplyHeld && a.Kind != ApplyOperatorDisable {
			return true
		}
	}
	return false
}

func (r *ApplyResult) add(a ApplyAction) {
	if a.Sub == uuid.Nil {
		a.Sub = r.Sub
	}
	r.Actions = append(r.Actions, a)
	c := &r.Counts
	switch a.Kind {
	case ApplyMemberAdded:
		c.Added++
	case ApplyRoleChanged:
		c.Roles++
	case ApplyMemberEnabled:
		c.Enabled++
	case ApplyMemberLost:
		c.Lost++
	case ApplyTeamCreated:
		c.TeamsCreated++
	case ApplyTeamRenamed, ApplyPersonalNamed:
		c.Renamed++
	case ApplyTeamClosed:
		c.Closed++
	case ApplyTeamReopened:
		c.Reopened++
	case ApplyServiceKept:
		c.ServicesKept++
	}
}

// ApplyPlan is a dry run's: the workspaces' parts, then the accounts', then
// the orphan services' sweep.
type ApplyPlan struct {
	Workspaces []ApplyResult
	Accounts   []ApplyResult
	Orphans    OrphanSweep
}

// Actions counts the plan's actions, held ones apart.
func (p ApplyPlan) Actions() (actions, held int) {
	for _, set := range [][]ApplyResult{p.Workspaces, p.Accounts} {
		for _, r := range set {
			for _, a := range r.Actions {
				if a.Kind == ApplyHeld {
					held++
				} else if a.Kind != ApplyOperatorDisable {
					actions++
				}
			}
		}
	}
	return actions + len(p.Orphans.Actions), held
}

// applyState is contract_state as an apply holds it.
type applyState struct {
	apply      bool
	mode       string
	generation *uuid.UUID
	confirmed  bool
}

// applyStateTx reads contract_state, FOR SHARE for an apply (DB23 step 1:
// StoreDocuments, CommitPage and SetMode wait, so neither the documents
// nor the mode change under it; two applies share it), and refuses one
// unless the mode is enforce when needEnforce.
func applyStateTx(ctx context.Context, tx pgx.Tx, apply, needEnforce bool) (applyState, error) {
	st := applyState{apply: apply}
	lock := ""
	if apply {
		lock = " FOR SHARE"
	}
	if err := tx.QueryRow(ctx, `SELECT mode, generation, generation_confirmed FROM contract_state`+lock).
		Scan(&st.mode, &st.generation, &st.confirmed); err != nil {
		return st, err
	}
	if needEnforce && st.mode != ContractEnforce {
		return st, ErrApplyNeedsEnforce
	}
	return st, nil
}

// applyTx runs fn as an apply: one transaction, retried on a deadlock,
// holding contract_state FOR SHARE (refused unless at enforce when gate).
func (c *Contract) applyTx(ctx context.Context, gate bool, fn func(pgx.Tx, applyState) error) error {
	return retryDeadlock(ctx, func() error {
		return pg.InTx(ctx, c.pool, func(tx pgx.Tx) error {
			st, err := applyStateTx(ctx, tx, true, gate)
			if err != nil {
				return err
			}
			return fn(tx, st)
		})
	})
}

// planTx runs fn as a plan: one REPEATABLE READ, read-only transaction.
func (c *Contract) planTx(ctx context.Context, fn func(pgx.Tx, applyState) error) error {
	return readOnly(ctx, c, func(tx pgx.Tx) error {
		st, err := applyStateTx(ctx, tx, false, false)
		if err != nil {
			return err
		}
		return fn(tx, st)
	})
}

// ApplyAccount applies sub's stored document: one transaction, under
// retryDeadlock (applyAccountTx). The teams it lists that Wappie lacks are
// created first, each in a transaction of its own (EnsureTeams), and the
// workspaces whose wversion is ahead of what was applied are applied by
// ApplyWorkspace; the caller (membership.Members.Apply) runs those first.
// A document of another generation than the stored one, or a sub Wappie
// does not hold, applies nothing.
func (c *Contract) ApplyAccount(ctx context.Context, sub uuid.UUID) (ApplyResult, error) {
	return c.applyAccount(ctx, sub, true)
}

func (c *Contract) applyAccount(ctx context.Context, sub uuid.UUID, gate bool) (ApplyResult, error) {
	var out ApplyResult
	err := c.applyTx(ctx, gate, func(tx pgx.Tx, st applyState) error {
		var err error
		out, err = applyAccountTx(ctx, tx, st, sub)
		return err
	})
	if err != nil {
		// The transaction rolled back: nothing it did stands, so nothing
		// of it is returned for a caller to act on.
		return ApplyResult{Sub: sub}, err
	}
	return out, nil
}

// PlanAccount is what applying sub's document would do now: its teams'
// creation, its workspaces' parts and its account's, read in one
// read-only transaction. It writes nothing, in any mode.
func (c *Contract) PlanAccount(ctx context.Context, sub uuid.UUID) (ApplyPlan, error) {
	var out ApplyPlan
	err := c.planTx(ctx, func(tx pgx.Tx, st applyState) error {
		ids, err := docWorkspacesTx(ctx, tx, sub)
		if err != nil {
			return err
		}
		slices.SortFunc(ids, compareIDs)
		for _, id := range slices.Compact(ids) {
			w, err := applyWorkspaceTx(ctx, tx, st, id)
			if err != nil {
				return err
			}
			if len(w.Actions) > 0 {
				out.Workspaces = append(out.Workspaces, w)
			}
		}
		a, err := applyAccountTx(ctx, tx, st, sub)
		out.Accounts = append(out.Accounts, a)
		return err
	})
	return out, err
}

// PlanAll is what a full pass would do now: every recorded workspace, every
// held sub with a document of the stored generation, and the orphan
// services' sweep, read in one read-only transaction. It writes nothing,
// in any mode.
func (c *Contract) PlanAll(ctx context.Context) (ApplyPlan, error) {
	var out ApplyPlan
	err := c.planTx(ctx, func(tx pgx.Tx, st applyState) error {
		rows, err := tx.Query(ctx, `SELECT workspace_id FROM contract_workspaces ORDER BY workspace_id`)
		if err != nil {
			return err
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			return err
		}
		for _, id := range ids {
			w, err := applyWorkspaceTx(ctx, tx, st, id)
			if err != nil {
				return err
			}
			if len(w.Actions) > 0 {
				out.Workspaces = append(out.Workspaces, w)
			}
		}
		rows, err = tx.Query(ctx, `SELECT a.sub FROM contract_accounts a JOIN platform_identities pi ON pi.sub = a.sub
			CROSS JOIN contract_state s WHERE a.doc IS NOT NULL AND a.generation = s.generation ORDER BY a.sub`)
		if err != nil {
			return err
		}
		subs, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			return err
		}
		for _, sub := range subs {
			a, err := applyAccountTx(ctx, tx, st, sub)
			if err != nil {
				return err
			}
			if len(a.Actions) > 0 {
				out.Accounts = append(out.Accounts, a)
			}
		}
		out.Orphans, err = sweepOrphanServicesTx(ctx, tx, st)
		return err
	})
	return out, err
}

// PendingApply lists what the leader's pass (E2) applies next, at most
// limit of each: the subs held with a document of the stored generation
// whose applied markers differ from the stored document, or with a part
// held, least recently applied first; and the recorded workspaces whose
// wversion is ahead of what was applied (a personal one only once its
// workspace exists), or a team that has no workspace yet and that a
// document of the stored generation still lists (teamListedSQL), in id
// order.
func (c *Contract) PendingApply(ctx context.Context, limit int) (subs, workspaces []uuid.UUID, err error) {
	rows, err := c.pool.Query(ctx, `SELECT a.sub FROM contract_accounts a
		JOIN platform_identities pi ON pi.sub = a.sub CROSS JOIN contract_state s
		WHERE a.doc IS NOT NULL AND a.generation = s.generation AND (a.apply_held IS NOT NULL
		   OR a.applied_generation IS DISTINCT FROM a.generation OR a.applied_version IS DISTINCT FROM a.version
		   OR a.applied_disabled_at IS DISTINCT FROM a.disabled_at
		   OR a.applied_sessions_revoked_at IS DISTINCT FROM a.sessions_revoked_at
		   OR a.applied_credentials_revoked_at IS DISTINCT FROM a.credentials_revoked_at)
		ORDER BY a.apply_last_at NULLS FIRST, a.sub LIMIT $1`, limit)
	if err != nil {
		return nil, nil, err
	}
	if subs, err = pgx.CollectRows(rows, pgx.RowTo[uuid.UUID]); err != nil {
		return nil, nil, err
	}
	rows, err = c.pool.Query(ctx, `SELECT w.workspace_id FROM contract_workspaces w LEFT JOIN tenants t ON t.id = w.workspace_id
		WHERE (t.id IS NOT NULL AND w.wversion > coalesce(w.applied_wversion, -1))
		   OR (w.kind = 'team' AND t.id IS NULL AND `+teamListedSQL+`)
		ORDER BY w.workspace_id LIMIT $1`, limit)
	if err != nil {
		return nil, nil, err
	}
	workspaces, err = pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	return subs, workspaces, err
}

// applyDocWorkspace is one workspace of a stored document, as the apply
// reads it.
type applyDocWorkspace struct {
	ID       uuid.UUID `json:"id"`
	Kind     string    `json:"kind"`
	Role     string    `json:"role"`
	Status   string    `json:"status"`
	WVersion int64     `json:"wversion"`
}

// applyDoc is the part of a stored document the apply reads.
type applyDoc struct {
	Status     string              `json:"status"`
	Workspaces []applyDocWorkspace `json:"workspaces"`
}

// applyAccountRow is contract_accounts' row of the sub applied.
type applyAccountRow struct {
	generation                                                 *uuid.UUID
	version                                                    *int64
	doc                                                        []byte
	disabledAt, sessionsAt, credentialsAt                      *time.Time
	appliedGeneration                                          *uuid.UUID
	appliedVersion                                             *int64
	appliedDisabledAt, appliedSessionsAt, appliedCredentialsAt *time.Time
	held                                                       string
}

// applyMembership is one of the person's local memberships.
type applyMembership struct {
	role, status string
	// deadline: a membership with an expiry, which the apply never
	// touches.
	deadline bool
}

// applyFacts is what Wappie knows of one workspace the apply touches.
type applyFacts struct {
	recorded           bool
	recordKind, record string
	local              bool
	kind, status       string
}

// applyRun is one account's apply, or its plan.
type applyRun struct {
	tx         pgx.Tx
	st         applyState
	sub, user  uuid.UUID
	acct       applyAccountRow
	doc        applyDoc
	identity   uuid.UUID
	userStatus string
	disabledBy string
	email      string
	personal   uuid.UUID
	members    map[uuid.UUID]applyMembership
	facts      map[uuid.UUID]applyFacts
	touched    []uuid.UUID
	held       map[string]bool
	due        map[uuid.UUID]bool
	out        *ApplyResult
	losses     int
	// closed: the document is closed; closingConfirmed: a fresh signed
	// answer confirmed it (contract_closings.confirmed_at).
	closed, closingConfirmed bool
}

// applyAccountTx is one sub's apply (st.apply) or plan, in tx, which holds
// contract_state as applyStateTx read it.
func applyAccountTx(ctx context.Context, tx pgx.Tx, st applyState, sub uuid.UUID) (ApplyResult, error) {
	out := ApplyResult{Sub: sub}
	r := &applyRun{tx: tx, st: st, sub: sub, out: &out, held: map[string]bool{}, due: map[uuid.UUID]bool{}}
	lock := ""
	if st.apply {
		lock = " FOR UPDATE"
	}
	a := &r.acct
	err := tx.QueryRow(ctx, `SELECT generation, version, doc, disabled_at, sessions_revoked_at, credentials_revoked_at,
			applied_generation, applied_version, applied_disabled_at, applied_sessions_revoked_at, applied_credentials_revoked_at,
			coalesce(apply_held, '')
		FROM contract_accounts WHERE sub = $1`+lock, sub).Scan(&a.generation, &a.version, &a.doc, &a.disabledAt, &a.sessionsAt,
		&a.credentialsAt, &a.appliedGeneration, &a.appliedVersion, &a.appliedDisabledAt, &a.appliedSessionsAt,
		&a.appliedCredentialsAt, &a.held)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	// Only a document of the stored generation applies.
	if a.doc == nil || a.generation == nil || a.version == nil || st.generation == nil || *a.generation != *st.generation {
		return out, nil
	}
	out.Version = *a.version
	err = tx.QueryRow(ctx, `SELECT user_id FROM platform_identities WHERE sub = $1`, sub).Scan(&r.user)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(a.doc, &r.doc); err != nil {
		return out, fmt.Errorf("store: a stored document: %w", err)
	}
	if err := r.read(ctx); err != nil {
		return out, err
	}
	if err := r.lock(ctx); err != nil {
		return out, err
	}
	if err := r.run(ctx); err != nil {
		return out, err
	}
	for _, reason := range heldOrder {
		if r.held[reason] {
			out.Held = reason
			break
		}
	}
	if !st.apply {
		return out, nil
	}
	return out, r.mark(ctx)
}

// read reads what the apply decides on, without locks: the person's
// identity workspace, memberships and personal workspace, and every
// workspace the apply may touch, which lock then locks in id order.
func (r *applyRun) read(ctx context.Context) error {
	if err := r.tx.QueryRow(ctx, `SELECT tenant_id FROM user_logins WHERE user_id = $1`, r.user).Scan(&r.identity); err != nil {
		return fmt.Errorf("store: the person's identity workspace: %w", err)
	}
	if err := r.readMembers(ctx); err != nil {
		return err
	}
	ids := make([]uuid.UUID, 0, len(r.members)+len(r.doc.Workspaces))
	for id := range r.members {
		ids = append(ids, id)
	}
	for _, w := range r.doc.Workspaces {
		ids = append(ids, w.ID)
	}
	// Where the person's keys, connections, invited services and pending
	// invitations are, for a suspension or a recovery's stop.
	rows, err := r.tx.Query(ctx, `SELECT tenant_id FROM api_keys WHERE (created_by = $1 OR acts_as = $1) AND revoked_at IS NULL
		UNION SELECT tenant_id FROM mcp_connections WHERE created_by = $1 AND status IN ('pending', 'active', 'reseal')
		UNION SELECT tenant_id FROM invites WHERE created_by = $1 AND role = 'service' AND NOT provisional AND claimed_by IS NOT NULL
		UNION SELECT tenant_id FROM invites WHERE created_by = $1 AND completed_at IS NULL AND revoked_at IS NULL`, r.user)
	if err != nil {
		return err
	}
	more, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return err
	}
	ids = append(ids, more...)
	slices.SortFunc(ids, compareIDs)
	r.touched = slices.Compact(ids)
	return r.readFacts(ctx)
}

// readMembers reads the person's memberships, by their identity's policy,
// and their local personal workspace.
func (r *applyRun) readMembers(ctx context.Context) error {
	if err := scope(ctx, r.tx, uuid.Nil, r.user); err != nil {
		return err
	}
	rows, err := r.tx.Query(ctx, `SELECT tenant_id, role, status, expires_at IS NOT NULL FROM workspace_memberships WHERE user_id = $1`, r.user)
	if err != nil {
		return err
	}
	r.members = map[uuid.UUID]applyMembership{}
	err = forEachRow(rows, func(row pgx.Rows) error {
		var id uuid.UUID
		var m applyMembership
		if err := row.Scan(&id, &m.role, &m.status, &m.deadline); err != nil {
			return err
		}
		r.members[id] = m
		return nil
	})
	if err != nil {
		return err
	}
	return r.tx.QueryRow(ctx, `SELECT coalesce(max(id::text), '00000000-0000-0000-0000-000000000000')::uuid
		FROM tenants WHERE personal_owner_id = $1`, r.user).Scan(&r.personal)
}

// readFacts reads the record and the local workspace of every touched
// workspace.
func (r *applyRun) readFacts(ctx context.Context) error {
	rows, err := r.tx.Query(ctx, `SELECT q.id, cw.workspace_id IS NOT NULL, coalesce(cw.kind, ''), coalesce(cw.status, ''),
			t.id IS NOT NULL, coalesce(t.kind, ''), coalesce(t.status, '')
		FROM unnest($1::uuid[]) AS q(id)
		LEFT JOIN contract_workspaces cw ON cw.workspace_id = q.id
		LEFT JOIN tenants t ON t.id = q.id`, r.touched)
	if err != nil {
		return err
	}
	r.facts = map[uuid.UUID]applyFacts{}
	return forEachRow(rows, func(row pgx.Rows) error {
		var id uuid.UUID
		var f applyFacts
		if err := row.Scan(&id, &f.recorded, &f.recordKind, &f.record, &f.local, &f.kind, &f.status); err != nil {
			return err
		}
		r.facts[id] = f
		return nil
	})
}

// lock takes an apply's locks in DB23's order, after contract_state and
// the account's row: the records of every touched workspace, then their
// tenants rows, each in id order and in one statement, then the person's
// users row; and reads again, under them, what it decides on. A plan reads
// the person's row and takes nothing.
func (r *applyRun) lock(ctx context.Context) error {
	if r.st.apply {
		if _, err := r.tx.Exec(ctx, lockWorkspacesSQL(`workspace_id = ANY ($1)`), r.touched); err != nil {
			return err
		}
		if _, err := r.tx.Exec(ctx, `SELECT id FROM tenants WHERE id = ANY ($1) ORDER BY id FOR UPDATE`, r.touched); err != nil {
			return err
		}
	}
	if err := scope(ctx, r.tx, r.identity, uuid.Nil); err != nil {
		return err
	}
	lock := ""
	if r.st.apply {
		lock = " FOR UPDATE"
	}
	if err := r.tx.QueryRow(ctx, `SELECT status, coalesce(disabled_by, ''), email FROM users WHERE id = $1`+lock, r.user).
		Scan(&r.userStatus, &r.disabledBy, &r.email); err != nil {
		return fmt.Errorf("store: the person's account: %w", err)
	}
	if !r.st.apply {
		return nil
	}
	// A membership in a workspace outside the touched set, made since the
	// read, is the next pass's.
	if err := r.readMembers(ctx); err != nil {
		return err
	}
	return r.readFacts(ctx)
}

// run is the account's steps, in the design's order: its status, its
// personal workspace, its memberships, its sessions, its credentials, and
// a closing's record.
func (r *applyRun) run(ctx context.Context) error {
	closed := r.doc.Status == "closed"
	r.closed = closed
	if closed {
		// Read under the account's row, which ConfirmClosing takes first.
		// A record forgotten, or of another local account, is not this
		// closing's (closing starts it again).
		err := r.tx.QueryRow(ctx, `SELECT confirmed_at IS NOT NULL AND forgotten_at IS NULL AND user_id IS NOT DISTINCT FROM $2
			FROM contract_closings WHERE sub = $1`, r.sub, r.user).Scan(&r.closingConfirmed)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
	} else if r.st.apply {
		// A closing the platform's document no longer says, never
		// confirmed, is dropped: a later closing starts its own record.
		if _, err := r.tx.Exec(ctx, `DELETE FROM contract_closings WHERE sub = $1 AND confirmed_at IS NULL`, r.sub); err != nil {
			return err
		}
	}
	switch {
	case closed || r.doc.Status == "disabled":
		switch {
		case r.userStatus == "active":
			if err := r.suspend(ctx); err != nil {
				return err
			}
		case r.disabledBy == "operator":
			r.out.OperatorDisable = true
		}
	case r.userStatus == "disabled" && r.disabledBy == "contract":
		if err := r.enable(ctx); err != nil {
			return err
		}
	case r.userStatus == "disabled":
		// An operator's disable stands over an active document.
		r.out.OperatorDisable = true
		r.out.add(ApplyAction{Kind: ApplyOperatorDisable, User: r.user})
	}
	if !closed && r.doc.Status == "active" && risen(r.acct.disabledAt, r.acct.appliedDisabledAt) {
		// A disable and an enable between two passes: what began before
		// the disable ends, and the account stays active.
		if err := r.endBefore(ctx, *r.acct.disabledAt); err != nil {
			return err
		}
	}

	var docPersonal uuid.UUID
	for _, w := range r.doc.Workspaces {
		if w.Kind == "personal" {
			docPersonal = w.ID
			break
		}
	}
	if !closed && docPersonal != r.personal {
		r.hold(HeldPersonalMismatch, docPersonal)
	}

	listed := map[uuid.UUID]bool{}
	if !closed {
		teams := slices.Clone(r.doc.Workspaces)
		slices.SortFunc(teams, func(a, b applyDocWorkspace) int { return compareIDs(a.ID, b.ID) })
		for _, w := range teams {
			listed[w.ID] = true
			if w.Kind != "team" {
				continue
			}
			if err := r.listedMembership(ctx, w); err != nil {
				return err
			}
		}
	}
	// The losses: a person's membership in a recorded workspace the
	// document does not list (every team, for a closed account), never
	// the person's own personal workspace, a service's, or one with a
	// deadline.
	var lost []uuid.UUID
	for id, m := range r.members {
		f := r.facts[id]
		switch {
		case id == r.personal || m.role == RoleService || m.deadline || listed[id]:
		case closed && f.local && f.kind == "team", f.recorded:
			lost = append(lost, id)
		}
	}
	slices.SortFunc(lost, compareIDs)
	for _, id := range lost {
		if err := r.loss(ctx, id); err != nil {
			return err
		}
	}

	if !closed && risen(r.acct.sessionsAt, r.acct.appliedSessionsAt) {
		if err := r.endSessions(ctx, *r.acct.sessionsAt); err != nil {
			return err
		}
	}
	if risen(r.acct.credentialsAt, r.acct.appliedCredentialsAt) {
		if err := r.stopCredentials(ctx, *r.acct.credentialsAt); err != nil {
			return err
		}
	}
	if closed {
		return r.closing(ctx)
	}
	return nil
}

// risen reports whether a revocation time is set and later than the one
// applied (or none was).
func risen(at, applied *time.Time) bool {
	return at != nil && (applied == nil || at.After(*applied))
}

// hold records a part left for later, and its action.
func (r *applyRun) hold(reason string, workspace uuid.UUID) {
	r.held[reason] = true
	r.out.add(ApplyAction{Kind: ApplyHeld, User: r.user, Workspace: workspace, Held: reason})
}

// changed marks a recorded workspace's snapshot due at the commit.
func (r *applyRun) changed(id uuid.UUID) {
	if r.facts[id].recorded {
		r.due[id] = true
	}
}

// inWorkspace scopes tx to a workspace's rows.
func (r *applyRun) inWorkspace(ctx context.Context, id uuid.UUID) error {
	return scope(ctx, r.tx, id, uuid.Nil)
}

// listedMembership applies one team the document lists: added with the
// document's role, its role changed (a demotion ends the person's sessions
// there and expires their pending invitations), or set active again with
// nothing restored. A membership with a deadline is left as it is.
func (r *applyRun) listedMembership(ctx context.Context, w applyDocWorkspace) error {
	f := r.facts[w.ID]
	m, member := r.members[w.ID]
	if !f.local {
		if r.st.apply {
			// EnsureTeams runs first; a team still missing waits.
			r.hold(HeldNoTenant, w.ID)
			return nil
		}
		r.out.add(ApplyAction{Kind: ApplyMemberAdded, User: r.user, Workspace: w.ID, Platform: w.Role})
		return nil
	}
	if member && (m.deadline || m.role == RoleService) {
		return nil
	}
	if !member {
		r.out.add(ApplyAction{Kind: ApplyMemberAdded, User: r.user, Workspace: w.ID, Platform: w.Role})
		r.changed(w.ID)
		if !r.st.apply {
			return nil
		}
		if err := r.inWorkspace(ctx, w.ID); err != nil {
			return err
		}
		_, err := r.tx.Exec(ctx, `INSERT INTO workspace_memberships (tenant_id, user_id, role) VALUES ($1, $2, $3)
			ON CONFLICT (tenant_id, user_id) DO NOTHING`, w.ID, r.user, w.Role)
		return err
	}
	if m.role != w.Role {
		r.out.add(ApplyAction{Kind: ApplyRoleChanged, User: r.user, Workspace: w.ID, Local: m.role, Platform: w.Role})
		r.changed(w.ID)
		if r.st.apply {
			if err := r.inWorkspace(ctx, w.ID); err != nil {
				return err
			}
			if _, err := r.tx.Exec(ctx, `UPDATE workspace_memberships SET role = $3 WHERE tenant_id = $1 AND user_id = $2`,
				w.ID, r.user, w.Role); err != nil {
				return err
			}
			if roleRank(w.Role) < roleRank(m.role) {
				if _, err := r.tx.Exec(ctx, `UPDATE sessions SET revoked_at = now() WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL`,
					w.ID, r.user); err != nil {
					return err
				}
				if _, err := r.tx.Exec(ctx, `UPDATE invites SET expires_at = now() WHERE tenant_id = $1 AND created_by = $2
					AND completed_at IS NULL AND revoked_at IS NULL AND expires_at > now()`, w.ID, r.user); err != nil {
					return err
				}
			}
		}
	}
	if m.status != "active" {
		r.out.add(ApplyAction{Kind: ApplyMemberEnabled, User: r.user, Workspace: w.ID})
		r.changed(w.ID)
		if r.st.apply {
			if err := r.inWorkspace(ctx, w.ID); err != nil {
				return err
			}
			if _, err := r.tx.Exec(ctx, `UPDATE workspace_memberships SET status = 'active' WHERE tenant_id = $1 AND user_id = $2`,
				w.ID, r.user); err != nil {
				return err
			}
		}
	}
	return nil
}

// roleRank orders a person's roles: owner above admin above member.
func roleRank(role string) int {
	switch role {
	case "owner":
		return 3
	case "admin":
		return 2
	case "member":
		return 1
	}
	return 0
}

// loss applies the loss of one membership (applyMembershipLossTx). One
// that would strand a number waits for the confirmed generation, and, for
// a closed account, for its closing's confirmation too: stranding deletes
// the last key holder's grants, which nothing undoes, so it needs the same
// fresh signed answer as the personal numbers' deletion.
func (r *applyRun) loss(ctx context.Context, id uuid.UUID) error {
	if err := r.inWorkspace(ctx, id); err != nil {
		return err
	}
	generation := r.st.generation != nil && r.st.confirmed
	l, err := applyMembershipLossTx(ctx, r.tx, id, r.user, r.email, generation && (!r.closed || r.closingConfirmed), r.st.apply)
	if err != nil {
		return err
	}
	if l.held {
		reason := HeldStrandsUnconfirmed
		if generation && r.closed {
			reason = HeldClosingUnconfirmed
		}
		r.hold(reason, id)
		return nil
	}
	r.out.add(ApplyAction{Kind: ApplyMemberLost, User: r.user, Workspace: id, Count: int64(l.stranded)})
	r.out.Counts.Strands += int64(l.stranded)
	r.out.Counts.Keychain += l.keychain
	r.out.Ended = append(r.out.Ended, l.ended...)
	r.changed(id)
	r.losses++
	if applyFaultAfter > 0 && r.losses == applyFaultAfter {
		return errApplyFault
	}
	return nil
}

// applyFaultAfter makes an apply fail after its n-th lost membership, for
// the test of a pass that crashes mid-way (SetApplyFaultForTest); 0 never.
var applyFaultAfter int

var errApplyFault = errors.New("store: the apply's test fault")

// mark writes the applied markers and makes every changed recorded
// workspace's snapshot due now.
func (r *applyRun) mark(ctx context.Context) error {
	held := r.out.Held
	if _, err := r.tx.Exec(ctx, `UPDATE contract_accounts SET applied_generation = generation, applied_version = version,
			applied_disabled_at = disabled_at, applied_sessions_revoked_at = sessions_revoked_at,
			applied_credentials_revoked_at = credentials_revoked_at,
			apply_held = nullif($2, ''),
			apply_held_since = CASE WHEN $2 = '' THEN NULL WHEN apply_held = $2 THEN apply_held_since ELSE clock_timestamp() END,
			apply_last_at = clock_timestamp()
		WHERE sub = $1`, r.sub, held); err != nil {
		return err
	}
	return snapshotsDueNowTx(ctx, r.tx, r.due)
}

// snapshotsDueNowTx makes the snapshots of ids due now; their rows are
// locked already (the apply's lock), or new in tx.
func snapshotsDueNowTx(ctx context.Context, tx pgx.Tx, due map[uuid.UUID]bool) error {
	if len(due) == 0 {
		return nil
	}
	ids := make([]uuid.UUID, 0, len(due))
	for id := range due {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, compareIDs)
	_, err := tx.Exec(ctx, `UPDATE contract_workspaces SET snapshot_due_at = clock_timestamp() WHERE workspace_id = ANY ($1)`, ids)
	return err
}

// EnsureTeams creates, for sub's stored document, every team it lists that
// Wappie has no workspace of: each in a transaction of its own
// (ensureTeamTx), at enforce. It returns the teams created (with an
// error, those created before it, each committed).
func (c *Contract) EnsureTeams(ctx context.Context, sub uuid.UUID) ([]uuid.UUID, error) {
	return c.ensureTeams(ctx, sub, true)
}

func (c *Contract) ensureTeams(ctx context.Context, sub uuid.UUID, gate bool) ([]uuid.UUID, error) {
	rows, err := c.pool.Query(ctx, `SELECT DISTINCT (w->>'id')::uuid FROM contract_accounts a
		JOIN contract_state s ON s.generation = a.generation
		CROSS JOIN LATERAL jsonb_array_elements(a.doc->'workspaces') w
		WHERE a.sub = $1 AND a.doc IS NOT NULL AND w->>'kind' = 'team'
		  AND NOT EXISTS (SELECT 1 FROM tenants t WHERE t.id = (w->>'id')::uuid)
		ORDER BY 1`, sub)
	if err != nil {
		return nil, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return nil, err
	}
	var made []uuid.UUID
	for _, id := range ids {
		created := false
		err := c.applyTx(ctx, gate, func(tx pgx.Tx, st applyState) error {
			var err error
			created, err = ensureTeamTx(ctx, tx, st, id)
			return err
		})
		if err != nil {
			return made, err
		}
		if created {
			made = append(made, id)
		}
	}
	return made, nil
}

// teamFallbackName names a team whose documents give it no name.
const teamFallbackName = "Equipe"

// teamListedSQL holds for a recorded workspace (alias w) that a stored
// document of the stored generation lists as a team. Records are never
// deleted, and a restart keeps them: a team only an older or a replaced
// document named is not created.
const teamListedSQL = `EXISTS (SELECT 1 FROM contract_accounts la
		JOIN contract_state ls ON ls.generation = la.generation
		CROSS JOIN LATERAL jsonb_array_elements(la.doc->'workspaces') lw
		WHERE la.doc IS NOT NULL AND lw->>'kind' = 'team' AND (lw->>'id')::uuid = w.workspace_id)`

// ensureTeamTx creates the team id when it is recorded, a document of the
// stored generation lists it (teamListedSQL), and Wappie has no workspace
// of it: the platform's id and its name at the highest wversion,
// kind team, suspended when its record is closed (and the suspension the
// contract's, applied_status), with no workspace_capacity row (the
// platform's teams have no cap) and no avatar. The record's row, locked
// first, serializes two subs creating the same team; the insert does
// nothing when it exists. A plan says whether it would. tx holds
// contract_state as st read it.
func ensureTeamTx(ctx context.Context, tx pgx.Tx, st applyState, id uuid.UUID) (bool, error) {
	lock := ""
	if st.apply {
		lock = " FOR UPDATE"
	}
	var kind, status string
	err := tx.QueryRow(ctx, `SELECT kind, coalesce(status, '') FROM contract_workspaces WHERE workspace_id = $1`+lock, id).Scan(&kind, &status)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && kind != "team" {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var exists, listed bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tenants WHERE id = $1),
			EXISTS (SELECT 1 FROM contract_workspaces w WHERE w.workspace_id = $1 AND `+teamListedSQL+`)`, id).
		Scan(&exists, &listed); err != nil || exists || !listed {
		return false, err
	}
	if !st.apply {
		return true, nil
	}
	names, err := docNamesTx(ctx, tx, []uuid.UUID{id})
	if err != nil {
		return false, err
	}
	name := teamFallbackName
	if n := names[id]; n != nil && *n != "" {
		name = workspaceName(*n)
	}
	tenantStatus := "active"
	if status == "closed" {
		tenantStatus = "suspended"
	}
	tag, err := tx.Exec(ctx, `INSERT INTO tenants (id, name, kind, status) VALUES ($1, $2, 'team', $3) ON CONFLICT (id) DO NOTHING`,
		id, name, tenantStatus)
	if err != nil || tag.RowsAffected() == 0 {
		return false, err
	}
	_, err = tx.Exec(ctx, `UPDATE contract_workspaces SET applied_status = CASE WHEN $2 THEN 'closed' ELSE applied_status END,
		snapshot_due_at = clock_timestamp() WHERE workspace_id = $1`, id, status == "closed")
	return true, err
}

// workspaceName is a document's name as tenants.name holds it: at most
// 200 characters.
func workspaceName(name string) string {
	if utf8.RuneCountInString(name) <= 200 {
		return name
	}
	return string([]rune(name)[:200])
}

// docNamesTx is each workspace's name as its stored documents give it at
// their highest wversion (README 6.2: a name moves only with a higher
// wversion): nil where the document at that wversion leaves it null, and
// no entry where no stored document names the workspace.
func docNamesTx(ctx context.Context, tx pgx.Tx, ids []uuid.UUID) (map[uuid.UUID]*string, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT ON (x.id) x.id, x.name FROM (
			SELECT (w->>'id')::uuid AS id, w->>'name' AS name, coalesce((w->>'wversion')::bigint, 0) AS wversion
			  FROM contract_accounts a CROSS JOIN LATERAL jsonb_array_elements(a.doc->'workspaces') w
			 WHERE a.doc IS NOT NULL AND (w->>'id')::uuid = ANY ($1)) x
		ORDER BY x.id, x.wversion DESC, x.name IS NULL, x.name`, ids)
	if err != nil {
		return nil, err
	}
	out := map[uuid.UUID]*string{}
	err = forEachRow(rows, func(row pgx.Rows) error {
		var id uuid.UUID
		var name *string
		if err := row.Scan(&id, &name); err != nil {
			return err
		}
		out[id] = name
		return nil
	})
	return out, err
}

// ApplyWorkspace applies one recorded workspace at its wversion, in one
// transaction (contract_state FOR SHARE, the record, the workspace's row):
// a team Wappie lacks is created; its name follows the stored documents at
// the highest wversion (a personal workspace whose name they leave null is
// named in its owner's language, PersonalWorkspaceName); a closed team is
// suspended, and reopened only when the contract suspended it.
func (c *Contract) ApplyWorkspace(ctx context.Context, id uuid.UUID) (ApplyResult, error) {
	return c.applyWorkspace(ctx, id, true)
}

func (c *Contract) applyWorkspace(ctx context.Context, id uuid.UUID, gate bool) (ApplyResult, error) {
	var out ApplyResult
	err := c.applyTx(ctx, gate, func(tx pgx.Tx, st applyState) error {
		var err error
		out, err = applyWorkspaceTx(ctx, tx, st, id)
		return err
	})
	if err != nil {
		// Rolled back: nothing of it is returned.
		return ApplyResult{Workspace: id}, err
	}
	return out, nil
}

// applyWorkspaceTx is one workspace's apply (st.apply) or plan.
func applyWorkspaceTx(ctx context.Context, tx pgx.Tx, st applyState, id uuid.UUID) (ApplyResult, error) {
	out := ApplyResult{Workspace: id}
	lock := ""
	if st.apply {
		lock = " FOR UPDATE"
	}
	var kind, status, appliedStatus string
	var wversion int64
	var appliedWVersion *int64
	err := tx.QueryRow(ctx, `SELECT kind, coalesce(status, ''), wversion, applied_wversion, coalesce(applied_status, '')
		FROM contract_workspaces WHERE workspace_id = $1`+lock, id).Scan(&kind, &status, &wversion, &appliedWVersion, &appliedStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	created, err := ensureTeamTx(ctx, tx, st, id)
	if err != nil {
		return out, err
	}
	if created {
		out.add(ApplyAction{Kind: ApplyTeamCreated, Workspace: id})
		if !st.apply {
			return out, nil
		}
		if status == "closed" {
			appliedStatus = "closed"
		}
	}
	var name, tenantStatus string
	var owner *uuid.UUID
	err = tx.QueryRow(ctx, `SELECT name, status, personal_owner_id FROM tenants WHERE id = $1`+lock, id).Scan(&name, &tenantStatus, &owner)
	if errors.Is(err, pgx.ErrNoRows) {
		// A personal workspace is the sign-up's to create.
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if !created && appliedWVersion != nil && wversion <= *appliedWVersion {
		return out, nil
	}

	names, err := docNamesTx(ctx, tx, []uuid.UUID{id})
	if err != nil {
		return out, err
	}
	docName, named := names[id]
	want := ""
	switch {
	case kind == "team" && named && docName != nil && *docName != "":
		want = workspaceName(*docName)
	case kind == "personal" && named && docName != nil && *docName != "":
		want = workspaceName(*docName)
	case kind == "personal" && owner != nil:
		var locale string
		if err := scope(ctx, tx, id, uuid.Nil); err != nil {
			return out, err
		}
		err := tx.QueryRow(ctx, `SELECT coalesce(locale, '') FROM users WHERE id = $1`, *owner).Scan(&locale)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return out, err
		}
		want = PersonalWorkspaceName(locale)
	}
	if want != "" && want != name {
		k := ApplyTeamRenamed
		if kind == "personal" {
			k = ApplyPersonalNamed
		}
		out.add(ApplyAction{Kind: k, Workspace: id})
		if st.apply {
			if _, err := tx.Exec(ctx, `UPDATE tenants SET name = $2 WHERE id = $1`, id, want); err != nil {
				return out, err
			}
		}
	}

	// A team's closure: closed suspends it (the contract's suspension);
	// open lifts only a suspension the contract made.
	if kind == "team" {
		switch {
		case status == "closed" && tenantStatus == "active":
			out.add(ApplyAction{Kind: ApplyTeamClosed, Workspace: id})
			appliedStatus = "closed"
			if st.apply {
				if _, err := tx.Exec(ctx, `UPDATE tenants SET status = 'suspended' WHERE id = $1`, id); err != nil {
					return out, err
				}
			}
		case status == "open" && tenantStatus == "suspended" && appliedStatus == "closed":
			out.add(ApplyAction{Kind: ApplyTeamReopened, Workspace: id})
			appliedStatus = "open"
			if st.apply {
				if _, err := tx.Exec(ctx, `UPDATE tenants SET status = 'active' WHERE id = $1`, id); err != nil {
					return out, err
				}
			}
		case status == "open" && appliedStatus == "closed":
			// Someone lifted the suspension already: no longer the
			// contract's.
			appliedStatus = "open"
		}
	}
	if !st.apply {
		return out, nil
	}
	_, err = tx.Exec(ctx, `UPDATE contract_workspaces SET applied_wversion = wversion, applied_status = nullif($2, ''),
		snapshot_due_at = CASE WHEN $3 THEN clock_timestamp() ELSE snapshot_due_at END
		WHERE workspace_id = $1`, id, appliedStatus, len(out.Actions) > 0)
	return out, err
}
