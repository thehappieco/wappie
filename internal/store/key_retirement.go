package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The retirement of Wappie's own API keys on a platform installation
// (whatserverd tokens retire-keys; step 7's plan, 7.1 and 7.2): once the
// platform's tokens are on, every live key that is not an MCP
// connection's, a setup in flight or an old local MCP token is revoked
// (retiredKey). A standing service account such a key acted as, or a
// revoked old local MCP token did, is removed where every number it holds
// a key of keeps a human holder.

// RevokeReasonPlatformTokens is api_keys.revoke_reason for a key the
// retirement revoked.
const RevokeReasonPlatformTokens = "platform_tokens"

// The classes of 0053's api_key_class (the plan's 7.1), by shape first and
// then by creator. Which are retired, retiredKey says.
const (
	KeyClassMCP       = "mcp"
	KeyClassMCPSetup  = "mcp_setup"
	KeyClassLegacyMCP = "legacy_mcp"
	KeyClassCLI       = "cli"
	KeyClassREST      = "rest"
)

// Why a standing service account is kept (KeptService.Reason).
const (
	// KeptNoRetiredKey: no retired key ever acted as it, nor a revoked old
	// local MCP token, and no earlier retirement kept it. It is not the
	// retirement's.
	KeptNoRetiredKey = "no_retired_key"
	// KeptSparedKey: a key the retirement spares acts as it.
	KeptSparedKey = "spared_key"
	// KeptSoleReader: a number it holds a key of has no other human
	// holder at that epoch (everyGrantKeepsAHumanHolderTx). A later run
	// removes it once one exists.
	KeptSoleReader = "sole_reader"
)

// ErrRetireNeedsTokens refuses the retirement unless the contract is on
// and the token mode is on: before then the platform's tokens replace
// nothing.
var ErrRetireNeedsTokens = errors.New("store: retire-keys needs the contract on and tokens on")

// ErrRetireConfirm is an apply whose -confirm is not the count of keys it
// would revoke now: nothing is written.
type ErrRetireConfirm struct{ Confirm, Revoke int }

func (e *ErrRetireConfirm) Error() string {
	return fmt.Sprintf("store: -confirm %d, but %d keys would be revoked now; run the dry run again", e.Confirm, e.Revoke)
}

// RetireKey is one live key of the retirement.
type RetireKey struct {
	Workspace uuid.UUID
	ID        uuid.UUID
	Prefix    string
	Name      string
	Scope     KeyScope
	// Class is api_key_class's; Origin is how the key was issued ("" for
	// none); Retire is retiredKey's answer.
	Class, Origin string
	Retire        bool
	// Creator is the creator's platform sub, else the address, else ""
	// (the command line's).
	Creator string
	// ActsAs is the service account's name, "" for none.
	ActsAs     string
	ActsAsID   *uuid.UUID
	LastUsedAt *time.Time
}

// RetireService is one standing service account: a service membership
// with no deadline, that no connection names and that is no token
// identity. Remove, or kept for Reason.
type RetireService struct {
	Workspace uuid.UUID
	UserID    uuid.UUID
	Name      string
	Remove    bool
	Reason    string
}

// RetireWorkspace is one workspace's part.
type RetireWorkspace struct {
	ID       uuid.UUID
	Name     string
	Keys     []RetireKey
	Services []RetireService
}

// KeyRetirement is what a dry run would do, or what an apply did.
type KeyRetirement struct {
	// AppliedAt is the apply's time (the revoked keys' revoked_at and the
	// key_retirements row's), zero for a dry run.
	AppliedAt  time.Time
	Workspaces []RetireWorkspace
	// Revoke counts the keys revoked; Removed the services removed; Kept
	// the services a retired key acted as that were kept (a later run may
	// remove them).
	Revoke, Removed, Kept int
}

// retireReport is key_retirements.report: each key revoked, which goes
// 13 months after the apply (RetainAPIKeys), and each service a retired
// key acted as that was kept, which stays, so a later run still finds it
// once those keys are deleted.
type retireReport struct {
	Keys []retireReportKey  `json:"keys"`
	Kept []retireReportKept `json:"kept"`
}

type retireReportKey struct {
	Workspace uuid.UUID `json:"workspace"`
	Prefix    string    `json:"prefix"`
	Name      string    `json:"name"`
	Class     string    `json:"class"`
	Creator   string    `json:"creator"`
	ActsAs    string    `json:"acts_as,omitempty"`
}

type retireReportKept struct {
	Workspace uuid.UUID `json:"workspace"`
	UserID    uuid.UUID `json:"user_id"`
	Reason    string    `json:"reason"`
}

// RetirePlan is the dry run: what Retire would do now, in one read-only
// transaction. It writes nothing.
func (a *APIKeys) RetirePlan(ctx context.Context) (KeyRetirement, error) {
	var out KeyRetirement
	err := pgx.BeginTxFunc(ctx, a.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var err error
		out, err = retireTx(ctx, tx, false, 0, "")
		return err
	})
	return out, err
}

// Retire is the apply, in one transaction over every workspace. It holds
// the modes it checks first: contract_state, then contract_token_state,
// FOR SHARE (DB25 steps 1 and 2), so neither mode turns off under it. Then
// each workspace's row (lockWorkspaceAccess, DB25 step 3), in workspace id
// order, held to the commit. That blocks every insert with a foreign key
// to the workspace (a message's capture, say) until then, for the run's
// fraction of a second.
//
// In each workspace it revokes every live key retiredKey names
// (revoked_at the apply's time, revoke_reason platform_tokens). Then it
// removes each standing service account that no spared live key acts as,
// that a key revoked by this or an earlier retirement acted as (or an
// earlier report kept, or a revoked old local MCP token acted as), and
// where every number it holds a key of keeps a human holder
// (everyGrantKeepsAHumanHolderTx), with a workspace_member_history row.
// Then it writes the key_retirements row, with the apply's time. One
// transaction checks confirm against the count once, and writes one row
// per apply.
//
// confirm must equal the count of keys to revoke, or nothing is written
// (ErrRetireConfirm). by is who ran it. Run again, it revokes nothing, and
// removes a service kept before that now has a human holder.
//
// The revoked keys' sockets live in the server processes: each closes
// within ConnectionKey's one-second check there.
func (a *APIKeys) Retire(ctx context.Context, confirm int, by string) (KeyRetirement, error) {
	var out KeyRetirement
	err := retryDeadlock(ctx, func() error {
		return pgx.BeginTxFunc(ctx, a.pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
			var err error
			out, err = retireTx(ctx, tx, true, confirm, by)
			return err
		})
	})
	return out, err
}

func retireTx(ctx context.Context, tx pgx.Tx, apply bool, confirm int, by string) (KeyRetirement, error) {
	var out KeyRetirement
	// The apply holds both modes until it commits, in DB25's order; the
	// dry run, read only, takes no lock.
	lock := ""
	if apply {
		lock = " FOR SHARE"
	}
	var contract, tokens string
	if err := tx.QueryRow(ctx, `SELECT mode FROM contract_state`+lock).Scan(&contract); err != nil {
		return out, err
	}
	if err := tx.QueryRow(ctx, `SELECT mode FROM contract_token_state`+lock).Scan(&tokens); err != nil {
		return out, err
	}
	if contract == ContractOff || tokens != TokensOn {
		return out, ErrRetireNeedsTokens
	}
	if apply {
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&out.AppliedAt); err != nil {
			return out, err
		}
	}
	rows, err := tx.Query(ctx, `SELECT id, name FROM tenants ORDER BY id`)
	if err != nil {
		return out, err
	}
	workspaces, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (RetireWorkspace, error) {
		var w RetireWorkspace
		err := r.Scan(&w.ID, &w.Name)
		return w, err
	})
	if err != nil {
		return out, err
	}
	var report retireReport
	for _, w := range workspaces {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, w.ID.String()); err != nil {
			return out, err
		}
		if apply {
			if err := lockWorkspaceAccess(ctx, tx, w.ID); err != nil {
				return out, err
			}
		}
		if err := retireWorkspaceTx(ctx, tx, &w, apply, out.AppliedAt); err != nil {
			return out, err
		}
		for _, k := range w.Keys {
			if k.Retire {
				out.Revoke++
				report.Keys = append(report.Keys, retireReportKey{Workspace: w.ID, Prefix: k.Prefix, Name: k.Name, Class: k.Class,
					Creator: k.Creator, ActsAs: k.ActsAs})
			}
		}
		for _, s := range w.Services {
			switch {
			case s.Remove:
				out.Removed++
			case s.Reason != KeptNoRetiredKey:
				out.Kept++
				report.Kept = append(report.Kept, retireReportKept{Workspace: w.ID, UserID: s.UserID, Reason: s.Reason})
			}
		}
		out.Workspaces = append(out.Workspaces, w)
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', '', true)`); err != nil {
		return out, err
	}
	if !apply {
		return out, nil
	}
	if out.Revoke != confirm {
		return out, &ErrRetireConfirm{Confirm: confirm, Revoke: out.Revoke}
	}
	if report.Keys == nil {
		report.Keys = []retireReportKey{}
	}
	if report.Kept == nil {
		report.Kept = []retireReportKept{}
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return out, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO key_retirements (applied_at, revoked, services_removed, services_kept, report, by)
		VALUES ($1, $2, $3, $4, $5, $6)`, out.AppliedAt, out.Revoke, out.Removed, out.Kept, raw, by)
	return out, err
}

// retiredKey is whether the retirement revokes a live key of class with
// origin (the plan's 7.1). A rest or cli key is. A key in an MCP setup's
// or an old local token's shape is too when it was issued as rest or cli:
// no consent made it. That is a new key in the old token's shape (only
// 0053's backfill writes legacy_mcp), which MCPPanel and M2L do not list,
// or one acting as a standing service. A connection's key (mcp) never is,
// whatever its origin, and a key with no origin keeps its class's rule.
func retiredKey(class, origin string) bool {
	switch class {
	case KeyClassREST, KeyClassCLI:
		return true
	case KeyClassLegacyMCP, KeyClassMCPSetup:
		return origin == OriginREST || origin == OriginCLI
	}
	return false
}

// retireWorkspaceTx is one workspace's part, under its app.tenant_id (and,
// for an apply, its row lock): its live keys, classified, revoked when
// applying; then its standing service accounts, judged, removed when
// applying.
func retireWorkspaceTx(ctx context.Context, tx pgx.Tx, w *RetireWorkspace, apply bool, at time.Time) error {
	lock := ""
	if apply {
		lock = " FOR UPDATE OF k"
	}
	// The creator's sub (platform_identities has no policy), else the
	// address, a removed member's from the history.
	rows, err := tx.Query(ctx, `SELECT k.id, k.prefix, k.name, k.scope, api_key_class(k), coalesce(k.origin, ''), k.last_used_at, k.acts_as,
			coalesce(pi.sub::text, u.email, creator.email, ''), coalesce(s.email, service.email, '')
		FROM api_keys k
		LEFT JOIN users u ON u.id = k.created_by
		LEFT JOIN platform_identities pi ON pi.user_id = k.created_by
		LEFT JOIN workspace_member_history creator ON creator.tenant_id = k.tenant_id AND creator.user_id = k.created_by
		LEFT JOIN users s ON s.id = k.acts_as
		LEFT JOIN workspace_member_history service ON service.tenant_id = k.tenant_id AND service.user_id = k.acts_as
		WHERE k.tenant_id = $1 AND k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at > now())
		ORDER BY k.created_at, k.id`+lock, w.ID)
	if err != nil {
		return err
	}
	w.Keys, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (RetireKey, error) {
		k := RetireKey{Workspace: w.ID}
		var actsAs string
		if err := r.Scan(&k.ID, &k.Prefix, &k.Name, &k.Scope, &k.Class, &k.Origin, &k.LastUsedAt, &k.ActsAsID, &k.Creator, &actsAs); err != nil {
			return k, err
		}
		if actsAs != "" {
			k.ActsAs = ServiceName(User{Role: RoleService, Email: actsAs})
		}
		k.Retire = retiredKey(k.Class, k.Origin)
		return k, nil
	})
	if err != nil {
		return err
	}
	var retired []uuid.UUID
	for _, k := range w.Keys {
		if k.Retire {
			retired = append(retired, k.ID)
		}
	}
	if apply && len(retired) > 0 {
		tag, err := tx.Exec(ctx, `UPDATE api_keys SET revoked_at = $2, revoke_reason = 'platform_tokens'
			WHERE id = ANY ($1) AND revoked_at IS NULL`, retired, at)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != int64(len(retired)) {
			return fmt.Errorf("store: retire-keys revoked %d of %d keys it locked", tag.RowsAffected(), len(retired))
		}
	}

	// A candidate: a key the retirement revoked acted as it, or an earlier
	// report kept it, or a revoked old local MCP token acted as it (12b's
	// M2L revokes one and keeps its account while a number has no other
	// human holder; a later run removes the account once one does).
	rows, err = tx.Query(ctx, `SELECT m.user_id, u.email,
			EXISTS (SELECT 1 FROM api_keys k WHERE k.tenant_id = m.tenant_id AND k.acts_as = m.user_id AND k.revoke_reason = 'platform_tokens')
			OR EXISTS (SELECT 1 FROM key_retirements r, jsonb_array_elements(r.report->'kept') e
				WHERE e->>'workspace' = m.tenant_id::text AND e->>'user_id' = m.user_id::text)
			OR EXISTS (SELECT 1 FROM api_keys k WHERE k.tenant_id = m.tenant_id AND k.acts_as = m.user_id
				AND k.origin = 'legacy_mcp' AND k.revoked_at IS NOT NULL)
		FROM workspace_memberships m JOIN users u ON u.id = m.user_id
		WHERE m.tenant_id = $1 AND m.role = 'service' AND m.expires_at IS NULL AND NOT u.token_identity
		  AND NOT EXISTS (SELECT 1 FROM mcp_connections c WHERE c.service_user_id = m.user_id)
		ORDER BY m.user_id`, w.ID)
	if err != nil {
		return err
	}
	type standing struct {
		RetireService
		email string
		acted bool
	}
	services, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (standing, error) {
		s := standing{RetireService: RetireService{Workspace: w.ID}}
		err := r.Scan(&s.UserID, &s.email, &s.acted)
		s.Name = ServiceName(User{Role: RoleService, Email: s.email})
		return s, err
	})
	if err != nil {
		return err
	}
	for _, s := range services {
		spared := false
		for _, k := range w.Keys {
			if k.ActsAsID != nil && *k.ActsAsID == s.UserID {
				// A dry run's keys to retire act as it from this run.
				s.acted = s.acted || k.Retire
				spared = spared || !k.Retire
			}
		}
		switch {
		case !s.acted:
			s.Reason = KeptNoRetiredKey
		case spared:
			s.Reason = KeptSparedKey
		default:
			backed, err := everyGrantKeepsAHumanHolderTx(ctx, tx, w.ID, s.UserID)
			if err != nil {
				return err
			}
			s.Remove = backed
			if !backed {
				s.Reason = KeptSoleReader
			}
		}
		if s.Remove && apply {
			if err := removeServiceAccountTx(ctx, tx, w.ID, s.UserID); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO workspace_member_history (tenant_id, user_id, email) VALUES ($1, $2, $3)
				ON CONFLICT (tenant_id, user_id) DO UPDATE SET email = excluded.email, removed_at = now()`, w.ID, s.UserID, s.email); err != nil {
				return err
			}
		}
		w.Services = append(w.Services, s.RetireService)
	}
	return nil
}

// everyGrantKeepsAHumanHolderTx reports whether every number where account
// holds a grant at an epoch not retired has another holder of that epoch
// who is human (the plan's 7.2, step 3):
//   - the user and the membership not of role service;
//   - the membership active with no deadline;
//   - the user active, with Read on the number;
//   - no connection's account.
//
// It is stricter than sole_key_holders (0051), where two standing services
// shield each other. A token identity is never a member, so never a holder
// here. A connection's account is a service account, so the role already
// leaves it out; it is named anyway, as the plan and sole_key_holders name
// it. An account with no such grant has none to keep.
//
// The retirement removes a standing service account only where this
// holds, and so does M2L's legacy token revoke (12b). The caller holds
// pg.InTenantTx(tenant), or app.tenant_id, and the workspace's row lock
// (lockWorkspaceAccess). A deleted number not purged yet counts, as in
// sole_key_holders: nothing here joins devices.
func everyGrantKeepsAHumanHolderTx(ctx context.Context, tx pgx.Tx, tenant, account uuid.UUID) (bool, error) {
	var backed bool
	err := tx.QueryRow(ctx, `SELECT NOT EXISTS (
		SELECT 1 FROM device_key_grants g
		  JOIN device_archive_keys k ON k.device_id = g.device_id AND k.epoch = g.epoch AND k.retired_at IS NULL
		 WHERE g.tenant_id = $1 AND g.user_id = $2
		   AND NOT EXISTS (
		     SELECT 1 FROM device_key_grants h
		       JOIN workspace_memberships hm ON hm.tenant_id = h.tenant_id AND hm.user_id = h.user_id
		            AND hm.status = 'active' AND hm.expires_at IS NULL AND hm.role <> 'service'
		       JOIN users hu ON hu.id = hm.user_id AND hu.status = 'active' AND hu.role <> 'service'
		       JOIN device_permissions hp ON hp.tenant_id = h.tenant_id AND hp.device_id = h.device_id
		            AND hp.user_id = h.user_id AND hp.can_read
		      WHERE h.tenant_id = g.tenant_id AND h.device_id = g.device_id AND h.epoch = g.epoch
		        AND h.user_id <> g.user_id
		        AND NOT EXISTS (SELECT 1 FROM mcp_connections c WHERE c.service_user_id = h.user_id)))`, tenant, account).Scan(&backed)
	return backed, err
}
