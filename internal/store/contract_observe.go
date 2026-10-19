package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Observe's comparison (the plan's 4.8; decision 0040, "Rollout"): each
// stored document against Wappie's own tables, read-only, people only
// (memberships that are not a service's and carry no expiry, as
// reader_safety.go's predicate treats them). Nothing here changes a row:
// observe compares and logs, and enforce applies. A difference holds ids,
// roles, statuses and counts, never an email, a name or a label (DB22).

// The kinds of difference, as observe logs them and contract diff lists
// them.
const (
	// DiffPersonalMismatch: the document's personal workspace is not the
	// person's local one (D6).
	DiffPersonalMismatch = "personal_mismatch"
	// DiffLocalOnly: a local membership in a platform workspace the
	// document lacks.
	DiffLocalOnly = "local_only"
	// DiffNoSub: a person in a platform workspace with no platform link.
	DiffNoSub = "no_sub"
	// DiffPlatformOnly: the document names a workspace where the person
	// has no local membership.
	DiffPlatformOnly = "platform_only"
	// DiffRole: the local role is not the document's.
	DiffRole = "role"
	// DiffAccountStatus: the document is disabled or closed and the person
	// active, or the reverse.
	DiffAccountStatus = "account_status"
	// DiffMembershipStatus: the local membership is disabled while the
	// document lists it.
	DiffMembershipStatus = "membership_status"
	// DiffTeamClosed and DiffName: the platform's team is closed, or
	// named otherwise, and the local workspace is not.
	DiffTeamClosed = "team_closed"
	DiffName       = "name"
	// DiffSessionsWouldEnd: live sessions whose family began before
	// sessions_revoked_at.
	DiffSessionsWouldEnd = "sessions_would_end"
	// DiffCredentialsWouldStop: keys, connections and standing service
	// accounts made before credentials_revoked_at.
	DiffCredentialsWouldStop = "credentials_would_stop"
	// DiffUnnamedTenant: a local team no document names (contract diff
	// only).
	DiffUnnamedTenant = "unnamed_tenant"
)

// ContractDifference is one difference, by ids. Only the fields its kind
// uses are set.
type ContractDifference struct {
	Kind      string
	Sub       uuid.UUID
	User      uuid.UUID
	Workspace uuid.UUID
	// LocalWorkspace is personal_mismatch's local personal workspace (Nil:
	// none), and Workspace the document's.
	LocalWorkspace uuid.UUID
	// Local and Platform are the two roles (role) or statuses
	// (account_status).
	Local, Platform string
	// Count is personal_mismatch's numbers in the local personal workspace,
	// or sessions_would_end's sessions.
	Count int64
	// Keys, Connections and Services are credentials_would_stop's.
	Keys, Connections, Services int64
	// TenantMissing: platform_only for a workspace Wappie has none of.
	TenantMissing bool
}

// storedDoc is the part of a stored document the comparison reads.
type storedDoc struct {
	Status     string `json:"status"`
	Workspaces []struct {
		ID     uuid.UUID `json:"id"`
		Kind   string    `json:"kind"`
		Role   string    `json:"role"`
		Status string    `json:"status"`
	} `json:"workspaces"`
}

// DifferencesOf compares sub's stored document with Wappie's tables: the
// differences of observe's log for one document, the people without a sub
// in the platform workspaces it names included. compared is false for a
// sub Wappie does not hold, or with no document stored: there was nothing
// to compare.
func (c *Contract) DifferencesOf(ctx context.Context, sub uuid.UUID) (out []ContractDifference, compared bool, err error) {
	err = readOnly(ctx, c, func(tx pgx.Tx) error {
		var held bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM platform_identities pi JOIN contract_accounts a ON a.sub = pi.sub
			WHERE pi.sub = $1 AND a.doc IS NOT NULL)`, sub).Scan(&held); err != nil || !held {
			return err
		}
		compared = true
		var err error
		out, err = differencesTx(ctx, tx, sub)
		if err != nil {
			return err
		}
		ws, err := docWorkspacesTx(ctx, tx, sub)
		if err != nil {
			return err
		}
		noSub, err := noSubTx(ctx, tx, ws)
		out = append(out, noSub...)
		return err
	})
	return out, compared, err
}

// Differences is contract diff's: every held sub's stored document against
// Wappie's tables, the people without a sub in every platform workspace
// once each, and every local team no document names (unnamed_tenant); with
// a tenant, only the differences that name it.
func (c *Contract) Differences(ctx context.Context, tenant uuid.UUID) ([]ContractDifference, error) {
	var out []ContractDifference
	err := readOnly(ctx, c, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT a.sub FROM contract_accounts a JOIN platform_identities pi ON pi.sub = a.sub
			WHERE a.doc IS NOT NULL ORDER BY a.sub`)
		if err != nil {
			return err
		}
		subs, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			return err
		}
		for _, sub := range subs {
			d, err := differencesTx(ctx, tx, sub)
			if err != nil {
				return err
			}
			out = append(out, d...)
		}
		rows, err = tx.Query(ctx, `SELECT workspace_id FROM contract_workspaces ORDER BY workspace_id`)
		if err != nil {
			return err
		}
		recorded, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			return err
		}
		noSub, err := noSubTx(ctx, tx, recorded)
		if err != nil {
			return err
		}
		out = append(out, noSub...)
		rows, err = tx.Query(ctx, `SELECT t.id FROM tenants t WHERE t.kind = 'team'
			AND NOT EXISTS (SELECT 1 FROM contract_workspaces w WHERE w.workspace_id = t.id) ORDER BY t.created_at, t.id`)
		if err != nil {
			return err
		}
		unnamed, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			return err
		}
		for _, id := range unnamed {
			out = append(out, ContractDifference{Kind: DiffUnnamedTenant, Workspace: id})
		}
		return nil
	})
	if err != nil || tenant == uuid.Nil {
		return out, err
	}
	kept := out[:0]
	for _, d := range out {
		if d.Workspace == tenant || d.LocalWorkspace == tenant {
			kept = append(kept, d)
		}
	}
	return kept, nil
}

// readOnly runs fn in one REPEATABLE READ, read-only transaction, so a
// comparison describes one moment.
func readOnly(ctx context.Context, c *Contract, fn func(pgx.Tx) error) error {
	return pgx.BeginTxFunc(ctx, c.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, fn)
}

// scope sets the transaction's row-level security context: a workspace
// (its rows), or a person (their own memberships).
func scope(ctx context.Context, tx pgx.Tx, tenant, user uuid.UUID) error {
	t, u := "", ""
	if tenant != uuid.Nil {
		t = tenant.String()
	}
	if user != uuid.Nil {
		u = user.String()
	}
	_, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true), set_config('app.user_id', $2, true)`, t, u)
	return err
}

// docWorkspacesTx is the workspaces sub's stored document names.
func docWorkspacesTx(ctx context.Context, tx pgx.Tx, sub uuid.UUID) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `SELECT (w->>'id')::uuid FROM contract_accounts a
		CROSS JOIN LATERAL jsonb_array_elements(a.doc->'workspaces') w WHERE a.sub = $1 AND a.doc IS NOT NULL`, sub)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

type localMembership struct {
	role, status string
}

type workspaceFacts struct {
	recorded       bool
	recordedStatus string
	local          bool
	name, status   string
}

// differencesTx is one held sub's differences but the no_sub ones.
func differencesTx(ctx context.Context, tx pgx.Tx, sub uuid.UUID) ([]ContractDifference, error) {
	var user uuid.UUID
	err := tx.QueryRow(ctx, `SELECT user_id FROM platform_identities WHERE sub = $1`, sub).Scan(&user)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var raw []byte
	var sessionsRevoked, credentialsRevoked *time.Time
	err = tx.QueryRow(ctx, `SELECT doc, sessions_revoked_at, credentials_revoked_at FROM contract_accounts
		WHERE sub = $1 AND doc IS NOT NULL`, sub).Scan(&raw, &sessionsRevoked, &credentialsRevoked)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var doc storedDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("store: a stored document: %w", err)
	}

	// The person's own memberships, by their identity's policy.
	if err := scope(ctx, tx, uuid.Nil, user); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT tenant_id, role, status FROM workspace_memberships
		WHERE user_id = $1 AND role <> 'service' AND expires_at IS NULL`, user)
	if err != nil {
		return nil, err
	}
	memberships := map[uuid.UUID]localMembership{}
	var tenants []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		var m localMembership
		if err := rows.Scan(&id, &m.role, &m.status); err != nil {
			rows.Close()
			return nil, err
		}
		memberships[id] = m
		tenants = append(tenants, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var personal uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT coalesce(max(id::text), '00000000-0000-0000-0000-000000000000')::uuid
		FROM tenants WHERE personal_owner_id = $1`, user).Scan(&personal); err != nil {
		return nil, err
	}

	ids := slices.Clone(tenants)
	for _, w := range doc.Workspaces {
		ids = append(ids, w.ID)
	}
	facts := map[uuid.UUID]workspaceFacts{}
	rows, err = tx.Query(ctx, `SELECT q.id, cw.workspace_id IS NOT NULL, coalesce(cw.status, ''), t.id IS NOT NULL,
			coalesce(t.name, ''), coalesce(t.status, '')
		FROM (SELECT DISTINCT unnest($1::uuid[]) AS id) q
		LEFT JOIN contract_workspaces cw ON cw.workspace_id = q.id
		LEFT JOIN tenants t ON t.id = q.id`, ids)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id uuid.UUID
		var f workspaceFacts
		if err := rows.Scan(&id, &f.recorded, &f.recordedStatus, &f.local, &f.name, &f.status); err != nil {
			rows.Close()
			return nil, err
		}
		facts[id] = f
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// A team's name is the one its stored documents give at its highest
	// wversion (README 6.2: a name moves only with a higher wversion).
	names := map[uuid.UUID]string{}
	rows, err = tx.Query(ctx, `SELECT DISTINCT ON (x.id) x.id, x.name FROM (
			SELECT (w->>'id')::uuid AS id, w->>'name' AS name, (w->>'wversion')::bigint AS wversion
			  FROM contract_accounts a CROSS JOIN LATERAL jsonb_array_elements(a.doc->'workspaces') w
			 WHERE a.doc IS NOT NULL AND w->>'kind' = 'team' AND (w->>'id')::uuid = ANY ($1)) x
		WHERE x.name IS NOT NULL ORDER BY x.id, x.wversion DESC`, ids)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id uuid.UUID
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			rows.Close()
			return nil, err
		}
		names[id] = name
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var out []ContractDifference
	add := func(d ContractDifference) {
		d.Sub, d.User = sub, user
		out = append(out, d)
	}

	// The personal workspace (D6).
	var docPersonal uuid.UUID
	for _, w := range doc.Workspaces {
		if w.Kind == "personal" {
			docPersonal = w.ID
			break
		}
	}
	if doc.Status != "closed" && docPersonal != personal {
		d := ContractDifference{Kind: DiffPersonalMismatch, Workspace: docPersonal, LocalWorkspace: personal}
		if personal != uuid.Nil {
			if err := scope(ctx, tx, personal, uuid.Nil); err != nil {
				return nil, err
			}
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM devices WHERE tenant_id = $1`, personal).Scan(&d.Count); err != nil {
				return nil, err
			}
		}
		add(d)
	}

	// The account's status. The person's row is read in a workspace of
	// theirs, as the directory reads it.
	if len(tenants) > 0 || personal != uuid.Nil {
		in := personal
		if in == uuid.Nil {
			in = tenants[0]
		}
		if err := scope(ctx, tx, in, uuid.Nil); err != nil {
			return nil, err
		}
		var local string
		err := tx.QueryRow(ctx, `SELECT status FROM users WHERE id = $1`, user).Scan(&local)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
		case err != nil:
			return nil, err
		case (doc.Status == "active") != (local == "active"):
			add(ContractDifference{Kind: DiffAccountStatus, Local: local, Platform: doc.Status})
		}
	}

	// The document's workspaces.
	listed := map[uuid.UUID]bool{}
	for _, w := range doc.Workspaces {
		listed[w.ID] = true
		f := facts[w.ID]
		m, member := memberships[w.ID]
		switch {
		case w.Kind == "personal":
			// Its difference is personal_mismatch's.
		case !member:
			add(ContractDifference{Kind: DiffPlatformOnly, Workspace: w.ID, TenantMissing: !f.local})
		default:
			if m.role != w.Role {
				add(ContractDifference{Kind: DiffRole, Workspace: w.ID, Local: m.role, Platform: w.Role})
			}
			if m.status != "active" {
				add(ContractDifference{Kind: DiffMembershipStatus, Workspace: w.ID, Local: m.status})
			}
		}
		if w.Kind == "team" && f.local {
			if f.recordedStatus == "closed" {
				add(ContractDifference{Kind: DiffTeamClosed, Workspace: w.ID})
			}
			if name, ok := names[w.ID]; ok && name != f.name {
				add(ContractDifference{Kind: DiffName, Workspace: w.ID})
			}
		}
	}
	// Local memberships in platform workspaces the document lacks.
	slices.SortFunc(tenants, compareIDs)
	for _, id := range tenants {
		if !listed[id] && facts[id].recorded && id != personal {
			add(ContractDifference{Kind: DiffLocalOnly, Workspace: id})
		}
	}

	// What enforce would end.
	if sessionsRevoked != nil {
		var n int64
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM sessions s WHERE s.user_id = $1 AND s.revoked_at IS NULL
				AND s.expires_at > clock_timestamp()
				AND (SELECT min(f.created_at) FROM sessions f WHERE f.user_id = $1 AND f.family_id = s.family_id) < $2`,
			user, *sessionsRevoked).Scan(&n); err != nil {
			return nil, err
		}
		if n > 0 {
			add(ContractDifference{Kind: DiffSessionsWouldEnd, Count: n})
		}
	}
	if credentialsRevoked != nil {
		d, err := credentialsTx(ctx, tx, user, tenants, *credentialsRevoked)
		if err != nil {
			return nil, err
		}
		if d.Keys+d.Connections+d.Services > 0 {
			add(d)
		}
	}
	return out, nil
}

// credentialsTx counts what the person made before at that enforce would
// stop (README 6.2, credentials_revoked_at): API keys of their own (a
// connection's key counts as its connection), MCP connections still live
// and AI connections (keychain entries) in their workspaces, and standing
// service accounts they invited that are still members.
func credentialsTx(ctx context.Context, tx pgx.Tx, user uuid.UUID, tenants []uuid.UUID, at time.Time) (ContractDifference, error) {
	d := ContractDifference{Kind: DiffCredentialsWouldStop}
	if err := tx.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM api_keys k WHERE k.created_by = $1 AND k.revoked_at IS NULL AND k.created_at < $2
			    AND (k.expires_at IS NULL OR k.expires_at > clock_timestamp())
			    AND NOT EXISTS (SELECT 1 FROM mcp_connections c WHERE c.api_key_id = k.id)),
			(SELECT count(*) FROM mcp_connections c WHERE c.created_by = $1 AND c.status IN ('pending', 'active') AND c.created_at < $2)`,
		user, at).Scan(&d.Keys, &d.Connections); err != nil {
		return d, err
	}
	rows, err := tx.Query(ctx, `SELECT tenant_id, claimed_by FROM invites WHERE created_by = $1 AND role = 'service'
		AND NOT provisional AND completed_at IS NOT NULL AND completed_at < $2 AND claimed_by IS NOT NULL`, user, at)
	if err != nil {
		return d, err
	}
	type service struct{ tenant, user uuid.UUID }
	services, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (service, error) {
		var s service
		err := row.Scan(&s.tenant, &s.user)
		return s, err
	})
	if err != nil {
		return d, err
	}
	for _, s := range services {
		if err := scope(ctx, tx, s.tenant, uuid.Nil); err != nil {
			return d, err
		}
		var live bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM workspace_memberships WHERE tenant_id = $1 AND user_id = $2
			AND status = 'active' AND expires_at IS NULL)`, s.tenant, s.user).Scan(&live); err != nil {
			return d, err
		}
		if live {
			d.Services++
		}
	}
	for _, t := range tenants {
		if err := scope(ctx, tx, t, uuid.Nil); err != nil {
			return d, err
		}
		var n int64
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM ai_keychain WHERE tenant_id = $1 AND user_id = $2
			AND deleted_at IS NULL AND created_at < $3`, t, user, at).Scan(&n); err != nil {
			return d, err
		}
		d.Connections += n
	}
	return d, nil
}

// noSubTx lists, for each of the workspaces that is a platform workspace
// Wappie has locally, its active people with no platform link (they count
// as backups today, the reply's "Rollout").
func noSubTx(ctx context.Context, tx pgx.Tx, workspaces []uuid.UUID) ([]ContractDifference, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT w.workspace_id FROM contract_workspaces w JOIN tenants t ON t.id = w.workspace_id
		WHERE w.workspace_id = ANY ($1) ORDER BY w.workspace_id`, workspaces)
	if err != nil {
		return nil, err
	}
	local, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return nil, err
	}
	var out []ContractDifference
	for _, ws := range local {
		if err := scope(ctx, tx, ws, uuid.Nil); err != nil {
			return nil, err
		}
		rows, err := tx.Query(ctx, `SELECT m.user_id FROM workspace_memberships m
			WHERE m.tenant_id = $1 AND m.role <> 'service' AND m.expires_at IS NULL AND m.status = 'active'
			  AND NOT EXISTS (SELECT 1 FROM platform_identities pi WHERE pi.user_id = m.user_id)
			ORDER BY m.user_id`, ws)
		if err != nil {
			return nil, err
		}
		users, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			return nil, err
		}
		for _, u := range users {
			out = append(out, ContractDifference{Kind: DiffNoSub, User: u, Workspace: ws})
		}
	}
	return out, nil
}
