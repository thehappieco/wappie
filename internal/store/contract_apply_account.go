package store

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The account's part of a document at enforce (DS54): a disable suspends
// the person, an active document lifts only a disable the contract made,
// sessions_revoked_at ends every session whose family began before it, and
// credentials_revoked_at stops what the person made before it (the
// platform's W45 ask). Grants, permissions and memberships stay through a
// suspension: sole_key_holders still protects a suspended holder, and an
// enable restores the person's access with nothing else.

// RevokeReasonContract is api_keys.revoke_reason for a key a suspension or
// a recovery's stop revoked; RevokeReasonOrphanService for a key acting as
// a service user with no membership in its workspace.
const (
	RevokeReasonContract      = "contract"
	RevokeReasonOrphanService = "orphan_service"
)

// ReasonCredentialsRevoked ends a connection its creator made before their
// account's recovery (credentials_revoked_at).
const ReasonCredentialsRevoked = "credentials_revoked"

// sessionsBeforeSQL is a person's ($1) live sessions whose family began
// before $2: what observe's diff counts as sessions_would_end and what the
// apply ends. A session is alias s.
const sessionsBeforeSQL = `s.user_id = $1 AND s.revoked_at IS NULL AND s.expires_at > clock_timestamp()
	AND (SELECT min(f.created_at) FROM sessions f WHERE f.user_id = $1 AND f.family_id = s.family_id) < $2`

// suspend disables the person's account as the contract's (the trigger
// users_disabled_by reads app.contract_apply), then ends every live
// session, every live connection they made (member_disabled) and every
// key they made or that acts as them, in every workspace (contract).
func (r *applyRun) suspend(ctx context.Context) error {
	r.out.add(ApplyAction{Kind: ApplyAccountSuspended, User: r.user})
	if r.st.apply {
		if err := scope(ctx, r.tx, r.identity, uuid.Nil); err != nil {
			return err
		}
		if _, err := r.tx.Exec(ctx, `SELECT set_config('app.contract_apply', 'on', true)`); err != nil {
			return err
		}
		if _, err := r.tx.Exec(ctx, `UPDATE users SET status = 'disabled' WHERE id = $1 AND status = 'active'`, r.user); err != nil {
			return err
		}
		if _, err := r.tx.Exec(ctx, `SELECT set_config('app.contract_apply', '', true)`); err != nil {
			return err
		}
	}
	for id := range r.members {
		r.changed(id)
	}
	return r.endEverything(ctx, nil, ReasonMemberDisabled)
}

// enable lifts the contract's own disable; an operator's stands.
func (r *applyRun) enable(ctx context.Context) error {
	r.out.add(ApplyAction{Kind: ApplyAccountEnabled, User: r.user})
	for id := range r.members {
		r.changed(id)
	}
	if !r.st.apply {
		return nil
	}
	if err := scope(ctx, r.tx, r.identity, uuid.Nil); err != nil {
		return err
	}
	_, err := r.tx.Exec(ctx, `UPDATE users SET status = 'active' WHERE id = $1 AND status = 'disabled' AND disabled_by = 'contract'`, r.user)
	return err
}

// endBefore is a risen disabled_at's on an account active again: what the
// person began before at ends, as a suspension ends it, and the account
// stays active.
func (r *applyRun) endBefore(ctx context.Context, at time.Time) error {
	return r.endEverything(ctx, &at, ReasonMemberDisabled)
}

// endEverything ends the person's live sessions (whose family began before
// *before, when set), their live connections (made before it) with reason,
// and their live keys and those acting as them (made before it), revoked
// as the contract's.
func (r *applyRun) endEverything(ctx context.Context, before *time.Time, reason string) error {
	var sessions, keys int64
	cut := before
	if cut == nil {
		// Everything: a time past every row.
		far := time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
		cut = &far
	}
	if r.st.apply {
		tag, err := r.tx.Exec(ctx, `UPDATE sessions s SET revoked_at = now() WHERE `+sessionsBeforeSQL, r.user, *cut)
		if err != nil {
			return err
		}
		sessions = tag.RowsAffected()
	} else if err := r.tx.QueryRow(ctx, `SELECT count(*) FROM sessions s WHERE `+sessionsBeforeSQL, r.user, *cut).Scan(&sessions); err != nil {
		return err
	}
	rows, err := r.tx.Query(ctx, `SELECT tenant_id, id::text, reader FROM mcp_connections
		WHERE created_by = $1 AND status IN ('pending', 'active', 'reseal') AND created_at < $2 ORDER BY tenant_id, id`, r.user, *cut)
	if err != nil {
		return err
	}
	conns, err := pgx.CollectRows(rows, scanConnRef)
	if err != nil {
		return err
	}
	ended, err := r.endConnections(ctx, conns, reason)
	if err != nil {
		return err
	}
	keysSQL := `FROM api_keys k WHERE (k.created_by = $1 OR k.acts_as = $1) AND k.revoked_at IS NULL AND k.created_at < $2
		AND (k.expires_at IS NULL OR k.expires_at > now())`
	if r.st.apply {
		tag, err := r.tx.Exec(ctx, `UPDATE api_keys SET revoked_at = now(), revoke_reason = 'contract' WHERE id IN (SELECT k.id `+keysSQL+`)`,
			r.user, *cut)
		if err != nil {
			return err
		}
		keys = tag.RowsAffected()
	} else if err := r.tx.QueryRow(ctx, `SELECT count(*) `+keysSQL+`
			AND NOT EXISTS (SELECT 1 FROM mcp_connections c WHERE c.api_key_id = k.id AND c.created_by = $1
			  AND c.status IN ('pending', 'active', 'reseal') AND c.created_at < $2)`, r.user, *cut).Scan(&keys); err != nil {
		return err
	}
	if sessions > 0 {
		r.out.add(ApplyAction{Kind: ApplySessionsEnded, User: r.user, Count: sessions})
	}
	r.out.Counts.Sessions += sessions
	r.out.Counts.Keys += keys
	r.out.Counts.Connections += int64(len(ended))
	return nil
}

// connRef is a connection to end.
type connRef struct {
	tenant uuid.UUID
	id     string
	reader string
}

func scanConnRef(row pgx.CollectableRow) (connRef, error) {
	var c connRef
	err := row.Scan(&c.tenant, &c.id, &c.reader)
	return c, err
}

// endConnections ends conns (sorted by workspace, then id) with reason,
// each in its workspace's scope; a plan counts them.
func (r *applyRun) endConnections(ctx context.Context, conns []connRef, reason string) ([]EndedConnection, error) {
	if !r.st.apply {
		out := make([]EndedConnection, 0, len(conns))
		for _, c := range conns {
			out = append(out, EndedConnection{ID: c.id, Reader: c.reader})
		}
		return out, nil
	}
	var ended []EndedConnection
	for _, c := range conns {
		if err := r.inWorkspace(ctx, c.tenant); err != nil {
			return nil, err
		}
		did, err := endMCPConnectionTx(ctx, r.tx, c.tenant, c.id, statusRevoked, reason)
		if err != nil {
			return nil, err
		}
		if did {
			ended = append(ended, EndedConnection{ID: c.id, Reader: c.reader})
		}
	}
	r.out.Ended = append(r.out.Ended, ended...)
	return ended, nil
}

// endSessions ends every live session of the person whose family began
// before at (sessions_revoked_at).
func (r *applyRun) endSessions(ctx context.Context, at time.Time) error {
	var n int64
	if r.st.apply {
		tag, err := r.tx.Exec(ctx, `UPDATE sessions s SET revoked_at = now() WHERE `+sessionsBeforeSQL, r.user, at)
		if err != nil {
			return err
		}
		n = tag.RowsAffected()
	} else if err := r.tx.QueryRow(ctx, `SELECT count(*) FROM sessions s WHERE `+sessionsBeforeSQL, r.user, at).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		r.out.add(ApplyAction{Kind: ApplySessionsEnded, User: r.user, Count: n})
	}
	r.out.Counts.Sessions += n
	return nil
}

// keychainRef is a person's live keychain item.
type keychainRef struct {
	tenant, id uuid.UUID
}

// serviceRef is a standing service account a person invited.
type serviceRef struct {
	tenant, user uuid.UUID
	email        string
}

// credentialTargets is what a person made before credentials_revoked_at
// that enforce stops (README 6.2): observe's diff counts it
// (credentials_would_stop) and the apply stops it.
type credentialTargets struct {
	// keys are their own live API keys but a connection's (a
	// connection's key counts as its connection).
	keys []uuid.UUID
	// connections are their live MCP and AI connections.
	connections []connRef
	// keychain are their live AI keychain items, in their workspaces.
	keychain []keychainRef
	// services are the standing service accounts they invited that are
	// still active members.
	services []serviceRef
}

// credentialTargetsTx reads what user made before at, among tenants (their
// workspaces, for the keychain).
func credentialTargetsTx(ctx context.Context, tx pgx.Tx, user uuid.UUID, tenants []uuid.UUID, at time.Time) (credentialTargets, error) {
	var t credentialTargets
	rows, err := tx.Query(ctx, `SELECT k.id FROM api_keys k WHERE k.created_by = $1 AND k.revoked_at IS NULL AND k.created_at < $2
		AND (k.expires_at IS NULL OR k.expires_at > clock_timestamp())
		AND NOT EXISTS (SELECT 1 FROM mcp_connections c WHERE c.api_key_id = k.id) ORDER BY k.id`, user, at)
	if err != nil {
		return t, err
	}
	if t.keys, err = pgx.CollectRows(rows, pgx.RowTo[uuid.UUID]); err != nil {
		return t, err
	}
	rows, err = tx.Query(ctx, `SELECT tenant_id, id::text, reader FROM mcp_connections
		WHERE created_by = $1 AND status IN ('pending', 'active', 'reseal') AND created_at < $2 ORDER BY tenant_id, id`, user, at)
	if err != nil {
		return t, err
	}
	if t.connections, err = pgx.CollectRows(rows, scanConnRef); err != nil {
		return t, err
	}
	rows, err = tx.Query(ctx, `SELECT DISTINCT tenant_id, claimed_by FROM invites WHERE created_by = $1 AND role = 'service'
		AND NOT provisional AND completed_at IS NOT NULL AND completed_at < $2 AND claimed_by IS NOT NULL
		ORDER BY tenant_id, claimed_by`, user, at)
	if err != nil {
		return t, err
	}
	invited, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (serviceRef, error) {
		var s serviceRef
		err := row.Scan(&s.tenant, &s.user)
		return s, err
	})
	if err != nil {
		return t, err
	}
	for _, s := range invited {
		if err := scope(ctx, tx, s.tenant, uuid.Nil); err != nil {
			return t, err
		}
		// A standing service: an active member with no deadline, no
		// connection's account and no token identity.
		err := tx.QueryRow(ctx, `SELECT u.email FROM workspace_memberships m JOIN users u ON u.id = m.user_id
			WHERE m.tenant_id = $1 AND m.user_id = $2 AND m.status = 'active' AND m.expires_at IS NULL AND m.role = 'service'
			  AND NOT u.token_identity
			  AND NOT EXISTS (SELECT 1 FROM mcp_connections c WHERE c.service_user_id = m.user_id)`, s.tenant, s.user).Scan(&s.email)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return t, err
		}
		t.services = append(t.services, s)
	}
	sorted := slices.Clone(tenants)
	slices.SortFunc(sorted, compareIDs)
	for _, ws := range slices.Compact(sorted) {
		if err := scope(ctx, tx, ws, uuid.Nil); err != nil {
			return t, err
		}
		rows, err := tx.Query(ctx, `SELECT id FROM ai_keychain WHERE tenant_id = $1 AND user_id = $2
			AND deleted_at IS NULL AND created_at < $3 ORDER BY id`, ws, user, at)
		if err != nil {
			return t, err
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			return t, err
		}
		for _, id := range ids {
			t.keychain = append(t.keychain, keychainRef{tenant: ws, id: id})
		}
	}
	return t, nil
}

// stopCredentials stops what the person made before at
// (credentials_revoked_at, the W45 ask): their keys (contract), their live
// connections (credentials_revoked, each through endMCPConnectionTx, which
// removes a content or AI connection's service account), their keychain
// items (emptied, and the AI connections naming them end), and every live
// key acting as a standing service account they invited (contract). Such
// an account is removed, with a history row, where every number it holds a
// key of keeps a human holder (everyGrantKeepsAHumanHolderTx, the
// retirement's rule); otherwise it is kept keyless (service_kept,
// sole_reader), so the number's last key is never lost. Platform tokens
// are not written: the belt refuses a token made before at from the stored
// document. Keys made after at are not touched.
func (r *applyRun) stopCredentials(ctx context.Context, at time.Time) error {
	tenants := make([]uuid.UUID, 0, len(r.members))
	for id := range r.members {
		tenants = append(tenants, id)
	}
	t, err := credentialTargetsTx(ctx, r.tx, r.user, tenants, at)
	if err != nil {
		return err
	}
	var keys int64
	counted := t.keys
	if counted == nil {
		counted = []uuid.UUID{}
	}
	if _, err := r.endConnections(ctx, t.connections, ReasonCredentialsRevoked); err != nil {
		return err
	}
	if r.st.apply && len(t.keys) > 0 {
		tag, err := r.tx.Exec(ctx, `UPDATE api_keys SET revoked_at = now(), revoke_reason = 'contract'
			WHERE id = ANY ($1) AND revoked_at IS NULL`, t.keys)
		if err != nil {
			return err
		}
		keys = tag.RowsAffected()
	} else {
		keys = int64(len(t.keys))
	}
	byTenant := map[uuid.UUID][]uuid.UUID{}
	for _, k := range t.keychain {
		byTenant[k.tenant] = append(byTenant[k.tenant], k.id)
	}
	var keychain int64
	for _, ws := range sortedKeys(byTenant) {
		if !r.st.apply {
			keychain += int64(len(byTenant[ws]))
			continue
		}
		if err := r.inWorkspace(ctx, ws); err != nil {
			return err
		}
		e, n, err := emptyKeychainTx(ctx, r.tx, ws, r.user, byTenant[ws])
		if err != nil {
			return err
		}
		keychain += n
		r.out.Ended = append(r.out.Ended, e...)
	}
	var removed, kept int64
	for _, s := range t.services {
		if err := r.inWorkspace(ctx, s.tenant); err != nil {
			return err
		}
		var n int64
		if r.st.apply {
			tag, err := r.tx.Exec(ctx, `UPDATE api_keys SET revoked_at = now(), revoke_reason = 'contract'
				WHERE tenant_id = $1 AND acts_as = $2 AND revoked_at IS NULL`, s.tenant, s.user)
			if err != nil {
				return err
			}
			n = tag.RowsAffected()
		} else if err := r.tx.QueryRow(ctx, `SELECT count(*) FROM api_keys WHERE tenant_id = $1 AND acts_as = $2 AND revoked_at IS NULL
				AND (expires_at IS NULL OR expires_at > now()) AND NOT (id = ANY ($3))`, s.tenant, s.user, counted).Scan(&n); err != nil {
			return err
		}
		keys += n
		backed, err := everyGrantKeepsAHumanHolderTx(ctx, r.tx, s.tenant, s.user)
		if err != nil {
			return err
		}
		if !backed {
			kept++
			r.out.add(ApplyAction{Kind: ApplyServiceKept, User: s.user, Workspace: s.tenant, Local: KeptSoleReader})
			continue
		}
		removed++
		r.changed(s.tenant)
		if !r.st.apply {
			continue
		}
		if err := removeServiceAccountTx(ctx, r.tx, s.tenant, s.user); err != nil {
			return err
		}
		if _, err := r.tx.Exec(ctx, `INSERT INTO workspace_member_history (tenant_id, user_id, email) VALUES ($1, $2, $3)
			ON CONFLICT (tenant_id, user_id) DO UPDATE SET email = excluded.email, removed_at = now()`, s.tenant, s.user, s.email); err != nil {
			return err
		}
	}
	total := keys + int64(len(t.connections)) + keychain + removed + kept
	if total > 0 {
		r.out.add(ApplyAction{Kind: ApplyCredentialsStopped, User: r.user, Count: total})
	}
	r.out.Counts.Keys += keys
	r.out.Counts.Connections += int64(len(t.connections))
	r.out.Counts.Keychain += keychain
	r.out.Counts.ServicesRemoved += removed
	return nil
}

// sortedKeys is m's keys in id order.
func sortedKeys[V any](m map[uuid.UUID]V) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	slices.SortFunc(out, compareIDs)
	return out
}
