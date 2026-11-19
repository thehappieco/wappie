package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The service users with no membership (DS54; E1d). Retire-keys looks only
// at service memberships, and a removal (removeServiceAccountTx, a
// connection's end, retention) deletes a service account's membership,
// grants and permissions and revokes its keys, but keeps its users row. So
// such a user should be inert already: with no membership ConnectionAccess
// fails, and every exit path revoked the keys acting as it. One gap stays:
// APIKeys.verify never checks that acts_as is still an active member (an
// auth change, the owner's to decide under 0049, not E1's). This sweep
// closes it from the data's side, at enforce: in each workspace it revokes
// every live key acting as a user with no membership there
// (orphan_service), and deletes the grants and empties the keychain items
// such a service user still holds there. Token identities, which are never
// members, are left alone. The users rows stay: mcp_connections names them
// with no ON DELETE, and api_keys.acts_as and workspace_member_history
// cascade, which would erase the 13-month records of ended keys and the
// attribution; deleting them is retention's, once the last record naming
// them ages out.

// OrphanSweep is what the sweep did, or would do.
type OrphanSweep struct {
	Keys, Grants, Keychain int64
	// Workspaces are those it wrote in (or would).
	Workspaces []uuid.UUID
	Actions    []ApplyAction
}

// SweepOrphanServices runs the sweep at enforce, in one transaction over
// every workspace in id order: contract_state FOR SHARE, then each
// workspace's row (lockWorkspaceAccess), as retire-keys takes them.
func (c *Contract) SweepOrphanServices(ctx context.Context) (OrphanSweep, error) {
	return c.sweepOrphanServices(ctx, true)
}

func (c *Contract) sweepOrphanServices(ctx context.Context, gate bool) (OrphanSweep, error) {
	var out OrphanSweep
	err := c.applyTx(ctx, gate, func(tx pgx.Tx, st applyState) error {
		var err error
		out, err = sweepOrphanServicesTx(ctx, tx, st)
		return err
	})
	return out, err
}

// orphanServiceSQL holds for a user ($2) of a workspace ($1) who has no
// membership there, is known as a service account (a key acts as it, a
// connection names it, or a service invitation was claimed by it), and is
// no token identity.
const orphanServiceSQL = `NOT EXISTS (SELECT 1 FROM workspace_memberships m WHERE m.tenant_id = $1 AND m.user_id = $2)
	AND NOT EXISTS (SELECT 1 FROM contract_tokens t WHERE t.identity_user_id = $2)
	AND (EXISTS (SELECT 1 FROM api_keys k WHERE k.acts_as = $2)
	     OR EXISTS (SELECT 1 FROM mcp_connections c WHERE c.service_user_id = $2)
	     OR EXISTS (SELECT 1 FROM invites i WHERE i.claimed_by = $2 AND i.role = 'service'))`

// sweepOrphanServicesTx is the sweep (st.apply) or its plan.
func sweepOrphanServicesTx(ctx context.Context, tx pgx.Tx, st applyState) (OrphanSweep, error) {
	var out OrphanSweep
	rows, err := tx.Query(ctx, `SELECT id FROM tenants ORDER BY id`)
	if err != nil {
		return out, err
	}
	workspaces, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return out, err
	}
	for _, ws := range workspaces {
		if err := scope(ctx, tx, ws, uuid.Nil); err != nil {
			return out, err
		}
		if st.apply {
			if err := lockWorkspaceAccess(ctx, tx, ws); err != nil {
				return out, err
			}
		}
		rows, err := tx.Query(ctx, `SELECT k.id FROM api_keys k WHERE k.tenant_id = $1 AND k.acts_as IS NOT NULL AND k.revoked_at IS NULL
			AND (k.expires_at IS NULL OR k.expires_at > now())
			AND NOT EXISTS (SELECT 1 FROM workspace_memberships m WHERE m.tenant_id = k.tenant_id AND m.user_id = k.acts_as)
			ORDER BY k.id`, ws)
		if err != nil {
			return out, err
		}
		keys, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			return out, err
		}
		rows, err = tx.Query(ctx, `SELECT DISTINCT g.user_id FROM device_key_grants g WHERE g.tenant_id = $1
			AND NOT EXISTS (SELECT 1 FROM workspace_memberships m WHERE m.tenant_id = $1 AND m.user_id = g.user_id)
			ORDER BY g.user_id`, ws)
		if err != nil {
			return out, err
		}
		holders, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			return out, err
		}
		rows, err = tx.Query(ctx, `SELECT DISTINCT a.user_id FROM ai_keychain a WHERE a.tenant_id = $1 AND a.deleted_at IS NULL
			AND NOT EXISTS (SELECT 1 FROM workspace_memberships m WHERE m.tenant_id = $1 AND m.user_id = a.user_id)
			ORDER BY a.user_id`, ws)
		if err != nil {
			return out, err
		}
		keyholders, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			return out, err
		}
		var grants, keychain int64
		for _, set := range []struct {
			users []uuid.UUID
			n     *int64
			count string
			write string
		}{
			{holders, &grants, `SELECT count(*) FROM device_key_grants WHERE tenant_id = $1 AND user_id = $2`,
				`DELETE FROM device_key_grants WHERE tenant_id = $1 AND user_id = $2`},
			{keyholders, &keychain, `SELECT count(*) FROM ai_keychain WHERE tenant_id = $1 AND user_id = $2 AND deleted_at IS NULL`,
				`UPDATE ai_keychain SET envelope = '\x', deleted_at = now() WHERE tenant_id = $1 AND user_id = $2 AND deleted_at IS NULL`},
		} {
			for _, u := range set.users {
				var orphan bool
				if err := tx.QueryRow(ctx, `SELECT `+orphanServiceSQL, ws, u).Scan(&orphan); err != nil {
					return out, err
				}
				if !orphan {
					continue
				}
				if !st.apply {
					var n int64
					if err := tx.QueryRow(ctx, set.count, ws, u).Scan(&n); err != nil {
						return out, err
					}
					*set.n += n
					continue
				}
				tag, err := tx.Exec(ctx, set.write, ws, u)
				if err != nil {
					return out, err
				}
				*set.n += tag.RowsAffected()
			}
		}
		n := int64(len(keys))
		if st.apply && len(keys) > 0 {
			tag, err := tx.Exec(ctx, `UPDATE api_keys SET revoked_at = now(), revoke_reason = 'orphan_service'
				WHERE id = ANY ($1) AND revoked_at IS NULL`, keys)
			if err != nil {
				return out, err
			}
			n = tag.RowsAffected()
		}
		if n+grants+keychain == 0 {
			continue
		}
		out.Keys += n
		out.Grants += grants
		out.Keychain += keychain
		out.Workspaces = append(out.Workspaces, ws)
		out.Actions = append(out.Actions, ApplyAction{Kind: ApplyOrphanKeysRevoked, Workspace: ws, Count: n + grants + keychain})
	}
	return out, scope(ctx, tx, uuid.Nil, uuid.Nil)
}
