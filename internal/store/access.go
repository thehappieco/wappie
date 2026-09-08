package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"whatserver2/internal/pg"
)

// ConnectionAccess checks an already authenticated connection without loading
// private-key envelopes or re-running password hashing. A zero session ID is
// reserved for service identities whose API key is checked separately.
func (u *Users) ConnectionAccess(ctx context.Context, tenant, user, session uuid.UUID) (string, int64, error) {
	var role string
	var version int64
	err := pg.InTenantTx(ctx, u.pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT m.role,m.access_version FROM workspace_memberships m
			JOIN users u ON u.id=m.user_id JOIN tenants t ON t.id=m.tenant_id
			WHERE m.tenant_id=$1 AND m.user_id=$2 AND m.status='active' AND u.status='active' AND t.status='active'
			AND ($3::uuid='00000000-0000-0000-0000-000000000000' OR EXISTS
			 (SELECT 1 FROM sessions s WHERE s.id=$3 AND s.user_id=$2 AND s.tenant_id=$1 AND s.revoked_at IS NULL AND s.expires_at>now()))`, tenant, user, session).Scan(&role, &version)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", 0, ErrNoSession
	}
	return role, version, err
}

// ConnectionKey checks the immutable key ID captured after authentication.
// No secret is kept in memory for revalidation and a reused prefix cannot
// revive an existing socket.
func (a *APIKeys) ConnectionKey(ctx context.Context, id uuid.UUID, tenant string, scope KeyScope, actsAs uuid.UUID) error {
	var active bool
	err := a.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM api_keys k JOIN tenants t ON t.id=k.tenant_id
		WHERE k.id=$1 AND k.tenant_id=$2 AND k.scope=$3 AND k.revoked_at IS NULL AND t.status='active'
		AND coalesce(k.acts_as,'00000000-0000-0000-0000-000000000000'::uuid)=$4)`, id, tenant, string(scope), actsAs).Scan(&active)
	if err != nil {
		return err
	}
	if !active {
		return ErrInvalidKey
	}
	return nil
}
