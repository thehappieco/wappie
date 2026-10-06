package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/pg"
)

// Reconnect hygiene (docs/mcp-enclave.md §19.35): a reconnect that replaces
// the connection it repeats, and the end of connections nobody uses.

// sameClient is a connection c of the same client as the consent named by
// $4 (client_kind), $5 (client_id), $6 (client_host) and $7 (client_local):
// a CIMD client by its client id, a registered one by its verified host and
// locality, since its id is random and not kept. A legacy row, a token and an
// AI authorization are never the same client as anything.
const sameClient = `((c.client_kind = 'cimd' AND $4 = 'cimd' AND c.client_id = $5)
	OR (c.client_kind = 'dcr' AND $4 = 'dcr' AND c.client_host = $6 AND c.client_local = $7))`

// ReplacePrevious ends, as replaced, the earlier live connections of the
// same person and client in the workspace of a connection that just
// activated with replaces set: an active or resealed one created before it,
// of any kind but AI. Each ends with its key and, for content, its service
// account, in the workspace's transaction. It returns what it ended, for the
// readers to be told; a connection that did not ask, or that is not one of
// this reader's, ends nothing.
func (m *MCPConnections) ReplacePrevious(ctx context.Context, reader, id string) ([]EndedConnection, error) {
	var tenant, actor uuid.UUID
	var replaces bool
	var kind, clientID, clientHost string
	var local bool
	var created time.Time
	err := m.pool.QueryRow(ctx, `SELECT tenant_id, created_by, replaces, client_kind, coalesce(client_id, ''), coalesce(client_host, ''), client_local, created_at
		FROM mcp_connections WHERE id=$1 AND reader=$2 AND status='active'`, id, reader).
		Scan(&tenant, &actor, &replaces, &kind, &clientID, &clientHost, &local, &created)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !replaces {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: read a reconnect: %w", err)
	}
	var out []EndedConnection
	err = pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		if err := lockWorkspaceAccess(ctx, tx, tenant); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT c.id::text, c.reader FROM mcp_connections c
			WHERE c.tenant_id=$1 AND c.created_by=$2 AND c.id <> $3 AND c.kind <> 'ai' AND c.status IN ('active','reseal')
			  AND c.created_at <= $8 AND coalesce(`+sameClient+`, false)
			ORDER BY c.created_at`, tenant, actor, id, kind, clientID, clientHost, local, created)
		if err != nil {
			return err
		}
		ended, err := pgx.CollectRows(rows, pgx.RowToStructByPos[EndedConnection])
		if err != nil {
			return err
		}
		for _, c := range ended {
			if _, err := endMCPConnectionTx(ctx, tx, tenant, c.ID, statusRevoked, ReasonReplaced); err != nil {
				return err
			}
		}
		out = ended
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("store: replace earlier connections: %w", err)
	}
	return out, nil
}

// IdleTime is how long a connection of this kind and limits tier may go
// unused before its assistant's refresh token dies in the reader: the
// image's CLIENT_LIMITS idle_days (docs/mcp-enclave.md §19.19), this
// server's copy. A token has none, and neither has an AI authorization,
// which no assistant holds: zero.
func IdleTime(kind, tier string) time.Duration {
	const day = 24 * time.Hour
	content := kind == KindContent
	switch {
	case kind == KindAI || tier == TierToken:
		return 0
	case tier == TierUnknown && content:
		return 3 * day
	case tier == TierUnknown, tier == TierLocalTested:
		return 7 * day
	case content:
		return 7 * day
	}
	return 30 * day
}

// idleGrace is the margin past a tier's idle time before a connection is
// ended: the reader counts from the last refresh, and this server sees reads.
const idleGrace = 24 * time.Hour

// idleLimit is how long a connection may go unused before the sweep ends it:
// its tier's idle time and idleGrace; zero for one that never idles.
func idleLimit(kind, trust string, local bool, clientKind string) time.Duration {
	idle := IdleTime(kind, LimitsTier(trust, local, clientKind))
	if idle <= 0 {
		return 0
	}
	return idle + idleGrace
}

// RevokeIdleMCPConnections ends, as idle, every live connection unused for
// longer than its tier's idle time and a day: by then its assistant's refresh
// token has died in the reader, so the row only holds a place under the
// workspace's cap and a stale line in the console. Use is the latest of its
// key's last read (every tool call reads the archive with it), its
// activation and its last renewal and, for a metadata connection, the
// reader's last status check; a content connection's status is asked every
// minute by the reader's sweep, used or idle, so it says nothing about use.
// Times are the database's. Each ends in its own workspace's transaction,
// and only if it is still idle under its row's lock (endIfIdle); it returns
// what it ended, for the readers to be told (WatchRevocations tells them in
// any case).
func RevokeIdleMCPConnections(ctx context.Context, pool *pgxpool.Pool) ([]EndedConnection, error) {
	// The ledger and api_keys carry no policy, so the candidates are found
	// across every workspace in one read.
	rows, err := pool.Query(ctx, `
		SELECT c.id::text, c.tenant_id, c.reader, c.kind, coalesce(c.trust, ''), c.client_local, c.client_kind,
		       extract(epoch FROM now() - greatest(k.last_used_at, c.activated_at, c.renewed_at, c.created_at,
		                CASE WHEN c.kind = 'metadata' THEN c.last_seen_at END))::float8
		  FROM mcp_connections c JOIN api_keys k ON k.id = c.api_key_id
		 WHERE c.status IN ('active','reseal') AND c.kind <> 'ai' AND c.client_kind <> 'token' AND c.expires_at > now()
		 ORDER BY c.id`)
	if err != nil {
		return nil, fmt.Errorf("store: idle mcp connections: %w", err)
	}
	type candidate struct {
		EndedConnection
		tenant uuid.UUID
	}
	var due []candidate
	for rows.Next() {
		var c candidate
		var kind, trust, clientKind string
		var local bool
		var unused float64
		if err := rows.Scan(&c.ID, &c.tenant, &c.Reader, &kind, &trust, &local, &clientKind, &unused); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store: idle mcp connections: %w", err)
		}
		if limit := idleLimit(kind, trust, local, clientKind); limit > 0 && time.Duration(unused*float64(time.Second)) > limit {
			due = append(due, c)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: idle mcp connections: %w", err)
	}
	m := NewMCPConnections(pool)
	var out []EndedConnection
	var errs []error
	for _, c := range due {
		// One row failing must not keep the rest alive.
		ended, err := m.endIfIdle(ctx, c.tenant, c.ID)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if ended {
			out = append(out, c.EndedConnection)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return out, fmt.Errorf("store: idle mcp connections: %w", err)
	}
	return out, nil
}

// endIfIdle ends one connection as idle when, under its row's lock, it still
// is: live and unexpired, of a kind and tier with an idle time, and unused
// for longer than that and idleGrace. The sweep picks its candidates outside
// any lock, so a person who renewed the connection, or an assistant that
// read with it, between that pick and this keeps it. It reports whether
// this call ended it.
func (m *MCPConnections) endIfIdle(ctx context.Context, tenant uuid.UUID, id string) (bool, error) {
	ended := false
	err := pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		if err := lockWorkspaceAccess(ctx, tx, tenant); err != nil {
			return err
		}
		var status, kind, trust, clientKind string
		var local, unexpired bool
		err := tx.QueryRow(ctx, `SELECT status, kind, coalesce(trust, ''), client_local, client_kind, expires_at > now()
			FROM mcp_connections WHERE id=$1 AND tenant_id=$2 FOR UPDATE`, id, tenant).
			Scan(&status, &kind, &trust, &local, &clientKind, &unexpired)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		limit := idleLimit(kind, trust, local, clientKind)
		if (status != statusActive && status != statusReseal) || kind == KindAI || clientKind == ClientToken || !unexpired || limit <= 0 {
			return nil
		}
		// A statement of its own, after the lock: it sees a renewal, or a
		// read, that committed while this waited for the row.
		var idleNow bool
		if err := tx.QueryRow(ctx, `SELECT now() - greatest(k.last_used_at, c.activated_at, c.renewed_at, c.created_at,
			       CASE WHEN c.kind = 'metadata' THEN c.last_seen_at END) > make_interval(secs => $3)
			  FROM mcp_connections c JOIN api_keys k ON k.id = c.api_key_id
			 WHERE c.id=$1 AND c.tenant_id=$2`, id, tenant, limit.Seconds()).Scan(&idleNow); err != nil {
			return err
		}
		if !idleNow {
			return nil
		}
		ended, err = endMCPConnectionTx(ctx, tx, tenant, id, statusRevoked, ReasonIdle)
		return err
	})
	if err != nil {
		return false, fmt.Errorf("store: end an idle mcp connection: %w", err)
	}
	return ended, nil
}

// ---------------------------------------------------------------------------
// The renewal round
// ---------------------------------------------------------------------------

// RenewalNotice is one person's renewal notice (docs/mcp-enclave.md
// §19.35): their content connections in one workspace whose key the reader
// lost and that no notice has covered since.
type RenewalNotice struct {
	TenantID, UserID         uuid.UUID
	Email, Locale, Workspace string
	// ConnectionIDs and Assistants are the waiting connections and their
	// verified names, oldest reseal first; Since is when that was. Tokens
	// marks the console tokens among them, in the same order: the notice
	// names a token by its label as the activation notice does.
	ConnectionIDs []string
	Assistants    []string
	Tokens        []bool
	Since         time.Time
	// OneByOne is how many of them the console's Renew all leaves to their
	// own Renew: an untested client's and a token's, whose renewal asks its
	// own confirmation.
	OneByOne int
}

// renewalName is the name a renewal notice gives a connection, as the
// activation notice never takes one from the client: a 0.6.0 row's verified
// client_name (a tested client's name from the reader's list, an untested
// one's host, a token's label), and for an older row, whose client_name is
// whatever the client registered itself as, its host.
const renewalName = `CASE WHEN c.client_kind IN ('cimd', 'dcr', 'token') THEN c.client_name
	ELSE coalesce(c.client_host, c.redirect_host) END`

// renewalSettle is how long a reseal waits before its notice may go: a
// restarted reader reseals its connections one after the other, and one
// e-mail should cover them all.
const renewalSettle = 2 * time.Minute

// renewalQuiet is the least time between two renewal notices to one person:
// a reader that restarts again within it adds no e-mail, and the connections
// it resealed wait for the next.
const renewalQuiet = 12 * time.Hour

// DueRenewalNotices returns the renewal notices that may go now: for each
// person and workspace, the live content connections they consented to that
// wait in reseal for longer than renewalSettle with no notice since, while
// the person is an active member whose address is verified and had no renewal
// notice in renewalQuiet. The ledger is read across workspaces, the people
// in each workspace's transaction.
func (m *MCPConnections) DueRenewalNotices(ctx context.Context) ([]RenewalNotice, error) {
	rows, err := m.pool.Query(ctx, `
		SELECT c.tenant_id, c.created_by, array_agg(c.id::text ORDER BY c.resealed_at, c.id), array_agg(`+renewalName+` ORDER BY c.resealed_at, c.id),
		       array_agg(c.client_kind = 'token' ORDER BY c.resealed_at, c.id),
		       min(c.resealed_at), count(*) FILTER (WHERE c.trust = 'unknown' OR c.client_kind = 'token')
		  FROM mcp_connections c
		 WHERE c.kind = 'content' AND c.status = 'reseal' AND c.expires_at > now()
		   AND c.resealed_at <= now() - make_interval(secs => $1)
		   AND (c.reseal_mailed_at IS NULL OR c.reseal_mailed_at < c.resealed_at)
		   AND NOT EXISTS (SELECT 1 FROM mcp_connections p WHERE p.tenant_id = c.tenant_id AND p.created_by = c.created_by
		                    AND p.reseal_mailed_at > now() - make_interval(secs => $2))
		 GROUP BY c.tenant_id, c.created_by
		 ORDER BY c.tenant_id, c.created_by`, renewalSettle.Seconds(), renewalQuiet.Seconds())
	if err != nil {
		return nil, fmt.Errorf("store: due renewal notices: %w", err)
	}
	var due []RenewalNotice
	for rows.Next() {
		var n RenewalNotice
		if err := rows.Scan(&n.TenantID, &n.UserID, &n.ConnectionIDs, &n.Assistants, &n.Tokens, &n.Since, &n.OneByOne); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store: due renewal notices: %w", err)
		}
		due = append(due, n)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: due renewal notices: %w", err)
	}
	var out []RenewalNotice
	for _, n := range due {
		err := pg.InTenantTx(ctx, m.pool, n.TenantID.String(), func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT u.email, coalesce(u.locale, ''), t.name
				  FROM users u JOIN workspace_memberships w ON w.user_id = u.id AND w.tenant_id = $1
				  JOIN tenants t ON t.id = w.tenant_id
				 WHERE u.id = $2 AND u.status = 'active' AND w.status = 'active' AND (w.expires_at IS NULL OR w.expires_at > now())
				   AND `+verifiedEmail, n.TenantID, n.UserID).Scan(&n.Email, &n.Locale, &n.Workspace)
		})
		if errors.Is(err, pgx.ErrNoRows) {
			// Gone, or no verified address: the console's banner still says it.
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("store: due renewal notices: %w", err)
		}
		out = append(out, n)
	}
	return out, nil
}

// ClaimRenewalNotice records that a renewal notice covers these
// connections, those of them still waiting with no notice since their
// reseal, and reports whether any were: false is a notice another process
// sent, or connections renewed meanwhile, and no e-mail goes.
func (m *MCPConnections) ClaimRenewalNotice(ctx context.Context, tenant, user uuid.UUID, ids []string) (bool, error) {
	tag, err := m.pool.Exec(ctx, `UPDATE mcp_connections SET reseal_mailed_at = now()
		WHERE tenant_id = $1 AND created_by = $2 AND id::text = ANY($3) AND kind = 'content' AND status = 'reseal'
		  AND (reseal_mailed_at IS NULL OR reseal_mailed_at < resealed_at)`, tenant, user, ids)
	if err != nil {
		return false, fmt.Errorf("store: claim a renewal notice: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}
