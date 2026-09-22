package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/pg"
)

// MCPConnections is the ledger of hosted assistant connections: every consent
// a workspace gave a remote MCP client, riding on one read-only API key.
//
// The table holds no secret. The sealed bundle, the OAuth tokens and the key
// itself live with the reader process; what is recorded here is who consented,
// to which client, for how long, and where the connection stands — enough for
// the console to show it and for a revocation to reach the key.
type MCPConnections struct{ pool *pgxpool.Pool }

// NewMCPConnections returns a connection ledger.
func NewMCPConnections(pool *pgxpool.Pool) *MCPConnections { return &MCPConnections{pool: pool} }

var (
	// ErrMCPConnectionNotFound is an id the ledger does not know, or one that
	// belongs to another workspace, which is the same thing to the asker.
	ErrMCPConnectionNotFound = errors.New("store: no such mcp connection")
	// ErrTooManyMCPConnections means the workspace already has as many live
	// connections as it is allowed.
	ErrTooManyMCPConnections = errors.New("store: too many live mcp connections")
	// ErrMCPConnectionState means the transition asked for does not apply to
	// the connection's current status.
	ErrMCPConnectionState = errors.New("store: mcp connection is not in that state")
	// ErrMCPKeyUnsuitable means the key exists in this workspace but is not
	// the kind a hosted assistant may ride on.
	ErrMCPKeyUnsuitable = errors.New("store: api key is not suitable for an mcp connection")
)

// maxLiveMCPConnections caps pending and active connections per workspace.
// Five is room for a couple of assistants and a retry, not for a fleet.
const maxLiveMCPConnections = 5

// maxProvisionalKeyLifetime is how far out the deadline of a key may be for
// a consent to bind it. The console mints the key twenty minutes before the
// consent; the margin is for clocks, not for keys issued for anything else.
// A key with a longer deadline was made for another purpose, and a consent
// must not quietly stretch it to a year.
const maxProvisionalKeyLifetime = 30 * time.Minute

// MCPConnection is one hosted assistant connection as the console sees it.
type MCPConnection struct {
	ID, TenantID, RequestID             string
	APIKeyID, CreatedBy                 uuid.UUID
	KeyPrefix, ClientName, RedirectHost string
	DeviceCount                         int
	ReaderKID, Status                   string
	CreatedAt                           time.Time
	ActivatedAt, RevokedAt, LastSeenAt  *time.Time
	ExpiresAt                           time.Time
}

// CreateMCPConnection is what a consent records.
type CreateMCPConnection struct {
	RequestID, KeyPrefix, ClientName, RedirectHost string
	DeviceCount                                    int
	ReaderKID                                      string
	// ExpiresAt is the lifetime the person chose. The key is extended to it.
	ExpiresAt time.Time
}

// Create records a consent and promotes its key from the provisional deadline
// the console issued it with to the lifetime the person chose.
//
// The key must be this workspace's and the actor's own, read-only,
// restricted to named devices, carry no service account, be live and carry
// the short provisional deadline the console issues before a consent.
// Anything else is a key that could reach more than metadata, one another
// person issued for something else, or one that would outlive the consent,
// and is refused. Only an owner or admin may consent, and the check reads
// policy-protected tables, so the whole thing runs in a tenant transaction
// like every other permission change.
func (m *MCPConnections) Create(ctx context.Context, tenant, actor uuid.UUID, in CreateMCPConnection) (MCPConnection, error) {
	in.RequestID = strings.TrimSpace(in.RequestID)
	in.KeyPrefix = strings.TrimSpace(in.KeyPrefix)
	in.ClientName = strings.TrimSpace(in.ClientName)
	in.RedirectHost = strings.TrimSpace(in.RedirectHost)
	in.ReaderKID = strings.TrimSpace(in.ReaderKID)
	if in.RequestID == "" || in.ClientName == "" || in.RedirectHost == "" || in.ReaderKID == "" || in.DeviceCount < 1 {
		// The handler validates the body before it gets here; this is the
		// backstop, not the message a person sees.
		return MCPConnection{}, errors.New("store: mcp connection needs a request id, client name, redirect host, reader kid and a device count")
	}
	if len(in.KeyPrefix) != prefixLen {
		return MCPConnection{}, ErrNotFound
	}
	if err := checkKeyExpiry(in.ExpiresAt); err != nil {
		return MCPConnection{}, err
	}
	out := MCPConnection{
		TenantID: tenant.String(), RequestID: in.RequestID, CreatedBy: actor,
		KeyPrefix: in.KeyPrefix, ClientName: in.ClientName, RedirectHost: in.RedirectHost,
		DeviceCount: in.DeviceCount, ReaderKID: in.ReaderKID, Status: "pending", ExpiresAt: in.ExpiresAt,
	}
	err := pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		if _, err := lockWorkspaceManager(ctx, tx, tenant, actor); err != nil {
			return err
		}
		// Lock the key so a concurrent revocation or a second consent on the
		// same key cannot slip in between the checks and the insert. A key
		// someone else issued is not found rather than unsuitable: the
		// person consenting only ever sees the key the console just minted
		// for them.
		var scope string
		var restricted bool
		var actsAs *uuid.UUID
		var revokedAt, expiresAt *time.Time
		err := tx.QueryRow(ctx, `SELECT id, scope, devices_restricted, acts_as, revoked_at, expires_at
			FROM api_keys WHERE prefix=$1 AND tenant_id=$2 AND created_by=$3 FOR UPDATE`, in.KeyPrefix, tenant, actor).
			Scan(&out.APIKeyID, &scope, &restricted, &actsAs, &revokedAt, &expiresAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		now := time.Now()
		if KeyScope(scope) != ScopeRead || !restricted || actsAs != nil || revokedAt != nil ||
			expiresAt == nil || !expiresAt.After(now) || expiresAt.After(now.Add(maxProvisionalKeyLifetime)) {
			return ErrMCPKeyUnsuitable
		}
		// The count is safe against a concurrent consent because
		// lockWorkspaceManager holds the workspace's tenants row FOR UPDATE
		// for the rest of the transaction: two consents on one workspace
		// run one after the other, whoever the actors are.
		var live int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM mcp_connections
			WHERE tenant_id=$1 AND status IN ('pending','active') AND expires_at > now()`, tenant).Scan(&live); err != nil {
			return err
		}
		if live >= maxLiveMCPConnections {
			return ErrTooManyMCPConnections
		}
		err = tx.QueryRow(ctx, `INSERT INTO mcp_connections
			(tenant_id, request_id, api_key_id, created_by, client_name, redirect_host, device_count, reader_kid, status, expires_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'pending',$9) RETURNING id::text, created_at`,
			tenant, in.RequestID, out.APIKeyID, actor, in.ClientName, in.RedirectHost, in.DeviceCount, in.ReaderKID, in.ExpiresAt).
			Scan(&out.ID, &out.CreatedAt)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				// The key already carries a connection, or the request was
				// already answered. Either way this consent cannot be recorded.
				if strings.Contains(pgErr.ConstraintName, "api_key") {
					return ErrMCPKeyUnsuitable
				}
				return ErrMCPConnectionState
			}
			return err
		}
		return extendAPIKeyExpiryTx(ctx, tx, out.APIKeyID, tenant, in.ExpiresAt)
	})
	if err != nil {
		return MCPConnection{}, err
	}
	return out, nil
}

// List returns a workspace's connections, newest first, in every status.
// A revoked connection is part of the answer to "what has reached this
// archive", exactly like a revoked key.
func (m *MCPConnections) List(ctx context.Context, tenant uuid.UUID) ([]MCPConnection, error) {
	// Neither table carries a row-level policy, so the WHERE is the whole of
	// the isolation, as it is for api_keys.
	rows, err := m.pool.Query(ctx, `
		SELECT c.id::text, c.tenant_id::text, c.request_id, c.api_key_id, c.created_by, k.prefix,
		       c.client_name, c.redirect_host, c.device_count, c.reader_kid, c.status,
		       c.created_at, c.activated_at, c.revoked_at, c.last_seen_at, c.expires_at
		  FROM mcp_connections c JOIN api_keys k ON k.id = c.api_key_id
		 WHERE c.tenant_id = $1
		 ORDER BY c.created_at DESC, c.id DESC`, tenant)
	if err != nil {
		return nil, fmt.Errorf("store: list mcp connections: %w", err)
	}
	defer rows.Close()
	out := []MCPConnection{}
	for rows.Next() {
		var c MCPConnection
		if err := rows.Scan(&c.ID, &c.TenantID, &c.RequestID, &c.APIKeyID, &c.CreatedBy, &c.KeyPrefix,
			&c.ClientName, &c.RedirectHost, &c.DeviceCount, &c.ReaderKID, &c.Status,
			&c.CreatedAt, &c.ActivatedAt, &c.RevokedAt, &c.LastSeenAt, &c.ExpiresAt); err != nil {
			return nil, fmt.Errorf("store: list mcp connections: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list mcp connections: %w", err)
	}
	return out, nil
}

// Revoke ends a connection on a person's behalf: the row and its key, in one
// transaction, so there is no moment where the assistant's key still opens
// the archive after the console says it does not. Revoking an already ended
// connection is not an error; the id must exist in this workspace.
func (m *MCPConnections) Revoke(ctx context.Context, tenant, actor uuid.UUID, id string) error {
	return pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		if _, err := lockWorkspaceManager(ctx, tx, tenant, actor); err != nil {
			return err
		}
		var keyID uuid.UUID
		err := tx.QueryRow(ctx, `SELECT api_key_id FROM mcp_connections WHERE id=$1 AND tenant_id=$2 FOR UPDATE`,
			id, tenant).Scan(&keyID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrMCPConnectionNotFound
		}
		if err != nil {
			return err
		}
		return revokeMCPConnectionTx(ctx, tx, id, keyID)
	})
}

// revokeMCPConnectionTx marks a live connection revoked and revokes its key.
// Both statements are idempotent, so an ended connection stays ended.
func revokeMCPConnectionTx(ctx context.Context, tx pgx.Tx, id string, keyID uuid.UUID) error {
	if _, err := tx.Exec(ctx, `UPDATE mcp_connections SET status='revoked', revoked_at=now()
		WHERE id=$1 AND status IN ('pending','active')`, id); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE api_keys SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL`, keyID)
	return err
}

// DeleteFailed removes a pending connection whose bundle never reached the
// reader and revokes the key it was issued for. Nothing consented survives a
// failed hand-off: the person will be asked again.
//
// Called on the relay path with no tenant in hand; both tables are free of
// row-level policy, so a plain transaction is enough.
func (m *MCPConnections) DeleteFailed(ctx context.Context, id string) error {
	return m.inTx(ctx, func(tx pgx.Tx) error {
		var keyID uuid.UUID
		err := tx.QueryRow(ctx, `DELETE FROM mcp_connections WHERE id=$1 AND status='pending' RETURNING api_key_id`, id).Scan(&keyID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrMCPConnectionNotFound
		}
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE api_keys SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL`, keyID)
		return err
	})
}

// Status answers the reader's question about one connection and notes that
// it asked. An active connection past its deadline is reported expired even
// before the janitor has recorded it, so the reader never serves on a
// consent that has run out.
func (m *MCPConnections) Status(ctx context.Context, id string) (status string, expiresAt time.Time, err error) {
	err = m.pool.QueryRow(ctx, `UPDATE mcp_connections SET last_seen_at=now() WHERE id=$1
		RETURNING CASE WHEN status='active' AND expires_at <= now() THEN 'expired' ELSE status END, expires_at`, id).
		Scan(&status, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", time.Time{}, ErrMCPConnectionNotFound
	}
	if err != nil {
		return "", time.Time{}, fmt.Errorf("store: mcp connection status: %w", err)
	}
	return status, expiresAt, nil
}

// Activate records that the reader completed the handshake. Only a pending
// connection that has not run out can become active; anything else is
// ErrMCPConnectionState, and an unknown id is ErrMCPConnectionNotFound.
func (m *MCPConnections) Activate(ctx context.Context, id string) error {
	tag, err := m.pool.Exec(ctx, `UPDATE mcp_connections SET status='active', activated_at=now()
		WHERE id=$1 AND status='pending' AND expires_at > now()`, id)
	if err != nil {
		return fmt.Errorf("store: activate mcp connection: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	var exists bool
	if err := m.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM mcp_connections WHERE id=$1)`, id).Scan(&exists); err != nil {
		return fmt.Errorf("store: activate mcp connection: %w", err)
	}
	if !exists {
		return ErrMCPConnectionNotFound
	}
	return ErrMCPConnectionState
}

// RevokeByID ends a connection on the reader's behalf — a bad proof, a burnt
// request, a bundle that failed its checks — and revokes its key. Idempotent
// for a known connection; an unknown id is ErrMCPConnectionNotFound.
func (m *MCPConnections) RevokeByID(ctx context.Context, id string) error {
	return m.inTx(ctx, func(tx pgx.Tx) error {
		var keyID uuid.UUID
		err := tx.QueryRow(ctx, `SELECT api_key_id FROM mcp_connections WHERE id=$1 FOR UPDATE`, id).Scan(&keyID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrMCPConnectionNotFound
		}
		if err != nil {
			return err
		}
		return revokeMCPConnectionTx(ctx, tx, id, keyID)
	})
}

// inTx runs fn in a transaction with no tenant set. Only for the tables that
// carry no row-level policy; a policy-protected read here would come back
// empty rather than fail.
func (m *MCPConnections) inTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := m.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	//nolint:errcheck // deferred rollback is a no-op once committed
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
