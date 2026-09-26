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
	// Reader is the id of the reader that holds the connection: "hosted"
	// for the process on this host, or an attested reader's id.
	Reader string
	// ReaderMeasurement is what an attested reader declared when the
	// consent was prepared, "nitro:pcr0=<hex>;doc=<hex>"; empty for hosted.
	ReaderMeasurement string
	// Kind is KindMetadata or KindContent.
	Kind string
	// ServiceUserID is a content connection's own service account; nil for
	// metadata.
	ServiceUserID *uuid.UUID
	// KeyMode is how the reader holds a content connection's key
	// (KeyModeEphemeral); empty for metadata.
	KeyMode string
	// RevokeReason says why an ended connection ended; empty while live and
	// for connections ended before reasons were recorded.
	RevokeReason string
	// ResealedAt and RenewedAt are when the reader last lost a content
	// connection's key and when the person last renewed it.
	ResealedAt, RenewedAt *time.Time
}

// Connection kinds. A metadata connection reads through a key with no
// account and sees ciphertext only; a content connection reads as its own
// service account, whose grants are sealed to a key that lives in an
// attested reader.
const (
	KindMetadata = "metadata"
	KindContent  = "content"
	// KeyModeEphemeral keeps a content connection's key in the reader's
	// memory only: a restart loses it and the connection waits in 'reseal'
	// for the person to renew.
	KeyModeEphemeral = "ephemeral"
	// ContentConsentVersion is the consent text a content connection was
	// given under.
	ContentConsentVersion = 1
	// maxContentLifetime bounds a content consent: ninety days, plus an hour
	// for the console's clock and the moment it took to click.
	maxContentLifetime = 90*24*time.Hour + time.Hour
)

// Connection statuses. "Live" is pending, active or reseal: a connection
// that still holds its consent, and a place under the workspace's cap.
const (
	statusPending = "pending"
	statusActive  = "active"
	statusReseal  = "reseal"
	statusRevoked = "revoked"
	statusExpired = "expired"
)

// Why a connection ended, as the migration's CHECK lists them.
const (
	ReasonConsole         = "console"
	ReasonReader          = "reader"
	ReasonReuseDetected   = "reuse_detected"
	ReasonRelayFailed     = "relay_failed"
	ReasonPendingExpired  = "pending_expired"
	ReasonExpired         = "expired"
	ReasonServiceRemoved  = "service_removed"
	ReasonServiceDisabled = "service_disabled"
	ReasonMemberRemoved   = "member_removed"
	ReasonMemberDisabled  = "member_disabled"
	ReasonAccessLost      = "access_lost"
)

// HostedReader is the reader id of the process on this host, and the one
// every connection recorded before attested readers existed belongs to.
const HostedReader = "hosted"

// CreateMCPConnection is what a consent records.
type CreateMCPConnection struct {
	RequestID, KeyPrefix, ClientName, RedirectHost string
	DeviceCount                                    int
	ReaderKID                                      string
	// ExpiresAt is the lifetime the person chose. The key is extended to it.
	ExpiresAt time.Time
	// Reader is the reader the bundle goes to; empty means HostedReader.
	Reader string
	// ReaderMeasurement is recorded as given, and only for an attested
	// reader; empty stores NULL.
	ReaderMeasurement string
	// Kind is KindMetadata (the default when empty) or KindContent. The
	// fields below are for content only and must be zero for metadata.
	Kind string
	// ServiceUserID is the service account the content connection reads
	// as; the key must act as it.
	ServiceUserID uuid.UUID
	// KeyMode must be KeyModeEphemeral, ConsentVersion
	// ContentConsentVersion.
	KeyMode        string
	ConsentVersion int
	// ReaderPublicKey is the per-request key the reader attested when the
	// console prepared the consent; the service account's public key must
	// be exactly this.
	ReaderPublicKey []byte
}

// Create records a consent and promotes its key from the provisional deadline
// the console issued it with to the lifetime the person chose.
//
// The key must be this workspace's and the actor's own, read-only,
// restricted to named devices, be live and carry the short provisional
// deadline the console issues before a consent. For a metadata connection it
// carries no service account: anything else could reach more than metadata.
// For a content connection it acts as the connection's own service account,
// which checkContentServiceTx holds to the consent's shape. Anything else is
// a key another person issued for something else, or one that would outlive
// the consent, and is refused. Only an owner or admin may consent, and the
// check reads policy-protected tables, so the whole thing runs in a tenant
// transaction like every other permission change.
func (m *MCPConnections) Create(ctx context.Context, tenant, actor uuid.UUID, in CreateMCPConnection) (MCPConnection, error) {
	in.RequestID = strings.TrimSpace(in.RequestID)
	in.KeyPrefix = strings.TrimSpace(in.KeyPrefix)
	in.ClientName = strings.TrimSpace(in.ClientName)
	in.RedirectHost = strings.TrimSpace(in.RedirectHost)
	in.ReaderKID = strings.TrimSpace(in.ReaderKID)
	if in.Reader == "" {
		in.Reader = HostedReader
	}
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
	if in.Kind == "" {
		in.Kind = KindMetadata
	}
	content := in.Kind == KindContent
	switch {
	case in.Kind != KindMetadata && !content:
		return MCPConnection{}, fmt.Errorf("store: %q is not a connection kind", in.Kind)
	case !content && (in.ServiceUserID != uuid.Nil || in.KeyMode != "" || in.ConsentVersion != 0 || in.ReaderPublicKey != nil):
		return MCPConnection{}, errors.New("store: a metadata connection carries no service account, key mode or consent version")
	case content && (in.Reader == HostedReader || in.ServiceUserID == uuid.Nil || in.KeyMode != KeyModeEphemeral ||
		in.ConsentVersion != ContentConsentVersion || len(in.ReaderPublicKey) != 32):
		// The handler gates content to attested readers and checks the
		// body; this is the backstop.
		return MCPConnection{}, ErrMCPKeyUnsuitable
	case content && in.ExpiresAt.After(time.Now().Add(maxContentLifetime)):
		return MCPConnection{}, ErrInvalidExpiry
	}
	out := MCPConnection{
		TenantID: tenant.String(), RequestID: in.RequestID, CreatedBy: actor,
		KeyPrefix: in.KeyPrefix, ClientName: in.ClientName, RedirectHost: in.RedirectHost,
		DeviceCount: in.DeviceCount, ReaderKID: in.ReaderKID, Status: statusPending, ExpiresAt: in.ExpiresAt,
		Reader: in.Reader, ReaderMeasurement: in.ReaderMeasurement, Kind: in.Kind,
	}
	if content {
		service := in.ServiceUserID
		out.ServiceUserID, out.KeyMode = &service, in.KeyMode
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
		if KeyScope(scope) != ScopeRead || !restricted || revokedAt != nil ||
			expiresAt == nil || !expiresAt.After(now) || expiresAt.After(now.Add(maxProvisionalKeyLifetime)) {
			return ErrMCPKeyUnsuitable
		}
		if content {
			if actsAs == nil || *actsAs != in.ServiceUserID {
				return ErrMCPKeyUnsuitable
			}
			if err := checkContentServiceTx(ctx, tx, tenant, in.ServiceUserID, out.APIKeyID, in.ReaderPublicKey); err != nil {
				return err
			}
		} else if actsAs != nil {
			return ErrMCPKeyUnsuitable
		}
		// The count is safe against a concurrent consent because
		// lockWorkspaceManager holds the workspace's tenants row FOR UPDATE
		// for the rest of the transaction: two consents on one workspace
		// run one after the other, whoever the actors are.
		var live int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM mcp_connections
			WHERE tenant_id=$1 AND status IN ('pending','active','reseal') AND expires_at > now()`, tenant).Scan(&live); err != nil {
			return err
		}
		if live >= maxLiveMCPConnections {
			return ErrTooManyMCPConnections
		}
		var service *uuid.UUID
		var keyMode *string
		var consentVersion *int
		if content {
			service, keyMode, consentVersion = &in.ServiceUserID, &in.KeyMode, &in.ConsentVersion
		}
		err = tx.QueryRow(ctx, `INSERT INTO mcp_connections
			(tenant_id, request_id, api_key_id, created_by, client_name, redirect_host, device_count, reader_kid, status, expires_at,
			 reader, reader_measurement, kind, service_user_id, key_mode, consent_version)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'pending',$9,$10,NULLIF($11,''),$12,$13,$14,$15) RETURNING id::text, created_at`,
			tenant, in.RequestID, out.APIKeyID, actor, in.ClientName, in.RedirectHost, in.DeviceCount, in.ReaderKID, in.ExpiresAt,
			in.Reader, in.ReaderMeasurement, in.Kind, service, keyMode, consentVersion).
			Scan(&out.ID, &out.CreatedAt)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				// The key already carries a connection, or the request was
				// already answered. Either way this consent cannot be recorded.
				if strings.Contains(pgErr.ConstraintName, "api_key") || strings.Contains(pgErr.ConstraintName, "service_user") {
					return ErrMCPKeyUnsuitable
				}
				return ErrMCPConnectionState
			}
			return err
		}
		if err := extendAPIKeyExpiryTx(ctx, tx, out.APIKeyID, tenant, in.ExpiresAt); err != nil {
			return err
		}
		if content {
			// The service account lives exactly as long as the consent.
			return extendServiceMembershipTx(ctx, tx, tenant, in.ServiceUserID, in.ExpiresAt)
		}
		return nil
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
		       c.created_at, c.activated_at, c.revoked_at, c.last_seen_at, c.expires_at,
		       c.reader, coalesce(c.reader_measurement, ''), c.kind, c.service_user_id, coalesce(c.key_mode, ''),
		       coalesce(c.revoke_reason, ''), c.resealed_at, c.renewed_at
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
			&c.CreatedAt, &c.ActivatedAt, &c.RevokedAt, &c.LastSeenAt, &c.ExpiresAt,
			&c.Reader, &c.ReaderMeasurement, &c.Kind, &c.ServiceUserID, &c.KeyMode,
			&c.RevokeReason, &c.ResealedAt, &c.RenewedAt); err != nil {
			return nil, fmt.Errorf("store: list mcp connections: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list mcp connections: %w", err)
	}
	return out, nil
}

// Revoke ends a connection on a person's behalf: the row, its key and, for
// content, its service account, in one transaction, so there is no moment
// where the assistant's key still opens the archive after the console says it
// does not. Revoking an already ended connection is not an error; the id must
// exist in this workspace. It returns the reader that holds the connection,
// which is the one to tell.
func (m *MCPConnections) Revoke(ctx context.Context, tenant, actor uuid.UUID, id string) (reader string, err error) {
	err = pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		if _, err := lockWorkspaceManager(ctx, tx, tenant, actor); err != nil {
			return err
		}
		err := tx.QueryRow(ctx, `SELECT reader FROM mcp_connections WHERE id=$1 AND tenant_id=$2`, id, tenant).Scan(&reader)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrMCPConnectionNotFound
		}
		if err != nil {
			return err
		}
		_, err = endMCPConnectionTx(ctx, tx, tenant, id, statusRevoked, ReasonConsole)
		return err
	})
	if err != nil {
		return "", err
	}
	return reader, nil
}

// DeleteFailed removes a pending connection whose bundle never reached the
// reader, with its key and, for content, its service account. Nothing
// consented survives a failed hand-off: the person will be asked again.
//
// Called on the relay path with no tenant in hand. The tenant is read from
// the ledger, which carries no policy, and the cascade then runs in that
// tenant's transaction: grants and permissions force row-level security, and
// outside one a DELETE of them would remove nothing, silently.
func (m *MCPConnections) DeleteFailed(ctx context.Context, id string) error {
	tenant, err := m.tenantOf(ctx, "", id)
	if err != nil {
		return err
	}
	return pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		if err := lockWorkspaceAccess(ctx, tx, tenant); err != nil {
			return err
		}
		var status string
		err := tx.QueryRow(ctx, `SELECT status FROM mcp_connections WHERE id=$1 AND tenant_id=$2 FOR UPDATE`, id, tenant).Scan(&status)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && status != statusPending {
			return ErrMCPConnectionNotFound
		}
		if err != nil {
			return err
		}
		if _, err := endMCPConnectionTx(ctx, tx, tenant, id, statusRevoked, ReasonRelayFailed); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `DELETE FROM mcp_connections WHERE id=$1 AND tenant_id=$2`, id, tenant)
		return err
	})
}

// Activate records that the reader completed the handshake. Only a pending
// connection that has not run out can become active; anything else is
// ErrMCPConnectionState, and an unknown id, or another reader's, is
// ErrMCPConnectionNotFound.
func (m *MCPConnections) Activate(ctx context.Context, reader, id string) error {
	tag, err := m.pool.Exec(ctx, `UPDATE mcp_connections SET status='active', activated_at=now()
		WHERE id=$1 AND reader=$2 AND status='pending' AND expires_at > now()`, id, reader)
	if err != nil {
		return fmt.Errorf("store: activate mcp connection: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	var exists bool
	if err := m.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM mcp_connections WHERE id=$1 AND reader=$2)`, id, reader).Scan(&exists); err != nil {
		return fmt.Errorf("store: activate mcp connection: %w", err)
	}
	if !exists {
		return ErrMCPConnectionNotFound
	}
	return ErrMCPConnectionState
}

// RevokeByID ends a connection on the reader's behalf — a bad proof, a burnt
// request, a bundle that failed its checks, a token family that died — and
// revokes its key and, for content, its service account. reason is
// ReasonReader, or ReasonReuseDetected when the family died of a replayed
// token. The reader said so itself, so the row is marked notified at once.
// Idempotent for a known connection; an unknown id, or another reader's, is
// ErrMCPConnectionNotFound.
func (m *MCPConnections) RevokeByID(ctx context.Context, reader, id, reason string) error {
	if reason != ReasonReader && reason != ReasonReuseDetected {
		return fmt.Errorf("store: %q is not a reason a reader revokes for", reason)
	}
	return m.end(ctx, reader, id, statusRevoked, reason, true)
}
