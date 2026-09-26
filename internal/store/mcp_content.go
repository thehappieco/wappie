package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"whatserver2/internal/pg"
)

// Content connections: an attested reader opens message text inside the
// enclave, reading as the connection's own service account.
//
// The account is created for the consent and never reused. Its public key is
// the per-connection key the browser verified in an attestation, so its
// grants open only inside that reader. Ending the connection, for whatever
// reason, removes the account's keys, grants, permissions and membership in
// the same transaction that ends the row: endMCPConnectionTx is the one way
// a connection ends, and every path goes through it.
//
// Every one of those tables but api_keys and mcp_connections forces
// row-level security, so the helper always runs in the connection's tenant
// transaction. Outside one, a DELETE of grants would remove nothing and
// report success.

// liveStatuses are the statuses that hold a consent.
func liveStatus(status string) bool {
	return status == statusPending || status == statusActive || status == statusReseal
}

// endMCPConnectionTx ends one connection: status (statusRevoked or
// statusExpired) and reason on the row if it is still live, its key, and for
// content removeServiceAccountTx. Idempotent: an ended row keeps its status
// and reason, and its key and service account are made sure of again. The
// caller holds pg.InTenantTx(tenant) and the tenants row lock
// (lockWorkspaceAccess or lockWorkspaceManager). ended reports whether this
// call changed the row's status.
func endMCPConnectionTx(ctx context.Context, tx pgx.Tx, tenant uuid.UUID, id, status, reason string) (ended bool, err error) {
	if status != statusRevoked && status != statusExpired {
		return false, fmt.Errorf("store: a connection ends revoked or expired, not %q", status)
	}
	var keyID uuid.UUID
	var kind, current string
	var service *uuid.UUID
	err = tx.QueryRow(ctx, `SELECT api_key_id, kind, status, service_user_id FROM mcp_connections
		WHERE id=$1 AND tenant_id=$2 FOR UPDATE`, id, tenant).Scan(&keyID, &kind, &current, &service)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrMCPConnectionNotFound
	}
	if err != nil {
		return false, err
	}
	if liveStatus(current) {
		if _, err := tx.Exec(ctx, `UPDATE mcp_connections
			SET status=$3, revoked_at=CASE WHEN $3='revoked' THEN now() ELSE revoked_at END, revoke_reason=$4
			WHERE id=$1 AND tenant_id=$2`, id, tenant, status, reason); err != nil {
			return false, err
		}
		ended = true
	}
	// An expired connection's key stopped working at the deadline it shares
	// with the connection; the key list says so. Anything else stops now.
	if _, err := tx.Exec(ctx, `UPDATE api_keys
		SET revoked_at = CASE WHEN $3 = 'expired' THEN least(coalesce(expires_at, now()), now()) ELSE now() END
		WHERE id=$1 AND tenant_id=$2 AND revoked_at IS NULL`, keyID, tenant, status); err != nil {
		return false, err
	}
	if kind == KindContent && service != nil {
		if err := removeServiceAccountTx(ctx, tx, tenant, *service); err != nil {
			return false, err
		}
	}
	return ended, nil
}

// endConnectionsOfMemberTx ends every live connection a member is part of,
// before the member loses access: the connections whose service account they
// are (service_removed or service_disabled) and the connections they
// consented to, of any kind (member_removed or member_disabled). A consent
// is given by a person; it does not outlive their place in the workspace.
// The caller holds the tenant transaction and the tenants row lock.
func endConnectionsOfMemberTx(ctx context.Context, tx pgx.Tx, tenant, member uuid.UUID, removed bool) error {
	rows, err := tx.Query(ctx, `SELECT id::text, service_user_id IS NOT DISTINCT FROM $2 FROM mcp_connections
		WHERE tenant_id=$1 AND status IN ('pending','active','reseal') AND (service_user_id=$2 OR created_by=$2)
		ORDER BY id`, tenant, member)
	if err != nil {
		return err
	}
	type target struct {
		id        string
		asService bool
	}
	var targets []target
	for rows.Next() {
		var t target
		if err := rows.Scan(&t.id, &t.asService); err != nil {
			rows.Close()
			return err
		}
		targets = append(targets, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, t := range targets {
		reason := ReasonMemberDisabled
		switch {
		case t.asService && removed:
			reason = ReasonServiceRemoved
		case t.asService:
			reason = ReasonServiceDisabled
		case removed:
			reason = ReasonMemberRemoved
		}
		if _, err := endMCPConnectionTx(ctx, tx, tenant, t.id, statusRevoked, reason); err != nil {
			return err
		}
	}
	return nil
}

// tenantOf reads a connection's workspace from the ledger, which carries no
// policy. reader "" matches any reader.
func (m *MCPConnections) tenantOf(ctx context.Context, reader, id string) (uuid.UUID, error) {
	var tenant uuid.UUID
	err := m.pool.QueryRow(ctx, `SELECT tenant_id FROM mcp_connections WHERE id=$1 AND ($2 = '' OR reader=$2)`, id, reader).Scan(&tenant)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrMCPConnectionNotFound
	}
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "22P02" {
			return uuid.Nil, ErrMCPConnectionNotFound
		}
		return uuid.Nil, fmt.Errorf("store: find mcp connection: %w", err)
	}
	return tenant, nil
}

// End ends a connection for callers with no tenant in hand: it reads the
// tenant from the ledger, then runs endMCPConnectionTx in that tenant's
// transaction. reader "" matches any reader. An unknown id, or another
// reader's, is ErrMCPConnectionNotFound.
func (m *MCPConnections) End(ctx context.Context, reader, id, status, reason string) error {
	return m.end(ctx, reader, id, status, reason, false)
}

// end is End, and notified marks the row as known to its reader: the reader
// asked for the end itself, or was just told in the answer to its question.
func (m *MCPConnections) end(ctx context.Context, reader, id, status, reason string, notified bool) error {
	tenant, err := m.tenantOf(ctx, reader, id)
	if err != nil {
		return err
	}
	return m.endInTenant(ctx, tenant, id, status, reason, notified)
}

func (m *MCPConnections) endInTenant(ctx context.Context, tenant uuid.UUID, id, status, reason string, notified bool) error {
	return pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		if err := lockWorkspaceAccess(ctx, tx, tenant); err != nil {
			return err
		}
		if _, err := endMCPConnectionTx(ctx, tx, tenant, id, status, reason); err != nil {
			return err
		}
		if notified {
			_, err := tx.Exec(ctx, `UPDATE mcp_connections SET reader_notified_at=coalesce(reader_notified_at, now())
				WHERE id=$1 AND tenant_id=$2`, id, tenant)
			return err
		}
		return nil
	})
}

// ---------------------------------------------------------------------------
// Standing
// ---------------------------------------------------------------------------

// StatusAnswer is what a reader is told about one of its connections.
type StatusAnswer struct {
	Status    string
	ExpiresAt time.Time
	Kind      string
	// ServiceUserID is the account a content connection reads as; the
	// reader wipes its key when this is not the account it holds a key for.
	ServiceUserID *uuid.UUID
}

// Status answers a reader's question about one of its connections and notes
// that it asked. Another reader's connection is not found: a reader learns
// about its own rows only.
//
// For a metadata connection, an active one past its deadline is reported
// expired even before the janitor has recorded it, so the reader never
// serves on a consent that has run out.
//
// A content connection is checked further, in its tenant's transaction, in
// this order: an ended row answers its status; one past its deadline is
// ended as expired; a revoked or expired key, or a missing, disabled or
// expired membership of the service account or of the person who consented,
// ends it (access_lost) and answers revoked; content not allowed for the
// workspace right now answers reseal, computed and never written, so the
// reader drops its key and the consent survives the switch; otherwise the
// row's status. contentAllowed nil allows nothing.
func (m *MCPConnections) Status(ctx context.Context, reader, id string, contentAllowed func(tenant uuid.UUID) bool) (StatusAnswer, error) {
	var a StatusAnswer
	var tenant uuid.UUID
	err := m.pool.QueryRow(ctx, `UPDATE mcp_connections SET last_seen_at=now() WHERE id=$1 AND reader=$2
		RETURNING tenant_id, status, expires_at, kind, service_user_id`, id, reader).
		Scan(&tenant, &a.Status, &a.ExpiresAt, &a.Kind, &a.ServiceUserID)
	if errors.Is(err, pgx.ErrNoRows) {
		return StatusAnswer{}, ErrMCPConnectionNotFound
	}
	if err != nil {
		return StatusAnswer{}, fmt.Errorf("store: mcp connection status: %w", err)
	}
	if !liveStatus(a.Status) {
		return a, nil
	}
	if a.Kind != KindContent {
		if a.Status == statusActive && !a.ExpiresAt.After(time.Now()) {
			a.Status = statusExpired
		}
		return a, nil
	}
	if !a.ExpiresAt.After(time.Now()) {
		// Checked before access: at the deadline the key runs out with the
		// connection, which is an expiry, not a lost access.
		if err := m.endInTenant(ctx, tenant, id, statusExpired, ReasonExpired, true); err != nil {
			return StatusAnswer{}, fmt.Errorf("store: expire mcp connection: %w", err)
		}
		a.Status = statusExpired
		return a, nil
	}
	var lost bool
	err = pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT NOT (
			EXISTS(SELECT 1 FROM api_keys k WHERE k.id=c.api_key_id AND k.revoked_at IS NULL
			       AND (k.expires_at IS NULL OR k.expires_at > now()))
			AND EXISTS(SELECT 1 FROM workspace_memberships m JOIN users u ON u.id=m.user_id
			       WHERE m.tenant_id=c.tenant_id AND m.user_id=c.service_user_id AND m.status='active' AND u.status='active'
			         AND (m.expires_at IS NULL OR m.expires_at > now()))
			AND EXISTS(SELECT 1 FROM workspace_memberships m JOIN users u ON u.id=m.user_id
			       WHERE m.tenant_id=c.tenant_id AND m.user_id=c.created_by AND m.status='active' AND u.status='active'
			         AND (m.expires_at IS NULL OR m.expires_at > now())))
			FROM mcp_connections c WHERE c.id=$1 AND c.tenant_id=$2`, id, tenant).Scan(&lost)
	})
	if err != nil {
		return StatusAnswer{}, fmt.Errorf("store: mcp connection access: %w", err)
	}
	if lost {
		if err := m.endInTenant(ctx, tenant, id, statusRevoked, ReasonAccessLost, true); err != nil {
			return StatusAnswer{}, fmt.Errorf("store: revoke mcp connection: %w", err)
		}
		a.Status = statusRevoked
		return a, nil
	}
	if contentAllowed == nil || !contentAllowed(tenant) {
		a.Status = statusReseal
	}
	return a, nil
}

// Reseal records that the reader holds no key for a content connection: it
// restarted, and the person renews in the console. The connection keeps its
// id, its consent and its token family. Only an active or resealed content
// connection inside its lifetime can be resealed; anything else is
// ErrMCPConnectionState, and an unknown id, or another reader's, is
// ErrMCPConnectionNotFound.
func (m *MCPConnections) Reseal(ctx context.Context, reader, id string) error {
	tag, err := m.pool.Exec(ctx, `UPDATE mcp_connections SET status='reseal', resealed_at=now()
		WHERE id=$1 AND reader=$2 AND kind='content' AND status IN ('active','reseal') AND expires_at > now()`, id, reader)
	if err != nil {
		return fmt.Errorf("store: reseal mcp connection: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	var exists bool
	if err := m.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM mcp_connections WHERE id=$1 AND reader=$2)`, id, reader).Scan(&exists); err != nil {
		return fmt.Errorf("store: reseal mcp connection: %w", err)
	}
	if !exists {
		return ErrMCPConnectionNotFound
	}
	return ErrMCPConnectionState
}

// ---------------------------------------------------------------------------
// The consent's shape
// ---------------------------------------------------------------------------

// checkContentServiceTx holds a content consent's service account to the
// shape the console builds, and refuses anything else with
// ErrMCPKeyUnsuitable:
//   - a service account, user and membership active, its membership
//     provisional (a deadline set, at most thirty minutes out), created in
//     the last thirty minutes, named by no connection, and whose public key
//     is the key the reader attested for this consent;
//   - read-only permissions on exactly the key's devices;
//   - exactly one grant per key device, at that device's current epoch,
//     whose archive key is not retired.
//
// The caller holds the tenant transaction and the tenants row lock.
func checkContentServiceTx(ctx context.Context, tx pgx.Tx, tenant, service, keyID uuid.UUID, readerPublicKey []byte) error {
	var memberRole, memberStatus, userRole, userStatus string
	var memberExpires *time.Time
	var created time.Time
	var publicKey []byte
	err := tx.QueryRow(ctx, `SELECT m.role, m.status, m.expires_at, u.role, u.status, u.created_at, u.public_key
		FROM workspace_memberships m JOIN users u ON u.id=m.user_id
		WHERE m.tenant_id=$1 AND m.user_id=$2 FOR UPDATE OF m`, tenant, service).
		Scan(&memberRole, &memberStatus, &memberExpires, &userRole, &userStatus, &created, &publicKey)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrMCPKeyUnsuitable
	}
	if err != nil {
		return err
	}
	now := time.Now()
	if memberRole != RoleService || userRole != RoleService || memberStatus != "active" || userStatus != "active" ||
		memberExpires == nil || !memberExpires.After(now) || memberExpires.After(now.Add(maxProvisionalKeyLifetime)) ||
		created.Before(now.Add(-maxProvisionalKeyLifetime)) ||
		len(readerPublicKey) != 32 || !bytes.Equal(publicKey, readerPublicKey) {
		return ErrMCPKeyUnsuitable
	}
	var named bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM mcp_connections WHERE service_user_id=$1)`, service).Scan(&named); err != nil {
		return err
	}
	if named {
		return ErrMCPKeyUnsuitable
	}
	devices, err := keyDevicesTx(ctx, tx, keyID)
	if err != nil {
		return err
	}
	if len(devices) == 0 {
		return ErrMCPKeyUnsuitable
	}

	rows, err := tx.Query(ctx, `SELECT device_id, can_read, can_send, can_manage FROM device_permissions
		WHERE tenant_id=$1 AND user_id=$2`, tenant, service)
	if err != nil {
		return err
	}
	permitted := map[uuid.UUID]bool{}
	suitable := true
	for rows.Next() {
		var device uuid.UUID
		var read, send, manage bool
		if err := rows.Scan(&device, &read, &send, &manage); err != nil {
			rows.Close()
			return err
		}
		if !devices[device] || !read || send || manage {
			suitable = false
		}
		permitted[device] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if !suitable || len(permitted) != len(devices) {
		return ErrMCPKeyUnsuitable
	}

	// A grant whose archive key row is missing drops out of the join, and
	// the count then refuses it.
	rows, err = tx.Query(ctx, `SELECT g.device_id, g.epoch = d.current_epoch AND k.retired_at IS NULL
		FROM device_key_grants g
		JOIN devices d ON d.id=g.device_id AND d.tenant_id=g.tenant_id
		JOIN device_archive_keys k ON k.device_id=g.device_id AND k.epoch=g.epoch
		WHERE g.tenant_id=$1 AND g.user_id=$2`, tenant, service)
	if err != nil {
		return err
	}
	granted := map[uuid.UUID]bool{}
	count := 0
	for rows.Next() {
		var device uuid.UUID
		var current bool
		if err := rows.Scan(&device, &current); err != nil {
			rows.Close()
			return err
		}
		if !devices[device] || !current {
			suitable = false
		}
		granted[device] = true
		count++
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	var all int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM device_key_grants WHERE tenant_id=$1 AND user_id=$2`, tenant, service).Scan(&all); err != nil {
		return err
	}
	if !suitable || count != all || count != len(devices) || len(granted) != len(devices) {
		return ErrMCPKeyUnsuitable
	}
	return nil
}

// keyDevicesTx is the set of devices a key is restricted to.
func keyDevicesTx(ctx context.Context, tx pgx.Tx, keyID uuid.UUID) (map[uuid.UUID]bool, error) {
	rows, err := tx.Query(ctx, `SELECT device_id FROM api_key_devices WHERE api_key_id=$1`, keyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[uuid.UUID]bool{}
	for rows.Next() {
		var device uuid.UUID
		if err := rows.Scan(&device); err != nil {
			return nil, err
		}
		out[device] = true
	}
	return out, rows.Err()
}

// extendServiceMembershipTx moves a connection service account's deadline to
// the connection's: provisional during the consent, the connection's
// lifetime after it. Only a membership that already carries a deadline is
// moved; a person's never gets one.
func extendServiceMembershipTx(ctx context.Context, tx pgx.Tx, tenant, service uuid.UUID, until time.Time) error {
	tag, err := tx.Exec(ctx, `UPDATE workspace_memberships SET expires_at=$3
		WHERE tenant_id=$1 AND user_id=$2 AND role='service' AND expires_at IS NOT NULL`, tenant, service, until)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrMCPKeyUnsuitable
	}
	return nil
}

// ---------------------------------------------------------------------------
// Renewal
// ---------------------------------------------------------------------------

// RenewMCPConnection is what a renewal records: the new key and service
// account, and what the reader attested for the renewal.
type RenewMCPConnection struct {
	KeyPrefix         string
	ServiceUserID     uuid.UUID
	ReaderKID         string
	ReaderMeasurement string
	// ReaderPublicKey is the renewal's attested key; the new service
	// account's public key must be exactly this.
	ReaderPublicKey []byte
}

// Renewable checks that a person may renew a content connection: it is this
// workspace's, of kind content, active or resealed and inside its lifetime,
// and the person consented to it and is still an owner or admin. The
// connection comes back with its reader, expiry and service account.
func (m *MCPConnections) Renewable(ctx context.Context, tenant, actor uuid.UUID, id string) (MCPConnection, error) {
	var out MCPConnection
	err := pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		if _, err := lockWorkspaceManager(ctx, tx, tenant, actor); err != nil {
			return err
		}
		var err error
		out, err = renewableTx(ctx, tx, tenant, actor, id)
		return err
	})
	return out, err
}

func renewableTx(ctx context.Context, tx pgx.Tx, tenant, actor uuid.UUID, id string) (MCPConnection, error) {
	out := MCPConnection{ID: id, TenantID: tenant.String()}
	err := tx.QueryRow(ctx, `SELECT api_key_id, created_by, status, expires_at, reader, kind, service_user_id, device_count
		FROM mcp_connections WHERE id=$1 AND tenant_id=$2 FOR UPDATE`, id, tenant).
		Scan(&out.APIKeyID, &out.CreatedBy, &out.Status, &out.ExpiresAt, &out.Reader, &out.Kind, &out.ServiceUserID, &out.DeviceCount)
	if errors.Is(err, pgx.ErrNoRows) {
		return MCPConnection{}, ErrMCPConnectionNotFound
	}
	if err != nil {
		return MCPConnection{}, err
	}
	switch {
	case out.Kind != KindContent || out.ServiceUserID == nil:
		return MCPConnection{}, ErrMCPConnectionNotFound
	case out.CreatedBy != actor:
		return MCPConnection{}, ErrMembershipForbidden
	case out.Status != statusActive && out.Status != statusReseal || !out.ExpiresAt.After(time.Now()):
		return MCPConnection{}, ErrMCPConnectionState
	}
	return out, nil
}

// errDryRun rolls back a transaction that only checked.
var errDryRun = errors.New("store: dry run")

// CheckRenewal runs every check Renew runs and changes nothing: it is asked
// before the reader is handed the renewal's bundle.
func (m *MCPConnections) CheckRenewal(ctx context.Context, tenant, actor uuid.UUID, id string, in RenewMCPConnection) error {
	_, err := m.renew(ctx, tenant, actor, id, in, false)
	return err
}

// Renew swaps a content connection's key and service account for the ones
// the person just made, in one transaction: the old service account and its
// key go, the row names the new ones and what the reader attested, and it is
// active again. The connection id, its expiry and the reader's token family
// stay. users.public_key is never updated: a new key is a new account.
//
// The new key and account are held to Create's rules, and the key must name
// exactly the devices the old one did. ErrMCPKeyUnsuitable otherwise.
func (m *MCPConnections) Renew(ctx context.Context, tenant, actor uuid.UUID, id string, in RenewMCPConnection) (MCPConnection, error) {
	return m.renew(ctx, tenant, actor, id, in, true)
}

func (m *MCPConnections) renew(ctx context.Context, tenant, actor uuid.UUID, id string, in RenewMCPConnection, apply bool) (MCPConnection, error) {
	in.KeyPrefix = strings.TrimSpace(in.KeyPrefix)
	in.ReaderKID = strings.TrimSpace(in.ReaderKID)
	if len(in.KeyPrefix) != prefixLen || in.ServiceUserID == uuid.Nil || in.ReaderKID == "" || len(in.ReaderPublicKey) != 32 {
		return MCPConnection{}, ErrMCPKeyUnsuitable
	}
	var out MCPConnection
	err := pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		if _, err := lockWorkspaceManager(ctx, tx, tenant, actor); err != nil {
			return err
		}
		conn, err := renewableTx(ctx, tx, tenant, actor, id)
		if err != nil {
			return err
		}
		if *conn.ServiceUserID == in.ServiceUserID {
			return ErrMCPKeyUnsuitable
		}
		var keyID uuid.UUID
		var scope string
		var restricted bool
		var actsAs *uuid.UUID
		var revokedAt, expiresAt *time.Time
		err = tx.QueryRow(ctx, `SELECT id, scope, devices_restricted, acts_as, revoked_at, expires_at
			FROM api_keys WHERE prefix=$1 AND tenant_id=$2 AND created_by=$3 FOR UPDATE`, in.KeyPrefix, tenant, actor).
			Scan(&keyID, &scope, &restricted, &actsAs, &revokedAt, &expiresAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		now := time.Now()
		if keyID == conn.APIKeyID || KeyScope(scope) != ScopeRead || !restricted || revokedAt != nil ||
			actsAs == nil || *actsAs != in.ServiceUserID ||
			expiresAt == nil || !expiresAt.After(now) || expiresAt.After(now.Add(maxProvisionalKeyLifetime)) {
			return ErrMCPKeyUnsuitable
		}
		oldDevices, err := keyDevicesTx(ctx, tx, conn.APIKeyID)
		if err != nil {
			return err
		}
		newDevices, err := keyDevicesTx(ctx, tx, keyID)
		if err != nil {
			return err
		}
		if len(oldDevices) != len(newDevices) {
			return ErrMCPKeyUnsuitable
		}
		for device := range newDevices {
			if !oldDevices[device] {
				return ErrMCPKeyUnsuitable
			}
		}
		if err := checkContentServiceTx(ctx, tx, tenant, in.ServiceUserID, keyID, in.ReaderPublicKey); err != nil {
			return err
		}
		if !apply {
			return errDryRun
		}

		// The old account and its key go first, so no moment has two.
		if err := removeServiceAccountTx(ctx, tx, tenant, *conn.ServiceUserID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE api_keys SET revoked_at=now() WHERE id=$1 AND tenant_id=$2 AND revoked_at IS NULL`,
			conn.APIKeyID, tenant); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE mcp_connections
			SET api_key_id=$3, service_user_id=$4, reader_kid=$5, reader_measurement=NULLIF($6,''),
			    status='active', renewed_at=now()
			WHERE id=$1 AND tenant_id=$2`, id, tenant, keyID, in.ServiceUserID, in.ReaderKID, in.ReaderMeasurement)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return ErrMCPKeyUnsuitable
			}
			return err
		}
		if err := extendAPIKeyExpiryTx(ctx, tx, keyID, tenant, conn.ExpiresAt); err != nil {
			return err
		}
		if err := extendServiceMembershipTx(ctx, tx, tenant, in.ServiceUserID, conn.ExpiresAt); err != nil {
			return err
		}
		service := in.ServiceUserID
		conn.APIKeyID, conn.ServiceUserID, conn.Status = keyID, &service, statusActive
		conn.ReaderKID, conn.ReaderMeasurement, conn.KeyPrefix = in.ReaderKID, in.ReaderMeasurement, in.KeyPrefix
		out = conn
		return nil
	})
	if errors.Is(err, errDryRun) {
		return MCPConnection{}, nil
	}
	if err != nil {
		return MCPConnection{}, err
	}
	return out, nil
}

// DiscardService removes a provisional service account a renewal made and
// the reader never took: its keys, grants, permissions and membership. An
// account a connection names, or one without a deadline, is not this
// method's to remove and is left alone with ErrMCPKeyUnsuitable.
func (m *MCPConnections) DiscardService(ctx context.Context, tenant, service uuid.UUID) error {
	return pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		if err := lockWorkspaceAccess(ctx, tx, tenant); err != nil {
			return err
		}
		var provisional, named bool
		err := tx.QueryRow(ctx, `SELECT
			EXISTS(SELECT 1 FROM workspace_memberships WHERE tenant_id=$1 AND user_id=$2 AND role='service' AND expires_at IS NOT NULL),
			EXISTS(SELECT 1 FROM mcp_connections WHERE service_user_id=$2)`, tenant, service).Scan(&provisional, &named)
		if err != nil {
			return err
		}
		if !provisional || named {
			return ErrMCPKeyUnsuitable
		}
		return removeServiceAccountTx(ctx, tx, tenant, service)
	})
}

// ---------------------------------------------------------------------------
// Revocation notices
// ---------------------------------------------------------------------------

// MarkNotified records that a reader confirmed it was told a connection
// ended. Another reader's row is left alone.
func (m *MCPConnections) MarkNotified(ctx context.Context, reader, id string) error {
	_, err := m.pool.Exec(ctx, `UPDATE mcp_connections SET reader_notified_at=now()
		WHERE id=$1 AND reader=$2 AND reader_notified_at IS NULL AND status IN ('revoked','expired')`, id, reader)
	if err != nil {
		return fmt.Errorf("store: mark mcp connection notified: %w", err)
	}
	return nil
}

// Unnotified lists up to limit of a reader's connections that ended in the
// last day and whose end the reader has not confirmed, oldest end first.
func (m *MCPConnections) Unnotified(ctx context.Context, reader string, limit int) ([]string, error) {
	rows, err := m.pool.Query(ctx, `SELECT id::text FROM mcp_connections
		WHERE reader=$1 AND reader_notified_at IS NULL AND status IN ('revoked','expired')
		  AND coalesce(revoked_at, expires_at) > now() - interval '1 day'
		ORDER BY coalesce(revoked_at, expires_at), id LIMIT $2`, reader, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list unnotified mcp connections: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("store: list unnotified mcp connections: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
