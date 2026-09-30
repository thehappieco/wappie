package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/pg"
)

// AI authorizations on the connections ledger: what a consent records beyond
// a content connection's, who may ask for a function, what a person may
// narrow, and what the reader reports.

// checkAIConsent holds a consent's ai_config to the consent it rides on: the
// same request, kid, service account and expiry, and at most AIDevicesMax
// numbers.
func checkAIConsent(c AIConfig, in CreateMCPConnection) error {
	switch {
	case c.Request != in.RequestID:
		return aiConfigError("ai_config.request must be the consent's request_id")
	case c.KID != in.ReaderKID:
		return aiConfigError("ai_config.kid must be the consent's kid")
	case c.ServiceUserID != in.ServiceUserID:
		return aiConfigError("ai_config.service_user_id must be the consent's service_user_id")
	case !c.ExpiresAt.Truncate(time.Second).Equal(in.ExpiresAt.Truncate(time.Second)):
		return aiConfigError("ai_config.expires_at must be the consent's expires_at")
	case len(c.Epochs) != in.DeviceCount:
		return aiConfigError("ai_config must cover exactly the key's numbers")
	}
	return nil
}

// checkAIConfigTx holds an ai_config to what it names: exactly the key's
// numbers, at most AIDevicesMax of them, and for each provider a live
// keychain item of the actor's for that provider. The caller holds the
// tenant transaction.
func checkAIConfigTx(ctx context.Context, tx pgx.Tx, tenant, actor, keyID uuid.UUID, c AIConfig) error {
	devices, err := keyDevicesTx(ctx, tx, keyID)
	if err != nil {
		return err
	}
	if len(devices) == 0 || len(devices) > AIDevicesMax || len(devices) != len(c.Epochs) {
		return aiConfigError("ai_config must cover exactly the key's numbers, at most %d", AIDevicesMax)
	}
	for device := range c.Epochs {
		if !devices[device] {
			return aiConfigError("ai_config must cover exactly the key's numbers, at most %d", AIDevicesMax)
		}
	}
	for provider, k := range c.Keys {
		var got string
		err := tx.QueryRow(ctx, `SELECT provider FROM ai_keychain
			WHERE id=$1 AND tenant_id=$2 AND user_id=$3 AND deleted_at IS NULL`, k.KeychainID, tenant, actor).Scan(&got)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && got != provider {
			return aiConfigError("the %s key must be one of your own keychain items for %s", provider, provider)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// aiRowConfigTx reads an AI row's configuration under the row's lock.
func aiRowConfigTx(ctx context.Context, tx pgx.Tx, tenant uuid.UUID, id string) (AIConfig, error) {
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT ai_config::text FROM mcp_connections WHERE id=$1 AND tenant_id=$2 AND kind='ai' FOR UPDATE`, id, tenant).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return AIConfig{}, ErrMCPConnectionNotFound
	}
	if err != nil {
		return AIConfig{}, err
	}
	return storedAIConfig(raw)
}

// storedAIConfig reads a configuration the ledger holds. Only a parsed one
// was ever written, so a failure here is a damaged row.
func storedAIConfig(raw []byte) (AIConfig, error) {
	c, err := ParseAIConfig(raw)
	if err != nil {
		return AIConfig{}, fmt.Errorf("store: a stored ai_config does not parse: %w", err)
	}
	return c, nil
}

// ---------------------------------------------------------------------------
// The reader's rows
// ---------------------------------------------------------------------------

// ReaderRow is what the reader's AI routes read of one of its connections:
// a media connection asking for AI results, or an AI authorization.
type ReaderRow struct {
	ID         string
	TenantID   uuid.UUID
	APIKeyID   uuid.UUID
	CreatedBy  uuid.UUID
	Kind       string
	Status     string
	ExpiresAt  time.Time
	Media      bool
	ConsentVer int
	// Config is an AI row's configuration; nil for any other kind.
	Config *AIConfig
	// Devices are the numbers the row's key is restricted to.
	Devices map[uuid.UUID]bool
}

// Active reports whether the row is active and inside its lifetime.
func (r ReaderRow) Active(now time.Time) bool {
	return r.Status == statusActive && r.ExpiresAt.After(now)
}

// Live reports whether the row still holds its consent.
func (r ReaderRow) Live(now time.Time) bool {
	return liveStatus(r.Status) && r.ExpiresAt.After(now)
}

// ReaderRow reads one of a reader's connections for its AI routes. Another
// reader's is ErrMCPConnectionNotFound.
func (m *MCPConnections) ReaderRow(ctx context.Context, reader, id string) (ReaderRow, error) {
	r := ReaderRow{ID: id}
	var raw []byte
	var version *int
	err := m.pool.QueryRow(ctx, `SELECT tenant_id, api_key_id, created_by, kind, status, expires_at, media, consent_version, ai_config::text
		FROM mcp_connections WHERE id=$1 AND reader=$2`, id, reader).
		Scan(&r.TenantID, &r.APIKeyID, &r.CreatedBy, &r.Kind, &r.Status, &r.ExpiresAt, &r.Media, &version, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return ReaderRow{}, ErrMCPConnectionNotFound
	}
	if err != nil {
		return ReaderRow{}, fmt.Errorf("store: read a reader's connection: %w", err)
	}
	if version != nil {
		r.ConsentVer = *version
	}
	if raw != nil {
		c, err := storedAIConfig(raw)
		if err != nil {
			return ReaderRow{}, err
		}
		r.Config = &c
	}
	err = pg.InTenantTx(ctx, m.pool, r.TenantID.String(), func(tx pgx.Tx) error {
		var err error
		r.Devices, err = keyDevicesTx(ctx, tx, r.APIKeyID)
		return err
	})
	if err != nil {
		return ReaderRow{}, fmt.Errorf("store: read a reader's connection: %w", err)
	}
	return r, nil
}

// ---------------------------------------------------------------------------
// Who may ask
// ---------------------------------------------------------------------------

// AIPolicy is what the switches say for a workspace right now: whether
// AIAllowed holds, and what is off everywhere.
type AIPolicy struct {
	Allowed                   bool
	OffFeatures, OffProviders []string
}

// AIPick is the authorization that answers a request for a function on a
// number, and the requester it is charged to. State is "active", or
// "reseal" for the requester's own authorization that only a renewal would
// bring back.
type AIPick struct {
	AuthorizationID string
	RequesterID     uuid.UUID
	State           string
}

// PickAIAuthorization decides which authorization answers a requester's
// request for a function on a number (docs/mcp-enclave.md §18.10). The
// candidates are the workspace's AI rows that are active, unexpired, not
// paused, cover the function on that number, and whose function and provider
// are not off, while policy.Allowed holds. The requester's own come first,
// newest first, unless their requesters are "console" and the origin is not;
// then another person's whose requesters are "readers", when the requester
// reads the number, oldest first. With none admitted, the requester's own
// rows in reseal that would otherwise be admitted answer "reseal", newest
// first; another person's never do. Nothing at all is ErrAINotEnabled.
func (m *MCPConnections) PickAIAuthorization(ctx context.Context, tenant, requester, device uuid.UUID, feature, origin string, policy AIPolicy) (AIPick, error) {
	if !policy.Allowed || !slices.Contains(AIFeatures, feature) || slices.Contains(policy.OffFeatures, feature) ||
		origin != AIOriginConsole && origin != AIOriginConnector {
		return AIPick{}, ErrAINotEnabled
	}
	type candidate struct {
		id        string
		createdBy uuid.UUID
		status    string
		config    AIConfig
	}
	var candidates []candidate
	var reads bool
	err := pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id::text, created_by, status, ai_config::text FROM mcp_connections
			WHERE tenant_id=$1 AND kind='ai' AND status IN ('active','reseal') AND expires_at > now()
			  AND ai_paused_at IS NULL AND NOT ($2 = ANY (ai_off)) AND ai_config->'features'->$3 ? $2
			ORDER BY created_at, id`, tenant, feature, device.String())
		if err != nil {
			return err
		}
		for rows.Next() {
			var c candidate
			var raw []byte
			if err := rows.Scan(&c.id, &c.createdBy, &c.status, &raw); err != nil {
				rows.Close()
				return err
			}
			if c.config, err = storedAIConfig(raw); err != nil {
				rows.Close()
				return err
			}
			candidates = append(candidates, c)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		p, err := devicePermissionTx(ctx, tx, tenant, requester, device)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		reads = err == nil && p.Allows(ActionRead)
		return nil
	})
	if err != nil {
		return AIPick{}, fmt.Errorf("store: pick an AI authorization: %w", err)
	}
	admitted := func(c candidate) bool {
		f, ok := c.config.Features[device][feature]
		if !ok || slices.Contains(policy.OffProviders, c.config.Functions[feature].Provider) {
			return false
		}
		if c.createdBy == requester {
			return f.Requesters != AIRequestersConsole || origin == AIOriginConsole
		}
		return f.Requesters == AIRequestersReaders && reads
	}
	// Oldest first as read: the requester's own are taken from the end.
	for i := len(candidates) - 1; i >= 0; i-- {
		if c := candidates[i]; c.status == statusActive && c.createdBy == requester && admitted(c) {
			return AIPick{AuthorizationID: c.id, RequesterID: requester, State: statusActive}, nil
		}
	}
	for _, c := range candidates {
		if c.status == statusActive && c.createdBy != requester && admitted(c) {
			return AIPick{AuthorizationID: c.id, RequesterID: requester, State: statusActive}, nil
		}
	}
	for i := len(candidates) - 1; i >= 0; i-- {
		if c := candidates[i]; c.status == statusReseal && c.createdBy == requester && admitted(c) {
			return AIPick{AuthorizationID: c.id, RequesterID: requester, State: statusReseal}, nil
		}
	}
	return AIPick{}, ErrAINotEnabled
}

// ---------------------------------------------------------------------------
// The console's list and controls
// ---------------------------------------------------------------------------

// AIAuthorization is one AI authorization as the console lists it.
type AIAuthorization struct {
	ID           string
	CreatedBy    uuid.UUID
	Status       string
	ExpiresAt    time.Time
	DeviceCount  int
	Config       json.RawMessage
	PausedAt     *time.Time
	Off          []string
	CapCents     *int
	Alerts       []AIAlert
	RevokeReason string
	CreatedAt    time.Time
	Reader       string
}

// AIAlert is something the reader reported about an authorization, kept
// until a renewal: a key rejected, a model gone, a quota spent.
type AIAlert struct {
	Code     string    `json:"code"`
	Feature  string    `json:"feature,omitempty"`
	Provider string    `json:"provider,omitempty"`
	At       time.Time `json:"at"`
}

// AI alert codes, as the reader reports them.
var AIAlertCodes = []string{"ai_key_rejected", "ai_model_unavailable", "ai_quota"}

const aiAuthorizationColumns = `id::text, created_by, status, expires_at, device_count, ai_config::text, ai_paused_at,
	ai_off, ai_cap_cents, ai_alerts::text, coalesce(revoke_reason, ''), created_at, reader`

func scanAIAuthorization(s interface{ Scan(...any) error }) (AIAuthorization, error) {
	var a AIAuthorization
	var config, alerts []byte
	if err := s.Scan(&a.ID, &a.CreatedBy, &a.Status, &a.ExpiresAt, &a.DeviceCount, &config, &a.PausedAt,
		&a.Off, &a.CapCents, &alerts, &a.RevokeReason, &a.CreatedAt, &a.Reader); err != nil {
		return AIAuthorization{}, err
	}
	a.Config = config
	if a.Off == nil {
		a.Off = []string{}
	}
	var byKey map[string]AIAlert
	if err := json.Unmarshal(alerts, &byKey); err != nil {
		return AIAuthorization{}, fmt.Errorf("store: stored ai_alerts: %w", err)
	}
	a.Alerts = []AIAlert{}
	for _, alert := range byKey {
		a.Alerts = append(a.Alerts, alert)
	}
	slices.SortFunc(a.Alerts, func(x, y AIAlert) int {
		return strings.Compare(x.Code+"|"+x.Provider+"|"+x.Feature, y.Code+"|"+y.Provider+"|"+y.Feature)
	})
	return a, nil
}

// AIAuthorizations lists a workspace's AI authorizations, newest first, in
// every status: all of them when all is set (an owner or an admin asking),
// otherwise the viewer's own.
func (m *MCPConnections) AIAuthorizations(ctx context.Context, tenant, viewer uuid.UUID, all bool) ([]AIAuthorization, error) {
	rows, err := m.pool.Query(ctx, `SELECT `+aiAuthorizationColumns+` FROM mcp_connections
		WHERE tenant_id=$1 AND kind='ai' AND ($2 OR created_by=$3)
		ORDER BY created_at DESC, id DESC`, tenant, all, viewer)
	if err != nil {
		return nil, fmt.Errorf("store: list AI authorizations: %w", err)
	}
	defer rows.Close()
	out := []AIAuthorization{}
	for rows.Next() {
		a, err := scanAIAuthorization(rows)
		if err != nil {
			return nil, fmt.Errorf("store: list AI authorizations: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// aiAuthorizationTx reads one AI authorization in the caller's transaction.
func aiAuthorizationTx(ctx context.Context, tx pgx.Tx, tenant uuid.UUID, id string) (AIAuthorization, error) {
	a, err := scanAIAuthorization(tx.QueryRow(ctx, `SELECT `+aiAuthorizationColumns+` FROM mcp_connections
		WHERE id=$1 AND tenant_id=$2 AND kind='ai'`, id, tenant))
	if errors.Is(err, pgx.ErrNoRows) {
		return AIAuthorization{}, ErrMCPConnectionNotFound
	}
	return a, err
}

// activeRoleTx is an actor's role in the workspace, ErrMembershipForbidden
// unless they are an active member of an active workspace. It takes the
// workspace's row lock, as every change to access does.
func activeRoleTx(ctx context.Context, tx pgx.Tx, tenant, actor uuid.UUID) (string, error) {
	var status string
	if err := tx.QueryRow(ctx, `SELECT status FROM tenants WHERE id=$1 FOR UPDATE`, tenant).Scan(&status); err != nil {
		return "", err
	}
	if status != "active" {
		return "", ErrMembershipForbidden
	}
	var role string
	err := tx.QueryRow(ctx, `SELECT m.role FROM workspace_memberships m JOIN users u ON u.id=m.user_id
		WHERE m.tenant_id=$1 AND m.user_id=$2 AND m.status='active' AND u.status='active'
		  AND (m.expires_at IS NULL OR m.expires_at > now())`, tenant, actor).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrMembershipForbidden
	}
	return role, err
}

func managerRole(role string) bool { return role == "owner" || role == "admin" }

// AIControls are a person's changes to an authorization: a pause, the
// functions switched off on it, and a monthly cap below the sealed budget.
// A nil field is left as it is; CapSet with a nil Cap removes the cap.
type AIControls struct {
	Paused *bool
	Off    *[]string
	CapSet bool
	Cap    *int
}

// SetAIControls applies a person's changes to one of the workspace's AI
// authorizations and returns it as listed. Pausing and narrowing (more
// functions off, a lower cap, or a cap where there was none) is for its
// creator, an owner or an admin; taking a pause off and undoing a narrowing
// is for its creator only. An ended authorization is ErrMCPConnectionState.
func (m *MCPConnections) SetAIControls(ctx context.Context, tenant, actor uuid.UUID, id string, in AIControls) (AIAuthorization, error) {
	if in.Off != nil {
		off := []string{}
		for _, feature := range *in.Off {
			if !slices.Contains(AIFeatures, feature) {
				return AIAuthorization{}, fmt.Errorf("%w: %q is not a function", ErrAIConfig, feature)
			}
			if !slices.Contains(off, feature) {
				off = append(off, feature)
			}
		}
		slices.SortFunc(off, func(a, b string) int { return slices.Index(AIFeatures, a) - slices.Index(AIFeatures, b) })
		in.Off = &off
	}
	if in.CapSet && in.Cap != nil && (*in.Cap < 1 || *in.Cap > aiMonthlyCentsMax) {
		return AIAuthorization{}, fmt.Errorf("%w: cap_cents must be 1 to %d", ErrAIConfig, aiMonthlyCentsMax)
	}
	var out AIAuthorization
	err := pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		role, err := activeRoleTx(ctx, tx, tenant, actor)
		if err != nil {
			return err
		}
		var createdBy uuid.UUID
		var status string
		var expires time.Time
		var paused bool
		var off []string
		var capCents *int
		err = tx.QueryRow(ctx, `SELECT created_by, status, expires_at, ai_paused_at IS NOT NULL, ai_off, ai_cap_cents
			FROM mcp_connections WHERE id=$1 AND tenant_id=$2 AND kind='ai' FOR UPDATE`, id, tenant).
			Scan(&createdBy, &status, &expires, &paused, &off, &capCents)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrMCPConnectionNotFound
		}
		if err != nil {
			return err
		}
		creator := createdBy == actor
		if !creator && !managerRole(role) {
			return ErrMembershipForbidden
		}
		if !liveStatus(status) || !expires.After(time.Now()) {
			return ErrMCPConnectionState
		}
		widens := in.Paused != nil && !*in.Paused && paused
		if in.Off != nil {
			for _, feature := range off {
				widens = widens || !slices.Contains(*in.Off, feature)
			}
		}
		if in.CapSet && capCents != nil && (in.Cap == nil || *in.Cap > *capCents) {
			widens = true
		}
		if widens && !creator {
			return ErrMembershipForbidden
		}
		if in.Paused != nil {
			if _, err := tx.Exec(ctx, `UPDATE mcp_connections SET ai_paused_at = CASE WHEN $3 THEN coalesce(ai_paused_at, now()) END
				WHERE id=$1 AND tenant_id=$2`, id, tenant, *in.Paused); err != nil {
				return err
			}
		}
		if in.Off != nil {
			if _, err := tx.Exec(ctx, `UPDATE mcp_connections SET ai_off=$3 WHERE id=$1 AND tenant_id=$2`, id, tenant, *in.Off); err != nil {
				return err
			}
		}
		if in.CapSet {
			if _, err := tx.Exec(ctx, `UPDATE mcp_connections SET ai_cap_cents=$3 WHERE id=$1 AND tenant_id=$2`, id, tenant, in.Cap); err != nil {
				return err
			}
		}
		out, err = aiAuthorizationTx(ctx, tx, tenant, id)
		return err
	})
	if err != nil {
		return AIAuthorization{}, err
	}
	return out, nil
}

// RevokeAI ends one of the workspace's AI authorizations on a person's
// behalf, reason console, with the same cascade as any connection: its
// creator, an owner or an admin may. With deleteResults its stored results
// go too. Ending an ended one is not an error. It returns the reader that
// holds it, which is the one to tell.
func (m *MCPConnections) RevokeAI(ctx context.Context, tenant, actor uuid.UUID, id string, deleteResults bool) (reader string, deleted int64, err error) {
	err = pg.InTenantTx(ctx, m.pool, tenant.String(), func(tx pgx.Tx) error {
		role, err := activeRoleTx(ctx, tx, tenant, actor)
		if err != nil {
			return err
		}
		var createdBy uuid.UUID
		err = tx.QueryRow(ctx, `SELECT reader, created_by FROM mcp_connections WHERE id=$1 AND tenant_id=$2 AND kind='ai'`, id, tenant).
			Scan(&reader, &createdBy)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrMCPConnectionNotFound
		}
		if err != nil {
			return err
		}
		if createdBy != actor && !managerRole(role) {
			return ErrMembershipForbidden
		}
		if _, err := endMCPConnectionTx(ctx, tx, tenant, id, statusRevoked, ReasonConsole); err != nil {
			return err
		}
		if deleteResults {
			tag, err := tx.Exec(ctx, `DELETE FROM ai_derived WHERE tenant_id=$1 AND authorization_id=$2`, tenant, id)
			if err != nil {
				return err
			}
			deleted = tag.RowsAffected()
		}
		return nil
	})
	if err != nil {
		return "", 0, err
	}
	return reader, deleted, nil
}

// RecordAIAlert keeps what the reader reported about one of its AI
// authorizations until the next renewal: one entry per code, provider and
// function, the latest time kept. The row must be the reader's, of kind ai
// and live.
func (m *MCPConnections) RecordAIAlert(ctx context.Context, reader, id string, alert AIAlert) error {
	if !slices.Contains(AIAlertCodes, alert.Code) {
		return fmt.Errorf("store: %q is not an alert", alert.Code)
	}
	value, err := json.Marshal(alert)
	if err != nil {
		return err
	}
	tag, err := m.pool.Exec(ctx, `UPDATE mcp_connections SET ai_alerts = ai_alerts || jsonb_build_object($3::text, $4::jsonb)
		WHERE id=$1 AND reader=$2 AND kind='ai' AND status IN ('pending','active','reseal')`,
		id, reader, alert.Code+"|"+alert.Provider+"|"+alert.Feature, string(value))
	if err != nil {
		return fmt.Errorf("store: record an AI alert: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrMCPConnectionNotFound
	}
	return nil
}
