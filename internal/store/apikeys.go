package store

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/argon2"

	"whatserver2/internal/pg"
)

// APIKeys issues and verifies API keys.
//
// A key is <prefix>.<secret>: the prefix is an indexed lookup selector and the
// secret is verified against an Argon2id hash. The v1 server instead iterated
// every key in a map doing a constant-time compare on each — each comparison
// was constant time, but the iteration was not, and the whole scheme fell over
// as soon as a tenant list grew.
type APIKeys struct{ pool *pgxpool.Pool }

// NewAPIKeys returns an API key store.
func NewAPIKeys(pool *pgxpool.Pool) *APIKeys { return &APIKeys{pool: pool} }

const (
	prefixLen = 8
	secretLen = 32
)

// KeyScope is what a key may do. Ordered: each level includes the previous.
type KeyScope string

const (
	// ScopeRead reaches the archive as ciphertext and nothing that touches
	// WhatsApp: list, subscribe, page, fetch sealed rows and attachments.
	ScopeRead KeyScope = "read"
	// ScopeSend adds outbound traffic: messages, edits, reactions, receipts,
	// attachments, typing. What a bot needs.
	ScopeSend KeyScope = "send"
	// ScopeFull adds what changes a device's behaviour: pairing, stopping,
	// history backfill, joining groups, receipt mode. What the CLI needs.
	ScopeFull KeyScope = "full"
)

// ParseKeyScope accepts the three names and nothing else.
func ParseKeyScope(s string) (KeyScope, error) {
	switch KeyScope(strings.ToLower(strings.TrimSpace(s))) {
	case ScopeRead:
		return ScopeRead, nil
	case ScopeSend:
		return ScopeSend, nil
	case ScopeFull:
		return ScopeFull, nil
	}
	return "", fmt.Errorf("store: scope must be read, send or full, not %q", s)
}

// Covers reports whether a key with this scope may do what need asks.
func (k KeyScope) Covers(need KeyScope) bool {
	return rank(k) >= rank(need)
}

func rank(k KeyScope) int {
	switch k {
	case ScopeRead:
		return 1
	case ScopeSend:
		return 2
	case ScopeFull:
		return 3
	}
	return 0
}

// Verified is what a presented key resolves to.
type Verified struct {
	AccessVersion int64
	ID            uuid.UUID
	TenantID      string
	Prefix        string
	Scope         KeyScope
	// ActsAs is the service account whose grants the key carries. Nil for a
	// key with no account, which reaches the archive as ciphertext only.
	ActsAs *uuid.UUID
}

// ErrInvalidKey covers every authentication failure: malformed, unknown,
// revoked or wrong secret. One error for all of them, deliberately — telling a
// caller which one it was hands them a probing oracle.
var ErrInvalidKey = errors.New("store: invalid api key")

// ErrInvalidKeyDevices covers an empty, duplicate, zero or unavailable selection.
// Foreign-workspace and missing devices deliberately produce the same error.
var ErrInvalidKeyDevices = errors.New("store: choose distinct devices in this workspace")

// ErrInvalidExpiry means a deadline in the past or further out than a key is
// allowed to live.
var ErrInvalidExpiry = errors.New("store: expiry must be in the future and within a year")

// maxKeyLifetime caps how far out a key's deadline may be set. A credential
// that "expires" in a decade is one with no expiry and a false sense of one.
const maxKeyLifetime = 365 * 24 * time.Hour

// A key's origin (0053's api_keys.origin): how it was issued. Keys issued
// before 0053 got theirs from api_key_class, once.
const (
	// OriginREST is a key a person asked for in any other shape: a
	// TokenPanel key, a REST client's.
	OriginREST = "rest"
	// OriginCLI is a key with no creator: whatserverd key and bootstrap.
	OriginCLI = "cli"
	// OriginMCPSetup is an MCP setup's key (setupShaped), or a connection's,
	// which was one.
	OriginMCPSetup = "mcp_setup"
	// OriginLegacyMCP is an old local MCP token, only from the backfill.
	OriginLegacyMCP = "legacy_mcp"
)

// SetupKeyName starts the name of every key an MCP setup asks for
// (the console's mcpSetup.ts).
const SetupKeyName = "MCP · "

// setupKeyLifetime is how far past its issue an MCP setup's key may
// expire: the setups ask 20 minutes and a consent binds at most 30
// (maxProvisionalKeyLifetime); a minute more for the clocks, as 0053's
// api_key_class has it (interval '31 minutes').
const setupKeyLifetime = maxProvisionalKeyLifetime + time.Minute

// setupShaped is an MCP setup's key (the plan's 7.3): read, a list of
// numbers, a deadline at most setupKeyLifetime after created (the key's
// created_at), and a name that starts with SetupKeyName. What it acts as
// (a provisional service, or none) the caller checks.
func setupShaped(name string, scope KeyScope, restricted bool, expiresAt *time.Time, created time.Time) bool {
	return strings.HasPrefix(name, SetupKeyName) && scope == ScopeRead && restricted &&
		expiresAt != nil && !expiresAt.After(created.Add(setupKeyLifetime))
}

// ErrTokensAreThePlatforms refuses what the platform's tokens replace
// while keys are narrowed (KeysNarrowed): a key in any shape but an MCP
// setup's, and a standing service account's invitation.
var ErrTokensAreThePlatforms = errors.New("store: this installation takes The Happie Co's API tokens; only an MCP setup's key is issued here")

// keysNarrowedSQL is the narrowing (the plan's 7.3): the token mode on, or
// a retirement of the keys made (key_retirements), which stays.
const keysNarrowedSQL = `SELECT EXISTS (SELECT 1 FROM contract_token_state WHERE mode = 'on')
	OR EXISTS (SELECT 1 FROM key_retirements)`

func keysNarrowedTx(ctx context.Context, tx pgx.Tx) (bool, error) {
	var narrowed bool
	err := tx.QueryRow(ctx, keysNarrowedSQL).Scan(&narrowed)
	return narrowed, err
}

// KeysNarrowed reports whether keys are narrowed: the token mode is on, or
// the keys were retired once. Then apikeys.create issues only an MCP
// setup's key, the command line's key and bootstrap refuse, a standing
// service account's invitation is refused, a setup's key works only
// through its connection, and discovery advertises tokens.platform.v1.
func (a *APIKeys) KeysNarrowed(ctx context.Context) (bool, error) {
	var narrowed bool
	err := a.pool.QueryRow(ctx, keysNarrowedSQL).Scan(&narrowed)
	return narrowed, err
}

// Argon2id parameters for verifying API keys.
//
// Much lighter than the parameters used for a user password, and on purpose:
// this runs on every authenticated request, and the input is 32 bytes of
// machine-generated randomness rather than something a human chose. There is no
// dictionary to attack, so the work factor is only there to blunt a database
// leak, not to withstand offline guessing of a weak secret.
const (
	argonTime    = 1
	argonMemory  = 19 * 1024 // 19 MiB, the OWASP floor
	argonThreads = 1
	argonKeyLen  = 32
	saltLen      = 16
)

// Issue creates a new API key with no record of who asked for it.
//
// Kept for the command line, where the answer is "whoever has the database
// password" and recording a user id would be a fiction.
func (a *APIKeys) Issue(ctx context.Context, tenantID, name string) (string, error) {
	return a.IssueScoped(ctx, tenantID, name, ScopeFull, nil)
}

// IssueFor creates a new API key and returns it in plaintext.
//
// This is the only moment the key exists in readable form; only its hash is
// stored. A lost key is reissued, never recovered.
//
// createdBy is the account that asked, when a person did. It is the difference
// between a list of keys and a list of keys somebody can account for — six
// machine credentials with no author is how a leaked one goes unnoticed.
func (a *APIKeys) IssueFor(ctx context.Context, tenantID, name string,
	createdBy *uuid.UUID) (string, error) {
	return a.IssueScoped(ctx, tenantID, name, ScopeFull, createdBy)
}

// IssueScoped creates a key that may do no more than scope allows.
func (a *APIKeys) IssueScoped(ctx context.Context, tenantID, name string, scope KeyScope,
	createdBy *uuid.UUID) (string, error) {
	return a.IssueActingAs(ctx, tenantID, name, scope, createdBy, nil)
}

// IssueActingAs creates a key that carries a service account's grants.
//
// The account is what decides which devices the key's holder can open; the
// scope is what decides what else it may do. A key acting as an account is
// refused devices the account has no grant for, exactly like a member.
func (a *APIKeys) IssueActingAs(ctx context.Context, tenantID, name string, scope KeyScope,
	createdBy, actsAs *uuid.UUID) (string, error) {
	return a.IssueActingAsForDevices(ctx, tenantID, name, scope, createdBy, actsAs, nil, nil)
}

// IssueActingAsForDevices atomically issues the credential and its device list.
// A nil selection preserves legacy unrestricted issuance. A supplied selection
// must be nonempty; removing its last device later leaves the key restricted.
//
// A nil expiresAt issues a key that lives until revoked. A deadline must be
// in the future and at most a year out; past that the key is refused as if
// it had never been valid, by the same query that refuses a revoked one.
//
// The key's origin is set here (0053's api_keys.origin): cli for a key with
// no creator, mcp_setup for an MCP setup's shape (setupShaped), else rest.
func (a *APIKeys) IssueActingAsForDevices(ctx context.Context, tenantID, name string, scope KeyScope,
	createdBy, actsAs *uuid.UUID, deviceIDs []uuid.UUID, expiresAt *time.Time) (string, error) {
	return a.issue(ctx, tenantID, name, scope, createdBy, actsAs, deviceIDs, expiresAt, false)
}

// IssueAsked is IssueActingAsForDevices for a key a person asks for
// (apikeys.create) or the operator does (whatserverd key and bootstrap,
// with no creator). While keys are narrowed (KeysNarrowed: tokens on, or a
// retirement made), it issues only an MCP setup's key, and refuses any
// other with ErrTokensAreThePlatforms, before anything is written.
func (a *APIKeys) IssueAsked(ctx context.Context, tenantID, name string, scope KeyScope,
	createdBy, actsAs *uuid.UUID, deviceIDs []uuid.UUID, expiresAt *time.Time) (string, error) {
	return a.issue(ctx, tenantID, name, scope, createdBy, actsAs, deviceIDs, expiresAt, true)
}

func (a *APIKeys) issue(ctx context.Context, tenantID, name string, scope KeyScope,
	createdBy, actsAs *uuid.UUID, deviceIDs []uuid.UUID, expiresAt *time.Time, asked bool) (string, error) {
	if _, err := ParseKeyScope(string(scope)); err != nil {
		return "", err
	}
	if expiresAt != nil {
		if err := checkKeyExpiry(*expiresAt); err != nil {
			return "", err
		}
	}
	if deviceIDs != nil {
		if len(deviceIDs) == 0 {
			return "", ErrInvalidKeyDevices
		}
		selection := make([]uuid.UUID, len(deviceIDs))
		copy(selection, deviceIDs)
		deviceIDs = selection
		seen := make(map[uuid.UUID]bool, len(deviceIDs))
		for _, id := range deviceIDs {
			if id == uuid.Nil || seen[id] {
				return "", ErrInvalidKeyDevices
			}
			seen[id] = true
		}
	}
	prefixBytes := make([]byte, prefixLen/2)
	secret := make([]byte, secretLen)
	if _, err := rand.Read(prefixBytes); err != nil {
		return "", fmt.Errorf("store: entropy: %w", err)
	}
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("store: entropy: %w", err)
	}
	prefix := hex.EncodeToString(prefixBytes)
	secretStr := base64.RawURLEncoding.EncodeToString(secret)

	hash, err := hashSecret(secretStr)
	if err != nil {
		return "", err
	}
	err = pg.InTenantTx(ctx, a.pool, tenantID, func(tx pgx.Tx) error {
		var status string
		// now() is the key's created_at, which 0053's api_key_class
		// measures a setup's deadline from.
		var created time.Time
		if err := tx.QueryRow(ctx, `SELECT status, now() FROM tenants WHERE id=$1 FOR SHARE`, tenantID).Scan(&status, &created); err != nil {
			return err
		}
		if status != "active" {
			return ErrMembershipForbidden
		}
		if createdBy != nil {
			var role string
			if err := tx.QueryRow(ctx, `SELECT m.role FROM workspace_memberships m JOIN users u ON u.id=m.user_id
				WHERE m.tenant_id=$1 AND m.user_id=$2 AND m.status='active' AND u.status='active' FOR SHARE OF m`, tenantID, createdBy).Scan(&role); err != nil {
				return ErrMembershipForbidden
			}
			if role != "owner" && role != "admin" {
				return ErrMembershipForbidden
			}
		}
		// A provisional service (a content consent's) has a deadline; a
		// standing one has none.
		provisional := true
		if actsAs != nil {
			if err := tx.QueryRow(ctx, `SELECT m.expires_at IS NOT NULL FROM workspace_memberships m JOIN users u ON u.id=m.user_id
				WHERE m.tenant_id=$1 AND m.user_id=$2 AND m.status='active' AND u.status='active' AND m.role='service' AND (m.expires_at IS NULL OR m.expires_at > now()) FOR SHARE OF m`, tenantID, actsAs).Scan(&provisional); err != nil {
				return ErrMembershipForbidden
			}
		}
		origin := OriginREST
		switch {
		case createdBy == nil:
			origin = OriginCLI
		case setupShaped(name, scope, deviceIDs != nil, expiresAt, created) && provisional:
			origin = OriginMCPSetup
		}
		if asked && origin != OriginMCPSetup {
			narrowed, err := keysNarrowedTx(ctx, tx)
			if err != nil {
				return err
			}
			if narrowed {
				return ErrTokensAreThePlatforms
			}
		}
		if deviceIDs != nil {
			// Lock ownership until the credential and its whitelist commit. A
			// concurrent transfer or deletion must not leave a stale selection.
			rows, err := tx.Query(ctx, `SELECT id FROM devices WHERE tenant_id=$1 AND id=ANY($2::uuid[]) ORDER BY id FOR SHARE`, tenantID, deviceIDs)
			if err != nil {
				return err
			}
			count := 0
			for rows.Next() {
				count++
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
			if count != len(deviceIDs) {
				return ErrInvalidKeyDevices
			}
		}
		var keyID uuid.UUID
		if err := tx.QueryRow(ctx, `INSERT INTO api_keys (tenant_id, prefix, key_hash, name, created_by, scope, acts_as, devices_restricted, expires_at, origin)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id`, tenantID, prefix, hash, name, createdBy, string(scope), actsAs, deviceIDs != nil, expiresAt, origin).Scan(&keyID); err != nil {
			return err
		}
		if deviceIDs != nil {
			_, err := tx.Exec(ctx, `INSERT INTO api_key_devices(api_key_id,device_id) SELECT $1,unnest($2::uuid[])`, keyID, deviceIDs)
			return err
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("store: issue api key: %w", err)
	}
	return prefix + "." + secretStr, nil
}

// checkKeyExpiry refuses a deadline that is already behind us or beyond the
// lifetime cap.
func checkKeyExpiry(at time.Time) error {
	now := time.Now()
	if !at.After(now) || at.After(now.Add(maxKeyLifetime)) {
		return ErrInvalidExpiry
	}
	return nil
}

// extendAPIKeyExpiryTx moves a key's deadline forward to until, and only
// forward: a key issued with a short provisional deadline is promoted to the
// lifetime a person consented to, never shortened or given a deadline it did
// not have. Anything else — unknown key, revoked, no deadline, or one already
// past until — is ErrInvalidKey, so the caller cannot tell them apart.
func extendAPIKeyExpiryTx(ctx context.Context, tx pgx.Tx, keyID, tenant uuid.UUID, until time.Time) error {
	tag, err := tx.Exec(ctx, `
		UPDATE api_keys SET expires_at = $3
		 WHERE id = $1 AND tenant_id = $2 AND revoked_at IS NULL
		   AND expires_at IS NOT NULL AND expires_at < $3`, keyID, tenant, until)
	if err != nil {
		return fmt.Errorf("store: extend api key expiry: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrInvalidKey
	}
	return nil
}

// Verify resolves a presented key to its tenant.
func (a *APIKeys) Verify(ctx context.Context, presented string) (tenantID string, err error) {
	v, err := a.VerifyScoped(ctx, presented)
	if err != nil {
		return "", err
	}
	return v.TenantID, nil
}

// VerifyScoped resolves a presented key to its tenant and what it may do.
func (a *APIKeys) VerifyScoped(ctx context.Context, presented string) (Verified, error) {
	return a.verify(ctx, presented, "")
}

// setupHeldSQL is a setup's key that no connection names, while keys are
// narrowed (keysNarrowedSQL): not a REST key (the plan's 7.3, L8). The
// setup asks for the key over the person's session, and the consent's
// connection names it before the key is first used.
const setupHeldSQL = ` AND NOT (api_keys.origin IS NOT DISTINCT FROM 'mcp_setup'
	AND NOT EXISTS (SELECT 1 FROM mcp_connections c WHERE c.api_key_id = api_keys.id)
	AND (EXISTS (SELECT 1 FROM contract_token_state WHERE mode = 'on') OR EXISTS (SELECT 1 FROM key_retirements)))`

// VerifyClient is VerifyScoped for REST, media, upload and the socket's
// hello: while keys are narrowed (KeysNarrowed), it also refuses a live
// setup's key (origin mcp_setup) that no MCP connection names, with
// ErrInvalidKey and the same work as an unknown key. Otherwise any admin
// could mint a renewable 30-minute read key. The MCP side keeps
// VerifyScoped, and checks a key against its connection.
func (a *APIKeys) VerifyClient(ctx context.Context, presented string) (Verified, error) {
	return a.verify(ctx, presented, setupHeldSQL)
}

func (a *APIKeys) verify(ctx context.Context, presented, held string) (Verified, error) {
	prefix, secret, ok := strings.Cut(presented, ".")
	if !ok || len(prefix) != prefixLen || secret == "" {
		return Verified{}, ErrInvalidKey
	}

	var tenantID, storedHash, scope string
	var id uuid.UUID
	var accessVersion int64
	var actsAs *uuid.UUID
	err := a.pool.QueryRow(ctx, `
		SELECT id, tenant_id::text, key_hash, scope, acts_as, access_version
		  FROM api_keys
		 WHERE prefix = $1 AND revoked_at IS NULL
		 AND (expires_at IS NULL OR expires_at > now())
		 AND EXISTS (SELECT 1 FROM tenants t WHERE t.id=api_keys.tenant_id AND t.status='active')`+held, prefix).Scan(&id, &tenantID, &storedHash, &scope, &actsAs, &accessVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		// Hash anyway so an unknown prefix costs the same time as a known one.
		// Without this the response time distinguishes the two, which is a free
		// oracle for enumerating valid prefixes. An expired key takes this same
		// path, on purpose: a faster answer for "known but past its deadline"
		// would be the same oracle by another door.
		//nolint:errcheck // the result is discarded on purpose; only the timing matters
		_, _ = hashSecret(secret)
		return Verified{}, ErrInvalidKey
	}
	if err != nil {
		return Verified{}, fmt.Errorf("store: look up api key: %w", err)
	}

	match, err := verifySecret(secret, storedHash)
	if err != nil {
		return Verified{}, err
	}
	if !match {
		return Verified{}, ErrInvalidKey
	}

	// Best effort and deliberately not in the request path's error handling:
	// a failed timestamp update must not fail an otherwise valid request.
	go func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		//nolint:errcheck // a failed timestamp update must not fail a valid request
		_, _ = a.pool.Exec(ctx, `UPDATE api_keys SET last_used_at = now() WHERE prefix = $1`, prefix)
	}()
	return Verified{AccessVersion: accessVersion, ID: id, TenantID: tenantID, Prefix: prefix, Scope: KeyScope(scope), ActsAs: actsAs}, nil
}

// Revoke disables a key by prefix.
func (a *APIKeys) Revoke(ctx context.Context, tenantID, prefix string) error {
	tag, err := a.pool.Exec(ctx, `
		UPDATE api_keys SET revoked_at = now()
		 WHERE prefix = $1 AND tenant_id = $2 AND revoked_at IS NULL`, prefix, tenantID)
	if err != nil {
		return fmt.Errorf("store: revoke api key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// APIKeyInfo is one key as an operator sees it: everything except the key.
type APIKeyInfo struct {
	Prefix string
	Name   string
	Scope  KeyScope
	// ActsAs is the service account's name, empty for a key with none.
	ActsAs string
	// ActsAsID identifies the service independently of its display name.
	ActsAsID *uuid.UUID
	// DeviceIDs lists remaining devices, including an explicit empty slice
	// after the final restricted device is deleted or transferred away.
	DeviceIDs         []string
	DevicesRestricted bool
	// CreatedBy is the address of the account that issued it, empty when it
	// came from the command line.
	CreatedBy  string
	CreatedAt  time.Time
	LastUsedAt time.Time
	RevokedAt  time.Time
	// ExpiresAt is the deadline the key was issued or extended to, nil for a
	// key that lives until revoked.
	ExpiresAt *time.Time
	// Origin is how the key was issued (OriginREST and the rest), empty
	// for one an older binary issued after 0053.
	Origin string
}

// List returns a tenant's keys, active ones first.
//
// Revoked keys stay in the list rather than disappearing. A key that was
// revoked last week is part of the answer to "what could have reached this
// archive", and hiding it turns an audit into a guess.
func (a *APIKeys) List(ctx context.Context, tenantID string) ([]APIKeyInfo, error) {
	// api_keys itself carries no row-level policy, because resolving a key to a
	// tenant is what decides the tenant in the first place — so the WHERE below
	// is the whole of the isolation for that half.
	//
	// The join is the other half, and it is why this runs in a tenant
	// transaction anyway: users IS policy-protected, and outside one every
	// email would come back NULL. A LEFT JOIN turns that into blank authorship
	// on every row rather than into an error, which is the quiet kind of wrong.
	var out []APIKeyInfo
	err := pg.InTenantTx(ctx, a.pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT k.prefix, k.name, k.scope, coalesce(creator.email, u.email, ''), coalesce(service.email, s.email, ''),
			       k.created_at, k.last_used_at, k.revoked_at, k.expires_at, k.acts_as, k.devices_restricted, coalesce(k.origin, ''),
			       ARRAY(SELECT x.device_id::text FROM api_key_devices x JOIN devices d ON d.id=x.device_id
			             WHERE x.api_key_id=k.id AND d.tenant_id=k.tenant_id ORDER BY x.device_id)
			  FROM api_keys k
			  LEFT JOIN users u ON u.id = k.created_by
			  LEFT JOIN users s ON s.id = k.acts_as
			  LEFT JOIN workspace_member_history creator ON creator.tenant_id=k.tenant_id AND creator.user_id=k.created_by
			  LEFT JOIN workspace_member_history service ON service.tenant_id=k.tenant_id AND service.user_id=k.acts_as
			 WHERE k.tenant_id = $1
			 ORDER BY (k.revoked_at IS NOT NULL), k.created_at DESC`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var k APIKeyInfo
			var used, revoked *time.Time
			var actsAs string
			if err := rows.Scan(&k.Prefix, &k.Name, &k.Scope, &k.CreatedBy, &actsAs,
				&k.CreatedAt, &used, &revoked, &k.ExpiresAt, &k.ActsAsID, &k.DevicesRestricted, &k.Origin, &k.DeviceIDs); err != nil {
				return err
			}
			if actsAs != "" {
				k.ActsAs = ServiceName(User{Role: RoleService, Email: actsAs})
			}
			if k.DeviceIDs == nil {
				k.DeviceIDs = []string{}
			}
			if used != nil {
				k.LastUsedAt = *used
			}
			if revoked != nil {
				k.RevokedAt = *revoked
			}
			out = append(out, k)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("store: list api keys: %w", err)
	}
	return out, nil
}

// hashSecret produces a PHC-formatted Argon2id hash.
func hashSecret(secret string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("store: entropy: %w", err)
	}
	sum := argon2.IDKey([]byte(secret), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(sum)), nil
}

// verifySecret checks a secret against a stored PHC hash. Parameters are read
// from the hash rather than assumed, so keys issued under older settings keep
// working after the cost factors are raised.
func verifySecret(secret, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, fmt.Errorf("store: unrecognised key hash format")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, fmt.Errorf("store: key hash version: %w", err)
	}
	var memory uint32
	var iterations uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &threads); err != nil {
		return false, fmt.Errorf("store: key hash parameters: %w", err)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("store: key hash salt: %w", err)
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("store: key hash digest: %w", err)
	}

	// The digest length comes from the stored hash we just decoded, so it is
	// bounded by what was written, not by anything a caller controls.
	//nolint:gosec // G115: length of a value read from our own column
	got := argon2.IDKey([]byte(secret), salt, iterations, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
