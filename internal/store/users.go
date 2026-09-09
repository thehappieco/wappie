package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/pg"
)

// Users are the people who can open an archive.
//
// The password never reaches this server in any form. The browser derives a
// master key from it with Argon2id and splits that in two: one branch is the
// auth key, sent over TLS and stored here only as a slow hash; the other never
// leaves the browser and unwraps the user's private key. So a database dump
// yields a hash to attack and a wrapped key to attack, and no shortcut past
// either.
//
// The user's private key is what opens key grants, and the grants are what open
// devices. That chain is why losing a password is survivable — the recovery
// wrap holds the same private key under a printed code — and why losing both is
// not.
type Users struct{ pool *pgxpool.Pool }

func NewUsers(pool *pgxpool.Pool) *Users { return &Users{pool: pool} }

// KDFParams are the client-side Argon2id settings, stored so a browser can
// reproduce the derivation and so the cost can be raised later without
// stranding existing accounts.
type KDFParams struct {
	Algorithm   string `json:"alg"`
	Memory      uint32 `json:"m"`
	Time        uint32 `json:"t"`
	Parallelism uint8  `json:"p"`
}

// DefaultKDFParams is what a new account uses, and what a decoy challenge
// reports for an address that does not exist.
func DefaultKDFParams() KDFParams {
	return KDFParams{Algorithm: "argon2id", Memory: 64 * 1024, Time: 3, Parallelism: 1}
}

// User is one account. AuthHash never leaves this package.
type User struct {
	ID       uuid.UUID
	TenantID uuid.UUID
	Email    string

	KDFSalt   []byte
	KDFParams KDFParams

	// PublicKey is the account's X25519 public half. Key grants are sealed to
	// it, which is the only reason the server holds it.
	PublicKey []byte
	// WrappedUSK is the private half under a key derived from the password.
	// Opaque here: stored, returned, never opened.
	WrappedUSK []byte
	// RecoveryWrap is the same private key under a printed recovery code. Null
	// when the account declined one, which is worth surfacing in a UI — it is
	// one fewer way back.
	RecoveryWrap []byte
	// RecoveryUsable reports whether the code can prove itself: accounts
	// created before recovery_hash existed hold a wrap nothing can redeem
	// until a new code is generated.
	RecoveryUsable bool

	Role      string
	Status    string
	CreatedAt time.Time
}

// NewUser is what signing up supplies. Everything secret in it was produced by
// the browser; this server only stores what it is given.
type NewUser struct {
	TenantID  uuid.UUID
	Email     string
	AuthKey   string
	KDFSalt   []byte
	KDFParams KDFParams

	PublicKey    []byte
	WrappedUSK   []byte
	RecoveryWrap []byte
	// RecoveryProof is the branch of the recovery code that is sent here and
	// stored as a hash, so the wrap is handed back only to somebody holding
	// the code. Required whenever RecoveryWrap is: a wrap with no proof is
	// the write-only column this replaces.
	RecoveryProof string
	Role          string
}

var (
	// ErrEmailTaken means the address already has an account somewhere in this
	// installation. Addresses are unique across tenants so that signing in
	// needs an email and a password and nothing else.
	ErrEmailTaken = errors.New("store: that email already has an account")
	// ErrBadCredentials is deliberately the same for a wrong password and an
	// unknown address.
	ErrBadCredentials = errors.New("store: email or password is wrong")
	ErrNoSession      = errors.New("store: no such session")
	ErrInviteInvalid  = errors.New("store: the invite is not valid")
)

const saltLenUser = 16

// RoleService marks an account that belongs to a system rather than a
// person: a keypair, no password, reached through an API key that acts as it.
const RoleService = "service"

// serviceDomain is what a service account's synthetic address ends in. Every
// account needs a globally unique address because sign-in is by address
// alone; a service never signs in, but the uniqueness is a table constraint
// and the tenant id keeps two tenants' "erp" apart.
const serviceDomain = "@service."

var serviceNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ServiceName returns the name a service account was registered under, or
// the address unchanged for a person.
func ServiceName(u User) string {
	if u.Role != RoleService {
		return u.Email
	}
	name, _, _ := strings.Cut(u.Email, serviceDomain)
	return name
}

// CreateService registers a system's public key as an account.
//
// Nothing secret arrives: the system generated its keypair and keeps the
// private half. What the server stores is what a grant is sealed to.
func (u *Users) CreateService(ctx context.Context, tenant uuid.UUID, name string, pub []byte) (User, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	switch {
	case !serviceNameRE.MatchString(name):
		return User{}, errors.New("store: a service name is lowercase letters, digits, dots, " +
			"dashes or underscores, up to 64 characters")
	case len(pub) != 32:
		return User{}, errors.New("store: a public key is 32 bytes")
	}
	email := name + serviceDomain + tenant.String()
	out := User{TenantID: tenant, Email: email, PublicKey: pub, Role: RoleService, Status: "active"}
	err := pg.InTenantTx(ctx, u.pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			INSERT INTO users (tenant_id, email, public_key, role)
			VALUES ($1,$2,$3,$4)
			RETURNING id, created_at`, tenant, email, pub, RoleService).Scan(&out.ID, &out.CreatedAt)
	})
	if err != nil {
		if strings.Contains(err.Error(), "users_email_key") ||
			strings.Contains(err.Error(), "user_logins_pkey") ||
			strings.Contains(err.Error(), "users_tenant_id_email_key") {
			return User{}, ErrEmailTaken
		}
		return User{}, fmt.Errorf("store: create service account: %w", err)
	}
	return out, nil
}

// Create records a new account.
func (u *Users) Create(ctx context.Context, in NewUser) (User, error) {
	switch {
	case !strings.Contains(in.Email, "@"):
		return User{}, errors.New("store: that is not an email address")
	case len(in.KDFSalt) != saltLenUser:
		return User{}, fmt.Errorf("store: kdf salt must be %d bytes", saltLenUser)
	case len(in.PublicKey) != 32:
		return User{}, errors.New("store: a public key is 32 bytes")
	case len(in.WrappedUSK) == 0:
		return User{}, errors.New("store: an account with no wrapped key can never sign in")
	case in.AuthKey == "":
		return User{}, errors.New("store: no auth key")
	case (len(in.RecoveryWrap) > 0) != (in.RecoveryProof != ""):
		return User{}, errors.New("store: a recovery wrap and its proof come together or not at all")
	}
	role := in.Role
	if role == "" {
		role = "member"
	}

	hash, err := hashSecret(in.AuthKey)
	if err != nil {
		return User{}, err
	}
	var recoveryHash *string
	if in.RecoveryProof != "" {
		h, err := hashSecret(in.RecoveryProof)
		if err != nil {
			return User{}, err
		}
		recoveryHash = &h
	}
	params, err := json.Marshal(in.KDFParams)
	if err != nil {
		return User{}, err
	}

	email := normaliseEmail(in.Email)
	out := User{
		TenantID: in.TenantID, Email: email,
		KDFSalt: in.KDFSalt, KDFParams: in.KDFParams,
		PublicKey: in.PublicKey, WrappedUSK: in.WrappedUSK,
		RecoveryWrap: in.RecoveryWrap, RecoveryUsable: recoveryHash != nil,
		Role: role, Status: "active",
	}
	err = pg.InTenantTx(ctx, u.pool, in.TenantID.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			INSERT INTO users (tenant_id, email, auth_hash, kdf_salt, kdf_params,
			                   public_key, wrapped_usk, recovery_wrap, recovery_hash, role)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
			RETURNING id, created_at`,
			in.TenantID, email, hash, in.KDFSalt, params,
			in.PublicKey, in.WrappedUSK, in.RecoveryWrap, recoveryHash, role).Scan(&out.ID, &out.CreatedAt)
	})
	if err != nil {
		if strings.Contains(err.Error(), "users_email_key") ||
			strings.Contains(err.Error(), "user_logins_pkey") {
			return User{}, ErrEmailTaken
		}
		return User{}, fmt.Errorf("store: create user: %w", err)
	}
	return out, nil
}

// Challenge returns the client-side derivation parameters for an address.
//
// It answers for addresses that do not exist, with a salt derived from the
// address itself. Otherwise the shape of the reply would tell an unauthenticated
// caller which addresses have accounts, one request at a time.
func (u *Users) Challenge(ctx context.Context, email string) ([]byte, KDFParams, error) {
	email = normaliseEmail(email)

	var tenant uuid.UUID
	var userID uuid.UUID
	err := u.pool.QueryRow(ctx,
		`SELECT tenant_id, user_id FROM user_logins WHERE email = $1`, email).Scan(&tenant, &userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return decoySalt(email), DefaultKDFParams(), nil
	}
	if err != nil {
		return nil, KDFParams{}, fmt.Errorf("store: login challenge: %w", err)
	}

	var salt []byte
	var raw []byte
	err = pg.InTenantTx(ctx, u.pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT kdf_salt, kdf_params FROM users WHERE id = $1`, userID).Scan(&salt, &raw)
	})
	if err != nil {
		return nil, KDFParams{}, fmt.Errorf("store: login challenge: %w", err)
	}
	if salt == nil || raw == nil {
		// A service account: no password, so no derivation to reproduce.
		// Answered like an address with no account, for the same reason.
		return decoySalt(email), DefaultKDFParams(), nil
	}
	var params KDFParams
	if err := json.Unmarshal(raw, &params); err != nil {
		return nil, KDFParams{}, fmt.Errorf("store: kdf params: %w", err)
	}
	return salt, params, nil
}

// decoySalt is stable per address, so an attacker probing the same address
// twice cannot tell a made-up answer from a real one by watching it change.
func decoySalt(email string) []byte {
	sum := sha256.Sum256([]byte("whatserver2/login-decoy/" + email))
	return sum[:saltLenUser]
}

// Authenticate checks an auth key and returns the account.
func (u *Users) Authenticate(ctx context.Context, email, authKey string) (User, error) {
	email = normaliseEmail(email)

	var tenant, userID uuid.UUID
	err := u.pool.QueryRow(ctx,
		`SELECT tenant_id, user_id FROM user_logins WHERE email = $1`, email).Scan(&tenant, &userID)
	if errors.Is(err, pgx.ErrNoRows) {
		// Spend roughly the same work as a real verification would, so the
		// response time does not separate an unknown address from a wrong
		// password.
		//nolint:errcheck // the decoy hash is thrown away by design
		_, _ = hashSecret(authKey)
		return User{}, ErrBadCredentials
	}
	if err != nil {
		return User{}, fmt.Errorf("store: authenticate: %w", err)
	}

	user, err := u.verify(ctx, tenant, userID, email, authKey, "auth_hash")
	if err != nil {
		return User{}, err
	}
	return u.defaultWorkspace(ctx, user)
}

// OpenRecovery is Authenticate against the recovery code's proof instead of
// the password's. What it unlocks is the same account; what the caller does
// with it — read the recovery wrap, then replace everything — is authapi's.
func (u *Users) OpenRecovery(ctx context.Context, email, proof string) (User, error) {
	email = normaliseEmail(email)

	var tenant, userID uuid.UUID
	err := u.pool.QueryRow(ctx,
		`SELECT tenant_id, user_id FROM user_logins WHERE email = $1`, email).Scan(&tenant, &userID)
	if errors.Is(err, pgx.ErrNoRows) {
		//nolint:errcheck // the decoy hash is thrown away by design
		_, _ = hashSecret(proof)
		return User{}, ErrBadCredentials
	}
	if err != nil {
		return User{}, fmt.Errorf("store: open recovery: %w", err)
	}
	user, err := u.verify(ctx, tenant, userID, email, proof, "recovery_hash")
	if err != nil {
		return User{}, err
	}
	return u.defaultWorkspace(ctx, user)
}

// verify loads an account and checks a secret against one of its two hashes.
//
// column is one of two literals chosen here, never a caller's string; it is
// interpolated only because a column name cannot be a bind parameter.
func (u *Users) verify(ctx context.Context, tenant, userID uuid.UUID, email, secret, column string) (User, error) {
	if column != "auth_hash" && column != "recovery_hash" {
		return User{}, fmt.Errorf("store: verify: unknown column %q", column)
	}
	var stored *string
	out := User{ID: userID, TenantID: tenant, Email: email}
	var raw []byte
	err := pg.InTenantTx(ctx, u.pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT `+column+`, kdf_salt, kdf_params, public_key, wrapped_usk,
			       recovery_wrap, recovery_hash IS NOT NULL, role, status, created_at
			  FROM users WHERE id = $1`, userID).Scan(&stored, &out.KDFSalt, &raw,
			&out.PublicKey, &out.WrappedUSK, &out.RecoveryWrap, &out.RecoveryUsable,
			&out.Role, &out.Status, &out.CreatedAt)
	})
	if err != nil {
		return User{}, fmt.Errorf("store: authenticate: %w", err)
	}
	if out.Status != "active" || stored == nil {
		// No hash to check against — an account that never set a recovery
		// code — costs the same as a wrong one, for the same reason the
		// unknown-address branch does.
		//nolint:errcheck // the decoy hash is thrown away by design
		_, _ = hashSecret(secret)
		return User{}, ErrBadCredentials
	}
	ok, err := verifySecret(secret, *stored)
	if err != nil {
		return User{}, err
	}
	if !ok {
		return User{}, ErrBadCredentials
	}
	if raw != nil {
		if err := json.Unmarshal(raw, &out.KDFParams); err != nil {
			return User{}, fmt.Errorf("store: kdf params: %w", err)
		}
	}
	return out, nil
}

// Rekey is what a password change or a recovery replaces, all at once.
//
// Everything the password protected is re-derived by the browser: a new salt,
// a new auth branch, the private key wrapped again. The recovery pair is
// optional on a password change and required on a recovery — the old code was
// just typed into a browser, so it is spent.
type Rekey struct {
	// Account recovery invalidates every passkey; ordinary password changes do not.
	RevokePasskeys bool
	AuthKey        string
	KDFSalt        []byte
	KDFParams      KDFParams
	// WrappedUSK is the same private key as before, under the new password.
	// The public key does not change: grants sealed to it keep opening.
	WrappedUSK    []byte
	RecoveryWrap  []byte
	RecoveryProof string
}

// Rekey replaces the password-derived material and ends every session.
//
// The sessions go because the reason somebody changes a password is usually
// that they no longer trust where the old one was typed. A session issued
// under the old password surviving the change is that distrust ignored.
func (u *Users) Rekey(ctx context.Context, tenant, userID uuid.UUID, in Rekey) error {
	if _, err := u.Get(ctx, tenant, userID); err != nil {
		return err
	}
	home, err := u.identityTenant(ctx, userID)
	if err != nil {
		return err
	}
	tenant = home
	switch {
	case in.AuthKey == "":
		return errors.New("store: no auth key")
	case len(in.KDFSalt) != saltLenUser:
		return fmt.Errorf("store: kdf salt must be %d bytes", saltLenUser)
	case len(in.WrappedUSK) == 0:
		return errors.New("store: an account with no wrapped key can never sign in")
	case (len(in.RecoveryWrap) > 0) != (in.RecoveryProof != ""):
		return errors.New("store: a recovery wrap and its proof come together or not at all")
	}
	hash, err := hashSecret(in.AuthKey)
	if err != nil {
		return err
	}
	params, err := json.Marshal(in.KDFParams)
	if err != nil {
		return err
	}
	var recoveryHash *string
	if in.RecoveryProof != "" {
		h, err := hashSecret(in.RecoveryProof)
		if err != nil {
			return err
		}
		recoveryHash = &h
	}
	err = pg.InTenantTx(ctx, u.pool, tenant.String(), func(tx pgx.Tx) error {
		if err := lockPasskeyRegistration(ctx, tx, userID); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `
			UPDATE users
			   SET auth_hash = $2, kdf_salt = $3, kdf_params = $4, wrapped_usk = $5,
			       recovery_wrap = CASE WHEN $6::bytea IS NULL THEN recovery_wrap ELSE $6 END,
			       recovery_hash = CASE WHEN $7::text IS NULL THEN recovery_hash ELSE $7 END,
			       updated_at = now()
			 WHERE id = $1 AND status = 'active'`,
			userID, hash, in.KDFSalt, params, in.WrappedUSK, nilIfEmpty(in.RecoveryWrap), recoveryHash)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if in.RevokePasskeys {
			if _, err = tx.Exec(ctx, `SELECT set_config('app.user_id',$1,true)`, userID.String()); err != nil {
				return err
			}
			if _, err = tx.Exec(ctx, `UPDATE user_passkeys SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL`, userID); err != nil {
				return err
			}
			if _, err = tx.Exec(ctx, `DELETE FROM passkey_challenges WHERE user_id=$1`, userID); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, `UPDATE sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL`, userID)
		return err
	})
	if err != nil {
		return fmt.Errorf("store: rekey: %w", err)
	}
	return nil
}

// Rewrap replaces the wrapped private key and nothing else.
//
// For a client that re-wraps the same key under the same password in a newer
// format. No session is touched: nothing a session was issued against has
// changed, and a silent upgrade that signed everybody out would be noticed
// for the wrong reason.
func (u *Users) Rewrap(ctx context.Context, tenant, userID uuid.UUID, wrapped []byte) error {
	if _, err := u.Get(ctx, tenant, userID); err != nil {
		return err
	}
	home, err := u.identityTenant(ctx, userID)
	if err != nil {
		return err
	}
	tenant = home
	if len(wrapped) == 0 {
		return errors.New("store: an account with no wrapped key can never sign in")
	}
	err = pg.InTenantTx(ctx, u.pool, tenant.String(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE users SET wrapped_usk = $2, updated_at = now()
			 WHERE id = $1 AND status = 'active'`, userID, wrapped)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("store: rewrap: %w", err)
	}
	return nil
}

// SetRecovery records a new recovery code for an account that is signed in:
// one that never had a usable code, or one rotating it.
func (u *Users) SetRecovery(ctx context.Context, tenant, userID uuid.UUID, wrap []byte, proof string) error {
	if _, err := u.Get(ctx, tenant, userID); err != nil {
		return err
	}
	home, err := u.identityTenant(ctx, userID)
	if err != nil {
		return err
	}
	tenant = home
	if len(wrap) == 0 || proof == "" {
		return errors.New("store: a recovery wrap and its proof come together")
	}
	hash, err := hashSecret(proof)
	if err != nil {
		return err
	}
	err = pg.InTenantTx(ctx, u.pool, tenant.String(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE users SET recovery_wrap = $2, recovery_hash = $3, updated_at = now()
			 WHERE id = $1 AND status = 'active'`, userID, wrap, hash)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("store: set recovery: %w", err)
	}
	return nil
}

// RevokeAllSessions signs an account out everywhere.
func (u *Users) RevokeAllSessions(ctx context.Context, userID uuid.UUID) error {
	if err := pg.InTx(ctx, u.pool, func(tx pgx.Tx) error {
		if err := lockPasskeyRegistration(ctx, tx, userID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`, userID)
		return err
	}); err != nil {
		return fmt.Errorf("store: revoke sessions: %w", err)
	}
	return nil
}

func nilIfEmpty(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}

// Get loads one account. The auth hash is not among the columns read: nothing
// outside Authenticate has any use for it.
func (u *Users) Get(ctx context.Context, tenant, id uuid.UUID) (User, error) {
	if tenant == uuid.Nil {
		return u.identity(ctx, id)
	}
	out := User{ID: id, TenantID: tenant}
	var raw []byte
	err := pg.InTenantTx(ctx, u.pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT u.email, u.kdf_salt, u.kdf_params, u.public_key, u.wrapped_usk,
			       u.recovery_wrap, u.recovery_hash IS NOT NULL, m.role, u.status, u.created_at
			  FROM users u JOIN workspace_memberships m ON m.user_id = u.id
			 WHERE u.id = $1 AND m.tenant_id = $2 AND m.status = 'active'`, id, tenant).Scan(&out.Email, &out.KDFSalt, &raw,
			&out.PublicKey, &out.WrappedUSK, &out.RecoveryWrap, &out.RecoveryUsable,
			&out.Role, &out.Status, &out.CreatedAt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("store: get user: %w", err)
	}
	if raw != nil {
		if err := json.Unmarshal(raw, &out.KDFParams); err != nil {
			return User{}, fmt.Errorf("store: kdf params: %w", err)
		}
	}
	return out, nil
}

// List returns a tenant's accounts, without any secret material.
func (u *Users) List(ctx context.Context, tenant uuid.UUID) ([]User, error) {
	var out []User
	err := pg.InTenantTx(ctx, u.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT u.id, u.email, u.public_key, m.role, u.status, m.created_at,
			       u.recovery_wrap IS NOT NULL AND u.recovery_hash IS NOT NULL
			  FROM users u JOIN workspace_memberships m ON m.user_id = u.id
			 WHERE u.status = 'active' AND m.status = 'active' AND m.tenant_id = $1
			 ORDER BY m.created_at`, tenant)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			user := User{TenantID: tenant}
			var hasRecovery bool
			if err := rows.Scan(&user.ID, &user.Email, &user.PublicKey,
				&user.Role, &user.Status, &user.CreatedAt, &hasRecovery); err != nil {
				return err
			}
			if hasRecovery {
				// Presence only. The wrap itself is never listed.
				user.RecoveryWrap = []byte{}
				user.RecoveryUsable = true
			}
			out = append(out, user)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("store: list users: %w", err)
	}
	return out, nil
}

// Count reports how many accounts a tenant has, for the bootstrap check.
func (u *Users) Count(ctx context.Context, tenant uuid.UUID) (int, error) {
	var n int
	err := pg.InTenantTx(ctx, u.pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM workspace_memberships WHERE tenant_id = $1 AND status = 'active'`, tenant).Scan(&n)
	})
	return n, err
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

// Session is a signed-in browser.
type Session struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	TenantID  uuid.UUID
	ExpiresAt time.Time
	PasskeyID uuid.UUID
	FamilyID  uuid.UUID
}

// SessionTTL is how long a sign-in lasts without further proof.
const SessionTTL = 14 * 24 * time.Hour

// StartSession issues a token. The token is returned once and stored hashed.
func (u *Users) StartSession(ctx context.Context, user User, userAgent string) (string, Session, error) {
	return u.startSession(ctx, user, userAgent, time.Now().Add(SessionTTL), uuid.Nil, nil)
}

func (u *Users) StartPasskeySession(ctx context.Context, user User, userAgent string, passkeyID uuid.UUID) (string, Session, error) {
	if passkeyID == uuid.Nil {
		return "", Session{}, ErrNoSession
	}
	return u.startSession(ctx, user, userAgent, time.Now().Add(SessionTTL), passkeyID, nil)
}

// StartWorkspaceSession does not extend the authentication lifetime of the
// source session. Selecting a space is not another proof of the password.
func (u *Users) StartWorkspaceSession(ctx context.Context, user User, userAgent string, source Session) (string, Session, error) {
	if source.ID == uuid.Nil || source.UserID != user.ID {
		return "", Session{}, ErrNoSession
	}
	// The source is re-read while locked. A previously authenticated request
	// cannot mint a new token after another tab has finished signing out.
	return u.startSession(ctx, user, userAgent, time.Time{}, uuid.Nil, &source)
}

func (u *Users) startSession(ctx context.Context, user User, userAgent string, expiresAt time.Time, passkeyID uuid.UUID, source *Session) (string, Session, error) {
	current, err := u.Get(ctx, user.TenantID, user.ID)
	if errors.Is(err, ErrNotFound) {
		return "", Session{}, ErrNoSession
	}
	if err != nil {
		return "", Session{}, err
	}
	if current.Status != "active" || current.Role == RoleService {
		return "", Session{}, ErrNoSession
	}
	var active bool
	if user.TenantID != uuid.Nil {
		if err := u.pool.QueryRow(ctx, `SELECT status = 'active' FROM tenants WHERE id = $1`, user.TenantID).Scan(&active); err != nil {
			return "", Session{}, err
		}
		if !active {
			return "", Session{}, ErrNoSession
		}
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", Session{}, fmt.Errorf("store: entropy: %w", err)
	}
	sum := sha256.Sum256(raw)

	s := Session{UserID: user.ID, TenantID: user.TenantID, ExpiresAt: expiresAt, PasskeyID: passkeyID}
	err = u.inIdentity(ctx, user.ID, func(tx pgx.Tx) error {
		// Recovery uses this same user lock before touching credentials or
		// sessions. Keep the order user -> family -> passkey -> source session.
		if err := lockPasskeyRegistration(ctx, tx, user.ID); err != nil {
			return err
		}
		if source == nil {
			var err error
			s.FamilyID, err = uuid.NewV7()
			if err != nil {
				return err
			}
		} else {
			if err := tx.QueryRow(ctx, `SELECT family_id, coalesce(passkey_id,'00000000-0000-0000-0000-000000000000'::uuid), expires_at
				FROM sessions WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at>clock_timestamp()`, source.ID, user.ID).
				Scan(&s.FamilyID, &s.PasskeyID, &s.ExpiresAt); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return ErrNoSession
				}
				return err
			}
		}
		if err := lockSessionFamily(ctx, tx, s.FamilyID); err != nil {
			return err
		}
		if s.PasskeyID != uuid.Nil {
			var id uuid.UUID
			// Serialize issuance with revocation, including workspace-derived sessions.
			if err := tx.QueryRow(ctx, `SELECT id FROM user_passkeys WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL FOR SHARE`, s.PasskeyID, user.ID).Scan(&id); err != nil {
				return ErrNoSession
			}
		}
		if source != nil {
			var id uuid.UUID
			if err := tx.QueryRow(ctx, `SELECT id FROM sessions WHERE id=$1 AND user_id=$2 AND family_id=$3
				AND revoked_at IS NULL AND expires_at>clock_timestamp() FOR SHARE`, source.ID, user.ID, s.FamilyID).Scan(&id); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return ErrNoSession
				}
				return err
			}
		}
		return tx.QueryRow(ctx, `INSERT INTO sessions (user_id,tenant_id,token_hash,user_agent,expires_at,passkey_id,family_id) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
			user.ID, nullableWorkspace(user.TenantID), sum[:], truncate(userAgent, 200), s.ExpiresAt, nullableWorkspace(s.PasskeyID), s.FamilyID).Scan(&s.ID)
	})
	if err != nil {
		return "", Session{}, fmt.Errorf("store: start session: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), s, nil
}

// Session resolves a token. Expired and revoked sessions are not found.
func (u *Users) Session(ctx context.Context, token string) (Session, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(token))
	if err != nil || len(raw) != 32 {
		return Session{}, ErrNoSession
	}
	sum := sha256.Sum256(raw)

	var s Session
	err = u.pool.QueryRow(ctx, `
		UPDATE sessions SET last_seen_at = now()
		 WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()
		 AND (sessions.tenant_id IS NULL OR EXISTS (SELECT 1 FROM tenants t WHERE t.id=sessions.tenant_id AND t.status='active'))
		 RETURNING id, user_id, coalesce(tenant_id,'00000000-0000-0000-0000-000000000000'::uuid), expires_at, coalesce(passkey_id,'00000000-0000-0000-0000-000000000000'::uuid), family_id`, sum[:]).
		Scan(&s.ID, &s.UserID, &s.TenantID, &s.ExpiresAt, &s.PasskeyID, &s.FamilyID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, ErrNoSession
	}
	if err != nil {
		return Session{}, fmt.Errorf("store: session: %w", err)
	}
	return s, nil
}

// ActiveSession resolves a token and the account behind it, refusing an
// account that has been disabled. Session alone does not look at the account
// — sessions carry no tenant transaction — so every caller that lets a token
// in goes through here rather than remembering to check twice.
func (u *Users) ActiveSession(ctx context.Context, token string) (Session, User, error) {
	s, err := u.Session(ctx, token)
	if err != nil {
		return Session{}, User{}, err
	}
	user, err := u.Get(ctx, s.TenantID, s.UserID)
	if errors.Is(err, ErrNotFound) {
		return Session{}, User{}, ErrNoSession
	}
	if err != nil {
		return Session{}, User{}, err
	}
	if user.Status != "active" {
		return Session{}, User{}, ErrNoSession
	}
	return s, user, nil
}

// EndSession revokes one token.
func (u *Users) EndSession(ctx context.Context, token string) error {
	return u.endSession(ctx, token, false)
}

// EndSessionFamily revokes the browser login and all tokens derived from it
// across workspaces. An unexpired token remains usable for this operation
// after token-only logout, so switching spaces cannot leave a hidden login.
// Unknown, malformed, and expired tokens all have the same idempotent result.
func (u *Users) EndSessionFamily(ctx context.Context, token string) error {
	return u.endSession(ctx, token, true)
}

func lockSessionFamily(ctx context.Context, tx pgx.Tx, familyID uuid.UUID) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "session-family/"+familyID.String())
	return err
}

func (u *Users) endSession(ctx context.Context, token string, allRelated bool) error {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(token))
	if err != nil || len(raw) != 32 {
		//nolint:nilerr // Logging out with a malformed token is intentionally idempotent.
		return nil
	}
	sum := sha256.Sum256(raw)
	var userID, familyID uuid.UUID
	err = u.pool.QueryRow(ctx, `SELECT user_id, family_id FROM sessions WHERE token_hash=$1 AND expires_at>now()`, sum[:]).Scan(&userID, &familyID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return pg.InTx(ctx, u.pool, func(tx pgx.Tx) error {
		if err := lockPasskeyRegistration(ctx, tx, userID); err != nil {
			return err
		}
		if err := lockSessionFamily(ctx, tx, familyID); err != nil {
			return err
		}
		// Re-check expiry after waiting for issuance/revocation to finish.
		var id uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT id FROM sessions WHERE token_hash=$1 AND user_id=$2 AND family_id=$3 AND expires_at>clock_timestamp() FOR UPDATE`, sum[:], userID, familyID).Scan(&id); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return err
		}
		if allRelated {
			_, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at=now() WHERE user_id=$1 AND family_id=$2 AND revoked_at IS NULL`, userID, familyID)
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL`, id)
		return err
	})
}

// ---------------------------------------------------------------------------
// Invites
// ---------------------------------------------------------------------------

// Invite is a one-time right to create an account in a tenant.
type Invite struct {
	TenantID  uuid.UUID
	Role      string
	Email     string
	ExpiresAt time.Time
}

// CreateInvite issues an invite secret. It is returned once.
//
// createdBy is nil for the invite bootstrap prints, which is the only one that
// can exist without an account behind it: the first person to join a tenant has
// nobody to be invited by.
func (u *Users) CreateInvite(ctx context.Context, tenant uuid.UUID, role, email string,
	createdBy *uuid.UUID, ttl time.Duration) (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("store: entropy: %w", err)
	}
	sum := sha256.Sum256(raw)

	var mail *string
	if email != "" {
		normalised := normaliseEmail(email)
		mail = &normalised
	}
	_, err := u.pool.Exec(ctx, `
		INSERT INTO invites (invite_id, tenant_id, role, created_by, email, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		sum[:], tenant, role, createdBy, mail, time.Now().Add(ttl))
	if err != nil {
		return "", fmt.Errorf("store: create invite: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// RedeemInvite consumes an invite and reports what it grants.
//
// Marked complete in the same statement that reads it, so two people racing the
// same code cannot both get an account.
func (u *Users) RedeemInvite(ctx context.Context, secret string) (Invite, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(secret))
	if err != nil || len(raw) != 24 {
		return Invite{}, ErrInviteInvalid
	}
	sum := sha256.Sum256(raw)

	var inv Invite
	var mail *string
	err = u.pool.QueryRow(ctx, `
		UPDATE invites SET completed_at = now()
		 WHERE invite_id = $1 AND completed_at IS NULL AND expires_at > now()
		 RETURNING tenant_id, role, email, expires_at`, sum[:]).
		Scan(&inv.TenantID, &inv.Role, &mail, &inv.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Invite{}, ErrInviteInvalid
	}
	if err != nil {
		return Invite{}, fmt.Errorf("store: redeem invite: %w", err)
	}
	if mail != nil {
		inv.Email = *mail
	}
	return inv, nil
}

func normaliseEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
