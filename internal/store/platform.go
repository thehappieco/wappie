package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
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

// Sign-in through an external identity provider (migration 0048,
// docs/platform-sign-in.md).
//
// The provider's sub names a person; Wappie's users.id names an account. A
// new account created through the provider takes users.id = sub; an
// existing (legacy) account keeps its id, because grants, foreign keys and
// AADs bind it, and is linked to its sub by the browser ceremony. Everything
// is keyed by sub, never by e-mail: an address is at most a hint shown to the
// verified owner of that address.
//
// The account key never reaches this server. What arrives is the 61-byte
// platform wrap (the account key under a key derived from the provider's
// product key, sealed in the browser), checked here for its length and
// version byte only, and the public key the account has had since it was
// created.

const (
	// PlatformAuthSource marks an account that signs in through the provider.
	PlatformAuthSource = "platform"
	// LocalAuthSource is every other account: a password, or a service.
	LocalAuthSource = "local"

	// PlatformTicketTTL is how long a sign-in may take to create or link its
	// account after the provider's answer.
	PlatformTicketTTL = 5 * time.Minute
	// platformTicketAttempts bounds the wrong legacy passwords one ticket may
	// try before it is spent, beside the address and account rate limits.
	platformTicketAttempts = 5

	// PlatformWrapLen is the platform wrap: version 0x01, a 12-byte nonce,
	// the 32-byte account key and the 16-byte tag.
	PlatformWrapLen     = 61
	PlatformWrapVersion = 0x01

	ticketLen = 32
)

// Ticket kinds: what a sign-in with no session may do next.
const (
	// TicketNew may create an account, or link a legacy one under another
	// address.
	TicketNew = "new"
	// TicketLink may only link a legacy account: one with the provider's
	// address exists, so a second account under it is not offered.
	TicketLink = "link"
	// TicketRewrap stores the wrap of a linked account for a new epoch.
	TicketRewrap = "rewrap"
)

var (
	// ErrTicketInvalid is a ticket that is unknown, used, expired, spent by
	// its failed attempts, or of another kind than the step needs.
	ErrTicketInvalid = errors.New("store: the sign-in ticket is not valid")
	// ErrAlreadyLinked is an account or a sub that already has its link.
	ErrAlreadyLinked = errors.New("store: that account or identity is already linked")
	// ErrPlatformWrap is a wrap that is not 61 bytes with version byte 1.
	ErrPlatformWrap = errors.New("store: the platform wrap is malformed")
)

// ValidPlatformWrap reports whether wrap has the platform wrap's shape. It
// cannot say more: only sk_p opens it.
func ValidPlatformWrap(wrap []byte) bool {
	return len(wrap) == PlatformWrapLen && wrap[0] == PlatformWrapVersion
}

// ---------------------------------------------------------------------------
// The pin (kit oidcrp.PinStore)
// ---------------------------------------------------------------------------

// PlatformPins keeps the first product key seen for each (sub,
// product_key_id), insert only: the table's trigger refuses any update or
// delete.
type PlatformPins struct{ pool *pgxpool.Pool }

func NewPlatformPins(pool *pgxpool.Pool) *PlatformPins { return &PlatformPins{pool: pool} }

// InsertPin implements oidcrp.PinStore: the two statements its documentation
// gives. ON CONFLICT DO NOTHING makes two concurrent first sign-ins agree:
// one inserts, the other reads the winner's key.
func (p *PlatformPins) InsertPin(ctx context.Context, sub, productKeyID string, productKey []byte) ([]byte, bool, error) {
	id, err := uuid.Parse(sub)
	if err != nil {
		return nil, false, fmt.Errorf("store: pin: %w", err)
	}
	tag, err := p.pool.Exec(ctx, `INSERT INTO platform_key_pins (sub, product_key_id, product_key)
		VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, id, productKeyID, productKey)
	if err != nil {
		return nil, false, fmt.Errorf("store: pin: %w", err)
	}
	var pinned []byte
	if err := p.pool.QueryRow(ctx, `SELECT product_key FROM platform_key_pins WHERE sub = $1 AND product_key_id = $2`,
		id, productKeyID).Scan(&pinned); err != nil {
		return nil, false, fmt.Errorf("store: pin: %w", err)
	}
	return pinned, tag.RowsAffected() == 1, nil
}

// ---------------------------------------------------------------------------
// Links and wraps
// ---------------------------------------------------------------------------

// PlatformIdentity is the link of one sub to one account.
type PlatformIdentity struct {
	Sub    uuid.UUID
	UserID uuid.UUID
	// Email is the provider's verified address at the last sign-in.
	Email string
	// LinkedFrom is "new" (users.id = sub) or "legacy".
	LinkedFrom string
}

// PlatformIdentity returns the link of sub, or ErrNotFound.
func (u *Users) PlatformIdentity(ctx context.Context, sub uuid.UUID) (PlatformIdentity, error) {
	out := PlatformIdentity{Sub: sub}
	err := u.pool.QueryRow(ctx, `SELECT user_id, email, linked_from FROM platform_identities WHERE sub = $1`, sub).
		Scan(&out.UserID, &out.Email, &out.LinkedFrom)
	if errors.Is(err, pgx.ErrNoRows) {
		return PlatformIdentity{}, ErrNotFound
	}
	if err != nil {
		return PlatformIdentity{}, fmt.Errorf("store: platform identity: %w", err)
	}
	return out, nil
}

// PlatformWrap returns the account key's wrap for one product key epoch, or
// ErrNotFound.
func (u *Users) PlatformWrap(ctx context.Context, userID uuid.UUID, productKeyID string) ([]byte, error) {
	var wrap []byte
	err := u.pool.QueryRow(ctx, `SELECT wrap FROM platform_wraps WHERE user_id = $1 AND product_key_id = $2`, userID, productKeyID).Scan(&wrap)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: platform wrap: %w", err)
	}
	return wrap, nil
}

// PlatformAccount loads a linked account for a sign-in: active or not, as the
// caller decides what a disabled one is answered. A service is never linked.
func (u *Users) PlatformAccount(ctx context.Context, userID uuid.UUID) (User, error) {
	user, err := u.identity(ctx, userID)
	if err != nil {
		return User{}, ErrNotFound
	}
	return user, nil
}

// PlatformSignIn is a linked account at the start of its session: the
// default workspace selected as for a password sign-in.
func (u *Users) PlatformSignIn(ctx context.Context, user User) (User, error) {
	return u.defaultWorkspace(ctx, user)
}

// UnlinkedLegacyAccount reports whether an active, unlinked account of a
// person signs in with a password under this address: the hint that a
// verified owner of the address should link rather than create a twin.
func (u *Users) UnlinkedLegacyAccount(ctx context.Context, email string) (bool, error) {
	email = normaliseEmail(email)
	var tenant, userID uuid.UUID
	err := u.pool.QueryRow(ctx, `SELECT tenant_id, user_id FROM user_logins WHERE email = $1`, email).Scan(&tenant, &userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: legacy account: %w", err)
	}
	var legacy bool
	err = pg.InTenantTx(ctx, u.pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT role <> 'service' AND status = 'active' AND auth_source = 'local'
			AND NOT EXISTS (SELECT 1 FROM platform_identities WHERE user_id = users.id)
			FROM users WHERE id = $1`, userID).Scan(&legacy)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: legacy account: %w", err)
	}
	return legacy, nil
}

// SyncPlatformEmail records the provider's current verified address at a
// sign-in. The link always takes it. An account created through the provider
// also takes it as users.email, unless another account holds that address
// (ErrEmailTaken: the old one stays). A linked legacy account keeps its
// users.email, which its legacy password wrap is bound to, until the end of
// the rollback window.
func (u *Users) SyncPlatformEmail(ctx context.Context, ident PlatformIdentity, email string) error {
	email = normaliseEmail(email)
	if email == "" {
		return nil
	}
	if email != ident.Email {
		if _, err := u.pool.Exec(ctx, `UPDATE platform_identities SET email = $2, email_changed_at = now() WHERE sub = $1`, ident.Sub, email); err != nil {
			return fmt.Errorf("store: platform e-mail: %w", err)
		}
	}
	if ident.LinkedFrom != "new" {
		return nil
	}
	home, err := u.identityTenant(ctx, ident.UserID)
	if err != nil {
		return fmt.Errorf("store: platform e-mail: %w", err)
	}
	err = pg.InTenantTx(ctx, u.pool, home.String(), func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE users SET email = $2, updated_at = now() WHERE id = $1 AND email <> $2`, ident.UserID, email)
		return e
	})
	if err = accountInsertError(err); err != nil {
		if errors.Is(err, ErrEmailTaken) {
			return ErrEmailTaken
		}
		return fmt.Errorf("store: platform e-mail: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Tickets
// ---------------------------------------------------------------------------

// PlatformTicket is what a sign-in with no session yet may do next, bound to
// the provider's answer.
type PlatformTicket struct {
	Kind         string
	Sub          uuid.UUID
	ProductKeyID string
	ProductKey   []byte
	Email        string
	Name         string
	// UserID is the linked account of a rewrap ticket.
	UserID uuid.UUID
}

func ticketDigest(secret string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimSpace(secret))
	if err != nil || len(raw) != ticketLen {
		return nil, ErrTicketInvalid
	}
	sum := sha256.Sum256(raw)
	clear(raw)
	return sum[:], nil
}

// CreatePlatformTicket stores a ticket and returns its secret, once. Tickets
// that expired more than an hour ago are swept on the way.
func (u *Users) CreatePlatformTicket(ctx context.Context, t PlatformTicket) (string, error) {
	switch {
	case t.Kind != TicketNew && t.Kind != TicketLink && t.Kind != TicketRewrap:
		return "", errors.New("store: unknown ticket kind")
	case (t.Kind == TicketRewrap) != (t.UserID != uuid.Nil):
		return "", errors.New("store: only a rewrap ticket names an account")
	case len(t.ProductKey) != 32:
		return "", errors.New("store: a product key is 32 bytes")
	}
	raw := make([]byte, ticketLen)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("store: entropy: %w", err)
	}
	sum := sha256.Sum256(raw)
	secret := base64.RawURLEncoding.EncodeToString(raw)
	clear(raw)
	var user any
	if t.UserID != uuid.Nil {
		user = t.UserID
	}
	name := strings.TrimSpace(t.Name)
	if !validProfileName(name, false) {
		name = ""
	}
	err := pg.InTx(ctx, u.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM platform_login_tickets WHERE expires_at < now() - interval '1 hour'`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO platform_login_tickets
			(ticket_hash, kind, sub, product_key_id, product_key, email, name, user_id, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now() + $9::int * interval '1 second')`,
			sum[:], t.Kind, t.Sub, t.ProductKeyID, t.ProductKey, normaliseEmail(t.Email), name, user, int(PlatformTicketTTL.Seconds()))
		return err
	})
	if err != nil {
		return "", fmt.Errorf("store: create ticket: %w", err)
	}
	return secret, nil
}

// PlatformTicketFor reads a live ticket of one of kinds without spending it.
func (u *Users) PlatformTicketFor(ctx context.Context, secret string, kinds ...string) (PlatformTicket, error) {
	sum, err := ticketDigest(secret)
	if err != nil {
		return PlatformTicket{}, err
	}
	return readTicket(ctx, u.pool, sum, false, kinds)
}

// FailPlatformTicket counts a wrong legacy password against a ticket; the
// fifth spends it.
func (u *Users) FailPlatformTicket(ctx context.Context, secret string) error {
	sum, err := ticketDigest(secret)
	if err != nil {
		return nil //nolint:nilerr // a malformed ticket names no row to count against
	}
	_, err = u.pool.Exec(ctx, `UPDATE platform_login_tickets
		SET attempts = attempts + 1, used_at = CASE WHEN attempts + 1 >= $2 THEN now() ELSE used_at END
		WHERE ticket_hash = $1 AND used_at IS NULL`, sum, platformTicketAttempts)
	return err
}

type queryRower interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// readTicket reads (or, with spend, consumes) a live ticket of one of kinds,
// and checks it against the pin it was issued from: pins are insert only,
// so a mismatch means a tampered row.
func readTicket(ctx context.Context, q queryRower, sum []byte, spend bool, kinds []string) (PlatformTicket, error) {
	var t PlatformTicket
	var user *uuid.UUID
	var pinned []byte
	query := `SELECT t.kind, t.sub, t.product_key_id, t.product_key, t.email, t.name, t.user_id, p.product_key
		FROM platform_login_tickets t JOIN platform_key_pins p ON p.sub = t.sub AND p.product_key_id = t.product_key_id
		WHERE t.ticket_hash = $1 AND t.used_at IS NULL AND t.expires_at > now() AND t.kind = ANY ($2)`
	if spend {
		query = `WITH spent AS (UPDATE platform_login_tickets SET used_at = now()
			WHERE ticket_hash = $1 AND used_at IS NULL AND expires_at > now() AND kind = ANY ($2)
			RETURNING kind, sub, product_key_id, product_key, email, name, user_id)
			SELECT t.kind, t.sub, t.product_key_id, t.product_key, t.email, t.name, t.user_id, p.product_key
			FROM spent t JOIN platform_key_pins p ON p.sub = t.sub AND p.product_key_id = t.product_key_id`
	}
	err := q.QueryRow(ctx, query, sum, kinds).Scan(&t.Kind, &t.Sub, &t.ProductKeyID, &t.ProductKey, &t.Email, &t.Name, &user, &pinned)
	if errors.Is(err, pgx.ErrNoRows) {
		return PlatformTicket{}, ErrTicketInvalid
	}
	if err != nil {
		return PlatformTicket{}, fmt.Errorf("store: ticket: %w", err)
	}
	if subtle.ConstantTimeCompare(pinned, t.ProductKey) != 1 {
		return PlatformTicket{}, ErrTicketInvalid
	}
	if user != nil {
		t.UserID = *user
	}
	return t, nil
}

// ---------------------------------------------------------------------------
// A new account
// ---------------------------------------------------------------------------

// NewPlatformUser is what the browser sends for an account created through
// the provider: the public half of the account key it generated, and that
// key under its product key. No password material exists.
type NewPlatformUser struct {
	Ticket    string
	PublicKey []byte
	Wrap      []byte
	Name      string
}

// SignupPlatform creates the account of a ticket of kind "new", with
// users.id = sub and auth_source = 'platform', in one transaction with its
// link, its wrap and its event. The insertion trigger creates the personal
// workspace, as for every person (interim, until the platform's workspaces).
func (u *Users) SignupPlatform(ctx context.Context, in NewPlatformUser) (User, error) {
	if len(in.PublicKey) != 32 {
		return User{}, errors.New("store: a public key is 32 bytes")
	}
	if !ValidPlatformWrap(in.Wrap) {
		return User{}, ErrPlatformWrap
	}
	sum, err := ticketDigest(in.Ticket)
	if err != nil {
		return User{}, err
	}
	name := strings.TrimSpace(in.Name)
	if !validProfileName(name, false) {
		return User{}, ErrInvalidMembership
	}
	var out User
	err = pg.InTx(ctx, u.pool, func(tx pgx.Tx) error {
		t, err := readTicket(ctx, tx, sum, true, []string{TicketNew})
		if err != nil {
			return err
		}
		if name == "" {
			name = t.Name
		}
		email, err := signupEmail(t.Email)
		if err != nil {
			return err
		}
		var linked bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM platform_identities WHERE sub = $1)`, t.Sub).Scan(&linked); err != nil {
			return err
		}
		if linked {
			return ErrAlreadyLinked
		}
		home := uuid.New()
		if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, home.String()); err != nil {
			return err
		}
		out = User{ID: t.Sub, TenantID: home, Email: email, Name: name, PublicKey: in.PublicKey, Role: "owner", Status: "active", AuthSource: PlatformAuthSource}
		err = tx.QueryRow(ctx, `INSERT INTO users (id, tenant_id, email, name, public_key, role, auth_source)
			VALUES ($1, $2, $3, $4, $5, 'owner', 'platform') RETURNING created_at`,
			t.Sub, home, email, name, in.PublicKey).Scan(&out.CreatedAt)
		if err != nil {
			if uniqueOn(err, "users_pkey") {
				return ErrAlreadyLinked
			}
			return accountInsertError(err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO platform_identities (sub, user_id, email, linked_from) VALUES ($1, $1, $2, 'new')`, t.Sub, email); err != nil {
			if uniqueOn(err, "") {
				return ErrAlreadyLinked
			}
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO platform_wraps (user_id, product_key_id, wrap) VALUES ($1, $2, $3)`, t.Sub, t.ProductKeyID, in.Wrap); err != nil {
			return err
		}
		return securityEvent(ctx, tx, "platform_linked", &t.Sub, t.Sub, map[string]string{"from": "new", "product_key_id": t.ProductKeyID})
	})
	if err != nil {
		return User{}, err
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Linking a legacy account
// ---------------------------------------------------------------------------

// LegacyProof is the old password's auth key, or the recovery code's proof.
type LegacyProof struct {
	Email    string
	Secret   string
	Recovery bool
}

func (p LegacyProof) column() string {
	if p.Recovery {
		return "recovery_hash"
	}
	return "auth_hash"
}

// verifyLegacy checks a legacy proof as a password sign-in does, and returns
// the account with the hash it was checked against.
func (u *Users) verifyLegacy(ctx context.Context, proof LegacyProof) (User, string, error) {
	email := normaliseEmail(proof.Email)
	var tenant, userID uuid.UUID
	err := u.pool.QueryRow(ctx, `SELECT tenant_id, user_id FROM user_logins WHERE email = $1`, email).Scan(&tenant, &userID)
	if errors.Is(err, pgx.ErrNoRows) {
		//nolint:errcheck // the decoy hash is thrown away by design
		_, _ = hashSecret(proof.Secret)
		return User{}, "", ErrBadCredentials
	}
	if err != nil {
		return User{}, "", fmt.Errorf("store: link: %w", err)
	}
	user, err := u.verify(ctx, tenant, userID, email, proof.Secret, proof.column())
	if err != nil {
		return User{}, "", err
	}
	var stored string
	err = pg.InTenantTx(ctx, u.pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT `+proof.column()+` FROM users WHERE id = $1`, userID).Scan(&stored)
	})
	if err != nil {
		return User{}, "", ErrBadCredentials
	}
	return user, stored, nil
}

// PrepareLegacyLink checks a live link ticket and a legacy proof, and returns
// the account: its id, its public key and the wrap the proof's other branch
// opens in the browser (the password wrap, or the recovery wrap). Nothing is
// spent or changed. The wrap is handed back only against the proof, as a
// password sign-in hands it back: never to a ticket alone.
func (u *Users) PrepareLegacyLink(ctx context.Context, ticket string, proof LegacyProof) (User, error) {
	t, err := u.PlatformTicketFor(ctx, ticket, TicketNew, TicketLink)
	if err != nil {
		return User{}, err
	}
	user, _, err := u.verifyLegacy(ctx, proof)
	if err != nil {
		return User{}, err
	}
	if user.Role == RoleService {
		return User{}, ErrBadCredentials
	}
	if user.AuthSource != LocalAuthSource {
		return User{}, ErrAlreadyLinked
	}
	var linked bool
	if err := u.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM platform_identities WHERE sub = $1 OR user_id = $2)`, t.Sub, user.ID).Scan(&linked); err != nil {
		return User{}, fmt.Errorf("store: link: %w", err)
	}
	if linked {
		return User{}, ErrAlreadyLinked
	}
	return user, nil
}

// LegacyLink is the link step: the ticket, the proof checked again, and the
// account key wrapped under the product key in the browser.
type LegacyLink struct {
	Ticket string
	Proof  LegacyProof
	Wrap   []byte
}

// LinkLegacy links a legacy account to the ticket's sub in one transaction:
// it spends the ticket, re-reads the account under its lock (active, a
// person, local, not linked, and the hash the proof was checked against
// unchanged), inserts the link and the wrap, marks the account 'platform',
// revokes every session and Wappie passkey of it, and records the event. It
// returns the account, for its new session. A wrong proof spends nothing
// but one of the ticket's attempts (the caller's FailPlatformTicket).
func (u *Users) LinkLegacy(ctx context.Context, in LegacyLink) (User, error) {
	if !ValidPlatformWrap(in.Wrap) {
		return User{}, ErrPlatformWrap
	}
	sum, err := ticketDigest(in.Ticket)
	if err != nil {
		return User{}, err
	}
	if _, err := readTicket(ctx, u.pool, sum, false, []string{TicketNew, TicketLink}); err != nil {
		return User{}, err
	}
	user, stored, err := u.verifyLegacy(ctx, in.Proof)
	if err != nil {
		return User{}, err
	}
	if user.Role == RoleService {
		return User{}, ErrBadCredentials
	}
	home, err := u.identityTenant(ctx, user.ID)
	if err != nil {
		return User{}, ErrBadCredentials
	}
	err = pg.InTx(ctx, u.pool, func(tx pgx.Tx) error {
		t, err := readTicket(ctx, tx, sum, true, []string{TicketNew, TicketLink})
		if err != nil {
			return err
		}
		if err := lockPasskeyRegistration(ctx, tx, user.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true), set_config('app.user_id', $2, true)`,
			home.String(), user.ID.String()); err != nil {
			return err
		}
		var current *string
		var status, role, source string
		if err := tx.QueryRow(ctx, `SELECT `+in.Proof.column()+`, status, role, auth_source FROM users WHERE id = $1 FOR UPDATE`, user.ID).
			Scan(&current, &status, &role, &source); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrBadCredentials
			}
			return err
		}
		if current == nil || subtle.ConstantTimeCompare([]byte(*current), []byte(stored)) != 1 || status != "active" || role == RoleService {
			return ErrBadCredentials
		}
		if source != LocalAuthSource {
			return ErrAlreadyLinked
		}
		var linked bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM platform_identities WHERE sub = $1 OR user_id = $2)`, t.Sub, user.ID).Scan(&linked); err != nil {
			return err
		}
		if linked {
			return ErrAlreadyLinked
		}
		if _, err := tx.Exec(ctx, `INSERT INTO platform_identities (sub, user_id, email, linked_from) VALUES ($1, $2, $3, 'legacy')`, t.Sub, user.ID, t.Email); err != nil {
			if uniqueOn(err, "") {
				return ErrAlreadyLinked
			}
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO platform_wraps (user_id, product_key_id, wrap) VALUES ($1, $2, $3)`, user.ID, t.ProductKeyID, in.Wrap); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET auth_source = 'platform', updated_at = now() WHERE id = $1`, user.ID); err != nil {
			return err
		}
		// Wappie's own passkeys unlock the legacy wrap: after the link the
		// account is opened through the provider, which does passkeys itself.
		if _, err := tx.Exec(ctx, `UPDATE user_passkeys SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`, user.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM passkey_challenges WHERE user_id = $1`, user.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`, user.ID); err != nil {
			return err
		}
		from := "legacy"
		if in.Proof.Recovery {
			from = "legacy_recovery"
		}
		return securityEvent(ctx, tx, "platform_linked", &user.ID, t.Sub, map[string]string{"from": from, "product_key_id": t.ProductKeyID})
	})
	if err != nil {
		return User{}, err
	}
	user.AuthSource = PlatformAuthSource
	return u.defaultWorkspace(ctx, user)
}

// ---------------------------------------------------------------------------
// A new epoch
// ---------------------------------------------------------------------------

// AddPlatformWrap stores the wrap of a linked account for the epoch of a
// rewrap ticket, spending it. The caller has checked that the session asking
// is the ticket's account.
func (u *Users) AddPlatformWrap(ctx context.Context, ticket string, userID uuid.UUID, wrap []byte) error {
	if !ValidPlatformWrap(wrap) {
		return ErrPlatformWrap
	}
	sum, err := ticketDigest(ticket)
	if err != nil {
		return err
	}
	return pg.InTx(ctx, u.pool, func(tx pgx.Tx) error {
		t, err := readTicket(ctx, tx, sum, true, []string{TicketRewrap})
		if err != nil {
			return err
		}
		if t.UserID != userID {
			return ErrTicketInvalid
		}
		tag, err := tx.Exec(ctx, `INSERT INTO platform_wraps (user_id, product_key_id, wrap) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, userID, t.ProductKeyID, wrap)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrAlreadyLinked
		}
		return securityEvent(ctx, tx, "platform_linked", &userID, t.Sub, map[string]string{"from": "rewrap", "product_key_id": t.ProductKeyID})
	})
}

// ---------------------------------------------------------------------------
// Security events
// ---------------------------------------------------------------------------

// RecordSecurityEvent writes an event: a refusal or a link an operator
// should be able to see. detail never holds a token, key or address.
func (u *Users) RecordSecurityEvent(ctx context.Context, kind string, userID *uuid.UUID, sub uuid.UUID, detail map[string]string) error {
	return pg.InTx(ctx, u.pool, func(tx pgx.Tx) error { return securityEvent(ctx, tx, kind, userID, sub, detail) })
}

func securityEvent(ctx context.Context, tx pgx.Tx, kind string, userID *uuid.UUID, sub uuid.UUID, detail map[string]string) error {
	if detail == nil {
		detail = map[string]string{}
	}
	raw, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	var user any
	if userID != nil {
		user = *userID
	}
	_, err = tx.Exec(ctx, `INSERT INTO security_events (kind, user_id, sub, detail) VALUES ($1, $2, $3, $4)`, kind, user, sub, raw)
	return err
}

// uniqueOn reports a unique violation, on constraint when it is not empty.
func uniqueOn(err error, constraint string) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		return false
	}
	return constraint == "" || pgErr.ConstraintName == constraint
}
