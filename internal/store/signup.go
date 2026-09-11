package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"whatserver2/internal/pg"
)

var ErrInviteEmailMismatch = errors.New("store: invitation belongs to another email address")
var ErrVerificationInvalid = errors.New("store: email verification is invalid or expired")
var ErrPersonalWorkspace = errors.New("store: personal workspaces cannot have additional human members")

func validProfileName(name string, required bool) bool {
	return utf8.ValidString(name) && (!required || utf8.RuneCountInString(name) > 0) && utf8.RuneCountInString(name) <= 80 && !strings.ContainsFunc(name, unicode.IsControl)
}
func signupEmail(email string) (string, error) {
	email = normaliseEmail(email)
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email || len(email) > 254 {
		return "", ErrInvalidMembership
	}
	return email, nil
}

type preparedUser struct {
	in           NewUser
	hash         string
	recoveryHash *string
	params       []byte
}

func prepareUser(in NewUser) (preparedUser, error) {
	var err error
	in.Email, err = signupEmail(in.Email)
	in.Name = strings.TrimSpace(in.Name)
	if err != nil || !validProfileName(in.Name, false) || len(in.KDFSalt) != saltLenUser || len(in.PublicKey) != 32 || len(in.WrappedUSK) == 0 || in.AuthKey == "" || ((len(in.RecoveryWrap) > 0) != (in.RecoveryProof != "")) {
		return preparedUser{}, errors.New("store: invalid account information")
	}
	if in.Role == "" {
		in.Role = "member"
	}
	if in.Role != "owner" && in.Role != "admin" && in.Role != "member" {
		return preparedUser{}, ErrInvalidMembership
	}
	p := preparedUser{in: in}
	p.hash, err = hashSecret(in.AuthKey)
	if err != nil {
		return p, err
	}
	if in.RecoveryProof != "" {
		h, e := hashSecret(in.RecoveryProof)
		if e != nil {
			return p, e
		}
		p.recoveryHash = &h
	}
	p.params, err = json.Marshal(in.KDFParams)
	return p, err
}
func insertPreparedUser(ctx context.Context, tx pgx.Tx, p preparedUser) (User, error) {
	in := p.in
	out := User{TenantID: in.TenantID, Email: in.Email, Name: in.Name, KDFSalt: in.KDFSalt, KDFParams: in.KDFParams, PublicKey: in.PublicKey, WrappedUSK: in.WrappedUSK, RecoveryWrap: in.RecoveryWrap, RecoveryUsable: p.recoveryHash != nil, Role: in.Role, Status: "active"}
	err := tx.QueryRow(ctx, `INSERT INTO users(tenant_id,email,name,auth_hash,kdf_salt,kdf_params,public_key,wrapped_usk,recovery_wrap,recovery_hash,role) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id,created_at`, in.TenantID, in.Email, in.Name, p.hash, in.KDFSalt, p.params, in.PublicKey, in.WrappedUSK, in.RecoveryWrap, p.recoveryHash, in.Role).Scan(&out.ID, &out.CreatedAt)
	return out, accountInsertError(err)
}
func accountInsertError(err error) error {
	if err != nil && (strings.Contains(err.Error(), "users_email_key") || strings.Contains(err.Error(), "user_logins_pkey") || strings.Contains(err.Error(), "users_tenant_id_email_key")) {
		return ErrEmailTaken
	}
	return err
}
func inviteDigest(secret string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(secret))
	if err != nil || len(raw) != 24 {
		return nil, ErrInviteInvalid
	}
	sum := sha256.Sum256(raw)
	return sum[:], nil
}
func lockSignupInvite(ctx context.Context, tx pgx.Tx, secret, email string, service bool) (Invite, []byte, error) {
	sum, err := inviteDigest(secret)
	if err != nil {
		return Invite{}, nil, err
	}
	var tenant uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT tenant_id FROM invites WHERE invite_id=$1`, sum).Scan(&tenant); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			err = ErrInviteInvalid
		}
		return Invite{}, nil, err
	}
	var kind, status string
	if err = tx.QueryRow(ctx, `SELECT kind,status FROM tenants WHERE id=$1 FOR UPDATE`, tenant).Scan(&kind, &status); err != nil {
		return Invite{}, nil, err
	}
	if status != "active" || (!service && kind != "team") {
		return Invite{}, nil, ErrInviteInvalid
	}
	var inv Invite
	var recipient *string
	err = tx.QueryRow(ctx, `SELECT tenant_id,role,email,expires_at FROM invites WHERE invite_id=$1 AND completed_at IS NULL AND revoked_at IS NULL AND expires_at>now() FOR UPDATE`, sum).Scan(&inv.TenantID, &inv.Role, &recipient, &inv.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrInviteInvalid
	}
	if err != nil {
		return inv, nil, err
	}
	if recipient != nil {
		inv.Email = *recipient
	}
	if (inv.Role == RoleService) != service {
		return inv, nil, ErrInviteInvalid
	}
	if !service && inv.Email != "" && inv.Email != normaliseEmail(email) {
		return inv, nil, ErrInviteEmailMismatch
	}
	return inv, sum, nil
}

// Signup creates a personal space and optionally joins a team. All writes,
// including consuming a verification or invitation, share one transaction.
func (u *Users) Signup(ctx context.Context, in NewUser, invite, verification string) (User, error) {
	in.TenantID = uuid.New()
	in.Role = "owner"
	prepared, err := prepareUser(in)
	if err != nil {
		return User{}, err
	}
	var out User
	err = pg.InTx(ctx, u.pool, func(tx pgx.Tx) error {
		var inv Invite
		var digest []byte
		if strings.TrimSpace(invite) != "" {
			var e error
			inv, digest, e = lockSignupInvite(ctx, tx, invite, in.Email, false)
			if e != nil {
				return e
			}
			// Preserve the existing credential routing for invited accounts.
			// The insertion trigger creates their distinct personal space.
			in.TenantID = inv.TenantID
			prepared.in.TenantID = inv.TenantID
			prepared.in.Role = inv.Role
		} else {
			hash, e := inviteDigest(verification)
			if e != nil {
				return ErrVerificationInvalid
			}
			var email string
			e = tx.QueryRow(ctx, `UPDATE email_signup_verifications SET completed_at=now() WHERE token_hash=$1 AND email=$2 AND completed_at IS NULL AND expires_at>now() RETURNING email`, hash, prepared.in.Email).Scan(&email)
			if errors.Is(e, pgx.ErrNoRows) {
				return ErrVerificationInvalid
			}
			if e != nil {
				return e
			}
		}
		if _, e := tx.Exec(ctx, `SELECT set_config('app.tenant_id',$1,true)`, in.TenantID.String()); e != nil {
			return e
		}
		var e error
		out, e = insertPreparedUser(ctx, tx, prepared)
		if e != nil {
			return e
		}
		if len(digest) > 0 {
			if _, e = tx.Exec(ctx, `SELECT set_config('app.tenant_id',$1,true)`, inv.TenantID.String()); e != nil {
				return e
			}
			if _, e = tx.Exec(ctx, `INSERT INTO workspace_memberships(tenant_id,user_id,role) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, inv.TenantID, out.ID, inv.Role); e != nil {
				return e
			}
			if _, e = tx.Exec(ctx, `UPDATE invites SET completed_at=now(),claimed_by=$2 WHERE invite_id=$1`, digest, out.ID); e != nil {
				return e
			}
			out.TenantID = inv.TenantID
			out.Role = inv.Role
		}
		return nil
	})
	return out, err
}
func (u *Users) SignupService(ctx context.Context, secret, name string, pub []byte) (User, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if !serviceNameRE.MatchString(name) || len(pub) != 32 {
		return User{}, ErrInvalidMembership
	}
	var out User
	err := pg.InTx(ctx, u.pool, func(tx pgx.Tx) error {
		inv, digest, e := lockSignupInvite(ctx, tx, secret, "", true)
		if e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `SELECT set_config('app.tenant_id',$1,true)`, inv.TenantID.String()); e != nil {
			return e
		}
		out = User{TenantID: inv.TenantID, Email: name + serviceDomain + inv.TenantID.String(), PublicKey: pub, Role: RoleService, Status: "active"}
		e = tx.QueryRow(ctx, `INSERT INTO users(tenant_id,email,public_key,role) VALUES($1,$2,$3,$4) RETURNING id,created_at`, inv.TenantID, out.Email, pub, RoleService).Scan(&out.ID, &out.CreatedAt)
		if e != nil {
			return accountInsertError(e)
		}
		_, e = tx.Exec(ctx, `UPDATE invites SET completed_at=now(),claimed_by=$2 WHERE invite_id=$1`, digest, out.ID)
		return e
	})
	return out, err
}
func (u *Users) CreateSignupVerification(ctx context.Context, email string) (string, error) {
	email, err := signupEmail(email)
	if err != nil {
		return "", err
	}
	raw := make([]byte, 24)
	if _, err = rand.Read(raw); err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	created := false
	err = pg.InTx(ctx, u.pool, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "signup-email/"+email); e != nil {
			return e
		}
		var blocked bool
		if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM user_logins WHERE email=$1) OR EXISTS(SELECT 1 FROM email_signup_verifications WHERE email=$1 AND created_at>now()-interval '60 seconds')`, email).Scan(&blocked); e != nil {
			return e
		}
		if blocked {
			return nil
		}
		_, e := tx.Exec(ctx, `INSERT INTO email_signup_verifications(token_hash,email,expires_at) VALUES($1,$2,$3)`, sum[:], email, time.Now().Add(30*time.Minute))
		created = e == nil
		return e
	})
	if err == nil && !created {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("store: create email verification: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
