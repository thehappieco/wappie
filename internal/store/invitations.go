package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"whatserver2/internal/pg"
)

var ErrInviteNotRecoverable = errors.New("store: the original invitation code is not recoverable; generate a new code")

type Invitation struct {
	ID          uuid.UUID  `json:"id"`
	Email       string     `json:"email"`
	Role        string     `json:"role"`
	Status      string     `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	CompletedAt *time.Time `json:"completed_at"`
	RevokedAt   *time.Time `json:"revoked_at"`
	CanReveal   bool       `json:"can_reveal"`
}

func (u *Users) SetInviteEncryptionKey(key []byte) error {
	if len(key) != 0 && len(key) != 32 {
		return errors.New("invite encryption key must be 32 bytes")
	}
	u.inviteEncryptionKey = append([]byte(nil), key...)
	return nil
}
func (u *Users) inviteCipher() (cipher.AEAD, error) {
	if len(u.inviteEncryptionKey) == 0 {
		return nil, ErrInviteNotRecoverable
	}
	block, err := aes.NewCipher(u.inviteEncryptionKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
func inviteAAD(tenant, id uuid.UUID) []byte {
	return []byte("wappie/invite/v1/" + tenant.String() + "/" + id.String())
}
func (u *Users) sealInvite(tenant, id uuid.UUID, secret string) ([]byte, error) {
	if len(u.inviteEncryptionKey) == 0 {
		return nil, nil
	}
	aead, err := u.inviteCipher()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, []byte(secret), inviteAAD(tenant, id)), nil
}
func (u *Users) createInviteTx(ctx context.Context, tx pgx.Tx, tenant uuid.UUID, role, email string, creator *uuid.UUID, ttl time.Duration) (string, Invitation, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", Invitation{}, err
	}
	secret := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256(raw)
	out := Invitation{ID: uuid.New(), Email: normaliseEmail(email), Role: role, Status: "pending", ExpiresAt: time.Now().Add(ttl), CanReveal: len(u.inviteEncryptionKey) == 32}
	sealed, err := u.sealInvite(tenant, out.ID, secret)
	if err != nil {
		return "", out, err
	}
	var address *string
	if email != "" {
		address = &out.Email
	}
	err = tx.QueryRow(ctx, `INSERT INTO invites(id,invite_id,tenant_id,role,email,created_by,expires_at,secret_ciphertext) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING created_at`, out.ID, sum[:], tenant, role, address, creator, out.ExpiresAt, sealed).Scan(&out.CreatedAt)
	return secret, out, err
}
func (u *Users) managerInvite(ctx context.Context, tx pgx.Tx, tenant, actor, id uuid.UUID) (Invitation, []byte, error) {
	actorRole, err := lockWorkspaceManager(ctx, tx, tenant, actor)
	if err != nil {
		return Invitation{}, nil, err
	}
	var out Invitation
	var sealed []byte
	err = tx.QueryRow(ctx, `SELECT id,coalesce(email,''),role,created_at,expires_at,completed_at,revoked_at,secret_ciphertext FROM invites WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, id).Scan(&out.ID, &out.Email, &out.Role, &out.CreatedAt, &out.ExpiresAt, &out.CompletedAt, &out.RevokedAt, &sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	if err != nil {
		return out, nil, err
	}
	if actorRole != "owner" && (out.Role == "owner" || out.Role == "admin") {
		return out, nil, ErrMembershipForbidden
	}
	out.finish(len(sealed) > 0 && len(u.inviteEncryptionKey) == 32)
	return out, sealed, nil
}
func (i *Invitation) finish(reveal bool) {
	i.Status = "pending"
	if i.CompletedAt != nil {
		i.Status = "accepted"
	} else if i.RevokedAt != nil {
		i.Status = "revoked"
	} else if !i.ExpiresAt.After(time.Now()) {
		i.Status = "expired"
	}
	i.CanReveal = reveal && i.Status == "pending"
}
func (u *Users) Invitations(ctx context.Context, tenant, actor uuid.UUID) ([]Invitation, error) {
	out := []Invitation{}
	err := pg.InTenantTx(ctx, u.pool, tenant.String(), func(tx pgx.Tx) error {
		role, e := lockWorkspaceManager(ctx, tx, tenant, actor)
		if e != nil {
			return e
		}
		rows, e := tx.Query(ctx, `SELECT id,coalesce(email,''),role,created_at,expires_at,completed_at,revoked_at,secret_ciphertext IS NOT NULL FROM invites WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 500`, tenant)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var item Invitation
			var hasCipher bool
			if e = rows.Scan(&item.ID, &item.Email, &item.Role, &item.CreatedAt, &item.ExpiresAt, &item.CompletedAt, &item.RevokedAt, &hasCipher); e != nil {
				return e
			}
			item.finish(hasCipher && len(u.inviteEncryptionKey) == 32 && (role == "owner" || (item.Role != "owner" && item.Role != "admin")))
			out = append(out, item)
		}
		return rows.Err()
	})
	return out, err
}
func (u *Users) RevealInvitation(ctx context.Context, tenant, actor, id uuid.UUID) (string, error) {
	var secret string
	err := pg.InTenantTx(ctx, u.pool, tenant.String(), func(tx pgx.Tx) error {
		inv, sealed, e := u.managerInvite(ctx, tx, tenant, actor, id)
		if e != nil {
			return e
		}
		if inv.Status != "pending" {
			return ErrInviteInvalid
		}
		if !inv.CanReveal {
			return ErrInviteNotRecoverable
		}
		aead, e := u.inviteCipher()
		if e != nil {
			return e
		}
		if len(sealed) < aead.NonceSize() {
			return ErrInviteNotRecoverable
		}
		raw, e := aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], inviteAAD(tenant, id))
		if e != nil {
			return ErrInviteNotRecoverable
		}
		secret = string(raw)
		return nil
	})
	return secret, err
}
func (u *Users) RevokeInvitation(ctx context.Context, tenant, actor, id uuid.UUID) error {
	return pg.InTenantTx(ctx, u.pool, tenant.String(), func(tx pgx.Tx) error {
		inv, _, e := u.managerInvite(ctx, tx, tenant, actor, id)
		if e != nil {
			return e
		}
		if inv.Status == "accepted" {
			return ErrInviteInvalid
		}
		_, e = tx.Exec(ctx, `UPDATE invites SET revoked_at=coalesce(revoked_at,now()),secret_ciphertext=NULL WHERE id=$1 AND tenant_id=$2`, id, tenant)
		return e
	})
}
func (u *Users) RegenerateInvitation(ctx context.Context, tenant, actor, id uuid.UUID) (string, Invitation, error) {
	var secret string
	var out Invitation
	err := pg.InTenantTx(ctx, u.pool, tenant.String(), func(tx pgx.Tx) error {
		old, _, e := u.managerInvite(ctx, tx, tenant, actor, id)
		if e != nil {
			return e
		}
		if old.Status == "accepted" {
			return ErrInviteInvalid
		}
		if e = canInviteHuman(ctx, tx, tenant, old.Role); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `UPDATE invites SET revoked_at=coalesce(revoked_at,now()),secret_ciphertext=NULL WHERE id=$1 AND tenant_id=$2`, id, tenant); e != nil {
			return e
		}
		secret, out, e = u.createInviteTx(ctx, tx, tenant, old.Role, old.Email, &actor, 7*24*time.Hour)
		return e
	})
	return secret, out, err
}
func canInviteHuman(ctx context.Context, tx pgx.Tx, tenant uuid.UUID, role string) error {
	var kind string
	if e := tx.QueryRow(ctx, `SELECT kind FROM tenants WHERE id=$1`, tenant).Scan(&kind); e != nil {
		return e
	}
	if kind == "personal" && role != RoleService {
		return ErrPersonalWorkspace
	}
	return nil
}
func (u *Users) NewMemberInvitation(ctx context.Context, tenant, actor uuid.UUID, role, email string) (string, Invitation, error) {
	if role != "owner" && role != "admin" && role != "member" && role != RoleService {
		return "", Invitation{}, ErrInvalidMembership
	}
	if strings.TrimSpace(email) != "" {
		var e error
		email, e = signupEmail(email)
		if e != nil {
			return "", Invitation{}, e
		}
	}
	var secret string
	var inv Invitation
	err := pg.InTenantTx(ctx, u.pool, tenant.String(), func(tx pgx.Tx) error {
		actorRole, e := lockWorkspaceManager(ctx, tx, tenant, actor)
		if e != nil {
			return e
		}
		if actorRole != "owner" && (role == "owner" || role == "admin") {
			return ErrMembershipForbidden
		}
		if e = canInviteHuman(ctx, tx, tenant, role); e != nil {
			return e
		}
		secret, inv, e = u.createInviteTx(ctx, tx, tenant, role, email, &actor, 7*24*time.Hour)
		return e
	})
	return secret, inv, err
}
