package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"whatserver2/internal/pg"
)

// Passkey stores public authenticator state and an opaque, client-encrypted key.
type Passkey struct {
	ID           uuid.UUID       `json:"id"`
	UserID       uuid.UUID       `json:"-"`
	CredentialID []byte          `json:"-"`
	Credential   json.RawMessage `json:"-"`
	Label        string          `json:"label"`
	RPID         string          `json:"-"`
	PRFSalt      []byte          `json:"-"`
	WrappedUSK   []byte          `json:"-"`
	Version      int64           `json:"-"`
	CreatedAt    time.Time       `json:"created_at"`
	LastUsedAt   *time.Time      `json:"last_used_at,omitempty"`
}

type PasskeyChallenge struct {
	ID        uuid.UUID
	Kind      string
	UserID    uuid.UUID
	SessionID uuid.UUID
	Origin    string
	Data      json.RawMessage
	Label     string
	ExpiresAt time.Time
}

func (u *Users) inIdentity(ctx context.Context, userID uuid.UUID, fn func(pgx.Tx) error) error {
	return pg.InTx(ctx, u.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.user_id',$1,true)`, userID.String()); err != nil {
			return err
		}
		return fn(tx)
	})
}

// LoginIdentity is a credential lookup, not authentication. Only callers that
// validate another authentication proof may issue a session for its result.
func (u *Users) LoginIdentity(ctx context.Context, id uuid.UUID) (User, error) {
	user, err := u.identity(ctx, id)
	if err != nil || user.Status != "active" {
		return User{}, ErrBadCredentials
	}
	return u.defaultWorkspace(ctx, user)
}

func (u *Users) Passkeys(ctx context.Context, userID uuid.UUID) ([]Passkey, error) {
	out := []Passkey{}
	err := u.inIdentity(ctx, userID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id,user_id,credential_id,credential,label,rp_id,prf_salt,wrapped_usk,version,created_at,last_used_at FROM user_passkeys WHERE user_id=$1 AND revoked_at IS NULL ORDER BY created_at`, userID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p Passkey
			if err := scanPasskey(rows, &p); err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	return out, err
}

func scanPasskey(row pgx.Row, p *Passkey) error {
	return row.Scan(&p.ID, &p.UserID, &p.CredentialID, &p.Credential, &p.Label, &p.RPID, &p.PRFSalt, &p.WrappedUSK, &p.Version, &p.CreatedAt, &p.LastUsedAt)
}

func (u *Users) Passkey(ctx context.Context, userID uuid.UUID, credentialID []byte) (Passkey, error) {
	var p Passkey
	err := u.inIdentity(ctx, userID, func(tx pgx.Tx) error {
		return scanPasskey(tx.QueryRow(ctx, `SELECT id,user_id,credential_id,credential,label,rp_id,prf_salt,wrapped_usk,version,created_at,last_used_at FROM user_passkeys WHERE user_id=$1 AND credential_id=$2 AND revoked_at IS NULL`, userID, credentialID), &p)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrBadCredentials
	}
	return p, err
}

func (u *Users) AddPasskey(ctx context.Context, p *Passkey, sessionID uuid.UUID) error {
	return u.inIdentity(ctx, p.UserID, func(tx pgx.Tx) error {
		if err := lockPasskeyRegistration(ctx, tx, p.UserID); err != nil {
			return err
		}
		// Registration challenges are bound to a particular authenticated session.
		// Lock it so logout/recovery cannot win between revalidation and insertion.
		var active uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT id FROM sessions WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at>now() FOR UPDATE`, sessionID, p.UserID).Scan(&active); err != nil {
			return ErrNoSession
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM user_passkeys WHERE user_id=$1 AND revoked_at IS NULL`, p.UserID).Scan(&n); err != nil {
			return err
		}
		if n >= 12 {
			return errors.New("at most 12 passkeys per account")
		}
		return tx.QueryRow(ctx, `INSERT INTO user_passkeys(user_id,credential_id,credential,label,rp_id,prf_salt,wrapped_usk) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id,version,created_at`, p.UserID, p.CredentialID, p.Credential, p.Label, p.RPID, p.PRFSalt, p.WrappedUSK).Scan(&p.ID, &p.Version, &p.CreatedAt)
	})
}

// Registration and recovery must serialize before either locks a session or
// credential row. Otherwise recovery can scan existing passkeys, wait for a
// registering session, and miss the new credential committed during that wait.
func lockPasskeyRegistration(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "passkeys/"+userID.String())
	return err
}

// UpdatePasskey uses a version guard so concurrent assertions cannot roll back
// signature counters. A competing successful assertion simply requires retry.
func (u *Users) UpdatePasskey(ctx context.Context, p Passkey, credential json.RawMessage) error {
	return u.inIdentity(ctx, p.UserID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE user_passkeys SET credential=$1,version=version+1,last_used_at=now() WHERE id=$2 AND user_id=$3 AND version=$4 AND revoked_at IS NULL`, credential, p.ID, p.UserID, p.Version)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrBadCredentials
		}
		return nil
	})
}

func (u *Users) RevokePasskey(ctx context.Context, userID, id uuid.UUID) error {
	return u.inIdentity(ctx, userID, func(tx pgx.Tx) error {
		if err := lockPasskeyRegistration(ctx, tx, userID); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE user_passkeys SET revoked_at=now() WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL`, id, userID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrNotFound
		}
		_, err = tx.Exec(ctx, `UPDATE sessions SET revoked_at=now() WHERE passkey_id=$1 AND user_id=$2 AND revoked_at IS NULL`, id, userID)
		return err
	})
}

func (u *Users) CreatePasskeyChallenge(ctx context.Context, c PasskeyChallenge) error {
	return pg.InTx(ctx, u.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM passkey_challenges WHERE expires_at<now()`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO passkey_challenges(id,kind,user_id,session_id,origin,data,label,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, c.ID, c.Kind, nullableWorkspace(c.UserID), nullableWorkspace(c.SessionID), c.Origin, c.Data, c.Label, c.ExpiresAt)
		return err
	})
}

// ConsumePasskeyChallenge spends the challenge even if signature validation
// subsequently fails. Wrong identity/session/origin cannot consume the flow.
func (u *Users) ConsumePasskeyChallenge(ctx context.Context, id uuid.UUID, kind, origin string, userID, sessionID uuid.UUID) (PasskeyChallenge, error) {
	c := PasskeyChallenge{ID: id, Kind: kind, Origin: origin, UserID: userID, SessionID: sessionID}
	err := u.pool.QueryRow(ctx, `DELETE FROM passkey_challenges WHERE id=$1 AND kind=$2 AND origin=$3 AND user_id IS NOT DISTINCT FROM $4::uuid AND session_id IS NOT DISTINCT FROM $5::uuid AND expires_at>now() RETURNING data,label,expires_at`, id, kind, origin, nullableWorkspace(userID), nullableWorkspace(sessionID)).Scan(&c.Data, &c.Label, &c.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrBadCredentials
	}
	return c, err
}
