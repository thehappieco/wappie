package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/pg"
)

// The token grant (the plan's 5.3): an owner or admin who reads a number now
// seals its key to a token's hidden identity, from Wappie's own grant-token
// page, once the token holds an applied Read there and a signed GET of its
// record is under a minute old.

// TokenGrantFresh is how old the last signed GET of a token's record may be
// for a grant to it (design 3.4): older, the page fetches it again first.
const TokenGrantFresh = time.Minute

// The refusals of a token grant. A token of another workspace answers
// ErrNotFound, exactly as an unknown one.
var (
	// ErrTokenNotLive: the token is revoked, expired, stopped, suspended
	// here, or tokens are off.
	ErrTokenNotLive = errors.New("store: this token is not live here")
	// ErrTokenKeyChanged: the token has no pinned reading key, its record
	// brought another, or its identity's key is not the pin.
	ErrTokenKeyChanged = errors.New("store: this token's reading key is not the one Wappie pinned")
	// ErrTokenStale: the last signed GET of its record is over a minute old.
	ErrTokenStale = errors.New("store: this token's record was not fetched in the last minute")
	// ErrTokenNoRead: the token holds no applied Read on the number.
	ErrTokenNoRead = errors.New("store: this token does not read this number")
	// ErrTokenEpoch: the grant is not for the number's current epoch.
	ErrTokenEpoch = errors.New("store: a token's grant is for the number's current epoch")
	// ErrSealerCannotRead: the one who sealed it is not an owner or admin who
	// reads the number now.
	ErrSealerCannotRead = errors.New("store: only an owner or admin who reads the number can share its key with a token")
)

// TokenGrant is a grant of a number's key to a token's identity: the
// number's key at its current epoch, sealed to the token's pinned key by
// Sealer, an owner or admin who reads it. Now is Wappie's clock at the
// request's start.
type TokenGrant struct {
	Workspace, Token, Device uuid.UUID
	Epoch                    uint16
	SealedDSK                []byte
	Sealer                   uuid.UUID
	Now                      time.Time
}

// PutTokenGrant writes a token grant in one transaction (the plan's 5.3):
//  1. the workspace's row (lockWorkspaceAccess, as PutGrant takes it), then
//     the token's row FOR SHARE and its Read perm on the number FOR SHARE
//     (DB25 steps 3 to 5), so a Read drop racing it waits for it and then
//     deletes the grant it wrote;
//  2. the token is live (tokenLiveSQL);
//  3. its pin exists, equals its identity's key, and its key never changed;
//  4. its record was fetched by a signed GET under a minute ago;
//  5. its Read on the number is applied;
//  6. the number is live in the workspace, and the epoch its current one;
//  7. the sealer is an owner or admin of the workspace who reads the number
//     now;
//  8. the grant, to the identity, sealed by the sealer.
func (t *Tokens) PutTokenGrant(ctx context.Context, g TokenGrant) error {
	if len(g.SealedDSK) == 0 {
		return errors.New("store: a grant with no sealed key is not a grant")
	}
	return pg.InTenantTx(ctx, t.pool, g.Workspace.String(), func(tx pgx.Tx) error {
		if err := lockWorkspaceAccess(ctx, tx, g.Workspace); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		var identity *uuid.UUID
		var live, keyed bool
		var fetched *time.Time
		err := tx.QueryRow(ctx, `SELECT CASE WHEN t.identity_dropped_at IS NULL THEN t.identity_user_id END, `+tokenLiveSQL("$2")+`,
				t.key_changed_at IS NULL AND EXISTS (SELECT 1 FROM contract_token_pins p JOIN users u ON u.id = t.identity_user_id
				                                     WHERE p.token_id = t.id AND u.token_identity AND u.public_key = p.key),
				t.fetched_at
			FROM contract_tokens t WHERE t.id = $1 FOR SHARE OF t`, g.Token, g.Now).Scan(&identity, &live, &keyed, &fetched)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		var state string
		err = tx.QueryRow(ctx, `SELECT state FROM contract_token_perms WHERE token_id = $1 AND device_id = $2 AND perm = 'read' FOR SHARE`,
			g.Token, g.Device).Scan(&state)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		switch {
		case !live:
			return ErrTokenNotLive
		case identity == nil || !keyed:
			return ErrTokenKeyChanged
		case fetched == nil || g.Now.Sub(*fetched) > TokenGrantFresh:
			return ErrTokenStale
		case state != tokenApplied:
			return ErrTokenNoRead
		}
		var epoch int32
		err = tx.QueryRow(ctx, `SELECT current_epoch FROM devices WHERE id = $1 AND deleted_at IS NULL`, g.Device).Scan(&epoch)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNumberGone
		}
		if err != nil {
			return err
		}
		if epoch != int32(g.Epoch) {
			return ErrTokenEpoch
		}
		if role, err := memberRoleTx(ctx, tx, g.Workspace, g.Sealer); err != nil || (role != "owner" && role != "admin") {
			if err != nil && !errors.Is(err, ErrNotFound) {
				return err
			}
			return ErrSealerCannotRead
		}
		p, err := devicePermissionTx(ctx, tx, g.Workspace, g.Sealer, g.Device)
		if errors.Is(err, ErrNotFound) || err == nil && !p.Allows(ActionRead) {
			return ErrSealerCannotRead
		}
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO device_key_grants (tenant_id, device_id, user_id, epoch, sealed_dsk, granted_by)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (user_id, device_id, epoch) DO UPDATE SET sealed_dsk = EXCLUDED.sealed_dsk, granted_by = EXCLUDED.granted_by`,
			g.Workspace, g.Device, *identity, int32(g.Epoch), g.SealedDSK, g.Sealer)
		return numberGone(err)
	})
}

// memberRoleTx is user's active role in tenant: an active membership of an
// active account, unexpired; ErrNotFound with none.
func memberRoleTx(ctx context.Context, tx pgx.Tx, tenant, user uuid.UUID) (string, error) {
	var role string
	err := tx.QueryRow(ctx, `SELECT m.role FROM workspace_memberships m JOIN users u ON u.id = m.user_id
		WHERE m.tenant_id = $1 AND m.user_id = $2 AND m.status = 'active' AND u.status = 'active'
		  AND (m.expires_at IS NULL OR m.expires_at > now())`, tenant, user).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return role, err
}

// The states of a token's Read on a number, as the grant page shows them.
const (
	TokenReadApplied = "applied"
	TokenReadWaiting = "waiting"
	TokenReadRefused = "refused"
	TokenReadNone    = "none"
)

// TokenGrantContext is what the grant page draws from (the plan's 5.3):
// the token's name, its pinned key and fingerprint, its identity, when its
// record was last fetched by a signed GET, and per number asked.
type TokenGrantContext struct {
	ID          uuid.UUID
	Name        string
	Key         []byte
	Fingerprint string
	Identity    uuid.UUID
	FetchedAt   *time.Time
	// Live is tokenLiveSQL at Now; KeyChanged its record's key is not the
	// pin.
	Live, KeyChanged bool
	Numbers          []TokenGrantNumber
}

// TokenGrantNumber is one number of a grant page: its archive namespace and
// current epoch, the token's Read there (TokenRead*), and whether the
// identity holds a grant at that epoch.
type TokenGrantNumber struct {
	Device          uuid.UUID
	ArchiveTenantID uuid.UUID
	CurrentEpoch    uint16
	Read            string
	Granted         bool
}

// TokenGrantContext reads a grant page's context, writing nothing: the
// identity is made at pin time. A token of another workspace, or one with no
// pin or identity yet, answers ErrNotFound, and a number that is not live in
// the workspace is left out.
func (t *Tokens) TokenGrantContext(ctx context.Context, workspace, token uuid.UUID, devices []uuid.UUID, now time.Time) (TokenGrantContext, error) {
	out := TokenGrantContext{ID: token, Numbers: []TokenGrantNumber{}}
	err := pg.InTenantTx(ctx, t.pool, workspace.String(), func(tx pgx.Tx) error {
		var identity *uuid.UUID
		err := tx.QueryRow(ctx, `SELECT t.name, p.key, p.fingerprint, CASE WHEN t.identity_dropped_at IS NULL THEN t.identity_user_id END,
				t.fetched_at, `+tokenLiveSQL("$2")+`, t.key_changed_at IS NOT NULL
			FROM contract_tokens t JOIN contract_token_pins p ON p.token_id = t.id WHERE t.id = $1`, token, now).
			Scan(&out.Name, &out.Key, &out.Fingerprint, &identity, &out.FetchedAt, &out.Live, &out.KeyChanged)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && identity == nil {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		out.Identity = *identity
		rows, err := tx.Query(ctx, `SELECT d.id, d.archive_tenant_id, d.current_epoch, coalesce(p.state, 'none'),
				EXISTS (SELECT 1 FROM device_key_grants g WHERE g.device_id = d.id AND g.user_id = $2 AND g.epoch = d.current_epoch)
			FROM devices d LEFT JOIN contract_token_perms p ON p.token_id = $1 AND p.device_id = d.id AND p.perm = 'read'
			WHERE d.id = ANY ($3) AND d.deleted_at IS NULL ORDER BY d.id`, token, out.Identity, devices)
		if err != nil {
			return err
		}
		return forEachRow(rows, func(row pgx.Rows) error {
			var n TokenGrantNumber
			var epoch int32
			var state string
			if err := row.Scan(&n.Device, &n.ArchiveTenantID, &epoch, &state, &n.Granted); err != nil {
				return err
			}
			if epoch < 0 || epoch > maxEpoch {
				return fmt.Errorf("store: epoch %d is out of range", epoch)
			}
			n.CurrentEpoch = uint16(epoch)
			switch state {
			case tokenApplied:
				n.Read = TokenReadApplied
			case tokenWaiting, tokenPending:
				n.Read = TokenReadWaiting
			case tokenRefused:
				n.Read = TokenReadRefused
			default:
				n.Read = TokenReadNone
			}
			out.Numbers = append(out.Numbers, n)
			return nil
		})
	})
	return out, err
}

// TokenKeyHolder is a token whose identity holds a number's key: never a
// reader, a holder or a backup (L2), listed apart.
type TokenKeyHolder struct {
	ID        uuid.UUID
	Name      string
	Epoch     uint16
	GrantedAt time.Time
	// GrantedBy is the address of whoever sealed it, empty when they are
	// gone.
	GrantedBy string
}

// TokenReaders lists the tokens whose identity holds a grant for one device,
// for device.readers' tokens.
func (k *Keys) TokenReaders(ctx context.Context, tenant, device uuid.UUID) ([]TokenKeyHolder, error) {
	out := []TokenKeyHolder{}
	err := pg.InTenantTx(ctx, k.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT t.id, t.name, g.epoch, g.created_at, coalesce(former.email, b.email, '')
			FROM device_key_grants g
			JOIN contract_tokens t ON g.user_id = t.identity_user_id AND t.identity_dropped_at IS NULL
			LEFT JOIN users b ON b.id = g.granted_by
			LEFT JOIN workspace_member_history former ON former.tenant_id = g.tenant_id AND former.user_id = g.granted_by
			WHERE g.device_id = $1 ORDER BY t.name, t.id, g.epoch`, device)
		if err != nil {
			return err
		}
		return forEachRow(rows, func(row pgx.Rows) error {
			var h TokenKeyHolder
			var epoch int32
			if err := row.Scan(&h.ID, &h.Name, &epoch, &h.GrantedAt, &h.GrantedBy); err != nil {
				return err
			}
			if epoch < 1 || epoch > maxEpoch {
				return fmt.Errorf("store: grant epoch %d is out of range", epoch)
			}
			h.Epoch = uint16(epoch)
			out = append(out, h)
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("store: list token readers: %w", err)
	}
	return out, nil
}
