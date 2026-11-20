package store

import (
	"bytes"
	"context"
	"encoding/base64"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/obs"
)

// A token's reading key (the plan's 5.1): the X25519 public key its client
// made, pinned per token id from a good record only, one that passed
// TokenRecord.Validate and ReadingKey.Check, from the feed or a by-id GET.
// A record that brings another key is still applied for what it narrows,
// but the token's key_changed_at is set for good: its new Read grants are
// refused as reading_key_changed by the judge, and so is every later grant
// write. Grants already sealed to the pinned key stay; only its holder
// opens them. A null key (after a reset) leaves the pin.

// decodeReadingKey reads a reading key's text, which the record's Validate
// checked: the unpadded base64url of 32 bytes.
func decodeReadingKey(text string) ([]byte, error) {
	if err := kc.ValidReadingKey(text); err != nil {
		return nil, err
	}
	return base64.RawURLEncoding.DecodeString(text)
}

// readingKeyFingerprint is a pinned key's fingerprint, as the
// acknowledgement's held entry names it.
func readingKeyFingerprint(key []byte) string {
	fp, err := kc.ReadingKeyFingerprint(base64.RawURLEncoding.EncodeToString(key))
	if err != nil {
		return ""
	}
	return fp
}

// pinTokenKeysTx pins each record's key in the workspace of tx (INSERT … ON
// CONFLICT DO NOTHING), then reads the pins back: a token whose key equals
// its pin gets its identity (ensureTokenIdentitiesTx), and one whose pin is
// another key gets key_changed_at, once, and one ERROR. The round holds the
// tokens' rows already (DB25 step 4).
func pinTokenKeysTx(ctx context.Context, tx pgx.Tx, ws uuid.UUID, now time.Time, pins []pinRow) error {
	if len(pins) == 0 {
		return nil
	}
	n := len(pins)
	tokens, keys, fps := make([]uuid.UUID, n), make([][]byte, n), make([]string, n)
	registered, until := make([]time.Time, n), make([]time.Time, n)
	want := map[uuid.UUID][]byte{}
	for i, p := range pins {
		tokens[i], keys[i], fps[i], registered[i], until[i] = p.token, p.key, p.fingerprint, p.registeredAt, p.until
		want[p.token] = p.key
	}
	if _, err := tx.Exec(ctx, `INSERT INTO contract_token_pins (token_id, tenant_id, key, fingerprint, registered_at, pinned_at, until)
		SELECT p.token, $1, p.key, p.fp, p.registered, $2, p.until
		FROM unnest($3::uuid[], $4::bytea[], $5::text[], $6::timestamptz[], $7::timestamptz[]) AS p(token, key, fp, registered, until)
		ON CONFLICT (token_id) DO NOTHING`, ws, now, tokens, keys, fps, registered, until); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT token_id, key FROM contract_token_pins WHERE token_id = ANY ($1)`, tokens)
	if err != nil {
		return err
	}
	var changed, same []uuid.UUID
	err = forEachRow(rows, func(row pgx.Rows) error {
		var id uuid.UUID
		var key []byte
		if err := row.Scan(&id, &key); err != nil {
			return err
		}
		if bytes.Equal(key, want[id]) {
			same = append(same, id)
		} else {
			changed = append(changed, id)
		}
		return nil
	})
	if err != nil {
		return err
	}
	// The key equals the pin: the token's identity, if it is live and has
	// none yet.
	if err := ensureTokenIdentitiesTx(ctx, tx, ws, now, same); err != nil || len(changed) == 0 {
		return err
	}
	rows, err = tx.Query(ctx, `UPDATE contract_tokens SET key_changed_at = $2
		WHERE id = ANY ($1) AND key_changed_at IS NULL RETURNING id`, changed, now)
	if err != nil {
		return err
	}
	return forEachRow(rows, func(row pgx.Rows) error {
		var id uuid.UUID
		if err := row.Scan(&id); err != nil {
			return err
		}
		obs.LoggerFrom(ctx).Error("contract: a token record brings another reading key than the one pinned; its new grants are refused",
			"token", id, "class", TokenErrorKeyChanged)
		return nil
	})
}

// The hidden identity (the plan's 5.1 and 5.2): a users row per live token,
// in its workspace, whose public key is the token's pinned reading key, so a
// grant can be sealed to it (GrantRow binds its user id, which never changes
// for the token's life). It is made at pin time, so the grant page's load
// writes nothing, and once dropped it is never made again. It has no
// membership (0053's create_initial_membership), so every listing and
// protection, which join workspace_memberships, leave it out, and its
// address, with no salt, is a decoy at sign-in.

// tokenIdentityEmail is a token identity's address: it is in user_logins,
// as every account's is, and answers as an unknown address.
func tokenIdentityEmail(token uuid.UUID) string { return "t-" + token.String() + "@token.invalid" }

// ensureTokenIdentitiesTx makes the identity of each of tokens that is live
// and has none yet, in the workspace of tx, whose rows the round holds.
func ensureTokenIdentitiesTx(ctx context.Context, tx pgx.Tx, ws uuid.UUID, now time.Time, tokens []uuid.UUID) error {
	if len(tokens) == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT t.id, p.key FROM contract_tokens t JOIN contract_token_pins p ON p.token_id = t.id
		WHERE t.id = ANY ($1) AND t.identity_user_id IS NULL AND t.identity_dropped_at IS NULL AND t.key_changed_at IS NULL
		  AND t.revoked_at IS NULL AND t.unlisted_at IS NULL AND t.ended_at IS NULL AND t.expires_at > $2
		ORDER BY t.id`, tokens, now)
	if err != nil {
		return err
	}
	var ids []uuid.UUID
	var keys [][]byte
	var emails []string
	err = forEachRow(rows, func(row pgx.Rows) error {
		var id uuid.UUID
		var key []byte
		if err := row.Scan(&id, &key); err != nil {
			return err
		}
		ids, keys, emails = append(ids, id), append(keys, key), append(emails, tokenIdentityEmail(id))
		return nil
	})
	if err != nil || len(ids) == 0 {
		return err
	}
	_, err = tx.Exec(ctx, `WITH made AS (
			INSERT INTO users (tenant_id, email, public_key, role, token_identity)
			SELECT $1, x.email, x.key, 'service', true FROM unnest($2::text[], $3::bytea[]) AS x(email, key)
			RETURNING id, email)
		UPDATE contract_tokens t SET identity_user_id = made.id
		FROM made JOIN unnest($4::uuid[], $2::text[]) AS x(token, email) ON x.email = made.email
		WHERE t.id = x.token`, ws, emails, keys, ids)
	return err
}

// dropTokenGrantsTx deletes token identities' grants on numbers, at every
// epoch: a Read dropped, an item un-ticked, a bad record's narrowing.
func dropTokenGrantsTx(ctx context.Context, tx pgx.Tx, drops []grantDrop) error {
	if len(drops) == 0 {
		return nil
	}
	users, devices := make([]uuid.UUID, len(drops)), make([]uuid.UUID, len(drops))
	for i, d := range drops {
		users[i], devices[i] = d.identity, d.device
	}
	_, err := tx.Exec(ctx, `DELETE FROM device_key_grants g USING unnest($1::uuid[], $2::uuid[]) AS d(u, device)
		WHERE g.user_id = d.u AND g.device_id = d.device`, users, devices)
	return err
}

// dropTokenIdentitiesTx deletes the hidden identity of each of tokens (a
// revocation of any reason, an unlisting, an expiry), whose rows tx holds:
// identity_dropped_at first (DB25 step 4), then the users row, whose grants
// and login cascade (step 6). The pin stays, and so does the id the token
// keeps, which no trigger ever writes.
func dropTokenIdentitiesTx(ctx context.Context, tx pgx.Tx, now time.Time, tokens []uuid.UUID) error {
	if len(tokens) == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `UPDATE contract_tokens SET identity_dropped_at = $2
		WHERE id = ANY ($1) AND identity_user_id IS NOT NULL AND identity_dropped_at IS NULL RETURNING identity_user_id`, tokens, now)
	if err != nil {
		return err
	}
	identities, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil || len(identities) == 0 {
		return err
	}
	_, err = tx.Exec(ctx, `DELETE FROM users WHERE id = ANY ($1) AND token_identity`, identities)
	return err
}

// lockGrantWorkspacesTx takes, in id order and before any token row (DB25
// step 3), the tenants rows of the workspaces where tx may delete a token
// identity or its grants: those with a token that holds an identity and
// meets cond (a condition on contract_tokens, with args(ws) its
// parameters). Every write to device_key_grants locks its workspace's row
// anyway (0036's archive_owner_lock), so taking it later, under the token
// rows, would invert the order against a grant write.
func lockGrantWorkspacesTx(ctx context.Context, tx pgx.Tx, workspaces []uuid.UUID, cond string, args func(uuid.UUID) []any) error {
	lock, err := grantWorkspacesTx(ctx, tx, workspaces, cond, args)
	if err != nil || len(lock) == 0 {
		return err
	}
	_, err = tx.Exec(ctx, `SELECT 1 FROM tenants WHERE id = ANY ($1) ORDER BY id FOR UPDATE`, lock)
	return err
}

// lockPageWorkspacesTx is a token commit's step 3, before any token row:
// every workspace of the page (workspaces, in id order), in one id-ordered
// pass, FOR UPDATE where tx may delete a token identity or its grants, else
// FOR KEY SHARE, what the foreign keys of the token rows and perms it
// inserts, and of an identity's token row it updates, take anyway. of(ws)
// is the workspace's tokens in the page, and whether one is listed twice.
// It may delete where one of its tokens holds an identity (as
// lockGrantWorkspacesTx), whether or not a record then drops anything, and
// where a token is listed twice, since an identity made by one record a
// later one may drop: any write to device_key_grants, cascades included,
// locks the row FOR UPDATE (0036), and taken then it would come after the
// token rows. One pass, so it never takes a lower workspace's row after a
// higher one's, nor upgrades a row it holds.
func lockPageWorkspacesTx(ctx context.Context, tx pgx.Tx, workspaces []uuid.UUID, of func(uuid.UUID) ([]uuid.UUID, bool)) error {
	lock, err := grantWorkspacesTx(ctx, tx, workspaces, `id = ANY ($1)`, func(ws uuid.UUID) []any {
		ids, _ := of(ws)
		return []any{ids}
	})
	if err != nil {
		return err
	}
	update := map[uuid.UUID]bool{}
	for _, ws := range lock {
		update[ws] = true
	}
	for _, ws := range workspaces {
		strength := `FOR KEY SHARE`
		if _, twice := of(ws); update[ws] || twice {
			strength = `FOR UPDATE`
		}
		if _, err := tx.Exec(ctx, `SELECT 1 FROM tenants WHERE id = $1 `+strength, ws); err != nil {
			return err
		}
	}
	return nil
}

// grantWorkspacesTx are those of workspaces, in their order, with a token
// that holds an identity and meets cond.
func grantWorkspacesTx(ctx context.Context, tx pgx.Tx, workspaces []uuid.UUID, cond string, args func(uuid.UUID) []any) ([]uuid.UUID, error) {
	var lock []uuid.UUID
	for _, ws := range workspaces {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, ws.String()); err != nil {
			return nil, err
		}
		var holds bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM contract_tokens
			WHERE identity_user_id IS NOT NULL AND identity_dropped_at IS NULL AND (`+cond+`))`, args(ws)...).Scan(&holds); err != nil {
			return nil, err
		}
		if holds {
			lock = append(lock, ws)
		}
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', '', true)`); err != nil {
		return nil, err
	}
	return lock, nil
}
