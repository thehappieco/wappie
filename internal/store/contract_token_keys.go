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
// CONFLICT DO NOTHING), then reads the pins back: a token whose pin is
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
	var changed []uuid.UUID
	err = forEachRow(rows, func(row pgx.Rows) error {
		var id uuid.UUID
		var key []byte
		if err := row.Scan(&id, &key); err != nil {
			return err
		}
		if !bytes.Equal(key, want[id]) {
			changed = append(changed, id)
		}
		return nil
	})
	if err != nil || len(changed) == 0 {
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
