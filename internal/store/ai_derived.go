package store

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/pg"
)

// Derived records (docs/mcp-enclave.md §18.8): one sealed result per message
// and function, made in the enclave under a key derived from the number's
// archive key, with a dedupe tag keyed the same way. This server stores them
// as they come, checks only what it can see (the message is on the number
// and of a type the function takes), and hands them to whoever reads the
// number. They count toward the storage quota, go with their message, and
// move with their device.

const (
	// AIDerivedSealedMax bounds a record: a 524,288-byte plaintext, the
	// header, the IV and the tag, as its column does.
	AIDerivedSealedMax = 524_323
	// aiDerivedHeader is "WDRV", the version byte and the epoch.
	aiDerivedHeader = 4 + 1 + 2
	// aiDerivedMin is the header, the IV and the tag.
	aiDerivedMin = aiDerivedHeader + 12 + 16
)

var aiDerivedMagic = []byte("WDRV")

// ValidAIDerived is a record of the derived format for this epoch: "WDRV",
// version 1, the epoch big-endian, then at least an IV and a tag, within
// AIDerivedSealedMax.
func ValidAIDerived(sealed []byte, epoch int) bool {
	return len(sealed) >= aiDerivedMin && len(sealed) <= AIDerivedSealedMax && bytes.HasPrefix(sealed, aiDerivedMagic) &&
		sealed[4] == 1 && int(binary.BigEndian.Uint16(sealed[5:7])) == epoch
}

// AIDerived is one stored result.
type AIDerived struct {
	MessageUID uuid.UUID
	Feature    string
	DeviceID   uuid.UUID
	Epoch      int
	Sealed     []byte
	DedupeTag  []byte
	// AuthorizationID is the authorization that stored it; nil once it has
	// ended and gone, or once the number moved to another workspace.
	AuthorizationID *uuid.UUID
	CreatedAt       time.Time
}

// PutAIDerived stores a result an authorization made, on the enclave's word.
// The message must be on the number and of a type the function takes
// (ErrAIDerivedMismatch). Without redo it only inserts, and a result already
// stored for the message and function is ErrAIDerivedExists; with redo it
// replaces it. A workspace whose storage is paused refuses it with
// ErrStoragePaused.
func (a *AI) PutAIDerived(ctx context.Context, tenant uuid.UUID, authorization string, in AIDerived, redo bool) error {
	switch {
	case !slices.Contains(AIFeatures, in.Feature), in.Epoch < 1 || in.Epoch > 65535, !ValidAIDerived(in.Sealed, in.Epoch), len(in.DedupeTag) != 32:
		return errors.New("store: a result needs a function, an epoch, a sealed record of that epoch and a 32-byte tag")
	}
	return pg.InTenantTx(ctx, a.pool, tenant.String(), func(tx pgx.Tx) error {
		var messageType string
		var isGIF bool
		err := tx.QueryRow(ctx, `SELECT m.type, coalesce(d.is_gif, false) FROM messages m LEFT JOIN media d ON d.message_uid = m.uid
			WHERE m.uid=$1 AND m.device_id=$2 AND m.kind='message'`, in.MessageUID, in.DeviceID).Scan(&messageType, &isGIF)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrAIDerivedMismatch
		}
		if err != nil {
			return err
		}
		if !AIFeatureFits(in.Feature, messageType, isGIF) {
			return ErrAIDerivedMismatch
		}
		conflict := `DO NOTHING`
		if redo {
			conflict = `DO UPDATE SET device_id=excluded.device_id, epoch=excluded.epoch, result_sealed=excluded.result_sealed,
				dedupe_tag=excluded.dedupe_tag, authorization_id=excluded.authorization_id, created_at=now()`
		}
		tag, err := tx.Exec(ctx, `INSERT INTO ai_derived (message_uid, feature, tenant_id, device_id, epoch, result_sealed, dedupe_tag, authorization_id)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (message_uid, feature) `+conflict,
			in.MessageUID, in.Feature, tenant, in.DeviceID, in.Epoch, in.Sealed, in.DedupeTag, authorization)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrAIDerivedExists
		}
		return nil
	})
}

const aiDerivedColumns = `message_uid, feature, device_id, epoch, result_sealed, dedupe_tag, authorization_id, created_at`

func scanAIDerived(rows pgx.Rows) ([]AIDerived, error) {
	defer rows.Close()
	out := []AIDerived{}
	for rows.Next() {
		var d AIDerived
		if err := rows.Scan(&d.MessageUID, &d.Feature, &d.DeviceID, &d.Epoch, &d.Sealed, &d.DedupeTag, &d.AuthorizationID, &d.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// AIDerivedFor lists the results stored for some of a number's messages, in
// the functions' order.
func (a *AI) AIDerivedFor(ctx context.Context, tenant, device uuid.UUID, uids []uuid.UUID) ([]AIDerived, error) {
	var out []AIDerived
	err := pg.InTenantTx(ctx, a.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+aiDerivedColumns+` FROM ai_derived
			WHERE tenant_id=$1 AND device_id=$2 AND message_uid = ANY ($3)
			ORDER BY message_uid, array_position(ARRAY['audio','video','image','document'], feature)`, tenant, device, uids)
		if err != nil {
			return err
		}
		out, err = scanAIDerived(rows)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("store: read AI results: %w", err)
	}
	return out, nil
}

// AIDedupeTag is one number's tag for a lookup.
type AIDedupeTag struct {
	DeviceID uuid.UUID
	Tag      []byte
}

// AIDerivedByTags finds the results of a function whose dedupe tag is one of
// the tags given for its number: the enclave's reuse lookup, which computes
// one tag per number it covers and asks for those pairs only. One result
// per number is enough to reuse, so it answers the newest of each.
func (a *AI) AIDerivedByTags(ctx context.Context, tenant uuid.UUID, feature string, tags []AIDedupeTag) ([]AIDerived, error) {
	devices := make([]uuid.UUID, 0, len(tags))
	values := make([][]byte, 0, len(tags))
	for _, t := range tags {
		devices = append(devices, t.DeviceID)
		values = append(values, t.Tag)
	}
	var out []AIDerived
	err := pg.InTenantTx(ctx, a.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT DISTINCT ON (d.device_id) d.message_uid, d.feature, d.device_id, d.epoch, d.result_sealed,
			       d.dedupe_tag, d.authorization_id, d.created_at
			FROM ai_derived d JOIN unnest($3::uuid[], $4::bytea[]) AS p(device_id, tag) ON d.device_id = p.device_id AND d.dedupe_tag = p.tag
			WHERE d.tenant_id=$1 AND d.feature=$2
			ORDER BY d.device_id, d.created_at DESC, d.message_uid`, tenant, feature, devices, values)
		if err != nil {
			return err
		}
		out, err = scanAIDerived(rows)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("store: look AI results up by tag: %w", err)
	}
	return out, nil
}

// DeleteAIDerived deletes one stored result: for its authorization's
// creator, an owner or an admin. A result whose authorization is gone, or
// that moved with its number, is the managers' alone.
func (a *AI) DeleteAIDerived(ctx context.Context, tenant, actor, uid uuid.UUID, feature string) error {
	return pg.InTenantTx(ctx, a.pool, tenant.String(), func(tx pgx.Tx) error {
		role, err := activeRoleTx(ctx, tx, tenant, actor)
		if err != nil {
			return err
		}
		var createdBy *uuid.UUID
		err = tx.QueryRow(ctx, `SELECT c.created_by FROM ai_derived d LEFT JOIN mcp_connections c ON c.id = d.authorization_id
			WHERE d.tenant_id=$1 AND d.message_uid=$2 AND d.feature=$3 FOR UPDATE OF d`, tenant, uid, feature).Scan(&createdBy)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrAINotFound
		}
		if err != nil {
			return err
		}
		if !managerRole(role) && (createdBy == nil || *createdBy != actor) {
			return ErrMembershipForbidden
		}
		_, err = tx.Exec(ctx, `DELETE FROM ai_derived WHERE tenant_id=$1 AND message_uid=$2 AND feature=$3`, tenant, uid, feature)
		return err
	})
}

// DeleteAIDerivedOf deletes every stored result of an authorization (its
// creator, an owner or an admin may) or of a number (an owner or an admin
// may). Exactly one of the two is named. An authorization this workspace
// does not have is ErrAINotFound.
func (a *AI) DeleteAIDerivedOf(ctx context.Context, tenant, actor uuid.UUID, authorization, device *uuid.UUID) (int64, error) {
	if (authorization == nil) == (device == nil) {
		return 0, errors.New("store: name an authorization or a number")
	}
	var deleted int64
	err := pg.InTenantTx(ctx, a.pool, tenant.String(), func(tx pgx.Tx) error {
		role, err := activeRoleTx(ctx, tx, tenant, actor)
		if err != nil {
			return err
		}
		if device != nil {
			if !managerRole(role) {
				return ErrMembershipForbidden
			}
			tag, err := tx.Exec(ctx, `DELETE FROM ai_derived WHERE tenant_id=$1 AND device_id=$2`, tenant, *device)
			deleted = tag.RowsAffected()
			return err
		}
		var createdBy uuid.UUID
		err = tx.QueryRow(ctx, `SELECT created_by FROM mcp_connections WHERE id=$1 AND tenant_id=$2 AND kind='ai'`, *authorization, tenant).Scan(&createdBy)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrAINotFound
		}
		if err != nil {
			return err
		}
		if createdBy != actor && !managerRole(role) {
			return ErrMembershipForbidden
		}
		tag, err := tx.Exec(ctx, `DELETE FROM ai_derived WHERE tenant_id=$1 AND authorization_id=$2`, tenant, *authorization)
		deleted = tag.RowsAffected()
		return err
	})
	if err != nil {
		return 0, err
	}
	return deleted, nil
}
