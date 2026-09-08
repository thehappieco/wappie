// Package store is the Postgres implementation of the persistence interfaces
// declared by the domain packages.
//
// The direction of the dependency matters: this package imports internal/wa to
// get its types, and internal/wa never imports this one. That is what lets the
// device supervisor be tested against a fake with no database at all, and it is
// wired together in cmd/whatserverd rather than by either side reaching for the
// other.
package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/pg"
	"whatserver2/internal/wa"
)

// Devices persists device rows.
type Devices struct{ pool *pgxpool.Pool }

// NewDevices returns a device store backed by pool.
func NewDevices(pool *pgxpool.Pool) *Devices { return &Devices{pool: pool} }

var _ wa.Store = (*Devices)(nil)

// ErrNotFound is returned when a device row does not exist for this tenant.
// Note that row-level security makes "belongs to another tenant" and "does not
// exist" indistinguishable here, which is the intended behaviour.
var ErrNotFound = errors.New("store: device not found")

// Device is a row from the devices table.
type Device struct {
	ID           string
	TenantID     string
	Identity     wa.Identity
	Label        string
	Status       wa.Status
	StatusReason string
	ReceiptMode  wa.ReceiptMode
	CreatedAt    time.Time
	// LastConnectedAt is when this device last reached "online", not when it
	// went offline. Zero for a device that has never connected.
	LastConnectedAt time.Time
	// Epoch is the archive key generation this device seals under. Zero means
	// no key, which is fatal to ingest on purpose.
	Epoch int
}

// SetStatus records a lifecycle transition.
// SetReceiptMode records what a device tells the other side.
//
// Persisted so the choice survives a restart: the mode is applied on connect,
// and a device that came back in the loud posture because nobody wrote the
// switch down would be a surprising way to stop being invisible.
func (d *Devices) SetReceiptMode(ctx context.Context, tenantID, deviceID string,
	mode wa.ReceiptMode) error {
	return pg.InTenantTx(ctx, d.pool, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE devices SET receipt_mode = $3 WHERE id = $1 AND tenant_id = $2`,
			deviceID, tenantID, string(mode))
		if err != nil {
			return fmt.Errorf("store: set receipt mode: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

func (d *Devices) SetStatus(ctx context.Context, tenantID, deviceID string, status wa.Status, reason string) error {
	return pg.InTenantTx(ctx, d.pool, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE devices
			   SET status = $2, status_reason = $3,
			       last_connected_at = CASE WHEN $2 = 'online' THEN now() ELSE last_connected_at END
			 WHERE id = $1`, deviceID, string(status), reason)
		if err != nil {
			return fmt.Errorf("store: set device status: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("%w: %s", ErrNotFound, deviceID)
		}
		return nil
	})
}

// SetIdentity records the LID and phone number learned from pairing.
//
// Each half is written only when present, using COALESCE so a later event that
// carries just one identifier cannot blank out the other. That mirrors the
// merge rule in wa.Identity and matters because LID may arrive without a phone
// number and, for some accounts, a phone number never arrives at all.
func (d *Devices) SetIdentity(ctx context.Context, tenantID, deviceID string, id wa.Identity) error {
	var lid, pn *string
	if !id.LID.IsEmpty() {
		s := id.LID.String()
		lid = &s
	}
	if !id.PN.IsEmpty() {
		s := id.PN.String()
		pn = &s
	}
	return pg.InTenantTx(ctx, d.pool, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE devices
			   SET lid       = COALESCE($2, lid),
			       pn        = COALESCE($3, pn),
			       push_name = CASE WHEN $4 <> '' THEN $4 ELSE push_name END
			 WHERE id = $1`, deviceID, lid, pn, id.PushName)
		if err != nil {
			return fmt.Errorf("store: set device identity: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("%w: %s", ErrNotFound, deviceID)
		}
		return nil
	})
}

// Create inserts a device that has not been paired yet.
func (d *Devices) Create(ctx context.Context, tenantID, label string, mode wa.ReceiptMode) (Device, error) {
	return d.CreateWithID(ctx, tenantID, "", label, mode)
}

// CreateWithID lets the caller choose the identifier.
//
// Pairing does, and has to: a key grant binds to the device, so the grants are
// sealed before this row exists. Asking for an id first and sealing afterwards
// would leave a device that exists with no key for the length of a round trip,
// and the first message can arrive inside that window. An empty id keeps the
// database's own uuidv7.
func (d *Devices) CreateWithID(ctx context.Context, tenantID, id, label string,
	mode wa.ReceiptMode) (Device, error) {
	dev := Device{TenantID: tenantID, Label: label, Status: wa.StatusNew, ReceiptMode: mode}
	var chosen *string
	if id != "" {
		if _, err := uuid.Parse(id); err != nil {
			return Device{}, fmt.Errorf("store: %q is not a device id: %w", id, err)
		}
		chosen = &id
	}
	err := pg.InTenantTx(ctx, d.pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			INSERT INTO devices (id, tenant_id, label, status, receipt_mode)
			VALUES (coalesce($4::uuid, uuidv7()), $1, $2, 'new', $3)
			RETURNING id::text`, tenantID, label, string(mode), chosen).Scan(&dev.ID)
	})
	if err != nil {
		return Device{}, fmt.Errorf("store: create device: %w", err)
	}
	return dev, nil
}

// ErrAmbiguous means an id prefix matched more than one device.
var ErrAmbiguous = errors.New("store: that id prefix matches more than one device")

// Resolve turns a full id or a unique prefix into a device.
//
// Prefixes are accepted because the listing shows a short form, the way git
// shows short hashes. Displaying an identifier that cannot then be typed back
// is a trap, and the alternative — printing full UUIDs in a table — makes the
// listing unreadable.
//
// A prefix matching several devices is an error rather than a guess: picking
// one would eventually send a message from the wrong account.
func (d *Devices) Resolve(ctx context.Context, tenantID, idOrPrefix string) (Device, error) {
	if idOrPrefix == "" {
		return Device{}, fmt.Errorf("%w: no device id given", ErrNotFound)
	}
	// A full uuid resolves directly; anything shorter is treated as a prefix.
	if _, err := uuid.Parse(idOrPrefix); err == nil {
		return d.Get(ctx, tenantID, idOrPrefix)
	}

	var matches []Device
	err := pg.InTenantTx(ctx, d.pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, selectDevices+` WHERE id::text LIKE $1 || '%' LIMIT 5`, idOrPrefix)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var dev Device
			if err := scanDevice(rows, &dev); err != nil {
				return err
			}
			matches = append(matches, dev)
		}
		return rows.Err()
	})
	if err != nil {
		return Device{}, fmt.Errorf("store: resolve device: %w", err)
	}

	switch len(matches) {
	case 0:
		return Device{}, fmt.Errorf("%w: %s", ErrNotFound, idOrPrefix)
	case 1:
		return matches[0], nil
	default:
		ids := make([]string, 0, len(matches))
		for _, m := range matches {
			ids = append(ids, m.ID)
		}
		return Device{}, fmt.Errorf("%w: %q matches %s", ErrAmbiguous, idOrPrefix, strings.Join(ids, ", "))
	}
}

// Get loads one device.
func (d *Devices) Get(ctx context.Context, tenantID, deviceID string) (Device, error) {
	var dev Device
	err := pg.InTenantTx(ctx, d.pool, tenantID, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, selectDevices+` WHERE id = $1`, deviceID)
		return scanDevice(row, &dev)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Device{}, fmt.Errorf("%w: %s", ErrNotFound, deviceID)
	}
	if err != nil {
		return Device{}, fmt.Errorf("store: get device: %w", err)
	}
	return dev, nil
}

// List returns every device for a tenant, newest first.
func (d *Devices) List(ctx context.Context, tenantID string) ([]Device, error) {
	var out []Device
	err := pg.InTenantTx(ctx, d.pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, selectDevices+` ORDER BY created_at DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var dev Device
			if err := scanDevice(rows, &dev); err != nil {
				return err
			}
			out = append(out, dev)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("store: list devices: %w", err)
	}
	return out, nil
}

// Delete removes a device row.
func (d *Devices) Delete(ctx context.Context, tenantID, deviceID string) error {
	return pg.InTenantTx(ctx, d.pool, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM devices WHERE id = $1`, deviceID)
		if err != nil {
			return fmt.Errorf("store: delete device: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("%w: %s", ErrNotFound, deviceID)
		}
		return nil
	})
}

const selectDevices = `
	SELECT id::text, tenant_id::text, coalesce(lid,''), coalesce(pn,''),
	       push_name, label, status, status_reason, receipt_mode,
	       created_at, last_connected_at, current_epoch
	  FROM devices`

// scanner is satisfied by both pgx.Row and pgx.Rows.
type scanner interface{ Scan(dest ...any) error }

func scanDevice(s scanner, dev *Device) error {
	var lid, pn string
	var connected *time.Time
	if err := s.Scan(&dev.ID, &dev.TenantID, &lid, &pn,
		&dev.Identity.PushName, &dev.Label, &dev.Status, &dev.StatusReason,
		&dev.ReceiptMode, &dev.CreatedAt, &connected, &dev.Epoch); err != nil {
		return err
	}
	if connected != nil {
		dev.LastConnectedAt = *connected
	}
	// Parsing is best effort: a malformed JID in the database should surface
	// the device as unpaired rather than fail the whole listing.
	dev.Identity.LID = parseJID(lid)
	dev.Identity.PN = parseJID(pn)
	return nil
}
