package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"whatserver2/internal/pg"
)

// DeviceStat is how much archive one device has accumulated.
//
// Everything here is envelope: how many rows, how many bytes, when the last one
// arrived. None of it needs a key to compute, which is the point — an operator
// has to be able to see that a device is working without being able to read
// what it archived.
type DeviceStat struct {
	DeviceID string
	Chats    int64
	Messages int64
	Media    int64
	// MediaBytes is the actual unique object bytes attributed exclusively to
	// this number. Shared objects are reported in the workspace breakdown.
	MediaBytes int64
	StorageBytes
	// LastMessageAt is the newest message this device archived, in its own
	// clock. Zero for a device that has archived nothing.
	LastMessageAt time.Time
}

// Stats counts what each device of a tenant has archived.
//
// Deliberately not part of List. Listing devices happens on every reconnect of
// every client, and counting rows is the one query here that grows with the
// size of the archive: putting it on that path would make a reconnect slower
// the longer the server had been useful. This runs when somebody opens the
// admin console and asks.
func (d *Devices) Stats(ctx context.Context, tenantID string) ([]DeviceStat, error) {
	byDevice := map[string]*DeviceStat{}
	at := func(id string) *DeviceStat {
		if s, ok := byDevice[id]; ok {
			return s
		}
		s := &DeviceStat{DeviceID: id}
		byDevice[id] = s
		return s
	}

	err := pg.InTenantTx(ctx, d.pool, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT 1 FROM tenants WHERE id=$1 FOR SHARE`, tenantID); err != nil {
			return err
		}
		// Chats first, and the newest activity with them: the chat rows already
		// carry a projection of their last message, so this answers "when did
		// anything last happen" without touching the messages table.
		rows, err := tx.Query(ctx, `
			SELECT device_id::text, count(*), max(last_ts)
			  FROM chats GROUP BY device_id`)
		if err != nil {
			return fmt.Errorf("store: count chats: %w", err)
		}
		for rows.Next() {
			var id string
			var n int64
			var last *time.Time
			if err := rows.Scan(&id, &n, &last); err != nil {
				rows.Close()
				return err
			}
			s := at(id)
			s.Chats = n
			if last != nil {
				s.LastMessageAt = *last
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		rows, err = tx.Query(ctx, `
			SELECT device_id::text, count(*) FROM messages GROUP BY device_id`)
		if err != nil {
			return fmt.Errorf("store: count messages: %w", err)
		}
		for rows.Next() {
			var id string
			var n int64
			if err := rows.Scan(&id, &n); err != nil {
				rows.Close()
				return err
			}
			at(id).Messages = n
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		// Attachments hang off messages rather than off devices, so this is the
		// one join. Media rows are a small fraction of message rows, so it
		// costs about what the count above already cost.
		rows, err = tx.Query(ctx, `
			SELECT m.device_id::text, count(*)
			  FROM media d JOIN messages m ON m.uid = d.message_uid
			 GROUP BY m.device_id`)
		if err != nil {
			return fmt.Errorf("store: count media: %w", err)
		}
		for rows.Next() {
			var id string
			var n int64
			if err := rows.Scan(&id, &n); err != nil {
				rows.Close()
				return err
			}
			at(id).Media = n
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		usage, err := storageBreakdownTx(ctx, tx)
		if err != nil {
			return err
		}
		for _, device := range usage.Devices {
			stat := at(device.DeviceID)
			stat.StorageBytes = device.StorageBytes
			stat.MediaBytes = device.ObjectBytes
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("store: device stats: %w", err)
	}

	out := make([]DeviceStat, 0, len(byDevice))
	for _, s := range byDevice {
		out = append(out, *s)
	}
	return out, nil
}
