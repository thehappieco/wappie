package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"whatserver2/internal/pg"
)

// StorageBytes always uses the same canonical byte measure as workspace quotas.
type StorageBytes struct {
	ArchiveBytes int64 `json:"archive_bytes"`
	ObjectBytes  int64 `json:"object_bytes"`
	UsedBytes    int64 `json:"used_bytes"`
}

type DeviceStorageUsage struct {
	DeviceID string `json:"device_id"`
	Label    string `json:"label"`
	PushName string `json:"push_name"`
	PN       string `json:"pn"`
	StorageBytes
}

// StorageBreakdown assigns objects referenced by several numbers to Shared, once.
// Reserved uploads
// and objects awaiting confirmed deletion belong to Unassigned until a live
// archive reference can identify a number. Neither bucket is charged again.
type StorageBreakdown struct {
	Devices    []DeviceStorageUsage `json:"devices"`
	Shared     StorageBytes         `json:"shared"`
	Unassigned StorageBytes         `json:"unassigned"`
}

// UsageDetailed is for administration, not the capture path: attribution grows
// with the archive. The workspace lock keeps the total and all rows in one
// snapshot while ingestion, retention and uploads are writing concurrently.
func (s *Storage) UsageDetailed(ctx context.Context, tenant uuid.UUID) (StorageUsage, error) {
	var out StorageUsage
	err := pg.InTenantTx(ctx, s.pool, tenant.String(), func(tx pgx.Tx) error {
		var err error
		out, err = StorageUsageDetailedTx(ctx, tx, tenant)
		return err
	})
	return out, err
}

func StorageUsageDetailedTx(ctx context.Context, tx pgx.Tx, tenant uuid.UUID) (StorageUsage, error) {
	out, err := StorageUsageTx(ctx, tx, tenant)
	if err != nil {
		return out, err
	}
	out.Breakdown, err = storageBreakdownTx(ctx, tx)
	return out, err
}

// Caller holds the workspace row lock before reading any archive table.
func storageBreakdownTx(ctx context.Context, tx pgx.Tx) (*StorageBreakdown, error) {
	out := &StorageBreakdown{Devices: []DeviceStorageUsage{}}
	byDevice := map[string]int{}
	rows, err := tx.Query(ctx, `SELECT id::text,label,push_name,coalesce(pn,'') FROM devices ORDER BY created_at,id`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var device DeviceStorageUsage
		if err := rows.Scan(&device.DeviceID, &device.Label, &device.PushName, &device.PN); err != nil {
			rows.Close()
			return nil, err
		}
		byDevice[device.DeviceID] = len(out.Devices)
		out.Devices = append(out.Devices, device)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = tx.Query(ctx, `
 WITH records AS (
  SELECT CASE
   WHEN i.source IN ('messages','media') THEN m.device_id
   WHEN i.source='group_changes' THEN g.device_id
   WHEN i.source IN ('chats','receipts','contacts','group_participants') THEN (i.identity::jsonb->>0)::uuid
  END device_id,i.bytes
  FROM storage_inventory i
  LEFT JOIN messages m ON m.uid=(CASE WHEN i.source IN ('messages','media') THEN i.identity::jsonb->>0 END)::uuid
  LEFT JOIN group_changes g ON g.id=(CASE WHEN i.source='group_changes' THEN i.identity::jsonb->>0 END)::bigint
 ), object_references AS (
  SELECT d.object_key,m.device_id FROM media d JOIN messages m ON m.uid=d.message_uid WHERE d.object_key IS NOT NULL
  UNION
  SELECT d.tenant_id::text||'/'||left(encode(d.file_enc_sha256,'hex'),2)||'/'||encode(d.file_enc_sha256,'hex'),m.device_id
  FROM media d JOIN messages m ON m.uid=d.message_uid WHERE d.file_enc_sha256 IS NOT NULL
 ), objects AS (
  SELECT o.object_key,o.bytes,count(r.device_id) device_count,min(r.device_id::text) device_id
  FROM storage_objects o LEFT JOIN object_references r ON r.object_key=o.object_key
  GROUP BY o.object_key,o.bytes
 )
 SELECT CASE WHEN device_id IS NULL THEN 'unassigned' ELSE 'device' END,coalesce(device_id::text,''),sum(bytes)::bigint,0::bigint FROM records GROUP BY device_id
 UNION ALL
 SELECT CASE device_count WHEN 0 THEN 'unassigned' WHEN 1 THEN 'device' ELSE 'shared' END,
  CASE WHEN device_count=1 THEN device_id ELSE '' END,0::bigint,sum(bytes)::bigint
 FROM objects GROUP BY 1,2`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var kind, id string
		var archiveBytes, objectBytes int64
		if err := rows.Scan(&kind, &id, &archiveBytes, &objectBytes); err != nil {
			return nil, err
		}
		target := &out.Unassigned
		if kind == "shared" {
			target = &out.Shared
		} else if index, ok := byDevice[id]; kind == "device" && ok {
			target = &out.Devices[index].StorageBytes
		}
		target.ArchiveBytes += archiveBytes
		target.ObjectBytes += objectBytes
		target.UsedBytes += archiveBytes + objectBytes
	}
	return out, rows.Err()
}
