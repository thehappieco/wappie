package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"whatserver2/internal/pg"
)

var ErrStoragePaused = pg.ErrStoragePaused

var ErrStorageUnmeasured = errors.New("measure the existing archive with storage reconcile before setting a limit")

type Storage struct{ pool *pgxpool.Pool }

func NewStorage(pool *pgxpool.Pool) *Storage { return &Storage{pool: pool} }

type StorageUsage struct {
	Breakdown        *StorageBreakdown `json:"breakdown,omitempty"`
	MeasurementReady bool              `json:"measurement_ready"`
	DailyGrowthBytes *int64            `json:"daily_growth_bytes,omitempty"`
	EstimatedFullAt  *time.Time        `json:"estimated_full_at,omitempty"`
	RuleVersion      int               `json:"rule_version"`
	LimitBytes       *int64            `json:"limit_bytes"`
	ArchiveBytes     int64             `json:"archive_bytes"`
	ObjectBytes      int64             `json:"object_bytes"`
	UsedBytes        int64             `json:"used_bytes"`
	OverSince        *time.Time        `json:"over_since"`
	GraceEndsAt      *time.Time        `json:"grace_ends_at"`
	PausedAt         *time.Time        `json:"paused_at"`
	WarningPercent   int               `json:"warning_percent"`
}

func (s *Storage) Usage(ctx context.Context, tenant uuid.UUID) (StorageUsage, error) {
	var u StorageUsage
	err := pg.InTenantTx(ctx, s.pool, tenant.String(), func(tx pgx.Tx) error {
		var err error
		u, err = StorageUsageTx(ctx, tx, tenant)
		return err
	})
	return u, err
}

// StorageUsageTx reads usage and its projection in an existing tenant-scoped
// transaction, so a private purchase summary can share the same workspace lock.
func StorageUsageTx(ctx context.Context, tx pgx.Tx, tenant uuid.UUID) (StorageUsage, error) {
	var u StorageUsage

	_, err := tx.Exec(ctx, `UPDATE tenants SET storage_paused_at=coalesce(storage_paused_at,clock_timestamp())
   WHERE id=$1 AND storage_limit_bytes IS NOT NULL AND
   (storage_archive_bytes::numeric+storage_object_bytes>=storage_limit_bytes::numeric*1.05 OR
    storage_over_since+interval '72 hours'<=clock_timestamp())`, tenant)
	if err != nil {
		return u, err
	}
	if err := tx.QueryRow(ctx, `SELECT storage_rule_version,storage_limit_bytes,storage_archive_bytes,storage_object_bytes,storage_over_since,storage_paused_at,storage_reconciled_at IS NOT NULL FROM tenants WHERE id=$1 FOR SHARE`, tenant).
		Scan(&u.RuleVersion, &u.LimitBytes, &u.ArchiveBytes, &u.ObjectBytes, &u.OverSince, &u.PausedAt, &u.MeasurementReady); err != nil {
		return u, err
	}
	u.UsedBytes = u.ArchiveBytes + u.ObjectBytes
	if err := sampleStorage(ctx, tx, tenant, &u); err != nil {
		return u, err
	}
	u.UsedBytes = u.ArchiveBytes + u.ObjectBytes
	if u.OverSince != nil {
		end := u.OverSince.Add(72 * time.Hour)
		u.GraceEndsAt = &end
	}
	if u.LimitBytes != nil {
		for _, n := range []int{80, 90, 100} {
			if float64(u.UsedBytes) >= float64(*u.LimitBytes)*float64(n)/100 {
				u.WarningPercent = n
			}
		}
	}
	return u, nil
}
func (s *Storage) Check(ctx context.Context, tenant uuid.UUID) error {
	u, err := s.Usage(ctx, tenant)
	if err != nil {
		return err
	}
	if u.PausedAt != nil {
		return ErrStoragePaused
	}
	return nil
}

// SetLimit configures installation policy. A nil limit means unlimited; neither
// a purchase nor an erasure clears a previously recorded pause.
func (s *Storage) SetLimit(ctx context.Context, tenant uuid.UUID, limit *int64) error {
	if limit != nil && *limit <= 0 {
		return errors.New("storage limit must be positive or null")
	}
	return pg.InTenantTx(ctx, s.pool, tenant.String(), func(tx pgx.Tx) error {
		return SetStorageLimitTx(ctx, tx, tenant, limit)
	})
}
func (s *Storage) Resume(ctx context.Context, tenant uuid.UUID) error {
	return pg.InTenantTx(ctx, s.pool, tenant.String(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE tenants SET storage_paused_at=NULL,storage_over_since=NULL
   WHERE id=$1 AND (storage_limit_bytes IS NULL OR storage_archive_bytes+storage_object_bytes<storage_limit_bytes)`, tenant)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrStoragePaused
		}
		return err
	})
}

// Reconcile rebuilds canonical record entries from the authoritative tables.
// Object reservations are retained: a crashed uploader may have stored bytes.
func (s *Storage) Reconcile(ctx context.Context, tenant uuid.UUID) (StorageUsage, error) {
	err := pg.InTenantTx(ctx, s.pool, tenant.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT 1 FROM tenants WHERE id=$1 FOR UPDATE`, tenant); err != nil {
			return err
		}
		// Rebuild while holding the same tenant lock as every accounted writer.
		// Suppress intermediate deltas so a damaged counter can be repaired.
		if _, err := tx.Exec(ctx, `SELECT set_config('app.storage_reconcile','true',true)`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM storage_inventory WHERE tenant_id=$1`, tenant); err != nil {
			return err
		}
		for _, table := range []string{"messages", "chats", "media", "receipts", "contacts", "group_participants", "group_changes"} {
			if _, err := tx.Exec(ctx, `UPDATE `+table+` SET tenant_id=tenant_id WHERE tenant_id=$1`, tenant); err != nil {
				return err
			}
		}
		// A repaired or first baseline cannot be compared to samples taken
		// from different/incomplete counters. Healthy reconciliations retain
		// their measured growth series.
		if _, err := tx.Exec(ctx, `DELETE FROM storage_samples WHERE tenant_id=$1 AND EXISTS(
          SELECT 1 FROM tenants WHERE id=$1 AND (storage_reconciled_at IS NULL OR
          storage_archive_bytes<>(SELECT coalesce(sum(bytes),0) FROM storage_inventory WHERE tenant_id=$1) OR
          storage_object_bytes<>(SELECT coalesce(sum(bytes),0) FROM storage_objects WHERE tenant_id=$1)))`, tenant); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE tenants SET storage_archive_bytes=(SELECT coalesce(sum(bytes),0) FROM storage_inventory WHERE tenant_id=$1),
   storage_object_bytes=(SELECT coalesce(sum(bytes),0) FROM storage_objects WHERE tenant_id=$1),storage_reconciled_at=clock_timestamp() WHERE id=$1`, tenant)
		return err
	})
	if err != nil {
		return StorageUsage{}, err
	}
	return s.Usage(ctx, tenant)
}

// ReserveObject charges the unique key before durable object storage. Keep the
// reservation on uncertain errors; retrying the same key never double charges.
func (s *Storage) ReserveObject(ctx context.Context, tenant uuid.UUID, key string, size int64) error {
	if key == "" || size < 0 {
		return errors.New("invalid storage object")
	}
	return pg.InTenantTx(ctx, s.pool, tenant.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT 1 FROM tenants WHERE id=$1 FOR UPDATE`, tenant); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO storage_objects VALUES($1,$2,$3) ON CONFLICT(tenant_id,object_key) DO UPDATE SET bytes=greatest(storage_objects.bytes,excluded.bytes)`, tenant, key, size)
		return err
	})
}

// ForgetObject must be called only after confirmed physical deletion. A key
// still referenced by the archive is never released.
func (s *Storage) ForgetObject(ctx context.Context, tenant uuid.UUID, key string) error {
	return pg.InTenantTx(ctx, s.pool, tenant.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT 1 FROM tenants WHERE id=$1 FOR UPDATE`, tenant); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM storage_objects WHERE tenant_id=$1 AND object_key=$2 AND NOT EXISTS(SELECT 1 FROM media WHERE tenant_id=$1 AND object_key=$2)`, tenant, key)
		return err
	})
}

// SetStorageLimitTx applies policy in the caller's commercial transaction.
func SetStorageLimitTx(ctx context.Context, tx pgx.Tx, tenant uuid.UUID, limit *int64) error {
	if limit != nil && *limit <= 0 {
		return errors.New("storage limit must be positive or null")
	}
	if limit != nil {
		var ready bool
		if err := tx.QueryRow(ctx, `SELECT storage_reconciled_at IS NOT NULL FROM tenants WHERE id=$1 FOR UPDATE`, tenant).Scan(&ready); err != nil {
			return err
		}
		if !ready {
			return ErrStorageUnmeasured
		}
	}
	tag, err := tx.Exec(ctx, `UPDATE tenants SET storage_limit_bytes=$2,
   storage_paused_at=CASE WHEN storage_limit_bytes IS NOT NULL AND
    (storage_archive_bytes::numeric+storage_object_bytes>=storage_limit_bytes::numeric*1.05 OR storage_over_since+interval '72 hours'<=clock_timestamp())
   THEN coalesce(storage_paused_at,clock_timestamp()) ELSE storage_paused_at END,
   storage_over_since=CASE WHEN $2::bigint IS NOT NULL AND storage_archive_bytes+storage_object_bytes >= $2
   THEN coalesce(storage_over_since,clock_timestamp()) ELSE NULL END WHERE id=$1 AND ($2::bigint IS NULL OR storage_reconciled_at IS NOT NULL)`, tenant, limit)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// DeleteObject serializes physical deletion with new references and uploads.
// It retains the charge on any ambiguous deletion failure. Retention, erasure,
// and administration should use this instead of a separate Delete/Forget pair.
func (s *Storage) DeleteObject(ctx context.Context, tenant uuid.UUID, key string, remove func(context.Context, string) error) error {
	return pg.InTenantTx(ctx, s.pool, tenant.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT 1 FROM tenants WHERE id=$1 FOR UPDATE`, tenant); err != nil {
			return err
		}
		// Acquisition follows the same workspace -> physical key order as ownership
		// insert/delete triggers. A concurrent transfer protects both workspaces.
		if _, err := tx.Exec(ctx, `SELECT storage_lock_object($1)`, key); err != nil {
			return err
		}
		var owned, referenced, otherOwner bool
		if err := tx.QueryRow(ctx, `SELECT
   EXISTS(SELECT 1 FROM storage_objects WHERE tenant_id=$1 AND object_key=$2),
   EXISTS(SELECT 1 FROM media WHERE object_key=$2 OR tenant_id::text||'/'||left(encode(file_enc_sha256,'hex'),2)||'/'||encode(file_enc_sha256,'hex')=$2),
   EXISTS(SELECT 1 FROM storage_object_owners WHERE object_key=$2 AND tenant_id<>$1)`, tenant, key).Scan(&owned, &referenced, &otherOwner); err != nil {
			return err
		}
		if !owned || referenced {
			return nil
		}
		// Removing a stale source reservation frees only its logical charge. Shared
		// ciphertext stays in place until the last workspace confirms physical GC.
		if !otherOwner {
			if err := remove(ctx, key); err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx, `DELETE FROM storage_objects WHERE tenant_id=$1 AND object_key=$2`, tenant, key)
		return err
	})
}

type StorageEvent struct {
	ID             int64     `json:"id"`
	OccurredAt     time.Time `json:"occurred_at"`
	Reason         string    `json:"reason"`
	UsedBytes      int64     `json:"used_bytes"`
	LimitBytes     *int64    `json:"limit_bytes"`
	WarningPercent int       `json:"warning_percent"`
}

func (s *Storage) History(ctx context.Context, tenant uuid.UUID) ([]StorageEvent, error) {
	out := []StorageEvent{}
	err := pg.InTenantTx(ctx, s.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id,occurred_at,reason,used_bytes,limit_bytes,warning_percent FROM storage_history WHERE tenant_id=$1 ORDER BY id DESC LIMIT 100`, tenant)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e StorageEvent
			if err := rows.Scan(&e.ID, &e.OccurredAt, &e.Reason, &e.UsedBytes, &e.LimitBytes, &e.WarningPercent); err != nil {
				return err
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	return out, err
}

// UnreferencedObjects includes failed or interrupted deletion candidates, so a
// later maintenance pass can retry even after their archive rows are gone.
func (s *Storage) UnreferencedObjects(ctx context.Context, tenant uuid.UUID, limit int) ([]string, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	out := []string{}
	err := pg.InTenantTx(ctx, s.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT object_key FROM storage_objects o WHERE tenant_id=$1 AND NOT EXISTS(
    SELECT 1 FROM media m WHERE m.object_key=o.object_key OR
    m.tenant_id::text||'/'||left(encode(m.file_enc_sha256,'hex'),2)||'/'||encode(m.file_enc_sha256,'hex')=o.object_key)
    ORDER BY object_key LIMIT $2`, tenant, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var key string
			if err := rows.Scan(&key); err != nil {
				return err
			}
			out = append(out, key)
		}
		return rows.Err()
	})
	return out, err
}
