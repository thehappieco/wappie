package store

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Samples are included service metadata. At least one day of measured history
// is required; projections use net growth, including retention and deletions.
func sampleStorage(ctx context.Context, tx pgx.Tx, tenant uuid.UUID, u *StorageUsage) error {
	if !u.MeasurementReady {
		return nil
	}
	if _, err := tx.Exec(ctx, `INSERT INTO storage_samples(tenant_id,sampled_at,used_bytes) VALUES($1,date_trunc('hour',now()),$2) ON CONFLICT DO NOTHING`, tenant, u.UsedBytes); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM storage_samples WHERE tenant_id=$1 AND sampled_at<now()-interval '90 days'`, tenant); err != nil {
		return err
	}
	var before int64
	var days float64
	err := tx.QueryRow(ctx, `SELECT used_bytes,extract(epoch FROM (now()-measured_at))/86400 FROM storage_samples WHERE tenant_id=$1 AND measured_at>=now()-interval '7 days' AND measured_at<=now()-interval '1 day' ORDER BY measured_at LIMIT 1`, tenant).Scan(&before, &days)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	rate := int64(math.Round(float64(u.UsedBytes-before) / days))
	u.DailyGrowthBytes = &rate
	if rate <= 0 || u.LimitBytes == nil || u.PausedAt != nil {
		return nil
	}
	remaining := *u.LimitBytes - u.UsedBytes
	if remaining <= 0 {
		return nil
	}
	seconds := float64(remaining) / float64(rate) * 86400
	// Do not convert unrealistic, overflow-prone predictions into a timestamp.
	if seconds > 3650*86400 {
		return nil
	}
	full := time.Now().Add(time.Duration(seconds * float64(time.Second)))
	u.EstimatedFullAt = &full
	return nil
}
