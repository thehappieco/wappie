package store_test

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"testing"
	"time"
	"whatserver2/internal/pg"
	"whatserver2/internal/store"
)

func TestStorageProjectionRequiresHistoryAndUsesNetGrowth(t *testing.T) {
	a := newArchive(t)
	ctx := context.Background()
	s := store.NewStorage(a.pool)
	u, err := s.Usage(ctx, a.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if u.EstimatedFullAt != nil || !u.MeasurementReady {
		t.Fatalf("new workspace: %+v", u)
	}
	if err := pg.InTenantTx(ctx, a.pool, a.tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO storage_samples(tenant_id,sampled_at,measured_at,used_bytes) VALUES($1,now()-interval '2 days',now()-interval '2 days',0)`, a.tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	a.insert(t, row{ts: time.Now(), chat: "growth"})
	baseline, err := s.Usage(ctx, a.tenant)
	if err != nil {
		t.Fatal(err)
	}
	limit := baseline.UsedBytes * 4
	if err = s.SetLimit(ctx, a.tenant, &limit); err != nil {
		t.Fatal(err)
	}
	u, err = s.Usage(ctx, a.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if u.DailyGrowthBytes == nil || *u.DailyGrowthBytes <= 0 || u.EstimatedFullAt == nil || u.EstimatedFullAt.Before(time.Now()) {
		t.Fatalf("missing positive trend: %+v", u)
	}
}

func TestStorageMustMeasureExistingWorkspaceBeforeLimiting(t *testing.T) {
	a := newArchive(t)
	ctx := context.Background()
	s := store.NewStorage(a.pool)
	if _, err := a.pool.Exec(ctx, `UPDATE tenants SET storage_reconciled_at=NULL WHERE id=$1`, a.tenant); err != nil {
		t.Fatal(err)
	}
	limit := int64(10000)
	if err := s.SetLimit(ctx, a.tenant, &limit); err == nil {
		t.Fatal("unmeasured workspace limited")
	}
	if _, err := s.Reconcile(ctx, a.tenant); err != nil {
		t.Fatal(err)
	}
	if err := s.SetLimit(ctx, a.tenant, &limit); err != nil {
		t.Fatal(err)
	}
}

func TestStorageProjectionRequiresFullDayOfActualObservations(t *testing.T) {
	a := newArchive(t)
	ctx := context.Background()
	s := store.NewStorage(a.pool)
	err := pg.InTenantTx(ctx, a.pool, a.tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO storage_samples(tenant_id,sampled_at,measured_at,used_bytes) VALUES($1,now()-interval '24 hours 10 minutes',now()-interval '23 hours 20 minutes',0)`, a.tenant)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	a.insert(t, row{ts: time.Now(), chat: "growth"})
	u, err := s.Usage(ctx, a.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if u.DailyGrowthBytes != nil {
		t.Fatal("rounded hour bucket was mistaken for a full day of measurements")
	}
}

func TestStorageCounterRepairInvalidatesHistoricalSamples(t *testing.T) {
	a := newArchive(t)
	ctx := context.Background()
	s := store.NewStorage(a.pool)
	a.insert(t, row{ts: time.Now(), chat: "growth"})
	if _, err := s.Usage(ctx, a.tenant); err != nil {
		t.Fatal(err)
	}
	err := pg.InTenantTx(ctx, a.pool, a.tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO storage_samples(tenant_id,sampled_at,measured_at,used_bytes) VALUES($1,now()-interval '2 days',now()-interval '2 days',0)`, a.tenant)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	// Healthy reconciliation retains a valid series.
	u, err := s.Reconcile(ctx, a.tenant)
	if err != nil || u.DailyGrowthBytes == nil {
		t.Fatalf("healthy reconcile: %+v %v", u, err)
	}
	if _, err = a.pool.Exec(ctx, `UPDATE tenants SET storage_archive_bytes=0 WHERE id=$1`, a.tenant); err != nil {
		t.Fatal(err)
	}
	u, err = s.Reconcile(ctx, a.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if u.DailyGrowthBytes != nil {
		t.Fatal("counter repair must not extrapolate from an incompatible series")
	}
}

func TestStoragePauseSurvivesRequestCancellation(t *testing.T) {
	a := newArchive(t)
	requestCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := pg.InTenantTx(requestCtx, a.pool, a.tenant.String(), func(_ pgx.Tx) error {
		cancel()
		return &pgconn.PgError{Code: "WS001", Message: "storage policy refused write"}
	})
	if !errors.Is(err, store.ErrStoragePaused) {
		t.Fatalf("quota error lost: %v", err)
	}
	usage, err := store.NewStorage(a.pool).Usage(context.Background(), a.tenant)
	if err != nil || usage.PausedAt == nil {
		t.Fatalf("disconnected request lost durable pause: %+v %v", usage, err)
	}
}
