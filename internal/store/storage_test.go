package store_test

import (
	"context"
	"errors"
	"testing"
	"time"
	"whatserver2/internal/store"
)

func TestStorageInventoryDedupRetentionAndResume(t *testing.T) {
	a := newArchive(t)
	ctx := context.Background()
	s := store.NewStorage(a.pool)
	a.insert(t, row{ts: time.Now().Add(-time.Hour), chat: "x", object: "same"})
	a.insert(t, row{ts: time.Now(), chat: "x", object: "same"})
	u, err := s.Usage(ctx, a.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if u.ObjectBytes != 10 || u.ArchiveBytes <= 0 {
		t.Fatalf("bad usage %+v", u)
	}
	before := u.UsedBytes
	reconciled, err := s.Reconcile(ctx, a.tenant)
	if err != nil || reconciled.UsedBytes != before {
		t.Fatalf("reconcile %+v %v", reconciled, err)
	}
	limit := int64(1)
	if err = s.SetLimit(ctx, a.tenant, &limit); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(s.Check(ctx, a.tenant), store.ErrStoragePaused) {
		t.Fatal("over limit should pause")
	}
	if _, err = store.Purge(ctx, a.pool, a.tenant, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err = s.ForgetObject(ctx, a.tenant, "same"); err != nil {
		t.Fatal(err)
	}
	u, err = s.Usage(ctx, a.tenant)
	if err != nil || u.ObjectBytes != 0 {
		t.Fatalf("purge %+v %v", u, err)
	}
	if err = s.SetLimit(ctx, a.tenant, nil); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(s.Check(ctx, a.tenant), store.ErrStoragePaused) {
		t.Fatal("capacity change must not resume")
	}
	if err = s.Resume(ctx, a.tenant); err != nil {
		t.Fatal(err)
	}
	if err = s.Check(ctx, a.tenant); err != nil {
		t.Fatal(err)
	}
}

func TestStorageConcurrentObjectReservationHardLimit(t *testing.T) {
	a := newArchive(t)
	ctx := context.Background()
	s := store.NewStorage(a.pool)
	limit := int64(1000)
	if err := s.SetLimit(ctx, a.tenant, &limit); err != nil {
		t.Fatal(err)
	}
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		go func() { errs <- s.ReserveObject(ctx, a.tenant, "same", 1000) }()
	}
	for i := 0; i < 20; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	u, err := s.Usage(ctx, a.tenant)
	if err != nil || u.UsedBytes != 1000 || u.WarningPercent != 100 || u.OverSince == nil {
		t.Fatalf("usage %+v %v", u, err)
	}
	if err = s.ReserveObject(ctx, a.tenant, "too-large", 51); !errors.Is(err, store.ErrStoragePaused) {
		t.Fatalf("hard limit: %v", err)
	}
	u, err = store.NewStorage(a.pool).Usage(ctx, a.tenant)
	if err != nil || u.UsedBytes != 1000 || u.PausedAt == nil {
		t.Fatalf("rollback/restart %+v %v", u, err)
	}
	if err = s.ReserveObject(ctx, a.tenant, "small", 1); !errors.Is(err, store.ErrStoragePaused) {
		t.Fatalf("pause latch: %v", err)
	}
}

func TestStorageGraceExpiryAndReconcile(t *testing.T) {
	a := newArchive(t)
	ctx := context.Background()
	s := store.NewStorage(a.pool)
	a.insert(t, row{ts: time.Now(), chat: "x"})
	u, err := s.Usage(ctx, a.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.SetLimit(ctx, a.tenant, &u.UsedBytes); err != nil {
		t.Fatal(err)
	}
	if err = s.Check(ctx, a.tenant); err != nil {
		t.Fatal("grace should permit writes", err)
	}
	if _, err = a.pool.Exec(ctx, `UPDATE tenants SET storage_over_since=now()-interval '73 hours' WHERE id=$1`, a.tenant); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(s.Check(ctx, a.tenant), store.ErrStoragePaused) {
		t.Fatal("grace expiry")
	}
	// Repair succeeds while paused and does not resume capture.
	if _, err = a.pool.Exec(ctx, `UPDATE tenants SET storage_archive_bytes=0 WHERE id=$1`, a.tenant); err != nil {
		t.Fatal(err)
	}
	repaired, err := s.Reconcile(ctx, a.tenant)
	if err != nil || repaired.UsedBytes != u.UsedBytes || repaired.PausedAt == nil {
		t.Fatalf("repair %+v %v", repaired, err)
	}
}

func TestStorageFailedPhysicalDeleteRetainsCharge(t *testing.T) {
	a := newArchive(t)
	ctx := context.Background()
	s := store.NewStorage(a.pool)
	if err := s.ReserveObject(ctx, a.tenant, "orphan", 55); err != nil {
		t.Fatal(err)
	}
	failed := errors.New("bucket unavailable")
	if err := s.DeleteObject(ctx, a.tenant, "orphan", func(context.Context, string) error { return failed }); !errors.Is(err, failed) {
		t.Fatal(err)
	}
	u, err := s.Usage(ctx, a.tenant)
	if err != nil || u.ObjectBytes != 55 {
		t.Fatalf("uncertain deletion %+v %v", u, err)
	}
	if err = s.DeleteObject(ctx, a.tenant, "orphan", func(context.Context, string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	u, err = s.Usage(ctx, a.tenant)
	if err != nil || u.ObjectBytes != 0 {
		t.Fatalf("confirmed deletion %+v %v", u, err)
	}
}
