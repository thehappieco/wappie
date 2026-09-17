package store_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
)

func TestStoragePhysicalObjectSurvivesUntilLastWorkspaceReleasesIt(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		t.Run(map[bool]string{false: "source-first", true: "destination-first"}[reverse], func(t *testing.T) {
			a := newArchive(t)
			ctx := context.Background()
			destination := uuid.MustParse(newTenant(t, a.pool, "destination"))
			storage := store.NewStorage(a.pool)
			key := a.tenant.String() + "/existing-ciphertext"
			for _, tenant := range []uuid.UUID{a.tenant, destination} {
				if err := storage.ReserveObject(ctx, tenant, key, 71); err != nil {
					t.Fatal(err)
				}
			}
			first, last := a.tenant, destination
			if reverse {
				first, last = last, first
			}
			var deleted atomic.Int32
			remove := func(context.Context, string) error { deleted.Add(1); return nil }
			if err := storage.DeleteObject(ctx, first, key, remove); err != nil {
				t.Fatal(err)
			}
			if deleted.Load() != 0 {
				t.Fatal("physical object was deleted while the other workspace still owned it")
			}
			usage, err := storage.Usage(ctx, first)
			if err != nil {
				t.Fatal(err)
			}
			otherUsage, err := storage.Usage(ctx, last)
			if err != nil {
				t.Fatal(err)
			}
			if usage.ObjectBytes != 0 || otherUsage.ObjectBytes != 71 {
				t.Fatalf("charges after first release: first=%d remaining=%d", usage.ObjectBytes, otherUsage.ObjectBytes)
			}
			if err := storage.DeleteObject(ctx, last, key, remove); err != nil {
				t.Fatal(err)
			}
			if deleted.Load() != 1 {
				t.Fatalf("physical delete count = %d, want 1", deleted.Load())
			}
			// An old maintenance work list cannot delete the same physical object again.
			if err := storage.DeleteObject(ctx, first, key, remove); err != nil {
				t.Fatal(err)
			}
			if deleted.Load() != 1 {
				t.Fatal("a stale cleanup candidate repeated physical deletion")
			}
		})
	}
}

func TestStorageConcurrentWorkspaceCleanupDeletesPhysicalBytesOnce(t *testing.T) {
	a := newArchive(t)
	ctx := context.Background()
	destination := uuid.MustParse(newTenant(t, a.pool, "destination"))
	storage := store.NewStorage(a.pool)
	key := a.tenant.String() + "/shared-ciphertext"
	for _, tenant := range []uuid.UUID{a.tenant, destination} {
		if err := storage.ReserveObject(ctx, tenant, key, 71); err != nil {
			t.Fatal(err)
		}
	}
	var deleted atomic.Int32
	errors := make(chan error, 2)
	start := make(chan struct{})
	for _, tenant := range []uuid.UUID{a.tenant, destination} {
		go func() {
			<-start
			errors <- storage.DeleteObject(ctx, tenant, key, func(context.Context, string) error { deleted.Add(1); return nil })
		}()
	}
	close(start)
	for i := 0; i < 2; i++ {
		if err := <-errors; err != nil {
			t.Fatal(err)
		}
	}
	if deleted.Load() != 1 {
		t.Fatalf("concurrent physical delete count = %d, want 1", deleted.Load())
	}
	var owners int
	if err := a.pool.QueryRow(ctx, `SELECT count(*) FROM storage_object_owners WHERE object_key=$1`, key).Scan(&owners); err != nil {
		t.Fatal(err)
	}
	if owners != 0 {
		t.Fatalf("owners remain after both workspaces released: %d", owners)
	}
}

func TestStorageCleanupWaitsForConcurrentWorkspaceOwnershipCommit(t *testing.T) {
	for _, commit := range []bool{true, false} {
		t.Run(map[bool]string{true: "commit", false: "rollback"}[commit], func(t *testing.T) {
			a := newArchive(t)
			ctx := context.Background()
			destination := uuid.MustParse(newTenant(t, a.pool, "destination"))
			storage := store.NewStorage(a.pool)
			key := a.tenant.String() + "/being-transferred"
			if err := storage.ReserveObject(ctx, a.tenant, key, 71); err != nil {
				t.Fatal(err)
			}
			staged, proceed := make(chan struct{}), make(chan struct{})
			insertDone := make(chan error, 1)
			rollback := errors.New("rollback test ownership")
			go func() {
				insertDone <- pg.InTenantTx(ctx, a.pool, destination.String(), func(tx pgx.Tx) error {
					if _, err := tx.Exec(ctx, `INSERT INTO storage_objects VALUES($1,$2,71)`, destination, key); err != nil {
						return err
					}
					close(staged)
					<-proceed
					if !commit {
						return rollback
					}
					return nil
				})
			}()
			select {
			case <-staged:
			case err := <-insertDone:
				t.Fatalf("ownership insert failed: %v", err)
			}
			var deleted atomic.Int32
			deleteDone := make(chan error, 1)
			go func() {
				deleteDone <- storage.DeleteObject(ctx, a.tenant, key, func(context.Context, string) error { deleted.Add(1); return nil })
			}()
			select {
			case err := <-deleteDone:
				close(proceed)
				<-insertDone
				t.Fatalf("cleanup passed an uncommitted ownership change: %v", err)
			case <-time.After(50 * time.Millisecond):
			}
			close(proceed)
			err := <-insertDone
			if commit && err != nil || !commit && !errors.Is(err, rollback) {
				t.Fatalf("ownership commit result: %v", err)
			}
			if err := <-deleteDone; err != nil {
				t.Fatal(err)
			}
			want := int32(0)
			if !commit {
				want = 1
			}
			if deleted.Load() != want {
				t.Fatalf("physical deletions=%d want %d", deleted.Load(), want)
			}
		})
	}
}

func TestStorageOwnershipMigrationBackfillsAllWorkspaceReservations(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Empty(t)
	migrations, err := migrate.Load()
	if err != nil {
		t.Fatal(err)
	}
	apply := func(m migrate.Migration) {
		t.Helper()
		if err := pg.InTx(ctx, pool, func(tx pgx.Tx) error { _, err := tx.Exec(ctx, m.SQL); return err }); err != nil {
			t.Fatalf("migration %d: %v", m.Version, err)
		}
	}
	for _, m := range migrations {
		if m.Version < 37 {
			apply(m)
		}
	}
	tenants := []uuid.UUID{uuid.MustParse(newTenant(t, pool, "source")), uuid.MustParse(newTenant(t, pool, "destination"))}
	storage := store.NewStorage(pool)
	for _, tenant := range tenants {
		if err := storage.ReserveObject(ctx, tenant, "preexisting-key", 71); err != nil {
			t.Fatal(err)
		}
	}
	for _, m := range migrations {
		if m.Version == 37 {
			apply(m)
		}
	}
	var owners int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM storage_object_owners WHERE object_key='preexisting-key'`).Scan(&owners); err != nil {
		t.Fatal(err)
	}
	if owners != 2 {
		t.Fatalf("only %d legacy reservations were indexed", owners)
	}
	var deleted atomic.Int32
	if err := storage.DeleteObject(ctx, tenants[0], "preexisting-key", func(context.Context, string) error { deleted.Add(1); return nil }); err != nil {
		t.Fatal(err)
	}
	if deleted.Load() != 0 {
		t.Fatal("legacy shared ciphertext deleted despite migrated ownership")
	}
}
