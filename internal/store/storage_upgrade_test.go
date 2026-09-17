package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

func TestStorageUpgradeAccountsOldRowsBeforeExplicitReconcile(t *testing.T) {
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
		if m.Version <= 33 {
			apply(m)
		}
	}
	tenant := uuid.MustParse(newTenant(t, pool, "legacy"))
	dev, err := store.NewDevices(pool).Create(ctx, tenant.String(), "phone", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	a := &archive{pool: pool, tenant: tenant, device: uuid.MustParse(dev.ID), messages: store.NewMessages(pool), media: store.NewMedia(pool)}
	first := a.insert(t, row{ts: time.Now(), chat: "legacy", object: "shared"})
	a.insert(t, row{ts: time.Now(), chat: "legacy", object: "shared"})
	for _, m := range migrations {
		if m.Version > 33 {
			apply(m)
		}
	}
	s := store.NewStorage(pool)
	before, err := s.Usage(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if before.MeasurementReady || before.ObjectBytes != 10 || before.ArchiveBytes == 0 {
		t.Fatalf("old archive baseline: %+v", before)
	}
	// The new measurement flag blocks commercial limits, not accounting. An old
	// record edited before explicit reconciliation must apply only its delta.
	err = pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE messages SET body_sealed=$2 WHERE uid=$1`, first, make([]byte, 10))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	edited, err := s.Usage(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if edited.ArchiveBytes != before.ArchiveBytes+9 {
		t.Fatalf("old row update recharged or omitted baseline: before %+v after %+v", before, edited)
	}
	err = pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error { _, err := tx.Exec(ctx, `DELETE FROM messages WHERE uid=$1`, first); return err })
	if err != nil {
		t.Fatal(err)
	}
	deleted, err := s.Usage(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if deleted.ArchiveBytes >= edited.ArchiveBytes || deleted.ObjectBytes != 10 {
		t.Fatalf("old row deletion: %+v", deleted)
	}
	rebuilt, err := s.Reconcile(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if !rebuilt.MeasurementReady || rebuilt.UsedBytes != deleted.UsedBytes {
		t.Fatalf("old accounting drifted before reconcile: before %+v after %+v", deleted, rebuilt)
	}
}
