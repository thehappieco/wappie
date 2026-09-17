package store_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"whatserver2/internal/pg"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

func TestTransferredStorageKeepsSharedCiphertextAndMatchingDeviceTotals(t *testing.T) {
	a := newArchive(t)
	ctx := context.Background()
	devices := store.NewDevices(a.pool)
	owner, target := transferOwner(t, a, "owner")
	remaining, err := devices.Create(ctx, a.tenant.String(), "Team remains", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	b := *a
	b.device = uuid.MustParse(remaining.ID)
	a.insert(t, row{ts: time.Now(), chat: "group", object: "original/shared-object"})
	b.insert(t, row{ts: time.Now(), chat: "group", object: "original/shared-object"})
	if err := pg.InTenantTx(ctx, a.pool, a.tenant.String(), func(tx pgx.Tx) error {
		for _, query := range []string{
			`INSERT INTO contacts(tenant_id,device_id,contact_key,uid,avatar_sealed) VALUES($1,$2,'contact',uuidv7(),decode('010203','hex'))`,
			`INSERT INTO group_participants(tenant_id,device_id,chat_key,participant_key) VALUES($1,$2,'group','member')`,
			`INSERT INTO group_changes(tenant_id,device_id,chat_key,ts,action) VALUES($1,$2,'group',now(),'snapshot')`,
		} {
			if _, err := tx.Exec(ctx, query, a.tenant, a.device); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := devices.SetPaused(ctx, a.tenant.String(), a.device.String(), true); err != nil {
		t.Fatal(err)
	}
	if _, err := devices.TransferPersonal(ctx, a.tenant, owner, a.device, target); err != nil {
		t.Fatal(err)
	}
	storage := store.NewStorage(a.pool)
	for _, tenant := range []uuid.UUID{a.tenant, target} {
		before, err := storage.UsageDetailed(ctx, tenant)
		if err != nil {
			t.Fatal(err)
		}
		if len(before.Breakdown.Devices) != 1 || before.Breakdown.Devices[0].UsedBytes != before.UsedBytes || before.ObjectBytes != 10 {
			t.Fatalf("moved attribution drifted: %+v %+v", before, before.Breakdown)
		}
		after, err := storage.Reconcile(ctx, tenant)
		if err != nil {
			t.Fatal(err)
		}
		if after.UsedBytes != before.UsedBytes {
			t.Fatalf("transfer inventory diverged from authoritative tables: before=%d after=%d", before.UsedBytes, after.UsedBytes)
		}
	}
	var deleted atomic.Int32
	remove := func(context.Context, string) error { deleted.Add(1); return nil }
	if err := devices.Delete(ctx, a.tenant.String(), remaining.ID); err != nil {
		t.Fatal(err)
	}
	if err := storage.DeleteObject(ctx, a.tenant, "original/shared-object", remove); err != nil {
		t.Fatal(err)
	}
	if deleted.Load() != 0 {
		t.Fatal("removing Team archive destroyed transferred Personal ciphertext")
	}
	if err := devices.Delete(ctx, target.String(), a.device.String()); err != nil {
		t.Fatal(err)
	}
	if err := storage.DeleteObject(ctx, target, "original/shared-object", remove); err != nil {
		t.Fatal(err)
	}
	if deleted.Load() != 1 {
		t.Fatal("last owner's cleanup did not remove physical ciphertext exactly once")
	}
}

func TestTransferPreviewChargesOnlyNewDestinationObjectBytes(t *testing.T) {
	a := newArchive(t)
	ctx := context.Background()
	devices := store.NewDevices(a.pool)
	owner, target := transferOwner(t, a, "owner")
	other, err := devices.Create(ctx, a.tenant.String(), "second", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	b := *a
	b.device = uuid.MustParse(other.ID)
	a.insert(t, row{ts: time.Now(), chat: "first", object: "shared/previously-transferred"})
	b.insert(t, row{ts: time.Now(), chat: "second", object: "shared/previously-transferred"})
	if err := devices.SetPaused(ctx, a.tenant.String(), a.device.String(), true); err != nil {
		t.Fatal(err)
	}
	if _, err := devices.TransferPersonal(ctx, a.tenant, owner, a.device, target); err != nil {
		t.Fatal(err)
	}
	preview, err := devices.PreviewPersonalTransfer(ctx, a.tenant, owner, b.device)
	if err != nil {
		t.Fatal(err)
	}
	if !preview.Eligible || preview.ObjectBytes != 0 {
		t.Fatalf("destination already owns shared key but preview charges it again: %+v", preview)
	}
	storage := store.NewStorage(a.pool)
	before, err := storage.Usage(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	limit := before.UsedBytes + preview.ArchiveBytes
	if err := storage.SetLimit(ctx, target, &limit); err != nil {
		t.Fatal(err)
	}
	if err := devices.SetPaused(ctx, a.tenant.String(), b.device.String(), true); err != nil {
		t.Fatal(err)
	}
	if _, err := devices.TransferPersonal(ctx, a.tenant, owner, b.device, target); err != nil {
		t.Fatal(err)
	}
	after, err := storage.UsageDetailed(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	if after.OverSince == nil || after.GraceEndsAt == nil {
		t.Fatal("a transfer filling the package must start its storage grace period")
	}
	if after.UsedBytes != limit || after.ObjectBytes != 10 || after.Breakdown.Shared.ObjectBytes != 10 {
		t.Fatalf("actual destination usage disagrees with incremental preview: %+v %+v", after, after.Breakdown)
	}
}
