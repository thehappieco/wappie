package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"whatserver2/internal/domain"
	"whatserver2/internal/pg"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

func TestDeviceStatsCountStoredObjectsInsteadOfReportedMediaLengths(t *testing.T) {
	a := newArchive(t)
	ctx := context.Background()
	a.insert(t, row{ts: time.Now(), chat: "chat", object: "shared-forward"})
	a.insert(t, row{ts: time.Now(), chat: "chat", object: "shared-forward"})
	if err := pg.InTenantTx(ctx, a.pool, a.tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE media SET file_length=1000`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	stats, err := store.NewDevices(a.pool).Stats(ctx, a.tenant.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(stats) != 1 || stats[0].MediaBytes != 10 {
		t.Fatalf("stored unique attachment bytes must be 10, not duplicated file lengths: %+v", stats)
	}
}

func TestStorageBreakdownMatchesWorkspaceAndSeparatesSharedAndPendingObjects(t *testing.T) {
	a := newArchive(t)
	ctx := context.Background()
	devices := store.NewDevices(a.pool)
	second, err := devices.Create(ctx, a.tenant.String(), "Support", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	b := *a
	b.device = uuid.MustParse(second.ID)
	firstID := a.insert(t, row{ts: time.Now(), chat: "group", object: "shared"})
	a.insert(t, row{ts: time.Now(), chat: "group", object: "shared"})
	b.insert(t, row{ts: time.Now(), chat: "group", object: "shared"})
	a.insert(t, row{ts: time.Now(), chat: "group", object: "only-first"})
	b.insert(t, row{ts: time.Now(), chat: "group", object: "only-second"})
	// All seven canonical record categories must remain attributed to their number.
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
	if _, err := store.NewReceipts(a.pool).Insert(ctx, store.InsertReceipt{TenantID: a.tenant, DeviceID: a.device, ChatKey: "group", ReaderKey: "reader", WAIDs: []string{"id"}, Kind: domain.ReceiptRead, TS: time.Now()}); err != nil {
		t.Fatal(err)
	}
	storage := store.NewStorage(a.pool)
	if err := storage.ReserveObject(ctx, a.tenant, "in-flight", 17); err != nil {
		t.Fatal(err)
	}
	// A second workspace may even have the same object key: it is not this bill.
	otherTenant := uuid.MustParse(newTenant(t, a.pool, "other"))
	if err := storage.ReserveObject(ctx, otherTenant, "shared", 9999); err != nil {
		t.Fatal(err)
	}
	check := func(wantShared, wantPending int64) store.StorageUsage {
		t.Helper()
		usage, err := storage.UsageDetailed(ctx, a.tenant)
		if err != nil {
			t.Fatal(err)
		}
		if usage.Breakdown == nil {
			t.Fatal("missing breakdown")
		}
		archiveBytes := usage.Breakdown.Shared.ArchiveBytes + usage.Breakdown.Unassigned.ArchiveBytes
		objectBytes := usage.Breakdown.Shared.ObjectBytes + usage.Breakdown.Unassigned.ObjectBytes
		sum := usage.Breakdown.Shared.UsedBytes + usage.Breakdown.Unassigned.UsedBytes
		for _, device := range usage.Breakdown.Devices {
			archiveBytes += device.ArchiveBytes
			objectBytes += device.ObjectBytes
			sum += device.UsedBytes
		}
		if archiveBytes != usage.ArchiveBytes || objectBytes != usage.ObjectBytes || sum != usage.UsedBytes {
			t.Fatalf("breakdown does not reconcile: %+v breakdown %+v", usage, usage.Breakdown)
		}
		if usage.Breakdown.Shared.ObjectBytes != wantShared || usage.Breakdown.Unassigned.ObjectBytes != wantPending || usage.Breakdown.Unassigned.ArchiveBytes != 0 {
			t.Fatalf("wrong shared/pending attribution: %+v", usage.Breakdown)
		}
		stats, err := devices.Stats(ctx, a.tenant.String())
		if err != nil {
			t.Fatal(err)
		}
		for _, device := range usage.Breakdown.Devices {
			found := false
			for _, stat := range stats {
				if stat.DeviceID == device.DeviceID {
					found = true
					if stat.StorageBytes != device.StorageBytes || stat.MediaBytes != device.ObjectBytes {
						t.Fatalf("device stats differ from bill: %+v %+v", stat, device)
					}
				}
			}
			if !found {
				t.Fatalf("missing stats for %+v", device)
			}
		}
		return usage
	}
	before := check(10, 17)
	if len(before.Breakdown.Devices) != 2 || before.ObjectBytes != 47 {
		t.Fatalf("unexpected baseline: %+v %+v", before, before.Breakdown)
	}
	// Reprocessing canonical raw data changes archive bytes, not object attribution.
	if err := pg.InTenantTx(ctx, a.pool, a.tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE messages SET raw_sealed=$2 WHERE uid=$1`, firstID, []byte{5, 6, 7})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	check(10, 17)
	if err := devices.Delete(ctx, a.tenant.String(), second.ID); err != nil {
		t.Fatal(err)
	}
	after := check(0, 27)
	if len(after.Breakdown.Devices) != 1 || after.Breakdown.Devices[0].ObjectBytes != 20 {
		t.Fatalf("shared object did not move to its surviving number: %+v", after.Breakdown)
	}
	if err := storage.DeleteObject(ctx, a.tenant, "only-second", func(context.Context, string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	check(0, 17)
}

func TestStorageBreakdownAccountsReservedObjectWithPendingArchiveReference(t *testing.T) {
	a := newArchive(t)
	ctx := context.Background()
	uid := uuid.New()
	hash := []byte{0x12, 0x34}
	_, err := a.messages.Insert(ctx, store.InsertMessage{UID: uid, TenantID: a.tenant, DeviceID: a.device, WAID: "pending", Kind: domain.KindMessage, Type: domain.TypeImage, Source: domain.SourceLive, TS: time.Now(), ChatKey: "pending", BodySealed: []byte{1}, Media: &store.InsertMedia{MediaType: "image", FileEncSHA256: hash, FileLength: 999}})
	if err != nil {
		t.Fatal(err)
	}
	storage := store.NewStorage(a.pool)
	key := a.tenant.String() + "/12/1234"
	if err := storage.ReserveObject(ctx, a.tenant, key, 42); err != nil {
		t.Fatal(err)
	}
	usage, err := storage.UsageDetailed(ctx, a.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if usage.ObjectBytes != 42 || usage.Breakdown.Devices[0].ObjectBytes != 42 || usage.Breakdown.Unassigned.UsedBytes != 0 {
		t.Fatalf("reservation lost its pending archive reference: %+v %+v", usage, usage.Breakdown)
	}
}

func TestStorageBreakdownStaysConsistentDuringConcurrentArchiveWrites(t *testing.T) {
	a := newArchive(t)
	ctx := context.Background()
	storage := store.NewStorage(a.pool)
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 20; i++ {
			uid := uuid.New()
			if _, err := a.messages.Insert(ctx, store.InsertMessage{UID: uid, TenantID: a.tenant, DeviceID: a.device, WAID: uid.String(), Kind: domain.KindMessage, Type: domain.TypeText, Source: domain.SourceLive, TS: time.Now(), ChatKey: "concurrent", BodySealed: []byte{1, 2, 3}}); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	for i := 0; i < 20; i++ {
		usage, err := storage.UsageDetailed(ctx, a.tenant)
		if err != nil {
			t.Fatal(err)
		}
		sum := usage.Breakdown.Shared.UsedBytes + usage.Breakdown.Unassigned.UsedBytes
		for _, device := range usage.Breakdown.Devices {
			sum += device.UsedBytes
		}
		if sum != usage.UsedBytes {
			t.Fatalf("concurrent snapshot drift: total %d, rows %d", usage.UsedBytes, sum)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
