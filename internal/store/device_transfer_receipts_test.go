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

func TestPersonalTransferRemapsReceiptBatches(t *testing.T) {
	a := newArchive(t)
	ctx := context.Background()
	owner, personal := transferOwner(t, a, "owner")
	devices := store.NewDevices(a.pool)
	existing, err := devices.Create(ctx, personal.String(), "existing number", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	receipts := store.NewReceipts(a.pool)
	insert := func(tenant, device uuid.UUID, waID string) store.ReceiptResult {
		t.Helper()
		res, err := receipts.Insert(ctx, store.InsertReceipt{TenantID: tenant, DeviceID: device,
			ChatKey: "peer", ReaderKey: "peer", WAIDs: []string{waID}, Kind: domain.ReceiptRead, TS: time.Now()})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	dstID := uuid.MustParse(existing.ID)
	sourceReceipt := insert(a.tenant, a.device, "source-message")
	destinationReceipt := insert(personal, dstID, "destination-message")
	if sourceReceipt.Seq != destinationReceipt.Seq {
		t.Fatal("fixture needs coincident source/destination sequences")
	}
	if err := devices.SetPaused(ctx, a.tenant.String(), a.device.String(), true); err != nil {
		t.Fatal(err)
	}
	if _, err := devices.TransferPersonal(ctx, a.tenant, owner, a.device, personal); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		seq    int64
		device uuid.UUID
		waID   string
	}{
		{destinationReceipt.Seq, dstID, "destination-message"},
		{sourceReceipt.Seq + destinationReceipt.Seq, a.device, "source-message"},
	} {
		batch, err := receipts.Batch(ctx, personal, tc.seq)
		if err != nil || batch.DeviceID != tc.device || len(batch.WAIDs) != 1 || batch.WAIDs[0] != tc.waID {
			t.Fatalf("receipt batch at %d: %+v, %v", tc.seq, batch, err)
		}
		var eventSeq int64
		if err := pg.InTenantTx(ctx, a.pool, personal.String(), func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT seq FROM events WHERE device_id=$1 AND kind='receipt'`, tc.device).Scan(&eventSeq)
		}); err != nil {
			t.Fatal(err)
		}
		if eventSeq != batch.Seq {
			t.Fatalf("event sequence %d differs from receipt %d", eventSeq, batch.Seq)
		}
	}
	replay, truncated, err := receipts.Since(ctx, personal, destinationReceipt.Seq, 10)
	if err != nil || truncated || len(replay) != 1 || replay[0].DeviceID != a.device {
		t.Fatalf("replay after old Personal cursor: %+v, truncated=%v, error=%v", replay, truncated, err)
	}
}
