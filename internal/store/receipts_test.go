package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/domain"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

func receiptFixture(t *testing.T) (*pgxpool.Pool, uuid.UUID, uuid.UUID, *store.Receipts) {
	t.Helper()
	pool := pgtest.Fresh(t, migrate.Run)
	tenantID := newTenant(t, pool, "acme")
	dev, err := store.NewDevices(pool).Create(context.Background(), tenantID, "test", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	return pool, uuid.MustParse(tenantID), uuid.MustParse(dev.ID), store.NewReceipts(pool)
}

func batch(tenant, device uuid.UUID, kind domain.ReceiptKind, ts time.Time, ids ...string) store.InsertReceipt {
	return store.InsertReceipt{
		TenantID: tenant, DeviceID: device,
		ChatKey:   "5511999999999@s.whatsapp.net",
		ReaderKey: "5511999999999@s.whatsapp.net",
		WAIDs:     ids,
		Kind:      kind,
		TS:        ts.Truncate(time.Second),
	}
}

func cursor(t *testing.T, pool *pgxpool.Pool, tenant uuid.UUID) int64 {
	t.Helper()
	var seq int64
	if err := pool.QueryRow(context.Background(),
		`SELECT last_seq FROM tenants WHERE id = $1`, tenant).Scan(&seq); err != nil {
		t.Fatal(err)
	}
	return seq
}

// TestOneAcknowledgementTakesOneSequence is the reason receipts are stored as a
// batch rather than a row at a time.
//
// A read receipt names every message the reader just saw. Allocating a sequence
// per id would take the tenant row lock once per message — two hundred times
// for one message in a two hundred person group — and would tear every
// connected client's cursor forward by the same amount.
func TestOneAcknowledgementTakesOneSequence(t *testing.T) {
	pool, tenant, device, receipts := receiptFixture(t)
	ctx := context.Background()

	before := cursor(t, pool, tenant)
	res, err := receipts.Insert(ctx, batch(tenant, device, domain.ReceiptRead, time.Now(),
		"A1", "A2", "A3", "A4", "A5"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Stored != 5 {
		t.Fatalf("stored %d rows, want 5", res.Stored)
	}
	if got := cursor(t, pool, tenant) - before; got != 1 {
		t.Fatalf("the cursor advanced by %d, want 1: five ids arrived as one event", got)
	}
}

// TestARedeliveredReceiptDoesNotMoveTheCursor. WhatsApp resends receipts on
// every resync; a resync must not look like new activity.
func TestARedeliveredReceiptDoesNotMoveTheCursor(t *testing.T) {
	pool, tenant, device, receipts := receiptFixture(t)
	ctx := context.Background()
	in := batch(tenant, device, domain.ReceiptRead, time.Now(), "A1", "A2")

	if _, err := receipts.Insert(ctx, in); err != nil {
		t.Fatal(err)
	}
	after := cursor(t, pool, tenant)

	res, err := receipts.Insert(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Duplicate {
		t.Fatal("the same batch twice was not reported as a duplicate")
	}
	if got := cursor(t, pool, tenant); got != after {
		t.Fatalf("cursor moved from %d to %d on a redelivery", after, got)
	}
}

// TestAPartlyKnownBatchStoresOnlyWhatIsNew. A resync can overlap: some ids
// already stored, some not.
func TestAPartlyKnownBatchStoresOnlyWhatIsNew(t *testing.T) {
	_, tenant, device, receipts := receiptFixture(t)
	ctx := context.Background()
	now := time.Now()

	if _, err := receipts.Insert(ctx, batch(tenant, device, domain.ReceiptRead, now, "A1")); err != nil {
		t.Fatal(err)
	}
	res, err := receipts.Insert(ctx, batch(tenant, device, domain.ReceiptRead, now, "A1", "A2"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Duplicate {
		t.Fatal("reported as a duplicate, but A2 had never been seen")
	}
	if res.Stored != 1 {
		t.Fatalf("stored %d rows, want 1: only A2 was new", res.Stored)
	}
}

// TestDeliveredAndReadAreSeparateFacts: the same message id acknowledged twice,
// differently, is two rows rather than an overwrite. Losing the delivery time
// would lose the evidence the version attribution rests on.
func TestDeliveredAndReadAreSeparateFacts(t *testing.T) {
	_, tenant, device, receipts := receiptFixture(t)
	ctx := context.Background()
	now := time.Now()

	if _, err := receipts.Insert(ctx,
		batch(tenant, device, domain.ReceiptDelivered, now, "A1")); err != nil {
		t.Fatal(err)
	}
	if _, err := receipts.Insert(ctx,
		batch(tenant, device, domain.ReceiptRead, now.Add(time.Minute), "A1")); err != nil {
		t.Fatal(err)
	}

	rows, err := receipts.ForMessages(ctx, tenant, device, []string{"A1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2 (delivered and read)", len(rows))
	}
}

// TestReplayNeverSplitsAnAcknowledgement.
//
// The read limit counts rows, so a batch can straddle it. Returning the first
// half would hand a client a two-id acknowledgement indistinguishable from a
// complete one — and the client would never learn about the rest, because its
// cursor had already moved past that sequence.
func TestReplayNeverSplitsAnAcknowledgement(t *testing.T) {
	_, tenant, device, receipts := receiptFixture(t)
	ctx := context.Background()
	now := time.Now()

	if _, err := receipts.Insert(ctx,
		batch(tenant, device, domain.ReceiptDelivered, now, "A1", "A2")); err != nil {
		t.Fatal(err)
	}
	if _, err := receipts.Insert(ctx,
		batch(tenant, device, domain.ReceiptRead, now, "B1", "B2", "B3")); err != nil {
		t.Fatal(err)
	}

	// A limit of three rows lands in the middle of the second batch.
	got, truncated, err := receipts.Since(ctx, tenant, 0, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !truncated {
		t.Fatal("truncation was not reported, so a caller merging streams would " +
			"trust sequences it has not fully read")
	}
	if len(got) != 1 {
		t.Fatalf("got %d batches, want 1: the incomplete one must be dropped", len(got))
	}
	if len(got[0].WAIDs) != 2 {
		t.Fatalf("first batch has %d ids, want 2", len(got[0].WAIDs))
	}

	// Reading again from the previous sequence returns it whole.
	rest, _, err := receipts.Since(ctx, tenant, got[0].Seq, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 1 || len(rest[0].WAIDs) != 3 {
		t.Fatalf("the second batch came back as %+v, want all three ids", rest)
	}
}

// TestTheSameAcknowledgementUnderTwoAddressingsIsOneFact.
//
// Found against real traffic. A message sent to a phone number is stored with
// that chat key, and the delivery receipt for it comes back addressed by LID.
// Keying receipts on the chat as well as the message would record one
// acknowledgement twice, burn a second sequence number, and — worse — make the
// projection's join miss it entirely.
func TestTheSameAcknowledgementUnderTwoAddressingsIsOneFact(t *testing.T) {
	_, tenant, device, receipts := receiptFixture(t)
	ctx := context.Background()
	now := time.Now()

	byPhone := batch(tenant, device, domain.ReceiptDelivered, now, "A1")
	byLID := byPhone
	byLID.ChatKey = "224437861388494@lid"

	if _, err := receipts.Insert(ctx, byPhone); err != nil {
		t.Fatal(err)
	}
	res, err := receipts.Insert(ctx, byLID)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Duplicate {
		t.Fatal("the same acknowledgement under a different chat key was stored again")
	}

	rows, err := receipts.ForMessages(ctx, tenant, device, []string{"A1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
}

// TestReceiptsAreFoundRegardlessOfHowTheChatWasAddressed is the other half of
// the same bug: the receipt arrives under one addressing and the message was
// stored under another, so the lookup cannot involve the chat at all.
func TestReceiptsAreFoundRegardlessOfHowTheChatWasAddressed(t *testing.T) {
	_, tenant, device, receipts := receiptFixture(t)
	ctx := context.Background()

	in := batch(tenant, device, domain.ReceiptRead, time.Now(), "A1")
	in.ChatKey = "224437861388494@lid"
	if _, err := receipts.Insert(ctx, in); err != nil {
		t.Fatal(err)
	}

	rows, err := receipts.ForMessages(ctx, tenant, device, []string{"A1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1: the message was stored under a phone number "+
			"and the receipt arrived under a LID", len(rows))
	}
}

// TestARepeatedIdWithinOneStanzaDoesNotBreakTheInsert. A malformed or resent
// stanza naming the same id twice would make the batch insert conflict with
// itself, which Postgres reports as a cardinality violation rather than
// skipping quietly.
func TestARepeatedIdWithinOneStanzaDoesNotBreakTheInsert(t *testing.T) {
	_, tenant, device, receipts := receiptFixture(t)

	res, err := receipts.Insert(context.Background(),
		batch(tenant, device, domain.ReceiptRead, time.Now(), "A1", "A1", "A2"))
	if err != nil {
		t.Fatalf("a duplicated id inside one batch failed the whole insert: %v", err)
	}
	if res.Stored != 2 {
		t.Fatalf("stored %d rows, want 2", res.Stored)
	}
}
