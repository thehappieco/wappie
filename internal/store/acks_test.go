package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/domain"
	"whatserver2/internal/store"
)

func ack(tenant, device uuid.UUID, reader, lid, pn string, fromMe bool,
	kind domain.ReceiptKind, at time.Time, ids ...string) store.InsertReceipt {
	return store.InsertReceipt{
		TenantID: tenant, DeviceID: device,
		ChatKey:   "120363000000000000@g.us",
		ReaderKey: reader, ReaderLID: lid, ReaderPN: pn,
		IsFromMe: fromMe, WAIDs: ids, Kind: kind, TS: at.Truncate(time.Second),
	}
}

// TestOurOwnAcknowledgementIsNotSomebodyElseReceivingIt is the bug that is on
// screen right now.
//
// types.ReceiptTypeSender is our own phone confirming it received a message WE
// sent, and normalize stores it as a delivery with is_from_me. Counting it puts
// two grey ticks on a message the instant our own handset acknowledges — and in
// a direct chat, where the denominator is one, that is every message we send.
// The recipient's phone may still be switched off.
func TestOurOwnAcknowledgementIsNotSomebodyElseReceivingIt(t *testing.T) {
	_, tenant, device, receipts := receiptFixture(t)
	ctx := context.Background()
	now := time.Now()

	if _, err := receipts.Insert(ctx, ack(tenant, device,
		"5511900000000@s.whatsapp.net", "", "", true,
		domain.ReceiptDelivered, now, "M1")); err != nil {
		t.Fatal(err)
	}
	got, err := receipts.AcksForPage(ctx, tenant, device, []string{"M1"})
	if err != nil {
		t.Fatal(err)
	}
	if got["M1"].Delivered != 0 {
		t.Errorf("delivered = %d, want 0 — our own device receiving our own "+
			"message is not the recipient receiving it", got["M1"].Delivered)
	}

	// A read from one of our own devices is worth reporting, apart, because
	// the message genuinely was read — elsewhere.
	if _, err := receipts.Insert(ctx, ack(tenant, device,
		"5511900000000@s.whatsapp.net", "", "", true,
		domain.ReceiptRead, now, "M1")); err != nil {
		t.Fatal(err)
	}
	got, _ = receipts.AcksForPage(ctx, tenant, device, []string{"M1"})
	if got["M1"].Read != 0 {
		t.Errorf("read = %d, want 0 — it was not read by the other side", got["M1"].Read)
	}
	if !got["M1"].ReadByUs {
		t.Error("a read from our own device was dropped entirely")
	}
}

// TestOnePersonWithTwoPhonesIsOneReader.
//
// Receipts are stored per device, suffix and all, which is what makes "received
// at 14:02 and again at 19:40" legible as a laptop and a handset. Counting rows
// would make a group of eight where three people carry two devices report
// eleven readers — so a tick waiting for everyone waits for a number that does
// not exist, and never turns.
func TestOnePersonWithTwoPhonesIsOneReader(t *testing.T) {
	_, tenant, device, receipts := receiptFixture(t)
	ctx := context.Background()
	early := time.Now().Add(-time.Hour)
	late := time.Now()

	for _, r := range []struct {
		key string
		at  time.Time
	}{
		{"224437861388494:12@lid", early},
		{"224437861388494:31@lid", late},
	} {
		if _, err := receipts.Insert(ctx, ack(tenant, device,
			r.key, r.key, "", false, domain.ReceiptDelivered, r.at, "M2")); err != nil {
			t.Fatal(err)
		}
	}

	got, err := receipts.AcksForPage(ctx, tenant, device, []string{"M2"})
	if err != nil {
		t.Fatal(err)
	}
	if got["M2"].Delivered != 1 {
		t.Errorf("delivered = %d, want 1 — two devices, one person", got["M2"].Delivered)
	}
	// The earliest, because that is when the person actually got it.
	if got["M2"].DeliveredAt == nil || !got["M2"].DeliveredAt.Equal(early.Truncate(time.Second)) {
		t.Errorf("deliveredAt = %v, want the earlier %v", got["M2"].DeliveredAt, early.Truncate(time.Second))
	}
}

// TestTheSamePersonAddressedTwoWaysIsOneReader.
//
// The same reader can be addressed by LID on one acknowledgement and by phone
// number on another — the reason receipts are keyed on the message id and never
// on the chat. Counting on a single column splits one person into two, which in
// a group inflates the numerator past the denominator and stalls the tick.
func TestTheSamePersonAddressedTwoWaysIsOneReader(t *testing.T) {
	_, tenant, device, receipts := receiptFixture(t)
	ctx := context.Background()
	now := time.Now()
	const lid = "224437861388494@lid"
	const pn = "5511988887777@s.whatsapp.net"

	// One row names both halves; the other names only the phone number. The
	// first is what lets the second be recognised as the same person.
	if _, err := receipts.Insert(ctx, ack(tenant, device,
		lid, lid, pn, false, domain.ReceiptDelivered, now, "M3")); err != nil {
		t.Fatal(err)
	}
	if _, err := receipts.Insert(ctx, ack(tenant, device,
		pn, "", pn, false, domain.ReceiptRead, now, "M3")); err != nil {
		t.Fatal(err)
	}

	got, _ := receipts.AcksForPage(ctx, tenant, device, []string{"M3"})
	if got["M3"].Delivered != 1 || got["M3"].Read != 1 {
		t.Errorf("delivered=%d read=%d, want 1 and 1 — one person, addressed two ways",
			got["M3"].Delivered, got["M3"].Read)
	}
}

// TestAMessageStuckInRetryIsNotDelivered.
//
// The archive keeps five receipt kinds and two of them are not acknowledgements
// at all. Letting retry or server-error fall into a default that counts as a
// delivery would draw two grey ticks on a message that never arrived — the
// single most misleading thing this screen can say.
func TestAMessageStuckInRetryIsNotDelivered(t *testing.T) {
	_, tenant, device, receipts := receiptFixture(t)
	ctx := context.Background()
	now := time.Now()

	for _, k := range []domain.ReceiptKind{domain.ReceiptRetry, domain.ReceiptError} {
		if _, err := receipts.Insert(ctx, ack(tenant, device,
			"5511988887777@s.whatsapp.net", "", "", false, k, now, "M4")); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := receipts.AcksForPage(ctx, tenant, device, []string{"M4"})
	if got["M4"].Delivered != 0 || got["M4"].Read != 0 {
		t.Errorf("delivered=%d read=%d, want zero of each", got["M4"].Delivered, got["M4"].Read)
	}
	if !got["M4"].Retrying || !got["M4"].Failed {
		t.Errorf("retry=%v error=%v, want both reported in their own fields",
			got["M4"].Retrying, got["M4"].Failed)
	}
}
