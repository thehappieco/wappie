package store_test

import (
	"testing"
	"time"

	"whatserver2/internal/store"
)

// The attribution rules, tested without a database because they are pure
// arithmetic over timestamps and the interesting cases are all about clock
// disagreement — which is far easier to construct here than to provoke against
// a real Postgres.

var base = time.Date(2026, 8, 24, 14, 0, 0, 0, time.UTC)

func at(offset time.Duration) *time.Time {
	t := base.Add(offset)
	return &t
}

func versions(offsets ...time.Duration) []store.VersionTime {
	out := make([]store.VersionTime, 0, len(offsets))
	for i, o := range offsets {
		out = append(out, store.VersionTime{
			Revision: i,
			WAID:     []string{"r0", "r1", "r2", "r3"}[i],
			TS:       at(o),
		})
	}
	return out
}

func TestAMessageNeverEditedIsAlwaysCertain(t *testing.T) {
	saw, confirmed, certain := store.AttributeRead(
		versions(0), nil, base.Add(5*time.Minute))
	if saw != 0 || confirmed != 0 || !certain {
		t.Fatalf("got saw=%d confirmed=%d certain=%v, want 0/0/true — there is only "+
			"one thing the reader could have been looking at", saw, confirmed, certain)
	}
}

func TestReadBeforeTheEditSawTheOriginal(t *testing.T) {
	saw, confirmed, certain := store.AttributeRead(
		versions(0, 10*time.Minute), nil, base.Add(5*time.Minute))
	if saw != 0 || confirmed != 0 || !certain {
		t.Fatalf("got saw=%d confirmed=%d certain=%v, want 0/0/true", saw, confirmed, certain)
	}
}

// TestDeliveryOfAnEditIsProofThatItArrived is the reason every version keeps
// its own WhatsApp id rather than being folded into the original's row.
//
// An edit is a stanza with an id of its own, so it collects its own delivery
// receipt. That receipt is the reader's own device stating the new text
// arrived, which is a different class of evidence from two clocks agreeing.
func TestDeliveryOfAnEditIsProofThatItArrived(t *testing.T) {
	delivered := map[string]time.Time{
		"r0": base.Add(1 * time.Second),
		"r1": base.Add(2 * time.Minute),
	}
	saw, confirmed, certain := store.AttributeRead(
		versions(0, 1*time.Minute), delivered, base.Add(5*time.Minute))
	if saw != 1 || confirmed != 1 || !certain {
		t.Fatalf("got saw=%d confirmed=%d certain=%v, want 1/1/true", saw, confirmed, certain)
	}
}

// TestAnEditWithNoDeliveryReceiptIsOnlyInferred is the case the whole
// three-value return exists for.
//
// The timestamps say the edit went out before the read, so the reader probably
// saw the new text. But nothing confirms the edit ever reached them, and a UI
// that renders this as fact is telling its user that someone read a correction
// they may never have been shown.
func TestAnEditWithNoDeliveryReceiptIsOnlyInferred(t *testing.T) {
	delivered := map[string]time.Time{"r0": base.Add(1 * time.Second)}
	saw, confirmed, certain := store.AttributeRead(
		versions(0, 1*time.Minute), delivered, base.Add(5*time.Minute))
	if saw != 1 {
		t.Fatalf("saw = %d, want 1: the timestamps do point at the edit", saw)
	}
	if confirmed != 0 {
		t.Fatalf("confirmed = %d, want 0: nothing says the edit arrived", confirmed)
	}
	if certain {
		t.Fatal("reported as certain, but only the clock says the reader saw the edit")
	}
}

// TestProofOutranksASkewedClock covers a sender whose clock runs fast.
//
// The edit carries a timestamp after the read, so a pure timestamp comparison
// concludes the reader saw the original. The reader's own device having
// acknowledged the edit beforehand settles it the other way.
func TestProofOutranksASkewedClock(t *testing.T) {
	delivered := map[string]time.Time{"r1": base.Add(1 * time.Minute)}
	saw, confirmed, certain := store.AttributeRead(
		versions(0, 30*time.Minute), delivered, base.Add(5*time.Minute))
	if saw != 1 || confirmed != 1 {
		t.Fatalf("got saw=%d confirmed=%d, want 1/1: the delivery receipt is not a guess",
			saw, confirmed)
	}
	if !certain {
		t.Fatal("proof and inference agree, so this is not uncertain")
	}
}

// TestDeliveryAfterTheReadProvesNothing: an edit that arrived later cannot have
// been on screen earlier.
func TestDeliveryAfterTheReadProvesNothing(t *testing.T) {
	delivered := map[string]time.Time{"r1": base.Add(9 * time.Minute)}
	saw, confirmed, _ := store.AttributeRead(
		versions(0, 8*time.Minute), delivered, base.Add(5*time.Minute))
	if saw != 0 || confirmed != 0 {
		t.Fatalf("got saw=%d confirmed=%d, want 0/0", saw, confirmed)
	}
}

// TestAVersionWithNoTimestampIsNeverGuessedAt keeps a row whose timestamp was
// refused as implausible from silently becoming "what the reader saw".
func TestAVersionWithNoTimestampIsNeverGuessedAt(t *testing.T) {
	vs := versions(0, 1*time.Minute)
	vs[1].TS = nil

	saw, _, _ := store.AttributeRead(vs, nil, base.Add(5*time.Minute))
	if saw != 0 {
		t.Fatalf("saw = %d, want 0: a version with no time cannot be placed on a timeline", saw)
	}

	// It can still be confirmed the hard way.
	delivered := map[string]time.Time{"r1": base.Add(2 * time.Minute)}
	saw, confirmed, certain := store.AttributeRead(vs, delivered, base.Add(5*time.Minute))
	if saw != 1 || confirmed != 1 || !certain {
		t.Fatalf("got saw=%d confirmed=%d certain=%v, want 1/1/true: the receipt does not "+
			"depend on the version carrying a usable timestamp", saw, confirmed, certain)
	}
}
