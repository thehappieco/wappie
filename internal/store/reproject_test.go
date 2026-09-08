package store_test

import (
	"context"
	"testing"

	"whatserver2/internal/domain"
	"whatserver2/internal/store"
)

// Retyping the rows that were never messages.
//
// An older build stored key distribution and other protocol traffic as
// unsupported. The classifier now skips those on the way in, so there is
// nothing to reclassify them AS — and leaving them unsupported meant the
// reprojection list offered them again on every press, for good.

func TestMachineryIsRetypedAsProtocolAndLeavesTheList(t *testing.T) {
	m, tenant, device := chatFixture(t)
	ctx := context.Background()

	res := arrive(t, m, tenant, device, "K1", store.InsertMessage{Type: domain.TypeUnsupported})
	if err := m.MarkProtocol(ctx, tenant, device, res.UID); err != nil {
		t.Fatal(err)
	}
	row, err := m.Get(ctx, tenant, res.UID)
	if err != nil {
		t.Fatal(err)
	}
	if row.Type != domain.TypeProtocol {
		t.Fatalf("type = %q, want protocol", row.Type)
	}
	left, err := m.Unsupported(ctx, tenant, device, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range left {
		if r.UID == res.UID {
			t.Fatal("the row is still offered for reprojection; it will be, on every press, forever")
		}
	}
}

func TestOnlyAnUnsupportedRowCanBeRetyped(t *testing.T) {
	// A caller that could retype anything could turn a photograph into
	// protocol traffic and make it vanish from every conversation.
	m, tenant, device := chatFixture(t)
	ctx := context.Background()

	text := arrive(t, m, tenant, device, "T1", store.InsertMessage{})
	if err := m.MarkProtocol(ctx, tenant, device, text.UID); err == nil {
		t.Fatal("a text message was retyped as protocol")
	}
}
