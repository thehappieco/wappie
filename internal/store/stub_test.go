package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/domain"
	"whatserver2/internal/store"
)

// A group message that also carried a Signal sender key used to arrive twice
// under one message id: the key first, classified as "unsupported" and written,
// then the real message -- rejected as a duplicate of the placeholder that had
// taken its row. 661 group messages on one installation were replaced that way.
//
// The classifier no longer stores those keys, but the placeholders are already
// written, and while they hold the (device, chat, wa_id) slot no history sync
// can put the real message back. So a row carrying nothing gives way to one
// carrying something.
//
// The dangerous version of this fix overwrites real messages. These tests are
// mostly about what must NOT be replaced.

func stub(t *testing.T, m *store.Messages, tenant, device uuid.UUID, chat, waID string) {
	t.Helper()
	_, err := m.Insert(context.Background(), store.InsertMessage{
		UID: uuid.New(), TenantID: tenant, DeviceID: device,
		WAID: waID, ChatKey: chat, ChatPN: chat,
		Kind: domain.KindMessage, Type: domain.TypeUnsupported,
		Source: domain.SourceLive, TS: time.Now().Truncate(time.Second),
		Unsupported: "senderKeyDistributionMessage",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func only(t *testing.T, m *store.Messages, tenant, device uuid.UUID, chat string) store.Row {
	t.Helper()
	rows, err := m.Page(context.Background(), tenant, device, []string{chat}, store.Cursor{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected one row, got %d", len(rows))
	}
	return rows[0]
}

func TestARealMessageReplacesTheStubThatStoleItsPlace(t *testing.T) {
	m, tenant, device := chatFixture(t)
	const chat, waID = "120363000000000000@g.us", "3AD9FC72C86E3D46A830"

	stub(t, m, tenant, device, chat, waID)
	// The real message, arriving second, under the same id.
	insert(t, m, tenant, device, chat, waID, domain.KindMessage, time.Now(), "a mensagem de verdade")

	row := only(t, m, tenant, device, chat)
	if row.Type != domain.TypeText {
		t.Errorf("type = %s, want text — the placeholder is still holding the row", row.Type)
	}
	if string(row.BodySealed) != "a mensagem de verdade" {
		t.Errorf("body = %q, want the real message", row.BodySealed)
	}
	if row.Unsupported != "" {
		t.Errorf("unsupported_field = %q, want it cleared", row.Unsupported)
	}
}

func TestARealMessageIsNeverOverwritten(t *testing.T) {
	m, tenant, device := chatFixture(t)
	const chat, waID = "120363000000000000@g.us", "3AD9FC72C86E3D46A830"

	insert(t, m, tenant, device, chat, waID, domain.KindMessage, time.Now(), "o original")
	// The same message again, as a history sync delivers it, with a different
	// body. Idempotency is the whole point of the conflict clause: the second
	// copy must change nothing.
	insert(t, m, tenant, device, chat, waID, domain.KindMessage, time.Now(), "uma cópia diferente")

	if body := string(only(t, m, tenant, device, chat).BodySealed); body != "o original" {
		t.Errorf("body = %q, want the first one stored", body)
	}
}

func TestAStubIsNotReplacedByAnotherStub(t *testing.T) {
	m, tenant, device := chatFixture(t)
	const chat, waID = "120363000000000000@g.us", "3AD9FC72C86E3D46A830"

	stub(t, m, tenant, device, chat, waID)
	stub(t, m, tenant, device, chat, waID)

	row := only(t, m, tenant, device, chat)
	if row.Type != domain.TypeUnsupported {
		t.Errorf("type = %s, want it left alone", row.Type)
	}
	if row.Unsupported != "senderKeyDistributionMessage" {
		t.Errorf("unsupported_field = %q, want the name kept", row.Unsupported)
	}
}

func TestAnEmptyMessageDoesNotClearAStub(t *testing.T) {
	m, tenant, device := chatFixture(t)
	const chat, waID = "120363000000000000@g.us", "3AD9FC72C86E3D46A830"

	stub(t, m, tenant, device, chat, waID)

	// Something classified but carrying nothing — a control row, say. It has no
	// content to contribute, so replacing the placeholder with it would trade
	// one empty row for another and lose the field name that says what happened.
	_, err := m.Insert(context.Background(), store.InsertMessage{
		UID: uuid.New(), TenantID: tenant, DeviceID: device,
		WAID: waID, ChatKey: chat, ChatPN: chat,
		Kind: domain.KindMessage, Type: domain.TypeText,
		Source: domain.SourceLive, TS: time.Now().Truncate(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}

	if row := only(t, m, tenant, device, chat); row.Unsupported != "senderKeyDistributionMessage" {
		t.Errorf("unsupported_field = %q; an empty message took the row", row.Unsupported)
	}
}
