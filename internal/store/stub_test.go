package store_test

import (
	"context"
	"errors"
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

func stub(t *testing.T, m *store.Messages, tenant, device uuid.UUID, chat, waID string) uuid.UUID {
	t.Helper()
	res, err := m.Insert(context.Background(), store.InsertMessage{
		UID: uuid.New(), TenantID: tenant, DeviceID: device,
		WAID: waID, ChatKey: chat, ChatPN: chat,
		Kind: domain.KindMessage, Type: domain.TypeUnsupported,
		Source: domain.SourceLive, TS: stubTS,
		Unsupported: "senderKeyDistributionMessage",
	})
	if err != nil {
		t.Fatal(err)
	}
	return res.UID
}

// stubTS is when the placeholder and its real message were sent.
var stubTS = time.Now().Truncate(time.Second)

// realMessage is the message a placeholder took the slot of, sealed to uid.
func realMessage(uid, tenant, device uuid.UUID, chat, waID, body string) store.InsertMessage {
	return store.InsertMessage{
		UID: uid, TenantID: tenant, DeviceID: device,
		WAID: waID, ChatKey: chat, ChatPN: chat,
		Kind: domain.KindMessage, Type: domain.TypeText,
		Source: domain.SourceLive, TS: stubTS, ContentKeyID: 1, BodySealed: []byte(body),
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

	uid := stub(t, m, tenant, device, chat, waID)
	// The real message, arriving second, under the same id, sealed to the
	// placeholder's uid (DS51).
	res, err := m.Insert(context.Background(), realMessage(uid, tenant, device, chat, waID, "a mensagem de verdade"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Filled || !res.Duplicate || res.UID != uid {
		t.Errorf("result = %+v, want the placeholder's row filled", res)
	}

	row := only(t, m, tenant, device, chat)
	if row.UID != uid {
		t.Errorf("uid = %v, want the placeholder's %v", row.UID, uid)
	}
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

// TestAFillSealedToAnotherUIDWritesNothing (DS51): the row keeps the
// placeholder's uid, and a sealed value opens only under the uid it was
// sealed to. A message sealed to another uid would read as tampered there,
// so it fills nothing and is told the placeholder's uid.
func TestAFillSealedToAnotherUIDWritesNothing(t *testing.T) {
	m, tenant, device := chatFixture(t)
	const chat, waID = "120363000000000000@g.us", "3AD9FC72C86E3D46A830"

	uid := stub(t, m, tenant, device, chat, waID)
	in := realMessage(uuid.New(), tenant, device, chat, waID, "selada para outra linha")
	in.Media = &store.InsertMedia{MediaType: "image", MimeType: "image/jpeg", MediaKeySealed: []byte("key")}
	_, err := m.Insert(context.Background(), in)
	var fill *store.PlaceholderError
	if !errors.As(err, &fill) || fill.UID != uid {
		t.Fatalf("err = %v, want a PlaceholderError naming %v", err, uid)
	}

	row := only(t, m, tenant, device, chat)
	if row.Type != domain.TypeUnsupported || len(row.BodySealed) != 0 || row.Media != nil {
		t.Errorf("row = %s, body %q, media %v: a fill sealed to another uid was written",
			row.Type, row.BodySealed, row.Media)
	}
}

// TestAFillKeepsItsAttachment (DS51): the attachment's row is written
// with the fill, under the placeholder's uid, and the chat list stops
// saying "unsupported" about it.
func TestAFillKeepsItsAttachment(t *testing.T) {
	m, tenant, device := chatFixture(t)
	const chat, waID = "120363000000000000@g.us", "3AD9FC72C86E3D46A830"

	uid := stub(t, m, tenant, device, chat, waID)
	if got := chatFor(t, m, tenant, device, chat).LastType; got != string(domain.TypeUnsupported) {
		t.Fatalf("chat last_type = %q before the fill, want unsupported", got)
	}
	in := realMessage(uid, tenant, device, chat, waID, "a legenda")
	in.Type = domain.TypeImage
	in.Media = &store.InsertMedia{
		MediaType: "image", MimeType: "image/jpeg", FileLength: 42,
		MediaKeySealed: []byte("key"), ThumbSealed: []byte("thumb"),
	}
	res, err := m.Insert(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Filled {
		t.Fatalf("result = %+v, want filled", res)
	}

	row := only(t, m, tenant, device, chat)
	if row.Type != domain.TypeImage {
		t.Errorf("type = %s, want image", row.Type)
	}
	if row.Media == nil {
		t.Fatal("no media row: the fill dropped the attachment")
	}
	if string(row.Media.MediaKeySealed) != "key" || string(row.Media.ThumbSealed) != "thumb" {
		t.Errorf("media = %+v", row.Media)
	}
	if row.Media.DownloadStatus != "pending" {
		t.Errorf("download_status = %q, want pending", row.Media.DownloadStatus)
	}
	if got := chatFor(t, m, tenant, device, chat).LastType; got != string(domain.TypeImage) {
		t.Errorf("chat last_type = %q, want image", got)
	}
}
