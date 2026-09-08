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

// WhatsApp names a person two ways and never joins them: a group addresses
// participants by LID, and the contact list a phone syncs is keyed by phone
// number. On one real account that left 860 of 883 group senders with no name --
// the names were there, filed under an identifier nobody looked up.
//
// whatsmeow has been recording the pairs all along. These tests are about
// reading them without breaking the archive, and the dangerous half is the
// direction: filling in a LID where only a number is known would rewrite
// sender_key and chat_key, because the LID is what those are derived from.

// linkFixture is chatFixture plus the pool, because the linking pass reads a
// table whatsmeow owns rather than one this package created.
func linkFixture(t *testing.T) (*store.Messages, *pgxpool.Pool, uuid.UUID, uuid.UUID) {
	t.Helper()
	pool := pgtest.Fresh(t, migrate.Run)
	tenantID := newTenant(t, pool, "acme")
	dev, err := store.NewDevices(pool).Create(context.Background(), tenantID, "test", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	// whatsmeow creates this when its session store opens; the migrations here
	// do not, because the table is not ours. Same shape: lid keyed, pn unique.
	if _, err := pool.Exec(context.Background(), `
		CREATE TABLE IF NOT EXISTS whatsmeow_lid_map (
			lid text PRIMARY KEY,
			pn  text NOT NULL UNIQUE
		)`); err != nil {
		t.Fatal(err)
	}
	return store.NewMessages(pool), pool, uuid.MustParse(tenantID), uuid.MustParse(dev.ID)
}

func lidMap(t *testing.T, pool *pgxpool.Pool, pairs map[string]string) {
	t.Helper()
	for lid, pn := range pairs {
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO whatsmeow_lid_map (lid, pn) VALUES ($1, $2)
			 ON CONFLICT (lid) DO UPDATE SET pn = EXCLUDED.pn`, lid, pn); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLinkingFillsInTheNumberBehindALID(t *testing.T) {
	m, pool, tenant, device := linkFixture(t)
	ctx := context.Background()
	const chat = "120363000000000000@g.us"

	// A group message from somebody addressed only by LID, which is how the
	// history sync delivers every one of them.
	_, err := m.Insert(ctx, store.InsertMessage{
		UID: uuid.New(), TenantID: tenant, DeviceID: device,
		WAID: "wa-1", ChatKey: chat, ChatPN: chat, IsGroup: true,
		SenderKey: "42631895773279@lid", SenderLID: "42631895773279@lid",
		Kind: domain.KindMessage, Type: domain.TypeText,
		Source: domain.SourceHistory, TS: time.Now().Truncate(time.Second),
		ContentKeyID: 1, BodySealed: []byte("oi"),
	})
	if err != nil {
		t.Fatal(err)
	}
	lidMap(t, pool, map[string]string{"42631895773279": "5511971446866"})

	got, err := store.LinkPhoneNumbers(ctx, pool, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if got.Messages != 1 {
		t.Fatalf("linked %d messages, want 1", got.Messages)
	}

	rows, err := m.Page(ctx, tenant, device, []string{chat}, store.Cursor{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if rows[0].SenderPN != "5511971446866@s.whatsapp.net" {
		t.Errorf("sender_pn = %q, want the number behind the LID", rows[0].SenderPN)
	}
	// And the identity the archive keys on must not have moved.
	if rows[0].SenderKey != "42631895773279@lid" {
		t.Errorf("sender_key = %q; linking rewrote the storage identity", rows[0].SenderKey)
	}
}

func TestLinkingNeverInventsALID(t *testing.T) {
	m, pool, tenant, device := linkFixture(t)
	ctx := context.Background()
	const chat = "5511971446866@s.whatsapp.net"

	// A one-to-one conversation, addressed by number, as most are.
	insert(t, m, tenant, device, chat, "wa-1", domain.KindMessage, time.Now(), "oi")
	lidMap(t, pool, map[string]string{"42631895773279": "5511971446866"})

	if _, err := store.LinkPhoneNumbers(ctx, pool, tenant); err != nil {
		t.Fatal(err)
	}

	rows, err := m.Page(ctx, tenant, device, []string{chat}, store.Cursor{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1 — the conversation forked", len(rows))
	}
	if rows[0].ChatKey != chat {
		t.Errorf("chat_key = %q, want %q; giving this row a LID would have made "+
			"Primary() return it and re-keyed the conversation", rows[0].ChatKey, chat)
	}
}

func TestLinkingLeavesAKnownNumberAlone(t *testing.T) {
	m, pool, tenant, device := linkFixture(t)
	ctx := context.Background()
	const chat = "120363000000000000@g.us"

	// The sender's number is already known, and the map disagrees with it.
	// Whatever the map says, a number the message itself carried wins: it came
	// from the stanza, and the map is a cache.
	_, err := m.Insert(ctx, store.InsertMessage{
		UID: uuid.New(), TenantID: tenant, DeviceID: device,
		WAID: "wa-1", ChatKey: chat, ChatPN: chat, IsGroup: true,
		SenderKey: "42631895773279@lid", SenderLID: "42631895773279@lid",
		SenderPN: "5511900000000@s.whatsapp.net",
		Kind:     domain.KindMessage, Type: domain.TypeText,
		Source: domain.SourceLive, TS: time.Now().Truncate(time.Second),
		ContentKeyID: 1, BodySealed: []byte("oi"),
	})
	if err != nil {
		t.Fatal(err)
	}
	lidMap(t, pool, map[string]string{"42631895773279": "5511971446866"})

	got, err := store.LinkPhoneNumbers(ctx, pool, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if got.Messages != 0 {
		t.Errorf("linked %d messages; a number that was already there was overwritten", got.Messages)
	}
}

func TestLinkingIsIdempotent(t *testing.T) {
	m, pool, tenant, device := linkFixture(t)
	ctx := context.Background()
	const chat = "120363000000000000@g.us"

	_, err := m.Insert(ctx, store.InsertMessage{
		UID: uuid.New(), TenantID: tenant, DeviceID: device,
		WAID: "wa-1", ChatKey: chat, ChatPN: chat, IsGroup: true,
		SenderKey: "42631895773279@lid", SenderLID: "42631895773279@lid",
		Kind: domain.KindMessage, Type: domain.TypeText,
		Source: domain.SourceHistory, TS: time.Now().Truncate(time.Second),
		ContentKeyID: 1, BodySealed: []byte("oi"),
	})
	if err != nil {
		t.Fatal(err)
	}
	lidMap(t, pool, map[string]string{"42631895773279": "5511971446866"})

	// It runs at every boot, so the second pass has to be free.
	if _, err := store.LinkPhoneNumbers(ctx, pool, tenant); err != nil {
		t.Fatal(err)
	}
	again, err := store.LinkPhoneNumbers(ctx, pool, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if again.Messages != 0 {
		t.Errorf("the second pass touched %d rows; it should touch none", again.Messages)
	}
	_ = device
}

func TestLinkingStripsTheDeviceSuffix(t *testing.T) {
	m, pool, tenant, device := linkFixture(t)
	ctx := context.Background()
	const chat = "120363000000000000@g.us"

	// A participant addressed with a device number. Left in, the lookup misses
	// and the result would be 5511971446866:5@s.whatsapp.net, which matches no
	// contact row.
	_, err := m.Insert(ctx, store.InsertMessage{
		UID: uuid.New(), TenantID: tenant, DeviceID: device,
		WAID: "wa-1", ChatKey: chat, ChatPN: chat, IsGroup: true,
		SenderKey: "42631895773279:5@lid", SenderLID: "42631895773279:5@lid",
		Kind: domain.KindMessage, Type: domain.TypeText,
		Source: domain.SourceHistory, TS: time.Now().Truncate(time.Second),
		ContentKeyID: 1, BodySealed: []byte("oi"),
	})
	if err != nil {
		t.Fatal(err)
	}
	lidMap(t, pool, map[string]string{"42631895773279": "5511971446866"})

	if _, err := store.LinkPhoneNumbers(ctx, pool, tenant); err != nil {
		t.Fatal(err)
	}
	rows, err := m.Page(ctx, tenant, device, []string{chat}, store.Cursor{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if rows[0].SenderPN != "5511971446866@s.whatsapp.net" {
		t.Errorf("sender_pn = %q, want the bare number", rows[0].SenderPN)
	}
}
