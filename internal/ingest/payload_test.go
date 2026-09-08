package ingest_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/domain"
	"whatserver2/internal/store"
)

// The structured content of a message — a location, a poll, contact cards, an
// event, a link preview, the mention list — is sealed as one value rather than
// spread across readable columns. These tests state both halves of that: it
// survives the round trip, and none of it is legible in the database.

func (f *fixture) structured(id string, typ domain.Type, body string, c domain.Content) domain.Envelope {
	env := f.envelope(id, domain.KindMessage, typ, body)
	c.Body = body
	env.Content = c
	env.Timestamp = time.Now().Truncate(time.Second)
	return env
}

func (f *fixture) payloadOf(t *testing.T, waID string) domain.Payload {
	t.Helper()
	rows, err := store.NewMessages(f.pool).Page(context.Background(),
		f.tenant, f.device, []string{chatJID.String()}, store.Cursor{}, 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.WAID != waID {
			continue
		}
		if len(r.PayloadSealed) == 0 {
			t.Fatalf("%s has no sealed payload", waID)
		}
		pt := f.open(t, r.UID, seal.KindPayload, r.ContentKeyID, r.PayloadSealed)
		pl, err := domain.ParsePayload(pt)
		if err != nil {
			t.Fatal(err)
		}
		return pl
	}
	t.Fatalf("no row with id %s", waID)
	return domain.Payload{}
}

func TestALocationSurvivesTheRoundTrip(t *testing.T) {
	f := newFixture(t)
	f.ingest(t, f.structured("L1", domain.TypeLocation, "aqui", domain.Content{
		Location: &domain.Location{
			Latitude: -23.5613, Longitude: -46.6565,
			Name: "MASP", Address: "Av. Paulista, 1578",
		},
	}))

	pl := f.payloadOf(t, "L1")
	if pl.Location == nil {
		t.Fatal("the location did not survive")
	}
	if pl.Location.Name != "MASP" || pl.Location.Address != "Av. Paulista, 1578" {
		t.Fatalf("location came back as %+v", pl.Location)
	}
	// Floats through JSON are the obvious place for a coordinate to drift.
	if pl.Location.Latitude != -23.5613 || pl.Location.Longitude != -46.6565 {
		t.Fatalf("coordinates drifted: %v, %v", pl.Location.Latitude, pl.Location.Longitude)
	}
}

func TestAPollSurvivesTheRoundTrip(t *testing.T) {
	f := newFixture(t)
	f.ingest(t, f.structured("P1", domain.TypePoll, "Onde vamos?", domain.Content{
		Poll: &domain.Poll{
			Question:        "Onde vamos?",
			Options:         []string{"praia", "serra", "ficar em casa"},
			SelectableCount: 1,
		},
	}))

	pl := f.payloadOf(t, "P1")
	if pl.Poll == nil || len(pl.Poll.Options) != 3 {
		t.Fatalf("poll came back as %+v", pl.Poll)
	}
	if pl.Poll.Options[2] != "ficar em casa" {
		t.Fatalf("options came back as %v", pl.Poll.Options)
	}
}

func TestAnEventKeepsMoreThanItsName(t *testing.T) {
	f := newFixture(t)
	start := time.Date(2026, 9, 1, 19, 0, 0, 0, time.UTC)
	f.ingest(t, f.structured("E1", domain.TypeEvent, "Jantar", domain.Content{
		Event: &domain.Event{
			Name: "Jantar", Description: "traz sobremesa",
			StartTime: start, JoinLink: "https://example.invalid/j",
			Location: &domain.Location{Latitude: -23.5, Longitude: -46.6, Name: "Casa"},
		},
	}))

	pl := f.payloadOf(t, "E1")
	if pl.Event == nil {
		t.Fatal("the event did not survive")
	}
	if !pl.Event.StartTime.Equal(start) {
		t.Fatalf("start time came back as %v, want %v", pl.Event.StartTime, start)
	}
	if pl.Event.Location == nil || pl.Event.Location.Name != "Casa" {
		t.Fatalf("the event location came back as %+v", pl.Event.Location)
	}
	if pl.Event.Description != "traz sobremesa" {
		t.Fatalf("description came back as %q", pl.Event.Description)
	}
}

// TestNoStructuredContentIsLegibleInTheDatabase is the promise, restated for
// the fields that phase 4 added.
//
// A coordinate, a poll option, a phone number on a contact card and a mentioned
// JID are all content. None of them may appear anywhere in the database in a
// form a stolen dump could read.
func TestNoStructuredContentIsLegibleInTheDatabase(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	f.ingest(t, f.structured("S1", domain.TypeContact, "cartao", domain.Content{
		Contacts: []domain.Contact{{
			DisplayName: "Fulano de Tal",
			VCard:       "BEGIN:VCARD\nTEL:+5511987654321\nEND:VCARD",
		}},
		Mentions: []string{"5511911112222@s.whatsapp.net"},
		Location: &domain.Location{Latitude: -23.5613, Longitude: -46.6565, Name: "MASP"},
	}))

	secrets := []string{
		"Fulano de Tal", "5511987654321", "MASP",
		"5511911112222", "-23.5613",
	}
	var tables []string
	if err := withTenant(ctx, f.pool, f.tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT tablename FROM pg_tables WHERE schemaname = current_schema()`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				return err
			}
			tables = append(tables, name)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}

	for _, table := range tables {
		var dump string
		if err := withTenant(ctx, f.pool, f.tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx,
				`SELECT coalesce(string_agg(t::text, ' '), '') FROM `+table+` t`).Scan(&dump)
		}); err != nil {
			// A table the tenant cannot see under RLS is exactly what should
			// happen; nothing to search.
			continue
		}
		for _, secret := range secrets {
			if strings.Contains(dump, secret) {
				t.Fatalf("%q is legible in table %q", secret, table)
			}
		}
	}

	// And it is all recoverable by someone holding the key.
	pl := f.payloadOf(t, "S1")
	if len(pl.Contacts) != 1 || !strings.Contains(pl.Contacts[0].VCard, "5511987654321") {
		t.Fatalf("the contact card did not come back: %+v", pl.Contacts)
	}
	if len(pl.Mentions) != 1 {
		t.Fatalf("mentions came back as %v", pl.Mentions)
	}
}

// TestTheChatTimerIsLearnedFromMessages.
//
// Disappearing messages are a chat setting, and a linked device is not told
// about it directly — it finds out because every message sent into such a chat
// carries the timer. That is also how an outbound message knows what to apply,
// so getting it wrong means sending into a disappearing chat as if it were an
// ordinary one.
func TestTheChatTimerIsLearnedFromMessages(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	messages := store.NewMessages(f.pool)

	env := f.envelope("M1", domain.KindMessage, domain.TypeText, "some em 24h")
	env.Expiration = 86400
	f.ingest(t, env)

	timer, err := messages.ChatTimer(ctx, f.tenant, f.device, chatJID.String())
	if err != nil {
		t.Fatal(err)
	}
	if timer != 86400 {
		t.Fatalf("timer = %d, want 86400", timer)
	}

	// A later message with no expiration says nothing about the setting. It is
	// the ordinary shape of a message, and letting it write zero would clear a
	// live timer the first time one arrived without one.
	f.ingest(t, f.envelope("M2", domain.KindMessage, domain.TypeText, "oi"))
	timer, err = messages.ChatTimer(ctx, f.tenant, f.device, chatJID.String())
	if err != nil {
		t.Fatal(err)
	}
	if timer != 86400 {
		t.Fatalf("timer = %d after a message with no expiration, want it untouched", timer)
	}

	// Turning it off is explicit, and it does clear.
	if err := messages.SetChatTimer(ctx, f.tenant, f.device, chatJID.String(), 0); err != nil {
		t.Fatal(err)
	}
	if timer, err = messages.ChatTimer(ctx, f.tenant, f.device, chatJID.String()); err != nil || timer != 0 {
		t.Fatalf("timer = %d (err %v), want 0", timer, err)
	}
}

// TestAnUnknownChatHasNoTimer. Asking about a chat nothing has arrived in must
// not fail; it just has no answer yet.
func TestAnUnknownChatHasNoTimer(t *testing.T) {
	f := newFixture(t)
	timer, err := store.NewMessages(f.pool).ChatTimer(context.Background(),
		f.tenant, f.device, "5599999999999@s.whatsapp.net")
	if err != nil {
		t.Fatal(err)
	}
	if timer != 0 {
		t.Fatalf("timer = %d, want 0", timer)
	}
}
