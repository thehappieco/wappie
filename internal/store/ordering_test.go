package store_test

import (
	"context"
	"testing"
	"time"

	"whatserver2/internal/domain"
	"whatserver2/internal/store"
)

// A conversation is ordered by when a message was sent, not by when it was
// stored, and the difference is not academic.
//
// seq is the tenant's insertion counter, so history sync writes last year's
// messages with today's numbers — and WhatsApp delivers each chunk
// newest-first, so within a backfill the numbers run opposite to the clock.
// Ordering by seq showed 17498 out-of-order adjacent pairs in a real archive:
// the history upside down, dropped into the middle of today.
//
// The failure is silent. Every message is there, every timestamp is right, and
// the conversation simply does not read like one.

func TestAConversationReadsInTheOrderItWasSent(t *testing.T) {
	m, tenant, device := chatFixture(t)
	ctx := context.Background()
	const chat = "5511999999999@s.whatsapp.net"

	now := time.Now().Truncate(time.Second)
	// Live first, so it takes the lowest sequence numbers.
	insert(t, m, tenant, device, chat, "live-1", domain.KindMessage, now.Add(-2*time.Minute), "hoje cedo")
	insert(t, m, tenant, device, chat, "live-2", domain.KindMessage, now, "agora")

	// Then a backfill of much older messages, delivered newest-first the way
	// WhatsApp sends them, taking the highest sequence numbers.
	year := now.AddDate(-1, 0, 0)
	insert(t, m, tenant, device, chat, "old-3", domain.KindMessage, year.Add(3*time.Hour), "ano passado, tarde")
	insert(t, m, tenant, device, chat, "old-2", domain.KindMessage, year.Add(2*time.Hour), "ano passado, meio")
	insert(t, m, tenant, device, chat, "old-1", domain.KindMessage, year.Add(time.Hour), "ano passado, cedo")

	rows, err := m.Page(ctx, tenant, device, []string{chat}, store.Cursor{}, 50)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(rows))
	for _, r := range rows {
		got = append(got, r.WAID)
	}
	want := []string{"old-1", "old-2", "old-3", "live-1", "live-2"}
	if len(got) != len(want) {
		t.Fatalf("page has %d rows, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

func TestPagingBackwardsDoesNotSkipOrRepeat(t *testing.T) {
	m, tenant, device := chatFixture(t)
	ctx := context.Background()
	const chat = "5511999999999@s.whatsapp.net"

	// Every message in the same second, which is the case the cursor exists
	// for: WhatsApp timestamps are whole seconds and a burst inside one is
	// ordinary. A cursor on time alone would either lose the rest of the second
	// or serve it again forever.
	at := time.Now().Truncate(time.Second)
	const total = 10
	for i := range total {
		insert(t, m, tenant, device, chat, "burst-"+string(rune('a'+i)),
			domain.KindMessage, at, "x")
	}

	seen := map[string]int{}
	cursor := store.Cursor{}
	for range 5 {
		rows, err := m.Page(ctx, tenant, device, []string{chat}, cursor, 3)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) == 0 {
			break
		}
		for _, r := range rows {
			seen[r.WAID]++
		}
		cursor = store.Before(rows)
	}

	if len(seen) != total {
		t.Errorf("saw %d distinct messages across the pages, want %d", len(seen), total)
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("%s appeared %d times", id, n)
		}
	}
}

func TestABackfillDoesNotMoveAChatToTheTop(t *testing.T) {
	m, tenant, device := chatFixture(t)
	ctx := context.Background()

	now := time.Now().Truncate(time.Second)
	insert(t, m, tenant, device, "quiet@s.whatsapp.net", "q1",
		domain.KindMessage, now.AddDate(-1, 0, 0), "ano passado")
	insert(t, m, tenant, device, "busy@s.whatsapp.net", "b1",
		domain.KindMessage, now, "agora")

	// A backfill arrives for the quiet conversation. It is old traffic, so the
	// sidebar must not treat it as activity — but it takes the newest sequence
	// numbers, which is exactly what the old ordering keyed on.
	insert(t, m, tenant, device, "quiet@s.whatsapp.net", "q2",
		domain.KindMessage, now.AddDate(-1, 0, 0).Add(time.Hour), "ano passado também")

	chats, err := m.Chats(ctx, tenant, device, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(chats) < 2 {
		t.Fatalf("expected two chats, got %d", len(chats))
	}
	if chats[0].ChatKey != "busy@s.whatsapp.net" {
		t.Errorf("first chat is %s; a backfill of old messages floated a quiet "+
			"conversation above one with a message from today", chats[0].ChatKey)
	}

	// And the quiet chat's own "latest" must be its newest message by time,
	// not whichever row happened to be written last.
	quiet := chatFor(t, m, tenant, device, "quiet@s.whatsapp.net")
	if quiet.LastTS == nil {
		t.Fatal("the chat has no last_ts")
	}
	if want := now.AddDate(-1, 0, 0).Add(time.Hour); !quiet.LastTS.Equal(want) {
		t.Errorf("last_ts = %s, want %s", quiet.LastTS, want)
	}
}
