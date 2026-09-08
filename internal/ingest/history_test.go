package ingest_test

import (
	"context"
	"testing"
	"time"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/domain"
	"whatserver2/internal/store"
)

// The projection tests. Everything here goes through the real pipeline into a
// real Postgres, so the rows under test are sealed exactly as production's are
// — which matters, because the point being made is that the server assembles
// this structure without ever being able to read a word of it.

func (f *fixture) control(id string, kind domain.Kind, target, body string, ts time.Time) domain.Envelope {
	env := f.envelope(id, kind, domain.TypeText, body)
	env.TargetID = target
	env.Timestamp = ts
	if kind == domain.KindReaction {
		env.Type = domain.TypeReaction
		env.TargetRel = domain.TargetMessage
	}
	return env
}

func (f *fixture) ingest(t *testing.T, env domain.Envelope) {
	t.Helper()
	if _, err := f.pipe.Ingest(context.Background(), env); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) history(t *testing.T, waID string) store.MessageHistory {
	t.Helper()
	h, err := store.NewMessages(f.pool).History(context.Background(),
		f.tenant, f.device, chatJID.String(), waID, store.NewReceipts(f.pool))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func (f *fixture) body(t *testing.T, r store.Row) string {
	t.Helper()
	return string(f.open(t, r.UID, seal.KindBody, r.ContentKeyID, r.BodySealed))
}

// TestEveryVersionOfAnEditedMessageSurvives is the central claim of the
// product, stated as a test.
//
// A normal client keeps the newest text and nothing else. Here the original and
// each revision are separate rows that were never written over, so all three
// come back — in the order they were sent, with the bracket of time each was
// the current one.
func TestEveryVersionOfAnEditedMessageSurvives(t *testing.T) {
	f := newFixture(t)
	t0 := time.Now().Add(-time.Hour).Truncate(time.Second)

	original := f.envelope("M1", domain.KindMessage, domain.TypeText, "vamos as 19h")
	original.Timestamp = t0
	f.ingest(t, original)
	f.ingest(t, f.control("E1", domain.KindEdit, "M1", "vamos as 20h", t0.Add(2*time.Minute)))
	f.ingest(t, f.control("E2", domain.KindEdit, "M1", "vamos as 21h", t0.Add(5*time.Minute)))

	h := f.history(t, "M1")
	if len(h.Versions) != 3 {
		t.Fatalf("got %d versions, want 3", len(h.Versions))
	}
	want := []string{"vamos as 19h", "vamos as 20h", "vamos as 21h"}
	for i, v := range h.Versions {
		if v.Revision != i {
			t.Fatalf("version %d reports revision %d", i, v.Revision)
		}
		if got := f.body(t, v.Row); got != want[i] {
			t.Fatalf("revision %d is %q, want %q", i, got, want[i])
		}
	}

	// Each version stops being current when the next one starts.
	for i := 0; i < len(h.Versions)-1; i++ {
		if h.Versions[i].Until == nil {
			t.Fatalf("revision %d has no end, but revision %d replaced it", i, i+1)
		}
		if !h.Versions[i].Until.Equal(*h.Versions[i+1].From) {
			t.Fatalf("revision %d ends at %v but revision %d starts at %v",
				i, h.Versions[i].Until, i+1, h.Versions[i+1].From)
		}
	}
	if h.Versions[2].Until != nil {
		t.Fatal("the newest revision was given an end time; nothing has replaced it")
	}
}

// TestOrderingUsesTheSequenceNotTheSenderClock.
//
// An edit can arrive carrying a timestamp older than the message it edits — a
// phone with a wrong clock is enough. Ordering by that would present the
// correction as if it came first.
func TestOrderingUsesTheSequenceNotTheSenderClock(t *testing.T) {
	f := newFixture(t)
	now := time.Now().Truncate(time.Second)

	original := f.envelope("M1", domain.KindMessage, domain.TypeText, "primeiro")
	original.Timestamp = now
	f.ingest(t, original)
	// The edit claims to predate the message.
	f.ingest(t, f.control("E1", domain.KindEdit, "M1", "segundo", now.Add(-time.Hour)))

	h := f.history(t, "M1")
	if len(h.Versions) != 2 {
		t.Fatalf("got %d versions, want 2", len(h.Versions))
	}
	if got := f.body(t, h.Versions[0].Row); got != "primeiro" {
		t.Fatalf("revision 0 is %q, want the original: a backwards clock reordered history", got)
	}
}

// TestADeletedMessageKeepsItsText. The revoke is a row beside the message
// rather than the erasure of it.
func TestADeletedMessageKeepsItsText(t *testing.T) {
	f := newFixture(t)
	now := time.Now().Truncate(time.Second)

	original := f.envelope("M1", domain.KindMessage, domain.TypeText, "desculpa, foi mal")
	original.Timestamp = now
	f.ingest(t, original)
	f.ingest(t, f.control("D1", domain.KindDelete, "M1", "", now.Add(time.Minute)))

	h := f.history(t, "M1")
	if h.Deletion == nil {
		t.Fatal("the message was revoked and the history does not say so")
	}
	if got := f.body(t, h.Versions[0].Row); got != "desculpa, foi mal" {
		t.Fatalf("the deleted text came back as %q; a normal client shows nothing here", got)
	}
}

// TestAWithdrawnReactionIsNotADeletedMessage is the v1 bug, in test form.
//
// Removing a reaction produces a revoke whose target is the reaction row, not
// the message. v1 recomputed that relation at render time in two places that
// disagreed, and showed "message deleted" where someone had merely taken back a
// thumbs-up.
func TestAWithdrawnReactionIsNotADeletedMessage(t *testing.T) {
	f := newFixture(t)
	now := time.Now().Truncate(time.Second)

	original := f.envelope("M1", domain.KindMessage, domain.TypeText, "ta combinado")
	original.Timestamp = now
	f.ingest(t, original)
	f.ingest(t, f.control("R1", domain.KindReaction, "M1", "\U0001F44D", now.Add(time.Minute)))
	f.ingest(t, f.control("D1", domain.KindDelete, "R1", "", now.Add(2*time.Minute)))

	h := f.history(t, "M1")
	if h.Deletion != nil {
		t.Fatal("a withdrawn reaction was reported as a deleted message")
	}
	if len(h.Reactions) != 1 {
		t.Fatalf("got %d reactions, want 1", len(h.Reactions))
	}
	if !h.Reactions[0].Revoked {
		t.Fatal("the reaction was revoked and the history does not say so")
	}
	if h.Reactions[0].RevokedAt == nil {
		t.Fatal("the revocation has no time")
	}
}

// TestReplacingAReactionMarksTheOlderOne. WhatsApp allows one reaction per
// party, so a second one supersedes the first — and the first is kept, for the
// same reason edits are.
func TestReplacingAReactionMarksTheOlderOne(t *testing.T) {
	f := newFixture(t)
	now := time.Now().Truncate(time.Second)

	original := f.envelope("M1", domain.KindMessage, domain.TypeText, "olha isso")
	original.Timestamp = now
	f.ingest(t, original)
	f.ingest(t, f.control("R1", domain.KindReaction, "M1", "\U0001F44D", now.Add(time.Minute)))
	f.ingest(t, f.control("R2", domain.KindReaction, "M1", "❤️", now.Add(2*time.Minute)))

	h := f.history(t, "M1")
	if len(h.Reactions) != 2 {
		t.Fatalf("got %d reactions, want 2: the first one is history too", len(h.Reactions))
	}
	if !h.Reactions[0].Superseded {
		t.Fatal("the first reaction was replaced and is not marked as such")
	}
	if h.Reactions[1].Superseded {
		t.Fatal("the newest reaction was marked superseded")
	}
	if got := f.body(t, h.Reactions[0].Row); got != "\U0001F44D" {
		t.Fatalf("the replaced reaction is %q, want the thumbs up", got)
	}
}

// TestAskingAboutAnEditReturnsTheWholeThread. A client holding an edit's uid
// wants the history of the message, not a thread of one row.
func TestAskingAboutAnEditReturnsTheWholeThread(t *testing.T) {
	f := newFixture(t)
	now := time.Now().Truncate(time.Second)

	original := f.envelope("M1", domain.KindMessage, domain.TypeText, "antes")
	original.Timestamp = now
	f.ingest(t, original)
	f.ingest(t, f.control("E1", domain.KindEdit, "M1", "depois", now.Add(time.Minute)))

	h := f.history(t, "E1")
	if h.WAID != "M1" {
		t.Fatalf("root is %q, want M1", h.WAID)
	}
	if len(h.Versions) != 2 {
		t.Fatalf("got %d versions, want 2", len(h.Versions))
	}
}

// TestTheServerAssemblesTheHistoryWithoutReadingIt.
//
// Every body in the projection comes back as ciphertext. The structure — how
// many versions, which was replaced, who deleted what — is built entirely from
// routing columns, and the words only appear after the private key does work
// this process cannot do.
func TestTheServerAssemblesTheHistoryWithoutReadingIt(t *testing.T) {
	f := newFixture(t)
	now := time.Now().Truncate(time.Second)

	original := f.envelope("M1", domain.KindMessage, domain.TypeText, "um segredo")
	original.Timestamp = now
	f.ingest(t, original)
	f.ingest(t, f.control("E1", domain.KindEdit, "M1", "outro segredo", now.Add(time.Minute)))

	h := f.history(t, "M1")
	for i, v := range h.Versions {
		if len(v.Row.BodySealed) == 0 {
			t.Fatalf("revision %d has no sealed body", i)
		}
		for _, secret := range []string{"um segredo", "outro segredo"} {
			if string(v.Row.BodySealed) == secret {
				t.Fatalf("revision %d carries plaintext", i)
			}
		}
	}
}

// TestReadersReportWhichVersionTheySaw ties the receipts to the revisions.
func TestReadersReportWhichVersionTheySaw(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	now := time.Now().Add(-time.Hour).Truncate(time.Second)

	original := f.envelope("M1", domain.KindMessage, domain.TypeText, "as 19h")
	original.Timestamp = now
	f.ingest(t, original)
	f.ingest(t, f.control("E1", domain.KindEdit, "M1", "as 21h", now.Add(5*time.Minute)))

	receipts := store.NewReceipts(f.pool)
	ack := func(kind domain.ReceiptKind, ts time.Time, ids ...string) {
		t.Helper()
		if _, err := receipts.Insert(ctx, store.InsertReceipt{
			TenantID: f.tenant, DeviceID: f.device,
			ChatKey:   chatJID.String(),
			ReaderKey: chatJID.String(),
			WAIDs:     ids, Kind: kind, TS: ts,
		}); err != nil {
			t.Fatal(err)
		}
	}
	// The original arrived; the edit did too, and only then did they read.
	ack(domain.ReceiptDelivered, now.Add(time.Second), "M1")
	ack(domain.ReceiptDelivered, now.Add(6*time.Minute), "E1")
	ack(domain.ReceiptRead, now.Add(10*time.Minute), "M1")

	h := f.history(t, "M1")
	if len(h.Readers) != 1 {
		t.Fatalf("got %d readers, want 1", len(h.Readers))
	}
	r := h.Readers[0]
	if r.SawRevision != 1 || r.ConfirmedRevision != 1 || !r.Confirmed {
		t.Fatalf("got saw=%d confirmed=%d certain=%v, want 1/1/true: their own device "+
			"acknowledged the edit before they read", r.SawRevision, r.ConfirmedRevision, r.Confirmed)
	}
	if r.Read == nil || r.Delivered == nil {
		t.Fatal("the reader has no delivery or read time")
	}
}

// TestAnUnconfirmedEditIsReportedAsInferred: same shape, but nothing says the
// edit ever reached them.
func TestAnUnconfirmedEditIsReportedAsInferred(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	now := time.Now().Add(-time.Hour).Truncate(time.Second)

	original := f.envelope("M1", domain.KindMessage, domain.TypeText, "as 19h")
	original.Timestamp = now
	f.ingest(t, original)
	f.ingest(t, f.control("E1", domain.KindEdit, "M1", "as 21h", now.Add(5*time.Minute)))

	receipts := store.NewReceipts(f.pool)
	if _, err := receipts.Insert(ctx, store.InsertReceipt{
		TenantID: f.tenant, DeviceID: f.device,
		ChatKey: chatJID.String(), ReaderKey: chatJID.String(),
		WAIDs: []string{"M1"}, Kind: domain.ReceiptRead, TS: now.Add(10 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	h := f.history(t, "M1")
	r := h.Readers[0]
	if r.SawRevision != 1 {
		t.Fatalf("saw = %d, want 1: the timestamps do point at the edit", r.SawRevision)
	}
	if r.Confirmed {
		t.Fatal("reported as confirmed; only the clock says they saw the correction")
	}
	if r.ConfirmedRevision != 0 {
		t.Fatalf("confirmed = %d, want 0", r.ConfirmedRevision)
	}
}
