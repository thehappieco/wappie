package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/domain"
	"whatserver2/internal/pg"
	"whatserver2/internal/store"
)

const unreadChat = "5511999999999@s.whatsapp.net"

// arrive inserts one message with everything the badge rule looks at spelled
// out, because every one of those fields is a way for the count to be wrong.
func arrive(t *testing.T, m *store.Messages, tenant, device uuid.UUID,
	waID string, in store.InsertMessage) store.InsertResult {
	t.Helper()
	in.UID, in.TenantID, in.DeviceID, in.WAID = uuid.New(), tenant, device, waID
	if in.ChatKey == "" {
		in.ChatKey = unreadChat
	}
	if in.Kind == "" {
		in.Kind = domain.KindMessage
	}
	if in.Type == "" {
		in.Type = domain.TypeText
	}
	if in.Source == "" {
		in.Source = domain.SourceLive
	}
	if in.TS.IsZero() {
		in.TS = time.Now().Truncate(time.Second)
	}
	in.ContentKeyID, in.BodySealed = 1, []byte("selado")
	res, err := m.Insert(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// TestARedeliveredMessageDoesNotCountTwice is the trap this whole placement is
// arranged around.
//
// History sync redelivers what has already been seen, in bulk, and the event
// stream is at-least-once — so the duplicate path is the hot path, not the edge
// case. The increment lives inside upsertChat precisely because Insert returns
// before reaching it on both duplicate paths. Move it to an Exec of its own and
// it sits one refactor above that return, at which point a re-pair adds
// thousands to a badge and nothing anywhere reports a problem.
func TestARedeliveredMessageDoesNotCountTwice(t *testing.T) {
	m, tenant, device := chatFixture(t)

	first := arrive(t, m, tenant, device, "A1", store.InsertMessage{})
	if !first.CountsUnread || first.Unread != 1 {
		t.Fatalf("first arrival: counts=%v unread=%d, want true/1", first.CountsUnread, first.Unread)
	}

	again := arrive(t, m, tenant, device, "A1", store.InsertMessage{})
	if !again.Duplicate {
		t.Fatal("the second insert was not recognised as a duplicate")
	}
	if got := chatFor(t, m, tenant, device, unreadChat).Unread; got != 1 {
		t.Errorf("unread = %d after a redelivery, want 1", got)
	}
}

// TestAHistorySyncDoesNotAddToItsOwnCount.
//
// storeChatMeta writes the phone's absolute count and runs BEFORE the messages
// of that conversation are ingested (internal/ingest/history.go). So a
// bootstrap that reports three unread would, with an unconditional increment,
// go on to add one per backfilled message — nineteen thousand of them on the
// archive this was written against. The badge would be catastrophically wrong
// and would look merely large.
func TestAHistorySyncDoesNotAddToItsOwnCount(t *testing.T) {
	m, tenant, device := chatFixture(t)

	for _, id := range []string{"H1", "H2", "H3"} {
		res := arrive(t, m, tenant, device, id, store.InsertMessage{Source: domain.SourceHistory})
		if res.CountsUnread {
			t.Fatalf("%s: a backfilled message counted towards the badge", id)
		}
	}
	if got := chatFor(t, m, tenant, device, unreadChat).Unread; got != 0 {
		t.Errorf("unread = %d after a history sync, want 0 — the sync writes its own count", got)
	}
}

// TestOnlyRealIncomingMessagesCount.
//
// Each exclusion here is a badge that would promise something new to read and
// deliver something else: our own message, somebody's thumbs-up, an edit of a
// line already on screen, a poll vote, or a status post — which is not a
// conversation at all but one pseudo-chat holding dozens of unrelated people.
func TestOnlyRealIncomingMessagesCount(t *testing.T) {
	m, tenant, device := chatFixture(t)

	for _, c := range []struct {
		name string
		in   store.InsertMessage
	}{
		{"nossa própria mensagem", store.InsertMessage{IsFromMe: true}},
		{"uma reação", store.InsertMessage{Kind: domain.KindReaction, Type: domain.TypeReaction}},
		{"uma edição", store.InsertMessage{Kind: domain.KindEdit}},
		{"uma exclusão", store.InsertMessage{Kind: domain.KindDelete}},
		{"um voto de enquete", store.InsertMessage{Type: domain.TypePollVote}},
		{"um status", store.InsertMessage{ChatKey: "status@broadcast"}},
	} {
		res := arrive(t, m, tenant, device, "X"+c.name, c.in)
		if res.CountsUnread {
			t.Errorf("%s contou para o badge", c.name)
		}
	}

	if got := chatFor(t, m, tenant, device, unreadChat).Unread; got != 0 {
		t.Errorf("unread = %d, want 0", got)
	}
}

// TestAskingForOlderHistoryDoesNotRelightTheBadge.
//
// An on-demand backfill fills in what came BEFORE the oldest message stored, so
// it writes rows the reader has demonstrably passed. Counting them would make
// asking for older history light up a badge for messages read months ago — the
// archive punishing you for reading it.
//
// What does the protecting is worth being exact about, because the obvious
// answer is wrong. It is NOT the read watermark: a backfilled row is old by
// timestamp and brand new by sequence — sequence is insertion order, which is
// the whole reason conversations are ordered by time instead — so it lands
// comfortably above any watermark. It is counts_unread excluding
// source='history', and a backfill arrives as an ON_DEMAND history sync.
//
// This test was written asserting the watermark did it, and failed. Keeping the
// scenario and correcting the mechanism, because the next person will have the
// same wrong intuition.
func TestAskingForOlderHistoryDoesNotRelightTheBadge(t *testing.T) {
	m, tenant, device, pool := chatFixtureWithPool(t)
	ctx := context.Background()
	unread := store.NewUnread(pool)

	live := arrive(t, m, tenant, device, "N1", store.InsertMessage{})
	if live.Unread != 1 {
		t.Fatalf("unread = %d, want 1", live.Unread)
	}
	// The reader catches up to here.
	if err := unread.MarkChatReadAt(ctx, tenant, device, unreadChat, nil); err != nil {
		t.Fatal(err)
	}
	if got := chatFor(t, m, tenant, device, unreadChat).Unread; got != 0 {
		t.Fatalf("unread = %d after catching up, want 0", got)
	}

	// A backfill lands: older by timestamp, higher by sequence, exactly as one
	// really arrives.
	back := arrive(t, m, tenant, device, "N0", store.InsertMessage{
		Source: domain.SourceHistory,
		TS:     time.Now().Add(-72 * time.Hour).Truncate(time.Second),
	})
	if back.Seq <= live.Seq {
		t.Fatalf("backfill seq %d is not above the live one %d — the scenario this "+
			"test exists for did not happen", back.Seq, live.Seq)
	}
	if got := chatFor(t, m, tenant, device, unreadChat).Unread; got != 0 {
		t.Errorf("unread = %d after asking for older history, want 0", got)
	}
}

// TestTheBadgeNeverDriftsFromTheRowsUnderIt.
//
// The badge and the watermark are two columns that have to keep agreeing with a
// third thing — the messages actually above the watermark. Clearing recounts
// rather than decrements precisely so that agreement is restored on every pass,
// however many times each clearing path has already run.
//
// The failure this guards is permanent rather than transient. Under READ
// COMMITTED an UPDATE that blocks on a row lock re-evaluates its SET
// expressions against the new row version, but a subquery inside them keeps the
// original statement snapshot — so a recount racing an arrival can write a
// number that was already stale, and every later increment builds on the wrong
// base. It looks like a badge that is quietly one short, forever, which nobody
// reports as a bug.
//
// Convergence, not a proof of the snapshot semantics: interleaving them
// deterministically is not possible through this API, because an insert needs
// the same chat row lock the recount does. What it does establish is the
// invariant that matters, under -race, with the two contending for real.
func TestTheBadgeNeverDriftsFromTheRowsUnderIt(t *testing.T) {
	m, tenant, device, pool := chatFixtureWithPool(t)
	ctx := context.Background()
	unread := store.NewUnread(pool)

	for round := range 12 {
		done := make(chan struct{})
		go func() {
			defer close(done)
			if err := unread.MarkChatReadAt(ctx, tenant, device, unreadChat, nil); err != nil {
				t.Error(err)
			}
		}()
		arrive(t, m, tenant, device, "R"+string(rune('a'+round)), store.InsertMessage{})
		<-done
	}

	// One quiet arrival after the contention, so the expected state is not
	// zero. Asserting agreement on an empty badge is agreement between two
	// zeros: the first version of this test did exactly that and passed with
	// the recount deliberately broken.
	arrive(t, m, tenant, device, "FINAL", store.InsertMessage{})

	// The badge must equal what is genuinely above the watermark. Anything else
	// is drift, and drift here never corrects itself.
	var above int32
	var watermark int64
	badge, err := unread.Count(ctx, tenant, device, unreadChat)
	if err != nil {
		t.Fatal(err)
	}
	if err := pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT read_through_seq FROM chats
			 WHERE device_id = $1 AND chat_key = $2`, device, unreadChat).Scan(&watermark); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM messages
			 WHERE device_id = $1 AND chat_key = $2 AND counts_unread AND seq > $3`,
			device, unreadChat, watermark).Scan(&above)
	}); err != nil {
		t.Fatal(err)
	}
	if badge == 0 {
		t.Fatal("the badge is zero after a quiet arrival, so this assertion is comparing " +
			"two zeros and would pass against a broken recount")
	}
	if badge != above {
		t.Errorf("badge = %d but %d messages sit above the watermark (seq %d) — "+
			"the count has drifted from the rows and will not recover",
			badge, above, watermark)
	}
}

// TestClearingPartOfAConversationLeavesTheRest exercises the recount itself.
//
// Reading is by POSITION: acknowledging a message clears everything at or below
// it and leaves what came after. That is what WhatsApp does, and it is what
// makes the badge mean "how much is left at the end of this conversation"
// rather than "how many individual rows remain unticked".
//
// It is also the only shape in which a broken recount is visible. Clear a whole
// conversation and the answer is zero, which a recount that counts nothing also
// produces; the increment on the next arrival then rebuilds a plausible number
// from the wrong base. Two of the three tests written before this one passed
// against a recount deliberately sabotaged to return zero.
func TestClearingPartOfAConversationLeavesTheRest(t *testing.T) {
	m, tenant, device, pool := chatFixtureWithPool(t)
	ctx := context.Background()
	unread := store.NewUnread(pool)

	for _, id := range []string{"P1", "P2", "P3", "P4"} {
		arrive(t, m, tenant, device, id, store.InsertMessage{})
	}
	if got, _ := unread.Count(ctx, tenant, device, unreadChat); got != 4 {
		t.Fatalf("unread = %d after four arrivals, want 4", got)
	}

	// Acknowledge the second. Everything at or below it goes; P3 and P4 stay.
	if err := unread.MarkReadThrough(ctx, tenant, device, []string{"P2"}); err != nil {
		t.Fatal(err)
	}
	got, err := unread.Count(ctx, tenant, device, unreadChat)
	if err != nil {
		t.Fatal(err)
	}
	if got != 2 {
		t.Fatalf("unread = %d after acknowledging the second of four, want 2", got)
	}

	// Idempotent: the same acknowledgement again changes nothing. Receipts are
	// resent on every resync, so this is the ordinary case.
	if err := unread.MarkReadThrough(ctx, tenant, device, []string{"P2"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := unread.Count(ctx, tenant, device, unreadChat); got != 2 {
		t.Errorf("unread = %d after a repeated acknowledgement, want 2", got)
	}

	// And going backwards does not resurrect anything: acknowledging an older
	// message than the watermark already covers must not raise the count.
	if err := unread.MarkReadThrough(ctx, tenant, device, []string{"P1"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := unread.Count(ctx, tenant, device, unreadChat); got != 2 {
		t.Errorf("unread = %d after acknowledging an older message, want 2", got)
	}
}

// TestTheMigrationLeavesNoStaleBadge.
//
// 0012 wrote the watermark and left the count beside it as the history sync had
// last reported it — so every conversation kept a frozen number with nothing
// behind it. On the archive this was written against: 305 badges totalling
// 14,865, and 302 of them with nothing above their watermark at all.
//
// The failure is invisible from inside the code. Both columns exist, both have
// plausible values, and the only way to see the disagreement is to count the
// rows. 0013 recounts; this asserts that a freshly migrated database has no
// conversation whose badge disagrees with what is under it.
func TestTheMigrationLeavesNoStaleBadge(t *testing.T) {
	m, tenant, device, pool := chatFixtureWithPool(t)
	ctx := context.Background()

	// A conversation with a badge and messages under it, in the shape the old
	// history-sync path produced: an absolute count written from outside.
	for _, id := range []string{"S1", "S2"} {
		arrive(t, m, tenant, device, id, store.InsertMessage{})
	}
	if err := pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE chats SET unread = 99, read_through_seq = (
				SELECT max(seq) FROM messages
				 WHERE device_id = $1 AND chat_key = $2)
			 WHERE device_id = $1 AND chat_key = $2`, device, unreadChat)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	var disagreeing int
	if err := pg.InTenantTx(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT count(*) FROM chats c
			 WHERE c.unread <> (
			     SELECT count(*) FROM messages m
			      WHERE m.device_id = c.device_id AND m.chat_key = c.chat_key
			        AND m.counts_unread AND m.seq > c.read_through_seq)`).Scan(&disagreeing)
	}); err != nil {
		t.Fatal(err)
	}
	if disagreeing == 0 {
		t.Fatal("the fixture did not reproduce a stale badge, so this proves nothing")
	}

	// The recount is what 0013 does, and what every clearing path does.
	if err := store.NewUnread(pool).MarkChatReadAt(ctx, tenant, device, unreadChat, nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := store.NewUnread(pool).Count(ctx, tenant, device, unreadChat); got != 0 {
		t.Errorf("unread = %d after a recount, want 0 — nothing sits above the watermark", got)
	}
}

// TestTheTimerReachesEveryRowOfOneConversation.
//
// A person can hold two chat rows — a LID one and a phone-number one — and the
// sidebar folds them into one conversation, advertising whichever key carries
// the name. The timer is one fact about that one conversation, and writing it
// to only the row the caller happened to name left the other half disagreeing:
// the fold takes the first non-zero, so a timer turned OFF on one row was
// resurrected from the other and the setting appeared to revert on its own.
func TestTheTimerReachesEveryRowOfOneConversation(t *testing.T) {
	m, tenant, device := chatFixture(t)
	ctx := context.Background()

	const lid = "224437861388494@lid"
	const pn = "5511999999999@s.whatsapp.net"

	// Two rows for one person, joined by the phone number, as siblings are.
	for _, key := range []string{lid, pn} {
		if err := m.UpsertChatMeta(ctx, store.ChatMeta{
			TenantID: tenant, DeviceID: device, ChatKey: key, ChatPN: pn,
		}); err != nil {
			t.Fatal(err)
		}
	}

	if err := m.SetChatTimer(ctx, tenant, device, lid, 86400); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{lid, pn} {
		got, err := m.ChatTimer(ctx, tenant, device, key)
		if err != nil {
			t.Fatal(err)
		}
		if got != 86400 {
			t.Errorf("timer read through %s = %d, want 86400 — half the "+
				"conversation does not know", key, got)
		}
	}

	// And turning it off has to reach both, or the fold puts it back.
	if err := m.SetChatTimer(ctx, tenant, device, pn, 0); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{lid, pn} {
		got, err := m.ChatTimer(ctx, tenant, device, key)
		if err != nil {
			t.Fatal(err)
		}
		if got != 0 {
			t.Errorf("timer read through %s = %d after being turned off; the "+
				"sidebar will resurrect it from the sibling", key, got)
		}
	}
}

// TestAnOutboundMessageSeesATimerLearnedOnTheOtherHalf.
//
// The worse half of the same defect, and invisible from the screen. Live
// traffic lands on whichever row WhatsApp addressed, so a timer can be learned
// on the row that is NOT the advertised one. A single-row read by the
// advertised key then answers zero, the message goes out without the
// disappearing envelope, and the composer has meanwhile been promising the
// reader "como a conversa: 24 horas".
func TestAnOutboundMessageSeesATimerLearnedOnTheOtherHalf(t *testing.T) {
	m, tenant, device := chatFixture(t)
	ctx := context.Background()

	const lid = "224437861388494@lid"
	const pn = "5511999999999@s.whatsapp.net"

	for _, key := range []string{lid, pn} {
		if err := m.UpsertChatMeta(ctx, store.ChatMeta{
			TenantID: tenant, DeviceID: device, ChatKey: key, ChatPN: pn,
		}); err != nil {
			t.Fatal(err)
		}
	}
	// A message arrives addressed to the LID half, carrying the timer.
	arrive(t, m, tenant, device, "E1", store.InsertMessage{
		ChatKey: lid, Expiration: 604800,
	})

	got, err := m.ChatTimer(ctx, tenant, device, pn)
	if err != nil {
		t.Fatal(err)
	}
	if got != 604800 {
		t.Fatalf("timer through the advertised key = %d, want 604800. An "+
			"outbound message would leave without the envelope, into a chat "+
			"the composer is calling temporary.", got)
	}
}
