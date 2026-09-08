package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

const groupChat = "120363000000000000@g.us"

func groupFixture(t *testing.T) (*store.Groups, uuid.UUID, uuid.UUID, *pgxpool.Pool) {
	t.Helper()
	pool := pgtest.Fresh(t, migrate.Run)
	tenantID := newTenant(t, pool, "acme")
	dev, err := store.NewDevices(pool).Create(context.Background(), tenantID, "test", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	return store.NewGroups(pool), uuid.MustParse(tenantID), uuid.MustParse(dev.ID), pool
}

func member(key string, admin bool) store.Participant {
	return store.Participant{Key: key, LID: key, IsAdmin: admin}
}

// The first snapshot is a marker, not a hundred arrivals.
//
// A group this archive has just looked at for the first time did not form at
// that moment. Writing an "add" per member would say it did, and the history —
// whose whole purpose is to record what happened — would open with a fiction.
func TestTheFirstSnapshotIsNotAHundredArrivals(t *testing.T) {
	g, tenant, device, _ := groupFixture(t)
	ctx := context.Background()

	changes, err := g.Snapshot(ctx, tenant, device, groupChat, []store.Participant{
		member("1@lid", true), member("2@lid", false), member("3@lid", false),
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if changes != 0 {
		t.Errorf("the first snapshot wrote %d membership changes, want none", changes)
	}

	members, err := g.Participants(ctx, tenant, device, groupChat)
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 3 {
		t.Fatalf("participants = %d, want 3", len(members))
	}
	// Admins first, so a panel does not have to sort what the query can.
	if !members[0].IsAdmin {
		t.Error("admins are not listed first")
	}

	// A marker, so the panel can say when the record begins rather than
	// presenting an empty history as a peaceful one.
	history, err := g.Changes(ctx, tenant, device, groupChat, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 || history[0].Action != store.ChangeSnapshot {
		t.Errorf("history = %+v, want one snapshot marker", history)
	}
}

// An empty answer is not everybody leaving.
//
// A snapshot with nobody in it is a request that failed, or a group this
// account was removed from, or an answer WhatsApp declined to give. Diffing
// against it writes a "removed" for every member, with no author and a
// timestamp of now — and the table whose entire purpose is to say what happened
// would be saying something that did not.
func TestAnEmptySnapshotIsNotEverybodyLeaving(t *testing.T) {
	g, tenant, device, _ := groupFixture(t)
	ctx := context.Background()

	if _, err := g.Snapshot(ctx, tenant, device, groupChat, []store.Participant{
		member("1@lid", true), member("2@lid", false),
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Snapshot(ctx, tenant, device, groupChat, nil, time.Now()); err != nil {
		t.Fatal(err)
	}

	members, _ := g.Participants(ctx, tenant, device, groupChat)
	if len(members) != 2 {
		t.Errorf("participants = %d after an empty answer, want both still there", len(members))
	}
	history, _ := g.Changes(ctx, tenant, device, groupChat, 10)
	for _, c := range history {
		if c.Action == store.ChangeRemove {
			t.Fatal("an empty answer was recorded as somebody being removed")
		}
	}
}

// The second snapshot is where the history actually starts.
func TestASnapshotRecordsWhatChangedSinceTheLast(t *testing.T) {
	g, tenant, device, _ := groupFixture(t)
	ctx := context.Background()

	if _, err := g.Snapshot(ctx, tenant, device, groupChat, []store.Participant{
		member("1@lid", true), member("2@lid", false), member("3@lid", false),
	}, time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}

	// 3 left, 4 arrived, 2 became an admin.
	n, err := g.Snapshot(ctx, tenant, device, groupChat, []store.Participant{
		member("1@lid", true), member("2@lid", true), member("4@lid", false),
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("recorded %d changes, want 3 (one arrival, one promotion, one departure)", n)
	}

	seen := map[string]string{}
	history, _ := g.Changes(ctx, tenant, device, groupChat, 20)
	for _, c := range history {
		if c.SubjectKey != "" {
			seen[c.SubjectKey] = c.Action
		}
	}
	if seen["4@lid"] != store.ChangeAdd {
		t.Errorf("4@lid = %q, want add", seen["4@lid"])
	}
	if seen["3@lid"] != store.ChangeRemove {
		t.Errorf("3@lid = %q, want remove", seen["3@lid"])
	}
	if seen["2@lid"] != store.ChangePromote {
		t.Errorf("2@lid = %q, want promote", seen["2@lid"])
	}
}

// A redelivered event is one fact, not two.
//
// WhatsApp resends group events on every resync. The same removal recorded
// twice reads as two removals of one person, in a table whose entire purpose is
// to say what happened.
func TestARedeliveredChangeIsRecordedOnce(t *testing.T) {
	g, tenant, device, _ := groupFixture(t)
	ctx := context.Background()
	at := time.Now().Truncate(time.Second)

	c := store.GroupChange{
		TS: at, Action: store.ChangeRemove,
		ActorKey: "9@lid", SubjectKey: "3@lid",
	}
	for range 3 {
		if err := g.Record(ctx, tenant, device, groupChat, c); err != nil {
			t.Fatal(err)
		}
	}
	history, _ := g.Changes(ctx, tenant, device, groupChat, 10)
	if len(history) != 1 {
		t.Fatalf("history has %d rows for one removal delivered three times", len(history))
	}
	// And it says who did it, which is the question the table exists for.
	if history[0].ActorKey != "9@lid" {
		t.Errorf("actor = %q, want the person who removed them", history[0].ActorKey)
	}
}
