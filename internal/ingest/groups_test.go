package ingest_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/ingest"
	"whatserver2/internal/store"
)

// TestJoiningAGroupPutsItInTheSidebar.
//
// Reported from the field: an invitation was accepted, WhatsApp created the
// group on the phone, and nothing appeared in the list. A chats row is written
// by the message path, so a conversation exists here only once somebody speaks
// in it — and a group joined in silence is a group that is not there.
//
// Being ADDED to a group had the same symptom and is far commoner.
func TestJoiningAGroupPutsItInTheSidebar(t *testing.T) {
	f := newFixture(t)
	r := f.router(t)
	ctx := context.Background()
	group := types.JID{User: "120363429965256963", Server: types.GroupServer}

	r.Handle(ctx, f.device.String(), &events.JoinedGroup{
		Reason: "invite",
		GroupInfo: types.GroupInfo{
			JID:       group,
			GroupName: types.GroupName{Name: "Churrasco de sábado"},
		},
	})

	chats, err := store.NewMessages(f.pool).Chats(ctx, f.tenant, f.device, 50)
	if err != nil {
		t.Fatal(err)
	}
	var found *store.ChatRow
	for i := range chats {
		if chats[i].ChatKey == group.String() {
			found = &chats[i]
		}
	}
	if found == nil {
		t.Fatal("the group was joined and never appeared in the chat list")
	}
	if !found.IsGroup {
		t.Error("the conversation was not recorded as a group")
	}

	// And it arrives NAMED. Until this path existed a name came only from a
	// history sync, so a group created after the last one showed as a numeric
	// id — for good, since nothing else ever names a chat.
	if len(found.NameSealed) == 0 {
		t.Fatal("the group has no name; the sidebar will draw its numeric id")
	}
	if got := f.open(t, store.ChatUID(f.device, group.String()),
		seal.KindContactName, found.NameKeyID, found.NameSealed); string(got) != "Churrasco de sábado" {
		t.Errorf("name opened as %q", got)
	}

	// A group's picture hangs on a contacts row, not on the conversation, so
	// without one the avatar worker never reaches it.
	if c := f.contact(t, group.String()); !c.IsGroup {
		t.Error("no identity row for the group, so it can never get a picture")
	}
}

// TestQuietGroupsAreFoundAndNamed.
//
// The two symptoms reported from the field, which turn out to be one cause:
// groups whose name never appeared, and groups joined with no message that were
// not in the sidebar at all.
//
// A conversation row is written by the message path. A group nobody has spoken
// in therefore does not exist here — not nameless, absent. And a name reaches
// the archive from a history sync or from the event that fires when we join, so
// a group that predates the pairing and has been quiet since is reached by
// neither. Nothing in the archive can repair that on its own; it has to be
// asked for.
func TestQuietGroupsAreFoundAndNamed(t *testing.T) {
	f := newFixture(t)
	r := f.router(t)
	ctx := context.Background()

	quiet := types.JID{User: "120363428763643519", Server: types.GroupServer}
	named := types.JID{User: "120363401443932789", Server: types.GroupServer}
	participants := []types.GroupParticipant{{JID: types.NewJID("111", types.HiddenUserServer)}}

	n := r.SyncGroups(ctx, f.tenant, f.device, []*types.GroupInfo{
		{JID: quiet, GroupName: types.GroupName{Name: "Vizinhos"}, Participants: participants},
		{JID: named, GroupName: types.GroupName{Name: "Trabalho"}, Participants: participants},
		nil, // a nil in the list must not take the pass down with it
		{},  // nor an entry with no JID
	})
	if n != 2 {
		t.Fatalf("recorded %d groups, want 2", n)
	}

	chats, err := store.NewMessages(f.pool).Chats(ctx, f.tenant, f.device, 50)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]store.ChatRow{}
	for _, c := range chats {
		seen[c.ChatKey] = c
	}
	for _, want := range []struct {
		jid  types.JID
		name string
	}{{quiet, "Vizinhos"}, {named, "Trabalho"}} {
		c, ok := seen[want.jid.String()]
		if !ok {
			t.Errorf("%s is not in the chat list", want.jid)
			continue
		}
		if !c.IsGroup {
			t.Errorf("%s was not recorded as a group", want.jid)
		}
		if len(c.NameSealed) == 0 {
			t.Errorf("%s has no name; the sidebar draws its numeric id", want.jid)
			continue
		}
		got := f.open(t, store.ChatUID(f.device, want.jid.String()),
			seal.KindContactName, c.NameKeyID, c.NameSealed)
		if string(got) != want.name {
			t.Errorf("%s opened as %q, want %q", want.jid, got, want.name)
		}
	}

	// Idempotent: it runs at every boot.
	if again := r.SyncGroups(ctx, f.tenant, f.device, []*types.GroupInfo{
		{JID: quiet, GroupName: types.GroupName{Name: "Vizinhos"}, Participants: participants},
	}); again != 1 {
		t.Errorf("a second pass recorded %d, want 1", again)
	}
}

func TestGroupSnapshotWithoutAStoreDoesNotReportRefreshed(t *testing.T) {
	f := newFixture(t)
	r, err := ingest.NewRouter(ingest.RouterConfig{
		Lookup: func(string) (ingest.DeviceInfo, bool) { return ingest.DeviceInfo{TenantID: f.tenant}, true },
		Keys:   f.keys, KeyStore: f.keys, Messages: store.NewMessages(f.pool), Log: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	group := &types.GroupInfo{JID: types.NewJID("120363111", types.GroupServer),
		Participants: []types.GroupParticipant{{JID: types.NewJID("111", types.HiddenUserServer)}}}
	if err := r.SnapshotGroup(context.Background(), f.tenant, f.device, group); err == nil {
		t.Fatal("missing store reported a successful composition snapshot")
	}
	if got := r.SyncGroups(context.Background(), f.tenant, f.device, []*types.GroupInfo{group}); got != 0 {
		t.Fatalf("refreshed=%d, want zero without a store", got)
	}
}

func TestPartialGroupSnapshotsPreserveMembersAndTheirHistory(t *testing.T) {
	f := newFixture(t)
	r := f.router(t)
	ctx := context.Background()
	group := types.NewJID("120363111", types.GroupServer)
	participants := []types.GroupParticipant{
		{JID: types.NewJID("111", types.HiddenUserServer), IsAdmin: true},
		{JID: types.NewJID("222", types.HiddenUserServer)},
		{JID: types.NewJID("333", types.HiddenUserServer)},
	}
	complete := &types.GroupInfo{JID: group, ParticipantCount: 3, Participants: participants}
	if got := r.SyncGroups(ctx, f.tenant, f.device, []*types.GroupInfo{complete}); got != 1 {
		t.Fatalf("complete snapshot count=%d, want one", got)
	}
	groups := store.NewGroups(f.pool)
	before, err := groups.Changes(ctx, f.tenant, f.device, group.String(), 20)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		info *types.GroupInfo
	}{
		{"nil", nil},
		{"empty", &types.GroupInfo{JID: group}},
		{"missing participant", &types.GroupInfo{JID: group, ParticipantCount: 3, Participants: participants[:2]}},
		{"failed addition", &types.GroupInfo{JID: group, Participants: []types.GroupParticipant{participants[0], {JID: participants[1].JID, Error: 403}}}},
		{"unknown participant", &types.GroupInfo{JID: group, Participants: []types.GroupParticipant{participants[0], {}}}},
		{"duplicate participant", &types.GroupInfo{JID: group, ParticipantCount: 3, Participants: []types.GroupParticipant{participants[0], participants[1], participants[1]}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := r.SnapshotGroup(ctx, f.tenant, f.device, tc.info); err == nil {
				t.Fatal("partial composition was accepted")
			}
			if got := r.SyncGroups(ctx, f.tenant, f.device, []*types.GroupInfo{tc.info}); got != 0 {
				t.Fatalf("refreshed=%d for a partial composition", got)
			}
			current, err := groups.Participants(ctx, f.tenant, f.device, group.String())
			if err != nil || len(current) != 3 {
				t.Fatalf("members were removed: %+v err=%v", current, err)
			}
			changes, err := groups.Changes(ctx, f.tenant, f.device, group.String(), 20)
			if err != nil || len(changes) != len(before) {
				t.Fatalf("partial data invented membership changes: %+v err=%v", changes, err)
			}
		})
	}
	// A complete smaller composition is a real removal and must still apply.
	if got := r.SyncGroups(ctx, f.tenant, f.device, []*types.GroupInfo{{JID: group, ParticipantCount: 2, Participants: participants[:2]}}); got != 1 {
		t.Fatalf("complete removal snapshot count=%d, want one", got)
	}
	current, err := groups.Participants(ctx, f.tenant, f.device, group.String())
	if err != nil || len(current) != 2 {
		t.Fatalf("complete composition was not persisted: %+v err=%v", current, err)
	}
}

// A group whose name comes back empty must not erase the one already stored.
//
// GetJoinedGroups can answer with a group and no name — a group nobody has
// named, or a field WhatsApp declined to fill — and a boot pass that wrote it
// through would blank a name a history sync had supplied. Nothing in this
// archive replaces a known value with an empty one.
func TestAnEmptyGroupNameDoesNotEraseAStoredOne(t *testing.T) {
	f := newFixture(t)
	r := f.router(t)
	ctx := context.Background()
	group := types.JID{User: "120363401443932789", Server: types.GroupServer}

	r.SyncGroups(ctx, f.tenant, f.device, []*types.GroupInfo{
		{JID: group, GroupName: types.GroupName{Name: "Trabalho"}},
	})
	r.SyncGroups(ctx, f.tenant, f.device, []*types.GroupInfo{{JID: group}})

	chats, _ := store.NewMessages(f.pool).Chats(ctx, f.tenant, f.device, 50)
	for _, c := range chats {
		if c.ChatKey != group.String() {
			continue
		}
		if len(c.NameSealed) == 0 {
			t.Fatal("the stored name was erased by a pass that carried none")
		}
		if got := f.open(t, store.ChatUID(f.device, group.String()),
			seal.KindContactName, c.NameKeyID, c.NameSealed); string(got) != "Trabalho" {
			t.Errorf("name = %q", got)
		}
	}
}

// TestAQuietGroupIsOrderedByWhenItWasMade.
//
// A conversation with no message has nothing to sort by, and the sidebar was
// falling back to when this archive wrote the row. For groups discovered by a
// boot sync that is one instant for all of them, so six hundred conversations
// came back in whatever order the listing happened to produce — which is how a
// group somebody joined last week ends up below one from 2019.
//
// WhatsApp says when each group was made, in the same answer that carries the
// name, so it costs nothing to ask for.
func TestAQuietGroupIsOrderedByWhenItWasMade(t *testing.T) {
	f := newFixture(t)
	r := f.router(t)
	ctx := context.Background()

	old := types.JID{User: "120363000000000001", Server: types.GroupServer}
	recent := types.JID{User: "120363000000000002", Server: types.GroupServer}
	madeLongAgo := time.Date(2019, 3, 1, 12, 0, 0, 0, time.UTC)
	madeLastWeek := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)

	// Recorded in the order that would give the wrong answer if the row's own
	// timestamp decided it: the ancient group is written last.
	r.SyncGroups(ctx, f.tenant, f.device, []*types.GroupInfo{
		{JID: recent, GroupName: types.GroupName{Name: "Recente"}, GroupCreated: madeLastWeek},
		{JID: old, GroupName: types.GroupName{Name: "Antigo"}, GroupCreated: madeLongAgo},
	})

	chats, err := store.NewMessages(f.pool).Chats(ctx, f.tenant, f.device, 50)
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, c := range chats {
		if c.ChatKey == old.String() || c.ChatKey == recent.String() {
			order = append(order, c.ChatKey)
		}
	}
	if len(order) != 2 {
		t.Fatalf("found %d of the two groups", len(order))
	}
	if order[0] != recent.String() {
		t.Errorf("order = %v; the group made last week must come before the one from 2019", order)
	}
}

// A pass that comes back without a creation time must not blank the one stored.
//
// WhatsApp supplies it when it feels like it. A boot sync that answered without
// one would otherwise reset the ordering key of every quiet conversation to
// null, and they would all collapse back into a single undifferentiated block —
// the exact state this replaced.
func TestAMissingCreationTimeDoesNotEraseAStoredOne(t *testing.T) {
	f := newFixture(t)
	r := f.router(t)
	ctx := context.Background()
	group := types.JID{User: "120363000000000003", Server: types.GroupServer}
	made := time.Date(2020, 5, 4, 9, 0, 0, 0, time.UTC)

	r.SyncGroups(ctx, f.tenant, f.device, []*types.GroupInfo{
		{JID: group, GroupName: types.GroupName{Name: "G"}, GroupCreated: made},
	})
	r.SyncGroups(ctx, f.tenant, f.device, []*types.GroupInfo{
		{JID: group, GroupName: types.GroupName{Name: "G"}},
	})

	chats, _ := store.NewMessages(f.pool).Chats(ctx, f.tenant, f.device, 50)
	for _, c := range chats {
		if c.ChatKey != group.String() {
			continue
		}
		if c.GroupCreatedAt == nil || !c.GroupCreatedAt.Equal(made) {
			t.Errorf("groupCreatedAt = %v, want the stored %v — a pass with no "+
				"creation time erased the ordering key", c.GroupCreatedAt, made)
		}
	}
}

// Who removed whom, which is the question the history table exists for.
//
// It is answerable only from the moment this archive started listening —
// WhatsApp delivers a group's current composition and its live changes, never
// its past — so the recording has to be right when it happens. There is no
// second chance and no way to reconstruct it later.
func TestAGroupChangeRecordsWhoDidIt(t *testing.T) {
	f := newFixture(t)
	r := f.router(t)
	ctx := context.Background()
	groups := store.NewGroups(f.pool)
	group := types.JID{User: "120363000000000000", Server: types.GroupServer}
	admin := types.JID{User: "5511900000000", Server: types.DefaultUserServer}
	victim := types.JID{User: "5511911112222", Server: types.DefaultUserServer}
	at := time.Now().Truncate(time.Second)

	r.Handle(ctx, f.device.String(), &events.GroupInfo{
		JID: group, Timestamp: at, Sender: &admin,
		Leave: []types.JID{victim},
	})

	history, err := groups.Changes(ctx, f.tenant, f.device, group.String(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 {
		t.Fatalf("history = %d rows, want 1", len(history))
	}
	c := history[0]
	if c.Action != store.ChangeRemove {
		t.Errorf("action = %q, want remove", c.Action)
	}
	if c.ActorKey != admin.String() {
		t.Errorf("actor = %q, want %q — 'who removed them' is the whole point",
			c.ActorKey, admin)
	}
	if c.SubjectKey != victim.String() {
		t.Errorf("subject = %q, want %q", c.SubjectKey, victim)
	}
}

// A change WhatsApp gives no author for is recorded with none.
//
// It often does not say, for a join through an invite link. Attributing it to
// somebody would be the archive inventing a fact about a person, which is the
// one thing it must never do.
func TestAChangeWithNoAuthorIsNotAttributed(t *testing.T) {
	f := newFixture(t)
	r := f.router(t)
	ctx := context.Background()
	groups := store.NewGroups(f.pool)
	group := types.JID{User: "120363000000000001", Server: types.GroupServer}
	joiner := types.JID{User: "5511911112222", Server: types.DefaultUserServer}

	r.Handle(ctx, f.device.String(), &events.GroupInfo{
		JID: group, Timestamp: time.Now().Truncate(time.Second),
		JoinReason: "invite", Join: []types.JID{joiner},
	})

	history, _ := groups.Changes(ctx, f.tenant, f.device, group.String(), 10)
	if len(history) != 1 {
		t.Fatalf("history = %d rows, want 1", len(history))
	}
	if history[0].ActorKey != "" {
		t.Errorf("actor = %q, want empty — WhatsApp did not say who",
			history[0].ActorKey)
	}
	// And the person is in the group now.
	members, _ := groups.Participants(ctx, f.tenant, f.device, group.String())
	if len(members) != 1 || members[0].Key != joiner.String() {
		t.Errorf("participants = %+v, want the person who joined", members)
	}
}
