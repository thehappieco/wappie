package membership

import (
	"context"
	"slices"
	"testing"

	"github.com/google/uuid"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/store"
)

// TB36: the owner's strand override (the plan's DB13), observing in a
// team the platform names, as the platform takes it. A disable and a
// removal each strand a deleted number whose last key holder the target
// was; each item.stranded is rendered with the target's sub as person and
// the act's cause, the owner as actor, and the target among its readers,
// and is accepted. The other owner gets a number_stranded notice for each;
// the acting owner gets none.
func TestStrandedEvent(t *testing.T) {
	w := newEventWorld(t)
	ctx := context.Background()
	coOwner, _, _ := w.heldAtHome(t)
	removed, removedSub, _ := w.heldAtHome(t)
	w.localTeam(t, w.team, "", member{coOwner, "owner", "active"}, member{removed, "member", "active"})
	devices := store.NewDevices(w.pool)
	disabledNumber := w.number(t, w.team, "Suporte", 2, w.second)
	removedNumber := w.number(t, w.team, "Compras", 3, removed)
	for device, reader := range map[uuid.UUID]uuid.UUID{disabledNumber: w.second, removedNumber: removed} {
		if _, err := devices.Quarantine(ctx, w.team, w.owner, device, []uuid.UUID{reader}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.users.UpdateMemberStrandDeleted(ctx, w.team, w.owner, w.second, "member", "disabled"); err != nil {
		t.Fatalf("the disable: %v", err)
	}
	if err := w.users.RemoveMemberStrandDeleted(ctx, w.team, w.owner, removed); err != nil {
		t.Fatalf("the removal: %v", err)
	}

	s := w.sender(t, w.members, w.logs)
	flush(t, s, w.team)
	stranded := map[string]kc.Event{}
	for _, ev := range w.sentTo(w.team) {
		if ev.Type == kc.EventStranded {
			stranded[ev.Item.ID] = ev
		}
	}
	if len(stranded) != 2 {
		t.Fatalf("%d item.stranded sent, want two: %+v", len(stranded), w.sentTo(w.team))
	}
	for device, want := range map[uuid.UUID]struct {
		person uuid.UUID
		cause  string
		label  string
	}{disabledNumber: {w.secondSub, "disabled", "Suporte"}, removedNumber: {removedSub, "revoked", "Compras"}} {
		ev, ok := stranded[device.String()]
		if !ok {
			t.Fatalf("no item.stranded for %s", device)
		}
		if ev.Person == nil || *ev.Person != want.person.String() || ev.Cause == nil || *ev.Cause != want.cause ||
			ev.Actor == nil || *ev.Actor != w.sub.String() || ev.ActorKind != kc.ActorPerson || ev.Item.Kind != "number" ||
			ev.Item.Label == nil || *ev.Item.Label != want.label || ev.Item.Hint == nil || ev.PurgeAt != nil || ev.To != nil {
			t.Fatalf("the %s stranding: %+v", want.cause, ev)
		}
		if ev.Readers == nil || !slices.Equal(*ev.Readers, []string{want.person.String()}) {
			t.Fatalf("the %s stranding's readers: %v", want.cause, ev.Readers)
		}
		if err := ev.Validate(); err != nil {
			t.Fatalf("the %s stranding: %v", want.cause, err)
		}
	}
	for _, device := range []uuid.UUID{disabledNumber, removedNumber} {
		id := uuid.MustParse(stranded[device.String()].EventID)
		if d := w.delivery(t, w.team, id); !d.settled || d.outcome != "accepted" {
			t.Fatalf("the stranding of %s: %+v", device, d)
		}
	}

	notices := func(user uuid.UUID) []store.DeviceNotice {
		t.Helper()
		var out []store.DeviceNotice
		all, err := devices.Notices(ctx, w.team, user)
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range all {
			if n.Kind == store.NoticeNumberStranded {
				out = append(out, n)
			}
		}
		return out
	}
	got := notices(coOwner)
	if len(got) != 2 {
		t.Fatalf("the other owner's notices: %+v", got)
	}
	for _, n := range got {
		if n.DeviceID != disabledNumber && n.DeviceID != removedNumber || n.Until == nil || n.RaisedByKind != "person" {
			t.Fatalf("a notice: %+v", n)
		}
	}
	if got := notices(w.owner); len(got) != 0 {
		t.Fatalf("the acting owner was told: %+v", got)
	}
}
