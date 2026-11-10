package store_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/google/uuid"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/store"
)

// The console's flags kinds (step 12b's F1; the plan's 5.1, DS18 to DS24):
// the target before the role, a raise against the stored flags as a set,
// a drop that takes only what it names, a remove that keeps an all-false
// row, the key's last reader kept, deleted numbers under the quarantine
// scope, and the snapshot after each.

var (
	canR   = []string{kc.CanRead}
	canRS  = []string{kc.CanRead, kc.CanSend}
	canRSM = []string{kc.CanRead, kc.CanSend, kc.CanManage}
)

// stored is user's stored row on device, as Wappie's screen reads it.
func (w *actWorld) stored(t *testing.T, device, user uuid.UUID) store.DevicePermission {
	t.Helper()
	p, err := w.users.StoredDevicePermission(context.Background(), w.tenant, user, device)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// grantsOf counts user's grants on device, at every epoch, a deleted
// number's included.
func (w *actWorld) grantsOf(t *testing.T, device, user uuid.UUID) int {
	t.Helper()
	return w.count(t, `SELECT count(*) FROM device_key_grants WHERE device_id = $1 AND user_id = $2`, device, user)
}

// epochKey gives device an archive key at epoch, its current one now.
func (w *actWorld) epochKey(t *testing.T, device uuid.UUID, epoch uint16) {
	t.Helper()
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := w.keys.CreateArchiveKey(context.Background(), w.tenant, device, epoch, pub); err != nil {
		t.Fatal(err)
	}
}

// grantAt gives user device's key at epoch.
func (w *actWorld) grantAt(t *testing.T, device, user uuid.UUID, epoch uint16) {
	t.Helper()
	if err := w.keys.PutGrant(context.Background(), store.Grant{TenantID: w.tenant, DeviceID: device, UserID: user, Epoch: epoch,
		SealedDSK: []byte("grant")}, &w.owner); err != nil {
		t.Fatal(err)
	}
}

// set gives user these flags on device through Wappie's own screen.
func (w *actWorld) set(t *testing.T, device, user uuid.UUID, read, send, manage bool) {
	t.Helper()
	if err := w.users.SetDevicePermission(context.Background(), w.tenant, w.owner, store.DevicePermission{DeviceID: device, UserID: user,
		Read: read, Send: send, Manage: manage}); err != nil {
		t.Fatal(err)
	}
}

// lineOf is sub's line on device in the snapshot, and whether the snapshot
// lists sub as protected there.
func (w *actWorld) lineOf(t *testing.T, device, sub uuid.UUID) (store.ContractSnapshotPerson, bool, bool) {
	t.Helper()
	snap, err := w.c.Snapshot(context.Background(), w.tenant)
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range snap.Items {
		if it.ID != device {
			continue
		}
		protected := slices.Contains(it.Protected, sub)
		for _, p := range it.People {
			if p.Sub == sub {
				return p, true, protected
			}
		}
		return store.ContractSnapshotPerson{}, false, protected
	}
	t.Fatalf("%s is not in the snapshot", device)
	return store.ContractSnapshotPerson{}, false, false
}

// foreignNumbers are a live number of another workspace, and a deleted
// one.
func (w *actWorld) foreignNumbers(t *testing.T) (live, deleted uuid.UUID) {
	t.Helper()
	other := uuid.MustParse(newTenant(t, w.pool, "other"))
	w.pns++
	live = linkedNumber(t, w.pool, other, "Theirs", fmt.Sprintf("55218%04d5678", w.pns), fmt.Sprintf("2000000%08d", w.pns))
	w.pns++
	deleted = linkedNumber(t, w.pool, other, "Theirs gone", fmt.Sprintf("55218%04d5678", w.pns), fmt.Sprintf("2000000%08d", w.pns))
	excludeNumber(t, w.pool, other, deleted)
	return live, deleted
}

func sameStored(p store.DevicePermission, read, send, manage bool) bool {
	return p.Read == read && p.Send == send && p.Manage == manage
}

// shownAt checks an act's ran: at its seq, the numbers section and the
// snapshot due now.
func (w *actWorld) shownAt(t *testing.T, what string, run store.ContractRun, act store.ContractAct, err error) {
	t.Helper()
	ranAct(t, what, act, err)
	sections, _, numbersDue, snapshotDue := w.clock(t)
	if l := w.ledger(t, run.ID); l.outcome != "ran" || l.seq == nil || *l.seq != act.Seq || act.Seq != sections {
		t.Fatalf("%s: the ledger %+v, the act's seq %d, the clock %d", what, l, act.Seq, sections)
	}
	if numbersDue > 0 || snapshotDue > 0 {
		t.Fatalf("%s: the numbers section is due in %v, the snapshot in %v", what, numbersDue, snapshotDue)
	}
	w.later(t)
}

// TestRunFlagsRaise: a raise writes after over a before that matches the
// stored flags as a set, never touches a grant, and refuses in order: the
// number (gone or another workspace's not_found, this workspace's deleted
// state_changed), the person (not_found), the role (not_authorized, local
// and document both), then before (state_changed). Params the kit refuses
// write nothing.
func TestRunFlagsRaise(t *testing.T) {
	ctx := context.Background()
	w := newActWorld(t)
	admin, adminSub := w.actor(t, "admin", "admin")
	target, _ := w.actor(t, "member", "member")
	device := w.number(t, "Vendas")
	w.reads(t, w.owner, device)
	w.reads(t, target, device)
	w.later(t)

	cmd := w.command(t, kc.OpItemFlagsRaise, admin, adminSub)
	act, wrote, err := w.c.RunFlagsRaise(ctx, cmd, device, target, canR, canRS)
	w.shownAt(t, "a raise of send", cmd, act, err)
	if !wrote || !sameStored(w.stored(t, device, target), true, true, false) || w.grantsOf(t, device, target) != 1 {
		t.Fatalf("after a raise of send: wrote %v, %+v, %d grants", wrote, w.stored(t, device, target), w.grantsOf(t, device, target))
	}
	// Once answered, never again.
	if _, _, err := w.c.RunFlagsRaise(ctx, cmd, device, target, canR, canRS); !errors.Is(err, store.ErrCommandFinished) {
		t.Fatalf("a second run of an answered raise: %v", err)
	}
	// before in another order than stored still matches.
	cmd = w.command(t, kc.OpItemFlagsRaise, admin, adminSub)
	act, wrote, err = w.c.RunFlagsRaise(ctx, cmd, device, target, []string{kc.CanSend, kc.CanRead}, []string{kc.CanManage, kc.CanRead, kc.CanSend})
	w.shownAt(t, "a raise of manage", cmd, act, err)
	if !wrote || !sameStored(w.stored(t, device, target), true, true, true) {
		t.Fatalf("after a raise of manage: %+v", w.stored(t, device, target))
	}
	// A before that is not the stored flags: state_changed, nothing written.
	w.set(t, device, target, true, false, false)
	act, wrote, err = w.c.RunFlagsRaise(ctx, w.command(t, kc.OpItemFlagsRaise, admin, adminSub), device, target, canRS, canRSM)
	refusedWith(t, "a stale before", act, err, kc.CodeStateChanged)
	if wrote || !sameStored(w.stored(t, device, target), true, false, false) {
		t.Fatalf("a stale before wrote: %+v", w.stored(t, device, target))
	}
	// A raise for oneself.
	w.reads(t, admin, device)
	act, _, err = w.c.RunFlagsRaise(ctx, w.command(t, kc.OpItemFlagsRaise, admin, adminSub), device, admin, canR, []string{kc.CanRead, kc.CanManage})
	ranAct(t, "a raise for oneself", act, err)

	// A key holder without Read: a raise of send keeps the key.
	dormant, _ := w.actor(t, "member", "member")
	w.reads(t, dormant, device)
	w.set(t, device, dormant, false, false, false)
	w.grantAt(t, device, dormant, 1)
	if !sameStored(w.stored(t, device, dormant), false, false, false) || w.grantsOf(t, device, dormant) != 1 {
		t.Fatalf("the dormant holder: %+v, %d grants", w.stored(t, device, dormant), w.grantsOf(t, device, dormant))
	}
	act, _, err = w.c.RunFlagsRaise(ctx, w.command(t, kc.OpItemFlagsRaise, admin, adminSub), device, dormant, []string{}, []string{kc.CanSend})
	ranAct(t, "a dormant holder's raise of send", act, err)
	if !sameStored(w.stored(t, device, dormant), false, true, false) || w.grantsOf(t, device, dormant) != 1 {
		t.Fatalf("a raise touched the key: %+v, %d grants", w.stored(t, device, dormant), w.grantsOf(t, device, dormant))
	}

	// The number: gone, another workspace's (live or deleted), this
	// workspace's deleted.
	live, theirsDeleted := w.foreignNumbers(t)
	for what, d := range map[string]uuid.UUID{"a number gone": uuid.New(), "another workspace's": live, "another workspace's deleted": theirsDeleted} {
		act, _, err := w.c.RunFlagsRaise(ctx, w.command(t, kc.OpItemFlagsRaise, admin, adminSub), d, target, canR, canRS)
		refusedWith(t, what, act, err, kc.CodeNotFound)
	}
	gone := w.number(t, "Gone")
	w.reads(t, w.owner, gone)
	w.reads(t, target, gone)
	w.quarantine(t, gone, target)
	act, _, err = w.c.RunFlagsRaise(ctx, w.command(t, kc.OpItemFlagsRaise, admin, adminSub), gone, target, canR, canRS)
	refusedWith(t, "this workspace's deleted number", act, err, kc.CodeStateChanged)

	// The person: none here, or suspended.
	stranger := uuid.MustParse(newTenant(t, w.pool, "elsewhere"))
	act, _, err = w.c.RunFlagsRaise(ctx, w.command(t, kc.OpItemFlagsRaise, admin, adminSub), device, stranger, canR, canRS)
	refusedWith(t, "a person with no membership", act, err, kc.CodeNotFound)
	suspended, _ := w.actor(t, "member", "member")
	w.reads(t, suspended, device)
	if err := w.users.UpdateMember(ctx, w.tenant, w.owner, suspended, "member", "disabled"); err != nil {
		t.Fatal(err)
	}
	act, _, err = w.c.RunFlagsRaise(ctx, w.command(t, kc.OpItemFlagsRaise, admin, adminSub), device, suspended, canR, canRS)
	refusedWith(t, "a suspended member", act, err, kc.CodeNotFound)

	// The role, both sides (DS15, DS18).
	for _, roles := range [][2]string{{"admin", "member"}, {"member", "admin"}, {"member", "member"}} {
		user, sub := w.actor(t, roles[0], roles[1])
		act, _, err := w.c.RunFlagsRaise(ctx, w.command(t, kc.OpItemFlagsRaise, user, sub), device, target, []string{kc.CanRead}, canRS)
		refusedWith(t, "a raise by "+roles[0]+"/"+roles[1], act, err, kc.CodeNotAuthorized)
	}
	ownerUser, ownerSub := w.actor(t, "owner", "owner")
	act, _, err = w.c.RunFlagsRaise(ctx, w.command(t, kc.OpItemFlagsRaise, ownerUser, ownerSub), device, target, canR, canRS)
	ranAct(t, "a raise by an owner", act, err)

	// What the kit refuses at take writes nothing, not even a result.
	for what, change := range map[string][2][]string{
		"read added":     {{kc.CanSend}, {kc.CanSend, kc.CanRead}},
		"nothing added":  {canRS, canRS},
		"a flag dropped": {canRS, {kc.CanRead, kc.CanManage}},
		"a mailbox flag": {canR, {kc.CanRead, kc.CanAct}},
		"a flag twice":   {canR, {kc.CanRead, kc.CanSend, kc.CanSend}},
	} {
		cmd := w.command(t, kc.OpItemFlagsRaise, admin, adminSub)
		if _, wrote, err := w.c.RunFlagsRaise(ctx, cmd, device, target, change[0], change[1]); !errors.Is(err, store.ErrInvalidFlags) || wrote {
			t.Fatalf("%s: %v", what, err)
		}
		if l := w.ledger(t, cmd.ID); l.outcome != "" {
			t.Fatalf("%s wrote a result: %+v", what, l)
		}
	}
}

// TestRunFlagsDrop: a drop takes from the stored flags only what before
// has and after has not, so a flag raised since stays; dropping read
// deletes every grant at every epoch, a dormant one too, unless the person
// is the last reader; it runs on a deleted number of the workspace, and on
// a suspended person; a person with no membership row is ran.
func TestRunFlagsDrop(t *testing.T) {
	ctx := context.Background()
	w := newActWorld(t)
	admin, adminSub := w.actor(t, "admin", "admin")
	target, _ := w.actor(t, "member", "member")
	device := w.number(t, "Vendas")
	w.reads(t, w.owner, device)
	w.reads(t, target, device)
	w.later(t)
	drop := func(device, user uuid.UUID, before, after []string) (store.ContractRun, store.ContractAct, bool, error) {
		cmd := w.command(t, kc.OpItemFlagsDrop, admin, adminSub) //nolint:contextcheck // the world's helpers run on a context of their own
		act, wrote, err := w.c.RunFlagsDrop(ctx, cmd, device, user, before, after)
		return cmd, act, wrote, err
	}

	// Send alone: the grants stay. A manage raised after the page was
	// drawn stays too.
	w.set(t, device, target, true, true, true)
	cmd, act, wrote, err := drop(device, target, canRS, canR)
	w.shownAt(t, "a drop of send", cmd, act, err)
	if !wrote || !sameStored(w.stored(t, device, target), true, false, true) || w.grantsOf(t, device, target) != 1 {
		t.Fatalf("after a drop of send: %+v, %d grants", w.stored(t, device, target), w.grantsOf(t, device, target))
	}
	// A flag already gone: ran, nothing written.
	version := w.accessVersion(t, target)
	_, act, wrote, err = drop(device, target, canRS, canR)
	ranAct(t, "a drop of a flag already gone", act, err)
	if wrote || w.accessVersion(t, target) != version || !sameStored(w.stored(t, device, target), true, false, true) {
		t.Fatalf("a drop of nothing wrote: %v %+v", wrote, w.stored(t, device, target))
	}
	// Read: every grant goes, at every epoch, and access_version moves.
	w.epochKey(t, device, 2)
	w.grantAt(t, device, target, 2)
	w.grantAt(t, device, w.owner, 2)
	if w.grantsOf(t, device, target) != 2 {
		t.Fatalf("the target holds %d grants", w.grantsOf(t, device, target))
	}
	cmd, act, wrote, err = drop(device, target, []string{kc.CanRead, kc.CanManage}, []string{kc.CanManage})
	w.shownAt(t, "a drop of read", cmd, act, err)
	if !wrote || !sameStored(w.stored(t, device, target), false, false, true) || w.grantsOf(t, device, target) != 0 ||
		w.accessVersion(t, target) == version {
		t.Fatalf("after a drop of read: %+v, %d grants", w.stored(t, device, target), w.grantsOf(t, device, target))
	}
	// A dormant key, with read already gone, goes with a drop of read.
	w.grantAt(t, device, target, 2)
	_, act, wrote, err = drop(device, target, []string{kc.CanRead, kc.CanManage}, []string{kc.CanManage})
	ranAct(t, "a drop of read already gone", act, err)
	if !wrote || w.grantsOf(t, device, target) != 0 || !sameStored(w.stored(t, device, target), false, false, true) {
		t.Fatalf("the dormant key stayed: %d grants, %+v", w.grantsOf(t, device, target), w.stored(t, device, target))
	}

	// The last reader: last_reader, nothing changed, on a live number and
	// on a deleted one (0044). The reader is the workspace's owner, so an
	// owner asks (an admin may not change an owner's flags, Q58).
	solo, soloGone := w.number(t, "Solo"), w.number(t, "Solo gone")
	w.reads(t, w.owner, solo)
	w.reads(t, w.owner, soloGone)
	w.quarantine(t, soloGone)
	owner, ownerSub := w.actor(t, "owner", "owner")
	for what, d := range map[string]uuid.UUID{"live": solo, "deleted": soloGone} {
		act, wrote, err := w.c.RunFlagsDrop(ctx, w.command(t, kc.OpItemFlagsDrop, owner, ownerSub), d, w.owner, canR, []string{})
		refusedWith(t, "the last reader of a "+what+" number", act, err, kc.CodeLastReader)
		if wrote || w.grantsOf(t, d, w.owner) != 1 || !sameStored(w.stored(t, d, w.owner), true, false, false) {
			t.Fatalf("the last reader of a %s number lost something", what)
		}
	}

	// This workspace's deleted number, under quarantine: ran.
	gone := w.number(t, "Gone")
	w.reads(t, w.owner, gone)
	w.reads(t, target, gone)
	w.quarantine(t, gone, target)
	_, act, wrote, err = drop(gone, target, canR, []string{})
	ranAct(t, "a drop on this workspace's deleted number", act, err)
	if !wrote || w.grantsOf(t, gone, target) != 0 || !sameStored(w.stored(t, gone, target), false, false, false) || !w.excluded(t, gone) {
		t.Fatalf("a deleted number's drop: %d grants, %+v", w.grantsOf(t, gone, target), w.stored(t, gone, target))
	}
	// Another workspace's numbers, deleted or not, and a number gone.
	live, theirsDeleted := w.foreignNumbers(t)
	for what, d := range map[string]uuid.UUID{"a number gone": uuid.New(), "another workspace's": live, "another workspace's deleted": theirsDeleted} {
		_, act, _, err := drop(d, target, canR, []string{})
		refusedWith(t, what, act, err, kc.CodeNotFound)
	}

	// A suspended membership, and a suspended account: their flags and
	// grants go all the same.
	for _, how := range []string{"membership", "account"} {
		person, _ := w.actor(t, "member", "member")
		w.reads(t, person, device)
		w.set(t, device, person, true, true, false)
		if how == "membership" {
			if err := w.users.UpdateMember(ctx, w.tenant, w.owner, person, "member", "disabled"); err != nil {
				t.Fatal(err)
			}
		} else {
			w.disableAccount(t, person)
		}
		_, act, wrote, err := drop(device, person, canRS, []string{})
		ranAct(t, "a drop for a suspended "+how, act, err)
		if !wrote || w.grantsOf(t, device, person) != 0 || !sameStored(w.stored(t, device, person), false, false, false) {
			t.Fatalf("a suspended %s kept %d grants, %+v", how, w.grantsOf(t, device, person), w.stored(t, device, person))
		}
	}
	// No membership row at all: nothing to take.
	removed, _ := w.actor(t, "member", "member")
	if err := w.users.RemoveMember(ctx, w.tenant, w.owner, removed); err != nil {
		t.Fatal(err)
	}
	_, act, wrote, err = drop(device, removed, canR, []string{})
	ranAct(t, "a drop for a person with no membership", act, err)
	if wrote {
		t.Fatal("a drop for a person with no membership wrote")
	}

	// The role comes before a ran: a member's drop of nobody is refused.
	member, memberSub := w.actor(t, "member", "member")
	act, _, err = w.c.RunFlagsDrop(ctx, w.command(t, kc.OpItemFlagsDrop, member, memberSub), device, removed, canR, []string{})
	refusedWith(t, "a member's drop", act, err, kc.CodeNotAuthorized)
	localOnly, localOnlySub := w.actor(t, "admin", "member")
	act, _, err = w.c.RunFlagsDrop(ctx, w.command(t, kc.OpItemFlagsDrop, localOnly, localOnlySub), device, target, []string{kc.CanManage}, []string{})
	refusedWith(t, "an admin whose document says member", act, err, kc.CodeNotAuthorized)

	for what, change := range map[string][2][]string{
		"a flag added": {canR, {kc.CanSend}},
		"nothing":      {canR, canR},
		"unknown":      {{"act"}, {}},
	} {
		if _, _, wrote, err := drop(device, target, change[0], change[1]); !errors.Is(err, store.ErrInvalidFlags) || wrote {
			t.Fatalf("%s: %v", what, err)
		}
	}
}

// TestRunAccessRemove: every flag false with the row kept, so a later key
// share gives no read or send, and every grant gone, a key holder's
// without Read too, unless they are the last reader; on a deleted number
// of the workspace too.
func TestRunAccessRemove(t *testing.T) {
	ctx := context.Background()
	w := newActWorld(t)
	admin, adminSub := w.actor(t, "admin", "admin")
	target, _ := w.actor(t, "member", "member")
	device := w.number(t, "Vendas")
	w.reads(t, w.owner, device)
	w.reads(t, target, device)
	w.set(t, device, target, true, true, true)
	w.later(t)
	remove := func(device, user uuid.UUID) (store.ContractRun, store.ContractAct, bool, error) {
		cmd := w.command(t, kc.OpItemAccessRemove, admin, adminSub) //nolint:contextcheck // the world's helpers run on a context of their own
		act, wrote, err := w.c.RunAccessRemove(ctx, cmd, device, user)
		return cmd, act, wrote, err
	}

	cmd, act, wrote, err := remove(device, target)
	w.shownAt(t, "a remove", cmd, act, err)
	if !wrote || w.grantsOf(t, device, target) != 0 || !sameStored(w.stored(t, device, target), false, false, false) ||
		w.count(t, `SELECT count(*) FROM device_permissions WHERE device_id = $1 AND user_id = $2`, device, target) != 1 {
		t.Fatalf("after a remove: %d grants, %+v", w.grantsOf(t, device, target), w.stored(t, device, target))
	}
	// The all-false row stays: a key shared again gives no read or send.
	w.grantAt(t, device, target, 1)
	if p := w.stored(t, device, target); !sameStored(p, false, false, false) || !p.HasKey {
		t.Fatalf("a key shared after a remove: %+v", p)
	}
	// A key holder without Read is removed too.
	_, act, wrote, err = remove(device, target)
	ranAct(t, "a remove of a key holder without read", act, err)
	if !wrote || w.grantsOf(t, device, target) != 0 {
		t.Fatalf("the key holder kept %d grants", w.grantsOf(t, device, target))
	}
	// Nothing held: ran.
	nobody, _ := w.actor(t, "member", "member")
	_, act, _, err = remove(device, nobody)
	ranAct(t, "a remove of someone holding nothing", act, err)
	// The last reader, the workspace's owner: an owner asks (Q58).
	solo := w.number(t, "Solo")
	w.reads(t, w.owner, solo)
	owner, ownerSub := w.actor(t, "owner", "owner")
	act, wrote, err = w.c.RunAccessRemove(ctx, w.command(t, kc.OpItemAccessRemove, owner, ownerSub), solo, w.owner)
	refusedWith(t, "the last reader", act, err, kc.CodeLastReader)
	if wrote || w.grantsOf(t, solo, w.owner) != 1 || !sameStored(w.stored(t, solo, w.owner), true, false, false) {
		t.Fatal("the last reader lost something")
	}
	// This workspace's deleted number.
	gone := w.number(t, "Gone")
	w.reads(t, w.owner, gone)
	w.reads(t, target, gone)
	w.quarantine(t, gone, target)
	_, act, wrote, err = remove(gone, target)
	ranAct(t, "a remove on a deleted number", act, err)
	if !wrote || w.grantsOf(t, gone, target) != 0 || !sameStored(w.stored(t, gone, target), false, false, false) {
		t.Fatalf("a deleted number's remove: %d grants", w.grantsOf(t, gone, target))
	}
	// No membership row.
	removed, _ := w.actor(t, "member", "member")
	if err := w.users.RemoveMember(ctx, w.tenant, w.owner, removed); err != nil {
		t.Fatal(err)
	}
	_, act, wrote, err = remove(device, removed)
	ranAct(t, "a remove of a person with no membership", act, err)
	if wrote {
		t.Fatal("a remove of a person with no membership wrote")
	}
	member, memberSub := w.actor(t, "member", "member")
	act, _, err = w.c.RunAccessRemove(ctx, w.command(t, kc.OpItemAccessRemove, member, memberSub), device, nobody)
	refusedWith(t, "a member's remove", act, err, kc.CodeNotAuthorized)
}

// TestFlagsActsSnapshot: the target's line in the snapshot after each
// act (can, reads, waiting, holds_key), and who it protects.
func TestFlagsActsSnapshot(t *testing.T) {
	ctx := context.Background()
	w := newActWorld(t)
	admin, adminSub := w.actor(t, "admin", "admin")
	target, targetSub := w.actor(t, "member", "member")
	ownerSub := linkSub(t, w.pool, w.owner)
	device := w.number(t, "Vendas")
	w.reads(t, w.owner, device)
	w.reads(t, target, device)
	line := func(want store.ContractSnapshotPerson, wantOwnerProtected bool) {
		t.Helper()
		got, listed, protected := w.lineOf(t, device, targetSub)
		want.Sub = targetSub
		if !listed || got != want || protected {
			t.Fatalf("the target's line: %+v (listed %v, protected %v), want %+v", got, listed, protected, want)
		}
		if _, _, owner := w.lineOf(t, device, ownerSub); owner != wantOwnerProtected {
			t.Fatalf("the owner protected: %v, want %v", owner, wantOwnerProtected)
		}
	}
	line(store.ContractSnapshotPerson{Read: true, Reads: true, HoldsKey: true}, false)

	act, _, err := w.c.RunFlagsRaise(ctx, w.command(t, kc.OpItemFlagsRaise, admin, adminSub), device, target, canR, canRS)
	ranAct(t, "a raise", act, err)
	line(store.ContractSnapshotPerson{Read: true, Send: true, Reads: true, HoldsKey: true}, false)

	act, _, err = w.c.RunFlagsDrop(ctx, w.command(t, kc.OpItemFlagsDrop, admin, adminSub), device, target, canRS, []string{kc.CanSend})
	ranAct(t, "a drop of read", act, err)
	line(store.ContractSnapshotPerson{Send: true}, true)

	act, _, err = w.c.RunAccessRemove(ctx, w.command(t, kc.OpItemAccessRemove, admin, adminSub), device, target)
	ranAct(t, "a remove", act, err)
	line(store.ContractSnapshotPerson{}, true)

	// Read without the key is waiting; a raise keeps it so.
	w.set(t, device, target, true, false, false)
	line(store.ContractSnapshotPerson{Read: true, Waiting: true}, true)
	act, _, err = w.c.RunFlagsRaise(ctx, w.command(t, kc.OpItemFlagsRaise, admin, adminSub), device, target, canR,
		[]string{kc.CanRead, kc.CanManage})
	ranAct(t, "a raise for someone waiting", act, err)
	line(store.ContractSnapshotPerson{Read: true, Manage: true, Waiting: true}, true)
}

// TestStoredFlags: R4's read of a flags target, in the kit's order, with
// the key at any epoch not retired, a deleted number's too; another
// workspace's number has none.
func TestStoredFlags(t *testing.T) {
	ctx := context.Background()
	w := newActWorld(t)
	target, _ := w.actor(t, "member", "member")
	device := w.number(t, "Vendas")
	w.reads(t, w.owner, device)
	w.reads(t, target, device)
	w.set(t, device, target, true, true, true)
	can, key, err := w.c.StoredFlags(ctx, w.tenant, device, target)
	if err != nil || !slices.Equal(can, canRSM) || !key {
		t.Fatalf("the stored flags: %v %v %v", can, key, err)
	}
	w.set(t, device, target, false, true, false)
	can, key, err = w.c.StoredFlags(ctx, w.tenant, device, target)
	if err != nil || !slices.Equal(can, []string{kc.CanSend}) || key {
		t.Fatalf("after read went: %v %v %v", can, key, err)
	}
	gone := w.number(t, "Gone")
	w.reads(t, w.owner, gone)
	w.reads(t, target, gone)
	w.quarantine(t, gone, target)
	can, key, err = w.c.StoredFlags(ctx, w.tenant, gone, target)
	if err != nil || !slices.Equal(can, canR) || !key {
		t.Fatalf("a deleted number's: %v %v %v", can, key, err)
	}
	live, _ := w.foreignNumbers(t)
	can, key, err = w.c.StoredFlags(ctx, w.tenant, live, target)
	if err != nil || len(can) != 0 || key {
		t.Fatalf("another workspace's number: %v %v %v", can, key, err)
	}
}

// TestFlagsOwnerTarget (the owner's answer to the platform's Q58): only an
// owner, on both sides, changes an owner's flags. An admin's raise, drop
// and remove of an owner (local, or named owner by their document alone)
// are not_authorized with nothing written, an admin whose document says
// owner included; an owner's run. Wappie's own screen refuses the admin
// the same way (ErrOwnerTarget, a 403 not_authorized), and lets the owner.
func TestFlagsOwnerTarget(t *testing.T) {
	ctx := context.Background()
	w := newActWorld(t)
	admin, adminSub := w.actor(t, "admin", "admin")
	halfOwner, halfOwnerSub := w.actor(t, "admin", "owner")
	owner, ownerSub := w.actor(t, "owner", "owner")
	localOwner, _ := w.actor(t, "owner", "owner")
	docOwner, _ := w.actor(t, "admin", "owner")
	device := w.number(t, "Vendas")
	w.reads(t, w.owner, device)
	for _, u := range []uuid.UUID{localOwner, docOwner} {
		w.reads(t, u, device)
		w.set(t, device, u, true, false, false)
	}
	w.later(t)

	for name, target := range map[string]uuid.UUID{"a local owner": localOwner, "an owner by the document": docOwner} {
		for who, by := range map[string][2]uuid.UUID{"an admin": {admin, adminSub}, "an admin the document calls owner": {halfOwner, halfOwnerSub}} {
			what := who + " on " + name
			act, wrote, err := w.c.RunFlagsRaise(ctx, w.command(t, kc.OpItemFlagsRaise, by[0], by[1]), device, target, canR, canRS)
			refusedWith(t, what+": a raise", act, err, kc.CodeNotAuthorized)
			if wrote {
				t.Fatalf("%s: the raise wrote", what)
			}
			act, wrote, err = w.c.RunFlagsDrop(ctx, w.command(t, kc.OpItemFlagsDrop, by[0], by[1]), device, target, canR, []string{})
			refusedWith(t, what+": a drop", act, err, kc.CodeNotAuthorized)
			if wrote {
				t.Fatalf("%s: the drop wrote", what)
			}
			act, wrote, err = w.c.RunAccessRemove(ctx, w.command(t, kc.OpItemAccessRemove, by[0], by[1]), device, target)
			refusedWith(t, what+": a remove", act, err, kc.CodeNotAuthorized)
			if wrote {
				t.Fatalf("%s: the remove wrote", what)
			}
			if p := w.stored(t, device, target); !sameStored(p, true, false, false) || w.grantsOf(t, device, target) != 1 {
				t.Fatalf("%s: %+v, %d grants", what, p, w.grantsOf(t, device, target))
			}
			err = w.users.SetDevicePermission(ctx, w.tenant, by[0], store.DevicePermission{DeviceID: device, UserID: target, Read: true, Send: true})
			if !errors.Is(err, store.ErrOwnerTarget) || !errors.Is(err, store.ErrMembershipForbidden) {
				t.Fatalf("%s: the screen: %v", what, err)
			}
		}
		// An owner runs all three.
		act, _, err := w.c.RunFlagsRaise(ctx, w.command(t, kc.OpItemFlagsRaise, owner, ownerSub), device, target, canR, canRS)
		ranAct(t, "an owner's raise on "+name, act, err)
		act, _, err = w.c.RunFlagsDrop(ctx, w.command(t, kc.OpItemFlagsDrop, owner, ownerSub), device, target, canRS, canR)
		ranAct(t, "an owner's drop on "+name, act, err)
		act, _, err = w.c.RunAccessRemove(ctx, w.command(t, kc.OpItemAccessRemove, owner, ownerSub), device, target)
		ranAct(t, "an owner's remove on "+name, act, err)
		if p := w.stored(t, device, target); !sameStored(p, false, false, false) || w.grantsOf(t, device, target) != 0 {
			t.Fatalf("after an owner's remove on %s: %+v", name, p)
		}
		if err := w.users.SetDevicePermission(ctx, w.tenant, owner, store.DevicePermission{DeviceID: device, UserID: target, Send: true}); err != nil {
			t.Fatalf("the screen, by an owner on %s: %v", name, err)
		}
	}
	// An admin still changes an admin's and a member's.
	member, _ := w.actor(t, "member", "member")
	w.reads(t, member, device)
	act, _, err := w.c.RunFlagsDrop(ctx, w.command(t, kc.OpItemFlagsDrop, admin, adminSub), device, member, canRS, canR)
	ranAct(t, "an admin's drop on a member", act, err)
	other, _ := w.actor(t, "admin", "admin")
	act, _, err = w.c.RunFlagsRaise(ctx, w.command(t, kc.OpItemFlagsRaise, admin, adminSub), device, other, []string{}, []string{kc.CanSend})
	ranAct(t, "an admin's raise on an admin", act, err)
}
