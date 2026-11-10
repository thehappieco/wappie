package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/store"
)

// A grant revoked alone counts as Read taken away (the platform's 0061,
// QF3, DS48): the socket's grant.revoke that leaves the person no grant at
// the number's current epoch ends their own connections and integrations
// that held it, whole, access_lost, as a drop of read does, though their
// Read flag stays. A rotation of the number's key, a revoke that leaves a
// grant at the current epoch, a grant replaced in the same transaction and
// a revoke of a dormant grant (no Read flag, so no Read) take nothing.

// TestGrantRevokeEndsOwnConnections: a lone grant.revoke leaves the rows a
// drop of read leaves (F3's left): every connection and integration of the
// person that held the number ended whole, those holding the shared number
// too, their drafts revoked; another person's connection, a workspace key
// and a legacy token keep the number. The Read flag stays, and is not Read
// without the grant: no consent on the number.
func TestGrantRevokeEndsOwnConnections(t *testing.T) {
	ctx := context.Background()
	w := newOwnWorld(t)
	person, _ := w.actor(t, "admin", "admin")
	s := w.own(t, person, "Revoke")
	ended, err := w.keys.RevokeGrantEnded(ctx, w.tenant, w.owner, s.number, person)
	if err != nil {
		t.Fatal(err)
	}
	w.left(t, "a lone grant.revoke", s, ended)
	if p := w.stored(t, s.number, person); !p.Read {
		t.Fatalf("the revoke took the Read flag: %+v", p)
	}
	// Again: no grant left to take, nothing more ended.
	if ended, err := w.keys.RevokeGrantEnded(ctx, w.tenant, w.owner, s.number, person); err != nil || len(ended) != 0 {
		t.Fatalf("the revoke again: %v %v", ended, err)
	}
	for _, kind := range []string{store.KindContent, store.KindAI, store.KindMetadata} {
		if _, err := w.conns.Create(ctx, w.tenant, person, w.prepare(t, person, kind, s.number)); !errors.Is(err, store.ErrMCPKeyUnsuitable) {
			t.Fatalf("a %s consent on the number with the flag and no grant: %v", kind, err)
		}
	}
}

// TestGrantRevokeTakesNothing: a revoke of a person with the Read flag and
// no grant left, a revoke of a dormant grant (no Read flag), a revoke that
// is refused (the number's last key), one of a person who holds no grant,
// an act that deletes an old epoch's grant and leaves the current one,
// and one that deletes the person's grants and puts the current one back
// in the same transaction end nothing and leave every connection as it
// was.
func TestGrantRevokeTakesNothing(t *testing.T) {
	ctx := context.Background()
	w := newOwnWorld(t)
	person, _ := w.actor(t, "admin", "admin")
	s := w.own(t, person, "Kept")

	// The Read flag and no grant left (a grant.revoke before F4), with a
	// connection on the number: no grant to take, so nothing ends. Such a
	// connection is the upgrade's sweep's.
	stale, _ := w.actor(t, "admin", "admin")
	w.reads(t, stale, s.number)
	staleMeta, _ := w.connect(t, stale, store.KindMetadata, s.number)
	w.execOne(t, `DELETE FROM device_key_grants WHERE device_id = $1 AND user_id = $2`, s.number, stale)
	if ended, err := w.keys.RevokeGrantEnded(ctx, w.tenant, w.owner, s.number, stale); err != nil || len(ended) != 0 {
		t.Fatalf("a revoke that finds no grant: %v %v", ended, err)
	}
	if r := w.row(t, staleMeta); r.status != "active" || !r.keyLive {
		t.Fatalf("a revoke that finds no grant ended %s: %+v", staleMeta, r)
	}
	w.untouched(t, "a revoke that finds no grant", s)

	// A dormant grant: the Read flag gone, the grant left (before DS47).
	// There was no Read to take: the revoke deletes the grant and ends
	// nothing, as Wappie's screen without Read does from the same state.
	dormant, _ := w.actor(t, "admin", "admin")
	w.reads(t, dormant, s.number)
	dormantMeta, _ := w.connect(t, dormant, store.KindMetadata, s.number)
	w.execOne(t, `UPDATE device_permissions SET can_read = false WHERE device_id = $1 AND user_id = $2`, s.number, dormant)
	if ended, err := w.keys.RevokeGrantEnded(ctx, w.tenant, w.owner, s.number, dormant); err != nil || len(ended) != 0 {
		t.Fatalf("a revoke of a dormant grant: %v %v", ended, err)
	}
	if g := w.grantsOf(t, s.number, dormant); g != 0 {
		t.Fatalf("the dormant grant is still there: %d", g)
	}
	if r := w.row(t, dormantMeta); r.status != "active" || !r.keyLive {
		t.Fatalf("a revoke of a dormant grant ended %s: %+v", dormantMeta, r)
	}
	w.untouched(t, "a revoke of a dormant grant", s)

	// The person holds the number's last key once the owner's and the
	// legacy token's account's are gone.
	for _, holder := range []uuid.UUID{w.owner, s.standing} {
		w.execOne(t, `DELETE FROM device_key_grants WHERE device_id = $1 AND user_id = $2`, s.number, holder)
	}
	if ended, err := w.keys.RevokeGrantEnded(ctx, w.tenant, w.owner, s.number, person); !errors.Is(err, store.ErrLastDeviceReader) || len(ended) != 0 {
		t.Fatalf("a revoke of the last key: %v %v", ended, err)
	}
	w.untouched(t, "a revoke of the last key", s)
	w.reads(t, w.owner, s.number)

	nobody := w.person(t, "nobody", "member")
	if ended, err := w.keys.RevokeGrantEnded(ctx, w.tenant, w.owner, s.number, nobody); err != nil || len(ended) != 0 {
		t.Fatalf("a revoke of nobody's grant: %v %v", ended, err)
	}
	w.untouched(t, "a revoke of nobody's grant", s)

	// The number at epoch 2, the person holding both epochs' keys: an
	// act that deletes the old one leaves them Read.
	w.epochKey(t, s.number, 2)
	w.grantAt(t, s.number, person, 2)
	ended, err := store.GrantTakenForTest(ctx, w.pool, w.tenant, person, s.number, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM device_key_grants WHERE device_id = $1 AND user_id = $2 AND epoch = 1`, s.number, person)
		return err
	})
	if err != nil || len(ended) != 0 {
		t.Fatalf("an old epoch's grant deleted: %v %v", ended, err)
	}
	w.untouched(t, "an old epoch's grant deleted", s)

	// Every grant of the person deleted and the current one put back, in
	// one transaction: replaced, not taken.
	ended, err = store.GrantTakenForTest(ctx, w.pool, w.tenant, person, s.number, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM device_key_grants WHERE device_id = $1 AND user_id = $2`, s.number, person); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO device_key_grants (tenant_id, device_id, user_id, epoch, sealed_dsk) VALUES ($1, $2, $3, 2, 'again')`,
			w.tenant, s.number, person)
		return err
	})
	if err != nil || len(ended) != 0 {
		t.Fatalf("a grant replaced in the same transaction: %v %v", ended, err)
	}
	w.untouched(t, "a grant replaced in the same transaction", s)
	if g := w.grantsOf(t, s.number, person); g != 1 {
		t.Fatalf("the person holds %d grants after the replacement", g)
	}
}

// TestGrantRevokeRotation: a rotation of the number's key deletes no grant
// and ends nothing, though the person holds only the old epoch's key
// until it is sealed to them again (0061 does not count it). A
// grant.revoke in the middle of it takes the key they would be sealed
// again from: their Read is gone, and their connections end as a lone
// revoke's do.
func TestGrantRevokeRotation(t *testing.T) {
	ctx := context.Background()
	w := newOwnWorld(t)
	person, _ := w.actor(t, "admin", "admin")
	s := w.own(t, person, "Rotated")
	w.epochKey(t, s.number, 2)
	w.untouched(t, "a rotation", s)
	ended, err := w.keys.RevokeGrantEnded(ctx, w.tenant, w.owner, s.number, person)
	if err != nil {
		t.Fatal(err)
	}
	w.left(t, "a revoke during a rotation", s, ended)
}

// TestGrantRevokeOwnerOnly: grant.revoke reads its actor's role again
// under the workspace's lock (DS48). Only an owner changes an owner's
// access (DS18, the platform's 0060): an admin's revoke of an owner's
// grant, live or dormant, or of a person whose stored document names them
// owner (read fail-closed), is ErrOwnerTarget before the last reader is
// looked at, and nothing changes. An owner's revoke of another owner's
// grant ends that owner's own connections, as any lone revoke does. An
// actor who is no longer an active owner or admin, or a workspace that is
// not active, is ErrMembershipForbidden.
func TestGrantRevokeOwnerOnly(t *testing.T) {
	ctx := context.Background()
	w := newOwnWorld(t)
	admin, _ := w.actor(t, "admin", "admin")
	owner, _ := w.actor(t, "owner", "owner")
	s := w.own(t, owner, "Owner's")
	refused := func(what string, actor, target, device uuid.UUID, want error) {
		t.Helper()
		before := w.grantsOf(t, device, target)
		if ended, err := w.keys.RevokeGrantEnded(ctx, w.tenant, actor, device, target); !errors.Is(err, want) || len(ended) != 0 {
			t.Fatalf("%s: %v %v, want %v", what, ended, err, want)
		}
		if g := w.grantsOf(t, device, target); g != before {
			t.Fatalf("%s: the target holds %d grants, had %d", what, g, before)
		}
	}
	refused("an admin on an owner", admin, owner, s.number, store.ErrOwnerTarget)
	w.untouched(t, "an admin on an owner", s)

	// The owner of the workspace is the last key holder here: the role is
	// asked first.
	solo := w.number(t, "Solo")
	w.reads(t, w.owner, solo)
	refused("an admin on the last key holder, an owner", admin, w.owner, solo, store.ErrOwnerTarget)

	// A dormant grant of an owner (the Read flag off): refused too.
	dormant := w.number(t, "Dormant")
	w.reads(t, w.owner, dormant)
	w.reads(t, owner, dormant)
	w.execOne(t, `UPDATE device_permissions SET can_read = false WHERE device_id = $1 AND user_id = $2`, dormant, owner)
	refused("an admin on an owner's dormant grant", admin, owner, dormant, store.ErrOwnerTarget)

	// An admin here whom their stored document names owner counts as an
	// owner.
	docOwner, _ := w.actor(t, "admin", "owner")
	w.reads(t, docOwner, s.number)
	refused("an admin on an owner by document", admin, docOwner, s.number, store.ErrOwnerTarget)
	// And as an actor they are an admin: the local role decides who acts.
	refused("an owner by document on an owner", docOwner, owner, s.number, store.ErrOwnerTarget)

	// Neither an admin's own role nor the session decides: a member, a
	// disabled admin and a suspended workspace are refused.
	member, _ := w.actor(t, "member", "member")
	w.reads(t, member, s.number)
	refused("a member on their own grant", member, member, s.number, store.ErrMembershipForbidden)
	former, _ := w.actor(t, "admin", "admin")
	if err := w.users.UpdateMember(ctx, w.tenant, w.owner, former, "admin", "disabled"); err != nil {
		t.Fatal(err)
	}
	refused("a disabled admin", former, member, s.number, store.ErrMembershipForbidden)
	if _, err := w.pool.Exec(ctx, `UPDATE tenants SET status = 'suspended' WHERE id = $1`, w.tenant); err != nil {
		t.Fatal(err)
	}
	refused("in a suspended workspace", w.owner, member, s.number, store.ErrMembershipForbidden)
	if _, err := w.pool.Exec(ctx, `UPDATE tenants SET status = 'active' WHERE id = $1`, w.tenant); err != nil {
		t.Fatal(err)
	}

	// An admin may revoke another admin's and a member's.
	if _, err := w.keys.RevokeGrantEnded(ctx, w.tenant, admin, s.number, member); err != nil {
		t.Fatal(err)
	}
	// An owner may revoke an owner's: their own connections end.
	ended, err := w.keys.RevokeGrantEnded(ctx, w.tenant, w.owner, s.number, owner)
	if err != nil {
		t.Fatal(err)
	}
	w.left(t, "an owner on an owner", s, ended)
}
