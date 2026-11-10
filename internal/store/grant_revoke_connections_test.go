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
	// connection is the start's check's.
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
		before := w.grantsOf(t, device, target) //nolint:contextcheck // the world's helpers run on a context of their own
		if ended, err := w.keys.RevokeGrantEnded(ctx, w.tenant, actor, device, target); !errors.Is(err, want) || len(ended) != 0 {
			t.Fatalf("%s: %v %v, want %v", what, ended, err, want)
		}
		if g := w.grantsOf(t, device, target); g != before { //nolint:contextcheck // the world's helpers run on a context of their own
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

// TestGrantRevokeConnectionAccount: a lone grant.revoke of a connection's
// own account (its service_user_id) on a number would narrow the
// connection, the state 0061 removes. It ends that connection whole,
// access_lost, in the same transaction, its other numbers with it, and
// returns it for its reader to be told. The person's other connections,
// their Read and a legacy token's standing account are not touched; a
// revoke of the account on a number it holds no grant on ends nothing.
func TestGrantRevokeConnectionAccount(t *testing.T) {
	ctx := context.Background()
	w := newOwnWorld(t)
	person, _ := w.actor(t, "admin", "admin")
	s := w.own(t, person, "Account")

	ended, err := w.keys.RevokeGrantEnded(ctx, w.tenant, w.owner, s.number, s.services[s.only])
	if err != nil {
		t.Fatal(err)
	}
	if len(ended) != 1 || ended[0] != (store.EndedConnection{ID: s.only, Reader: "enclave"}) {
		t.Fatalf("ended %+v, want %s", ended, s.only)
	}
	// An integration on both numbers, its account's grant on the shared
	// one revoked: it ends whole, the number with it.
	ended, err = w.keys.RevokeGrantEnded(ctx, w.tenant, w.owner, w.shared, s.services[s.aiBoth])
	if err != nil {
		t.Fatal(err)
	}
	if len(ended) != 1 || ended[0] != (store.EndedConnection{ID: s.aiBoth, Reader: "enclave"}) {
		t.Fatalf("ended %+v, want %s", ended, s.aiBoth)
	}
	for _, id := range []string{s.only, s.aiBoth} {
		if r := w.row(t, id); r.status != "revoked" || r.reason != store.ReasonAccessLost || r.keyLive {
			t.Fatalf("connection %s %+v", id, r)
		}
		if tr := w.trace(t, s.services[id]); tr != (serviceTrace{}) {
			t.Fatalf("an ended connection's account remains: %+v", tr)
		}
	}
	// A number its account holds no grant on: nothing to narrow.
	other := w.number(t, "Other")
	w.reads(t, w.owner, other)
	if ended, err := w.keys.RevokeGrantEnded(ctx, w.tenant, w.owner, other, s.services[s.both]); err != nil || len(ended) != 0 {
		t.Fatalf("a revoke of no grant: %v %v", ended, err)
	}
	// A legacy token's standing account is named by no connection.
	if ended, err := w.keys.RevokeGrantEnded(ctx, w.tenant, w.owner, s.number, s.standing); err != nil || len(ended) != 0 {
		t.Fatalf("a standing account's revoke: %v %v", ended, err)
	}
	if !w.allows(t, s.legacy, s.number) {
		t.Fatal("the legacy token lost the number")
	}
	for _, id := range []string{s.both, s.metaBoth, s.aiOnly, s.meta, s.theirs} {
		if r := w.row(t, id); r.status != "active" || !r.keyLive {
			t.Fatalf("connection %s %+v", id, r)
		}
	}
	if p := w.stored(t, s.number, person); !p.Read || !p.HasKey {
		t.Fatalf("the person's Read: %+v", p)
	}
}

// TestGrantAddConnectionAccount: a live connection's own account takes a
// grant only on a number its key names and its person reads
// (ErrConnectionAccountGrant, DS48), since the check at every start
// counts each grant of the account as a number the connection holds. A
// grant again on its own number is taken; a provisional account no
// connection names yet, and a standing one, take any. CheckGrant answers
// as PutGrant does, and writes nothing.
func TestGrantAddConnectionAccount(t *testing.T) {
	ctx := context.Background()
	w := newOwnWorld(t)
	person, _ := w.actor(t, "admin", "admin")
	s := w.own(t, person, "Granted")
	grant := func(device, user uuid.UUID) error {
		return w.keys.PutGrant(ctx, store.Grant{TenantID: w.tenant, DeviceID: device, UserID: user, Epoch: 1, SealedDSK: []byte("again")}, &w.owner)
	}
	account := s.services[s.only]
	// The shared number: the person reads it, the key does not name it.
	if err := grant(w.shared, account); !errors.Is(err, store.ErrConnectionAccountGrant) {
		t.Fatalf("a number its key does not name: %v", err)
	}
	if g := w.grantsOf(t, w.shared, account); g != 0 {
		t.Fatalf("the account holds %d grants on the shared number", g)
	}
	// CheckGrant, which device-key asks of every account before it makes
	// a key, answers as PutGrant does.
	if err := w.keys.CheckGrant(ctx, w.tenant, w.shared, account); !errors.Is(err, store.ErrConnectionAccountGrant) {
		t.Fatalf("CheckGrant of a number its key does not name: %v", err)
	}
	if err := w.keys.CheckGrant(ctx, w.tenant, w.shared, person); err != nil {
		t.Fatalf("CheckGrant of a person: %v", err)
	}
	if err := w.keys.CheckGrant(ctx, w.tenant, w.shared, uuid.New()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("CheckGrant of nobody: %v", err)
	}
	// Its own number, sealed again: taken.
	if err := grant(s.number, account); err != nil {
		t.Fatalf("its own number again: %v", err)
	}
	// Its key names the number, but the person no longer reads it (their
	// grant lost before F4): refused.
	w.execOne(t, `DELETE FROM device_key_grants WHERE device_id = $1 AND user_id = $2`, s.number, person)
	if err := grant(s.number, account); !errors.Is(err, store.ErrConnectionAccountGrant) {
		t.Fatalf("a number its person does not read: %v", err)
	}
	// Accounts no live connection names.
	provisional := w.prepare(t, person, store.KindContent, w.shared)
	for name, user := range map[string]uuid.UUID{"a provisional account": provisional.ServiceUserID, "a standing account": s.standing} {
		if err := grant(s.number, user); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// TestSetPermissionConnectionAccount: Wappie's screen's PUT on a live
// connection's own account (DS48), which the REST API reaches. A PUT that
// takes the account's Read, or deletes its grant, would narrow the
// connection, the state 0061 removes: it ends that connection whole,
// access_lost, in the same transaction, and returns it for its reader to
// be told, as grant.revoke does. Any other change is held to PutGrant's
// rule: on a number its key does not name, or that its person does not
// read, ErrConnectionAccountGrant, and nothing is written, a row with no
// flag included. A raise on its own number is taken and ends nothing. A
// provisional account no connection names yet takes any. The check at
// the next start then finds nothing to end.
func TestSetPermissionConnectionAccount(t *testing.T) {
	ctx := context.Background()
	w := newOwnWorld(t)
	person, _ := w.actor(t, "admin", "admin")
	s := w.own(t, person, "Put")
	put := func(device, user uuid.UUID, read, send bool) ([]store.EndedConnection, error) {
		return w.users.SetDevicePermissionEnded(ctx, w.tenant, w.owner, store.DevicePermission{DeviceID: device, UserID: user, Read: read, Send: send})
	}
	other := w.number(t, "Other")
	w.reads(t, w.owner, other)
	only := s.services[s.only]

	// Wider than the consent: refused, nothing written. other is read by
	// the owner alone; the person reads the shared number, which s.only's
	// key does not name.
	for _, c := range []struct {
		what       string
		device     uuid.UUID
		read, send bool
	}{
		{"Read on a number nobody consented to", other, true, false},
		{"send alone there", other, false, true},
		{"a row with no flag there", other, false, false},
		{"Read on a number its key does not name", w.shared, true, false},
	} {
		if ended, err := put(c.device, only, c.read, c.send); !errors.Is(err, store.ErrConnectionAccountGrant) || len(ended) != 0 {
			t.Fatalf("%s: %v %v", c.what, ended, err)
		}
		if p, g := w.holds(t, only, c.device); p != 0 || g != 0 {
			t.Fatalf("%s: the account holds %d permissions and %d grants", c.what, p, g)
		}
	}
	// Its own number, Read kept: taken, nothing ends.
	if ended, err := put(s.number, only, true, true); err != nil || len(ended) != 0 {
		t.Fatalf("a raise on its own number: %v %v", ended, err)
	}
	w.untouched(t, "a raise on its own number", s)

	// Narrower than the consent: the connection ends whole, the other
	// number with it. Every flag dropped on a content connection's
	// account, Read dropped and send kept on an integration's.
	for _, c := range []struct {
		id   string
		send bool
	}{{s.both, false}, {s.aiBoth, true}} {
		ended, err := put(w.shared, s.services[c.id], false, c.send)
		if err != nil || len(ended) != 1 || ended[0] != (store.EndedConnection{ID: c.id, Reader: "enclave"}) {
			t.Fatalf("Read taken off %s's account: %+v %v", c.id, ended, err)
		}
		if r := w.row(t, c.id); r.status != "revoked" || r.reason != store.ReasonAccessLost || r.keyLive {
			t.Fatalf("connection %s %+v", c.id, r)
		}
		if tr := w.trace(t, s.services[c.id]); tr != (serviceTrace{}) {
			t.Fatalf("an ended connection's account remains: %+v", tr)
		}
	}
	for _, id := range []string{s.only, s.aiOnly, s.meta, s.metaBoth, s.theirs} {
		if r := w.row(t, id); r.status != "active" || !r.keyLive {
			t.Fatalf("connection %s %+v", id, r)
		}
	}
	if p := w.stored(t, w.shared, person); !p.Read || !p.HasKey {
		t.Fatalf("the person's Read on the shared number: %+v", p)
	}

	// An account no live connection names yet: a consent's, before it is
	// recorded.
	provisional := w.prepare(t, person, store.KindContent, s.number)
	if _, err := put(other, provisional.ServiceUserID, true, false); err != nil {
		t.Fatalf("a provisional account: %v", err)
	}
	if got, _ := sweep(t, w); len(got) != 0 {
		t.Fatalf("the check after: %v", got)
	}
}
