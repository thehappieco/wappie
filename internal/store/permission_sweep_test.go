package store_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/pg"
	"whatserver2/internal/store"
)

// The check at every start (DS48): every live connection whose person no
// longer reads one of its numbers ends whole, access_lost, whatever its
// kind and its status; one whose person waits for a rotated number's new
// key is kept, until that rotation is over for them.

// sweep runs the check and wants it to end without an error and leave no
// workspace busy, returning what it ended by id with its reader.
func sweep(t *testing.T, w *ownWorld) (map[string]string, []store.SweptConnection) {
	t.Helper()
	res, err := store.EndConnectionsWithoutRead(context.Background(), w.pool)
	if err != nil || len(res.Busy) != 0 {
		t.Fatalf("the check: %+v %v", res, err)
	}
	got := map[string]string{}
	for _, e := range res.Ended {
		got[e.ID] = e.Reader
	}
	if len(got) != len(res.Ended) {
		t.Fatalf("a connection ended twice: %+v", res.Ended)
	}
	return got, res.Ended
}

// TestConnectionsWithoutReadSweep builds what the rules before F3 and F4
// left behind, with Read stripped in SQL as those paths stripped it:
//   - gone: the Read flag and the grant off one number (the screen before
//     DS47), with a content connection on it and the shared number, an AI
//     integration, a metadata connection and a pending one on it alone,
//     and a metadata connection on the shared number only;
//   - revoked: the flag kept, the grant gone (a grant.revoke before F4),
//     with a content connection and an AI integration;
//   - waiting: a number rotated to epoch 2, the person holding epoch 1's
//     key only, with a content connection in reseal on it and the shared
//     number and a metadata one on it alone; and a metadata connection on
//     it and a number whose grant they lost;
//   - a reader's AI integration and the owner's content connection, on
//     numbers they read.
//
// The sweep ends exactly the ones whose person does not read a number
// they hold, and names them with their readers; the workspace key and the
// legacy token on the lost number keep it. A second pass finds nothing.
// Once the rotated number's old key is retired, the person no longer
// waits, and a pass ends theirs too.
func TestConnectionsWithoutReadSweep(t *testing.T) {
	ctx := context.Background()
	w := newOwnWorld(t)
	gone, _ := w.actor(t, "admin", "admin")
	revoked, _ := w.actor(t, "admin", "admin")
	waiting, _ := w.actor(t, "admin", "admin")
	reader, _ := w.actor(t, "admin", "admin")
	nGone, nRevoked, nRotating, nLost, nFine := w.number(t, "Gone"), w.number(t, "Revoked"), w.number(t, "Rotating"),
		w.number(t, "Lost"), w.number(t, "Fine")
	for _, d := range []uuid.UUID{nGone, nRevoked, nRotating, nLost, nFine} {
		w.reads(t, w.owner, d)
	}
	services := map[string]uuid.UUID{}
	connect := func(actor uuid.UUID, kind string, devices ...uuid.UUID) string {
		t.Helper()
		id, svc := w.connect(t, actor, kind, devices...)
		if svc != uuid.Nil {
			services[id] = svc
		}
		return id
	}

	w.reads(t, gone, nGone)
	w.reads(t, gone, w.shared)
	goneBoth := connect(gone, store.KindContent, nGone, w.shared)
	goneAI := connect(gone, store.KindAI, nGone)
	goneMeta := connect(gone, store.KindMetadata, nGone)
	pending, err := w.conns.Create(ctx, w.tenant, gone, w.prepare(t, gone, store.KindMetadata, nGone))
	if err != nil {
		t.Fatal(err)
	}
	goneShared := connect(gone, store.KindMetadata, w.shared)
	rest, err := w.apiKeys.IssueActingAsForDevices(ctx, w.tenant.String(), "rest", store.ScopeRead, &gone, nil, []uuid.UUID{nGone}, nil)
	if err != nil {
		t.Fatal(err)
	}
	restID := w.keyID(ctx, t, rest)
	secret, _, err := w.users.NewMemberInvitation(ctx, w.tenant, w.owner, store.RoleService, "")
	if err != nil {
		t.Fatal(err)
	}
	standing, err := w.users.SignupService(ctx, secret, "mcp-"+hex.EncodeToString(randomBytes(t, 4)), randomBytes(t, 32))
	if err != nil {
		t.Fatal(err)
	}
	w.reads(t, standing.ID, nGone)
	legacy, err := w.apiKeys.IssueActingAsForDevices(ctx, w.tenant.String(), "MCP · Claude", store.ScopeRead, &gone, &standing.ID,
		[]uuid.UUID{nGone}, nil)
	if err != nil {
		t.Fatal(err)
	}
	legacyID := w.keyID(ctx, t, legacy)
	w.execOne(t, `UPDATE device_permissions SET can_read = false WHERE device_id = $1 AND user_id = $2`, nGone, gone)
	w.execOne(t, `DELETE FROM device_key_grants WHERE device_id = $1 AND user_id = $2`, nGone, gone)

	w.reads(t, revoked, nRevoked)
	revokedContent := connect(revoked, store.KindContent, nRevoked)
	revokedAI := connect(revoked, store.KindAI, nRevoked)
	w.execOne(t, `DELETE FROM device_key_grants WHERE device_id = $1 AND user_id = $2`, nRevoked, revoked)

	w.reads(t, waiting, nRotating)
	w.reads(t, waiting, nLost)
	w.reads(t, waiting, w.shared)
	waitingBoth := connect(waiting, store.KindContent, nRotating, w.shared)
	if err := w.conns.Reseal(ctx, "enclave", waitingBoth); err != nil {
		t.Fatal(err)
	}
	waitingMeta := connect(waiting, store.KindMetadata, nRotating)
	waitingLost := connect(waiting, store.KindMetadata, nRotating, nLost)
	w.epochKey(t, nRotating, 2)
	w.grantAt(t, nRotating, w.owner, 2)
	w.execOne(t, `DELETE FROM device_key_grants WHERE device_id = $1 AND user_id = $2`, nLost, waiting)

	w.reads(t, reader, nFine)
	readerAI := connect(reader, store.KindAI, nFine)
	theirs := connect(w.owner, store.KindContent, nGone)

	got, ended := sweep(t, w)
	want := map[string]string{goneBoth: "enclave", goneAI: "enclave", goneMeta: store.HostedReader, pending.ID: store.HostedReader,
		revokedContent: "enclave", revokedAI: "enclave", waitingLost: store.HostedReader}
	if !maps.Equal(got, want) {
		t.Fatalf("ended %+v, want %v", ended, want)
	}
	// Each of these numbers has a key and a grant: no remedy to name.
	for _, e := range ended {
		if e.Tenant != w.tenant || len(e.Keyless) != 0 || len(e.Orphan) != 0 {
			t.Fatalf("ended %+v", e)
		}
	}
	for id := range want {
		if r := w.row(t, id); r.status != "revoked" || r.reason != store.ReasonAccessLost || r.keyLive {
			t.Fatalf("connection %s %+v", id, r)
		}
		if svc, ok := services[id]; ok {
			if tr := w.trace(t, svc); tr != (serviceTrace{}) {
				t.Fatalf("an ended connection's account remains: %+v", tr)
			}
		}
	}
	kept := map[string]string{goneShared: "active", waitingBoth: "reseal", waitingMeta: "active", readerAI: "active", theirs: "active"}
	for id, status := range kept {
		if r := w.row(t, id); r.status != status || !r.keyLive {
			t.Fatalf("a connection whose person reads, or waits: %s %+v, want %s", id, r, status)
		}
	}
	if !w.allows(t, restID, nGone) || !w.allows(t, legacyID, nGone) {
		t.Fatal("a workspace key or a legacy token lost the number")
	}

	// Nothing more to end.
	if got, _ := sweep(t, w); len(got) != 0 {
		t.Fatalf("a second pass: %v", got)
	}
	for id, status := range kept {
		if r := w.row(t, id); r.status != status {
			t.Fatalf("a second pass: %s %+v", id, r)
		}
	}

	// The rotation is over: its old key retired, the person was never
	// given the new one, and no longer waits.
	w.execOne(t, `UPDATE device_archive_keys SET retired_at = now() WHERE device_id = $1 AND epoch = 1`, nRotating)
	if got, _ := sweep(t, w); !maps.Equal(got, map[string]string{waitingBoth: "enclave", waitingMeta: store.HostedReader}) {
		t.Fatalf("after the rotation: ended %v", got)
	}
	for id, status := range map[string]string{goneShared: "active", readerAI: "active", theirs: "active"} {
		if r := w.row(t, id); r.status != status || !r.keyLive {
			t.Fatalf("after the rotation: %s %+v", id, r)
		}
	}
}

// TestConnectionsWithoutReadSweepHeldByService: a connection holds a number
// through its service account as well as through its key's rows, as
// leaveOwnConnectionsTx counts it. One whose key no longer names a number
// that its account still holds, by a grant alone or by a permission alone,
// ends when its person lost Read there. One that holds only what its key
// names, all read, is kept.
func TestConnectionsWithoutReadSweepHeldByService(t *testing.T) {
	w := newOwnWorld(t)
	person, _ := w.actor(t, "admin", "admin")
	nKeyed, nHeld := w.number(t, "Keyed"), w.number(t, "Held")
	for _, d := range []uuid.UUID{nKeyed, nHeld} {
		w.reads(t, w.owner, d)
		w.reads(t, person, d)
	}
	byGrant, svcGrant := w.connect(t, person, store.KindContent, nKeyed, nHeld)
	byPermission, svcPermission := w.connect(t, person, store.KindAI, nKeyed, nHeld)
	keyed, _ := w.connect(t, person, store.KindContent, nKeyed)
	// Both keys keep nKeyed alone. byGrant's account keeps only its grant
	// on nHeld, byPermission's only its permission.
	for _, id := range []string{byGrant, byPermission} {
		w.execOne(t, `DELETE FROM api_key_devices x USING mcp_connections c
			WHERE c.id = $1 AND x.api_key_id = c.api_key_id AND x.device_id = $2`, id, nHeld)
	}
	w.execOne(t, `DELETE FROM device_permissions WHERE device_id = $1 AND user_id = $2`, nHeld, svcGrant)
	w.execOne(t, `DELETE FROM device_key_grants WHERE device_id = $1 AND user_id = $2`, nHeld, svcPermission)
	// The person's grant on nHeld goes, as a grant.revoke before F4 took it.
	w.execOne(t, `DELETE FROM device_key_grants WHERE device_id = $1 AND user_id = $2`, nHeld, person)

	if got, _ := sweep(t, w); !maps.Equal(got, map[string]string{byGrant: "enclave", byPermission: "enclave"}) {
		t.Fatalf("ended %v", got)
	}
	for _, id := range []string{byGrant, byPermission} {
		if r := w.row(t, id); r.status != "revoked" || r.reason != store.ReasonAccessLost || r.keyLive {
			t.Fatalf("connection %s %+v", id, r)
		}
	}
	if r := w.row(t, keyed); r.status != "active" || !r.keyLive {
		t.Fatalf("a connection on a number its person reads: %+v", r)
	}
}

// TestConnectionsWithoutReadSweepBusyWorkspace: the check waits a bounded
// time for each workspace's locks, so it never holds up a start. A
// workspace kept busy is named in Busy and keeps its connections; another
// workspace's are still ended and returned. The next pass ends the busy
// one's.
func TestConnectionsWithoutReadSweepBusyWorkspace(t *testing.T) {
	ctx := context.Background()
	store.SetSweepLockTimeoutForTest(t, 200*time.Millisecond)
	w := newOwnWorld(t)
	other := ownOf(&actWorld{delWorld: &delWorld{pool: w.pool, tenant: uuid.MustParse(newTenant(t, w.pool, "other")),
		devices: w.devices, users: w.users, keys: w.keys, apiKeys: w.apiKeys, pns: 100}, gen: w.gen})
	other.owner = other.person(t, "owner", "owner")
	// leftover is a metadata connection whose person kept the Read flag and
	// lost the grant, in w's workspace.
	leftover := func(w *ownWorld) string {
		t.Helper()
		person, _ := w.actor(t, "admin", "admin")
		n := w.number(t, "Leftover")
		w.reads(t, w.owner, n)
		w.reads(t, person, n)
		id, _ := w.connect(t, person, store.KindMetadata, n)
		w.execOne(t, `DELETE FROM device_key_grants WHERE device_id = $1 AND user_id = $2`, n, person)
		return id
	}
	busy, free := leftover(w), leftover(other)

	locked, release, held := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		held <- pg.InTenantTx(ctx, w.pool, w.tenant.String(), func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SELECT 1 FROM tenants WHERE id = $1 FOR UPDATE`, w.tenant); err != nil {
				return err
			}
			close(locked)
			<-release
			return nil
		})
	}()
	select {
	case <-locked:
	case err := <-held:
		t.Fatalf("holding the workspace: %v", err)
	}
	// Bounded here too, so a check that waits for the lock fails the test
	// rather than hanging it.
	sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	res, sweepErr := store.EndConnectionsWithoutRead(sctx, w.pool)
	cancel()
	close(release)
	if err := <-held; err != nil {
		t.Fatal(err)
	}
	if sweepErr != nil || !slices.Equal(res.Busy, []uuid.UUID{w.tenant}) {
		t.Fatalf("a busy workspace: %+v %v", res, sweepErr)
	}
	if len(res.Ended) != 1 || res.Ended[0].ID != free || res.Ended[0].Tenant != other.tenant {
		t.Fatalf("with one workspace busy, ended %+v, want %s", res.Ended, free)
	}
	if r := w.row(t, busy); r.status != "active" || !r.keyLive {
		t.Fatalf("the busy workspace's connection: %+v", r)
	}
	if r := other.row(t, free); r.status != "revoked" || r.reason != store.ReasonAccessLost {
		t.Fatalf("the other workspace's connection: %+v", r)
	}

	if got, _ := sweep(t, w); !maps.Equal(got, map[string]string{busy: store.HostedReader}) {
		t.Fatalf("the next pass: %v", got)
	}
}

// TestConnectionsWithoutReadSweepLocksNothing: in the steady state, where
// every live connection's person reads what it holds, the check takes no
// lock. A workspace whose tenants row is held, as ingest holds it for its
// sequence while a start's history work runs, is neither waited for nor
// named busy, and its connections stay.
func TestConnectionsWithoutReadSweepLocksNothing(t *testing.T) {
	ctx := context.Background()
	store.SetSweepLockTimeoutForTest(t, 200*time.Millisecond)
	w := newOwnWorld(t)
	person, _ := w.actor(t, "admin", "admin")
	w.reads(t, person, w.shared)
	id, _ := w.connect(t, person, store.KindContent, w.shared)

	locked, release, held := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		held <- pg.InTenantTx(ctx, w.pool, w.tenant.String(), func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `UPDATE tenants SET last_seq = last_seq + 1 WHERE id = $1`, w.tenant); err != nil {
				return err
			}
			close(locked)
			<-release
			return nil
		})
	}()
	select {
	case <-locked:
	case err := <-held:
		t.Fatalf("holding the workspace: %v", err)
	}
	sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	res, err := store.EndConnectionsWithoutRead(sctx, w.pool)
	cancel()
	close(release)
	if err := <-held; err != nil {
		t.Fatal(err)
	}
	if err != nil || len(res.Busy) != 0 || len(res.Ended) != 0 {
		t.Fatalf("the check in the steady state: %+v %v", res, err)
	}
	if r := w.row(t, id); r.status != "active" || !r.keyLive {
		t.Fatalf("the connection: %+v", r)
	}
}

// TestConnectionsWithoutReadSweepNobodyReads: a number nobody reads ends
// every connection that holds it, and the check names which kind it is,
// for the remedy the start's log line gives:
//   - keyless (epoch 0), as a row older than 0009 or a pairing cut off
//     between its row and its key leaves one: Keyless;
//   - orphan, a key and no grant to anyone (wsctl pair -orphan, or
//     device-key with no account): Orphan;
//   - every number of a workspace an older binary reset with its numbers
//     kept, its connections left live: Keyless;
//   - a workspace this binary reset with its numbers kept: the reset ended
//     its connections, and nothing is left to end.
//
// A connection on a number its person reads, beside them, is kept.
func TestConnectionsWithoutReadSweepNobodyReads(t *testing.T) {
	ctx := context.Background()
	w := newOwnWorld(t)
	person, _ := w.actor(t, "admin", "admin")
	nKeyless, nOrphan, nFine := w.number(t, "Keyless"), w.number(t, "Orphan"), w.number(t, "Fine")
	for _, d := range []uuid.UUID{nKeyless, nOrphan, nFine} {
		w.reads(t, w.owner, d)
		w.reads(t, person, d)
	}
	keyless, _ := w.connect(t, person, store.KindMetadata, nKeyless, nFine)
	orphan, _ := w.connect(t, person, store.KindContent, nOrphan)
	both, _ := w.connect(t, person, store.KindMetadata, nKeyless, nOrphan)
	fine, _ := w.connect(t, person, store.KindAI, nFine)
	w.scoped(t, func(tx pgx.Tx) error {
		// No key at all: its grants go with it.
		if _, err := tx.Exec(ctx, `DELETE FROM device_archive_keys WHERE device_id = $1`, nKeyless); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE devices SET current_epoch = 0 WHERE id = $1`, nKeyless); err != nil {
			return err
		}
		// A key nobody holds.
		_, err := tx.Exec(ctx, `DELETE FROM device_key_grants WHERE device_id = $1`, nOrphan)
		return err
	})

	// A workspace an older binary reset with its numbers kept.
	world := func(name string, pns int) *ownWorld {
		o := ownOf(&actWorld{delWorld: &delWorld{pool: w.pool, tenant: uuid.MustParse(newTenant(t, w.pool, name)),
			devices: w.devices, users: w.users, keys: w.keys, apiKeys: w.apiKeys, pns: pns}, gen: w.gen})
		o.owner = o.person(t, "owner", "owner")
		return o
	}
	older := world("older", 100)
	oldPerson, _ := older.actor(t, "admin", "admin")
	o1, o2 := older.number(t, "One"), older.number(t, "Two")
	for _, d := range []uuid.UUID{o1, o2} {
		older.reads(t, older.owner, d)
		older.reads(t, oldPerson, d)
	}
	oldMeta, _ := older.connect(t, oldPerson, store.KindMetadata, o1, o2)
	oldContent, _ := older.connect(t, older.owner, store.KindContent, o2)
	older.scoped(t, func(tx pgx.Tx) error {
		for _, q := range []string{`DELETE FROM device_key_grants`, `DELETE FROM device_archive_keys`, `UPDATE devices SET current_epoch = 0`} {
			if _, err := tx.Exec(ctx, q); err != nil {
				return err
			}
		}
		return nil
	})

	// A workspace this binary reset with its numbers kept.
	reset := world("reset", 200)
	resetPerson, _ := reset.actor(t, "admin", "admin")
	r1 := reset.number(t, "One")
	reset.reads(t, reset.owner, r1)
	reset.reads(t, resetPerson, r1)
	resetMeta, _ := reset.connect(t, resetPerson, store.KindMetadata, r1)
	if counts, err := store.ResetArchive(ctx, w.pool, reset.tenant, true); err != nil || counts.Connections != 1 {
		t.Fatalf("the reset: %+v %v", counts, err)
	}

	_, ended := sweep(t, w)
	type named struct {
		tenant           uuid.UUID
		keyless, orphans string
	}
	got := map[string]named{}
	for _, e := range ended {
		got[e.ID] = named{e.Tenant, fmt.Sprint(e.Keyless), fmt.Sprint(e.Orphan)}
	}
	none := fmt.Sprint([]uuid.UUID(nil))
	want := map[string]named{
		keyless:    {w.tenant, fmt.Sprint([]uuid.UUID{nKeyless}), none},
		orphan:     {w.tenant, none, fmt.Sprint([]uuid.UUID{nOrphan})},
		both:       {w.tenant, fmt.Sprint([]uuid.UUID{nKeyless}), fmt.Sprint([]uuid.UUID{nOrphan})},
		oldMeta:    {older.tenant, fmt.Sprint(sorted(o1, o2)), none},
		oldContent: {older.tenant, fmt.Sprint([]uuid.UUID{o2}), none},
	}
	if !maps.Equal(got, want) {
		t.Fatalf("ended %+v, want %+v", got, want)
	}
	if r := w.row(t, fine); r.status != "active" || !r.keyLive {
		t.Fatalf("a connection on a number its person reads: %+v", r)
	}
	if r := reset.row(t, resetMeta); r.status != "revoked" || r.reason != store.ReasonAccessLost {
		t.Fatalf("the reset's connection: %+v", r)
	}
}

// sorted is ids in uuid order, as the check lists a connection's numbers.
func sorted(ids ...uuid.UUID) []uuid.UUID {
	return slices.SortedFunc(slices.Values(ids), func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
}
