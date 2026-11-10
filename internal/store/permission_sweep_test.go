package store_test

import (
	"context"
	"encoding/hex"
	"errors"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/pg"
	"whatserver2/internal/store"
)

// The upgrade's sweep (DS48): every live connection whose person no longer
// reads one of its numbers ends whole, access_lost, whatever its kind and
// its status; one whose person waits for a rotated number's new key is
// kept, until that rotation is over for them.

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

	ended, err := store.EndConnectionsWithoutRead(ctx, w.pool)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range ended {
		got[e.ID] = e.Reader
	}
	want := map[string]string{goneBoth: "enclave", goneAI: "enclave", goneMeta: store.HostedReader, pending.ID: store.HostedReader,
		revokedContent: "enclave", revokedAI: "enclave", waitingLost: store.HostedReader}
	if len(ended) != len(want) || !maps.Equal(got, want) {
		t.Fatalf("ended %+v, want %v", ended, want)
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
	if ended, err := store.EndConnectionsWithoutRead(ctx, w.pool); err != nil || len(ended) != 0 {
		t.Fatalf("a second pass: %v %v", ended, err)
	}
	for id, status := range kept {
		if r := w.row(t, id); r.status != status {
			t.Fatalf("a second pass: %s %+v", id, r)
		}
	}

	// The rotation is over: its old key retired, the person was never
	// given the new one, and no longer waits.
	w.execOne(t, `UPDATE device_archive_keys SET retired_at = now() WHERE device_id = $1 AND epoch = 1`, nRotating)
	ended, err = store.EndConnectionsWithoutRead(ctx, w.pool)
	if err != nil {
		t.Fatal(err)
	}
	got = map[string]string{}
	for _, e := range ended {
		got[e.ID] = e.Reader
	}
	if want := map[string]string{waitingBoth: "enclave", waitingMeta: store.HostedReader}; !maps.Equal(got, want) {
		t.Fatalf("after the rotation: ended %+v, want %v", ended, want)
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
	ctx := context.Background()
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

	ended, err := store.EndConnectionsWithoutRead(ctx, w.pool)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range ended {
		got[e.ID] = e.Reader
	}
	if want := map[string]string{byGrant: "enclave", byPermission: "enclave"}; len(ended) != len(want) || !maps.Equal(got, want) {
		t.Fatalf("ended %+v, want %v", ended, want)
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

// TestConnectionsWithoutReadSweepBusyWorkspace: the sweep waits a bounded
// time for each workspace's locks, so it never holds up a start. A
// workspace kept busy fails with ErrWorkspaceBusy, named in the error, and
// keeps its connections; another workspace's are still ended and returned.
// The next pass ends the busy one's.
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
	// Bounded here too, so a sweep that waits for the lock fails the test
	// rather than hanging it.
	sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	ended, sweepErr := store.EndConnectionsWithoutRead(sctx, w.pool)
	cancel()
	close(release)
	if err := <-held; err != nil {
		t.Fatal(err)
	}
	if !errors.Is(sweepErr, store.ErrWorkspaceBusy) || !strings.Contains(sweepErr.Error(), w.tenant.String()) {
		t.Fatalf("a busy workspace: %v", sweepErr)
	}
	if len(ended) != 1 || ended[0].ID != free {
		t.Fatalf("with one workspace busy, ended %+v, want %s", ended, free)
	}
	if r := w.row(t, busy); r.status != "active" || !r.keyLive {
		t.Fatalf("the busy workspace's connection: %+v", r)
	}
	if r := other.row(t, free); r.status != "revoked" || r.reason != store.ReasonAccessLost {
		t.Fatalf("the other workspace's connection: %+v", r)
	}

	ended, err := store.EndConnectionsWithoutRead(ctx, w.pool)
	if err != nil || len(ended) != 1 || ended[0].ID != busy {
		t.Fatalf("the next pass: %+v %v", ended, err)
	}
}
