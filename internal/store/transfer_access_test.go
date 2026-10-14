package store_test

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/ledger"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// Moving a Team's number to Personal only while nobody else has access to it
// (decision 0040; the plan's D16, 4.12 and tests 43, 63 and 64).

// transferWorld is the AI fixture (an owner who is the Team's only owner,
// reads the number and holds its key) with the number linked and the
// owner's Personal at hand.
type transferWorld struct {
	*aiFixture
	devices  *store.Devices
	personal uuid.UUID
}

func newTransferWorld(t *testing.T) *transferWorld {
	t.Helper()
	ctx := context.Background()
	f := newAIFixture(t)
	w := &transferWorld{aiFixture: f, devices: store.NewDevices(f.pool)}
	if err := w.devices.SetIdentity(ctx, f.tenant.String(), f.device.String(), wa.Identity{
		PN: types.JID{User: "5511912340042", Server: types.DefaultUserServer}}); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT id FROM tenants WHERE personal_owner_id=$1`, f.owner).Scan(&w.personal); err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *transferWorld) preview(t *testing.T) store.PersonalTransferPreview {
	t.Helper()
	p, err := w.devices.PreviewPersonalTransfer(context.Background(), w.tenant, w.owner, w.device)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func (w *transferWorld) move(t *testing.T) (store.PersonalTransferPreview, error) {
	t.Helper()
	ctx := context.Background()
	if err := w.devices.SetPaused(ctx, w.tenant.String(), w.device.String(), true); err != nil {
		t.Fatal(err)
	}
	return w.devices.TransferPersonal(ctx, w.tenant, w.owner, w.device, w.personal)
}

func (w *transferWorld) permit(t *testing.T, user uuid.UUID, p store.DevicePermission) {
	t.Helper()
	p.DeviceID, p.UserID = w.device, user
	if err := w.users.SetDevicePermission(context.Background(), w.tenant, w.owner, p); err != nil {
		t.Fatalf("permission for %s: %v", user, err)
	}
}

func (w *transferWorld) grant(t *testing.T, user uuid.UUID, epoch uint16) {
	t.Helper()
	if err := w.grants.PutGrant(context.Background(), store.Grant{TenantID: w.tenant, DeviceID: w.device, UserID: user, Epoch: epoch,
		SealedDSK: []byte("grant")}, &w.owner); err != nil {
		t.Fatal(err)
	}
}

// stripSelf takes away a person's own access, leaving what they created.
func (w *transferWorld) stripSelf(t *testing.T, user uuid.UUID) {
	w.permit(t, user, store.DevicePermission{})
}

// onlyItsKey leaves a connection's service account with no row for the
// number: only the connection's key still names it.
func (w *transferWorld) onlyItsKey(t *testing.T, service uuid.UUID) {
	t.Helper()
	w.inTenantSQL(t, `DELETE FROM device_permissions WHERE device_id=$1 AND user_id=$2`, w.device, service)
	w.inTenantSQL(t, `DELETE FROM device_key_grants WHERE device_id=$1 AND user_id=$2`, w.device, service)
}

// onlyItsRows takes the number off a connection's key: only its service
// account's rows still reach it.
func (w *transferWorld) onlyItsRows(t *testing.T, connection string) {
	t.Helper()
	w.inTenantSQL(t, `DELETE FROM api_key_devices WHERE device_id=$1
		AND api_key_id=(SELECT api_key_id FROM mcp_connections WHERE id=$2)`, w.device, connection)
}

func (w *transferWorld) inTenantSQL(t *testing.T, sql string, args ...any) {
	t.Helper()
	ctx := context.Background()
	inTenantTx(ctx, t, w.pool, w.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	})
}

func (w *transferWorld) countIn(t *testing.T, tenant uuid.UUID, sql string, args ...any) int {
	t.Helper()
	ctx := context.Background()
	var n int
	inTenantTx(ctx, t, w.pool, tenant, func(tx pgx.Tx) error { return tx.QueryRow(ctx, sql, args...).Scan(&n) })
	return n
}

// holder names one entry of a refusal, as the console would show it.
func holder(o store.TransferAccess) string {
	who := o.Name
	if o.UserID != nil {
		who = o.UserID.String()
	}
	switch o.Kind {
	case "assistant", "ai":
		who = o.ConnectionID
	case "key":
		who = o.KeyName
	}
	out := o.Kind + ":" + who + ":" + strings.Join(o.Why, ",")
	if o.Status != "" {
		out += ":" + o.Status
	}
	return out
}

func holders(others []store.TransferAccess) []string {
	out := []string{}
	for _, o := range others {
		out = append(out, holder(o))
	}
	slices.Sort(out)
	return out
}

func (w *transferWorld) wantRefused(t *testing.T, want ...string) store.PersonalTransferPreview {
	t.Helper()
	p := w.preview(t)
	slices.Sort(want)
	if p.Eligible || p.ReasonCode != store.ReasonOthersHaveAccess || p.Reason == "" || !slices.Equal(holders(p.Others), want) {
		t.Fatalf("preview: eligible %v, %q, holders\n  %v\nwant\n  %v", p.Eligible, p.ReasonCode, holders(p.Others), want)
	}
	return p
}

// TestTransferRefusedWhileOthersHaveAccess is the plan's test 63, store
// half: every holder that refuses a move, listed exactly with why and
// status, each cleared by the store call its way out in the console makes,
// then the move.
func TestTransferRefusedWhileOthersHaveAccess(t *testing.T) {
	w := newTransferWorld(t)
	ctx := context.Background()
	if p := w.preview(t); !p.Eligible || len(p.Others) != 0 {
		t.Fatalf("the positive control, a number nobody else has: %+v", p)
	}

	// Another admin's assistant, another admin's AI authorization: their
	// own access goes, what they connected stays.
	assistantOwner, aiOwner, keyOwner := w.member(t, "admin"), w.member(t, "admin"), w.member(t, "admin")
	w.ownerReads(ctx, t, assistantOwner, w.device)
	assistant, _ := w.consentContent(ctx, t, assistantOwner)
	// Each way a connection reaches the number counts by itself: its key
	// naming it, with its service account's rows gone, or those rows, with
	// its key no longer naming it.
	byKey, byKeyConsent := w.consentContent(ctx, t, assistantOwner)
	byRows, _ := w.consentContent(ctx, t, assistantOwner)
	w.stripSelf(t, assistantOwner)
	w.onlyItsKey(t, byKeyConsent.service)
	w.onlyItsRows(t, byRows.ID)
	w.ownerReads(ctx, t, aiOwner, w.device)
	ai, _ := w.consentAI(ctx, t, aiOwner, w.aiKeys(ctx, t, aiOwner), nil)
	w.stripSelf(t, aiOwner)
	if _, err := w.keys.IssueActingAsForDevices(ctx, w.tenant.String(), "erp-key", store.ScopeSend, &keyOwner, nil, []uuid.UUID{w.device}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := w.keys.IssueActingAsForDevices(ctx, w.tenant.String(), "orphan-key", store.ScopeRead, nil, nil, []uuid.UUID{w.device}, nil); err != nil {
		t.Fatal(err)
	}

	// A second epoch: the owner holds both; a member, and the connections'
	// copies, only the older one.
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := w.grants.CreateArchiveKey(ctx, w.tenant, w.device, 2, pub); err != nil {
		t.Fatal(err)
	}
	w.grant(t, w.owner, 2)

	sender, manager, oldKey, disabled := w.member(t, "member"), w.member(t, "member"), w.member(t, "member"), w.member(t, "member")
	w.permit(t, sender, store.DevicePermission{Send: true})
	w.permit(t, manager, store.DevicePermission{Manage: true})
	// A grant gives Read and Send by default (0023): the old key's holder
	// keeps the key with no permission row at all.
	w.grant(t, oldKey, 1)
	w.inTenantSQL(t, `DELETE FROM device_permissions WHERE device_id=$1 AND user_id=$2`, w.device, oldKey)
	w.permit(t, disabled, store.DevicePermission{Read: true})
	w.inTenantSQL(t, `UPDATE workspace_memberships SET status='disabled' WHERE tenant_id=$1 AND user_id=$2`, w.tenant, disabled)
	svc, err := w.users.CreateService(ctx, w.tenant, "erp", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	w.permit(t, svc.ID, store.DevicePermission{Read: true})
	// The current key and nothing else, no flag set: a member, and a
	// standing service account.
	keyOnly := w.member(t, "member")
	keySvc, err := w.users.CreateService(ctx, w.tenant, "backup", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, user := range []uuid.UUID{keyOnly, keySvc.ID} {
		w.permit(t, user, store.DevicePermission{})
		w.grant(t, user, 2)
	}

	before := w.countIn(t, w.tenant, `SELECT (SELECT count(*) FROM device_permissions WHERE device_id=$1) + (SELECT count(*) FROM device_key_grants WHERE device_id=$1)`, w.device)
	p := w.wantRefused(t,
		"person:"+sender.String()+":send:active",
		"person:"+manager.String()+":manage:active",
		"person:"+oldKey.String()+":old_key:active",
		"person:"+disabled.String()+":read:disabled",
		"service:"+svc.ID.String()+":read:active",
		"person:"+keyOnly.String()+":key:active",
		"service:"+keySvc.ID.String()+":key:active",
		"assistant:"+assistant.ID+":read,old_key",
		"assistant:"+byKey.ID+":read",
		"assistant:"+byRows.ID+":read,old_key",
		"ai:"+ai.ID+":read,old_key",
		"key:erp-key:read,send",
		"key:orphan-key:read",
	)
	serviceNames := map[uuid.UUID]string{}
	for _, s := range []store.User{svc, keySvc} {
		serviceNames[s.ID] = store.ServiceName(store.User{Email: s.Email, Role: store.RoleService})
	}
	for _, o := range p.Others {
		if o.Kind == "service" && (o.UserID == nil || o.Name != serviceNames[*o.UserID]) {
			t.Fatalf("a service account by another name: %+v", o)
		}
		switch o.Kind {
		case "assistant", "ai":
			if o.UserID == nil || o.ClientName == "" || o.CreatedByName == "" {
				t.Fatalf("a connection with no creator named: %+v", o)
			}
		case "key":
			if o.KeyName == "erp-key" && (o.UserID == nil || *o.UserID != keyOwner || o.KeyID == "") ||
				o.KeyName == "orphan-key" && o.UserID != nil {
				t.Fatalf("a key's creator: %+v", o)
			}
		}
	}

	// A refusal changes nothing: rows, the pause, notices, events, moves.
	var denied *store.TransferDenied
	if _, err := w.move(t); !errors.As(err, &denied) || denied.Code != store.ReasonOthersHaveAccess || len(denied.Others) != 13 {
		t.Fatalf("the move: %v", err)
	}
	if d, err := w.devices.Get(ctx, w.tenant.String(), w.device.String()); err != nil || !d.Paused {
		t.Fatalf("after the refusal: %+v %v", d, err)
	}
	after := w.countIn(t, w.tenant, `SELECT (SELECT count(*) FROM device_permissions WHERE device_id=$1) + (SELECT count(*) FROM device_key_grants WHERE device_id=$1)`, w.device)
	if after != before || w.countIn(t, w.tenant, `SELECT count(*) FROM item_events`) != 0 ||
		w.countIn(t, w.tenant, `SELECT count(*) FROM device_transfers`) != 0 {
		t.Fatalf("a refusal changed rows: %d then %d", before, after)
	}

	// Only an owner gets the list.
	admin := w.member(t, "admin")
	if ap, err := w.devices.PreviewPersonalTransfer(ctx, w.tenant, admin, w.device); err != nil || ap.Eligible || ap.Others != nil ||
		ap.ReasonCode != "" || !strings.HasPrefix(ap.Reason, "Somente o proprietário") {
		t.Fatalf("an admin's preview: %+v %v", ap, err)
	}

	// The ways out, one by one.
	for _, user := range []uuid.UUID{sender, manager, svc.ID, oldKey, keyOnly, keySvc.ID} {
		w.permit(t, user, store.DevicePermission{})
	}
	for _, user := range []uuid.UUID{oldKey, keyOnly, keySvc.ID} {
		if n := w.countIn(t, w.tenant, `SELECT count(*) FROM device_key_grants WHERE user_id=$1`, user); n != 0 {
			t.Fatalf("a key holder kept %d grants", n)
		}
	}
	if err := w.users.RemoveMember(ctx, w.tenant, w.owner, disabled); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{assistant.ID, byKey.ID, byRows.ID} {
		if _, err := w.conns.Revoke(ctx, w.tenant, w.owner, id); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := w.conns.RevokeAI(ctx, w.tenant, w.owner, ai.ID, false); err != nil {
		t.Fatal(err)
	}
	for _, o := range w.preview(t).Others {
		if o.Kind == "key" {
			if err := w.keys.Revoke(ctx, w.tenant.String(), o.KeyID); err != nil {
				t.Fatal(err)
			}
		}
	}
	if p := w.preview(t); !p.Eligible || len(p.Others) != 0 {
		t.Fatalf("after every way out: %+v", p)
	}
	if _, err := w.move(t); err != nil {
		t.Fatalf("the move after every way out: %v", err)
	}
}

// What does not refuse a move, and what the preview lists instead.
func TestTransferIgnoresWhatHasNoAccess(t *testing.T) {
	w := newTransferWorld(t)
	ctx := context.Background()
	// An admin with no row, and one given Read, then Read and Send unticked
	// through the console's PUT, which sends Manage for them.
	w.member(t, "admin")
	ticked := w.member(t, "admin")
	w.ownerReads(ctx, t, ticked, w.device)
	w.permit(t, ticked, store.DevicePermission{Manage: true})
	// A key for every number, the owner's own restricted key, and a key
	// acting as a service account with no row.
	if _, err := w.keys.Issue(ctx, w.tenant.String(), "all"); err != nil {
		t.Fatal(err)
	}
	if _, err := w.keys.IssueActingAsForDevices(ctx, w.tenant.String(), "mine", store.ScopeRead, &w.owner, nil, []uuid.UUID{w.device}, nil); err != nil {
		t.Fatal(err)
	}
	idle, err := w.users.CreateService(ctx, w.tenant, "idle", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	// Restricted to the number, so only acting as the account sets it aside.
	if _, err := w.keys.IssueActingAsForDevices(ctx, w.tenant.String(), "as-idle", store.ScopeRead, &ticked, &idle.ID, []uuid.UUID{w.device}, nil); err != nil {
		t.Fatal(err)
	}
	// The owner's own assistant and AI authorization, and a consent of the
	// owner's still in progress.
	mine, _ := w.consentContent(ctx, t, w.owner)
	myAI, _ := w.consentAI(ctx, t, w.owner, w.aiKeys(ctx, t, w.owner), nil)
	w.prepareContent(ctx, t, w.owner)
	// A member with a grant only at a retired epoch.
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := w.grants.CreateArchiveKey(ctx, w.tenant, w.device, 2, pub); err != nil {
		t.Fatal(err)
	}
	w.grant(t, w.owner, 2)
	// Its grant alone, with no flag: a grant gives Read and Send only where
	// no permission row exists yet (0023).
	retired := w.member(t, "member")
	w.permit(t, retired, store.DevicePermission{})
	w.grant(t, retired, 1)
	w.inTenantSQL(t, `UPDATE device_archive_keys SET retired_at=now() WHERE device_id=$1 AND epoch=1`, w.device)

	p := w.preview(t)
	if !p.Eligible || len(p.Others) != 0 {
		t.Fatalf("a preview refused for what has no access: %+v", holders(p.Others))
	}
	if len(p.AllNumberKeys) != 1 || p.AllNumberKeys[0].Name != "all" || len(p.Keys) != 1 || p.Keys[0].Name != "mine" {
		t.Fatalf("the preview's keys: %+v, all-number %+v", p.Keys, p.AllNumberKeys)
	}
	ended := map[string]string{}
	for _, a := range p.AssistantsEnded {
		ended[a.ID.String()] = a.Kind
	}
	if len(ended) != 2 || ended[mine.ID] != "assistant" || ended[myAI.ID] != "ai" {
		t.Fatalf("the preview's assistants: %+v", p.AssistantsEnded)
	}
}

// TestTransferRecordsMovedOut is the plan's test 43, without its ledger case
// (the ledger export comes with the purge).
func TestTransferRecordsMovedOut(t *testing.T) {
	w := newTransferWorld(t)
	ctx := context.Background()
	ownerSub := linkSub(t, w.pool, w.owner)
	all, err := w.keys.Issue(ctx, w.tenant.String(), "all")
	if err != nil {
		t.Fatal(err)
	}
	mineKey, err := w.keys.IssueActingAsForDevices(ctx, w.tenant.String(), "mine", store.ScopeRead, &w.owner, nil, []uuid.UUID{w.device}, nil)
	if err != nil {
		t.Fatal(err)
	}
	mine, mineConsent := w.consentContent(ctx, t, w.owner)
	myAI, aiConsent := w.consentAI(ctx, t, w.owner, w.aiKeys(ctx, t, w.owner), nil)
	// Each way the owner's own connection reaches the number ends it by
	// itself.
	byKey, byKeyConsent := w.consentContent(ctx, t, w.owner)
	byRows, _ := w.consentContent(ctx, t, w.owner)
	w.onlyItsKey(t, byKeyConsent.service)
	w.onlyItsRows(t, byRows.ID)
	other, err := w.devices.Create(ctx, w.tenant.String(), "other", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	otherNumber := uuid.MustParse(other.ID)
	// The owner's own notice: a key with no creator paused the number.
	cli, err := w.keys.IssueActingAsForDevices(ctx, w.tenant.String(), "cli", store.ScopeFull, nil, nil, []uuid.UUID{w.device}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.devices.Pause(ctx, w.tenant, w.device, store.PauseActor{Key: w.keyID(ctx, t, cli)}); err != nil {
		t.Fatal(err)
	}
	if n := w.countIn(t, w.tenant, `SELECT count(*) FROM device_notices WHERE device_id=$1`, w.device); n != 1 {
		t.Fatalf("%d notices before the move", n)
	}
	// That key is nobody's: it refuses the move until it is revoked.
	if p := w.preview(t); p.Eligible {
		t.Fatalf("a key with no creator did not refuse: %+v", p)
	}
	cliPrefix, _, _ := strings.Cut(cli, ".")
	if err := w.keys.Revoke(ctx, w.tenant.String(), cliPrefix); err != nil {
		t.Fatal(err)
	}
	preview := w.preview(t)
	if !preview.Eligible || len(preview.AllNumberKeys) != 1 || preview.AllNumberKeys[0].Name != "all" {
		t.Fatalf("the preview: %+v", preview)
	}
	events := len(readEvents(t, w.pool, w.tenant, w.device))

	out, err := w.move(t)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]string{}
	for _, a := range out.AssistantsEnded {
		kinds[a.ID.String()] = a.Kind
	}
	if len(kinds) != 4 || kinds[mine.ID] != "assistant" || kinds[myAI.ID] != "ai" || kinds[byKey.ID] != "assistant" || kinds[byRows.ID] != "assistant" {
		t.Fatalf("assistants_ended: %+v", out.AssistantsEnded)
	}
	if len(out.KeysNarrowed) != 1 || out.KeysNarrowed[0].Name != "mine" {
		t.Fatalf("keys_narrowed: %+v", out.KeysNarrowed)
	}
	for _, id := range []string{mine.ID, myAI.ID, byKey.ID, byRows.ID} {
		var status, reason string
		if err := w.pool.QueryRow(ctx, `SELECT status, coalesce(revoke_reason,'') FROM mcp_connections WHERE id=$1`, id).Scan(&status, &reason); err != nil {
			t.Fatal(err)
		}
		if status != "revoked" || reason != store.ReasonAccessLost {
			t.Fatalf("the owner's connection %s: %s %s", id, status, reason)
		}
	}
	for _, service := range []uuid.UUID{mineConsent.service, aiConsent.service} {
		if tr := w.trace(ctx, t, service); tr.grants+tr.permissions+tr.memberships != 0 {
			t.Fatalf("an ended connection's service account remains: %+v", tr)
		}
	}
	// The owner's key is narrowed, not revoked: still restricted, to no
	// number, so it reaches none, the Team's others included. The key for
	// every number stays in the Team, reaching its numbers but not the
	// moved one.
	mineID, allID := w.keyID(ctx, t, mineKey), w.keyID(ctx, t, all)
	reaches := func(key, device uuid.UUID) bool {
		t.Helper()
		ok, err := w.keys.AllowsDevice(ctx, key, w.tenant, device)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if reaches(mineID, w.device) || reaches(mineID, otherNumber) || reaches(allID, w.device) || !reaches(allID, otherNumber) {
		t.Fatalf("after the move: mine %v %v, all %v %v", reaches(mineID, w.device), reaches(mineID, otherNumber),
			reaches(allID, w.device), reaches(allID, otherNumber))
	}
	var revoked, restricted bool
	if err := w.pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL, devices_restricted FROM api_keys WHERE id=$1`, mineID).Scan(&revoked, &restricted); err != nil ||
		revoked || !restricted {
		t.Fatalf("the owner's key: revoked %v, restricted %v (%v)", revoked, restricted, err)
	}
	if n := w.countIn(t, w.tenant, `SELECT count(*) FROM api_key_devices WHERE api_key_id=$1`, mineID); n != 0 {
		t.Fatalf("the owner's key still names %d numbers", n)
	}

	// One moved_out, in the Team, from the move's own clock.
	rows := readEvents(t, w.pool, w.tenant, w.device)
	if len(rows) != events+1 {
		t.Fatalf("rows: %+v", rows)
	}
	moved := rows[len(rows)-1]
	var completed time.Time
	inTenantTx(ctx, t, w.pool, w.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT completed_at FROM device_transfers WHERE device_id=$1`, w.device).Scan(&completed)
	})
	if moved.Type != "moved_out" || moved.ToTenantID == nil || *moved.ToTenantID != w.personal || moved.ActorKind != "person" ||
		moved.ActorSub == nil || *moved.ActorSub != ownerSub || !sameSubs(moved.ReaderSubs, ownerSub) || !moved.OccurredAt.Equal(completed) ||
		moved.DedupeKey != "moved_out:"+w.device.String()+":"+strconv.FormatInt(completed.UnixMicro(), 10) || moved.Ledgered ||
		moved.Hint == nil || *moved.Hint != "…0042" || moved.Label == nil || *moved.Label != "phone" {
		t.Fatalf("moved_out: %+v (completed %s)", moved, completed)
	}
	if n := len(eventsOf(t, w.pool, w.personal, w.device, "moved_out")) + len(eventsOf(t, w.pool, w.personal, w.device, "sync_paused")); n != 0 {
		t.Fatalf("%d rows in Personal", n)
	}
	for _, tenant := range []uuid.UUID{w.tenant, w.personal} {
		if n := w.countIn(t, tenant, `SELECT count(*) FROM device_notices WHERE device_id=$1`, w.device); n != 0 {
			t.Fatalf("%d notices left in %s", n, tenant)
		}
	}
	if n := len(eventsOf(t, w.pool, w.tenant, w.device, "sync_paused")); n != 1 {
		t.Fatalf("the move wrote a pause: %d sync_paused rows", n)
	}

	// The move is in the ledger, with where the number went, so a restore
	// from before it never puts the number back in the Team.
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	if n, err := store.ExportLedger(ctx, w.pool, w.tenant, &ledger.File{Path: path}); err != nil || n != 1 {
		t.Fatalf("the export: %d %v", n, err)
	}
	lines := readLedger(t, path)
	if len(lines) != 1 || lines[0].Type != ledger.TypeMovedOut || lines[0].DeviceID != w.device || lines[0].WorkspaceID != w.tenant ||
		lines[0].ToWorkspaceID == nil || *lines[0].ToWorkspaceID != w.personal || !lines[0].OccurredAt.Equal(completed) ||
		lines[0].DeletedAt != nil || lines[0].DeletedBy != nil {
		t.Fatalf("the ledger: %+v", lines)
	}
	if moved := eventsOf(t, w.pool, w.tenant, w.device, "moved_out"); len(moved) != 1 || !moved[0].Ledgered {
		t.Fatalf("the moved_out row after the export: %+v", moved)
	}
}

// An owner who holds the keys without Read is not among a move's readers.
func TestTransferMovedOutWithoutRead(t *testing.T) {
	a := newArchive(t)
	ctx := context.Background()
	owner, personal := transferOwner(t, a, "owner")
	linkSub(t, a.pool, owner)
	keys := store.NewKeys(a.pool)
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.CreateArchiveKey(ctx, a.tenant, a.device, 1, pub); err != nil {
		t.Fatal(err)
	}
	// Read withheld first, so the grant's default Read (0023) does not apply.
	if err := store.NewUsers(a.pool).SetDevicePermission(ctx, a.tenant, owner, store.DevicePermission{DeviceID: a.device, UserID: owner, Manage: true}); err != nil {
		t.Fatal(err)
	}
	if err := keys.PutGrant(ctx, store.Grant{TenantID: a.tenant, DeviceID: a.device, UserID: owner, Epoch: 1, SealedDSK: []byte("g")}, &owner); err != nil {
		t.Fatal(err)
	}
	devices := store.NewDevices(a.pool)
	if err := devices.SetPaused(ctx, a.tenant.String(), a.device.String(), true); err != nil {
		t.Fatal(err)
	}
	if _, err := devices.TransferPersonal(ctx, a.tenant, owner, a.device, personal); err != nil {
		t.Fatal(err)
	}
	rows := eventsOf(t, a.pool, a.tenant, a.device, "moved_out")
	if len(rows) != 1 || len(rows[0].ReaderSubs) != 0 || rows[0].ActorSub == nil {
		t.Fatalf("moved_out of an owner who does not read: %+v", rows)
	}
}

// With the owner holding the keys without Read, removing the last other
// reader is refused until the owner turns their own Read on.
func TestTransferWayOutNeedsTheOwnersRead(t *testing.T) {
	w := newTransferWorld(t)
	ctx := context.Background()
	reader := w.member(t, "member")
	w.ownerReads(ctx, t, reader, w.device)
	w.permit(t, w.owner, store.DevicePermission{})
	w.grant(t, w.owner, 1)
	err := w.users.SetDevicePermission(ctx, w.tenant, w.owner, store.DevicePermission{DeviceID: w.device, UserID: reader})
	if !errors.Is(err, store.ErrLastDeviceReader) {
		t.Fatalf("removing the last reader: %v", err)
	}
	w.permit(t, w.owner, store.DevicePermission{Read: true})
	w.permit(t, reader, store.DevicePermission{})
	if p := w.preview(t); !p.Eligible {
		t.Fatalf("after the way out: %+v", holders(p.Others))
	}
}

// TestTransferAccessRace is the plan's test 64, store half: a grant, a
// permission or a key that waits for the transfer's lock lands nowhere; one
// committed before the transfer locked makes it refuse.
func TestTransferAccessRace(t *testing.T) {
	w := newTransferWorld(t)
	ctx := context.Background()
	other, admin := w.member(t, "member"), w.member(t, "admin")
	if err := w.devices.SetPaused(ctx, w.tenant.String(), w.device.String(), true); err != nil {
		t.Fatal(err)
	}
	// Hold the device's row, which the transfer locks after the workspaces:
	// it then waits holding them, and so does everyone who comes after.
	blocker, err := w.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Rollback(context.Background()) }()
	if _, err := blocker.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, w.tenant.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := blocker.Exec(ctx, `SELECT 1 FROM devices WHERE id=$1 FOR UPDATE`, w.device); err != nil {
		t.Fatal(err)
	}
	pid := int(blocker.Conn().PgConn().PID())
	moved := make(chan error, 1)
	go func() {
		_, err := w.devices.TransferPersonal(ctx, w.tenant, w.owner, w.device, w.personal)
		moved <- err
	}()
	waitBlockedOn(t, w.pool, pid, 1)
	granted, permitted, issued := make(chan error, 1), make(chan error, 1), make(chan error, 1)
	go func() {
		granted <- w.grants.PutGrant(ctx, store.Grant{TenantID: w.tenant, DeviceID: w.device, UserID: other, Epoch: 1, SealedDSK: []byte("late")}, &w.owner)
	}()
	go func() {
		permitted <- w.users.SetDevicePermission(ctx, w.tenant, w.owner, store.DevicePermission{DeviceID: w.device, UserID: other, Read: true})
	}()
	go func() {
		_, err := w.keys.IssueActingAsForDevices(ctx, w.tenant.String(), "late", store.ScopeRead, &admin, nil, []uuid.UUID{w.device}, nil)
		issued <- err
	}()
	waitBlockedOn(t, w.pool, pid, 4)
	if err := blocker.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-moved; err != nil {
		t.Fatalf("the transfer: %v", err)
	}
	if err := <-granted; !errors.Is(err, store.ErrNumberGone) {
		t.Fatalf("a grant that waited for the move: %v", err)
	}
	if err := <-permitted; !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a permission that waited for the move: %v", err)
	}
	if err := <-issued; !errors.Is(err, store.ErrInvalidKeyDevices) {
		t.Fatalf("a key that waited for the move: %v", err)
	}
	for _, sql := range []string{
		`SELECT count(*) FROM device_key_grants WHERE device_id=$1`,
		`SELECT count(*) FROM device_permissions WHERE device_id=$1`,
	} {
		if n := w.countIn(t, w.tenant, sql, w.device); n != 0 {
			t.Fatalf("%s: %d left in the Team", sql, n)
		}
	}
	var keyed int
	if err := w.pool.QueryRow(ctx, `SELECT count(*) FROM api_key_devices WHERE device_id=$1`, w.device).Scan(&keyed); err != nil || keyed != 0 {
		t.Fatalf("%d key rows name the moved number (%v)", keyed, err)
	}
}

// A grant committed after a preview, before the transfer took its lock,
// makes the transfer refuse.
func TestTransferRefusesAGrantAfterItsPreview(t *testing.T) {
	w := newTransferWorld(t)
	if p := w.preview(t); !p.Eligible {
		t.Fatalf("preview: %+v", p)
	}
	late := w.member(t, "member")
	w.grant(t, late, 1)
	var denied *store.TransferDenied
	if _, err := w.move(t); !errors.As(err, &denied) || denied.Code != store.ReasonOthersHaveAccess || len(denied.Others) != 1 {
		t.Fatalf("the move: %v", err)
	}
	if n := w.countIn(t, w.tenant, `SELECT count(*) FROM device_transfers`); n != 0 {
		t.Fatal("a refused move was recorded")
	}
	if rows := eventsOf(t, w.pool, w.tenant, w.device, "moved_out"); len(rows) != 0 {
		t.Fatalf("a refused move wrote %+v", rows)
	}
}

// waitBlockedOn waits until n backends wait on pid, directly or behind
// another waiter.
func waitBlockedOn(t *testing.T, pool interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, pid, n int) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		var blocked int
		if err := pool.QueryRow(context.Background(), `WITH RECURSIVE waiting(pid) AS (
			SELECT pid FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid))
			UNION SELECT a.pid FROM pg_stat_activity a JOIN waiting w ON w.pid=ANY(pg_blocking_pids(a.pid))
		) SELECT count(*) FROM waiting`, pid).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked >= n {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("fewer than %d transactions waited", n)
}

// A transfer's own pause is undone only while nobody paused the number
// since (the plan's 4.12): a stop that found it paused, or another of
// Wappie's own pauses, stands, and so does a resume; a number that moved
// is not found and stays paused in Personal.
func TestMovePauseUndo(t *testing.T) {
	w := newTransferWorld(t)
	ctx := context.Background()
	paused := func() bool {
		t.Helper()
		d, err := w.devices.Get(ctx, w.tenant.String(), w.device.String())
		if err != nil {
			t.Fatal(err)
		}
		return d.Paused
	}
	set := func(on bool) {
		t.Helper()
		if err := w.devices.SetPaused(ctx, w.tenant.String(), w.device.String(), on); err != nil {
			t.Fatal(err)
		}
	}
	pauseForMove := func() store.MovePause {
		t.Helper()
		p, err := w.devices.PauseForMove(ctx, w.tenant, w.device)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	undo := func(p store.MovePause) bool {
		t.Helper()
		undone, err := w.devices.UndoMovePause(ctx, w.tenant, w.device, p)
		if err != nil {
			t.Fatal(err)
		}
		return undone
	}

	if p := pauseForMove(); !p.Changed || !paused() || !undo(p) || paused() {
		t.Fatalf("the handler's own pause, undone: %+v, paused %v", p, paused())
	}
	set(true)
	if p := pauseForMove(); p.Changed || undo(p) || !paused() {
		t.Fatalf("a number paused before the move: %+v, paused %v", p, paused())
	}
	set(false)
	for name, stop := range map[string]func(){
		"a person's stop": func() {
			if _, err := w.devices.Pause(ctx, w.tenant, w.device, store.PauseActor{User: w.owner}); err != nil {
				t.Fatal(err)
			}
		},
		"Wappie's own pause": func() { set(true) },
	} {
		p := pauseForMove()
		stop()
		if undo(p) || !paused() {
			t.Fatalf("%s during the move was undone", name)
		}
		set(false)
	}
	resumed := pauseForMove()
	set(false)
	if undo(resumed) || paused() {
		t.Fatal("a resume during the move: the undo paused the number or reported undoing")
	}

	p := pauseForMove()
	if _, err := w.devices.TransferPersonal(ctx, w.tenant, w.owner, w.device, w.personal); err != nil {
		t.Fatal(err)
	}
	if _, err := w.devices.UndoMovePause(ctx, w.tenant, w.device, p); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the undo of a number that moved: %v", err)
	}
	if d, err := w.devices.Get(ctx, w.personal.String(), w.device.String()); err != nil || !d.Paused {
		t.Fatalf("the moved number: %+v %v", d, err)
	}
}
