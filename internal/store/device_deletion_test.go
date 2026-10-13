package store_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/domain"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// Deleting a number (decision 0038): owners only, readers acknowledged, the
// row excluded for 30 days, no API key revoked, assistant connections ended,
// and a recovery that brings back exactly what is still there.

type delWorld struct {
	pool    *pgxpool.Pool
	tenant  uuid.UUID
	devices *store.Devices
	users   *store.Users
	keys    *store.Keys
	apiKeys *store.APIKeys
	owner   uuid.UUID
	pns     int
}

func newDelWorld(t *testing.T) *delWorld {
	t.Helper()
	pool := pgtest.Fresh(t, migrate.Run)
	w := &delWorld{pool: pool, tenant: uuid.MustParse(newTenant(t, pool, "team")),
		devices: store.NewDevices(pool), users: store.NewUsers(pool), keys: store.NewKeys(pool), apiKeys: store.NewAPIKeys(pool)}
	w.owner = w.person(t, "owner", "owner")
	return w
}

func (w *delWorld) person(t *testing.T, name, role string) uuid.UUID {
	t.Helper()
	u, err := w.users.Create(context.Background(), store.NewUser{TenantID: w.tenant, Email: name + "-" + uuid.NewString()[:8] + "@acme.test",
		Role: role, AuthKey: "test", KDFSalt: make([]byte, 16), KDFParams: store.DefaultKDFParams(), PublicKey: make([]byte, 32), WrappedUSK: []byte("wrapped")})
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}

// number is a linked number with an archive key at epoch 1, as pairing
// leaves one.
func (w *delWorld) number(t *testing.T, label string) uuid.UUID {
	t.Helper()
	w.pns++
	device := linkedNumber(t, w.pool, w.tenant, label, fmt.Sprintf("55119%04d5678", w.pns), fmt.Sprintf("1000000%08d", w.pns))
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := w.keys.CreateArchiveKey(context.Background(), w.tenant, device, 1, pub); err != nil {
		t.Fatal(err)
	}
	return device
}

// reads gives an account the number's grant and Read.
func (w *delWorld) reads(t *testing.T, user, device uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	if err := w.keys.PutGrant(ctx, store.Grant{TenantID: w.tenant, DeviceID: device, UserID: user, Epoch: 1, SealedDSK: []byte("grant")}, &w.owner); err != nil {
		t.Fatal(err)
	}
	if err := w.users.SetDevicePermission(ctx, w.tenant, w.owner, store.DevicePermission{DeviceID: device, UserID: user, Read: true}); err != nil {
		t.Fatal(err)
	}
}

// scoped runs fn in the workspace with excluded numbers visible.
func (w *delWorld) scoped(t *testing.T, fn func(pgx.Tx) error) {
	t.Helper()
	ctx := context.Background()
	inTenantTx(ctx, t, w.pool, w.tenant, func(tx pgx.Tx) error {
		return store.WithQuarantineForTest(ctx, tx, func() error { return fn(tx) })
	})
}

func (w *delWorld) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	w.scoped(t, func(tx pgx.Tx) error { return tx.QueryRow(context.Background(), query, args...).Scan(&n) })
	return n
}

func (w *delWorld) quarantine(t *testing.T, device uuid.UUID, ack ...uuid.UUID) store.Quarantined {
	t.Helper()
	q, err := w.devices.Quarantine(context.Background(), w.tenant, w.owner, device, ack)
	if err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	return q
}

func (w *delWorld) excluded(t *testing.T, device uuid.UUID) bool {
	t.Helper()
	return w.count(t, `SELECT count(*) FROM devices WHERE id=$1 AND deleted_at IS NOT NULL`, device) == 1
}

func (w *delWorld) accessVersion(t *testing.T, user uuid.UUID) int64 {
	t.Helper()
	var v int64
	w.scoped(t, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT access_version FROM workspace_memberships WHERE tenant_id=$1 AND user_id=$2`, w.tenant, user).Scan(&v)
	})
	return v
}

func (w *delWorld) keyID(ctx context.Context, t *testing.T, key string) uuid.UUID {
	t.Helper()
	v, err := w.apiKeys.VerifyScoped(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	return v.ID
}

// sessionStore creates the two whatsmeow tables a deletion reads, as the
// session store's own migrations would in a deployment.
func sessionStore(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		CREATE TABLE whatsmeow_device (jid text PRIMARY KEY, registration_id bigint NOT NULL);
		CREATE TABLE whatsmeow_privacy_tokens (our_jid text, their_jid text, token bytea NOT NULL, timestamp bigint NOT NULL, PRIMARY KEY (our_jid, their_jid))`); err != nil {
		t.Fatal(err)
	}
}

func (w *delWorld) pn(ctx context.Context, t *testing.T, device uuid.UUID) string {
	t.Helper()
	d, err := w.devices.Get(ctx, w.tenant.String(), device.String())
	if err != nil {
		t.Fatal(err)
	}
	return d.Identity.PN.String()
}

func TestExcludedHiddenEverywhere(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	device, other := w.number(t, "Suporte"), w.number(t, "Vendas")
	w.reads(t, w.owner, device)
	w.reads(t, w.owner, other)
	if _, err := store.NewMessages(w.pool).Insert(ctx, store.InsertMessage{UID: uuid.New(), TenantID: w.tenant, DeviceID: device,
		WAID: "one", ChatKey: "chat", Kind: domain.KindMessage, Type: domain.TypeText, Source: domain.SourceLive,
		TS: time.Now(), BodySealed: []byte{1}}); err != nil {
		t.Fatal(err)
	}
	all, err := w.apiKeys.Issue(ctx, w.tenant.String(), "all")
	if err != nil {
		t.Fatal(err)
	}
	restricted, err := w.apiKeys.IssueActingAsForDevices(ctx, w.tenant.String(), "restricted", store.ScopeRead, &w.owner, nil, []uuid.UUID{device, other}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Positive controls first.
	if _, err := w.devices.Get(ctx, w.tenant.String(), device.String()); err != nil {
		t.Fatal(err)
	}
	if ok, err := w.apiKeys.AllowsDevice(ctx, w.keyID(ctx, t, all), w.tenant, device); err != nil || !ok {
		t.Fatalf("control: %v %v", ok, err)
	}
	before := w.count(t, `SELECT (SELECT count(*) FROM device_key_grants WHERE device_id=$1)+(SELECT count(*) FROM device_archive_keys WHERE device_id=$1)
		+(SELECT count(*) FROM device_permissions WHERE device_id=$1)+(SELECT count(*) FROM messages WHERE device_id=$1)`, device)

	w.quarantine(t, device)

	if _, err := w.devices.Get(ctx, w.tenant.String(), device.String()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get: %v", err)
	}
	if _, err := w.devices.Resolve(ctx, w.tenant.String(), device.String()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Resolve: %v", err)
	}
	// A prefix finds the live number it shares a timestamp with, at most.
	if got, err := w.devices.Resolve(ctx, w.tenant.String(), device.String()[:8]); err == nil && got.ID == device.String() {
		t.Fatal("Resolve by prefix found the excluded number")
	}
	listed, err := w.devices.List(ctx, w.tenant.String())
	if err != nil || len(listed) != 1 || listed[0].ID != other.String() {
		t.Fatalf("List: %+v %v", listed, err)
	}
	if _, err := w.users.DevicePermission(ctx, w.tenant, w.owner, device); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("DevicePermission: %v", err)
	}
	for _, key := range []string{all, restricted} {
		if ok, err := w.apiKeys.AllowsDevice(ctx, w.keyID(ctx, t, key), w.tenant, device); err != nil || ok {
			t.Fatalf("AllowsDevice: %v %v", ok, err)
		}
	}
	if ok, err := w.apiKeys.AllowsDevice(ctx, w.keyID(ctx, t, restricted), w.tenant, other); err != nil || !ok {
		t.Fatalf("the restricted key lost its other number: %v %v", ok, err)
	}
	grants, err := w.keys.GrantsFor(ctx, w.tenant, w.owner)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range grants {
		if g.DeviceID == device {
			t.Fatal("GrantsFor names the excluded number")
		}
	}
	if has, err := w.keys.HasGrant(ctx, w.tenant, device, w.owner); err != nil || has {
		t.Fatalf("HasGrant: %v %v", has, err)
	}
	stats, err := w.devices.Stats(ctx, w.tenant.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range stats {
		if s.DeviceID == device.String() {
			t.Fatal("Stats counts the excluded number")
		}
	}
	members, err := w.users.Members(ctx, w.tenant, w.owner)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range members {
		for _, a := range m.DeviceAccess {
			if a.DeviceID == device {
				t.Fatal("the members list names the excluded number")
			}
		}
	}
	var used int64
	inTenantTx(ctx, t, w.pool, w.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT workspace_device_usage($1)`, w.tenant).Scan(&used)
	})
	if used != 1 {
		t.Fatalf("capacity counts %d numbers, want the live one", used)
	}
	usage, err := store.NewStorage(w.pool).UsageDetailed(ctx, w.tenant, w.owner)
	if err != nil {
		t.Fatal(err)
	}
	addsUp(t, usage, device)
	after := w.count(t, `SELECT (SELECT count(*) FROM device_key_grants WHERE device_id=$1)+(SELECT count(*) FROM device_archive_keys WHERE device_id=$1)
		+(SELECT count(*) FROM device_permissions WHERE device_id=$1)+(SELECT count(*) FROM messages WHERE device_id=$1)`, device)
	if after != before {
		t.Fatalf("the excluded number holds %d rows, had %d", after, before)
	}
}

func TestDeleteOwnerOnly(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	for _, role := range []string{"admin", "member"} {
		actor := w.person(t, role, role)
		device := w.number(t, role)
		if _, err := w.devices.Quarantine(ctx, w.tenant, actor, device, nil); !errors.Is(err, store.ErrOwnerOnly) {
			t.Fatalf("%s: %v", role, err)
		}
		if w.excluded(t, device) {
			t.Fatalf("%s excluded it", role)
		}
	}
	w.quarantine(t, w.number(t, "owner's"))

	// A personal workspace's one member is its owner.
	var personal uuid.UUID
	if err := w.pool.QueryRow(ctx, `SELECT id FROM tenants WHERE personal_owner_id=$1`, w.owner).Scan(&personal); err != nil {
		t.Fatal(err)
	}
	mine := linkedNumber(t, w.pool, personal, "Meu", "5511977776666", "200000000000001")
	if q, err := w.devices.Quarantine(ctx, personal, w.owner, mine, nil); err != nil || q.Already {
		t.Fatalf("a personal owner: %+v %v", q, err)
	}

	// A disabled owner, a demoted one, and a suspended workspace.
	second := w.person(t, "second", "owner")
	device := w.number(t, "x")
	if err := w.users.UpdateMember(ctx, w.tenant, w.owner, second, "owner", "disabled"); err != nil {
		t.Fatal(err)
	}
	if _, err := w.devices.Quarantine(ctx, w.tenant, second, device, nil); !errors.Is(err, store.ErrOwnerOnly) {
		t.Fatalf("a disabled owner: %v", err)
	}
	third := w.person(t, "third", "owner")
	if err := w.users.UpdateMember(ctx, w.tenant, w.owner, third, "admin", "active"); err != nil {
		t.Fatal(err)
	}
	if _, err := w.devices.Quarantine(ctx, w.tenant, third, device, nil); !errors.Is(err, store.ErrOwnerOnly) {
		t.Fatalf("a demoted owner: %v", err)
	}
	if _, err := w.pool.Exec(ctx, `UPDATE tenants SET status='suspended' WHERE id=$1`, w.tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := w.devices.Quarantine(ctx, w.tenant, w.owner, device, nil); !errors.Is(err, store.ErrOwnerOnly) {
		t.Fatalf("a suspended workspace: %v", err)
	}
	if w.excluded(t, device) {
		t.Fatal("a refused deletion excluded the number")
	}
}

func TestDeleteReadersAck(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	device := w.number(t, "Suporte")
	reader := w.person(t, "reader", "member")
	w.reads(t, w.owner, device)
	w.reads(t, reader, device)
	// A standing service account, and an assistant's provisional one.
	standing, err := w.users.CreateService(ctx, w.tenant, "erp", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	w.reads(t, standing.ID, device)
	secret, _, err := w.users.NewProvisionalServiceInvitation(ctx, w.tenant, w.owner)
	if err != nil {
		t.Fatal(err)
	}
	provisional, err := w.users.SignupService(ctx, secret, "mcp-x", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	w.reads(t, provisional.ID, device)

	check, err := w.devices.DeleteCheck(ctx, w.tenant, w.owner, device)
	if err != nil {
		t.Fatal(err)
	}
	if len(check.Readers) != 1 || check.Readers[0].UserID != reader {
		t.Fatalf("readers = %+v, want the member alone", check.Readers)
	}
	if len(check.ServiceAccounts) != 1 || check.ServiceAccounts[0].ID != standing.ID || check.ServiceAccounts[0].Name != "erp" {
		t.Fatalf("service accounts = %+v", check.ServiceAccounts)
	}

	_, err = w.devices.Quarantine(ctx, w.tenant, w.owner, device, nil)
	var refused *store.ErrDeviceHasReaders
	if !errors.As(err, &refused) || len(refused.Readers) != 1 || refused.Readers[0].UserID != reader {
		t.Fatalf("unacknowledged: %v", err)
	}
	if w.excluded(t, device) || w.count(t, `SELECT count(*) FROM item_events`) != 0 {
		t.Fatal("a refused deletion changed something")
	}
	// The set grew after the check.
	late := w.person(t, "late", "member")
	w.reads(t, late, device)
	if _, err := w.devices.Quarantine(ctx, w.tenant, w.owner, device, []uuid.UUID{reader}); !errors.As(err, &refused) || len(refused.Readers) != 2 {
		t.Fatalf("a grown set: %v", err)
	}
	w.quarantine(t, device, reader, late)
	if !w.excluded(t, device) {
		t.Fatal("not excluded")
	}
}

func TestDeleteIdempotent(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	device := w.number(t, "Suporte")
	check, err := w.devices.DeleteCheck(ctx, w.tenant, w.owner, device)
	if err != nil {
		t.Fatal(err)
	}
	if check.RecoverableUntilPreview.Sub(check.CheckedAt) != 30*24*time.Hour {
		t.Fatalf("preview window %v", check.RecoverableUntilPreview.Sub(check.CheckedAt))
	}
	q := w.quarantine(t, device)
	if q.Already || q.PurgeAfter.Before(check.RecoverableUntilPreview) {
		t.Fatalf("first deletion %+v, preview %v", q, check.RecoverableUntilPreview)
	}
	again := w.quarantine(t, device)
	if !again.Already || !again.DeletedAt.Equal(q.DeletedAt) || !again.PurgeAfter.Equal(q.PurgeAfter) {
		t.Fatalf("second deletion %+v", again)
	}
	if n := w.count(t, `SELECT count(*) FROM devices WHERE id=$1 AND purge_after - deleted_at = interval '30 days' AND purge_after=$2`, device, q.PurgeAfter); n != 1 {
		t.Fatal("the window is not exactly 30 days on the stored row")
	}
	if n := w.count(t, `SELECT count(*) FROM item_events WHERE type='deleted' AND item_id=$1 AND purge_after=$2 AND deleted_at=$3 AND actor_user_id=$4`,
		device, q.PurgeAfter, q.DeletedAt, w.owner); n != 1 {
		t.Fatalf("%d deleted rows with the stored dates", n)
	}
	if n := w.count(t, `SELECT count(*) FROM item_events`); n != 1 {
		t.Fatalf("%d event rows", n)
	}
	excluded, err := w.devices.GetExcluded(ctx, w.tenant, w.owner, device)
	if err != nil || !excluded.PurgeAfter.Equal(q.PurgeAfter) || !excluded.Unlinked {
		t.Fatalf("GetExcluded %+v %v", excluded, err)
	}
	admin := w.person(t, "admin", "admin")
	if _, err := w.devices.GetExcluded(ctx, w.tenant, admin, device); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an admin learns of the excluded number: %v", err)
	}
}

func TestDeleteBumpsOthersNotActor(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	device := w.number(t, "Suporte")
	reader := w.person(t, "reader", "member")
	service, err := w.users.CreateService(ctx, w.tenant, "erp", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	bystander := w.person(t, "bystander", "member")
	for _, u := range []uuid.UUID{w.owner, reader, service.ID} {
		w.reads(t, u, device)
	}
	key, err := w.apiKeys.IssueActingAsForDevices(ctx, w.tenant.String(), "restricted", store.ScopeRead, &w.owner, nil, []uuid.UUID{device}, nil)
	if err != nil {
		t.Fatal(err)
	}
	keyVersion := func() (v int64) {
		if err := w.pool.QueryRow(ctx, `SELECT access_version FROM api_keys WHERE id=$1`, w.keyID(ctx, t, key)).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	versions := map[uuid.UUID]int64{}
	for _, u := range []uuid.UUID{w.owner, reader, service.ID, bystander} {
		versions[u] = w.accessVersion(t, u)
	}
	kv := keyVersion()
	w.quarantine(t, device, reader)
	for _, u := range []uuid.UUID{reader, service.ID} {
		if w.accessVersion(t, u) <= versions[u] {
			t.Fatalf("%s was not bumped", u)
		}
	}
	for _, u := range []uuid.UUID{w.owner, bystander} {
		if got := w.accessVersion(t, u); got != versions[u] {
			t.Fatalf("%s was bumped: %d -> %d", u, versions[u], got)
		}
	}
	if keyVersion() <= kv {
		t.Fatal("the restricted key was not bumped")
	}
}

func TestDeleteEndsAssistantsAndKeepsKeys(t *testing.T) {
	f := newAIFixture(t)
	ctx := context.Background()
	devices := store.NewDevices(f.pool)
	if err := devices.SetIdentity(ctx, f.tenant.String(), f.device.String(), wa.Identity{PN: types.JID{User: "5511900000011", Server: types.DefaultUserServer}}); err != nil {
		t.Fatal(err)
	}
	// A second number, with a connection that does not name the first.
	other := linkedNumber(t, f.pool, f.tenant, "Vendas", "5511900000077", "100000000000077")
	f.archiveKey(ctx, t, other, 1)
	f.ownerReads(ctx, t, f.owner, other)
	named, namedConsent := f.consentContent(ctx, t, f.owner)
	keys := f.aiKeys(ctx, t, f.owner)
	ai, aiConsent := f.consentAI(ctx, t, f.owner, keys, nil)
	unrelatedConsent := f.prepareContent(ctx, t, f.owner, withDevices(other))
	unrelated, err := f.conns.Create(ctx, f.tenant, f.owner, unrelatedConsent.in)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.conns.Activate(ctx, "enclave", unrelated.ID); err != nil {
		t.Fatal(err)
	}
	both, err := f.keys.IssueActingAsForDevices(ctx, f.tenant.String(), "both", store.ScopeRead, &f.owner, nil, []uuid.UUID{f.device, other}, nil)
	if err != nil {
		t.Fatal(err)
	}
	only, err := f.keys.IssueActingAsForDevices(ctx, f.tenant.String(), "only", store.ScopeRead, &f.owner, nil, []uuid.UUID{f.device}, nil)
	if err != nil {
		t.Fatal(err)
	}
	all, err := f.keys.Issue(ctx, f.tenant.String(), "all")
	if err != nil {
		t.Fatal(err)
	}
	keyOf := func(key string) uuid.UUID {
		v, err := f.keys.VerifyScoped(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		return v.ID
	}
	bothID, onlyID, allID := keyOf(both), keyOf(only), keyOf(all)
	var bothVersion int64
	if err := f.pool.QueryRow(ctx, `SELECT access_version FROM api_keys WHERE id=$1`, bothID).Scan(&bothVersion); err != nil {
		t.Fatal(err)
	}

	check, err := devices.DeleteCheck(ctx, f.tenant, f.owner, f.device)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]string{}
	for _, a := range check.Assistants {
		kinds[a.ID.String()] = a.Kind
	}
	if kinds[named.ID] != "assistant" || kinds[ai.ID] != "ai" || len(kinds) != 2 {
		t.Fatalf("preflight assistants = %+v", check.Assistants)
	}
	onlyNumber := map[string]bool{}
	for _, k := range check.Keys {
		onlyNumber[k.Name] = k.OnlyNumber
	}
	if len(onlyNumber) != 2 || onlyNumber["both"] || !onlyNumber["only"] {
		t.Fatalf("preflight keys = %+v", check.Keys)
	}
	if len(check.AllNumberKeys) != 1 || check.AllNumberKeys[0].Name != "all" {
		t.Fatalf("preflight all-number keys = %+v", check.AllNumberKeys)
	}

	q, err := devices.Quarantine(ctx, f.tenant, f.owner, f.device, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(q.AssistantsEnded) != 2 {
		t.Fatalf("assistants ended = %+v", q.AssistantsEnded)
	}
	narrowed := []string{}
	for _, k := range q.KeysNarrowed {
		narrowed = append(narrowed, k.Name)
	}
	slices.Sort(narrowed)
	if !slices.Equal(narrowed, []string{"both", "only"}) {
		t.Fatalf("keys narrowed = %v", narrowed)
	}
	connection := func(id string) (status, reason string) {
		t.Helper()
		if err := f.pool.QueryRow(ctx, `SELECT status, coalesce(revoke_reason, '') FROM mcp_connections WHERE id=$1`, id).Scan(&status, &reason); err != nil {
			t.Fatal(err)
		}
		return status, reason
	}
	for _, id := range []string{named.ID, ai.ID} {
		if status, reason := connection(id); status != "revoked" || reason != store.ReasonAccessLost {
			t.Fatalf("connection %s: %s %s", id, status, reason)
		}
	}
	for _, service := range []uuid.UUID{namedConsent.service, aiConsent.service} {
		if tr := f.trace(ctx, t, service); tr.grants+tr.permissions+tr.memberships+tr.liveKeys != 0 {
			t.Fatalf("an ended connection's service account remains: %+v", tr)
		}
	}
	if status, _ := connection(unrelated.ID); status != "active" {
		t.Fatalf("the unrelated connection: %s", status)
	}
	var revoked int
	var restricted bool
	var version int64
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE revoked_at IS NOT NULL), bool_and(devices_restricted) FILTER (WHERE id <> $3),
		max(access_version) FILTER (WHERE id = $1) FROM api_keys WHERE id IN ($1,$2,$3)`, bothID, onlyID, allID).Scan(&revoked, &restricted, &version); err != nil {
		t.Fatal(err)
	}
	if revoked != 0 || !restricted || version <= bothVersion {
		t.Fatalf("keys: %d revoked, restricted %v, version %d (was %d)", revoked, restricted, version, bothVersion)
	}
	for id, want := range map[uuid.UUID]bool{bothID: true, onlyID: false, allID: true} {
		if ok, err := f.keys.AllowsDevice(ctx, id, f.tenant, other); err != nil || ok != want {
			t.Fatalf("key %s on the other number: %v %v", id, ok, err)
		}
		if ok, err := f.keys.AllowsDevice(ctx, id, f.tenant, f.device); err != nil || ok {
			t.Fatalf("key %s reaches the excluded number: %v %v", id, ok, err)
		}
	}

	if _, err := devices.Recover(ctx, f.tenant, f.owner, f.device); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[uuid.UUID]bool{bothID: false, onlyID: false, allID: true} {
		if ok, err := f.keys.AllowsDevice(ctx, id, f.tenant, f.device); err != nil || ok != want {
			t.Fatalf("after the recovery, key %s: %v %v", id, ok, err)
		}
	}
	if status, _ := connection(named.ID); status != "revoked" {
		t.Fatal("a recovery brought an assistant connection back")
	}
}

// An excluded number's AI usage keeps its lines for the totals, but only an
// owner sees which number they belong to.
func TestAIUsageFoldsExcludedForNonOwners(t *testing.T) {
	f := newAIFixture(t)
	ctx := context.Background()
	devices := store.NewDevices(f.pool)
	if err := devices.SetIdentity(ctx, f.tenant.String(), f.device.String(), wa.Identity{PN: types.JID{User: "5511900000011", Server: types.DefaultUserServer}}); err != nil {
		t.Fatal(err)
	}
	admin := f.member(t, "admin")
	conn, _ := f.consentAI(ctx, t, f.owner, f.aiKeys(ctx, t, f.owner), nil)
	if err := f.ai.RecordAIUsage(ctx, f.tenant, conn.ID, store.AIUsage{DeviceID: f.device, Feature: "audio", Provider: "google", Model: geminiModel,
		Origin: "connector", RequesterID: f.owner, Items: 1, ChargedTokens: 100}); err != nil {
		t.Fatal(err)
	}
	device := func(viewer uuid.UUID) uuid.UUID {
		t.Helper()
		rows, err := f.ai.AIUsageMonth(ctx, f.tenant, viewer, true, time.Now())
		if err != nil || len(rows) != 1 || rows[0].ChargedTokens != 100 {
			t.Fatalf("usage = %+v %v", rows, err)
		}
		return rows[0].DeviceID
	}
	if device(admin) != f.device {
		t.Fatal("control: an admin does not see a live number's id")
	}
	if _, err := devices.Quarantine(ctx, f.tenant, f.owner, f.device, nil); err != nil {
		t.Fatal(err)
	}
	if got := device(f.owner); got != f.device {
		t.Fatalf("an owner sees %s", got)
	}
	if got := device(admin); got != uuid.Nil {
		t.Fatalf("an admin sees the excluded number's id %s", got)
	}
}
