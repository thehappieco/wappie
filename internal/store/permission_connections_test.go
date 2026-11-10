package store_test

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/store"
)

// A person's lost Read on a number ends their own MCP connections and AI
// integrations that held it, whole (the owner's Q8 and the platform's
// 0061, DS47), on Wappie's own screen and in the console's drop of read
// and remove alike: one that also holds other numbers ends access_lost as
// one with this number alone does, and nobody else's connection, no
// workspace key and no legacy token loses anything. Every consent,
// metadata included, and every renewal needs Read on every number.

// ownWorld is the acts' world with connections and integrations made in it.
type ownWorld struct {
	*actWorld
	conns *store.MCPConnections
	ai    *store.AI
	// shared is a second number every path's person and the owner read.
	shared uuid.UUID
	// items are each person's keychain items, by provider.
	items map[uuid.UUID]map[string]uuid.UUID
}

func newOwnWorld(t *testing.T) *ownWorld {
	t.Helper()
	w := ownOf(newActWorld(t))
	w.shared = w.number(t, "Shared")
	w.reads(t, w.owner, w.shared)
	return w
}

// ownOf makes connections in an acts' world.
func ownOf(w *actWorld) *ownWorld {
	return &ownWorld{actWorld: w, conns: store.NewMCPConnections(w.pool), ai: store.NewAI(w.pool), items: map[uuid.UUID]map[string]uuid.UUID{}}
}

// aiKeysOf are actor's keychain items for the two providers aiConfigFor
// uses, made once.
func (w *ownWorld) aiKeysOf(t *testing.T, actor uuid.UUID) map[string]uuid.UUID {
	t.Helper()
	if keys, ok := w.items[actor]; ok {
		return keys
	}
	keys := map[string]uuid.UUID{}
	for _, provider := range []string{"google", "anthropic"} {
		item, err := w.ai.AddKeychainItem(context.Background(), w.tenant, actor, store.AIKeychainItem{
			ID: uuid.New(), Provider: provider, Label: provider + " key", Suffix: "a1B2",
			Envelope: append([]byte("WKC1"), randomBytes(t, 60)...),
		})
		if err != nil {
			t.Fatal(err)
		}
		keys[provider] = item.ID
	}
	w.items[actor] = keys
	return keys
}

// connect records and activates a live connection of kind that actor
// consents to on devices, as the console builds one; a content or AI one
// with its own service account, read-only with one grant per number.
func (w *ownWorld) connect(t *testing.T, actor uuid.UUID, kind string, devices ...uuid.UUID) (id string, service uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	in := w.prepare(t, actor, kind, devices...)
	conn, err := w.conns.Create(ctx, w.tenant, actor, in)
	if err != nil {
		t.Fatal(err)
	}
	reader := "enclave"
	if kind == store.KindMetadata {
		reader = store.HostedReader
	}
	if err := w.conns.Activate(ctx, reader, conn.ID); err != nil {
		t.Fatal(err)
	}
	return conn.ID, in.ServiceUserID
}

// connectMedia is connect of a content connection with attachments.
func (w *ownWorld) connectMedia(t *testing.T, actor uuid.UUID, devices ...uuid.UUID) store.MCPConnection {
	t.Helper()
	ctx := context.Background()
	in := w.prepare(t, actor, store.KindContent, devices...)
	in.Media, in.ConsentVersion = true, store.MediaConsentVersion
	conn, err := w.conns.Create(ctx, w.tenant, actor, in)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.conns.Activate(ctx, "enclave", conn.ID); err != nil {
		t.Fatal(err)
	}
	return conn
}

// renewal is what the console builds before actor renews a content
// connection on devices: a new service account and key, as prepare's.
func (w *ownWorld) renewal(t *testing.T, actor uuid.UUID, devices ...uuid.UUID) store.RenewMCPConnection {
	t.Helper()
	next := w.prepare(t, actor, store.KindContent, devices...)
	return store.RenewMCPConnection{KeyPrefix: next.KeyPrefix, ServiceUserID: next.ServiceUserID, ReaderKID: "abcdefabcdefabcd",
		ReaderPublicKey: next.ReaderPublicKey}
}

// prepare is what the console builds before actor consents to a
// connection of kind on devices: the key, and for content or AI the
// service account, read-only with one grant per number. Nothing is
// recorded yet.
func (w *ownWorld) prepare(t *testing.T, actor uuid.UUID, kind string, devices ...uuid.UUID) store.CreateMCPConnection {
	t.Helper()
	ctx := context.Background()
	in20 := time.Now().Add(20 * time.Minute)
	if kind == store.KindMetadata {
		key, err := w.apiKeys.IssueActingAsForDevices(ctx, w.tenant.String(), "assistant", store.ScopeRead, &actor, nil, devices, &in20)
		if err != nil {
			t.Fatal(err)
		}
		prefix, _, _ := strings.Cut(key, ".")
		in := consent(prefix)
		in.DeviceCount = len(devices)
		return in
	}
	c := contentConsent{actor: actor, devices: devices, grantEpoch: 1, publicKey: randomBytes(t, 32)}
	secret, _, err := w.users.NewProvisionalServiceInvitation(ctx, w.tenant, actor)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := w.users.SignupService(ctx, secret, "mcp-"+hex.EncodeToString(randomBytes(t, 4)), c.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	c.service = svc.ID
	for _, d := range devices {
		if err := w.users.SetDevicePermission(ctx, w.tenant, actor, store.DevicePermission{DeviceID: d, UserID: c.service, Read: true}); err != nil {
			t.Fatal(err)
		}
		w.grantAt(t, d, c.service, 1)
	}
	key, err := w.apiKeys.IssueActingAsForDevices(ctx, w.tenant.String(), "assistant", store.ScopeRead, &actor, &c.service, devices, &in20)
	if err != nil {
		t.Fatal(err)
	}
	prefix, _, _ := strings.Cut(key, ".")
	c.in = consent(prefix)
	c.in.DeviceCount = len(devices)
	c.in.ExpiresAt = time.Now().Add(30 * 24 * time.Hour)
	c.in.Reader, c.in.Kind, c.in.ServiceUserID = "enclave", store.KindContent, c.service
	c.in.KeyMode, c.in.ConsentVersion, c.in.ReaderPublicKey = store.KeyModeEphemeral, store.ContentConsentVersion, c.publicKey
	if kind == store.KindAI {
		c.in.Kind, c.in.ClientName, c.in.RedirectHost = store.KindAI, store.AIClientName, store.AIRedirectHost
		c.in.RequestID = requestID(t)
		c.in.ExpiresAt = time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
		cfg, err := store.ParseAIConfig(aiConfigFor(t, c, w.aiKeysOf(t, actor), nil))
		if err != nil {
			t.Fatal(err)
		}
		c.in.AIConfig = &cfg
	}
	return c.in
}

// endAll ends every live connection of the workspace, through the
// console's own revokes.
func (w *ownWorld) endAll(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	rows, err := w.pool.Query(ctx, `SELECT id::text, kind FROM mcp_connections WHERE tenant_id = $1 AND status IN ('pending', 'active', 'reseal')`,
		w.tenant)
	if err != nil {
		t.Fatal(err)
	}
	type live struct{ id, kind string }
	all, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (live, error) {
		var l live
		return l, row.Scan(&l.id, &l.kind)
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range all {
		if l.kind == store.KindAI {
			_, _, err = w.conns.RevokeAI(ctx, w.tenant, w.owner, l.id, false)
		} else {
			_, err = w.conns.Revoke(ctx, w.tenant, w.owner, l.id)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

// draft leaves a draft of connection on device waiting for a person.
func (w *ownWorld) draft(t *testing.T, connection string, device uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	w.execOne(t, `INSERT INTO mcp_outbound (id, tenant_id, connection_id, device_id, chat_key, kind, status, sealed, epoch, expires_at)
		VALUES ($1, $2, $3, $4, 'chat', 'draft', 'pending', '\x01', 1, now() + interval '1 day')`, id, w.tenant, connection, device)
	return id
}

// ownSet is what one path's person made: on number, the one whose Read
// goes, and on the shared one.
type ownSet struct {
	person, number uuid.UUID
	// both, aiBoth and metaBoth reach number and shared; only, aiOnly and
	// meta number alone; theirs is the owner's, on number.
	both, aiBoth, metaBoth, only, aiOnly, meta, theirs string
	services                                           map[string]uuid.UUID
	// rest is the person's workspace key on both numbers, legacy their
	// legacy MCP token on number, acting as its standing account.
	rest, legacy, standing uuid.UUID
	drafted, draftedShared uuid.UUID
}

// own makes a path's set: person, an admin who reads number and shared.
func (w *ownWorld) own(t *testing.T, person uuid.UUID, label string) ownSet {
	t.Helper()
	ctx := context.Background()
	s := ownSet{person: person, number: w.number(t, label), services: map[string]uuid.UUID{}}
	w.reads(t, w.owner, s.number)
	w.reads(t, person, s.number)
	w.reads(t, person, w.shared)
	var svc uuid.UUID
	s.both, svc = w.connect(t, person, store.KindContent, s.number, w.shared)
	s.services[s.both] = svc
	s.aiBoth, svc = w.connect(t, person, store.KindAI, s.number, w.shared)
	s.services[s.aiBoth] = svc
	s.only, svc = w.connect(t, person, store.KindContent, s.number)
	s.services[s.only] = svc
	s.aiOnly, svc = w.connect(t, person, store.KindAI, s.number)
	s.services[s.aiOnly] = svc
	s.meta, _ = w.connect(t, person, store.KindMetadata, s.number)
	s.metaBoth, _ = w.connect(t, person, store.KindMetadata, s.number, w.shared)
	s.theirs, svc = w.connect(t, w.owner, store.KindContent, s.number)
	s.services[s.theirs] = svc
	s.drafted, s.draftedShared = w.draft(t, s.both, s.number), w.draft(t, s.both, w.shared)
	rest, err := w.apiKeys.IssueActingAsForDevices(ctx, w.tenant.String(), "rest", store.ScopeRead, &person, nil,
		[]uuid.UUID{s.number, w.shared}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.rest = w.keyID(ctx, t, rest)
	// The legacy shape: "MCP · …", read, restricted, no deadline, no
	// connection, acting as a standing mcp-… account that reads the number.
	secret, _, err := w.users.NewMemberInvitation(ctx, w.tenant, w.owner, store.RoleService, "")
	if err != nil {
		t.Fatal(err)
	}
	standing, err := w.users.SignupService(ctx, secret, "mcp-"+hex.EncodeToString(randomBytes(t, 4)), randomBytes(t, 32))
	if err != nil {
		t.Fatal(err)
	}
	s.standing = standing.ID
	w.reads(t, s.standing, s.number)
	legacy, err := w.apiKeys.IssueActingAsForDevices(ctx, w.tenant.String(), "MCP · Claude", store.ScopeRead, &person, &s.standing,
		[]uuid.UUID{s.number}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.legacy = w.keyID(ctx, t, legacy)
	return s
}

// ownRow is one connection's standing after a path: keyLive is its key
// not revoked.
type ownRow struct {
	status, reason string
	devices        []uuid.UUID
	count          int
	keyLive        bool
}

func (w *ownWorld) row(t *testing.T, id string) ownRow {
	t.Helper()
	ctx := context.Background()
	var r ownRow
	w.scoped(t, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT c.status, coalesce(c.revoke_reason, ''), c.device_count, k.revoked_at IS NULL
			FROM mcp_connections c JOIN api_keys k ON k.id = c.api_key_id WHERE c.id = $1`, id).
			Scan(&r.status, &r.reason, &r.count, &r.keyLive); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT x.device_id FROM mcp_connections c JOIN api_key_devices x ON x.api_key_id = c.api_key_id
			WHERE c.id = $1 ORDER BY x.device_id`, id)
		if err != nil {
			return err
		}
		r.devices, err = pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		return err
	})
	return r
}

// holds counts what user holds on device: its permission row and grants.
func (w *ownWorld) holds(t *testing.T, user, device uuid.UUID) (permissions, grants int) {
	t.Helper()
	return w.count(t, `SELECT count(*) FROM device_permissions WHERE user_id = $1 AND device_id = $2`, user, device),
		w.grantsOf(t, device, user)
}

func (w *ownWorld) allows(t *testing.T, key, device uuid.UUID) bool {
	t.Helper()
	ok, err := w.apiKeys.AllowsDevice(context.Background(), key, w.tenant, device)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

func (w *ownWorld) draftStatus(t *testing.T, id uuid.UUID) (status string, sealed bool) {
	t.Helper()
	w.scoped(t, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT status, sealed IS NOT NULL FROM mcp_outbound WHERE id = $1`, id).Scan(&status, &sealed)
	})
	return status, sealed
}

// untouched checks that nothing of s changed: every connection live with
// its numbers and its key, every account holding what it held.
func (w *ownWorld) untouched(t *testing.T, what string, s ownSet) {
	t.Helper()
	for _, id := range []string{s.both, s.aiBoth, s.metaBoth, s.only, s.aiOnly, s.meta, s.theirs} {
		if r := w.row(t, id); r.status != "active" || !r.keyLive || !slices.Contains(r.devices, s.number) {
			t.Fatalf("%s: connection %s %+v", what, id, r)
		}
	}
	for id, svc := range s.services {
		if p, g := w.holds(t, svc, s.number); p != 1 || g != 1 {
			t.Fatalf("%s: connection %s's account holds %d permissions and %d grants on the number", what, id, p, g)
		}
	}
	if status, _ := w.draftStatus(t, s.drafted); status != "pending" {
		t.Fatalf("%s: the draft is %s", what, status)
	}
}

// left checks what a path that took Read off s.person leaves, and the
// connections it says it ended: every one of the person's that held the
// number, ended whole, those that also held the shared one too.
func (w *ownWorld) left(t *testing.T, what string, s ownSet, ended []store.EndedConnection) {
	t.Helper()
	ctx := context.Background()
	got := map[string]string{}
	for _, e := range ended {
		got[e.ID] = e.Reader
	}
	want := map[string]string{s.both: "enclave", s.aiBoth: "enclave", s.only: "enclave", s.aiOnly: "enclave",
		s.meta: store.HostedReader, s.metaBoth: store.HostedReader}
	if len(ended) != len(want) || !maps.Equal(got, want) {
		t.Fatalf("%s: ended %+v, want %v", what, ended, want)
	}
	// Ended access_lost whole, the shared number with it: its key revoked,
	// its account gone on both numbers.
	for id := range want {
		if r := w.row(t, id); r.status != "revoked" || r.reason != store.ReasonAccessLost || r.keyLive {
			t.Fatalf("%s: connection %s %+v", what, id, r)
		}
		if svc, ok := s.services[id]; ok {
			if tr := w.trace(t, svc); tr != (serviceTrace{}) {
				t.Fatalf("%s: an ended connection's account remains: %+v", what, tr)
			}
		}
	}
	// Its drafts go with it, the shared number's too.
	for _, draft := range []uuid.UUID{s.drafted, s.draftedShared} {
		if status, sealed := w.draftStatus(t, draft); status != "revoked" || sealed {
			t.Fatalf("%s: a draft is %s, sealed %v", what, status, sealed)
		}
	}
	// Nobody else's, and no key behind no connection.
	if r := w.row(t, s.theirs); r.status != "active" || !r.keyLive || !slices.Contains(r.devices, s.number) {
		t.Fatalf("%s: the owner's connection %+v", what, r)
	}
	if p, g := w.holds(t, s.services[s.theirs], s.number); p != 1 || g != 1 {
		t.Fatalf("%s: the owner's connection's account lost the number: %d %d", what, p, g)
	}
	if !w.allows(t, s.rest, s.number) || !w.allows(t, s.legacy, s.number) {
		t.Fatalf("%s: a workspace key or a legacy token lost the number", what)
	}
	if p, g := w.holds(t, s.standing, s.number); p != 1 || g != 1 {
		t.Fatalf("%s: the legacy token's account lost the number: %d %d", what, p, g)
	}
	// The person: no grant left on the number, the shared one still read.
	if g := w.grantsOf(t, s.number, s.person); g != 0 {
		t.Fatalf("%s: the person keeps %d grants", what, g)
	}
	if g := w.grantsOf(t, w.shared, s.person); g != 1 {
		t.Fatalf("%s: the person's grant on the shared number: %d", what, g)
	}
	// No integration of theirs answers for either number any more.
	policy := store.AIPolicy{Allowed: true}
	for _, device := range []uuid.UUID{s.number, w.shared} {
		if _, err := w.conns.PickAIAuthorization(ctx, w.tenant, s.person, device, "audio", store.AIOriginConsole, policy); !errors.Is(err, store.ErrAINotEnabled) {
			t.Fatalf("%s: an integration still answers for %s: %v", what, device, err)
		}
	}
}

func (w *ownWorld) trace(t *testing.T, user uuid.UUID) serviceTrace {
	t.Helper()
	var s serviceTrace
	w.scoped(t, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT
			(SELECT count(*) FROM device_key_grants WHERE tenant_id=$1 AND user_id=$2),
			(SELECT count(*) FROM device_permissions WHERE tenant_id=$1 AND user_id=$2),
			(SELECT count(*) FROM workspace_memberships WHERE tenant_id=$1 AND user_id=$2),
			(SELECT count(*) FROM api_keys WHERE tenant_id=$1 AND acts_as=$2 AND revoked_at IS NULL)`, w.tenant, user).
			Scan(&s.grants, &s.permissions, &s.memberships, &s.liveKeys)
	})
	return s
}

// TestOwnConnectionsLeaveWithRead: Wappie's screen without Read, the
// console's drop of read and its remove, each on its own number, leave
// the same rows: every connection and integration of the person that held
// the number ended whole, those holding the shared number too (the
// platform's 0061); a raise and a drop of send leave everything as it was.
func TestOwnConnectionsLeaveWithRead(t *testing.T) {
	ctx := context.Background()
	w := newOwnWorld(t)
	admin, adminSub := w.actor(t, "admin", "admin")

	// A raise and a drop of send take nothing off anything.
	person, _ := w.actor(t, "admin", "admin")
	s := w.own(t, person, "Screen")
	if ended, err := w.users.SetDevicePermissionEnded(ctx, w.tenant, admin, store.DevicePermission{DeviceID: s.number, UserID: person,
		Read: true, Send: true, Manage: true}); err != nil || len(ended) != 0 {
		t.Fatalf("a raise on the screen: %v %v", ended, err)
	}
	w.untouched(t, "a raise on the screen", s)
	if ended, err := w.users.SetDevicePermissionEnded(ctx, w.tenant, admin, store.DevicePermission{DeviceID: s.number, UserID: person,
		Read: true, Manage: true}); err != nil || len(ended) != 0 {
		t.Fatalf("a drop of send on the screen: %v %v", ended, err)
	}
	w.untouched(t, "a drop of send on the screen", s)
	act, wrote, ended, err := w.c.RunFlagsDrop(ctx, w.command(t, kc.OpItemFlagsDrop, admin, adminSub), s.number, person,
		[]string{kc.CanRead, kc.CanManage}, []string{kc.CanRead})
	if ranAct(t, "a drop of manage", act, err); !wrote || len(ended) != 0 {
		t.Fatalf("a drop of manage: wrote %v, ended %v", wrote, ended)
	}
	w.untouched(t, "a drop of manage", s)
	act, wrote, err = w.c.RunFlagsRaise(ctx, w.command(t, kc.OpItemFlagsRaise, admin, adminSub), s.number, person,
		[]string{kc.CanRead}, []string{kc.CanRead, kc.CanSend})
	if ranAct(t, "a raise of send", act, err); !wrote {
		t.Fatal("a raise of send wrote nothing")
	}
	w.untouched(t, "a raise of send", s)

	// Wappie's screen without Read.
	ended, err = w.users.SetDevicePermissionEnded(ctx, w.tenant, admin, store.DevicePermission{DeviceID: s.number, UserID: person, Send: true})
	if err != nil {
		t.Fatal(err)
	}
	w.left(t, "the screen", s, ended)
	// Again: nothing more to take, nothing more ended.
	if ended, err := w.users.SetDevicePermissionEnded(ctx, w.tenant, admin, store.DevicePermission{DeviceID: s.number, UserID: person}); err != nil ||
		len(ended) != 0 {
		t.Fatalf("the screen again: %v %v", ended, err)
	}

	// The console's drop of read.
	person, _ = w.actor(t, "admin", "admin")
	s = w.own(t, person, "Drop")
	act, wrote, ended, err = w.c.RunFlagsDrop(ctx, w.command(t, kc.OpItemFlagsDrop, admin, adminSub), s.number, person,
		[]string{kc.CanRead, kc.CanSend}, []string{kc.CanSend})
	if ranAct(t, "a drop of read", act, err); !wrote {
		t.Fatal("a drop of read wrote nothing")
	}
	w.left(t, "a drop of read", s, ended)

	// The console's remove.
	person, _ = w.actor(t, "admin", "admin")
	s = w.own(t, person, "Remove")
	act, wrote, ended, err = w.c.RunAccessRemove(ctx, w.command(t, kc.OpItemAccessRemove, admin, adminSub), s.number, person)
	if ranAct(t, "a remove", act, err); !wrote {
		t.Fatal("a remove wrote nothing")
	}
	w.left(t, "a remove", s, ended)
}

// TestOwnConnectionsKeptByRefusals: an act or a screen change that is
// refused (the last reader, an admin on an owner's flags) takes nothing
// off the person's connections, and reports none ended.
func TestOwnConnectionsKeptByRefusals(t *testing.T) {
	ctx := context.Background()
	w := newOwnWorld(t)
	admin, adminSub := w.actor(t, "admin", "admin")

	// Once the owner's key and the legacy token's account's are gone, the
	// person holds the number's last: the connections' accounts never
	// count.
	person, _ := w.actor(t, "admin", "admin")
	s := w.own(t, person, "Last")
	for _, holder := range []uuid.UUID{w.owner, s.standing} {
		w.execOne(t, `DELETE FROM device_key_grants WHERE device_id = $1 AND user_id = $2`, s.number, holder)
	}
	if _, err := w.users.SetDevicePermissionEnded(ctx, w.tenant, admin, store.DevicePermission{DeviceID: s.number, UserID: person}); !errors.Is(err, store.ErrLastDeviceReader) {
		t.Fatalf("the screen on the last reader: %v", err)
	}
	act, wrote, ended, err := w.c.RunAccessRemove(ctx, w.command(t, kc.OpItemAccessRemove, admin, adminSub), s.number, person)
	if err != nil || act.Result.Code != kc.CodeLastReader || wrote || len(ended) != 0 {
		t.Fatalf("a remove of the last reader: %+v %v %v %v", act, wrote, ended, err)
	}
	w.untouched(t, "the last reader", s)

	// An owner's own connections: an admin may not take an owner's Read.
	owner, _ := w.actor(t, "owner", "owner")
	o := w.own(t, owner, "Owner")
	if _, err := w.users.SetDevicePermissionEnded(ctx, w.tenant, admin, store.DevicePermission{DeviceID: o.number, UserID: owner}); !errors.Is(err, store.ErrOwnerTarget) {
		t.Fatalf("an admin's screen on an owner: %v", err)
	}
	act, wrote, ended, err = w.c.RunFlagsDrop(ctx, w.command(t, kc.OpItemFlagsDrop, admin, adminSub), o.number, owner,
		[]string{kc.CanRead}, []string{})
	if err != nil || act.Result.Code != kc.CodeNotAuthorized || wrote || len(ended) != 0 {
		t.Fatalf("an admin's drop of an owner: %+v %v %v %v", act, wrote, ended, err)
	}
	w.untouched(t, "an admin on an owner", o)
}

// TestOwnConnectionsConsentAfterDrop: a content, AI or metadata consent
// the console prepared while the person read the number, and recorded
// after their Read went (the screen, a drop of read or a remove), is
// refused, so no live connection of theirs reaches the number (DS47, the
// platform's 0061). One on a number they still read is recorded, of
// either kind.
func TestOwnConnectionsConsentAfterDrop(t *testing.T) {
	ctx := context.Background()
	w := newOwnWorld(t)
	admin, adminSub := w.actor(t, "admin", "admin")
	for _, name := range []string{"the screen", "a drop of read", "a remove"} {
		person, _ := w.actor(t, "admin", "admin")
		number := w.number(t, name)
		w.reads(t, w.owner, number)
		w.reads(t, person, number)
		w.reads(t, person, w.shared)
		prepared := map[string]store.CreateMCPConnection{
			"content":  w.prepare(t, person, store.KindContent, number, w.shared),
			"ai":       w.prepare(t, person, store.KindAI, number),
			"metadata": w.prepare(t, person, store.KindMetadata, number, w.shared),
		}
		still := map[string]store.CreateMCPConnection{
			"content":  w.prepare(t, person, store.KindContent, w.shared),
			"metadata": w.prepare(t, person, store.KindMetadata, w.shared),
		}
		switch name {
		case "the screen":
			if _, err := w.users.SetDevicePermissionEnded(ctx, w.tenant, admin, store.DevicePermission{DeviceID: number, UserID: person, Send: true}); err != nil {
				t.Fatal(err)
			}
		case "a drop of read":
			act, _, _, err := w.c.RunFlagsDrop(ctx, w.command(t, kc.OpItemFlagsDrop, admin, adminSub), number, person, []string{kc.CanRead}, []string{})
			ranAct(t, name, act, err)
		case "a remove":
			act, _, _, err := w.c.RunAccessRemove(ctx, w.command(t, kc.OpItemAccessRemove, admin, adminSub), number, person)
			ranAct(t, name, act, err)
		}
		for kind, in := range prepared {
			if _, err := w.conns.Create(ctx, w.tenant, person, in); !errors.Is(err, store.ErrMCPKeyUnsuitable) {
				t.Errorf("%s: the %s consent prepared before it: %v", name, kind, err)
			}
		}
		if t.Failed() {
			return
		}
		for kind, in := range still {
			if _, err := w.conns.Create(ctx, w.tenant, person, in); err != nil {
				t.Fatalf("%s: a %s consent on a number still read: %v", name, kind, err)
			}
		}
		if n := w.count(t, `SELECT count(*) FROM mcp_connections c JOIN api_key_devices x ON x.api_key_id = c.api_key_id
			WHERE c.created_by = $1 AND x.device_id = $2 AND c.status IN ('pending', 'active', 'reseal')`, person, number); n != 0 {
			t.Fatalf("%s: %d of the person's connections reach the number", name, n)
		}
		w.endAll(t)
	}
}

// TestOwnConnectionsRenewNeedsRead: a renewal is held to the consent's
// rule. A content connection left from before DS47 on a number whose Read
// its person lost cannot be renewed; with Read back, it can.
func TestOwnConnectionsRenewNeedsRead(t *testing.T) {
	ctx := context.Background()
	w := newOwnWorld(t)
	person, _ := w.actor(t, "admin", "admin")
	number := w.number(t, "Renew")
	w.reads(t, w.owner, number)
	w.reads(t, person, number)
	id, _ := w.connect(t, person, store.KindContent, number)
	// Read gone the way the screen took it before DS47: the flag off, the
	// grants deleted, the connection left as it was.
	w.execOne(t, `UPDATE device_permissions SET can_read = false WHERE device_id = $1 AND user_id = $2`, number, person)
	w.execOne(t, `DELETE FROM device_key_grants WHERE device_id = $1 AND user_id = $2`, number, person)
	if _, err := w.conns.Renew(ctx, w.tenant, person, id, w.renewal(t, person, number)); !errors.Is(err, store.ErrMCPKeyUnsuitable) {
		t.Fatalf("a renewal without Read: %v", err)
	}
	if r := w.row(t, id); r.status != "active" {
		t.Fatalf("the refused renewal changed the connection: %+v", r)
	}
	w.reads(t, person, number)
	if _, err := w.conns.Renew(ctx, w.tenant, person, id, w.renewal(t, person, number)); err != nil {
		t.Fatalf("a renewal with Read back: %v", err)
	}
}

// TestOwnConnectionsReadAlreadyGone: with the person's Read already gone
// and a connection left on the number from before DS47, a change that
// keeps send or manage (a raise, a drop of the other) ends nothing, on the
// screen as in the acts; one that leaves no flag ends them, as a remove
// does.
func TestOwnConnectionsReadAlreadyGone(t *testing.T) {
	ctx := context.Background()
	w := newOwnWorld(t)
	admin, adminSub := w.actor(t, "admin", "admin")
	gone := func(label string) (person, number uuid.UUID, only, meta string) {
		person, _ = w.actor(t, "admin", "admin")
		number = w.number(t, label)
		w.reads(t, w.owner, number)
		w.reads(t, person, number)
		only, _ = w.connect(t, person, store.KindContent, number)
		meta, _ = w.connect(t, person, store.KindMetadata, number)
		w.execOne(t, `UPDATE device_permissions SET can_read = false WHERE device_id = $1 AND user_id = $2`, number, person)
		w.execOne(t, `DELETE FROM device_key_grants WHERE device_id = $1 AND user_id = $2`, number, person)
		return person, number, only, meta
	}
	live := func(what string, ids ...string) {
		t.Helper()
		for _, id := range ids {
			if r := w.row(t, id); r.status != "active" || len(r.devices) != 1 {
				t.Fatalf("%s: connection %s %+v", what, id, r)
			}
		}
	}
	lost := func(what string, ended []store.EndedConnection, ids ...string) {
		t.Helper()
		if len(ended) != len(ids) {
			t.Fatalf("%s: ended %+v", what, ended)
		}
		for _, id := range ids {
			if r := w.row(t, id); r.status != "revoked" || r.reason != store.ReasonAccessLost {
				t.Fatalf("%s: connection %s %+v", what, id, r)
			}
		}
	}

	// The screen: a raise of send, then a raise of manage with a drop of
	// send, keep them; no flag left ends them.
	person, number, only, meta := gone("Screen")
	for _, p := range []store.DevicePermission{{Send: true}, {Manage: true}} {
		p.DeviceID, p.UserID = number, person
		if ended, err := w.users.SetDevicePermissionEnded(ctx, w.tenant, admin, p); err != nil || len(ended) != 0 {
			t.Fatalf("the screen's %+v: %v %v", p, ended, err)
		}
		live(fmt.Sprintf("the screen's %+v", p), only, meta)
	}
	ended, err := w.users.SetDevicePermissionEnded(ctx, w.tenant, admin, store.DevicePermission{DeviceID: number, UserID: person})
	if err != nil {
		t.Fatal(err)
	}
	lost("the screen with no flag", ended, only, meta)

	// The acts: a raise of send and a drop of it keep them; a remove ends
	// them.
	person, number, only, meta = gone("Acts")
	act, _, err := w.c.RunFlagsRaise(ctx, w.command(t, kc.OpItemFlagsRaise, admin, adminSub), number, person, []string{}, []string{kc.CanSend})
	ranAct(t, "a raise of send", act, err)
	live("a raise of send", only, meta)
	act, _, ended, err = w.c.RunFlagsDrop(ctx, w.command(t, kc.OpItemFlagsDrop, admin, adminSub), number, person, []string{kc.CanSend}, []string{})
	if ranAct(t, "a drop of send", act, err); len(ended) != 0 {
		t.Fatalf("a drop of send ended %+v", ended)
	}
	live("a drop of send", only, meta)
	act, _, ended, err = w.c.RunAccessRemove(ctx, w.command(t, kc.OpItemAccessRemove, admin, adminSub), number, person)
	ranAct(t, "a remove", act, err)
	lost("a remove", ended, only, meta)
}

// TestOwnConnectionsEndWhole: every connection and integration of the
// person that held the number ends whole when their Read on it goes,
// whatever other number it holds and whatever it is (media, content, AI,
// metadata): narrowed, it could never renew (the platform's 0061). One that
// never held the number keeps going, and the person consents again for the
// number they still read, never for the one they lost.
func TestOwnConnectionsEndWhole(t *testing.T) {
	ctx := context.Background()
	w := newOwnWorld(t)
	admin, _ := w.actor(t, "admin", "admin")
	person, _ := w.actor(t, "admin", "admin")
	number := w.number(t, "Whole")
	w.reads(t, w.owner, number)
	w.reads(t, person, number)
	w.reads(t, person, w.shared)
	media := w.connectMedia(t, person, number, w.shared)
	plain, plainService := w.connect(t, person, store.KindContent, number, w.shared)
	ai, aiService := w.connect(t, person, store.KindAI, number, w.shared)
	meta, _ := w.connect(t, person, store.KindMetadata, number, w.shared)
	elsewhere, elsewhereService := w.connect(t, person, store.KindContent, w.shared)
	ended, err := w.users.SetDevicePermissionEnded(ctx, w.tenant, admin, store.DevicePermission{DeviceID: number, UserID: person, Send: true})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range ended {
		got[e.ID] = e.Reader
	}
	want := map[string]string{media.ID: "enclave", plain: "enclave", ai: "enclave", meta: store.HostedReader}
	if len(ended) != len(want) || !maps.Equal(got, want) {
		t.Fatalf("ended %+v, want %v", ended, want)
	}
	for id := range want {
		if r := w.row(t, id); r.status != "revoked" || r.reason != store.ReasonAccessLost || r.keyLive {
			t.Fatalf("connection %s %+v", id, r)
		}
	}
	for _, svc := range []uuid.UUID{*media.ServiceUserID, plainService, aiService} {
		if tr := w.trace(t, svc); tr != (serviceTrace{}) {
			t.Fatalf("an ended connection's account remains: %+v", tr)
		}
	}
	if r := w.row(t, elsewhere); r.status != "active" || !r.keyLive || !slices.Equal(r.devices, []uuid.UUID{w.shared}) {
		t.Fatalf("the connection that never held the number %+v", r)
	}
	if p, g := w.holds(t, elsewhereService, w.shared); p != 1 || g != 1 {
		t.Fatalf("its account on the shared number: %d %d", p, g)
	}
	// Consenting again: the shared number, of every kind; never the one
	// lost.
	w.connect(t, person, store.KindContent, w.shared)
	w.connect(t, person, store.KindAI, w.shared)
	w.connect(t, person, store.KindMetadata, w.shared)
	for _, kind := range []string{store.KindContent, store.KindAI, store.KindMetadata} {
		if _, err := w.conns.Create(ctx, w.tenant, person, w.prepare(t, person, kind, number, w.shared)); !errors.Is(err, store.ErrMCPKeyUnsuitable) {
			t.Fatalf("a %s consent again on the number lost: %v", kind, err)
		}
	}
}

// TestOwnConnectionsMetadataNeedsRead: a metadata consent, as a content
// one, names only numbers its person reads now: the Read flag and a grant
// at the number's current epoch (the platform's 0061, as a token needs
// Read for metadata, 0053). The flag alone, a grant alone, a grant of an
// epoch the number left, or one number of two not read is refused
// (key_unsuitable) and records nothing. A metadata connection has no
// renewal of its own: a reconnection that replaces it is a new consent,
// held to the same rule.
func TestOwnConnectionsMetadataNeedsRead(t *testing.T) {
	ctx := context.Background()
	w := newOwnWorld(t)
	person, _ := w.actor(t, "admin", "admin")
	number := w.number(t, "Metadata")
	rotated := w.number(t, "Rotated")
	for _, d := range []uuid.UUID{number, rotated} {
		w.reads(t, w.owner, d)
	}
	w.reads(t, person, w.shared)
	refused := func(what string, in store.CreateMCPConnection) {
		t.Helper()
		if _, err := w.conns.Create(ctx, w.tenant, person, in); !errors.Is(err, store.ErrMCPKeyUnsuitable) {
			t.Fatalf("%s: %v", what, err)
		}
	}
	refused("no Read at all", w.prepare(t, person, store.KindMetadata, number))
	// Send alone, then the key shared: the row keeps Read off.
	w.set(t, number, person, false, true, false)
	w.grantAt(t, number, person, 1)
	refused("a grant without the flag", w.prepare(t, person, store.KindMetadata, number))
	w.execOne(t, `DELETE FROM device_key_grants WHERE device_id = $1 AND user_id = $2`, number, person)
	w.set(t, number, person, true, false, false)
	refused("the flag without a grant", w.prepare(t, person, store.KindMetadata, number))
	// A grant of epoch 1 on a number now at epoch 2.
	w.reads(t, person, rotated)
	w.epochKey(t, rotated, 2)
	refused("a grant of an epoch the number left", w.prepare(t, person, store.KindMetadata, rotated))
	w.grantAt(t, number, person, 1)
	refused("one number of two not read", w.prepare(t, person, store.KindMetadata, w.shared, rotated))
	if n := w.count(t, `SELECT count(*) FROM mcp_connections WHERE created_by = $1`, person); n != 0 {
		t.Fatalf("the refused consents left %d rows", n)
	}

	// Read on every number: recorded.
	w.grantAt(t, rotated, person, 2)
	id, _ := w.connect(t, person, store.KindMetadata, number, w.shared, rotated)
	if _, err := w.conns.Renewable(ctx, w.tenant, person, id); !errors.Is(err, store.ErrMCPConnectionNotFound) {
		t.Fatalf("a metadata connection renewable: %v", err)
	}
	// Read gone the way the screen took it before DS47: the flag off, the
	// grants deleted, the connection left as it was. A reconnection that
	// would replace it is refused; with Read back, recorded.
	w.execOne(t, `UPDATE device_permissions SET can_read = false WHERE device_id = $1 AND user_id = $2`, number, person)
	w.execOne(t, `DELETE FROM device_key_grants WHERE device_id = $1 AND user_id = $2`, number, person)
	again := func() store.CreateMCPConnection {
		in := w.prepare(t, person, store.KindMetadata, number, w.shared)
		in = clientConsent(in, store.ClientCIMD, store.TrustTested)
		in.Replaces = true
		return in
	}
	refused("a reconnection without Read", again())
	w.reads(t, person, number)
	if _, err := w.conns.Create(ctx, w.tenant, person, again()); err != nil {
		t.Fatalf("a reconnection with Read back: %v", err)
	}
}
