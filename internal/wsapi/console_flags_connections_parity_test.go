package wsapi_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/authapi"
	"whatserver2/internal/numberacts"
	"whatserver2/internal/store"
	"whatserver2/internal/wsapi"
)

// The person's own connections (the owner's Q8, DS47) through Wappie's
// own screen and the console's runners: PUT …/permissions without read,
// item.flags_drop of read and item.access_remove, and the socket's lone
// grant.revoke (DS48), each on its own number with the same connections,
// by the same admin, must leave the same rows and tell the readers of the
// same ended connections. Every one of the
// person's that held the number ends access_lost whole, one that also
// reaches another number too (the platform's 0061); another person's
// connection and a workspace key keep the number. With Read already gone,
// a raise of send ends nothing on either side, and a change that leaves no
// flag ends them as a remove does: the screen's PUT with no flag and the
// console's drop of send, the last flag, alike. A dormant grant's deletion
// ends nothing, on the screen and through grant.revoke alike.

// tells records the connections a route or a runner told readers about.
type tells struct {
	mu   sync.Mutex
	told []string
}

func (r *tells) TellRevoked(_ context.Context, reader, id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.told = append(r.told, reader+"/"+id)
}

func (r *tells) take() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.told
	r.told = nil
	return out
}

var (
	_ authapi.Readers    = (*tells)(nil)
	_ numberacts.Readers = (*tells)(nil)
	_ wsapi.MCPReaders   = (*tells)(nil)
)

// connParity is the flags parity world whose route and runner tell.
type connParity struct {
	*flagsParity
	told  *tells
	conns *store.MCPConnections
}

func newConnParity(t *testing.T) *connParity {
	t.Helper()
	told := &tells{}
	p := newParityWith(t, told)
	p.runner.Readers = told
	mux := http.NewServeMux()
	(&authapi.Handler{Users: p.users, Keys: store.NewKeys(p.pool), Devices: p.devices, AccessChanged: p.srv.RevalidateAccess,
		Readers: told}).Mount(mux)
	auth := httptest.NewServer(mux)
	t.Cleanup(auth.Close)
	return &connParity{flagsParity: &flagsParity{parity: p, auth: auth}, told: told, conns: store.NewMCPConnections(p.pool)}
}

// connect records and activates a connection actor consents to on
// devices: a content one with its own service account, read-only with one
// grant per number, or a metadata one.
func (c *connParity) connect(t *testing.T, actor uuid.UUID, content bool, devices ...uuid.UUID) (string, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	in20 := time.Now().Add(20 * time.Minute)
	in := store.CreateMCPConnection{RequestID: uuid.NewString(), ClientName: "Claude", RedirectHost: "claude.ai",
		DeviceCount: len(devices), ReaderKID: "0123456789abcdef", ExpiresAt: time.Now().Add(30 * 24 * time.Hour)}
	var service uuid.UUID
	var actsAs *uuid.UUID
	reader := store.HostedReader
	if content {
		pub := make([]byte, 32)
		if _, err := rand.Read(pub); err != nil {
			t.Fatal(err)
		}
		secret, _, err := c.users.NewProvisionalServiceInvitation(ctx, c.tenant, actor)
		if err != nil {
			t.Fatal(err)
		}
		svc, err := c.users.SignupService(ctx, secret, "mcp-"+hex.EncodeToString(pub[:4]), pub)
		if err != nil {
			t.Fatal(err)
		}
		service, actsAs, reader = svc.ID, &svc.ID, "enclave"
		for _, d := range devices {
			if err := c.users.SetDevicePermission(ctx, c.tenant, actor, store.DevicePermission{DeviceID: d, UserID: service, Read: true}); err != nil {
				t.Fatal(err)
			}
			if err := store.NewKeys(c.pool).PutGrant(ctx, store.Grant{TenantID: c.tenant, DeviceID: d, UserID: service, Epoch: 1,
				SealedDSK: []byte("sealed to the attested key")}, &actor); err != nil {
				t.Fatal(err)
			}
		}
		in.Reader, in.Kind, in.ServiceUserID = reader, store.KindContent, service
		in.KeyMode, in.ConsentVersion, in.ReaderPublicKey = store.KeyModeEphemeral, store.ContentConsentVersion, pub
	}
	key, err := c.keys.IssueActingAsForDevices(ctx, c.tenant.String(), "assistant", store.ScopeRead, &actor, actsAs, devices, &in20)
	if err != nil {
		t.Fatal(err)
	}
	in.KeyPrefix, _, _ = strings.Cut(key, ".")
	conn, err := c.conns.Create(ctx, c.tenant, actor, in)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.conns.Activate(ctx, reader, conn.ID); err != nil {
		t.Fatal(err)
	}
	return conn.ID, service
}

// connSet is what one path's person made: on number, the one whose Read
// goes; both reaches the shared number too, theirs is the owner's.
type connSet struct {
	person, number             uuid.UUID
	both, only, meta, theirs   string
	bothService, theirsService uuid.UUID
	rest                       uuid.UUID
}

func (c *connParity) set(t *testing.T, person, shared uuid.UUID, label string) connSet {
	t.Helper()
	s := connSet{person: person, number: c.linkedDevice(t, label)}
	c.reads(t, c.owner, s.number)
	c.reads(t, person, s.number)
	c.reads(t, person, shared)
	s.both, s.bothService = c.connect(t, person, true, s.number, shared)
	s.only, _ = c.connect(t, person, true, s.number)
	s.meta, _ = c.connect(t, person, false, s.number)
	s.theirs, s.theirsService = c.connect(t, c.owner, true, s.number)
	rest, err := c.keys.IssueActingAsForDevices(context.Background(), c.tenant.String(), "rest", store.ScopeRead, &person, nil,
		[]uuid.UUID{s.number}, nil)
	if err != nil {
		t.Fatal(err)
	}
	prefix, _, _ := strings.Cut(rest, ".")
	c.scoped(context.Background(), t, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT id FROM api_keys WHERE prefix = $1`, prefix).Scan(&s.rest)
	})
	return s
}

// left is what a path left of a set, in terms the three paths share.
type left struct {
	Both, Only, Meta, Theirs   string
	BothService, TheirsService held
	Rest                       bool
	PersonGrants               int
	Told                       []string
}

func (c *connParity) left(t *testing.T, s connSet) left {
	t.Helper()
	ctx := context.Background()
	row := func(id string) string {
		var status, reason string
		var count int
		var reaches bool
		c.scoped(ctx, t, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT status, coalesce(revoke_reason, ''), device_count,
				EXISTS (SELECT 1 FROM api_key_devices x WHERE x.api_key_id = c.api_key_id AND x.device_id = $2)
				FROM mcp_connections c WHERE id = $1`, id, s.number).Scan(&status, &reason, &count, &reaches)
		})
		return fmt.Sprintf("%s %s %d %v", status, reason, count, reaches)
	}
	allows, err := c.keys.AllowsDevice(ctx, s.rest, c.tenant, s.number)
	if err != nil {
		t.Fatal(err)
	}
	roles := map[string]string{s.both: "both", s.only: "only", s.meta: "meta", s.theirs: "theirs"}
	told := []string{}
	for _, e := range c.told.take() {
		reader, id, _ := strings.Cut(e, "/")
		told = append(told, reader+"/"+roles[id])
	}
	slices.Sort(told)
	return left{Both: row(s.both), Only: row(s.only), Meta: row(s.meta), Theirs: row(s.theirs),
		BothService: c.held(t, s.number, s.bothService), TheirsService: c.held(t, s.number, s.theirsService),
		Rest: allows, PersonGrants: c.held(t, s.number, s.person).Grants, Told: told}
}

// endAll ends the workspace's live connections, through the console's
// own revoke, so the next set stays under the workspace's cap.
func (c *connParity) endAll(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	rows, err := c.pool.Query(ctx, `SELECT id::text FROM mcp_connections WHERE tenant_id = $1 AND status IN ('pending', 'active', 'reseal')`, c.tenant)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if _, err := c.conns.Revoke(ctx, c.tenant, c.owner, id); err != nil {
			t.Fatal(err)
		}
	}
}

func TestConsoleParityOwnConnections(t *testing.T) {
	c := newConnParity(t)
	ctx := context.Background()
	admin, adminToken := c.person(t, "bia", "admin")
	adminSub := c.link(t, admin, "admin")
	shared := c.linkedDevice(t, "Shared")
	c.reads(t, c.owner, shared)
	want := left{
		Both: "revoked access_lost 2 true", Only: "revoked access_lost 1 true", Meta: "revoked access_lost 1 true", Theirs: "active  1 true",
		BothService: held{}, TheirsService: held{Read: true, Grants: 1},
		Rest: true, Told: []string{"enclave/both", "enclave/only", store.HostedReader + "/meta"},
	}

	// A drop of send on the screen and in the console takes nothing off.
	person, _ := c.person(t, "caio", "admin")
	s := c.set(t, person, shared, "Send")
	if fo := c.put(t, adminToken, s.number, person, true, false, false); fo != "ok" {
		t.Fatalf("the screen's drop of send: %s", fo)
	}
	if fo := c.put(t, adminToken, s.number, person, true, true, false); fo != "ok" {
		t.Fatalf("the screen's raise of send: %s", fo)
	}
	if co := c.outcome(c.runner.FlagsDrop(ctx, c.command(t, kc.OpItemFlagsDrop, admin, adminSub), s.number, person, //nolint:contextcheck // the world's helpers run on a context of their own
		[]string{kc.CanRead, kc.CanSend}, []string{kc.CanRead})); co != "ok" {
		t.Fatalf("the console's drop of send: %s", co)
	}
	kept := left{Both: "active  2 true", Only: "active  1 true", Meta: "active  1 true", Theirs: "active  1 true",
		BothService: held{Read: true, Grants: 1}, TheirsService: held{Read: true, Grants: 1}, Rest: true, PersonGrants: 1, Told: []string{}}
	if got := c.left(t, s); fmt.Sprint(got) != fmt.Sprint(kept) {
		t.Fatalf("a drop of send: left %+v, want %+v", got, kept)
	}
	c.endAll(t)

	paths := map[string]func(s connSet) string{
		"the screen without read": func(s connSet) string {
			return c.put(t, adminToken, s.number, s.person, false, true, false)
		},
		"a drop of read": func(s connSet) string {
			return c.outcome(c.runner.FlagsDrop(ctx, c.command(t, kc.OpItemFlagsDrop, admin, adminSub), s.number, s.person, //nolint:contextcheck // the world's helpers run on a context of their own
				[]string{kc.CanRead, kc.CanSend}, []string{kc.CanSend}))
		},
		"a remove": func(s connSet) string {
			return c.outcome(c.runner.AccessRemove(ctx, c.command(t, kc.OpItemAccessRemove, admin, adminSub), s.number, s.person)) //nolint:contextcheck // the world's helpers run on a context of their own
		},
		// The socket's grant.revoke, the Read flag kept: no grant at the
		// number's epoch is left, so Read is gone (the platform's 0061,
		// QF3, DS48).
		"a lone grant.revoke": func(s connSet) string {
			return frameOutcome(t, ask(t, c.console, wsapi.Hello{Session: adminToken}, wsapi.TypeGrantRevoke,
				wsapi.GrantRevoke{DeviceID: s.number.String(), UserID: s.person.String()}), wsapi.TypeReaders)
		},
	}
	for _, name := range []string{"the screen without read", "a drop of read", "a remove", "a lone grant.revoke"} {
		person, _ := c.person(t, strings.ReplaceAll(name, " ", "-"), "admin")
		s := c.set(t, person, shared, name)
		if out := paths[name](s); out != "ok" {
			t.Fatalf("%s: %s", name, out)
		}
		if got := c.left(t, s); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("%s: left %+v, want %+v", name, got, want)
		}
		if h := c.held(t, s.number, person); name == "a lone grant.revoke" && !h.Read {
			t.Fatalf("%s took the Read flag: %+v", name, h)
		}
		c.endAll(t)
	}

	// Read gone before DS47 (the Read flag off, send off or kept, the
	// grants deleted, the connections left as they were).
	keptGone := kept
	keptGone.PersonGrants = 0
	gone := map[string]struct {
		send   bool
		change func(s connSet) string
		want   left
	}{
		"the screen's raise of send": {false, func(s connSet) string { return c.put(t, adminToken, s.number, s.person, false, true, false) }, keptGone},
		"the console's raise of send": {false, func(s connSet) string {
			return c.outcome(c.runner.FlagsRaise(ctx, c.command(t, kc.OpItemFlagsRaise, admin, adminSub), s.number, s.person, //nolint:contextcheck // the world's helpers run on a context of their own
				[]string{}, []string{kc.CanSend}))
		}, keptGone},
		"the screen with no flag": {false, func(s connSet) string { return c.put(t, adminToken, s.number, s.person, false, false, false) }, want},
		"the screen's drop of send to none": {true, func(s connSet) string {
			return c.put(t, adminToken, s.number, s.person, false, false, false)
		}, want},
		"the console's drop of send to none": {true, func(s connSet) string {
			return c.outcome(c.runner.FlagsDrop(ctx, c.command(t, kc.OpItemFlagsDrop, admin, adminSub), s.number, s.person, //nolint:contextcheck // the world's helpers run on a context of their own
				[]string{kc.CanSend}, []string{}))
		}, want},
		"a remove with read gone": {false, paths["a remove"], want},
	}
	for _, name := range []string{"the screen's raise of send", "the console's raise of send", "the screen with no flag",
		"the screen's drop of send to none", "the console's drop of send to none", "a remove with read gone"} {
		person, _ := c.person(t, strings.ReplaceAll(name, " ", "-"), "admin")
		s := c.set(t, person, shared, name)
		c.scoped(ctx, t, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `UPDATE device_permissions SET can_read = false, can_send = $3 WHERE device_id = $1 AND user_id = $2`,
				s.number, person, gone[name].send); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `DELETE FROM device_key_grants WHERE device_id = $1 AND user_id = $2`, s.number, person)
			return err
		})
		if out := gone[name].change(s); out != "ok" {
			t.Fatalf("%s: %s", name, out)
		}
		if got := c.left(t, s); fmt.Sprint(got) != fmt.Sprint(gone[name].want) {
			t.Fatalf("%s: left %+v, want %+v", name, got, gone[name].want)
		}
		c.endAll(t)
	}

	// A dormant grant (the Read flag off, the grant left, before DS47):
	// the screen without Read and a lone grant.revoke have no Read to
	// take. Both delete the grant and end nothing (DS48).
	dormant := map[string]func(s connSet) string{
		"the screen's raise of send on a dormant grant": func(s connSet) string {
			return c.put(t, adminToken, s.number, s.person, false, true, false)
		},
		"a grant.revoke of a dormant grant": paths["a lone grant.revoke"],
	}
	for _, name := range []string{"the screen's raise of send on a dormant grant", "a grant.revoke of a dormant grant"} {
		person, _ := c.person(t, strings.ReplaceAll(name, " ", "-"), "admin")
		s := c.set(t, person, shared, name)
		c.scoped(ctx, t, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE device_permissions SET can_read = false WHERE device_id = $1 AND user_id = $2`, s.number, person)
			return err
		})
		if out := dormant[name](s); out != "ok" {
			t.Fatalf("%s: %s", name, out)
		}
		if got := c.left(t, s); fmt.Sprint(got) != fmt.Sprint(keptGone) {
			t.Fatalf("%s: left %+v, want %+v", name, got, keptGone)
		}
		c.endAll(t)
	}
}

// TestGrantFramesConnectionAccount: the socket's grant frames and the
// screen's PUT on an assistant connection's own account (DS48). A
// grant.add of a number its key does not name is not_authorized, and so
// is a PUT of Read there (403); nothing is recorded. A grant.revoke of
// the account's grant on its number ends the connection whole,
// access_lost, and tells its reader, where it once narrowed it; so does a
// PUT that takes the account's Read.
func TestGrantFramesConnectionAccount(t *testing.T) {
	c := newConnParity(t)
	ctx := context.Background()
	person, _ := c.person(t, "caio", "admin")
	number, shared := c.linkedDevice(t, "Number"), c.linkedDevice(t, "Shared")
	for _, d := range []uuid.UUID{number, shared} {
		c.reads(t, c.owner, d)
		c.reads(t, person, d)
	}
	id, account := c.connect(t, person, true, number)
	owner := wsapi.Hello{Session: c.token}

	f := ask(t, c.console, owner, wsapi.TypeGrantAdd, wsapi.GrantRequest{DeviceID: shared.String(), UserID: account.String(), Epoch: 1,
		SealedDSK: []byte("sealed")})
	if got := frameOutcome(t, f, wsapi.TypeReaders); got != kc.CodeNotAuthorized {
		t.Fatalf("a grant.add of a number its key does not name: %s", got)
	}
	if got := c.put(t, c.token, shared, account, true, false, false); got != "not_authorized" {
		t.Fatalf("a PUT of Read on a number its key does not name: %s", got)
	}
	if h := c.held(t, shared, account); h != (held{}) {
		t.Fatalf("the account holds %+v on the shared number", h)
	}

	// The screen's PUT without Read on the account of a second
	// connection: it ends, and its reader is told.
	second, secondAccount := c.connect(t, person, true, number)
	if got := c.put(t, c.token, number, secondAccount, false, false, false); got != "ok" {
		t.Fatalf("a PUT without Read on the account: %s", got)
	}
	if told := c.told.take(); !slices.Equal(told, []string{"enclave/" + second}) {
		t.Fatalf("told %v", told)
	}

	if got := c.revoke(t, c.token, number, account); got != "ok" {
		t.Fatalf("the account's grant.revoke: %s", got)
	}
	var status, reason string
	c.scoped(ctx, t, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT status, coalesce(revoke_reason, '') FROM mcp_connections WHERE id = $1`, id).Scan(&status, &reason)
	})
	if status != "revoked" || reason != store.ReasonAccessLost {
		t.Fatalf("the connection is %s %s", status, reason)
	}
	c.scoped(ctx, t, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT status, coalesce(revoke_reason, '') FROM mcp_connections WHERE id = $1`, second).Scan(&status, &reason)
	})
	if status != "revoked" || reason != store.ReasonAccessLost {
		t.Fatalf("the second connection is %s %s", status, reason)
	}
	if told := c.told.take(); !slices.Equal(told, []string{"enclave/" + id}) {
		t.Fatalf("told %v", told)
	}
}
