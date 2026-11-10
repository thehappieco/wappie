package wsapi_test

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/store"
	"whatserver2/internal/wsapi"
)

// apikeys.create while the platform's tokens are on, or once the keys were
// retired (step 7's plan, 7.3 and 10.7).

// TestAPIKeyCreateIsNarrowedWhileTokensAreOn: with tokens off the generic
// create works as before; with tokens on, and after a retirement with
// tokens off again, only an MCP setup's shape is issued (read, numbers,
// 20 minutes, "MCP · …", a provisional service or none), and every other
// shape gets tokens_are_the_platforms with no key written. Each key's
// origin comes back in the reply and the listing.
func TestAPIKeyCreateIsNarrowedWhileTokensAreOn(t *testing.T) {
	c := newConsole(t)
	ctx := context.Background()
	user, err := c.users.Create(ctx, store.NewUser{TenantID: c.tenant, Email: "owner@acme.test", Role: "owner",
		AuthKey: "auth-owner", KDFSalt: make([]byte, 16), KDFParams: store.DefaultKDFParams(),
		PublicKey: make([]byte, 32), WrappedUSK: []byte("wrapped")})
	if err != nil {
		t.Fatal(err)
	}
	session, _, err := c.users.StartSession(ctx, user, "test")
	if err != nil {
		t.Fatal(err)
	}
	owner := wsapi.Hello{Session: session}
	device := c.deviceWithKey(t, "Phone")
	service := func(provisional bool) string {
		t.Helper()
		var secret string
		var err error
		if provisional {
			secret, _, err = c.users.NewProvisionalServiceInvitation(ctx, c.tenant, user.ID)
		} else {
			secret, _, err = c.users.NewMemberInvitation(ctx, c.tenant, user.ID, store.RoleService, "")
		}
		if err != nil {
			t.Fatal(err)
		}
		pub := make([]byte, 32)
		if _, err := rand.Read(pub); err != nil {
			t.Fatal(err)
		}
		svc, err := c.users.SignupService(ctx, secret, "mcp-"+uuid.NewString()[:8], pub)
		if err != nil {
			t.Fatal(err)
		}
		return svc.ID.String()
	}
	provisional, standing := service(true), service(false)
	in20 := time.Now().Add(20 * time.Minute).UTC().Format(time.RFC3339)
	setup := func(actsAs string) map[string]any {
		req := map[string]any{"name": "MCP · Claude", "scope": "read", "device_ids": []string{device}, "expires_at": in20}
		if actsAs != "" {
			req["acts_as"] = actsAs
		}
		return req
	}
	others := map[string]map[string]any{
		"a panel's full key":      {"name": "deploy bot", "scope": "full"},
		"a read key for numbers":  {"name": "reader", "scope": "read", "device_ids": []string{device}},
		"a setup's with no limit": {"name": "MCP · Claude", "scope": "read", "device_ids": []string{device}},
		"a setup's for an hour": {"name": "MCP · Claude", "scope": "read", "device_ids": []string{device},
			"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)},
		"a setup's as a standing service": setup(standing),
	}
	keys := func() int {
		listed, err := c.keys.List(ctx, c.tenant.String())
		if err != nil {
			t.Fatal(err)
		}
		return len(listed)
	}
	issued := func(state string, req map[string]any, origin string) {
		t.Helper()
		f := ask(t, c, owner, wsapi.TypeKeyCreate, req)
		if f.Type != wsapi.TypeAPIKeyNew {
			t.Fatalf("%s: %v: %s %s", state, req, f.Type, f.Payload)
		}
		if got := payload[wsapi.APIKeyCreated](t, f).Info.Origin; got != origin {
			t.Errorf("%s: %v: origin %q, want %q", state, req, got, origin)
		}
	}

	issued("tokens off", setup(""), store.OriginMCPSetup)
	issued("tokens off", setup(provisional), store.OriginMCPSetup)
	for _, req := range others {
		issued("tokens off", req, store.OriginREST)
	}
	narrowed := func(state string) {
		t.Helper()
		issued(state, setup(""), store.OriginMCPSetup)
		issued(state, setup(provisional), store.OriginMCPSetup)
		for name, req := range others {
			before := keys()
			wantError(t, ask(t, c, owner, wsapi.TypeKeyCreate, req), wsapi.ErrCodeTokensAreThePlatforms)
			if keys() != before {
				t.Errorf("%s: %s: a refused key was written", state, name)
			}
		}
	}
	exec := func(sql string) {
		t.Helper()
		if _, err := c.pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	exec(`UPDATE contract_token_state SET mode = 'on'`)
	narrowed("tokens on")
	exec(`UPDATE contract_token_state SET mode = 'off'`)
	exec(`INSERT INTO key_retirements (revoked, services_removed, services_kept, report, by) VALUES (0, 0, 0, '{}', 'root')`)
	narrowed("tokens off after a retirement")

	listed := payload[wsapi.APIKeys](t, ask(t, c, owner, wsapi.TypeKeysList, nil))
	origins := map[string]int{}
	for _, k := range listed.Keys {
		origins[k.Origin]++
	}
	// The console's own CLI key, 6 setups and 5 others.
	if origins[store.OriginCLI] != 1 || origins[store.OriginMCPSetup] != 6 || origins[store.OriginREST] != len(others) {
		t.Fatalf("the listing's origins: %v", origins)
	}
}

// TestASetupKeyWorksOnlyThroughItsConnectionOnTheSocket (the plan's 7.3):
// with tokens on, a setup's key that no connection names gets the hello's
// "invalid api key", as an unknown key does; once a connection names it,
// it is welcomed.
func TestASetupKeyWorksOnlyThroughItsConnectionOnTheSocket(t *testing.T) {
	ts := newTokenSocket(t)
	w := ts.w
	ctx := context.Background()
	device := w.Number("Vendas")
	in20 := time.Now().Add(20 * time.Minute)
	keys := store.NewAPIKeys(ts.pool)
	key, err := keys.IssueAsked(ctx, w.Tenant.String(), "MCP · Claude", store.ScopeRead, &w.Owner, nil, []uuid.UUID{device}, &in20)
	if err != nil {
		t.Fatal(err)
	}
	v, err := keys.VerifyScoped(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	_, f := ts.hello(t, wsapi.Hello{APIKey: key})
	if e := wantError(t, f, wsapi.ErrCodeUnauthorized); e.Message != "invalid api key" {
		t.Fatalf("an unbound setup's key: %q", e.Message)
	}
	w.Exec(`INSERT INTO mcp_connections (tenant_id, request_id, api_key_id, created_by, client_name, redirect_host,
		device_count, reader_kid, status, expires_at) VALUES ($1, $2, $3, $4, 'Claude', 'claude.ai', 1, '0123456789abcdef', 'pending',
		clock_timestamp() + interval '1 day')`, w.Tenant, uuid.NewString(), v.ID, w.Owner)
	if _, f := ts.hello(t, wsapi.Hello{APIKey: key}); f.Type != wsapi.TypeWelcome {
		t.Fatalf("a bound one: %s %s", f.Type, f.Payload)
	}
}

// TestARevokedKeysSocketClosesWithinASecond (step 7's plan, 7.2 and 10.7):
// tokens retire-keys runs in a process of its own, which holds no socket,
// so it closes none itself; a socket of a key it revoked closes at the
// server's next one-second check (ConnectionKey), as the store's write
// alone reaches it here.
func TestARevokedKeysSocketClosesWithinASecond(t *testing.T) {
	c := newConsole(t)
	ctx := context.Background()
	conn := dial(t, c.srv)
	send(t, conn, wsapi.TypeHello, wsapi.Hello{APIKey: c.apiKey, Version: wsapi.Version})
	if f := read(t, conn); f.Type != wsapi.TypeWelcome {
		t.Fatalf("hello: %s %s", f.Type, f.Payload)
	}
	for _, sql := range []string{
		`UPDATE contract_state SET mode = 'observe', events_from = coalesce(events_from, clock_timestamp()), events_paused_at = NULL`,
		`UPDATE contract_token_state SET mode = 'on'`,
	} {
		if _, err := c.pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	done, err := store.NewAPIKeys(c.pool).Retire(ctx, 1, "root")
	if err != nil || done.Revoke != 1 {
		t.Fatalf("the retirement: %+v %v", done, err)
	}
	expectAccessClosed(t, conn)
}
