package store_test

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/store"
)

// A key's origin and the narrowed issue (step 7's plan, 2.1 and 7.3).

// serviceOf is a service account of the workspace: provisional (a content
// consent's, with a deadline) or standing (none).
func (w *delWorld) serviceOf(t *testing.T, provisional bool) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	var secret string
	var err error
	if provisional {
		secret, _, err = w.users.NewProvisionalServiceInvitation(ctx, w.tenant, w.owner)
	} else {
		secret, _, err = w.users.NewMemberInvitation(ctx, w.tenant, w.owner, store.RoleService, "")
	}
	if err != nil {
		t.Fatal(err)
	}
	svc, err := w.users.SignupService(ctx, secret, "mcp-"+hex.EncodeToString(randomBytes(t, 4)), randomBytes(t, 32))
	if err != nil {
		t.Fatal(err)
	}
	return svc.ID
}

// originOf is the origin the store gave key, and what 0053's api_key_class
// says of it now, read in its workspace.
func (w *delWorld) originOf(t *testing.T, key string) (origin, class string) {
	t.Helper()
	prefix, _, _ := strings.Cut(key, ".")
	inTenantTx(context.Background(), t, w.pool, w.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT coalesce(origin, ''), api_key_class(k) FROM api_keys k WHERE prefix = $1`,
			prefix).Scan(&origin, &class)
	})
	return origin, class
}

// Every key gets its origin at issue: cli with no creator, mcp_setup in an
// MCP setup's shape (read, numbers, a deadline within 31 minutes of its
// issue, "MCP · …", acting as a provisional service or none), rest for
// everything else. A setup's key is what 0053's api_key_class calls one.
func TestAKeysOriginIsSetAtIssue(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	device := w.number(t, "Phone")
	devices := []uuid.UUID{device}
	provisional, standing := w.serviceOf(t, true), w.serviceOf(t, false)
	in := func(d time.Duration) *time.Time { at := time.Now().Add(d); return &at }
	owner := &w.owner

	cli, err := w.apiKeys.Issue(ctx, w.tenant.String(), "ci")
	if err != nil {
		t.Fatal(err)
	}
	if origin, class := w.originOf(t, cli); origin != store.OriginCLI || class != "cli" {
		t.Errorf("a key with no creator: %q, class %q", origin, class)
	}
	for _, c := range []struct {
		name, keyName string
		scope         store.KeyScope
		actsAs        *uuid.UUID
		devices       []uuid.UUID
		expires       *time.Time
		origin        string
	}{
		{"a setup's", "MCP · Claude", store.ScopeRead, nil, devices, in(20 * time.Minute), store.OriginMCPSetup},
		{"a content setup's", "MCP · Claude", store.ScopeRead, &provisional, devices, in(20 * time.Minute), store.OriginMCPSetup},
		{"a setup's near its bound", "MCP · Claude", store.ScopeRead, nil, devices, in(28 * time.Minute), store.OriginMCPSetup},
		{"past the bound", "MCP · Claude", store.ScopeRead, nil, devices, in(35 * time.Minute), store.OriginREST},
		{"no deadline", "MCP · Claude", store.ScopeRead, nil, devices, nil, store.OriginREST},
		{"another name", "assistant", store.ScopeRead, nil, devices, in(20 * time.Minute), store.OriginREST},
		{"no numbers", "MCP · Claude", store.ScopeRead, nil, nil, in(20 * time.Minute), store.OriginREST},
		{"send", "MCP · Claude", store.ScopeSend, nil, devices, in(20 * time.Minute), store.OriginREST},
		{"a standing service", "MCP · Claude", store.ScopeRead, &standing, devices, in(20 * time.Minute), store.OriginREST},
		{"a panel's", "deploy bot", store.ScopeFull, nil, nil, nil, store.OriginREST},
	} {
		key, err := w.apiKeys.IssueActingAsForDevices(ctx, w.tenant.String(), c.keyName, c.scope, owner, c.actsAs, c.devices, c.expires)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		origin, class := w.originOf(t, key)
		if origin != c.origin {
			t.Errorf("%s: origin %q, want %q", c.name, origin, c.origin)
		}
		// The class does not look at what a key acts as, and calls a new
		// key in the old local token's shape legacy_mcp; at issue it is
		// rest (the plan's 2.1).
		if want := map[string]string{"no deadline": "legacy_mcp", "a standing service": "mcp_setup"}[c.name]; want != "" {
			if class != want {
				t.Errorf("%s: api_key_class says %q, want %q", c.name, class, want)
			}
		} else if class != origin {
			t.Errorf("%s: origin %q, but api_key_class says %q", c.name, origin, class)
		}
	}
	listed, err := w.apiKeys.List(ctx, w.tenant.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range listed {
		if k.Origin == "" {
			t.Errorf("%s is listed with no origin", k.Prefix)
		}
	}
}

// While keys are narrowed (tokens on, or a retirement made), a key asked
// for is issued only in an MCP setup's shape: any other, the command
// line's included, is refused before anything is written. Off the
// narrowing every shape is issued as before.
func TestAnAskedKeyIsNarrowedWhileTokensAreOn(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	devices := []uuid.UUID{w.number(t, "Phone")}
	standing := w.serviceOf(t, false)
	in20 := time.Now().Add(20 * time.Minute)
	ask := func(keyName string, creator, actsAs *uuid.UUID, devices []uuid.UUID, expires *time.Time) error {
		_, err := w.apiKeys.IssueAsked(ctx, w.tenant.String(), keyName, store.ScopeRead, creator, actsAs, devices, expires)
		return err
	}
	count := func() int {
		var n int
		if err := w.pool.QueryRow(ctx, `SELECT count(*) FROM api_keys`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	check := func(state string, narrowed bool) {
		t.Helper()
		if got, err := w.apiKeys.KeysNarrowed(ctx); err != nil || got != narrowed {
			t.Fatalf("%s: KeysNarrowed %v %v, want %v", state, got, err, narrowed)
		}
		if err := ask("MCP · Claude", &w.owner, nil, devices, &in20); err != nil {
			t.Errorf("%s: a setup's key: %v", state, err)
		}
		for name, err := range map[string]func() error{
			"a panel's":          func() error { return ask("deploy bot", &w.owner, nil, nil, nil) },
			"the command line's": func() error { return ask("cli", nil, nil, nil, nil) },
			"a standing service": func() error { return ask("MCP · Claude", &w.owner, &standing, devices, &in20) },
		} {
			before := count()
			got := err()
			if narrowed && !errors.Is(got, store.ErrTokensAreThePlatforms) {
				t.Errorf("%s: %s: %v, want ErrTokensAreThePlatforms", state, name, got)
			}
			if !narrowed && got != nil {
				t.Errorf("%s: %s: %v", state, name, got)
			}
			if narrowed && count() != before {
				t.Errorf("%s: %s: a refused key was written", state, name)
			}
		}
		// IssueActingAsForDevices asks nothing of the narrowing: the tests'
		// own keys and nothing a person reaches.
		if _, err := w.apiKeys.IssueActingAsForDevices(ctx, w.tenant.String(), "fixture", store.ScopeFull, &w.owner, nil, nil, nil); err != nil {
			t.Errorf("%s: an unasked key: %v", state, err)
		}
	}
	check("tokens off", false)
	w.exec(t, `UPDATE contract_token_state SET mode = 'on'`)
	check("tokens on", true)
	w.exec(t, `UPDATE contract_token_state SET mode = 'off'`)
	w.exec(t, `INSERT INTO key_retirements (revoked, services_removed, services_kept, report, by) VALUES (0, 0, 0, '{}', 'root')`)
	check("tokens off after a retirement", true)
}

// bind names key in a connection of the workspace, as a consent does.
func (w *delWorld) bind(t *testing.T, key string) {
	t.Helper()
	w.exec(t, `INSERT INTO mcp_connections (tenant_id, request_id, api_key_id, created_by, client_name, redirect_host,
		device_count, reader_kid, status, expires_at) VALUES ($1, $2, $3, $4, 'Claude', 'claude.ai', 1, '0123456789abcdef', 'pending',
		clock_timestamp() + interval '1 day')`, w.tenant, uuid.NewString(), w.keyID(context.Background(), t, key), w.owner)
}

// TestASetupKeyWorksOnlyThroughItsConnection (the plan's 7.3, L8): while
// keys are narrowed, VerifyClient (REST, media, upload, the socket's
// hello) refuses a live setup's key that acts as no account and that no
// connection names, as it refuses an unknown key; once a connection names
// it, it works. A renewal's new key, which acts as a provisional account
// and which the reader proves its grants with before the ledger names it,
// works unbound. Off the narrowing every one works as before; VerifyScoped
// (the MCP side) never asks.
func TestASetupKeyWorksOnlyThroughItsConnection(t *testing.T) {
	w := newDelWorld(t)
	ctx := context.Background()
	devices := []uuid.UUID{w.number(t, "Phone")}
	in20 := time.Now().Add(20 * time.Minute)
	setup := func() string {
		key, err := w.apiKeys.IssueAsked(ctx, w.tenant.String(), "MCP · Claude", store.ScopeRead, &w.owner, nil, devices, &in20)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	unbound, bound := setup(), setup()
	w.bind(t, bound)
	rest, err := w.apiKeys.IssueAsked(ctx, w.tenant.String(), "deploy bot", store.ScopeFull, &w.owner, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	// A renewal's new key acts as the renewal's new provisional account,
	// and the reader proves its grants with it before the ledger names it.
	provisional := w.serviceOf(t, true)
	renewal, err := w.apiKeys.IssueAsked(ctx, w.tenant.String(), "MCP · Claude", store.ScopeRead, &w.owner, &provisional, devices, &in20)
	if err != nil {
		t.Fatal(err)
	}
	if origin, _ := w.originOf(t, renewal); origin != store.OriginMCPSetup {
		t.Fatalf("a renewal's key: origin %q", origin)
	}
	check := func(state string, narrowed bool) {
		t.Helper()
		for name, key := range map[string]string{"an unbound setup's key": unbound, "a bound one": bound, "a panel's key": rest,
			"a renewal's unbound key": renewal} {
			_, err := w.apiKeys.VerifyClient(ctx, key)
			refused := narrowed && key == unbound
			if refused && !errors.Is(err, store.ErrInvalidKey) || !refused && err != nil {
				t.Errorf("%s: %s: VerifyClient %v, refused %v", state, name, err, refused)
			}
			if _, err := w.apiKeys.VerifyScoped(ctx, key); err != nil {
				t.Errorf("%s: %s: VerifyScoped %v", state, name, err)
			}
		}
	}
	check("tokens off", false)
	w.exec(t, `UPDATE contract_token_state SET mode = 'on'`)
	check("tokens on", true)
	w.exec(t, `UPDATE contract_token_state SET mode = 'off'`)
	w.exec(t, `INSERT INTO key_retirements (revoked, services_removed, services_kept, report, by) VALUES (0, 0, 0, '{}', 'root')`)
	check("after a retirement", true)
	// Bound later, it works from then on.
	w.bind(t, unbound)
	if _, err := w.apiKeys.VerifyClient(ctx, unbound); err != nil {
		t.Errorf("bound later: %v", err)
	}
}
