package restapi_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/store"
	"whatserver2/internal/tokentest"
)

// setupKey issues an MCP setup's key on device by user, as the console's
// apikeys.create does, and its id.
func setupKey(t *testing.T, pool *pgxpool.Pool, tenant, user, device uuid.UUID) (string, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	in20 := time.Now().Add(20 * time.Minute)
	keys := store.NewAPIKeys(pool)
	key, err := keys.IssueAsked(ctx, tenant.String(), "MCP · Claude", store.ScopeRead, &user, nil, []uuid.UUID{device}, &in20)
	if err != nil {
		t.Fatal(err)
	}
	v, err := keys.VerifyScoped(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, v.ID
}

// TestASetupKeyWorksOnlyThroughItsConnectionOnREST (the plan's 7.3): with
// tokens on, a setup's key that no connection names gets the one 401 an
// unknown key gets; once a connection names it, and with tokens off, it
// lists the numbers.
func TestASetupKeyWorksOnlyThroughItsConnectionOnREST(t *testing.T) {
	r := newTokenREST(t)
	device := r.w.Number("Vendas")
	unbound, _ := setupKey(t, r.pool, r.w.Tenant, r.w.Owner, device)
	bound, id := setupKey(t, r.pool, r.w.Tenant, r.w.Owner, device)
	r.w.Exec(`INSERT INTO mcp_connections (tenant_id, request_id, api_key_id, created_by, client_name, redirect_host,
		device_count, reader_kid, status, expires_at) VALUES ($1, $2, $3, $4, 'Claude', 'claude.ai', 1, '0123456789abcdef', 'pending',
		clock_timestamp() + interval '1 day')`, r.w.Tenant, uuid.NewString(), id, r.w.Owner)
	if code, body := r.do(t, "/v1/devices", bearer(unbound)...); code != http.StatusUnauthorized || body != tokenUnauthorized {
		t.Fatalf("an unbound setup's key with tokens on: %d %q", code, body)
	}
	if code, body := r.do(t, "/v1/devices", bearer(bound)...); code != http.StatusOK {
		t.Fatalf("a bound one: %d %s", code, body)
	}
	r.w.Exec(`UPDATE contract_token_state SET mode = 'off'`)
	if code, body := r.do(t, "/v1/devices", bearer(unbound)...); code != http.StatusOK {
		t.Fatalf("an unbound setup's key with tokens off: %d %s", code, body)
	}
}

// TestARenewalsKeyProvesItsGrantsOnREST (the plan's 7.3, and its L8's
// limit): a content or AI renewal's new key acts as the renewal's new
// provisional account, and the enclave's reader lists its grants with it
// (GET /v1/grants) before the renewal is recorded and the ledger names
// the key. With tokens on it works unbound, where a setup's key that acts
// as no account does not.
func TestARenewalsKeyProvesItsGrantsOnREST(t *testing.T) {
	r := newTokenREST(t)
	ctx := context.Background()
	device := r.w.Number("Vendas")
	secret, _, err := r.w.Users.NewProvisionalServiceInvitation(ctx, r.w.Tenant, r.w.Owner)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := r.w.Users.SignupService(ctx, secret, "mcp-renewal", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.w.Keys.PutGrant(ctx, store.Grant{TenantID: r.w.Tenant, DeviceID: device, UserID: svc.ID, Epoch: r.w.Epoch(device),
		SealedDSK: []byte("sealed to the attested key")}, &r.w.Owner); err != nil {
		t.Fatal(err)
	}
	in20 := time.Now().Add(20 * time.Minute)
	key, err := store.NewAPIKeys(r.pool).IssueAsked(ctx, r.w.Tenant.String(), "MCP · Claude", store.ScopeRead, &r.w.Owner, &svc.ID,
		[]uuid.UUID{device}, &in20)
	if err != nil {
		t.Fatal(err)
	}
	code, body := r.do(t, "/v1/grants", bearer(key)...)
	if code != http.StatusOK || !strings.Contains(body, svc.ID.String()) || !strings.Contains(body, device.String()) {
		t.Fatalf("a renewal's key proving its grants: %d %s", code, body)
	}
	unbound, _ := setupKey(t, r.pool, r.w.Tenant, r.w.Owner, device)
	if code, body := r.do(t, "/v1/grants", bearer(unbound)...); code != http.StatusUnauthorized || body != tokenUnauthorized {
		t.Fatalf("a setup's key that acts as no account: %d %q", code, body)
	}
}

// keysBeforeTheRetirement issues, as before keys were narrowed, an old
// local MCP token on device (origin legacy_mcp, as 0053's backfill found
// it) and a panel's full key, both the owner's.
func keysBeforeTheRetirement(t *testing.T, r *tokenREST, device uuid.UUID) (legacy, panel string) {
	t.Helper()
	ctx := context.Background()
	keys := store.NewAPIKeys(r.pool)
	legacy, err := keys.IssueActingAsForDevices(ctx, r.w.Tenant.String(), "MCP · Cursor", store.ScopeRead, &r.w.Owner, nil, []uuid.UUID{device}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.w.Exec(`UPDATE api_keys SET origin = 'legacy_mcp' WHERE prefix = $1`, strings.SplitN(legacy, ".", 2)[0])
	panel, err = keys.IssueActingAsForDevices(ctx, r.w.Tenant.String(), "deploy bot", store.ScopeFull, &r.w.Owner, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return legacy, panel
}

// TestTheRetirementOnREST (the plan's 7.2 and 10.7): after tokens
// retire-keys, a key it revoked gets the 401 an unknown key gets, and a
// key it spared (an old local MCP token) still lists its number.
func TestTheRetirementOnREST(t *testing.T) {
	r := newTokenREST(t)
	ctx := context.Background()
	device := r.w.Number("Vendas")
	legacy, panel := keysBeforeTheRetirement(t, r, device)
	for name, key := range map[string]string{"an old token": legacy, "a panel's key": panel} {
		if code, body := r.do(t, "/v1/devices", bearer(key)...); code != http.StatusOK {
			t.Fatalf("%s before the retirement: %d %s", name, code, body)
		}
	}
	keys := store.NewAPIKeys(r.pool)
	plan, err := keys.RetirePlan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keys.Retire(ctx, plan.Revoke, "root"); err != nil {
		t.Fatal(err)
	}
	if code, body := r.do(t, "/v1/devices", bearer(legacy)...); code != http.StatusOK || !strings.Contains(body, device.String()) {
		t.Fatalf("the old token after the retirement: %d %s", code, body)
	}
	if code, body := r.do(t, "/v1/devices", bearer(panel)...); code != http.StatusUnauthorized || body != tokenUnauthorized {
		t.Fatalf("the panel's key after the retirement: %d %q", code, body)
	}
}

// TestASelfHostedInstallationKeepsItsKeysOnREST (the plan's 10.7, the
// self-hosted regression): with the contract off, tokens off and no
// retirement, a panel's key is still issued and lists the numbers, and a
// platform token is refused.
func TestASelfHostedInstallationKeepsItsKeysOnREST(t *testing.T) {
	r := newTokenREST(t)
	ctx := context.Background()
	device := r.w.Number("Vendas")
	tok := r.w.Token(tokentest.Read(device))
	if code, body := r.do(t, "/v1/devices", bearer(tok.Text)...); code != http.StatusOK {
		t.Fatalf("the token with tokens on: %d %s", code, body)
	}
	r.w.Exec(`UPDATE contract_token_state SET mode = 'off'`)
	r.w.Exec(`UPDATE contract_state SET mode = 'off', events_paused_at = clock_timestamp()`)
	keys := store.NewAPIKeys(r.pool)
	if g, err := keys.Gate(ctx); err != nil || !g.OffThePlatform() {
		t.Fatalf("not off the platform: %+v %v", g, err)
	}
	panel, err := keys.IssueAsked(ctx, r.w.Tenant.String(), "deploy bot", store.ScopeFull, &r.w.Owner, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if code, body := r.do(t, "/v1/devices", bearer(panel)...); code != http.StatusOK || !strings.Contains(body, device.String()) {
		t.Fatalf("a panel's key: %d %s", code, body)
	}
	if code, body := r.do(t, "/v1/devices", bearer(tok.Text)...); code != http.StatusUnauthorized {
		t.Fatalf("a platform token: %d %s", code, body)
	}
}
