package restapi_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/store"
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
