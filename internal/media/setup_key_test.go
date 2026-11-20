package media_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/store"
)

// TestASetupKeyWorksOnlyThroughItsConnectionOnMedia (the plan's 7.3): with
// tokens on, a setup's key that no connection names gets the 401 an
// unknown key gets on /v1/media; once a connection names it, it fetches.
func TestASetupKeyWorksOnlyThroughItsConnectionOnMedia(t *testing.T) {
	m := newTokenMedia(t)
	w := m.w
	ctx := context.Background()
	device := w.Number("Vendas")
	uid := m.attachment(t, device, 100)
	in20 := time.Now().Add(20 * time.Minute)
	keys := store.NewAPIKeys(m.pool)
	key, err := keys.IssueAsked(ctx, w.Tenant.String(), "MCP · Claude", store.ScopeRead, &w.Owner, nil, []uuid.UUID{device}, &in20)
	if err != nil {
		t.Fatal(err)
	}
	v, err := keys.VerifyScoped(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	_, unknown := m.do(t, http.MethodGet, "/v1/media/"+uid.String(), nil, "Bearer 0a1b2c3d.unknown")
	if code, body := m.do(t, http.MethodGet, "/v1/media/"+uid.String(), nil, "Bearer "+key); code != http.StatusUnauthorized || body != unknown {
		t.Fatalf("an unbound setup's key: %d %q, want %q", code, body, unknown)
	}
	w.Exec(`INSERT INTO mcp_connections (tenant_id, request_id, api_key_id, created_by, client_name, redirect_host,
		device_count, reader_kid, status, expires_at) VALUES ($1, $2, $3, $4, 'Claude', 'claude.ai', 1, '0123456789abcdef', 'pending',
		clock_timestamp() + interval '1 day')`, w.Tenant, uuid.NewString(), v.ID, w.Owner)
	// A connection's key asks MCP's gate (its consent's attachments).
	m.handler.Gate = func(context.Context, uuid.UUID, uuid.UUID) (bool, error) { return true, nil }
	if code, body := m.do(t, http.MethodGet, "/v1/media/"+uid.String(), nil, "Bearer "+key); code != http.StatusOK || len(body) != 100 {
		t.Fatalf("a bound one: %d %d bytes", code, len(body))
	}
}
