package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
)

func TestExpireAPIKeysMarksRevoked(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	keys := store.NewAPIKeys(pool)
	ctx := context.Background()
	tenant := newTenant(t, pool, "acme")

	in := time.Now().Add(time.Hour)
	dead, err := keys.IssueActingAsForDevices(ctx, tenant, "dead", store.ScopeRead, nil, nil, nil, &in)
	if err != nil {
		t.Fatal(err)
	}
	live, err := keys.IssueActingAsForDevices(ctx, tenant, "live", store.ScopeRead, nil, nil, nil, &in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keys.Issue(ctx, tenant, "forever"); err != nil {
		t.Fatal(err)
	}
	prefix, _, _ := strings.Cut(dead, ".")
	if _, err := pool.Exec(ctx, `UPDATE api_keys SET expires_at = now() - interval '1 hour' WHERE prefix = $1`, prefix); err != nil {
		t.Fatal(err)
	}
	n, err := store.ExpireAPIKeys(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expired %d keys, want the one past its deadline", n)
	}
	if n, err := store.ExpireAPIKeys(ctx, pool); err != nil || n != 0 {
		t.Fatalf("second pass: %d %v", n, err)
	}
	if _, err := keys.Verify(ctx, live); err != nil {
		t.Fatalf("the live key was swept: %v", err)
	}
	listed, err := keys.List(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range listed {
		if k.Prefix == prefix {
			// Revoked at the deadline, not at the sweep: the list should say
			// when the key actually stopped working.
			if k.RevokedAt.IsZero() || k.ExpiresAt == nil || !k.RevokedAt.Equal(*k.ExpiresAt) {
				t.Fatalf("revoked_at = %v, expires_at = %v", k.RevokedAt, k.ExpiresAt)
			}
		} else if !k.RevokedAt.IsZero() {
			t.Fatalf("%s revoked by the sweep", k.Name)
		}
	}
}

func TestExpireMCPConnectionsPendingAndActive(t *testing.T) {
	f := newMCPFixture(t)
	ctx := context.Background()

	staleKey, stalePrefix := f.provisionalKey(ctx, t, "stale")
	stale, err := f.conns.Create(ctx, f.tenant, f.owner, consent(stalePrefix))
	if err != nil {
		t.Fatal(err)
	}
	_, freshPrefix := f.provisionalKey(ctx, t, "fresh")
	fresh, err := f.conns.Create(ctx, f.tenant, f.owner, consent(freshPrefix))
	if err != nil {
		t.Fatal(err)
	}
	doneKey, donePrefix := f.provisionalKey(ctx, t, "done")
	done, err := f.conns.Create(ctx, f.tenant, f.owner, consent(donePrefix))
	if err != nil {
		t.Fatal(err)
	}
	_, runningPrefix := f.provisionalKey(ctx, t, "running")
	running, err := f.conns.Create(ctx, f.tenant, f.owner, consent(runningPrefix))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{done.ID, running.ID} {
		if err := f.conns.Activate(ctx, store.HostedReader, id); err != nil {
			t.Fatal(err)
		}
	}
	// A consent whose handshake never came, and one that ran its full course.
	if _, err := f.pool.Exec(ctx, `UPDATE mcp_connections SET created_at = now() - interval '30 minutes' WHERE id = $1`, stale.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE mcp_connections SET expires_at = now() - interval '1 minute' WHERE id = $1`, done.ID); err != nil {
		t.Fatal(err)
	}
	if answer, err := f.conns.Status(ctx, store.HostedReader, done.ID, nil); err != nil || answer.Status != "expired" {
		t.Fatalf("status before the sweep = %+v %v, want expired", answer, err)
	}

	n, err := store.ExpireMCPConnections(ctx, f.pool, 20*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("settled %d connections, want 2", n)
	}
	if n, err := store.ExpireMCPConnections(ctx, f.pool, 20*time.Minute); err != nil || n != 0 {
		t.Fatalf("second pass: %d %v", n, err)
	}
	want := map[string]string{stale.ID: "revoked", fresh.ID: "pending", done.ID: "expired", running.ID: "active"}
	listed, err := f.conns.List(ctx, f.tenant)
	if err != nil || len(listed) != 4 {
		t.Fatalf("list = %+v %v", listed, err)
	}
	for _, c := range listed {
		if c.Status != want[c.ID] {
			t.Errorf("%s: status %q, want %q", c.ClientName, c.Status, want[c.ID])
		}
	}
	// Both ended connections' keys went with them, through the one helper
	// every end takes; the live connections' keys are untouched.
	for name, key := range map[string]string{"stale": staleKey, "done": doneKey} {
		if _, err := f.keys.Verify(ctx, key); !errors.Is(err, store.ErrInvalidKey) {
			t.Fatalf("the %s connection's key still works: %v", name, err)
		}
	}
	keys, err := f.keys.List(ctx, f.tenant.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		ended := k.Prefix == stalePrefix || k.Prefix == donePrefix
		if ended && k.RevokedAt.IsZero() {
			t.Fatalf("%s: an ended connection's key not recorded as revoked", k.Name)
		}
		if !ended && !k.RevokedAt.IsZero() {
			t.Fatalf("%s revoked by the connection sweep", k.Name)
		}
	}
	reasons := map[string]string{}
	listed, _ = f.conns.List(ctx, f.tenant)
	for _, c := range listed {
		reasons[c.ID] = c.RevokeReason
	}
	if reasons[stale.ID] != store.ReasonPendingExpired || reasons[done.ID] != store.ReasonExpired || reasons[running.ID] != "" {
		t.Fatalf("reasons = %v", reasons)
	}
}

// The console mints the key before the person has finished consenting, with a
// twenty-minute deadline. Abandon the consent and the key dies by itself.
func TestUnlinkedProvisionalKeyDiesAfter20Min(t *testing.T) {
	f := newMCPFixture(t)
	ctx := context.Background()

	key, prefix := f.provisionalKey(ctx, t, "abandoned")
	if _, err := f.keys.Verify(ctx, key); err != nil {
		t.Fatalf("provisional key refused within its window: %v", err)
	}
	// The clock passes twenty minutes.
	if _, err := f.pool.Exec(ctx, `UPDATE api_keys SET expires_at = expires_at - interval '21 minutes' WHERE prefix = $1`, prefix); err != nil {
		t.Fatal(err)
	}
	if _, err := f.keys.Verify(ctx, key); !errors.Is(err, store.ErrInvalidKey) {
		t.Fatalf("abandoned provisional key still authenticates: %v", err)
	}
	// Too late to consent with it, too.
	if _, err := f.conns.Create(ctx, f.tenant, f.owner, consent(prefix)); !errors.Is(err, store.ErrMCPKeyUnsuitable) {
		t.Fatalf("a dead provisional key was bound: %v", err)
	}
	n, err := store.ExpireAPIKeys(ctx, f.pool)
	if err != nil || n != 1 {
		t.Fatalf("sweep: %d %v", n, err)
	}
	keys, err := f.keys.List(ctx, f.tenant.String())
	if err != nil || len(keys) != 1 || keys[0].RevokedAt.IsZero() {
		t.Fatalf("keys = %+v %v", keys, err)
	}
}
