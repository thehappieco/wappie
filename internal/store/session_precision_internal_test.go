package store

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
)

func TestSessionReplyUsesPersistedExpiryPrecision(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	var tenant uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO tenants(name) VALUES ('session precision') RETURNING id`).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	users := NewUsers(pool)
	user, err := users.Create(ctx, NewUser{
		TenantID: tenant, Email: "precision@example.com", AuthKey: "precision-proof", Role: "owner",
		KDFSalt: make([]byte, 16), KDFParams: DefaultKDFParams(), PublicKey: make([]byte, 32), WrappedUSK: []byte("wrapped-key"),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Force a fraction that Postgres cannot preserve, independently of the
	// operating system's time.Now resolution (macOS previously hid the CI bug).
	requested := time.Now().Add(SessionTTL).Truncate(time.Second).Add(123456789 * time.Nanosecond)
	token, issued, err := users.startSession(ctx, user, "precision browser", requested, uuid.Nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := users.Session(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if requested.Equal(persisted.ExpiresAt) {
		t.Fatal("fixture did not exercise submicrosecond precision loss")
	}
	if !issued.ExpiresAt.Equal(persisted.ExpiresAt) {
		t.Fatalf("session reply expiry %s differs from persisted expiry %s", issued.ExpiresAt.Format(time.RFC3339Nano), persisted.ExpiresAt.Format(time.RFC3339Nano))
	}
	_, derived, err := users.StartWorkspaceSession(ctx, user, "workspace", issued)
	if err != nil {
		t.Fatal(err)
	}
	if !derived.ExpiresAt.Equal(issued.ExpiresAt) {
		t.Fatalf("workspace expiry %s differs from login reply %s", derived.ExpiresAt.Format(time.RFC3339Nano), issued.ExpiresAt.Format(time.RFC3339Nano))
	}
}
