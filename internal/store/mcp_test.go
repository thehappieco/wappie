package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/store"
)

// A hosted assistant connection rides on a read-only, device-restricted key
// with a short provisional deadline. These tests pin what Create refuses and
// what it promotes.

type mcpFixture struct {
	*archive
	owner uuid.UUID
	keys  *store.APIKeys
	conns *store.MCPConnections
}

func newMCPFixture(t *testing.T) *mcpFixture {
	t.Helper()
	a := newArchive(t)
	var unsafeRole bool
	if err := a.pool.QueryRow(context.Background(), `SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user`).Scan(&unsafeRole); err != nil || unsafeRole {
		t.Fatalf("ordinary RLS role required: %v %v", unsafeRole, err)
	}
	owner, _ := transferOwner(t, a, "owner")
	return &mcpFixture{archive: a, owner: owner, keys: store.NewAPIKeys(a.pool), conns: store.NewMCPConnections(a.pool)}
}

// provisionalKey issues the key the console mints before consent: read-only,
// restricted to the fixture's device, dead in twenty minutes.
func (f *mcpFixture) provisionalKey(ctx context.Context, t *testing.T, name string) (key, prefix string) {
	t.Helper()
	in := time.Now().Add(20 * time.Minute)
	key, err := f.keys.IssueActingAsForDevices(ctx, f.tenant.String(), name, store.ScopeRead, &f.owner, nil, []uuid.UUID{f.device}, &in)
	if err != nil {
		t.Fatal(err)
	}
	prefix, _, _ = strings.Cut(key, ".")
	return key, prefix
}

func consent(prefix string) store.CreateMCPConnection {
	return store.CreateMCPConnection{
		RequestID: uuid.NewString(), KeyPrefix: prefix, ClientName: "Claude", RedirectHost: "claude.ai",
		DeviceCount: 1, ReaderKID: "0123456789abcdef", ExpiresAt: time.Now().Add(90 * 24 * time.Hour),
	}
}

func TestCreateConnectionInvariants(t *testing.T) {
	f := newMCPFixture(t)
	ctx := context.Background()
	foreign := newTenant(t, f.pool, "Foreign")
	admin, _ := transferOwner(t, f.archive, "admin")

	t.Run("foreign key", func(t *testing.T) {
		key, err := f.keys.IssueScoped(ctx, foreign, "theirs", store.ScopeRead, nil)
		if err != nil {
			t.Fatal(err)
		}
		prefix, _, _ := strings.Cut(key, ".")
		if _, err := f.conns.Create(ctx, f.tenant, f.owner, consent(prefix)); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("another workspace's key was accepted: %v", err)
		}
	})
	t.Run("wrong scope", func(t *testing.T) {
		in := time.Now().Add(20 * time.Minute)
		key, err := f.keys.IssueActingAsForDevices(ctx, f.tenant.String(), "send", store.ScopeSend, &f.owner, nil, []uuid.UUID{f.device}, &in)
		if err != nil {
			t.Fatal(err)
		}
		prefix, _, _ := strings.Cut(key, ".")
		if _, err := f.conns.Create(ctx, f.tenant, f.owner, consent(prefix)); !errors.Is(err, store.ErrMCPKeyUnsuitable) {
			t.Fatalf("a key that can send was accepted: %v", err)
		}
	})
	t.Run("unrestricted", func(t *testing.T) {
		in := time.Now().Add(20 * time.Minute)
		key, err := f.keys.IssueActingAsForDevices(ctx, f.tenant.String(), "all devices", store.ScopeRead, &f.owner, nil, nil, &in)
		if err != nil {
			t.Fatal(err)
		}
		prefix, _, _ := strings.Cut(key, ".")
		if _, err := f.conns.Create(ctx, f.tenant, f.owner, consent(prefix)); !errors.Is(err, store.ErrMCPKeyUnsuitable) {
			t.Fatalf("a key with no device restriction was accepted: %v", err)
		}
	})
	t.Run("acts_as set", func(t *testing.T) {
		service, err := store.NewUsers(f.pool).CreateService(ctx, f.tenant, "erp", make([]byte, 32))
		if err != nil {
			t.Fatal(err)
		}
		in := time.Now().Add(20 * time.Minute)
		key, err := f.keys.IssueActingAsForDevices(ctx, f.tenant.String(), "erp", store.ScopeRead, &f.owner, &service.ID, []uuid.UUID{f.device}, &in)
		if err != nil {
			t.Fatal(err)
		}
		prefix, _, _ := strings.Cut(key, ".")
		if _, err := f.conns.Create(ctx, f.tenant, f.owner, consent(prefix)); !errors.Is(err, store.ErrMCPKeyUnsuitable) {
			t.Fatalf("a key carrying a service account was accepted: %v", err)
		}
	})
	t.Run("no deadline", func(t *testing.T) {
		key, err := f.keys.IssueActingAsForDevices(ctx, f.tenant.String(), "forever", store.ScopeRead, &f.owner, nil, []uuid.UUID{f.device}, nil)
		if err != nil {
			t.Fatal(err)
		}
		prefix, _, _ := strings.Cut(key, ".")
		if _, err := f.conns.Create(ctx, f.tenant, f.owner, consent(prefix)); !errors.Is(err, store.ErrMCPKeyUnsuitable) {
			t.Fatalf("a key with no deadline was accepted: %v", err)
		}
	})
	t.Run("another person's key", func(t *testing.T) {
		// An admin's own provisional key is not the owner's to bind: to the
		// owner it does not exist, exactly like another workspace's.
		in := time.Now().Add(20 * time.Minute)
		key, err := f.keys.IssueActingAsForDevices(ctx, f.tenant.String(), "theirs", store.ScopeRead, &admin, nil, []uuid.UUID{f.device}, &in)
		if err != nil {
			t.Fatal(err)
		}
		prefix, _, _ := strings.Cut(key, ".")
		if _, err := f.conns.Create(ctx, f.tenant, f.owner, consent(prefix)); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("another person's key was accepted: %v", err)
		}
		// And the admin may bind it, being its creator and an admin.
		if _, err := f.conns.Create(ctx, f.tenant, admin, consent(prefix)); err != nil {
			t.Fatalf("the creator was refused their own key: %v", err)
		}
	})
	t.Run("key with no creator", func(t *testing.T) {
		in := time.Now().Add(20 * time.Minute)
		key, err := f.keys.IssueActingAsForDevices(ctx, f.tenant.String(), "nobody's", store.ScopeRead, nil, nil, []uuid.UUID{f.device}, &in)
		if err != nil {
			t.Fatal(err)
		}
		prefix, _, _ := strings.Cut(key, ".")
		if _, err := f.conns.Create(ctx, f.tenant, f.owner, consent(prefix)); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("a key with no creator was accepted: %v", err)
		}
	})
	t.Run("long deadline", func(t *testing.T) {
		// A read-only, device-restricted key issued for a week is one made
		// for something else; a consent must not stretch it to a year.
		for name, in := range map[string]time.Time{"a week": time.Now().Add(7 * 24 * time.Hour), "an hour": time.Now().Add(time.Hour)} {
			in := in
			key, err := f.keys.IssueActingAsForDevices(ctx, f.tenant.String(), name, store.ScopeRead, &f.owner, nil, []uuid.UUID{f.device}, &in)
			if err != nil {
				t.Fatal(err)
			}
			prefix, _, _ := strings.Cut(key, ".")
			if _, err := f.conns.Create(ctx, f.tenant, f.owner, consent(prefix)); !errors.Is(err, store.ErrMCPKeyUnsuitable) {
				t.Fatalf("%s: a key with a long deadline was accepted: %v", name, err)
			}
		}
	})
	t.Run("revoked key", func(t *testing.T) {
		_, prefix := f.provisionalKey(ctx, t, "revoked")
		if err := f.keys.Revoke(ctx, f.tenant.String(), prefix); err != nil {
			t.Fatal(err)
		}
		if _, err := f.conns.Create(ctx, f.tenant, f.owner, consent(prefix)); !errors.Is(err, store.ErrMCPKeyUnsuitable) {
			t.Fatalf("a revoked key was accepted: %v", err)
		}
	})
	t.Run("bad expiry", func(t *testing.T) {
		_, prefix := f.provisionalKey(ctx, t, "expiry")
		for name, at := range map[string]time.Time{"past": time.Now().Add(-time.Minute), "too far": time.Now().Add(366 * 24 * time.Hour)} {
			in := consent(prefix)
			in.ExpiresAt = at
			if _, err := f.conns.Create(ctx, f.tenant, f.owner, in); !errors.Is(err, store.ErrInvalidExpiry) {
				t.Fatalf("%s: err = %v, want ErrInvalidExpiry", name, err)
			}
		}
	})
	t.Run("same key twice", func(t *testing.T) {
		_, prefix := f.provisionalKey(ctx, t, "twice")
		if _, err := f.conns.Create(ctx, f.tenant, f.owner, consent(prefix)); err != nil {
			t.Fatal(err)
		}
		// The first consent promoted the key past the provisional deadline;
		// a second one on the same key has nothing to extend and no row to add.
		if _, err := f.conns.Create(ctx, f.tenant, f.owner, consent(prefix)); !errors.Is(err, store.ErrMCPKeyUnsuitable) {
			t.Fatalf("one key carried two connections: %v", err)
		}
	})
	// Two rows so far: the admin's own consent and the "same key twice" one.
	if listed, err := f.conns.List(ctx, f.tenant); err != nil || len(listed) != 2 {
		t.Fatalf("refused consents left rows behind: %+v %v", listed, err)
	}
	t.Run("sixth connection", func(t *testing.T) {
		for i := 0; i < 3; i++ {
			_, prefix := f.provisionalKey(ctx, t, "live")
			if _, err := f.conns.Create(ctx, f.tenant, f.owner, consent(prefix)); err != nil {
				t.Fatal(err)
			}
		}
		_, prefix := f.provisionalKey(ctx, t, "sixth")
		if _, err := f.conns.Create(ctx, f.tenant, f.owner, consent(prefix)); !errors.Is(err, store.ErrTooManyMCPConnections) {
			t.Fatalf("sixth live connection: err = %v", err)
		}
		// Ending one frees the slot.
		listed, err := f.conns.List(ctx, f.tenant)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.conns.Revoke(ctx, f.tenant, f.owner, listed[0].ID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.conns.Create(ctx, f.tenant, f.owner, consent(prefix)); err != nil {
			t.Fatalf("slot not freed by a revocation: %v", err)
		}
	})
}

// The owner/admin check reads policy-protected tables. Run outside a tenant
// transaction it would find no membership and refuse the owner too, so this
// test fails the moment Create stops using one.
func TestCreateConnectionOwnerUnderRLS(t *testing.T) {
	f := newMCPFixture(t)
	ctx := context.Background()
	member, _ := transferOwner(t, f.archive, "member")

	key, prefix := f.provisionalKey(ctx, t, "owner")
	in := consent(prefix)
	got, err := f.conns.Create(ctx, f.tenant, f.owner, in)
	if err != nil {
		t.Fatalf("owner refused: %v", err)
	}
	if got.ID == "" || got.Status != "pending" || got.KeyPrefix != prefix || got.CreatedBy != f.owner || got.CreatedAt.IsZero() {
		t.Fatalf("connection = %+v", got)
	}
	listed, err := f.conns.List(ctx, f.tenant)
	if err != nil || len(listed) != 1 || listed[0].ID != got.ID || listed[0].RequestID != in.RequestID {
		t.Fatalf("list = %+v %v", listed, err)
	}
	// The consent promoted the key from twenty minutes to the chosen lifetime.
	keys, err := f.keys.List(ctx, f.tenant.String())
	if err != nil || len(keys) != 1 || keys[0].ExpiresAt == nil {
		t.Fatalf("keys = %+v %v", keys, err)
	}
	if d := keys[0].ExpiresAt.Sub(in.ExpiresAt); d > time.Second || d < -time.Second {
		t.Fatalf("key expires %v, consent was %v", keys[0].ExpiresAt, in.ExpiresAt)
	}
	if _, err := f.keys.Verify(ctx, key); err != nil {
		t.Fatalf("the bound key stopped working: %v", err)
	}

	// The reader's side of the ledger.
	status, expires, err := f.conns.Status(ctx, got.ID)
	if err != nil || status != "pending" || expires.Sub(in.ExpiresAt) > time.Second {
		t.Fatalf("status = %q %v %v", status, expires, err)
	}
	if err := f.conns.Activate(ctx, got.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.conns.Activate(ctx, got.ID); !errors.Is(err, store.ErrMCPConnectionState) {
		t.Fatalf("second activation: err = %v", err)
	}
	if err := f.conns.Activate(ctx, uuid.NewString()); !errors.Is(err, store.ErrMCPConnectionNotFound) {
		t.Fatalf("unknown activation: err = %v", err)
	}
	listed, _ = f.conns.List(ctx, f.tenant)
	if listed[0].Status != "active" || listed[0].ActivatedAt == nil || listed[0].LastSeenAt == nil {
		t.Fatalf("after activation: %+v", listed[0])
	}

	// A plain member may not consent on the workspace's behalf.
	_, memberPrefix := f.provisionalKey(ctx, t, "member")
	if _, err := f.conns.Create(ctx, f.tenant, member, consent(memberPrefix)); !errors.Is(err, store.ErrMembershipForbidden) {
		t.Fatalf("member consented: %v", err)
	}
	if err := f.conns.Revoke(ctx, f.tenant, member, got.ID); !errors.Is(err, store.ErrMembershipForbidden) {
		t.Fatalf("member revoked: %v", err)
	}
	// Nor may an owner of another workspace reach this one's connection.
	if err := f.conns.Revoke(ctx, uuid.MustParse(newTenant(t, f.pool, "Other")), f.owner, got.ID); !errors.Is(err, store.ErrMembershipForbidden) {
		t.Fatalf("foreign revoke: %v", err)
	}

	if err := f.conns.Revoke(ctx, f.tenant, f.owner, got.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.keys.Verify(ctx, key); !errors.Is(err, store.ErrInvalidKey) {
		t.Fatalf("revoking the connection left the key working: %v", err)
	}
	if err := f.conns.Revoke(ctx, f.tenant, f.owner, got.ID); err != nil {
		t.Fatalf("second revoke: %v", err)
	}
	if err := f.conns.Revoke(ctx, f.tenant, f.owner, uuid.NewString()); !errors.Is(err, store.ErrMCPConnectionNotFound) {
		t.Fatalf("unknown revoke: err = %v", err)
	}
	status, _, err = f.conns.Status(ctx, got.ID)
	if err != nil || status != "revoked" {
		t.Fatalf("status after revoke = %q %v", status, err)
	}
}

// A hand-off the reader never acknowledged leaves nothing behind.
func TestDeleteFailedRemovesPendingAndRevokesKey(t *testing.T) {
	f := newMCPFixture(t)
	ctx := context.Background()
	key, prefix := f.provisionalKey(ctx, t, "relay")
	got, err := f.conns.Create(ctx, f.tenant, f.owner, consent(prefix))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.conns.DeleteFailed(ctx, got.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.conns.DeleteFailed(ctx, got.ID); !errors.Is(err, store.ErrMCPConnectionNotFound) {
		t.Fatalf("second delete: err = %v", err)
	}
	if listed, err := f.conns.List(ctx, f.tenant); err != nil || len(listed) != 0 {
		t.Fatalf("row survived: %+v %v", listed, err)
	}
	if _, err := f.keys.Verify(ctx, key); !errors.Is(err, store.ErrInvalidKey) {
		t.Fatalf("key survived a failed hand-off: %v", err)
	}

	// Only a pending row is deletable; an active one is revoked, never erased.
	key, prefix = f.provisionalKey(ctx, t, "active")
	got, err = f.conns.Create(ctx, f.tenant, f.owner, consent(prefix))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.conns.Activate(ctx, got.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.conns.DeleteFailed(ctx, got.ID); !errors.Is(err, store.ErrMCPConnectionNotFound) {
		t.Fatalf("active row deleted: %v", err)
	}
	if err := f.conns.RevokeByID(ctx, got.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.conns.RevokeByID(ctx, got.ID); err != nil {
		t.Fatalf("second reader revoke: %v", err)
	}
	if err := f.conns.RevokeByID(ctx, uuid.NewString()); !errors.Is(err, store.ErrMCPConnectionNotFound) {
		t.Fatalf("unknown reader revoke: err = %v", err)
	}
	if _, err := f.keys.Verify(ctx, key); !errors.Is(err, store.ErrInvalidKey) {
		t.Fatalf("reader revoke left the key working: %v", err)
	}
	if listed, _ := f.conns.List(ctx, f.tenant); len(listed) != 1 || listed[0].Status != "revoked" || listed[0].RevokedAt == nil {
		t.Fatalf("after reader revoke: %+v", listed)
	}
}
