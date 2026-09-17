package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

func TestRestrictedAPIKeyStoreRejectsInvalidSelections(t *testing.T) {
	a := newArchive(t)
	ctx := context.Background()
	keys := store.NewAPIKeys(a.pool)
	owner, _ := transferOwner(t, a, "owner")
	member, _ := transferOwner(t, a, "member")
	foreign := newTenant(t, a.pool, "Foreign")
	foreignDevice, err := store.NewDevices(a.pool).Create(ctx, foreign, "Foreign", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	var unsafeRole bool
	if err := a.pool.QueryRow(ctx, `SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user`).Scan(&unsafeRole); err != nil || unsafeRole {
		t.Fatalf("ordinary RLS role required: %v %v", unsafeRole, err)
	}
	for name, selection := range map[string][]uuid.UUID{
		"empty": {}, "zero": {uuid.Nil}, "duplicate": {a.device, a.device},
		"foreign": {a.device, uuid.MustParse(foreignDevice.ID)}, "missing": {a.device, uuid.New()},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := keys.IssueActingAsForDevices(ctx, a.tenant.String(), name, store.ScopeRead, &owner, nil, selection)
			if !errors.Is(err, store.ErrInvalidKeyDevices) {
				t.Fatalf("invalid selection accepted: %v", err)
			}
		})
	}
	if _, err := keys.IssueActingAsForDevices(ctx, a.tenant.String(), "Member", store.ScopeRead, &member, nil, []uuid.UUID{a.device}); !errors.Is(err, store.ErrMembershipForbidden) {
		t.Fatalf("member could issue a restricted key: %v", err)
	}
	listed, err := keys.List(ctx, a.tenant.String())
	if err != nil || len(listed) != 0 {
		t.Fatalf("rejected issuance left a key: %+v %v", listed, err)
	}
}

func TestRestrictedAPIKeyRollsBackWhenWhitelistInsertFails(t *testing.T) {
	a := newArchive(t)
	ctx := context.Background()
	keys := store.NewAPIKeys(a.pool)
	// An actual database failure after the key INSERT must roll back the key,
	// rather than publish a credential whose restrictions were not committed.
	if _, err := a.pool.Exec(ctx, `CREATE FUNCTION reject_test_key_device() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'test whitelist insert failed'; END $$;
		CREATE TRIGGER reject_test_key_device BEFORE INSERT ON api_key_devices FOR EACH ROW EXECUTE FUNCTION reject_test_key_device()`); err != nil {
		t.Fatal(err)
	}
	key, err := keys.IssueActingAsForDevices(ctx, a.tenant.String(), "Must roll back", store.ScopeRead, nil, nil, []uuid.UUID{a.device})
	if err == nil || key != "" {
		t.Fatalf("failed whitelist returned a credential: error=%v", err)
	}
	listed, err := keys.List(ctx, a.tenant.String())
	if err != nil || len(listed) != 0 {
		t.Fatalf("key survived failed whitelist: %+v %v", listed, err)
	}
}

func TestRestrictedAPIKeyKeepsEmptyScopeAfterPersonalTransfer(t *testing.T) {
	a := newArchive(t)
	ctx := context.Background()
	keys, devices := store.NewAPIKeys(a.pool), store.NewDevices(a.pool)
	owner, personal := transferOwner(t, a, "owner")
	service, err := store.NewUsers(a.pool).CreateService(ctx, a.tenant, "mcp-test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	key, err := keys.IssueActingAsForDevices(ctx, a.tenant.String(), "MCP", store.ScopeRead, &owner, &service.ID, []uuid.UUID{a.device})
	if err != nil {
		t.Fatal(err)
	}
	prefix, _, _ := strings.Cut(key, ".")
	other, err := devices.Create(ctx, a.tenant.String(), "Remaining", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	if err := devices.SetPaused(ctx, a.tenant.String(), a.device.String(), true); err != nil {
		t.Fatal(err)
	}
	if _, err := devices.TransferPersonal(ctx, a.tenant, owner, a.device, personal); err != nil {
		t.Fatal(err)
	}
	listed, err := keys.List(ctx, a.tenant.String())
	if err != nil || len(listed) != 1 {
		t.Fatalf("list after transfer: %+v %v", listed, err)
	}
	info := listed[0]
	if info.Prefix != prefix || !info.DevicesRestricted || info.DeviceIDs == nil || len(info.DeviceIDs) != 0 || info.ActsAsID == nil || *info.ActsAsID != service.ID || info.ActsAs != "mcp-test" {
		t.Fatalf("empty restriction or service identity lost: %+v", info)
	}
	verified, err := keys.VerifyScoped(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []uuid.UUID{a.device, uuid.MustParse(other.ID)} {
		allowed, err := keys.AllowsDevice(ctx, verified.ID, a.tenant, id)
		if err != nil || allowed {
			t.Fatalf("empty whitelist widened access to %s: %v %v", id, allowed, err)
		}
	}
}
