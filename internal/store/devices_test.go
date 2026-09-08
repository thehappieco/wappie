package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

func newTenant(t *testing.T, pool *pgxpool.Pool, name string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO tenants (name) VALUES ($1) RETURNING id::text`, name).Scan(&id); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	return id
}

func TestCreateAndGet(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	devices := store.NewDevices(pool)
	ctx := context.Background()
	tenant := newTenant(t, pool, "acme")

	created, err := devices.Create(ctx, tenant, "atendimento", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	got, err := devices.Get(ctx, tenant, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Label != "atendimento" || got.Status != wa.StatusNew {
		t.Errorf("device = %+v", got)
	}
	// Passive is the default posture: a device is quiet unless asked otherwise.
	if got.ReceiptMode != wa.ModePassive {
		t.Errorf("ReceiptMode = %q, want passive", got.ReceiptMode)
	}
	if got.Identity.Known() {
		t.Error("a brand-new device should have no identity yet")
	}
}

// Each half of the identity is written only when present. A later event that
// carries just the LID must not blank out a phone number learned earlier, and
// for many contacts a phone number never arrives at all.
func TestSetIdentityDoesNotEraseTheOtherHalf(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	devices := store.NewDevices(pool)
	ctx := context.Background()
	tenant := newTenant(t, pool, "acme")

	dev, err := devices.Create(ctx, tenant, "d", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	lid := types.JID{User: "123456789", Server: types.HiddenUserServer}
	pn := types.JID{User: "5511999999999", Server: types.DefaultUserServer}

	if err := devices.SetIdentity(ctx, tenant, dev.ID, wa.Identity{LID: lid, PN: pn, PushName: "Acme"}); err != nil {
		t.Fatal(err)
	}
	// A later update carrying only a push name.
	if err := devices.SetIdentity(ctx, tenant, dev.ID, wa.Identity{PushName: "Acme Suporte"}); err != nil {
		t.Fatal(err)
	}

	got, err := devices.Get(ctx, tenant, dev.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Identity.LID != lid {
		t.Errorf("LID = %v, want %v — it was erased by an unrelated update", got.Identity.LID, lid)
	}
	if got.Identity.PN != pn {
		t.Errorf("PN = %v, want %v — it was erased by an unrelated update", got.Identity.PN, pn)
	}
	if got.Identity.PushName != "Acme Suporte" {
		t.Errorf("PushName = %q", got.Identity.PushName)
	}
}

// A LID-only device is normal, not an error: LID exists to withhold the phone
// number, so for some accounts one will never be available.
func TestLIDOnlyIdentity(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	devices := store.NewDevices(pool)
	ctx := context.Background()
	tenant := newTenant(t, pool, "acme")

	dev, _ := devices.Create(ctx, tenant, "d", wa.ModePassive)
	lid := types.JID{User: "123456789", Server: types.HiddenUserServer}
	if err := devices.SetIdentity(ctx, tenant, dev.ID, wa.Identity{LID: lid}); err != nil {
		t.Fatal(err)
	}
	got, _ := devices.Get(ctx, tenant, dev.ID)
	if !got.Identity.Known() {
		t.Error("a LID-only identity must count as known")
	}
	if got.Identity.Primary() != lid {
		t.Errorf("Primary() = %v, want the LID", got.Identity.Primary())
	}
}

func TestSetStatusAndListing(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	devices := store.NewDevices(pool)
	ctx := context.Background()
	tenant := newTenant(t, pool, "acme")

	dev, _ := devices.Create(ctx, tenant, "d", wa.ModePassive)
	for _, s := range []wa.Status{wa.StatusPairing, wa.StatusOnline, wa.StatusOffline} {
		if err := devices.SetStatus(ctx, tenant, dev.ID, s, "because"); err != nil {
			t.Fatalf("set %q: %v", s, err)
		}
	}
	got, err := devices.Get(ctx, tenant, dev.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != wa.StatusOffline {
		t.Errorf("status = %q, want offline", got.Status)
	}

	list, err := devices.List(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("List returned %d devices, want 1", len(list))
	}
}

// Row-level security makes "belongs to another tenant" indistinguishable from
// "does not exist", which is the intended behaviour: a probe learns nothing.
func TestCrossTenantAccessLooksLikeNotFound(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	devices := store.NewDevices(pool)
	ctx := context.Background()
	acme := newTenant(t, pool, "acme")
	globex := newTenant(t, pool, "globex")

	dev, err := devices.Create(ctx, acme, "d", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := devices.Get(ctx, globex, dev.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Get across tenants: err = %v, want ErrNotFound", err)
	}
	if err := devices.SetStatus(ctx, globex, dev.ID, wa.StatusOnline, ""); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("SetStatus across tenants: err = %v, want ErrNotFound", err)
	}
	if err := devices.Delete(ctx, globex, dev.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Delete across tenants: err = %v, want ErrNotFound", err)
	}

	// And the device is untouched.
	got, err := devices.Get(ctx, acme, dev.ID)
	if err != nil || got.Status != wa.StatusNew {
		t.Errorf("device was modified across tenants: %+v, %v", got, err)
	}

	list, err := devices.List(ctx, globex)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Errorf("globex sees %d of acme's devices", len(list))
	}
}

func TestDelete(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	devices := store.NewDevices(pool)
	ctx := context.Background()
	tenant := newTenant(t, pool, "acme")

	dev, _ := devices.Create(ctx, tenant, "d", wa.ModePassive)
	if err := devices.Delete(ctx, tenant, dev.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := devices.Get(ctx, tenant, dev.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

// The device listing shows a short id, so the short id has to work wherever an
// id is asked for. Displaying an identifier that cannot be typed back is a
// trap, and it caught a real user twice before this existed.
func TestResolveAcceptsPrefix(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	devices := store.NewDevices(pool)
	ctx := context.Background()
	tenant := newTenant(t, pool, "acme")

	dev, err := devices.Create(ctx, tenant, "atendimento", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}

	for name, given := range map[string]string{
		"full id":       dev.ID,
		"short prefix":  dev.ID[:8],
		"longer prefix": dev.ID[:16],
	} {
		t.Run(name, func(t *testing.T) {
			got, err := devices.Resolve(ctx, tenant, given)
			if err != nil {
				t.Fatalf("Resolve(%q): %v", given, err)
			}
			if got.ID != dev.ID {
				t.Errorf("resolved to %s, want %s", got.ID, dev.ID)
			}
		})
	}
}

// An ambiguous prefix is an error, not a guess. Picking one would eventually
// send a message from the wrong account.
func TestResolveRefusesAmbiguousPrefix(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	devices := store.NewDevices(pool)
	ctx := context.Background()
	tenant := newTenant(t, pool, "acme")

	// uuidv7 values created together share a long leading run, so a one
	// character prefix reliably collides.
	for range 3 {
		if _, err := devices.Create(ctx, tenant, "d", wa.ModePassive); err != nil {
			t.Fatal(err)
		}
	}
	all, err := devices.List(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	prefix := all[0].ID[:1]

	if _, err := devices.Resolve(ctx, tenant, prefix); !errors.Is(err, store.ErrAmbiguous) {
		t.Fatalf("err = %v, want ErrAmbiguous", err)
	}
}

func TestResolveRejectsUnknown(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	devices := store.NewDevices(pool)
	ctx := context.Background()
	tenant := newTenant(t, pool, "acme")

	for _, given := range []string{"", "zzzzzzzz", "01a034bb-0000-0000-0000-000000000000"} {
		if _, err := devices.Resolve(ctx, tenant, given); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Resolve(%q): err = %v, want ErrNotFound", given, err)
		}
	}
}

// A prefix must not reach across tenants, even a unique one.
func TestResolveIsTenantScoped(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	devices := store.NewDevices(pool)
	ctx := context.Background()
	acme := newTenant(t, pool, "acme")
	globex := newTenant(t, pool, "globex")

	dev, err := devices.Create(ctx, acme, "d", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := devices.Resolve(ctx, globex, dev.ID[:8]); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a prefix reached across tenants: %v", err)
	}
}
