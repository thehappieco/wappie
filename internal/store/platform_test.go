package store_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/thehappieco/kit/oidcrp"

	"whatserver2/internal/migrate"
	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
)

// The store is the kit's PinStore: oidcrp.Pin's verdicts over it are the
// conformance the kit's documentation asks of a database implementation.
var _ oidcrp.PinStore = (*store.PlatformPins)(nil)

type platformFixture struct {
	pool   *pgxpool.Pool
	users  *store.Users
	pins   *store.PlatformPins
	tenant uuid.UUID
}

func newPlatformFixture(t *testing.T) *platformFixture {
	t.Helper()
	pool := pgtest.Fresh(t, migrate.Run)
	var tenant uuid.UUID
	if err := pool.QueryRow(context.Background(), `INSERT INTO tenants (name) VALUES ('team') RETURNING id`).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	return &platformFixture{pool: pool, users: store.NewUsers(pool), pins: store.NewPlatformPins(pool), tenant: tenant}
}

func platformBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func platformWrap(t *testing.T) []byte {
	t.Helper()
	w := platformBytes(t, store.PlatformWrapLen)
	w[0] = store.PlatformWrapVersion
	return w
}

// legacy signs a password account up through an invitation.
func (f *platformFixture) legacy(t *testing.T, email, authKey string) store.User {
	t.Helper()
	invite, err := f.users.CreateInvite(context.Background(), f.tenant, "member", "", nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	user, err := f.users.Signup(context.Background(), store.NewUser{Email: email, AuthKey: authKey, KDFSalt: platformBytes(t, 16),
		KDFParams: store.DefaultKDFParams(), PublicKey: platformBytes(t, 32), WrappedUSK: platformBytes(t, 61)}, invite, "")
	if err != nil {
		t.Fatal(err)
	}
	return user
}

// ticket pins a fresh product key for sub and issues a ticket of kind for it.
func (f *platformFixture) ticket(t *testing.T, kind string, sub uuid.UUID, email string, user uuid.UUID) string {
	t.Helper()
	key := platformBytes(t, 32)
	if _, _, err := f.pins.InsertPin(context.Background(), sub.String(), "wappie:1", key); err != nil {
		t.Fatal(err)
	}
	secret, err := f.users.CreatePlatformTicket(context.Background(), store.PlatformTicket{Kind: kind, Sub: sub, ProductKeyID: "wappie:1", ProductKey: key, Email: email, UserID: user})
	if err != nil {
		t.Fatal(err)
	}
	return secret
}

func TestPlatformPinsAreInsertOnly(t *testing.T) {
	f := newPlatformFixture(t)
	ctx := context.Background()
	sub := uuid.NewString()
	a, b := platformBytes(t, 32), platformBytes(t, 32)

	pinned, inserted, err := f.pins.InsertPin(ctx, sub, "wappie:1", a)
	if err != nil || !inserted || !bytes.Equal(pinned, a) {
		t.Fatalf("first: %v %v %v", pinned, inserted, err)
	}
	pinned, inserted, err = f.pins.InsertPin(ctx, sub, "wappie:1", b)
	if err != nil || inserted || !bytes.Equal(pinned, a) {
		t.Fatalf("another key: %v %v %v", pinned, inserted, err)
	}
	if v, err := oidcrp.Pin(ctx, f.pins, sub, "wappie:1", a); err != nil || v != oidcrp.PinSame {
		t.Fatalf("the pinned key: %v %v", v, err)
	}
	if v, err := oidcrp.Pin(ctx, f.pins, sub, "wappie:1", b); !errors.Is(err, oidcrp.ErrAccountKeyChanged) || v != oidcrp.PinChanged {
		t.Fatalf("another key: %v %v", v, err)
	}
	if v, err := oidcrp.Pin(ctx, f.pins, sub, "wappie:2", b); err != nil || v != oidcrp.PinNew {
		t.Fatalf("a new epoch: %v %v", v, err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE platform_key_pins SET product_key = $2 WHERE sub = $1`, sub, b); err == nil {
		t.Fatal("a pin was updated")
	}
	if _, err := f.pool.Exec(ctx, `DELETE FROM platform_key_pins WHERE sub = $1`, sub); err == nil {
		t.Fatal("a pin was deleted")
	}
	for _, bad := range []string{"wappie:0", "wappie:01", "Wappie:1", "wappie", ":1", "wappie:12345678901"} {
		if _, _, err := f.pins.InsertPin(ctx, uuid.NewString(), bad, a); err == nil {
			t.Errorf("pinned under %q", bad)
		}
	}
	if _, _, err := f.pins.InsertPin(ctx, uuid.NewString(), "wappie:1", a[:31]); err == nil {
		t.Error("pinned a 31-byte key")
	}
}

// users_credentials_by_source: a service has no password, a local person
// all of it, a platform person all of it (linked, in its window) or none.
func TestPlatformCredentialsBySource(t *testing.T) {
	f := newPlatformFixture(t)
	ctx := context.Background()
	insert := func(source, role string, password bool, recovery bool) error {
		home := uuid.New()
		return pg.InTenantTx(ctx, f.pool, home.String(), func(tx pgx.Tx) error {
			var hash, salt, params, wrap, rwrap, rhash any
			if password {
				hash, salt, params, wrap = "hash", platformBytes(t, 16), `{}`, platformBytes(t, 61)
			}
			if recovery {
				rwrap, rhash = platformBytes(t, 61), "rhash"
			}
			_, err := tx.Exec(ctx, `INSERT INTO users (tenant_id, email, auth_hash, kdf_salt, kdf_params, wrapped_usk, recovery_wrap, recovery_hash, public_key, role, auth_source)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`, home, uuid.NewString()+"@example.com", hash, salt, params, wrap, rwrap, rhash, platformBytes(t, 32), role, source)
			return err
		})
	}
	for _, tc := range []struct {
		source, role       string
		password, recovery bool
		ok                 bool
	}{
		{"local", "owner", true, false, true},
		{"local", "owner", false, false, false},
		{"platform", "owner", false, false, true},
		{"platform", "owner", true, true, true},
		{"platform", "owner", false, true, false},
		{"local", "service", false, false, true},
		{"platform", "service", false, false, false},
		{"other", "owner", true, false, false},
	} {
		if err := insert(tc.source, tc.role, tc.password, tc.recovery); (err == nil) != tc.ok {
			t.Errorf("%+v: %v", tc, err)
		}
	}
}

func TestPlatformLinkRowsNeverChange(t *testing.T) {
	f := newPlatformFixture(t)
	ctx := context.Background()
	sub := uuid.New()
	secret := f.ticket(t, store.TicketNew, sub, "ivo@example.com", uuid.Nil)
	user, err := f.users.SignupPlatform(ctx, store.NewPlatformUser{Ticket: secret, PublicKey: platformBytes(t, 32), Wrap: platformWrap(t)})
	if err != nil {
		t.Fatal(err)
	}
	if user.ID != sub || user.AuthSource != store.PlatformAuthSource {
		t.Fatalf("user %+v", user)
	}
	for _, stmt := range []string{
		`UPDATE platform_identities SET user_id = gen_random_uuid() WHERE sub = $1`,
		`UPDATE platform_identities SET linked_from = 'legacy' WHERE sub = $1`,
		`DELETE FROM platform_identities WHERE sub = $1`,
		`UPDATE platform_wraps SET wrap = wrap WHERE user_id = $1`,
		`DELETE FROM platform_wraps WHERE user_id = $1`,
		`DELETE FROM security_events WHERE sub = $1`,
	} {
		if _, err := f.pool.Exec(ctx, stmt, sub); err == nil {
			t.Errorf("%s succeeded", stmt)
		}
	}
	if _, err := f.pool.Exec(ctx, `UPDATE platform_identities SET email = 'ivo@new.example.com', email_changed_at = now() WHERE sub = $1`, sub); err != nil {
		t.Fatalf("the address may change: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO platform_wraps (user_id, product_key_id, wrap) VALUES ($1, 'wappie:2', $2)`, sub, platformBytes(t, 61)); err == nil {
		t.Error("a wrap without version byte 1 was stored")
	}
	// The account's deletion takes its link and wraps with it.
	if err := deleteUser(ctx, f.pool, sub); err != nil {
		t.Fatalf("deleting the account: %v", err)
	}
	var left int
	if err := f.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM platform_identities) + (SELECT count(*) FROM platform_wraps)`).Scan(&left); err != nil || left != 0 {
		t.Fatalf("%d rows left %v", left, err)
	}
}

func deleteUser(ctx context.Context, pool *pgxpool.Pool, id uuid.UUID) error {
	var home uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT tenant_id FROM user_logins WHERE user_id = $1`, id).Scan(&home); err != nil {
		return err
	}
	return pg.InTenantTx(ctx, pool, home.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
		return err
	})
}

func TestPlatformTicketsAreSingleUseAndBoundToTheirKind(t *testing.T) {
	f := newPlatformFixture(t)
	ctx := context.Background()
	sub := uuid.New()
	link := f.ticket(t, store.TicketLink, sub, "jo@example.com", uuid.Nil)
	if _, err := f.users.SignupPlatform(ctx, store.NewPlatformUser{Ticket: link, PublicKey: platformBytes(t, 32), Wrap: platformWrap(t)}); !errors.Is(err, store.ErrTicketInvalid) {
		t.Fatalf("an account from a link ticket: %v", err)
	}
	if _, err := f.users.PlatformTicketFor(ctx, link, store.TicketLink); err != nil {
		t.Fatalf("the refused use spent the ticket: %v", err)
	}
	for range 5 {
		if err := f.users.FailPlatformTicket(ctx, link); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.users.PlatformTicketFor(ctx, link, store.TicketLink); !errors.Is(err, store.ErrTicketInvalid) {
		t.Fatalf("a ticket after five failures: %v", err)
	}
	if _, err := f.users.CreatePlatformTicket(ctx, store.PlatformTicket{Kind: store.TicketRewrap, Sub: sub, ProductKeyID: "wappie:1", ProductKey: platformBytes(t, 32)}); err == nil {
		t.Fatal("a rewrap ticket without its account")
	}
	if _, err := f.users.CreatePlatformTicket(ctx, store.PlatformTicket{Kind: "admin", Sub: sub, ProductKeyID: "wappie:1", ProductKey: platformBytes(t, 32)}); err == nil {
		t.Fatal("a ticket of an unknown kind")
	}
	// A ticket stored with another key than the pin opens nothing.
	other := uuid.New()
	if _, _, err := f.pins.InsertPin(ctx, other.String(), "wappie:1", platformBytes(t, 32)); err != nil {
		t.Fatal(err)
	}
	forged, err := f.users.CreatePlatformTicket(ctx, store.PlatformTicket{Kind: store.TicketNew, Sub: other, ProductKeyID: "wappie:1", ProductKey: platformBytes(t, 32), Email: "k@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.users.SignupPlatform(ctx, store.NewPlatformUser{Ticket: forged, PublicKey: platformBytes(t, 32), Wrap: platformWrap(t)}); !errors.Is(err, store.ErrTicketInvalid) {
		t.Fatalf("a ticket that disagrees with its pin: %v", err)
	}
}

// 0048's down-step, exactly as the migration's header documents it, as the
// table owner: it refuses while an account created through the provider
// exists; once that account is deleted it brings a linked account back to
// local with its old password, drops the tables and columns, restores
// 0020's constraint, forgets version 48; and 0048 comes back up.
func TestMigration0048DownStep(t *testing.T) {
	f := newPlatformFixture(t)
	ctx := context.Background()
	legacy := f.legacy(t, "lia@example.com", "lia-auth-key")
	linkSub := uuid.New()
	if _, err := f.users.LinkLegacy(ctx, store.LegacyLink{Ticket: f.ticket(t, store.TicketNew, linkSub, "lia@id.example.com", uuid.Nil),
		Proof: store.LegacyProof{Email: "lia@example.com", Secret: "lia-auth-key"}, Wrap: platformWrap(t)}); err != nil {
		t.Fatalf("link: %v", err)
	}
	native := uuid.New()
	if _, err := f.users.SignupPlatform(ctx, store.NewPlatformUser{Ticket: f.ticket(t, store.TicketNew, native, "max@example.com", uuid.Nil),
		PublicKey: platformBytes(t, 32), Wrap: platformWrap(t)}); err != nil {
		t.Fatalf("new account: %v", err)
	}

	if _, err := f.pool.Exec(ctx, downStep(t, 48)); err == nil || !strings.Contains(err.Error(), "created through the identity provider") {
		t.Fatalf("the down-step ran with an account that has no password: %v", err)
	}
	var version int
	if err := f.pool.QueryRow(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&version); err != nil || version != 48 {
		t.Fatalf("a refused down-step changed the ledger: %d %v", version, err)
	}
	if err := deleteUser(ctx, f.pool, native); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, downStep(t, 48)); err != nil {
		t.Fatalf("down-step: %v", err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&version); err != nil || version != 47 {
		t.Fatalf("ledger at %d %v", version, err)
	}
	var left int
	if err := f.pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM information_schema.tables WHERE table_schema = current_schema()
		   AND table_name IN ('platform_key_pins', 'platform_identities', 'platform_wraps', 'platform_login_tickets', 'security_events'))
		+ (SELECT count(*) FROM information_schema.columns WHERE table_schema = current_schema()
		   AND ((table_name = 'users' AND column_name = 'auth_source') OR (table_name = 'sessions' AND column_name LIKE 'step_up%')))
		+ (SELECT count(*) FROM pg_proc WHERE proname IN ('platform_insert_only', 'platform_identity_guard') AND pronamespace = current_schema()::regnamespace)
		+ (SELECT count(*) FROM pg_constraint WHERE conname = 'users_credentials_by_source' AND connamespace = current_schema()::regnamespace)`).Scan(&left); err != nil || left != 0 {
		t.Fatalf("%d things left %v", left, err)
	}
	var restored string
	if err := f.pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'users_service_has_no_password'
		AND connamespace = current_schema()::regnamespace`).Scan(&restored); err != nil || !strings.Contains(restored, "auth_hash IS NOT NULL") {
		t.Fatalf("0020's constraint: %q %v", restored, err)
	}
	// The linked account keeps everything its old password signs in with
	// (read as SQL: this binary's queries know auth_source, an older one's
	// do not).
	var home uuid.UUID
	if err := f.pool.QueryRow(ctx, `SELECT tenant_id FROM user_logins WHERE user_id = $1`, legacy.ID).Scan(&home); err != nil {
		t.Fatal(err)
	}
	var credentials bool
	if err := pg.InTenantTx(ctx, f.pool, home.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT auth_hash IS NOT NULL AND kdf_salt IS NOT NULL AND wrapped_usk IS NOT NULL AND status = 'active'
			FROM users WHERE id = $1`, legacy.ID).Scan(&credentials)
	}); err != nil || !credentials {
		t.Fatalf("the linked account's password after the down-step: %v %v", credentials, err)
	}

	if err := migrate.Run(ctx, f.pool, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatalf("re-applying 0048: %v", err)
	}
	if user, err := f.users.Authenticate(ctx, "lia@example.com", "lia-auth-key"); err != nil || user.ID != legacy.ID || user.AuthSource != store.LocalAuthSource {
		t.Fatalf("the old password after 0048 again: %+v %v", user, err)
	}
}
