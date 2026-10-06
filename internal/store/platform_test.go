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
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/thehappieco/kit/oidcrp"
	"github.com/thehappieco/kit/profiles/wappie"

	"whatserver2/internal/migrate"
	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/stepup"
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

// platformWrap has a platform wrap's shape (kit SPEC section 6.8), which is
// all the server can check: 61 bytes starting with the header 0x03.
func platformWrap(t *testing.T) []byte {
	t.Helper()
	w := platformBytes(t, wappie.PlatformWrapLen)
	w[0] = wappie.PlatformWrapHeader
	return w
}

// The store checks a wrap's length and header byte only. Wappie's passkey
// envelope (0x01) and its password and recovery wraps (0x02) are 61 bytes
// over the same account key too, and are refused at their header.
func TestValidPlatformWrap(t *testing.T) {
	if !store.ValidPlatformWrap(platformWrap(t)) {
		t.Fatal("a 61-byte wrap with header 0x03 was refused")
	}
	for _, header := range []byte{0x00, 0x01, 0x02, 0x04, 0xff} {
		w := platformWrap(t)
		w[0] = header
		if store.ValidPlatformWrap(w) {
			t.Errorf("header 0x%02x was accepted", header)
		}
	}
	for _, n := range []int{0, 1, 60, 62} {
		w := platformBytes(t, n)
		if n > 0 {
			w[0] = wappie.PlatformWrapHeader
		}
		if store.ValidPlatformWrap(w) {
			t.Errorf("a wrap of %d bytes was accepted", n)
		}
	}
	if store.ValidPlatformWrap(nil) {
		t.Error("no wrap was accepted")
	}
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
	// TRUNCATE fires no row trigger: a statement trigger refuses it.
	for _, table := range []string{"platform_key_pins", "platform_wraps", "platform_identities", "security_events"} {
		if _, err := f.pool.Exec(ctx, `TRUNCATE `+table); err == nil || !strings.Contains(err.Error(), "insert-only") {
			t.Errorf("TRUNCATE %s: %v", table, err)
		}
	}
	if _, err := f.pool.Exec(ctx, `UPDATE platform_identities SET email = 'ivo@new.example.com', email_changed_at = now() WHERE sub = $1`, sub); err != nil {
		t.Fatalf("the address may change: %v", err)
	}
	// 0048's CHECK is the store's shape: 61 bytes starting with 0x03.
	for _, header := range []byte{0x00, 0x01, 0x02, 0x04} {
		w := platformWrap(t)
		w[0] = header
		var pgErr *pgconn.PgError
		if _, err := f.pool.Exec(ctx, `INSERT INTO platform_wraps (user_id, product_key_id, wrap) VALUES ($1, 'wappie:2', $2)`, sub, w); !errors.As(err, &pgErr) || pgErr.Code != "23514" {
			t.Errorf("a wrap with header 0x%02x: %v", header, err)
		}
	}
	var pgErr *pgconn.PgError
	if _, err := f.pool.Exec(ctx, `INSERT INTO platform_wraps (user_id, product_key_id, wrap) VALUES ($1, 'wappie:2', $2)`, sub, platformWrap(t)[:60]); !errors.As(err, &pgErr) || pgErr.Code != "23514" {
		t.Errorf("a wrap of 60 bytes: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO platform_wraps (user_id, product_key_id, wrap) VALUES ($1, 'wappie:2', $2)`, sub, platformWrap(t)); err != nil {
		t.Errorf("a wrap with header 0x03 for another epoch: %v", err)
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

// LinkLegacy checks the proof, then re-reads the account under its row lock
// in the transaction that links it. A password change, or a disabled
// account, that lands between the two is refused there. The test holds the
// row lock until LinkLegacy, past its proof check, waits on it; then it
// changes the row and lets go.
func TestPlatformLinkRechecksTheAccountUnderItsLock(t *testing.T) {
	f := newPlatformFixture(t)
	for _, tc := range []struct{ name, change string }{
		{"a new password", `UPDATE users SET auth_hash = 'changed in between' WHERE id = $1`},
		{"a disabled account", `UPDATE users SET status = 'disabled' WHERE id = $1`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			email := uuid.NewString() + "@example.com"
			legacy := f.legacy(t, email, "auth-key")
			ticket := f.ticket(t, store.TicketNew, uuid.New(), "linker@id.example.com", uuid.Nil)
			wrap := platformWrap(t)
			var home uuid.UUID
			if err := f.pool.QueryRow(ctx, `SELECT tenant_id FROM user_logins WHERE user_id = $1`, legacy.ID).Scan(&home); err != nil {
				t.Fatal(err)
			}
			tx, err := f.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			var holder int
			if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&holder); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, home.String()); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, `SELECT 1 FROM users WHERE id = $1 FOR UPDATE`, legacy.ID); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				_, err := f.users.LinkLegacy(ctx, store.LegacyLink{Ticket: ticket, Proof: store.LegacyProof{Email: email, Secret: "auth-key"}, Wrap: wrap})
				done <- err
			}()
			for deadline := time.Now().Add(10 * time.Second); ; {
				var waiting int
				if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE $1 = ANY (pg_blocking_pids(pid))`, holder).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting > 0 {
					break
				}
				select {
				case err := <-done:
					t.Fatalf("LinkLegacy returned before it waited on the account: %v", err)
				default:
				}
				if time.Now().After(deadline) {
					t.Fatal("LinkLegacy never waited on the account's lock")
				}
				time.Sleep(10 * time.Millisecond)
			}
			if _, err := tx.Exec(ctx, tc.change, legacy.ID); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-done; !errors.Is(err, store.ErrBadCredentials) {
				t.Fatalf("the link after %s: %v", tc.name, err)
			}
			var linked int
			if err := f.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM platform_identities WHERE user_id = $1) + (SELECT count(*) FROM platform_wraps WHERE user_id = $1)`, legacy.ID).Scan(&linked); err != nil || linked != 0 {
				t.Fatalf("%d link rows %v", linked, err)
			}
			// The refused transaction spent nothing.
			if _, err := f.users.PlatformTicketFor(ctx, ticket, store.TicketNew); err != nil {
				t.Fatalf("the ticket after a refused link: %v", err)
			}
		})
	}
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

// A session started through the provider holds no step-up proof until step
// 4 takes the provider's re-authentication (internal/stepup): it is never
// fresh, nor is a workspace switch made from it, while a password sign-in of
// the same linked account is; a step-up recorded on it counts as on any.
func TestPlatformSessionHoldsNoStepUpProof(t *testing.T) {
	f := newPlatformFixture(t)
	ctx := context.Background()
	f.legacy(t, "lia@example.com", "lia-auth-key")
	linked, err := f.users.LinkLegacy(ctx, store.LegacyLink{Ticket: f.ticket(t, store.TicketNew, uuid.New(), "lia@id.example.com", uuid.Nil),
		Proof: store.LegacyProof{Email: "lia@example.com", Secret: "lia-auth-key"}, Wrap: platformWrap(t)})
	if err != nil {
		t.Fatalf("link: %v", err)
	}
	native, err := f.users.SignupPlatform(ctx, store.NewPlatformUser{Ticket: f.ticket(t, store.TicketNew, uuid.New(), "max@example.com", uuid.Nil),
		PublicKey: platformBytes(t, 32), Wrap: platformWrap(t)})
	if err != nil {
		t.Fatalf("new account: %v", err)
	}
	checker := stepup.Recent(f.users)
	for name, user := range map[string]store.User{"the linked account": linked, "the new account": native} {
		_, s, err := f.users.StartPlatformSession(ctx, user, "test")
		if err != nil {
			t.Fatalf("%s: session: %v", name, err)
		}
		if fresh, err := checker.Fresh(ctx, s.ID); err != nil || fresh {
			t.Fatalf("%s: a sign-in through the provider is a proof: %v %v", name, fresh, err)
		}
		if left, err := f.users.StepUpRemaining(ctx, s.ID, stepup.Window); err != nil || left != 0 {
			t.Fatalf("%s: remaining %v %v", name, left, err)
		}
		_, switched, err := f.users.StartWorkspaceSession(ctx, user, "test", s)
		if err != nil {
			t.Fatalf("%s: a workspace switch: %v", name, err)
		}
		if fresh, err := checker.Fresh(ctx, switched.ID); err != nil || fresh {
			t.Fatalf("%s: a switch made a proof: %v %v", name, fresh, err)
		}
		if err := f.users.MarkStepUp(ctx, s.ID); err != nil {
			t.Fatalf("%s: mark: %v", name, err)
		}
		if fresh, err := checker.Fresh(ctx, s.ID); err != nil || !fresh {
			t.Fatalf("%s: after a recorded step-up: %v %v", name, fresh, err)
		}
	}
	// Both doors: the linked account's legacy password proves the person at
	// sign-in, as any password does.
	_, s, err := f.users.StartSession(ctx, linked, "test")
	if err != nil {
		t.Fatal(err)
	}
	if fresh, err := checker.Fresh(ctx, s.ID); err != nil || !fresh {
		t.Fatalf("a password sign-in of the linked account: %v %v", fresh, err)
	}
}

// 0048's down-step, exactly as the migration's header documents it, as the
// table owner: it refuses while an account created through the provider
// exists; once that account is deleted it brings a linked account back to
// local with its old password, signs out every session started through the
// provider (via_provider), even one a step-up at the provider has given a
// proof, drops the tables and columns, restores 0020's constraint, forgets
// version 48; and 0048 comes back up.
func TestMigration0048DownStep(t *testing.T) {
	f := newPlatformFixture(t)
	ctx := context.Background()
	legacy := f.legacy(t, "lia@example.com", "lia-auth-key")
	linkSub := uuid.New()
	linked, err := f.users.LinkLegacy(ctx, store.LegacyLink{Ticket: f.ticket(t, store.TicketNew, linkSub, "lia@id.example.com", uuid.Nil),
		Proof: store.LegacyProof{Email: "lia@example.com", Secret: "lia-auth-key"}, Wrap: platformWrap(t)})
	if err != nil {
		t.Fatalf("link: %v", err)
	}
	// A session through the provider (no proof: -infinity, which the older
	// binary cannot read) and one with the old password.
	_, throughProvider, err := f.users.StartPlatformSession(ctx, linked, "test")
	if err != nil {
		t.Fatal(err)
	}
	_, withPassword, err := f.users.StartSession(ctx, linked, "test")
	if err != nil {
		t.Fatal(err)
	}
	// One through the provider that has since been confirmed there: its
	// proof is a plain time, but it came through the provider all the same.
	_, confirmed, err := f.users.StartPlatformSession(ctx, linked, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE sessions SET via_provider = true, authenticated_at = now() WHERE id = $1`, confirmed.ID); err != nil {
		t.Fatal(err)
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
	// The sessions through the provider are signed out, the confirmed one
	// too; the password's stays, and every live session's proof reads as a
	// plain time, as the older binary's workspace switch reads it.
	for id, live := range map[uuid.UUID]bool{throughProvider.ID: false, confirmed.ID: false, withPassword.ID: true} {
		var revoked bool
		if err := f.pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM sessions WHERE id = $1`, id).Scan(&revoked); err != nil || revoked == live {
			t.Fatalf("session %s revoked = %v %v", id, revoked, err)
		}
	}
	rows, err := f.pool.Query(ctx, `SELECT authenticated_at FROM sessions WHERE revoked_at IS NULL`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pgx.CollectRows(rows, pgx.RowTo[time.Time]); err != nil {
		t.Fatalf("a live session's proof after the down-step: %v", err)
	}
	var left int
	if err := f.pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM information_schema.tables WHERE table_schema = current_schema()
		   AND table_name IN ('platform_key_pins', 'platform_identities', 'platform_wraps', 'platform_login_tickets', 'security_events'))
		+ (SELECT count(*) FROM information_schema.columns WHERE table_schema = current_schema()
		   AND ((table_name = 'users' AND column_name = 'auth_source')
		     OR (table_name = 'sessions' AND (column_name LIKE 'step_up%' OR column_name = 'via_provider'))))
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
