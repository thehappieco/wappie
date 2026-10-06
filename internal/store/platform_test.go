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
	user, _, err := f.users.SignupPlatform(ctx, store.NewPlatformUser{Ticket: secret, PublicKey: platformBytes(t, 32), Wrap: platformWrap(t)})
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
	if _, _, err := f.users.SignupPlatform(ctx, store.NewPlatformUser{Ticket: link, PublicKey: platformBytes(t, 32), Wrap: platformWrap(t)}); !errors.Is(err, store.ErrTicketInvalid) {
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
	if _, _, err := f.users.SignupPlatform(ctx, store.NewPlatformUser{Ticket: forged, PublicKey: platformBytes(t, 32), Wrap: platformWrap(t)}); !errors.Is(err, store.ErrTicketInvalid) {
		t.Fatalf("a ticket that disagrees with its pin: %v", err)
	}
}

// A sign-in through the provider proves its person from the provider's
// auth_time (Decision 2 of step 4), never later than now and never from the
// session's creation: a recent one is a proof for the rest of its ten
// minutes, an old one is none, and one userinfo named no auth_time for
// holds none (-infinity). Every such session, and a workspace switch made
// from it, is via_provider; a link's proof is now; a password sign-in of the
// same linked account is neither via_provider nor short of a proof.
func TestPlatformSessionProofIsTheProvidersAuthTime(t *testing.T) {
	f := newPlatformFixture(t)
	ctx := context.Background()
	f.legacy(t, "lia@example.com", "lia-auth-key")
	linked, err := f.users.LinkLegacy(ctx, store.LegacyLink{Ticket: f.ticket(t, store.TicketNew, uuid.New(), "lia@id.example.com", uuid.Nil),
		Proof: store.LegacyProof{Email: "lia@example.com", Secret: "lia-auth-key"}, Wrap: platformWrap(t)})
	if err != nil {
		t.Fatalf("link: %v", err)
	}
	native, _, err := f.users.SignupPlatform(ctx, store.NewPlatformUser{Ticket: f.ticket(t, store.TicketNew, uuid.New(), "max@example.com", uuid.Nil),
		PublicKey: platformBytes(t, 32), Wrap: platformWrap(t)})
	if err != nil {
		t.Fatalf("new account: %v", err)
	}
	checker := stepup.Recent(f.users)
	remaining := func(name string, s store.Session) time.Duration {
		t.Helper()
		left, err := f.users.StepUpRemaining(ctx, s.ID, stepup.Window)
		if err != nil {
			t.Fatalf("%s: remaining: %v", name, err)
		}
		return left
	}
	for name, user := range map[string]store.User{"the linked account": linked, "the new account": native} {
		for _, tc := range []struct {
			what     string
			authTime time.Time
			min, max time.Duration
		}{
			{"a recent auth_time", time.Now().Add(-time.Minute), 8 * time.Minute, 9*time.Minute + 30*time.Second},
			{"an auth_time eleven minutes old", time.Now().Add(-11 * time.Minute), 0, 0},
			{"no auth_time", time.Time{}, 0, 0},
			// A provider's clock ahead of this one earns nothing past now.
			{"an auth_time an hour ahead", time.Now().Add(time.Hour), 9 * time.Minute, stepup.Window},
		} {
			_, s, err := f.users.StartPlatformSession(ctx, user, "test", tc.authTime)
			if err != nil {
				t.Fatalf("%s, %s: session: %v", name, tc.what, err)
			}
			if !s.ViaProvider {
				t.Fatalf("%s, %s: not via_provider", name, tc.what)
			}
			if left := remaining(name+", "+tc.what, s); left < tc.min || left > tc.max {
				t.Fatalf("%s, %s: remaining %v, want %v to %v", name, tc.what, left, tc.min, tc.max)
			}
			// A workspace switch copies the proof and the mark, and proves
			// nothing of its own.
			_, switched, err := f.users.StartWorkspaceSession(ctx, user, "test", s)
			if err != nil {
				t.Fatalf("%s, %s: a workspace switch: %v", name, tc.what, err)
			}
			if !switched.ViaProvider {
				t.Fatalf("%s, %s: the switch is not via_provider", name, tc.what)
			}
			if left := remaining(name+", "+tc.what+", switched", switched); left < tc.min || left > tc.max {
				t.Fatalf("%s, %s: the switch's remaining %v", name, tc.what, left)
			}
		}
	}
	// The mark reads back with the token.
	token, _, err := f.users.StartPlatformSession(ctx, native, "test", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if s, err := f.users.Session(ctx, token); err != nil || !s.ViaProvider {
		t.Fatalf("the session read back: %+v %v", s, err)
	}
	// A link proves the old password now.
	_, s, err := f.users.StartLinkedSession(ctx, linked, "test")
	if err != nil {
		t.Fatal(err)
	}
	if fresh, err := checker.Fresh(ctx, s.ID); err != nil || !fresh || !s.ViaProvider {
		t.Fatalf("a link's session: %v %v %+v", fresh, err, s)
	}
	// Both doors: the linked account's legacy password proves the person at
	// sign-in, as any password does, and the session is not via_provider.
	token, s, err = f.users.StartSession(ctx, linked, "test")
	if err != nil {
		t.Fatal(err)
	}
	if fresh, err := checker.Fresh(ctx, s.ID); err != nil || !fresh || s.ViaProvider {
		t.Fatalf("a password sign-in of the linked account: %v %v %+v", fresh, err, s)
	}
	if read, err := f.users.Session(ctx, token); err != nil || read.ViaProvider {
		t.Fatalf("the password session read back: %+v %v", read, err)
	}
	_, switched, err := f.users.StartWorkspaceSession(ctx, linked, "test", s)
	if err != nil || switched.ViaProvider {
		t.Fatalf("a switch from the password session: %+v %v", switched, err)
	}
}

// A new account's first session starts with the auth_time of the userinfo
// its ticket was issued on, which the ticket keeps; none when it had none.
func TestPlatformTicketKeepsTheAuthTime(t *testing.T) {
	f := newPlatformFixture(t)
	ctx := context.Background()
	at := time.Now().Add(-2 * time.Minute).Truncate(time.Second)
	for name, want := range map[string]time.Time{"with an auth_time": at, "without one": {}} {
		sub := uuid.New()
		key := platformBytes(t, 32)
		if _, _, err := f.pins.InsertPin(ctx, sub.String(), "wappie:1", key); err != nil {
			t.Fatal(err)
		}
		secret, err := f.users.CreatePlatformTicket(ctx, store.PlatformTicket{Kind: store.TicketNew, Sub: sub, ProductKeyID: "wappie:1",
			ProductKey: key, Email: sub.String() + "@example.com", AuthTime: want})
		if err != nil {
			t.Fatal(err)
		}
		ticket, err := f.users.PlatformTicketFor(ctx, secret, store.TicketNew)
		if err != nil || !ticket.AuthTime.Equal(want) {
			t.Fatalf("%s: the ticket's auth_time %v %v", name, ticket.AuthTime, err)
		}
		user, authTime, err := f.users.SignupPlatform(ctx, store.NewPlatformUser{Ticket: secret, PublicKey: platformBytes(t, 32), Wrap: platformWrap(t)})
		if err != nil || user.ID != sub || !authTime.Equal(want) {
			t.Fatalf("%s: the new account's auth_time %v %v", name, authTime, err)
		}
	}
}

// One start, one proof (Decision 3 of step 4): the finish records the proof
// only against the start it read, while that start is younger than ten
// minutes and the provider's auth_time is not more than the clocks'
// tolerance before it; it clears the start in the same statement, so a
// second finish, or the finish of a start a newer one replaced, records
// nothing. A refusal leaves the start as it was.
func TestProviderStepUpOneStartOneProof(t *testing.T) {
	f := newPlatformFixture(t)
	ctx := context.Background()
	user, _, err := f.users.SignupPlatform(ctx, store.NewPlatformUser{Ticket: f.ticket(t, store.TicketNew, uuid.New(), "noa@example.com", uuid.Nil),
		PublicKey: platformBytes(t, 32), Wrap: platformWrap(t)})
	if err != nil {
		t.Fatal(err)
	}
	checker := stepup.Recent(f.users)
	session := func() store.Session {
		t.Helper()
		_, s, err := f.users.StartPlatformSession(ctx, user, "test", time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	fresh := func(s store.Session) bool {
		t.Helper()
		ok, err := checker.Fresh(ctx, s.ID)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	finish := func(s store.Session, notBefore, authTime time.Time) error {
		return f.users.FinishProviderStepUp(ctx, s.ID, store.PendingStepUp{Session: s.ID, NotBefore: notBefore}, authTime, stepup.Window, stepup.ProviderClockTolerance)
	}
	pendingOf := func(s store.Session) (time.Time, error) {
		t.Helper()
		p, err := f.users.PendingProviderStepUp(ctx, s.ID, stepup.Window)
		if err == nil && p.Session != s.ID {
			t.Fatalf("the pending start is %v's, want %v's", p.Session, s.ID)
		}
		return p.NotBefore, err
	}

	s := session()
	if _, err := f.users.PendingProviderStepUp(ctx, s.ID, stepup.Window); !errors.Is(err, store.ErrStepUpNotStarted) {
		t.Fatalf("nothing started: %v", err)
	}
	if err := finish(s, time.Now(), time.Now()); !errors.Is(err, store.ErrStepUpNotStarted) {
		t.Fatalf("a finish with no start: %v", err)
	}
	notBefore, err := f.users.StartProviderStepUp(ctx, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if pending, err := pendingOf(s); err != nil || !pending.Equal(notBefore) {
		t.Fatalf("pending %v %v, want %v", pending, err, notBefore)
	}
	// An auth_time past the tolerance before the start: the provider did
	// not ask again. Nothing is recorded and the start stays.
	for _, stale := range []time.Time{{}, notBefore.Add(-stepup.ProviderClockTolerance - time.Second), notBefore.Add(-time.Hour)} {
		if err := finish(s, notBefore, stale); !errors.Is(err, store.ErrStepUpStale) || fresh(s) {
			t.Fatalf("auth_time %v: %v", stale, err)
		}
	}
	if pending, err := pendingOf(s); err != nil || !pending.Equal(notBefore) {
		t.Fatalf("a refusal moved the start: %v %v", pending, err)
	}
	// Within the tolerance: the proof, now, and the start is spent.
	if err := finish(s, notBefore, notBefore.Add(-30*time.Second)); err != nil || !fresh(s) {
		t.Fatalf("an auth_time within the tolerance: %v", err)
	}
	if left, err := f.users.StepUpRemaining(ctx, s.ID, stepup.Window); err != nil || left < 9*time.Minute {
		t.Fatalf("the proof is not now: %v %v", left, err)
	}
	if err := finish(s, notBefore, time.Now()); !errors.Is(err, store.ErrStepUpNotStarted) {
		t.Fatalf("a second finish of one start: %v", err)
	}
	if _, err := f.users.PendingProviderStepUp(ctx, s.ID, stepup.Window); !errors.Is(err, store.ErrStepUpNotStarted) {
		t.Fatalf("the start after its proof: %v", err)
	}

	// Two starts: the first is void, the second makes the proof.
	s = session()
	first, err := f.users.StartProviderStepUp(ctx, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.users.StartProviderStepUp(ctx, s.ID)
	if err != nil || !second.After(first) {
		t.Fatalf("second start %v %v", second, err)
	}
	if err := finish(s, first, time.Now()); !errors.Is(err, store.ErrStepUpNotStarted) || fresh(s) {
		t.Fatalf("the finish of a replaced start: %v", err)
	}
	if err := finish(s, second, time.Now()); err != nil || !fresh(s) {
		t.Fatalf("the finish of the newer start: %v", err)
	}

	// A start older than ten minutes is no start (and a workspace switch
	// copies none: TestProviderStepUpAcrossTheSessionFamily).
	s = session()
	if _, err := f.users.StartProviderStepUp(ctx, s.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE sessions SET step_up_not_before = step_up_not_before - interval '10 minutes 1 second' WHERE id = $1`, s.ID); err != nil {
		t.Fatal(err)
	}
	var aged time.Time
	if err := f.pool.QueryRow(ctx, `SELECT step_up_not_before FROM sessions WHERE id = $1`, s.ID).Scan(&aged); err != nil {
		t.Fatal(err)
	}
	if _, err := f.users.PendingProviderStepUp(ctx, s.ID, stepup.Window); !errors.Is(err, store.ErrStepUpNotStarted) {
		t.Fatalf("a start eleven minutes old: %v", err)
	}
	if err := finish(s, aged, aged.Add(time.Second)); !errors.Is(err, store.ErrStepUpNotStarted) || fresh(s) {
		t.Fatalf("the finish of a start past the window: %v", err)
	}

	// A session that is not live starts and finishes nothing.
	s = session()
	notBefore, err = f.users.StartProviderStepUp(ctx, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE sessions SET revoked_at = now() WHERE id = $1`, s.ID); err != nil {
		t.Fatal(err)
	}
	if err := finish(s, notBefore, time.Now()); !errors.Is(err, store.ErrNoSession) {
		t.Fatalf("a revoked session's finish: %v", err)
	}
	if _, err := f.users.StartProviderStepUp(ctx, s.ID); !errors.Is(err, store.ErrNoSession) {
		t.Fatalf("a revoked session's start: %v", err)
	}
	if _, err := f.users.PendingProviderStepUp(ctx, s.ID, stepup.Window); !errors.Is(err, store.ErrNoSession) {
		t.Fatalf("a revoked session's pending start: %v", err)
	}

	// Two finishes of one start at once, as two windows would send them:
	// one proof.
	s = session()
	notBefore, err = f.users.StartProviderStepUp(ctx, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	const racers = 6
	errs := make(chan error, racers)
	for range racers {
		go func() { errs <- finish(s, notBefore, time.Now()) }()
	}
	won := 0
	for range racers {
		switch err := <-errs; {
		case err == nil:
			won++
		case !errors.Is(err, store.ErrStepUpNotStarted):
			t.Fatalf("a racing finish: %v", err)
		}
	}
	if won != 1 || !fresh(s) {
		t.Fatalf("%d finishes of one start recorded a proof", won)
	}
}

// A finish answers the newest start of the finishing session's family, the
// browser sign-in it and the starter were derived from: the console's
// confirmation window holds the sign-in's token while the page that started
// works in a session a workspace switch derived from it (and a page that
// confirmed in its own tab reopens a new one from the sign-in). The proof goes
// to the starter and to the finisher; the switch copies no start of its
// own; a session of another sign-in of the same account finds nothing; and
// one start still makes one proof, whichever sessions of the family race.
func TestProviderStepUpAcrossTheSessionFamily(t *testing.T) {
	f := newPlatformFixture(t)
	ctx := context.Background()
	user, _, err := f.users.SignupPlatform(ctx, store.NewPlatformUser{Ticket: f.ticket(t, store.TicketNew, uuid.New(), "ivo@example.com", uuid.Nil),
		PublicKey: platformBytes(t, 32), Wrap: platformWrap(t)})
	if err != nil {
		t.Fatal(err)
	}
	checker := stepup.Recent(f.users)
	fresh := func(s store.Session) bool {
		t.Helper()
		ok, err := checker.Fresh(ctx, s.ID)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	ownStart := func(s store.Session) bool {
		t.Helper()
		var started bool
		if err := f.pool.QueryRow(ctx, `SELECT step_up_not_before IS NOT NULL FROM sessions WHERE id = $1`, s.ID).Scan(&started); err != nil {
			t.Fatal(err)
		}
		return started
	}
	family := func() (login, switched store.Session) {
		t.Helper()
		_, login, err := f.users.StartPlatformSession(ctx, user, "test", time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		_, switched, err = f.users.StartWorkspaceSession(ctx, user, "test", login)
		if err != nil {
			t.Fatal(err)
		}
		return login, switched
	}

	// The page's workspace session starts; the window finishes with the sign-in's token.
	login, switched := family()
	notBefore, err := f.users.StartProviderStepUp(ctx, switched.ID)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := f.users.PendingProviderStepUp(ctx, login.ID, stepup.Window)
	if err != nil || pending.Session != switched.ID || !pending.NotBefore.Equal(notBefore) {
		t.Fatalf("the family's pending start %+v %v, want %v at %v", pending, err, switched.ID, notBefore)
	}
	if err := f.users.FinishProviderStepUp(ctx, login.ID, pending, time.Now(), stepup.Window, stepup.ProviderClockTolerance); err != nil {
		t.Fatal(err)
	}
	if !fresh(switched) || !fresh(login) || ownStart(switched) {
		t.Fatalf("after the finish: starter fresh %v, finisher fresh %v, start left %v", fresh(switched), fresh(login), ownStart(switched))
	}
	if err := f.users.FinishProviderStepUp(ctx, switched.ID, pending, time.Now(), stepup.Window, stepup.ProviderClockTolerance); !errors.Is(err, store.ErrStepUpNotStarted) {
		t.Fatalf("a second finish of one start from the family: %v", err)
	}

	// The other way: the sign-in's session starts, a switch made since copies
	// no start but finishes it, and a session it derives later copies the proof.
	login, _ = family()
	notBefore, err = f.users.StartProviderStepUp(ctx, login.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, later, err := f.users.StartWorkspaceSession(ctx, user, "test", login)
	if err != nil {
		t.Fatal(err)
	}
	if ownStart(later) {
		t.Fatal("a switch copied the start")
	}
	if pending, err = f.users.PendingProviderStepUp(ctx, later.ID, stepup.Window); err != nil || pending.Session != login.ID {
		t.Fatalf("the switch's family start %+v %v", pending, err)
	}
	if err := f.users.FinishProviderStepUp(ctx, later.ID, pending, time.Now(), stepup.Window, stepup.ProviderClockTolerance); err != nil || !fresh(login) || !fresh(later) {
		t.Fatalf("a switch finishing its source's start: %v", err)
	}
	_, derived, err := f.users.StartWorkspaceSession(ctx, user, "test", login)
	if err != nil || !fresh(derived) {
		t.Fatalf("a session derived after the proof: %v fresh %v", err, err == nil && fresh(derived))
	}

	// Another sign-in of the same account is another family: nothing to finish.
	login, switched = family()
	if _, err := f.users.StartProviderStepUp(ctx, switched.ID); err != nil {
		t.Fatal(err)
	}
	other, _ := family()
	if _, err := f.users.PendingProviderStepUp(ctx, other.ID, stepup.Window); !errors.Is(err, store.ErrStepUpNotStarted) {
		t.Fatalf("another sign-in saw the start: %v", err)
	}
	pending, err = f.users.PendingProviderStepUp(ctx, login.ID, stepup.Window)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.users.FinishProviderStepUp(ctx, other.ID, pending, time.Now(), stepup.Window, stepup.ProviderClockTolerance); !errors.Is(err, store.ErrStepUpNotStarted) || fresh(switched) || fresh(other) {
		t.Fatalf("another sign-in finished the start: %v", err)
	}

	// Two starts in one family (two tabs in two workspaces): the newest is the
	// one a finish answers; the older one is left, and its tab is told to start again.
	_, second, err := f.users.StartWorkspaceSession(ctx, user, "test", login)
	if err != nil {
		t.Fatal(err)
	}
	newest, err := f.users.StartProviderStepUp(ctx, second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if pending, err = f.users.PendingProviderStepUp(ctx, login.ID, stepup.Window); err != nil || pending.Session != second.ID || !pending.NotBefore.Equal(newest) {
		t.Fatalf("two starts in a family: %+v %v", pending, err)
	}

	// Racing finishes from every session of the family: one proof.
	const racers = 6
	errs := make(chan error, racers)
	for i := range racers {
		from := []store.Session{login, switched, second}[i%3]
		go func() {
			errs <- f.users.FinishProviderStepUp(ctx, from.ID, pending, time.Now(), stepup.Window, stepup.ProviderClockTolerance)
		}()
	}
	won := 0
	for range racers {
		switch err := <-errs; {
		case err == nil:
			won++
		case !errors.Is(err, store.ErrStepUpNotStarted):
			t.Fatalf("a racing finish: %v", err)
		}
	}
	if won != 1 || !fresh(second) || ownStart(second) || !ownStart(switched) {
		t.Fatalf("%d finishes recorded a proof; newest start fresh %v", won, fresh(second))
	}
}

// The step-up reads the pin and the link and writes neither: a pin that does
// not exist stays absent.
func TestPlatformPinAndLinkReads(t *testing.T) {
	f := newPlatformFixture(t)
	ctx := context.Background()
	sub := uuid.New()
	if _, err := f.pins.Pinned(ctx, sub, "wappie:1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("no pin: %v", err)
	}
	var pins int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM platform_key_pins WHERE sub = $1`, sub).Scan(&pins); err != nil || pins != 0 {
		t.Fatalf("reading a pin made %d %v", pins, err)
	}
	key := platformBytes(t, 32)
	if _, _, err := f.pins.InsertPin(ctx, sub.String(), "wappie:1", key); err != nil {
		t.Fatal(err)
	}
	if got, err := f.pins.Pinned(ctx, sub, "wappie:1"); err != nil || !bytes.Equal(got, key) {
		t.Fatalf("the pin: %v %v", got, err)
	}
	if _, err := f.pins.Pinned(ctx, sub, "wappie:2"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("another epoch: %v", err)
	}

	legacy := f.legacy(t, "ria@example.com", "ria-auth-key")
	if _, err := f.users.PlatformLinkOf(ctx, legacy.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an unlinked account: %v", err)
	}
	linkSub := uuid.New()
	if _, err := f.users.LinkLegacy(ctx, store.LegacyLink{Ticket: f.ticket(t, store.TicketNew, linkSub, "ria@id.example.com", uuid.Nil),
		Proof: store.LegacyProof{Email: "ria@example.com", Secret: "ria-auth-key"}, Wrap: platformWrap(t)}); err != nil {
		t.Fatal(err)
	}
	if link, err := f.users.PlatformLinkOf(ctx, legacy.ID); err != nil || link.Sub != linkSub || link.Email != "ria@id.example.com" || link.LinkedFrom != "legacy" {
		t.Fatalf("the link: %+v %v", link, err)
	}
}

// An address the identity provider confirmed counts as verified (the
// precondition of an untested assistant's or a token's text, and of the
// notice and renewal e-mails): the address of an account created through the
// provider is the provider's, and so is a linked account's when its own
// address is the one id. knows. A linked account whose address differs keeps
// its own state, and a password account none.
func TestPlatformAddressIsVerified(t *testing.T) {
	f := newPlatformFixture(t)
	ctx := context.Background()
	verified := func(u store.User) bool {
		t.Helper()
		ok, err := f.users.EmailVerified(ctx, u.TenantID, u.ID)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	created, _, err := f.users.SignupPlatform(ctx, store.NewPlatformUser{Ticket: f.ticket(t, store.TicketNew, uuid.New(), "Lia@Example.com", uuid.Nil),
		PublicKey: platformBytes(t, 32), Wrap: platformWrap(t)})
	if err != nil {
		t.Fatal(err)
	}
	if !verified(created) {
		t.Fatal("an account created through the provider has no verified address")
	}

	same := f.legacy(t, "rui@example.com", "rui-auth-key")
	other := f.legacy(t, "ria@example.com", "ria-auth-key")
	if verified(same) || verified(other) {
		t.Fatal("a password account made by invitation is verified")
	}
	for _, link := range []struct {
		user  store.User
		email string
	}{{same, "RUI@example.com"}, {other, "ria@id.example.com"}} {
		if _, err := f.users.LinkLegacy(ctx, store.LegacyLink{Ticket: f.ticket(t, store.TicketNew, uuid.New(), link.email, uuid.Nil),
			Proof: store.LegacyProof{Email: link.user.Email, Secret: strings.Split(link.user.Email, "@")[0] + "-auth-key"}, Wrap: platformWrap(t)}); err != nil {
			t.Fatal(err)
		}
	}
	if !verified(same) {
		t.Fatal("a linked account whose address is the provider's is not verified")
	}
	if verified(other) {
		t.Fatal("a linked account whose address is not the provider's became verified")
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
	// A session through the provider with no proof (-infinity, which the
	// older binary cannot read), one whose sign-in's auth_time is its proof,
	// one confirmed at the provider since, a workspace switch from that
	// one, the link's own session, and one with the old password. Every one
	// but the last came through the provider.
	_, throughProvider, err := f.users.StartPlatformSession(ctx, linked, "test", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	_, signedIn, err := f.users.StartPlatformSession(ctx, linked, "test", time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	_, confirmed, err := f.users.StartPlatformSession(ctx, linked, "test", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	notBefore, err := f.users.StartProviderStepUp(ctx, confirmed.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.users.FinishProviderStepUp(ctx, confirmed.ID, store.PendingStepUp{Session: confirmed.ID, NotBefore: notBefore}, time.Now(), stepup.Window, stepup.ProviderClockTolerance); err != nil {
		t.Fatal(err)
	}
	_, switched, err := f.users.StartWorkspaceSession(ctx, linked, "test", confirmed)
	if err != nil {
		t.Fatal(err)
	}
	_, linkSession, err := f.users.StartLinkedSession(ctx, linked, "test")
	if err != nil {
		t.Fatal(err)
	}
	_, withPassword, err := f.users.StartSession(ctx, linked, "test")
	if err != nil {
		t.Fatal(err)
	}
	native := uuid.New()
	if _, _, err := f.users.SignupPlatform(ctx, store.NewPlatformUser{Ticket: f.ticket(t, store.TicketNew, native, "max@example.com", uuid.Nil),
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
	// The sessions through the provider are signed out, the confirmed ones
	// too; the password's stays, and every live session's proof reads as a
	// plain time, as the older binary's workspace switch reads it.
	for id, live := range map[uuid.UUID]bool{throughProvider.ID: false, signedIn.ID: false, confirmed.ID: false, switched.ID: false,
		linkSession.ID: false, withPassword.ID: true} {
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
