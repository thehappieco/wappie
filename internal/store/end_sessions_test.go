package store_test

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/google/uuid"

	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
)

// A logout's log line says how many sessions it ended (authapi logout.go):
// the family of a browser that opened two workspaces is three, a repeat is
// none, one token alone is one, and a token that names nothing is nobody's.
// EndSession and EndSessionFamily do what they did.
func TestEndSessionsCounts(t *testing.T) {
	pool := pgtest.Fresh(t, migrate.Run)
	ctx := context.Background()
	tenant := uuid.MustParse(newTenant(t, pool, "acme"))
	users := store.NewUsers(pool)
	user, err := users.Create(ctx, store.NewUser{
		TenantID: tenant, Email: "ends@example.com", AuthKey: "k", KDFSalt: make([]byte, 16),
		KDFParams: store.DefaultKDFParams(), PublicKey: make([]byte, 32), WrappedUSK: []byte("w"),
	})
	if err != nil {
		t.Fatal(err)
	}
	browser := func() (string, []string) {
		t.Helper()
		token, login, err := users.StartSession(ctx, user, "browser")
		if err != nil {
			t.Fatal(err)
		}
		var derived []string
		for range 2 {
			minted, _, err := users.StartWorkspaceSession(ctx, user, "browser workspace", login)
			if err != nil {
				t.Fatal(err)
			}
			derived = append(derived, minted)
		}
		return token, derived
	}
	gone := func(tokens ...string) {
		t.Helper()
		for _, token := range tokens {
			if _, err := users.Session(ctx, token); !errors.Is(err, store.ErrNoSession) {
				t.Fatalf("a session survived its logout: %v", err)
			}
		}
	}

	login, derived := browser()
	other, otherDerived := browser()
	ended, err := users.EndSessions(ctx, derived[0], false)
	if err != nil || ended != (store.EndedSessions{User: user.ID, Revoked: 1}) {
		t.Fatalf("one token: %+v %v, want one of %s", ended, err, user.ID)
	}
	gone(derived[0])
	if ended, err = users.EndSessions(ctx, derived[0], false); err != nil || ended != (store.EndedSessions{User: user.ID, Revoked: 0}) {
		t.Fatalf("the same token again: %+v %v, want none", ended, err)
	}
	// The family is the login and what it minted, the token already ended
	// excepted; the other browser's stays.
	if ended, err = users.EndSessions(ctx, login, true); err != nil || ended != (store.EndedSessions{User: user.ID, Revoked: 2}) {
		t.Fatalf("the family: %+v %v, want the two left", ended, err)
	}
	gone(login, derived[1])
	if ended, err = users.EndSessions(ctx, login, true); err != nil || ended != (store.EndedSessions{User: user.ID, Revoked: 0}) {
		t.Fatalf("the family again: %+v %v, want none", ended, err)
	}
	if ended, err = users.EndSessions(ctx, otherDerived[1], true); err != nil || ended != (store.EndedSessions{User: user.ID, Revoked: 3}) {
		t.Fatalf("another browser's family, from a workspace token: %+v %v, want all three", ended, err)
	}
	gone(other, otherDerived[0], otherDerived[1])
	for _, token := range []string{"", "malformed", base64.RawURLEncoding.EncodeToString(make([]byte, 32))} {
		for _, all := range []bool{false, true} {
			if ended, err := users.EndSessions(ctx, token, all); err != nil || ended != (store.EndedSessions{}) {
				t.Fatalf("token %q (all_related %v): %+v %v, want nobody's", token, all, ended, err)
			}
		}
	}

	// The two that drop the count behave as before.
	single, family := browser()
	if err := users.EndSession(ctx, family[0]); err != nil {
		t.Fatal(err)
	}
	gone(family[0])
	if _, err := users.Session(ctx, single); err != nil {
		t.Fatalf("one token's logout ended the login: %v", err)
	}
	if err := users.EndSessionFamily(ctx, family[0]); err != nil {
		t.Fatal(err)
	}
	gone(single, family[1])
	if err := users.EndSessionFamily(ctx, "malformed"); err != nil {
		t.Fatal(err)
	}
}
