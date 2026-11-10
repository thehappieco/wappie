package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/access"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/store"
	"whatserver2/internal/tokentest"
)

func newAuthWorld(t *testing.T) *tokentest.World {
	t.Helper()
	return tokentest.New(t, pgtest.Fresh(t, migrate.Run), uuid.Nil)
}

// forAuth is ForAuth now, as (auth, failure, refused).
func forAuth(t *testing.T, w *tokentest.World, text string) (store.TokenAuth, store.TokenFailure, bool) {
	t.Helper()
	auth, fail, err := w.Tokens.ForAuth(context.Background(), text, time.Now())
	if err != nil && !errors.Is(err, store.ErrInvalidToken) {
		t.Fatal(err)
	}
	return auth, fail, err != nil
}

// TestForAuthVerifiesTheSecretFirst: a text that does not parse, a
// selector Wappie holds none of, and a wrong secret under a known selector
// are each refused with their class and no token, so nothing is counted;
// a matching one is the token, and a second ForAuth of an unchanged token
// equals the first (TokenAuth is comparable).
func TestForAuthVerifiesTheSecretFirst(t *testing.T) {
	w := newAuthWorld(t)
	device := w.Number("Vendas")
	tok := w.Token(tokentest.Read(device))

	other, _, _ := tokentest.Mint()
	wrong := tok.Text[:21] + other[21:]
	for name, c := range map[string]struct{ text, class string }{
		"not a token":      {"thc_" + strings.Repeat("x", 60), store.TokenFailParse},
		"empty":            {"", store.TokenFailParse},
		"unknown selector": {other, store.TokenFailUnknown},
		"wrong secret":     {wrong, store.TokenFailMismatch},
	} {
		_, fail, refused := forAuth(t, w, c.text)
		if !refused || fail.Class != c.class || fail.Token != uuid.Nil || fail.Code != "" {
			t.Errorf("%s: refused %v, %+v", name, refused, fail)
		}
	}
	auth, _, refused := forAuth(t, w, tok.Text)
	if refused || auth.ID != tok.ID || auth.Tenant != w.Tenant || auth.Selector != tok.Selector || auth.CreatedBy != w.OwnerSub || auth.Version < 1 {
		t.Fatalf("the token: %+v %v", auth, refused)
	}
	again, _, _ := forAuth(t, w, tok.Text)
	if again != auth {
		t.Fatalf("an unchanged token authenticates as another value: %+v != %+v", again, auth)
	}
}

// TestForAuthRefusesEveryPartWithItsCode: each part of the one predicate
// refuses on its own, undone before the next, with the usage code the plan
// gives it: revoked (the belt too), expired, suspended_here, and nothing
// for an unlisted token, tokens off, the contract off and an inactive
// workspace. A token row retention forgot still reads its sticky
// revocation.
func TestForAuthRefusesEveryPartWithItsCode(t *testing.T) {
	w := newAuthWorld(t)
	device := w.Number("Vendas")
	cases := []struct {
		name       string
		code       string
		set, unset func(tok *tokentest.Token)
	}{
		{"revoked", kc.UseRevoked, func(tok *tokentest.Token) { w.Revoke(tok) }, nil},
		{"expired", kc.UseExpired, func(tok *tokentest.Token) {
			tok.Version++
			w.Commit(tok, func(r *kc.TokenRecord) { r.ExpiresAt = kc.T(time.Now().Add(-time.Minute)) })
		}, nil},
		{"the belt: the creator's document drops the workspace", kc.UseRevoked, func(*tokentest.Token) {
			w.Exec(`UPDATE contract_accounts SET doc = jsonb_set(doc, '{workspaces}', '[]'::jsonb) WHERE sub = $1`, w.OwnerSub)
		}, func(*tokentest.Token) {
			w.Exec(`UPDATE contract_accounts SET doc = jsonb_set(doc, '{workspaces}', jsonb_build_array(jsonb_build_object('id', $2::text,
				'kind', 'team', 'role', 'owner', 'status', 'open', 'wversion', 1))) WHERE sub = $1`, w.OwnerSub, w.Tenant)
		}},
		{"the belt: a disable after the token", kc.UseRevoked, func(*tokentest.Token) {
			w.Exec(`UPDATE contract_accounts SET disabled_at = clock_timestamp() WHERE sub = $1`, w.OwnerSub)
		}, func(*tokentest.Token) {
			w.Exec(`UPDATE contract_accounts SET disabled_at = NULL WHERE sub = $1`, w.OwnerSub)
		}},
		{"an operator's stop", kc.UseSuspendedHere, func(tok *tokentest.Token) {
			w.Exec(`INSERT INTO contract_token_stops (selector, cause, stopped_by) VALUES ($1, 'operator', 'test')`, tok.Selector)
		}, func(tok *tokentest.Token) {
			w.Exec(`UPDATE contract_token_stops SET lifted_at = clock_timestamp() WHERE selector = $1`, tok.Selector)
		}},
		{"the creator disabled here", kc.UseSuspendedHere, func(*tokentest.Token) {
			w.ExecIn(`UPDATE users SET status = 'disabled' WHERE id = $1`, w.Owner)
		}, func(*tokentest.Token) { w.ExecIn(`UPDATE users SET status = 'active' WHERE id = $1`, w.Owner) }},
		{"local_rule: the creator a member", kc.UseSuspendedHere, func(*tokentest.Token) {
			w.ExecIn(`UPDATE workspace_memberships SET role = 'member' WHERE user_id = $1`, w.Owner)
		}, func(*tokentest.Token) {
			w.ExecIn(`UPDATE workspace_memberships SET role = 'owner' WHERE user_id = $1`, w.Owner)
		}},
		{"unlisted", "", func(tok *tokentest.Token) {
			w.ExecIn(`UPDATE contract_tokens SET unlisted_at = clock_timestamp() WHERE id = $1`, tok.ID)
		}, nil},
		{"tokens off", "", func(*tokentest.Token) { w.Exec(`UPDATE contract_token_state SET mode = 'off'`) },
			func(*tokentest.Token) {
				w.Exec(`UPDATE contract_token_state SET mode = 'on', caught_up_at = clock_timestamp()`)
			}},
		{"not caught up", "", func(*tokentest.Token) { w.Exec(`UPDATE contract_token_state SET caught_up_at = NULL`) },
			func(*tokentest.Token) { w.Exec(`UPDATE contract_token_state SET caught_up_at = clock_timestamp()`) }},
		{"the contract off", "", func(*tokentest.Token) {
			w.Exec(`UPDATE contract_state SET mode = 'off', events_paused_at = clock_timestamp()`)
		}, func(*tokentest.Token) { w.Exec(`UPDATE contract_state SET mode = 'observe', events_paused_at = NULL`) }},
		{"an inactive workspace", "", func(*tokentest.Token) { w.Exec(`UPDATE tenants SET status = 'suspended' WHERE id = $1`, w.Tenant) },
			func(*tokentest.Token) { w.Exec(`UPDATE tenants SET status = 'active' WHERE id = $1`, w.Tenant) }},
		{"a row retention forgot, revoked in the sticky set", kc.UseRevoked, func(tok *tokentest.Token) {
			w.ExecIn(`DELETE FROM contract_tokens WHERE id = $1`, tok.ID)
			w.Exec(`INSERT INTO contract_token_sticky (token_id, revoked_at, ended, until) VALUES ($1, clock_timestamp(), 'revoked',
				clock_timestamp() + interval '1 day') ON CONFLICT (token_id) DO UPDATE SET revoked_at = excluded.revoked_at, ended = excluded.ended`, tok.ID)
		}, nil},
		{"a row retention forgot, unlisted", "", func(tok *tokentest.Token) {
			w.ExecIn(`DELETE FROM contract_tokens WHERE id = $1`, tok.ID)
		}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tok := w.Token(tokentest.Read(device))
			if _, _, refused := forAuth(t, w, tok.Text); refused {
				t.Fatal("the token is not live before the case")
			}
			c.set(tok)
			_, fail, refused := forAuth(t, w, tok.Text)
			if !refused || fail.Class != store.TokenFailState || fail.Token != tok.ID || fail.Code != c.code {
				t.Fatalf("refused %v, %+v; want the code %q", refused, fail, c.code)
			}
			if c.unset != nil {
				c.unset(tok)
				if _, fail, refused := forAuth(t, w, tok.Text); refused {
					t.Fatalf("the part does not lift: %+v", fail)
				}
			}
		})
	}
}

// TestTokenAllowsGivesEachRefusalItsCode walks the plan's 4.3 table: a
// token that narrowed acts on nothing with no code; a made-up or deleted
// number refuses with no code; a closed workspace, then for a read the
// perm, the switches and the grant, and for send, manage and pause the perm
// and the feed's freshness, each with its code.
func TestTokenAllowsGivesEachRefusalItsCode(t *testing.T) {
	w := newAuthWorld(t)
	ctx := context.Background()
	readable, other := w.Number("Vendas"), w.Number("Suporte")
	tok := w.Token(tokentest.Read(readable), tokentest.Send(other), tokentest.Manage(other))
	auth := w.Auth(tok)
	allows := func(device uuid.UUID, need store.TokenNeed, sw store.TokenSwitches) store.TokenVerdict {
		t.Helper()
		v, err := w.Tokens.Allows(ctx, auth, device, need, sw, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	on := store.TokenSwitches{Default: true}
	read, media := store.TokenNeed{Action: store.ActionRead}, store.TokenNeed{Action: store.ActionRead, Media: true}
	view, send := store.TokenNeed{Action: store.ActionView}, store.TokenNeed{Action: store.ActionSend}
	manage, pause := store.TokenNeed{Action: store.ActionManage}, store.TokenNeed{Action: store.ActionPause}
	want := func(name string, v store.TokenVerdict, ok bool, code, perm string) {
		t.Helper()
		if v.OK != ok || v.Code != code || v.Perm != perm {
			t.Errorf("%s: %+v, want ok %v, code %q, perm %q", name, v, ok, code, perm)
		}
	}
	want("read", allows(readable, read, on), true, "", "")
	want("view is read", allows(readable, view, on), true, "", "")
	want("media", allows(readable, media, on), true, "", "")
	want("send", allows(other, send, on), true, "", "")
	want("manage", allows(other, manage, on), true, "", "")
	want("pause is manage", allows(other, pause, on), true, "", "")
	want("read without the perm", allows(other, read, on), false, kc.UseNoPermission, kc.CanRead)
	want("view without read", allows(other, view, on), false, kc.UseNoPermission, kc.CanRead)
	want("send without the perm", allows(readable, send, on), false, kc.UseNoPermission, kc.CanSend)
	want("pause without manage", allows(readable, pause, on), false, kc.UseNoPermission, kc.CanManage)
	if v := allows(uuid.New(), read, on); v.OK || v.Code != "" || v.Number || !v.Live {
		t.Errorf("a made-up number: %+v", v)
	}

	// The switches: the operator's default under a workspace that set none,
	// the workspace's own, and the deny list over both.
	off, yes, no := store.TokenSwitches{}, true, false
	want("text off by default", allows(readable, read, off), false, kc.UseSwitchOff, kc.CanRead)
	w.Switches(&yes, &no)
	want("the workspace's text on", allows(readable, read, off), true, "", "")
	want("its attachments off", allows(readable, media, on), false, kc.UseSwitchOff, kc.CanRead)
	want("the deny list", allows(readable, read, store.TokenSwitches{Default: true, Deny: []uuid.UUID{w.Tenant}}), false, kc.UseSwitchOff, kc.CanRead)
	w.Switches(nil, nil)

	// The feed: over an hour old refuses send, manage and pause, never read.
	w.Stale(time.Now().Add(-61 * time.Minute))
	want("a stale send", allows(other, send, on), false, kc.UseStaleFeed, kc.CanSend)
	want("a stale manage", allows(other, manage, on), false, kc.UseStaleFeed, kc.CanManage)
	want("a stale pause", allows(other, pause, on), false, kc.UseStaleFeed, kc.CanManage)
	want("a read on a stale feed", allows(readable, read, on), true, "", "")
	w.Stale(time.Now())

	// The grant at the current epoch: a rotation leaves none.
	w.Rotate(readable, 2)
	want("no grant at the new epoch", allows(readable, read, on), false, kc.UseNoGrant, kc.CanRead)
	w.Seal(tok, readable, 2)
	want("sealed again", allows(readable, read, on), true, "", "")

	// A closed workspace refuses every act with its code.
	w.Exec(`INSERT INTO contract_workspaces (workspace_id, kind, status) VALUES ($1, 'team', 'closed')
		ON CONFLICT (workspace_id) DO UPDATE SET status = 'closed'`, w.Tenant)
	want("closed: read", allows(readable, read, on), false, kc.UseWorkspaceClosed, kc.CanRead)
	want("closed: send", allows(other, send, on), false, kc.UseWorkspaceClosed, kc.CanSend)
	w.Exec(`UPDATE contract_workspaces SET status = 'open' WHERE workspace_id = $1`, w.Tenant)

	// A narrowing: the old version acts on nothing, and says no code.
	w.SetPerms(tok, tokentest.Read(readable))
	if v := allows(readable, read, on); v.OK || v.Live || v.Code != "" {
		t.Errorf("a narrowed token's old version: %+v", v)
	}
	auth = w.Auth(tok)
	want("the new version", allows(readable, read, on), true, "", "")
	want("the dropped send", allows(other, send, on), false, kc.UseNoPermission, kc.CanSend)

	// A deleted number is no number.
	w.Scoped(func(tx pgx.Tx) error {
		return store.WithQuarantineForTest(ctx, tx, func() error {
			_, err := tx.Exec(ctx, `UPDATE devices SET paused = true, deleted_at = clock_timestamp(), purge_after = clock_timestamp() + interval '30 days' WHERE id = $1`, readable)
			return err
		})
	})
	if v := allows(readable, read, on); v.OK || v.Code != "" || v.Number {
		t.Errorf("a deleted number: %+v", v)
	}
}

// TestConnectionTokenSets: the sets a socket keeps, from the same parts as
// Allows: read needs the grant and the text switch, send and manage a fresh
// feed, a closed workspace empties them all, and a narrowed or dead token
// is not live.
func TestConnectionTokenSets(t *testing.T) {
	w := newAuthWorld(t)
	ctx := context.Background()
	a, b := w.Number("Vendas"), w.Number("Suporte")
	tok := w.Token(tokentest.Read(a), tokentest.Send(b), tokentest.Manage(a))
	auth := w.Auth(tok)
	on := store.TokenSwitches{Default: true}
	sets := func(sw store.TokenSwitches) store.TokenLive {
		t.Helper()
		live, err := w.Tokens.ConnectionToken(ctx, auth, sw, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return live
	}
	has := func(m map[uuid.UUID]struct{}, ids ...uuid.UUID) bool {
		if len(m) != len(ids) {
			return false
		}
		for _, id := range ids {
			if _, ok := m[id]; !ok {
				return false
			}
		}
		return true
	}
	if l := sets(on); !l.Live || !l.MediaOn || !has(l.Reads, a) || !has(l.Sends, b) || !has(l.Manages, a) {
		t.Fatalf("the sets: %+v", l)
	}
	if l := sets(store.TokenSwitches{}); !l.Live || l.MediaOn || len(l.Reads) != 0 || !has(l.Sends, b) {
		t.Fatalf("text off: %+v", l)
	}
	w.Stale(time.Now().Add(-2 * time.Hour))
	if l := sets(on); !has(l.Reads, a) || len(l.Sends) != 0 || len(l.Manages) != 0 {
		t.Fatalf("a stale feed: %+v", l)
	}
	w.Stale(time.Now())
	w.Rotate(a, 2)
	if l := sets(on); len(l.Reads) != 0 {
		t.Fatalf("after a rotation: %+v", l)
	}
	w.Exec(`INSERT INTO contract_workspaces (workspace_id, kind, status) VALUES ($1, 'team', 'closed')`, w.Tenant)
	if l := sets(on); !l.Live || !l.Closed || len(l.Sends)+len(l.Manages)+len(l.Reads) != 0 {
		t.Fatalf("a closed workspace: %+v", l)
	}
	w.Exec(`UPDATE contract_workspaces SET status = 'open' WHERE workspace_id = $1`, w.Tenant)
	w.Revoke(tok)
	if l := sets(on); l.Live {
		t.Fatalf("a revoked token: %+v", l)
	}
}

// TestATokensPauseIsItsCreators (F3): a token's device.stop pauses the
// number as its record's creator: a key's actor kind, the creator's sub,
// the local account linked to it, left out of the notices.
func TestATokensPauseIsItsCreators(t *testing.T) {
	w := newAuthWorld(t)
	ctx := context.Background()
	device := w.Number("Vendas")
	member := w.Linked("member", "member", uuid.New())
	if err := w.Keys.PutGrant(ctx, store.Grant{TenantID: w.Tenant, DeviceID: device, UserID: member, Epoch: 1, SealedDSK: []byte("g")}, &w.Owner); err != nil {
		t.Fatal(err)
	}
	if err := w.Users.SetDevicePermission(ctx, w.Tenant, w.Owner, store.DevicePermission{DeviceID: device, UserID: member, Read: true}); err != nil {
		t.Fatal(err)
	}
	tok := w.Token(tokentest.Manage(device))
	paused, err := w.Devices.Pause(ctx, w.Tenant, device, store.PauseActor{Token: tok.ID})
	if err != nil {
		t.Fatal(err)
	}
	if !paused.Changed || paused.ActorKind != "key" || paused.ActorUser == nil || *paused.ActorUser != w.Owner {
		t.Fatalf("the pause: %+v", paused)
	}
	for _, n := range paused.Notices {
		if n.UserID == w.Owner {
			t.Fatal("the token's creator was told of their own token's pause")
		}
	}
	if len(paused.Notices) != 1 || paused.Notices[0].UserID != member || !paused.Recorded {
		t.Fatalf("the notices: %+v", paused)
	}
	var kind string
	var sub, user *uuid.UUID
	w.Scoped(func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT actor_kind, actor_sub, actor_user_id FROM item_events WHERE item_id = $1 AND type = 'sync_paused'`, device).
			Scan(&kind, &sub, &user)
	})
	if kind != "key" || sub == nil || *sub != w.OwnerSub || user == nil || *user != w.Owner {
		t.Fatalf("the event's actor: %s %v %v", kind, sub, user)
	}
}

// identityOf is a token's hidden identity.
func identityOf(t *testing.T, w *tokentest.World, tok *tokentest.Token) uuid.UUID {
	t.Helper()
	var identity *uuid.UUID
	w.Scoped(func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT identity_user_id FROM contract_tokens WHERE id = $1`, tok.ID).Scan(&identity)
	})
	if identity == nil {
		t.Fatal("the token has no identity")
	}
	return *identity
}

// TestATokenIdentityNeverAuthenticates (the plan's 10.4): a token's hidden
// identity opens no session, a key cannot be issued to act as it, and a key
// made to act as it anyway authenticates as nothing.
func TestATokenIdentityNeverAuthenticates(t *testing.T) {
	w := newAuthWorld(t)
	ctx := context.Background()
	tok := w.Token(tokentest.Read(w.Number("Vendas")))
	identity := identityOf(t, w, tok)
	if user, err := w.Users.Get(ctx, w.Tenant, identity); err == nil {
		if _, _, err := w.Users.StartSession(ctx, user, "test"); err == nil {
			t.Fatal("a token's identity opened a session")
		}
	}
	keys := store.NewAPIKeys(w.Pool)
	if _, err := keys.IssueActingAs(ctx, w.Tenant.String(), "as the identity", store.ScopeRead, &w.Owner, &identity); err == nil {
		t.Fatal("a key was issued to act as a token's identity")
	}
	key, err := keys.IssueScoped(ctx, w.Tenant.String(), "made to act as it", store.ScopeRead, &w.Owner)
	if err != nil {
		t.Fatal(err)
	}
	prefix, _, _ := strings.Cut(key, ".")
	w.Exec(`UPDATE api_keys SET acts_as = $2 WHERE prefix = $1`, prefix, identity)
	c := &access.Checker{Keys: keys, Users: w.Users, Tokens: w.Tokens}
	if a, err := c.Authenticate(ctx, key); err == nil || a.User == identity {
		t.Fatalf("a key acting as a token's identity authenticated: %+v %v", a, err)
	}
	if a, err := c.Authenticate(ctx, tok.Text); err != nil || a.User != uuid.Nil || a.Token.ID != tok.ID {
		t.Fatalf("the token: %+v %v", a, err)
	}
}

// TestATokenGrantNeverHoldsAKeyForARelink (the relink release): a number
// whose only key holder at its current epoch is a token's identity, with
// Read, holds no key for a relink (KeyHeld), so the relink's check answers
// no_reader.
func TestATokenGrantNeverHoldsAKeyForARelink(t *testing.T) {
	w := newAuthWorld(t)
	ctx := context.Background()
	device := w.Number("Vendas")
	w.Rotate(device, 2)
	tok := w.Token(tokentest.Read(device))
	held, err := w.Devices.KeyHeld(ctx, w.Tenant, device)
	if err != nil || !held {
		t.Fatalf("the owner's key: %v %v", held, err)
	}
	// The owner gives up the new epoch's key: only the token's identity
	// holds it.
	w.ExecIn(`DELETE FROM device_key_grants WHERE device_id = $1 AND user_id = $2 AND epoch = 2`, device, w.Owner)
	v, err := w.Tokens.Allows(ctx, w.Auth(tok), device, store.TokenNeed{Action: store.ActionRead}, store.TokenSwitches{Default: true}, time.Now())
	if err != nil || !v.OK {
		t.Fatalf("the token reads the number: %+v %v", v, err)
	}
	if held, err := w.Devices.KeyHeld(ctx, w.Tenant, device); err != nil || held {
		t.Fatalf("a token's grant held the key for a relink: %v %v", held, err)
	}
}

// TestPauseByAToken (the plan's 10.5): a token whose creator has no local
// account pauses as a key, with the creator's sub from its record, and no
// local actor: every reader is told, and the event names the sub.
func TestPauseByAToken(t *testing.T) {
	w := newAuthWorld(t)
	ctx := context.Background()
	device := snapshotNumber(w, "Vendas", "5511900000001")
	// Its record as the applier keeps it, created by a sub no local
	// account is linked to.
	tok, stranger := uuid.New(), uuid.New()
	w.Exec(`INSERT INTO contract_token_selectors (selector, token_id, tenant_id, hash, until)
		VALUES ('00000000000000cd', $1, $2, decode(repeat('cd', 32), 'hex'), clock_timestamp() + interval '1 day')`, tok, w.Tenant)
	w.ExecIn(`INSERT INTO contract_tokens (id, tenant_id, name, created_by, created_at, expires_at)
		VALUES ($1, $2, 'n', $3, clock_timestamp(), clock_timestamp() + interval '1 day')`, tok, w.Tenant, stranger)
	paused, err := w.Devices.Pause(ctx, w.Tenant, device, store.PauseActor{Token: tok})
	if err != nil {
		t.Fatal(err)
	}
	if !paused.Changed || paused.ActorKind != "key" || paused.ActorUser != nil || !paused.Recorded {
		t.Fatalf("the pause: %+v", paused)
	}
	if len(paused.Notices) != 1 || paused.Notices[0].UserID != w.Owner {
		t.Fatalf("the notices: %+v", paused.Notices)
	}
	var kind string
	var sub, user *uuid.UUID
	w.Scoped(func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT actor_kind, actor_sub, actor_user_id FROM item_events WHERE item_id = $1 AND type = 'sync_paused'`, device).
			Scan(&kind, &sub, &user)
	})
	if kind != "key" || sub == nil || *sub != stranger || user != nil {
		t.Fatalf("the event's actor: %s %v %v", kind, sub, user)
	}
}
