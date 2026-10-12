package authapi_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/config"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pg"
)

// Step 6 of the sign-in (docs/platform-sign-in.md, "The rollback window"):
// migration 0049 nulls the legacy credentials of every account linked to
// the provider and deletes its passkeys. A test database is migrated while
// it is empty, so these tests make the accounts through the routes and then
// apply 0049's text again, as the migrator applies it.

// replay0049 runs migration 0049 in a transaction of its own.
func replay0049(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ms, err := migrate.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ms {
		if m.Version != 49 {
			continue
		}
		ctx := context.Background()
		if err := pg.InTx(ctx, pool, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, m.SQL)
			return err
		}); err != nil {
			t.Fatalf("0049: %v", err)
		}
		return
	}
	t.Fatal("no migration 49")
}

// inAccount runs fn in a transaction that sees the account's own rows: its
// users row (its home workspace) and its passkeys (the account itself).
func (h *platformHarness) inAccount(t *testing.T, id string, fn func(tx pgx.Tx) error) {
	t.Helper()
	ctx := context.Background()
	var home uuid.UUID
	if err := h.pool.QueryRow(ctx, `SELECT tenant_id FROM user_logins WHERE user_id = $1`, id).Scan(&home); err != nil {
		t.Fatal(err)
	}
	if err := pg.InTenantTx(ctx, h.pool, home.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.user_id', $1, true)`, id); err != nil {
			return err
		}
		return fn(tx)
	}); err != nil {
		t.Fatal(err)
	}
}

// accountState is everything of an account that 0049 could change, as
// JSON: its users row, its passkeys, its passkey flows and its sessions.
func (h *platformHarness) accountState(t *testing.T, id string) string {
	t.Helper()
	var state string
	h.inAccount(t, id, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT jsonb_build_object(
			'user', (SELECT to_jsonb(u) FROM users u WHERE u.id = $1),
			'passkeys', (SELECT coalesce(jsonb_agg(to_jsonb(p) ORDER BY p.id), '[]') FROM user_passkeys p WHERE p.user_id = $1),
			'flows', (SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY c.id), '[]') FROM passkey_challenges c WHERE c.user_id = $1),
			'sessions', (SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY s.id), '[]') FROM sessions s WHERE s.user_id = $1))::text`, id).Scan(&state)
	})
	return state
}

// legacyCredentials reports which of the six legacy credential columns an
// account still has, and its auth source and public key.
func (h *platformHarness) legacyCredentials(t *testing.T, id string) (held int, source, publicKey string) {
	t.Helper()
	h.inAccount(t, id, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT num_nonnulls(auth_hash, kdf_salt, kdf_params, wrapped_usk, recovery_wrap, recovery_hash),
			auth_source, encode(public_key, 'base64') FROM users WHERE id = $1`, id).Scan(&held, &source, &publicKey)
	})
	return held, source, publicKey
}

func (h *platformHarness) passkeyCount(t *testing.T, id string) int {
	t.Helper()
	var n int
	h.inAccount(t, id, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT count(*) FROM user_passkeys WHERE user_id = $1`, id).Scan(&n)
	})
	return n
}

// passkeyLogin signs in with a registered passkey, the n-th use of it.
func (h *passkeyHarness) passkeyLogin(t *testing.T, key *softwarePasskey, n uint32) (int, sessionReply) {
	t.Helper()
	flow := h.flow(t, false, passkeyApp)
	var out sessionReply
	code := h.request(t, "POST", "/v1/auth/passkeys/login/finish", passkeyApp, "", map[string]any{
		"flow_id": flow.ID, "credential": key.assertion(t, flow, passkeyApp, passkeyRP, 0x05, n)}, &out)
	return code, out
}

// The end of the rollback window. A linked legacy account loses its old
// password's verifier, salt and parameters, its password and recovery wraps
// and the recovery code's verifier, its Wappie passkeys (the one the link
// revoked, and one added while the provider was switched off), its passkey
// flows, and every session a legacy credential started; it still signs in
// through the provider with the same account key and steps up there, and
// nothing it signed in with before opens it any more, with the provider
// switched off too. An account created through the provider, an unlinked
// password account and a service account are unchanged to the byte, and a
// second run changes nothing.
func TestMigration0049EndsTheRollbackWindow(t *testing.T) {
	h := newPlatformHarness(t, config.LocalLoginOn)
	provider := h.handler.Platform

	// The unlinked password account, with a recovery code and a passkey.
	if _, pk := h.register(t); pk.ID == uuid.Nil {
		t.Fatal("no passkey")
	}
	// A service account.
	var service sessionReply
	if code := h.post(t, "/v1/auth/signup", map[string]string{"invite": h.invite(t, "service"), "name": "erp", "public_key": randomKey(t)}, &service, ""); code != http.StatusOK {
		t.Fatalf("service: %d", code)
	}
	// An account created through the provider has no legacy credential.
	_, first := h.signIn(t, newPerson(t, "bea@example.com"), 1)
	code, created, _, _ := h.createAccount(t, first.Ticket)
	if code != http.StatusOK {
		t.Fatalf("account: %d %+v", code, created)
	}
	if held, source, _ := h.legacyCredentials(t, created.User.ID); held != 0 || source != "platform" || h.passkeyCount(t, created.User.ID) != 0 {
		t.Fatalf("an account created through the provider holds %d legacy credentials, %d passkeys (%s)", held, h.passkeyCount(t, created.User.ID), source)
	}

	// The legacy account: a password, a recovery code, and a passkey it
	// signed in with before the link.
	body, _ := newAccount(t, h.invite(t, "member"), "lia@example.com", "lia-auth-key")
	body.RecoveryWrap = base64.StdEncoding.EncodeToString([]byte("lia-recovery-wrap"))
	body.RecoveryProof = "lia-recovery-proof"
	lia := &passkeyHarness{harness: h.harness, account: body}
	if code := h.post(t, "/v1/auth/signup", body, &lia.signed, ""); code != http.StatusOK {
		t.Fatalf("signup: %d", code)
	}
	id := lia.signed.User.ID
	before, _ := lia.register(t)
	if code, _ := lia.passkeyLogin(t, before, 1); code != http.StatusOK {
		t.Fatalf("passkey sign-in before the link: %d", code)
	}
	p := newPerson(t, "lia@example.com")
	_, answer := h.signIn(t, p, 1)
	wrap := randomWrap(t)
	var linked platformAnswer
	if code := h.pagePost(t, "/v1/auth/platform/link", map[string]string{"ticket": answer.Ticket, "email": "lia@example.com",
		"auth_key": body.AuthKey, "platform_wrap": wrap}, &linked, "", nil); code != http.StatusOK || linked.Token == "" {
		t.Fatalf("link: %d %+v", code, linked)
	}
	// With the provider switched off, the window's other door: the old
	// password signs in, a Wappie passkey is added and signs in, and a
	// second registration is left half done.
	h.handler.Platform = nil
	if code := h.post(t, "/v1/auth/login", map[string]string{"email": "lia@example.com", "auth_key": body.AuthKey}, &lia.signed, ""); code != http.StatusOK {
		t.Fatalf("password sign-in with the provider off: %d", code)
	}
	password := lia.signed
	added, _ := lia.register(t)
	code, withPasskey := lia.passkeyLogin(t, added, 1)
	if code != http.StatusOK {
		t.Fatalf("passkey sign-in with the provider off: %d", code)
	}
	lia.flow(t, true, passkeyApp)
	h.handler.Platform = provider
	var passwordSwitch sessionReply
	if code := h.post(t, "/v1/auth/workspaces/session", map[string]string{"tenant_id": password.User.TenantID}, &passwordSwitch, password.Token); code != http.StatusOK {
		t.Fatalf("switch: %d", code)
	}
	_, through := h.signIn(t, p, 1)
	if through.Kind != "session" {
		t.Fatalf("sign-in through the provider: %+v", through)
	}
	var throughSwitch sessionReply
	if code := h.post(t, "/v1/auth/workspaces/session", map[string]string{"tenant_id": through.User.TenantID}, &throughSwitch, through.Token); code != http.StatusOK {
		t.Fatalf("switch: %d", code)
	}
	held, source, publicKey := h.legacyCredentials(t, id)
	if held != 6 || source != "platform" || publicKey != body.PublicKey || h.passkeyCount(t, id) != 2 ||
		h.count(t, `SELECT count(*) FROM passkey_challenges WHERE user_id = $1`, id) == 0 {
		t.Fatalf("the linked account in its window: %d legacy credentials, %s, %d passkeys", held, source, h.passkeyCount(t, id))
	}
	viaProvider := h.count(t, `SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL AND via_provider`, id)
	untouched := map[string]string{}
	for _, other := range []string{h.signed.User.ID, service.User.ID, created.User.ID} {
		untouched[other] = h.accountState(t, other)
	}

	replay0049(t, h.pool)

	if held, source, publicKey := h.legacyCredentials(t, id); held != 0 || source != "platform" || publicKey != body.PublicKey {
		t.Fatalf("after 0049: %d legacy credentials, %s, public key kept %v", held, source, publicKey == body.PublicKey)
	}
	if n := h.passkeyCount(t, id); n != 0 {
		t.Fatalf("%d passkeys after 0049", n)
	}
	for name, query := range map[string]string{
		"passkey flows":                          `SELECT count(*) FROM passkey_challenges WHERE user_id = $1`,
		"sessions naming a passkey":              `SELECT count(*) FROM sessions WHERE user_id = $1 AND passkey_id IS NOT NULL`,
		"live sessions not through the provider": `SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL AND NOT via_provider`,
	} {
		if n := h.count(t, query, id); n != 0 {
			t.Fatalf("%d %s after 0049", n, name)
		}
	}
	if n := h.count(t, `SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL AND via_provider`, id); n != viaProvider {
		t.Fatalf("live sessions through the provider: %d, were %d", n, viaProvider)
	}
	for other, state := range untouched {
		if got := h.accountState(t, other); got != state {
			t.Fatalf("0049 changed an account it does not cover:\n%s\nwas\n%s", got, state)
		}
	}

	// What a legacy credential started has ended; what came through the
	// provider goes on, and /me hands none of it a legacy wrap.
	for name, token := range map[string]string{"the password's": password.Token, "its switch's": passwordSwitch.Token, "the passkey's": withPasskey.Token} {
		if code := h.get(t, "/v1/auth/me", nil, token); code != http.StatusUnauthorized {
			t.Fatalf("%s session after 0049: %d", name, code)
		}
	}
	again := func() platformAnswer {
		t.Helper()
		code, out := h.signIn(t, p, 1)
		if code != http.StatusOK || out.Kind != "session" || out.User.ID != id || out.PlatformWrap != wrap || out.User.PublicKey != body.PublicKey || out.User.WrappedUSK != "" {
			t.Fatalf("sign-in through the provider after 0049: %d %+v", code, out)
		}
		return out
	}
	signed := again()
	for name, token := range map[string]string{"the link's": linked.Token, "a sign-in's": through.Token, "its switch's": throughSwitch.Token, "a new sign-in's": signed.Token} {
		var me struct {
			User struct {
				ID          string `json:"id"`
				WrappedUSK  string `json:"wrapped_usk"`
				PlatformSub string `json:"platform_sub"`
				HasRecovery bool   `json:"has_recovery"`
			} `json:"user"`
		}
		if code := h.get(t, "/v1/auth/me", &me, token); code != http.StatusOK || me.User.ID != id || me.User.WrappedUSK != "" || me.User.PlatformSub != p.sub || me.User.HasRecovery {
			t.Fatalf("%s session's me after 0049: %d %+v", name, code, me)
		}
	}
	// It steps up at the provider, as before.
	h.age(t, signed.Token)
	if code, out := h.start(t, signed.Token); code != http.StatusOK || out.LoginHint != "lia@example.com" {
		t.Fatalf("start: %d %+v", code, out)
	}
	if code, out := h.finish(t, signed.Token, h.id.issue(t, p.userinfo(t, 1))); code != http.StatusOK || !out.Fresh {
		t.Fatalf("finish: %d %+v", code, out)
	}

	// Nothing it signed in with before opens it: not the old password, not
	// the recovery code, not a passkey, with the provider on or switched off.
	var refusal platformAnswer
	if code := h.post(t, "/v1/auth/step-up/password", map[string]string{"auth_key": body.AuthKey}, &refusal, signed.Token); code != http.StatusConflict || refusal.Code != "step_up_at_provider" {
		t.Fatalf("a password step-up: %d %+v", code, refusal)
	}
	for _, off := range []bool{false, true} {
		if off {
			h.handler.Platform = nil
		}
		if code := h.post(t, "/v1/auth/login", map[string]string{"email": "lia@example.com", "auth_key": body.AuthKey}, nil, ""); code != http.StatusUnauthorized {
			t.Fatalf("the old password (provider off %v): %d", off, code)
		}
		if code := h.post(t, "/v1/auth/recover/open", map[string]string{"email": "lia@example.com", "recovery_proof": body.RecoveryProof}, nil, ""); code != http.StatusUnauthorized {
			t.Fatalf("the recovery code (provider off %v): %d", off, code)
		}
		if code, _ := lia.passkeyLogin(t, added, 2); code != http.StatusUnauthorized {
			t.Fatalf("the deleted passkey (provider off %v): %d", off, code)
		}
		if code := h.post(t, "/v1/auth/password", map[string]any{"auth_key": body.AuthKey, "new": fresh(t, "another", "w2", "", "")}, nil, signed.Token); code != http.StatusUnauthorized {
			t.Fatalf("a password change (provider off %v): %d", off, code)
		}
	}
	h.handler.Platform = provider
	// The challenge answers for the address as for one with no password.
	var challenge struct {
		Salt string `json:"salt"`
	}
	if code := h.post(t, "/v1/auth/challenge", map[string]string{"email": "lia@example.com"}, &challenge, ""); code != http.StatusOK || challenge.Salt == "" || challenge.Salt == body.KDFSalt {
		t.Fatalf("the challenge after 0049: %d %+v", code, challenge)
	}

	// Run again, it changes nothing.
	state := h.accountState(t, id)
	replay0049(t, h.pool)
	if got := h.accountState(t, id); got != state {
		t.Fatalf("a second 0049 changed the linked account:\n%s\nwas\n%s", got, state)
	}
	for other, want := range untouched {
		if got := h.accountState(t, other); got != want {
			t.Fatalf("a second 0049 changed another account:\n%s\nwas\n%s", got, want)
		}
	}

	// Step 6 is 0049 and WS_LOCAL_LOGIN=off: the provider is the only way in.
	h.handler.LocalLogin = config.LocalLoginOff
	again()
	if code := h.post(t, "/v1/auth/login", map[string]string{"email": "lia@example.com", "auth_key": body.AuthKey}, &refusal, ""); code != http.StatusForbidden || refusal.Code != "local_login_disabled" {
		t.Fatalf("the old password with local login off: %d %+v", code, refusal)
	}
}

// 0049 covers every account linked when it runs. One linked after it keeps
// its legacy credentials, and with the provider switched off its old
// password, until 0049 is applied again, as it is after its down-step when a
// release that carries it comes back: then they go too, and the account the
// first run covered is left as it was.
func TestMigration0049AgainCoversAnAccountLinkedSince(t *testing.T) {
	h := newPlatformHarness(t, config.LocalLoginOn)
	provider := h.handler.Platform
	link := func(email, authKey string) string {
		t.Helper()
		_, answer := h.signIn(t, newPerson(t, email), 1)
		var out platformAnswer
		if code := h.pagePost(t, "/v1/auth/platform/link", map[string]string{"ticket": answer.Ticket, "email": email,
			"auth_key": authKey, "platform_wrap": randomWrap(t)}, &out, "", nil); code != http.StatusOK || out.Kind != "session" {
			t.Fatalf("link of %s: %d %+v", email, code, out)
		}
		return out.User.ID
	}
	passwordSignIn := func(email, authKey string) int {
		t.Helper()
		h.handler.Platform = nil
		defer func() { h.handler.Platform = provider }()
		return h.post(t, "/v1/auth/login", map[string]string{"email": email, "auth_key": authKey}, nil, "")
	}

	first := link("passkey@example.com", h.account.AuthKey)
	replay0049(t, h.pool)
	if held, _, _ := h.legacyCredentials(t, first); held != 0 {
		t.Fatalf("the account linked before 0049 holds %d legacy credentials", held)
	}
	covered := h.accountState(t, first)

	body, _ := newAccount(t, h.invite(t, "member"), "noa@example.com", "noa-auth-key")
	body.RecoveryWrap = base64.StdEncoding.EncodeToString([]byte("noa-recovery-wrap"))
	body.RecoveryProof = "noa-recovery-proof"
	if code := h.post(t, "/v1/auth/signup", body, nil, ""); code != http.StatusOK {
		t.Fatalf("signup: %d", code)
	}
	later := link("noa@example.com", body.AuthKey)
	if held, source, _ := h.legacyCredentials(t, later); held != 6 || source != "platform" {
		t.Fatalf("the account linked after 0049: %d legacy credentials, %s", held, source)
	}
	if code := passwordSignIn("noa@example.com", body.AuthKey); code != http.StatusOK {
		t.Fatalf("its old password with the provider off, before 0049 runs again: %d", code)
	}
	// What a backup from before 0049 holds of it.
	var backup string
	h.inAccount(t, later, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT jsonb_build_object('auth_hash', auth_hash, 'kdf_salt', encode(kdf_salt, 'base64'),
			'kdf_params', kdf_params, 'wrapped_usk', encode(wrapped_usk, 'base64'), 'recovery_wrap', encode(recovery_wrap, 'base64'),
			'recovery_hash', recovery_hash)::text FROM users WHERE id = $1`, later).Scan(&backup)
	})

	replay0049(t, h.pool)

	if held, source, _ := h.legacyCredentials(t, later); held != 0 || source != "platform" {
		t.Fatalf("0049 again left the account linked since %d legacy credentials (%s)", held, source)
	}
	if n := h.count(t, `SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL AND NOT via_provider`, later); n != 0 {
		t.Fatalf("%d live password sessions after 0049 again", n)
	}
	if code := passwordSignIn("noa@example.com", body.AuthKey); code != http.StatusUnauthorized {
		t.Fatalf("its old password with the provider off, after 0049 again: %d", code)
	}
	if got := h.accountState(t, first); got != covered {
		t.Fatalf("0049 again changed the account it had covered:\n%s\nwas\n%s", got, covered)
	}

	// Until the console can rewrap a new epoch, the backup is the account
	// key's other copy (0049's header): its six columns put back, with the
	// provider switched off and local login on, the old password signs in
	// and hands back the password wrap.
	ctx := context.Background()
	if err := pg.InTx(ctx, h.pool, func(tx pgx.Tx) error {
		for _, stmt := range []string{
			`ALTER TABLE users DISABLE ROW LEVEL SECURITY`,
			`UPDATE users SET auth_hash = b->>'auth_hash', kdf_salt = decode(b->>'kdf_salt', 'base64'), kdf_params = b->'kdf_params',
			        wrapped_usk = decode(b->>'wrapped_usk', 'base64'), recovery_wrap = decode(b->>'recovery_wrap', 'base64'),
			        recovery_hash = b->>'recovery_hash'
			   FROM (SELECT $2::jsonb AS b) backup WHERE id = $1`,
			`ALTER TABLE users ENABLE ROW LEVEL SECURITY`,
			`ALTER TABLE users FORCE ROW LEVEL SECURITY`,
		} {
			var args []any
			if strings.HasPrefix(stmt, "UPDATE") {
				args = []any{later, backup}
			}
			if _, err := tx.Exec(ctx, stmt, args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("putting the backup's columns back: %v", err)
	}
	h.handler.Platform = nil
	var restored sessionReply
	if code := h.post(t, "/v1/auth/login", map[string]string{"email": "noa@example.com", "auth_key": body.AuthKey}, &restored, ""); code != http.StatusOK ||
		restored.User.WrappedUSK != body.WrappedUSK {
		t.Fatalf("the old password once the backup's columns are back: %d %+v", code, restored.User)
	}
	h.handler.Platform = provider
}
