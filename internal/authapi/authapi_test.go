package authapi_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"whatserver2/internal/authapi"
	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/ratelimit"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

type harness struct {
	srv    *httptest.Server
	pool   *pgxpool.Pool
	users  *store.Users
	keys   *store.Keys
	tenant uuid.UUID
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	pool := pgtest.Fresh(t, migrate.Run)

	var tenantID string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO tenants (name) VALUES ('acme') RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	h := &authapi.Handler{
		Users:   store.NewUsers(pool),
		Keys:    store.NewKeys(pool),
		Devices: store.NewDevices(pool),
	}
	h.Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &harness{
		srv: srv, pool: pool, users: store.NewUsers(pool),
		keys: store.NewKeys(pool), tenant: uuid.MustParse(tenantID),
	}
}

func (h *harness) post(t *testing.T, path string, body, into any, token string) int {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, h.srv.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return h.do(t, req, into)
}

func (h *harness) get(t *testing.T, path string, into any, token string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, h.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return h.do(t, req, into)
}

func (h *harness) do(t *testing.T, req *http.Request, into any) int {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		//nolint:errcheck // the body is drained; a close error changes nothing
		_ = resp.Body.Close()
	}()
	if into != nil {
		if err := json.NewDecoder(resp.Body).Decode(into); err != nil && resp.StatusCode < 300 {
			t.Fatalf("decoding a %d reply: %v", resp.StatusCode, err)
		}
	}
	return resp.StatusCode
}

// signup posts an account the way a browser would: everything secret is
// produced here, and only derived material crosses the wire.
type signupBody struct {
	Invite        string          `json:"invite"`
	Email         string          `json:"email"`
	AuthKey       string          `json:"auth_key"`
	KDFSalt       string          `json:"kdf_salt"`
	KDFParams     store.KDFParams `json:"kdf_params"`
	PublicKey     string          `json:"public_key"`
	WrappedUSK    string          `json:"wrapped_usk"`
	RecoveryWrap  string          `json:"recovery_wrap,omitempty"`
	RecoveryProof string          `json:"recovery_proof,omitempty"`
}

type sessionReply struct {
	Token string `json:"token"`
	User  struct {
		ID         string `json:"id"`
		TenantID   string `json:"tenant_id"`
		Email      string `json:"email"`
		Role       string `json:"role"`
		WrappedUSK string `json:"wrapped_usk"`
		PublicKey  string `json:"public_key"`
	} `json:"user"`
}

func (h *harness) invite(t *testing.T, role string) string {
	t.Helper()
	code, err := h.users.CreateInvite(context.Background(), h.tenant, role, "", nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func newAccount(t *testing.T, invite, email, authKey string) (signupBody, seal.PrivateKey) {
	t.Helper()
	pub, priv, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	// A real browser wraps the private key under the other half of its
	// derivation. The wrap is opaque to the server, so any bytes exercise the
	// same path.
	privBytes, err := priv.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return signupBody{
		Invite: invite, Email: email, AuthKey: authKey,
		KDFSalt: base64.StdEncoding.EncodeToString(salt), KDFParams: store.DefaultKDFParams(),
		PublicKey:  base64.StdEncoding.EncodeToString(pub.Bytes()),
		WrappedUSK: base64.StdEncoding.EncodeToString(append([]byte("wrapped:"), privBytes...)),
	}, priv
}

func TestSignUpThenSignIn(t *testing.T) {
	h := newHarness(t)
	body, _ := newAccount(t, h.invite(t, "owner"), "felipe@example.com", "auth-key-1")

	var created sessionReply
	if code := h.post(t, "/v1/auth/signup", body, &created, ""); code != http.StatusOK {
		t.Fatalf("signup returned %d", code)
	}
	if created.Token == "" {
		t.Fatal("signup returned no session token")
	}
	if created.User.Role != "owner" {
		t.Errorf("role = %q, want the one the invite carried", created.User.Role)
	}

	var in sessionReply
	code := h.post(t, "/v1/auth/login",
		map[string]string{"email": "FELIPE@example.com", "auth_key": "auth-key-1"}, &in, "")
	if code != http.StatusOK {
		t.Fatalf("sign-in returned %d", code)
	}
	// The address is matched case-insensitively; the wrapped key comes back
	// byte for byte, because opening it is not this server's job.
	if in.User.WrappedUSK != body.WrappedUSK {
		t.Error("the wrapped key did not come back unchanged")
	}
}

func TestThePasswordNeverReachesTheServer(t *testing.T) {
	h := newHarness(t)
	// There is no field for it. This is the schema-level counterpart to that:
	// a scan of every text and bytea column for the value a browser would have
	// derived from, which must appear nowhere.
	const password = "correct horse battery staple"
	body, _ := newAccount(t, h.invite(t, "owner"), "ana@example.com", "derived-from-"+password)
	if code := h.post(t, "/v1/auth/signup", body, nil, ""); code != http.StatusOK {
		t.Fatalf("signup returned %d", code)
	}

	rows, err := h.pool.Query(context.Background(), `
		SELECT c.table_name, c.column_name
		  FROM information_schema.columns c
		  JOIN information_schema.tables t
		    ON t.table_name = c.table_name AND t.table_schema = c.table_schema
		 WHERE c.table_schema = current_schema()
		   AND t.table_type = 'BASE TABLE'
		   AND c.data_type IN ('text', 'bytea', 'character varying')`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	type column struct{ table, name string }
	var columns []column
	for rows.Next() {
		var c column
		if err := rows.Scan(&c.table, &c.name); err != nil {
			t.Fatal(err)
		}
		columns = append(columns, c)
	}

	for _, c := range columns {
		vals, err := h.pool.Query(context.Background(),
			`SELECT `+c.name+`::text FROM `+c.table+` WHERE `+c.name+` IS NOT NULL`)
		if err != nil {
			continue // a policy hides the table without a tenant set, which is fine
		}
		for vals.Next() {
			var v string
			if err := vals.Scan(&v); err != nil {
				continue
			}
			if v != "" && bytes.Contains([]byte(v), []byte(password)) {
				vals.Close()
				t.Fatalf("the password appears in %s.%s", c.table, c.name)
			}
		}
		vals.Close()
	}
}

func TestAnInviteWorksOnce(t *testing.T) {
	h := newHarness(t)
	code := h.invite(t, "member")

	first, _ := newAccount(t, code, "one@example.com", "k1")
	if got := h.post(t, "/v1/auth/signup", first, nil, ""); got != http.StatusOK {
		t.Fatalf("the first signup returned %d", got)
	}
	second, _ := newAccount(t, code, "two@example.com", "k2")
	if got := h.post(t, "/v1/auth/signup", second, nil, ""); got != http.StatusForbidden {
		t.Fatalf("the same invite was accepted twice: %d", got)
	}
}

func TestWrongPasswordAndUnknownAddressAnswerTheSame(t *testing.T) {
	h := newHarness(t)
	body, _ := newAccount(t, h.invite(t, "owner"), "real@example.com", "right")
	if got := h.post(t, "/v1/auth/signup", body, nil, ""); got != http.StatusOK {
		t.Fatalf("signup returned %d", got)
	}

	var wrong, unknown struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	codeWrong := h.post(t, "/v1/auth/login",
		map[string]string{"email": "real@example.com", "auth_key": "nope"}, &wrong, "")
	codeUnknown := h.post(t, "/v1/auth/login",
		map[string]string{"email": "ghost@example.com", "auth_key": "nope"}, &unknown, "")

	if codeWrong != http.StatusUnauthorized || codeUnknown != http.StatusUnauthorized {
		t.Fatalf("status codes differ: %d and %d", codeWrong, codeUnknown)
	}
	// Telling them apart is an account-enumeration oracle, one request at a
	// time, against an endpoint that has to stay open.
	if wrong.Code != unknown.Code || wrong.Message != unknown.Message {
		t.Fatalf("a wrong password and an unknown address answer differently: %+v vs %+v",
			wrong, unknown)
	}
}

func TestTheChallengeDoesNotRevealWhoHasAnAccount(t *testing.T) {
	h := newHarness(t)
	body, _ := newAccount(t, h.invite(t, "owner"), "known@example.com", "k")
	if got := h.post(t, "/v1/auth/signup", body, nil, ""); got != http.StatusOK {
		t.Fatalf("signup returned %d", got)
	}

	type reply struct {
		Salt   string          `json:"salt"`
		Params store.KDFParams `json:"params"`
	}
	var known, ghost, ghostAgain reply
	h.post(t, "/v1/auth/challenge", map[string]string{"email": "known@example.com"}, &known, "")
	h.post(t, "/v1/auth/challenge", map[string]string{"email": "ghost@example.com"}, &ghost, "")
	h.post(t, "/v1/auth/challenge", map[string]string{"email": "ghost@example.com"}, &ghostAgain, "")

	if known.Salt == "" || ghost.Salt == "" {
		t.Fatal("a challenge came back without a salt")
	}
	if ghost.Salt != ghostAgain.Salt {
		t.Error("the decoy salt changes between requests, which gives the answer away")
	}
	if ghost.Params != known.Params {
		t.Error("the decoy parameters differ from a real account's")
	}
}

// The grants are what turn a sealed archive into a readable one, and what stops
// one account reading another's WhatsApp number.
func TestGrantsAreListedPerAccount(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	mine, _ := newAccount(t, h.invite(t, "owner"), "mine@example.com", "k1")
	var me sessionReply
	if got := h.post(t, "/v1/auth/signup", mine, &me, ""); got != http.StatusOK {
		t.Fatalf("signup returned %d", got)
	}
	theirs, _ := newAccount(t, h.invite(t, "member"), "theirs@example.com", "k2")
	var them sessionReply
	if got := h.post(t, "/v1/auth/signup", theirs, &them, ""); got != http.StatusOK {
		t.Fatalf("signup returned %d", got)
	}

	// Two devices, each with its own archive key, and a grant for one account
	// on each.
	devices := store.NewDevices(h.pool)
	for i, holder := range []sessionReply{me, them} {
		dev, err := devices.Create(ctx, h.tenant.String(), "dev", wa.ModePassive)
		if err != nil {
			t.Fatal(err)
		}
		device := uuid.MustParse(dev.ID)
		pub, priv, err := seal.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		if err := h.keys.CreateArchiveKey(ctx, h.tenant, device, 1, pub); err != nil {
			t.Fatal(err)
		}
		raw, err := priv.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		userPubRaw, err := base64.StdEncoding.DecodeString(holder.User.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		userPub, err := seal.ParsePublicKey(userPubRaw)
		if err != nil {
			t.Fatal(err)
		}
		user := uuid.MustParse(holder.User.ID)
		sealed, err := seal.SealDirect(userPub, seal.KindDeviceGrant, h.tenant,
			seal.GrantRow(h.tenant, device, user, 1), 1, raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := h.keys.PutGrant(ctx, store.Grant{
			TenantID: h.tenant, DeviceID: device, UserID: user, Epoch: 1, SealedDSK: sealed,
		}, nil); err != nil {
			t.Fatalf("grant %d: %v", i, err)
		}
	}

	var mineReply struct {
		Grants []struct {
			DeviceID  string `json:"device_id"`
			SealedDSK string `json:"sealed_dsk"`
		} `json:"grants"`
	}
	if got := h.get(t, "/v1/auth/me", &mineReply, me.Token); got != http.StatusOK {
		t.Fatalf("me returned %d", got)
	}
	if len(mineReply.Grants) != 1 {
		t.Fatalf("one account can reach %d devices, want 1", len(mineReply.Grants))
	}
	if mineReply.Grants[0].SealedDSK == "" {
		t.Error("the grant came back without the sealed key, so nothing could open")
	}
}

func TestMeNeedsASession(t *testing.T) {
	h := newHarness(t)
	if got := h.get(t, "/v1/auth/me", nil, ""); got != http.StatusUnauthorized {
		t.Fatalf("me without a token returned %d", got)
	}
	if got := h.get(t, "/v1/auth/me", nil, "not-a-real-token"); got != http.StatusUnauthorized {
		t.Fatalf("me with a bogus token returned %d", got)
	}
}

func TestSigningOutEndsTheSession(t *testing.T) {
	h := newHarness(t)
	body, _ := newAccount(t, h.invite(t, "owner"), "bye@example.com", "k")
	var in sessionReply
	if got := h.post(t, "/v1/auth/signup", body, &in, ""); got != http.StatusOK {
		t.Fatalf("signup returned %d", got)
	}
	if got := h.get(t, "/v1/auth/me", nil, in.Token); got != http.StatusOK {
		t.Fatalf("me returned %d before signing out", got)
	}
	if got := h.post(t, "/v1/auth/logout", struct{}{}, nil, in.Token); got != http.StatusNoContent {
		t.Fatalf("logout returned %d", got)
	}
	if got := h.get(t, "/v1/auth/me", nil, in.Token); got != http.StatusUnauthorized {
		t.Fatalf("the token still works after signing out: %d", got)
	}
}

// Every sign-in attempt costs an Argon2id derivation here and is a guess at
// somebody's password. Neither should be free.
func TestSignInIsRateLimited(t *testing.T) {
	h := newHarness(t)
	body, _ := newAccount(t, h.invite(t, "owner"), "limited@example.com", "right")
	if got := h.post(t, "/v1/auth/signup", body, nil, ""); got != http.StatusOK {
		t.Fatalf("signup returned %d", got)
	}

	// A fresh handler with a tight limit, on the same store.
	mux := http.NewServeMux()
	(&authapi.Handler{
		Users: h.users, Keys: h.keys, Devices: store.NewDevices(h.pool),
		Limits: &ratelimit.Auth{PerIP: ratelimit.New(60, 100), PerSubject: ratelimit.New(1, 3)},
	}).Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	limited := &harness{srv: srv, pool: h.pool, users: h.users, keys: h.keys, tenant: h.tenant}

	wrong := map[string]string{"email": "limited@example.com", "auth_key": "nope"}
	for i := range 3 {
		if got := limited.post(t, "/v1/auth/login", wrong, nil, ""); got != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status %d, want 401", i+1, got)
		}
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/auth/login",
		strings.NewReader(`{"email":"limited@example.com","auth_key":"right"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	//nolint:errcheck // the status and headers are what matter
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("the fourth attempt — with the right password — got %d, want 429", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Error("a 429 without Retry-After leaves a client guessing")
	}

	// Another account from the same address is not held back by the first
	// one's mistakes; that is what the per-address limit is generous for.
	other := map[string]string{"email": "someone-else@example.com", "auth_key": "x"}
	if got := limited.post(t, "/v1/auth/login", other, nil, ""); got != http.StatusUnauthorized {
		t.Fatalf("a different subject got %d, want 401", got)
	}
}

// The recovery code was generated and stored by every signup and read by
// nothing: there was no endpoint. A forgotten password lost the archive, which
// is the exact failure the code was added to prevent.

type rekeyBody struct {
	AuthKey       string          `json:"auth_key"`
	KDFSalt       string          `json:"kdf_salt"`
	KDFParams     store.KDFParams `json:"kdf_params"`
	WrappedUSK    string          `json:"wrapped_usk"`
	RecoveryWrap  string          `json:"recovery_wrap,omitempty"`
	RecoveryProof string          `json:"recovery_proof,omitempty"`
}

func fresh(t *testing.T, authKey, wrapped, recoveryWrap, recoveryProof string) rekeyBody {
	t.Helper()
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	return rekeyBody{
		AuthKey: authKey, KDFSalt: base64.StdEncoding.EncodeToString(salt),
		KDFParams:  store.DefaultKDFParams(),
		WrappedUSK: base64.StdEncoding.EncodeToString([]byte(wrapped)),
		RecoveryWrap: func() string {
			if recoveryWrap == "" {
				return ""
			}
			return base64.StdEncoding.EncodeToString([]byte(recoveryWrap))
		}(),
		RecoveryProof: recoveryProof,
	}
}

func TestARecoveryCodeOpensTheAccountAndReplacesEverything(t *testing.T) {
	h := newHarness(t)
	body, _ := newAccount(t, h.invite(t, "owner"), "lost@example.com", "old-auth")
	body.RecoveryWrap = base64.StdEncoding.EncodeToString([]byte("wrapped-under-code"))
	body.RecoveryProof = "proof-of-code"
	var created sessionReply
	if code := h.post(t, "/v1/auth/signup", body, &created, ""); code != http.StatusOK {
		t.Fatalf("signup returned %d", code)
	}

	var me struct {
		User struct {
			HasRecovery bool `json:"has_recovery"`
		} `json:"user"`
	}
	h.get(t, "/v1/auth/me", &me, created.Token)
	if !me.User.HasRecovery {
		t.Fatal("an account that signed up with a code and its proof should report recovery as usable")
	}

	// Step one: the code proves itself and the wrap comes back.
	var opened struct {
		RecoveryWrap string `json:"recovery_wrap"`
		PublicKey    string `json:"public_key"`
	}
	code := h.post(t, "/v1/auth/recover/open",
		map[string]string{"email": "LOST@example.com", "recovery_proof": "proof-of-code"}, &opened, "")
	if code != http.StatusOK {
		t.Fatalf("recover/open returned %d", code)
	}
	if opened.RecoveryWrap != body.RecoveryWrap {
		t.Fatal("the recovery wrap did not come back as stored")
	}
	if opened.PublicKey != body.PublicKey {
		t.Fatal("the public key changed, which would strand every grant")
	}

	// Step two: a new password, and a new code, because the old one was just
	// typed into a browser.
	var signedIn sessionReply
	code = h.post(t, "/v1/auth/recover/finish", map[string]any{
		"email": "lost@example.com", "recovery_proof": "proof-of-code",
		"new": fresh(t, "new-auth", "wrapped-under-new-password", "wrapped-under-new-code", "new-proof"),
	}, &signedIn, "")
	if code != http.StatusOK {
		t.Fatalf("recover/finish returned %d", code)
	}
	if signedIn.Token == "" || signedIn.Token == created.Token {
		t.Fatal("a recovery should sign in with a fresh token")
	}

	// The old password, the old code and the old session are all spent.
	if code := h.post(t, "/v1/auth/login",
		map[string]string{"email": "lost@example.com", "auth_key": "old-auth"}, nil, ""); code != http.StatusUnauthorized {
		t.Errorf("the old password still works: %d", code)
	}
	if code := h.post(t, "/v1/auth/recover/open",
		map[string]string{"email": "lost@example.com", "recovery_proof": "proof-of-code"}, nil, ""); code != http.StatusUnauthorized {
		t.Errorf("the spent recovery code still opens: %d", code)
	}
	if code := h.get(t, "/v1/auth/me", nil, created.Token); code != http.StatusUnauthorized {
		t.Errorf("the session from before the recovery still works: %d", code)
	}
	// The new ones work.
	var again sessionReply
	if code := h.post(t, "/v1/auth/login",
		map[string]string{"email": "lost@example.com", "auth_key": "new-auth"}, &again, ""); code != http.StatusOK {
		t.Fatalf("the new password does not sign in: %d", code)
	}
	if again.User.WrappedUSK != base64.StdEncoding.EncodeToString([]byte("wrapped-under-new-password")) {
		t.Error("the new wrap did not come back")
	}
	if code := h.post(t, "/v1/auth/recover/open",
		map[string]string{"email": "lost@example.com", "recovery_proof": "new-proof"}, nil, ""); code != http.StatusOK {
		t.Errorf("the new recovery code does not open: %d", code)
	}
}

func TestAWrongRecoveryCodeAnswersLikeAnUnknownAddress(t *testing.T) {
	h := newHarness(t)
	with, _ := newAccount(t, h.invite(t, "owner"), "with@example.com", "a")
	with.RecoveryWrap, with.RecoveryProof = base64.StdEncoding.EncodeToString([]byte("w")), "right"
	without, _ := newAccount(t, h.invite(t, "owner"), "without@example.com", "b")
	for _, b := range []signupBody{with, without} {
		if code := h.post(t, "/v1/auth/signup", b, nil, ""); code != http.StatusOK {
			t.Fatalf("signup returned %d", code)
		}
	}
	type reply struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	var wrong, none, ghost reply
	c1 := h.post(t, "/v1/auth/recover/open", map[string]string{"email": "with@example.com", "recovery_proof": "nope"}, &wrong, "")
	c2 := h.post(t, "/v1/auth/recover/open", map[string]string{"email": "without@example.com", "recovery_proof": "nope"}, &none, "")
	c3 := h.post(t, "/v1/auth/recover/open", map[string]string{"email": "ghost@example.com", "recovery_proof": "nope"}, &ghost, "")
	if c1 != http.StatusUnauthorized || c2 != http.StatusUnauthorized || c3 != http.StatusUnauthorized {
		t.Fatalf("statuses %d %d %d, want 401 for all", c1, c2, c3)
	}
	if wrong != none || none != ghost {
		t.Fatalf("a wrong code, no code and no account answer differently: %+v %+v %+v", wrong, none, ghost)
	}
	// A recovery must not be usable to finish without opening either.
	if code := h.post(t, "/v1/auth/recover/finish", map[string]any{
		"email": "with@example.com", "recovery_proof": "nope",
		"new": fresh(t, "x", "y", "z", "p"),
	}, nil, ""); code != http.StatusUnauthorized {
		t.Fatalf("finish with a wrong code returned %d", code)
	}
}

func TestChangingThePasswordEndsEveryOtherSession(t *testing.T) {
	h := newHarness(t)
	body, _ := newAccount(t, h.invite(t, "owner"), "rotate@example.com", "first")
	var laptop, phone sessionReply
	if code := h.post(t, "/v1/auth/signup", body, &laptop, ""); code != http.StatusOK {
		t.Fatalf("signup returned %d", code)
	}
	h.post(t, "/v1/auth/login", map[string]string{"email": "rotate@example.com", "auth_key": "first"}, &phone, "")

	// A session alone is not enough: the current password is proved again.
	if code := h.post(t, "/v1/auth/password", map[string]any{
		"auth_key": "wrong", "new": fresh(t, "second", "w2", "", ""),
	}, nil, laptop.Token); code != http.StatusUnauthorized {
		t.Fatalf("a wrong current password was accepted: %d", code)
	}

	var after sessionReply
	if code := h.post(t, "/v1/auth/password", map[string]any{
		"auth_key": "first", "new": fresh(t, "second", "w2", "", ""),
	}, &after, laptop.Token); code != http.StatusOK {
		t.Fatalf("password change returned %d", code)
	}
	if code := h.get(t, "/v1/auth/me", nil, phone.Token); code != http.StatusUnauthorized {
		t.Errorf("the other device's session survived the password change: %d", code)
	}
	if code := h.get(t, "/v1/auth/me", nil, after.Token); code != http.StatusOK {
		t.Errorf("the session issued by the change does not work: %d", code)
	}
	if code := h.post(t, "/v1/auth/login",
		map[string]string{"email": "rotate@example.com", "auth_key": "first"}, nil, ""); code != http.StatusUnauthorized {
		t.Errorf("the old password still signs in: %d", code)
	}
}

// Accounts from before recovery could be redeemed hold a wrap and no proof.
// They report no usable recovery, and can set one while signed in.
func TestAnOldAccountCanSetARecoveryCodeLater(t *testing.T) {
	h := newHarness(t)
	body, _ := newAccount(t, h.invite(t, "owner"), "early@example.com", "pw")
	body.RecoveryWrap = base64.StdEncoding.EncodeToString([]byte("wrap-without-proof"))
	var created sessionReply
	// A wrap with no proof is refused at signup now; the old rows are
	// simulated by writing the column directly, the way migration left them.
	if code := h.post(t, "/v1/auth/signup", body, &created, ""); code != http.StatusBadRequest {
		t.Fatalf("a wrap with no proof was accepted: %d", code)
	}
	body.RecoveryWrap = ""
	if code := h.post(t, "/v1/auth/signup", body, &created, ""); code != http.StatusOK {
		t.Fatalf("signup returned %d", code)
	}
	// users is policy-protected: outside a tenant transaction the update
	// would match nothing and report success.
	if err := pg.InTenantTx(context.Background(), h.pool, h.tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(),
			`UPDATE users SET recovery_wrap = $1 WHERE email = 'early@example.com'`,
			[]byte("wrap-without-proof"))
		return err
	}); err != nil {
		t.Fatal(err)
	}

	var me struct {
		User struct {
			HasRecovery bool `json:"has_recovery"`
		} `json:"user"`
	}
	h.get(t, "/v1/auth/me", &me, created.Token)
	if me.User.HasRecovery {
		t.Fatal("a wrap nothing can redeem is reported as a usable recovery")
	}
	if code := h.post(t, "/v1/auth/recovery", map[string]string{
		"auth_key": "pw", "recovery_wrap": base64.StdEncoding.EncodeToString([]byte("new-wrap")),
		"recovery_proof": "new-proof",
	}, nil, created.Token); code != http.StatusNoContent {
		t.Fatalf("setting a recovery code returned %d", code)
	}
	h.get(t, "/v1/auth/me", &me, created.Token)
	if !me.User.HasRecovery {
		t.Fatal("recovery is still reported unusable after a code was set")
	}
	if code := h.post(t, "/v1/auth/recover/open",
		map[string]string{"email": "early@example.com", "recovery_proof": "new-proof"}, nil, ""); code != http.StatusOK {
		t.Errorf("the new code does not open: %d", code)
	}
}

func TestADisabledAccountsSessionsStopWorking(t *testing.T) {
	h := newHarness(t)
	body, _ := newAccount(t, h.invite(t, "owner"), "gone@example.com", "pw")
	var created sessionReply
	if code := h.post(t, "/v1/auth/signup", body, &created, ""); code != http.StatusOK {
		t.Fatalf("signup returned %d", code)
	}
	if err := pg.InTenantTx(context.Background(), h.pool, h.tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(),
			`UPDATE users SET status = 'disabled' WHERE email = 'gone@example.com'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if code := h.get(t, "/v1/auth/me", nil, created.Token); code != http.StatusUnauthorized {
		t.Fatalf("a disabled account's session still works: %d", code)
	}
}

// A service registers a name and a public key against an invite issued for a
// service, and nothing else: no password, no wrap, no session.
func TestAServiceRegistersWithAPublicKeyOnly(t *testing.T) {
	h := newHarness(t)
	pub, _, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	invite, err := h.users.CreateInvite(context.Background(), h.tenant, store.RoleService, "", nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var reply struct {
		Token string `json:"token"`
		User  struct {
			ID    string `json:"id"`
			Email string `json:"email"`
			Role  string `json:"role"`
		} `json:"user"`
	}
	code := h.post(t, "/v1/auth/signup", map[string]string{
		"invite": invite, "name": "ERP-Sync", "public_key": base64.StdEncoding.EncodeToString(pub.Bytes()),
	}, &reply, "")
	if code != http.StatusOK {
		t.Fatalf("service signup returned %d", code)
	}
	if reply.Token != "" {
		t.Error("a service was issued a session token; it has no way to use one")
	}
	if reply.User.Role != store.RoleService || reply.User.Email != "erp-sync" {
		t.Errorf("registered as %+v, want role service named erp-sync", reply.User)
	}

	// Nothing signs in as it: no password exists to match, and the
	// challenge answers like an unknown address.
	if code := h.post(t, "/v1/auth/login",
		map[string]string{"email": "erp-sync", "auth_key": "anything"}, nil, ""); code != http.StatusUnauthorized {
		t.Errorf("a service signed in with a password: %d", code)
	}

	// A person's invite does not register a service, and vice versa.
	personInvite := h.invite(t, "member")
	if code := h.post(t, "/v1/auth/signup", map[string]string{
		"invite": personInvite, "name": "sneaky", "public_key": base64.StdEncoding.EncodeToString(pub.Bytes()),
	}, nil, ""); code != http.StatusForbidden {
		t.Errorf("a service registered against a person's invite: %d", code)
	}
	serviceInvite, _ := h.users.CreateInvite(context.Background(), h.tenant, store.RoleService, "", nil, time.Hour)
	body, _ := newAccount(t, serviceInvite, "person@example.com", "k")
	if code := h.post(t, "/v1/auth/signup", body, nil, ""); code != http.StatusForbidden {
		t.Errorf("a person signed up against a service invite: %d", code)
	}
}
