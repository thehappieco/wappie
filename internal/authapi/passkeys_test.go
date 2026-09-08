package authapi_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/authapi"
	"whatserver2/internal/config"
	"whatserver2/internal/store"
)

const passkeyRP = "wappie.example.com"
const passkeyApp = "https://app.wappie.example.com"
const passkeyConsole = "https://console.wappie.example.com"

type testPasskeyFlow struct {
	ID        string `json:"flow_id"`
	RPID      string `json:"rp_id"`
	UserID    string `json:"user_id"`
	Salt      string `json:"prf_salt"`
	PublicKey struct {
		Challenge              string `json:"challenge"`
		RPID                   string `json:"rpId"`
		UserVerification       string `json:"userVerification"`
		AllowCredentials       []any  `json:"allowCredentials"`
		AuthenticatorSelection struct {
			ResidentKey      string `json:"residentKey"`
			UserVerification string `json:"userVerification"`
		} `json:"authenticatorSelection"`
	} `json:"publicKey"`
}

type passkeyHarness struct {
	*harness
	account signupBody
	signed  sessionReply
}

func newPasskeyHarness(t *testing.T) *passkeyHarness {
	t.Helper()
	h := newHarness(t)
	provider, err := authapi.NewPasskeyProvider(config.Passkeys{RPID: passkeyRP, Origins: []string{passkeyApp, passkeyConsole}})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	(&authapi.Handler{Users: h.users, Keys: h.keys, Devices: store.NewDevices(h.pool), Passkeys: provider}).Mount(mux)
	h.srv.Close()
	h.srv = httptest.NewServer(mux)
	t.Cleanup(h.srv.Close)
	body, _ := newAccount(t, h.invite(t, "owner"), "passkey@example.com", "password-auth-key")
	body.RecoveryWrap = base64.StdEncoding.EncodeToString([]byte("recovery-wrap"))
	body.RecoveryProof = "recovery-proof"
	p := &passkeyHarness{harness: h, account: body}
	if code := h.post(t, "/v1/auth/signup", body, &p.signed, ""); code != 200 {
		t.Fatalf("signup: %d", code)
	}
	return p
}

func (h *passkeyHarness) request(t *testing.T, method, path, origin, token string, body, into any) int {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(method, h.srv.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return h.do(t, req, into)
}

func (h *passkeyHarness) flow(t *testing.T, register bool, origin string) testPasskeyFlow {
	t.Helper()
	path, token, body := "/v1/auth/passkeys/login/options", "", map[string]any{}
	if register {
		path = "/v1/auth/passkeys/register/options"
		token = h.signed.Token
		body = map[string]any{"auth_key": h.account.AuthKey, "label": "My authenticator"}
	}
	var flow testPasskeyFlow
	if code := h.request(t, "POST", path, origin, token, body, &flow); code != 200 {
		t.Fatalf("options: %d", code)
	}
	if flow.ID == "" || flow.PublicKey.Challenge == "" || flow.RPID != passkeyRP {
		t.Fatalf("invalid options: %+v", flow)
	}
	salt, err := base64.StdEncoding.DecodeString(flow.Salt)
	if err != nil || len(salt) != 32 {
		t.Fatal("invalid PRF salt")
	}
	return flow
}

// This is an ES256 authenticator, not a signature-validation mock. Its none
// attestation and assertions exercise the WebAuthn verifier through HTTP.
type softwarePasskey struct {
	private *ecdsa.PrivateKey
	id      []byte
	user    uuid.UUID
}

func newSoftwarePasskey(t *testing.T, userID string) *softwarePasskey {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	return &softwarePasskey{private: private, id: id, user: uuid.MustParse(userID)}
}

func passkeyB64(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

func (p *softwarePasskey) creation(t *testing.T, flow testPasskeyFlow, origin string) map[string]any {
	t.Helper()
	cose, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: p.private.X.FillBytes(make([]byte, 32)), -3: p.private.Y.FillBytes(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	rp := sha256.Sum256([]byte(passkeyRP))
	authData := append(append([]byte{}, rp[:]...), 0x45, 0, 0, 0, 0)
	authData = append(authData, make([]byte, 16)...)
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(p.id)))
	authData = append(authData, p.id...)
	authData = append(authData, cose...)
	attestation, err := cbor.Marshal(map[string]any{"fmt": "none", "authData": authData, "attStmt": map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	client, _ := json.Marshal(map[string]any{"type": "webauthn.create", "challenge": flow.PublicKey.Challenge, "origin": origin, "crossOrigin": false})
	return map[string]any{"id": passkeyB64(p.id), "rawId": passkeyB64(p.id), "type": "public-key", "response": map[string]any{"clientDataJSON": passkeyB64(client), "attestationObject": passkeyB64(attestation), "transports": []string{"internal"}}, "clientExtensionResults": map[string]any{"credProps": map[string]any{"rk": true}, "prf": map[string]any{"enabled": true}}}
}

func (p *softwarePasskey) assertion(t *testing.T, flow testPasskeyFlow, origin, rpID string, flags byte, counter uint32) map[string]any {
	t.Helper()
	client, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": flow.PublicKey.Challenge, "origin": origin, "crossOrigin": false})
	rp := sha256.Sum256([]byte(rpID))
	authData := append(append([]byte{}, rp[:]...), flags)
	authData = binary.BigEndian.AppendUint32(authData, counter)
	clientHash := sha256.Sum256(client)
	digest := sha256.Sum256(append(append([]byte{}, authData...), clientHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, p.private, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"id": passkeyB64(p.id), "rawId": passkeyB64(p.id), "type": "public-key", "response": map[string]any{"clientDataJSON": passkeyB64(client), "authenticatorData": passkeyB64(authData), "signature": passkeyB64(signature), "userHandle": passkeyB64(p.user[:])}, "clientExtensionResults": map[string]any{}}
}

func testPasskeyWrap() string {
	raw := make([]byte, 61)
	raw[0] = 1
	return base64.StdEncoding.EncodeToString(raw)
}

func (h *passkeyHarness) register(t *testing.T) (*softwarePasskey, store.Passkey) {
	t.Helper()
	flow := h.flow(t, true, passkeyApp)
	if flow.UserID != h.signed.User.ID || flow.PublicKey.AuthenticatorSelection.ResidentKey != "required" || flow.PublicKey.AuthenticatorSelection.UserVerification != "required" {
		t.Fatal("registration must require a discoverable, verified credential")
	}
	p := newSoftwarePasskey(t, h.signed.User.ID)
	var result struct {
		Passkey store.Passkey `json:"passkey"`
	}
	if code := h.request(t, "POST", "/v1/auth/passkeys/register/finish", passkeyApp, h.signed.Token, map[string]any{"flow_id": flow.ID, "credential": p.creation(t, flow, passkeyApp), "wrapped_usk": testPasskeyWrap()}, &result); code != 200 {
		t.Fatalf("register finish: %d", code)
	}
	if result.Passkey.ID == uuid.Nil {
		t.Fatal("no passkey id")
	}
	return p, result.Passkey
}

func TestPasskeyRegistrationLoginAndRevocation(t *testing.T) {
	h := newPasskeyHarness(t)
	p, key := h.register(t)
	var listed struct {
		Passkeys []map[string]any `json:"passkeys"`
	}
	if code := h.get(t, "/v1/auth/passkeys", &listed, h.signed.Token); code != 200 || len(listed.Passkeys) != 1 {
		t.Fatalf("list: %d %+v", code, listed)
	}
	for _, hidden := range []string{"credential", "credential_id", "wrapped_usk", "prf_salt", "user_id"} {
		if _, ok := listed.Passkeys[0][hidden]; ok {
			t.Fatalf("metadata leaked %s", hidden)
		}
	}
	flow := h.flow(t, false, passkeyConsole)
	if len(flow.PublicKey.AllowCredentials) != 0 || flow.PublicKey.UserVerification != "required" {
		t.Fatal("login must be discoverable and require UV")
	}
	body := map[string]any{"flow_id": flow.ID, "credential": p.assertion(t, flow, passkeyConsole, passkeyRP, 0x05, 1)}
	var login struct {
		sessionReply
		Passkey struct {
			ID      string `json:"id"`
			Wrapped string `json:"wrapped_usk"`
			Salt    string `json:"prf_salt"`
		} `json:"passkey"`
	}
	if code := h.request(t, "POST", "/v1/auth/passkeys/login/finish", passkeyConsole, "", body, &login); code != 200 {
		t.Fatalf("login: %d", code)
	}
	if login.Token == "" || login.User.ID != h.signed.User.ID || login.Passkey.Wrapped != testPasskeyWrap() || login.Passkey.ID != key.ID.String() || login.Passkey.Salt != flow.Salt {
		t.Fatal("incorrect login envelope")
	}
	if code := h.request(t, "POST", "/v1/auth/passkeys/login/finish", passkeyConsole, "", body, nil); code != 401 {
		t.Fatalf("replay: %d", code)
	}
	var workspace sessionReply
	if code := h.post(t, "/v1/auth/workspaces/session", map[string]string{"tenant_id": h.tenant.String()}, &workspace, login.Token); code != 200 {
		t.Fatalf("workspace: %d", code)
	}
	for _, token := range []string{login.Token, workspace.Token} {
		session, err := h.users.Session(context.Background(), token)
		if err != nil || session.PasskeyID != key.ID {
			t.Fatal("passkey provenance lost")
		}
	}
	path := "/v1/auth/passkeys/" + key.ID.String()
	if code := h.request(t, "DELETE", path, passkeyApp, h.signed.Token, map[string]string{"auth_key": "wrong"}, nil); code != 401 {
		t.Fatalf("deletion without password: %d", code)
	}
	if code := h.request(t, "DELETE", path, passkeyApp, h.signed.Token, map[string]string{"auth_key": h.account.AuthKey}, nil); code != 200 {
		t.Fatalf("delete: %d", code)
	}
	for _, token := range []string{login.Token, workspace.Token} {
		if _, err := h.users.Session(context.Background(), token); !errors.Is(err, store.ErrNoSession) {
			t.Fatal("revoked passkey retained a session")
		}
	}
	if _, err := h.users.Session(context.Background(), h.signed.Token); err != nil {
		t.Fatal("password session unexpectedly revoked")
	}
	flow = h.flow(t, false, passkeyApp)
	if code := h.request(t, "POST", "/v1/auth/passkeys/login/finish", passkeyApp, "", map[string]any{"flow_id": flow.ID, "credential": p.assertion(t, flow, passkeyApp, passkeyRP, 0x05, 2)}, nil); code != 401 {
		t.Fatalf("revoked login: %d", code)
	}
}

func TestPasskeyVerificationRejectsInvalidAssertions(t *testing.T) {
	h := newPasskeyHarness(t)
	p, _ := h.register(t)
	for _, name := range []string{"origin", "rp", "uv", "presence", "challenge", "signature", "user", "counter", "secret-output"} {
		t.Run(name, func(t *testing.T) {
			flow := h.flow(t, false, passkeyApp)
			origin, rp, flags := passkeyApp, passkeyRP, byte(0x05)
			if name == "origin" {
				origin = passkeyConsole
			}
			if name == "rp" {
				rp = "evil.example.com"
			}
			if name == "uv" {
				flags = 0x01
			}
			if name == "presence" {
				flags = 0x04
			}
			assertionFlow := flow
			if name == "challenge" {
				assertionFlow.PublicKey.Challenge = passkeyB64(make([]byte, 32))
			}
			credential := p.assertion(t, assertionFlow, origin, rp, flags, 1)
			response := credential["response"].(map[string]any)
			if name == "signature" {
				response["signature"] = passkeyB64(make([]byte, 64))
			}
			if name == "user" {
				other := uuid.New()
				response["userHandle"] = passkeyB64(other[:])
			}
			if name == "secret-output" {
				credential["clientExtensionResults"] = map[string]any{"prf": map[string]any{"results": map[string]any{"first": "never-store-this"}}}
			}
			if name == "counter" {
				prior := h.flow(t, false, passkeyApp)
				if code := h.request(t, "POST", "/v1/auth/passkeys/login/finish", passkeyApp, "", map[string]any{"flow_id": prior.ID, "credential": p.assertion(t, prior, passkeyApp, passkeyRP, 0x05, 2)}, nil); code != 200 {
					t.Fatalf("prior login: %d", code)
				}
			}
			code := h.request(t, "POST", "/v1/auth/passkeys/login/finish", passkeyApp, "", map[string]any{"flow_id": flow.ID, "credential": credential}, nil)
			want := 401
			if name == "secret-output" {
				want = 400
			}
			if code != want {
				t.Fatalf("%s accepted/status %d", name, code)
			}
			if code := h.request(t, "POST", "/v1/auth/passkeys/login/finish", passkeyApp, "", map[string]any{"flow_id": flow.ID, "credential": p.assertion(t, flow, passkeyApp, passkeyRP, 0x05, 3)}, nil); code != 401 {
				t.Fatalf("failed proof left challenge reusable: %d", code)
			}
		})
	}
}

func TestPasskeyRegistrationBindsSessionAndExpires(t *testing.T) {
	h := newPasskeyHarness(t)
	var second sessionReply
	if code := h.post(t, "/v1/auth/login", map[string]string{"email": h.account.Email, "auth_key": h.account.AuthKey}, &second, ""); code != 200 {
		t.Fatal(code)
	}
	flow := h.flow(t, true, passkeyApp)
	p := newSoftwarePasskey(t, h.signed.User.ID)
	body := map[string]any{"flow_id": flow.ID, "credential": p.creation(t, flow, passkeyApp), "wrapped_usk": testPasskeyWrap()}
	if code := h.request(t, "POST", "/v1/auth/passkeys/register/finish", passkeyApp, second.Token, body, nil); code != 401 {
		t.Fatalf("different session: %d", code)
	}
	if code := h.request(t, "POST", "/v1/auth/passkeys/register/finish", passkeyApp, h.signed.Token, body, nil); code != 200 {
		t.Fatalf("original session: %d", code)
	}
	flow = h.flow(t, false, passkeyApp)
	if _, err := h.pool.Exec(context.Background(), `UPDATE passkey_challenges SET expires_at=now()-interval '1 second' WHERE id=$1`, flow.ID); err != nil {
		t.Fatal(err)
	}
	if code := h.request(t, "POST", "/v1/auth/passkeys/login/finish", passkeyApp, "", map[string]any{"flow_id": flow.ID, "credential": p.assertion(t, flow, passkeyApp, passkeyRP, 0x05, 1)}, nil); code != 401 {
		t.Fatalf("expired: %d", code)
	}
	if code := h.request(t, "POST", "/v1/auth/passkeys/login/options", "https://evil.example.com", "", map[string]any{}, nil); code != 403 {
		t.Fatalf("untrusted origin: %d", code)
	}
	if code := h.request(t, "POST", "/v1/auth/passkeys/register/options", passkeyApp, h.signed.Token, map[string]string{"auth_key": "wrong", "label": "attack"}, nil); code != 401 {
		t.Fatalf("registration without password: %d", code)
	}
}

func TestPasskeyRecoveryRevokesCredentialsAndPendingFlows(t *testing.T) {
	h := newPasskeyHarness(t)
	_, key := h.register(t)
	flow := h.flow(t, true, passkeyApp)
	user, err := h.users.LoginIdentity(context.Background(), uuid.MustParse(h.signed.User.ID))
	if err != nil {
		t.Fatal(err)
	}
	// Ordinary password changes preserve the credential and its encrypted wrap.
	rekey := store.Rekey{AuthKey: "new-auth-key", KDFSalt: make([]byte, 16), KDFParams: store.DefaultKDFParams(), WrappedUSK: []byte("new-wrap")}
	if err := h.users.Rekey(context.Background(), h.tenant, user.ID, rekey); err != nil {
		t.Fatal(err)
	}
	keys, err := h.users.Passkeys(context.Background(), user.ID)
	if err != nil || len(keys) != 1 || keys[0].ID != key.ID {
		t.Fatal("password change removed passkey")
	}
	// Recovery through the public endpoint must revoke all passkeys.
	newBody := map[string]any{"auth_key": "recovered-auth-key", "kdf_salt": base64.StdEncoding.EncodeToString(make([]byte, 16)), "kdf_params": store.DefaultKDFParams(), "wrapped_usk": base64.StdEncoding.EncodeToString([]byte("recovered-wrap")), "recovery_wrap": base64.StdEncoding.EncodeToString([]byte("new-recovery-wrap")), "recovery_proof": "new-recovery-proof"}
	if code := h.post(t, "/v1/auth/recover/finish", map[string]any{"email": h.account.Email, "recovery_proof": h.account.RecoveryProof, "new": newBody}, nil, ""); code != 200 {
		t.Fatalf("recover: %d", code)
	}
	keys, err = h.users.Passkeys(context.Background(), user.ID)
	if err != nil || len(keys) != 0 {
		t.Fatal("recovery kept passkeys")
	}
	_, err = h.users.ConsumePasskeyChallenge(context.Background(), uuid.MustParse(flow.ID), "register", passkeyApp, user.ID, uuid.New())
	if !errors.Is(err, store.ErrBadCredentials) {
		t.Fatal("recovery kept flow")
	}
	var count int
	if err := h.pool.QueryRow(context.Background(), `SELECT count(*) FROM passkey_challenges WHERE id=$1`, flow.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("recovery flow was not deleted")
	}
}

func TestPasskeysAreIsolatedByIdentityAndChallengeIsSingleUse(t *testing.T) {
	h := newPasskeyHarness(t)
	_, key := h.register(t)
	other := uuid.New()
	keys, err := h.users.Passkeys(context.Background(), other)
	if err != nil || len(keys) != 0 {
		t.Fatal("another identity sees passkey")
	}
	if err := h.users.RevokePasskey(context.Background(), other, key.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("another identity revoked passkey")
	}
	// FORCE RLS protects the public credential and wrap even outside API filters.
	if err := h.pool.QueryRow(context.Background(), `SELECT id FROM user_passkeys WHERE id=$1`, key.ID).Scan(&other); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("unscoped RLS lookup: %v", err)
	}
	flow := store.PasskeyChallenge{ID: uuid.New(), Kind: "login", Origin: passkeyApp, Data: json.RawMessage(`{}`), ExpiresAt: time.Now().Add(time.Minute)}
	if err := h.users.CreatePasskeyChallenge(context.Background(), flow); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			_, err := h.users.ConsumePasskeyChallenge(context.Background(), flow.ID, "login", passkeyApp, uuid.Nil, uuid.Nil)
			results <- err
		}()
	}
	wins := 0
	for i := 0; i < 2; i++ {
		if <-results == nil {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("challenge had %d winners", wins)
	}
}

func TestPasskeyConfigDisabledByDefault(t *testing.T) {
	mux := http.NewServeMux()
	(&authapi.Handler{}).Mount(mux)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/v1/auth/passkeys/config", nil))
	if w.Code != 200 || w.Body.String() != "{\"enabled\":false,\"rp_id\":\"\",\"origins\":[]}\n" {
		t.Fatalf("disabled config: %s", w.Body.String())
	}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("POST", "/v1/auth/passkeys/login/options", nil))
	if w.Code != 404 {
		t.Fatalf("disabled login: %d", w.Code)
	}
	provider, err := authapi.NewPasskeyProvider(config.Passkeys{RPID: passkeyRP, Origins: []string{passkeyApp, passkeyConsole}})
	if err != nil {
		t.Fatal(err)
	}
	mux = http.NewServeMux()
	(&authapi.Handler{Passkeys: provider}).Mount(mux)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/v1/auth/passkeys/config", nil))
	var cfg struct {
		Enabled bool     `json:"enabled"`
		RPID    string   `json:"rp_id"`
		Origins []string `json:"origins"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &cfg); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || !cfg.Enabled || cfg.RPID != passkeyRP || len(cfg.Origins) != 2 || cfg.Origins[0] != passkeyApp || cfg.Origins[1] != passkeyConsole {
		t.Fatalf("enabled config: %s", w.Body.String())
	}
}

func TestPasskeyRegistrationCannotEscapeConcurrentRecovery(t *testing.T) {
	h := newPasskeyHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	session, err := h.users.Session(ctx, h.signed.Token)
	if err != nil {
		t.Fatal(err)
	}
	// Hold the shared lock so registration enters first and recovery queues
	// behind it. Before the fix, registration already held the session here,
	// and recovery scanned credentials before waiting for that session.
	blocker, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(context.Background())
	var blockerPID int
	if err := blocker.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&blockerPID); err != nil {
		t.Fatal(err)
	}
	if _, err := blocker.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "passkeys/"+session.UserID.String()); err != nil {
		t.Fatal(err)
	}
	waitBlocked := func(count int) {
		t.Helper()
		for {
			var waiting int
			err := h.pool.QueryRow(ctx, `WITH RECURSIVE waiting(pid) AS (
				SELECT pid FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid))
				UNION SELECT a.pid FROM pg_stat_activity a JOIN waiting w ON w.pid=ANY(pg_blocking_pids(a.pid))
			) SELECT count(*) FROM waiting`, blockerPID).Scan(&waiting)
			if err != nil {
				t.Fatal(err)
			}
			if waiting >= count {
				return
			}
			select {
			case <-ctx.Done():
				t.Fatal("operations did not reach the controlled race")
			case <-time.After(5 * time.Millisecond):
			}
		}
	}
	key := store.Passkey{UserID: session.UserID, CredentialID: []byte("concurrent-credential"), Credential: json.RawMessage(`{}`), Label: "Concurrent", RPID: passkeyRP, PRFSalt: make([]byte, 32), WrappedUSK: make([]byte, 61)}
	added := make(chan error, 1)
	go func() { added <- h.users.AddPasskey(ctx, &key, session.ID) }()
	waitBlocked(1)
	recovered := make(chan error, 1)
	go func() {
		recovered <- h.users.Rekey(ctx, h.tenant, session.UserID, store.Rekey{RevokePasskeys: true, AuthKey: "recovered-key", KDFSalt: make([]byte, 16), KDFParams: store.DefaultKDFParams(), WrappedUSK: []byte("recovered-wrap")})
	}()
	waitBlocked(2)
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-added; err != nil && !errors.Is(err, store.ErrNoSession) {
		t.Fatal(err)
	}
	if err := <-recovered; err != nil {
		t.Fatal(err)
	}
	keys, err := h.users.Passkeys(ctx, session.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatal("a passkey registered concurrently survived account recovery")
	}
	if _, err := h.users.Session(ctx, h.signed.Token); !errors.Is(err, store.ErrNoSession) {
		t.Fatal("recovery left registration session active")
	}
}
