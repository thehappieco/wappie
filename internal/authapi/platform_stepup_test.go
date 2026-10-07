package authapi_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/config"
	"whatserver2/internal/pg"
	"whatserver2/internal/ratelimit"
	"whatserver2/internal/stepup"
)

// The step-up at the identity provider (step 4 of the sign-in plan, owner
// decision D3; docs/platform-sign-in.md, "Step-ups"): start records when the
// session asked, the provider re-authenticates the person, and finish takes
// the access token to userinfo once and records the proof against that
// start, for the linked sub, this client, the pinned key and an auth_time
// after the start.

const (
	stepUpStartPath  = "/v1/auth/platform/step-up/start"
	stepUpFinishPath = "/v1/auth/platform/step-up/finish"
)

// stepUpAnswer is any answer of the two routes: a start's, a finish's (the
// step-up status), or a refusal.
type stepUpAnswer struct {
	stepUpState
	LoginHint    string `json:"login_hint"`
	Code         string `json:"code"`
	Message      string `json:"message"`
	ProductKeyID string `json:"product_key_id"`
}

func (h *platformHarness) start(t *testing.T, token string) (int, stepUpAnswer) {
	t.Helper()
	var out stepUpAnswer
	return h.pagePost(t, stepUpStartPath, map[string]any{}, &out, token, nil), out
}

func (h *platformHarness) finish(t *testing.T, token, accessToken string) (int, stepUpAnswer) {
	t.Helper()
	var out stepUpAnswer
	return h.pagePost(t, stepUpFinishPath, map[string]string{"access_token": accessToken}, &out, token, nil), out
}

// pageRaw posts a raw body as the console's page does.
func (h *platformHarness) pageRaw(t *testing.T, path, body, token string) (int, stepUpAnswer) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, h.srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", passkeyApp)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	var out stepUpAnswer
	return h.do(t, req, &out), out
}

// providerAccount creates an account through the provider and returns its
// person and the session it signed in with, ten minutes on: past the proof
// its sign-in gave it.
func (h *platformHarness) providerAccount(t *testing.T, email string) (person, platformAnswer) {
	t.Helper()
	p := newPerson(t, email)
	_, first := h.signIn(t, p, 1)
	code, created, _, _ := h.createAccount(t, first.Ticket)
	if code != http.StatusOK || created.Token == "" {
		t.Fatalf("account: %d %+v", code, created)
	}
	h.age(t, created.Token)
	return p, created
}

// sessionID is a token's session.
func (h *platformHarness) sessionID(t *testing.T, token string) uuid.UUID {
	t.Helper()
	s, err := h.users.Session(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	return s.ID
}

// pending is the session's step_up_not_before, nil when it has none.
func (h *platformHarness) pending(t *testing.T, token string) *time.Time {
	t.Helper()
	var at *time.Time
	if err := h.pool.QueryRow(context.Background(), `SELECT step_up_not_before FROM sessions WHERE id = $1`, h.sessionID(t, token)).Scan(&at); err != nil {
		t.Fatal(err)
	}
	return at
}

// backdate moves the session's start back by d, as if it had been made then.
func (h *platformHarness) backdate(t *testing.T, token string, d time.Duration) {
	t.Helper()
	if _, err := h.pool.Exec(context.Background(), `UPDATE sessions SET step_up_not_before = step_up_not_before - make_interval(secs => $2) WHERE id = $1`,
		h.sessionID(t, token), d.Seconds()); err != nil {
		t.Fatal(err)
	}
}

func (h *platformHarness) state(t *testing.T, token string) stepUpState {
	t.Helper()
	var state stepUpState
	if code := h.get(t, "/v1/auth/step-up", &state, token); code != http.StatusOK {
		t.Fatalf("step-up status: %d", code)
	}
	return state
}

// issueAfter registers a userinfo answer for a fresh token that runs before
// first, while the finish waits on userinfo.
func (f *fakeID) issueAfter(t *testing.T, body map[string]any, before func()) string {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	token := newAccessToken(t)
	f.mu.Lock()
	f.answers[token] = func(w http.ResponseWriter) {
		before()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	}
	f.mu.Unlock()
	return token
}

func withAuthTime(u map[string]any, at time.Time) map[string]any {
	if at.IsZero() {
		delete(u, "auth_time")
	} else {
		u["auth_time"] = at.Unix()
	}
	return u
}

var provisionalInvite = map[string]any{"role": "service", "email": "", "provisional": true}

// The way through: a session past its proof is refused a guarded write;
// start names the provider's address of the account; finish with the
// provider's re-authentication records the proof, answered as the other
// step-ups answer; the write passes. One start makes one proof: a second
// finish is refused before anything goes to the provider. A linked account
// is hinted with the provider's address of the link, not its Wappie one.
func TestPlatformStepUpAtTheProvider(t *testing.T) {
	h := newPlatformHarness(t, config.LocalLoginOn)
	p, signed := h.providerAccount(t, "sol@example.com")
	token := signed.Token

	if state := h.state(t, token); state.Fresh || !state.Provider || state.Passkey {
		t.Fatalf("before: %+v", state)
	}
	var refusal stepUpAnswer
	if code := h.post(t, "/v1/auth/workspaces/invites", provisionalInvite, &refusal, token); code != http.StatusForbidden || refusal.Code != stepup.Code ||
		refusal.Message != stepup.Message {
		t.Fatalf("a guarded write before: %d %+v", code, refusal)
	}
	before := h.id.requests.Load()
	if code, out := h.finish(t, token, h.id.issue(t, p.userinfo(t, 1))); code != http.StatusConflict || out.Code != "step_up_not_started" ||
		out.Message != "no confirmation was started for this session, or it was already used or is older than ten minutes; start it again" {
		t.Fatalf("a finish before any start: %d %+v", code, out)
	}
	if h.id.requests.Load() != before {
		t.Fatal("a finish with no start went to userinfo")
	}

	code, started := h.start(t, token)
	if code != http.StatusOK || started.LoginHint != "sol@example.com" || started.WindowSeconds != 600 {
		t.Fatalf("start: %d %+v", code, started)
	}
	if h.pending(t, token) == nil {
		t.Fatal("start recorded nothing")
	}
	code, done := h.finish(t, token, h.id.issue(t, p.userinfo(t, 1)))
	if code != http.StatusOK || !done.Fresh || !done.Provider || done.Passkey || done.WindowSeconds != 600 || done.RemainingSeconds < 590 {
		t.Fatalf("finish: %d %+v", code, done)
	}
	if h.pending(t, token) != nil {
		t.Fatal("the finish left its start")
	}
	if state := h.state(t, token); !state.Fresh || !state.Provider {
		t.Fatalf("after: %+v", state)
	}
	if code := h.post(t, "/v1/auth/workspaces/invites", provisionalInvite, nil, token); code != http.StatusCreated {
		t.Fatalf("a guarded write after: %d", code)
	}
	// One start, one proof.
	before = h.id.requests.Load()
	if code, out := h.finish(t, token, h.id.issue(t, p.userinfo(t, 1))); code != http.StatusConflict || out.Code != "step_up_not_started" {
		t.Fatalf("a second finish of one start: %d %+v", code, out)
	}
	if h.id.requests.Load() != before {
		t.Fatal("the second finish went to userinfo")
	}

	// A linked account: the hint is the provider's address in the link.
	q := newPerson(t, "ana@id.example.com")
	_, answer := h.signIn(t, q, 1)
	var linked platformAnswer
	if code := h.pagePost(t, "/v1/auth/platform/link", map[string]string{"ticket": answer.Ticket, "email": "passkey@example.com",
		"auth_key": h.account.AuthKey, "platform_wrap": randomWrap(t)}, &linked, "", nil); code != http.StatusOK {
		t.Fatalf("link: %d %+v", code, linked)
	}
	h.age(t, linked.Token)
	if code, out := h.start(t, linked.Token); code != http.StatusOK || out.LoginHint != "ana@id.example.com" {
		t.Fatalf("the linked account's start: %d %+v", code, out)
	}
	if code, out := h.finish(t, linked.Token, h.id.issue(t, q.userinfo(t, 1))); code != http.StatusOK || !out.Fresh {
		t.Fatalf("the linked account's finish: %d %+v", code, out)
	}
	// Both doors: a session of the linked account that signed in with the
	// old password steps up at the provider too, once its own proof is past.
	var password sessionReply
	if code := h.post(t, "/v1/auth/login", map[string]string{"email": "passkey@example.com", "auth_key": h.account.AuthKey}, &password, ""); code != http.StatusOK {
		t.Fatalf("legacy sign-in: %d", code)
	}
	h.age(t, password.Token)
	if code, out := h.start(t, password.Token); code != http.StatusOK || out.LoginHint != "ana@id.example.com" {
		t.Fatalf("the password session's start: %d %+v", code, out)
	}
	if code, out := h.finish(t, password.Token, h.id.issue(t, q.userinfo(t, 1))); code != http.StatusOK || !out.Fresh {
		t.Fatalf("the password session's finish: %d %+v", code, out)
	}
}

// The start a finish answers is the session's latest, while it is younger
// than ten minutes; a newer start voids an older one, so a re-authentication
// made for the first start does not pass for a second one made minutes
// later; a workspace switch copies no start, but a finish answers the start
// of any session of its family (the browser's sign-in and what it derived)
// and proves both, while another sign-in's answers nothing.
func TestPlatformStepUpStarts(t *testing.T) {
	h := newPlatformHarness(t, config.LocalLoginOn)
	p, signed := h.providerAccount(t, "tom@example.com")
	token := signed.Token

	// Two starts, three minutes apart, and the finish of the first: the
	// person re-authenticated two minutes ago, before the second start.
	if code, _ := h.start(t, token); code != http.StatusOK {
		t.Fatalf("first start: %d", code)
	}
	h.backdate(t, token, 3*time.Minute)
	forFirst := h.id.issue(t, withAuthTime(p.userinfo(t, 1), time.Now().Add(-2*time.Minute)))
	if code, _ := h.start(t, token); code != http.StatusOK {
		t.Fatalf("second start: %d", code)
	}
	if code, out := h.finish(t, token, forFirst); code != http.StatusForbidden || out.Code != "step_up_stale" ||
		out.Message != "the identity provider did not ask for the password or passkey again after this confirmation started; start it again" {
		t.Fatalf("the finish of the first start: %d %+v", code, out)
	}
	if code, out := h.finish(t, token, h.id.issue(t, p.userinfo(t, 1))); code != http.StatusOK || !out.Fresh {
		t.Fatalf("the finish of the second start: %d %+v", code, out)
	}

	// A start more than ten minutes old is none, and nothing goes to the
	// provider for it.
	h.age(t, token)
	if code, _ := h.start(t, token); code != http.StatusOK {
		t.Fatal(code)
	}
	h.backdate(t, token, 10*time.Minute+time.Second)
	before := h.id.requests.Load()
	if code, out := h.finish(t, token, h.id.issue(t, p.userinfo(t, 1))); code != http.StatusConflict || out.Code != "step_up_not_started" {
		t.Fatalf("a start past ten minutes: %d %+v", code, out)
	}
	if h.id.requests.Load() != before || h.state(t, token).Fresh {
		t.Fatal("a start past ten minutes went to userinfo or made a proof")
	}

	// A workspace switch copies no start of its own, but a finish from it
	// answers its source's: they are one family, the browser's sign-in and
	// what it derived. Both get the proof.
	if code, _ := h.start(t, token); code != http.StatusOK {
		t.Fatal(code)
	}
	var switched sessionReply
	if code := h.post(t, "/v1/auth/workspaces/session", map[string]string{"tenant_id": signed.User.TenantID}, &switched, token); code != http.StatusOK {
		t.Fatalf("switch: %d", code)
	}
	if h.pending(t, switched.Token) != nil {
		t.Fatal("the switch copied the start")
	}
	if code, out := h.finish(t, switched.Token, h.id.issue(t, p.userinfo(t, 1))); code != http.StatusOK || !out.Fresh {
		t.Fatalf("a finish from the switch: %d %+v", code, out)
	}
	if !h.state(t, token).Fresh || h.pending(t, token) != nil {
		t.Fatal("the switch's finish left its source without the proof, or the start in place")
	}

}

// The console's confirmation, as its page and window make it: the page works
// in a workspace session (a switch from the browser's sign-in) and starts
// there; the window holds only the sign-in's token and finishes with it. The
// page's session gets the proof, and so does the sign-in's, which every
// session the page derives later copies. Another sign-in of the same account
// is another family: its finish answers nothing.
func TestPlatformStepUpAcrossTheSessionFamily(t *testing.T) {
	h := newPlatformHarness(t, config.LocalLoginOn)
	p, signed := h.providerAccount(t, "ines@example.com")
	token := signed.Token
	var switched sessionReply
	if code := h.post(t, "/v1/auth/workspaces/session", map[string]string{"tenant_id": signed.User.TenantID}, &switched, token); code != http.StatusOK {
		t.Fatalf("switch: %d", code)
	}
	h.age(t, token)
	h.age(t, switched.Token)
	if code, _ := h.start(t, switched.Token); code != http.StatusOK {
		t.Fatal(code)
	}
	if h.pending(t, token) != nil {
		t.Fatal("the page's start was recorded on the sign-in")
	}
	if code, out := h.finish(t, token, h.id.issue(t, p.userinfo(t, 1))); code != http.StatusOK || !out.Fresh {
		t.Fatalf("the sign-in's finish of its switch's start: %d %+v", code, out)
	}
	if !h.state(t, switched.Token).Fresh || h.pending(t, switched.Token) != nil {
		t.Fatal("the page's session did not get the proof, or kept its start")
	}
	var later sessionReply
	if code := h.post(t, "/v1/auth/workspaces/session", map[string]string{"tenant_id": signed.User.TenantID}, &later, token); code != http.StatusOK || !h.state(t, later.Token).Fresh {
		t.Fatalf("a session derived after the proof: %d", code)
	}
	if code, out := h.finish(t, token, h.id.issue(t, p.userinfo(t, 1))); code != http.StatusConflict || out.Code != "step_up_not_started" {
		t.Fatalf("a second finish of one start: %d %+v", code, out)
	}

	h.age(t, switched.Token)
	if code, _ := h.start(t, switched.Token); code != http.StatusOK {
		t.Fatal(code)
	}
	code, other := h.signIn(t, p, 1)
	if code != http.StatusOK || other.Token == "" {
		t.Fatalf("another sign-in: %d %+v", code, other)
	}
	before := h.id.requests.Load()
	if code, out := h.finish(t, other.Token, h.id.issue(t, p.userinfo(t, 1))); code != http.StatusConflict || out.Code != "step_up_not_started" {
		t.Fatalf("another sign-in's finish: %d %+v", code, out)
	}
	if h.id.requests.Load() != before || h.state(t, switched.Token).Fresh {
		t.Fatal("another sign-in's finish went to userinfo or made a proof")
	}
}

// Two tabs of the family, each in its own workspace session, start one after
// the other: the later start voids the earlier one, so the family makes one
// proof, the later tab's, whichever window finishes.
func TestPlatformStepUpTwoTabs(t *testing.T) {
	h := newPlatformHarness(t, config.LocalLoginOn)
	p, signed := h.providerAccount(t, "eva@example.com")
	token := signed.Token

	h.age(t, token)
	var tabA, tabB sessionReply
	for _, tab := range []*sessionReply{&tabA, &tabB} {
		if code := h.post(t, "/v1/auth/workspaces/session", map[string]string{"tenant_id": signed.User.TenantID}, tab, token); code != http.StatusOK {
			t.Fatalf("switch: %d", code)
		}
	}
	if code, _ := h.start(t, tabA.Token); code != http.StatusOK {
		t.Fatal(code)
	}
	if code, _ := h.start(t, tabB.Token); code != http.StatusOK {
		t.Fatal(code)
	}
	if h.pending(t, tabA.Token) != nil || h.pending(t, tabB.Token) == nil {
		t.Fatal("the later tab's start left the earlier one's")
	}
	if code, out := h.finish(t, token, h.id.issue(t, p.userinfo(t, 1))); code != http.StatusOK || !out.Fresh {
		t.Fatalf("the finish of the later tab's start: %d %+v", code, out)
	}
	if !h.state(t, tabB.Token).Fresh || h.state(t, tabA.Token).Fresh {
		t.Fatal("the proof went to the wrong tab's session")
	}
	before := h.id.requests.Load()
	if code, out := h.finish(t, tabA.Token, h.id.issue(t, p.userinfo(t, 1))); code != http.StatusConflict || out.Code != "step_up_not_started" {
		t.Fatalf("a second finish in the family: %d %+v", code, out)
	}
	if h.id.requests.Load() != before || h.state(t, tabA.Token).Fresh {
		t.Fatal("a second finish in the family went to userinfo or made a proof")
	}
}

// Decision 3: the provider's auth_time may fall up to a minute before the
// start, for the two clocks, and no earlier; userinfo that names none is no
// re-authentication. A refused finish leaves the start for the next one.
func TestPlatformStepUpAuthTime(t *testing.T) {
	h := newPlatformHarness(t, config.LocalLoginOn)
	p, signed := h.providerAccount(t, "uma@example.com")
	token := signed.Token
	if code, _ := h.start(t, token); code != http.StatusOK {
		t.Fatal(code)
	}
	notBefore := *h.pending(t, token)
	for name, at := range map[string]time.Time{
		"61 seconds before the start": time.Unix(notBefore.Unix()-61, 0),
		"an hour before":              notBefore.Add(-time.Hour),
		"no auth_time":                {},
	} {
		if code, out := h.finish(t, token, h.id.issue(t, withAuthTime(p.userinfo(t, 1), at))); code != http.StatusForbidden || out.Code != "step_up_stale" {
			t.Fatalf("%s: %d %+v", name, code, out)
		}
		if pending := h.pending(t, token); pending == nil || !pending.Equal(notBefore) || h.state(t, token).Fresh {
			t.Fatalf("%s: the refusal moved the start or made a proof: %v", name, pending)
		}
	}
	if code, out := h.finish(t, token, h.id.issue(t, withAuthTime(p.userinfo(t, 1), time.Unix(notBefore.Unix()-59, 0)))); code != http.StatusOK || !out.Fresh {
		t.Fatalf("59 seconds before the start: %d %+v", code, out)
	}
}

// What userinfo must say, each refused by name and none of them a proof:
// another account at the provider, another client, a token the provider
// refuses (sent once), a string that is not a token (sent nowhere), a
// userinfo failure, and an account disabled while the finish waited. None
// clears the start: the right confirmation still passes after them all.
func TestPlatformStepUpRefusals(t *testing.T) {
	h := newPlatformHarness(t, config.LocalLoginOn)
	p, signed := h.providerAccount(t, "vic@example.com")
	token := signed.Token
	if code, _ := h.start(t, token); code != http.StatusOK {
		t.Fatal(code)
	}
	refused := func(name string, accessToken string, status int, code, message string) {
		t.Helper()
		got, out := h.finish(t, token, accessToken)
		if got != status || out.Code != code || (message != "" && out.Message != message) {
			t.Fatalf("%s: %d %+v", name, got, out)
		}
		if h.state(t, token).Fresh || h.pending(t, token) == nil {
			t.Fatalf("%s: a proof was recorded or the start cleared", name)
		}
	}

	other := newPerson(t, "someone@example.com")
	refused("another account", h.id.issue(t, other.userinfo(t, 1)), http.StatusForbidden, "step_up_other_account",
		"that confirmation was made with another account at the identity provider")
	wrongClient := p.userinfo(t, 1)
	wrongClient["client_id"] = "thehappie-console"
	refused("another client", h.id.issue(t, wrongClient), http.StatusForbidden, "wrong_client", "that confirmation was not made for this application")
	before := h.id.requests.Load()
	refused("a refused token", newAccessToken(t), http.StatusUnauthorized, "token_refused", "the identity provider refused this confirmation; confirm again")
	if n := h.id.requests.Load() - before; n != 1 {
		t.Fatalf("a refused token was sent %d times", n)
	}
	before = h.id.requests.Load()
	refused("not a token", "not-a-token", http.StatusBadRequest, "bad_request", "")
	if h.id.requests.Load() != before {
		t.Fatal("a string that is not a token was sent")
	}
	for name, accessToken := range map[string]string{
		"500":        h.id.raw(t, 500, "application/json", `{}`),
		"text/plain": h.id.raw(t, 200, "text/plain", `{}`),
		"no key":     h.id.issue(t, map[string]any{"sub": p.sub, "client_id": "wappie-app", "auth_time": time.Now().Unix()}),
	} {
		refused(name, accessToken, http.StatusBadGateway, "userinfo", "the identity provider could not check this confirmation; try again")
	}

	// The account disabled while userinfo answers.
	q, second := h.providerAccount(t, "wes@example.com")
	if code, _ := h.start(t, second.Token); code != http.StatusOK {
		t.Fatal(code)
	}
	ctx := context.Background()
	disable := func() {
		var home uuid.UUID
		if err := h.pool.QueryRow(ctx, `SELECT tenant_id FROM user_logins WHERE user_id = $1`, q.sub).Scan(&home); err != nil {
			t.Error(err)
			return
		}
		if err := pg.InTenantTx(ctx, h.pool, home.String(), func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE users SET status = 'disabled' WHERE id = $1`, q.sub)
			return err
		}); err != nil {
			t.Error(err)
		}
	}
	if code, out := h.finish(t, second.Token, h.id.issueAfter(t, q.userinfo(t, 1), disable)); code != http.StatusForbidden || out.Code != "account_disabled" {
		t.Fatalf("an account disabled meanwhile: %d %+v", code, out)
	}
	if n := h.count(t, `SELECT count(*) FROM sessions WHERE user_id = $1 AND authenticated_at > now() - interval '1 minute'`, q.sub); n != 0 {
		t.Fatalf("a disabled account got a proof on %d sessions", n)
	}

	// After every refusal, the start still answers the right confirmation.
	if code, out := h.finish(t, token, h.id.issue(t, p.userinfo(t, 1))); code != http.StatusOK || !out.Fresh {
		t.Fatalf("the right confirmation after the refusals: %d %+v", code, out)
	}

	// No session, or a dead one.
	for _, bearer := range []string{"", "not-a-session"} {
		if code, out := h.start(t, bearer); code != http.StatusUnauthorized || out.Code != "unauthorized" {
			t.Fatalf("start with %q: %d %+v", bearer, code, out)
		}
		if code, out := h.finish(t, bearer, newAccessToken(t)); code != http.StatusUnauthorized || out.Code != "unauthorized" {
			t.Fatalf("finish with %q: %d %+v", bearer, code, out)
		}
	}
}

// Decision 4: the key the provider presents at a step-up must be the one
// the sign-ins pinned for its epoch. Another key, or an epoch no sign-in
// here has pinned, is refused as account_key_changed and raises the alert
// (a security event, the Error line, the step-up's mail to the operator and
// to the account in its language); the pin stays, none is made, no proof is
// recorded, and the session and its start stay.
func TestPlatformStepUpAccountKeyChanged(t *testing.T) {
	h := newPlatformHarness(t, config.LocalLoginOn)
	ctx := context.Background()
	p, signed := h.providerAccount(t, "xia@example.com")
	token := signed.Token
	if _, err := h.users.SetLocale(ctx, uuid.MustParse(p.sub), "de"); err != nil {
		t.Fatal(err)
	}
	if code, _ := h.start(t, token); code != http.StatusOK {
		t.Fatal(code)
	}
	pinned := func() string {
		t.Helper()
		var key string
		if err := h.pool.QueryRow(ctx, `SELECT encode(product_key, 'base64') FROM platform_key_pins WHERE sub = $1 AND product_key_id = 'wappie:1'`, p.sub).Scan(&key); err != nil {
			t.Fatal(err)
		}
		return key
	}
	pin := pinned()
	alerted := func(name string) {
		t.Helper()
		got := map[string]bool{}
		for range 2 {
			select {
			case to := <-h.stepUpAlerts:
				got[to] = true
			case <-time.After(5 * time.Second):
				t.Fatalf("%s: alerts sent: %v", name, got)
			}
		}
		if !got["operator@example.com "] || !got["xia@example.com de"] {
			t.Fatalf("%s: alerts sent: %v", name, got)
		}
		select {
		case to := <-h.alerts:
			t.Fatalf("%s: the sign-in's alert went to %s", name, to)
		default:
		}
	}

	swapped := p
	swapped.root = make([]byte, 32)
	if _, err := rand.Read(swapped.root); err != nil {
		t.Fatal(err)
	}
	code, out := h.finish(t, token, h.id.issue(t, swapped.userinfo(t, 1)))
	if code != http.StatusConflict || out.Code != "account_key_changed" || out.ProductKeyID != "wappie:1" ||
		out.Message != "the account key presented differs from the one this account signed in with before; nothing was recorded" {
		t.Fatalf("another key: %d %+v", code, out)
	}
	if pinned() != pin || h.state(t, token).Fresh || h.pending(t, token) == nil {
		t.Fatal("the refusal moved the pin, made a proof or cleared the start")
	}
	if n := h.count(t, `SELECT count(*) FROM security_events WHERE kind = 'platform_account_key_changed' AND sub = $1 AND user_id = $1
		AND detail = '{"product_key_id":"wappie:1","step":"step_up"}'::jsonb`, p.sub); n != 1 {
		t.Fatalf("%d step-up alert events", n)
	}
	alerted("another key")

	// An epoch no sign-in here has pinned: refused the same way, with no pin
	// made for it.
	code, out = h.finish(t, token, h.id.issue(t, p.userinfo(t, 2)))
	if code != http.StatusConflict || out.Code != "account_key_changed" || out.ProductKeyID != "wappie:2" {
		t.Fatalf("an unpinned epoch: %d %+v", code, out)
	}
	if n := h.count(t, `SELECT count(*) FROM platform_key_pins WHERE sub = $1 AND product_key_id = 'wappie:2'`, p.sub); n != 0 {
		t.Fatal("a step-up pinned a key")
	}
	if n := h.count(t, `SELECT count(*) FROM security_events WHERE kind = 'platform_account_key_changed' AND sub = $1
		AND detail = '{"product_key_id":"wappie:2","step":"step_up","pin":"missing"}'::jsonb`, p.sub); n != 1 {
		t.Fatalf("%d unpinned-epoch events", n)
	}
	alerted("an unpinned epoch")

	// The session still works, and the pinned key confirms.
	if code, out := h.finish(t, token, h.id.issue(t, p.userinfo(t, 1))); code != http.StatusOK || !out.Fresh {
		t.Fatalf("the pinned key after the refusals: %d %+v", code, out)
	}
}

// A local account steps up here, with a passkey or the password: both
// routes answer step_up_here. With the provider unset, both answer
// platform_login_disabled. A platform account's passkey and password
// step-ups still answer step_up_at_provider, now naming the start route.
func TestPlatformStepUpIsForPlatformAccountsOnly(t *testing.T) {
	h := newPlatformHarness(t, config.LocalLoginOn)
	for path, body := range map[string]any{stepUpStartPath: map[string]any{}, stepUpFinishPath: map[string]string{"access_token": newAccessToken(t)}} {
		var out stepUpAnswer
		if code := h.pagePost(t, path, body, &out, h.signed.Token, nil); code != http.StatusConflict || out.Code != "step_up_here" ||
			out.Message != "this account confirms it is you on this server, with its passkey or password, not at the identity provider" {
			t.Fatalf("a local account at %s: %d %+v", path, code, out)
		}
	}
	if h.pending(t, h.signed.Token) != nil {
		t.Fatal("a local account's start was recorded")
	}

	_, signed := h.providerAccount(t, "yan@example.com")
	for name, call := range map[string]func(into any) int{
		"password": func(into any) int {
			return h.post(t, "/v1/auth/step-up/password", map[string]string{"auth_key": "x"}, into, signed.Token)
		},
		"passkey options": func(into any) int {
			return h.request(t, "POST", "/v1/auth/step-up/passkey/options", passkeyApp, signed.Token, map[string]any{}, into)
		},
		"passkey": func(into any) int {
			return h.request(t, "POST", "/v1/auth/step-up/passkey", passkeyApp, signed.Token, map[string]any{"flow_id": uuid.NewString()}, into)
		},
	} {
		var out stepUpAnswer
		if code := call(&out); code != http.StatusConflict || out.Code != stepup.ProviderCode || out.Message != stepup.ProviderMessage ||
			!strings.Contains(out.Message, stepUpStartPath) {
			t.Fatalf("the %s step-up of a platform account: %d %+v", name, code, out)
		}
	}

	h.handler.Platform = nil
	for _, path := range []string{stepUpStartPath, stepUpFinishPath} {
		var out stepUpAnswer
		if code := h.pagePost(t, path, map[string]any{}, &out, signed.Token, nil); code != http.StatusForbidden || out.Code != "platform_login_disabled" {
			t.Fatalf("%s with the provider unset: %d %+v", path, code, out)
		}
	}
}

// Every /platform route's rules, before the body is read: the console's
// own Origin, Sec-Fetch-Site: same-origin and JSON; then at most 4 KiB, one
// object, no unknown member. Nothing a refusal reaches is recorded or sent.
func TestPlatformStepUpRequestRules(t *testing.T) {
	h := newPlatformHarness(t, config.LocalLoginOn)
	p, signed := h.providerAccount(t, "zoe@example.com")
	token := signed.Token
	sent := h.id.requests.Load()
	for _, path := range []string{stepUpStartPath, stepUpFinishPath} {
		for _, tc := range []struct {
			headers map[string]string
			status  int
		}{
			{map[string]string{"Origin": ""}, http.StatusForbidden},
			{map[string]string{"Origin": "null"}, http.StatusForbidden},
			{map[string]string{"Origin": "https://evil.example"}, http.StatusForbidden},
			{map[string]string{"Origin": passkeyConsole}, http.StatusForbidden},
			{map[string]string{"Sec-Fetch-Site": ""}, http.StatusForbidden},
			{map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
			{map[string]string{"Sec-Fetch-Site": "same-site"}, http.StatusForbidden},
			{map[string]string{"Content-Type": "text/plain;charset=UTF-8"}, http.StatusUnsupportedMediaType},
			{map[string]string{"Content-Type": ""}, http.StatusUnsupportedMediaType},
		} {
			var out stepUpAnswer
			if code := h.pagePost(t, path, map[string]string{"access_token": h.id.issue(t, p.userinfo(t, 1))}, &out, token, tc.headers); code != tc.status {
				t.Errorf("%s %v: %d %+v", path, tc.headers, code, out)
			}
		}
	}
	if h.pending(t, token) != nil || h.id.requests.Load() != sent {
		t.Fatalf("a refused request was recorded or sent to userinfo (%d)", h.id.requests.Load()-sent)
	}
	for name, body := range map[string]string{
		"an unknown member": `{"session":"x"}`,
		"two objects":       `{}{}`,
		"no body":           ``,
		"over 4 KiB":        `{` + strings.Repeat(" ", 5000) + `}`,
	} {
		if code, out := h.pageRaw(t, stepUpStartPath, body, token); code != http.StatusBadRequest || out.Code != "bad_request" {
			t.Errorf("start with %s: %d %+v", name, code, out)
		}
	}
	if h.pending(t, token) != nil {
		t.Fatal("a refused start was recorded")
	}
	if code, _ := h.start(t, token); code != http.StatusOK {
		t.Fatal(code)
	}
	for name, body := range map[string]string{
		"an unknown member": `{"access_token":"` + h.id.issue(t, p.userinfo(t, 1)) + `","sub":"` + p.sub + `"}`,
		"two objects":       `{"access_token":"` + h.id.issue(t, p.userinfo(t, 1)) + `"}{}`,
		"over 4 KiB":        `{"access_token":"` + strings.Repeat("a", 5000) + `"}`,
	} {
		if code, out := h.pageRaw(t, stepUpFinishPath, body, token); code != http.StatusBadRequest || out.Code != "bad_request" {
			t.Errorf("finish with %s: %d %+v", name, code, out)
		}
	}
	if h.id.requests.Load() != sent || h.state(t, token).Fresh {
		t.Fatalf("a refused finish was sent to userinfo (%d) or made a proof", h.id.requests.Load()-sent)
	}
	// Answers are never cached.
	req, err := http.NewRequest(http.MethodPost, h.srv.URL+stepUpStartPath, strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", passkeyApp)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("start: %d, Cache-Control %q", resp.StatusCode, resp.Header.Get("Cache-Control"))
	}
}

// An account starts at most five step-ups in ten minutes, across its
// sessions; the start spends the address limit too, and the finish the
// address and account limits before anything goes to the provider, all on
// the sign-in limits (Limits), never the setups' (SetupLimits).
func TestPlatformStepUpRateLimits(t *testing.T) {
	h := newPlatformHarness(t, config.LocalLoginOn)
	p, signed := h.providerAccount(t, "ada@example.com")
	_, again := h.signIn(t, p, 1)
	if again.Kind != "session" {
		t.Fatalf("second session: %+v", again)
	}
	for i, token := range []string{signed.Token, signed.Token, signed.Token, again.Token, again.Token} {
		if code, out := h.start(t, token); code != http.StatusOK {
			t.Fatalf("start %d: %d %+v", i+1, code, out)
		}
	}
	for _, token := range []string{signed.Token, again.Token} {
		if code, out := h.start(t, token); code != http.StatusTooManyRequests || out.Code != "rate_limited" {
			t.Fatalf("a sixth start: %d %+v", code, out)
		}
	}
	// Another account has its own.
	_, other := h.providerAccount(t, "bob@example.com")
	if code, _ := h.start(t, other.Token); code != http.StatusOK {
		t.Fatalf("another account's start: %d", code)
	}

	h.handler.Limits = &ratelimit.Auth{PerIP: ratelimit.New(60, 100), PerSubject: ratelimit.New(1, 2)}
	for range 2 {
		if code, out := h.finish(t, other.Token, newAccessToken(t)); code != http.StatusUnauthorized || out.Code != "token_refused" {
			t.Fatalf("a finish within the limit: %d %+v", code, out)
		}
	}
	before := h.id.requests.Load()
	if code, out := h.finish(t, other.Token, h.id.issue(t, p.userinfo(t, 1))); code != http.StatusTooManyRequests || out.Code != "rate_limited" {
		t.Fatalf("a finish past the account limit: %d %+v", code, out)
	}
	if h.id.requests.Load() != before {
		t.Fatal("a rate-limited finish went to userinfo")
	}

	// The start's address limit: a second start from this address is
	// refused although the account's window has room.
	_, cy := h.providerAccount(t, "cy@example.com")
	h.handler.Limits = &ratelimit.Auth{PerIP: ratelimit.New(1, 1), PerSubject: ratelimit.New(60, 100)}
	if code, out := h.start(t, cy.Token); code != http.StatusOK {
		t.Fatalf("a start within the address limit: %d %+v", code, out)
	}
	if code, out := h.start(t, cy.Token); code != http.StatusTooManyRequests || out.Code != "rate_limited" {
		t.Fatalf("a start past the address limit: %d %+v", code, out)
	}
}

// Decision 2: a sign-in through the provider is a proof from its userinfo's
// auth_time, never from the session's creation: a recent one for the rest
// of its ten minutes, an old one or none not at all. A new account's first
// session takes its ticket's auth_time; a link's session is proved now. A
// workspace switch copies the proof and the mark, never a pending start.
func TestPlatformSignInProofIsTheAuthTime(t *testing.T) {
	h := newPlatformHarness(t, config.LocalLoginOn)
	ctx := context.Background()
	signInAt := func(p person, at time.Time) platformAnswer {
		t.Helper()
		var out platformAnswer
		if code := h.pagePost(t, "/v1/auth/platform/session", map[string]string{"access_token": h.id.issue(t, withAuthTime(p.userinfo(t, 1), at))}, &out, "", nil); code != http.StatusOK {
			t.Fatalf("sign-in: %d %+v", code, out)
		}
		return out
	}
	viaProvider := func(token string) bool {
		t.Helper()
		s, err := h.users.Session(ctx, token)
		if err != nil {
			t.Fatal(err)
		}
		var via bool
		if err := h.pool.QueryRow(ctx, `SELECT via_provider FROM sessions WHERE id = $1`, s.ID).Scan(&via); err != nil {
			t.Fatal(err)
		}
		return via
	}

	// A new account whose ticket came from an old sign-in at the provider.
	old := newPerson(t, "old@example.com")
	ticket := signInAt(old, time.Now().Add(-11*time.Minute))
	code, created, _, _ := h.createAccount(t, ticket.Ticket)
	if code != http.StatusOK || h.state(t, created.Token).Fresh || !viaProvider(created.Token) {
		t.Fatalf("a new account from an old sign-in: %d %+v", code, h.state(t, created.Token))
	}
	// One from a recent sign-in asks nothing.
	recent := newPerson(t, "recent@example.com")
	ticket = signInAt(recent, time.Now().Add(-5*time.Second))
	if code, created, _, _ = h.createAccount(t, ticket.Ticket); code != http.StatusOK {
		t.Fatal(code)
	}
	if state := h.state(t, created.Token); !state.Fresh || state.RemainingSeconds < 590 {
		t.Fatalf("a new account from a recent sign-in: %+v", state)
	}
	if code := h.post(t, "/v1/auth/workspaces/invites", provisionalInvite, nil, created.Token); code != http.StatusCreated {
		t.Fatalf("a guarded write right after the sign-in: %d", code)
	}

	for name, tc := range map[string]struct {
		at       time.Time
		min, max int
	}{
		"three minutes ago": {time.Now().Add(-3 * time.Minute), 400, 425},
		"eleven ago":        {time.Now().Add(-11 * time.Minute), 0, 0},
		"none":              {time.Time{}, 0, 0},
		"an hour ahead":     {time.Now().Add(time.Hour), 590, 600},
	} {
		signed := signInAt(recent, tc.at)
		if signed.Kind != "session" || !viaProvider(signed.Token) {
			t.Fatalf("%s: %+v", name, signed)
		}
		state := h.state(t, signed.Token)
		if state.RemainingSeconds < tc.min || state.RemainingSeconds > tc.max || state.Fresh != (tc.max > 0) {
			t.Fatalf("%s: %+v", name, state)
		}
		if code, _ := h.start(t, signed.Token); code != http.StatusOK {
			t.Fatalf("%s: start %d", name, code)
		}
		var switched sessionReply
		if code := h.post(t, "/v1/auth/workspaces/session", map[string]string{"tenant_id": signed.User.TenantID}, &switched, signed.Token); code != http.StatusOK {
			t.Fatalf("%s: switch %d", name, code)
		}
		if got := h.state(t, switched.Token); got.Fresh != state.Fresh || got.RemainingSeconds > state.RemainingSeconds || got.RemainingSeconds < state.RemainingSeconds-5 {
			t.Fatalf("%s: the switch's proof %+v, its source's %+v", name, got, state)
		}
		if !viaProvider(switched.Token) || h.pending(t, switched.Token) != nil {
			t.Fatalf("%s: the switch lost the mark or copied the start", name)
		}
	}

	// A link checks the old password: its session is proved now, whatever
	// the ticket's sign-in.
	p := newPerson(t, "passkey@example.com")
	ticket = signInAt(p, time.Now().Add(-11*time.Minute))
	var linked platformAnswer
	if code := h.pagePost(t, "/v1/auth/platform/link", map[string]string{"ticket": ticket.Ticket, "email": "passkey@example.com",
		"auth_key": h.account.AuthKey, "platform_wrap": randomWrap(t)}, &linked, "", nil); code != http.StatusOK {
		t.Fatalf("link: %d %+v", code, linked)
	}
	if state := h.state(t, linked.Token); !state.Fresh || state.RemainingSeconds < 590 || !viaProvider(linked.Token) {
		t.Fatalf("the link's session: %+v", state)
	}
}
