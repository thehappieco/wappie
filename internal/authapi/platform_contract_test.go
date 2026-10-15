package authapi_test

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/thehappieco/kit/contract/contracttest"

	"whatserver2/internal/config"
	"whatserver2/internal/membership"
	"whatserver2/internal/membership/membershiptest"
	"whatserver2/internal/store"
)

// The contract at sign-in (decision 0040; the plan's 4.5, DB2, DB8 and
// DB21): the PUT at each of the three sign-in routes, a new account's home
// from the platform's document, and the unsubscribe of a refused sign-up.

type contractHarness struct {
	*platformHarness
	fake     *membershiptest.Fake
	members  *membership.Members
	contract *store.Contract
	logs     *membershiptest.Logs
}

// The contract's modes as a test sets them: never observed, observing, and
// off after an observe.
const (
	modeNever    = "never"
	modeObserve  = "observe"
	modeOffAfter = "off_after"
)

func newContractHarness(t *testing.T, mode string) *contractHarness {
	t.Helper()
	h := newPlatformHarness(t, config.LocalLoginOn)
	secret := membershiptest.Secret(t)
	fake := membershiptest.StartFake(t, secret)
	client := membership.NewClient(&http.Client{}, fake.URL, nil)
	if err := client.Use(secret, ""); err != nil {
		t.Fatal(err)
	}
	logs := &membershiptest.Logs{}
	c := store.NewContract(h.pool)
	members := &membership.Members{Client: client, Contract: c, Log: logs.Logger(), ModeCache: -1}
	h.handler.Membership = members
	setContractMode(t, h.pool, mode)
	return &contractHarness{platformHarness: h, fake: fake, members: members, contract: c, logs: logs}
}

func setContractMode(t *testing.T, pool *pgxpool.Pool, mode string) {
	t.Helper()
	var stmt string
	switch mode {
	case modeNever:
		return
	case modeObserve:
		stmt = `UPDATE contract_state SET mode = 'observe', events_from = coalesce(events_from, clock_timestamp()), events_paused_at = NULL`
	case modeOffAfter:
		stmt = `UPDATE contract_state SET mode = 'off', events_from = coalesce(events_from, clock_timestamp()), events_paused_at = clock_timestamp()`
	default:
		t.Fatalf("mode %q", mode)
	}
	if _, err := pool.Exec(context.Background(), stmt); err != nil {
		t.Fatal(err)
	}
}

// platformPerson is a person at id. who has an account on the fake
// platform too, and that account's personal workspace.
func (h *contractHarness) platformPerson(t *testing.T, email string) (person, uuid.UUID) {
	t.Helper()
	p := newPerson(t, email)
	personal, err := h.fake.AddAccount(p.sub)
	if err != nil {
		t.Fatal(err)
	}
	return p, uuid.MustParse(personal)
}

// signUp signs p in for the first time and creates the account.
func (h *contractHarness) signUp(t *testing.T, p person) (int, platformAnswer) {
	t.Helper()
	code, first := h.signIn(t, p, 1)
	if code != http.StatusOK || first.Kind != "new" {
		t.Fatalf("first sign-in: %d %+v", code, first)
	}
	code, out, _, _ := h.createAccount(t, first.Ticket)
	return code, out
}

func (h *contractHarness) following(sub string) bool { return h.fake.Following("wappie", sub) }

// intent is sub's contract_accounts row: whether it exists, and whether a
// document's version is stored on it.
func (h *contractHarness) intent(t *testing.T, sub string) (exists, versioned bool) {
	t.Helper()
	var v *int64
	err := h.pool.QueryRow(context.Background(), `SELECT version FROM contract_accounts WHERE sub = $1`, sub).Scan(&v)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return false, false
		}
		t.Fatal(err)
	}
	return true, v != nil
}

// TB15: each of the three sign-in routes sends one PUT, after its intent
// row; a sign-in of a sub nobody holds and a changed account key send none;
// a returning person's sign-in goes on with the platform down, and logs
// "would refuse" once the last trusted published_through is over an hour
// old. With the contract off, a returning sign-in sends nothing.
func TestSignInSubscribes(t *testing.T) {
	h := newContractHarness(t, modeObserve)
	ctx := context.Background()
	// Each PUT's intent row, as the fake sees it when the PUT arrives.
	var mu sync.Mutex
	intents := map[string][]*time.Time{}
	h.fake.Before(contracttest.CallSubscribe, func(sub string) {
		var at *time.Time
		if err := h.pool.QueryRow(ctx, `SELECT subscribed_at FROM contract_accounts WHERE sub = $1`, sub).Scan(&at); err != nil {
			at = nil
		}
		mu.Lock()
		intents[sub] = append(intents[sub], at)
		mu.Unlock()
	})
	afterIntents := func(sub string, n int) {
		t.Helper()
		mu.Lock()
		defer mu.Unlock()
		got := intents[sub]
		if len(got) != n {
			t.Fatalf("%s: %d PUTs, want %d", sub, len(got), n)
		}
		for i, at := range got {
			if at == nil || (i > 0 && !at.After(*got[i-1])) {
				t.Fatalf("%s: PUT %d was not sent after an intent row of its own: %v", sub, i, got)
			}
		}
	}

	// A sub nobody holds: the ticket, and no PUT.
	p, _ := h.platformPerson(t, "ana@example.com")
	code, first := h.signIn(t, p, 1)
	if code != http.StatusOK || first.Kind != "new" {
		t.Fatalf("first sign-in: %d %+v", code, first)
	}
	if exists, _ := h.intent(t, p.sub); exists || h.following(p.sub) || h.fake.Count(contracttest.CallSubscribe) != 0 {
		t.Fatal("platformUnlinked subscribed the sub")
	}
	// The sign-up's PUT, then the session route's.
	if code, out, _, _ := h.createAccount(t, first.Ticket); code != http.StatusOK || out.Kind != "session" {
		t.Fatalf("account: %d %+v", code, out)
	}
	afterIntents(p.sub, 1)
	if code, out := h.signIn(t, p, 1); code != http.StatusOK || out.Kind != "session" {
		t.Fatalf("sign-in: %d %+v", code, out)
	}
	afterIntents(p.sub, 2)
	if !h.following(p.sub) {
		t.Fatal("the platform does not follow the person")
	}
	var fresh bool
	if err := h.pool.QueryRow(ctx, `SELECT version IS NOT NULL AND fresh_at > clock_timestamp() - interval '1 minute' FROM contract_accounts WHERE sub = $1`, p.sub).Scan(&fresh); err != nil || !fresh {
		t.Fatalf("the sign-in's document was not stored fresh: %v %v", fresh, err)
	}

	// A changed account key: refused before the identity lookup, no PUT.
	swapped := p
	swapped.root = append([]byte(nil), p.root...)
	swapped.root[0] ^= 0xff
	if code, out := h.signIn(t, swapped, 1); code != http.StatusConflict || out.Code != "account_key_changed" {
		t.Fatalf("a changed key: %d %+v", code, out)
	}
	afterIntents(p.sub, 2)

	// The link route: a legacy account linked through the provider.
	q, _ := h.platformPerson(t, "passkey@example.com")
	code, answer := h.signIn(t, q, 1)
	if code != http.StatusOK || answer.Kind != "link_required" {
		t.Fatalf("legacy sign-in: %d %+v", code, answer)
	}
	afterIntents(q.sub, 0)
	var linked platformAnswer
	if code := h.pagePost(t, "/v1/auth/platform/link", map[string]string{"ticket": answer.Ticket, "email": "passkey@example.com",
		"auth_key": h.account.AuthKey, "platform_wrap": randomWrap(t)}, &linked, "", nil); code != http.StatusOK || linked.Kind != "session" {
		t.Fatalf("link: %d %+v", code, linked)
	}
	afterIntents(q.sub, 1)
	if _, versioned := h.intent(t, q.sub); !versioned || !h.following(q.sub) {
		t.Fatal("the linked person's document was not stored")
	}

	// The platform down: the sign-in goes on. With no trusted
	// published_through, the sign-in would be refused at enforce.
	h.fake.SetDown(true)
	if code, out := h.signIn(t, p, 1); code != http.StatusOK || out.Kind != "session" {
		t.Fatalf("a sign-in with the platform down: %d %+v", code, out)
	}
	if n := len(h.logs.Lines("contract: sign-in would refuse", p.sub, "reason=stale")); n != 1 {
		t.Fatalf("%d would-refuse lines: %s", n, h.logs.String())
	}
	// Under an hour old, it vouches for a followed sub; over an hour, not.
	for _, tc := range []struct {
		age   string
		lines int
	}{{"30 minutes", 1}, {"61 minutes", 2}} {
		if _, err := h.pool.Exec(ctx, `UPDATE contract_state SET published_through = clock_timestamp() - $1::interval`, tc.age); err != nil {
			t.Fatal(err)
		}
		if code, _ := h.signIn(t, p, 1); code != http.StatusOK {
			t.Fatalf("%s: %d", tc.age, code)
		}
		if n := len(h.logs.Lines("contract: sign-in would refuse", p.sub, "reason=stale")); n != tc.lines {
			t.Fatalf("published_through %s old: %d would-refuse lines", tc.age, n)
		}
	}
	h.fake.SetDown(false)

	// A disabled document at sign-in: would refuse, and the sign-in goes on.
	if err := h.fake.Disable(p.sub, time.Now()); err != nil {
		t.Fatal(err)
	}
	if code, out := h.signIn(t, p, 1); code != http.StatusOK || out.Kind != "session" {
		t.Fatalf("a disabled document's sign-in: %d %+v", code, out)
	}
	if n := len(h.logs.Lines("contract: sign-in would refuse", p.sub, "reason=account_disabled")); n != 1 {
		t.Fatalf("%d would-refuse lines for a disabled document", n)
	}

	// Off after an observe: a returning sign-in sends nothing.
	setContractMode(t, h.pool, modeOffAfter)
	before := h.fake.Count(contracttest.CallSubscribe)
	if code, _ := h.signIn(t, p, 1); code != http.StatusOK {
		t.Fatalf("a sign-in with the contract off: %d", code)
	}
	if n := h.fake.Count(contracttest.CallSubscribe); n != before {
		t.Fatalf("the contract off, a sign-in sent %d PUTs", n-before)
	}
	if strings.Contains(h.logs.String(), "ana@example.com") || strings.Contains(h.logs.String(), "passkey@example.com") {
		t.Fatalf("a log line names an address: %s", h.logs.String())
	}
}

// Before the contract's first observe, nothing changes: no PUT at any
// route, no row, and a new account's home is Wappie's own.
func TestSignInBeforeTheContractChangesNothing(t *testing.T) {
	h := newContractHarness(t, modeNever)
	p, personal := h.platformPerson(t, "bea@example.com")
	code, out := h.signUp(t, p)
	if code != http.StatusOK || out.Kind != "session" {
		t.Fatalf("account: %d %+v", code, out)
	}
	if out.User.TenantID == personal.String() {
		t.Fatal("the platform's home before the contract")
	}
	if code, _ := h.signIn(t, p, 1); code != http.StatusOK {
		t.Fatalf("sign-in: %d", code)
	}
	if n := h.fake.Count(contracttest.CallSubscribe); n != 0 {
		t.Fatalf("%d PUTs before the contract", n)
	}
	if n := h.count(t, `SELECT count(*) FROM contract_accounts`); n != 0 {
		t.Fatalf("%d contract rows before the contract", n)
	}
	// Release A's answers, in release A's order: a malformed ticket is
	// refused before the request's name.
	var out2 platformAnswer
	if code := h.pagePost(t, "/v1/auth/platform/account", map[string]string{"ticket": "x", "public_key": randomKey(t), "platform_wrap": randomWrap(t),
		"display_name": strings.Repeat("n", 81)}, &out2, "", nil); code != http.StatusUnauthorized || out2.Code != "ticket_invalid" {
		t.Fatalf("a malformed ticket before the contract: %d %+v", code, out2)
	}
}

// TB16: a new account's personal workspace has the document's id, made by
// the insertion trigger; the document and every workspace it names are
// stored in the account's transaction, and a document that cannot be
// stored with it leaves nothing but the intent row.
func TestSignUpHome(t *testing.T) {
	h := newContractHarness(t, modeObserve)
	ctx := context.Background()
	owner, _ := h.platformPerson(t, "owner@example.com")
	team, err := h.fake.AddTeam("TBFG", owner.sub)
	if err != nil {
		t.Fatal(err)
	}
	p, personal := h.platformPerson(t, "carla@example.com")
	if err := h.fake.SetRole(team, p.sub, "member"); err != nil {
		t.Fatal(err)
	}

	// A fault after the insert: the stored generation is not the
	// platform's, so the document cannot be stored with the account.
	other := uuid.New()
	if _, err := h.pool.Exec(ctx, `UPDATE contract_state SET generation = $1`, other); err != nil {
		t.Fatal(err)
	}
	listen, err := h.pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Release()
	if _, err := listen.Exec(ctx, `LISTEN `+store.ContractModeChannel); err != nil {
		t.Fatal(err)
	}
	code, first := h.signIn(t, p, 1)
	if code != http.StatusOK {
		t.Fatalf("sign-in: %d", code)
	}
	if code, out, _, _ := h.createAccount(t, first.Ticket); code != http.StatusServiceUnavailable || out.Code != "platform_unavailable" {
		t.Fatalf("a document of another generation: %d %+v", code, out)
	}
	for q, want := range map[string]int{
		`SELECT count(*) FROM users WHERE id = $1`:                                  0,
		`SELECT count(*) FROM platform_identities WHERE sub = $1`:                   0,
		`SELECT count(*) FROM tenants WHERE personal_owner_id = $1`:                 0,
		`SELECT count(*) FROM contract_accounts WHERE sub = $1 AND version IS NULL`: 1,
		`SELECT count(*) FROM contract_accounts WHERE sub = $1`:                     1,
		`SELECT count(*) FROM security_events WHERE sub = $1`:                       0,
	} {
		if n := h.count(t, q, p.sub); n != want {
			t.Fatalf("after the fault, %s: %d, want %d", q, n, want)
		}
	}
	if n := h.count(t, `SELECT count(*) FROM contract_workspaces`); n != 0 {
		t.Fatalf("after the fault, %d workspaces recorded", n)
	}
	// The notice of the other generation outlives the rollback.
	wait, cancel := context.WithTimeout(ctx, 5*time.Second)
	n, err := listen.Conn().WaitForNotification(wait)
	cancel()
	if err != nil || n.Payload != "generation" {
		t.Fatalf("no notice of another generation: %v %v", n, err)
	}

	// The same ticket, once the generation is the platform's.
	if _, err := h.pool.Exec(ctx, `UPDATE contract_state SET generation = NULL`); err != nil {
		t.Fatal(err)
	}
	code, out, _, _ := h.createAccount(t, first.Ticket)
	if code != http.StatusOK || out.Kind != "session" || out.User.TenantID != personal.String() {
		t.Fatalf("account: %d %+v (home %s)", code, out, personal)
	}
	var kind string
	var personalOwner uuid.UUID
	if err := h.pool.QueryRow(ctx, `SELECT kind, personal_owner_id FROM tenants WHERE id = $1`, personal).Scan(&kind, &personalOwner); err != nil ||
		kind != "personal" || personalOwner.String() != p.sub {
		t.Fatalf("the home: %s %s %v", kind, personalOwner, err)
	}
	spaces, err := h.users.Workspaces(ctx, uuid.MustParse(p.sub))
	if err != nil || len(spaces) != 1 || spaces[0].ID != personal || spaces[0].Role != "owner" {
		t.Fatalf("workspaces: %+v %v", spaces, err)
	}
	if n := h.count(t, `SELECT count(*) FROM contract_accounts WHERE sub = $1 AND version IS NOT NULL AND doc IS NOT NULL
		AND fresh_at > clock_timestamp() - interval '1 minute'`, p.sub); n != 1 {
		t.Fatal("the document was not stored with the account")
	}
	for ws, want := range map[string]string{personal.String(): "personal", team: "team"} {
		if n := h.count(t, `SELECT count(*) FROM contract_workspaces WHERE workspace_id = $1 AND kind = $2`, ws, want); n != 1 {
			t.Fatalf("workspace %s (%s) not recorded", ws, want)
		}
	}
	// Observe applies nothing: the team is recorded, no membership made.
	if n := h.count(t, `SELECT count(*) FROM tenants WHERE id = $1`, team); n != 0 {
		t.Fatal("observe created the platform's team")
	}
	if !h.following(p.sub) {
		t.Fatal("the new account is not followed")
	}
}

// TB17: a tenant here with the document's personal workspace id refuses the
// account with workspace_conflict: nobody is created or added to it, the
// refusal is a security event written after the rollback, and the sub is
// unsubscribed.
func TestSignUpRefusesExistingHome(t *testing.T) {
	h := newContractHarness(t, modeObserve)
	ctx := context.Background()
	p, personal := h.platformPerson(t, "dora@example.com")
	if _, err := h.pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, 'taken')`, personal); err != nil {
		t.Fatal(err)
	}
	code, out := h.signUp(t, p)
	if code != http.StatusConflict || out.Code != "workspace_conflict" {
		t.Fatalf("a taken home: %d %+v", code, out)
	}
	for q, want := range map[string]int{
		`SELECT count(*) FROM users WHERE id = $1`:                                                                      0,
		`SELECT count(*) FROM platform_identities WHERE sub = $1`:                                                       0,
		`SELECT count(*) FROM security_events WHERE kind = 'platform_home_taken' AND sub = $1 AND user_id IS NULL`:      1,
		`SELECT count(*) FROM security_events WHERE kind = 'platform_home_taken' AND sub = $1 AND detail = '{}'::jsonb`: 1,
		`SELECT count(*) FROM contract_accounts WHERE sub = $1`:                                                         0,
	} {
		if n := h.count(t, q, p.sub); n != want {
			t.Fatalf("%s: %d, want %d", q, n, want)
		}
	}
	if n := h.count(t, `SELECT count(*) FROM tenants t WHERE t.id = $1 AND t.kind = 'team' AND t.personal_owner_id IS NULL`, personal); n != 1 {
		t.Fatal("the taken tenant changed")
	}
	if h.following(p.sub) || h.fake.Count(contracttest.CallUnsubscribe) != 1 {
		t.Fatalf("the refused sub is still followed (%d unsubscribes)", h.fake.Count(contracttest.CallUnsubscribe))
	}
}

// TB18: once the contract was observed, a new account with no signed
// document is refused, retryably, and never given a home of Wappie's
// choosing: with the platform down, a signed 503, a signed not_found (a
// platform fault, README 6.1), or no transport. The ticket stays valid and
// nothing is written but the intent row. Before the first observe it is
// release A's path; off after an observe, the platform's home still.
func TestSignUpWithoutPlatform(t *testing.T) {
	h := newContractHarness(t, modeObserve)
	client := h.members.Client
	refused := func(t *testing.T, p person, ticket string, intent bool) {
		t.Helper()
		if code, out, _, _ := h.createAccount(t, ticket); code != http.StatusServiceUnavailable || out.Code != "platform_unavailable" {
			t.Fatalf("account: %d %+v", code, out)
		}
		if n := h.count(t, `SELECT count(*) FROM users WHERE id = $1`, p.sub) + h.count(t, `SELECT count(*) FROM tenants WHERE personal_owner_id = $1`, p.sub); n != 0 {
			t.Fatal("a refused account was created")
		}
		if exists, versioned := h.intent(t, p.sub); exists != intent || versioned {
			t.Fatalf("intent row %v (versioned %v), want %v", exists, versioned, intent)
		}
		if n := h.count(t, `SELECT count(*) FROM platform_login_tickets WHERE sub = $1 AND used_at IS NULL`, p.sub); n != 1 {
			t.Fatal("the ticket was spent")
		}
	}
	created := func(t *testing.T, ticket string, home uuid.UUID) {
		t.Helper()
		code, out, _, _ := h.createAccount(t, ticket)
		if code != http.StatusOK || out.Kind != "session" || out.User.TenantID != home.String() {
			t.Fatalf("account: %d %+v, want home %s", code, out, home)
		}
	}
	for _, tc := range []struct {
		name   string
		spoil  func()
		mend   func()
		intent bool
	}{
		{"down", func() { h.fake.SetDown(true) }, func() { h.fake.SetDown(false) }, true},
		{"signed 503", func() { h.fake.RefuseAlways(contracttest.CallSubscribe, "unavailable") }, func() { h.fake.RefuseAlways(contracttest.CallSubscribe, "") }, true},
		{"signed not_found", func() { h.fake.RefuseAlways(contracttest.CallSubscribe, "not_found") }, func() { h.fake.RefuseAlways(contracttest.CallSubscribe, "") }, true},
		{"unverified", func() { h.fake.RefuseAlways(contracttest.CallSubscribe, "unauthenticated") }, func() { h.fake.RefuseAlways(contracttest.CallSubscribe, "") }, true},
		{"no transport", func() { h.members.Client = nil }, func() { h.members.Client = client }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, personal := h.platformPerson(t, strings.ReplaceAll(tc.name, " ", "-")+"@example.com")
			code, first := h.signIn(t, p, 1)
			if code != http.StatusOK || first.Kind != "new" {
				t.Fatalf("sign-in: %d", code)
			}
			tc.spoil()
			refused(t, p, first.Ticket, tc.intent)
			tc.mend()
			created(t, first.Ticket, personal)
		})
	}

	// Off after an observe: still the PUT and the platform's home, or the
	// refusal.
	setContractMode(t, h.pool, modeOffAfter)
	p, personal := h.platformPerson(t, "off@example.com")
	_, first := h.signIn(t, p, 1)
	h.fake.SetDown(true)
	refused(t, p, first.Ticket, true)
	h.fake.SetDown(false)
	created(t, first.Ticket, personal)
	if !h.following(p.sub) {
		t.Fatal("the contract off, a new account was not subscribed")
	}
}

// TB19, the routes' part: email_taken, workspace_conflict and a document
// not active each unsubscribe the sub once it is seen unlinked;
// already_linked (two tabs) and a spent ticket (a double submit) never do,
// and leave the winner subscribed with its document; a DELETE that fails
// leaves the intent row, which the sweep removes an hour later.
func TestUnsubscribeAfterRefusal(t *testing.T) {
	h := newContractHarness(t, modeObserve)
	ctx := context.Background()
	unsubscribed := func(t *testing.T, sub string) {
		t.Helper()
		if exists, _ := h.intent(t, sub); exists || h.following(sub) {
			t.Fatalf("the refused sub is still subscribed (row %v)", exists)
		}
	}

	// email_taken.
	a, _ := h.platformPerson(t, "ema@example.com")
	if code, _ := h.signUp(t, a); code != http.StatusOK {
		t.Fatalf("first account: %d", code)
	}
	b, _ := h.platformPerson(t, "ema@example.com")
	if code, out := h.signUp(t, b); code != http.StatusConflict || out.Code != "email_taken" {
		t.Fatalf("a taken address: %d %+v", code, out)
	}
	unsubscribed(t, b.sub)
	// A document not active.
	c, _ := h.platformPerson(t, "dis@example.com")
	if err := h.fake.Disable(c.sub, time.Now()); err != nil {
		t.Fatal(err)
	}
	if code, out := h.signUp(t, c); code != http.StatusForbidden || out.Code != "account_disabled" {
		t.Fatalf("a disabled document: %d %+v", code, out)
	}
	unsubscribed(t, c.sub)
	if n := h.count(t, `SELECT count(*) FROM users WHERE id = $1`, c.sub); n != 0 {
		t.Fatal("a disabled document's account was created")
	}
	unsubscribes := h.fake.Count(contracttest.CallUnsubscribe)

	// Two tabs: two tickets of one sub. The second is already_linked and
	// leaves the first's subscription.
	d, _ := h.platformPerson(t, "tabs@example.com")
	_, tab1 := h.signIn(t, d, 1)
	_, tab2 := h.signIn(t, d, 1)
	_, tab3 := h.signIn(t, d, 1)
	if code, _, _, _ := h.createAccount(t, tab1.Ticket); code != http.StatusOK {
		t.Fatalf("tab 1: %d", code)
	}
	if code, out, _, _ := h.createAccount(t, tab2.Ticket); code != http.StatusConflict || out.Code != "already_linked" {
		t.Fatalf("tab 2: %d %+v", code, out)
	}
	// A double submit: one ticket, two POSTs at once.
	e, _ := h.platformPerson(t, "twice@example.com")
	_, once := h.signIn(t, e, 1)
	codes := make(chan string, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			code, out, _, _ := h.createAccount(t, once.Ticket)
			codes <- http.StatusText(code) + " " + out.Code
		})
	}
	wg.Wait()
	close(codes)
	got := map[string]int{}
	for c := range codes {
		got[c]++
	}
	if got["OK "] != 1 || got["Unauthorized ticket_invalid"] != 1 {
		t.Fatalf("a double submit: %v", got)
	}
	for _, sub := range []string{d.sub, e.sub} {
		if _, versioned := h.intent(t, sub); !versioned || !h.following(sub) {
			t.Fatalf("%s: the winner lost its subscription", sub)
		}
	}
	// A third tab after the platform disabled the account: refused, and the
	// person Wappie now holds keeps the subscription (DB21: never a held
	// person's DELETE).
	if err := h.fake.Disable(d.sub, time.Now()); err != nil {
		t.Fatal(err)
	}
	if code, out, _, _ := h.createAccount(t, tab3.Ticket); code != http.StatusForbidden || out.Code != "account_disabled" {
		t.Fatalf("tab 3: %d %+v", code, out)
	}
	if !h.following(d.sub) {
		t.Fatal("a held person was unsubscribed")
	}
	if n := h.fake.Count(contracttest.CallUnsubscribe); n != unsubscribes {
		t.Fatalf("already_linked, ticket_invalid or a held person unsubscribed (%d)", n-unsubscribes)
	}

	// A DELETE that fails on each refusal leaves its intent row, which the
	// sweep removes once it is an hour old.
	h.fake.RefuseAlways(contracttest.CallUnsubscribe, "unavailable")
	f, _ := h.platformPerson(t, "ema@example.com")
	if code, _ := h.signUp(t, f); code != http.StatusConflict {
		t.Fatalf("a taken address: %d", code)
	}
	g, ghome := h.platformPerson(t, "home@example.com")
	if _, err := h.pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, 'taken')`, ghome); err != nil {
		t.Fatal(err)
	}
	if code, _ := h.signUp(t, g); code != http.StatusConflict {
		t.Fatalf("a taken home: %d", code)
	}
	k, _ := h.platformPerson(t, "dis2@example.com")
	if err := h.fake.Disable(k.sub, time.Now()); err != nil {
		t.Fatal(err)
	}
	if code, _ := h.signUp(t, k); code != http.StatusForbidden {
		t.Fatalf("a disabled document: %d", code)
	}
	orphans := []string{f.sub, g.sub, k.sub}
	for _, sub := range orphans {
		if exists, _ := h.intent(t, sub); !exists || !h.following(sub) {
			t.Fatalf("%s: a failed DELETE lost the intent row", sub)
		}
	}
	h.fake.RefuseAlways(contracttest.CallUnsubscribe, "")
	if n, err := h.members.Sweep(ctx); err != nil || n != 0 {
		t.Fatalf("a sweep within the hour: %d %v", n, err)
	}
	if _, err := h.pool.Exec(ctx, `UPDATE contract_accounts SET subscribed_at = subscribed_at - interval '61 minutes' WHERE sub = ANY ($1::uuid[])`, orphans); err != nil {
		t.Fatal(err)
	}
	if n, err := h.members.Sweep(ctx); err != nil || n != 3 {
		t.Fatalf("the sweep: %d %v", n, err)
	}
	for _, sub := range orphans {
		unsubscribed(t, sub)
	}
	// Everyone Wappie holds kept theirs.
	for _, sub := range []string{a.sub, d.sub, e.sub} {
		if !h.following(sub) {
			t.Fatalf("%s: a held person was unsubscribed", sub)
		}
	}
}

// The step-up's GET (the plan's 4.5): a person whose document is over an
// hour old is asked for it after a step-up at the provider, so the act the
// step-up opens finds them fresh; a fresh person is not asked again.
func TestStepUpRefreshesAStaleDocument(t *testing.T) {
	h := newContractHarness(t, modeObserve)
	ctx := context.Background()
	p, _ := h.platformPerson(t, "sol@example.com")
	code, created := h.signUp(t, p)
	if code != http.StatusOK {
		t.Fatalf("account: %d", code)
	}
	h.age(t, created.Token)
	if _, err := h.pool.Exec(ctx, `UPDATE contract_accounts SET fresh_at = clock_timestamp() - interval '2 hours' WHERE sub = $1`, p.sub); err != nil {
		t.Fatal(err)
	}
	stepUp := func() {
		t.Helper()
		if code, _ := h.start(t, created.Token); code != http.StatusOK {
			t.Fatalf("start: %d", code)
		}
		if code, done := h.finish(t, created.Token, h.id.issue(t, p.userinfo(t, 1))); code != http.StatusOK || !done.Fresh {
			t.Fatalf("finish: %d %+v", code, done)
		}
	}
	stepUp()
	if n := h.fake.Count(contracttest.CallAccount); n != 1 {
		t.Fatalf("%d GETs after a stale person's step-up", n)
	}
	if n := h.count(t, `SELECT count(*) FROM contract_accounts WHERE sub = $1 AND fresh_at > clock_timestamp() - interval '1 minute'`, p.sub); n != 1 {
		t.Fatal("the step-up's GET did not refresh the person")
	}
	stepUp()
	if n := h.fake.Count(contracttest.CallAccount); n != 1 {
		t.Fatalf("a fresh person was asked again (%d GETs)", n)
	}
	// Its failure changes nothing: the step-up goes on.
	if _, err := h.pool.Exec(ctx, `UPDATE contract_accounts SET fresh_at = clock_timestamp() - interval '2 hours' WHERE sub = $1`, p.sub); err != nil {
		t.Fatal(err)
	}
	h.fake.SetDown(true)
	stepUp()
}
