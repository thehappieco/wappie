package store_test

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"whatserver2/internal/migrate"
	"whatserver2/internal/stepup"
	"whatserver2/internal/store"
)

// Fewer steps between an assistant and the archive (docs/mcp-enclave.md
// §19.30): the step-up on the session, the language on the account, each
// workspace's assistant switches, reconnects that replace, the idle sweep and
// the renewal round. They run as the ordinary role, as every MCP store test
// does, so a cascade that forgot its workspace's transaction fails here.

// session signs a person in to the fixture's workspace.
func (f *contentFixture) session(ctx context.Context, t *testing.T, person uuid.UUID) (string, store.Session) {
	t.Helper()
	user, err := f.users.Get(ctx, f.tenant, person)
	if err != nil {
		t.Fatal(err)
	}
	token, s, err := f.users.StartSession(ctx, user, "test")
	if err != nil {
		t.Fatal(err)
	}
	return token, s
}

// age moves a session's last proof back by d, on the database's clock.
func (f *contentFixture) age(ctx context.Context, t *testing.T, session uuid.UUID, d time.Duration) {
	t.Helper()
	if _, err := f.pool.Exec(ctx, `UPDATE sessions SET authenticated_at = now() - make_interval(secs => $2) WHERE id=$1`, session, d.Seconds()); err != nil {
		t.Fatal(err)
	}
}

// A sign-in is a proof for ten minutes; a workspace switch inherits it rather
// than renewing it; a step-up renews it; an ended session has none.
func TestStepUpWindow(t *testing.T) {
	f := newContentFixture(t)
	ctx := context.Background()
	checker := stepup.Recent(f.users)
	_, s := f.session(ctx, t, f.owner)
	if fresh, err := checker.Fresh(ctx, s.ID); err != nil || !fresh {
		t.Fatalf("a new sign-in is not fresh: %v %v", fresh, err)
	}
	left, err := f.users.StepUpRemaining(ctx, s.ID, stepup.Window)
	if err != nil || left <= 9*time.Minute || left > stepup.Window {
		t.Fatalf("remaining = %v %v", left, err)
	}
	f.age(ctx, t, s.ID, 11*time.Minute)
	if fresh, err := checker.Fresh(ctx, s.ID); err != nil || fresh {
		t.Fatalf("an eleven-minute-old sign-in is fresh: %v %v", fresh, err)
	}
	// Selecting a workspace proves nothing: the derived session is as stale
	// as its source.
	user, err := f.users.Get(ctx, f.tenant, f.owner)
	if err != nil {
		t.Fatal(err)
	}
	_, switched, err := f.users.StartWorkspaceSession(ctx, user, "test", s)
	if err != nil {
		t.Fatal(err)
	}
	if fresh, err := checker.Fresh(ctx, switched.ID); err != nil || fresh {
		t.Fatalf("a workspace switch renewed the proof: %v %v", fresh, err)
	}
	if err := f.users.MarkStepUp(ctx, switched.ID); err != nil {
		t.Fatal(err)
	}
	if fresh, err := checker.Fresh(ctx, switched.ID); err != nil || !fresh {
		t.Fatalf("a step-up is not fresh: %v %v", fresh, err)
	}
	// The step-up is the switched session's: the source stays stale.
	if fresh, _ := checker.Fresh(ctx, s.ID); fresh {
		t.Fatal("a step-up on one session made another fresh")
	}
	if _, err := f.pool.Exec(ctx, `UPDATE sessions SET revoked_at = now() WHERE id=$1`, switched.ID); err != nil {
		t.Fatal(err)
	}
	if fresh, err := checker.Fresh(ctx, switched.ID); err != nil || fresh {
		t.Fatalf("a revoked session is fresh: %v %v", fresh, err)
	}
	if err := f.users.MarkStepUp(ctx, switched.ID); !errors.Is(err, store.ErrNoSession) {
		t.Fatalf("a revoked session stepped up: %v", err)
	}
	if _, err := f.users.StepUpRemaining(ctx, switched.ID, stepup.Window); !errors.Is(err, store.ErrNoSession) {
		t.Fatalf("remaining on a revoked session = %v", err)
	}
	if fresh, err := checker.Fresh(ctx, uuid.Nil); err != nil || fresh {
		t.Fatalf("no session is fresh: %v %v", fresh, err)
	}
}

// The console's language reaches the account, and only one of five.
func TestAccountLocale(t *testing.T) {
	f := newContentFixture(t)
	ctx := context.Background()
	if p, err := f.users.Profile(ctx, f.owner); err != nil || p.Locale != "" {
		t.Fatalf("before = %+v %v", p, err)
	}
	if p, err := f.users.SetLocale(ctx, f.owner, "pt"); err != nil || p.Locale != "pt" {
		t.Fatalf("set = %+v %v", p, err)
	}
	if p, err := f.users.Profile(ctx, f.owner); err != nil || p.Locale != "pt" {
		t.Fatalf("after = %+v %v", p, err)
	}
	for _, bad := range []string{"", "pt-BR", "it", "EN"} {
		if _, err := f.users.SetLocale(ctx, f.owner, bad); !errors.Is(err, store.ErrInvalidLocale) {
			t.Fatalf("%q = %v", bad, err)
		}
	}
}

// Only an owner sets what assistants may do in a workspace; the switches are
// read for every workspace at once.
func TestWorkspaceSwitchesOwnerOnly(t *testing.T) {
	f := newContentFixture(t)
	ctx := context.Background()
	if all, err := f.conns.WorkspaceSwitches(ctx); err != nil || len(all) != 0 {
		t.Fatalf("none set = %v %v", all, err)
	}
	if a, err := f.conns.WorkspaceSwitchesOf(ctx, f.tenant); err != nil || a.Set() {
		t.Fatalf("unset = %+v %v", a, err)
	}
	admin, _ := transferOwner(t, f.archive, "admin")
	member, _ := transferOwner(t, f.archive, "member")
	for name, who := range map[string]uuid.UUID{"admin": admin, "member": member, "stranger": uuid.New()} {
		if _, err := f.conns.SetWorkspaceSwitches(ctx, f.tenant, who, false, false, false, false); !errors.Is(err, store.ErrMembershipForbidden) {
			t.Fatalf("%s changed the switches: %v", name, err)
		}
	}
	a, err := f.conns.SetWorkspaceSwitches(ctx, f.tenant, f.owner, true, false, true, false)
	if err != nil || a.Text == nil || !*a.Text || *a.Media || !*a.Send || *a.AI || a.SwitchedBy == nil || *a.SwitchedBy != f.owner || a.SwitchedAt == nil {
		t.Fatalf("set = %+v %v", a, err)
	}
	all, err := f.conns.WorkspaceSwitches(ctx)
	if err != nil || len(all) != 1 || *all[f.tenant].Media {
		t.Fatalf("all = %v %v", all, err)
	}
	if _, err := f.conns.WorkspaceSwitchesOf(ctx, uuid.New()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an unknown workspace = %v", err)
	}
}

// replaceConsent is a content consent of the CIMD client the clients' tests
// use, consent version 4.
func (f *contentFixture) replaceConsent(ctx context.Context, t *testing.T, actor uuid.UUID, replaces bool) (store.MCPConnection, contentConsent) {
	t.Helper()
	c := f.prepareContent(ctx, t, actor)
	c.in = clientConsent(c.in, store.ClientCIMD, store.TrustTested)
	c.in.Replaces = replaces
	conn, err := f.conns.Create(ctx, f.tenant, actor, c.in)
	if err != nil {
		t.Fatal(err)
	}
	return conn, c
}

// A reconnect that asked to replace ends the person's earlier connections of
// the same client in the workspace, with their keys and service accounts, on
// activation; another client's, another person's, a metadata connection of
// another client and an AI authorization stay.
func TestReplacePrevious(t *testing.T) {
	f := newContentFixture(t)
	ctx := context.Background()
	old, oc := f.replaceConsent(ctx, t, f.owner, false)
	if err := f.conns.Activate(ctx, "enclave", old.ID); err != nil {
		t.Fatal(err)
	}
	older, olc := f.replaceConsent(ctx, t, f.owner, false)
	if err := f.conns.Activate(ctx, "enclave", older.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.conns.Reseal(ctx, "enclave", older.ID); err != nil {
		t.Fatal(err)
	}
	// Another person, the same client.
	admin, _ := transferOwner(t, f.archive, "admin")
	f.ownerReads(ctx, t, admin, f.device)
	theirs, tc := f.replaceConsent(ctx, t, admin, false)
	if err := f.conns.Activate(ctx, "enclave", theirs.ID); err != nil {
		t.Fatal(err)
	}
	// The same person, another client (a registered one).
	other := f.prepareContent(ctx, t, f.owner)
	other.in = clientConsent(other.in, store.ClientDCR, store.TrustTested)
	otherConn, err := f.conns.Create(ctx, f.tenant, f.owner, other.in)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.conns.Activate(ctx, "enclave", otherConn.ID); err != nil {
		t.Fatal(err)
	}
	// Without replaces, nothing ends.
	if ended, err := f.conns.ReplacePrevious(ctx, "enclave", old.ID); err != nil || len(ended) != 0 {
		t.Fatalf("a consent that did not ask = %v %v", ended, err)
	}

	fresh, fc := f.replaceConsent(ctx, t, f.owner, true)
	// Pending, it replaces nothing yet.
	if ended, err := f.conns.ReplacePrevious(ctx, "enclave", fresh.ID); err != nil || len(ended) != 0 {
		t.Fatalf("a pending reconnect = %v %v", ended, err)
	}
	if err := f.conns.Activate(ctx, "enclave", fresh.ID); err != nil {
		t.Fatal(err)
	}
	// Another reader's word ends nothing.
	if ended, err := f.conns.ReplacePrevious(ctx, "hosted", fresh.ID); err != nil || len(ended) != 0 {
		t.Fatalf("another reader = %v %v", ended, err)
	}
	ended, err := f.conns.ReplacePrevious(ctx, "enclave", fresh.ID)
	if err != nil || len(ended) != 2 || ended[0].ID != old.ID || ended[1].ID != older.ID || ended[0].Reader != "enclave" {
		t.Fatalf("ended = %+v %v", ended, err)
	}
	for _, c := range []struct {
		id      string
		consent contentConsent
		status  string
	}{{old.ID, oc, "revoked"}, {older.ID, olc, "revoked"}, {theirs.ID, tc, "active"}, {otherConn.ID, other, "active"}, {fresh.ID, fc, "active"}} {
		row := f.row(ctx, t, c.id)
		if row.Status != c.status {
			t.Errorf("%s: status %s, want %s", c.id, row.Status, c.status)
		}
		tr := f.trace(ctx, t, c.consent.service)
		if c.status == "revoked" {
			if row.RevokeReason != store.ReasonReplaced || tr != (serviceTrace{}) {
				t.Errorf("%s: reason %q, the account kept %+v", c.id, row.RevokeReason, tr)
			}
			if _, err := f.keys.Verify(ctx, c.consent.key); !errors.Is(err, store.ErrInvalidKey) {
				t.Errorf("%s: the key survived: %v", c.id, err)
			}
		} else if tr.grants != 1 || tr.memberships != 1 || tr.liveKeys != 1 {
			t.Errorf("%s: lost its account: %+v", c.id, tr)
		}
	}
	// Twice is once.
	if again, err := f.conns.ReplacePrevious(ctx, "enclave", fresh.ID); err != nil || len(again) != 0 {
		t.Fatalf("again = %v %v", again, err)
	}
	// A token never replaces.
	_, prefix := f.provisionalKey(ctx, t, "token")
	token := clientConsent(consent(prefix), store.ClientToken, store.TrustUnknown)
	token.Replaces = true
	if _, err := f.conns.Create(ctx, f.tenant, f.owner, token); !errors.Is(err, store.ErrMCPClient) {
		t.Fatalf("a token that replaces = %v", err)
	}
}

// At the cap of ten, a reconnect that replaces is not refused for the
// connection it takes the place of; one that does not, is.
func TestReplaceAtTheCap(t *testing.T) {
	f := newContentFixture(t)
	ctx := context.Background()
	old, _ := f.replaceConsent(ctx, t, f.owner, false)
	if err := f.conns.Activate(ctx, "enclave", old.ID); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 9; i++ {
		_, prefix := f.provisionalKey(ctx, t, "meta")
		conn, err := f.conns.Create(ctx, f.tenant, f.owner, consent(prefix))
		if err != nil {
			t.Fatal(err)
		}
		if err := f.conns.Activate(ctx, "hosted", conn.ID); err != nil {
			t.Fatal(err)
		}
	}
	c := f.prepareContent(ctx, t, f.owner)
	c.in = clientConsent(c.in, store.ClientCIMD, store.TrustTested)
	if _, err := f.conns.Create(ctx, f.tenant, f.owner, c.in); !errors.Is(err, store.ErrTooManyMCPConnections) {
		t.Fatalf("an eleventh = %v", err)
	}
	c.in.Replaces = true
	c.in.RequestID = uuid.NewString()
	if _, err := f.conns.Create(ctx, f.tenant, f.owner, c.in); err != nil {
		t.Fatalf("a reconnect at the cap = %v", err)
	}
}

// setUse moves a connection's last use back: its key's last read, its
// activation and its last status check.
func (f *contentFixture) setUse(ctx context.Context, t *testing.T, id string, keyUsed, activated, seen time.Duration) {
	t.Helper()
	if _, err := f.pool.Exec(ctx, `UPDATE mcp_connections SET activated_at = now() - make_interval(secs => $2),
		created_at = now() - make_interval(secs => $2), last_seen_at = now() - make_interval(secs => $3) WHERE id=$1`,
		id, activated.Seconds(), seen.Seconds()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE api_keys SET last_used_at = now() - make_interval(secs => $2)
		WHERE id = (SELECT api_key_id FROM mcp_connections WHERE id=$1)`, id, keyUsed.Seconds()); err != nil {
		t.Fatal(err)
	}
}

// The idle sweep ends what its tier's idle time and a day have passed without
// a read, and nothing else: a content connection's minute-by-minute status
// checks are not use, a metadata connection's are, and a token has no idle
// time.
func TestRevokeIdleConnections(t *testing.T) {
	f := newContentFixture(t)
	ctx := context.Background()
	const day = 24 * time.Hour
	idleText, itc := f.replaceConsent(ctx, t, f.owner, false)
	usedText, utc := f.replaceConsent(ctx, t, f.owner, false)
	graceText, _ := f.replaceConsent(ctx, t, f.owner, false)
	for _, id := range []string{idleText.ID, usedText.ID, graceText.ID} {
		if err := f.conns.Activate(ctx, "enclave", id); err != nil {
			t.Fatal(err)
		}
	}
	// Tested web text: seven days, and a day's grace. Its status was asked a
	// minute ago, by the reader's sweep. Half the grace past its idle time,
	// a connection stays.
	f.setUse(ctx, t, idleText.ID, 9*day, 20*day, time.Minute)
	f.setUse(ctx, t, usedText.ID, 2*day, 20*day, time.Minute)
	f.setUse(ctx, t, graceText.ID, 7*day+12*time.Hour, 20*day, time.Minute)
	meta := func(name string, keyUsed, seen time.Duration) string {
		_, prefix := f.provisionalKey(ctx, t, name)
		conn, err := f.conns.Create(ctx, f.tenant, f.owner, consent(prefix))
		if err != nil {
			t.Fatal(err)
		}
		if err := f.conns.Activate(ctx, "hosted", conn.ID); err != nil {
			t.Fatal(err)
		}
		f.setUse(ctx, t, conn.ID, keyUsed, 60*day, seen)
		return conn.ID
	}
	// Legacy metadata: thirty days.
	idleMeta := meta("idle", 40*day, 40*day)
	seenMeta := meta("seen", 40*day, 3*day)
	usedMeta := meta("used", 10*day, 40*day)
	_, prefix := f.provisionalKey(ctx, t, "token")
	token, err := f.conns.Create(ctx, f.tenant, f.owner, clientConsent(consent(prefix), store.ClientToken, store.TrustUnknown))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.conns.Activate(ctx, "hosted", token.ID); err != nil {
		t.Fatal(err)
	}
	f.setUse(ctx, t, token.ID, 80*day, 80*day, 80*day)

	ended, err := store.RevokeIdleMCPConnections(ctx, f.pool)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, e := range ended {
		got[e.ID] = true
	}
	if len(ended) != 2 || !got[idleText.ID] || !got[idleMeta] {
		t.Fatalf("ended = %+v", ended)
	}
	for id, want := range map[string]string{idleText.ID: "revoked", idleMeta: "revoked", usedText.ID: "active", graceText.ID: "active",
		seenMeta: "active", usedMeta: "active", token.ID: "active"} {
		row := f.row(ctx, t, id)
		if row.Status != want || (want == "revoked") != (row.RevokeReason == store.ReasonIdle) {
			t.Errorf("%s = %s %q, want %s", id, row.Status, row.RevokeReason, want)
		}
	}
	// Under row-level security the cascade reached the account.
	if tr := f.trace(ctx, t, itc.service); tr != (serviceTrace{}) {
		t.Fatalf("the idle connection's account kept %+v", tr)
	}
	if tr := f.trace(ctx, t, utc.service); tr.grants != 1 || tr.memberships != 1 {
		t.Fatalf("the used connection's account lost %+v", tr)
	}
	// The reader is told by the revocation watch.
	unnotified, err := f.conns.Unnotified(ctx, "enclave", 100)
	if err != nil || len(unnotified) != 1 || unnotified[0] != idleText.ID {
		t.Fatalf("unnotified = %v %v", unnotified, err)
	}
	if again, err := store.RevokeIdleMCPConnections(ctx, f.pool); err != nil || len(again) != 0 {
		t.Fatalf("again = %v %v", again, err)
	}
}

// The sweep picks its candidates outside any lock and ends each only if it
// is still idle under its row's lock: a connection renewed, or read with,
// after the pick stays; one still idle ends once.
func TestIdleSweepRechecksUnderTheLock(t *testing.T) {
	f := newContentFixture(t)
	ctx := context.Background()
	const day = 24 * time.Hour
	renewed, _ := f.replaceConsent(ctx, t, f.owner, false)
	read, _ := f.replaceConsent(ctx, t, f.owner, false)
	idle, _ := f.replaceConsent(ctx, t, f.owner, false)
	for _, id := range []string{renewed.ID, read.ID, idle.ID} {
		if err := f.conns.Activate(ctx, "enclave", id); err != nil {
			t.Fatal(err)
		}
		f.setUse(ctx, t, id, 9*day, 20*day, time.Minute)
	}
	// What happened between the sweep's pick and its end of each row.
	if _, err := f.pool.Exec(ctx, `UPDATE mcp_connections SET renewed_at = now() WHERE id=$1`, renewed.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE api_keys SET last_used_at = now() WHERE id = (SELECT api_key_id FROM mcp_connections WHERE id=$1)`, read.ID); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]bool{renewed.ID: false, read.ID: false, idle.ID: true} {
		ended, err := f.conns.EndIfIdle(ctx, f.tenant, id)
		if err != nil || ended != want {
			t.Fatalf("%s ended = %v %v, want %v", id, ended, err, want)
		}
	}
	for id, want := range map[string]string{renewed.ID: "active", read.ID: "active", idle.ID: "revoked"} {
		if row := f.row(ctx, t, id); row.Status != want {
			t.Errorf("%s = %s, want %s", id, row.Status, want)
		}
	}
	if ended, err := f.conns.EndIfIdle(ctx, f.tenant, idle.ID); err != nil || ended {
		t.Fatalf("an ended connection ended again: %v %v", ended, err)
	}
	if ended, err := f.conns.EndIfIdle(ctx, f.tenant, uuid.NewString()); err != nil || ended {
		t.Fatalf("an unknown connection = %v %v", ended, err)
	}
}

func TestIdleTimeByTier(t *testing.T) {
	const day = 24 * time.Hour
	for _, c := range []struct {
		kind, tier string
		want       time.Duration
	}{
		{store.KindMetadata, store.TierWebTested, 30 * day}, {store.KindContent, store.TierWebTested, 7 * day},
		{store.KindMetadata, store.TierLocalTested, 7 * day}, {store.KindContent, store.TierLocalTested, 7 * day},
		{store.KindMetadata, store.TierUnknown, 7 * day}, {store.KindContent, store.TierUnknown, 3 * day},
		{store.KindMetadata, store.TierToken, 0}, {store.KindContent, store.TierToken, 0}, {store.KindAI, store.TierWebTested, 0},
	} {
		if got := store.IdleTime(c.kind, c.tier); got != c.want {
			t.Errorf("%s %s = %v, want %v", c.kind, c.tier, got, c.want)
		}
	}
}

// A renewal round: once the reseals settle, one notice per person and
// workspace, claimed once, in their language, to a verified address only;
// then quiet for twelve hours.
func TestRenewalNotices(t *testing.T) {
	f := newContentFixture(t)
	ctx := context.Background()
	f.verify(ctx, t, f.owner)
	if _, err := f.users.SetLocale(ctx, f.owner, "de"); err != nil {
		t.Fatal(err)
	}
	a, _ := f.consentContent(ctx, t, f.owner)
	b, _ := f.consentContent(ctx, t, f.owner)
	// A row an older reader wrote carries the name the client registered
	// itself as: the notice names its host instead.
	if _, err := f.pool.Exec(ctx, `UPDATE mcp_connections SET client_name = 'Wappie support: call +1 555 0100' WHERE id=$1`, b.ID); err != nil {
		t.Fatal(err)
	}
	// A 0.6.0 row's verified name: a tested client's, and an untested one's
	// host, which Renew all leaves to its own Renew.
	v2 := func(kind, trust string) string {
		c := f.prepareContent(ctx, t, f.owner)
		conn, err := f.conns.Create(ctx, f.tenant, f.owner, clientConsent(c.in, kind, trust))
		if err != nil {
			t.Fatal(err)
		}
		if err := f.conns.Activate(ctx, "enclave", conn.ID); err != nil {
			t.Fatal(err)
		}
		return conn.ID
	}
	tested, untested := v2(store.ClientDCR, store.TrustTested), v2(store.ClientCIMD, store.TrustUnknown)
	for _, id := range []string{a.ID, b.ID, tested, untested} {
		if err := f.conns.Reseal(ctx, "enclave", id); err != nil {
			t.Fatal(err)
		}
	}
	// An unverified admin's resealed connection gets no e-mail.
	admin, _ := transferOwner(t, f.archive, "admin")
	f.ownerReads(ctx, t, admin, f.device)
	theirs, _ := f.consentContent(ctx, t, admin)
	if err := f.conns.Reseal(ctx, "enclave", theirs.ID); err != nil {
		t.Fatal(err)
	}
	// Not settled yet.
	if due, err := f.conns.DueRenewalNotices(ctx); err != nil || len(due) != 0 {
		t.Fatalf("before it settled = %+v %v", due, err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE mcp_connections SET resealed_at = now() - interval '5 minutes' WHERE status='reseal'`); err != nil {
		t.Fatal(err)
	}
	due, err := f.conns.DueRenewalNotices(ctx)
	if err != nil || len(due) != 1 {
		t.Fatalf("due = %+v %v", due, err)
	}
	n := due[0]
	names := slices.Sorted(slices.Values(n.Assistants))
	if n.UserID != f.owner || n.TenantID != f.tenant || n.Locale != "de" || n.Workspace == "" || len(n.ConnectionIDs) != 4 ||
		!slices.Equal(names, []string{"ChatGPT", "agent.example.com", "claude.ai", "claude.ai"}) || n.OneByOne != 1 || n.Email == "" {
		t.Fatalf("notice = %+v", n)
	}
	if claimed, err := f.conns.ClaimRenewalNotice(ctx, n.TenantID, n.UserID, n.ConnectionIDs); err != nil || !claimed {
		t.Fatalf("claim = %v %v", claimed, err)
	}
	if claimed, err := f.conns.ClaimRenewalNotice(ctx, n.TenantID, n.UserID, n.ConnectionIDs); err != nil || claimed {
		t.Fatalf("a second claim = %v %v", claimed, err)
	}
	// Resealed again within twelve hours: quiet.
	if _, err := f.pool.Exec(ctx, `UPDATE mcp_connections SET reseal_mailed_at = now() - interval '10 minutes',
		resealed_at = now() - interval '3 minutes' WHERE id=$1`, a.ID); err != nil {
		t.Fatal(err)
	}
	if due, err := f.conns.DueRenewalNotices(ctx); err != nil || len(due) != 0 {
		t.Fatalf("within the quiet hours = %+v %v", due, err)
	}
	// Past them, the connection still waiting is due again; a renewed one
	// is not.
	if _, err := f.pool.Exec(ctx, `UPDATE mcp_connections SET reseal_mailed_at = now() - interval '13 hours' WHERE id = ANY($1::uuid[])`,
		[]string{a.ID, b.ID, tested, untested}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE mcp_connections SET status='active' WHERE id = ANY($1::uuid[])`, []string{b.ID, tested, untested}); err != nil {
		t.Fatal(err)
	}
	if due, err := f.conns.DueRenewalNotices(ctx); err != nil || len(due) != 1 || len(due[0].ConnectionIDs) != 1 || due[0].ConnectionIDs[0] != a.ID {
		t.Fatalf("after the quiet hours = %+v %v", due, err)
	}
}

// A new-assistant notice says each recipient's language.
func TestNoticeRecipientsLocales(t *testing.T) {
	f := newContentFixture(t)
	ctx := context.Background()
	email := f.verify(ctx, t, f.owner)
	if _, err := f.users.SetLocale(ctx, f.owner, "fr"); err != nil {
		t.Fatal(err)
	}
	conn, _ := f.consentContent(ctx, t, f.owner)
	n, err := f.conns.RaiseNotice(ctx, "enclave", conn.ID, store.NoticeActivated)
	if err != nil || len(n.Recipients) != 1 || n.Recipients[0] != email || n.Locales[email] != "fr" {
		t.Fatalf("notice = %+v %v", n, err)
	}
}

// 0047's down-step, exactly as its header documents it, run as the table
// owner: the reasons it added are dropped from the rows that had them, its
// columns and its step-up flows go, version 47 is forgotten; and up again.
func TestMigration0047DownStep(t *testing.T) {
	f := newContentFixture(t)
	ctx := context.Background()
	old, _ := f.replaceConsent(ctx, t, f.owner, false)
	if err := f.conns.Activate(ctx, "enclave", old.ID); err != nil {
		t.Fatal(err)
	}
	fresh, _ := f.replaceConsent(ctx, t, f.owner, true)
	if err := f.conns.Activate(ctx, "enclave", fresh.ID); err != nil {
		t.Fatal(err)
	}
	if ended, err := f.conns.ReplacePrevious(ctx, "enclave", fresh.ID); err != nil || len(ended) != 1 {
		t.Fatalf("replace = %v %v", ended, err)
	}
	if _, err := f.conns.SetWorkspaceSwitches(ctx, f.tenant, f.owner, true, true, true, true); err != nil {
		t.Fatal(err)
	}
	if _, err := f.users.SetLocale(ctx, f.owner, "es"); err != nil {
		t.Fatal(err)
	}
	_, s := f.session(ctx, t, f.owner)
	if err := f.users.CreatePasskeyChallenge(ctx, store.PasskeyChallenge{ID: uuid.New(), Kind: "step_up", UserID: f.owner, SessionID: s.ID,
		Origin: "https://app.example.test", Data: []byte(`{}`), ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("a step-up flow: %v", err)
	}

	// A sign-in eleven minutes old, and a workspace switch made from it a
	// moment ago: re-applying 0047 gives both their family's first sign-in,
	// so neither counts as a step-up after a deploy.
	_, early := f.session(ctx, t, f.owner)
	if _, err := f.pool.Exec(ctx, `UPDATE sessions SET created_at = now() - interval '11 minutes' WHERE id=$1`, early.ID); err != nil {
		t.Fatal(err)
	}
	owner, err := f.users.Get(ctx, f.tenant, f.owner)
	if err != nil {
		t.Fatal(err)
	}
	_, switched, err := f.users.StartWorkspaceSession(ctx, owner, "test", early)
	if err != nil {
		t.Fatal(err)
	}

	// A later migration in the ledger comes down first: until it has, this
	// down-step refuses and changes nothing.
	if _, err := f.pool.Exec(ctx, `INSERT INTO schema_migrations (version, name, checksum, duration_ms) VALUES (48, 'later', 'x', 0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, downStep(t, 47)); err == nil || !strings.Contains(err.Error(), "after 0047 is applied") {
		t.Fatalf("the down-step ran below a later migration: %v", err)
	}
	var version, left int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations WHERE version = 47`).Scan(&left); err != nil || left != 1 {
		t.Fatalf("a refused down-step changed the ledger: %d %v", left, err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema()
		AND table_name='sessions' AND column_name='authenticated_at'`).Scan(&left); err != nil || left != 1 {
		t.Fatalf("a refused down-step dropped sessions.authenticated_at: %d %v", left, err)
	}
	if _, err := f.pool.Exec(ctx, `DELETE FROM schema_migrations WHERE version = 48`); err != nil {
		t.Fatal(err)
	}

	if _, err := f.pool.Exec(ctx, downStep(t, 47)); err != nil {
		t.Fatalf("down-step: %v", err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&version); err != nil || version != 46 {
		t.Fatalf("ledger at %d %v", version, err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema()
		AND ((table_name='sessions' AND column_name='authenticated_at') OR (table_name='users' AND column_name='locale')
		  OR (table_name='tenants' AND column_name LIKE 'mcp\_%')
		  OR (table_name='mcp_connections' AND column_name IN ('replaces', 'reseal_mailed_at')))`).Scan(&left); err != nil || left != 0 {
		t.Fatalf("%d columns left %v", left, err)
	}
	var status string
	var reason *string
	if err := f.pool.QueryRow(ctx, `SELECT status, revoke_reason FROM mcp_connections WHERE id=$1`, old.ID).Scan(&status, &reason); err != nil ||
		status != "revoked" || reason != nil {
		t.Fatalf("the replaced row = %s %v %v", status, reason, err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM passkey_challenges`).Scan(&left); err != nil || left != 0 {
		t.Fatalf("%d flows left %v", left, err)
	}
	// An older binary's challenge kinds are what the table takes again.
	if _, err := f.pool.Exec(ctx, `INSERT INTO passkey_challenges (id, kind, user_id, session_id, origin, data, expires_at)
		VALUES ($1, 'step_up', $2, $3, 'o', '{}', now() + interval '1 minute')`, uuid.New(), f.owner, s.ID); err == nil {
		t.Fatal("the restored check took a step-up flow")
	}

	// Up again: every session is as old as its family's first sign-in, and
	// everything above works.
	if err := migrate.Run(ctx, f.pool, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatalf("re-applying 0047: %v", err)
	}
	if fresh, err := stepup.Recent(f.users).Fresh(ctx, s.ID); err != nil || !fresh {
		t.Fatalf("after re-applying, the new session = %v %v", fresh, err)
	}
	for name, id := range map[string]uuid.UUID{"the eleven-minute-old sign-in": early.ID, "a switch from it": switched.ID} {
		if fresh, err := stepup.Recent(f.users).Fresh(ctx, id); err != nil || fresh {
			t.Fatalf("after re-applying, %s is fresh: %v %v", name, fresh, err)
		}
	}
	if _, err := f.conns.SetWorkspaceSwitches(ctx, f.tenant, f.owner, false, false, false, false); err != nil {
		t.Fatal(err)
	}
	var locale *string
	f.inTenant(ctx, t, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT locale FROM users WHERE id=$1`, f.owner).Scan(&locale)
	})
	if locale != nil {
		t.Fatalf("locale = %v", *locale)
	}
	again, _ := f.replaceConsent(ctx, t, f.owner, true)
	if err := f.conns.Activate(ctx, "enclave", again.ID); err != nil {
		t.Fatal(err)
	}
	if ended, err := f.conns.ReplacePrevious(ctx, "enclave", again.ID); err != nil || len(ended) != 1 || ended[0].ID != fresh.ID {
		t.Fatalf("replace after re-applying = %v %v", ended, err)
	}
}
