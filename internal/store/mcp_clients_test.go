package store_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"whatserver2/internal/migrate"
	"whatserver2/internal/pg"
	"whatserver2/internal/store"
)

// Any MCP client (docs/mcp-enclave.md §19.20 to §19.22): who a connection is
// for, the caps, the banner's seen marks, the notices and their e-mail's
// caps, and the revoke-only link.

// clientConsent fills a consent's client fields for kind ("cimd", "dcr",
// "token") and trust; an unknown client and a token read 30 days.
func clientConsent(in store.CreateMCPConnection, kind, trust string) store.CreateMCPConnection {
	in.ClientKind, in.Trust = kind, trust
	switch kind {
	case store.ClientCIMD:
		in.ClientID, in.ClientHost = "https://agent.example.com/oauth/client.json", "agent.example.com"
		in.ClientName, in.RedirectHost = "agent.example.com", "agent.example.com"
	case store.ClientDCR:
		in.ClientHost, in.ClientName, in.RedirectHost = "chatgpt.com", "ChatGPT", "chatgpt.com"
	case store.ClientToken:
		in.ClientName, in.RedirectHost = "Cursor on the laptop", store.TokenRedirectHost
	}
	if trust == store.TrustUnknown {
		in.HistoryDays = 30
	}
	if in.Kind == store.KindContent {
		in.ConsentVersion = store.ClientConsentVersion
	}
	return in
}

// verify records that a person's address was confirmed, as public sign-up
// does.
func (f *mcpFixture) verify(ctx context.Context, t *testing.T, user uuid.UUID) string {
	t.Helper()
	var email string
	if err := f.pool.QueryRow(ctx, `SELECT email FROM user_logins WHERE user_id=$1`, user).Scan(&email); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(uuid.NewString()))
	if _, err := f.pool.Exec(ctx, `INSERT INTO email_signup_verifications (token_hash, email, expires_at, completed_at)
		VALUES ($1, $2, now() - interval '400 days', now() - interval '400 days')`, sum[:], email); err != nil {
		t.Fatal(err)
	}
	return email
}

func TestCreateClientConnections(t *testing.T) {
	f := newContentFixture(t)
	ctx := context.Background()

	_, prefix := f.provisionalKey(ctx, t, "cimd")
	unknown, err := f.conns.Create(ctx, f.tenant, f.owner, clientConsent(consent(prefix), store.ClientCIMD, store.TrustUnknown))
	if err != nil {
		t.Fatal(err)
	}
	c := f.row(ctx, t, unknown.ID)
	if c.ClientKind != store.ClientCIMD || c.ClientID != "https://agent.example.com/oauth/client.json" || c.ClientHost != "agent.example.com" ||
		c.Trust != store.TrustUnknown || c.HistoryDays != 30 || c.ClientLocal || c.ClaimedName != "" || c.ClientName != "agent.example.com" {
		t.Fatalf("listed = %+v", c)
	}

	local := f.prepareContent(ctx, t, f.owner)
	local.in = clientConsent(local.in, store.ClientCIMD, store.TrustTested)
	local.in.ClientID, local.in.ClientHost, local.in.ClientLocal = "https://claude.ai/oauth/claude-code-client-metadata", "claude.ai", true
	local.in.ClientName, local.in.RedirectHost, local.in.ClaimedName = "Claude Code", "claude.ai", "Claude Code"
	if _, err := f.conns.Create(ctx, f.tenant, f.owner, local.in); err != nil {
		t.Fatalf("a tested local client: %v", err)
	}
	web := f.prepareContent(ctx, t, f.owner)
	web.in = clientConsent(web.in, store.ClientDCR, store.TrustTested)
	web.in.SendMode = store.SendModeDraft
	if _, err := f.conns.Create(ctx, f.tenant, f.owner, web.in); err != nil {
		t.Fatalf("a tested web client that drafts: %v", err)
	}
	text := f.prepareContent(ctx, t, f.owner)
	text.in = clientConsent(text.in, store.ClientToken, store.TrustUnknown)
	text.in.ExpiresAt = time.Now().Add(24 * time.Hour)
	token, err := f.conns.Create(ctx, f.tenant, f.owner, text.in)
	if err != nil {
		t.Fatalf("a text token: %v", err)
	}
	if c := f.row(ctx, t, token.ID); c.ClientKind != store.ClientToken || c.Trust != store.TrustUnknown || c.RedirectHost != "token" ||
		c.ClientHost != "" || c.ClientName != "Cursor on the laptop" || c.Kind != store.KindContent || c.ConsentVersion != 4 {
		t.Fatalf("token = %+v", c)
	}

	for name, mutate := range map[string]func(*store.CreateMCPConnection){
		"cimd without a client id":     func(in *store.CreateMCPConnection) { in.ClientID = "" },
		"cimd over http":               func(in *store.CreateMCPConnection) { in.ClientID = "http://agent.example.com/c.json" },
		"cimd with an upper-case host": func(in *store.CreateMCPConnection) { in.ClientHost = "Agent.example.com" },
		"unknown with no window":       func(in *store.CreateMCPConnection) { in.HistoryDays = 0 },
		"unknown reading 14 days":      func(in *store.CreateMCPConnection) { in.HistoryDays = 14 },
		"tested with a window": func(in *store.CreateMCPConnection) {
			in.Trust = store.TrustTested
		},
		"no trust":             func(in *store.CreateMCPConnection) { in.Trust, in.HistoryDays = "", 0 },
		"a name of 101":        func(in *store.CreateMCPConnection) { in.ClaimedName = strings.Repeat("é", 101) },
		"redirecting nowhere":  func(in *store.CreateMCPConnection) { in.RedirectHost = store.TokenRedirectHost },
		"not a kind":           func(in *store.CreateMCPConnection) { in.ClientKind = "oauth" },
		"dcr with a client id": func(in *store.CreateMCPConnection) { in.ClientKind = store.ClientDCR },
		"dcr over loopback": func(in *store.CreateMCPConnection) {
			in.ClientKind, in.ClientID, in.ClientLocal = store.ClientDCR, "", true
		},
		"token with a host":         func(in *store.CreateMCPConnection) { in.ClientKind, in.ClientID = store.ClientToken, "" },
		"legacy that is unknown":    func(in *store.CreateMCPConnection) { in.ClientKind, in.ClientID, in.ClientHost = "", "", "" },
		"legacy with a claimed one": func(in *store.CreateMCPConnection) { *in = consent(in.KeyPrefix); in.ClaimedName = "Claude" },
	} {
		t.Run(name, func(t *testing.T) {
			_, prefix := f.provisionalKey(ctx, t, name)
			in := clientConsent(consent(prefix), store.ClientCIMD, store.TrustUnknown)
			mutate(&in)
			if _, err := f.conns.Create(ctx, f.tenant, f.owner, in); !errors.Is(err, store.ErrMCPClient) {
				t.Fatalf("err = %v", err)
			}
		})
	}
	for name, mutate := range map[string]func(*contentConsent){
		"unknown text that drafts": func(c *contentConsent) {
			c.in = clientConsent(c.in, store.ClientCIMD, store.TrustUnknown)
			c.in.SendMode = store.SendModeDraft
		},
		"a local app that notes to itself": func(c *contentConsent) {
			c.in = clientConsent(c.in, store.ClientCIMD, store.TrustTested)
			c.in.ClientLocal, c.in.SendMode, c.in.SendSelf = true, store.SendModeDraft, true
		},
		"a token that drafts": func(c *contentConsent) {
			c.in = clientConsent(c.in, store.ClientToken, store.TrustUnknown)
			c.in.SendMode = store.SendModeDraft
		},
		"a client's text on version 3": func(c *contentConsent) {
			c.in = clientConsent(c.in, store.ClientDCR, store.TrustTested)
			c.in.ConsentVersion, c.in.SendMode = store.SendConsentVersion, store.SendModeDraft
		},
		"a legacy text on version 4": func(c *contentConsent) { c.in.ConsentVersion = store.ClientConsentVersion },
	} {
		t.Run(name, func(t *testing.T) {
			c := f.prepareContent(ctx, t, f.owner)
			mutate(&c)
			if _, err := f.conns.Create(ctx, f.tenant, f.owner, c.in); !errors.Is(err, store.ErrMCPClient) {
				t.Fatalf("err = %v", err)
			}
		})
	}

	// The lifetimes by limits tier (§19.19): every tier but a tested web
	// client's is ninety days for metadata and thirty for text, with the
	// console's hour.
	t.Run("ceilings", func(t *testing.T) {
		_, prefix := f.provisionalKey(ctx, t, "long metadata")
		in := clientConsent(consent(prefix), store.ClientCIMD, store.TrustUnknown)
		in.ExpiresAt = time.Now().Add(92 * 24 * time.Hour)
		if _, err := f.conns.Create(ctx, f.tenant, f.owner, in); !errors.Is(err, store.ErrInvalidExpiry) {
			t.Fatalf("an unknown client for 92 days: %v", err)
		}
		c := f.prepareContent(ctx, t, f.owner)
		c.in = clientConsent(c.in, store.ClientCIMD, store.TrustTested)
		c.in.ClientLocal, c.in.ExpiresAt = true, time.Now().Add(32*24*time.Hour)
		if _, err := f.conns.Create(ctx, f.tenant, f.owner, c.in); !errors.Is(err, store.ErrInvalidExpiry) {
			t.Fatalf("a local app's text for 32 days: %v", err)
		}
		for tier, want := range map[string]time.Duration{
			store.TierWebTested: 90*24*time.Hour + time.Hour, store.TierLocalTested: 30*24*time.Hour + time.Hour,
			store.TierUnknown: 30*24*time.Hour + time.Hour, store.TierToken: 30*24*time.Hour + time.Hour,
		} {
			if got := store.MaxLifetime(store.KindContent, tier); got != want {
				t.Errorf("%s text: %v, want %v", tier, got, want)
			}
		}
		if got := store.MaxLifetime(store.KindMetadata, store.TierToken); got != 90*24*time.Hour+time.Hour {
			t.Errorf("token metadata: %v", got)
		}
		if got := store.MaxLifetime(store.KindMetadata, store.TierWebTested); got != 365*24*time.Hour {
			t.Errorf("tested metadata: %v", got)
		}
	})

	// Three live untested connections, tokens included, then the fourth is
	// refused while a tested one still fits; one ending frees a place.
	t.Run("three unknown", func(t *testing.T) {
		_, prefix := f.provisionalKey(ctx, t, "third")
		third, err := f.conns.Create(ctx, f.tenant, f.owner, clientConsent(consent(prefix), store.ClientToken, store.TrustUnknown))
		if err != nil {
			t.Fatal(err)
		}
		_, prefix = f.provisionalKey(ctx, t, "fourth")
		fourth := clientConsent(consent(prefix), store.ClientCIMD, store.TrustUnknown)
		if _, err := f.conns.Create(ctx, f.tenant, f.owner, fourth); !errors.Is(err, store.ErrTooManyUnknownMCPConnections) {
			t.Fatalf("a fourth unknown: %v", err)
		}
		_, tested := f.provisionalKey(ctx, t, "tested")
		if _, err := f.conns.Create(ctx, f.tenant, f.owner, clientConsent(consent(tested), store.ClientDCR, store.TrustTested)); err != nil {
			t.Fatalf("a tested client beside three unknown: %v", err)
		}
		if _, err := f.conns.Revoke(ctx, f.tenant, f.owner, third.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.conns.Create(ctx, f.tenant, f.owner, fourth); err != nil {
			t.Fatalf("the place was not freed: %v", err)
		}
	})
}

// The list as a viewer sees it: who connected, whether the viewer saw it,
// its first use and the limits it reached.
func TestListSeenAndFirstUse(t *testing.T) {
	f := newContentFixture(t)
	ctx := context.Background()
	admin, _ := transferOwner(t, f.archive, "admin")
	ownerEmail := f.verify(ctx, t, f.owner)

	_, prefix := f.provisionalKey(ctx, t, "cimd")
	in := clientConsent(consent(prefix), store.ClientCIMD, store.TrustUnknown)
	in.ClaimedName = "Example Agent"
	conn, err := f.conns.Create(ctx, f.tenant, f.owner, in)
	if err != nil {
		t.Fatal(err)
	}
	row := func(viewer uuid.UUID) store.MCPConnection {
		t.Helper()
		listed, err := f.conns.ListFor(ctx, f.tenant, viewer)
		if err != nil || len(listed) != 1 {
			t.Fatalf("listed %+v %v", listed, err)
		}
		return listed[0]
	}
	if c := row(admin); c.Seen || c.CreatedByEmail != ownerEmail || c.FirstUsedAt != nil || c.ClaimedName != "Example Agent" ||
		c.BudgetHits == nil || len(c.BudgetHits) != 0 {
		t.Fatalf("before = %+v", c)
	}

	// Seen is per viewer, idempotent, and only for this workspace's
	// assistant connections.
	for range 2 {
		if err := f.conns.MarkSeen(ctx, f.tenant, admin, conn.ID); err != nil {
			t.Fatal(err)
		}
	}
	if !row(admin).Seen || row(f.owner).Seen {
		t.Fatal("seen is not the viewer's own")
	}
	if err := f.conns.MarkSeen(ctx, uuid.MustParse(newTenant(t, f.pool, "Other")), admin, conn.ID); !errors.Is(err, store.ErrMCPConnectionNotFound) {
		t.Fatalf("another workspace's connection: %v", err)
	}
	if err := f.conns.MarkSeen(ctx, f.tenant, admin, uuid.NewString()); !errors.Is(err, store.ErrMCPConnectionNotFound) {
		t.Fatalf("no such connection: %v", err)
	}

	// The first status that lets the reader serve is the first use, and it
	// stays the first.
	if _, err := f.conns.Status(ctx, store.HostedReader, conn.ID, nil); err != nil {
		t.Fatal(err)
	}
	if row(admin).FirstUsedAt != nil {
		t.Fatal("a pending connection was used")
	}
	if err := f.conns.Activate(ctx, store.HostedReader, conn.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.conns.Status(ctx, store.HostedReader, conn.ID, nil); err != nil {
		t.Fatal(err)
	}
	first := row(admin).FirstUsedAt
	if first == nil {
		t.Fatal("no first use after an active status")
	}
	time.Sleep(10 * time.Millisecond)
	if _, err := f.conns.Status(ctx, store.HostedReader, conn.ID, nil); err != nil {
		t.Fatal(err)
	}
	if again := row(admin).FirstUsedAt; again == nil || !again.Equal(*first) {
		t.Fatalf("first use moved: %v, was %v", again, first)
	}

	// A limit reached is listed, and the banner shows the row again.
	if _, err := f.conns.RaiseNotice(ctx, store.HostedReader, conn.ID, "daily_messages"); err != nil {
		t.Fatal(err)
	}
	if c := row(admin); c.Seen || len(c.BudgetHits) != 1 || c.BudgetHits[0].Code != "daily_messages" || c.BudgetHits[0].At.IsZero() {
		t.Fatalf("after a budget hit = %+v", c)
	}
}

func TestRaiseNotice(t *testing.T) {
	f := newMCPFixture(t)
	ctx := context.Background()
	admin, _ := transferOwner(t, f.archive, "admin")
	member, _ := transferOwner(t, f.archive, "member")
	secondOwner, _ := transferOwner(t, f.archive, "owner")
	ownerEmail := f.verify(ctx, t, f.owner)
	adminEmail := f.verify(ctx, t, admin)
	f.verify(ctx, t, member)
	// secondOwner never confirmed an address: no e-mail goes there.
	_ = secondOwner

	key, err := f.keys.IssueActingAsForDevices(ctx, f.tenant.String(), "admin's", store.ScopeRead, &admin, nil, []uuid.UUID{f.device}, ptr(time.Now().Add(20*time.Minute)))
	if err != nil {
		t.Fatal(err)
	}
	prefix, _, _ := strings.Cut(key, ".")
	conn, err := f.conns.Create(ctx, f.tenant, admin, clientConsent(consent(prefix), store.ClientCIMD, store.TrustUnknown))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.conns.Activate(ctx, store.HostedReader, conn.ID); err != nil {
		t.Fatal(err)
	}
	n, err := f.conns.RaiseNotice(ctx, store.HostedReader, conn.ID, store.NoticeActivated)
	if err != nil {
		t.Fatal(err)
	}
	if !n.First || n.Event != store.NoticeActivated || n.TenantID != f.tenant || n.ClientHost != "agent.example.com" || n.Trust != store.TrustUnknown ||
		n.ClientKind != store.ClientCIMD || n.Kind != store.KindMetadata || n.DeviceCount != 1 || n.HistoryDays != 30 || n.CreatedBy != admin {
		t.Fatalf("notice = %+v", n)
	}
	// The person who consented and the owners, with a confirmed address;
	// never an unconfirmed owner or a member who did not consent.
	want := []string{adminEmail, ownerEmail}
	if adminEmail > ownerEmail {
		want = []string{ownerEmail, adminEmail}
	}
	if strings.Join(n.Recipients, ",") != strings.Join(want, ",") {
		t.Fatalf("recipients = %v, want %v", n.Recipients, want)
	}
	if again, err := f.conns.RaiseNotice(ctx, store.HostedReader, conn.ID, store.NoticeActivated); err != nil || again.First {
		t.Fatalf("a second activation notice was first: %+v %v", again, err)
	}
	if _, err := f.conns.RaiseNotice(ctx, store.HostedReader, conn.ID, "spam"); err == nil {
		t.Fatal("an event that is not one was raised")
	}
	if _, err := f.conns.RaiseNotice(ctx, "enclave", conn.ID, "network"); !errors.Is(err, store.ErrMCPConnectionNotFound) {
		t.Fatalf("another reader raised a notice: %v", err)
	}
	if _, err := f.conns.Revoke(ctx, f.tenant, f.owner, conn.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.conns.RaiseNotice(ctx, store.HostedReader, conn.ID, "network"); !errors.Is(err, store.ErrMCPConnectionNotFound) {
		t.Fatalf("an ended connection raised a notice: %v", err)
	}
}

func ptr[T any](v T) *T { return &v }

// sha is a revoke link's stored form.
func sha(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// One e-mail per connection and event, twenty a day per workspace, none for
// an ended connection; each claim carries a link of its own, which works
// beside the earlier ones.
func TestClaimNoticeMail(t *testing.T) {
	f := newMCPFixture(t)
	ctx := context.Background()
	live := func(name string) store.MCPConnection {
		t.Helper()
		_, prefix := f.provisionalKey(ctx, t, name)
		conn, err := f.conns.Create(ctx, f.tenant, f.owner, consent(prefix))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.conns.RaiseNotice(ctx, store.HostedReader, conn.ID, store.NoticeActivated); err != nil {
			t.Fatal(err)
		}
		return conn
	}
	conn := live("first")
	if ok, err := f.conns.ClaimNoticeMail(ctx, f.tenant, conn.ID, store.NoticeActivated, sha("one")); err != nil || !ok {
		t.Fatalf("first claim: %v %v", ok, err)
	}
	if target, err := f.conns.RevokeLinkTarget(ctx, sha("one")); err != nil || target != (store.RevokeTarget{Host: "claude.ai"}) {
		t.Fatalf("the link names %+v %v", target, err)
	}
	if ok, err := f.conns.ClaimNoticeMail(ctx, f.tenant, conn.ID, store.NoticeActivated, sha("two")); err != nil || ok {
		t.Fatalf("a second e-mail for the same event: %v %v", ok, err)
	}
	if _, err := f.conns.RevokeLinkTarget(ctx, sha("two")); !errors.Is(err, store.ErrMCPConnectionNotFound) {
		t.Fatalf("a refused claim stored its link: %v", err)
	}
	if ok, err := f.conns.ClaimNoticeMail(ctx, f.tenant, conn.ID, "daily_messages", sha("three")); err != nil || ok {
		t.Fatalf("an event never raised was claimed: %v %v", ok, err)
	}
	if _, err := f.conns.RaiseNotice(ctx, store.HostedReader, conn.ID, "daily_messages"); err != nil {
		t.Fatal(err)
	}
	if ok, err := f.conns.ClaimNoticeMail(ctx, f.tenant, conn.ID, "daily_messages", sha("three")); err != nil || !ok {
		t.Fatalf("a new event: %v %v", ok, err)
	}
	// The later link joins the earlier one: both name the connection.
	for _, link := range []string{"one", "three"} {
		if target, err := f.conns.RevokeLinkTarget(ctx, sha(link)); err != nil || target.Host != "claude.ai" {
			t.Fatalf("link %s names %+v %v", link, target, err)
		}
	}
	if _, err := f.conns.ClaimNoticeMail(ctx, f.tenant, conn.ID, store.NoticeActivated, "not hex"); err == nil {
		t.Fatal("a link that is not a hash was stored")
	}

	// An ended connection's e-mail does not go, and leaves its claim.
	ended := live("ended")
	if _, err := f.conns.Revoke(ctx, f.tenant, f.owner, ended.ID); err != nil {
		t.Fatal(err)
	}
	if ok, err := f.conns.ClaimNoticeMail(ctx, f.tenant, ended.ID, store.NoticeActivated, sha("ended")); err != nil || ok {
		t.Fatalf("an ended connection's e-mail: %v %v", ok, err)
	}

	// Two e-mails so far, and five more of the ended connection's from
	// yesterday's last hour: thirteen more are the day's, and the
	// twenty-first waits, whatever connection raised it.
	if err := pg.InTenantTx(ctx, f.pool, f.tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO mcp_connection_notices (connection_id, tenant_id, event, mailed_at)
			SELECT $1, $2, e, now() - interval '23 hours' FROM unnest($3::text[]) e`,
			ended.ID, f.tenant, []string{"daily_messages", "daily_attachments", "first_hour_messages", "first_hour_attachments", "network"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for mailed := 7; mailed < 20; mailed++ {
		c := live("busy")
		if ok, err := f.conns.ClaimNoticeMail(ctx, f.tenant, c.ID, store.NoticeActivated, sha(c.ID)); err != nil || !ok {
			t.Fatalf("e-mail %d: %v %v", mailed+1, ok, err)
		}
		// Room under the cap of ten live connections.
		if _, err := f.conns.Revoke(ctx, f.tenant, f.owner, c.ID); err != nil {
			t.Fatal(err)
		}
	}
	c := live("twenty-first")
	if ok, err := f.conns.ClaimNoticeMail(ctx, f.tenant, c.ID, store.NoticeActivated, sha(c.ID)); err != nil || ok {
		t.Fatalf("the twenty-first e-mail of the day: %v %v", ok, err)
	}
	// Another workspace has its own twenty.
	other := uuid.MustParse(newTenant(t, f.pool, "Other"))
	if ok, err := f.conns.ClaimNoticeMail(ctx, other, c.ID, store.NoticeActivated, sha("other")); err != nil || ok {
		t.Fatalf("another workspace claimed this one's notice: %v %v", ok, err)
	}
}

// The revoke-only link: looking changes nothing, the first POST of any of a
// connection's links revokes the one connection with its key, and spends
// them all; nothing after it does.
func TestRevokeByLink(t *testing.T) {
	f := newContentFixture(t)
	ctx := context.Background()
	conn, c := f.consentContent(ctx, t, f.owner)
	other, _ := f.consentContent(ctx, t, f.owner)
	for _, id := range []string{conn.ID, other.ID} {
		if _, err := f.conns.RaiseNotice(ctx, "enclave", id, store.NoticeActivated); err != nil {
			t.Fatal(err)
		}
	}
	if ok, err := f.conns.ClaimNoticeMail(ctx, f.tenant, conn.ID, store.NoticeActivated, sha("link")); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if _, err := f.conns.RaiseNotice(ctx, "enclave", conn.ID, "daily_messages"); err != nil {
		t.Fatal(err)
	}
	if ok, err := f.conns.ClaimNoticeMail(ctx, f.tenant, conn.ID, "daily_messages", sha("later")); err != nil || !ok {
		t.Fatal(ok, err)
	}
	for range 2 {
		if target, err := f.conns.RevokeLinkTarget(ctx, sha("link")); err != nil || target.Host != "claude.ai" || target.Token {
			t.Fatalf("target = %+v %v", target, err)
		}
	}
	if s := f.row(ctx, t, conn.ID).Status; s != "active" {
		t.Fatalf("looking changed the status to %s", s)
	}
	for _, bad := range []string{sha("unknown"), "", "LINK"} {
		if _, _, err := f.conns.RevokeByLink(ctx, bad); !errors.Is(err, store.ErrMCPConnectionNotFound) {
			t.Fatalf("%q revoked: %v", bad, err)
		}
	}
	id, reader, err := f.conns.RevokeByLink(ctx, sha("link"))
	if err != nil || id != conn.ID || reader != "enclave" {
		t.Fatalf("revoke = %s %s %v", id, reader, err)
	}
	if got := f.row(ctx, t, conn.ID); got.Status != "revoked" || got.RevokeReason != store.ReasonConsole {
		t.Fatalf("revoked row = %+v", got)
	}
	if _, err := f.keys.Verify(ctx, c.key); !errors.Is(err, store.ErrInvalidKey) {
		t.Fatalf("the key survived: %v", err)
	}
	if tr := f.trace(ctx, t, c.service); tr != (serviceTrace{}) {
		t.Fatalf("the service account kept %+v", tr)
	}
	if _, _, err := f.conns.RevokeByLink(ctx, sha("link")); !errors.Is(err, store.ErrMCPConnectionNotFound) {
		t.Fatalf("a second POST: %v", err)
	}
	for _, link := range []string{"link", "later"} {
		if _, err := f.conns.RevokeLinkTarget(ctx, sha(link)); !errors.Is(err, store.ErrMCPConnectionNotFound) {
			t.Fatalf("a spent link (%s) still names its connection: %v", link, err)
		}
		if _, _, err := f.conns.RevokeByLink(ctx, sha(link)); !errors.Is(err, store.ErrMCPConnectionNotFound) {
			t.Fatalf("a spent link (%s) revoked: %v", link, err)
		}
	}
	if s := f.row(ctx, t, other.ID).Status; s != "active" {
		t.Fatalf("the other connection is %s", s)
	}
}

func TestEmailVerified(t *testing.T) {
	f := newMCPFixture(t)
	ctx := context.Background()
	users := store.NewUsers(f.pool)
	if ok, err := users.EmailVerified(ctx, f.tenant, f.owner); err != nil || ok {
		t.Fatalf("an invited account is verified: %v %v", ok, err)
	}
	f.verify(ctx, t, f.owner)
	if ok, err := users.EmailVerified(ctx, f.tenant, f.owner); err != nil || !ok {
		t.Fatalf("a confirmed address is not verified: %v %v", ok, err)
	}
	// Housekeeping keeps a completed verification while its address has a
	// login, and drops a dead unconsumed one.
	sum := sha256.Sum256([]byte("dead"))
	if _, err := f.pool.Exec(ctx, `INSERT INTO email_signup_verifications (token_hash, email, expires_at) VALUES ($1, 'dead@example.test', now() - interval '400 days')`,
		sum[:]); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Housekeeping(ctx, f.pool, time.Hour); err != nil {
		t.Fatal(err)
	}
	if ok, err := users.EmailVerified(ctx, f.tenant, f.owner); err != nil || !ok {
		t.Fatalf("housekeeping forgot a confirmed address: %v %v", ok, err)
	}
	var left int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM email_signup_verifications WHERE email='dead@example.test'`).Scan(&left); err != nil || left != 0 {
		t.Fatalf("a dead verification stayed: %d %v", left, err)
	}
}

// 0046 on a ledger an older binary keeps writing to: its inserts name no
// client_kind and no trust, and still pass; the new CHECKs refuse what does
// not hold together; the two new tables force row-level security; and the
// down-step, as its header documents it, ends the untested connections with
// their keys and leaves everything else.
func TestMigration0046(t *testing.T) {
	f := newAIFixture(t)
	ctx := context.Background()

	// An older binary's metadata insert, and an AI insert the trigger
	// marks.
	_, prefix := f.provisionalKey(ctx, t, "old")
	var keyID uuid.UUID
	f.inTenant(ctx, t, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id FROM api_keys WHERE prefix=$1`, prefix).Scan(&keyID)
	})
	var oldKind string
	var oldTrust *string
	if err := f.pool.QueryRow(ctx, `INSERT INTO mcp_connections
		(tenant_id, request_id, api_key_id, created_by, client_name, redirect_host, device_count, reader_kid, status, expires_at, reader, kind)
		VALUES ($1, 'old-binary', $2, $3, 'Claude', 'claude.ai', 1, '0123456789abcdef', 'pending', now() + interval '1 day', 'hosted', 'metadata')
		RETURNING client_kind, trust`, f.tenant, keyID, f.owner).Scan(&oldKind, &oldTrust); err != nil {
		t.Fatalf("an older binary's insert: %v", err)
	}
	if oldKind != store.ClientLegacy || oldTrust != nil {
		t.Fatalf("old insert = %s %v", oldKind, oldTrust)
	}
	// An AI row as an older binary writes it: every column it knows, none
	// of 0046's. The trigger makes it ai, and trust stays NULL.
	ai, _ := f.consentAI(ctx, t, f.owner, f.aiKeys(ctx, t, f.owner), nil)
	var aiKind string
	var aiTrust *string
	if err := pgx.BeginFunc(ctx, f.pool, func(tx pgx.Tx) error {
		var columns string
		if err := tx.QueryRow(ctx, `SELECT string_agg(quote_ident(column_name), ', ' ORDER BY ordinal_position) FROM information_schema.columns
			WHERE table_schema = current_schema() AND table_name = 'mcp_connections'
			  AND column_name NOT IN ('client_kind','client_id','client_host','client_local','trust','claimed_name','history_days',
			                          'first_used_at')`).Scan(&columns); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `CREATE TEMP TABLE old_ai ON COMMIT DROP AS SELECT * FROM mcp_connections WHERE id = $1`, ai.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM mcp_connections WHERE id = $1`, ai.ID); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO mcp_connections (`+columns+`) SELECT `+columns+` FROM old_ai RETURNING client_kind, trust`).
			Scan(&aiKind, &aiTrust)
	}); err != nil || aiKind != store.ClientAI || aiTrust != nil {
		t.Fatalf("an older binary's AI insert = %s %v %v", aiKind, aiTrust, err)
	}
	var forced int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM pg_class WHERE relname IN ('mcp_connection_seen', 'mcp_connection_notices')
		AND relrowsecurity AND relforcerowsecurity AND relnamespace = current_schema()::regnamespace`).Scan(&forced); err != nil || forced != 2 {
		t.Fatalf("forced row-level security on %d tables %v", forced, err)
	}
	// Outside a tenant transaction the policy shows and admits nothing.
	if _, err := f.pool.Exec(ctx, `INSERT INTO mcp_connection_seen (connection_id, tenant_id, user_id) VALUES ($1, $2, $3)`,
		ai.ID, f.tenant, f.owner); err == nil {
		t.Fatal("a seen mark was written outside its workspace")
	}

	for name, stmt := range map[string]string{
		"a token that is tested":   `UPDATE mcp_connections SET client_kind='token', trust='tested', redirect_host='token' WHERE request_id='old-binary'`,
		"a token with a redirect":  `UPDATE mcp_connections SET client_kind='token', trust='unknown' WHERE request_id='old-binary'`,
		"cimd without a client id": `UPDATE mcp_connections SET client_kind='cimd' WHERE request_id='old-binary'`,
		"an assistant marked ai":   `UPDATE mcp_connections SET client_kind='ai' WHERE request_id='old-binary'`,
		"a client id over http":    `UPDATE mcp_connections SET client_id='http://x.example/c' WHERE request_id='old-binary'`,
		"an upper-case host":       `UPDATE mcp_connections SET client_host='Example.com' WHERE request_id='old-binary'`,
		"fourteen days":            `UPDATE mcp_connections SET history_days=14 WHERE request_id='old-binary'`,
		"a trust that is not one":  `UPDATE mcp_connections SET trust='verified' WHERE request_id='old-binary'`,
		"a claimed name of 101":    `UPDATE mcp_connections SET claimed_name=repeat('a', 101) WHERE request_id='old-binary'`,
		"a revoke link that is not hex": `INSERT INTO mcp_revoke_links (sha256, connection_id, tenant_id, event)
			SELECT 'LINK', id, tenant_id, 'activated' FROM mcp_connections WHERE request_id='old-binary'`,
	} {
		var pgErr *pgconn.PgError
		if _, err := f.pool.Exec(ctx, stmt); !errors.As(err, &pgErr) || pgErr.Code != "23514" {
			t.Errorf("%s: %v", name, err)
		}
	}

	// The down-step: an untested connection and a token end with their keys
	// and accounts, every other row stays as it was.
	unknownConn, uc := f.consentContent(ctx, t, f.owner)
	if _, err := f.pool.Exec(ctx, `UPDATE mcp_connections SET client_kind='cimd', trust='unknown', history_days=30,
		client_id='https://agent.example.com/c.json', client_host='agent.example.com', consent_version=4 WHERE id=$1`, unknownConn.ID); err != nil {
		t.Fatal(err)
	}
	_, tokenPrefix := f.provisionalKey(ctx, t, "token")
	token, err := f.conns.Create(ctx, f.tenant, f.owner, clientConsent(consent(tokenPrefix), store.ClientToken, store.TrustUnknown))
	if err != nil {
		t.Fatal(err)
	}
	tested, tc := f.consentContent(ctx, t, f.owner)
	if _, err := f.conns.RaiseNotice(ctx, "enclave", tested.ID, store.NoticeActivated); err != nil {
		t.Fatal(err)
	}
	if err := f.conns.MarkSeen(ctx, f.tenant, f.owner, tested.ID); err != nil {
		t.Fatal(err)
	}

	// 0048 (platform sign-in) comes down first, then 0047 (fewer steps).
	if _, err := f.pool.Exec(ctx, downStep(t, 48)); err != nil {
		t.Fatalf("0048 down-step: %v", err)
	}
	if _, err := f.pool.Exec(ctx, downStep(t, 47)); err != nil {
		t.Fatalf("0047 down-step: %v", err)
	}
	if _, err := f.pool.Exec(ctx, downStep(t, 46)); err != nil {
		t.Fatalf("down-step: %v", err)
	}
	var version int
	if err := f.pool.QueryRow(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&version); err != nil || version != 45 {
		t.Fatalf("ledger at %d %v", version, err)
	}
	var left int
	if err := f.pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM information_schema.tables WHERE table_schema=current_schema()
		   AND table_name IN ('mcp_connection_seen', 'mcp_connection_notices', 'mcp_revoke_links'))
		+ (SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='mcp_connections'
		   AND column_name IN ('client_kind','client_id','client_host','client_local','trust','claimed_name','history_days',
		                       'first_used_at'))
		+ (SELECT count(*) FROM pg_constraint WHERE conname='mcp_connections_client_coherent' AND connamespace=current_schema()::regnamespace)
		+ (SELECT count(*) FROM pg_proc WHERE proname='mcp_connections_ai_kind' AND pronamespace=current_schema()::regnamespace)`).Scan(&left); err != nil || left != 0 {
		t.Fatalf("%d things left %v", left, err)
	}
	statuses := map[string]string{}
	rows, err := f.pool.Query(ctx, `SELECT id::text, status FROM mcp_connections`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id, status string
		if err := rows.Scan(&id, &status); err != nil {
			t.Fatal(err)
		}
		statuses[id] = status
	}
	if statuses[unknownConn.ID] != "revoked" || statuses[token.ID] != "revoked" || statuses[tested.ID] != "active" || statuses[ai.ID] != "active" {
		t.Fatalf("statuses = %v", statuses)
	}
	if _, err := f.keys.Verify(ctx, uc.key); !errors.Is(err, store.ErrInvalidKey) {
		t.Fatalf("the untested connection's key survived: %v", err)
	}
	if tr := f.trace(ctx, t, uc.service); tr != (serviceTrace{}) {
		t.Fatalf("the untested connection's account kept %+v", tr)
	}
	if _, err := f.keys.Verify(ctx, tc.key); err != nil {
		t.Fatalf("a tested connection's key was revoked: %v", err)
	}

	// Up again: the rows written before it are legacy and tested, the AI
	// rows ai, and every insert works.
	if err := migrate.Run(ctx, f.pool, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatalf("re-applying 0046: %v", err)
	}
	kinds := map[string][2]string{}
	rows, err = f.pool.Query(ctx, `SELECT id::text, client_kind, coalesce(trust, '') FROM mcp_connections`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id, kind, trust string
		if err := rows.Scan(&id, &kind, &trust); err != nil {
			t.Fatal(err)
		}
		kinds[id] = [2]string{kind, trust}
	}
	if kinds[tested.ID] != [2]string{"legacy", "tested"} || kinds[ai.ID] != [2]string{"ai", ""} || kinds[token.ID] != [2]string{"legacy", "tested"} {
		t.Fatalf("after re-applying = %v", kinds)
	}
	if listed, err := f.conns.ListFor(ctx, f.tenant, f.owner); err != nil || len(listed) == 0 || listed[0].Seen {
		t.Fatalf("list after re-applying = %v %v", listed, err)
	}
	f.consentAI(ctx, t, f.owner, f.aiKeys(ctx, t, f.owner), nil)
	f.consentContent(ctx, t, f.owner)
}
