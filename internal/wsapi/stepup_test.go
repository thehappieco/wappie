package wsapi_test

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/stepup"
	"whatserver2/internal/store"
	"whatserver2/internal/wsapi"
)

// Every grant hands a number's key on: to a connection's service account, a
// standing service account whose private key its registrant holds, or a
// member, each waits for the person's fresh step-up (docs/mcp-enclave.md
// §19.35), so a browser left open past the window cannot give an archive
// away. A step-up lets each through again.
func TestEveryGrantNeedsAStepUp(t *testing.T) {
	c := newConsole(t)
	ctx := context.Background()
	token := c.account(t, "owner@acme.test", "owner")
	session, err := c.users.Session(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	owner := session.UserID
	member := c.accountID(t, "reader@acme.test", "member")
	dev := c.deviceWithKey(t, "phone")
	secret, _, err := c.users.NewProvisionalServiceInvitation(ctx, c.tenant, owner)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := c.users.SignupService(ctx, secret, "mcp-stepup", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	// A standing service account, as an invitation that is not provisional
	// makes one: whoever registered it holds its private key.
	secret, _, err = c.users.NewMemberInvitation(ctx, c.tenant, owner, store.RoleService, "")
	if err != nil {
		t.Fatal(err)
	}
	standing, err := c.users.SignupService(ctx, secret, "erp", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	grant := func(to uuid.UUID) wsapi.Frame {
		return ask(t, c, wsapi.Hello{Session: token}, wsapi.TypeGrantAdd, wsapi.GrantRequest{
			DeviceID: dev, UserID: to.String(), Epoch: 1, SealedDSK: []byte("sealed"),
		})
	}
	grantees := map[string]uuid.UUID{"a connection's service account": connection.ID, "a standing service account": standing.ID, "a member": member}
	for name, to := range grantees {
		if f := grant(to); f.Type != wsapi.TypeReaders {
			t.Fatalf("a fresh session's grant to %s = %q: %s", name, f.Type, f.Payload)
		}
	}
	if _, err := c.pool.Exec(ctx, `UPDATE sessions SET authenticated_at = now() - make_interval(secs => $2) WHERE id=$1`,
		session.ID, (11 * time.Minute).Seconds()); err != nil {
		t.Fatal(err)
	}
	for name, to := range grantees {
		t.Logf("a stale session's grant to %s", name)
		wantError(t, grant(to), wsapi.ErrCodeStepUpRequired)
	}
	if err := c.users.MarkStepUp(ctx, session.ID); err != nil {
		t.Fatal(err)
	}
	for name, to := range grantees {
		if f := grant(to); f.Type != wsapi.TypeReaders {
			t.Fatalf("after a step-up, the grant to %s = %q: %s", name, f.Type, f.Payload)
		}
	}
}

// An account that signs in through the identity provider earns its proof
// there (step 4 of the sign-in plan): a session with none is refused a
// grant over the WebSocket like any other; a step-up at the provider,
// recorded as the finish route records it, lets the grant through, as does
// a sign-in whose provider auth_time is recent, and not one whose is old.
func TestAGrantAfterAStepUpAtTheProvider(t *testing.T) {
	c := newConsole(t)
	ctx := context.Background()
	const email = "lin@acme.test"
	legacy, err := c.users.Create(ctx, store.NewUser{
		TenantID: c.tenant, Email: email, Role: "owner",
		AuthKey: "auth-" + email, KDFSalt: make([]byte, 16), KDFParams: store.DefaultKDFParams(),
		PublicKey: make([]byte, 32), WrappedUSK: []byte("wrapped"),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Link it to an account at the provider, as the link ceremony does.
	sub, key := uuid.New(), make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.NewPlatformPins(c.pool).InsertPin(ctx, sub.String(), "wappie:1", key); err != nil {
		t.Fatal(err)
	}
	ticket, err := c.users.CreatePlatformTicket(ctx, store.PlatformTicket{Kind: store.TicketNew, Sub: sub, ProductKeyID: "wappie:1", ProductKey: key, Email: "lin@id.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	wrap := make([]byte, 61)
	wrap[0] = 0x03 // the platform wrap's header (kit SPEC 6.8)
	linked, err := c.users.LinkLegacy(ctx, store.LegacyLink{Ticket: ticket, Proof: store.LegacyProof{Email: email, Secret: "auth-" + email}, Wrap: wrap})
	if err != nil {
		t.Fatal(err)
	}
	if linked.ID != legacy.ID || linked.TenantID != c.tenant || linked.AuthSource != store.PlatformAuthSource {
		t.Fatalf("linked %+v", linked)
	}
	member := c.accountID(t, "reader@acme.test", "member")
	dev := c.deviceWithKey(t, "phone")
	grant := func(token string) wsapi.Frame {
		return ask(t, c, wsapi.Hello{Session: token}, wsapi.TypeGrantAdd, wsapi.GrantRequest{
			DeviceID: dev, UserID: member.String(), Epoch: 1, SealedDSK: []byte("sealed"),
		})
	}

	token, session, err := c.users.StartPlatformSession(ctx, linked, "test", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	wantError(t, grant(token), wsapi.ErrCodeStepUpRequired)
	notBefore, err := c.users.StartProviderStepUp(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	wantError(t, grant(token), wsapi.ErrCodeStepUpRequired)
	if err := c.users.FinishProviderStepUp(ctx, session.ID, store.PendingStepUp{Session: session.ID, NotBefore: notBefore}, time.Now(), stepup.Window, stepup.ProviderClockTolerance); err != nil {
		t.Fatal(err)
	}
	if f := grant(token); f.Type != wsapi.TypeReaders {
		t.Fatalf("a grant after the step-up at the provider = %q: %s", f.Type, f.Payload)
	}

	for name, tc := range map[string]struct {
		authTime time.Time
		passes   bool
	}{
		"a recent sign-in at the provider":  {time.Now().Add(-time.Minute), true},
		"an old sign-in at the provider":    {time.Now().Add(-11 * time.Minute), false},
		"a sign-in that named no auth_time": {time.Time{}, false},
	} {
		token, _, err := c.users.StartPlatformSession(ctx, linked, "test", tc.authTime)
		if err != nil {
			t.Fatal(err)
		}
		if f := grant(token); (f.Type == wsapi.TypeReaders) != tc.passes {
			t.Fatalf("%s: %q %s", name, f.Type, f.Payload)
		}
	}
}
