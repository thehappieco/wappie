package wsapi_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/store"
	"whatserver2/internal/wsapi"
)

// Every grant hands a number's key on: to a connection's service account, a
// standing service account whose private key its registrant holds, or a
// member, each waits for the person's fresh step-up (docs/mcp-enclave.md
// §19.30), so a browser left open past the window cannot give an archive
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
