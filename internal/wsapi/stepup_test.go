package wsapi_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/wsapi"
)

// A grant to a connection's service account hands a number to an
// assistant's reader: it waits for the person's fresh step-up
// (docs/mcp-enclave.md §19.30). A grant to anyone else does not.
func TestGrantToAConnectionServiceNeedsAStepUp(t *testing.T) {
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
	service, err := c.users.SignupService(ctx, secret, "mcp-stepup", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	grant := func(to uuid.UUID) wsapi.Frame {
		return ask(t, c, wsapi.Hello{Session: token}, wsapi.TypeGrantAdd, wsapi.GrantRequest{
			DeviceID: dev, UserID: to.String(), Epoch: 1, SealedDSK: []byte("sealed"),
		})
	}
	if f := grant(service.ID); f.Type != wsapi.TypeReaders {
		t.Fatalf("a fresh session's grant = %q: %s", f.Type, f.Payload)
	}
	if _, err := c.pool.Exec(ctx, `UPDATE sessions SET authenticated_at = now() - make_interval(secs => $2) WHERE id=$1`,
		session.ID, (11 * time.Minute).Seconds()); err != nil {
		t.Fatal(err)
	}
	wantError(t, grant(service.ID), wsapi.ErrCodeStepUpRequired)
	if f := grant(member); f.Type != wsapi.TypeReaders {
		t.Fatalf("a grant to a person = %q: %s", f.Type, f.Payload)
	}
	if err := c.users.MarkStepUp(ctx, session.ID); err != nil {
		t.Fatal(err)
	}
	if f := grant(service.ID); f.Type != wsapi.TypeReaders {
		t.Fatalf("after a step-up = %q: %s", f.Type, f.Payload)
	}
}
