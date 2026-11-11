package wsapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/authapi"
	"whatserver2/internal/store"
	"whatserver2/internal/wsapi"
)

// The console's flags runners (step 12b's F1) against Wappie's own
// screen: PUT …/permissions and the socket's grant.revoke on one of twin
// numbers, the runner on the other, by the same admin; each pair must
// leave the same flags and grants, and refuse the same people, an admin
// on an owner's flags included (Q58), with the last reader kept
// (ErrLastDeviceReader where the act says last_reader).
// The known differences are pinned: a deleted number (DS21), and a raise,
// which never touches a key (the screen's PUT without read deletes one).

// flagsParity is the parity world with Wappie's HTTP routes beside it.
type flagsParity struct {
	*parity
	auth *httptest.Server
}

func newFlagsParity(t *testing.T) *flagsParity {
	t.Helper()
	p := newParity(t)
	mux := http.NewServeMux()
	(&authapi.Handler{Users: p.users, Keys: store.NewKeys(p.pool), Devices: p.devices, AccessChanged: p.srv.RevalidateAccess}).Mount(mux)
	auth := httptest.NewServer(mux)
	t.Cleanup(auth.Close)
	return &flagsParity{parity: p, auth: auth}
}

// put is the screen's permission change by token: "ok", or the error's
// code.
func (p *flagsParity) put(t *testing.T, token string, device, user uuid.UUID, read, send, manage bool) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{"user_id": user, "read": read, "send": send, "manage": manage})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPut,
		p.auth.URL+"/v1/auth/workspaces/devices/"+device.String()+"/permissions", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode == http.StatusNoContent {
		return "ok"
	}
	var e struct{ Code string }
	if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
		t.Fatalf("PUT %d: %v", res.StatusCode, err)
	}
	return e.Code
}

// revoke is the socket's grant.revoke by token: "ok", or the error's code.
func (p *flagsParity) revoke(t *testing.T, token string, device, user uuid.UUID) string {
	t.Helper()
	return frameOutcome(t, ask(t, p.console, wsapi.Hello{Session: token}, wsapi.TypeGrantRevoke,
		wsapi.GrantRevoke{DeviceID: device.String(), UserID: user.String()}), wsapi.TypeReaders)
}

// held is what user holds on device: the stored flags and the grants, at
// every epoch, a deleted number's included.
type held struct {
	Read, Send, Manage bool
	Grants             int
}

func (p *flagsParity) held(t *testing.T, device, user uuid.UUID) held {
	t.Helper()
	ctx := context.Background()
	var h held
	p.scoped(ctx, t, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT coalesce(bool_or(can_read), false), coalesce(bool_or(can_send), false),
			coalesce(bool_or(can_manage), false) FROM device_permissions WHERE device_id = $1 AND user_id = $2`, device, user).
			Scan(&h.Read, &h.Send, &h.Manage); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM device_key_grants WHERE device_id = $1 AND user_id = $2`, device, user).Scan(&h.Grants)
	})
	return h
}

// same checks that user holds the same on both twins, and that it is want.
func (p *flagsParity) same(t *testing.T, what string, frame, console, user uuid.UUID, want held) {
	t.Helper()
	if f, c := p.held(t, frame, user), p.held(t, console, user); f != c || f != want {
		t.Fatalf("%s: the screen left %+v, the runner %+v, want %+v", what, f, c, want)
	}
}

// grant shares device's key with user at epoch 1, as a reader's client
// does.
func (p *flagsParity) grant(t *testing.T, device, user uuid.UUID) {
	t.Helper()
	if err := store.NewKeys(p.pool).PutGrant(context.Background(), store.Grant{TenantID: p.tenant, DeviceID: device, UserID: user, Epoch: 1,
		SealedDSK: []byte("grant")}, &p.owner); err != nil {
		t.Fatal(err)
	}
}

func TestConsoleParityFlags(t *testing.T) {
	p := newFlagsParity(t)
	ctx := context.Background()
	admin, adminToken := p.person(t, "bia", "admin")
	adminSub := p.link(t, admin, "admin")
	member, memberToken := p.person(t, "ana", "member")
	memberSub := p.link(t, member, "member")
	target, _ := p.person(t, "caio", "member")
	frame, console := p.linkedDevice(t, "Frame"), p.linkedDevice(t, "Console")
	for _, d := range []uuid.UUID{frame, console} {
		p.reads(t, p.owner, d)
		p.reads(t, target, d)
	}
	p.same(t, "to start", frame, console, target, held{Read: true, Send: true, Grants: 1})
	raise := func(user, sub, person uuid.UUID, before, after []string) string {
		return p.outcome(p.runner.FlagsRaise(ctx, p.command(t, kc.OpItemFlagsRaise, user, sub), console, person, before, after)) //nolint:contextcheck // the world's helpers run on a context of their own
	}
	drop := func(device, person uuid.UUID, before, after []string) string {
		return p.outcome(p.runner.FlagsDrop(ctx, p.command(t, kc.OpItemFlagsDrop, admin, adminSub), device, person, before, after)) //nolint:contextcheck // the world's helpers run on a context of their own
	}
	remove := func(device, person uuid.UUID) string {
		return p.outcome(p.runner.AccessRemove(ctx, p.command(t, kc.OpItemAccessRemove, admin, adminSub), device, person)) //nolint:contextcheck // the world's helpers run on a context of their own
	}

	// A member: refused by both.
	fo := p.put(t, memberToken, frame, target, true, true, true)
	co := raise(member, memberSub, target, []string{kc.CanRead, kc.CanSend}, []string{kc.CanRead, kc.CanSend, kc.CanManage})
	if fo != kc.CodeNotAuthorized || co != kc.CodeNotAuthorized {
		t.Fatalf("a member's raise: the screen %s, the runner %s", fo, co)
	}
	p.same(t, "a member's raise", frame, console, target, held{Read: true, Send: true, Grants: 1})

	// An admin raises manage, drops send, then drops read: the same rows.
	fo = p.put(t, adminToken, frame, target, true, true, true)
	co = raise(admin, adminSub, target, []string{kc.CanRead, kc.CanSend}, []string{kc.CanRead, kc.CanSend, kc.CanManage})
	if fo != "ok" || co != "ok" {
		t.Fatalf("a raise of manage: the screen %s, the runner %s", fo, co)
	}
	p.same(t, "a raise of manage", frame, console, target, held{Read: true, Send: true, Manage: true, Grants: 1})
	fo = p.put(t, adminToken, frame, target, true, false, true)
	co = drop(console, target, []string{kc.CanRead, kc.CanSend, kc.CanManage}, []string{kc.CanRead, kc.CanManage})
	if fo != "ok" || co != "ok" {
		t.Fatalf("a drop of send: the screen %s, the runner %s", fo, co)
	}
	p.same(t, "a drop of send", frame, console, target, held{Read: true, Manage: true, Grants: 1})
	fo = p.put(t, adminToken, frame, target, false, false, true)
	co = drop(console, target, []string{kc.CanRead, kc.CanManage}, []string{kc.CanManage})
	if fo != "ok" || co != "ok" {
		t.Fatalf("a drop of read: the screen %s, the runner %s", fo, co)
	}
	p.same(t, "a drop of read", frame, console, target, held{Manage: true})

	// A dormant key (no read): grant.revoke and a remove both take it; a
	// remove takes every flag too, as the screen's PUT of none does.
	for _, d := range []uuid.UUID{frame, console} {
		p.grant(t, d, target)
	}
	p.same(t, "a dormant key", frame, console, target, held{Manage: true, Grants: 1})
	if fo, co := p.revoke(t, adminToken, frame, target), remove(console, target); fo != "ok" || co != "ok" {
		t.Fatalf("a dormant key's removal: the screen %s, the runner %s", fo, co)
	}
	if fo := p.put(t, adminToken, frame, target, false, false, false); fo != "ok" {
		t.Fatalf("the screen's PUT of none: %s", fo)
	}
	p.same(t, "a remove", frame, console, target, held{})
	// The row stays all false on both: a key shared again gives no read.
	for _, d := range []uuid.UUID{frame, console} {
		p.grant(t, d, target)
	}
	p.same(t, "a key shared after a remove", frame, console, target, held{Grants: 1})

	// The owner alone reads these. An owner's flags are only an owner's
	// (Q58): the admin is refused by both, before the last reader.
	soloFrame, soloConsole := p.linkedDevice(t, "Solo frame"), p.linkedDevice(t, "Solo console")
	for _, d := range []uuid.UUID{soloFrame, soloConsole} {
		p.reads(t, p.owner, d)
	}
	fo = p.put(t, adminToken, soloFrame, p.owner, false, true, false)
	co = drop(soloConsole, p.owner, []string{kc.CanRead, kc.CanSend}, []string{kc.CanSend})
	if fo != kc.CodeNotAuthorized || co != kc.CodeNotAuthorized {
		t.Fatalf("an admin's drop of an owner: the screen %s, the runner %s", fo, co)
	}
	if co := remove(soloConsole, p.owner); co != kc.CodeNotAuthorized {
		t.Fatalf("an admin's remove of an owner: the runner %s", co)
	}
	// The socket's grant.revoke reads the role again and keeps the same
	// rule (DS48): not_authorized, a frame, before the last reader.
	if fo := p.revoke(t, adminToken, soloFrame, p.owner); fo != kc.CodeNotAuthorized {
		t.Fatalf("an admin's grant.revoke of an owner: %s", fo)
	}
	// The last reader is kept by both, for another owner.
	second, secondToken := p.person(t, "duda", "owner")
	secondSub := p.link(t, second, "owner")
	fo = p.put(t, secondToken, soloFrame, p.owner, false, true, false)
	co = p.outcome(p.runner.FlagsDrop(ctx, p.command(t, kc.OpItemFlagsDrop, second, secondSub), soloConsole, p.owner, //nolint:contextcheck // the world's helpers run on a context of their own
		[]string{kc.CanRead, kc.CanSend}, []string{kc.CanSend}))
	if fo != wsapi.ErrCodeLastDeviceReader || co != kc.CodeLastReader {
		t.Fatalf("the last reader's drop: the screen %s, the runner %s", fo, co)
	}
	fo = p.revoke(t, secondToken, soloFrame, p.owner)
	co = p.outcome(p.runner.AccessRemove(ctx, p.command(t, kc.OpItemAccessRemove, second, secondSub), soloConsole, p.owner)) //nolint:contextcheck // the world's helpers run on a context of their own
	if fo != wsapi.ErrCodeLastDeviceReader || co != kc.CodeLastReader {
		t.Fatalf("the last reader's removal: the screen %s, the runner %s", fo, co)
	}
	p.same(t, "the last reader", soloFrame, soloConsole, p.owner, held{Read: true, Send: true, Grants: 1})

	// Known difference: a raise never touches a key. The screen's PUT
	// without read deletes a dormant one; the runner's raise of send
	// keeps it.
	p.same(t, "a dormant key again", frame, console, target, held{Grants: 1})
	fo = p.put(t, adminToken, frame, target, false, true, false)
	co = raise(admin, adminSub, target, []string{}, []string{kc.CanSend})
	if f, c := p.held(t, frame, target), p.held(t, console, target); fo != "ok" || co != "ok" ||
		f != (held{Send: true}) || c != (held{Send: true, Grants: 1}) {
		t.Fatalf("a raise of send for a dormant key: the screen %s %+v, the runner %s %+v", fo, f, co, c)
	}

	// Known difference (DS21): a deleted number. The screen finds none;
	// the runner's drop and remove run on it, its raise is state_changed.
	goneFrame, goneConsole := p.linkedDevice(t, "Gone frame"), p.linkedDevice(t, "Gone console")
	for _, d := range []uuid.UUID{goneFrame, goneConsole} {
		p.reads(t, p.owner, d)
		p.reads(t, target, d)
		if _, err := p.devices.Quarantine(ctx, p.tenant, p.owner, d, []uuid.UUID{target}); err != nil {
			t.Fatal(err)
		}
	}
	fo = p.put(t, adminToken, goneFrame, target, false, true, false)
	co = drop(goneConsole, target, []string{kc.CanRead, kc.CanSend}, []string{kc.CanSend})
	if fo != kc.CodeNotFound || co != "ok" {
		t.Fatalf("a deleted number's drop of read: the screen %s, the runner %s", fo, co)
	}
	if f, c := p.held(t, goneFrame, target), p.held(t, goneConsole, target); f != (held{Read: true, Send: true, Grants: 1}) ||
		c != (held{Send: true}) {
		t.Fatalf("a deleted number's drop of read: the screen left %+v, the runner %+v", f, c)
	}
	if co := p.outcome(p.runner.FlagsRaise(ctx, p.command(t, kc.OpItemFlagsRaise, admin, adminSub), goneConsole, target,
		[]string{kc.CanSend}, []string{kc.CanSend, kc.CanManage})); co != kc.CodeStateChanged {
		t.Fatalf("a deleted number's raise: the runner %s", co)
	}
	if fo, co := p.revoke(t, adminToken, goneFrame, target), remove(goneConsole, target); fo != kc.CodeNotFound || co != "ok" {
		t.Fatalf("a deleted number's removal: the screen %s, the runner %s", fo, co)
	}
}
