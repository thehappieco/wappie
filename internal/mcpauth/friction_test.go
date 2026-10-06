package mcpauth_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"whatserver2/internal/mailer"
	"whatserver2/internal/mcpauth"
	"whatserver2/internal/stepup"
)

// Fewer steps between an assistant and the archive (docs/mcp-enclave.md
// §19.35): the step-up the server holds every content write to, each
// workspace's own switches, reconnects that replace, the renewal notice and
// the notices in each person's language.

// stale moves the proof of the session behind token back by d.
func (h *harness) stale(t *testing.T, token string, d time.Duration) uuid.UUID {
	t.Helper()
	s, err := h.users.Session(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(context.Background(), `UPDATE sessions SET authenticated_at = now() - make_interval(secs => $2) WHERE id=$1`,
		s.ID, d.Seconds()); err != nil {
		t.Fatal(err)
	}
	return s.ID
}

// A content consent, an AI consent and a renewal are refused to a session
// whose person has not proved themselves in ten minutes, before anything is
// written or relayed; a metadata consent is not. A step-up lets them through.
func TestStepUpGuardsContentWrites(t *testing.T) {
	h := newAttestedHarness(t)
	h.contentOn.Store(true)
	owner := h.session(t, h.owner)
	session := h.stale(t, owner, 11*time.Minute)

	pub := randomKey(t)
	requestID := h.enclave.pendingKey(t, pub)
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/requests/"+requestID+"/prepare", prepareNonce(t, 32), nil), http.StatusOK, "")
	service, _, prefix := h.serviceFor(t, h.owner.ID, pub)
	body := contentBody(t, requestID, prefix, service)
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", body, bearer(owner)), http.StatusForbidden, stepup.Code)
	if h.enclave.bundle(requestID) != nil {
		t.Fatal("a refused consent reached the reader")
	}
	// The AI kind waits for it too, before its request is even looked at.
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", map[string]any{"kind": "ai"}, bearer(owner)), http.StatusForbidden, stepup.Code)
	// Metadata opens nothing and asks for nothing.
	h.approve(t, owner)

	if err := h.users.MarkStepUp(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	r := h.call(t, http.MethodPost, "/v1/mcp/connections", body, bearer(owner))
	id := created(t, r)
	a, _ := h.signedCall(t, http.MethodPost, "/v1/mcp/enclave/connections/"+id+"/activate", asEnclave(t))
	expect(t, a, http.StatusNoContent, "")

	// A renewal waits for it too, before its body is even read.
	rs, _ := h.signedCall(t, http.MethodPost, "/v1/mcp/enclave/connections/"+id+"/reseal", asEnclave(t))
	expect(t, rs, http.StatusNoContent, "")
	h.stale(t, owner, 11*time.Minute)
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections/"+id+"/renew", map[string]any{}, bearer(owner)), http.StatusForbidden, stepup.Code)

	// A checker of the handler's own is asked instead of the session's record.
	h.handler.StepUp = never{}
	fresh := h.session(t, h.owner)
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections/"+id+"/renew", map[string]any{}, bearer(fresh)), http.StatusForbidden, stepup.Code)
}

// A console token with text waits for the step-up too: refused before its
// row is written or its bundle relayed, while a metadata token asks for
// none; a step-up lets the same request through.
func TestStepUpGuardsTokenText(t *testing.T) {
	h := newClientsHarness(t)
	ctx := context.Background()
	h.verify(t, h.owner)
	h.activateTokens(t)
	h.contentOn.Store(true)
	session := h.stale(t, h.ownerToken, 11*time.Minute)

	requestID := h.tokenRequest(t, h.ownerToken)
	h.enclave.mu.Lock()
	pub, err := base64.RawURLEncoding.DecodeString(h.enclave.tokenRequests[requestID]["reader_public_key"].(string))
	h.enclave.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	service, _, prefix := h.serviceFor(t, h.owner.ID, pub)
	text := tokenBody(t, prefix)
	text["kind"], text["service_user_id"], text["key_mode"], text["consent_version"] = "content", service.String(), "ephemeral", 4
	text["expires_at"] = time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	bundle := "/v1/mcp/token-requests/" + requestID + "/bundle"
	expect(t, h.call(t, http.MethodPost, bundle, text, bearer(h.ownerToken)), http.StatusForbidden, stepup.Code)
	if listed, err := h.conns.List(ctx, h.tenant); err != nil || len(listed) != 0 {
		t.Fatalf("a refused token left rows: %d %v", len(listed), err)
	}
	h.enclave.mu.Lock()
	_, relayed := h.enclave.tokenBundles[requestID]
	h.enclave.mu.Unlock()
	if relayed {
		t.Fatal("a refused token reached the reader")
	}

	// Metadata opens nothing and asks for nothing.
	metadata := h.tokenRequest(t, h.ownerToken)
	_, metaPrefix := h.provisionalKey(t, "metadata token")
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/token-requests/"+metadata+"/bundle", tokenBody(t, metaPrefix), bearer(h.ownerToken)), http.StatusCreated, "")

	if err := h.users.MarkStepUp(ctx, session); err != nil {
		t.Fatal(err)
	}
	r := h.call(t, http.MethodPost, bundle, text, bearer(h.ownerToken))
	expect(t, r, http.StatusCreated, "")
	h.enclave.mu.Lock()
	got := h.enclave.tokenBundles[requestID]
	h.enclave.mu.Unlock()
	if got["kind"] != "content" {
		t.Fatalf("relayed = %v", got)
	}
}

// A reseal arms the renewal round's send on its own: the notice goes once
// the round settles, with no call from the maintenance loop.
func TestResealSendsTheRenewalNotice(t *testing.T) {
	h := newClientsHarness(t)
	h.contentOn.Store(true)
	h.verify(t, h.owner)
	box := &renewalBox{}
	h.handler.MailRenewal = box.send
	h.handler.SetRenewalDelay(2 * time.Second)
	id, _, _ := h.consentContent(t, h.owner)
	rs, _ := h.signedCall(t, http.MethodPost, "/v1/mcp/enclave/connections/"+id+"/reseal", asEnclave(t))
	expect(t, rs, http.StatusNoContent, "")
	// The round settled long ago, as far as the store can tell.
	if _, err := h.pool.Exec(context.Background(), `UPDATE mcp_connections SET resealed_at = now() - interval '5 minutes' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		box.mu.Lock()
		sent := len(box.sent)
		box.mu.Unlock()
		if sent == 1 {
			break
		}
		if sent > 1 || time.Now().After(deadline) {
			t.Fatalf("the reseal's timer sent %d notices", sent)
		}
		time.Sleep(50 * time.Millisecond)
	}
	box.mu.Lock()
	defer box.mu.Unlock()
	if got := box.sent[0]; got.to != h.owner.Email || len(got.n.Assistants) != 1 {
		t.Fatalf("notice = %+v", got)
	}
}

type never struct{}

func (never) Fresh(context.Context, uuid.UUID) (bool, error) { return false, nil }

// switchesHarness is the attested harness with each workspace's switches
// between the operator's gates and the handler, as main wires them.
func switchesHarness(t *testing.T, def bool) (*attestedHarness, *mcpauth.WorkspaceSwitches) {
	t.Helper()
	h := newAttestedHarness(t)
	operator := func(tenant uuid.UUID) bool { return tenant == h.tenant }
	sw := mcpauth.NewWorkspaceSwitches(h.conns, def, mcpauth.OperatorGates{Content: operator, Media: operator, Send: operator, AI: operator})
	if err := sw.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.handler.Workspaces = sw
	h.handler.ContentAllowed, h.handler.MediaAllowed, h.handler.SendAllowed, h.handler.AIAllowed = sw.Content, sw.Media, sw.Send, sw.AI
	return h, sw
}

type switchesReply struct {
	CanChange bool `json:"can_change"`
	Default   bool `json:"default"`
	Switches  struct {
		Text, Media, Send, AI *bool
	} `json:"switches"`
	Operator  struct{ Text, Media, Send, AI bool } `json:"operator"`
	Effective struct{ Text, Media, Send, AI bool } `json:"effective"`
}

func readSwitches(t *testing.T, h *attestedHarness, token string) switchesReply {
	t.Helper()
	r := h.call(t, http.MethodGet, "/v1/mcp/workspace", nil, bearer(token))
	expect(t, r, http.StatusOK, "")
	var out switchesReply
	r.into(t, &out)
	return out
}

// The owner switches what assistants may do in the workspace; anyone may
// look; the change reaches every gate at once, live connections included,
// and survives in the database for the next process.
func TestWorkspaceSwitchesRoute(t *testing.T) {
	h, sw := switchesHarness(t, false)
	owner := h.session(t, h.owner)
	admin := h.session(t, h.person(t, "admin"))
	member := h.session(t, h.person(t, "member"))

	got := readSwitches(t, h, owner)
	if !got.CanChange || got.Default || got.Switches.Text != nil || !got.Operator.Text || got.Effective.Text {
		t.Fatalf("a self-hosted default = %+v", got)
	}
	if enabled, _ := contentStatus(t, h.harness, owner); enabled {
		t.Fatal("text with every switch at its off default")
	}
	if readSwitches(t, h, admin).CanChange || readSwitches(t, h, member).CanChange {
		t.Fatal("a non-owner may change the switches")
	}
	on := map[string]any{"text": true, "media": false, "send": false, "ai": false}
	expect(t, h.call(t, http.MethodPut, "/v1/mcp/workspace", on, bearer(admin)), http.StatusForbidden, "not_authorized")
	expect(t, h.call(t, http.MethodPut, "/v1/mcp/workspace", map[string]any{"text": true}, bearer(owner)), http.StatusBadRequest, "bad_request")
	expect(t, h.call(t, http.MethodPut, "/v1/mcp/workspace", on, nil), http.StatusUnauthorized, "unauthorized")
	r := h.call(t, http.MethodPut, "/v1/mcp/workspace", on, bearer(owner))
	expect(t, r, http.StatusOK, "")
	if enabled, _ := contentStatus(t, h.harness, owner); !enabled {
		t.Fatal("the owner's switch did not reach the gate at once")
	}
	got = readSwitches(t, h, member)
	if got.Switches.Text == nil || !*got.Switches.Text || !got.Effective.Text || got.Effective.Media {
		t.Fatalf("after = %+v", got)
	}

	// A live connection follows the switch within the reader's check.
	id, _, _ := h.consentContent(t, h.owner)
	if s := h.standing(t, id); s.Status != "active" {
		t.Fatalf("standing = %+v", s)
	}
	off := map[string]any{"text": false, "media": false, "send": false, "ai": false}
	expect(t, h.call(t, http.MethodPut, "/v1/mcp/workspace", off, bearer(owner)), http.StatusOK, "")
	if s := h.standing(t, id); s.Status != "reseal" {
		t.Fatalf("text off: standing = %+v", s)
	}
	// Computed, never written: the consent survives, and is not renewable
	// while text is off.
	if listed := h.listed(t, owner, id); listed.Status != "active" || listed.Renewable {
		t.Fatalf("text off: listed = %+v", listed)
	}

	// Another process's change arrives with the next refresh; a refresh that
	// fails keeps what it had.
	if _, err := h.conns.SetWorkspaceSwitches(context.Background(), h.tenant, h.owner.ID, true, true, false, false); err != nil {
		t.Fatal(err)
	}
	if sw.Content(h.tenant) {
		t.Fatal("a change arrived before the refresh")
	}
	if err := sw.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !sw.Content(h.tenant) || !sw.Media(h.tenant) || sw.Send(h.tenant) || sw.AI(h.tenant) {
		t.Fatal("the refresh did not bring the change")
	}
	dead, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sw.Load(dead); err == nil {
		t.Fatal("a refresh with no database succeeded")
	}
	if !sw.Content(h.tenant) {
		t.Fatal("a failed refresh turned text off")
	}
	// The operator still comes first.
	if sw.Content(uuid.New()) {
		t.Fatal("a workspace the operator does not allow has text")
	}
}

// Wappie Cloud's default: every workspace on until its owner says, each
// switch riding on the one before it, and the platform's hook able to say
// no for one workspace.
func TestWorkspaceSwitchesDefaultOn(t *testing.T) {
	h, sw := switchesHarness(t, true)
	if !sw.Content(h.tenant) || !sw.Media(h.tenant) || !sw.Send(h.tenant) || !sw.AI(h.tenant) {
		t.Fatal("the cloud default is not on")
	}
	if _, err := h.conns.SetWorkspaceSwitches(context.Background(), h.tenant, h.owner.ID, false, true, true, true); err != nil {
		t.Fatal(err)
	}
	if err := sw.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if sw.Content(h.tenant) || sw.Media(h.tenant) || sw.Send(h.tenant) || sw.AI(h.tenant) {
		t.Fatal("attachments, drafts or AI without text")
	}
	if _, err := h.conns.SetWorkspaceSwitches(context.Background(), h.tenant, h.owner.ID, true, false, true, true); err != nil {
		t.Fatal(err)
	}
	if err := sw.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !sw.Content(h.tenant) || sw.Media(h.tenant) || !sw.Send(h.tenant) || sw.AI(h.tenant) {
		t.Fatal("AI without attachments, or drafts lost with them")
	}
	sw.Platform = func(uuid.UUID) bool { return false }
	if sw.Content(h.tenant) || sw.Send(h.tenant) {
		t.Fatal("the platform's hook did not gate")
	}
	got := readSwitches(t, h, h.session(t, h.owner))
	if !got.Default || got.Operator.Text || got.Effective.Text {
		t.Fatalf("with the platform saying no = %+v", got)
	}
}

// A reconnect that asks to replace ends the person's earlier connection of
// the same client when it activates, and tells the reader; one that does not
// ask, and a version-1 consent, replace nothing.
func TestReconnectReplaces(t *testing.T) {
	h := newClientsHarness(t)
	h.contentOn.Store(true)
	_, first := h.v2Content(t, testedWeb)
	firstID := created(t, h.call(t, http.MethodPost, "/v1/mcp/connections", first, bearer(h.ownerToken)))
	a, _ := h.signedCall(t, http.MethodPost, "/v1/mcp/enclave/connections/"+firstID+"/activate", asEnclave(t))
	expect(t, a, http.StatusNoContent, "")
	_, second := h.v2Content(t, testedWeb)
	secondID := created(t, h.call(t, http.MethodPost, "/v1/mcp/connections", second, bearer(h.ownerToken)))
	a, _ = h.signedCall(t, http.MethodPost, "/v1/mcp/enclave/connections/"+secondID+"/activate", asEnclave(t))
	expect(t, a, http.StatusNoContent, "")
	if h.client(t, h.ownerToken, firstID).Status != "active" {
		t.Fatal("a reconnect that did not ask replaced the first")
	}

	_, third := h.v2Content(t, testedWeb)
	third["replace"] = true
	thirdID := created(t, h.call(t, http.MethodPost, "/v1/mcp/connections", third, bearer(h.ownerToken)))
	if h.client(t, h.ownerToken, firstID).Status != "active" {
		t.Fatal("replaced before the activation")
	}
	a, _ = h.signedCall(t, http.MethodPost, "/v1/mcp/enclave/connections/"+thirdID+"/activate", asEnclave(t))
	expect(t, a, http.StatusNoContent, "")
	r := h.call(t, http.MethodGet, "/v1/mcp/connections", nil, bearer(h.ownerToken))
	var out struct {
		Connections []replacedRow `json:"connections"`
	}
	r.into(t, &out)
	for _, id := range []string{firstID, secondID} {
		i := slices.IndexFunc(out.Connections, func(c replacedRow) bool { return c.ID == id })
		if i < 0 || out.Connections[i].Status != "revoked" || out.Connections[i].RevokeReason == nil || *out.Connections[i].RevokeReason != "replaced" ||
			!out.Connections[i].Mine {
			t.Fatalf("%s = %+v", id, out.Connections)
		}
		if !slices.Contains(h.enclave.revocations(), id) {
			t.Fatalf("the reader was not told of %s", id)
		}
	}
	if h.client(t, h.ownerToken, thirdID).Status != "active" {
		t.Fatal("the reconnect itself ended")
	}

	// A version-1 descriptor's consent cannot ask.
	requestID, _ := h.reader.pending(t, "Claude", "claude.ai")
	_, prefix := h.provisionalKey(t, "v1")
	body := consent(requestID, prefix)
	body["sealed"], body["replace"] = sealed(t), true
	expect(t, h.call(t, http.MethodPost, "/v1/mcp/connections", body, bearer(h.ownerToken)), http.StatusBadRequest, "bad_request")
}

// replacedRow is what the replacement test reads of a listed connection.
type replacedRow struct {
	ID           string  `json:"id"`
	Status       string  `json:"status"`
	RevokeReason *string `json:"revoke_reason"`
	Mine         bool    `json:"mine"`
}

// renewalBox keeps the renewal notices a test's handler sent.
type renewalBox struct {
	mu   sync.Mutex
	sent []struct {
		to string
		n  mailer.MCPRenewal
	}
}

func (b *renewalBox) send(_ context.Context, to string, n mailer.MCPRenewal) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sent = append(b.sent, struct {
		to string
		n  mailer.MCPRenewal
	}{to, n})
	return nil
}

// A restart reseals; once the round settles, the person who consented gets
// one notice, in their language, naming the connections; a second round of
// sends in the same hours sends nothing more.
func TestRenewalNoticeSent(t *testing.T) {
	h := newClientsHarness(t)
	h.contentOn.Store(true)
	box := &renewalBox{}
	h.verify(t, h.owner)
	if _, err := h.users.SetLocale(context.Background(), h.owner.ID, "pt"); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for range 2 {
		id, _, _ := h.consentContent(t, h.owner)
		rs, _ := h.signedCall(t, http.MethodPost, "/v1/mcp/enclave/connections/"+id+"/reseal", asEnclave(t))
		expect(t, rs, http.StatusNoContent, "")
		ids = append(ids, id)
	}
	// Set after the reseals, so no timer of the round outlives the test.
	h.handler.MailRenewal = box.send
	h.handler.SendRenewalNotices(context.Background())
	if len(box.sent) != 0 {
		t.Fatal("a notice went before the round settled")
	}
	if _, err := h.pool.Exec(context.Background(), `UPDATE mcp_connections SET resealed_at = now() - interval '5 minutes' WHERE id = ANY($1::uuid[])`, ids); err != nil {
		t.Fatal(err)
	}
	h.handler.SendRenewalNotices(context.Background())
	h.handler.SendRenewalNotices(context.Background())
	if len(box.sent) != 1 {
		t.Fatalf("sent = %+v", box.sent)
	}
	got := box.sent[0]
	if got.to != h.owner.Email || got.n.Lang != "pt" || len(got.n.Assistants) != 2 || got.n.Workspace != "acme" || got.n.Since.IsZero() {
		t.Fatalf("notice = %+v", got)
	}
	// Neither is a console token: the e-mail names both as they are.
	if len(got.n.Tokens) != 2 || got.n.Tokens[0] || got.n.Tokens[1] {
		t.Fatalf("token marks = %v", got.n.Tokens)
	}
	if strings.Contains(strings.Join(got.n.Assistants, ","), "http") {
		t.Fatal("a notice names an address")
	}
}

// The new-assistant notice goes in each recipient's language.
func TestActivationNoticeLanguage(t *testing.T) {
	h := newClientsHarness(t)
	h.verify(t, h.owner)
	if _, err := h.users.SetLocale(context.Background(), h.owner.ID, "es"); err != nil {
		t.Fatal(err)
	}
	requestID, prefix := h.prepareV2(t, testedWeb)
	id := created(t, h.call(t, http.MethodPost, "/v1/mcp/connections", v2Body(t, requestID, prefix, testedWeb), bearer(h.ownerToken)))
	a, _ := h.signedCall(t, http.MethodPost, "/v1/mcp/enclave/connections/"+id+"/activate", asEnclave(t))
	expect(t, a, http.StatusNoContent, "")
	h.handler.WaitNotices()
	mails := h.mail.mails()
	if len(mails) != 1 || mails[0].n.Lang != "es" {
		t.Fatalf("mails = %+v", mails)
	}
}
