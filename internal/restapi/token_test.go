package restapi_test

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/thehappieco/kit/vectors"

	"whatserver2/internal/access"
	"whatserver2/internal/domain"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/restapi"
	"whatserver2/internal/store"
	"whatserver2/internal/tokentest"
	"whatserver2/internal/wa"
	"whatserver2/internal/wsapi"
)

// The token's one 401 on REST, and today's answer to a request with no
// usable credential.
const (
	tokenUnauthorized = `{"code":"unauthorized","message":"credential expired, revoked or invalid"}` + "\n"
	noCredential      = `{"code":"unauthorized","message":"a bearer session or API key is required"}` + "\n"
)

type tokenREST struct {
	w       *tokentest.World
	pool    *pgxpool.Pool
	handler *restapi.Handler
	mux     *http.ServeMux
	use     *access.TokenUse
	// running, when set, runs for each listed number that is online: a
	// seam between a request's first check and its last (finish).
	running func()
}

func newTokenREST(t *testing.T) *tokenREST {
	t.Helper()
	pool := pgtest.Fresh(t, migrate.Run)
	r := &tokenREST{w: tokentest.New(t, pool, uuid.Nil), pool: pool, mux: http.NewServeMux()}
	r.use = &access.TokenUse{Store: r.w.Tokens}
	users := store.NewUsers(pool)
	r.handler = &restapi.Handler{APIKeys: store.NewAPIKeys(pool), Users: users, Keys: store.NewKeys(pool), Devices: store.NewDevices(pool),
		Messages: store.NewMessages(pool), Contacts: store.NewContacts(pool), Receipts: store.NewReceipts(pool),
		Running: func(string) bool {
			if r.running != nil {
				r.running()
			}
			return false
		},
		Access: &access.Checker{Keys: store.NewAPIKeys(pool), Users: users, Tokens: r.w.Tokens,
			Switches: store.TokenSwitches{Default: true}, Use: r.use}}
	r.handler.Mount(r.mux)
	return r
}

// do serves one GET with the Authorization values given, set as they are.
func (r *tokenREST) do(t *testing.T, path string, auth ...string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if len(auth) > 0 {
		req.Header["Authorization"] = auth
	}
	rec := httptest.NewRecorder()
	r.mux.ServeHTTP(rec, req)
	if rec.Code == http.StatusUnauthorized && rec.Header().Get("WWW-Authenticate") != `Bearer realm="wappie"` {
		t.Fatalf("%s: a 401 without its challenge", path)
	}
	return rec.Code, rec.Body.String()
}

// message stores a message of kind type on device, with a body, a payload
// and, for an attachment, its sealed key, thumbnail and file name.
func (r *tokenREST) message(t *testing.T, device uuid.UUID, typ domain.Type) uuid.UUID {
	t.Helper()
	uid := uuid.New()
	in := store.InsertMessage{UID: uid, TenantID: r.w.Tenant, DeviceID: device, WAID: "wa-" + uid.String(), ChatKey: "5511999999999@s.whatsapp.net",
		TS: time.Now(), Kind: domain.KindMessage, Type: typ, Source: domain.SourceLive, BodySealed: []byte("sealed caption"),
		PayloadSealed: []byte("sealed payload")}
	if typ.HasMedia() {
		in.Media = &store.InsertMedia{MediaType: string(typ), MimeType: "image/jpeg", FileLength: 1234, MediaKeySealed: []byte("sealed key"),
			ThumbSealed: []byte("sealed thumb"), FileNameSealed: []byte("sealed name")}
	}
	if _, err := store.NewMessages(r.pool).Insert(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	return uid
}

func bearer(text string) []string { return []string{"Bearer " + text} }

// TestATokenLearnsNoNumberIdsOrExistenceOnREST (F8, the plan's 5.2): a
// token names a number by its full id only, and a number it cannot read,
// one that does not exist, a deleted one and another workspace's get the
// same 403, which holds no id; so do a message it cannot read and one that
// does not exist. Only the refusal on a number of its workspace is counted.
func TestATokenLearnsNoNumberIdsOrExistenceOnREST(t *testing.T) {
	r := newTokenREST(t)
	w := r.w
	readable, refused := w.Number("Vendas"), w.Number("Suporte")
	tok := w.Token(tokentest.Read(readable), tokentest.Send(refused))
	gone := w.Number("Antigo")
	goneTok := w.Token(tokentest.Read(gone))
	w.Delete(gone)
	foreign := uuid.New()
	w.Exec(`INSERT INTO tenants (id, name) VALUES ($1, 'other')`, foreign)
	other, err := store.NewDevices(r.pool).Create(context.Background(), foreign.String(), "Theirs", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	inRefused := r.message(t, refused, domain.TypeText)
	inReadable := r.message(t, readable, domain.TypeText)

	var device403 string
	for name, id := range map[string]string{"refused": refused.String(), "missing": uuid.NewString(), "another workspace's": other.ID, "deleted": gone.String()} {
		code, body := r.do(t, "/v1/devices/"+id+"/chats", bearer(tok.Text)...)
		if code != http.StatusForbidden || !strings.Contains(body, "this credential cannot access the device") {
			t.Fatalf("%s: %d %s", name, code, body)
		}
		if device403 != "" && body != device403 {
			t.Fatalf("%s answers apart: %s != %s", name, body, device403)
		}
		device403 = body
	}
	for name, id := range map[string]string{"a prefix": readable.String()[:8], "upper case": strings.ToUpper(readable.String())} {
		if code, body := r.do(t, "/v1/devices/"+id+"/chats", bearer(tok.Text)...); code != http.StatusBadRequest {
			t.Fatalf("%s: %d %s", name, code, body)
		}
	}
	if code, body := r.do(t, "/v1/devices/"+readable.String()+"/chats", bearer(tok.Text)...); code != http.StatusOK {
		t.Fatalf("the readable number: %d %s", code, body)
	}
	_, refusedMessage := r.do(t, "/v1/messages/"+inRefused.String(), bearer(tok.Text)...)
	code, missingMessage := r.do(t, "/v1/messages/"+uuid.NewString(), bearer(tok.Text)...)
	if code != http.StatusForbidden || refusedMessage != missingMessage || !strings.Contains(missingMessage, "cannot read the message") {
		t.Fatalf("the messages: %d %s / %s", code, refusedMessage, missingMessage)
	}
	if code, body := r.do(t, "/v1/messages/"+inRefused.String()+"/history", bearer(tok.Text)...); code != http.StatusForbidden || body != missingMessage {
		t.Fatalf("a refused history: %d %s", code, body)
	}
	if code, body := r.do(t, "/v1/messages/"+inReadable.String(), bearer(tok.Text)...); code != http.StatusOK {
		t.Fatalf("a readable message: %d %s", code, body)
	}
	if code, body := r.do(t, "/v1/devices/"+gone.String()+"/chats", bearer(goneTok.Text)...); code != http.StatusForbidden || body != device403 {
		t.Fatalf("a deleted number it read: %d %s", code, body)
	}
	// Its grants: only the number it reads, and nothing counted.
	code, body := r.do(t, "/v1/grants", bearer(tok.Text)...)
	var grants restapi.Grants
	if code != http.StatusOK || json.Unmarshal([]byte(body), &grants) != nil || len(grants.Grants.Grants) != 1 || grants.Grants.Grants[0].DeviceID != readable.String() {
		t.Fatalf("grants: %d %s", code, body)
	}
	if err := r.use.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := w.Refusals(tok)
	if len(got) != 1 || got[refused.String()+"/read=no_permission"] != 3 {
		t.Fatalf("the refusals: %v", got)
	}
	if got := w.Refusals(goneTok); len(got) != 0 {
		t.Fatalf("a deleted number counted: %v", got)
	}
}

// TestTokenListingAndReadNeedTheFlagAndAGrant: GET /v1/devices lists only
// the numbers a token reads, with its other flags; a send-only token lists
// and reads nothing; after a rotation the number goes from the listing and
// its reads are no_grant until it is sealed again.
func TestTokenListingAndReadNeedTheFlagAndAGrant(t *testing.T) {
	r := newTokenREST(t)
	w := r.w
	a, b := w.Number("Vendas"), w.Number("Suporte")
	tok := w.Token(tokentest.Read(a), tokentest.Manage(a), tokentest.Send(b))
	sendOnly := w.Token(tokentest.Send(a))
	var listed restapi.Devices
	code, body := r.do(t, "/v1/devices", bearer(tok.Text)...)
	if code != http.StatusOK || json.Unmarshal([]byte(body), &listed) != nil {
		t.Fatalf("%d %s", code, body)
	}
	if len(listed.Devices) != 1 || listed.Devices[0].ID != a.String() || !listed.Devices[0].CanManage || !listed.Devices[0].CanPause ||
		listed.Devices[0].CanSend || listed.Devices[0].ReaderReceiptMode != "" {
		t.Fatalf("the listing: %s", body)
	}
	if code, body := r.do(t, "/v1/devices", bearer(sendOnly.Text)...); code != http.StatusOK || strings.Contains(body, a.String()) {
		t.Fatalf("a send-only listing: %d %s", code, body)
	}
	if code, _ := r.do(t, "/v1/devices/"+a.String()+"/chats", bearer(sendOnly.Text)...); code != http.StatusForbidden {
		t.Fatalf("a send-only read: %d", code)
	}
	w.Rotate(a, 2)
	if code, body := r.do(t, "/v1/devices", bearer(tok.Text)...); code != http.StatusOK || strings.Contains(body, a.String()) {
		t.Fatalf("after a rotation: %d %s", code, body)
	}
	if code, _ := r.do(t, "/v1/devices/"+a.String()+"/chats", bearer(tok.Text)...); code != http.StatusForbidden {
		t.Fatalf("a read after a rotation: %d", code)
	}
	w.Seal(tok, a, 2)
	if code, _ := r.do(t, "/v1/devices/"+a.String()+"/chats", bearer(tok.Text)...); code != http.StatusOK {
		t.Fatalf("a read sealed again: %d", code)
	}
	if err := r.use.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := w.Refusals(tok); got[a.String()+"/read=no_grant"] != 1 || len(got) != 1 {
		t.Fatalf("the token's refusals: %v", got)
	}
	if got := w.Refusals(sendOnly); got[a.String()+"/read=no_permission"] != 1 || len(got) != 1 {
		t.Fatalf("the send-only refusals: %v", got)
	}
}

// TestRESTFinishComparesTheToken: a change that bumps no version between a
// request's first check and its last (a widening record) leaves the token
// equal and the answer goes; a narrowing between them gets 403.
func TestRESTFinishComparesTheToken(t *testing.T) {
	r := newTokenREST(t)
	w := r.w
	a, b := w.Number("Vendas"), w.Number("Suporte")
	w.ExecIn(`UPDATE devices SET status = 'online' WHERE id = $1`, a)
	tok := w.Token(tokentest.Read(a))
	r.running = func() {
		r.running = nil
		w.SetPerms(tok, tokentest.Read(a), tokentest.Send(b))
	}
	if code, body := r.do(t, "/v1/devices", bearer(tok.Text)...); code != http.StatusOK || !strings.Contains(body, a.String()) {
		t.Fatalf("a widening mid-request: %d %s", code, body)
	}
	r.running = func() {
		r.running = nil
		w.SetPerms(tok, tokentest.Read(a))
	}
	if code, body := r.do(t, "/v1/devices", bearer(tok.Text)...); code != http.StatusForbidden || !strings.Contains(body, "workspace access changed") {
		t.Fatalf("a narrowing mid-request: %d %s", code, body)
	}
	// A switch turned off mid-request bumps no version: the number is no
	// longer in the token's reads at the last check.
	r.running = func() {
		r.running = nil
		off := false
		w.Switches(&off, nil)
	}
	if code, body := r.do(t, "/v1/devices", bearer(tok.Text)...); code != http.StatusForbidden || !strings.Contains(body, "device access changed") {
		t.Fatalf("text off mid-request: %d %s", code, body)
	}
}

// TestRESTWithholdsAttachments: with the workspace's attachments switch off,
// a token reads a media row's envelope but not its caption, payload, key,
// thumbnail or file name, on every route that returns rows; a text row
// keeps its content; a key reads everything.
func TestRESTWithholdsAttachments(t *testing.T) {
	r := newTokenREST(t)
	w := r.w
	a := w.Number("Vendas")
	tok := w.Token(tokentest.Read(a))
	image := r.message(t, a, domain.TypeImage)
	text := r.message(t, a, domain.TypeText)
	yes, no := true, false
	w.Switches(&yes, &no)
	_, body := r.do(t, "/v1/messages/"+image.String(), bearer(tok.Text)...)
	var m restapi.Message
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatal(err)
	}
	if m.BodySealed != nil || m.PayloadSealed != nil || m.Media == nil || m.Media.MediaKeySealed != nil || m.Media.ThumbSealed != nil ||
		m.Media.FileNameSealed != nil || m.Withheld != wsapi.WithheldAttachments || m.Media.MimeType != "image/jpeg" || m.Media.FileLength != 1234 {
		t.Fatalf("the withheld row: %s", body)
	}
	_, body = r.do(t, "/v1/messages/"+text.String(), bearer(tok.Text)...)
	var textRow restapi.Message
	if err := json.Unmarshal([]byte(body), &textRow); err != nil || textRow.BodySealed == nil || textRow.Withheld != "" {
		t.Fatalf("a text row: %s", body)
	}
	for _, path := range []string{
		"/v1/devices/" + a.String() + "/messages?chat_key=5511999999999@s.whatsapp.net",
		"/v1/messages/" + image.String() + "/history",
		"/v1/devices/" + a.String() + "/messages/scan?from=2000-01-01T00:00:00Z&until=2100-01-01T00:00:00Z",
	} {
		code, body := r.do(t, path, bearer(tok.Text)...)
		if code != http.StatusOK || strings.Contains(body, `"media_key_sealed"`) || !strings.Contains(body, `"withheld":"attachments"`) {
			t.Fatalf("%s: %d %s", path, code, body)
		}
	}
	w.Switches(nil, nil)
	if _, body := r.do(t, "/v1/messages/"+image.String(), bearer(tok.Text)...); !strings.Contains(body, `"media_key_sealed"`) {
		t.Fatalf("attachments on: %s", body)
	}
}

// TestTodaysRESTBodiesStayByteForByte: a request with no thc_ gets today's
// exact answer; a key holding thc_ authenticates as a key.
func TestTodaysRESTBodiesStayByteForByte(t *testing.T) {
	r := newTokenREST(t)
	for name, auth := range map[string][]string{
		"no header": nil, "Bearer alone": {"Bearer"}, "two headers": {"Bearer a", "Bearer b"},
		"the comma pair": {"Bearer a, Bearer b"}, "Basic": {"Basic abc"},
	} {
		if code, body := r.do(t, "/v1/devices", auth...); code != http.StatusUnauthorized || body != noCredential {
			t.Errorf("%s: %d %q", name, code, body)
		}
	}
	if code, body := r.do(t, "/v1/devices", bearer("0a1b2c3d.wrong")...); code != http.StatusUnauthorized || body != tokenUnauthorized {
		t.Errorf("a wrong key: %d %q", code, body)
	}
	key := tokentest.KeyHolding(t, r.pool, r.w.Tenant, store.ScopeRead, "thc_")
	if code, body := r.do(t, "/v1/devices", bearer(key)...); code != http.StatusOK {
		t.Errorf("a key holding thc_: %d %s", code, body)
	}
}

type kitAuthorization struct {
	Tokens []struct {
		Name, Token, Selector, Hash string
	} `json:"tokens"`
	Refused []struct {
		Name, Token string
	} `json:"refused"`
	Authorization []struct {
		Name   string
		Values []string
		Valid  bool
	} `json:"authorization"`
}

func readKit(t *testing.T) kitAuthorization {
	t.Helper()
	raw, err := fs.ReadFile(vectors.FS, "platform/contract-v1/tokens.json")
	if err != nil {
		t.Fatal(err)
	}
	var v kitAuthorization
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// TestEveryAuthorizationVectorGetsItsPinnedBodyOnREST: the kit's tokens
// are live with their own selectors and hashes. Every authorization case
// marked valid authenticates, in any case of Bearer; every other one that
// holds thc_ gets the token 401; "no header" and "Bearer alone" get
// today's answer. Every refused text, sent as "Bearer <text>", gets the
// token 401 when it holds thc_ in some case, and today's answer otherwise.
// Two texts that share a secret authenticate each as its own token. Over a
// real connection Go trims a trailing space, and the token is accepted.
func TestEveryAuthorizationVectorGetsItsPinnedBodyOnREST(t *testing.T) {
	r := newTokenREST(t)
	w := r.w
	v := readKit(t)
	device := w.Number("Vendas")
	toks := map[string]*tokentest.Token{}
	for _, k := range v.Tokens {
		toks[k.Token] = w.TokenWith(k.Token, k.Selector, k.Hash, tokentest.Read(device))
	}
	for _, c := range v.Authorization {
		code, body := r.do(t, "/v1/devices", c.Values...)
		switch {
		case c.Valid:
			if code != http.StatusOK {
				t.Errorf("%s: %d %s", c.Name, code, body)
			}
		case c.Name == "no header" || c.Name == "Bearer alone":
			if code != http.StatusUnauthorized || body != noCredential {
				t.Errorf("%s: %d %q", c.Name, code, body)
			}
		default:
			if code != http.StatusUnauthorized || body != tokenUnauthorized {
				t.Errorf("%s: %d %q", c.Name, code, body)
			}
		}
	}
	for _, c := range v.Refused {
		code, body := r.do(t, "/v1/devices", "Bearer "+c.Token)
		want := tokenUnauthorized
		if c.Token == "" {
			want = noCredential
		}
		if code != http.StatusUnauthorized || body != want {
			t.Errorf("refused %q: %d %q", c.Name, code, body)
		}
	}
	// One secret, two selectors: each text is its own token.
	for text, tok := range toks {
		a, err := r.handler.Access.Authenticate(context.Background(), text)
		if err != nil || a.Token.ID != tok.ID {
			t.Errorf("%s authenticates as %+v (%v), want %s", tok.Selector, a.Token, err, tok.ID)
		}
	}
	// Over the wire, net/http trims the trailing space before the handler
	// reads the header.
	srv := httptest.NewServer(r.mux)
	defer srv.Close()
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := io.WriteString(conn, "GET /v1/devices HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer "+v.Tokens[0].Token+" \r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(conn)
	if err != nil || !strings.HasPrefix(string(reply), "HTTP/1.1 200") {
		t.Fatalf("a trailing space over the wire: %v %.200s", err, reply)
	}
}
