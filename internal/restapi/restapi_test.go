package restapi_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/domain"
	"whatserver2/internal/migrate"
	"whatserver2/internal/pg"
	"whatserver2/internal/pgtest"
	"whatserver2/internal/restapi"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
	"whatserver2/internal/wsapi"
)

type fixture struct {
	pool     *pgxpool.Pool
	api      *store.APIKeys
	users    *store.Users
	keys     *store.Keys
	devices  *store.Devices
	messages *store.Messages
	receipts *store.Receipts
	tenant   uuid.UUID
	device   uuid.UUID
	key      *seal.ContentKey
	private  seal.PrivateKey
	handler  *restapi.Handler
	srv      *httptest.Server
}

func setup(t *testing.T) *fixture {
	t.Helper()
	pool := pgtest.Fresh(t, migrate.Run)
	f := &fixture{pool: pool, api: store.NewAPIKeys(pool), users: store.NewUsers(pool), keys: store.NewKeys(pool), devices: store.NewDevices(pool), messages: store.NewMessages(pool), receipts: store.NewReceipts(pool)}
	ctx := context.Background()
	var unsafeRole bool
	if err := pool.QueryRow(ctx, `SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user`).Scan(&unsafeRole); err != nil || unsafeRole {
		t.Fatalf("tests require ordinary RLS role: %v %v", unsafeRole, err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO tenants(name) VALUES ('REST test') RETURNING id`).Scan(&f.tenant); err != nil {
		t.Fatal(err)
	}
	f.device = f.addDevice(t, f.tenant, "First number")
	pub, priv, err := seal.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	f.private = priv
	if err := f.keys.CreateArchiveKey(ctx, f.tenant, f.device, 1, pub); err != nil {
		t.Fatal(err)
	}
	_, err = f.keys.CreateContentKey(ctx, f.tenant, f.device, 1, func(id uint32) ([]byte, error) {
		var err error
		f.key, err = seal.NewContentKey(pub, f.tenant, f.device, 1, id)
		if err != nil {
			return nil, err
		}
		return f.key.Sealed, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	f.handler = &restapi.Handler{APIKeys: f.api, Users: f.users, Keys: f.keys, Devices: f.devices, Messages: f.messages, Receipts: f.receipts}
	f.handler.Mount(mux)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fixture) addDevice(t *testing.T, tenant uuid.UUID, label string) uuid.UUID {
	t.Helper()
	d, err := f.devices.Create(context.Background(), tenant.String(), label, wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	return uuid.MustParse(d.ID)
}
func (f *fixture) user(t *testing.T, role string) (store.User, string) {
	t.Helper()
	if role == "service" {
		u, err := f.users.CreateService(context.Background(), f.tenant, "rest-integration", make([]byte, 32))
		if err != nil {
			t.Fatal(err)
		}
		return u, ""
	}
	u, err := f.users.Create(context.Background(), store.NewUser{TenantID: f.tenant, Email: uuid.NewString() + "@rest.test", Role: role, AuthKey: "proof", KDFSalt: make([]byte, 16), KDFParams: store.DefaultKDFParams(), PublicKey: make([]byte, 32), WrappedUSK: []byte("wrapped")})
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := f.users.StartSession(context.Background(), u, "rest test")
	if err != nil {
		t.Fatal(err)
	}
	return u, token
}
func (f *fixture) token(t *testing.T, acting *uuid.UUID) string {
	t.Helper()
	token, err := f.api.IssueActingAs(context.Background(), f.tenant.String(), "read integration", store.ScopeRead, nil, acting)
	if err != nil {
		t.Fatal(err)
	}
	return token
}
func (f *fixture) grant(t *testing.T, user, device uuid.UUID) {
	t.Helper()
	if device != f.device {
		pub, _, err := seal.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		if err = f.keys.CreateArchiveKey(context.Background(), f.tenant, device, 1, pub); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.keys.PutGrant(context.Background(), store.Grant{TenantID: f.tenant, DeviceID: device, UserID: user, Epoch: 1, SealedDSK: []byte("sealed grant")}, nil); err != nil {
		t.Fatal(err)
	}
}
func (f *fixture) insert(t *testing.T, chat, id string, at time.Time, kind domain.Kind, target string) store.InsertResult {
	t.Helper()
	uid := uuid.New()
	sealed, err := f.key.Seal(seal.KindBody, f.tenant, uid, []byte("private message "+id))
	if err != nil {
		t.Fatal(err)
	}
	result, err := f.messages.Insert(context.Background(), store.InsertMessage{UID: uid, TenantID: f.tenant, DeviceID: f.device, WAID: id, ChatKey: chat, ChatPN: chat, TS: at, Kind: kind, Type: domain.TypeText, TargetWAID: target, Source: domain.SourceLive, ContentKeyID: 1, BodySealed: sealed})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func (f *fixture) get(t *testing.T, path, token string, want int, into any) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, f.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var raw json.RawMessage
	if err := json.NewDecoder(res.Body).Decode(&raw); err != nil {
		t.Fatalf("decode %s status%d: %v", path, res.StatusCode, err)
	}
	if res.StatusCode != want {
		t.Fatalf("%s got %d want %d: %s", path, res.StatusCode, want, raw)
	}
	if res.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("private response cacheable: %s", path)
	}
	if into != nil {
		if err := json.Unmarshal(raw, into); err != nil {
			t.Fatal(err)
		}
	}
	if want == http.StatusOK && path != "/v1/openapi.json" {
		var body struct {
			TenantID string `json:"tenant_id"`
		}
		if err := json.Unmarshal(raw, &body); err != nil || body.TenantID != f.tenant.String() {
			t.Fatalf("wrong workspace: %+v %v", body, err)
		}
	}
	return string(raw)
}

func TestDeviceAndContentPermissions(t *testing.T) {
	f := setup(t)
	owner, ownerToken := f.user(t, "owner")
	member, memberToken := f.user(t, "member")
	f.grant(t, owner.ID, f.device)
	other := f.addDevice(t, f.tenant, "Hidden number")
	row := f.insert(t, "5511000000001@s.whatsapp.net", "one", time.Now(), domain.KindMessage, "")
	var list wsapi.Devices
	f.get(t, "/v1/devices", "", 401, nil)
	f.get(t, "/v1/devices", memberToken, 200, &list)
	if len(list.Devices) != 0 {
		t.Fatal("member saw ungranted devices")
	}
	f.get(t, "/v1/devices", ownerToken, 200, &list)
	if len(list.Devices) != 2 {
		t.Fatal("owner directory missing registered devices")
	}
	f.get(t, "/v1/messages/"+row.UID.String(), memberToken, 403, nil)
	f.get(t, "/v1/devices/"+other.String()+"/keys?ids=1", ownerToken, 403, nil)
	f.grant(t, member.ID, f.device)
	f.get(t, "/v1/devices", memberToken, 200, &list)
	if len(list.Devices) != 1 || list.Devices[0].ID != f.device.String() {
		t.Fatalf("wrong directory: %+v", list)
	}
	var msg wsapi.SealedMessage
	raw := f.get(t, "/v1/messages/"+row.UID.String(), memberToken, 200, &msg)
	if strings.Contains(raw, "private message") {
		t.Fatal("plaintext crossed REST")
	}
	if opened, err := f.key.Open(seal.KindBody, f.tenant, row.UID, msg.BodySealed); err != nil || string(opened) != "private message one" {
		t.Fatalf("ciphertext changed: %s %v", opened, err)
	}
	var keys wsapi.Keys
	f.get(t, "/v1/devices/"+f.device.String()+"/keys?ids=1,999", memberToken, 200, &keys)
	if keys.ArchiveTenantID != f.tenant.String() || len(keys.Keys) != 1 || keys.Keys[0].ID != 1 {
		t.Fatalf("keys: %+v", keys)
	}
	if _, err := seal.OpenContentKey(f.private, f.tenant, f.device, 1, keys.Keys[0].Sealed); err != nil {
		t.Fatal(err)
	}
	if err := f.keys.RevokeGrant(context.Background(), f.tenant, f.device, member.ID); err != nil {
		t.Fatal(err)
	}
	f.get(t, "/v1/messages/"+row.UID.String(), memberToken, 403, nil)
	f.get(t, "/v1/devices/"+f.device.String()+"/keys?ids=1", memberToken, 403, nil)
}

func TestRestrictedServiceKeyGrantsAndRevocation(t *testing.T) {
	f := setup(t)
	service, _ := f.user(t, "service")
	other := f.addDevice(t, f.tenant, "Restricted number")
	f.grant(t, service.ID, f.device)
	f.grant(t, service.ID, other)
	token := f.token(t, &service.ID)
	verified, err := f.api.VerifyScoped(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if err := pg.InTenantTx(context.Background(), f.pool, f.tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `INSERT INTO api_key_devices(api_key_id,device_id) VALUES($1,$2)`, verified.ID, f.device)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var list wsapi.Devices
	f.get(t, "/v1/devices", token, 200, &list)
	if len(list.Devices) != 1 {
		t.Fatalf("whitelist ignored: %+v", list)
	}
	var grants wsapi.Grants
	f.get(t, "/v1/grants", token, 200, &grants)
	if grants.UserID != service.ID.String() || len(grants.Grants) != 1 || grants.Grants[0].DeviceID != f.device.String() {
		t.Fatalf("grants bypassed whitelist: %+v", grants)
	}
	f.get(t, "/v1/devices/"+other.String()+"/chats", token, 403, nil)
	f.get(t, "/v1/grants", f.token(t, nil), 403, nil)
	if err := pg.InTenantTx(context.Background(), f.pool, f.tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `DELETE FROM api_key_devices WHERE api_key_id=$1`, verified.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	f.get(t, "/v1/devices", token, 200, &list)
	if len(list.Devices) != 0 {
		t.Fatal("empty whitelist expanded access")
	}
	f.get(t, "/v1/grants", token, 200, &grants)
	if len(grants.Grants) != 0 {
		t.Fatal("grants retained after empty whitelist")
	}
	if err := f.api.Revoke(context.Background(), f.tenant.String(), verified.Prefix); err != nil {
		t.Fatal(err)
	}
	f.get(t, "/v1/devices", token, 401, nil)
}

func TestRESTPageHistoryAndValidation(t *testing.T) {
	f := setup(t)
	token := f.token(t, nil)
	at := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	chat := "5511000000001@s.whatsapp.net"
	for i := range 5 {
		f.insert(t, chat, fmt.Sprintf("burst-%d", i), at, domain.KindMessage, "")
	}
	root := f.insert(t, chat, "original", at.Add(time.Second), domain.KindMessage, "")
	f.insert(t, chat, "edited", at.Add(2*time.Second), domain.KindEdit, "original")
	f.insert(t, "5511000000002@s.whatsapp.net", "second-chat", at.Add(time.Second), domain.KindMessage, "")
	base := "/v1/devices/" + f.device.String() + "/messages?chat_key=" + url.QueryEscape(chat) + "&limit=2"
	seen := map[string]bool{}
	next := base
	for range 5 {
		var page wsapi.Page
		f.get(t, next, token, 200, &page)
		for _, row := range page.Messages {
			if seen[row.UID] {
				t.Fatal("duplicate page row")
			}
			seen[row.UID] = true
		}
		if !page.HasMore {
			break
		}
		if page.NextTS == nil || page.NextSeq <= 0 {
			t.Fatal("missing pagination cursor")
		}
		next = base + "&before_ts=" + url.QueryEscape(page.NextTS.Format(time.RFC3339Nano)) + fmt.Sprintf("&before_seq=%d", page.NextSeq)
	}
	if len(seen) != 7 {
		t.Fatalf("pagination lost rows: %d", len(seen))
	}
	var history restapi.History
	f.get(t, "/v1/messages/"+root.UID.String()+"/history", token, 200, &history)
	if len(history.Versions) != 2 || history.Versions[1].Message.WAID != "edited" || history.RequestedUID != root.UID.String() {
		t.Fatalf("history: %+v", history)
	}
	var chats struct {
		wsapi.Chats
		Limit     int  `json:"limit"`
		Truncated bool `json:"truncated"`
	}
	f.get(t, "/v1/devices/"+f.device.String()+"/chats?limit=1", token, 200, &chats)
	if len(chats.Chats.Chats) != 1 || !chats.Truncated || chats.Limit != 1 {
		t.Fatalf("truncation not disclosed: %+v", chats)
	}
	for _, path := range []string{base + "&before_seq=3", base + "&before_ts=invalid&before_seq=3", base + "&limit=201", "/v1/devices/" + f.device.String() + "/messages", "/v1/devices/" + f.device.String() + "/keys?ids=0", "/v1/devices/" + f.device.String() + "/keys?ids=abc", "/v1/messages/not-a-uuid", "/v1/devices/" + f.device.String()[:8] + "/chats"} {
		f.get(t, path, token, 400, nil)
	}
	var foreign uuid.UUID
	if err := f.pool.QueryRow(context.Background(), `INSERT INTO tenants(name) VALUES ('foreign') RETURNING id`).Scan(&foreign); err != nil {
		t.Fatal(err)
	}
	foreignDevice := f.addDevice(t, foreign, "Foreign")
	f.get(t, "/v1/devices/"+foreignDevice.String()+"/chats", token, 404, nil)
	f.get(t, "/v1/messages/"+uuid.NewString(), token, 404, nil)
	if _, err := f.pool.Exec(context.Background(), `UPDATE tenants SET status='suspended' WHERE id=$1`, f.tenant); err != nil {
		t.Fatal(err)
	}
	f.get(t, "/v1/devices", token, 401, nil)
}

func TestRESTReadScopeAndPausedStorage(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	row := f.insert(t, "friend", "paused", time.Now(), domain.KindMessage, "")
	readToken := f.token(t, nil)
	sendToken, err := f.api.IssueScoped(ctx, f.tenant.String(), "send only", store.ScopeSend, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Scopes are hierarchical: send includes read. A read key must never
	// advertise send or administration capabilities in the directory.
	var devices wsapi.Devices
	f.get(t, "/v1/devices", readToken, 200, &devices)
	if len(devices.Devices) != 1 || devices.Devices[0].CanSend || devices.Devices[0].CanManage {
		t.Fatalf("read scope advertised write capabilities: %+v", devices)
	}
	f.get(t, "/v1/devices", sendToken, 200, &devices)
	if len(devices.Devices) != 1 || !devices.Devices[0].CanSend || devices.Devices[0].CanManage {
		t.Fatalf("send scope capabilities wrong: %+v", devices)
	}
	f.get(t, "/v1/messages/"+row.UID.String(), sendToken, 200, nil)
	if err := f.devices.SetPaused(ctx, f.tenant.String(), f.device.String(), true); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE tenants SET storage_paused_at=now() WHERE id=$1`, f.tenant); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v1/devices", "/v1/messages/" + row.UID.String(), "/v1/messages/" + row.UID.String() + "/history", "/v1/devices/" + f.device.String() + "/keys?ids=1", "/v1/devices/" + f.device.String() + "/messages?chat_key=friend"} {
		f.get(t, path, readToken, 200, nil)
	}
	var paused bool
	if err := f.pool.QueryRow(ctx, `SELECT storage_paused_at IS NOT NULL FROM tenants WHERE id=$1`, f.tenant).Scan(&paused); err != nil || !paused {
		t.Fatalf("reading changed capture suspension: %v %v", paused, err)
	}
}

func TestRESTTransferKeepsOriginalCryptographicNamespace(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	owner, oldToken := f.user(t, "owner")
	f.grant(t, owner.ID, f.device)
	row := f.insert(t, "friend", "move", time.Now(), domain.KindMessage, "")
	archiveTenant := f.tenant
	var personal uuid.UUID
	if err := f.pool.QueryRow(ctx, `SELECT id FROM tenants WHERE personal_owner_id=$1`, owner.ID).Scan(&personal); err != nil {
		t.Fatal(err)
	}
	if err := f.devices.SetPaused(ctx, f.tenant.String(), f.device.String(), true); err != nil {
		t.Fatal(err)
	}
	if _, err := f.devices.TransferPersonal(ctx, f.tenant, owner.ID, f.device, personal); err != nil {
		t.Fatal(err)
	}
	f.get(t, "/v1/messages/"+row.UID.String(), oldToken, 404, nil)
	f.get(t, "/v1/devices/"+f.device.String()+"/keys?ids=1", oldToken, 404, nil)
	f.tenant = personal
	user, err := f.users.Get(ctx, personal, owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := f.users.StartSession(ctx, user, "personal REST test")
	if err != nil {
		t.Fatal(err)
	}
	var msg restapi.Message
	f.get(t, "/v1/messages/"+row.UID.String(), token, 200, &msg)
	var keys restapi.Keys
	f.get(t, "/v1/devices/"+f.device.String()+"/keys?ids=1", token, 200, &keys)
	if keys.ArchiveTenantID != archiveTenant.String() || len(keys.Keys.Keys) != 1 {
		t.Fatalf("wrong keys namespace: %+v", keys)
	}
	key, err := seal.OpenContentKey(f.private, archiveTenant, f.device, 1, keys.Keys.Keys[0].Sealed)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := key.Open(seal.KindBody, archiveTenant, row.UID, msg.BodySealed)
	if err != nil || string(opened) != "private message move" {
		t.Fatalf("moved archive no longer decrypts: %s %v", opened, err)
	}
	var grants restapi.Grants
	f.get(t, "/v1/grants", token, 200, &grants)
	if len(grants.Grants.Grants) != 1 || grants.Grants.Grants[0].ArchiveTenantID != archiveTenant.String() {
		t.Fatalf("wrong grant namespace: %+v", grants)
	}
}

func TestRESTRevalidatesCredentialBeforePublishing(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	token := f.token(t, nil)
	verified, err := f.api.VerifyScoped(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if err := pg.InTenantTx(ctx, f.pool, f.tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE devices SET status='online' WHERE id=$1`, f.device)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// Running is evaluated after the directory query and its permission checks.
	// Revoke at this deterministic point to test the final authentication check.
	f.handler.Running = func(string) bool {
		if err := f.api.Revoke(ctx, f.tenant.String(), verified.Prefix); err != nil {
			t.Error(err)
		}
		return true
	}
	f.get(t, "/v1/devices", token, 401, nil)
}

func TestRESTPaginationUsesCreationTimeWithoutChangingMissingTimestamp(t *testing.T) {
	f := setup(t)
	token := f.token(t, nil)
	at := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	older := f.insert(t, "friend", "older", at.Add(-time.Second), domain.KindMessage, "")
	middle := f.insert(t, "friend", "missing-time", at, domain.KindMessage, "")
	newer := f.insert(t, "friend", "newer", at.Add(time.Second), domain.KindMessage, "")
	if err := pg.InTenantTx(context.Background(), f.pool, f.tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `UPDATE messages SET ts=NULL,created_at=$2 WHERE uid=$1`, middle.UID, at)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	base := "/v1/devices/" + f.device.String() + "/messages?chat_key=friend&limit=2"
	var page wsapi.Page
	f.get(t, base, token, 200, &page)
	if !page.HasMore || len(page.Messages) != 2 || page.Messages[0].UID != middle.UID.String() || page.Messages[1].UID != newer.UID.String() {
		t.Fatalf("wrong first page: %+v", page)
	}
	if page.Messages[0].TS != nil {
		t.Fatal("fallback invented a sender timestamp")
	}
	if page.NextTS == nil || !page.NextTS.Equal(at) || page.NextSeq != middle.Seq {
		t.Fatalf("missing effective sort cursor: %+v", page)
	}
	f.get(t, base+"&before_ts="+url.QueryEscape(page.NextTS.Format(time.RFC3339Nano))+fmt.Sprintf("&before_seq=%d", page.NextSeq), token, 200, &page)
	if page.HasMore || len(page.Messages) != 1 || page.Messages[0].UID != older.UID.String() {
		t.Fatalf("older rows lost: %+v", page)
	}
}

func TestRESTUsesExistingWireCiphertext(t *testing.T) {
	// A byte fixture is useful here: encoding must stay Go/SDK interoperable,
	// and an HTTP layer must never accidentally stringify raw binary data.
	f := setup(t)
	token := f.token(t, nil)
	row := f.insert(t, "5511000000001@s.whatsapp.net", "sealed", time.Now(), domain.KindMessage, "")
	var body struct {
		Body string `json:"body_sealed"`
	}
	f.get(t, "/v1/messages/"+row.UID.String(), token, 200, &body)
	raw, err := base64.StdEncoding.DecodeString(body.Body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.key.Open(seal.KindBody, f.tenant, row.UID, raw); err != nil {
		t.Fatal(err)
	}
}
