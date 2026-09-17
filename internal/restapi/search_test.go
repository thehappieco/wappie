package restapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"whatserver2/internal/crypto/seal"
	"whatserver2/internal/domain"
	"whatserver2/internal/pg"
	"whatserver2/internal/store"
	"whatserver2/internal/wsapi"
)

type contactPage struct {
	wsapi.Contacts
	HasMore bool   `json:"has_more"`
	NextKey string `json:"next_key"`
}
type scanRow struct {
	wsapi.SealedMessage
	OrderTS time.Time `json:"order_ts"`
}
type scanPage struct {
	DeviceID string     `json:"device_id"`
	From     time.Time  `json:"from"`
	Until    time.Time  `json:"until"`
	Messages []scanRow  `json:"messages"`
	HasMore  bool       `json:"has_more"`
	NextTS   *time.Time `json:"next_ts"`
	NextSeq  int64      `json:"next_seq"`
}

func scanPath(device uuid.UUID, from, until time.Time) string {
	return "/v1/devices/" + device.String() + "/messages/scan?from=" + url.QueryEscape(from.Format(time.RFC3339Nano)) + "&until=" + url.QueryEscape(until.Format(time.RFC3339Nano))
}
func TestRESTContactsPageIsSealedAndComplete(t *testing.T) {
	f := setup(t)
	contacts := store.NewContacts(f.pool)
	token := f.token(t, nil)
	ctx := context.Background()
	for i, key := range []string{"100@s.whatsapp.net", "200@lid", "300@g.us"} {
		var sealed []byte
		if i < 2 {
			var err error
			sealed, err = f.key.Seal(seal.KindFullName, f.tenant, store.ContactUID(f.device, key), []byte("Private contact"))
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := contacts.Upsert(ctx, store.ContactName{TenantID: f.tenant, DeviceID: f.device, ContactKey: key, FullNameSealed: sealed, ContentKeyID: 1, IsGroup: i == 2}); err != nil {
			t.Fatal(err)
		}
	}
	base := "/v1/devices/" + f.device.String() + "/contacts?limit=2"
	var page contactPage
	raw := f.get(t, base, token, 200, &page)
	if strings.Contains(raw, "Private contact") || len(page.Contacts.Contacts) != 2 || !page.HasMore || page.NextKey != "200@lid" || page.DeviceID != f.device.String() {
		t.Fatalf("wrong contacts page: %s", raw)
	}
	stored, err := contacts.List(ctx, f.tenant, f.device, 10)
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range page.Contacts.Contacts {
		if c.UID != stored[i].UID.String() || !reflect.DeepEqual(c.FullNameSealed, stored[i].FullNameSealed) {
			t.Fatal("contact ciphertext or identity changed")
		}
		if opened, err := f.key.Open(seal.KindFullName, f.tenant, stored[i].UID, c.FullNameSealed); err != nil || string(opened) != "Private contact" {
			t.Fatal("contact cannot be opened")
		}
	}
	page = contactPage{}
	f.get(t, base+"&after_key=200%40lid", token, 200, &page)
	if page.HasMore || page.NextKey != "" || len(page.Contacts.Contacts) != 1 || page.Contacts.Contacts[0].ContactKey != "300@g.us" || len(page.Contacts.Contacts[0].FullNameSealed) != 0 {
		t.Fatalf("wrong final page: %+v", page)
	}
	for _, query := range []string{"limit=501", "after_key=", "after_key=a&after_key=b", "unknown=x"} {
		f.get(t, "/v1/devices/"+f.device.String()+"/contacts?"+query, token, 400, nil)
	}
}
func TestRESTDeviceScanRangeTiesMissingTimestampAndControls(t *testing.T) {
	f := setup(t)
	token := f.token(t, nil)
	from := time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)
	until := from.Add(time.Hour)
	f.insert(t, "a", "before", from.Add(-time.Microsecond), domain.KindMessage, "")
	first := f.insert(t, "a", "included", from, domain.KindMessage, "")
	f.insert(t, "a", "edit", from.Add(time.Minute), domain.KindEdit, "included")
	f.insert(t, "a", "delete", from.Add(2*time.Minute), domain.KindDelete, "included")
	f.insert(t, "a", "reaction", from.Add(3*time.Minute), domain.KindReaction, "included")
	for i := range 3 {
		f.insert(t, "b", fmt.Sprintf("tie-%d", i), from.Add(4*time.Minute), domain.KindMessage, "")
	}
	missing := f.insert(t, "c", "missing", from.Add(4*time.Minute), domain.KindMessage, "")
	if err := pg.InTenantTx(context.Background(), f.pool, f.tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `UPDATE messages SET ts=NULL,created_at=$2 WHERE uid=$1`, missing.UID, from.Add(4*time.Minute))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	f.insert(t, "a", "excluded", until, domain.KindMessage, "")
	base := scanPath(f.device, from, until) + "&limit=2"
	next := base
	seen := map[string]bool{}
	kinds := map[string]bool{}
	for range 10 {
		var page scanPage
		raw := f.get(t, next, token, 200, &page)
		if strings.Contains(raw, "private message") || page.DeviceID != f.device.String() || !page.From.Equal(from) || !page.Until.Equal(until) {
			t.Fatalf("bad scan envelope: %s", raw)
		}
		for i, row := range page.Messages {
			if seen[row.UID] || row.OrderTS.Before(from) || !row.OrderTS.Before(until) {
				t.Fatalf("duplicate or out-of-range row: %+v", row)
			}
			if i > 0 && (row.OrderTS.Before(page.Messages[i-1].OrderTS) || row.OrderTS.Equal(page.Messages[i-1].OrderTS) && row.Seq <= page.Messages[i-1].Seq) {
				t.Fatal("page not oldest first")
			}
			if row.UID == missing.UID.String() && row.TS != nil {
				t.Fatal("invented missing sender timestamp")
			}
			seen[row.UID] = true
			kinds[row.Kind] = true
		}
		if !page.HasMore {
			if page.NextTS != nil || page.NextSeq != 0 {
				t.Fatal("final page advertised cursor")
			}
			break
		}
		if page.NextTS == nil || page.NextSeq < 1 || len(page.Messages) == 0 || !page.NextTS.Equal(page.Messages[0].OrderTS) || page.NextSeq != page.Messages[0].Seq {
			t.Fatal("wrong scan cursor")
		}
		next = base + "&before_ts=" + url.QueryEscape(page.NextTS.Format(time.RFC3339Nano)) + fmt.Sprintf("&before_seq=%d", page.NextSeq)
	}
	if len(seen) != 8 || !seen[first.UID.String()] || !seen[missing.UID.String()] || len(kinds) != 4 {
		t.Fatalf("lost archive rows: %d %+v", len(seen), kinds)
	}
	var history wsapi.History
	f.get(t, "/v1/messages/"+first.UID.String()+"/history", token, 200, &history)
	if len(history.Versions) != 2 || history.Deletion == nil {
		t.Fatal("scan changed preserved revision/deletion history")
	}
	for _, query := range []string{"&from=2026-01-01T00:00:00Z", "&direction=sideways", "&kind=unknown", "&type=unknown", "&sender_keys=a,b,c,d", "&sender_keys=a,,b", "&chat_key=", "&before_seq=1", "&before_ts=no&before_seq=1", "&limit=201"} {
		f.get(t, base+query, token, 400, nil)
	}
	f.get(t, "/v1/devices/"+f.device.String()+"/messages/scan", token, 400, nil)
	f.get(t, scanPath(f.device, until, from), token, 400, nil)
}
func TestRESTDeviceScanFiltersAliasesAndPermissions(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	token := f.token(t, nil)
	from := time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)
	until := from.Add(time.Hour)
	pn := "15551234567@s.whatsapp.net"
	lid := "12345@lid"
	a := f.insert(t, pn, "pn", from, domain.KindMessage, "")
	b := f.insert(t, lid, "lid", from, domain.KindMessage, "")
	c := f.insert(t, "group@g.us", "group", from, domain.KindMessage, "")
	if err := pg.InTenantTx(ctx, f.pool, f.tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE chats SET chat_pn=$2 WHERE device_id=$1 AND chat_key=$3`, f.device, pn, lid)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE messages SET sender_key=$2 WHERE uid=$1`, a.UID, pn)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE messages SET sender_key=$2,sender_pn=$3,is_from_me=true,type='image' WHERE uid=$1`, b.UID, lid, pn)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE messages SET sender_lid=$2 WHERE uid=$1`, c.UID, lid)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	base := scanPath(f.device, from, until)
	cases := []struct {
		query string
		ids   []string
	}{
		{"&sender_keys=" + url.QueryEscape(pn), []string{a.UID.String(), b.UID.String()}},
		{"&sender_keys=" + url.QueryEscape(pn+","+lid), []string{a.UID.String(), b.UID.String(), c.UID.String()}},
		{"&sender_keys=12345", []string{}},
		{"&chat_key=" + url.QueryEscape(lid), []string{a.UID.String(), b.UID.String()}},
		{"&direction=outgoing&type=image&kind=message&chat_key=" + url.QueryEscape(pn), []string{b.UID.String()}},
		{"&direction=incoming", []string{a.UID.String(), c.UID.String()}},
	}
	for _, tc := range cases {
		var page scanPage
		f.get(t, base+tc.query, token, 200, &page)
		got := []string{}
		for _, m := range page.Messages {
			got = append(got, m.UID)
		}
		if !reflect.DeepEqual(got, tc.ids) {
			t.Fatalf("%s got %v want %v", tc.query, got, tc.ids)
		}
	}
	owner, _ := f.user(t, "owner")
	f.grant(t, owner.ID, f.device)
	service, _ := f.user(t, "service")
	other := f.addDevice(t, f.tenant, "Other")
	f.grant(t, service.ID, f.device)
	f.grant(t, service.ID, other)
	scoped := f.token(t, &service.ID)
	verified, err := f.api.VerifyScoped(ctx, scoped)
	if err != nil {
		t.Fatal(err)
	}
	if err := pg.InTenantTx(ctx, f.pool, f.tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO api_key_devices(api_key_id,device_id) VALUES($1,$2)`, verified.ID, f.device)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{scanPath(other, from, until), "/v1/devices/" + other.String() + "/contacts"} {
		f.get(t, path, scoped, 403, nil)
	}
	var foreign uuid.UUID
	if err := f.pool.QueryRow(ctx, `INSERT INTO tenants(name) VALUES('Foreign scan') RETURNING id`).Scan(&foreign); err != nil {
		t.Fatal(err)
	}
	foreignDevice := f.addDevice(t, foreign, "Foreign")
	for _, path := range []string{scanPath(foreignDevice, from, until), "/v1/devices/" + foreignDevice.String() + "/contacts"} {
		f.get(t, path, token, 404, nil)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE tenants SET storage_paused_at=now() WHERE id=$1`, f.tenant); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{base, "/v1/devices/" + f.device.String() + "/contacts"} {
		f.get(t, path, scoped, 200, nil)
	}
	if err := f.keys.RevokeGrant(ctx, f.tenant, f.device, service.ID); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{base, "/v1/devices/" + f.device.String() + "/contacts"} {
		f.get(t, path, scoped, 403, nil)
	}
}

func TestRESTScanNanosecondBoundsPreserveStoredMicroseconds(t *testing.T) {
	f := setup(t)
	token := f.token(t, nil)
	at := time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)
	f.insert(t, "one", "before", at, domain.KindMessage, "")
	included := f.insert(t, "two", "included", at.Add(time.Microsecond), domain.KindMessage, "")
	f.insert(t, "two", "after", at.Add(2*time.Microsecond), domain.KindMessage, "")
	var page scanPage
	f.get(t, scanPath(f.device, at.Add(time.Nanosecond), at.Add(time.Microsecond+time.Nanosecond)), token, 200, &page)
	if len(page.Messages) != 1 || page.Messages[0].UID != included.UID.String() {
		t.Fatalf("nanosecond bounds lost half-open meaning: %+v", page)
	}
	base := scanPath(f.device, at, at.Add(time.Second))
	f.get(t, base+"&before_ts="+url.QueryEscape(at.Add(time.Microsecond+time.Nanosecond).Format(time.RFC3339Nano))+"&before_seq=1", token, 200, &page)
	if len(page.Messages) != 2 || page.Messages[1].UID != included.UID.String() {
		t.Fatalf("nanosecond cursor lost earlier microsecond: %+v", page)
	}
}

func TestRESTNewReadsRevalidateAccessAfterBlockedQuery(t *testing.T) {
	for _, table := range []string{"contacts", "messages"} {
		t.Run(table, func(t *testing.T) {
			f := setup(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			owner, _ := f.user(t, "owner")
			f.grant(t, owner.ID, f.device)
			reader, _ := f.user(t, "service")
			f.grant(t, reader.ID, f.device)
			token := f.token(t, &reader.ID)
			verified, err := f.api.VerifyScoped(ctx, token)
			if err != nil {
				t.Fatal(err)
			}
			at := time.Now().UTC()
			f.insert(t, "one", "blocked", at, domain.KindMessage, "")
			path := "/v1/devices/" + f.device.String() + "/contacts"
			if table == "messages" {
				path = scanPath(f.device, at.Add(-time.Hour), at.Add(time.Hour))
			}
			blocker, err := f.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer blocker.Rollback(context.Background())
			if _, err := blocker.Exec(ctx, "LOCK TABLE "+table+" IN ACCESS EXCLUSIVE MODE"); err != nil {
				t.Fatal(err)
			}
			type result struct {
				status int
				body   map[string]any
				err    error
			}
			done := make(chan result, 1)
			go func() {
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.srv.URL+path, nil)
				if err != nil {
					done <- result{err: err}
					return
				}
				req.Header.Set("Authorization", "Bearer "+token)
				res, err := http.DefaultClient.Do(req)
				if err != nil {
					done <- result{err: err}
					return
				}
				defer res.Body.Close()
				var body map[string]any
				err = json.NewDecoder(res.Body).Decode(&body)
				done <- result{res.StatusCode, body, err}
			}()
			for {
				var waiting int
				if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid))`, blocker.Conn().PgConn().PID()).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting > 0 {
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal("read did not reach controlled query barrier")
				case <-time.After(5 * time.Millisecond):
				}
			}
			want := http.StatusUnauthorized
			if table == "contacts" {
				err = f.api.Revoke(ctx, f.tenant.String(), verified.Prefix)
			} else {
				want = http.StatusForbidden
				err = f.keys.RevokeGrant(ctx, f.tenant, f.device, reader.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := blocker.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-done:
				if got.err != nil || got.status != want || got.body["contacts"] != nil || got.body["messages"] != nil {
					t.Fatalf("revoked read published data: %+v", got)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		})
	}
}
