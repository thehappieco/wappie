package membership

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kc "github.com/thehappieco/kit/contract"

	"whatserver2/internal/membership/membershiptest"
	"whatserver2/internal/pg"
	"whatserver2/internal/store"
)

// The person's document (the plan's 6.6, DS12): notices of platform
// workspaces as Wappie's own page lists them, labels cut over at render,
// actors as subs, the wire's encoding, and a notice deleted.

// notice writes one notice of kind for user in ws, raised by by (nil for
// none), labelled label, raised ago before now; it returns its id.
func (w *snapshotWorld) notice(t *testing.T, ws, device, user uuid.UUID, kind string, label *string, by *uuid.UUID, ago time.Duration) int64 {
	t.Helper()
	ctx := context.Background()
	var id int64
	if err := pg.InTenantTx(ctx, w.pool, ws.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `INSERT INTO device_notices (tenant_id, device_id, user_id, kind, label, hint, raised_by, raised_by_kind,
			raised_at, until)
			VALUES ($1, $2, $3, $4, $5, '…5678', $6, 'person', clock_timestamp() - $7::interval,
			        CASE WHEN $4 = 'number_deleted' THEN clock_timestamp() + interval '30 days' END)
			RETURNING id`, ws, device, user, kind, label, by, ago).Scan(&id)
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

// personDocOf is the document of sub as the sender renders it now.
func (w *snapshotWorld) personDocOf(t *testing.T, sub uuid.UUID) (kc.PersonSettingsDoc, kc.WappiePersonSettings, int) {
	t.Helper()
	read, ok, err := w.contract.PersonOf(context.Background(), sub)
	if err != nil || !ok {
		t.Fatalf("the person: %v %v", ok, err)
	}
	doc, left, err := personDoc(read, store.SettingsOn)
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatalf("the document: %v", err)
	}
	var data kc.WappiePersonSettings
	if err := json.Unmarshal(doc.Data, &data); err != nil {
		t.Fatal(err)
	}
	return doc, data, left
}

func noticeByID(data kc.WappiePersonSettings, id int64) (kc.Notice, bool) {
	for _, n := range data.Notices {
		if n.ID == strconv.FormatInt(id, 10) {
			return n, true
		}
	}
	return kc.Notice{}, false
}

func strp(s string) *string { return &s }

// TestPersonNoticesLabelsCutOver (a gate; the platform's correction 2): a
// notice stored before the label cutover whose label was the number's push
// name goes with label null; one whose label today's rule gives the same
// keeps it; one stored after keeps its own; the document validates.
func TestPersonNoticesLabelsCutOver(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	w.exec(ctx, t, `UPDATE contract_settings_state SET label_cutover_at = clock_timestamp() - interval '1 hour'`)
	pushed, typed, after := w.number(t, w.team, "Vendas", 11), w.number(t, w.team, "Suporte", 12), w.number(t, w.team, "Loja", 13)
	pushName := w.notice(t, w.team, pushed, w.owner, store.NoticeNumberMovedOut, strp("Fulano"), &w.owner, 2*time.Hour)
	sameRule := w.notice(t, w.team, typed, w.owner, store.NoticeNumberMovedOut, strp("Suporte"), &w.owner, 2*time.Hour)
	since := w.notice(t, w.team, after, w.owner, store.NoticeNumberMovedOut, strp("Outro nome"), &w.owner, time.Minute)
	_, data, left := w.personDocOf(t, w.sub)
	for _, c := range []struct {
		id   int64
		want *string
	}{{pushName, nil}, {sameRule, strp("Suporte")}, {since, strp("Outro nome")}} {
		n, ok := noticeByID(data, c.id)
		if !ok {
			t.Fatalf("notice %d is not sent", c.id)
		}
		if (n.Label == nil) != (c.want == nil) || n.Label != nil && *n.Label != *c.want {
			t.Errorf("notice %d's label %v, want %v", c.id, n.Label, c.want)
		}
	}
	if left != 0 {
		t.Fatalf("%d notices left out", left)
	}
}

// TestPersonNoticesActorIsSub (a gate): a notice's actor is the sub of who
// raised it, or null for someone with none; no name or address anywhere in
// the document.
func TestPersonNoticesActorIsSub(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	unlinked := w.users
	stranger, err := unlinked.Create(ctx, store.NewUser{TenantID: w.team, Email: "named-person@example.com", Role: "member", AuthKey: "x",
		KDFSalt: make([]byte, 16), KDFParams: store.DefaultKDFParams(), PublicKey: make([]byte, 32), WrappedUSK: []byte("w")})
	if err != nil {
		t.Fatal(err)
	}
	a, b := w.number(t, w.team, "A", 21, w.owner), w.number(t, w.team, "B", 22, w.owner)
	bySub := w.notice(t, w.team, a, w.owner, store.NoticeSyncPaused, strp("A"), &w.owner, time.Minute)
	byNobody := w.notice(t, w.team, b, w.owner, store.NoticeSyncPaused, strp("B"), &stranger.ID, time.Minute)
	doc, data, _ := w.personDocOf(t, w.sub)
	actorOf := func(id int64) *string {
		n, ok := noticeByID(data, id)
		if !ok {
			t.Fatalf("notice %d is not sent", id)
		}
		var p kc.SyncPausedParams
		if err := json.Unmarshal(n.Params, &p); err != nil {
			t.Fatal(err)
		}
		return p.Actor
	}
	if got := actorOf(bySub); got == nil || *got != w.sub.String() {
		t.Errorf("the linked actor: %v, want %s", got, w.sub)
	}
	if got := actorOf(byNobody); got != nil {
		t.Errorf("an actor with no sub: %v, want null", *got)
	}
	body, err := encodeData(doc)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "@") || strings.Contains(string(body), "named-person") || strings.Contains(string(body), stranger.ID.String()) {
		t.Fatalf("the document names someone: %s", body)
	}
}

// TestPersonNoticesMatchWappie: the notices sent are, workspace by
// workspace, those Wappie's own page lists (Devices.Notices), a pause
// notice of a number the person no longer reads hidden in both; a local
// workspace's are never sent.
func TestPersonNoticesMatchWappie(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	read, unread := w.number(t, w.team, "Lida", 31, w.owner), w.number(t, w.team, "Nao lida", 32)
	w.notice(t, w.team, read, w.owner, store.NoticeSyncPaused, strp("Lida"), &w.owner, time.Minute)
	w.notice(t, w.team, unread, w.owner, store.NoticeSyncPaused, strp("Nao lida"), &w.owner, time.Minute)
	w.notice(t, w.team, uuid.New(), w.owner, store.NoticeNumberDeleted, strp("Gone"), &w.owner, time.Minute)
	_, data, _ := w.personDocOf(t, w.sub)
	var sent []string
	for _, n := range data.Notices {
		if *n.WorkspaceID == w.team.String() {
			sent = append(sent, n.ID)
		}
	}
	listed, err := store.NewDevices(w.pool).Notices(ctx, w.team, w.owner)
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, n := range listed {
		want = append(want, strconv.FormatInt(n.ID, 10))
	}
	slices.Sort(sent)
	slices.Sort(want)
	if !slices.Equal(sent, want) || len(want) != 2 {
		t.Fatalf("sent %v, Wappie's page lists %v", sent, want)
	}
}

// TestPersonNoticeLeftOut: a notice the wire refuses (a number_deleted
// with no purge date) is left out, the document marked truncated, every
// other row sent whole.
func TestPersonNoticeLeftOut(t *testing.T) {
	sub, ws := uuid.New(), uuid.New()
	until := time.Now().Add(time.Hour)
	read := store.ContractPerson{Sub: sub, Seq: 1, MeasuredAt: time.Now(), Notices: []store.ContractNotice{
		{ID: 1, Workspace: ws, Device: uuid.New(), Kind: store.NoticeNumberDeleted, RaisedAt: time.Now(), Until: &until, ActorKind: "person"},
		{ID: 2, Workspace: ws, Device: uuid.New(), Kind: store.NoticeNumberDeleted, RaisedAt: time.Now(), ActorKind: "person"},
		{ID: 3, Workspace: ws, Device: uuid.New(), Kind: store.NoticeNumberMovedOut, RaisedAt: time.Now(), ActorKind: "person",
			Label: strp("bad@label")},
	}}
	doc, left, err := personDoc(read, store.SettingsRead)
	if err != nil || left != 2 || !doc.Truncated {
		t.Fatalf("left %d, truncated %v: %v", left, doc.Truncated, err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
	var data kc.WappiePersonSettings
	if err := json.Unmarshal(doc.Data, &data); err != nil || len(data.Notices) != 1 || data.Notices[0].ID != "1" || doc.Accepts == nil {
		t.Fatalf("the notices %+v, accepts %v: %v", data.Notices, doc.Accepts, err)
	}
}

// TestPersonNoticesCutToFit (the spec's 14.2 and 14.5): a person with more
// notices than kc.MaxNotices gets the newest kc.MaxNotices, and the
// document is truncated, a list cut to fit; none is counted as left out
// (no ERROR: the bound is the spec's). Exactly kc.MaxNotices go whole.
func TestPersonNoticesCutToFit(t *testing.T) {
	sub, ws := uuid.New(), uuid.New()
	now := time.Now()
	read := func(n int) store.ContractPerson {
		p := store.ContractPerson{Sub: sub, Seq: 1, MeasuredAt: now}
		// Newest first, as PersonOf reads them.
		for i := range n {
			p.Notices = append(p.Notices, store.ContractNotice{ID: int64(n - i), Workspace: ws, Device: uuid.New(),
				Kind: store.NoticeNumberMovedOut, RaisedAt: now.Add(-time.Duration(i) * time.Second), ActorKind: "person"})
		}
		return p
	}
	doc, left, err := personDoc(read(kc.MaxNotices), store.SettingsOn)
	if err != nil || left != 0 || doc.Truncated {
		t.Fatalf("%d notices: left %d, truncated %v: %v", kc.MaxNotices, left, doc.Truncated, err)
	}
	doc, left, err = personDoc(read(kc.MaxNotices+1), store.SettingsOn)
	if err != nil || left != 0 || !doc.Truncated {
		t.Fatalf("%d notices: left %d, truncated %v: %v", kc.MaxNotices+1, left, doc.Truncated, err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
	var data kc.WappiePersonSettings
	if err := json.Unmarshal(doc.Data, &data); err != nil || len(data.Notices) != kc.MaxNotices {
		t.Fatalf("%d notices sent: %v", len(data.Notices), err)
	}
	if first, last := data.Notices[0].ID, data.Notices[kc.MaxNotices-1].ID; first != strconv.Itoa(kc.MaxNotices+1) || last != "2" {
		t.Fatalf("the notices sent run from %s to %s, not the newest", first, last)
	}
}

// bodies records the person documents' bodies a client sends.
type bodies struct {
	mu   sync.Mutex
	sent [][]byte
}

func (b *bodies) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/settings") && strings.Contains(r.URL.Path, "/accounts/") && r.Body != nil {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		_ = r.Body.Close() //nolint:errcheck // read whole
		b.mu.Lock()
		b.sent = append(b.sent, body)
		b.mu.Unlock()
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	return http.DefaultTransport.RoundTrip(r)
}

func (b *bodies) last() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.sent) == 0 {
		return nil
	}
	return b.sent[len(b.sent)-1]
}

// TestPersonNoticesEncoding (a gate): a notice labelled "A&B <x>" reaches
// the platform with &, < and > as they are, never as escapes of six
// bytes; and a notice deleted (a recovery deletes a number_deleted one)
// sends the document again within the debounce, without it.
func TestPersonNoticesEncoding(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	w.settingsOn(t, store.SettingsRead)
	sent := &bodies{}
	client := NewClient(&http.Client{Transport: sent}, w.fake.URL, nil)
	if err := client.Use(w.secret, ""); err != nil {
		t.Fatal(err)
	}
	logs := &membershiptest.Logs{}
	m := &Members{Client: client, Contract: w.contract, Log: logs.Logger(), ModeCache: -1, Pace: time.Millisecond}
	labelled := w.number(t, w.team, "A&B <x>", 41)
	id := w.notice(t, w.team, labelled, w.owner, store.NoticeNumberMovedOut, strp("A&B <x>"), &w.owner, 0)
	deleted := w.notice(t, w.team, uuid.New(), w.owner, store.NoticeNumberDeleted, strp("Gone"), &w.owner, 0)
	run(t, w.settingsLeader(m, logs, settingsTimes()))
	eventually(t, soon, "the person's document with both notices", func() bool {
		body := sent.last()
		return bytes.Contains(body, []byte(strconv.FormatInt(deleted, 10))) && bytes.Contains(body, []byte(strconv.FormatInt(id, 10)))
	})
	body := string(sent.last())
	if !strings.Contains(body, `"label":"A&B <x>"`) || strings.Contains(body, "\\u0026") || strings.Contains(body, "\\u003c") ||
		strings.Contains(body, "\\u003e") {
		t.Fatalf("the label on the wire: %s", body)
	}
	if err := pg.InTenantTx(ctx, w.pool, w.team.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM device_notices WHERE id = $1`, deleted)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	gone := strconv.FormatInt(deleted, 10)
	eventually(t, 10*time.Second, "the document sent again without the deleted notice", func() bool {
		doc, ok := w.fake.PersonSettings("wappie", w.sub.String())
		if !ok {
			return false
		}
		var data kc.WappiePersonSettings
		if json.Unmarshal(doc.Data, &data) != nil {
			return false
		}
		_, still := noticeByID(data, deleted)
		return !still && !bytes.Contains(sent.last(), []byte(`"id":"`+gone+`"`))
	})
}
