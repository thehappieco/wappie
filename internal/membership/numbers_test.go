package membership

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kc "github.com/thehappieco/kit/contract"
	"github.com/thehappieco/kit/jcs"
	"go.mau.fi/whatsmeow/types"

	"whatserver2/internal/pg"
	"whatserver2/internal/store"
	"whatserver2/internal/wa"
)

// The numbers section (the spec's 14.3; the plan's 5.1 and 5.5): its
// render, checked by the kit, and its gates.

// looks is a registry's view for the tests: the pairings it runs and the
// numbers it holds.
type looks struct {
	pairing map[string]time.Time
	held    map[string]bool
}

func (l looks) PairingSince(id string) (time.Time, bool) {
	at, ok := l.pairing[id]
	return at, ok
}

func (l looks) Holds(id string) bool { _, pairing := l.pairing[id]; return pairing || l.held[id] }

// numbersRead is a read of every kind of number and registration.
func numbersRead(t *testing.T) (store.ContractNumbers, map[string]uuid.UUID) {
	t.Helper()
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	at := now.Add(-time.Hour)
	sub := uuid.New()
	ids := map[string]uuid.UUID{}
	id := func(name string) uuid.UUID {
		ids[name] = uuid.New()
		return ids[name]
	}
	read := store.ContractNumbers{Workspace: uuid.New(), Seq: now.UnixMilli(), SnapshotSeq: now.UnixMilli() - 5, MeasuredAt: now,
		Local: true, CanLink: true}
	for _, p := range []struct {
		name  string
		epoch int
	}{{"pairing", 1}, {"retry", 1}, {"held", 1}, {"no key", 0}} {
		read.Pending = append(read.Pending, store.ContractPending{ID: id(p.name), CreatedAt: at, Epoch: p.epoch})
	}
	read.Items = append(read.Items, []store.ContractNumber{
		{ID: id("online"), Status: "online", Known: true, LastConnectedAt: &at, Epoch: 1},
		{ID: id("offline"), Status: "offline", Known: true, LastConnectedAt: &at, Epoch: 2},
		{ID: id("new"), Status: "new", Known: true},
		{ID: id("pairing row"), Status: "pairing", LastConnectedAt: &at},
		{ID: id("phone"), Status: "logged_out", LogoutCause: "phone", Known: true, Epoch: 1},
		{ID: id("deletion"), Status: "logged_out", LogoutCause: "deletion", Known: true, Epoch: 1},
		{ID: id("banned"), Status: "banned", Known: true, Epoch: 1},
		{ID: id("by a person"), Status: "offline", Known: true, Paused: true, PauseCause: "person", PausedAt: &at,
			PausedByKind: kc.ActorPerson, PausedBySub: &sub, Epoch: 1},
		{ID: id("by a key"), Status: "offline", Known: true, Paused: true, PauseCause: "person", PausedAt: &at,
			PausedByKind: kc.ActorKey, PausedBySub: &sub, Epoch: 1},
		{ID: id("by a key with no sub"), Status: "offline", Known: true, Paused: true, PauseCause: "person", PausedAt: &at,
			PausedByKind: kc.ActorKey, Epoch: 1},
		{ID: id("moved"), Status: "offline", Known: true, Paused: true, PauseCause: "move", PausedAt: &at, PausedByKind: kc.ActorApp, Epoch: 1},
		{ID: id("told nobody"), Status: "online", Known: true, Paused: true, PauseCause: "person", Epoch: 1},
		{ID: id("a time, no actor"), Status: "online", Known: true, Paused: true, PauseCause: "person", PausedAt: &at, Epoch: 1},
		{ID: id("no time"), Status: "online", Known: true, Paused: true, PauseCause: "person", PausedByKind: kc.ActorPerson, PausedBySub: &sub},
		{ID: id("deleted"), Status: "offline", Known: true, Deleted: true, Paused: true, PauseCause: "deletion", PausedAt: &at,
			PausedByKind: kc.ActorApp, RecoveryOpen: true, Epoch: 1},
		{ID: id("deleted, not paused"), Status: "online", Known: true, Deleted: true, Epoch: 1},
		{ID: id("deleted banned"), Status: "banned", Known: true, Deleted: true, Paused: true, PauseCause: "deletion", Epoch: 1},
		{ID: id("deleted and purging"), Status: "logged_out", LogoutCause: "deletion", Known: true, Deleted: true, Paused: true,
			PauseCause: "deletion", Epoch: 1},
	}...)
	return read, ids
}

// numbersOf is ws's numbers section as the sender reads it, once a
// snapshot of it is numbered (a section names one).
func (w *world) numbersOf(t *testing.T, ws uuid.UUID) store.ContractNumbers {
	t.Helper()
	ctx := context.Background()
	if _, ok, err := w.contract.SnapshotNumbered(ctx, ws); err != nil || !ok {
		t.Fatalf("a snapshot's seq: %v %v", ok, err)
	}
	read, ok, err := w.contract.NumbersOf(ctx, ws)
	if err != nil || !ok {
		t.Fatalf("the read: %v %v", ok, err)
	}
	return read
}

func rowsOf(t *testing.T, doc kc.SettingsDoc) kc.NumbersSettings {
	t.Helper()
	data, err := doc.DecodeData()
	if err != nil {
		t.Fatal(err)
	}
	return *data.(*kc.NumbersSettings)
}

// TestNumbersDocMatchesTheKit: every kind of number and registration
// renders a section the kit's Validate takes (as the platform reads it,
// strictly), in each mode; each row says what Wappie's tables say; and the
// numbers cases of wire-settings.json, the valid ones, decode strictly as
// the renderer's type and encode back as they came.
func TestNumbersDocMatchesTheKit(t *testing.T) {
	read, ids := numbersRead(t)
	l := looks{pairing: map[string]time.Time{ids["pairing"].String(): time.Now()}, held: map[string]bool{ids["held"].String(): true}}
	for _, mode := range []string{store.SettingsRead, store.SettingsOn, "sideways"} {
		doc, err := numbersDoc(read, mode, l)
		if err != nil {
			t.Fatal(err)
		}
		if err := doc.Validate(); err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		if doc.StateSeq != read.Seq || *doc.SnapshotSeq != read.SnapshotSeq || doc.Truncated || doc.Producer != kc.ProducerWappie {
			t.Errorf("%s: the envelope %+v", mode, doc)
		}
	}
	doc, err := numbersDoc(read, store.SettingsRead, l)
	if err != nil {
		t.Fatal(err)
	}
	data := rowsOf(t, doc)
	pending := map[string]kc.PendingRegistration{}
	for _, p := range data.Pending {
		pending[p.ID] = p
	}
	for name, want := range map[string][2]bool{"pairing": {true, false}, "retry": {false, true}, "held": {false, false}, "no key": {false, false}} {
		if p := pending[ids[name].String()]; p.Pairing != want[0] || p.CanRetry != want[1] {
			t.Errorf("pending %s: pairing %v can_retry %v, want %v", name, p.Pairing, p.CanRetry, want)
		}
	}
	rows := map[string]kc.NumberRow{}
	for _, r := range data.Items {
		rows[r.ID] = r
	}
	row := func(name string) kc.NumberRow { return rows[ids[name].String()] }
	for name, want := range map[string]string{
		"online": "online", "offline": "offline", "new": "offline", "pairing row": "pairing", "phone": "logged_out_phone",
		"deletion": "logged_out_deletion", "banned": "banned", "deleted": "logged_out_deletion", "deleted banned": "banned",
		"deleted and purging": "logged_out_deletion",
	} {
		if got := row(name).Connection; got != want {
			t.Errorf("%s: connection %s, want %s", name, got, want)
		}
	}
	for name, want := range map[string]string{"by a person": kc.ActorPerson, "by a key": kc.ActorKey, "moved": kc.ActorApp,
		"by a key with no sub": kc.ActorKey, "deleted": kc.ActorApp} {
		p := row(name).PausedBy
		if p == nil || p.Kind != want || p.At.IsZero() || (p.Sub != nil) != (name == "by a person" || name == "by a key") {
			t.Errorf("%s: paused_by %+v, want %s", name, p, want)
		}
	}
	for _, name := range []string{"told nobody", "a time, no actor", "no time", "deleted, not paused", "online"} {
		if row(name).PausedBy != nil {
			t.Errorf("%s: paused_by %+v, want null", name, row(name).PausedBy)
		}
	}
	for name, want := range map[string]bool{"by a person": true, "moved": true, "told nobody": true, "deleted": false, "online": false} {
		if got := row(name).CanResume; got != want {
			t.Errorf("%s: can_resume %v, want %v", name, got, want)
		}
	}
	for name, want := range map[string]bool{"phone": true, "banned": true, "deleted": true, "pairing row": true, "online": false,
		"by a person": false, "new": false} {
		if got := row(name).ReadOnly; got != want {
			t.Errorf("%s: read_only %v, want %v", name, got, want)
		}
	}
	if e := row("offline").KeyEpoch; e == nil || *e != 2 {
		t.Errorf("key_epoch %v", e)
	}
	if row("new").KeyEpoch != nil || !row("deleted").RecoveryOpen || row("online").RecoveryOpen {
		t.Error("key_epoch is null for epoch 0, recovery_open the deleted number's")
	}
	if row("online").LastConnectedAt == nil || row("new").LastConnectedAt != nil {
		t.Error("last_connected_at")
	}

	var v struct {
		Sections []struct {
			Name  string          `json:"name"`
			Value json.RawMessage `json:"value"`
			Valid bool            `json:"valid"`
		} `json:"sections"`
	}
	readVectors(t, "wire-settings.json", &v)
	n := 0
	for _, c := range v.Sections {
		var head struct {
			App     string          `json:"app"`
			Section string          `json:"section"`
			Data    json.RawMessage `json:"data"`
		}
		if json.Unmarshal(c.Value, &head) != nil || head.App != App || head.Section != kc.SectionNumbers || !c.Valid {
			continue
		}
		n++
		var data kc.NumbersSettings
		if err := kc.DecodeStrict(head.Data, &data); err != nil {
			t.Errorf("%s: %v", c.Name, err)
			continue
		}
		back, err := encodeData(data)
		if err != nil {
			t.Fatal(err)
		}
		if canonical(t, back) != canonical(t, head.Data) {
			t.Errorf("%s: the renderer's type does not keep it:\n%s\n%s", c.Name, back, head.Data)
		}
	}
	if n == 0 {
		t.Fatal("no valid numbers case in wire-settings.json")
	}
}

// canonical is raw's JCS text.
func canonical(t *testing.T, raw []byte) string {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	out, err := jcs.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// TestNumbersBytesNull (a gate): every row's bytes is JSON null, and so are
// places_free and every move_out.
func TestNumbersBytesNull(t *testing.T) {
	read, _ := numbersRead(t)
	doc, err := numbersDoc(read, store.SettingsRead, nil)
	if err != nil {
		t.Fatal(err)
	}
	var data struct {
		PlacesFree json.RawMessage              `json:"places_free"`
		Items      []map[string]json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(doc.Data, &data); err != nil {
		t.Fatal(err)
	}
	if string(data.PlacesFree) != "null" || len(data.Items) != len(read.Items) {
		t.Fatalf("places_free %s, %d items", data.PlacesFree, len(data.Items))
	}
	for _, it := range data.Items {
		for _, member := range []string{"bytes", "move_out"} {
			if raw, ok := it[member]; !ok || string(raw) != "null" {
				t.Errorf("an item's %s is %q", member, raw)
			}
		}
	}
}

// TestSettingsEncoding (a gate): empty lists are [], never null, in the
// data and in accepts, in every mode; and encodeData writes &, < and > as
// they are, where encoding/json's default would write each as six bytes.
// (The numbers data carries no free text; the wire's own check of these
// characters is the person's document's, and the fake's body of an empty
// section is checked in TestSettingsKindNotAccepted.)
func TestSettingsEncoding(t *testing.T) {
	read := store.ContractNumbers{Workspace: uuid.New(), Seq: 2, SnapshotSeq: 1, MeasuredAt: time.Now(), Local: true}
	for _, mode := range []string{store.SettingsRead, store.SettingsOn} {
		doc, err := numbersDoc(read, mode, nil)
		if err != nil {
			t.Fatal(err)
		}
		// read lists no kind; on the numbers kinds the commands releases
		// run, item.sync_now among them since the frame asks Read too (DS13).
		want := []string{}
		if mode == store.SettingsOn {
			want = []string{kc.OpItemRename, kc.OpItemSyncStop, kc.OpItemSyncResume, kc.OpItemSyncNow, kc.OpItemRegistrationDelete}
		}
		if doc.Accepts == nil || !slices.Equal(doc.Accepts, want) {
			t.Errorf("%s: accepts %#v", mode, doc.Accepts)
		}
		for _, want := range []string{`"pending":[]`, `"items":[]`} {
			if !strings.Contains(string(doc.Data), want) {
				t.Errorf("%s: the data %s has no %s", mode, doc.Data, want)
			}
		}
		body, err := encodeData(doc)
		if err != nil {
			t.Fatal(err)
		}
		if mode == store.SettingsRead && !strings.Contains(string(body), `"accepts":[]`) || strings.Contains(string(body), "null,\"data\"") {
			t.Errorf("%s: the body %s", mode, body)
		}
	}
	plain, err := encodeData(map[string]string{"label": "A&B <x>"})
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != `{"label":"A&B <x>"}` {
		t.Errorf("encodeData wrote %s", plain)
	}
	if escaped, _ := json.Marshal(map[string]string{"label": "A&B <x>"}); string(escaped) == string(plain) { //nolint:errchkjson // a map of strings
		t.Error("the check would pass with HTML escaping on")
	}
}

// TestNumbersLogoutCauses (a gate): each writer of logged_out (0052's
// table, whose cause each writer leaves is store's TestLogoutCauseEveryWriter)
// renders its connection code: the phone's logout and a missing session
// logged_out_phone, a deletion's two reasons logged_out_deletion, a number
// the phone logged out and then deleted logged_out_phone until it is
// deleted, and a deleted number logged_out_deletion, or banned; written
// through the store and read back by the section's own read.
func TestNumbersLogoutCauses(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	devices := store.NewDevices(w.pool)
	number := func(name string, n int) uuid.UUID { return w.number(t, w.team, name, n, w.owner) }
	setStatus := func(id uuid.UUID, s wa.Status, reason string) {
		t.Helper()
		if err := devices.SetStatus(ctx, w.team.String(), id.String(), s, reason); err != nil {
			t.Fatal(err)
		}
	}
	phone, missing, atStart := number("phone", 1), number("missing", 2), number("at start", 3)
	setStatus(phone, wa.StatusLoggedOut, "unlinked (logged out from the phone)")
	setStatus(missing, wa.StatusLoggedOut, "session missing")
	setStatus(atStart, wa.StatusLoggedOut, "session missing at startup")
	noSession, unlinked := number("no session", 4), number("unlinked", 5)
	for id, reason := range map[uuid.UUID]string{noSession: "no session at deletion", unlinked: "unlinked when deleted"} {
		setStatus(id, wa.StatusLoggedOut, reason)
	}
	// The phone's logout, then a deletion's reason: the cause stays.
	phoneThenDeletion := number("phone then deletion", 6)
	setStatus(phoneThenDeletion, wa.StatusLoggedOut, "unlinked (logged out from the phone)")
	setStatus(phoneThenDeletion, wa.StatusLoggedOut, "no session at deletion")
	banned := number("banned", 7)
	setStatus(banned, wa.StatusBanned, "temporary")
	deleted, deletedBanned := number("deleted", 8), number("deleted banned", 9)
	setStatus(deletedBanned, wa.StatusBanned, "temporary")
	for _, id := range []uuid.UUID{deleted, deletedBanned} {
		if _, err := devices.Quarantine(ctx, w.team, w.owner, id, nil); err != nil {
			t.Fatal(err)
		}
	}
	read := w.numbersOf(t, w.team)
	doc, err := numbersDoc(read, store.SettingsRead, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
	rows := map[string]kc.NumberRow{}
	for _, r := range rowsOf(t, doc).Items {
		rows[r.ID] = r
	}
	for id, want := range map[uuid.UUID]string{
		phone: "logged_out_phone", missing: "logged_out_phone", atStart: "logged_out_phone", noSession: "logged_out_deletion",
		unlinked: "logged_out_deletion", phoneThenDeletion: "logged_out_phone", banned: "banned", deleted: "logged_out_deletion",
		deletedBanned: "banned", w.device: "offline",
	} {
		r, ok := rows[id.String()]
		if !ok || r.Connection != want {
			t.Errorf("%s: connection %q (%v), want %s", id, r.Connection, ok, want)
		}
		if !r.ReadOnly && want != "offline" {
			t.Errorf("%s: not read_only", id)
		}
	}
}

// TestNumbersDeletedRow (the platform's answers, Wappie's commitment): a
// deleted number, kept until its purge, sends capture "paused" and
// read_only true, so no console button shows on it, deleted through the
// store and read by the section; and so does a deleted row whose pause
// the read finds lifted.
func TestNumbersDeletedRow(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	if _, err := store.NewDevices(w.pool).Quarantine(ctx, w.team, w.owner, w.device, nil); err != nil {
		t.Fatal(err)
	}
	read := w.numbersOf(t, w.team)
	doc, err := numbersDoc(read, store.SettingsRead, nil)
	if err != nil {
		t.Fatal(err)
	}
	rows := rowsOf(t, doc).Items
	if len(rows) != 1 || rows[0].Capture != "paused" || !rows[0].ReadOnly || rows[0].CanResume || !rows[0].RecoveryOpen {
		t.Fatalf("the deleted number's row: %+v", rows)
	}
	unpaused := store.ContractNumber{ID: uuid.New(), Status: "online", Known: true, Deleted: true}
	if r := numberRow(unpaused); r.Capture != "paused" || !r.ReadOnly || r.PausedBy != nil {
		t.Fatalf("a deleted row not paused: %+v", r)
	}
}

// TestNumbersUnknownIdentityReadOnly (the platform's check of fcffb55,
// finding 5): a number whose identity Wappie never learned (it connected
// for a pairing that never linked) is read_only as the section reads it
// from the database, so the console holds back its sync now, which Wappie
// refuses not_linked, and its stop, whose pause it could not lift
// (can_resume false). Once linked, it is not.
func TestNumbersUnknownIdentityReadOnly(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	devices := store.NewDevices(w.pool)
	d, err := devices.Create(ctx, w.team.String(), "Vendas RJ", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	unknown := uuid.MustParse(d.ID)
	for _, status := range []wa.Status{wa.StatusOnline, wa.StatusOffline} {
		if err := devices.SetStatus(ctx, w.team.String(), d.ID, status, ""); err != nil {
			t.Fatal(err)
		}
	}
	rowOf := func(what string, id uuid.UUID) kc.NumberRow {
		t.Helper()
		doc, err := numbersDoc(w.numbersOf(t, w.team), store.SettingsOn, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rowsOf(t, doc).Items {
			if r.ID == id.String() {
				return r
			}
		}
		t.Fatalf("%s: no row", what)
		return kc.NumberRow{}
	}
	if r := rowOf("never linked", unknown); !r.ReadOnly || r.CanResume || r.Capture != "on" || r.Connection != "offline" {
		t.Fatalf("a number never linked: %+v", r)
	}
	if r := rowOf("linked", w.device); r.ReadOnly {
		t.Fatalf("a linked number: %+v", r)
	}
	if err := devices.SetIdentity(ctx, w.team.String(), d.ID, wa.Identity{PN: types.JID{User: "5511998765432", Server: types.DefaultUserServer}}); err != nil {
		t.Fatal(err)
	}
	if r := rowOf("linked since", unknown); r.ReadOnly {
		t.Fatalf("a number linked since: %+v", r)
	}
}

// TestNumbersCarryNoLabel (a gate, PR 2's): the section's data names no
// label, and a number named only by its push name shows no name in the
// section or in the snapshot sent beside it.
func TestNumbersCarryNoLabel(t *testing.T) {
	w := newSnapshotWorld(t)
	ctx := context.Background()
	const pushName = "Fulano Pushname"
	d, err := store.NewDevices(w.pool).Create(ctx, w.team.String(), "", wa.ModePassive)
	if err != nil {
		t.Fatal(err)
	}
	if err := pg.InTenantTx(ctx, w.pool, w.team.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE devices SET pn = '5511900003333@s.whatsapp.net', push_name = $2, label = '' WHERE id = $1`, d.ID, pushName)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	read := w.numbersOf(t, w.team)
	doc, err := numbersDoc(read, store.SettingsRead, nil)
	if err != nil {
		t.Fatal(err)
	}
	var items []map[string]json.RawMessage
	var data struct {
		Items *[]map[string]json.RawMessage `json:"items"`
	}
	data.Items = &items
	if err := json.Unmarshal(doc.Data, &data); err != nil || len(items) != 2 {
		t.Fatalf("the data: %v, %d items", err, len(items))
	}
	for _, it := range items {
		if _, ok := it["label"]; ok {
			t.Error("a numbers row carries a label member")
		}
	}
	_, snap := w.snapshotOf(t, w.team)
	body, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	for what, b := range map[string][]byte{"section": doc.Data, "snapshot": body} {
		if bytes.Contains(b, []byte(pushName)) || bytes.Contains(b, []byte("Fulano")) {
			t.Errorf("the %s names the number by its push name", what)
		}
	}
	if it, ok := itemOf(snap, uuid.MustParse(d.ID)); !ok || it.Label != nil {
		t.Errorf("the snapshot's item: %+v %v", it, ok)
	}
}

// TestSectionRefusedLocally: a section the kit's Validate refuses, or over
// the call's limit, is one Wappie would not send, named by its rule.
func TestSectionRefusedLocally(t *testing.T) {
	read, _ := numbersRead(t)
	doc, err := numbersDoc(read, store.SettingsRead, nil)
	if err != nil {
		t.Fatal(err)
	}
	if why, rule := sectionRule(doc); why != "" {
		t.Fatalf("a valid section: %s %v", why, rule)
	}
	bad := doc
	bad.Accepts = []string{"item.relink"}
	if why, rule := sectionRule(bad); why != "invalid" || rule == nil {
		t.Errorf("a kind the kit does not know in accepts: %q %v", why, rule)
	}
	bad = doc
	bad.Data = []byte(strings.Replace(string(doc.Data), `"connection":"online"`, `"connection":"asleep"`, 1))
	if why, _ := sectionRule(bad); why != "invalid" {
		t.Errorf("an unknown connection code: %q", why)
	}
	big := doc
	big.Data = []byte(`{"can_link":true,"places_free":null,"storage_paused":false,"pending":[],"items":[],"pad":"` +
		strings.Repeat("x", kc.SettingsBodyLimit) + `"}`)
	if why, _ := sectionRule(big); why == "" {
		t.Error("a section over the call's limit")
	}
}

// TestCommandPageMoves: a command feed page of the generation held is one
// the spec describes only when its next_after is not behind the cursor,
// its commands come after the cursor and none past next_after, and a page
// with more ends at its last item; an empty final page is one.
func TestCommandPageMoves(t *testing.T) {
	item := func(cseq int64) kc.CommandFeedItem {
		return kc.CommandFeedItem{CSeq: cseq, Command: json.RawMessage(`{}`)}
	}
	for _, c := range []struct {
		name   string
		page   kc.CommandFeed
		cursor int64
		want   bool
	}{
		{"an empty final page", kc.CommandFeed{NextAfter: 5, Items: []kc.CommandFeedItem{}}, 5, true},
		{"a page of two", kc.CommandFeed{NextAfter: 7, Items: []kc.CommandFeedItem{item(6), item(7)}}, 5, true},
		{"next_after behind the cursor", kc.CommandFeed{NextAfter: 4, Items: []kc.CommandFeedItem{}}, 5, false},
		{"more with no item", kc.CommandFeed{NextAfter: 5, More: true, Items: []kc.CommandFeedItem{}}, 5, false},
		{"more past its last item", kc.CommandFeed{NextAfter: 9, More: true, Items: []kc.CommandFeedItem{item(6)}}, 5, false},
		{"more at its last item", kc.CommandFeed{NextAfter: 6, More: true, Items: []kc.CommandFeedItem{item(6)}}, 5, true},
		{"a final page past its last item", kc.CommandFeed{NextAfter: 9, Items: []kc.CommandFeedItem{item(6)}}, 5, true},
		// A broken platform's page, served whatever the cursor: taken, it
		// would be asked again at once and taken again, without end.
		{"an item at the cursor, next_after there", kc.CommandFeed{NextAfter: 1, Items: []kc.CommandFeedItem{item(1)}}, 1, false},
		{"items at or before the cursor", kc.CommandFeed{NextAfter: 6, Items: []kc.CommandFeedItem{item(5), item(6)}}, 5, false},
		{"next_after before its last item", kc.CommandFeed{NextAfter: 6, Items: []kc.CommandFeedItem{item(6), item(7)}}, 5, false},
	} {
		if got := commandPageMoves(c.page, c.cursor); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// TestSectionLeavesOutRefusedRows: a row the wire refuses is left out and
// the section goes truncated, the rest sent whole (the spec's 14.2, "A
// row the wire refuses"); a section that fails with no row at all, or for
// a rule no row breaks alone (an item twice), is not sent, nothing left
// out. No database row makes one: here a paused_by kind and a pending
// registration's time no database row holds.
func TestSectionLeavesOutRefusedRows(t *testing.T) {
	read, ids := numbersRead(t)
	doc, dropped, why, rule := numbersSection(read, store.SettingsRead, nil)
	if why != "" || rule != nil || len(dropped) != 0 || doc.Truncated {
		t.Fatalf("a valid section: %q %v %v %v", why, rule, dropped, doc.Truncated)
	}
	bad := read
	bad.Items = append([]store.ContractNumber{}, read.Items...)
	at := time.Date(2026, 11, 8, 11, 0, 0, 0, time.UTC)
	robot, zero := uuid.New(), uuid.New()
	bad.Items = append(bad.Items, store.ContractNumber{ID: robot, Status: "online", Known: true, Paused: true, PauseCause: "person",
		PausedAt: &at, PausedByKind: "robot", Epoch: 1})
	bad.Pending = append(append([]store.ContractPending{}, read.Pending...), store.ContractPending{ID: zero, Epoch: 1})
	if whole, err := numbersDoc(bad, store.SettingsRead, nil); err != nil || whole.Validate() == nil {
		t.Fatalf("the section with both rows is one the kit refuses: %v", err)
	}
	doc, dropped, why, rule = numbersSection(bad, store.SettingsRead, nil)
	if why != "" || rule != nil || !doc.Truncated || len(dropped) != 2 || doc.Validate() != nil {
		t.Fatalf("rows the wire refuses: %q %v %v truncated=%v", why, rule, dropped, doc.Truncated)
	}
	if got := map[uuid.UUID]bool{dropped[0]: true, dropped[1]: true}; !got[robot] || !got[zero] {
		t.Fatalf("left out %v, want %s and %s", dropped, robot, zero)
	}
	rows := rowsOf(t, doc)
	if len(rows.Items) != len(read.Items) || len(rows.Pending) != len(read.Pending) {
		t.Fatalf("sent %d items and %d pending, want %d and %d", len(rows.Items), len(rows.Pending), len(read.Items), len(read.Pending))
	}
	if rows.Items[0].ID != ids["online"].String() {
		t.Fatalf("the rows kept: %+v", rows.Items[0])
	}

	// No row to blame: the envelope fails, or an item comes twice.
	noSeq := bad
	noSeq.Seq = 0
	if _, dropped, why, _ := numbersSection(noSeq, store.SettingsRead, nil); why != "invalid" || len(dropped) != 0 {
		t.Fatalf("a state_seq of 0: %q %v", why, dropped)
	}
	twice := read
	twice.Items = append(append([]store.ContractNumber{}, read.Items...), read.Items[0])
	if _, dropped, why, _ := numbersSection(twice, store.SettingsRead, nil); why != "invalid" || len(dropped) != 0 {
		t.Fatalf("an item twice: %q %v", why, dropped)
	}
}
